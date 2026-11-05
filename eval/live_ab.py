#!/usr/bin/env python3
"""Run the model-tier A/B against LIVE endpoints and report per-tier accuracy.

Everything else in ``eval/`` measures this pipeline against replay recordings, because
a committed artifact has to be reproducible by a reviewer with no inference host. That
is the right default and it is also why the model tiers have never actually been
measured: the committed recordings cover ``fixtures/synthetic`` only, so every external
row in ``eval/metrics.json`` was dispositioned with zero model judgments, and the
artifact says so in capitals.

This script closes that gap. It calls real services and reports, per tier, how often
each one was right - which is the question the whole cost-ladder argument rests on and
which no amount of deterministic-only measurement can answer.

Two things it deliberately does NOT do:

* It does not write ``eval/metrics.json``. That artifact describes reproducible offline
  measurement; a live run describes a moment and a set of hosts. Mixing them would make
  the committed numbers unverifiable by anyone else. Output goes to ``eval/live-ab.json``
  and is labelled with the endpoints used.
* It does not record replay fixtures from external corpora. Model responses quote their
  input, and the external corpora are third-party data whose licences permit evaluation
  but not redistribution of derived text. Recording our own synthetic fixtures is fine
  and is what ``tools/record_replay.py`` already does.

Tiers are addressed by the same ``ModelEndpoints`` fields the production config uses, so
this measures the shipped code path rather than a parallel one. A tier whose endpoint is
not supplied simply does not run, which is how the fast tiers are measured across every
message while the expensive adjudication tier is measured across a sample.

    python3 eval/live_ab.py --tiers classifier,url_reputation,prompt_injection \\
        --corpora synthetic,adversarial,external --concurrency 6
"""

from __future__ import annotations

import argparse
import dataclasses
import concurrent.futures as futures
import json
import os
import pathlib
import re
import statistics
import sys
import time
from typing import Any
from urllib.parse import urlsplit

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))

from tenable_email import pipeline  # noqa: E402
from tenable_email.config import Config  # noqa: E402
from tenable_email.evidence import Provenance  # noqa: E402

import eval.run as run  # noqa: E402
import eval.external as external  # noqa: E402
from eval.selective import HOSTILE_LABELS  # noqa: E402

#: Which endpoint field each tier reads, so --tiers maps to configuration rather than
#: to a second implementation of tier selection.
TIER_ENDPOINT_FIELD = {
    "classifier": "fraudfox_url",
    "url_reputation": "secmodels_url",
    "prompt_injection": "secmodels_url",
    "spam_three_way": "spam_classifier_url",
    "injection_classifier": "injection_classifier_url",
    "vision": "vlm_url",
    "llm": "llm_url",
}


def hostile(label: str) -> bool:
    return (label or "").strip().lower() in HOSTILE_LABELS


def redact_url(url: str) -> str:
    """Keep the shape of an endpoint, drop the address.

    This artifact is committed and the repository is published, so a private inference
    host must not appear in it. Scheme and port survive because they say something
    reproducible - which service family was called and where it listened - while the host
    is replaced. The unredacted mapping is written to a gitignored sidecar, so the
    internal record of which host produced which number stays complete. Loopback is left
    alone: it names no host but the machine running the measurement.

    This errs toward withholding. Anything that is not loopback and not a public literal
    IP is treated as private, so a genuine public API host is redacted too. That is
    deliberate: deciding whether ``host.internal.example`` is public requires knowing the
    network, and guessing wrong publishes an address that cannot be unpublished from git
    history. Attribution for a remote API rests on the recorded model id, which is not
    redacted, so nothing needed to interpret the numbers is lost.
    """
    try:
        parts = urlsplit(str(url))
    except ValueError:
        return "<unparsable-endpoint>"
    host = parts.hostname or ""
    if not host or host in ("localhost", "127.0.0.1", "::1"):
        return str(url)
    private = (
        host.startswith(("10.", "192.168.", "169.254."))
        or bool(re.match(r"^172\.(?:1[6-9]|2\d|3[01])\.", host))
        or not re.match(r"^[\d.]+$", host)
    )
    if not private:
        return str(url)
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://<withheld>{port}{parts.path or ''}"


#: Every endpoint field that addresses a tier, grouped by the tier it belongs to.
#:
#: ``build_config`` must clear the groups it was not asked for, because
#: ``Config.from_env()`` reads all of them from the environment. Leaving an unrequested
#: group populated means an arm silently measures tiers it never named - and that is not
#: hypothetical. The adjudication tier is configured purely by ``TENABLE_EMAIL_LLM_URL``
#: plus ``TENABLE_EMAIL_LLM_MODEL``, so with those exported a run that asked for
#: ``["classifier", "prompt_injection"]`` consults the language model too. The same three
#: real benign messages disposition CLEAN with those variables unset and MANUAL_REVIEW
#: with them set, because clearance takes the weakest self-reported confidence across
#: every consulted tier and a language model hedges where a softmax classifier emits 0.99.
#:
#: A runner that cannot guarantee which tiers it addressed cannot support any claim about
#: them, and this one publishes the project's headline numbers. Note that ``secmodels_url``
#: is shared by two tiers, so it survives if either is requested.
_TIER_ENDPOINT_FIELDS: dict[str, tuple[str, ...]] = {
    "classifier": ("fraudfox_url",),
    "url_reputation": ("secmodels_url",),
    "prompt_injection": ("secmodels_url",),
    "spam_three_way": ("spam_classifier_url", "spam_classifier_model"),
    "injection_classifier": ("injection_classifier_url", "injection_classifier_model"),
    "vision": ("vlm_url", "vlm_model", "vlm_api_key", "vlm_max_tokens",
               "vlm_thinking_enabled", "vlm_supports_chat_template_kwargs"),
    "llm": ("llm_url", "llm_model", "llm_api_key", "llm_max_tokens",
            "llm_thinking_enabled", "llm_supports_chat_template_kwargs"),
}


def build_config(tiers: list[str], *, llm: dict[str, str] | None = None) -> Config:
    """A live Config with exactly the requested tiers addressed.

    Endpoints come from the environment, which is how the production CLI is configured,
    so the measurement exercises the same wiring an operator would use. "Exactly" is
    enforced rather than assumed: every endpoint field belonging to a tier that was not
    requested is reset to its default, so an exported variable cannot smuggle a tier into
    an arm that never named it.
    """
    endpoints: dict[str, Any] = {}
    for tier in tiers:
        field = TIER_ENDPOINT_FIELD.get(tier)
        if not field:
            raise SystemExit(f"unknown tier {tier!r}; known: {sorted(TIER_ENDPOINT_FIELD)}")
        env = "TENABLE_EMAIL_" + field.upper()
        value = os.environ.get(env)
        if not value:
            raise SystemExit(f"tier {tier!r} needs {env} to be set")
        endpoints[field] = value
    if llm:
        for key, value in llm.items():
            endpoints[key] = value
    cfg = Config.from_env()
    endpoints.setdefault("timeout_seconds", cfg.endpoints.timeout_seconds)

    requested = set(tiers) | ({"llm"} if llm else set())
    keep = {f for t in requested for f in _TIER_ENDPOINT_FIELDS.get(t, ())}
    fields = cfg.endpoints.__dataclass_fields__
    cleared: list[str] = []
    for tier, group in _TIER_ENDPOINT_FIELDS.items():
        if tier in requested:
            continue
        for f in group:
            if f in keep or f in endpoints:
                continue
            default = fields[f].default
            if default is dataclasses.MISSING:
                continue
            if getattr(cfg.endpoints, f) != default:
                cleared.append(f)
            endpoints[f] = default
    if cleared:
        print(f"  build_config: cleared unrequested tier endpoint(s) inherited from the "
              f"environment: {', '.join(sorted(set(cleared)))}")

    object.__setattr__(cfg, "replay", False)
    object.__setattr__(cfg, "endpoints", type(cfg.endpoints)(**{
        **{f: getattr(cfg.endpoints, f) for f in fields},
        **endpoints,
    }))
    return cfg


def redact_text(text: str) -> str:
    """Strip absolute host paths out of text that is about to be committed.

    An error string is not safe to publish just because the message is. A
    ``FileNotFoundError`` carries the absolute path it failed on, and this artifact is
    committed to a repository that gets published, so a corrupted run would otherwise
    print the build host's home directory fifty times into the public record. The leak
    guard catches that, but catching it at the end means the artifact has to be scrubbed
    by hand; redacting where the string is recorded means it cannot happen. The
    replacement names the repository root rather than an angle-bracket placeholder,
    because the same guard rejects those in XML attribute positions elsewhere.
    """
    out = str(text)
    home = str(pathlib.Path.home())
    repo = str(REPO)
    for value, label in ((repo, "<repo>"), (home, "<home>")):
        if value and value in out:
            out = out.replace(value, label)
    return re.sub(r"/home/[A-Za-z0-9_.-]+", "<home>", out)


def collect_entries(corpus_name: str, plan: dict[str, Any] | None) -> list[dict]:
    if corpus_name in ("synthetic", "adversarial"):
        corpora = run.corpora()
        block = corpora.get(corpus_name)
        return list(block["entries"]) if block else []
    if corpus_name == "external":
        if plan is None:
            raise SystemExit("external plan was not built; is eval/internal fetched?")
        # build_plan() publishes TWO similarly-named keys and only one is measurable:
        # "_corpora" carries name/kind/label/messages_dir/entries/descriptor, while
        # "corpora" carries the provenance descriptor (licence, revision, digest). Reading
        # the wrong one yields dicts with no "entries" key, so prefer the measurable one
        # and refuse rather than silently measuring nothing.
        block = plan.get("_corpora") or {}
        if not block:
            raise SystemExit(
                "the external plan carries no measurable corpora under '_corpora' - was "
                f"eval/internal fetched? plan keys were {sorted(plan)}"
            )
        out: list[dict] = []
        for name, corpus in sorted(block.items()):
            if name.startswith("_"):
                continue
            for entry in corpus["entries"]:
                out.append({**entry, "corpus": name})
        return out
    raise SystemExit(f"unknown corpus {corpus_name!r}")


def triage_one(entry: dict, cfg: Config) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        verdict = pipeline.triage_file(entry["path"], cfg)
    except Exception as exc:  # a crash is a result, not a reason to stop the run
        return {
            "case": entry.get("case"), "corpus": entry.get("corpus"),
            "label": entry.get("label"),
            "error": redact_text(f"{type(exc).__name__}: {exc}"),
            "ms": (time.perf_counter() - started) * 1000,
        }
    tiers: dict[str, Any] = {}
    for finding in verdict.evidence:
        if finding.provenance is not Provenance.MODEL_JUDGMENT:
            continue
        value = finding.value if isinstance(finding.value, dict) else {}
        name = str(value.get("tier") or finding.key)
        detail = str(finding.detail or "")
        # The detail reads "... 148.9 ms verdict=..." - the number and the unit are
        # separate whitespace-delimited tokens, so matching a token that ENDS in "ms"
        # never fired and every latency came back None. Cost per tier is part of the
        # argument for the cost ladder, so it is worth parsing properly.
        latency = None
        match = re.search(r"(\d+(?:\.\d+)?)\s*ms\b", detail)
        if match:
            latency = float(match.group(1))
        tiers[name] = {
            "stance": value.get("stance"),
            "confidence": value.get("confidence"),
            "attack_type": value.get("attack_type"),
            "latency_ms": latency,
            "abstained": value.get("stance") in (None, "abstain"),
        }
    return {
        "case": entry.get("case"),
        "corpus": entry.get("corpus"),
        "label": entry.get("label"),
        "status": entry.get("status"),
        "disposition": verdict.disposition.value,
        "confidence": round(float(verdict.confidence), 4),
        "attack_type": verdict.attack_type.value,
        "escalated": bool(verdict.escalated),
        "truncated": bool(verdict.truncated),
        "tiers": tiers,
        "ms": (time.perf_counter() - started) * 1000,
    }


def score_tier(rows: list[dict], tier: str) -> dict[str, Any]:
    """Confusion counts for one tier against the corpus labels.

    A tier that abstained is counted separately rather than folded into either side:
    "did not answer" and "answered correctly" are different facts, and an abstention
    rate is itself a result worth reporting.
    """
    tp = fp = tn = fn = abstained = absent = 0
    confidences: list[float] = []
    latencies: list[float] = []
    wrong: list[dict[str, Any]] = []
    for row in rows:
        if row.get("error"):
            continue
        vote = (row.get("tiers") or {}).get(tier)
        label = row.get("label") or ""
        is_hostile = hostile(label)
        if vote is None:
            absent += 1
            continue
        if vote.get("latency_ms") is not None:
            latencies.append(float(vote["latency_ms"]))
        if vote.get("abstained"):
            abstained += 1
            continue
        says_threat = str(vote.get("stance")) in ("threat", "spam")
        if vote.get("confidence") is not None:
            confidences.append(float(vote["confidence"]))
        if is_hostile and says_threat:
            tp += 1
        elif is_hostile and not says_threat:
            fn += 1
            wrong.append({"case": row.get("case"), "corpus": row.get("corpus"),
                          "kind": "false_negative", "label": label,
                          "stance": vote.get("stance"),
                          "confidence": vote.get("confidence")})
        elif not is_hostile and says_threat:
            fp += 1
            wrong.append({"case": row.get("case"), "corpus": row.get("corpus"),
                          "kind": "false_positive", "label": label,
                          "stance": vote.get("stance"),
                          "confidence": vote.get("confidence")})
        else:
            tn += 1
    answered = tp + fp + tn + fn
    return {
        "tier": tier,
        "rows": len(rows),
        "answered": answered,
        "abstained": abstained,
        "absent": absent,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "recall": (tp / (tp + fn)) if (tp + fn) else None,
        "false_positive_rate": (fp / (fp + tn)) if (fp + tn) else None,
        "precision": (tp / (tp + fp)) if (tp + fp) else None,
        "accuracy": ((tp + tn) / answered) if answered else None,
        "mean_confidence": (statistics.fmean(confidences) if confidences else None),
        "median_latency_ms": (statistics.median(latencies) if latencies else None),
        "p95_latency_ms": (
            sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)] if latencies else None
        ),
        "errors_sample": wrong[:40],
        "error_count": len(wrong),
    }


def score_pipeline(rows: list[dict]) -> dict[str, Any]:
    """End-to-end disposition accuracy, with deferral counted as its own outcome."""
    total = cleared = accused = deferred = 0
    fn = fp = 0
    for row in rows:
        if row.get("error"):
            continue
        total += 1
        disp = row.get("disposition")
        is_hostile = hostile(row.get("label") or "")
        if disp == "manual_review":
            deferred += 1
        elif disp == "clean":
            cleared += 1
            if is_hostile:
                fn += 1
        else:
            accused += 1
            if not is_hostile:
                fp += 1
    answered = cleared + accused
    return {
        "rows": len(rows), "measured": total, "cleared": cleared, "accused": accused,
        "deferred": deferred,
        "coverage": (answered / total) if total else None,
        "false_negatives": fn, "false_positives": fp,
        "selective_risk": ((fn + fp) / answered) if answered else None,
    }


def run_set(name: str, entries: list[dict], cfg: Config, concurrency: int) -> dict[str, Any]:
    started = time.perf_counter()
    rows: list[dict[str, Any]] = []
    if concurrency <= 1:
        for entry in entries:
            rows.append(triage_one(entry, cfg))
    else:
        with futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            for result in pool.map(lambda e: triage_one(e, cfg), entries):
                rows.append(result)
    wall = time.perf_counter() - started
    errors = [r for r in rows if r.get("error")]
    tiers_seen = sorted({t for r in rows for t in (r.get("tiers") or {})})
    out = {
        "name": name,
        "messages": len(rows),
        "errors": len(errors),
        "error_samples": [
            {"case": e.get("case"), "error": e.get("error")} for e in errors[:10]
        ],
        "wall_seconds": round(wall, 2),
        "ms_per_message": round((wall * 1000) / len(rows), 1) if rows else None,
        "tiers_consulted": tiers_seen,
        "pipeline": score_pipeline(rows),
        "per_tier": {t: score_tier(rows, t) for t in tiers_seen},
    }
    return out, rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--tiers", default="classifier,url_reputation,prompt_injection")
    parser.add_argument("--corpora", default="synthetic,adversarial")
    parser.add_argument("--llm-url"), parser.add_argument("--llm-model")
    parser.add_argument("--llm-sample", type=int, default=0,
                        help="run a second pass with the adjudication tier over at most "
                             "this many messages per corpus; 0 disables it")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--max-messages", type=int, default=None)
    parser.add_argument("-o", "--out", default="eval/live-ab.json")
    parser.add_argument("--seed", default=external.DEFAULT_SEED)
    args = parser.parse_args(argv)

    tiers = [t.strip() for t in args.tiers.split(",") if t.strip()]
    corpus_names = [c.strip() for c in args.corpora.split(",") if c.strip()]

    plan = None
    if "external" in corpus_names:
        kwargs: dict[str, Any] = {}
        if args.max_messages is not None:
            kwargs["max_messages"] = args.max_messages
        plan = external.build_plan(**kwargs)

    cfg = build_config(tiers)
    active = {
        field: getattr(cfg.endpoints, field)
        for field in sorted({TIER_ENDPOINT_FIELD[t] for t in tiers})
    }
    print(f"tiers: {tiers}")
    print(f"endpoints: {json.dumps(active)}")
    print(f"concurrency: {args.concurrency}")

    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "commit": run._git("rev-parse", "--short", "HEAD"),
        "dirty": bool(run._git("status", "--porcelain")),
        "mode": "live",
        "tiers_requested": tiers,
        # Redacted: this file is committed and the repository is published.
        "endpoints": {k: redact_url(v) for k, v in active.items()},
        "endpoints_note": (
            "Host addresses are withheld because this artifact is committed to a "
            "published repository. Scheme and port are retained so the service "
            "family is identifiable; the full mapping is recorded under "
            "eval/internal/, which is gitignored."
        ),
        "llm": None,
        "concurrency": args.concurrency,
        "note": (
            "Live measurement against real inference services. Not reproducible offline "
            "and deliberately kept out of eval/metrics.json, which describes recordings "
            "a reviewer can replay with no inference host. Endpoints and model ids are "
            "named so the numbers can be attributed to the hosts that produced them."
        ),
        "sets": {},
    }

    all_rows: dict[str, list[dict]] = {}
    for corpus in corpus_names:
        entries = collect_entries(corpus, plan)
        if not entries:
            print(f"  {corpus}: no entries, skipped")
            continue
        grouped: dict[str, list[dict]] = {corpus: entries}
        if corpus == "external":
            grouped = {}
            for entry in entries:
                grouped.setdefault(entry.get("corpus") or "external", []).append(entry)
        for name, group in sorted(grouped.items()):
            print(f"  measuring {name}: {len(group)} messages ...", flush=True)
            result, rows = run_set(name, group, cfg, args.concurrency)
            payload["sets"][name] = result
            all_rows[name] = rows
            pipe = result["pipeline"]
            print(f"    {result['wall_seconds']}s  {result['ms_per_message']} ms/msg  "
                  f"tiers={result['tiers_consulted']}  errors={result['errors']}")
            print(f"    pipeline: coverage={pipe['coverage']} risk={pipe['selective_risk']} "
                  f"cleared={pipe['cleared']} accused={pipe['accused']} deferred={pipe['deferred']}")
            for tier, sc in result["per_tier"].items():
                r = sc["recall"]; f = sc["false_positive_rate"]
                print(f"    tier {tier:18} answered={sc['answered']:5} "
                      f"recall={r if r is None else round(r,4)} "
                      f"fpr={f if f is None else round(f,4)} "
                      f"tp={sc['true_positive']} fp={sc['false_positive']} "
                      f"tn={sc['true_negative']} fn={sc['false_negative']} "
                      f"abstain={sc['abstained']} med_ms={sc['median_latency_ms']}")

    if args.llm_sample and args.llm_url:
        llm_cfg = build_config(tiers, llm={
            "llm_url": args.llm_url,
            "llm_model": args.llm_model or "",
        })
        payload["llm"] = {
            "url": redact_url(args.llm_url), "model": args.llm_model,
            "sample_per_corpus": args.llm_sample, "seed": args.seed,
        }
        print(f"\n  adjudication pass over a sample of {args.llm_sample}/corpus")
        for name, rows in all_rows.items():
            if not rows:
                continue
            keys = external.sample_keys(args.seed, name, list(range(len(rows))),
                                        args.llm_sample)
            entries = [e for i, e in enumerate(collect_entries(
                "external" if rows[0].get("corpus") else name, plan)) if i in keys]
            if not entries:
                continue
            result, _ = run_set(f"{name}+llm", entries, llm_cfg, args.concurrency)
            payload["sets"][f"{name}+llm"] = result
            pipe = result["pipeline"]
            print(f"    {name}+llm: {result['wall_seconds']}s coverage={pipe['coverage']} "
                  f"risk={pipe['selective_risk']} tiers={result['tiers_consulted']}")
            for tier, sc in result["per_tier"].items():
                if tier != "llm":
                    continue
                print(f"      llm recall={sc['recall']} fpr={sc['false_positive_rate']} "
                      f"answered={sc['answered']} abstain={sc['abstained']} "
                      f"med_ms={sc['median_latency_ms']}")

    out = REPO / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    #: The unredacted sidecar. eval/internal/ is gitignored, so this never ships.
    try:
        sidecar = external.fetch.INTERNAL / "live-endpoints.json"
        sidecar.parent.mkdir(parents=True, exist_ok=True)
        sidecar.write_text(json.dumps({
            "endpoints": active, "llm_url": args.llm_url,
            "llm_model": args.llm_model,
            "generated_utc": payload["generated_utc"], "artifact": str(out),
        }, indent=2) + "\n", encoding="utf-8")
        os.chmod(sidecar, 0o600)
    except OSError:
        #: Losing the sidecar must not lose the measurement.
        pass
    print(f"\nwrote {out} ({out.stat().st_size} bytes)")
    print("endpoints recorded redacted; unredacted sidecar under eval/internal/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
