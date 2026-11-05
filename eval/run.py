#!/usr/bin/env python3
"""Measure the pipeline against the committed corpora, and - with --external - fetched public ones.

The default path is the half that can run anywhere: it needs no network, no
credentials and no downloads, because it measures against ``fixtures/synthetic/`` and
``fixtures/adversarial/`` using the committed replay recordings, and every number it
emits is reproducible by someone with no inference host.

``--external`` adds the other half, built by Bundle N phases 1 and 1b: ``eval/fetch.py``
downloads public corpora that passed a closed licence gate, ``--rows`` reads the ones that
ship only as Parquet as JSON from the datasets-server conversion service, and
``eval/external.py`` wraps their rows in a synthesized ``.eml`` so the same
``measure_corpus`` can score them. Those numbers are labelled with their licence,
revision, digest, the object the text actually came from, and the limitation the wrapper
imposes, and they are **not** comparable to the committed ones: the corpora are text, so
the authentication layer that settles most real mail cannot fire. Fetching them at
evaluation time rather than committing them is the point - most public corpora are
copyleft, non-commercial, share-alike, or declare no licence at all
(``docs/EVAL-SUITES.md``). Running the injection A/B against real model weights
(Bundle N phase 2, N8) is still not implemented: with the committed recordings keyed by
content address, an external message has no recording, so the tiers abstain and
corpus-backed equals deterministic-only on every external row - which is why the
external block carries a required ``model_tier`` field that says so, and a
``per_dataset`` rollup whose rates are reported beside their denominators.

Writing the artifact does not delete a measurement it was not asked to make
---------------------------------------------------------------------------

``measure()`` reports what *this invocation* measured. The writer adds one rule on top,
because the two are not the same question and conflating them destroyed committed
evidence once: **a top-level block the previous artifact carried and this run did not
produce is either carried forward and marked, or removed and stated - never silently
dropped.** ``--external`` is the block this is about (``external`` is produced only when
it is asked for, and the corpora it measures are gitignored, so most invocations cannot
produce it at all), but the rule is written over the payload's top level rather than as a
special case for that one key. See :func:`carry_forward`.

A carried block is marked ``reproduced_here: false`` with a note naming where it came
from, so nothing can mistake it for a fresh measurement; every other field of it is
byte-identical to the block that was already there. Asking for the measurement is what
disables the carry: with ``--external`` the run's own numbers simply replace the block,
markers and all, because stale data must never survive a real measurement.

Two configurations are measured, and the difference between them is the point:

``deterministic-only``
    ``Config(replay=True, replay_dir=None)``. Every model tier records
    UNAVAILABLE and no model judgment is emitted. This is what a reviewer gets
    with no inference host at all, and it is the configuration being attacked in
    ``fixtures/adversarial/``.

``corpus-backed``
    The same, plus the committed recordings in ``fixtures/replay/``, so the tiers
    answer from real responses captured against live endpoints.

The metrics reported are the ones the external red-team review asked for by name:
auto-clearance rate, escalation volume, and **false-negative rate among
auto-closed messages** -- that last being the number that says whether clearing a
message is trustworthy, without which a clearance rate is a boast rather than a
measurement. A clearance rate reported alone is the same mistake as an F1
reported without its false-positive rate, and ``docs/EVAL-SUITES.md`` records a
published model with F1 0.992 whose false-positive rate was 1.00.

Usage::

    python3 eval/run.py                      # markdown report to stdout
    python3 eval/run.py --json               # machine-readable metrics
    python3 eval/run.py --json -o eval/metrics.json
    python3 eval/run.py --corpus adversarial --config deterministic-only
    python3 eval/run.py --json --external    # also measure the fetched public corpora

``--external`` adds the corpora ``eval/fetch.py`` downloaded under the licence gate.
Those numbers are **not** the committed ones and are not comparable to them: an
external row is plain text wrapped in a synthesized ``.eml``, so the authentication
layer the committed corpora mostly turn on cannot fire, and the deferral rate that
produces is a property of the wrapper rather than of real mail. See
``eval/external.py`` and ``docs/EVAL-SUITES.md``.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
from typing import Any

REPO = pathlib.Path(__file__).resolve().parents[1]
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))
# Loaded by path rather than by name so this module works both as a script and
# when imported by the test suite, where `eval` is not on sys.path and is not an
# importable package name anyway.
sys.path.insert(0, str(HERE))

from tenable_email.config import Config  # noqa: E402
from tenable_email.evidence import Provenance  # noqa: E402
from tenable_email.pipeline import triage_file  # noqa: E402
from tenable_email.verdict import Disposition  # noqa: E402

from report import render_markdown  # noqa: E402  (sibling module, see sys.path above)
from selective import (  # noqa: E402
    ACCUSATIONS,
    DEFERRALS,
    HOSTILE_LABELS,
    selective_report,
)
import external as external_corpora  # noqa: E402  (sibling module; leaf - it must not
# import this file, or the measurement would depend on its own caller)

#: What a deferral is, which dispositions accuse, and which labels mean a message must
#: not be cleared are all owned by ``selective.py`` and imported here rather than
#: restated. They were defined in both modules for one session and had already drifted:
#: this file said hostile labels were {threat, spam} while the selective metrics also
#: knew about {hostile, phishing, malicious}, which is why the adversarial corpus -
#: whose cases are all labelled ``hostile`` - briefly measured as entirely undecidable.
#: One owner, so the two cannot disagree again.

#: Labels that mean the message must not be cleared. See ``selective.HOSTILE_LABELS``:
#: "hostile" overstates one of them, since the synthetic corpus labels a legitimate
#: marketing message `spam` that somebody over-reported. It counts not because it is an
#: attack but because clearing it silently is the same class of error - a message that
#: should have been looked at was closed without a person.


def _git(*args: str) -> str:
    """Run git, or return a string that says it could not be determined.

    Returning "" on failure recorded `commit: ""` and `dirty: false`, which
    renders as "clean tree, no commit" rather than as "git did not answer". An
    unknown stated as a negative is the failure mode this project's evidence rules
    exist to prevent, so the sentinel is explicit and visible in the artifact.
    """
    try:
        completed = subprocess.run(
            ["git", *args], cwd=REPO, capture_output=True, text=True, timeout=15,
        )
    except Exception:
        return "UNDETERMINED"
    if completed.returncode != 0:
        return "UNDETERMINED"
    return completed.stdout.strip()


def configurations() -> dict[str, Config]:
    replay_dir = REPO / "fixtures" / "replay"
    return {
        "deterministic-only": Config(replay=True, replay_dir=None),
        "corpus-backed": Config(
            replay=True,
            replay_dir=str(replay_dir) if replay_dir.is_dir() else None,
        ),
    }


def corpora() -> dict[str, dict[str, Any]]:
    """The labelled corpora, with their ground truth read from the manifest.

    Labels come from ``labels.json`` beside the messages and never from the file
    name, so the measurement cannot flatter itself by renaming a fixture.
    """
    out: dict[str, dict[str, Any]] = {}

    synthetic = REPO / "fixtures" / "synthetic"
    manifest = synthetic / "labels.json"
    if manifest.is_file():
        out["synthetic"] = {
            "directory": synthetic,
            "kind": "labelled",
            "entries": [
                {
                    "case": e["case"],
                    "path": synthetic / e["file"],
                    "label": e["label"],
                }
                for e in json.loads(manifest.read_text(encoding="utf-8"))
            ],
        }

    adversarial = REPO / "fixtures" / "adversarial"
    manifest = adversarial / "labels.json"
    if manifest.is_file():
        out["adversarial"] = {
            "directory": adversarial,
            # Every case here is hostile by construction. The manifest carries a
            # status rather than a label because what varies is whether the
            # pipeline currently catches it, not what the message is.
            "kind": "hostile",
            "entries": [
                {
                    "case": e["case"],
                    "path": adversarial / e["file"],
                    "label": "hostile",
                    "status": e["status"],
                }
                for e in json.loads(manifest.read_text(encoding="utf-8"))
            ],
        }

    return out


def measure_corpus(entries: list[dict], kind: str, config: Config) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for entry in entries:
        verdict = triage_file(entry["path"], config)
        model_judgments = [
            f.key for f in verdict.evidence
            if f.provenance is Provenance.MODEL_JUDGMENT
        ]
        rows.append({
            "case": entry["case"],
            "label": entry["label"],
            "status": entry.get("status"),
            "disposition": verdict.disposition.value,
            "confidence": round(float(verdict.confidence), 4),
            "confidence_band": verdict.confidence_band.value,
            "attack_type": verdict.attack_type.value,
            "escalated": bool(verdict.escalated),
            "truncated": bool(verdict.truncated),
            "model_judgments": model_judgments,
            "stages_run": list(verdict.stages_run),
        })

    total = len(rows)
    by_disposition: dict[str, int] = {}
    for row in rows:
        by_disposition[row["disposition"]] = (
            by_disposition.get(row["disposition"], 0) + 1
        )

    def rate(numerator: int) -> float | None:
        return round(numerator / total, 4) if total else None

    cleared = [r for r in rows if r["disposition"] == Disposition.CLEAN.value]
    deferred = [r for r in rows if r["disposition"] in DEFERRALS]
    accused = [r for r in rows if r["disposition"] in ACCUSATIONS]
    model_assisted = [r for r in rows if r["model_judgments"]]

    metrics: dict[str, Any] = {
        "kind": kind,
        "messages": total,
        "by_disposition": dict(sorted(by_disposition.items())),
        "auto_clearance_rate": rate(len(cleared)),
        "escalation_rate": rate(len(deferred)),
        "accusation_rate": rate(len(accused)),
        #: The pitch metric, and the one that must never be reported without the
        #: false-negative rate beside it.
        "no_model_call_rate": rate(total - len(model_assisted)),
        "model_assisted": len(model_assisted),
    }

    if kind == "hostile":
        # For a corpus where every message is hostile, the only number that
        # matters is how many were cleared. Status is carried so a case that is
        # open by declaration cannot hide inside an aggregate.
        metrics["hostile_cleared"] = [r["case"] for r in cleared]
        metrics["hostile_cleared_count"] = len(cleared)
        metrics["hostile_deferred"] = len(deferred)
        metrics["hostile_accused"] = len(accused)
        metrics["declared_open"] = [
            r["case"] for r in rows if r.get("status") == "open"
        ]
        metrics["cleared_while_declared_closed"] = [
            r["case"] for r in cleared if r.get("status") == "closed"
        ]
    else:
        agreement = {"agree": 0, "escalated": 0, "disagree": 0, "unlabelled": 0}
        false_negatives: list[dict[str, str]] = []
        false_accusations: list[dict[str, str]] = []
        for row in rows:
            label, got = row["label"], row["disposition"]
            if not label:
                agreement["unlabelled"] += 1
            elif got == label:
                agreement["agree"] += 1
            elif got in DEFERRALS:
                # A deferral is counted separately whatever the label: it is a
                # coverage cost, not a wrong answer, and lumping it with
                # disagreement both understates the tool and hides real misses.
                agreement["escalated"] += 1
            else:
                agreement["disagree"] += 1
            if label in HOSTILE_LABELS and got == Disposition.CLEAN.value:
                false_negatives.append({"case": row["case"], "label": label})
            if label == "clean" and got in ACCUSATIONS:
                false_accusations.append({"case": row["case"], "got": got})

        hostile = [r for r in rows if r["label"] in HOSTILE_LABELS]
        benign = [r for r in rows if r["label"] == "clean"]
        metrics["label_agreement"] = agreement
        metrics["false_negatives"] = false_negatives
        metrics["false_negative_count"] = len(false_negatives)
        #: The number the review asked for by name: of the messages this
        #: configuration closed without a human, how many were hostile. A
        #: clearance rate without this is not a measurement.
        metrics["false_negative_rate_among_auto_closed"] = (
            round(len(false_negatives) / len(cleared), 4) if cleared else None
        )
        metrics["false_accusations"] = false_accusations
        metrics["false_accusation_count"] = len(false_accusations)
        metrics["false_accusation_rate_among_benign"] = (
            round(len(false_accusations) / len(benign), 4) if benign else None
        )
        metrics["hostile_messages"] = len(hostile)
        metrics["benign_messages"] = len(benign)
        hostile_cleared = [
            r for r in hostile if r["disposition"] == Disposition.CLEAN.value
        ]
        metrics["hostile_auto_cleared"] = len(hostile_cleared)
        metrics["hostile_auto_clear_rate"] = (
            round(len(hostile_cleared) / len(hostile), 4) if hostile else None
        )

    metrics["rows"] = rows

    #: Selective-prediction view of the same rows: coverage, risk among the automated
    #: subset, the risk-coverage curve, AURC and E-AURC, coverage at fixed risk budgets,
    #: and the composition of the deferred slice. Reported with ``calibrated: false``
    #: because the confidence values are policy labels, not probabilities - selective
    #: prediction needs only a ranking, but every operating point below inherits that
    #: caveat and the renderer is not allowed to drop it.
    metrics["selective"] = selective_report(rows)
    return metrics


def model_tier_rollup(results: dict[str, Any]) -> dict[str, Any]:
    """How many external messages a model judgment touched, per configuration.

    This exists because a disposition table without it invites the reader to assume the
    tiers took part. The committed recordings are keyed by content address, so an
    external message - text never sent to an endpoint - has no recording, the tiers
    abstain, and `corpus-backed` measures the same deterministic layer as
    `deterministic-only`. That is stated as a number (0 of N) and as a sentence, because
    the number alone reads like a result about models.
    """
    per_configuration: dict[str, Any] = {}
    for config_name, per_corpus in results.items():
        messages = sum(m["messages"] for m in per_corpus.values())
        assisted = sum(m["model_assisted"] for m in per_corpus.values())
        per_configuration[config_name] = {
            "messages": messages,
            "model_assisted": assisted,
            "model_assisted_rate": (
                round(assisted / messages, 4) if messages else None
            ),
        }
    return {
        "per_configuration": per_configuration,
        "has_run": any(
            value["model_assisted"] for value in per_configuration.values()
        ),
        "statement": external_corpora.MODEL_TIER_STATEMENT,
    }


def per_dataset_rollup(corpora: dict[str, Any], results: dict[str, Any]
                       ) -> dict[str, Any]:
    """Sums of counts the corpora already carry, grouped by dataset.

    Nothing is re-measured here: every term is a published count from a corpus
    descriptor or a metrics block, and the only arithmetic is addition and a rate over
    the summed numerator and denominator. It exists because a decision was made to
    describe one pinned file as one corpus - NotInject ships three files, deepset two -
    and the figure a reader needs is the 339-row and 662-row view, with its denominator,
    on one line. The per-corpus blocks stay in the artifact beside it.

    The hostile and clean denominators are kept apart on purpose: "263 injection-labelled
    rows, 3 flagged" and "399 not-injection-labelled rows, 0 flagged" are two measurements
    with two denominators, and summing them into one flag rate over 662 rows would be the
    exact mixing of tasks `docs/EVAL-SUITES.md` forbids.
    """
    out: dict[str, Any] = {}
    for name, corpus in sorted(corpora.items()):
        descriptor = corpus["descriptor"]
        dataset_id = descriptor["dataset"]
        block = out.setdefault(dataset_id, {
            "dataset": dataset_id,
            "slug": descriptor.get("slug"),
            "license_observed": descriptor.get("license_observed"),
            "corpora": [],
            "text_surface": {
                "rows": 0, "rows_flagged": 0,
                "hostile_rows": 0, "hostile_rows_flagged": 0,
                "clean_rows": 0, "clean_rows_flagged": 0,
            },
            "configurations": {},
            "measurement_limits": list(descriptor.get("measurement_limits") or []),
        })
        surface = descriptor.get("text_surface") or {}
        rows = int(surface.get("rows") or 0)
        flagged = int(surface.get("injection_indicator_rows") or 0)
        hostile = descriptor["label"] in HOSTILE_LABELS
        side = "hostile" if hostile else "clean"
        totals = block["text_surface"]
        totals["rows"] += rows
        totals["rows_flagged"] += flagged
        totals[f"{side}_rows"] += rows
        totals[f"{side}_rows_flagged"] += flagged
        block["corpora"].append({
            "corpus": name,
            "label": descriptor["label"],
            "split": descriptor.get("split"),
            "file": descriptor.get("file"),
            "rows": rows,
            "rows_flagged": flagged,
            "rows_flagged_rate": surface.get("injection_indicator_rate"),
        })
        for config_name, per_corpus in results.items():
            metrics = per_corpus.get(name)
            if metrics is None:
                continue
            cfg = block["configurations"].setdefault(config_name, {
                "messages": 0, "cleared": 0, "deferred": 0, "accused": 0,
                "model_assisted": 0,
            })
            #: Taken from each corpus's own ``by_disposition`` counts rather than by
            #: re-reading its rows: the distribution is the published number, and this
            #: is a sum of published numbers, not a second measurement.
            by_disposition = metrics["by_disposition"]
            cfg["messages"] += metrics["messages"]
            cfg["cleared"] += by_disposition.get(Disposition.CLEAN.value, 0)
            cfg["accused"] += sum(by_disposition.get(d, 0) for d in ACCUSATIONS)
            cfg["deferred"] += sum(by_disposition.get(d, 0) for d in DEFERRALS)
            cfg["model_assisted"] += metrics["model_assisted"]

    for block in out.values():
        totals = block["text_surface"]
        for side in ("hostile", "clean"):
            rows = totals[f"{side}_rows"]
            totals[f"{side}_rows_flagged_rate"] = (
                round(totals[f"{side}_rows_flagged"] / rows, 4) if rows else None
            )
        totals["rows_flagged_rate"] = (
            round(totals["rows_flagged"] / totals["rows"], 4) if totals["rows"] else None
        )
        for cfg in block["configurations"].values():
            messages = cfg["messages"]
            cfg["auto_clearance_rate"] = (
                round(cfg["cleared"] / messages, 4) if messages else None
            )
            cfg["accusation_rate"] = (
                round(cfg["accused"] / messages, 4) if messages else None
            )
            cfg["escalation_rate"] = (
                round(cfg["deferred"] / messages, 4) if messages else None
            )
    return out


def measure_external(
    config_names: list[str],
    *,
    plan: dict[str, Any] | None = None,
    max_messages: int | None = None,
) -> dict[str, Any]:
    """Measure every evaluable fetched corpus with ``measure_corpus``, unchanged.

    There is no second metrics implementation here on purpose. ``external.build_plan``
    produces entries in the same shape ``corpora()`` produces - ``case``, ``path``,
    ``label``, ``status`` - and this function hands them to the same code that measures
    the committed corpora, so a false-positive rate means one thing across both.

    The corpus descriptor - licence, revision, digest, sample spec and the
    synthesized-envelope limitation - is attached to each metrics block as
    ``external``, which is what lets ``eval/report.py`` print the provenance beside the
    numbers instead of in a separate document nobody reads.
    """
    if plan is None:
        kwargs: dict[str, Any] = {}
        if max_messages is not None:
            kwargs["max_messages"] = max_messages
        plan = external_corpora.build_plan(**kwargs)
    plan = dict(plan)
    corpora = plan.pop("_corpora", {})
    plan["configurations"] = list(config_names)

    results: dict[str, Any] = {}
    for config_name in config_names:
        config = configurations()[config_name]
        results[config_name] = {}
        for corpus_name, corpus in sorted(corpora.items()):
            metrics = measure_corpus(corpus["entries"], corpus["kind"], config)
            metrics["external"] = corpus["descriptor"]
            results[config_name][corpus_name] = metrics
    plan["results"] = results
    #: Two views the per-corpus blocks cannot give on their own, both computed from
    #: counts the corpora already publish: the model-tier position of the whole external
    #: run, and the per-dataset totals whose denominators the decisions are taken on.
    plan["model_tier"] = model_tier_rollup(results)
    plan["per_dataset"] = per_dataset_rollup(corpora, results)
    return plan


def measure(
    corpus_names: list[str] | None = None,
    config_names: list[str] | None = None,
    *,
    external: bool = False,
    external_max_messages: int | None = None,
) -> dict[str, Any]:
    available_corpora = corpora()
    available_configs = configurations()
    selected_corpora = corpus_names or list(available_corpora)
    selected_configs = config_names or list(available_configs)

    unknown = [c for c in selected_corpora if c not in available_corpora]
    if unknown:
        raise SystemExit(
            f"unknown corpus/corpora: {', '.join(unknown)}. "
            f"Available: {', '.join(available_corpora)}"
        )
    unknown = [c for c in selected_configs if c not in available_configs]
    if unknown:
        raise SystemExit(
            f"unknown configuration(s): {', '.join(unknown)}. "
            f"Available: {', '.join(available_configs)}"
        )

    results: dict[str, Any] = {}
    for config_name in selected_configs:
        config = available_configs[config_name]
        results[config_name] = {}
        for corpus_name in selected_corpora:
            corpus = available_corpora[corpus_name]
            results[config_name][corpus_name] = measure_corpus(
                corpus["entries"], corpus["kind"], config
            )

    payload = {
        "schema_version": 1,
        "commit": _git("rev-parse", "HEAD"),
        "commit_short": _git("rev-parse", "--short", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        # "UNDETERMINED" is truthy, so a git failure records the tree as dirty
        # rather than clean. Failing towards "might be dirty" is the safe
        # direction for an artifact that claims to describe a specific commit.
        "dirty": bool(_git("status", "--porcelain")),
        "corpora": selected_corpora,
        "configurations": selected_configs,
        "note": (
            "Measured on synthetic and adversarial fixtures committed to this "
            "repository, offline, with no credentials and no network. These are "
            "not accuracy estimates for real mail: the corpora are small, "
            "constructed, and the adversarial one is hostile by design. What they "
            "establish is which dispositions the pipeline reaches and what it "
            "costs to reach them, reproducibly."
        ),
        "results": results,
    }
    if external:
        #: A separate top-level block, deliberately not merged into ``results``.
        #: The corpora in it are fetched under a licence gate, wrapped in a
        #: synthesized envelope, and have different denominators from the committed
        #: ones. The TODO's instruction - "do not mix spam, phishing and prompt
        #: injection into one headline metric" - is honoured by keeping the blocks
        #: beside each other and letting the renderer say which is which.
        payload["external"] = measure_external(
            selected_configs, max_messages=external_max_messages
        )
    return payload


#: Top-level payload fields that describe **the run which wrote the file** rather than a
#: measurement, so they are never carried forward: a stale ``commit`` or ``dirty`` would
#: make the artifact claim to describe a revision it was not measured at, which is the
#: one thing those fields exist to prevent. If a future run stops emitting one of them,
#: the writer says so instead of quietly inheriting the previous value.
RUN_LOCAL_FIELDS = frozenset(
    {"schema_version", "commit", "commit_short", "branch", "dirty"}
)

#: The only two fields :func:`carry_forward` ever adds to a block it carries. Nothing
#: else in the block is touched, so a reader can diff a carried block against the one it
#: came from and find exactly these and nothing more.
CARRY_FIELDS = ("reproduced_here", "carried_forward")

#: Why a block can be absent from a run, in the words that go into the artifact. A block
#: not listed here is still carried and still marked; the table exists so the common case
#: says something a reader can act on rather than something merely true.
BLOCK_NOTES: dict[str, dict[str, str]] = {
    "external": {
        "asked_for_by": "--external",
        "reason": (
            "measuring the external corpora needs the public data eval/fetch.py "
            "downloaded under the licence gate, which lives in eval/internal/ and is "
            "gitignored by policy, so it is absent on a fresh clone, in a review bundle "
            "and in a public export - and this invocation did not pass --external in "
            "any case"
        ),
        "regenerate_with": (
            "python3 eval/run.py --json --external -o eval/metrics.json"
        ),
    },
}

DEFAULT_BLOCK_NOTE = {
    "asked_for_by": "(this block has no entry in BLOCK_NOTES)",
    "reason": "this invocation did not produce this block",
    "regenerate_with": (
        "re-run the measurement this block describes; `python3 eval/run.py --help` "
        "lists what this harness can measure"
    ),
}


def _display_path(destination: pathlib.Path) -> str:
    """How ``destination`` is named inside a committed artifact.

    Repository-relative where possible. An absolute path outside the repository is not
    published into a tracked file: this artifact is read by people on other machines, and
    a working-tree path is both meaningless to them and host-identifying, which
    ``tests/test_eval.py::test_the_committed_metrics_leak_no_host_identity`` forbids.
    """
    try:
        return destination.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return f"<{destination.name}, outside this repository>"


def read_previous_artifact(destination: pathlib.Path) -> dict[str, Any] | None:
    """The artifact about to be overwritten, parsed, or ``None`` if there is nothing to read.

    A file that exists but is not a JSON object is *not* read as "no previous artifact".
    That reading is how a truncated or hand-mangled file would authorise the loss of
    whatever it held: the writer would see nothing to carry and drop it in silence. It
    raises instead, and names the way out.
    """
    if not destination.is_file():
        return None
    try:
        raw = destination.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(
            f"refusing to overwrite {_display_path(destination)}: it could not be read "
            f"({exc}), so nothing in it can be carried forward. Write to another path, "
            f"or pass --discard-stale-blocks to say out loud that it is being thrown "
            f"away."
        )
    try:
        previous = json.loads(raw)
    except ValueError as exc:
        raise SystemExit(
            f"refusing to overwrite {_display_path(destination)}: it is not valid JSON "
            f"({exc}), so any measurement in it would be dropped blind. Fix or remove "
            f"the file, or pass --discard-stale-blocks."
        )
    if not isinstance(previous, dict):
        raise SystemExit(
            f"refusing to overwrite {_display_path(destination)}: it holds "
            f"{type(previous).__name__}, not a metrics object."
        )
    return previous


def _carry_note(key: str, previous: dict[str, Any],
                destination: pathlib.Path) -> dict[str, Any]:
    hint = BLOCK_NOTES.get(key, DEFAULT_BLOCK_NOTE)
    return {
        "statement": (
            f"The `{key}` block of this artifact was not produced by the run that wrote "
            "this file. It is the block that was already in this file, carried forward "
            "because a run that was not asked to make this measurement does not get to "
            "delete it."
        ),
        "carried_from": {
            "path": _display_path(destination),
            "commit": previous.get("commit"),
            "commit_short": previous.get("commit_short"),
            "branch": previous.get("branch"),
        },
        "why": hint["reason"],
        "asked_for_by": hint["asked_for_by"],
        "regenerate_with": hint["regenerate_with"],
    }


def carry_forward(
    payload: dict[str, Any],
    destination: pathlib.Path,
    *,
    discard: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    """Carry forward every top-level block ``payload`` drops but the artifact has.

    Returns ``(payload to write, lines the caller must print)``. The rule is stated once
    and applies to every top-level key, so it covers whatever the payload grows into:

    * a key the previous artifact had, this run did not produce, and that describes a
      measurement - carried forward, marked ``reproduced_here: false`` plus a
      ``carried_forward`` note, and otherwise untouched;
    * a key that describes this run (``commit``, ``dirty``, ...) - never carried, and
      the removal is stated;
    * ``discard=True`` (``--discard-stale-blocks``) - removed, and the removal is stated.

    Marking a block as carried is what keeps this from becoming a way to keep stale data
    looking fresh; asking for the measurement is what keeps it from becoming a way to
    keep stale data at all, because a run that produced its own ``external`` block simply
    wins and the markers do not come with it.
    """
    previous = read_previous_artifact(destination)
    if previous is None:
        return payload, []

    statements: list[str] = []
    shown = _display_path(destination)
    for key, block in previous.items():
        if key in payload:
            continue
        if key in RUN_LOCAL_FIELDS:
            statements.append(
                f"  {shown}: `{key}` names the run that wrote this file, so the previous "
                f"value is not carried forward"
            )
            continue
        if discard:
            statements.append(
                f"  {shown}: DROPPED the previous `{key}` block, because "
                f"--discard-stale-blocks was given and this run did not produce it. "
                f"That is a stated removal, not an accident."
            )
            continue
        if not isinstance(block, dict):
            raise SystemExit(
                f"refusing to overwrite {shown}: the previous artifact's `{key}` block "
                f"is {type(block).__name__}, not an object, so it cannot be marked as "
                f"carried forward - and dropping it silently is not an option. "
                f"Re-measure it, or pass --discard-stale-blocks to remove it on record."
            )
        if block.get("reproduced_here") is False and isinstance(
                block.get("carried_forward"), dict):
            # Already a carried block: restate it verbatim rather than rewriting its
            # note to point at itself, so the note keeps naming the measurement that
            # made it and a second run over the same file is byte-identical to the first.
            payload[key] = block
            statements.append(
                f"  {shown}: carried the `{key}` block forward again; it was already "
                f"carried, and this run did not produce it either"
            )
            continue
        marked = dict(block)          # shallow: no field inside it is touched
        marked["reproduced_here"] = False
        marked["carried_forward"] = _carry_note(key, previous, destination)
        payload[key] = marked
        statements.append(
            f"  {shown}: carried forward the previous `{key}` block "
            f"({len(block)} fields) marked reproduced_here: false; this run did not "
            f"produce it, and a run that was not asked to measure something does not "
            f"get to delete it"
        )
    return payload, statements


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    # Markdown is the default, so there is no `--markdown`: the format has to be
    # asked for only when it is not the default one.
    parser.add_argument(
        "--json", action="store_true",
        help="emit metrics as JSON instead of the default Markdown report",
    )
    parser.add_argument(
        "-o", "--output", type=pathlib.Path,
        help="write to this file instead of stdout",
    )
    parser.add_argument(
        "--corpus", action="append",
        help="restrict to this corpus (repeatable); default is all",
    )
    parser.add_argument(
        "--config", action="append",
        help="restrict to this configuration (repeatable); default is all",
    )
    parser.add_argument(
        "--no-rows", action="store_true",
        help="omit per-message rows from JSON output",
    )
    parser.add_argument(
        "--external", action="store_true",
        help="also measure the public corpora eval/fetch.py has downloaded under the "
             "licence gate, including the JSON rows `--rows` cached for the "
             "Parquet-only ones. Their numbers carry a licence, a revision, which of "
             "the two objects the text came from, and the synthesized-envelope "
             "limitation, and are reported in their own block",
    )
    parser.add_argument(
        "--external-max-messages", type=int, default=None,
        help="sampling cap for external corpora (default: eval/external.py's "
             "DEFAULT_MAX_MESSAGES). Recorded in the artifact either way",
    )
    parser.add_argument(
        "--discard-stale-blocks", action="store_true",
        help="allow this run to drop a top-level block the artifact already carried and "
             "this run did not produce. Without it such a block is carried forward and "
             "marked reproduced_here: false; with it the removal is stated on stdout. "
             "Either way it is never silent, which is the point: dropping the committed "
             "external block was what this rule exists to stop",
    )
    args = parser.parse_args(argv)

    payload = measure(args.corpus, args.config, external=args.external,
                      external_max_messages=args.external_max_messages)
    if args.no_rows:
        #: Applied before the carry, so a block that is carried forward keeps every field
        #: it had - including its rows. `--no-rows` is about the size of what *this run
        #: measured*; silently thinning somebody else's committed measurement would be a
        #: second way to destroy evidence while appearing to preserve it.
        for per_corpus in payload["results"].values():
            for metrics in per_corpus.values():
                metrics.pop("rows", None)
        for per_corpus in (payload.get("external") or {}).get("results", {}).values():
            for metrics in per_corpus.values():
                metrics.pop("rows", None)

    if args.output:
        payload, statements = carry_forward(
            payload, args.output, discard=args.discard_stale_blocks
        )
        for line in statements:
            print(line)

    if args.json:
        text = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    else:
        text = render_markdown(payload)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
