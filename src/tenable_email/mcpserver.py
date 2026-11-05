"""The MCP surface: read-only tools over the same core the CLI runs.

SWARM Black Hat 2026 2nd place was an MCP server: python, ``transport:
stdio``, a FastMCP wrapper, and -- in its own words -- a process that "sits in
the background and waits for an external AI to ask", executing the tools
locally and handing the data back. That is the shape this module implements,
for a reason deeper than imitation. An investigating agent already knows how to
ask questions; what it cannot do is run header forensics on a host it does not
control, or read a replay corpus it does not have. So the external model
orchestrates and this server holds the typed, deterministic tools.

Three rules hold the module together.

1. **The tool logic is plain Python; the MCP layer is a thin wrapper above it.**
   Only :func:`_fastmcp_class` and :func:`build_server` touch the ``mcp``
   package, and nothing at module scope imports it. ``dependencies = []`` in
   ``pyproject.toml`` therefore stays empty, ``mcp`` stays an optional extra,
   and every function here is importable and unit-tested on a machine that
   never installed it. A reviewer who runs ``pip install -e . --no-deps`` gets
   the same green suite -- which is what the zero-dependency claim in README
   actually asserts.
2. **No tool mutates anything.** Nothing in this module writes a file, opens a
   socket, spawns a process, or spends a credential. Two mechanisms, not one
   intention: every tool runs under :func:`tool_config`, which forces
   ``replay=True`` (a tier in replay mode reads the committed corpus and never
   reaches the network, and the store's write path is only reachable after a
   live call), and no tool constructs an
   :class:`~tenable_email.runner.OfflineRunner` with a ``root``. Where a caller
   would need a write -- a durable case record, a mail label, an analyst
   notification -- the response carries the *proposed* actions from
   :mod:`~tenable_email.writeback` plus the command that would actually run
   the gated stage. ``disposition-writeback`` is the contract's only
   ``access: write`` stage and it requires human approval;
   an MCP client is not a human, and the server does not pretend to be one.
3. **Nothing leaves here that a receipt would not carry.** The evidence record
   holds values that quote the message body -- extracted link anchor text,
   injection pattern matches, a forwarded message's inner headers, and every
   model's prose about the content, including a vision model's verbatim
   transcription of an image. Those are the payload, and this is an
   agent-facing surface: it returns a digest and the explanatory detail for
   them (:data:`WITHHELD_VALUE_NOTE` names the reason), inlines values only for
   the keys in :data:`CARRIABLE_VALUE_KEYS`, and never a body or an attachment
   byte. ``tests/test_mcp_tools.py`` asserts that against every fixture rather
   than trusting this paragraph.

Errors cross the boundary as values. A tool that raised would surface to a
client as a transport failure with the traceback stripped, which is how an
agent learns "the server is broken" when the truth is "that file is not there".
Every response is therefore the same envelope: ``ok``, ``tool``, ``error``, and
the payload merged alongside them.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

from .cli import classify_agreement, label_rows
from .config import Config, ModelEndpoints, default_replay_dir
from .contract import (
    Contract,
    ContractError,
    contract_summary,
    load_contract,
)
from .evidence import Evidence, Finding, Provenance
from .parse import (
    Message,
    parse_file,
    scan_eml_dir,
)
from .pipeline import (
    ALL_STAGES_IN_ORDER,
    MODEL_TIERS,
    STAGE_ATTACHMENTS,
    STAGE_WRITEBACK,
    build_evidence,
    consult_tiers,
    derive_facts,
    triage_file,
)
from .receipt import EvidenceItem, Receipt, ReceiptError
from .replay import ReplayStore, open_store
from .signals import (
    assess_alignment,
    classify_link_destinations,
    detect_lookalike_domain,
    extract_auth_results,
    extract_links,
    extract_signals,
    parse_address,
    registrable_domain,
    second_level_label,
)
from .tiers import (
    MAX_URL_LOOKUPS_PER_MESSAGE,
    Judgment,
    TierResult,
    UrlReputationTier,
    consult,
    read_judgment,
)
from .verdict import Verdict
from .writeback import proposed_actions

__all__ = [
    "CARRIABLE_VALUE_KEYS",
    "INSTALL_HINT",
    "MCP_WRAPPERS",
    "SERVER_INSTRUCTIONS",
    "SERVER_NAME",
    "TOOL_ARGUMENTS",
    "TOOL_DESCRIPTIONS",
    "TOOL_ORDER",
    "McpUnavailable",
    "ToolError",
    "analyze_eml",
    "analyze_eml_directory",
    "analyze_urls",
    "build_arg_parser",
    "build_server",
    "check_auth",
    "classify_local",
    "explain_verdict",
    "get_case_record",
    "list_contracts",
    "lookalike_domain",
    "main",
    "registered_tool_names",
    "tool_config",
    "tools_payload",
]

#: The server name a client sees in its tool list.
SERVER_NAME = "tenable-email"

#: The nine tools the server exposes, in registration order. This is the list
#: ``docs/listing-drafts/mcp-server.md`` promises to the Exchange, and
#: ``tests/test_mcp_tools.py`` compares the two: a listing that advertises a
#: tool the server does not ship is a reviewer finding, and so is the reverse.
TOOL_ORDER: tuple[str, ...] = (
    "analyze_eml",
    "analyze_eml_directory",
    "explain_verdict",
    "check_auth",
    "lookalike_domain",
    "analyze_urls",
    "classify_local",
    "list_contracts",
    "get_case_record",
)

TOOL_DESCRIPTIONS: dict[str, str] = {
    "analyze_eml": (
        "Full staged triage of one .eml file: disposition, confidence float and "
        "band, attack class, reasons, analysis narrative, the stages that ran, "
        "and the evidence grouped by provenance. Read-only; returns no message "
        "body and no attachment bytes."
    ),
    "analyze_eml_directory": (
        "Read-only batch triage over a directory of .eml files, offline: one "
        "line per message, counts per disposition, and label agreement when a "
        "labels.json manifest sits beside the corpus. The walk is bounded by "
        "file count and depth, never leaves the directory through a symlink, "
        "and refuses a corpus too large to read completely rather than "
        "returning a partial answer as a whole one; the answer says what was "
        "scanned. Writes nothing."
    ),
    "explain_verdict": (
        "The provenance-grouped evidence behind a saved case record: verified "
        "facts, model judgments, and gaps -- with unknowns and unavailable tiers "
        "labelled as gaps rather than as findings of absence."
    ),
    "check_auth": (
        "SPF, DKIM and DMARC outcomes as the receiving MTA recorded them, "
        "alignment against the sender domain, and the raw header values "
        "truncated. Verified facts only: passing authentication does not "
        "establish legitimacy."
    ),
    "lookalike_domain": (
        "Deterministic lookalike analysis of any domain against the configured "
        "org profile: edit distance to a protected or vendor label, modifier "
        "tokens, and whether the domain is owned or trusted outright."
    ),
    "analyze_urls": (
        "Deterministic link analysis for arbitrary URLs: redirect unwrapping "
        "with the resolved destination, anchor-versus-href mismatch, IP-literal "
        "hosts, sender/trusted/neither classification, and the URL reputation "
        "tier where a configured endpoint or a committed recording answers."
    ),
    "classify_local": (
        "The model-tier judgments for one message, each with its own stance, "
        "score, source and error, and no merged number: disagreement between "
        "tiers is the escalation signal and this surface keeps it visible."
    ),
    "list_contracts": (
        "The stages.yaml chain as data: stage id, title, capability, provider, "
        "access, optionality, model tier and approval requirement, so a calling "
        "agent can learn the shape of the pipeline before asking it to run."
    ),
    "get_case_record": (
        "One durable case record as JSON plus its Markdown rendering, with its "
        "digests, stage history and closure blockers. Read-only."
    ),
}

#: ``(argument name -> type label)`` per tool, as advertised to clients. The
#: tests compare it against the real signature of each wrapper and of each tool
#: function, which is what keeps the schema honest without ``mcp`` installed.
TOOL_ARGUMENTS: dict[str, dict[str, str]] = {
    "analyze_eml": {"path": "str"},
    "analyze_eml_directory": {"path": "str"},
    "explain_verdict": {"reference": "str", "case_dir": "str | None"},
    "check_auth": {"path": "str"},
    "lookalike_domain": {"domain": "str"},
    "analyze_urls": {"urls": "list", "sender_domain": "str | None"},
    "classify_local": {"path": "str"},
    "list_contracts": {},
    "get_case_record": {"reference": "str", "case_dir": "str | None"},
}

#: The only place a missing ``mcp`` extra is explained, so the CLI message, the
#: exception and the README all carry the same instruction.
INSTALL_HINT = (
    "The MCP server needs the `mcp` package, which this project ships as an "
    "optional extra so the core stays dependency-free. Install it with:\n"
    "\n"
    "    pip install -e .[mcp]\n"
    "\n"
    "or, from an installed distribution: pip install 'tenable-email[mcp]'.\n"
    "Nothing else in this package needs it: the deterministic stages, the "
    "replay corpus, the CLI and every tool function in "
    "src/tenable_email/mcpserver.py run with no third-party dependency at all."
)

#: What the calling agent is told about how to use the surface: the compressed
#: form of SKILL.md, because an agent may never open the file.
SERVER_INSTRUCTIONS = (
    "Local-first phishing triage. Nine read-only tools over a staged chain: "
    "deterministic header, authentication and link forensics, then optional "
    "model tiers answered from committed recordings when no endpoint is "
    "configured.\n"
    "\n"
    "How to use the results:\n"
    "\n"
    "* Provenance is the payload, not decoration. `verified` findings are "
    "reproducible observations of the message; `model_judgment` findings are "
    "opinions with a score; `unknown` means not knowable from a message; "
    "`unavailable` means the tier that could have answered did not run. "
    "UNAVAILABLE is not UNKNOWN, and neither is evidence of absence.\n"
    "* `manual_review` is an outcome, not a failure. Do not re-ask this server "
    "hoping for a different disposition: the escalation is the finding. Route "
    "it to a human with the reasons attached.\n"
    "* When the tiers disagree, that is the signal. `classify_local` gives you "
    "each vote separately. Averaging them produces a number that neither a fact "
    "nor an opinion supports.\n"
    "* Authentication passing never establishes legitimacy. Valid DKIM plus a "
    "payment request and no links is the business-email-compromise shape, and "
    "it routes to a person.\n"
    "* `truncated: true` means a partial reading. Report it as partial.\n"
    "* A directory answer carries `scan`: the root, how many files it found, and "
    "whether a bound was hit. A directory that cannot be read completely -- more "
    "files than the bound, or nested deeper than it -- is refused rather than "
    "answered in part, and no walk leaves the directory it was given through a "
    "symlink. Narrow the path; do not retry the same one.\n"
    "* No tool here writes anything. Anything outward is returned as a proposed "
    "action requiring human approval; run the CLI to produce case records.\n"
)

#: Evidence keys whose values are technical facts and may be returned inline.
#: Every key not listed here comes back as a digest with
#: :data:`WITHHELD_VALUE_NOTE`, because its value quotes message content.
CARRIABLE_VALUE_KEYS = frozenset(
    {
        "intake", "sender", "reply_to", "return_path", "recipients", "subject",
        "date", "message_id", "auth", "alignment", "lookalike",
        "display_name_spoofing", "reply_to_mismatch", "links", "attachments",
        "bulk", "boilerplate_removed", "truncated", "body_chars",
        "original_body_length", "inline_image_count", "attachment_count",
        "injection_indicator_count",
    }
)

WITHHELD_VALUE_NOTE = (
    "value withheld from this surface: it quotes message-body text or model "
    "prose about the content. The value digest is present, so the finding stays "
    "citable without the message travelling with it."
)

GAP_NOTE = (
    "a gap in the record, not a finding: this says what did not run, or what "
    "cannot be known from a message -- never that nothing was found"
)


class ToolError(ValueError):
    """A request this surface cannot serve, returned as an error value.

    Distinct from the pipeline's own "this message could not be read", which is
    a *disposition* (``UNKNOWN``) and not an error at all: a caller's typo is a
    failure of the call, an unreadable message is a finding about the message.
    """


class McpUnavailable(RuntimeError):
    """The ``mcp`` extra is not installed. Carries the instruction, not a stack."""


# --------------------------------------------------------------------------
# configuration: offline, replay-backed, and never live
# --------------------------------------------------------------------------


def tool_config(environ: Mapping[str, str] | None = None) -> Config:
    """The configuration every tool runs under.

    Endpoints still arrive from the environment, exactly as the CLI reads them,
    because a replay lookup needs the model id an operator named. But
    ``replay=True`` is forced rather than inherited: in replay mode a tier reads
    the committed corpus, and the live transport -- with which the store's write
    path arrives -- becomes unreachable. That is how "no tool mutates anything"
    is a property of the code path instead of a promise about behaviour.
    """
    return Config(
        endpoints=ModelEndpoints.from_env(environ),
        replay=True,
        replay_dir=default_replay_dir(),
    )


def _store_for(config: Config) -> ReplayStore | None:
    try:
        return open_store(config)
    except OSError:  # pragma: no cover - an unreadable corpus directory
        return None


def _offline_view(config: Config, store: ReplayStore | None) -> dict[str, Any]:
    """What a caller needs to know about how this answer was produced.

    Which endpoint *fields* are set is reported; the addresses themselves are
    not. A configured inference host is the operator's private infrastructure,
    and an agent-facing surface is not where it gets published.
    """
    fields = {tier: field for tier, field, _stage in MODEL_TIERS}
    configured = sorted(
        f"{tier} ({field})"
        for tier, field in fields.items()
        if getattr(config.endpoints, field, None)
    )
    return {
        "mode": "offline: deterministic signals plus the committed replay corpus",
        "replay_corpus": Path(store.root).name if store is not None else None,
        "recordings": store.total if store is not None else 0,
        "tiers_with_recordings": (
            store.tiers_with_recordings() if store is not None else []
        ),
        "corpus_note": (
            "" if store is not None else
            "no replay corpus was located from this install, so every model tier "
            "records UNAVAILABLE and this is a deterministic-only reading -- a "
            "fact about the deployment, not about the message"
        ),
        "endpoint_fields_configured": configured,
        "live_calls": (
            "never from this surface: replay is forced on, so no tool reaches an "
            "endpoint and no tool writes a recording"
        ),
    }


# --------------------------------------------------------------------------
# the response envelope
# --------------------------------------------------------------------------

#: Exception type -> machine-readable error code. Codes are stable so a calling
#: agent can branch on them instead of pattern-matching prose.
_ERROR_CODES = {
    "FileNotFoundError": "not-found",
    "NotADirectoryError": "not-a-directory",
    "IsADirectoryError": "is-a-directory",
    "PermissionError": "not-permitted",
    "ToolError": "bad-request",
    "DirectoryScanError": "bad-request",
    "ReceiptError": "case-record-unreadable",
    "ContractError": "contract-unreadable",
    "TypeError": "bad-request",
    "ValueError": "bad-request",
    "KeyError": "internal",
    "AttributeError": "internal",
    "OSError": "not-readable",
}


def _error_shape(exc: BaseException) -> dict[str, Any]:
    return {
        "code": _ERROR_CODES.get(type(exc).__name__, "internal"),
        "type": type(exc).__name__,
        "message": str(exc) or type(exc).__name__,
    }


def _guard(name: str, action: Callable[[], Mapping[str, Any]]) -> dict[str, Any]:
    """Run one tool, converting any exception into a structured error value.

    Catching broadly is deliberate and it is not a bug-hiding device: the error
    carries the exception *type*, so a ``KeyError`` from a defect in here reads
    differently from a ``FileNotFoundError`` from a caller's mistyped path.
    Raising instead would tell the client only that the call failed.
    """
    try:
        payload = dict(action())
        envelope: dict[str, Any] = {"ok": True, "tool": name, "error": None}
        for key, value in payload.items():
            if key in envelope:
                raise ToolError(
                    f"tool {name!r} tried to overwrite envelope key {key!r}"
                )
            envelope[key] = value
    except Exception as exc:  # noqa: BLE001 - the MCP boundary must not raise
        return {"ok": False, "tool": name, "error": _error_shape(exc)}
    return envelope


# --------------------------------------------------------------------------
# small shared views
# --------------------------------------------------------------------------


def _require_file(path: Any, *, tool: str) -> Path:
    """One existing file, or a message that says which and why."""
    if path is None or not str(path).strip():
        raise ToolError(f"{tool}: a file path is required")
    candidate = Path(str(path))
    if candidate.is_dir():
        raise ToolError(
            f"{tool}: {candidate.name!r} is a directory. Use "
            f"analyze_eml_directory for a batch, or point at one .eml file."
        )
    if not candidate.is_file():
        raise FileNotFoundError(f"no such file: {candidate.name}")
    return candidate


def _require_dir(path: Any, *, tool: str) -> Path:
    if path is None or not str(path).strip():
        raise ToolError(f"{tool}: a directory path is required")
    candidate = Path(str(path))
    if candidate.is_file():
        raise ToolError(
            f"{tool}: {candidate.name!r} is a file, not a directory. Use "
            f"analyze_eml for a single message."
        )
    if not candidate.is_dir():
        raise FileNotFoundError(f"no such directory: {candidate.name}")
    return candidate


def _host_of(href: Any) -> str:
    try:
        return (urlsplit(str(href or "").strip()).hostname or "").lower()
    except ValueError:
        return ""


def _fact(evidence: Evidence, key: str, default: Any = None) -> Any:
    """A recorded fact by key, read back out of the evidence record."""
    for finding in evidence.findings:
        if finding.key == key and finding.provenance in (
            Provenance.VERIFIED, Provenance.MODEL_JUDGMENT
        ):
            return finding.value
    return default


def _evidence_item(finding: Finding) -> dict[str, Any]:
    """One finding in the form this surface is allowed to carry.

    The digest comes from :class:`~tenable_email.receipt.EvidenceItem`, so an MCP
    response and a saved case record digest a value the same way, which is what
    lets a caller match one to the other.
    """
    item = EvidenceItem.of(finding).as_dict()
    if finding.key in CARRIABLE_VALUE_KEYS:
        item["value"] = finding.value
    else:
        item["value"] = None
        item["value_note"] = WITHHELD_VALUE_NOTE
    return item


def _evidence_groups(evidence: Evidence) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {p.value: [] for p in Provenance}
    for finding in evidence.findings:
        groups.setdefault(finding.provenance.value, []).append(
            _evidence_item(finding)
        )
    return groups


def _gap_view(evidence: Evidence) -> dict[str, Any]:
    """The record's holes, split the way an agent has to act on them.

    ``UNAVAILABLE`` (a tier did not run) and ``UNKNOWN`` (not knowable from a
    message) are both gaps and both are named as gaps here, but they are not the
    same instruction: the first says "this deployment has no such capability
    configured", the second says "nobody could answer that from a mail".
    """
    unavailable = evidence.by_provenance(Provenance.UNAVAILABLE)
    unknown = evidence.by_provenance(Provenance.UNKNOWN)
    return {
        "count": len(unavailable) + len(unknown),
        "note": GAP_NOTE,
        "tier_did_not_run": [
            {
                "key": f.key,
                "stage": f.source,
                "detail": f.detail,
                "kind": "unavailable",
                "means": (
                    "this check was not performed; it is not evidence that "
                    "nothing was found"
                ),
            }
            for f in unavailable
        ],
        "not_knowable_from_the_message": [
            {
                "key": f.key,
                "stage": f.source,
                "detail": f.detail,
                "kind": "unknown",
                "means": (
                    "no amount of analysis of this message can answer it; a "
                    "human or another system has to"
                ),
            }
            for f in unknown
        ],
    }


def _model_votes(evidence: Evidence) -> dict[str, Any]:
    """Each tier's opinion, kept apart, and whether they conflict.

    The disagreement test mirrors :func:`tenable_email.ensemble.combine`: an
    abstaining tier is not a vote, and more than one remaining stance is
    disagreement. It is reported as information here rather than resolved,
    because resolving it is the ensemble's job and averaging it away is the
    failure mode this project refuses.
    """
    votes: list[dict[str, Any]] = []
    for finding in evidence.by_provenance(Provenance.MODEL_JUDGMENT):
        value = finding.value if isinstance(finding.value, Mapping) else {}
        votes.append(
            {
                "tier": str(value.get("tier") or finding.key),
                "stance": value.get("stance"),
                "confidence": value.get("confidence"),
                "attack_type": value.get("attack_type"),
                "scores": dict(value.get("scores") or {}),
                "stage": finding.source,
                "value_digest": EvidenceItem.of(finding).value_digest,
            }
        )
    decided = [v for v in votes if v["stance"] in ("threat", "spam", "clean")]
    stances = sorted({str(v["stance"]) for v in decided})
    return {
        "votes": votes,
        "tiers_that_voted": len(decided),
        "distinct_stances": stances,
        "disagreement": len(stances) > 1,
        "note": (
            "no merged number is offered here. The ensemble combines these "
            "asymmetrically: a verified fact is a floor a model cannot talk "
            "down, unanimity adopts the weakest vote's confidence rather than a "
            "mean, and disagreement routes to a person."
        ),
    }


def _stage_view(verdict: Verdict) -> dict[str, Any]:
    """Which stages of the chain ran for this message, and why the rest did not.

    Derived from the evidence rather than from the contract file, so the tool
    still works from an installed wheel that carries no ``stages.yaml``.
    """
    gaps: dict[str, str] = {}
    for finding in verdict.evidence.by_provenance(Provenance.UNAVAILABLE):
        gaps.setdefault(finding.source, finding.detail or "")
    skipped: list[dict[str, Any]] = []
    for stage in ALL_STAGES_IN_ORDER:
        if stage in verdict.stages_run:
            continue
        if stage == STAGE_WRITEBACK:
            reason = (
                "the contract's only write stage: gated behind human approval "
                "and never advanced by this surface"
            )
        elif stage == STAGE_ATTACHMENTS:
            reason = (
                "attachment structure inspection is optional and is not enabled "
                "in this configuration: these tools always run the offline "
                "replay path, which never turns on the external analyzer, so a "
                "retained attachment's contents stay an explicit unknown rather "
                "than a finding of nothing"
            )
        else:
            reason = gaps.get(stage) or (
                "no tier ran for this stage in this configuration"
            )
        skipped.append({"stage": stage, "reason": reason})
    return {"stages_run": list(verdict.stages_run), "stages_not_run": skipped}


def _shape(evidence: Evidence) -> dict[str, Any]:
    """Counts and booleans a caller can act on, read back from the record.

    A projection, not a copy: every field here is a number, a boolean, a
    mechanism name or a host, so no body text can ride out on it. The keys that
    genuinely quote the message -- injection matches, forwarding headers,
    anchor text, the BEC phrase list -- are absent by construction and come back
    as digests in the evidence groups instead.
    """
    links = _fact(evidence, "links") or {}
    att = _fact(evidence, "attachments") or {}
    bulk = _fact(evidence, "bulk") or {}
    auth = _fact(evidence, "auth") or {}
    align = _fact(evidence, "alignment") or {}
    injection = _fact(evidence, "injection") or {}
    forwarding = _fact(evidence, "forwarding") or {}
    return {
        "link_count": links.get("link_count", 0),
        "resolved_hosts": list(links.get("resolved_hosts") or []),
        "hosts_matching_sender": list(links.get("hosts_matching_sender") or []),
        "hosts_matching_trusted": list(links.get("hosts_matching_trusted") or []),
        "hosts_matching_neither": list(links.get("hosts_matching_neither") or []),
        "ip_literal_hosts": list(links.get("ip_literal_hosts") or []),
        "javascript_uris": list(links.get("javascript_uris") or []),
        "anchor_mismatch_count": links.get("anchor_mismatch_count", 0),
        "redirect_wrappers_seen": sorted(
            {
                str(entry.get("wrapper") or "")
                for entry in (links.get("unwrapped_redirects") or [])
                if entry.get("wrapper")
            }
        ),
        "attachment_count": att.get("count", 0),
        "inline_image_count": _fact(evidence, "inline_image_count", 0),
        "dangerous_attachments_from_external_sender": att.get(
            "dangerous_and_external_count", 0
        ),
        "is_forwarded": bool(forwarding.get("is_forward")),
        "auth_results": {
            "spf": auth.get("spf"), "dkim": auth.get("dkim"),
            "dmarc": auth.get("dmarc"),
        },
        "auth_passes": bool(align.get("auth_passes")),
        "claims_protected_domain": bool(align.get("claims_protected_domain")),
        "injection_indicator_count": injection.get("hit_count", 0),
        "bulk_headers": list(bulk.get("bulk_headers") or []),
        "rfc8058_one_click": bool(bulk.get("rfc8058_one_click")),
        "truncated": bool(_fact(evidence, "truncated")),
    }


def _proposal(verdict: Verdict, target: str) -> dict[str, Any]:
    """What the write stage *would* do, as data, and how to actually do it.

    This is the answer to "a tool that would need to write returns a proposed
    action instead". The proposals come from the same
    :func:`~tenable_email.writeback.proposed_actions` the runner binds its
    approval to, so nothing here invents a second write vocabulary.
    """
    return {
        "actions": [a.as_dict() for a in proposed_actions(verdict, target=target)],
        "executed": False,
        "gate": (
            "human approval required -- per action, bound to the verdict digest, "
            "single-use. No MCP client is a human approver and this server holds "
            "no write capability."
        ),
        "how_to_act": (
            "tenable-email run <path> --out <dir> opens the case records; the "
            "gated stage is advanced through the runner, never from here"
        ),
    }


def _truncation(verdict: Verdict, evidence: Evidence) -> dict[str, Any]:
    """A partial reading says so, in its own field, next to the disposition."""
    original = _fact(evidence, "original_body_length") or _fact(
        evidence, "body_chars", 0
    )
    return {
        "truncated": bool(verdict.truncated),
        "body_chars_retained": _fact(evidence, "body_chars", 0),
        "original_body_length": original,
        "warning": (
            "PARTIAL READING: the body was cut before analysis, so content that "
            "was not read cannot have been considered. Report this result as "
            "partial -- never as a complete reading of the message."
            if verdict.truncated else ""
        ),
    }


def _verdict_view(verdict: Verdict) -> dict[str, Any]:
    """The reference-shaped decision, with its provenance alongside it."""
    out: dict[str, Any] = {
        "verdict": verdict.disposition.value,
        "disposition": verdict.disposition.value,
        "confidence": float(verdict.confidence),
        "confidence_band": verdict.confidence_band.value,
        "attack_type": verdict.attack_type.value,
        "escalated": bool(verdict.escalated),
        "truncated": bool(verdict.truncated),
        "reasons": list(verdict.reasons),
        "analysis": verdict.analysis,
        "stages_run": list(verdict.stages_run),
        "cited_findings": list(verdict.cited_findings),
        "identity": {
            "id": verdict.id, "subject": verdict.subject,
            "sender": verdict.sender, "reported_by": verdict.reported_by,
        },
        "evidence": _evidence_groups(verdict.evidence),
        "evidence_counts": {
            p.value: len(verdict.evidence.by_provenance(p)) for p in Provenance
        },
        "gaps": _gap_view(verdict.evidence),
        "model_votes": _model_votes(verdict.evidence),
    }
    return out


# --------------------------------------------------------------------------
# F1: the tools
# --------------------------------------------------------------------------


def analyze_eml(path: str) -> dict:
    """Triage one ``.eml`` end to end and return the decision with its evidence.

    The full chain: parse, authenticate, deterministic signals, the model tiers
    (from the committed recordings, or recorded as unavailable -- never from a
    live call on this surface, see :func:`tool_config`), then adjudication and
    the ensemble. Nothing is written and no message content travels back out.
    """
    def work() -> dict[str, Any]:
        target = _require_file(path, tool="analyze_eml")
        config = tool_config()
        verdict = triage_file(target, config)
        view = _verdict_view(verdict)
        view.update(
            {
                "source": target.name,
                "shape": _shape(verdict.evidence),
                **_stage_view(verdict),
                "truncation": _truncation(verdict, verdict.evidence),
                "proposed_writeback": _proposal(verdict, target.name),
                "offline": _offline_view(config, _store_for(config)),
                "reading": (
                    "escalate this to a human rather than re-asking the server: "
                    "a manual_review disposition is the finding, and running the "
                    "same evidence through the same tiers again cannot produce "
                    "new information"
                    if verdict.escalated else ""
                ),
            }
        )
        return view

    return _guard("analyze_eml", work)


def analyze_eml_directory(path: str) -> dict:
    """Batch triage over a directory, with counts and label agreement.

    One row per message plus the disposition totals. If the corpus carries a
    ``labels.json`` beside it, agreement is reported in three counts -- agree,
    escalated, disagreed -- because folding a conservative escalation into
    "correct" flatters the engine and folding it into "wrong" calls a person in
    the loop a failure. Escalation is neither, so it is its own number, exactly
    as ``tenable-email demo`` reports it.

    The walk is the bounded one in :mod:`~tenable_email.parse`, and the answer
    carries :meth:`~tenable_email.parse.EmlScan.summary`: the root, how many
    ``.eml`` files were found, and whether the scan saw everything below it. A
    directory that needs more than the bound is refused with the bound named in
    the error, never answered with a subset of rows that looks like the whole
    corpus: pointing at ``/`` used to walk the machine and triage everybody's
    mail, and a caller must not be able to do that through this surface.
    """
    def work() -> dict[str, Any]:
        root = _require_dir(path, tool="analyze_eml_directory")
        scan = scan_eml_dir(root)
        paths = list(scan.paths)
        if not paths:
            raise ToolError(
                f"no .eml files under {root.name or root}: nothing to triage. "
                "This wants a directory of reported messages, not a directory of "
                "case records."
            )
        config = tool_config()
        store = _store_for(config)
        labels = label_rows(root / "labels.json")
        rows: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        agreement = {"agree": 0, "escalated": 0, "disagree": 0, "unlabelled": 0}
        truncated = 0
        escalated = 0
        judgments = 0
        for message_path in paths:
            verdict = triage_file(message_path, config)
            name = verdict.disposition.value
            counts[name] = counts.get(name, 0) + 1
            label = labels.get(message_path.name, "")
            call = classify_agreement(label, name) if label else "unlabelled"
            agreement[call] = agreement.get(call, 0) + 1
            model_judgments = len(
                verdict.evidence.by_provenance(Provenance.MODEL_JUDGMENT)
            )
            judgments += model_judgments
            truncated += 1 if verdict.truncated else 0
            escalated += 1 if verdict.escalated else 0
            rows.append(
                {
                    "source": message_path.name,
                    "label": label or None,
                    "disposition": name,
                    "confidence": float(verdict.confidence),
                    "confidence_band": verdict.confidence_band.value,
                    "attack_type": verdict.attack_type.value,
                    "escalated": bool(verdict.escalated),
                    "truncated": bool(verdict.truncated),
                    "stages_run": len(verdict.stages_run),
                    "model_judgments": model_judgments,
                    "agreement": call,
                    "top_reason": verdict.reasons[0] if verdict.reasons else "",
                    "line": (
                        f"{message_path.stem:<46} {name:<13} "
                        f"{verdict.confidence:>4.2f} "
                        f"{verdict.confidence_band.value:<6} "
                        f"{verdict.attack_type.value:<18} "
                        f"{len(verdict.stages_run)} stages, "
                        f"{model_judgments} judgment"
                        f"{'s' if model_judgments != 1 else ''}  {call}"
                    ),
                }
            )
        return {
            "directory": root.name or str(root),
            "scan": scan.summary(),
            "messages": len(rows),
            "results": rows,
            "counts_by_disposition": counts,
            "totals": {
                "escalated_to_a_human": escalated,
                "truncated_readings": truncated,
                "model_judgments": judgments,
            },
            "label_agreement": {
                "manifest": "labels.json" if labels else None,
                "present": bool(labels),
                **agreement,
                "summary": (
                    "" if not labels else
                    f"{agreement['agree']} agree, {agreement['escalated']} "
                    f"escalated on a threat label (reported separately: neither "
                    f"agreement nor a miss), {agreement['disagree']} disagreed"
                ),
                "note": (
                    "escalation on a threat label is the conservative direction "
                    "and is counted separately in both ways: neither correct nor "
                    "incorrect"
                    if labels else
                    "no label manifest beside this directory, so nothing here "
                    "claims to know the ground truth"
                ),
            },
            "case_records": {
                "written": False,
                "how": (
                    "tenable-email run <dir> --out <dir> writes one durable case "
                    "record per message through the receipt contract; this tool "
                    "only reads"
                ),
            },
            "offline": _offline_view(config, store),
        }

    return _guard("analyze_eml_directory", work)


def _resolve_case(reference: Any, case_dir: Any, *, tool: str) -> tuple[Receipt, str]:
    """Find one saved case record, or say what was searched.

    Accepts a path to a record, a bare receipt id together with the directory a
    ``run --out`` wrote, or a receipt id alone when the working directory holds a
    ``receipts/``. A record is data an operator already chose where to put, so
    guessing a permanent home for it would be a fiction, and the error names
    every form it tried.
    """
    text = str(reference or "").strip()
    if not text:
        raise ToolError(f"{tool}: a receipt id or a case-record path is required")
    direct = Path(text)
    if direct.suffix == ".eml":
        raise ToolError(
            f"{tool}: {direct.name} is a message, not a case record. Use "
            f"analyze_eml to triage it, or run the CLI with --out to produce a "
            f"record first."
        )
    bases: list[Path] = []
    if case_dir:
        base = Path(str(case_dir))
        if not base.is_dir():
            raise FileNotFoundError(f"no such case directory: {base.name}")
        bases.append(base)
    else:
        bases.append(Path.cwd())

    names = [
        direct.name,
        direct.name.removesuffix(".json"),
    ]
    tried: list[str] = []
    candidates: list[Path] = []
    if direct.is_file():
        candidates.append(direct)
    for wanted in dict.fromkeys(n for n in names if n):
        for root in bases:
            candidates.extend(
                [
                    root / f"{wanted}.json",
                    root / "receipts" / f"{wanted}.json",
                    root / f"{wanted}.receipt.json",
                    root / "receipts" / f"{wanted}.receipt.json",
                ]
            )
    for candidate in candidates:
        tried.append(candidate.name)
        if candidate.is_file():
            return Receipt.load(candidate), candidate.name

    raise ReceiptError(
        f"no case record found for {direct.name}. Searched for: "
        f"{', '.join(dict.fromkeys(tried))}. Pass the record's path, or its "
        "receipt id together with the directory written by "
        "'tenable-email run --out'."
    )


def explain_verdict(reference: str, case_dir: str | None = None) -> dict:
    """The provenance-grouped evidence behind one saved case record.

    A receipt stores each finding's value as a digest, which is the point of it:
    the record proves what was seen without carrying what was seen. So this
    returns provenance, the stage that produced it, the explanatory detail and
    the digest -- and labels the gaps as gaps, because "the vision tier did not
    run" is a statement about the deployment that a reader is entitled to.
    """
    def work() -> dict[str, Any]:
        receipt, loaded = _resolve_case(reference, case_dir, tool="explain_verdict")
        blockers = receipt.closure_blockers()
        grouped: dict[str, list[dict[str, Any]]] = {
            p.value: [] for p in Provenance
        }
        for item in receipt.evidence:
            entry = dict(item.as_dict())
            entry["cited_by_disposition"] = item.key in set(receipt.cited_findings)
            if not item.supports_verdict():
                entry["gap"] = True
                entry["means"] = (
                    "not knowable from the message"
                    if item.provenance == Provenance.UNKNOWN.value else
                    "the stage that would have produced this did not run"
                )
            grouped.setdefault(item.provenance, []).append(entry)
        gap_count = sum(
            len(v) for k, v in grouped.items()
            if k in (Provenance.UNKNOWN.value, Provenance.UNAVAILABLE.value)
        )
        return {
            "receipt_id": receipt.receipt_id,
            "loaded_from": loaded,
            "source": receipt.source,
            "state": receipt.state,
            "disposition": receipt.disposition,
            "confidence": float(receipt.confidence),
            "confidence_band": receipt.confidence_band,
            "attack_type": receipt.attack_type,
            "escalated": bool(receipt.escalated),
            "truncated": bool(receipt.truncated),
            "simulated": bool(receipt.simulated),
            "reasons": list(receipt.reasons),
            "analysis": receipt.analysis,
            "cited_findings": list(receipt.cited_findings),
            "evidence": grouped,
            "evidence_counts": receipt.counts(),
            "gaps": {"count": gap_count, "note": GAP_NOTE},
            "chain": {
                "stages_run": list(receipt.stages_run),
                "completed_stages": list(receipt.completed_stages),
                "skipped_stages": [dict(s) for s in receipt.skipped_stages],
            },
            "digests": {
                "verdict": receipt.verdict_digest,
                "corpus_manifest": receipt.corpus_manifest,
                "corpus_manifest_digest": receipt.corpus_manifest_digest,
            },
            "closure": {
                "blockers": blockers,
                "can_close": not blockers,
                "note": (
                    "a closure blocker says this case may not be advanced; it is "
                    "not a bug. The four are: simulated evidence, a cited gap, an "
                    "UNKNOWN disposition, or a truncated reading claiming to be "
                    "complete"
                ),
            },
            "truncation": {
                "truncated": bool(receipt.truncated),
                "original_body_length": receipt.original_length,
                "warning": (
                    "PARTIAL READING: report this case as partial, never as a "
                    "finished look at the message."
                    if receipt.truncated else ""
                ),
            },
            "writeback": {
                "proposed_actions": [a.as_dict() for a in receipt.proposed_actions],
                "approval_state": receipt.approval_state,
                "executed_here": False,
            },
        }

    return _guard("explain_verdict", work)


def check_auth(path: str) -> dict:
    """Authentication results as verified facts, with the interpretation bounded.

    The receiving MTA's verdicts, the domains that actually authenticated, and
    the raw header values truncated the way the evidence record truncates them.
    What is *not* here is a legitimacy judgment: ``auth_passes`` is a statement
    about SPF, DKIM and DMARC alignment, and a business-email-compromise message
    satisfies it. The reference playbook reads a matching destination as "a
    strong indicator of a clean email", which is the inference this project
    refuses -- so the caveat travels in the response rather than in a manual
    nobody reads.
    """
    def work() -> dict[str, Any]:
        target = _require_file(path, tool="check_auth")
        config = tool_config()
        message = parse_file(
            target, body_char_limit=config.thresholds.body_char_limit
        )
        auth = extract_auth_results(message)
        sender = parse_address(message.from_raw)
        alignment = assess_alignment(auth, sender.domain, config.profile)
        checked = (
            "authentication-results", "arc-authentication-results",
            "received-spf", "x-google-dkim-signature",
        )
        seen = {name for name, _value in message.headers if name in checked}
        unresolved = sorted(
            mechanism for mechanism, value in (
                ("spf", auth.spf), ("dkim", auth.dkim), ("dmarc", auth.dmarc)
            ) if value == "unknown"
        )
        return {
            "source": target.name,
            "provenance": Provenance.VERIFIED.value,
            "sender": {
                "raw": sender.raw, "display_name": sender.display_name,
                "address": sender.address, "domain": sender.domain,
            },
            "auth": auth.as_dict(),
            "alignment": alignment,
            "auth_headers_seen": sorted(seen),
            "auth_headers_absent": sorted(h for h in checked if h not in seen),
            "mechanisms_with_no_recorded_result": unresolved,
            "raw_header_limit": 200,
            "absent_is_not_passing": (
                "An outcome recorded as 'unknown' means no header reported it. "
                "That is a gap in the record, not a pass and not a failure -- "
                "collapsing the three is how an absent check becomes a passing "
                "one."
            ),
            "interpretation": {
                "authenticated_at_the_receiving_mta": bool(
                    alignment["auth_passes"]
                ),
                "claims_a_protected_domain": bool(
                    alignment["claims_protected_domain"]
                ),
                "does_not_establish": (
                    "legitimacy. Valid SPF, DKIM and DMARC are equally "
                    "consistent with a compromised account sending a payment "
                    "request -- the business-email-compromise shape. "
                    "Authentication says the message really came from that "
                    "domain, not that its content is honest."
                ),
            },
        }

    return _guard("check_auth", work)


def lookalike_domain(domain: str) -> dict:
    """Lookalike analysis of any domain against the configured profile.

    Purely deterministic -- edit distance and modifier-token analysis over the
    second-level label -- so identical input gives an identical answer and an
    agent investigating something it found elsewhere can ask about it without
    triaging a message first. The thresholds are reported with the result,
    because "is this a lookalike" is a function of configuration, not a property
    of the string.
    """
    def work() -> dict[str, Any]:
        raw = str(domain or "").strip()
        if not raw:
            raise ToolError("lookalike_domain: a domain is required")
        host = _host_of(raw) if ("://" in raw or "/" in raw) else ""
        used = (host or raw.split("/")[0]).strip().strip(".").lower()
        if not used:
            raise ToolError(f"lookalike_domain: {raw!r} contains no domain")
        config = tool_config()
        result = detect_lookalike_domain(used, config.profile, config.thresholds)
        return {
            "input": raw,
            "domain": used,
            "provenance": Provenance.VERIFIED.value,
            "registrable_domain": registrable_domain(used),
            "second_level_label": second_level_label(used),
            "lookalike": result.as_dict(),
            "owned_by_the_profile": config.profile.owns_domain(used),
            "trusted_by_the_profile": any(
                used == t or used.endswith("." + t)
                for t in config.profile.trusted_domains
            ),
            "profile": {
                "protected_domains": list(config.profile.protected_domains),
                "trusted_domains": list(config.profile.trusted_domains),
            },
            "thresholds": {
                "lookalike_max_distance": config.thresholds.lookalike_max_distance,
                "short_label_len": config.thresholds.lookalike_short_label_len,
                "short_max_distance":
                    config.thresholds.lookalike_short_max_distance,
                "vendor_min_label_len": config.thresholds.vendor_min_label_len,
            },
            "reading": (
                "is_lookalike is the impersonation finding. A shared label with "
                "no modifier token is recorded in contains_protected_label and "
                "is *not* impersonation: example-outfitters.com is a company "
                "named Example, not a lookalike of example.edu. "
                "registrable_domain() is naive -- no Public Suffix List -- so "
                "multi-part TLDs reduce wrongly; the second-level label is what "
                "the comparison actually uses."
            ),
        }

    return _guard("lookalike_domain", work)


def _url_items(urls: Any) -> list[dict[str, str]]:
    """Normalize a caller's link list into ``{href, anchor_text}`` pairs.

    Strings, ``{"href": ..., "anchor_text": ...}`` objects and single values all
    arrive from different clients. Anchor text is what makes the
    anchor-versus-href comparison possible, so a caller that has it should pass
    it; a bare URL still yields resolution, IP-literal and destination facts.
    """
    if urls is None:
        return []
    if isinstance(urls, (str, Mapping)):
        urls = [urls]
    if not isinstance(urls, (list, tuple)):
        raise ToolError(
            f"analyze_urls: expected a list of URLs or objects, got "
            f"{type(urls).__name__}"
        )
    out: list[dict[str, str]] = []
    for item in urls:
        if isinstance(item, Mapping):
            href = str(item.get("href") or item.get("url") or "").strip()
            anchor = str(item.get("anchor_text") or item.get("text") or "")
        else:
            href = str(item or "").strip()
            anchor = ""
        if href:
            out.append({"href": href, "anchor_text": anchor})
    return out


def analyze_urls(urls: list, sender_domain: str | None = None) -> dict:
    """Deterministic link analysis for arbitrary URLs, plus reputation if known.

    The same machinery the deterministic stage runs over a message -- Safe Links,
    Proofpoint and Mimecast style wrapper unwrapping with percent-decoding,
    anchor-versus-href comparison, IP-literal and non-http schemes, and sender /
    trusted / neither classification against the configured profile -- applied to
    links an agent found anywhere. Anchor text is optional; without it there is
    no visible claim to compare a destination against, and the result says so
    rather than inventing one.

    URL reputation is consulted per *unwrapped* destination: querying a proxy's
    own domain is querying Microsoft. With no endpoint configured the tier
    answers from the committed recordings where one exists and reports a replay
    miss otherwise -- it never reaches out, and never guesses.
    """
    def work() -> dict[str, Any]:
        items = _url_items(urls)
        if not items:
            raise ToolError(
                "analyze_urls: no usable URL in the request (expected a list of "
                "strings or {href, anchor_text} objects)"
            )
        config = tool_config()
        store = _store_for(config)
        sender = str(sender_domain or "").strip().lower().strip(".")
        anchor = sender or "no-sender-supplied.invalid"

        # One synthetic message carrying the caller's anchors, so the parser
        # that reads a real reported message reads these too: one implementation
        # of entity handling and href extraction, not a second to drift from it.
        parts: list[str] = []
        for item in items:
            href = html.escape(item["href"], quote=True)
            text = html.escape(item["anchor_text"])
            parts.append(f'<a href="{href}">{text}</a>')
        probe = Message(source="inline", html_body=" ".join(parts))
        links = extract_links(probe, config.profile)
        summary = classify_link_destinations(links, anchor, config.profile)
        by_href = {link.href: link for link in links}
        unwrapped = {
            str(entry.get("href") or ""): str(entry.get("resolved") or "")
            for entry in (summary.get("unwrapped_redirects") or [])
        }
        neither = set(summary.get("hosts_matching_neither") or [])

        def destination_class(host: str) -> str:
            """Where this destination sits, relative to what the caller told us.

            With no ``sender_domain`` there is no reference point, so a host that
            is merely somebody else's comes back ``unclassified`` rather than
            ``neither``: ``neither`` is a claim about the sender, and an agent
            that did not supply one is not owed that claim.
            """
            if not host:
                return "unparseable"
            if sender and (host == sender or host.endswith("." + sender)):
                return "sender"
            if any(host == t or host.endswith("." + t)
                   for t in config.profile.trusted_domains):
                return "trusted"
            if not sender:
                return "unclassified"
            if host in neither:
                return "neither"
            return "unclassified"

        queried: list[str] = []
        entries: list[dict[str, Any]] = []

        def not_queried(reason: str) -> dict[str, Any]:
            """The same shape as a lookup, with the answer left empty.

            A caller that branches on ``reputation["ok"]`` must not meet a
            different key set because the cap bound: "this destination was not
            checked" is a gap, and a gap is reported the way every other gap in
            this project is.
            """
            return {
                "tier": "url_reputation",
                "stage": "classifier-cascade",
                "queried": False,
                "available": False,
                "ok": False,
                "source": None,
                "model": None,
                "latency_ms": None,
                "tokens": None,
                "stance": None,
                "confidence": None,
                "attack_type": None,
                "scores": {},
                "error": reason,
                "reason": reason,
            }

        for item in items:
            link = by_href.get(item["href"])
            resolved = (
                unwrapped.get(item["href"])
                or (link.resolved_href if link else item["href"])
            )
            host = (link.resolved_host if link else "") or _host_of(resolved)
            klass = destination_class(host)
            url = resolved if "://" in str(resolved) else f"https://{resolved}"
            if len(queried) < MAX_URL_LOOKUPS_PER_MESSAGE and url not in queried:
                queried.append(url)
                reputation = _tier_entry(
                    consult(UrlReputationTier(), {"url": url}, config, store),
                    config=config, stage="classifier-cascade",
                )
                reputation["queried"] = True
            elif url in queried:
                reputation = not_queried("already queried for this destination")
            else:
                reputation = not_queried(
                    f"lookup cap of {MAX_URL_LOOKUPS_PER_MESSAGE} destinations "
                    "reached; these links were not checked, which is not the "
                    "same as their being clean"
                )
            entries.append(
                {
                    "href": item["href"],
                    "anchor_text": item["anchor_text"],
                    "anchor_claim": link.anchor_host_hint if link else None,
                    "anchor_mismatch": bool(link and link.anchor_mismatch),
                    "resolved_href": resolved,
                    "resolved_host": host,
                    "scheme": link.scheme if link else "",
                    "unwrapped_by": link.unwrapped_by if link else None,
                    "is_ip_literal": bool(link and link.is_ip_literal),
                    "destination_class": klass,
                    "concealment": bool(
                        link and link.unwrapped_by
                        and klass not in ("sender", "trusted", "unparseable")
                    ),
                    "reputation": reputation,
                }
            )
        return {
            "sender_domain": sender or None,
            "sender_domain_supplied": bool(sender),
            "links": entries,
            "summary": {
                "requested_links": len(entries),
                "links_parsed": summary.get("link_count", 0),
                "destinations_queried": len(queried),
                "lookup_cap": MAX_URL_LOOKUPS_PER_MESSAGE,
                "anchor_mismatches": summary.get("anchor_mismatch_count", 0),
                "anchor_text_supplied": any(e["anchor_text"] for e in entries),
                "ip_literal_hosts": summary.get("ip_literal_hosts", []),
                "javascript_uris": summary.get("javascript_uris", []),
                "non_http_schemes": summary.get("non_http_schemes", []),
                "hosts_matching_sender": summary.get("hosts_matching_sender", []),
                "hosts_matching_trusted": summary.get("hosts_matching_trusted", []),
                "hosts_matching_neither": (
                    summary.get("hosts_matching_neither", []) if sender else []
                ),
                "no_reference_point": not bool(sender),
                "concealed_destinations": [
                    e["resolved_host"] for e in entries if e["concealment"]
                ],
            },
            "reading": (
                "a destination matching neither the sender nor a trusted domain "
                "is not a verdict: legitimate mail links to unrelated services "
                "constantly, and without a sender_domain argument this "
                "classification has no reference point. What is not ordinary is "
                "a wrapper hiding such a destination -- concealment is the "
                "finding, and concealed_destinations lists exactly those."
            ),
            "offline": _offline_view(config, store),
        }

    return _guard("analyze_urls", work)


def _tier_entry(
    result: TierResult | None, *, config: Config, stage: str,
    unavailable_detail: str = "", tier_name: str = "",
) -> dict[str, Any]:
    """One tier's answer as data: its own score, its own source, its own error.

    ``raw`` is deliberately absent. A service response can echo the text it was
    shown -- the injection engine reports pattern matches, the vision tier
    reports a transcription -- and an opinion's score does not need the payload
    in order to be useful.
    """
    if result is None:
        # Same key set as an answer, with the gaps filled in, so a caller can
        # read a list of tiers without special-casing the ones that did not run.
        return {
            "tier": tier_name or stage,
            "stage": stage,
            "available": False,
            "ok": False,
            "source": None,
            "model": None,
            "latency_ms": None,
            "tokens": None,
            "stance": None,
            "confidence": None,
            "attack_type": None,
            "scores": {},
            "error": unavailable_detail or "the tier did not run",
        }
    entry: dict[str, Any] = {
        "tier": result.tier,
        "stage": stage,
        "available": bool(result.available),
        "ok": bool(result.ok),
        "source": result.source,
        "model": result.model,
        "latency_ms": result.latency_ms,
        "tokens": result.tokens,
        "error": result.error,
        "stance": None,
        "confidence": None,
        "attack_type": None,
        "scores": {},
    }
    if result.ok:
        try:
            judgment: Judgment = read_judgment(result, config)
        except Exception as exc:  # noqa: BLE001 - an unreadable answer is a value
            entry["error"] = f"answered but not readable: {exc}"
            return entry
        entry.update(
            {
                "stance": judgment.stance.value,
                "confidence": judgment.confidence,
                "attack_type": (
                    judgment.attack_type.value if judgment.attack_type else None
                ),
                "scores": dict(judgment.score_fields),
            }
        )
    if entry["source"] not in ("live", "replay"):
        entry["provenance_warning"] = (
            f"source={entry['source']}: this answer came from neither a live "
            "call nor a recording the replay store attests to, so it is authored "
            "content standing in for evidence. The receipt contract refuses to "
            "close a case on it."
        )
    return entry


def classify_local(path: str) -> dict:
    """The model tiers' separate opinions for one message -- and nothing else.

    Deliberately no disposition and no merged confidence. Each tier's answer is
    returned with its own stance, its own score, its own ``source`` (``replay``
    for a recording the store attests to, ``live`` for a call that just
    happened, ``unattested-recording`` for a file nobody observed) and its own
    error. An agent that sees ``classifier: threat 0.99`` beside ``llm: clean
    0.95`` should escalate; given one averaged number instead it would have no
    way to know that two very different things were said.
    """
    def work() -> dict[str, Any]:
        target = _require_file(path, tool="classify_local")
        config = tool_config()
        store = _store_for(config)
        message = parse_file(
            target, body_char_limit=config.thresholds.body_char_limit
        )
        signals = extract_signals(message, config.profile, config.thresholds)
        evidence = build_evidence(message, signals, config, store=store)
        facts = derive_facts(signals, evidence)
        results, _judgments, _stages = consult_tiers(
            message, signals, evidence, config, store, facts
        )
        stage_of = {tier: stage for tier, _field, stage in MODEL_TIERS}
        field_of = {tier: field for tier, field, _stage in MODEL_TIERS}
        by_tier: dict[str, list[TierResult]] = {}
        for result in results:
            by_tier.setdefault(result.tier, []).append(result)

        unavailable_detail = {
            f.key: f.detail
            for f in evidence.by_provenance(Provenance.UNAVAILABLE)
        }
        entries: list[dict[str, Any]] = []
        for name, _field, stage in MODEL_TIERS:
            found = by_tier.get(name) or []
            if not found:
                # No UNAVAILABLE finding for this tier means it *could* have run:
                # build_evidence records a gap for every tier with neither an
                # endpoint nor an attested recording. So the honest reason for its
                # silence here is that the cascade had nothing to ask it, which is
                # a different fact from "this check is missing".
                detail = unavailable_detail.get(name) or (
                    "the cascade had nothing to ask this tier about this message. "
                    "It was able to run, so no gap is recorded: an unasked "
                    "question is not a missing capability"
                )
                entry = _tier_entry(
                    None, config=config, stage=stage, tier_name=name,
                    unavailable_detail=detail,
                )
                entry["endpoint_field"] = field_of.get(name, "")
                entries.append(entry)
                continue
            for result in found:
                entry = _tier_entry(result, config=config, stage=stage_of[name])
                entry["endpoint_field"] = field_of.get(name, "")
                entries.append(entry)

        decided = [e for e in entries if e["stance"] in ("threat", "spam", "clean")]
        stances = sorted({str(e["stance"]) for e in decided})
        return {
            "source": target.name,
            "tiers": entries,
            "tiers_that_answered": sum(1 for e in entries if e["ok"]),
            "tiers_that_voted": len(decided),
            "tiers_unavailable": sum(1 for e in entries if not e["available"]),
            "distinct_stances": stances,
            "disagreement": len(stances) > 1,
            "no_tier_ran": all(not e["ok"] for e in entries),
            "provenance": Provenance.MODEL_JUDGMENT.value,
            "reading": (
                "these are opinions, not facts, and they are not combined here. "
                "Where they disagree the correct action is a human, not a "
                "weighted mean: a verified finding already outranks them in "
                "either direction, and where the facts left the band open it is "
                "unanimity -- not agreement with one loud tier -- that the "
                "ensemble will act on, at the weakest vote's confidence."
            ),
            "offline": _offline_view(config, store),
        }

    return _guard("classify_local", work)


def _contract_or_raise() -> Contract:
    try:
        return load_contract()
    except ContractError as exc:
        raise ContractError(
            f"{exc}. stages.yaml is the source of the stage order, and it lives "
            "at the repository root -- an installed wheel does not carry it"
        ) from None


def list_contracts() -> dict:
    """The stage chain as data, straight from ``stages.yaml``.

    Field for field what the contract file says: :meth:`Contract.as_dict` is the
    same projection the runner enforces, so a calling agent learns the order, the
    access class of every stage and where the approval gate sits before asking
    any of it to run. ``tests/test_mcp_tools.py`` compares this against the file
    itself, not only against the parser.
    """
    def work() -> dict[str, Any]:
        contract = _contract_or_raise()
        writes = contract.write_stages()
        view = contract.as_dict()
        return {
            "version": contract.version,
            "summary": contract_summary(contract),
            "stage_count": len(contract.stages),
            "stages": view["stages"],
            "stage_ids": contract.ids(),
            "stage_titles": contract.titles(),
            "read_only_stages": [
                s.id for s in contract.stages if s.access == "read-only"
            ],
            "write_stages": [s.id for s in writes],
            "approval_gates": [
                {
                    "stage": s.id,
                    "required": bool(s.approval_required),
                    "language": s.approval_language,
                }
                for s in writes
            ],
            "providers": {
                s.provider: {
                    "stage": s.id, "access": s.access, "capability": s.capability,
                }
                for s in contract.stages
            },
            "this_surface": {
                "mutates": False,
                "reason": (
                    "every stage a tool can reach is read-only; the one write "
                    "stage is gated on human approval and is not advanced from "
                    "an MCP call"
                ),
            },
        }

    return _guard("list_contracts", work)


def get_case_record(reference: str, case_dir: str | None = None) -> dict:
    """One durable case record: its JSON, and its Markdown rendering.

    The record is the artifact an auditor reads, so it comes back both ways. It
    contains no message body by construction -- each finding is stored with a
    digest of its value rather than the value -- which is why this tool can hand
    a whole record over a protocol without shipping the mail inside it.
    """
    def work() -> dict[str, Any]:
        receipt, loaded = _resolve_case(reference, case_dir, tool="get_case_record")
        return {
            "receipt_id": receipt.receipt_id,
            "loaded_from": loaded,
            "receipt": receipt.to_dict(),
            "markdown": receipt.to_markdown(),
            "closure_blockers": receipt.closure_blockers(),
            "schema_version": receipt.schema_version,
            "contains_no_message_content": (
                "the record carries digests of findings, our own reasons and "
                "analysis text, and the source file name -- not the body, not "
                "attachment bytes"
            ),
        }

    return _guard("get_case_record", work)


# --------------------------------------------------------------------------
# F2: the thin stdio wrapper
# --------------------------------------------------------------------------


def tool_analyze_eml(path: str) -> dict:
    return analyze_eml(path)


def tool_analyze_eml_directory(path: str) -> dict:
    return analyze_eml_directory(path)


def tool_explain_verdict(reference: str, case_dir: str | None = None) -> dict:
    return explain_verdict(reference, case_dir)


def tool_check_auth(path: str) -> dict:
    return check_auth(path)


def tool_lookalike_domain(domain: str) -> dict:
    return lookalike_domain(domain)


def tool_analyze_urls(urls: list, sender_domain: str | None = None) -> dict:
    return analyze_urls(urls, sender_domain)


def tool_classify_local(path: str) -> dict:
    return classify_local(path)


def tool_list_contracts() -> dict:
    return list_contracts()


def tool_get_case_record(reference: str, case_dir: str | None = None) -> dict:
    return get_case_record(reference, case_dir)


#: ``(tool name -> wrapper)``. The wrappers exist so the MCP layer validates a
#: real signature per tool while the logic above stays importable and testable
#: with nothing installed. Every tool in :data:`TOOL_ORDER` must have one, and
#: :func:`build_server` refuses to start a partial surface.
MCP_WRAPPERS: dict[str, Callable[..., dict]] = {
    "analyze_eml": tool_analyze_eml,
    "analyze_eml_directory": tool_analyze_eml_directory,
    "explain_verdict": tool_explain_verdict,
    "check_auth": tool_check_auth,
    "lookalike_domain": tool_lookalike_domain,
    "analyze_urls": tool_analyze_urls,
    "classify_local": tool_classify_local,
    "list_contracts": tool_list_contracts,
    "get_case_record": tool_get_case_record,
}


def _fastmcp_class() -> Any:
    """The server class this version of ``mcp`` supplies, or :class:`McpUnavailable`.

    The only import of ``mcp`` anywhere in the package, and it is inside a
    function: importing this module -- for the CLI, for the tests, for a library
    caller who installed with ``--no-deps`` -- must never require the dependency.

    Two locations, because the library moved the class and the pinned extra
    accepts both majors: ``mcp.server.fastmcp.FastMCP`` is the 1.x home, and
    ``mcp.server.mcpserver.MCPServer`` is what 2.x calls it (the 2.x
    ``mcp.server.fastmcp`` stub raises ``ModuleNotFoundError`` with a migration
    note, which is an ``ImportError``, so the first branch fails cleanly into the
    second). The wrapper only uses ``tool(name=, description=)``, ``run(transport
    =)`` and the ``name``/``instructions`` attributes, which are the same shape in
    both. Trying the modern location second rather than first is deliberate: a
    machine with 1.x installed must not be told to upgrade in order to run a
    server that works there today.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as first_error:
        try:
            from mcp.server.mcpserver import MCPServer as FastMCP
        except ImportError as second_error:
            raise McpUnavailable(
                "the MCP server needs the `mcp` package, and neither import "
                f"location this wrapper understands resolved: "
                f"mcp.server.fastmcp ({first_error}) and "
                f"mcp.server.mcpserver ({second_error}).\n\n{INSTALL_HINT}"
            ) from second_error
    return FastMCP


def build_server(name: str = SERVER_NAME, instructions: str | None = None) -> Any:
    """A server with all nine read-only tools registered, for the stdio transport.

    Registration is explicit per tool rather than generated, because a wrapper
    that silently went missing would leave the listing advertising a tool that
    does not exist. That is the same drift this repository runs a validator
    against for stages and providers, so the tool surface gets the same check:
    the advertised set, the registered set and the served set have to agree.
    """
    fastmcp = _fastmcp_class()
    app = fastmcp(name, instructions=instructions or SERVER_INSTRUCTIONS)
    for tool_name in TOOL_ORDER:
        wrapper = MCP_WRAPPERS.get(tool_name)
        if wrapper is None:
            raise McpUnavailable(
                f"tool {tool_name!r} is advertised but has no wrapper; refusing "
                "to serve a partial surface"
            )
        app.tool(name=tool_name, description=TOOL_DESCRIPTIONS[tool_name])(wrapper)
    served = registered_tool_names(app)
    if served and set(served) != set(TOOL_ORDER):
        raise McpUnavailable(
            f"registered {sorted(served)} but advertises {sorted(TOOL_ORDER)}; "
            "the served surface and the advertised surface must be the same set"
        )
    return app


def registered_tool_names(app: Any) -> tuple[str, ...]:
    """Best-effort list of the tool names ``app`` is serving.

    Reads whichever tool manager this version of the library keeps, through
    whichever attribute and accessor it exposes, and returns an empty tuple when
    none of them are there. It exists so a test -- and an operator -- can prove
    the advertised surface is the served one without hard-coding a private
    attribute name that a library release will change.
    """
    for attribute in ("_tool_manager", "tool_manager"):
        manager = getattr(app, attribute, None)
        if manager is None:
            continue
        for accessor in ("list_tools", "get_tools"):
            listing = getattr(manager, accessor, None)
            if not callable(listing):
                continue
            try:
                tools = listing()
            except TypeError:
                continue
            names: list[str] = []
            for tool in tools:
                name = getattr(tool, "name", None)
                if name is None and isinstance(tool, Mapping):
                    name = tool.get("name")
                if name:
                    names.append(str(name))
            if names:
                return tuple(names)
    return ()


def tools_payload() -> list[dict[str, Any]]:
    """The advertised surface, as data. Works with ``mcp`` not installed."""
    return [
        {
            "name": name,
            "description": TOOL_DESCRIPTIONS[name],
            "arguments": TOOL_ARGUMENTS.get(name, {}),
            "mutates": False,
        }
        for name in TOOL_ORDER
    ]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tenable-email-mcp",
        description=(
            "Start the read-only MCP server for local-first phishing triage "
            "(stdio). Needs the optional extra: pip install -e .[mcp]"
        ),
    )
    parser.add_argument(
        "--name", default=SERVER_NAME, help="server name a client displays"
    )
    parser.add_argument(
        "--list-tools", action="store_true",
        help=(
            "print the tool surface as JSON and exit. Works with the mcp extra "
            "NOT installed, so a reviewer can check the promise before "
            "installing anything"
        ),
    )
    parser.add_argument(
        "--version", action="store_true", help="print the package version and exit"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Console script and ``python3 -m tenable_email.mcpserver``.

    A missing extra is a message, not a traceback. The reader has just typed the
    documented command on a machine that carries only the dependency-free core,
    and ``ModuleNotFoundError`` tells them nothing about the fix while
    ``pip install -e .[mcp]`` tells them everything.
    """
    args = build_arg_parser().parse_args(list(argv) if argv is not None else None)
    if args.version:
        from . import __version__

        print(f"tenable-email {__version__}")
        return 0
    if args.list_tools:
        print(
            json.dumps(
                {"server": args.name, "transport": "stdio", "tools": tools_payload()},
                indent=2, sort_keys=True,
            )
        )
        return 0
    try:
        app = build_server(name=args.name)
    except McpUnavailable as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    try:
        app.run(transport="stdio")
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        print("interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(main(sys.argv[1:]))
