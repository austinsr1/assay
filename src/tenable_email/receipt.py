"""The receipt contract: one durable record per dispositioned message.

A verdict answers "what did we conclude?". A receipt answers the question an
auditor asks afterwards: "what exactly did you have when you concluded it, and
who agreed to act on it?". It is the artifact the offline runner transitions on,
the thing an approval binds to, and the record a reviewer reads without running
anything.

Shape, and why each piece is there:

* ``receipt_id`` -- derived from content (source name + verdict digest + corpus
  manifest digest), so re-running the same message over the same corpus yields
  the same id. An id that changed between runs would make a journal unresumable
  and a replayed approval undetectable.
* ``source`` -- the message's **file name, never its directory**. A receipt is
  written to shipped output, and a local path is infrastructure detail; the
  evidence record already made this rule for findings and a receipt must not be
  the one place it leaks.
* ``verdict_digest`` -- sha256 over the canonical JSON of ``Verdict.to_dict()``.
  This is what an approval signs. If anything about the verdict or the evidence
  behind it changes, the digest changes, and the approval stops matching.
* ``corpus_manifest_digest`` -- sha256 over the fixture/label manifest the case
  was drawn from. A receipt recorded against one corpus must not be closed
  against another, which is how a relabelled corpus silently "passes".
* ``stages_run`` / ``completed_stages`` / ``skipped_stages`` -- the chain as it
  actually went, with skips carrying a reason. Optional, because a stage that
  was never configured is not a stage that failed.
* ``proposed_actions`` / ``approval`` / ``approval_state`` / ``execution`` -- the
  write side, gated. ``execution`` records what a provider did or would have
  done; with the shipped non-mutating provider it is a list of intentions, which
  is the honest content for a demo.
* timestamps -- wall clock, recorded, never fed into any digest.

What a receipt never contains: **attachment bytes or message bodies.** Not as a
policy statement -- as a construction rule. The evidence record is stored as
provenance, source, our own detail prose, and a *digest of each finding's value*,
so the record can prove it saw something without reproducing it. The reasons and
the narrative are our analysis text, quoted from the record rather than copied
from the message. There is a test on ``tests/test_receipt.py`` that rebuilds a
fixture body and checks it is absent, and another that no ``data`` key appears at
any depth.

The limit, stated the way the first-place playbook states its own: a receipt
proves structure and consistency. It does not authenticate the human who
approved, and it cannot attest that a tool which wrote a dishonest record was
told the truth. ``to_markdown()`` is therefore a review document, not evidence
that review happened.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .evidence import Evidence, Finding, Provenance
from .replay import canonical_json
from .verdict import Disposition, Verdict
from .writeback import Approval, ProposedAction

__all__ = [
    "APPROVAL_CONSUMED",
    "APPROVAL_GRANTED",
    "APPROVAL_NOT_REQUIRED",
    "APPROVAL_PENDING",
    "COMPLETENESS_CLAIMING",
    "EvidenceItem",
    "NO_MANIFEST",
    "Receipt",
    "ReceiptError",
    "RECEIPT_SUFFIX",
    "SCHEMA_VERSION",
    "STATE_CLOSED",
    "STATE_OPENED",
    "corpus_manifest",
    "default_actions",
    "evidence_items",
    "format_line",
    "file_sha256",
    "make_receipt_id",
    "source_name",
    "summarise",
    "text_sha256",
    "verdict_digest",
]

#: Bumped when the record shape changes. A reader refuses a record it cannot
#: name a version of, rather than guessing at fields.
SCHEMA_VERSION = 1

#: File-name suffix for a written case record, and the extension ``show`` reads.
RECEIPT_SUFFIX = ".receipt.json"

STATE_OPENED = "opened"
STATE_CLOSED = "closed"

#: The manifest label and digest used when a run has no corpus manifest at all.
#: An empty digest means "nothing to compare against", and the runner says so
#: instead of refusing every transition.
NO_MANIFEST = "none"

#: Dispositions that assert we finished reading and decided. A truncated verdict
#: may escalate honestly; it may not claim one of these and be closed.
COMPLETENESS_CLAIMING = frozenset(
    {Disposition.THREAT, Disposition.SPAM, Disposition.CLEAN}
)

APPROVAL_PENDING = "pending"
APPROVAL_GRANTED = "granted"
APPROVAL_CONSUMED = "consumed"
APPROVAL_NOT_REQUIRED = "not-required"


class ReceiptError(ValueError):
    """A receipt that cannot be built, read or written -- a bug, not a refusal.

    Refusals to *advance* a case are values (:class:`~tenable_email.runner.
    Refusal`). This type is for a record that is structurally impossible: a
    receipt source that arrived as an absolute path, a saved record from a schema
    this build does not understand.
    """


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_sha256(path: str | Path) -> str:
    return text_sha256(Path(path).read_bytes().decode("utf-8", "replace"))


def verdict_digest(verdict: Verdict) -> str:
    """The content address of a verdict.

    Canonical JSON -- sorted keys, no incidental whitespace -- so the digest is a
    property of the *decision*, not of dict ordering or pretty-printing. This is
    the same canonicalization the replay store keys on, which is what makes
    "approve this verdict" and "replay this answer" speak the same identity.
    """
    return text_sha256(canonical_json(verdict.to_dict()))


def _value_digest(value: Any) -> str:
    """Digest one finding's value, or name why it could not be digested.

    ``canonical_json`` is strict and raises on a ``bytes`` value rather than
    stringifying it. That is the right behaviour for a key and the right
    behaviour here too, with one addition: a record must not be unwritable
    because some stage attached raw bytes to a finding. The fallback records the
    *type* and nothing of the content, so the gap is visible and the leak is not.
    """
    if value is None:
        return "none"
    try:
        return text_sha256(canonical_json(value))
    except (TypeError, ValueError):
        return f"undigestable:{type(value).__name__}"


def source_name(source: str) -> str:
    """The file name a message came from, with no directory attached.

    ``"inline"`` is a legitimate source for a message supplied from bytes and is
    passed through; anything else is reduced to its last component. An absolute
    path reaching a receipt would put a build host's directory layout into a
    published artifact, which operating rule 15 forbids and this function makes
    hard to do by accident.
    """
    if not source:
        return "unknown"
    if source == "inline":
        return source
    name = Path(source).name
    if not name:
        raise ReceiptError(f"cannot derive a file name from source {source!r}")
    return name


def _source_of(verdict: Verdict) -> str:
    """Where this message came from, taken from the record that already scrubbed it."""
    for finding in verdict.evidence.all("intake"):
        value = finding.value
        if isinstance(value, Mapping) and value.get("source"):
            return source_name(str(value["source"]))
    if verdict.id:
        return source_name(str(verdict.id))
    return "unknown"


def corpus_manifest(
    manifest_path: str | Path | None = None,
    corpus_dir: str | Path | None = None,
) -> tuple[str, str]:
    """``(label, digest)`` for the corpus a case was drawn from.

    The manifest is the label file: it is what makes "this message is a threat"
    a claim with a source, and editing it is exactly the tampering the runner
    refuses to close on. With no manifest at all the digest is empty and the
    runner treats that as *no comparison*, never as agreement.

    With no manifest but a corpus directory, the digest covers a sorted listing
    of file names and content hashes. That is a weaker claim than a label file --
    it detects a changed corpus, not a changed ground truth -- and the label
    ``listing:`` says which one a reader is looking at.
    """
    if manifest_path is not None:
        path = Path(manifest_path)
        if path.is_file():
            return path.name, file_sha256(path)
    if corpus_dir is not None:
        root = Path(corpus_dir)
        if root.is_dir():
            rows = sorted(
                (
                    {"name": p.name, "sha256": file_sha256(p)}
                    for p in root.glob("*.eml")
                    if p.is_file()
                ),
                key=lambda row: row["name"],
            )
            if rows:
                return f"listing:{root.name}", text_sha256(canonical_json(rows))
    return NO_MANIFEST, ""


def make_receipt_id(
    *, source: str, digest: str, manifest_digest: str, schema_version: int = SCHEMA_VERSION
) -> str:
    """A stable identifier, derived only from content.

    Timestamps are excluded on purpose: a receipt written twice by a resumed run
    has to arrive at the same id, or "resumable" would mean "duplicated".
    """
    material = canonical_json(
        {
            "schema_version": schema_version,
            "source": source,
            "verdict_digest": digest,
            "corpus_manifest_digest": manifest_digest,
        }
    )
    return f"rcpt-{text_sha256(material)[:16]}"


@dataclass(frozen=True)
class EvidenceItem:
    """One finding, as a receipt can honestly carry it.

    Provenance, the stage that produced it, the detail line that explains it --
    and a digest instead of the value. That is what lets :func:`show` print the
    record grouped by provenance without shipping the message inside the record.
    """

    key: str
    provenance: str
    source: str
    detail: str = ""
    value_digest: str = ""

    def supports_verdict(self) -> bool:
        try:
            return Provenance(self.provenance) in (
                Provenance.VERIFIED,
                Provenance.MODEL_JUDGMENT,
            )
        except ValueError:
            return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "provenance": self.provenance,
            "source": self.source,
            "detail": self.detail,
            "value_digest": self.value_digest,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceItem":
        return cls(
            key=str(data.get("key") or ""),
            provenance=str(data.get("provenance") or ""),
            source=str(data.get("source") or ""),
            detail=str(data.get("detail") or ""),
            value_digest=str(data.get("value_digest") or ""),
        )

    @classmethod
    def of(cls, finding: Finding) -> "EvidenceItem":
        return cls(
            key=finding.key,
            provenance=finding.provenance.value,
            source=finding.source,
            detail=finding.detail,
            value_digest=_value_digest(finding.value),
        )


def evidence_items(evidence: Evidence) -> list[EvidenceItem]:
    return [EvidenceItem.of(f) for f in evidence.findings]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Receipt:
    """The durable record for one message."""

    receipt_id: str
    source: str
    case: str = ""
    message_id: str = ""
    subject: str = ""
    sender: str = ""
    reported_by: str = ""

    disposition: str = Disposition.UNKNOWN.value
    confidence: float = 0.0
    confidence_band: str = "low"
    attack_type: str = "NONE"
    escalated: bool = False
    truncated: bool = False
    simulated: bool = False
    original_length: int | None = None

    verdict_digest: str = ""
    corpus_manifest: str = NO_MANIFEST
    corpus_manifest_digest: str = ""
    contract_version: int = 1

    stages_run: list[str] = field(default_factory=list)
    completed_stages: list[str] = field(default_factory=list)
    skipped_stages: list[dict[str, str]] = field(default_factory=list)
    cited_findings: list[str] = field(default_factory=list)

    reasons: list[str] = field(default_factory=list)
    analysis: str = ""
    evidence: list[EvidenceItem] = field(default_factory=list)

    proposed_actions: list[ProposedAction] = field(default_factory=list)
    approval: Approval | None = None
    approval_state: str = APPROVAL_PENDING
    execution: list[dict[str, Any]] = field(default_factory=list)

    state: str = STATE_OPENED
    schema_version: int = SCHEMA_VERSION
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    closed_at: str = ""

    # -- construction --------------------------------------------------------

    @classmethod
    def for_verdict(
        cls,
        verdict: Verdict,
        *,
        source: str | None = None,
        manifest_path: str | Path | None = None,
        corpus_dir: str | Path | None = None,
        proposed_actions: Sequence[ProposedAction] | None = None,
        contract_version: int = 1,
        now: str | None = None,
    ) -> "Receipt":
        """Build the record for one verdict, with the digests that bind it."""
        who = source_name(source) if source else _source_of(verdict)
        digest = verdict_digest(verdict)
        label, manifest_digest = corpus_manifest(manifest_path, corpus_dir)
        stamp = now or _now_iso()
        actions = (
            list(proposed_actions)
            if proposed_actions is not None
            else default_actions(verdict, who)
        )
        return cls(
            receipt_id=make_receipt_id(
                source=who, digest=digest, manifest_digest=manifest_digest
            ),
            source=who,
            case=verdict.id or Path(who).stem,
            message_id=_first_message_id(verdict),
            subject=verdict.subject,
            sender=verdict.sender,
            reported_by=verdict.reported_by,
            disposition=verdict.disposition.value,
            confidence=round(float(verdict.confidence), 4),
            confidence_band=verdict.confidence_band.value,
            attack_type=verdict.attack_type.value,
            escalated=bool(verdict.escalated),
            truncated=bool(verdict.truncated),
            simulated=bool(verdict.evidence.simulated),
            original_length=verdict.evidence.original_length,
            verdict_digest=digest,
            corpus_manifest=label,
            corpus_manifest_digest=manifest_digest,
            contract_version=contract_version,
            stages_run=list(verdict.stages_run),
            cited_findings=list(verdict.cited_findings),
            reasons=list(verdict.reasons),
            analysis=verdict.analysis,
            evidence=evidence_items(verdict.evidence),
            proposed_actions=actions,
            approval_state=APPROVAL_PENDING if actions else APPROVAL_NOT_REQUIRED,
            state=STATE_OPENED,
            created_at=stamp,
            updated_at=stamp,
        )

    # -- digests -------------------------------------------------------------

    def digest_matches(self, verdict: Verdict) -> bool:
        return self.verdict_digest == verdict_digest(verdict)

    def manifest_matches(self, label: str, digest: str) -> bool:
        """Whether a corpus is the corpus this record was made against.

        An empty recorded digest means there was no manifest to record, which is
        *not* a mismatch -- it is the honest "nothing to compare" case, and the
        receipt says so in :meth:`to_markdown`.
        """
        if not self.corpus_manifest_digest:
            return True
        return (
            self.corpus_manifest_digest == digest
            and self.corpus_manifest == label
        )

    # -- closure -------------------------------------------------------------

    @property
    def claims_completeness(self) -> bool:
        try:
            return Disposition(self.disposition) in COMPLETENESS_CLAIMING
        except ValueError:
            return False

    def gap_findings(self) -> list[EvidenceItem]:
        return [item for item in self.evidence if not item.supports_verdict()]

    def cited_items(self) -> list[EvidenceItem]:
        """Every finding this record cites, resolved by key.

        Keyed rather than positional, because that is what a verdict stores; a
        key that resolves to more than one finding returns all of them, which is
        the strict reading -- if any finding under a cited key is a gap, the
        disposition is resting on a hole.
        """
        return [item for item in self.evidence if item.key in set(self.cited_findings)]

    def closure_blockers(self) -> list[str]:
        """Every reason this record may not be closed, named specifically.

        The four checks are the receipt contract's, and each one is the answer to
        a way a case gets closed that should not be:

        * ``simulated`` -- something in here was authored, not observed. Closing
          on it would present a fabrication as a completed investigation, which
          is the failure the first-place SWARM runner refuses by name.
        * a cited gap -- the disposition rests on an unknown or an unavailable
          tier. The pipeline already refuses to *issue* such a verdict; this is
          the second gate, for a record built or edited outside the pipeline.
        * ``UNKNOWN`` -- we could not read the message. It is not a soft clean.
        * truncated while claiming completeness -- a partial reading reported as
          a finished one. An escalation on a truncated verdict is honest ("I only
          read part of it, a person must"), a clearance is not.
        """
        blockers: list[str] = []
        if self.simulated:
            causes = [
                item.detail for item in self.evidence
                if item.key == "simulated_evidence" and item.detail
            ]
            blockers.append(
                "simulated evidence: this record contains an answer that was "
                "authored rather than observed, so it cannot close as a finding "
                + (
                    f" ({'; '.join(causes[:3])})"
                    if causes
                    else "(no specific cause was recorded on the finding)"
                )
            )
        for item in self.cited_items():
            if not item.supports_verdict():
                blockers.append(
                    f"cited finding {item.key!r} has provenance "
                    f"{item.provenance} and cannot support a closed disposition "
                    f"(stage {item.source})"
                )
        if self.disposition == Disposition.UNKNOWN.value:
            blockers.append(
                "disposition is UNKNOWN: a message that could not be read does "
                "not close, it goes to a person with the parse failure attached"
            )
        if self.truncated and self.claims_completeness:
            length = (
                f" of {self.original_length}" if self.original_length else ""
            )
            blockers.append(
                f"truncated verdict claimed complete: the analysis is a partial "
                f"reading (body retained{length}) and {self.disposition} asserts "
                "that the message was settled"
            )
        return blockers

    def is_closed(self) -> bool:
        return self.state == STATE_CLOSED

    # -- transition plumbing (used by the runner) ----------------------------

    def touch(self, now: str | None = None) -> None:
        self.updated_at = now or _now_iso()

    def stage_is_done(self, stage_id: str) -> bool:
        return stage_id in self.completed_stages or any(
            s.get("id") == stage_id for s in self.skipped_stages
        )

    # -- serialization -------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "state": self.state,
            "source": self.source,
            "case": self.case,
            "identity": {
                "message_id": self.message_id,
                "subject": self.subject,
                "sender": self.sender,
                "reported_by": self.reported_by,
            },
            "verdict": {
                "disposition": self.disposition,
                "confidence": self.confidence,
                "confidence_band": self.confidence_band,
                "attack_type": self.attack_type,
                "escalated": self.escalated,
                "truncated": self.truncated,
                "simulated": self.simulated,
                "original_length": self.original_length,
                "reasons": list(self.reasons),
                "analysis": self.analysis,
            },
            "digests": {
                "verdict": self.verdict_digest,
                "corpus_manifest": self.corpus_manifest,
                "corpus_manifest_digest": self.corpus_manifest_digest,
            },
            "chain": {
                "contract_version": self.contract_version,
                "stages_run": list(self.stages_run),
                "completed_stages": list(self.completed_stages),
                "skipped_stages": [dict(s) for s in self.skipped_stages],
                "cited_findings": list(self.cited_findings),
                "evidence": [item.as_dict() for item in self.evidence],
                "counts": self.counts(),
            },
            "writeback": {
                "proposed_actions": [a.as_dict() for a in self.proposed_actions],
                "approval": self.approval.as_dict() if self.approval else None,
                "approval_state": self.approval_state,
                "execution": [dict(e) for e in self.execution],
            },
            "timestamps": {
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "closed_at": self.closed_at,
            },
        }

    def counts(self) -> dict[str, int]:
        out = {p.value: 0 for p in Provenance}
        for item in self.evidence:
            out[item.provenance] = out.get(item.provenance, 0) + 1
        return out

    def to_json(self, *, indent: int = 2) -> str:
        """Serialize. No ``default=`` hook, same reason as :meth:`Verdict.to_json`:
        a fallback would stringify a stray ``bytes`` value into the record, and
        the leak this exists to prevent is precisely that one.
        """
        return canonical_json_indent(self.to_dict(), indent)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Receipt":
        """Read back a saved record, refusing one this build cannot understand."""
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ReceiptError(
                f"case record declares schema_version {version!r}; this build "
                f"reads {SCHEMA_VERSION}. Refusing to reinterpret a durable record."
            )
        verdict = data.get("verdict") or {}
        digests = data.get("digests") or {}
        chain = data.get("chain") or {}
        write = data.get("writeback") or {}
        stamps = data.get("timestamps") or {}
        identity = data.get("identity") or {}
        approval = write.get("approval")
        return cls(
            receipt_id=str(data.get("receipt_id") or ""),
            source=str(data.get("source") or "unknown"),
            case=str(data.get("case") or ""),
            message_id=str(identity.get("message_id") or ""),
            subject=str(identity.get("subject") or ""),
            sender=str(identity.get("sender") or ""),
            reported_by=str(identity.get("reported_by") or ""),
            disposition=str(verdict.get("disposition") or "unknown"),
            confidence=float(verdict.get("confidence") or 0.0),
            confidence_band=str(verdict.get("confidence_band") or "low"),
            attack_type=str(verdict.get("attack_type") or "NONE"),
            escalated=bool(verdict.get("escalated")),
            truncated=bool(verdict.get("truncated")),
            simulated=bool(verdict.get("simulated")),
            original_length=verdict.get("original_length"),
            verdict_digest=str(digests.get("verdict") or ""),
            corpus_manifest=str(digests.get("corpus_manifest") or NO_MANIFEST),
            corpus_manifest_digest=str(digests.get("corpus_manifest_digest") or ""),
            contract_version=int(chain.get("contract_version") or 1),
            stages_run=[str(s) for s in chain.get("stages_run") or []],
            completed_stages=[str(s) for s in chain.get("completed_stages") or []],
            skipped_stages=[
                dict(s) for s in chain.get("skipped_stages") or [] if isinstance(s, Mapping)
            ],
            cited_findings=[str(s) for s in chain.get("cited_findings") or []],
            reasons=[str(s) for s in verdict.get("reasons") or []],
            analysis=str(verdict.get("analysis") or ""),
            evidence=[
                EvidenceItem.from_dict(item)
                for item in chain.get("evidence") or []
                if isinstance(item, Mapping)
            ],
            proposed_actions=[
                ProposedAction.from_dict(a)
                for a in write.get("proposed_actions") or []
                if isinstance(a, Mapping)
            ],
            approval=Approval.from_dict(approval) if approval else None,
            approval_state=str(write.get("approval_state") or APPROVAL_PENDING),
            execution=[dict(e) for e in write.get("execution") or [] if isinstance(e, Mapping)],
            state=str(data.get("state") or STATE_OPENED),
            schema_version=int(version),
            created_at=str(stamps.get("created_at") or ""),
            updated_at=str(stamps.get("updated_at") or ""),
            closed_at=str(stamps.get("closed_at") or ""),
        )

    @classmethod
    def from_json(cls, text: str) -> "Receipt":
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ReceiptError(f"case record is not valid JSON: {exc}") from None
        if not isinstance(data, dict):
            raise ReceiptError("case record must be a JSON object")
        return cls.from_dict(data)

    @classmethod
    def load(cls, path: str | Path) -> "Receipt":
        p = Path(path)
        if not p.is_file():
            raise ReceiptError(f"no case record at {p.name}")
        return cls.from_json(p.read_text(encoding="utf-8"))

    # -- human rendering -----------------------------------------------------

    def grouped(self) -> dict[str, list[EvidenceItem]]:
        """The evidence by provenance, in the order a reviewer reads it.

        Facts first, then opinions, then the two kinds of gap, each under its own
        heading. Labelled rather than merged: the difference between "a tier did
        not run" and "this is not knowable from a message" is a difference a human
        acts on differently.
        """
        groups = {p.value: [] for p in Provenance}
        for item in self.evidence:
            groups.setdefault(item.provenance, []).append(item)
        return groups

    def to_markdown(self) -> str:
        data = self.to_dict()
        lines: list[str] = []
        add = lines.append
        add(f"# Case record {self.receipt_id}")
        add("")
        add(f"- **source**: `{self.source}` (file name only, by contract)")
        add(f"- **case**: `{self.case or '-'}`")
        if self.message_id:
            add(f"- **message-id**: `{self.message_id}`")
        add(f"- **subject**: {self.subject or '(none)'}")
        add(f"- **sender**: {self.sender or '(none)'}")
        if self.reported_by:
            add(f"- **reported by**: {self.reported_by}")
        add(
            f"- **disposition**: `{self.disposition.upper()}` at "
            f"{self.confidence:.2f} ({self.confidence_band}), attack class "
            f"`{self.attack_type}`"
        )
        add(f"- **state**: `{self.state}` | escalated: {self.escalated} | "
            f"truncated: {self.truncated} | simulated: {self.simulated}")
        add(f"- **created**: {self.created_at} | **updated**: {self.updated_at}"
            + (f" | **closed**: {self.closed_at}" if self.closed_at else ""))
        add("")
        add("## Digests")
        add("")
        add(f"- verdict digest: `{self.verdict_digest}`")
        add(
            f"- corpus manifest: `{self.corpus_manifest}`"
            + (f" -> `{self.corpus_manifest_digest}`" if self.corpus_manifest_digest
               else " (no manifest recorded: nothing to compare against)")
        )
        add(f"- contract version: {self.contract_version}")
        add("")
        add("## Chain")
        add("")
        add(f"- stages run: {', '.join(self.stages_run) or 'none'}")
        add(f"- stages completed: {', '.join(self.completed_stages) or 'none'}")
        for skipped in self.skipped_stages:
            add(
                f"- stage `{skipped.get('id')}` skipped: {skipped.get('reason')}"
            )
        add(f"- findings cited: {', '.join(self.cited_findings) or 'none'}")
        counts = data["chain"]["counts"]
        add(
            "- finding counts: "
            + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        )
        add("")
        add("## Why this disposition")
        add("")
        for reason in self.reasons:
            add(f"- {reason}")
        if self.analysis:
            add("")
            add(self.analysis)
        add("")
        add("## Evidence by provenance")
        for provenance, label in (
            ("verified", "Verified facts (observed in the message itself)"),
            ("model_judgment", "Model judgments (opinions, with their confidence)"),
            ("unknown", "Unknowns (not knowable from the message -- never facts)"),
            (
                "unavailable",
                "Unavailable (the stage that would have produced this did not run)",
            ),
        ):
            items = self.grouped().get(provenance) or []
            add("")
            add(f"### {label} -- {len(items)}")
            if not items:
                add("- (none recorded)")
                continue
            for item in items:
                cited = "cited" if item.key in self.cited_findings else "not cited"
                add(
                    f"- `{item.key}` [{cited}] from `{item.source}`: "
                    f"{item.detail or '(no detail)'} | value digest "
                    f"`{item.value_digest[:16] or '-'}`"
                )
        add("")
        add("## Proposed actions (write stage -- human approval required)")
        add("")
        if not self.proposed_actions:
            add("- none: this disposition proposes no outward mutation")
        for action in self.proposed_actions:
            add(
                f"- `{action.kind}` on `{action.target}`: {action.summary} "
                f"-- {action.rationale}"
            )
        add("")
        add(f"- approval state: `{self.approval_state}`")
        if self.approval:
            approval = self.approval
            add(
                f"- approved by `{approval.approver}` at {approval.granted_at} "
                f"for verdict `{approval.verdict_digest[:16]}`..., targets "
                f"{', '.join(approval.targets)}, actions "
                f"{', '.join(approval.actions)}, token {approval.token}"
            )
        if self.execution:
            add("- provider results:")
            for entry in self.execution:
                add(
                    f"  - `{entry.get('kind')}` on `{entry.get('target')}` via "
                    f"`{entry.get('provider')}`: performed="
                    f"{entry.get('performed')} -- {entry.get('detail')}"
                )
        else:
            add("- provider results: none (nothing was executed)")
        add("")
        add("## Closure")
        add("")
        blockers = self.closure_blockers()
        if blockers:
            add(f"- may not close ({len(blockers)} reason(s)):")
            for blocker in blockers:
                add(f"  - {blocker}")
        else:
            add("- no closure blocker outstanding")
        if self.state == STATE_CLOSED:
            add(f"- closed at {self.closed_at or '(unrecorded)'}")
        add("")
        add(
            "This record proves structure, not identity: it cannot authenticate "
            "the approver or attest that a tool wrote it honestly. See "
            "src/tenable_email/receipt.py."
        )
        add("")
        return "\n".join(lines)


def canonical_json_indent(data: Mapping[str, Any], indent: int = 2) -> str:
    """Pretty JSON that is still deterministic.

    ``canonical_json`` has no indentation because it is hash material. A saved
    record is read by humans and diffed by git, so it gets newlines and sorted
    keys -- and sorted keys matter here too: two runs must produce the same file.
    """
    if indent in (None, 0):
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
    return json.dumps(data, sort_keys=True, indent=indent) + "\n"


def default_actions(verdict: Verdict, target: str) -> list[ProposedAction]:
    """The mutations a verdict implies. Imported lazily to keep this module's
    dependency direction one-way (receipt -> writeback, never back)."""
    from .writeback import proposed_actions

    return proposed_actions(verdict, target=target)


def _first_message_id(verdict: Verdict) -> str:
    for finding in verdict.evidence.all("message_id"):
        if isinstance(finding.value, str):
            return finding.value.strip().strip("<>")
    return ""


def summarise(receipts: Iterable[Receipt]) -> dict[str, int]:
    """Counts per disposition, for a summary table."""
    out: dict[str, int] = {}
    for receipt in receipts:
        out[receipt.disposition] = out.get(receipt.disposition, 0) + 1
    return out


def format_line(receipt: Receipt, *, width: int = 38) -> str:
    """The one-line-per-message form the CLI prints."""
    name = receipt.source
    label = name[:-4] if name.endswith(".eml") else name
    return (
        f"{label:<{width}} {receipt.disposition:<13} "
        f"{receipt.confidence:>4.2f} {receipt.confidence_band:<6} "
        f"{receipt.attack_type:<18} {receipt.state}"
    )
