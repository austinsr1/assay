"""Verdict assembly: signals in, disposition out, provenance attached.

The reference playbook emits one JSON object per message --
``{id, subject, sender, reported_by, verdict, analysis, reasons[], confidence}``
-- and this module produces that shape and nothing stranger. Three additions the
reference does not have:

* **A band derived from the float, not a float replacing it.** ``confidence`` is
  a number we can threshold and measure against; ``confidence_band`` is the
  ``high`` / ``medium`` / ``low`` vocabulary the reference and a human reviewer
  both speak. The cut points are configuration (:class:`~tenable_email.config.
  Thresholds`), never literals in the decision code.
* **``MANUAL_REVIEW`` as a real disposition.** The reference has three verdicts
  and pushes anything it finds ambiguous into one of them. An escalation band is
  a distinct outcome, and it is the one that a measured false-positive rate can
  be reported against.
* **The evidence record travels with the verdict.** A disposition that cannot
  name the findings behind it is an opinion, so :class:`Verdict` carries the
  :class:`~tenable_email.evidence.Evidence` it was built from and the keys it
  cites. Unknowns and unavailable tiers stay in the record and never enter the
  citation list -- that is enforced by ``Evidence.assert_citable()``.

Serialization is the leak surface. ``to_json()`` writes the evidence record,
which includes an attachment *inventory*; it must never write attachment
*bytes*. :class:`~tenable_email.parse.Attachment.without_data` is the only form
used, and a test asserts the word ``"data"`` and the fixture's own bytes are
absent from the output.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from .config import DEFAULT_THRESHOLDS, Thresholds
from .evidence import Evidence, Finding

__all__ = [
    "AttackType",
    "ConfidenceBand",
    "Disposition",
    "Verdict",
    "band_for",
]


class Disposition(str, enum.Enum):
    """What we conclude about one reported message.

    The first three values are the reference taxonomy verbatim, so a comparison
    against the published playbook is a comparison of like for like.
    ``MANUAL_REVIEW`` is the escalation band -- the reference has no way to say
    "the deterministic layer cannot settle this" without guessing. ``UNKNOWN``
    is reserved for messages that could not be parsed or evidenced at all; it is
    not a softer word for "clean".
    """

    THREAT = "threat"
    SPAM = "spam"
    CLEAN = "clean"
    MANUAL_REVIEW = "manual_review"
    UNKNOWN = "unknown"


class ConfidenceBand(str, enum.Enum):
    """The reference's three-word confidence vocabulary, derived from the float."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AttackType(str, enum.Enum):
    """What kind of harm the message appears to want.

    ``NONE`` means "no attack indicated", ``UNCLASSIFIED`` means "something is
    wrong but the deterministic layer cannot name it". Collapsing the two would
    lose the distinction between a clean information message and an
    unrecognized one, which is exactly the distinction a reviewer checks.
    """

    NONE = "NONE"
    CREDENTIAL_HARVEST = "CREDENTIAL_HARVEST"
    MALWARE = "MALWARE"
    BEC = "BEC"
    SPAM = "SPAM"
    AGENT_MANIPULATION = "AGENT_MANIPULATION"
    UNCLASSIFIED = "UNCLASSIFIED"


#: Dispositions that route to a person rather than to an action.
ESCALATING = frozenset({Disposition.MANUAL_REVIEW, Disposition.UNKNOWN})


def band_for(
    confidence: float, thresholds: Thresholds = DEFAULT_THRESHOLDS
) -> ConfidenceBand:
    """Map a float confidence onto the reference's band vocabulary.

    Both cut points come from configuration so a cascade threshold can be
    selected against a measured accuracy target without editing this function.
    """
    c = max(0.0, min(1.0, float(confidence)))
    if c >= thresholds.band_high:
        return ConfidenceBand.HIGH
    if c >= thresholds.band_medium:
        return ConfidenceBand.MEDIUM
    return ConfidenceBand.LOW


@dataclass
class Verdict:
    """One dispositioned message.

    Field order follows the reference's output contract, then the additions.
    ``reported_by`` is the user who reported the message where that is known:
    for a forwarded report the outer ``From`` is the reporting user and the
    inner message is what gets triaged, so the two fields genuinely differ.
    """

    id: str = ""
    subject: str = ""
    sender: str = ""
    reported_by: str = ""

    disposition: Disposition = Disposition.UNKNOWN
    confidence: float = 0.0
    confidence_band: ConfidenceBand = ConfidenceBand.LOW
    attack_type: AttackType = AttackType.NONE

    reasons: list[str] = field(default_factory=list)
    analysis: str = ""
    evidence: Evidence = field(default_factory=Evidence)

    truncated: bool = False
    escalated: bool = False
    stages_run: list[str] = field(default_factory=list)

    #: Keys of the findings this disposition rests on. Kept as keys rather than
    #: finding objects so the verdict serializes without holding the record
    #: twice; :meth:`cited` resolves them against the evidence.
    cited_findings: list[str] = field(default_factory=list)

    # -- construction helpers ------------------------------------------------

    def set_confidence(
        self, confidence: float, thresholds: Thresholds = DEFAULT_THRESHOLDS
    ) -> None:
        """Set the float and re-derive the band. Always use this instead of
        assigning ``confidence`` directly, or the two disagree."""
        self.confidence = max(0.0, min(1.0, float(confidence)))
        self.confidence_band = band_for(self.confidence, thresholds)

    def add_reason(self, reason: str) -> None:
        if reason and reason not in self.reasons:
            self.reasons.append(reason)

    def cite(self, findings: Iterable[Finding]) -> None:
        """Record the keys of the findings this disposition relies on."""
        for f in findings:
            if f.key not in self.cited_findings:
                self.cited_findings.append(f.key)

    def cited(self, evidence: Evidence | None = None) -> list[Finding]:
        """Resolve :attr:`cited_findings` back to findings."""
        record = evidence if evidence is not None else self.evidence
        found: list[Finding] = []
        for key in self.cited_findings:
            found.extend(record.all(key))
        return found

    def assert_citable(self) -> None:
        """Re-check the invariant that supports this disposition.

        Called by the pipeline at assembly time and available to any consumer --
        including the offline runner, which must not close a case on a finding
        marked unknown or unavailable.
        """
        self.evidence.assert_citable(self.cited())

    # -- output -------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Reference-shaped output, with our extra fields kept alongside.

        ``verdict`` is the reference's key name and ``disposition`` is ours; both
        carry the same value. Parity with the published playbook is a stated
        goal, and a reviewer diffing our output against theirs should not have to
        rename a field to do it.
        """
        return {
            "id": self.id,
            "subject": self.subject,
            "sender": self.sender,
            "reported_by": self.reported_by,
            "verdict": self.disposition.value,
            "disposition": self.disposition.value,
            "confidence": round(self.confidence, 4),
            "confidence_band": self.confidence_band.value,
            "attack_type": self.attack_type.value,
            "reasons": list(self.reasons),
            "analysis": self.analysis,
            "truncated": self.truncated,
            "escalated": self.escalated,
            "stages_run": list(self.stages_run),
            "cited_findings": list(self.cited_findings),
            "evidence": self.evidence.as_dict(),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize the verdict.

        No ``default=`` fallback on purpose: a fallback would silently stringify
        a stray ``bytes`` value into the output, which is precisely the leak this
        method exists to prevent. If something unserializable appears here, the
        call raises and the bug is caught in a test rather than in a review.
        """
        return json.dumps(self.to_dict(), indent=indent)
