"""Evidence model.

The central invariant of this project: an investigation record must keep
verified facts, model judgments, and unknowns separate, and no stage may
promote an unknown into a fact.

This is not stylistic. The reference playbook's prompt treats a link destination
matching the sender's domain as "a strong indicator of a clean email", which
collapses an inference into a fact and breaks on business email compromise --
a compromised legitimate account sends mail with valid DKIM whose links point at
its own domain. Keeping provenance explicit makes that class of error
representable, and therefore testable.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator


class Provenance(str, enum.Enum):
    """Where a finding came from, and therefore how much weight it carries."""

    VERIFIED = "verified"
    """Deterministically observed in the message itself. Reproducible: the same
    bytes always yield the same finding. Authentication-Results parsing, URL
    extraction, attachment inventory, header presence, edit distance."""

    MODEL_JUDGMENT = "model_judgment"
    """A model's opinion. May be right, may be wrong, and carries a score.
    Classifier verdicts, LLM reasoning, visual impression of an image."""

    UNKNOWN = "unknown"
    """Explicitly not known, and recorded as such rather than defaulted.
    Whether an account was compromised, whether a recipient entered
    credentials, whether an unexamined attachment is malicious."""

    UNAVAILABLE = "unavailable"
    """The stage that would have produced this did not run or failed. Distinct
    from UNKNOWN: here we know which check is missing, so a consumer can decide
    whether the gap is tolerable."""


#: Provenances that may support a disposition. UNKNOWN and UNAVAILABLE may not.
SUPPORTING = frozenset({Provenance.VERIFIED, Provenance.MODEL_JUDGMENT})


class EvidenceError(RuntimeError):
    """Raised when an evidence operation would break an invariant."""


@dataclass(frozen=True)
class Finding:
    """A single observation with its provenance and the stage that produced it."""

    key: str
    value: Any
    provenance: Provenance
    source: str
    detail: str = ""

    def supports_verdict(self) -> bool:
        """Whether this finding may be cited in support of a disposition."""
        return self.provenance in SUPPORTING

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "provenance": self.provenance.value,
            "source": self.source,
            "detail": self.detail,
        }


@dataclass
class Evidence:
    """An append-only record of findings about one message.

    Append-only by design. A stage that disagrees with an earlier stage adds a
    finding; it does not overwrite one. Overwriting is how an inference silently
    becomes a fact.
    """

    findings: list[Finding] = field(default_factory=list)

    #: Set when input was truncated before analysis. A truncated record must
    #: never be reported as complete -- see the reference playbook's
    #: ``<TRUNCATED/>`` convention, which our predecessor engine lacked.
    truncated: bool = False
    original_length: int | None = None

    #: Set when something in this record was authored rather than observed: a
    #: hand-written recording, a stubbed tier, a canned answer. The offline runner
    #: refuses to close a case on simulated evidence, following the 1st-place
    #: SWARM playbook's receipt contract.
    #:
    #: A replayed recording does **not** set this. It is a real model's answer to
    #: this exact request, captured by a live call and written by the replay
    #: store; :meth:`mark_simulated` is reached only when the store cannot attest
    #: to a recording, or when a caller supplies an answer it built itself. Set
    #: that flag on replay and every offline receipt becomes unclosable, which is
    #: how a mechanism meant to catch fabrication ends up catching the reviewer.
    simulated: bool = False

    def add(
        self,
        key: str,
        value: Any,
        provenance: Provenance,
        source: str,
        detail: str = "",
    ) -> Finding:
        f = Finding(
            key=key,
            value=value,
            provenance=provenance,
            source=source,
            detail=detail,
        )
        self.findings.append(f)
        return f

    def verified(self, key: str, value: Any, source: str, detail: str = "") -> Finding:
        return self.add(key, value, Provenance.VERIFIED, source, detail)

    def judgment(self, key: str, value: Any, source: str, detail: str = "") -> Finding:
        return self.add(key, value, Provenance.MODEL_JUDGMENT, source, detail)

    def unknown(self, key: str, source: str, detail: str = "") -> Finding:
        """Record that something is not known.

        The value is deliberately ``None``. An unknown has no value; giving it
        one is how it becomes a fact by accident.
        """
        return self.add(key, None, Provenance.UNKNOWN, source, detail)

    def unavailable(self, key: str, source: str, detail: str = "") -> Finding:
        return self.add(key, None, Provenance.UNAVAILABLE, source, detail)

    def mark_simulated(self, source: str, reason: str) -> Finding:
        """Flag that part of this record was authored rather than observed.

        ``simulated`` is what the offline runner refuses closure on, so setting it
        correctly matters in both directions. A **replayed** model answer is not
        simulated: it is the answer a real model gave to this exact request, and
        refusing it would refuse the only offline path a reviewer can run. What
        *is* simulated is a response nobody observed -- a hand-written recording,
        a stubbed tier, a default an operator typed in. Those are recorded here as
        an explicit unknown, because "this answer has no provenance" is a hole in
        the record and not a finding about the message.
        """
        self.simulated = True
        return self.unknown("simulated_evidence", source, reason)

    # -- queries ---------------------------------------------------------

    def all(self, key: str) -> list[Finding]:
        return [f for f in self.findings if f.key == key]

    def supporting(self) -> list[Finding]:
        """Findings that may be cited in support of a disposition."""
        return [f for f in self.findings if f.supports_verdict()]

    def gaps(self) -> list[Finding]:
        """Findings that are unknown or unavailable -- the record's holes."""
        return [
            f
            for f in self.findings
            if f.provenance in (Provenance.UNKNOWN, Provenance.UNAVAILABLE)
        ]

    def by_provenance(self, provenance: Provenance) -> list[Finding]:
        return [f for f in self.findings if f.provenance is provenance]

    def has_verified(self, key: str) -> bool:
        return any(
            f.key == key and f.provenance is Provenance.VERIFIED for f in self.findings
        )

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    # -- invariant enforcement -------------------------------------------

    def assert_citable(self, findings: Iterable[Finding]) -> None:
        """Raise if any finding in ``findings`` may not support a verdict.

        Called by the disposition stage. This is the enforcement point for the
        rule that an unknown never becomes a fact: a verdict that tries to cite
        one fails loudly instead of being quietly downgraded.
        """
        for f in findings:
            if not f.supports_verdict():
                raise EvidenceError(
                    f"finding {f.key!r} has provenance {f.provenance.value} and "
                    f"cannot support a disposition (source: {f.source})"
                )

    def as_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.as_dict() for f in self.findings],
            "truncated": self.truncated,
            "original_length": self.original_length,
            "simulated": self.simulated,
            "counts": {p.value: len(self.by_provenance(p)) for p in Provenance},
        }
