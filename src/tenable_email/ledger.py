"""The case ledger: what the machine decided, next to what a human decided.

Google Alert Center's only writable annotation is a four-value enum about whether
the *alert* was useful. There is no comment field and no place to record a
disposition, so the reference playbook's "post our analysis back to the platform"
step has no destination here - the platform it targets is a commercial product that
provides one. This module is ours.

It is also the instrument this project was missing. An external red-team review found
the pipeline auto-clearing adversarial mail, and the durable fix for that class of
bug is not another rule. It is a record of what the machine concluded beside what a
person finally concluded, so agreement can be measured over time instead of being
discovered by an outsider with hostile test cases.

The data model borrows from PhishER's schema, read out of the reference workflow's
own GraphQL query rather than guessed at. See
``docs/REFERENCE-BASELINE.md`` for what was adopted and what was rejected. In short:
two status axes because "has the machine finished" and "has a person closed this" are
different questions; an append-only event trail with a causer, because applying a
label and notifying an analyst are things a SOC needs to see and neither is a
verdict; and plural notes, because a case accumulates a conversation over days.

Two invariants carry the design and both are enforced by the database rather than by
the caller's discipline:

**The machine verdict is append-only.** Resolving inserts into ``resolutions``; it
never updates ``cases``. SQLite triggers abort any UPDATE or DELETE on ``cases``, so
a revision is impossible without dropping a trigger deliberately. A ledger whose
historical verdicts can be edited is not a measurement, it is a narrative - and the
wrong verdicts are the part worth keeping.

**No message bodies, no attachment bytes.** Digests and metadata only, exactly as
receipts do. A case ledger is a record of decisions; a second copy of real reported
mail on disk is a second thing to leak.

The case id is the receipt id, so a receipt, an approval token and a ledger row all
name the same thing instead of three identifiers that must be kept in agreement.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .receipt import Receipt
from .verdict import Disposition
from .writeback import (
    Approval,
    ProposedAction,
    ProviderResult,
    WritebackError,
    WritebackProvider,
)

__all__ = [
    "LEDGER_ENV",
    "LEDGER_FILENAME",
    "ACTION_OPEN",
    "ACTION_RESOLVED",
    "LedgerError",
    "CaseRecord",
    "Resolution",
    "Note",
    "CaseEvent",
    "CaseLedger",
    "LedgerProvider",
]

#: Where an unconfigured run puts its store, under the caller-chosen run root.
LEDGER_FILENAME = "ledger.sqlite3"

#: Where ``LedgerProvider`` looks for an explicit path, because the provider
#: registry constructs providers with no arguments.
LEDGER_ENV = "TENABLE_EMAIL_LEDGER"

#: The human axis. Deliberately separate from the machine's own pipeline state:
#: a case can be fully processed and still be waiting on a person, and collapsing
#: the two loses the queue an analyst actually works from.
ACTION_OPEN = "open"
ACTION_RESOLVED = "resolved"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id         TEXT PRIMARY KEY,
    opened_at       TEXT NOT NULL,
    pipeline_status TEXT NOT NULL,
    disposition     TEXT NOT NULL,
    confidence      REAL NOT NULL,
    confidence_band TEXT NOT NULL,
    attack_type     TEXT NOT NULL,
    reasons         TEXT NOT NULL,
    analysis        TEXT NOT NULL,
    subject         TEXT NOT NULL,
    sender          TEXT NOT NULL,
    reported_by     TEXT NOT NULL,
    source          TEXT NOT NULL,
    escalated       INTEGER NOT NULL DEFAULT 0,
    truncated       INTEGER NOT NULL DEFAULT 0,
    verdict_digest  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resolutions (
    case_id     TEXT PRIMARY KEY REFERENCES cases(case_id),
    resolved_at TEXT NOT NULL,
    disposition TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    resolver    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS notes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    at      TEXT NOT NULL,
    author  TEXT NOT NULL DEFAULT '',
    body    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    TEXT NOT NULL REFERENCES cases(case_id),
    at         TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_notes_case ON notes(case_id);
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);
CREATE INDEX IF NOT EXISTS idx_cases_disposition ON cases(disposition);

-- The machine verdict is a historical fact, so it is never revised and never
-- erased - including a wrong one, because the wrong ones are the measurement.
-- These triggers are why the invariant survives a future contributor who has not
-- read this file: both raise sqlite3.IntegrityError, not OperationalError.
CREATE TRIGGER IF NOT EXISTS cases_no_update
BEFORE UPDATE ON cases
BEGIN
    SELECT RAISE(ABORT, 'cases is append-only: record a resolution instead');
END;

CREATE TRIGGER IF NOT EXISTS cases_no_delete
BEFORE DELETE ON cases
BEGIN
    SELECT RAISE(ABORT, 'cases is append-only: wrong verdicts are the measurement');
END;
"""


class LedgerError(RuntimeError):
    """A ledger operation was refused. ``reason`` is recordable.

    Carries a reason rather than only a message so a caller can distinguish an
    unknown case from an already-resolved one from a store it cannot open. Those are
    three different facts and should not read the same to an operator.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason if not detail else f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


def _now(clock: Callable[[], float] | None) -> str:
    """UTC, second resolution, always with an explicit offset.

    A naive local timestamp in a store two analysts share is how they end up
    arguing about ordering.
    """
    if clock is None:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
    return datetime.fromtimestamp(clock(), timezone.utc).isoformat(timespec="seconds")


def _value(enum_or_text: Any) -> str:
    """Dispositions arrive as enums from the pipeline and as strings from storage."""
    return str(getattr(enum_or_text, "value", enum_or_text) or "")


@dataclass(frozen=True)
class Resolution:
    """The human verdict on one case. There is exactly one, or none."""

    case_id: str
    resolved_at: str
    disposition: str
    note: str = ""
    resolver: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "resolved_at": self.resolved_at,
            "disposition": self.disposition,
            "note": self.note,
            "resolver": self.resolver,
        }


@dataclass(frozen=True)
class Note:
    """One analyst comment. Plural by design - a case accumulates a conversation."""

    case_id: str
    at: str
    author: str
    body: str

    def as_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "at": self.at, "author": self.author,
                "body": self.body}


@dataclass(frozen=True)
class CaseEvent:
    """One thing that happened to a case, with who caused it."""

    case_id: str
    at: str
    event_type: str
    actor: str = ""
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "at": self.at,
                "event_type": self.event_type, "actor": self.actor,
                "detail": self.detail}


@dataclass(frozen=True)
class CaseRecord:
    """One case: the machine verdict, the human one if any, notes and events."""

    case_id: str
    opened_at: str
    pipeline_status: str
    disposition: str
    confidence: float
    confidence_band: str
    attack_type: str
    reasons: tuple[str, ...]
    analysis: str
    subject: str
    sender: str
    reported_by: str
    source: str
    escalated: bool
    truncated: bool
    verdict_digest: str
    resolution: Resolution | None = None
    notes: tuple[Note, ...] = ()
    events: tuple[CaseEvent, ...] = ()

    @property
    def action_status(self) -> str:
        return ACTION_RESOLVED if self.resolution else ACTION_OPEN

    @property
    def state(self) -> str:
        """Alias for the human axis, which is the one an operator filters on."""
        return self.action_status

    @property
    def human_disposition(self) -> str | None:
        """What a person decided, or ``None`` while the case is open.

        ``None`` is a real answer, not an empty string: an open case has no human
        verdict, and counting it as either agreement or disagreement would both be
        fabrication.
        """
        return self.resolution.disposition if self.resolution else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "opened_at": self.opened_at,
            "pipeline_status": self.pipeline_status,
            "action_status": self.action_status,
            "machine": {
                "disposition": self.disposition,
                "confidence": self.confidence,
                "confidence_band": self.confidence_band,
                "attack_type": self.attack_type,
                "reasons": list(self.reasons),
                "analysis": self.analysis,
                "escalated": self.escalated,
                "truncated": self.truncated,
                "verdict_digest": self.verdict_digest,
            },
            "message": {
                "subject": self.subject,
                "sender": self.sender,
                "reported_by": self.reported_by,
                "source": self.source,
            },
            "human": self.resolution.as_dict() if self.resolution else None,
            "notes": [n.as_dict() for n in self.notes],
            "events": [e.as_dict() for e in self.events],
        }


class CaseLedger:
    """A SQLite case store. Standard library only, so ``dependencies`` stays empty."""

    def __init__(self, path: str | Path, *, clock: Callable[[], float] | None = None) -> None:
        self.path = Path(path)
        self._clock = clock
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(self.path))
        except OSError as exc:
            raise LedgerError("ledger_unopenable", f"{self.path}: {exc}") from None
        self._db.row_factory = sqlite3.Row
        # A store two analysts share must not corrupt when one is interrupted.
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        try:
            self._db.executescript(_SCHEMA)
            self._db.commit()
        except sqlite3.Error as exc:
            raise LedgerError("ledger_schema_failed", f"{self.path}: {exc}") from None

    # -- writing ----------------------------------------------------------

    def record_receipt(self, receipt: Receipt) -> CaseRecord:
        """Store one machine verdict, from the receipt that already owns it.

        The receipt is the source rather than the verdict because it is what an
        approval binds to, it already holds exactly the metadata-without-bodies a
        case row needs, and deriving the row from it keeps the ledger consistent
        with what was approved instead of with what was computed a moment earlier.

        Idempotent on the receipt id: re-running the same message produces the same
        receipt, so recording twice neither errors nor duplicates. An existing case
        is returned unchanged - silently overwriting would break the append-only
        invariant through the front door instead of the back.
        """
        case_id = receipt.receipt_id
        if not case_id:
            raise LedgerError("case_id_required", "a receipt with no id cannot be a case")

        existing = self.get_case(case_id)
        if existing is not None:
            return existing

        pipeline = "processed" if receipt.state == "closed" else "opened"
        try:
            self._db.execute(
                """INSERT INTO cases (case_id, opened_at, pipeline_status, disposition,
                       confidence, confidence_band, attack_type, reasons, analysis,
                       subject, sender, reported_by, source, escalated, truncated,
                       verdict_digest)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    case_id,
                    _now(self._clock),
                    pipeline,
                    str(receipt.disposition or ""),
                    float(receipt.confidence),
                    str(receipt.confidence_band or ""),
                    str(receipt.attack_type or ""),
                    json.dumps(list(receipt.reasons or ()), ensure_ascii=False),
                    str(receipt.analysis or ""),
                    str(receipt.subject or ""),
                    str(receipt.sender or ""),
                    str(receipt.reported_by or ""),
                    str(receipt.source or ""),
                    1 if receipt.escalated else 0,
                    1 if receipt.truncated else 0,
                    str(receipt.verdict_digest or ""),
                ),
            )
            self._db.execute(
                """INSERT INTO events (case_id, at, event_type, actor, detail)
                   VALUES (?,?,?,?,?)""",
                (case_id, _now(self._clock), "case_recorded", "machine",
                 f"{receipt.disposition} at {receipt.confidence}"),
            )
            self._db.commit()
        except sqlite3.IntegrityError:
            # Two writers raced on the same case. The first wins; the second reads it
            # back, which is the same answer either way.
            self._db.rollback()
            raced = self.get_case(case_id)
            if raced is None:
                raise LedgerError("case_record_failed", case_id) from None
            return raced
        except sqlite3.Error as exc:
            self._db.rollback()
            raise LedgerError("case_record_failed", f"{case_id}: {exc}") from None

        stored = self.get_case(case_id)
        if stored is None:
            raise LedgerError(
                "case_record_failed", f"{case_id} was inserted and cannot be read back"
            )
        return stored

    def resolve(
        self,
        case_id: str,
        *,
        disposition: Disposition | str,
        note: str = "",
        resolver: str = "",
    ) -> Resolution:
        """Record what a human decided. Refuses an unknown or already-resolved case.

        The machine verdict is untouched, and the schema triggers make that true even
        if this method were rewritten badly.
        """
        if self.get_case(case_id) is None:
            raise LedgerError("unknown_case", f"no case {case_id!r} in {self.path}")
        if self._count("resolutions", case_id) > 0:
            raise LedgerError(
                "already_resolved",
                f"case {case_id} already has a human resolution; a second one would "
                "make it ambiguous which decision the ledger reports",
            )
        wanted = _value(disposition)
        valid = {_value(d) for d in Disposition}
        if wanted not in valid:
            raise LedgerError(
                "unknown_disposition",
                f"{wanted!r} is not one of {', '.join(sorted(valid))}",
            )
        resolution = Resolution(
            case_id=case_id, resolved_at=_now(self._clock), disposition=wanted,
            note=str(note or ""), resolver=str(resolver or ""),
        )
        try:
            self._db.execute(
                """INSERT INTO resolutions (case_id, resolved_at, disposition, note,
                       resolver) VALUES (?,?,?,?,?)""",
                (case_id, resolution.resolved_at, wanted, resolution.note,
                 resolution.resolver),
            )
            self._db.execute(
                """INSERT INTO events (case_id, at, event_type, actor, detail)
                   VALUES (?,?,?,?,?)""",
                (case_id, resolution.resolved_at, "resolved", resolver or "",
                 f"human disposition {wanted}"
                 + (f": {note}" if note else "")),
            )
            self._db.commit()
        except sqlite3.Error as exc:
            self._db.rollback()
            raise LedgerError("resolution_failed", f"{case_id}: {exc}") from None
        return resolution

    def add_note(self, case_id: str, body: str, *, author: str = "") -> Note:
        """Append an analyst comment. Notes are a conversation, not a single field."""
        if self.get_case(case_id) is None:
            raise LedgerError("unknown_case", f"no case {case_id!r} in {self.path}")
        text = str(body or "").strip()
        if not text:
            raise LedgerError("empty_note", "a note with no content records nothing")
        note = Note(case_id=case_id, at=_now(self._clock), author=str(author or ""),
                    body=text)
        try:
            self._db.execute(
                "INSERT INTO notes (case_id, at, author, body) VALUES (?,?,?,?)",
                (note.case_id, note.at, note.author, note.body),
            )
            self._db.execute(
                """INSERT INTO events (case_id, at, event_type, actor, detail)
                   VALUES (?,?,?,?,?)""",
                (case_id, note.at, "note_added", note.author, ""),
            )
            self._db.commit()
        except sqlite3.Error as exc:
            self._db.rollback()
            raise LedgerError("note_failed", f"{case_id}: {exc}") from None
        return note

    def record_event(
        self, case_id: str, event_type: str, *, actor: str = "", detail: str = ""
    ) -> CaseEvent:
        """Append to the audit trail.

        Public because the things worth recording are not all ledger-internal: a
        label applied to a mailbox, an analyst notified, a case reopened after new
        reports. Each is an event with a causer, and none of them is a verdict.
        """
        if self.get_case(case_id) is None:
            raise LedgerError("unknown_case", f"no case {case_id!r} in {self.path}")
        kind = str(event_type or "").strip()
        if not kind:
            raise LedgerError("empty_event_type", "an event needs a type")
        event = CaseEvent(case_id=case_id, at=_now(self._clock), event_type=kind,
                          actor=str(actor or ""), detail=str(detail or ""))
        try:
            self._db.execute(
                """INSERT INTO events (case_id, at, event_type, actor, detail)
                   VALUES (?,?,?,?,?)""",
                (event.case_id, event.at, event.event_type, event.actor, event.detail),
            )
            self._db.commit()
        except sqlite3.Error as exc:
            self._db.rollback()
            raise LedgerError("event_failed", f"{case_id}: {exc}") from None
        return event

    # -- reading ----------------------------------------------------------

    def _count(self, table: str, case_id: str) -> int:
        row = self._db.execute(
            f"SELECT COUNT(*) AS n FROM {table} WHERE case_id = ?", (case_id,)
        ).fetchone()
        return int(row["n"]) if row else 0

    def get_case(self, case_id: str) -> CaseRecord | None:
        row = self._db.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        return self._hydrate(row) if row is not None else None

    def list_cases(
        self,
        *,
        state: str | None = None,
        disposition: str | None = None,
        limit: int | None = None,
    ) -> list[CaseRecord]:
        """Open cases oldest first, so the list is a queue rather than a pile.

        ``state`` filters the human axis (``open`` or ``resolved``) and
        ``disposition`` the machine verdict. Both are pushed into SQL: a ledger grows
        without bound and this is the query an analyst runs constantly.
        """
        if state is not None and state not in (ACTION_OPEN, ACTION_RESOLVED):
            raise LedgerError(
                "unknown_state", f"{state!r} is not {ACTION_OPEN!r} or {ACTION_RESOLVED!r}"
            )
        if limit is not None and limit < 0:
            raise LedgerError("bad_limit", "limit must not be negative")

        # action status is derived, so it is filtered in a wrapping select rather
        # than in a WHERE that cannot see the join.
        query = (
            "SELECT c.*, (r.case_id IS NOT NULL) AS is_resolved FROM cases c "
            "LEFT JOIN resolutions r ON r.case_id = c.case_id"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if state == ACTION_OPEN:
            clauses.append("is_resolved = 0")
        elif state == ACTION_RESOLVED:
            clauses.append("is_resolved = 1")
        if disposition is not None:
            # Unqualified: this clause runs against the wrapping select below, where
            # the inner table aliases are no longer in scope.
            clauses.append("disposition = ?")
            params.append(_value(disposition))
        if clauses:
            query = f"SELECT * FROM ({query}) WHERE " + " AND ".join(clauses)
        query += " ORDER BY opened_at ASC, case_id ASC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(int(limit))

        return [self._hydrate(row) for row in self._db.execute(query, params).fetchall()]

    def _hydrate(self, row: sqlite3.Row) -> CaseRecord:
        case_id = row["case_id"]
        try:
            reasons = tuple(str(r) for r in json.loads(row["reasons"] or "[]"))
        except (ValueError, TypeError):
            # A corrupt reasons column must not make the whole case unreadable. The
            # rest of the record is still worth having and the loss stays visible.
            reasons = ("<unparsable reasons>",)
        res = self._db.execute(
            "SELECT * FROM resolutions WHERE case_id = ?", (case_id,)
        ).fetchone()
        notes = tuple(
            Note(case_id=n["case_id"], at=n["at"], author=n["author"] or "",
                 body=n["body"] or "")
            for n in self._db.execute(
                "SELECT * FROM notes WHERE case_id = ? ORDER BY id ASC", (case_id,)
            ).fetchall()
        )
        events = tuple(
            CaseEvent(case_id=e["case_id"], at=e["at"], event_type=e["event_type"],
                      actor=e["actor"] or "", detail=e["detail"] or "")
            for e in self._db.execute(
                "SELECT * FROM events WHERE case_id = ? ORDER BY id ASC", (case_id,)
            ).fetchall()
        )
        return CaseRecord(
            case_id=case_id,
            opened_at=row["opened_at"],
            pipeline_status=row["pipeline_status"],
            disposition=row["disposition"],
            confidence=float(row["confidence"]),
            confidence_band=row["confidence_band"],
            attack_type=row["attack_type"],
            reasons=reasons,
            analysis=row["analysis"],
            subject=row["subject"],
            sender=row["sender"],
            reported_by=row["reported_by"],
            source=row["source"],
            escalated=bool(row["escalated"]),
            truncated=bool(row["truncated"]),
            verdict_digest=row["verdict_digest"],
            resolution=Resolution(
                case_id=res["case_id"], resolved_at=res["resolved_at"],
                disposition=res["disposition"], note=res["note"] or "",
                resolver=res["resolver"] or "",
            ) if res is not None else None,
            notes=notes,
            events=events,
        )

    # -- the reason this table exists -------------------------------------

    def agreement_summary(self) -> dict[str, Any]:
        """Machine versus human, with the dangerous number kept separate.

        A general agreement rate can be made to look good by escalating everything,
        so the count that matters is reported on its own and never folded into a
        rate: **how many messages the machine cleared were then found hostile by a
        person.** That is the false-negative-among-auto-closed figure the external
        red-team review asked for by name, and it is the number that should decide
        whether the clearance policy is safe.

        Threat and spam are counted separately among cleared cases: clearing a
        newsletter is a nuisance and clearing a credential harvester is an incident,
        and averaging them hides the one that matters.

        Counts run over resolved cases only.
        """
        rows = self._db.execute(
            """SELECT c.disposition AS machine, r.disposition AS human
               FROM cases c JOIN resolutions r ON r.case_id = c.case_id"""
        ).fetchall()
        total = int(
            self._db.execute("SELECT COUNT(*) AS n FROM cases").fetchone()["n"]
        )
        resolved = len(rows)
        agree = sum(1 for r in rows if r["machine"] == r["human"])

        clean = _value(Disposition.CLEAN)
        threat = _value(Disposition.THREAT)
        spam = _value(Disposition.SPAM)

        cleared = [r for r in rows if r["machine"] == clean]
        accused = [r for r in rows if r["machine"] in (threat, spam)]

        def rate(numerator: int, denominator: int) -> float | None:
            # None, not 0.0. "No cleared case has been resolved yet" and "no cleared
            # case was ever wrong" are different facts and must not read the same.
            return round(numerator / denominator, 4) if denominator else None

        return {
            "total_cases": total,
            "open_cases": total - resolved,
            "resolved_cases": resolved,
            "agree": agree,
            "disagree": resolved - agree,
            "agreement_rate": rate(agree, resolved),
            "machine_cleared_resolved": len(cleared),
            "cleared_then_threat": sum(1 for r in cleared if r["human"] == threat),
            "cleared_then_spam": sum(1 for r in cleared if r["human"] == spam),
            "false_negative_rate_among_cleared": rate(
                sum(1 for r in cleared if r["human"] == threat), len(cleared)
            ),
            "machine_accused_resolved": len(accused),
            "accused_then_clean": sum(1 for r in accused if r["human"] == clean),
            "false_accusation_rate_among_accused": rate(
                sum(1 for r in accused if r["human"] == clean), len(accused)
            ),
        }

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        try:
            self._db.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "CaseLedger":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


class LedgerProvider(WritebackProvider):
    """Performs ``record_case`` and honestly declines everything else.

    ``mutates`` is True: it writes to disk. The declaration matters because the
    runner uses it to decide whether a write stage is satisfied, and a provider that
    claimed not to mutate while writing a database would defeat the check.

    Every other action kind returns ``performed = False`` naming the kind. It does
    not fake success and does not quietly skip: an operator who believes a label was
    applied when nothing happened has been told something false about their own
    queue. Applying a label to a mailbox is a different destination's job.
    """

    name = "ledger"
    mutates = True

    def __init__(
        self, path: str | Path | None = None, *, root: str | Path | None = None
    ) -> None:
        resolved = path
        if resolved is None:
            resolved = (os.environ.get(LEDGER_ENV) or "").strip() or None
        if resolved is None and root is not None:
            resolved = Path(root) / LEDGER_FILENAME
        if resolved is None:
            raise WritebackError(
                f"the ledger provider needs a store path. Set {LEDGER_ENV}, pass one "
                "explicitly, or pass the run root. Nothing here invents a default "
                "location, because a case record written somewhere the operator did "
                "not choose is a case record they cannot find."
            )
        self.ledger = CaseLedger(resolved)
        self.root = Path(root) if root is not None else None

    def _load_receipt(self, receipt_id: str) -> Receipt:
        """Read the receipt the runner already wrote, by id.

        ``execute`` receives the receipt id and its digest but not the receipt, and
        the ledger row must come from the same object the approval bound to. The run
        root owns ``receipts/*.json``, so the row is loaded rather than reconstructed
        from the action's summary text.
        """
        if self.root is None:
            raise LedgerError(
                "ledger_root_unknown",
                "the ledger provider was constructed without a run root, so it cannot "
                f"load receipt {receipt_id!r}. Pass root= or record cases through "
                "CaseLedger.record_receipt directly.",
            )
        matches = sorted((self.root / "receipts").glob(f"{receipt_id}*.json"))
        if not matches:
            raise LedgerError(
                "receipt_not_found",
                f"no receipt file for {receipt_id!r} under {self.root / 'receipts'}",
            )
        if len(matches) > 1:
            raise LedgerError(
                "receipt_ambiguous",
                f"{len(matches)} receipt files match {receipt_id!r}: "
                + ", ".join(m.name for m in matches),
            )
        try:
            data = json.loads(matches[0].read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise LedgerError(
                "receipt_unreadable", f"{matches[0]}: {exc}"
            ) from None
        return Receipt.from_dict(data)

    def execute(
        self,
        action: ProposedAction,
        *,
        receipt_id: str,
        verdict_digest: str,
        approval: Approval,
    ) -> ProviderResult:
        at = _now(None)
        if action.kind != "record_case":
            return ProviderResult(
                kind=action.kind, target=action.target, provider=self.name,
                performed=False,
                detail=(
                    f"the ledger records cases only; it has no destination for "
                    f"{action.kind!r}. Nothing was changed and nothing was faked."
                ),
                at=at,
            )
        try:
            record = self.ledger.record_receipt(self._load_receipt(receipt_id))
        except LedgerError as exc:
            # A refusal is a result, not an exception: the runner records it and the
            # operator reads why, rather than the write stage crashing.
            return ProviderResult(
                kind=action.kind, target=action.target, provider=self.name,
                performed=False, detail=f"{exc.reason}: {exc.detail}", at=at,
            )
        agreed = record.verdict_digest == verdict_digest
        return ProviderResult(
            kind=action.kind, target=action.target, provider=self.name,
            performed=True,
            detail=(
                f"case {record.case_id} recorded as {record.disposition}"
                + ("" if agreed else
                   f"; WARNING the stored digest does not match the approved one "
                   f"({record.verdict_digest} != {verdict_digest})"),
            ),
            at=at,
        )

    def describe(self) -> str:
        return f"ledger at {self.ledger.path} (mutating: writes case records)"
