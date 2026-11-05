"""The case ledger.

The tests that matter most here are the two invariants the design rests on: that a
machine verdict cannot be revised even by code that tries, and that no message body
or attachment byte reaches the disk. Both are asserted at the level where they are
actually enforced - the database and the raw file bytes - rather than through the
API, because an API-level assertion only proves the API behaves.
"""

from __future__ import annotations

import json
import pathlib
import sqlite3
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config  # noqa: E402
from tenable_email.ledger import (  # noqa: E402
    ACTION_OPEN,
    ACTION_RESOLVED,
    CaseLedger,
    LedgerError,
    LedgerProvider,
)
from tenable_email.pipeline import triage_file  # noqa: E402
from tenable_email.receipt import Receipt  # noqa: E402
from tenable_email.verdict import Disposition  # noqa: E402
from tenable_email.writeback import (  # noqa: E402
    DryRunProvider,
    ProposedAction,
    WritebackError,
    provider_for,
)

FIXTURES = REPO / "fixtures" / "synthetic"


@pytest.fixture()
def config():
    """Deterministic-only: no replay directory, so every tier is UNAVAILABLE."""
    return Config(replay=True, replay_dir=None)


@pytest.fixture()
def receipt(config):
    return Receipt.for_verdict(
        triage_file(FIXTURES / "threat_bec_valid_auth.eml", config)
    )


@pytest.fixture()
def ledger(tmp_path):
    store = CaseLedger(tmp_path / "ledger.sqlite3")
    yield store
    store.close()


def _clock(start: float = 1_700_000_000.0, step: float = 60.0):
    """A monotonic fake clock, so ordering is assertable without sleeping."""
    state = {"t": start}

    def now() -> float:
        state["t"] += step
        return state["t"]

    return now


# --------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------


def test_opening_an_existing_store_does_not_error_or_duplicate_schema(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    first = CaseLedger(path)
    first.close()
    second = CaseLedger(path)
    tables = {
        row["name"]
        for row in second._db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert {"cases", "resolutions", "notes", "events"} <= tables
    second.close()
    third = CaseLedger(path)
    triggers = {
        row["name"]
        for row in third._db.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall()
    }
    assert {"cases_no_update", "cases_no_delete"} <= triggers
    third.close()


def test_a_store_cannot_be_created_somewhere_impossible(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    with pytest.raises(LedgerError) as exc:
        CaseLedger(blocker / "ledger.sqlite3")
    assert exc.value.reason == "ledger_unopenable"


# --------------------------------------------------------------------------
# the machine verdict is append-only, enforced by the database
# --------------------------------------------------------------------------


def test_an_update_to_a_machine_verdict_is_refused_by_the_database(ledger, receipt):
    record = ledger.record_receipt(receipt)
    with pytest.raises(sqlite3.IntegrityError) as exc:
        ledger._db.execute(
            "UPDATE cases SET disposition = ? WHERE case_id = ?",
            (Disposition.CLEAN.value, record.case_id),
        )
    assert "append-only" in str(exc.value)


def test_a_delete_of_a_machine_verdict_is_refused_by_the_database(ledger, receipt):
    """Including a wrong one. The wrong verdicts are the measurement."""
    record = ledger.record_receipt(receipt)
    with pytest.raises(sqlite3.IntegrityError) as exc:
        ledger._db.execute("DELETE FROM cases WHERE case_id = ?", (record.case_id,))
    assert "append-only" in str(exc.value)


def test_resolving_leaves_every_machine_field_byte_identical(tmp_path, receipt):
    """The whole point: a human decision is recorded beside, not over, the machine's."""
    path = tmp_path / "ledger.sqlite3"
    store = CaseLedger(path)
    before = store.record_receipt(receipt)

    def machine_row(case_id):
        row = store._db.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        return bytes(repr(tuple(row)).encode("utf-8"))

    snapshot = machine_row(before.case_id)
    store.resolve(
        before.case_id, disposition=Disposition.THREAT, note="confirmed", resolver="s"
    )
    assert machine_row(before.case_id) == snapshot, (
        "resolving a case changed the machine verdict row"
    )

    after = store.get_case(before.case_id)
    assert after.disposition == before.disposition
    assert after.confidence == before.confidence
    assert after.verdict_digest == before.verdict_digest
    assert after.analysis == before.analysis
    assert after.reasons == before.reasons
    store.close()


# --------------------------------------------------------------------------
# no message content on disk
# --------------------------------------------------------------------------


def test_no_message_body_or_attachment_byte_reaches_the_disk(tmp_path, config):
    """Asserted against the raw file bytes, not through the API.

    An API-level check would only prove the API does not return bodies. The store is
    the thing on disk, so the store is what gets read.
    """
    path = tmp_path / "ledger.sqlite3"
    store = CaseLedger(path)
    for name in sorted(p.name for p in FIXTURES.glob("*.eml"))[:4]:
        store.record_receipt(Receipt.for_verdict(triage_file(FIXTURES / name, config)))
    store.close()

    raw = path.read_bytes().lower()
    for name in sorted(p.name for p in FIXTURES.glob("*.eml"))[:4]:
        text = (FIXTURES / name).read_text(encoding="utf-8", errors="replace")
        body = text.split("\n\n", 1)[-1]
        # A distinctive slice of the body, long enough that a coincidental match in
        # a metadata column is implausible.
        probe = " ".join(body.split())[:120].lower().encode("utf-8")
        if len(probe) < 40:
            continue
        assert probe not in raw, f"{name}: message body found in the ledger file"


def test_the_stored_digest_equals_the_receipt_digest(ledger, receipt):
    record = ledger.record_receipt(receipt)
    assert record.verdict_digest == receipt.verdict_digest
    assert record.case_id == receipt.receipt_id, (
        "one identifier shared by receipt, approval and ledger row, not three"
    )


# --------------------------------------------------------------------------
# recording
# --------------------------------------------------------------------------


def test_recording_the_same_receipt_twice_is_idempotent(ledger, receipt):
    first = ledger.record_receipt(receipt)
    second = ledger.record_receipt(receipt)
    assert first.case_id == second.case_id
    assert ledger.agreement_summary()["total_cases"] == 1


def test_recording_is_lazy_about_a_case_that_already_exists(ledger, receipt):
    """An existing case is returned unchanged, never overwritten."""
    first = ledger.record_receipt(receipt)
    ledger.resolve(first.case_id, disposition=Disposition.SPAM, resolver="x")
    again = ledger.record_receipt(receipt)
    assert again.action_status == ACTION_RESOLVED, (
        "re-recording must not reset a case a human already closed"
    )


def test_a_receipt_with_no_id_is_refused(ledger, receipt):
    blank = Receipt.for_verdict(triage_file(FIXTURES / "threat_bec_valid_auth.eml",
                                             Config(replay=True, replay_dir=None)))
    object.__setattr__(blank, "receipt_id", "") if hasattr(blank, "__dict__") else None
    if blank.receipt_id:
        pytest.skip("receipt_id is not settable; covered by the constructor check")
    with pytest.raises(LedgerError) as exc:
        ledger.record_receipt(blank)
    assert exc.value.reason == "case_id_required"


def test_the_two_status_axes_are_independent(ledger, receipt):
    """'Has the machine finished' is not 'has a person closed this'."""
    record = ledger.record_receipt(receipt)
    assert record.pipeline_status in ("opened", "processed")
    assert record.action_status == ACTION_OPEN
    ledger.resolve(record.case_id, disposition=Disposition.CLEAN, resolver="x")
    after = ledger.get_case(record.case_id)
    assert after.action_status == ACTION_RESOLVED
    assert after.pipeline_status == record.pipeline_status, (
        "a human resolution must not change what the machine did"
    )


# --------------------------------------------------------------------------
# notes and the event trail
# --------------------------------------------------------------------------


def test_notes_accumulate_rather_than_replace(ledger, receipt):
    record = ledger.record_receipt(receipt)
    ledger.add_note(record.case_id, "waiting on the sender's manager", author="a")
    ledger.add_note(record.case_id, "confirmed compromise", author="b")
    notes = ledger.get_case(record.case_id).notes
    assert [n.body for n in notes] == [
        "waiting on the sender's manager",
        "confirmed compromise",
    ]
    assert [n.author for n in notes] == ["a", "b"]


def test_an_empty_note_is_refused(ledger, receipt):
    record = ledger.record_receipt(receipt)
    with pytest.raises(LedgerError) as exc:
        ledger.add_note(record.case_id, "   ")
    assert exc.value.reason == "empty_note"


def test_the_event_trail_records_what_happened_and_who_caused_it(ledger, receipt):
    record = ledger.record_receipt(receipt)
    ledger.record_event(record.case_id, "label_applied", actor="runner",
                        detail="triage/needs-review")
    ledger.resolve(record.case_id, disposition=Disposition.THREAT, resolver="shawn")
    events = ledger.get_case(record.case_id).events
    assert [e.event_type for e in events] == ["case_recorded", "label_applied", "resolved"]
    assert events[1].actor == "runner"
    assert events[2].actor == "shawn"


# --------------------------------------------------------------------------
# resolving
# --------------------------------------------------------------------------


def test_resolving_an_unknown_case_is_refused(ledger):
    with pytest.raises(LedgerError) as exc:
        ledger.resolve("no-such-case", disposition=Disposition.CLEAN)
    assert exc.value.reason == "unknown_case"


def test_a_second_resolution_is_refused(ledger, receipt):
    record = ledger.record_receipt(receipt)
    ledger.resolve(record.case_id, disposition=Disposition.THREAT, resolver="a")
    with pytest.raises(LedgerError) as exc:
        ledger.resolve(record.case_id, disposition=Disposition.CLEAN, resolver="b")
    assert exc.value.reason == "already_resolved"


def test_an_invalid_disposition_is_refused(tmp_path, receipt):
    """On an open case, so the disposition check is the one that fires."""
    store = CaseLedger(tmp_path / "l.sqlite3")
    record = store.record_receipt(receipt)
    with pytest.raises(LedgerError) as exc:
        store.resolve(record.case_id, disposition="probably-fine")
    assert exc.value.reason == "unknown_disposition"
    store.close()


def test_an_unknown_state_filter_is_refused_rather_than_ignored(ledger):
    with pytest.raises(LedgerError) as exc:
        ledger.list_cases(state="maybe")
    assert exc.value.reason == "unknown_state"


# --------------------------------------------------------------------------
# listing
# --------------------------------------------------------------------------


def test_open_cases_come_oldest_first_so_the_list_is_a_queue(tmp_path, config):
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    names = sorted(p.name for p in FIXTURES.glob("*.eml"))[:5]
    for name in names:
        store.record_receipt(
            Receipt.for_verdict(triage_file(FIXTURES / name, config))
        )
    listed = store.list_cases(state=ACTION_OPEN)
    assert [c.opened_at for c in listed] == sorted(c.opened_at for c in listed)
    assert len(listed) == 5
    assert len(store.list_cases(limit=2)) == 2
    store.close()


def test_filters_narrow_rather_than_return_everything(tmp_path, config):
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    for name in sorted(p.name for p in FIXTURES.glob("*.eml")):
        store.record_receipt(
            Receipt.for_verdict(triage_file(FIXTURES / name, config))
        )
    everything = store.list_cases()
    threats = store.list_cases(disposition=Disposition.THREAT)
    assert threats, "the corpus should contain at least one threat-labelled verdict"
    assert all(c.disposition == Disposition.THREAT.value for c in threats)
    assert len(threats) < len(everything), (
        "a filter that returns every row is not a filter"
    )

    open_before = len(store.list_cases(state=ACTION_OPEN))
    first = threats[0].case_id
    store.resolve(first, disposition=Disposition.CLEAN, resolver="x")

    assert len(store.list_cases(state=ACTION_OPEN)) == open_before - 1
    resolved = store.list_cases(state=ACTION_RESOLVED)
    assert [c.case_id for c in resolved] == [first]
    # The disposition filter still reads the machine verdict, not the human one.
    assert first in {c.case_id for c in store.list_cases(disposition=Disposition.THREAT)}
    store.close()


def test_a_negative_limit_is_refused(ledger):
    with pytest.raises(LedgerError) as exc:
        ledger.list_cases(limit=-1)
    assert exc.value.reason == "bad_limit"


# --------------------------------------------------------------------------
# the reason the table exists
# --------------------------------------------------------------------------


def _summary_for(pairs, tmp_path):
    """Build a ledger from (machine, human) disposition pairs and summarize it."""
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    for index, (machine, human) in enumerate(pairs):
        receipt = Receipt.for_verdict(
            triage_file(FIXTURES / "threat_bec_valid_auth.eml",
                        Config(replay=True, replay_dir=None))
        )
        object.__setattr__(receipt, "receipt_id", f"case-{index}")
        object.__setattr__(receipt, "disposition", machine)
        store.record_receipt(receipt)
        if human is not None:
            store.resolve(f"case-{index}", disposition=human, resolver="t")
    summary = store.agreement_summary()
    store.close()
    return summary


def test_a_cleared_message_a_human_called_a_threat_is_counted_separately(tmp_path):
    """The number the red-team review asked for by name.

    It is reported on its own rather than folded into an agreement rate, because a
    rate can be made to look good by escalating everything while the dangerous case
    stays hidden in the denominator.
    """
    summary = _summary_for(
        [
            (Disposition.CLEAN.value, Disposition.THREAT.value),
            (Disposition.CLEAN.value, Disposition.CLEAN.value),
            (Disposition.THREAT.value, Disposition.THREAT.value),
        ],
        tmp_path,
    )
    assert summary["machine_cleared_resolved"] == 2
    assert summary["cleared_then_threat"] == 1
    assert summary["false_negative_rate_among_cleared"] == 0.5
    assert summary["agree"] == 2 and summary["disagree"] == 1


def test_clearing_a_newsletter_is_not_averaged_with_clearing_a_threat(tmp_path):
    summary = _summary_for(
        [
            (Disposition.CLEAN.value, Disposition.SPAM.value),
            (Disposition.CLEAN.value, Disposition.THREAT.value),
        ],
        tmp_path,
    )
    assert summary["cleared_then_spam"] == 1
    assert summary["cleared_then_threat"] == 1
    assert summary["false_negative_rate_among_cleared"] == 0.5, (
        "only the threat counts as a false negative; spam is a nuisance, not an incident"
    )


def test_a_rate_with_no_denominator_is_none_and_not_zero(tmp_path):
    """'Nothing cleared has been resolved yet' is not 'nothing cleared was wrong'."""
    summary = _summary_for([(Disposition.MANUAL_REVIEW.value, Disposition.THREAT.value)],
                           tmp_path)
    assert summary["machine_cleared_resolved"] == 0
    assert summary["false_negative_rate_among_cleared"] is None


def test_open_cases_are_excluded_from_agreement_rather_than_counted_as_either(tmp_path):
    summary = _summary_for(
        [(Disposition.CLEAN.value, None), (Disposition.CLEAN.value, Disposition.CLEAN.value)],
        tmp_path,
    )
    assert summary["total_cases"] == 2
    assert summary["open_cases"] == 1
    assert summary["resolved_cases"] == 1
    assert summary["agree"] == 1 and summary["disagree"] == 0


def test_a_false_accusation_is_measured_too(tmp_path):
    """Symmetry matters: only tracking false negatives rewards accusing everything."""
    summary = _summary_for(
        [(Disposition.THREAT.value, Disposition.CLEAN.value)], tmp_path
    )
    assert summary["machine_accused_resolved"] == 1
    assert summary["accused_then_clean"] == 1
    assert summary["false_accusation_rate_among_accused"] == 1.0


# --------------------------------------------------------------------------
# the writeback provider
# --------------------------------------------------------------------------


def _action(kind: str) -> ProposedAction:
    return ProposedAction(
        kind=kind, target="case-1", summary=f"would {kind}", rationale="test"
    )


def test_the_ledger_provider_declares_that_it_mutates(tmp_path):
    provider = LedgerProvider(tmp_path / "l.sqlite3")
    assert provider.name == "ledger"
    assert provider.mutates is True, (
        "the runner uses this to decide whether a write stage is satisfied"
    )
    provider.ledger.close()


def test_the_provider_refuses_every_kind_it_has_no_destination_for(tmp_path):
    provider = LedgerProvider(tmp_path / "l.sqlite3")
    for kind in ("apply_label", "notify_analyst", "post_comment"):
        result = provider.execute(
            _action(kind), receipt_id="r", verdict_digest="d", approval=None
        )
        assert result.performed is False, f"{kind} was reported as performed"
        assert kind in result.detail
    provider.ledger.close()


def test_the_provider_refuses_record_case_when_it_cannot_find_the_receipt(tmp_path):
    """A refusal is a result, not an exception - and never a fabricated success."""
    provider = LedgerProvider(tmp_path / "l.sqlite3", root=tmp_path)
    result = provider.execute(
        _action("record_case"), receipt_id="missing", verdict_digest="d", approval=None
    )
    assert result.performed is False
    assert "receipt_not_found" in result.detail
    provider.ledger.close()


def test_the_provider_without_a_root_says_why_it_cannot_load_a_receipt(tmp_path):
    provider = LedgerProvider(tmp_path / "l.sqlite3")
    result = provider.execute(
        _action("record_case"), receipt_id="r", verdict_digest="d", approval=None
    )
    assert result.performed is False
    assert "ledger_root_unknown" in result.detail
    provider.ledger.close()


def test_an_unconfigured_ledger_provider_fails_fast_rather_than_defaulting(tmp_path,
                                                                          monkeypatch):
    monkeypatch.delenv("TENABLE_EMAIL_LEDGER", raising=False)
    with pytest.raises(WritebackError) as exc:
        LedgerProvider()
    assert "TENABLE_EMAIL_LEDGER" in str(exc.value)


def test_the_ledger_path_comes_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("TENABLE_EMAIL_LEDGER", str(tmp_path / "env.sqlite3"))
    provider = LedgerProvider()
    assert provider.ledger.path == tmp_path / "env.sqlite3"
    provider.ledger.close()


def test_the_default_provider_is_still_the_one_that_changes_nothing(monkeypatch):
    """Registering a mutating provider must not change what an unconfigured run does."""
    monkeypatch.delenv("TENABLE_EMAIL_WRITEBACK_PROVIDER", raising=False)
    provider = provider_for(None)
    assert isinstance(provider, DryRunProvider)
    assert provider.mutates is False


# --------------------------------------------------------------------------
# reachable from the CLI, because a store no operator can query is dead weight
# --------------------------------------------------------------------------


def _populated(tmp_path, config, count=14):
    store = CaseLedger(tmp_path / "run" / "ledger.sqlite3", clock=_clock())
    names = sorted(p.name for p in FIXTURES.glob("*.eml"))[:count]
    for name in names:
        store.record_receipt(
            Receipt.for_verdict(triage_file(FIXTURES / name, config))
        )
    store.close()
    return tmp_path / "run"


def _cli(argv, capsys):
    from tenable_email import cli

    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def test_the_ledger_verbs_complete_a_full_human_round_trip(tmp_path, config, capsys):
    root = _populated(tmp_path, config)
    base = ["ledger", "--root", str(root)]

    code, out = _cli(base + ["list", "--state", "open"], capsys)
    assert code == 0
    assert "14 case(s)" in out

    listing = [line for line in out.splitlines() if line.strip() and not line.startswith("CASE")]
    short = listing[0].split()[0]

    code, out = _cli(base + ["show", short], capsys)
    assert code == 0
    assert "machine " in out and "human       (unresolved)" in out

    code, out = _cli(base + ["resolve", short, "--disposition", "threat",
                             "--resolver", "analyst", "--note", "confirmed"], capsys)
    assert code == 0, out
    assert f"resolved {short} as threat" in out

    code, out = _cli(base + ["note", short, "waiting on the sender's manager",
                             "--author", "analyst"], capsys)
    assert code == 0, out

    code, out = _cli(base + ["show", short], capsys)
    assert "human       threat by analyst" in out
    assert "waiting on the sender's manager" in out

    code, out = _cli(base + ["list", "--state", "resolved"], capsys)
    assert "1 case(s)" in out

    code, out = _cli(base + ["agreement"], capsys)
    assert code == 0
    # The dangerous number is its own labelled line, never folded into the rate.
    assert "CLEARED THEN FOUND HOSTILE" in out
    assert "agreement" in out


def test_querying_a_ledger_that_does_not_exist_exits_with_a_message_not_a_traceback(
    tmp_path, capsys
):
    code, out = _cli(["ledger", "--root", str(tmp_path / "nothing"), "list"], capsys)
    assert code == 1
    assert "ledger_not_found" in out
    assert "Traceback" not in out


def test_an_unknown_case_exits_non_zero(tmp_path, config, capsys):
    root = _populated(tmp_path, config, count=2)
    code, out = _cli(
        ["ledger", "--root", str(root), "resolve", "no-such", "--disposition", "clean"],
        capsys,
    )
    assert code == 1
    assert "unknown_case" in out
    assert "Traceback" not in out


def test_a_second_resolution_exits_non_zero_naming_the_real_reason(tmp_path, config, capsys):
    root = _populated(tmp_path, config, count=2)
    base = ["ledger", "--root", str(root)]
    _, out = _cli(base + ["list"], capsys)
    short = [l for l in out.splitlines() if l.strip() and not l.startswith("CASE")][0].split()[0]

    assert _cli(base + ["resolve", short, "--disposition", "clean"], capsys)[0] == 0
    code, out = _cli(base + ["resolve", short, "--disposition", "threat"], capsys)
    assert code == 1
    assert "already_resolved" in out


def test_an_ambiguous_short_id_is_refused_rather_than_guessed(tmp_path, config, capsys):
    root = _populated(tmp_path, config, count=4)
    # Every receipt id starts with the same prefix, so a one-character id is ambiguous.
    code, out = _cli(["ledger", "--root", str(root), "show", "r"], capsys)
    assert code == 1
    assert "ambiguous_case_id" in out


def test_the_json_verbs_emit_parsable_json(tmp_path, config, capsys):
    root = _populated(tmp_path, config, count=3)
    base = ["ledger", "--root", str(root)]

    code, out = _cli(base + ["list", "--json"], capsys)
    assert code == 0
    records = json.loads(out)
    assert len(records) == 3
    assert {"case_id", "machine", "message", "human", "notes", "events"} <= set(records[0])

    code, out = _cli(base + ["agreement", "--json"], capsys)
    assert code == 0
    summary = json.loads(out)
    assert summary["total_cases"] == 3
    assert "false_negative_rate_among_cleared" in summary


def test_an_empty_note_is_refused_at_the_cli(tmp_path, config, capsys):
    root = _populated(tmp_path, config, count=1)
    _, out = _cli(["ledger", "--root", str(root), "list"], capsys)
    short = [l for l in out.splitlines() if l.strip() and not l.startswith("CASE")][0].split()[0]
    code, out = _cli(["ledger", "--root", str(root), "note", short, "   "], capsys)
    assert code == 1
    assert "empty_note" in out


def test_the_ledger_is_selectable_as_a_writeback_provider(tmp_path, monkeypatch):
    monkeypatch.setenv("TENABLE_EMAIL_LEDGER", str(tmp_path / "p.sqlite3"))
    provider = provider_for("ledger")
    assert provider.name == "ledger" and provider.mutates is True
    provider.ledger.close()


def test_a_run_with_the_ledger_provider_records_every_case_not_only_approved_ones(
    tmp_path, capsys
):
    """Load-bearing, and easy to regress.

    Recording happens when a case is opened, not when an outward action is approved.
    A ledger holding only approved cases would be a biased sample - the careful
    analyst approves the ones they looked at - and the false-negative-among-cleared
    figure computed from it would be meaningless. Recording into our own local store
    is not an outward mutation and needs no approval; labelling a mailbox does.
    """
    from tenable_email import cli

    out = tmp_path / "run"
    assert cli.main(["run", str(FIXTURES), "--out", str(out), "--provider", "ledger"]) == 0
    capsys.readouterr()

    store = CaseLedger(out / "ledger.sqlite3")
    summary = store.agreement_summary()
    store.close()
    assert summary["total_cases"] == 14, (
        "every triaged message must be recorded, whether or not anything was approved"
    )
    assert summary["open_cases"] == 14
    assert summary["resolved_cases"] == 0


def test_a_run_without_the_ledger_provider_writes_no_store(tmp_path, capsys):
    """The ledger is opt-in: an existing caller's behaviour does not change."""
    from tenable_email import cli

    out = tmp_path / "run"
    assert cli.main(["run", str(FIXTURES), "--out", str(out)]) == 0
    capsys.readouterr()
    assert not (out / "ledger.sqlite3").exists()


def test_a_human_can_find_a_clearance_that_was_wrong(tmp_path, capsys):
    """The workflow the whole store exists for, driven through the CLI."""
    from tenable_email import cli

    out = tmp_path / "run"
    assert cli.main(["run", str(FIXTURES), "--out", str(out), "--provider", "ledger"]) == 0
    capsys.readouterr()
    base = ["ledger", "--root", str(out)]

    code, out_text = _cli(base + ["list", "--disposition", "clean", "--json"], capsys)
    assert code == 0
    cleared = json.loads(out_text)
    assert cleared, "the corpus contains clearances; if it stops, this test is vacuous"

    case_id = cleared[0]["case_id"]
    code, _ = _cli(base + ["resolve", case_id, "--disposition", "threat",
                           "--resolver", "analyst"], capsys)
    assert code == 0

    code, out_text = _cli(base + ["agreement"], capsys)
    assert "CLEARED THEN FOUND HOSTILE   1 of 1" in out_text, (
        "a clearance a human overturned must surface as its own number"
    )
