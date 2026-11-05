"""The offline state-machine runner: every refusal, and what a refusal leaves behind.

Bundle D3, D5 and the enforcement half of D4. Two properties matter more than the
rest, and both are tested structurally rather than by reading a message:

* **Each refusal is its own case.** A skipped non-optional stage, an altered
  corpus manifest, a widened target set, a replayed approval, a mismatched
  approval digest, a later stage presented early -- six ways a case can be
  advanced wrongly, each with a code a consumer can branch on and a reason that
  names the specific thing wrong.
* **A refusal is transactional.** The run directory is snapshotted before and
  after, byte for byte, including the journal's length, and the caller's receipt
  object is asserted unmutated. Nothing is written on the refusal path -- that is
  a property of the call graph (every check returns before ``_commit`` is reached),
  and these tests are what make that claim checkable.

The runner also has to work with no network at all, which is asserted at the
transport seam -- ``socket.create_connection`` replaced by a raiser -- over the
whole fixture corpus, not claimed.
"""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config, default_replay_dir  # noqa: E402
from tenable_email.contract import load_contract  # noqa: E402
from tenable_email.evidence import Provenance  # noqa: E402
from tenable_email.parse import iter_eml_dir, parse_file  # noqa: E402
from tenable_email.pipeline import triage_file  # noqa: E402
from tenable_email.receipt import Receipt, corpus_manifest  # noqa: E402
from tenable_email.replay import ReplayStore, build_entry  # noqa: E402
from tenable_email.runner import (  # noqa: E402
    JOURNAL_FILE,
    RECEIPTS_DIR,
    REFUSAL_CODES,
    OfflineRunner,
    Refusal,
    RunnerError,
    Transition,
)
from tenable_email.tiers import FraudFoxTier  # noqa: E402
from tenable_email.writeback import Approval, DryRunProvider, issue_approval  # noqa: E402

FIXTURES = REPO / "fixtures" / "synthetic"
LABELS = FIXTURES / "labels.json"
THREAT_FIXTURE = FIXTURES / "threat_lookalike_credential_harvest.eml"
CLEAN_FIXTURE = FIXTURES / "clean_vendor_docusign.eml"


def replay_config() -> Config:
    return Config(replay=True, replay_dir=default_replay_dir())


def snapshot(root: Path) -> dict[str, bytes]:
    """Every file under ``root``, keyed by relative name.

    Directory listings are included as zero-byte entries, so creating an empty
    directory counts as a change rather than being invisible.
    """
    out: dict[str, bytes] = {}
    if not root.exists():
        return out
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            out[str(path.relative_to(root)) + "/"] = b""
        else:
            out[str(path.relative_to(root))] = path.read_bytes()
    return out


def make_receipt(path: Path = THREAT_FIXTURE, *, manifest: Path = LABELS) -> Receipt:
    verdict = triage_file(path, replay_config())
    return Receipt.for_verdict(verdict, manifest_path=manifest)


def runner_for(tmp_path: Path, *, manifest: Path = LABELS) -> OfflineRunner:
    return OfflineRunner(
        contract=load_contract(), root=tmp_path / "run", manifest_path=manifest
    )


def opened(tmp_path: Path, *, fixture: Path = THREAT_FIXTURE, manifest=LABELS):
    """A runner with one case opened and driven to the end of its read stages."""
    runner = runner_for(tmp_path, manifest=manifest)
    receipt = make_receipt(fixture, manifest=manifest)
    begun = runner.begin(receipt)
    assert begun.ok, begun.reason()
    steps = runner.drive(receipt.receipt_id)
    refused = [s.refusal for s in steps if not s.ok]
    assert not refused, f"the corpus case should drive cleanly: {refused}"
    return runner, receipt.receipt_id


# --- the happy path, and what makes it evidence ----------------------------


def test_the_runner_imports_nothing_that_could_make_a_live_call():
    """The structural half of "without any live call".

    The socket-blocking test over the whole corpus proves the behaviour; this
    proves the shape: the state machine does not import the tier layer or a
    transport at all, so a future stage cannot reach a host from inside a
    transition without adding an import that fails here first.
    """
    import ast
    import tenable_email.runner as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"urllib", "socket", "http", "requests", "subprocess", "smtplib",
                 "ftplib", "tenable_email"}
    reached = sorted(imported & forbidden)
    assert not reached, f"the runner reaches {reached}; it must enforce offline"
    # And inside the package: it may read the contract and the record, but never
    # the module that calls a model or the chain that assembles a verdict.
    internal = {
        (node.module or "") + ":" + a.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level
        for a in node.names
    }
    owners = sorted({key.split(":")[0] for key in internal})
    assert not {"tiers", "pipeline"} & set(owners), (
        f"the runner imports from {owners}; a transition must not be able to "
        f"reach a model call"
    )


def test_the_contract_stages_are_the_ones_declared_in_stages_yaml():
    runner = OfflineRunner(contract=load_contract())
    assert runner.stage_ids() == load_contract().ids()
    assert runner.write_stage.id == "disposition-writeback"
    assert runner.write_stage.access == "write"


def test_a_corpus_case_opens_drives_and_closes(tmp_path):
    runner, receipt_id = opened(tmp_path)
    closed = runner.close(receipt_id)
    assert closed.ok, closed.reason()
    assert closed.receipt.state == "closed"
    receipt = runner.get(receipt_id)
    contract = load_contract()
    for stage in contract.stages:
        assert receipt.stage_is_done(stage.id), f"{stage.id} was never settled"
    assert "adjudication" in receipt.completed_stages
    assert "disposition-writeback" not in receipt.completed_stages, (
        "an unapproved write stage is skipped, never completed"
    )
    skips = {s["id"] for s in receipt.skipped_stages}
    assert {"vision", "attachment-content", "disposition-writeback"} == skips
    reasons = {s["id"]: s["reason"] for s in receipt.skipped_stages}
    assert all(reasons[s] for s in skips), (
        "an optional stage may be skipped, never skipped silently"
    )
    assert "not enabled" in reasons["attachment-content"], (
        "the attachment stage is implemented in this build; the honest reason it "
        "did not run is that this configuration left its optional provider off"
    )
    assert "not implemented" not in reasons["attachment-content"], (
        "claiming a capability is missing when it is present is the overstated "
        "contract this rename corrected, and a receipt is where a reviewer reads "
        "what the engine did"
    )
    written = Path(runner.root) / RECEIPTS_DIR / f"{receipt_id}.json"
    assert written.is_file()
    on_disk = Receipt.load(written)
    assert on_disk.state == "closed"
    assert on_disk.closure_blockers() == []


def test_the_whole_corpus_runs_with_no_network_and_closes_every_case(tmp_path, monkeypatch):
    """D3's claim, tested at the transport seam rather than asserted in prose."""

    def blocked(*args, **kwargs):
        raise AssertionError("the offline runner reached the network")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:1")

    runner = runner_for(tmp_path)
    paths = list(iter_eml_dir(FIXTURES))
    assert len(paths) == 14, f"expected the full corpus, found {len(paths)}"
    refusals = []
    for path in paths:
        receipt = make_receipt(path)
        begun = runner.begin(receipt)
        assert begun.ok, begun.reason()
        for step in runner.drive(receipt.receipt_id):
            if not step.ok:
                refusals.append(step.refusal)
                break
        else:
            closed = runner.close(receipt.receipt_id)
            if not closed.ok:
                refusals.append(closed.refusal)
    assert not refusals, [f"{r.code}: {r.reason}" for r in refusals]
    assert len(runner.receipts()) == 14
    assert all(r.state == "closed" for r in runner.receipts())


def test_a_skip_is_recorded_with_a_reason_and_a_non_optional_stage_cannot_be_skipped(
    tmp_path,
):
    # A case begun but not driven: the optional stage is still open, so a skip
    # is a real decision rather than a rewrite of one already taken.
    runner = runner_for(tmp_path)
    receipt = make_receipt(CLEAN_FIXTURE)
    assert runner.begin(receipt).ok
    receipt_id = receipt.receipt_id
    skipped = runner.skip(receipt_id, "vision", reason="no vlm endpoint configured")
    assert skipped.ok, skipped.reason()
    entry = skipped.receipt.skipped_stages[-1]
    assert entry["id"] == "vision" and "vlm" in entry["reason"]

    refused = runner.skip(receipt_id, "deterministic-signals", reason="convenience")
    assert not refused.ok
    assert refused.refusal.code == "skipped-stage"
    assert "deterministic-signals" in refused.refusal.reason


# --- refusal 1: a skipped non-optional stage -------------------------------


def test_closing_with_a_non_optional_stage_never_run_is_refused_by_name(tmp_path):
    runner = runner_for(tmp_path)
    receipt = make_receipt()
    assert runner.begin(receipt).ok
    # Only intake: the three remaining non-optional stages were never settled.
    assert runner.complete_stage(receipt.receipt_id, "intake").ok
    closed = runner.close(receipt.receipt_id)
    assert not closed.ok
    assert closed.refusal.code == "skipped-stage"
    for stage in ("parse-authenticate", "deterministic-signals", "adjudication"):
        assert stage in closed.refusal.reason, (
            f"the refusal must name every stage that was skipped, missing {stage}"
        )


# --- refusal 2: a later stage presented before an earlier one --------------


def test_a_later_stage_presented_early_is_refused_as_out_of_order(tmp_path):
    runner = runner_for(tmp_path)
    receipt = make_receipt()
    runner.begin(receipt)
    step = runner.complete_stage(receipt.receipt_id, "adjudication")
    assert not step.ok
    assert step.refusal.code == "out-of-order-stage"
    # Every stage the contract requires before adjudication is named.
    for stage in ("intake", "parse-authenticate", "deterministic-signals"):
        assert stage in step.refusal.reason
    assert step.receipt is None, "a refused transition returns no new state"


def test_a_stage_presented_after_the_case_has_passed_it_is_also_refused(tmp_path):
    runner = runner_for(tmp_path)
    receipt = make_receipt()
    runner.begin(receipt)
    assert runner.complete_stage(receipt.receipt_id, "intake").ok
    assert runner.complete_stage(receipt.receipt_id, "parse-authenticate").ok
    assert runner.complete_stage(receipt.receipt_id, "deterministic-signals").ok
    backward = runner.complete_stage(receipt.receipt_id, "intake")
    assert not backward.ok
    assert backward.refusal.code == "stage-already-completed"


def test_an_unknown_stage_cannot_be_completed(tmp_path):
    runner, receipt_id = opened(tmp_path)
    step = runner.complete_stage(receipt_id, "send-it-to-the-vendor")
    assert not step.ok
    assert step.refusal.code == "unknown-stage"


def test_the_write_stage_is_not_completed_by_assertion(tmp_path):
    """``access: write`` is reachable only through an approved execution."""
    runner, receipt_id = opened(tmp_path)
    step = runner.complete_stage(receipt_id, "disposition-writeback")
    assert not step.ok
    assert step.refusal.code == "write-stage-requires-execution"
    assert "human approval required" in step.refusal.reason


# --- refusal 3: an altered corpus manifest ---------------------------------


def test_a_manifest_that_changed_under_the_run_is_refused(tmp_path):
    manifest = tmp_path / "labels.json"
    manifest.write_text(
        json.dumps([{"file": "x.eml", "label": "threat", "case": "x"}]),
        encoding="utf-8",
    )
    runner = OfflineRunner(
        contract=load_contract(),
        root=tmp_path / "run",
        manifest_path=manifest,
    )
    receipt = Receipt.for_verdict(
        triage_file(THREAT_FIXTURE, replay_config()), manifest_path=manifest
    )
    assert runner.begin(receipt).ok
    assert runner.complete_stage(receipt.receipt_id, "intake").ok

    # The ground truth moves: same file name, different labels.
    manifest.write_text(
        json.dumps([{"file": "x.eml", "label": "clean", "case": "x"}]),
        encoding="utf-8",
    )
    step = runner.complete_stage(receipt.receipt_id, "parse-authenticate")
    assert not step.ok
    assert step.refusal.code == "altered-manifest"
    assert receipt.corpus_manifest_digest[:16] in step.refusal.reason
    closed = runner.close(receipt.receipt_id)
    assert not closed.ok and closed.refusal.code == "altered-manifest"


def test_a_run_with_no_manifest_does_not_invent_a_mismatch(tmp_path):
    runner = OfflineRunner(contract=load_contract(), root=tmp_path / "run")
    receipt = Receipt.for_verdict(triage_file(CLEAN_FIXTURE, replay_config()))
    assert receipt.corpus_manifest == "none"
    assert runner.begin(receipt).ok
    for step in runner.drive(receipt.receipt_id):
        assert step.ok, step.reason()
    assert runner.close(receipt.receipt_id).ok


# --- refusals 4 and 5: replayed and mismatched approvals -------------------


def _approve(runner: OfflineRunner, receipt_id: str, **kwargs) -> Approval:
    approval = runner.request_approval(
        receipt_id, approver=kwargs.pop("approver", "analyst@example.edu"), **kwargs
    )
    return approval


def test_a_replayed_approval_token_is_refused(tmp_path):
    runner, receipt_id = opened(tmp_path)
    approval = _approve(runner, receipt_id)
    first = runner.grant(receipt_id, approval)
    assert first.ok, first.reason()
    replay = runner.grant(receipt_id, approval)
    assert not replay.ok
    assert replay.refusal.code == "replayed-approval"
    assert approval.token in replay.refusal.reason


def test_a_spent_token_cannot_authorize_a_second_execution(tmp_path):
    runner, receipt_id = opened(tmp_path)
    runner.grant(receipt_id, _approve(runner, receipt_id))
    executed = runner.execute(receipt_id)
    assert executed.ok, executed.reason()
    again = runner.execute(receipt_id)
    assert not again.ok
    assert again.refusal.code == "replayed-approval"
    # The provider was called once, not twice: the record has one set of results.
    assert len(Receipt.load(Path(runner.root) / RECEIPTS_DIR /
                           f"{receipt_id}.json").execution) == len(
        executed.receipt.proposed_actions
    )


def test_an_approval_bound_to_a_different_verdict_digest_is_refused(tmp_path):
    runner, receipt_id = opened(tmp_path)
    receipt = runner.get(receipt_id)
    wrong = issue_approval(
        approver="analyst@example.edu",
        verdict_digest="0" * 64,
        targets=[receipt_id],
        actions=[a.kind for a in receipt.proposed_actions],
    )
    granted = runner.grant(receipt_id, wrong)
    assert not granted.ok
    assert granted.refusal.code == "mismatched-approval"
    assert "stale" in granted.refusal.reason or "another case" in granted.refusal.reason
    assert runner.get(receipt_id).approval is None, (
        "a refused grant must not leave an approval on the record"
    )


def test_a_stale_approval_is_refused_when_the_verdict_moves_under_it(tmp_path):
    """The digest is the binding, so a re-decided case invalidates the yes."""
    runner, receipt_id = opened(tmp_path)
    approval = _approve(runner, receipt_id)
    assert runner.grant(receipt_id, approval).ok
    # Re-open the same message with a different reading: different digest,
    # different receipt id, so the old approval cannot attach to it.
    other = Receipt.for_verdict(
        triage_file(THREAT_FIXTURE, Config(replay=True, replay_dir=None)),
        manifest_path=LABELS,
    )
    assert other.verdict_digest != approval.verdict_digest
    assert runner.begin(other).ok
    # A fresh token, minted against the reading that no longer stands: the case
    # was re-decided deterministically, so the old digest is stale.
    stale_approval = issue_approval(
        approver="analyst@example.edu",
        verdict_digest=approval.verdict_digest,
        targets=[other.receipt_id],
        actions=[a.kind for a in other.proposed_actions],
    )
    stale = runner.grant(other.receipt_id, stale_approval)
    assert not stale.ok
    assert stale.refusal.code == "mismatched-approval"


# --- refusal 6: a widened target set ---------------------------------------


def test_an_approval_for_n_messages_refuses_n_plus_k(tmp_path):
    runner, receipt_id = opened(tmp_path)
    second = make_receipt(CLEAN_FIXTURE)
    assert runner.begin(second).ok
    receipt = runner.get(receipt_id)
    narrow = issue_approval(
        approver="analyst@example.edu",
        verdict_digest=receipt.verdict_digest,
        targets=[receipt_id],
        actions=[a.kind for a in receipt.proposed_actions],
    )
    widened = runner.grant(
        receipt_id, narrow, targets=[receipt_id, second.receipt_id]
    )
    assert not widened.ok
    assert widened.refusal.code == "widened-target-set"
    assert "1 message(s)" in widened.refusal.reason
    assert second.receipt_id in widened.refusal.reason
    assert runner.get(receipt_id).approval is None
    assert runner.get(second.receipt_id).approval is None


def test_a_target_the_approval_never_named_cannot_be_executed(tmp_path):
    runner, receipt_id = opened(tmp_path)
    other = make_receipt(CLEAN_FIXTURE)
    runner.begin(other)
    receipt = runner.get(receipt_id)
    approval = issue_approval(
        approver="analyst@example.edu",
        verdict_digest=receipt.verdict_digest,
        targets=[other.receipt_id],
        actions=[a.kind for a in receipt.proposed_actions],
    )
    step = runner.grant(receipt_id, approval, targets=[receipt_id])
    assert not step.ok
    assert step.refusal.code == "widened-target-set"


def test_an_action_kind_that_was_not_approved_is_refused_without_execution(
    tmp_path,
):
    """Each mutation is approved separately -- so a kind off-list stops the lot."""
    runner, receipt_id = opened(tmp_path)
    receipt = runner.get(receipt_id)
    partial = _approve(runner, receipt_id, actions=["record_case"])
    assert runner.grant(receipt_id, partial).ok
    executed = runner.execute(receipt_id)
    assert not executed.ok
    assert executed.refusal.code == "unapproved-action"
    assert "apply_label" in executed.refusal.reason
    assert runner.provider.log == [], "a refused execution must not touch a provider"
    assert runner.get(receipt_id).execution == []


# --- D5: refusals are values, and they are transactional -------------------


def test_a_refusal_is_a_value_with_the_three_fields_a_caller_needs(tmp_path):
    runner = OfflineRunner(contract=load_contract())
    step = runner.complete_stage("rcpt-does-not-exist", "intake")
    assert isinstance(step, Transition)
    assert not step.ok
    refusal = step.refusal
    assert isinstance(refusal, Refusal)
    assert set(["reason", "stage", "receipt_id"]) <= set(refusal.as_dict())
    assert refusal.code in REFUSAL_CODES
    assert refusal.receipt_id == "rcpt-does-not-exist"
    assert "nothing was written" in refusal.reason


def test_expected_refusals_raise_nothing(tmp_path):
    """Every wrong move is answerable as data, so a caller can act on it."""
    runner, receipt_id = opened(tmp_path)
    attempts = [
        runner.complete_stage(receipt_id, "not-a-stage"),
        runner.complete_stage("rcpt-missing", "intake"),
        runner.skip(receipt_id, "intake", reason="no"),
        runner.grant(receipt_id, Approval(approver="x", verdict_digest="y",
                                          token="")),
        runner.close("rcpt-missing"),
        runner.execute("rcpt-missing"),
    ]
    for step in attempts:
        assert isinstance(step, Transition)
        assert not step.ok
        assert step.receipt is None
        assert step.refusal.reason.strip()


def test_a_refusal_leaves_the_run_directory_byte_identical(tmp_path):
    """Transactional: the snapshot around a refusal must match exactly."""
    root = tmp_path / "run"
    runner = OfflineRunner(contract=load_contract(), root=root,
                           manifest_path=LABELS)
    receipt = make_receipt()
    assert runner.begin(receipt).ok
    assert runner.complete_stage(receipt.receipt_id, "intake").ok
    before = snapshot(root)
    assert before, "the run directory should already hold the opened case"

    step = runner.complete_stage(receipt.receipt_id, "adjudication")
    assert not step.ok and step.refusal.code == "out-of-order-stage"
    assert snapshot(root) == before, "a refusal wrote to the run directory"

    # The journal is the same length, so nothing was even appended.
    journal = root / JOURNAL_FILE
    lines_before = len(journal.read_text().splitlines())
    runner.grant(receipt.receipt_id, Approval(approver="a", verdict_digest="b",
                                              token="c" * 24))
    runner.close(receipt.receipt_id)
    runner.execute(receipt.receipt_id)
    runner.skip(receipt.receipt_id, "intake", reason="no")
    assert snapshot(root) == before
    assert len(journal.read_text().splitlines()) == lines_before


def test_a_refused_transition_does_not_mutate_the_callers_receipt(tmp_path):
    runner = runner_for(tmp_path)
    receipt = make_receipt(CLEAN_FIXTURE)
    runner.begin(receipt)
    receipt_id = receipt.receipt_id
    before = receipt.to_dict()
    runner.complete_stage(receipt_id, "adjudication")
    runner.grant(receipt_id, Approval(approver="a", verdict_digest="b", token="c" * 24))
    runner.skip(receipt_id, "intake", reason="no")
    assert receipt.to_dict() == before, (
        "the record the caller holds must survive a refusal untouched"
    )


def test_a_refused_run_is_resumable_and_remembers_spent_tokens(tmp_path):
    runner, receipt_id = opened(tmp_path)
    assert not runner.complete_stage(receipt_id, "adjudication").ok
    approval = _approve(runner, receipt_id)
    assert runner.grant(receipt_id, approval).ok
    assert runner.execute(receipt_id).ok
    assert runner.close(receipt_id).ok

    resumed = OfflineRunner(
        contract=load_contract(), root=Path(runner.root), manifest_path=LABELS
    )
    restored = resumed.get(receipt_id)
    assert restored is not None and restored.state == "closed"
    assert restored.approval_state == "consumed"
    # The spent token is still spent in a fresh process: replay stays detected.
    assert not resumed.grant(receipt_id, approval).ok
    assert resumed.grant(receipt_id, approval).refusal.code == "replayed-approval"


def test_an_invalid_contract_is_programmer_error_not_a_refusal(tmp_path):
    from tenable_email.contract import Contract

    with pytest.raises(RunnerError):
        OfflineRunner(contract=Contract(version=1, stages=[]), root=tmp_path)
    with pytest.raises(RunnerError):
        OfflineRunner(contract=load_contract()).begin("not a receipt")
    with pytest.raises(RunnerError):
        Refusal(code="made-up-code", reason="x")


# --- D4 on the runner: a fabricated recording cannot close -----------------


def _fabricated_store(tmp_path: Path, *, fixture: Path, response: dict) -> Path:
    """A corpus with one genuine capture and one hand-written recording.

    The genuine one is written through the store, so the index attests it and the
    tier is replayable. The fabricated one is written straight to disk: same key
    shape, no index row. That is the difference between a recording and a claim
    about a recording, and it is what ``ReplayStore.attested`` can see.
    """
    store = ReplayStore(root=tmp_path)
    tier = FraudFoxTier()
    config = Config()
    model = tier.model_id(config)
    store.put_response(
        tier=tier.name, model=model, payload=tier.prepare({"text": "baseline"}, config),
        response={"verdict": "SAFE", "safe_score": 0.9},
        endpoint_role="onnx-classifier",
    )
    message = parse_file(fixture)
    entry = build_entry(
        tier=tier.name,
        model=model,
        payload=tier.prepare({"text": message.body}, config),
        response=response,
        endpoint_role="hand-written",
    )
    path = store.path_for(tier.name, entry["key"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entry, sort_keys=True), encoding="utf-8")
    assert not store.attested(entry), (
        "the fixture is only meaningful if the store cannot attest to it"
    )
    return tmp_path


def test_a_fabricated_recording_is_refused_for_closure_naming_the_cause(tmp_path):
    """The mechanism, exercised the way an attacker or a lazy stub would.

    A hand-written recording says this verified credential-harvesting message is
    safe. The disposition still comes out THREAT -- the deterministic layer is a
    floor an opinion cannot talk down -- and the refusal is not about the answer
    being unfavourable: it is that the answer has no provenance, so the case may
    not close on it.
    """
    store = _fabricated_store(
        tmp_path / "corpus",
        fixture=THREAT_FIXTURE,
        response={"verdict": "SAFE", "safe_score": 0.99, "confidence": 0.99},
    )
    config = Config(replay=True, replay_dir=str(store))
    verdict = triage_file(THREAT_FIXTURE, config)

    assert verdict.evidence.simulated is True, (
        "an unattested recording must mark the record simulated"
    )
    assert verdict.disposition.value == "threat", (
        "the fabricated 'safe' answer must not talk a verified threat down"
    )
    causes = [
        f.detail for f in verdict.evidence.all("simulated_evidence")
    ]
    assert causes and "classifier" in causes[0]

    receipt = Receipt.for_verdict(verdict, manifest_path=LABELS)
    blockers = receipt.closure_blockers()
    assert any("simulated" in b for b in blockers), blockers

    runner = OfflineRunner(contract=load_contract(), root=tmp_path / "run",
                           manifest_path=LABELS)
    assert runner.begin(receipt).ok
    for step in runner.drive(receipt.receipt_id):
        assert step.ok, step.reason()
    closed = runner.close(receipt.receipt_id)
    assert not closed.ok
    assert closed.refusal.code == "closure-refused"
    assert "simulated" in closed.refusal.reason
    assert "classifier" in closed.refusal.reason, (
        "the refusal has to name which tier's answer is the problem"
    )
    on_disk = Receipt.load(
        Path(runner.root) / RECEIPTS_DIR / f"{receipt.receipt_id}.json"
    )
    assert on_disk.state == "opened", "a refused closure must not write a closed one"


def test_an_attested_recording_from_the_same_store_is_not_simulated(tmp_path):
    """The other side of the same mechanism: a real capture is evidence.

    Without this, the check above could be satisfied by refusing everything, which
    would be indistinguishable from a broken runner.
    """
    store = ReplayStore(root=tmp_path / "corpus")
    tier = FraudFoxTier()
    config = Config()
    message = parse_file(THREAT_FIXTURE)
    payload = tier.prepare({"text": message.body}, config)
    store.put_response(
        tier=tier.name, model=tier.model_id(config), payload=payload,
        response={"verdict": "PHISHING", "phishing_score": 0.97},
        endpoint_role="onnx-classifier",
    )
    verdict = triage_file(
        THREAT_FIXTURE, Config(replay=True, replay_dir=str(tmp_path / "corpus"))
    )
    assert verdict.evidence.simulated is False
    judged = verdict.evidence.by_provenance(Provenance.MODEL_JUDGMENT)
    assert judged and "source=replay" in judged[0].detail
    receipt = Receipt.for_verdict(verdict, manifest_path=LABELS)
    assert receipt.closure_blockers() == []


def test_a_stubbed_tier_answer_marks_the_record_simulated(tmp_path, monkeypatch):
    """The second way authored evidence arrives: a caller hands in an answer."""
    from tenable_email import tiers
    from tenable_email.pipeline import triage_message

    real = tiers.consult

    def stub(tier, request, config, store=None):
        result = real(tier, request, config, store)
        if tier.name == "prompt_injection":
            return tiers.TierResult(
                tier=tier.name, available=True, ok=True,
                raw={"verdict": "injection", "score": 0.99},
                source=tiers.SOURCE_STUB, model="a-stub",
            )
        return result

    monkeypatch.setattr(tiers, "consult", stub)
    verdict = triage_message(
        parse_file(CLEAN_FIXTURE), Config(replay=True, replay_dir=default_replay_dir())
    )
    assert verdict.evidence.simulated is True
    assert Provenance.UNKNOWN in [
        f.provenance for f in verdict.evidence.all("simulated_evidence")
    ]
    receipt = Receipt.for_verdict(verdict, manifest_path=LABELS)
    assert receipt.simulated is True
    assert any("stub" in b or "simulated" in b for b in receipt.closure_blockers())
