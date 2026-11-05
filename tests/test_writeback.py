"""The human-approval gate on the one write stage (D6).

``stages.yaml`` declares a single ``access: write`` stage with
``approval_required: true``. Bundle B made that declaration machine-checkable; this
module's tests are about the gate itself: the actions a verdict proposes, the
approval that binds a human's yes to one verdict digest and one target set, the
non-mutating provider that is the default, and the fact that nothing in this
bundle holds or reads a credential.

The reference playbook posts a tag *and* a comment. Our feed has no comment API, so
``post_comment`` is named in the vocabulary for parity and is deliberately never
proposed -- inventing a destination would be a fiction about an integration nobody
has decided on (``NOTES.md`` open decision 2).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config, default_replay_dir  # noqa: E402
from tenable_email.contract import load_contract  # noqa: E402
from tenable_email.pipeline import triage_file  # noqa: E402
from tenable_email.receipt import Receipt  # noqa: E402
from tenable_email.runner import OfflineRunner  # noqa: E402
from tenable_email.verdict import Disposition, Verdict  # noqa: E402
from tenable_email.writeback import (  # noqa: E402
    ACTION_KINDS,
    DEFAULT_PROVIDER,
    GENERATED_ACTION_KINDS,
    PROVIDER_ENV,
    Approval,
    DryRunProvider,
    ProposedAction,
    WritebackError,
    issue_approval,
    label_for,
    proposed_actions,
    provider_for,
    token_for,
)

FIXTURES = REPO / "fixtures" / "synthetic"
LABELS = FIXTURES / "labels.json"


def receipt_for(name: str) -> Receipt:
    verdict = triage_file(
        FIXTURES / name, Config(replay=True, replay_dir=default_replay_dir())
    )
    return Receipt.for_verdict(verdict, manifest_path=LABELS)


def runner_with(tmp_path, name: str = "threat_lookalike_credential_harvest.eml"):
    runner = OfflineRunner(
        contract=load_contract(), root=tmp_path / "run", manifest_path=LABELS
    )
    receipt = receipt_for(name)
    begun = runner.begin(receipt)
    assert begun.ok, begun.reason()
    for step in runner.drive(receipt.receipt_id):
        assert step.ok, step.reason()
    return runner, receipt.receipt_id


# --- proposed actions ------------------------------------------------------


def test_a_threat_proposes_a_label_and_a_case_record_and_nothing_else():
    verdict = triage_file(
        FIXTURES / "threat_lookalike_credential_harvest.eml",
        Config(replay=True, replay_dir=default_replay_dir()),
    )
    actions = proposed_actions(verdict, target="threat_lookalike.eml")
    kinds = [a.kind for a in actions]
    assert kinds == ["record_case", "apply_label"]
    assert all(a.target == "threat_lookalike.eml" for a in actions)
    label_action = next(a for a in actions if a.kind == "apply_label")
    assert label_for(Disposition.THREAT) in label_action.summary


def test_an_escalated_case_notifies_an_analyst():
    actions = receipt_for("threat_bec_valid_auth.eml").proposed_actions
    kinds = [a.kind for a in actions]
    assert "notify_analyst" in kinds, (
        "an escalation that nobody is told about is not an escalation"
    )
    assert "apply_label" in kinds


def test_an_unreadable_message_proposes_no_label():
    """Nothing may be labelled outward when nothing was read."""
    verdict = Verdict(id="blank", disposition=Disposition.UNKNOWN)
    verdict.set_confidence(0.0)
    kinds = [a.kind for a in proposed_actions(verdict, target="blank.eml")]
    assert "apply_label" not in kinds
    assert kinds and kinds[0] == "record_case"


def test_post_comment_is_declared_for_parity_and_never_generated():
    assert "post_comment" in ACTION_KINDS
    assert "post_comment" not in GENERATED_ACTION_KINDS
    # Every kind the corpus actually proposes is one an operator could approve,
    # and none of them is the comment the reference playbook posts.
    for name in sorted(p.name for p in FIXTURES.glob("*.eml")):
        actions = receipt_for(name).proposed_actions
        assert {a.kind for a in actions} <= set(GENERATED_ACTION_KINDS)
        assert {a.kind for a in actions} <= set(ACTION_KINDS)


def test_an_action_summary_describes_the_payload_without_carrying_it():
    actions = receipt_for("threat_image_credential_harvest.eml").proposed_actions
    text = json.dumps([a.as_dict() for a in actions])
    assert "data" not in text
    body = (FIXTURES / "threat_image_credential_harvest.eml").read_bytes()
    assert body[200:500] not in text.encode("utf-8", "ignore")


def test_an_unknown_action_kind_is_a_programming_error():
    with pytest.raises(WritebackError):
        ProposedAction(kind="email-the-press", target="x.eml", summary="s",
                       rationale="r")
    with pytest.raises(WritebackError):
        ProposedAction(kind="apply_label", target="", summary="s", rationale="r")


def test_action_digests_are_content_derived_and_order_sensitive():
    one = ProposedAction("apply_label", "a.eml", "label triage/threat", "why")
    two = ProposedAction("apply_label", "a.eml", "label triage/threat", "why")
    three = ProposedAction("apply_label", "b.eml", "label triage/threat", "why")
    assert one.digest() == two.digest() != three.digest()
    assert one.binding == "apply_label:a.eml"


# --- approvals -------------------------------------------------------------


def test_an_approval_binds_approver_digest_targets_and_actions():
    receipt = receipt_for("threat_anchor_mismatch.eml")
    approval = issue_approval(
        approver="analyst@example.edu",
        verdict_digest=receipt.verdict_digest,
        targets=[receipt.receipt_id],
        actions=["record_case", "apply_label"],
    )
    assert approval.approver == "analyst@example.edu"
    assert approval.matches(receipt.verdict_digest)
    assert approval.covers(receipt.receipt_id)
    assert approval.covers_action("apply_label")
    assert not approval.covers_action("notify_analyst")
    assert not approval.covers("rcpt-someone-elses-case")
    assert len(approval.token) == 24


def test_the_token_is_deterministic_from_what_it_approves():
    base = dict(approver="a@example.edu", verdict_digest="d" * 64,
                targets=["r1"], actions=["record_case"])
    assert token_for(**base) == token_for(**base)
    assert token_for(**base, nonce="1") != token_for(**base, nonce="2")
    wider = dict(base, targets=["r1", "r2"])
    assert token_for(**wider) != token_for(**base)
    other_actions = dict(base, actions=["record_case", "apply_label"])
    assert token_for(**other_actions) != token_for(**base)


def test_an_approval_must_name_an_approver_a_digest_a_target_and_known_actions():
    with pytest.raises(WritebackError):
        issue_approval(approver=" ", verdict_digest="x", targets=["r"])
    with pytest.raises(WritebackError):
        issue_approval(approver="a", verdict_digest="", targets=["r"])
    with pytest.raises(WritebackError):
        issue_approval(approver="a", verdict_digest="x", targets=[])
    with pytest.raises(WritebackError):
        issue_approval(approver="a", verdict_digest="x", targets=["r"],
                       actions=["sell-the-data"])


def test_approvals_round_trip_through_a_receipt():
    receipt = receipt_for("clean_vendor_docusign.eml")
    approval = issue_approval(
        approver="analyst@example.edu",
        verdict_digest=receipt.verdict_digest,
        targets=[receipt.receipt_id],
        actions=[a.kind for a in receipt.proposed_actions],
        note="checked the DKIM alignment myself",
    )
    receipt.approval = approval
    back = Receipt.from_json(receipt.to_json())
    assert back.approval == approval
    assert back.approval.note == "checked the DKIM alignment myself"


# --- the default provider changes nothing ----------------------------------


def test_dry_run_is_the_default_and_is_declared_non_mutating():
    provider = provider_for()
    assert isinstance(provider, DryRunProvider)
    assert provider.name == DEFAULT_PROVIDER == "dry-run"
    assert provider.mutates is False
    assert "dry-run" in provider.describe()


def test_the_provider_is_selected_by_name_or_environment_never_by_credential(
    monkeypatch,
):
    assert provider_for("dry-run").name == "dry-run"
    monkeypatch.setenv(PROVIDER_ENV, "dry-run")
    assert provider_for().name == "dry-run"
    monkeypatch.setenv(PROVIDER_ENV, "gmail-labels")
    with pytest.raises(WritebackError) as excinfo:
        provider_for()
    assert "open decision 2" in str(excinfo.value)
    # A name that is not a provider is refused rather than quietly downgraded.
    with pytest.raises(WritebackError):
        provider_for("gmail")


def test_dry_run_records_the_intention_and_changes_nothing(tmp_path):
    runner, receipt_id = runner_with(tmp_path)
    receipt = runner.get(receipt_id)
    approval = runner.request_approval(receipt_id, approver="analyst@example.edu")
    assert runner.grant(receipt_id, approval).ok

    watched = tmp_path / "watched"
    watched.mkdir()

    executed = runner.execute(receipt_id)
    assert executed.ok, executed.reason()
    assert watched.is_dir() and list(watched.iterdir()) == []
    assert all(not r.performed for r in executed.results), (
        "the default provider must report that it performed nothing"
    )
    assert list(runner.provider.log) == list(executed.results)
    kinds = [entry["kind"] for entry in executed.receipt.execution]
    assert kinds == [a.kind for a in receipt.proposed_actions]
    for entry in executed.receipt.execution:
        assert entry["provider"] == "dry-run"
        assert entry["performed"] is False
        assert "would have" in entry["detail"]
        assert approval.token not in entry["detail"], (
            "the record names the approver, not the instrument"
        )


def test_no_credential_is_read_or_recorded_anywhere_in_the_write_path(
    tmp_path, monkeypatch
):
    """The runner holds no credentials: neither an env value nor a key file.

    A fake secret is put in the environment where a live endpoint's key would go,
    and asserted absent from every record the bundle writes. ``ModelEndpoints``
    may read that variable for a live tier call -- Bundle C's behaviour, and only
    when an address is named -- so what this test pins is the boundary this bundle
    owns: a credential must not reach a receipt, a journal line, a provider log
    entry or a proposed action.
    """
    from tenable_email.cli import config_for, resolve_corpus

    secret = "NOT-A-REAL-KEY-1234567890"
    monkeypatch.setenv("TENABLE_EMAIL_LLM_API_KEY", secret)

    config = config_for(resolve_corpus(None))
    assert config.endpoints.llm_api_key == secret, (
        "the pre-existing config plumbing still reads it, which is exactly why "
        "the records below are checked"
    )

    runner = OfflineRunner(
        contract=load_contract(), root=tmp_path / "run", manifest_path=LABELS
    )
    receipt = Receipt.for_verdict(
        triage_file(FIXTURES / "threat_redirect_wrapped.eml", config),
        manifest_path=LABELS,
    )
    assert runner.begin(receipt).ok
    for step in runner.drive(receipt.receipt_id):
        assert step.ok, step.reason()
    approval = runner.request_approval(receipt.receipt_id, approver="a@example.edu")
    assert runner.grant(receipt.receipt_id, approval).ok
    assert runner.execute(receipt.receipt_id).ok
    assert runner.close(receipt.receipt_id).ok

    written = [path for path in Path(runner.root).rglob("*") if path.is_file()]
    assert written, "the run directory should not be empty"
    for path in written:
        assert secret not in path.read_text(encoding="utf-8"), path.name
    assert secret not in json.dumps(runner.journal())
    assert secret not in runner.receipts()[0].to_markdown()
    assert secret not in json.dumps(config.endpoints.as_dict()), (
        "the endpoints view a record could embed is the redacting one"
    )
    assert secret not in json.dumps(
        [a.as_dict() for a in runner.provider.log]
    )


def test_the_write_path_has_no_transport_to_configure():
    """No provider in this bundle can reach a network, a shell or a service.

    Checked on the import graph rather than by grepping the source: the module's
    own prose says "no socket, no subprocess", and a text search would then fail
    on the sentence that makes the promise. What matters is that nothing is
    imported that could perform it.
    """
    import ast
    import pathlib as _pathlib

    import tenable_email.writeback as module

    tree = ast.parse(
        _pathlib.Path(module.__file__).read_text(encoding="utf-8")
    )
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    forbidden = {"urllib", "socket", "http", "requests", "subprocess", "smtplib",
                 "ssl", "ftplib", "asyncio"}
    reached = sorted(imported & forbidden)
    assert not reached, (
        f"the write-gate module imports {reached}; a mutation is a provider's job, "
        f"and the only provider shipped performs none"
    )
    # The positive form of the same claim: standard library only, and no
    # third-party import that would break ``dependencies = []``.
    assert imported <= {
        "__future__", "hashlib", "os", "dataclasses", "datetime", "typing",
    }, f"unexpected imports: {sorted(imported)}"


def test_no_provider_ships_that_mutates_an_external_system():
    """The policy this test exists to hold, restated for what is now true.

    It used to assert that nothing at all mutates, because the only provider was
    dry-run. The ledger changed that: it writes a local SQLite case record. What the
    policy was actually protecting is narrower and still holds - nothing in this
    build reaches out and changes a system the operator does not own. A mail-system
    destination remains an open operator decision, and no provider here invents one.

    Asserting only "ledger mutates" would lose that, and asserting "nothing mutates"
    is now simply false. So the invariant is stated as the thing that matters: the
    one mutating provider writes a local file and holds no transport.
    """
    from tenable_email.writeback import PROVIDERS, _resolve

    assert set(PROVIDERS) == {"dry-run", "ledger"}

    # The ledger entry is a name until first use, because importing it eagerly would
    # be circular. Resolve before inspecting, the way any real caller does.
    classes = {name: _resolve(name) for name in PROVIDERS}
    mutating = sorted(name for name, cls in classes.items() if cls.mutates)
    assert mutating == ["ledger"], (
        f"a new mutating provider appeared: {mutating}. If it contacts an external "
        "system it needs an operator decision and a destination, not a default."
    )
    LedgerProvider = classes["ledger"]

    # The ledger is mutating, but only locally: no socket, no subprocess, no
    # credential, and no transport attribute of any kind.
    for attr in ("session", "transport", "http", "client", "url", "endpoint",
                 "credentials", "token"):
        assert not hasattr(LedgerProvider, attr), (
            f"LedgerProvider grew a {attr!r}; the local-only invariant is that it "
            "has no transport"
        )
    assert not classes["dry-run"].mutates


def test_an_approval_can_cover_only_the_actions_it_lists(tmp_path):
    """The gate is per mutation, so a partial approval is a partial execution."""
    runner, receipt_id = runner_with(tmp_path)
    receipt = runner.get(receipt_id)
    kinds = [a.kind for a in receipt.proposed_actions]
    assert len(kinds) >= 2, "this test needs more than one mutation to be meaningful"
    approval = issue_approval(
        approver="analyst@example.edu",
        verdict_digest=receipt.verdict_digest,
        targets=[receipt_id],
        actions=[kinds[0]],
    )
    assert runner.grant(receipt_id, approval).ok
    executed = runner.execute(receipt_id)
    assert not executed.ok
    assert executed.refusal.code == "unapproved-action"
    assert kinds[1] in executed.refusal.reason
    assert runner.provider.log == []
    assert runner.get(receipt_id).approval_state == "granted", (
        "a refused execution leaves the grant intact and the case resumable"
    )
