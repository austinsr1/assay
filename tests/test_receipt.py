"""The receipt contract: what a case record must carry, and what it must never.

Bundle D2 and the data half of D4. The receipt is the durable record an auditor
reads, so the tests are about three things: identity (the digests, and a file name
rather than a path), completeness (the closure rules that refuse simulated
evidence, a cited gap, an UNKNOWN, and a truncated verdict claiming to be done),
and the leak surface -- a receipt that embedded message bodies or attachment bytes
would be the thing this project promises not to ship.

The leak assertions are rebuilt from the fixtures themselves rather than trusting
the constructor: every body line long enough to be content, every attachment's
bytes, and its base64 form, are checked against the serialized record.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config, Thresholds, default_replay_dir  # noqa: E402
from tenable_email.evidence import Evidence, Provenance  # noqa: E402
from tenable_email.parse import parse_file  # noqa: E402
from tenable_email.pipeline import triage_bytes, triage_file  # noqa: E402
from tenable_email.receipt import (  # noqa: E402
    NO_MANIFEST,
    Receipt,
    ReceiptError,
    corpus_manifest,
    make_receipt_id,
    source_name,
    verdict_digest,
)
from tenable_email.verdict import AttackType, Disposition, Verdict  # noqa: E402

FIXTURES = REPO / "fixtures" / "synthetic"
LABELS = FIXTURES / "labels.json"


def replay_config() -> Config:
    return Config(replay=True, replay_dir=default_replay_dir())


def receipt_for(path: Path, config: Config | None = None) -> Receipt:
    verdict = triage_file(path, config or replay_config())
    return Receipt.for_verdict(verdict, manifest_path=LABELS)


def walk_keys(node) -> set[str]:
    """Every dict key at any depth -- the shape a leak would hide under."""
    if isinstance(node, dict):
        out = set(node)
        for value in node.values():
            out |= walk_keys(value)
        return out
    if isinstance(node, list):
        out = set()
        for item in node:
            out |= walk_keys(item)
        return out
    return set()


# --- D2: the record carries the right things --------------------------------


def test_a_receipt_carries_the_digest_of_the_verdict_it_was_made_from():
    verdict = triage_file(FIXTURES / "threat_lookalike_credential_harvest.eml",
                          replay_config())
    receipt = Receipt.for_verdict(verdict, manifest_path=LABELS)
    assert receipt.verdict_digest == verdict_digest(verdict)
    assert len(receipt.verdict_digest) == 64
    assert receipt.digest_matches(verdict)


def test_the_verdict_digest_is_canonical_so_dict_order_cannot_change_it():
    verdict = triage_file(FIXTURES / "clean_internal_registrar.eml", replay_config())
    again = triage_file(FIXTURES / "clean_internal_registrar.eml", replay_config())
    assert verdict_digest(verdict) == verdict_digest(again)
    verdict.reasons.append("an appended reason")
    assert verdict_digest(verdict) != verdict_digest(again), (
        "the digest must cover the whole record, not a subset of it"
    )


def test_the_receipt_id_is_stable_and_content_derived():
    a = receipt_for(FIXTURES / "clean_vendor_docusign.eml")
    b = receipt_for(FIXTURES / "clean_vendor_docusign.eml")
    assert a.receipt_id == b.receipt_id
    assert a.created_at == b.created_at or a.receipt_id == b.receipt_id
    other = receipt_for(FIXTURES / "spam_bulk_marketing.eml")
    assert other.receipt_id != a.receipt_id
    assert a.receipt_id.startswith("rcpt-")


def test_the_id_ignores_timestamps_but_binds_the_corpus():
    digest = "a" * 64
    one = make_receipt_id(source="x.eml", digest=digest, manifest_digest="b" * 64)
    two = make_receipt_id(source="x.eml", digest=digest, manifest_digest="b" * 64)
    three = make_receipt_id(source="x.eml", digest=digest, manifest_digest="c" * 64)
    assert one == two != three


def test_a_receipt_names_its_source_as_a_file_name_and_never_a_directory():
    absolute = FIXTURES / "threat_anchor_mismatch.eml"
    verdict = triage_file(absolute, replay_config())
    receipt = Receipt.for_verdict(verdict)
    assert receipt.source == "threat_anchor_mismatch.eml"
    assert "/" not in receipt.source
    text = receipt.to_json()
    # The directory the fixture lives in must not reach the record either.
    assert str(absolute) not in text
    assert "fixtures" not in text


def test_source_name_scrubs_a_path_supplied_by_a_caller():
    assert source_name("/some/where/message.eml") == "message.eml"
    assert source_name("message.eml") == "message.eml"
    assert source_name("inline") == "inline"
    assert source_name("") == "unknown"


def test_an_inline_source_is_kept_as_inline_rather_than_invented():
    verdict = triage_bytes(
        "From: Test <t@example.test>\r\nSubject: hi\r\n\r\nbody\r\n",
        Config(replay=True, replay_dir=None),
    )
    receipt = Receipt.for_verdict(verdict, source="inline")
    assert receipt.source == "inline"


# --- D2: digests and the corpus manifest ----------------------------------


def test_the_corpus_manifest_digest_binds_the_labels():
    label, digest = corpus_manifest(LABELS)
    assert label == "labels.json" and len(digest) == 64
    receipt = receipt_for(FIXTURES / "clean_internal_registrar.eml")
    assert receipt.corpus_manifest_digest == digest
    assert receipt.manifest_matches(label, digest)
    assert not receipt.manifest_matches(label, "f" * 64)


def test_a_run_with_no_manifest_records_none_instead_of_claiming_one(tmp_path):
    label, digest = corpus_manifest(tmp_path / "absent.json", tmp_path)
    assert label == NO_MANIFEST and digest == ""
    receipt = Receipt.for_verdict(
        triage_file(FIXTURES / "spam_bulk_marketing.eml", replay_config())
    )
    assert receipt.corpus_manifest == NO_MANIFEST
    # "nothing to compare" is not a mismatch, and must not be reported as one.
    assert receipt.manifest_matches(NO_MANIFEST, "")
    assert receipt.manifest_matches("labels.json", "abc")


def test_a_corpus_directory_without_a_manifest_falls_back_to_a_listing_digest(
    tmp_path,
):
    for name in ("a.eml", "b.eml"):
        (tmp_path / name).write_bytes(b"From: a@example.test\r\n\r\nx\r\n")
    label, digest = corpus_manifest(None, tmp_path)
    assert label.startswith("listing:") and len(digest) == 64
    (tmp_path / "a.eml").write_bytes(b"changed")
    assert corpus_manifest(None, tmp_path)[1] != digest, (
        "the listing digest must move when the corpus moves"
    )


# --- D2: serialization -----------------------------------------------------


def test_the_record_round_trips_through_json():
    receipt = receipt_for(FIXTURES / "threat_prompt_injection.eml")
    back = Receipt.from_json(receipt.to_json())
    assert back.receipt_id == receipt.receipt_id
    assert back.verdict_digest == receipt.verdict_digest
    assert back.disposition == receipt.disposition
    assert [i.key for i in back.evidence] == [i.key for i in receipt.evidence]
    assert [a.kind for a in back.proposed_actions] == [
        a.kind for a in receipt.proposed_actions
    ]
    assert back.closure_blockers() == receipt.closure_blockers()


def test_a_record_from_another_schema_version_is_refused_not_reinterpreted():
    data = receipt_for(FIXTURES / "clean_vendor_docusign.eml").to_dict()
    data["schema_version"] = 99
    with pytest.raises(ReceiptError):
        Receipt.from_dict(data)


def test_a_record_that_is_not_json_raises_a_receipt_error(tmp_path):
    path = tmp_path / "broken.receipt.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ReceiptError):
        Receipt.load(path)


def test_the_markdown_rendering_groups_evidence_by_provenance():
    receipt = receipt_for(FIXTURES / "clean_vendor_docusign.eml")
    text = receipt.to_markdown()
    for heading in (
        "Verified facts",
        "Model judgments",
        "Unknowns",
        "Unavailable",
        "Proposed actions",
        "Closure",
    ):
        assert heading in text, f"{heading} missing from the rendering"
    assert "human approval required" in text, (
        "the write stage's approval language must appear in the review document"
    )
    gaps = receipt.grouped()
    for provenance in ("unknown", "unavailable"):
        for item in gaps[provenance]:
            assert item.key in text, f"{provenance} finding {item.key} not rendered"


def test_the_serialized_record_has_no_bytes_and_no_data_key():
    receipt = receipt_for(FIXTURES / "threat_dangerous_attachment.eml")
    data = receipt.to_dict()
    assert "data" not in walk_keys(data)
    text = receipt.to_json()
    assert "\\u" not in text  # no escaped binary rendered as a string
    message = parse_file(FIXTURES / "threat_dangerous_attachment.eml")
    for attachment in message.attachments:
        assert attachment.data not in text.encode("utf-8", "ignore")


# --- no bodies, no attachment bytes: asserted, not assumed -----------------

BODY_FRAGMENT = 30  # characters of a body line that count as content, not prose


@pytest.mark.parametrize(
    "path", sorted(FIXTURES.glob("*.eml")), ids=lambda p: p.stem
)
def test_no_case_record_contains_a_message_body_or_attachment_bytes(path):
    """The receipt is a record *about* a message, never a copy of it.

    Checked against the fixture rather than against the constructor: the body text,
    every body line long enough to be real content, the attachment bytes, and
    their base64 form are all searched for in both serialized renderings. A
    verdict digest is what belongs in the record -- which is why the digest itself
    is asserted present, or this test would also pass by writing nothing.
    """
    message = parse_file(path)
    receipt = receipt_for(path)
    text = receipt.to_json() + receipt.to_markdown()

    assert receipt.verdict_digest in text, "the record must carry what it records"
    body = " ".join((message.text_body or message.html_body or "").split())
    if body:
        assert body not in text
    for line in (message.text_body + "\n" + message.html_body).splitlines():
        flat = " ".join(line.split())
        if len(flat) >= BODY_FRAGMENT:
            assert flat[:BODY_FRAGMENT] not in text, (
                f"{path.name}: a body line of {BODY_FRAGMENT} characters reached "
                f"the case record"
            )
    for attachment in message.attachments:
        payload = attachment.data
        if not payload:
            continue
        assert payload not in text.encode("utf-8", "ignore")
        encoded = base64.b64encode(payload).decode("ascii")
        assert encoded not in text
        assert encoded[:120] not in text
    assert "data" not in walk_keys(receipt.to_dict())


# --- D4: what may not close ------------------------------------------------


@pytest.mark.parametrize(
    "path", sorted(FIXTURES.glob("*.eml")), ids=lambda p: p.stem
)
def test_replayed_model_judgments_are_not_simulated(path):
    """The distinction that decides whether the offline path is usable.

    A recording is a real model's answer to this exact request. Marking replay as
    simulated would refuse closure on every case a reviewer can actually run, so
    this asserts the negative on the whole committed corpus, one fixture at a
    time, and names the tier whose answer it was.
    """
    verdict = triage_file(path, replay_config())
    assert verdict.evidence.simulated is False, (
        f"{path.name}: a corpus-backed run marked its evidence simulated"
    )
    receipt = Receipt.for_verdict(verdict, manifest_path=LABELS)
    assert receipt.simulated is False
    for item in receipt.evidence:
        if item.provenance == Provenance.MODEL_JUDGMENT.value:
            assert "source=replay" in item.detail


def _hand_built_verdict(
    *, disposition: Disposition = Disposition.THREAT,
    evidence: Evidence | None = None,
    cited: tuple[str, ...] = ("auth",),
    truncated: bool = False,
) -> Verdict:
    """A verdict assembled outside the pipeline.

    The pipeline cannot emit a verdict that cites a gap -- ``assert_citable``
    stops it -- so the closure gate is exercised on a record a caller built by
    hand. That is not a hypothetical: a receipt loaded from disk, a record written
    by another tool, and a future adapter all arrive this way.
    """
    ev = evidence or Evidence()
    ev.verified("auth", {"spf": "PASS"}, "parse-authenticate", "as recorded")
    verdict = Verdict(
        id="hand-built",
        subject="hand",
        sender="someone@example.test",
        disposition=disposition,
        attack_type=AttackType.CREDENTIAL_HARVEST,
        evidence=ev,
        truncated=truncated,
        reasons=["a reason a caller wrote"],
    )
    verdict.set_confidence(0.9)
    verdict.cited_findings = list(cited)
    return verdict


def test_a_verdict_citing_an_unavailable_finding_cannot_close():
    ev = Evidence()
    ev.verified("auth", {"spf": "PASS"}, "parse-authenticate")
    ev.unavailable("classifier", "classifier-cascade", "endpoint not configured")
    verdict = _hand_built_verdict(evidence=ev, cited=("auth", "classifier"))
    receipt = Receipt.for_verdict(verdict, manifest_path=LABELS)
    blockers = receipt.closure_blockers()
    assert any("classifier" in b and "unavailable" in b for b in blockers), blockers


def test_a_verdict_citing_an_unknown_finding_cannot_close():
    ev = Evidence()
    ev.unknown("account_compromised", "adjudication", "not knowable from a message")
    verdict = _hand_built_verdict(evidence=ev, cited=("account_compromised",))
    receipt = Receipt.for_verdict(verdict, manifest_path=LABELS)
    assert any("unknown" in b for b in receipt.closure_blockers())


def test_an_unknown_disposition_cannot_close_even_with_no_other_problem():
    verdict = _hand_built_verdict(disposition=Disposition.UNKNOWN)
    receipt = Receipt.for_verdict(verdict, manifest_path=LABELS)
    reasons = " | ".join(receipt.closure_blockers())
    assert "UNKNOWN" in reasons
    assert verdict.disposition is Disposition.UNKNOWN


def test_a_simulated_record_cannot_close_and_names_the_cause():
    ev = Evidence()
    ev.verified("auth", {"spf": "PASS"}, "parse-authenticate")
    ev.mark_simulated("classifier-cascade", "the classifier answer was hand-written")
    verdict = _hand_built_verdict(evidence=ev)
    receipt = Receipt.for_verdict(verdict, manifest_path=LABELS)
    assert receipt.simulated is True
    blockers = receipt.closure_blockers()
    assert any("simulated" in b for b in blockers)
    assert any("hand-written" in b for b in blockers), (
        "the refusal must carry the cause, not just the flag"
    )


def test_a_truncated_verdict_may_not_close_as_complete():
    """A partial reading that claims a settled answer is refused.

    The bound is set deliberately small: cutting the body at 40 characters removes
    the link the anchor-mismatch fixture is judged on, so the deterministic layer
    reaches a different answer than a full reading would. That is the whole reason
    the rule exists -- truncation does not merely lose detail, it changes the
    answer -- and both readings are asserted here rather than described.
    """
    config = Config(
        replay=True, replay_dir=None, thresholds=Thresholds(body_char_limit=40)
    )
    truncated = triage_file(
        FIXTURES / "threat_lookalike_credential_harvest.eml", config
    )
    assert truncated.truncated is True
    assert truncated.disposition is Disposition.THREAT
    receipt = Receipt.for_verdict(truncated, manifest_path=LABELS)
    assert receipt.claims_completeness
    blockers = receipt.closure_blockers()
    assert any("truncated" in b for b in blockers), blockers

    # The same cut, on the fixture whose evidence lives in the part that was
    # dropped. The answer still changes -- a full reading says THREAT and this one
    # does not -- but it no longer changes to a *clearance*, and that is worth
    # recording rather than papering over: since the clearance gate was tightened
    # in response to the red-team review, a truncated message from a sender nobody
    # vouches for cannot be cleared at all, so the protection now arrives earlier
    # than this closure rule. The rule is still load-bearing, and the first half
    # of this test is what proves it: a truncated verdict that does reach a
    # settled disposition may not claim to be complete.
    lost = triage_file(FIXTURES / "threat_anchor_mismatch.eml", config)
    assert lost.truncated, "the premise is that this cut actually truncates"
    assert lost.disposition is not Disposition.THREAT, (
        "the premise of this rule is that truncation changes the answer; if a "
        "future corpus stops demonstrating that, say so here rather than keeping "
        "a comment about it"
    )
    assert lost.disposition is Disposition.MANUAL_REVIEW, (
        "a truncated message from an unvouched sender goes to a human; if this "
        "moved to CLEAN the clearance gate has been weakened again"
    )


def test_a_truncated_escalation_is_honest_and_may_close():
    """The nuance the rule needs: partial reading + "a person must look" is true.

    Refusing every truncated record would make the flag meaningless -- it would
    refuse the escalation that exists precisely *because* of the truncation. The
    refusal is for a record that claims to have finished.
    """
    config = Config(
        replay=True, replay_dir=None, thresholds=Thresholds(body_char_limit=60)
    )
    verdict = triage_bytes(
        "From: Finance <finance@example.edu>\r\n"
        "Subject: Payment today\r\n"
        "Authentication-Results: mx.example.edu; spf=pass dkim=pass dmarc=pass\r\n"
        "Reply-To: finance-office@secure-transfer.test\r\n"
        "Content-Type: text/plain\r\n\r\n"
        + "please arrange the wire payment today and treat this as urgent. " * 12,
        config,
    )
    assert verdict.truncated is True
    assert verdict.disposition is Disposition.MANUAL_REVIEW
    receipt = Receipt.for_verdict(verdict, manifest_path=LABELS)
    assert not receipt.claims_completeness
    assert not any("truncated" in b for b in receipt.closure_blockers())


def test_a_clean_corpus_case_has_no_closure_blocker():
    receipt = receipt_for(FIXTURES / "threat_anchor_mismatch.eml")
    assert receipt.closure_blockers() == []
    assert receipt.disposition == Disposition.THREAT.value
    assert receipt.cited_items(), "a closable record still has to cite something"


def test_the_record_counts_each_provenance_separately():
    receipt = receipt_for(FIXTURES / "threat_lookalike_credential_harvest.eml")
    counts = receipt.counts()
    assert counts[Provenance.VERIFIED.value] > 0
    assert counts[Provenance.MODEL_JUDGMENT.value] > 0
    assert sum(counts.values()) == len(receipt.evidence)


def test_the_proposed_actions_are_recorded_but_nothing_is_executed():
    receipt = receipt_for(FIXTURES / "threat_bec_valid_auth.eml")
    kinds = [a.kind for a in receipt.proposed_actions]
    assert "record_case" in kinds
    assert "notify_analyst" in kinds, "an escalation nobody is told about is not one"
    assert receipt.approval_state == "pending"
    assert receipt.execution == []
    assert receipt.approval is None
