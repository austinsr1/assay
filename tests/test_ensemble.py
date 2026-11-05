"""The ensemble: asymmetric by construction, and never an average of a fact.

These tests are the reason :mod:`tenable_email.ensemble` exists instead of a
weighted mean. Each one states a property that a naive combination would fail:

* a model cannot talk a verified lookalike finding down to ``CLEAN``;
* two tiers that disagree produce a person, not a number between them;
* clearing a message requires more certainty than flagging one, and the ratio is
  a parameter with a reason attached rather than a comparison in the middle of a
  conditional;
* an opinion formed from less information than the deterministic layer had cannot
  reopen a settled message.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config  # noqa: E402
from tenable_email.evidence import Provenance  # noqa: E402
from tenable_email.pipeline import triage_bytes  # noqa: E402
from tenable_email.tiers import Judgment, LlmTier, Stance, VlmTier  # noqa: E402
from tenable_email.verdict import AttackType, Disposition  # noqa: E402
from tenable_email import ensemble  # noqa: E402
from tenable_email.ensemble import (  # noqa: E402
    ADJUDICATION_TIER,
    DEFAULT_POLICY,
    Deterministic,
    EnsemblePolicy,
    combine,
)

CONFIG = Config()


def judgment(tier: str = "classifier", stance: Stance = Stance.CLEAN,
             confidence: float | None = 0.9,
             attack_type: AttackType | None = None) -> Judgment:
    return Judgment(tier=tier, stance=stance, confidence=confidence,
                    attack_type=attack_type)


CLEAN_THREAT = Deterministic(
    disposition=Disposition.THREAT, confidence=0.95,
    attack_type=AttackType.CREDENTIAL_HARVEST, decisive=True, clear_blocked=True,
    reasons=("Sender domain 'example-portal-verify.com' impersonates a protected "
             "domain.",),
    cited=("lookalike", "links"),
)

OPEN = Deterministic(
    disposition=Disposition.MANUAL_REVIEW, confidence=0.5,
    attack_type=AttackType.BEC, decisive=False, clear_blocked=True,
    reasons=("Authentication passes but this is the compromise shape.",),
    cited=("alignment",),
)

OPEN_UNBLOCKED = Deterministic(
    disposition=Disposition.MANUAL_REVIEW, confidence=0.5,
    attack_type=AttackType.UNCLASSIFIED, decisive=False, clear_blocked=False,
    reasons=("Nothing deterministic settles this.",),
    cited=("auth",),
)

SETTLED_CLEAN = Deterministic(
    disposition=Disposition.CLEAN, confidence=0.9, attack_type=AttackType.NONE,
    decisive=True, clear_blocked=False,
    reasons=("Authentication passed and no adverse indicator was found.",),
    cited=("auth", "links", "attachments"),
)

SETTLED_SPAM = Deterministic(
    disposition=Disposition.SPAM, confidence=0.8, attack_type=AttackType.NONE,
    decisive=True, clear_blocked=False,
    reasons=("Bulk-mail headers are present and authentication passes.",),
    cited=("bulk", "auth"),
)


# --- the asymmetric penalty -------------------------------------------------


def test_the_clearance_bar_is_derived_from_the_cost_ratio_not_chosen():
    assert DEFAULT_POLICY.false_negative_cost == 6.0
    assert DEFAULT_POLICY.clearance_bar == pytest.approx(6.0 / 7.0, abs=1e-3)
    harsher = EnsemblePolicy(false_negative_cost=9.0)
    assert harsher.clearance_bar > DEFAULT_POLICY.clearance_bar
    # The bar is a *clearance* bar: flagging needs only the medium band.
    assert harsher.clearance_bar > CONFIG.thresholds.band_medium


def test_clearing_needs_more_certainty_than_flagging():
    """Same votes, opposite stances, opposite bars."""
    weak_threat = combine(
        OPEN_UNBLOCKED,
        [judgment("classifier", Stance.THREAT, 0.70)],
        CONFIG,
    )
    weak_clean = combine(
        OPEN_UNBLOCKED,
        [judgment("classifier", Stance.CLEAN, 0.70)],
        CONFIG,
    )
    assert weak_threat.disposition is Disposition.THREAT
    assert weak_clean.disposition is Disposition.MANUAL_REVIEW
    assert any("0.857" in r for r in weak_clean.reasons)


def test_a_model_cannot_downgrade_a_verified_lookalike_finding_to_clean():
    """The rule the reference playbook's domain-match flaw breaks.

    The dissent is recorded rather than dropped: "the classifier said safe" is
    information a reviewer is owed, even when it changes nothing.
    """
    outcome = combine(
        CLEAN_THREAT,
        [judgment("classifier", Stance.CLEAN, 0.99998),
         judgment("prompt_injection", Stance.CLEAN, 0.97)],
        CONFIG,
    )
    assert outcome.disposition is Disposition.THREAT
    assert outcome.confidence == pytest.approx(0.95)
    assert outcome.attack_type is AttackType.CREDENTIAL_HARVEST
    assert outcome.changed_deterministic is False
    text = " ".join(outcome.reasons)
    assert "not applied" in text
    assert "verified findings" in text
    assert "lookalike" in text


def test_a_verified_anchor_mismatch_survives_a_unanimous_clean_vote():
    outcome = combine(
        CLEAN_THREAT,
        [judgment(t, Stance.CLEAN, 0.99) for t in
         ("classifier", "url_reputation", "prompt_injection", "vision")],
        CONFIG,
    )
    assert outcome.disposition is Disposition.THREAT


def test_a_model_may_escalate_a_settled_message_only_if_it_saw_the_facts():
    """Only the adjudication tier, and only above the clearance bar.

    The other tiers read the body text, one URL or one image: they never see the
    authentication results or the MIME inventory the disposition was built from.
    Measured on this corpus, the text classifier reads a mailer-daemon bounce as
    phishing at 0.99 and a security newsletter as phishing at 0.98 -- an opinion
    formed on less information than the fact cannot reopen it.

    It can, since the red-team review, *veto an automatic clearance* above
    ``specialist_veto_bar``, which moves the disposition to MANUAL_REVIEW and
    stops there. That is a different power from authoring a verdict and the two
    are asserted separately below.
    """
    # A text tier may not reopen a settled message at all: it reads the same body
    # text the rules already parsed, and on this corpus it reads a mailer-daemon
    # bounce as phishing at 0.99. Its vote is recorded, not applied.
    from_a_text_tier = combine(
        SETTLED_CLEAN, [judgment("classifier", Stance.THREAT, 0.99)], CONFIG
    )
    assert from_a_text_tier.disposition is Disposition.CLEAN
    assert from_a_text_tier.changed_deterministic is False
    assert from_a_text_tier.clearance_vetoed is False

    # A tier that saw evidence the rules could not -- pixels, in this case -- may
    # veto the clearance. This is R11 from the external red-team review: the old
    # code returned CLEAN here, so a vision tier reporting a credential-harvesting
    # image at 0.999 was recorded and then ignored, and nothing downstream could
    # reopen the message. The veto moves it to a human; it does not author a
    # threat verdict, and no attack type is asserted over the verified findings.
    vetoed = combine(
        SETTLED_CLEAN, [judgment(VlmTier.name, Stance.THREAT, 0.999)], CONFIG
    )
    assert vetoed.disposition is Disposition.MANUAL_REVIEW
    assert vetoed.clearance_vetoed is True
    assert vetoed.changed_deterministic is True
    assert vetoed.attack_type is AttackType.NONE

    # Below the veto bar the clearance stands, so this is not a general "any
    # independent tier may escalate" rule.
    unpersuasive = combine(
        SETTLED_CLEAN,
        [judgment(VlmTier.name, Stance.THREAT,
                  DEFAULT_POLICY.specialist_veto_bar - 0.05)],
        CONFIG,
    )
    assert unpersuasive.disposition is Disposition.CLEAN
    assert unpersuasive.clearance_vetoed is False

    confident = combine(
        SETTLED_CLEAN,
        [judgment(ADJUDICATION_TIER, Stance.THREAT, 0.95,
                  AttackType.BEC)],
        CONFIG,
    )
    assert confident.disposition is Disposition.THREAT
    assert confident.confidence == pytest.approx(0.95)
    assert confident.attack_type is AttackType.BEC
    assert confident.changed_deterministic is True

    hesitant = combine(
        SETTLED_CLEAN,
        [judgment(LlmTier.name, Stance.THREAT,
                  DEFAULT_POLICY.clearance_bar - 0.05)],
        CONFIG,
    )
    assert hesitant.disposition is Disposition.CLEAN


def test_adjudication_tier_name_is_the_registered_one():
    assert ADJUDICATION_TIER == "llm"
    assert LlmTier().name == ADJUDICATION_TIER


# --- disagreement escalates -------------------------------------------------


def test_tiers_that_disagree_produce_a_person_not_an_average():
    outcome = combine(
        OPEN_UNBLOCKED,
        [judgment("classifier", Stance.THREAT, 0.9),
         judgment("llm", Stance.CLEAN, 0.9)],
        CONFIG,
    )
    assert outcome.disposition is Disposition.MANUAL_REVIEW
    assert outcome.disagreement is True
    assert outcome.confidence < CONFIG.thresholds.band_medium
    assert "do not agree" in " ".join(outcome.reasons)
    # Neither vote's number was carried into the result as if it were the answer.
    assert outcome.confidence != 0.9


def test_a_model_confidence_below_the_medium_band_routes_to_manual_review():
    outcome = combine(
        OPEN_UNBLOCKED,
        [judgment("classifier", Stance.THREAT, 0.4),
         judgment("llm", Stance.THREAT, 0.55)],
        CONFIG,
    )
    assert outcome.disposition is Disposition.MANUAL_REVIEW
    assert outcome.confidence < CONFIG.thresholds.band_medium
    assert "not confident enough" in " ".join(outcome.reasons)


def test_an_unquantified_opinion_can_escalate_but_cannot_be_adopted():
    """A one-word label has no confidence, and pretending otherwise is a lie."""
    outcome = combine(
        OPEN_UNBLOCKED,
        [judgment("injection_classifier", Stance.THREAT, None)],
        CONFIG,
    )
    assert outcome.disposition is Disposition.MANUAL_REVIEW
    assert outcome.disagreement is True


def test_unanimous_votes_adopt_the_weakest_confidence_not_the_mean():
    outcome = combine(
        OPEN_UNBLOCKED,
        [judgment("classifier", Stance.THREAT, 0.99),
         judgment("llm", Stance.THREAT, 0.70)],
        CONFIG,
    )
    assert outcome.disposition is Disposition.THREAT
    assert outcome.confidence == pytest.approx(0.70)
    assert 0.70 < (0.99 + 0.70) / 2, "the mean would overstate the agreement"


def test_the_bec_shape_is_not_cleared_by_tiers_agreeing_with_each_other():
    """Whether the account is compromised is an UNKNOWN, and a vote is not an answer.

    Every tier reading the same text can only read the same text: unanimity about
    a message that authenticates correctly and asks for money is not evidence that
    the account is not compromised.
    """
    outcome = combine(
        OPEN,
        [judgment("classifier", Stance.CLEAN, 0.999),
         judgment("llm", Stance.CLEAN, 0.95)],
        CONFIG,
    )
    assert outcome.disposition is Disposition.MANUAL_REVIEW
    assert outcome.attack_type is AttackType.BEC
    assert "compromised" in " ".join(outcome.reasons)


def test_a_unanimous_spam_vote_produces_the_spam_class():
    """The third class the reference has and the predecessor engine lacked."""
    outcome = combine(
        OPEN_UNBLOCKED,
        [judgment("spam_three_way", Stance.SPAM, 0.88),
         judgment("llm", Stance.SPAM, 0.9)],
        CONFIG,
    )
    assert outcome.disposition is Disposition.SPAM
    assert outcome.attack_type is AttackType.SPAM
    assert outcome.confidence == pytest.approx(0.88)
    assert "unwanted" in " ".join(outcome.reasons).lower()


def test_a_unanimous_confident_clean_vote_clears_an_open_message():
    outcome = combine(
        OPEN_UNBLOCKED,
        [judgment("classifier", Stance.CLEAN, 0.99),
         judgment("llm", Stance.CLEAN, 0.97)],
        CONFIG,
    )
    assert outcome.disposition is Disposition.CLEAN
    assert outcome.attack_type is AttackType.NONE
    assert outcome.escalated is False


def test_no_votes_at_all_leaves_the_deterministic_outcome_untouched():
    for base in (CLEAN_THREAT, OPEN, OPEN_UNBLOCKED, SETTLED_CLEAN):
        outcome = combine(base, [], CONFIG)
        assert outcome.disposition is base.disposition
        assert outcome.confidence == pytest.approx(base.confidence)
        assert outcome.changed_deterministic is False


def test_an_abstaining_tier_is_recorded_and_changes_nothing():
    outcome = combine(
        CLEAN_THREAT,
        [Judgment(tier="vision", stance=Stance.ABSTAIN, confidence=None,
                  detail="vision output was not JSON")],
        CONFIG,
    )
    assert outcome.disposition is Disposition.THREAT
    assert outcome.model_reasons and "abstain" in outcome.model_reasons[0]


def test_cited_keys_carry_over_from_the_deterministic_outcome():
    outcome = combine(CLEAN_THREAT, [judgment("classifier", Stance.CLEAN, 0.9)],
                      CONFIG)
    assert set(("lookalike", "links")) <= set(outcome.cited)


# --- through the pipeline, where provenance is actually attached ------------


BEC_BYTES = (
    "From: Colleague <colleague@example.edu>\r\n"
    "To: finance@example.edu\r\n"
    "Subject: Quick favor - vendor payment\r\n"
    "Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n"
    "Reply-To: colleague.personal@mailbox-external.test\r\n\r\n"
    "Can you wire payment today? Do not mention this, it is not announced.\r\n"
)

LOOKALIKE_BYTES = (
    "From: IT Service Desk <noreply@example-portal-verify.com>\r\n"
    "To: staff@example.edu\r\n"
    "Subject: Action Required: your mailbox storage is full\r\n"
    "Authentication-Results: mx; spf=fail dkim=none dmarc=fail\r\n\r\n"
    "Verify at http://example-portal-verify.com/auth/login\r\n"
)


def test_model_judgments_never_reach_the_record_as_verified(tmp_path):
    """The provenance rule, checked on the findings a verdict actually cites."""
    from tenable_email.replay import ReplayStore
    from tenable_email.tiers import FraudFoxTier

    store = ReplayStore(root=tmp_path)
    tier = FraudFoxTier()
    config = Config(replay=True, replay_dir=str(tmp_path))
    body = parse_body(BEC_BYTES)
    store.put_response(
        tier=tier.name, model=tier.model_id(Config()),
        payload=tier.prepare({"text": body}, config),
        response={"verdict": "SAFE", "safe_score": 0.999, "confidence": 0.999},
        endpoint_role="onnx-classifier",
    )
    verdict = triage_bytes(BEC_BYTES, config)
    judgments = verdict.evidence.by_provenance(Provenance.MODEL_JUDGMENT)
    assert [f.key for f in judgments] == ["classifier"]
    assert all(f.provenance is Provenance.MODEL_JUDGMENT for f in judgments)
    assert verdict.disposition is Disposition.MANUAL_REVIEW
    verdict.assert_citable()


def parse_body(raw: str) -> str:
    from tenable_email.parse import parse_message

    return parse_message(raw).body


def test_a_verified_threat_stays_a_threat_with_a_model_voting_clean(tmp_path):
    from tenable_email.replay import ReplayStore
    from tenable_email.tiers import FraudFoxTier

    store = ReplayStore(root=tmp_path)
    tier = FraudFoxTier()
    config = Config(replay=True, replay_dir=str(tmp_path))
    store.put_response(
        tier=tier.name, model=tier.model_id(Config()),
        payload=tier.prepare({"text": parse_body(LOOKALIKE_BYTES)}, config),
        response={"verdict": "SAFE", "safe_score": 0.9999, "confidence": 0.9999},
        endpoint_role="onnx-classifier",
    )
    verdict = triage_bytes(LOOKALIKE_BYTES, config)
    assert verdict.disposition is Disposition.THREAT
    assert verdict.attack_type is AttackType.CREDENTIAL_HARVEST
    assert verdict.confidence == pytest.approx(0.95)
    assert any("not applied" in r for r in verdict.reasons)
    verdict.assert_citable()


def test_stages_run_grows_only_for_the_messages_a_tier_actually_answered():
    """The measurement this project's pitch rests on, made checkable.

    A stage is listed because it ran. Bulk mail that the headers settle carries no
    classifier stage at all, and the fixture corpus proves the difference rather
    than asserting it.
    """
    settled = triage_bytes(
        "From: Example Outfitters <news@example-outfitters.com>\r\n"
        "To: staff@example.edu\r\nSubject: Winter clearance\r\n"
        "Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n"
        "List-Unsubscribe: <https://example-outfitters.com/u/1>\r\n"
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
        "Precedence: bulk\r\n\r\n"
        "Everything is on sale this weekend.\r\n"
    )
    assert settled.disposition is Disposition.SPAM
    assert "classifier-cascade" not in settled.stages_run
    assert "adjudication" in settled.stages_run
    assert settled.evidence.by_provenance(Provenance.MODEL_JUDGMENT) == []


def test_combine_is_pure_and_does_not_touch_evidence():
    """Recording is the pipeline's job; combining is arithmetic on opinions."""
    before = DEFAULT_POLICY
    outcome = combine(OPEN_UNBLOCKED, [judgment("llm", Stance.THREAT, 0.95)],
                      CONFIG)
    assert outcome.disposition is Disposition.THREAT
    assert DEFAULT_POLICY is before
    assert isinstance(ensemble.EnsemblePolicy(), EnsemblePolicy)


# --- regressions from the code review of the clearance-policy change ----------


def test_a_settled_spam_can_also_be_vetoed_not_only_a_clean():
    """SPAM is just as decisive and just as unreopenable as CLEAN.

    The spam path consults no models at all, so a bulk newsletter from an
    authenticated sender carrying a malicious inline image would be dispositioned
    SPAM on headers alone -- and a queue may be configured to delete on SPAM, so
    the payload is discarded rather than read. The cost argument for the veto is
    identical: one analyst look against a compromised account.
    """
    vetoed = combine(
        SETTLED_SPAM, [judgment(VlmTier.name, Stance.THREAT, 0.999)], CONFIG
    )
    assert vetoed.disposition is Disposition.MANUAL_REVIEW
    assert vetoed.clearance_vetoed is True
    assert vetoed.attack_type is AttackType.NONE, (
        "a veto defers to a human; it must not assert a threat classification"
    )


def test_a_veto_reports_a_deferral_confidence_not_the_confidence_it_overruled():
    """The least decided outcome must not carry the most confident label.

    Taking the minimum of the two inputs produced 0.90 -- HIGH band -- on a
    disposition that means "we are declining to decide", while every other
    escalation path in the pipeline reports 0.5. An operator reading the record
    would see the strongest label attached to the weakest conclusion.
    """
    from tenable_email.ensemble import DEFERRAL_CONFIDENCE
    from tenable_email.verdict import ConfidenceBand, band_for

    vetoed = combine(
        SETTLED_CLEAN, [judgment(VlmTier.name, Stance.THREAT, 0.999)], CONFIG
    )
    assert vetoed.confidence == pytest.approx(DEFERRAL_CONFIDENCE)
    assert band_for(vetoed.confidence) is ConfidenceBand.LOW


def test_an_incoherent_decisive_deferral_does_not_raise():
    """``Deterministic`` is public and frozen, and its fields are independent.

    A caller can mark MANUAL_REVIEW decisive, which is incoherent: nothing is
    more or less severe than "a person must look", so the severity table has no
    entry for it. Indexing the table directly turned that into a KeyError out of
    a public function. It is now treated as unsettled.
    """
    incoherent = Deterministic(
        disposition=Disposition.MANUAL_REVIEW, confidence=0.5,
        attack_type=AttackType.UNCLASSIFIED, decisive=True, clear_blocked=False,
        reasons=("A caller set this incoherently.",), cited=("auth",),
    )
    outcome = combine(
        incoherent, [judgment("classifier", Stance.THREAT, 0.9)], CONFIG
    )
    assert outcome.disposition is not Disposition.CLEAN
