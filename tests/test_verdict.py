"""Verdict shape, confidence bands, and the serialization leak surface.

The three-way taxonomy is reference parity; the band is derived from the float
rather than replacing it; and ``to_json()`` is where message content could leak
into a shipped artifact, so it is tested as an adversarial surface rather than
as a formatting convenience.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config, Thresholds  # noqa: E402
from tenable_email.evidence import Evidence, EvidenceError, Provenance  # noqa: E402
from tenable_email.parse import parse_file  # noqa: E402
from tenable_email.pipeline import triage_file  # noqa: E402
from tenable_email.verdict import (  # noqa: E402
    AttackType,
    ConfidenceBand,
    Disposition,
    Verdict,
    band_for,
)

FIXTURES = REPO / "fixtures" / "synthetic"


@pytest.fixture(scope="module", autouse=True)
def corpus():
    """Regenerate the shipped corpus so labels cannot drift from the generator."""
    import subprocess

    subprocess.run(
        [sys.executable, str(REPO / "fixtures" / "generate.py"),
         "--out", str(FIXTURES), "--manifest"],
        check=True,
    )
    return FIXTURES


def verdict_for(name: str) -> Verdict:
    return triage_file(FIXTURES / f"{name}.eml")


def dict_keys_in(node, path=""):
    """Every mapping key appearing anywhere in a decoded JSON document."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.append(key)
            found += dict_keys_in(value, f"{path}.{key}")
    elif isinstance(node, list):
        for item in node:
            found += dict_keys_in(item, path)
    return found


# --- taxonomy --------------------------------------------------------------


def test_disposition_values_are_the_reference_taxonomy_plus_two():
    assert Disposition.THREAT == "threat"
    assert Disposition.SPAM == "spam"
    assert Disposition.CLEAN == "clean"
    assert Disposition.MANUAL_REVIEW == "manual_review"
    assert Disposition.UNKNOWN == "unknown"
    assert {d.value for d in Disposition} == {
        "threat", "spam", "clean", "manual_review", "unknown",
    }


def test_attack_type_vocabulary():
    assert {a.value for a in AttackType} == {
        "NONE", "CREDENTIAL_HARVEST", "MALWARE", "BEC", "SPAM",
        "AGENT_MANIPULATION", "UNCLASSIFIED",
    }


def test_band_values_match_the_reference_vocabulary():
    assert [b.value for b in ConfidenceBand] == ["high", "medium", "low"]


# --- bands ------------------------------------------------------------------


@pytest.mark.parametrize(
    "confidence,expected",
    [
        (1.0, ConfidenceBand.HIGH),
        (0.95, ConfidenceBand.HIGH),
        (0.85, ConfidenceBand.HIGH),   # band_high is inclusive
        (0.84, ConfidenceBand.MEDIUM),
        (0.8, ConfidenceBand.MEDIUM),
        (0.6, ConfidenceBand.MEDIUM),  # band_medium is inclusive
        (0.59, ConfidenceBand.LOW),
        (0.5, ConfidenceBand.LOW),
        (0.4, ConfidenceBand.LOW),
        (0.0, ConfidenceBand.LOW),
    ],
)
def test_band_for_uses_the_configured_cut_points(confidence, expected):
    assert band_for(confidence, Thresholds()) is expected


def test_band_for_respects_reconfigured_thresholds():
    strict = Thresholds(band_high=0.99, band_medium=0.9)
    assert band_for(0.95, strict) is ConfidenceBand.MEDIUM
    assert band_for(0.85, strict) is ConfidenceBand.LOW
    assert band_for(0.995, strict) is ConfidenceBand.HIGH


def test_band_for_clamps_out_of_range_confidence():
    assert band_for(2.5, Thresholds()) is ConfidenceBand.HIGH
    assert band_for(-1.0, Thresholds()) is ConfidenceBand.LOW


def test_set_confidence_keeps_the_band_in_sync():
    v = Verdict()
    v.set_confidence(0.95, Thresholds())
    assert v.confidence == 0.95
    assert v.confidence_band is ConfidenceBand.HIGH
    v.set_confidence(0.4, Thresholds())
    assert v.confidence_band is ConfidenceBand.LOW
    v.set_confidence(9.0, Thresholds())
    assert v.confidence == 1.0


# --- output shape -----------------------------------------------------------


def test_verdict_echoes_the_reference_fields():
    v = verdict_for("threat_lookalike_credential_harvest")
    payload = v.to_dict()
    for key in ("id", "subject", "sender", "reported_by", "verdict", "analysis",
                "reasons", "confidence"):
        assert key in payload, f"reference field {key!r} missing from the output"
    assert payload["verdict"] == payload["disposition"] == "threat"
    assert payload["confidence_band"] in ("high", "medium", "low")
    assert payload["subject"] == "Action Required: your mailbox storage is full"
    assert payload["sender"] == "noreply@example-portal-verify.com"


def test_verdict_carries_the_full_evidence_record():
    v = verdict_for("clean_internal_registrar")
    payload = v.to_dict()
    assert payload["evidence"]["findings"], "no findings in the record"
    assert set(payload["evidence"]) == {
        "findings", "truncated", "original_length", "simulated", "counts",
    }
    assert payload["evidence"]["counts"]["verified"] > 10


def test_reasons_are_a_list_of_sentences():
    v = verdict_for("threat_anchor_mismatch")
    assert isinstance(v.reasons, list) and v.reasons
    for reason in v.reasons:
        assert isinstance(reason, str) and len(reason) > 40
        assert reason.strip().endswith(".")


def test_to_json_is_one_valid_object():
    v = verdict_for("threat_bec_valid_auth")
    decoded = json.loads(v.to_json())
    assert isinstance(decoded, dict)
    assert decoded["verdict"] == "manual_review"
    assert decoded["attack_type"] == "BEC"


# --- the leak surface -------------------------------------------------------


def test_to_json_never_serializes_attachment_bytes():
    """The attachment fixture carries real bytes in ``Attachment.data``.

    ``to_json`` must emit the inventory -- name, type, size, hash -- and nothing
    of the payload. This is the test that keeps a shipped artifact from
    containing a malware sample or someone's mail attachment.
    """
    msg = parse_file(FIXTURES / "threat_dangerous_attachment.eml")
    assert msg.attachments and msg.attachments[0].data, (
        "fixture is expected to carry retained bytes for the leak test to mean "
        "anything"
    )
    payload = msg.attachments[0].data
    encoded = msg.attachments[0].without_data()
    assert "data" not in encoded

    v = verdict_for("threat_dangerous_attachment")
    text = v.to_json()
    assert "data" not in dict_keys_in(json.loads(text)), (
        "a serialized verdict must not carry a 'data' key"
    )
    assert '"data"' not in text
    assert payload.hex() not in text
    assert "UEsDBBQAAAAIAAAAAACKIYOwWgAAAFoAAAAIAAAAbWltZXR5cGU=" not in text
    # The inventory itself is still there, which is the point of the record.
    assert "invoice-revised.docm" in text
    assert msg.attachments[0].sha256 in text


@pytest.mark.parametrize(
    "name",
    [
        "clean_internal_registrar", "clean_vendor_docusign", "spam_bulk_marketing",
        "threat_dangerous_attachment", "threat_prompt_injection",
        "clean_security_newsletter_discussing_injection",
    ],
)
def test_no_verdict_serialization_carries_a_data_key(name):
    text = verdict_for(name).to_json()
    assert "data" not in dict_keys_in(json.loads(text))


def test_serialization_has_no_strfallback_for_bytes():
    """``to_json`` deliberately does not stringify unknown types.

    A ``default=`` would turn a leaked ``bytes`` value into a printable string
    and the leak would ship. Instead the call must raise.
    """
    ev = Evidence()
    ev.verified("oops", b"raw-attachment-bytes", source="test")
    v = Verdict(evidence=ev)
    with pytest.raises(TypeError):
        v.to_json()


# --- provenance enforcement -------------------------------------------------


def test_cited_findings_are_always_supporting():
    for name in ("clean_internal_registrar", "threat_prompt_injection",
                 "threat_bec_valid_auth", "spam_bulk_marketing"):
        v = verdict_for(name)
        cited = v.cited()
        assert cited, f"{name} cites no findings at all"
        for f in cited:
            assert f.provenance in (Provenance.VERIFIED, Provenance.MODEL_JUDGMENT), (
                f"{name}: cited {f.key} with provenance {f.provenance.value}"
            )
        v.assert_citable()  # must not raise


def test_a_verdict_may_not_close_on_an_unknown():
    """The invariant, tested from the consumer's side.

    ``pipeline._recorded`` returns a finding of any provenance, so a rule that
    cited a gap would reach ``assert_citable`` and be stopped. If the citation
    path were ever filtered to skip gaps, that would look like safety while
    making the check unreachable -- this test keeps it reachable.
    """
    v = verdict_for("threat_dangerous_attachment")
    assert v.evidence.by_provenance(Provenance.UNKNOWN), "fixture must carry a gap"
    gap = v.evidence.by_provenance(Provenance.UNKNOWN)[0]
    assert gap.key == "account_compromised"
    v.cited_findings.append(gap.key)
    with pytest.raises(EvidenceError):
        v.assert_citable()


def test_unavailable_findings_cannot_support_a_disposition_either():
    v = verdict_for("clean_vendor_docusign")
    gap = v.evidence.by_provenance(Provenance.UNAVAILABLE)[0]
    v.cited_findings.append(gap.key)
    with pytest.raises(EvidenceError):
        v.assert_citable()


def test_escalated_tracks_the_dispositions_that_reach_a_human():
    v = verdict_for("threat_bec_valid_auth")
    assert v.disposition is Disposition.MANUAL_REVIEW and v.escalated is True
    clean = verdict_for("clean_internal_registrar")
    assert clean.escalated is False
    unknown = Verdict(disposition=Disposition.UNKNOWN)
    assert unknown.escalated is False  # escalated is set by the pipeline, not derived


def test_add_reason_deduplicates():
    v = Verdict()
    v.add_reason("Authentication failed.")
    v.add_reason("Authentication failed.")
    v.add_reason("")
    assert v.reasons == ["Authentication failed."]


def test_config_fixture_defaults_keep_endpoints_unset():
    """No endpoint has a default address, so a fresh clone runs offline."""
    config = Config()
    for field_name in (
        "fraudfox_url", "secmodels_url", "spam_classifier_url",
        "llm_url", "vlm_url",
    ):
        assert getattr(config.endpoints, field_name) is None
