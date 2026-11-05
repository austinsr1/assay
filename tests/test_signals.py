"""Deterministic-signal tests, driven by the shipped synthetic corpus.

Each test asserts that a specific stage fired on the fixture that exists to
exercise it. These are the tests that make the parity claims in docs/PARITY.md
checkable rather than asserted.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import EXAMPLE_PROFILE, DEFAULT_THRESHOLDS  # noqa: E402
from tenable_email.evidence import Evidence, Provenance, EvidenceError  # noqa: E402
from tenable_email.parse import parse_file  # noqa: E402
from tenable_email.signals import extract_signals, levenshtein  # noqa: E402

FIXTURES = REPO / "fixtures" / "synthetic"


@pytest.fixture(scope="session", autouse=True)
def corpus(tmp_path_factory):
    """Generate the corpus once per session, from the shipped generator.

    Generated rather than committed so the labels cannot drift from the
    generator, and so no message bytes are checked into git history.
    """
    subprocess.run(
        [sys.executable, str(REPO / "fixtures" / "generate.py"),
         "--out", str(FIXTURES), "--manifest"],
        check=True,
    )
    return FIXTURES


def sig(name: str) -> dict:
    msg = parse_file(FIXTURES / f"{name}.eml")
    return extract_signals(msg, EXAMPLE_PROFILE, DEFAULT_THRESHOLDS)


# --- clean cases must stay clean ------------------------------------------

def test_clean_internal_passes_auth_and_is_not_lookalike():
    s = sig("clean_internal_registrar")
    assert s["auth"]["spf"] == "PASS"
    assert s["auth"]["dkim"] == "PASS"
    assert s["auth"]["dmarc"] == "PASS"
    assert s["alignment"]["claims_protected_domain"] is True
    assert s["lookalike"]["is_lookalike"] is False
    assert s["display_name_spoofing"]["is_spoofed"] is False


def test_clean_delivery_failure_is_recognized_as_automated():
    s = sig("clean_delivery_failure")
    assert s["bulk"]["auto_submitted"] == "auto-replied"
    assert s["bulk"]["precedence_bulk"] is True


def test_trusted_vendor_links_are_not_a_mismatch():
    s = sig("clean_vendor_docusign")
    assert s["links"]["hosts_matching_trusted"] == ["docusign.net"]
    assert s["links"]["hosts_matching_neither"] == []
    assert s["links"]["anchor_mismatch_count"] == 0


# --- spam class ------------------------------------------------------------

def test_bulk_marketing_carries_list_headers():
    s = sig("spam_bulk_marketing")
    assert s["bulk"]["has_list_unsubscribe"] is True
    assert s["bulk"]["rfc8058_one_click"] is True
    assert s["bulk"]["precedence_bulk"] is True
    assert s["bulk"]["bulk_header_count"] >= 5
    # Marketing mail is not a threat: no lookalike, no anchor mismatch.
    assert s["lookalike"]["is_lookalike"] is False
    assert s["links"]["anchor_mismatch_count"] == 0


# --- threat cases ----------------------------------------------------------

def test_lookalike_substring_without_modifier_is_not_impersonation():
    """The false positive the fixture corpus caught.

    ``example-outfitters.com`` shares a word with the protected domain but is an
    unrelated organization. The predecessor engine flagged on substring alone.
    The fact is recorded; the impersonation finding is not.
    """
    from tenable_email.signals import detect_lookalike_domain

    r = detect_lookalike_domain(
        "example-outfitters.com", EXAMPLE_PROFILE, DEFAULT_THRESHOLDS
    )
    assert r.is_lookalike is False
    assert r.contains_protected_label is True
    assert r.modifiers_found == ()
    assert r.target == "example"


@pytest.mark.parametrize(
    "domain,expect_lookalike",
    [
        ("example-login.com", True),          # protected label + modifier
        ("example-portal-verify.com", True),   # protected label + 2 modifiers
        ("examp1e.com", True),                 # homoglyph, edit distance 1
        ("example-outfitters.com", False),     # shared word, no modifier
        ("example.edu", False),                # the protected domain itself
        ("sub.example.edu", False),            # a protected subdomain
        ("docusign.net", False),               # explicitly trusted
        ("docus1gn.net", True),                # vendor homoglyph
        ("", False),
    ],
)
def test_lookalike_domain_matrix(domain, expect_lookalike):
    from tenable_email.signals import detect_lookalike_domain

    r = detect_lookalike_domain(domain, EXAMPLE_PROFILE, DEFAULT_THRESHOLDS)
    assert r.is_lookalike is expect_lookalike, f"{domain}: {r}"


def test_lookalike_detected_when_models_missed_it():
    s = sig("threat_lookalike_credential_harvest")
    assert s["lookalike"]["is_lookalike"] is True
    assert s["lookalike"]["target"] == "example"
    assert s["auth"]["spf"] == "FAIL"
    assert s["auth"]["dkim"] == "NONE"
    assert s["auth"]["dmarc"] == "FAIL"
    assert s["reply_to_mismatch"]["mismatch"] is True
    assert s["display_name_spoofing"]["is_spoofed"] is True


def test_anchor_text_mismatch_detected():
    s = sig("threat_anchor_mismatch")
    assert s["links"]["anchor_mismatch_count"] == 1
    mm = s["links"]["anchor_mismatches"][0]
    assert mm["hint"] == "example.edu"
    assert mm["actual"] == "harvest-credentials.test"


def test_redirect_wrapper_is_unwrapped_deterministically():
    """The reference playbook asks an LLM to percent-decode Safe Links.

    This is a string operation and belongs in the deterministic stage.
    """
    s = sig("threat_redirect_wrapped")
    assert len(s["links"]["unwrapped_redirects"]) == 1
    unwrapped = s["links"]["unwrapped_redirects"][0]
    assert unwrapped["wrapper"] == "safelinks.protection.outlook.com"
    assert unwrapped["resolved"] == "https://deposit-confirm.test/verify"
    assert "deposit-confirm.test" in s["links"]["resolved_hosts"]
    assert "safelinks.protection.outlook.com" not in s["links"]["resolved_hosts"]


def test_forwarded_message_unwraps_to_inner_sender():
    """The outer From is the reporting user, not the attacker."""
    s = sig("threat_forwarded_by_user")
    assert s["forwarding"]["is_forward"] is True
    assert s["sender"]["domain"] == "example.edu"
    assert s["lookalike"]["is_lookalike"] is False
    assert "invoice-settlement.test" in s["forwarding"]["inner_from"]


def test_dangerous_attachment_from_external_sender():
    s = sig("threat_dangerous_attachment")
    assert s["attachments"]["count"] == 1
    item = s["attachments"]["items"][0]
    assert item["filename"] == "invoice-revised.docm"
    assert item["extension"] == ".docm"
    assert item["dangerous_extension"] is True
    assert item["dangerous_and_external"] is True
    assert item["sha256"]
    assert s["attachments"]["dangerous_and_external_count"] == 1


def test_prompt_injection_attempt_is_recorded():
    """The predecessor engine had no guard here at all."""
    s = sig("threat_prompt_injection")
    assert s["injection"]["attempt_detected"] is True
    assert s["injection"]["hit_count"] >= 2
    joined = " ".join(h["match"].lower() for h in s["injection"]["hits"])
    assert "ignore all previous instructions" in joined


def test_bec_with_valid_auth_is_not_auto_cleared_by_deterministic_rules():
    """The case the reference playbook's domain-match rule gets wrong.

    Authentication passes and there is no suspicious link, so nothing
    deterministic may conclude clean. The signals are recorded and the
    adjudication tier must decide. What we assert is that the deterministic
    layer does NOT produce a clean verdict and DOES surface the real evidence:
    a Reply-To pointing outside the organization.
    """
    s = sig("threat_bec_valid_auth")
    assert s["auth"]["dmarc"] == "PASS"
    assert s["alignment"]["auth_passes"] is True
    assert s["alignment"]["claims_protected_domain"] is True
    assert s["lookalike"]["is_lookalike"] is False
    assert s["links"]["link_count"] == 0
    # The signal that remains is the external Reply-To.
    assert s["reply_to_mismatch"]["mismatch"] is True
    assert s["reply_to_mismatch"]["reply_to_domain"] == "mailbox-external.test"


def test_security_newsletter_quoting_injection_is_a_known_false_positive():
    """Executable record of the trap in docs/MODELS.md.

    A legitimate newsletter that QUOTES injection phrases while discussing them.
    The deterministic scanner fires on it, because a regex cannot tell "contains
    an instruction aimed at an agent" from "quotes an instruction while
    discussing it". This test pins that behaviour so the gap is visible.

    Bundle B must ensure this fixture is NOT dispositioned as a threat:
    deterministic-only injection hits are capped at low confidence and require
    corroboration. If this test is ever changed to assert no detection, the
    scanner has been made less sensitive to compensate - fix the verdict logic
    instead.
    """
    s = sig("clean_security_newsletter_discussing_injection")

    # The scanner does fire. That is the known limitation, asserted not hidden.
    assert s["injection"]["attempt_detected"] is True

    # But everything else about this message says legitimate bulk mail.
    assert s["auth"]["dmarc"] == "PASS"
    assert s["alignment"]["auth_passes"] is True
    assert s["lookalike"]["is_lookalike"] is False
    assert s["display_name_spoofing"]["is_spoofed"] is False
    assert s["links"]["anchor_mismatch_count"] == 0
    assert s["bulk"]["has_list_unsubscribe"] is True
    assert s["bulk"]["rfc8058_one_click"] is True
    assert s["bulk"]["auto_submitted"] == "auto-generated"


# --- unit-level ------------------------------------------------------------

@pytest.mark.parametrize(
    "a,b,expected",
    [("example", "example", 0), ("example", "examp1e", 1),
     ("EXAMPLE", "example", 0), ("", "abc", 3)],
)
def test_levenshtein(a, b, expected):
    assert levenshtein(a, b) == expected


def test_unparsed_from_header_is_preserved_not_dropped():
    """Parsing loses information; the raw value must survive."""
    s = sig("clean_internal_registrar")
    assert s["sender"]["raw"].startswith("Office of the Registrar")
    assert s["sender"]["address"] == "registrar@example.edu"
    assert s["sender"]["display_name"] == "Office of the Registrar"


# --- evidence invariants ---------------------------------------------------

def test_unknown_finding_cannot_support_a_verdict():
    ev = Evidence()
    ev.verified("spf", "FAIL", source="stage2")
    ev.unknown("account_compromised", source="stage7",
               detail="cannot be determined from the message")
    assert len(ev.supporting()) == 1
    assert len(ev.gaps()) == 1
    with pytest.raises(EvidenceError):
        ev.assert_citable(ev.gaps())
    # A verified finding is citable.
    ev.assert_citable(ev.supporting())


def test_unavailable_is_distinct_from_unknown():
    """A tier that did not run must not be reported as a finding of absence."""
    ev = Evidence()
    ev.unavailable("spam_classifier", source="stage4",
                   detail="endpoint not configured")
    gaps = ev.gaps()
    assert len(gaps) == 1
    assert gaps[0].provenance is Provenance.UNAVAILABLE
    assert gaps[0].value is None


def test_evidence_is_append_only_and_counts_by_provenance():
    ev = Evidence()
    ev.verified("a", 1, source="s")
    ev.judgment("b", 2, source="s")
    ev.unknown("c", source="s")
    d = ev.as_dict()
    assert d["counts"] == {
        "verified": 1, "model_judgment": 1, "unknown": 1, "unavailable": 0,
    }
    assert len(ev) == 3


def test_truncation_is_recorded_not_silent():
    """The predecessor sliced body[:8000] and told nobody."""
    from tenable_email.parse import parse_message

    long_body = "x" * 20000
    raw = (
        "From: a@example.test\r\nTo: b@example.test\r\nSubject: long\r\n"
        'Content-Type: text/plain; charset="utf-8"\r\n\r\n' + long_body
    )
    msg = parse_message(raw, body_char_limit=8000)
    assert msg.body_truncated is True
    assert msg.original_body_length == 20000
    assert len(msg.text_body) == 8000
