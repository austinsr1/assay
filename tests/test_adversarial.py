"""The adversarial corpus: inputs built to defeat the pipeline, not illustrate it.

Every case here is a message that must never be dispositioned ``CLEAN``, sent
from a subdomain of the protected domain with authentication headers that
genuinely pass. That is the attacker's strongest realistic position: it
satisfies "the sender is one of us" without requiring any forgery the receiver
would catch, so nothing downstream can lean on an authentication failure.

This suite exists because the shipped synthetic corpus could not catch what an
external red-team review found. ``fixtures/synthetic/`` was written to
demonstrate the design, and one of its fixtures encoded the exact assumption
under attack -- authenticated sender, link to an unrelated domain, no
concealment, labelled clean. The tests passed because they pinned the unsafe
belief. A corpus built to illustrate a design cannot also be the corpus that
attacks it.

Cases marked ``closed`` are asserted directly. Cases marked ``open`` are wrapped
in a **strict** xfail, which is the mechanism that makes this suite durable: the
assertion states what *should* happen, it currently fails, and the day someone
fixes the underlying defect the test XPASSes and the run goes red until the
expectation is consciously moved. A regression therefore cannot be quietly
reintroduced, and a fix cannot land without anyone noticing that the status
table in ``docs/RED-TEAM-RESPONSE.md`` is now stale.

Run with no model access at all (``replay_dir=None``), so every verdict here
comes from the deterministic layer alone. That is deliberate: the configuration a
reviewer or a judge runs is the one being attacked.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config  # noqa: E402
from tenable_email.parse import parse_file, parse_message  # noqa: E402
from tenable_email.pipeline import triage_bytes, triage_file  # noqa: E402
from tenable_email.signals import (  # noqa: E402
    extract_auth_results,
    extract_signals,
)
from tenable_email.verdict import Disposition  # noqa: E402

CORPUS = REPO / "fixtures" / "adversarial"
MANIFEST = CORPUS / "labels.json"

#: No model tier is reachable, so nothing here can be rescued by an inference
#: call. Whatever the deterministic layer decides is what a judge sees.
NO_MODELS = Config(replay=True, replay_dir=None)


def _manifest() -> list[dict]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _cases(status: str | None = None) -> list[dict]:
    entries = _manifest()
    if status is None:
        return entries
    return [e for e in entries if e["status"] == status]


def _ids(entries: list[dict]) -> list[str]:
    return [e["case"] for e in entries]


# --------------------------------------------------------------------------
# the corpus is what it claims to be
# --------------------------------------------------------------------------


def test_the_manifest_exists_and_describes_every_file():
    """No orphan .eml and no manifest entry pointing at nothing.

    A corpus that drifts from its manifest is worse than no corpus: the entry
    nobody runs gives false confidence, and the file nobody declared is a case
    that silently stopped being tested.
    """
    assert MANIFEST.is_file(), f"missing {MANIFEST}"
    entries = _manifest()
    assert entries, "the adversarial manifest is empty"
    declared = {e["file"] for e in entries}
    present = {p.name for p in CORPUS.glob("*.eml")}
    assert declared == present, (
        f"manifest and directory disagree; only in manifest: "
        f"{sorted(declared - present)}, only on disk: {sorted(present - declared)}"
    )


def test_every_entry_declares_a_status_and_what_it_exercises():
    for entry in _manifest():
        assert entry["status"] in ("closed", "open"), entry
        assert len(entry["exercises"]) >= 20, (
            f"{entry['case']} does not say what it exercises; a case whose "
            f"purpose is not written down stops being maintained"
        )


def test_the_corpus_is_reproducible_from_its_generator():
    """The committed files are generated, so they cannot drift silently.

    Regenerating into a temporary directory and comparing bytes catches an
    edited fixture that nobody re-derived, which would leave the committed corpus
    testing something the generator no longer produces.
    """
    generator = CORPUS / "generate.py"
    assert generator.is_file(), f"missing {generator}"
    with pytest.MonkeyPatch.context() as monkey:
        monkey.chdir(REPO)
        result = subprocess.run(
            [sys.executable, str(generator), "--out", "/tmp/_adversarial_regen"],
            capture_output=True, text=True, timeout=120,
        )
    assert result.returncode == 0, result.stderr
    regen = pathlib.Path("/tmp/_adversarial_regen")
    try:
        for entry in _manifest():
            original = (CORPUS / entry["file"]).read_bytes()
            produced = (regen / entry["file"]).read_bytes()
            assert original == produced, (
                f"{entry['file']} differs from what generate.py produces; edit "
                f"the generator, not the fixture"
            )
        assert (regen / "labels.json").read_bytes() == MANIFEST.read_bytes()
    finally:
        for path in sorted(regen.glob("*")):
            path.unlink()
        regen.rmdir()


# --------------------------------------------------------------------------
# the assertions that matter
# --------------------------------------------------------------------------


@pytest.mark.parametrize("entry", _cases("closed"), ids=_ids(_cases("closed")))
def test_a_closed_attack_is_not_cleared(entry):
    verdict = triage_file(CORPUS / entry["file"], NO_MODELS)
    assert verdict.disposition is not Disposition.CLEAN, (
        f"{entry['case']} was dispositioned CLEAN. It exercises: "
        f"{entry['exercises']}"
    )


@pytest.mark.parametrize("entry", _cases("open"), ids=_ids(_cases("open")))
@pytest.mark.xfail(
    strict=True,
    reason=(
        "a known-open finding from the external red-team review; see "
        "docs/RED-TEAM-RESPONSE.md. Strict: when this starts passing, move the "
        "case to 'closed' in fixtures/adversarial/generate.py and update the "
        "status table -- do not delete the xfail silently."
    ),
)
def test_an_open_attack_is_not_cleared_yet(entry):
    verdict = triage_file(CORPUS / entry["file"], NO_MODELS)
    assert verdict.disposition is not Disposition.CLEAN, (
        f"{entry['case']} still clears. It exercises: {entry['exercises']}"
    )


def test_no_adversarial_case_is_ever_called_spam():
    """Escalating is acceptable; mislabelling an attack as junk mail is not.

    ``SPAM`` is a disposition a queue can be configured to delete on, so an
    attack that lands there is discarded rather than read. Every one of these
    cases carries a hostile payload.
    """
    for entry in _manifest():
        verdict = triage_file(CORPUS / entry["file"], NO_MODELS)
        assert verdict.disposition is not Disposition.SPAM, (
            f"{entry['case']} was dispositioned SPAM, which a queue may delete"
        )


def test_the_open_findings_are_exactly_the_ones_the_response_document_claims():
    """Keep the corpus and docs/RED-TEAM-RESPONSE.md from drifting apart, in both
    directions.

    The response document is what a reviewer reads, and it names the findings
    still open by id. If a case here is closed but the document still lists it
    as open -- or the reverse -- one of the two is lying. The ids are matched
    against the ``exercises`` text each case carries.

    This test used to check only the first direction: every *open* case had to
    name a finding id the document mentions. That passed for months while the
    document's prose claimed three open cases and the corpus held one, because
    nothing compared what the document asserted against what the corpus declared.
    A one-directional cross-check cannot catch a document that overstates how much
    is still broken, and overstating it is the direction that costs credibility:
    a reviewer who reads "three open" and then finds a status table saying
    otherwise stops trusting the table. The comparison below reads the document's
    own structured status table, so both directions are covered and the test's
    name is finally accurate.
    """
    response = (REPO / "docs" / "RED-TEAM-RESPONSE.md").read_text(encoding="utf-8")

    corpus_open = {entry["case"] for entry in _cases("open")}

    # The status table marks an unresolved case with "(open)" in its After column.
    # Parsing the table rather than the prose is deliberate: prose is where the drift
    # happened, and a table row is structured enough to read without guessing.
    doc_open = {
        cells[0].strip().strip("`")
        for line in response.splitlines()
        if line.strip().startswith("|")
        for cells in [ [c.strip() for c in line.strip().strip("|").split("|") ] ]
        if len(cells) >= 3 and "(open)" in cells[-1]
    }

    assert doc_open == corpus_open, (
        "docs/RED-TEAM-RESPONSE.md and fixtures/adversarial disagree about which cases "
        f"are open. Document only: {sorted(doc_open - corpus_open)}. "
        f"Corpus only: {sorted(corpus_open - doc_open)}. Fix whichever is stale; do not "
        "widen this assertion."
    )
    assert corpus_open, (
        "no case is marked open in the corpus, which would mean every red-team finding "
        "is closed. If that is genuinely true, remove the strict xfail and the open-case "
        "prose deliberately rather than letting this guard fail mysteriously."
    )

    for entry in _cases("open"):
        found = [
            token for token in ("R01", "R04", "R05", "R06", "R08", "R09")
            if token in entry["exercises"]
        ]
        assert found, (
            f"{entry['case']} is marked open but names no finding id in its "
            f"exercises text, so nothing can cross-check it"
        )
        for finding in found:
            assert finding in response, (
                f"{entry['case']} is open on {finding} but "
                f"docs/RED-TEAM-RESPONSE.md does not mention that id"
            )


# --------------------------------------------------------------------------
# the specific mechanism each closed case proves
# --------------------------------------------------------------------------


def test_a_form_action_is_a_destination_the_link_analysis_sees():
    """The defect that made eleven of these cases work.

    A credential-harvesting form produced a message with **zero** links, so
    "every destination is accounted for" was true by vacuous truth and the
    clearance gate passed at 0.90. The fix enumerates every attribute that can
    carry a destination, not only ``<a href>``.
    """
    msg = parse_file(CORPUS / "form_action_credential_harvest.eml")
    config = Config()
    signals = extract_signals(msg, config.profile, config.thresholds)
    elements = {e for e in signals["links"].get("elements", [])}
    assert "form.action" in elements, signals["links"]
    assert signals["links"]["link_count"] >= 1
    assert signals["links"]["hosts_matching_neither"], (
        "the form's destination must be reported as matching neither the sender "
        "nor a trusted domain, which is what blocks the clearance"
    )


def test_a_nested_wrapper_resolves_past_the_inner_trusted_hop():
    """R09: one-hop unwrapping reported the inner wrapper as the destination.

    Because the inner wrapper is itself on the trusted list, a single unwrap
    made a concealed destination look accounted for. Unwrapping is now iterative
    and bounded, so the real destination surfaces.
    """
    msg = parse_file(CORPUS / "nested_redirect_wrapper.eml")
    config = Config()
    signals = extract_signals(msg, config.profile, config.thresholds)
    resolved = " ".join(signals["links"]["resolved_hosts"])
    assert "harvest-credentials.test" in resolved, signals["links"]["resolved_hosts"]
    assert signals["links"]["hosts_matching_neither"], (
        "the fully unwrapped destination must match neither sender nor trusted"
    )


def test_contradictory_authentication_headers_block_a_clearance():
    """R01: a forged pass could previously outrank a genuine fail.

    The old merge took the strongest value per mechanism and ratcheted PASS so a
    later FAIL could never override it, which meant a sender-supplied
    ``dmarc=pass`` beat the receiver's ``dmarc=fail`` below it. First mention now
    wins and any later disagreement is recorded as a conflict that blocks
    clearance outright.
    """
    eml = (
        'From: "IT Service Desk" <security@security.example.edu>\r\n'
        "To: staff@example.edu\r\nSubject: Contradictory Auth\r\n"
        "Authentication-Results: attacker-controlled; dmarc=pass\r\n"
        "Authentication-Results: mx.example.edu; spf=fail; dkim=fail; dmarc=fail\r\n"
        'Content-Type: text/plain; charset="utf-8"\r\nMIME-Version: 1.0\r\n\r\n'
        "Mail services will be unavailable on Saturday.\r\n"
    )
    verdict = triage_bytes(eml, NO_MODELS)
    assert verdict.disposition is not Disposition.CLEAN, verdict.reasons

    config = Config()
    signals = extract_signals(
        parse_message(eml), config.profile, config.thresholds
    )
    assert signals["alignment"]["auth_conflicting"] is True
    assert signals["alignment"]["auth_header_count"] == 2
    assert signals["alignment"]["auth_passes"] is False or (
        signals["auth"]["spf"] == "FAIL" and signals["auth"]["dkim"] == "FAIL"
    ), signals["auth"]


def test_a_prose_mention_of_sender_does_not_fabricate_an_spf_pass():
    """The heuristic that read ``pass`` ... ``sender`` anywhere in a header.

    A DKIM result with a comment mentioning "sender policy" was enough to
    manufacture an SPF PASS. A mechanism is PASS because a result token says so,
    or it is not.
    """
    msg = parse_message(
        "From: someone@example.edu\r\nSubject: x\r\n"
        "Authentication-Results: mx; dkim=pass (see sender policy framework)\r\n"
        "\r\nbody\r\n"
    )
    auth = extract_auth_results(msg)
    assert auth.spf == "unknown", auth.as_dict()
    assert auth.dkim == "PASS"


def test_a_policy_action_is_not_read_as_a_dmarc_result():
    """``action=reject`` is what the receiver was told to do, not what happened.

    Mapping policy onto the result axis mislabels a passing message's evidence.
    The direction was conservative, so this is a correctness fix rather than a
    safety one, but the evidence record is what an analyst reads.
    """
    msg = parse_message(
        "From: someone@example.edu\r\nSubject: x\r\n"
        "Authentication-Results: mx; dmarc=pass action=reject\r\n\r\nbody\r\n"
    )
    assert extract_auth_results(msg).dmarc == "PASS"


def test_an_unexamined_inline_image_blocks_a_clearance():
    """Pixels are content the deterministic layer provably cannot read.

    Clearing on the strength of everything it *could* read is clearing on partial
    evidence. A message from a protected sender whose only payload is an inline
    image must not be cleared deterministically: it becomes unsettled, the vision
    tier is asked, and if no vision tier is configured the honest outcome is a
    human. This is also what makes the clearance veto reachable in the real
    pipeline rather than only in a unit test.
    """
    eml = (
        'From: "IT Service Desk" <security@security.example.edu>\r\n'
        "To: staff@example.edu\r\nSubject: Unexamined Inline Image\r\n"
        "Authentication-Results: mx.example.edu; spf=pass "
        "smtp.mailfrom=security.example.edu; dkim=pass "
        "header.d=security.example.edu; dmarc=pass\r\n"
        'Content-Type: multipart/related; boundary="RR"\r\n'
        "MIME-Version: 1.0\r\n\r\n"
        '--RR\r\nContent-Type: text/plain; charset="utf-8"\r\n\r\n'
        "See the attached notice.\r\n"
        '--RR\r\nContent-Type: image/png\r\n'
        "Content-Disposition: inline; filename=\"notice.png\"\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        "iVBORw0KGgo=\r\n"
        "--RR--\r\n"
    )
    msg = parse_message(eml)
    config = Config()
    signals = extract_signals(msg, config.profile, config.thresholds)
    assert signals["inline_image_count"] >= 1, "the premise: there is an image"

    verdict = triage_bytes(eml, NO_MODELS)
    assert verdict.disposition is not Disposition.CLEAN, verdict.reasons
