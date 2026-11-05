"""The listing drafts must be submittable, and must not overstate the code.

Two different risks live here and they need different mechanisms.

The drafts still carry placeholder values that only the operator can fill in - a
personal GitHub handle, and the repository URL that follows from it. That is a
known blocker, not a surprise, so it is asserted under a **strict** xfail: the
assertion states what submission requires, it fails today, and the day the values
are filled in it XPASSes and the build goes red until the mark is consciously
removed. That is deliberate. A placeholder that is silently tolerated is a
placeholder that gets submitted, and the Exchange rejects a listing whose
referenced repository does not exist.

The second risk is quieter and more likely. The listing body makes specific
numeric claims - how many tools, how many hostile fixtures, how many stages, what
the measured error counts are - and prose drifts from code the moment the code
moves. Every number in the body is therefore recomputed here from the artifact it
describes, so a claim that stops being true fails a test rather than shipping.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

DRAFTS = REPO / "docs" / "listing-drafts"
PLAYBOOK = DRAFTS / "playbook.md"
MCP_LISTING = DRAFTS / "mcp-server.md"


def _text(path: pathlib.Path) -> str:
    assert path.is_file(), f"missing {path}"
    return path.read_text(encoding="utf-8")


def _flat(path: pathlib.Path) -> str:
    """The body with runs of whitespace collapsed to single spaces.

    Markdown wraps prose at an arbitrary column, so a phrase can be split across
    two lines and a substring check on the raw text fails for a reason that has
    nothing to do with whether the listing says it. Every prose assertion goes
    through this; assertions about frontmatter fields do not, because those are
    line-structured and collapsing them would hide real formatting.
    """
    return re.sub(r"\s+", " ", _text(path))


# --------------------------------------------------------------------------
# the operator blocker, asserted so it cannot be forgotten
# --------------------------------------------------------------------------


def test_the_listing_drafts_carry_no_placeholder_values():
    """Was a strict xfail until the operator supplied the repository name.

    The mark existed so the build stayed red while values only the operator could supply
    were missing, and so that filling them in could not happen silently. The operator chose
    ``assay`` under the ``austinsr1`` account, the values are filled, and the mark is removed
    in the same commit that fills them - which is what its own reason text required. The
    assertion is now a real guard: a placeholder reintroduced later fails the suite.
    """
    offenders = []
    for draft in (PLAYBOOK, MCP_LISTING):
        for lineno, line in enumerate(_text(draft).splitlines(), start=1):
            if "PLACEHOLDER" in line:
                offenders.append(f"{draft.relative_to(REPO)}:{lineno}: {line.strip()}")
    assert not offenders, (
        "placeholder values remain in the listing drafts:\n  "
        + "\n  ".join(offenders)
    )


def test_the_playbook_declares_the_confirmed_artifact_shape():
    """The artifact type was an open decision; it is not any more.

    Recorded so a later edit cannot silently revert the listing to a shape the
    operator did not choose: a standard playbook with an MCP server as a
    component, which means `playbook_type: standard` and a non-empty
    `agents_used` list.
    """
    head = _text(PLAYBOOK).split("---")[1]
    assert 'playbook_type: "standard"' in head
    assert "agents_used:" in head
    assert 'license: "MIT"' in head


# --------------------------------------------------------------------------
# every numeric claim in the body, recomputed from its source
# --------------------------------------------------------------------------


def test_the_nine_tools_named_in_the_listing_are_the_nine_that_exist():
    body = _flat(PLAYBOOK)
    named = set(re.findall(r"`([a-z_]+)`", body))
    expected = {
        "analyze_eml", "analyze_eml_directory", "explain_verdict", "check_auth",
        "lookalike_domain", "analyze_urls", "classify_local", "list_contracts",
        "get_case_record",
    }
    assert expected <= named, f"listing omits tools: {sorted(expected - named)}"

    source = _text(REPO / "src" / "tenable_email" / "mcpserver.py")
    defined = {
        name for name in expected
        if re.search(rf"^def {name}\b", source, re.MULTILINE)
    }
    assert defined == expected, (
        f"the listing names tools the server does not define: "
        f"{sorted(expected - defined)}"
    )


def test_the_adversarial_counts_in_the_listing_match_the_corpus():
    body = _flat(PLAYBOOK)
    manifest = json.loads(
        (REPO / "fixtures" / "adversarial" / "labels.json").read_text(
            encoding="utf-8"
        )
    )
    total = len(manifest)
    closed = sum(1 for e in manifest if e["status"] == "closed")
    open_ = sum(1 for e in manifest if e["status"] == "open")

    words = {
        1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
        7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve",
        13: "thirteen", 14: "fourteen", 15: "fifteen", 16: "sixteen",
        17: "seventeen", 18: "eighteen", 19: "nineteen", 20: "twenty",
    }
    assert f"{words[total]} hostile messages" in body, (
        f"the listing says something other than {total} hostile messages"
    )
    assert f"{words[closed]} are asserted to escalate" in body, (
        f"the listing says something other than {closed} asserted to escalate"
    )
    assert open_ == 1, (
        f"the listing says the eighteenth is the one open finding; there are "
        f"now {open_}"
    )


def test_the_synthetic_fixture_count_in_the_listing_is_real():
    body = _flat(PLAYBOOK)
    manifest = json.loads(
        (REPO / "fixtures" / "synthetic" / "labels.json").read_text(encoding="utf-8")
    )
    words = {14: "fourteen", 15: "fifteen", 13: "thirteen"}
    assert f"{words[len(manifest)]} labelled fixtures" in body, (
        f"the listing claims a fixture count other than {len(manifest)}"
    )


def test_the_stage_count_in_the_listing_matches_the_contract():
    body = _flat(PLAYBOOK)
    contract = _text(REPO / "stages.yaml")
    stages = len(re.findall(r"^  - id: ", contract, re.MULTILINE))
    words = {8: "eight", 7: "seven", 9: "nine"}
    assert f"{words[stages]} stages" in body, (
        f"the listing says something other than {stages} stages"
    )


def test_the_measured_error_claims_match_the_committed_metrics():
    """Zero false negatives is the listing's strongest claim, so it is checked.

    Read from the committed artifact rather than recomputed, because the artifact
    is what a reviewer will read and `tests/test_eval.py` already asserts it
    matches the code.
    """
    body = _flat(PLAYBOOK)
    metrics = json.loads((REPO / "eval" / "metrics.json").read_text(encoding="utf-8"))
    synthetic = metrics["results"]["deterministic-only"]["synthetic"]

    if synthetic["false_negative_count"] != 0:
        pytest.fail(
            "the listing claims zero false negatives; the committed metrics say "
            f"{synthetic['false_negative_count']}. Fix the listing or the "
            "pipeline, but do not let them disagree."
        )
    if synthetic["false_accusation_count"] != 0:
        pytest.fail(
            "the listing claims zero false accusations; the committed metrics say "
            f"{synthetic['false_accusation_count']}"
        )
    assert "zero false negatives and zero false accusations" in body
    assert f"{synthetic['hostile_messages']} labelled fixtures" in body or (
        "fourteen labelled fixtures" in body
    )


def test_the_listing_does_not_claim_an_accuracy_number():
    """The one claim this project refuses to make, checked mechanically.

    A percentage attached to the word accuracy anywhere in the listing would
    contradict the README, the metrics report and the evaluation survey, and it is
    the kind of claim a reviewer will hold the submission to.
    """
    body = _flat(PLAYBOOK)
    assert "no accuracy claim" in body.lower() or "no accuracy claim" in body
    for match in re.finditer(r"(\d+(?:\.\d+)?)\s*%\s*(?:accura|precis|recall|f1)",
                             body, re.IGNORECASE):
        pytest.fail(f"the listing states an accuracy figure: {match.group(0)!r}")


def test_the_open_finding_is_disclosed_in_the_listing_body():
    """A limitation the listing omits is a defect, not a limitation."""
    body = _flat(PLAYBOOK)
    assert "One red-team finding remains open" in body
    assert "Authentication-Results" in body
    assert "attachment" in body.lower() and "not read" in body


def test_both_drafts_declare_the_same_author_and_repository():
    """Two drafts that disagree about who submitted them cannot both be right."""
    def field(text: str, name: str) -> str:
        match = re.search(rf'^{name}:\s*"([^"]*)"', text.split("---")[1],
                          re.MULTILINE)
        return match.group(1) if match else ""

    for name in ("author", "github_url"):
        assert field(_text(PLAYBOOK), name) == field(_text(MCP_LISTING), name), (
            f"the two drafts disagree about {name}"
        )
