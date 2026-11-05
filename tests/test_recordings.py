"""The committed recordings in ``fixtures/replay/`` are an artifact, not a cache.

They are what lets a judge run the model tiers with no inference host, which makes
them simultaneously the most useful files in the repository and the ones with the
most ways to be wrong: a recording that leaks the address it came from publishes
private infrastructure, a recording made against real mail publishes real mail, and
a recording nobody can match to a request is decoration.

So the checks run against the committed files themselves, on every test run.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config  # noqa: E402
from tenable_email.pipeline import MODEL_TIERS  # noqa: E402
from tenable_email.replay import (  # noqa: E402
    ENTRY_FIELDS,
    INDEX_FILE,
    KEY_PREFIX,
    SCHEMA_VERSION,
    ReplayStore,
    find_addresses,
)
from tenable_email.tiers import TIER_REGISTRY  # noqa: E402

STORE = REPO / "fixtures" / "replay"
CORPUS = REPO / "fixtures" / "synthetic"

ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def entries() -> list[dict]:
    return ReplayStore(root=STORE).entries()


def test_the_store_directory_exists_and_is_populated():
    assert STORE.is_dir(), (
        "fixtures/replay/ is missing: run tools/record-replay.sh against live "
        "endpoints. It must not be hand-written -- a fabricated recording is the "
        "one thing worse than no recording."
    )
    assert entries(), "fixtures/replay/ holds no readable recordings"


def test_recordings_are_not_gitignored():
    """They are committed on purpose: this is the offline path's data."""
    sample = sorted(STORE.glob("*.json"))
    assert sample, "nothing to check"
    probe = subprocess.run(
        ["git", "check-ignore", "-v"] + [str(p.relative_to(REPO)) for p in sample],
        cwd=REPO, capture_output=True, text=True,
    )
    assert probe.returncode != 0, (
        "some recordings are ignored by .gitignore and would not ship:\n"
        + probe.stdout
    )


@pytest.mark.parametrize("tier", sorted({t.name for t in TIER_REGISTRY}))
def test_every_tier_is_either_recorded_or_explicitly_unreachable(tier):
    """A tier with no recording is a tier that was not reachable, not a tier
    somebody forgot. Both are legitimate; silence about which is not, so the
    store's coverage is asserted here and reported per tier by the record tool.
    """
    recorded = {entry["tier"] for entry in entries()}
    unrecorded = {t.name for t in TIER_REGISTRY} - recorded
    assert tier in recorded or tier in unrecorded
    if tier not in recorded:
        assert tier in {"injection_classifier", "spam_three_way"}, (
            f"{tier} has a live endpoint in this estate and no recording: re-run "
            f"tools/record-replay.sh"
        )


def test_recorded_tiers_cover_the_tiers_the_offline_demo_asks_for():
    """At least the four tiers reachable on this estate: classifier, URL
    reputation, prompt injection, vision and adjudication.
    """
    recorded = {entry["tier"] for entry in entries()}
    assert {"classifier", "url_reputation", "prompt_injection", "vision", "llm"} <= recorded


def test_each_entry_has_the_declared_shape_and_a_usable_key():
    for entry in entries():
        where = f"{entry.get('tier')}/{str(entry.get('key'))[:KEY_PREFIX]}"
        assert set(entry) == set(ENTRY_FIELDS), where
        assert entry["schema_version"] == SCHEMA_VERSION, where
        assert re.fullmatch(r"[0-9a-f]{64}", str(entry["key"])), where
        assert entry["tier"] in {t.name for t in TIER_REGISTRY}, where
        assert ISO_UTC.match(str(entry["recorded_at"])), where
        assert isinstance(entry["response"], dict), where
        assert entry["response"], where


def test_each_entry_names_a_role_and_never_an_address():
    for entry in entries():
        role = str(entry["endpoint_role"])
        where = f"{entry['tier']}/{entry['key'][:KEY_PREFIX]}"
        assert role.strip(), where
        assert "://" not in role, where
        assert not find_addresses(role), f"{where}: role {role!r} looks like an address"
        text = json.dumps(entry, sort_keys=True)
        leaks = find_addresses(text)
        assert not leaks, f"{where} contains infrastructure detail: {leaks}"


def test_the_index_agrees_with_the_files_on_disk():
    index = json.loads((STORE / INDEX_FILE).read_text())
    on_disk = {
        p.name for p in STORE.glob("*.json") if p.name != INDEX_FILE
    }
    assert set(index["entries"]) == on_disk
    for name, item in index["entries"].items():
        entry = json.loads((STORE / name).read_text())
        assert item["key"] == entry["key"]
        assert item["tier"] == entry["tier"]
        assert item["model"] == entry["model"]
        assert item["endpoint_role"] == entry["endpoint_role"]
    assert index["schema_version"] == SCHEMA_VERSION


def test_file_names_match_tier_and_key_prefix():
    for entry in entries():
        expected = f"{entry['tier']}__{entry['key'][:KEY_PREFIX]}.json"
        assert (STORE / expected).is_file(), expected


def test_every_echoed_input_in_a_recording_comes_from_the_synthetic_corpus():
    """The data policy's tripwire, checked rather than promised.

    Some services echo back what they were shown -- the reputation and injection
    engines return the exact ``input`` they scored -- so a recording made against
    real mail would carry real mail into a committed file. Every echoed input is
    therefore required to appear in the fixture corpus, and a recording that does
    not come from ``fixtures/synthetic/`` fails here.

    Model *answers* are deliberately not compared: an LLM's analysis of a fixture
    is new text by definition, and prose is not what this checks. The general
    guard for employer-specific strings is
    ``tests/test_doc_references.py``, which scans every tracked file -- these
    recordings included -- for private infrastructure and organization terms.
    """
    corpus_text = "\n".join(
        path.read_bytes().decode("utf-8", "replace")
        for path in sorted(CORPUS.glob("*.eml"))
    )
    # Percent-decoded too: a wrapped link is recorded as the destination the
    # deterministic unwrapper produced, which is the same string the fixture
    # carries with %3A and %2F in place of the punctuation.
    variants = [corpus_text, unquote(corpus_text)]
    normalized = [" ".join(v.split()) for v in variants]
    offenders: list[str] = []
    checked = 0
    for entry in entries():
        for value in _echoed_inputs(entry["response"]):
            probe = " ".join(value.split())
            if not probe:
                continue
            checked += 1
            if not any(
                probe in space_collapse
                or probe.replace(" ", "") in space_collapse.replace(" ", "")
                for space_collapse in normalized
            ):
                offenders.append(
                    f"{entry['tier']}/{entry['key'][:8]}: {probe[:80]!r}"
                )
    assert checked, "no echoed inputs found in any recording: the check is vacuous"
    assert not offenders, (
        "recording content that appears in no fixture -- a recording must be "
        "generated from fixtures/synthetic/ only:\n"
        + "\n".join(sorted(set(offenders))[:10])
    )


def _echoed_inputs(node):
    """Every value stored under an ``input`` key inside a service response."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "input" and isinstance(value, str):
                yield value
            else:
                yield from _echoed_inputs(value)
    elif isinstance(node, list):
        for value in node:
            yield from _echoed_inputs(value)


def test_the_store_replays_without_a_single_miss():
    """The corpus asks the store for exactly what was recorded, no more, no less."""
    from tenable_email.parse import parse_file
    from tenable_email.pipeline import triage_message

    config = Config(replay=True, replay_dir=str(STORE))
    store = ReplayStore(root=STORE)
    for path in sorted(CORPUS.glob("*.eml")):
        triage_message(parse_file(path), config, store=store)
    assert store.miss_count == 0
    assert store.hit_count >= len(list(CORPUS.glob("*.eml")))


def test_replayed_verdicts_carry_model_judgments_and_name_the_unavailable_tiers():
    """The offline demo's actual output, checked end to end."""
    from tenable_email.evidence import Provenance
    from tenable_email.parse import parse_file
    from tenable_email.pipeline import triage_message

    config = Config(replay=True, replay_dir=str(STORE))
    judged = 0
    for path in sorted(CORPUS.glob("*.eml")):
        verdict = triage_message(parse_file(path), config)
        verdict.assert_citable()
        gaps = {
            f.key: f.detail
            for f in verdict.evidence.by_provenance(Provenance.UNAVAILABLE)
        }
        for tier, _field, _stage in MODEL_TIERS:
            if tier in {entry["tier"] for entry in entries()}:
                continue
            assert tier in gaps, f"{path.stem}: {tier} is neither judged nor absent"
        if verdict.evidence.by_provenance(Provenance.MODEL_JUDGMENT):
            judged += 1
    assert judged >= 12, "the offline demo produced almost no model contributions"


def test_no_recording_carries_attachment_bytes_from_a_message_part():
    """Serialization is the leak surface, and base64 is how a leak looks.

    The vision tier legitimately sends an image, so base64 appears in its payload
    key -- but nowhere in a *response*, and no response may carry a long base64
    run that could be an attachment.
    """
    pattern = re.compile(r"[A-Za-z0-9+/]{2048,}={0,2}")
    for entry in entries():
        text = json.dumps(entry["response"])
        assert not pattern.search(text), entry["key"][:KEY_PREFIX]
