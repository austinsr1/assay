"""Prove the contract validator has teeth by breaking the contract on purpose.

A validator that has never failed is indistinguishable from a validator that
cannot fail. This module injects each drift the mechanism is supposed to catch --
a dropped stage, a reordered stage, a renamed provider, a stripped approval, a
duplicated id, an unknown model tier, malformed YAML -- and asserts that
validation reports *that specific* violation, in that document, and that the
command a reviewer runs exits non-zero.

The mutations are applied to a copy in a tmp directory. The working tree is
never touched, so a crashed run cannot leave the contract broken.

Every drift test is paired with :func:`test_the_unmutated_contract_passes`,
without which all of these could pass vacuously on a validator that rejects
everything.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "validate_contract.py"
STAGES_YAML = REPO / "stages.yaml"
README = REPO / "README.md"
SKILL = REPO / "SKILL.md"

sys.path.insert(0, str(REPO / "src"))

from tenable_email.contract import ContractError, load_contract, validate_contract  # noqa: E402

spec = importlib.util.spec_from_file_location("validate_contract_tool", TOOL)
assert spec and spec.loader, f"cannot load {TOOL}"
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

APPROVAL_LANGUAGE = "human approval required"


def pristine() -> str:
    return STAGES_YAML.read_text(encoding="utf-8")


def mutate(tmp_path: Path, text: str, label: str, name: str = "stages.yaml") -> Path:
    """Write a mutated contract to a tmp path, refusing a mutation that did nothing.

    An unapplied ``str.replace`` would silently hand the validator the pristine
    contract and every assertion downstream would fail for the wrong reason --
    "expected a violation, got none" -- which reads like a validator with no
    teeth rather than like a broken test.
    """
    assert text != pristine(), f"drift case {label} did not modify stages.yaml"
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def violations_for(mutated_path: Path, readme_text: str | None = None) -> list[str]:
    _contract, violations, _notes = tool.collect(
        mutated_path, readme_text=readme_text
    )
    return violations


def assert_reports(violations: list[str], needle: str, label: str) -> None:
    assert violations, f"{label}: validator reported nothing"
    joined = "\n".join(violations)
    assert needle in joined, (
        f"{label}: expected {needle!r} in the report, got:\n{joined}"
    )


def drop_stage(text: str, stage_id: str) -> str:
    """Remove one stage block from the contract, leaving the rest untouched."""
    chunks = text.split("\n\n")
    kept = [c for c in chunks if not c.lstrip().startswith(f"- id: {stage_id}")]
    assert len(kept) == len(chunks) - 1, f"no block starting '- id: {stage_id}'"
    return "\n\n".join(kept)


def reorder(text: str, first_id: str, second_id: str) -> str:
    """Swap two stage blocks in the contract text, order otherwise untouched."""
    chunks = text.split("\n\n")

    def find(stage_id: str) -> int:
        for n, chunk in enumerate(chunks):
            if chunk.lstrip().startswith(f"- id: {stage_id}"):
                return n
        raise AssertionError(f"no block starting '- id: {stage_id}' in the contract")

    a, b = find(first_id), find(second_id)
    chunks[a], chunks[b] = chunks[b], chunks[a]
    return "\n\n".join(chunks)


# --- the control: nothing is wrong with the real contract --------------------


def test_the_unmutated_contract_passes(tmp_path):
    """The control, in both states of one document Bundle F created.

    This assertion used to require the tool to report SKILL.md's stage check as
    *skipped*, which was a placeholder for "that document does not exist yet".
    Bundle F wrote it, so the check is live, and the live state is pinned more
    strictly than the placeholder was: the real skill has to agree with the
    contract, and a skill whose stage list has drifted has to be reported by
    name. Silently passing a document that is present is the failure the note
    existed to prevent, so both branches are asserted rather than one assumed.
    """
    contract, violations, notes = tool.collect(STAGES_YAML)
    assert violations == [], f"real contract is not valid: {violations}"
    assert contract is not None and len(contract.stages) == 8

    if not SKILL.is_file():
        assert any("SKILL.md" in n for n in notes), (
            "with no SKILL.md present the tool must report its stage check as "
            "skipped, not silently pass it"
        )
        return

    assert not any("SKILL.md" in n for n in notes), (
        "SKILL.md exists, so its stage list must be validated rather than "
        f"reported as skipped: {notes}"
    )
    drifted = SKILL.read_text(encoding="utf-8").replace(
        "**Adjudication**", "**Judgment**", 1
    )
    assert drifted != SKILL.read_text(encoding="utf-8"), (
        "SKILL.md must carry the stage title this mutation targets, or the "
        "drift check below passes vacuously"
    )
    _c, skill_violations, _n = tool.collect(STAGES_YAML, skill_text=drifted)
    assert any("SKILL.md" in v for v in skill_violations), (
        "a SKILL.md stage list that disagrees with stages.yaml has to be "
        f"reported against SKILL.md, got: {skill_violations}"
    )


def test_the_tool_exits_zero_on_the_real_contract():
    result = subprocess.run(
        [sys.executable, str(TOOL)], capture_output=True, text=True, cwd=REPO
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "contract OK: 8 stages, 1 write stage, 1 approval gate" in result.stdout, (
        result.stdout
    )


def test_the_tool_exits_non_zero_for_a_reviewer_who_edits_a_copy(tmp_path):
    """The acceptance test a human can repeat by hand.

    Delete a stage from a copy of stages.yaml, run the documented command
    against the copy, and it must fail. This is the drift case exercised
    through the CLI rather than through the function, so a bug that only
    appears in main() cannot hide.
    """
    path = mutate(
        tmp_path,
        drop_stage(pristine(), "attachment-content"),
        "cli dropped stage",
        name="broken-stages.yaml",
    )
    result = subprocess.run(
        [sys.executable, str(TOOL), str(path)],
        capture_output=True, text=True, cwd=REPO,
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "contract FAILED" in result.stdout, result.stdout


# --- drift 1: a stage disappears -------------------------------------------


def test_dropped_stage_is_caught(tmp_path):
    path = mutate(tmp_path, drop_stage(pristine(), "vision"), "dropped stage")
    contract = load_contract(path)
    assert len(contract.stages) == 7, "the stage really was removed from the file"
    assert_reports(
        violations_for(path),
        "README.md declares but contract omits: ['Vision']",
        "dropped stage",
    )
    # The contract is internally valid on its own; it is the prose comparison
    # that catches a stage quietly disappearing.
    assert validate_contract(contract) == []


def test_reordered_stages_are_caught(tmp_path):
    """Swapping two adjacent stages must fail even though the set is unchanged.

    Cascade order is the whole design -- a stage that runs out of order spends
    an LLM call the deterministic layer would have saved.
    """
    text = reorder(pristine(), "classifier-cascade", "vision")
    path = mutate(tmp_path, text, "swapped stages")
    contract = load_contract(path)
    assert contract.ids()[3] == "vision", "the swap did not take"
    violations = violations_for(path)
    joined = "\n".join(violations)
    assert "wrong order" in joined, joined
    assert "Classifier cascade" in joined and "Vision" in joined


def test_validate_contract_alone_does_not_care_about_order(tmp_path):
    """Order is a prose-contract property, checked by the tool, not by the file.

    Recorded so nobody later "fixes" the drift test by moving the order check
    into validate_contract and leaving this one passing for the wrong reason.
    """
    text = pristine().replace(
        "  - id: intake\n    title: Intake\n",
        "  - id: intake\n    title: Intake renamed\n",
    )
    path = mutate(tmp_path, text, "renamed title only")
    from tenable_email.contract import validate_contract

    assert validate_contract(load_contract(path)) == []
    assert_reports(
        violations_for(path),
        "stage list does not match stages.yaml",
        "renamed title vs prose",
    )


# --- drift 2: a provider is renamed ----------------------------------------


def test_renamed_provider_is_caught(tmp_path):
    path = mutate(
        tmp_path,
        pristine().replace("provider: local_vlm", "provider: estate_vlm"),
        "renamed provider",
    )
    assert_reports(
        violations_for(path),
        "provider 'estate_vlm' (stage 'vision') is not in COMPONENT_REGISTRY",
        "renamed provider",
    )


def test_provider_access_flip_is_caught(tmp_path):
    """A write stage cannot be dressed as read-only by editing the stage alone."""
    path = mutate(
        tmp_path,
        pristine().replace(
            "    provider: case_record_writeback\n    access: write",
            "    provider: case_record_writeback\n    access: read-only",
        ),
        "access flip",
    )
    joined = "\n".join(violations_for(path))
    assert "is registered as write but the stage declares access 'read-only'" in joined


# --- drift 3: the approval gate is weakened --------------------------------


def test_write_stage_without_approval_flag_is_caught(tmp_path):
    path = mutate(
        tmp_path,
        pristine().replace(
            "    approval_required: true\n    approval_language: human approval required",
            "    approval_required: false\n    approval_language: human approval required",
        ),
        "approval flag stripped",
    )
    joined = "\n".join(violations_for(path))
    assert "does not declare approval_required: true" in joined
    assert "access is 'write' but approval_required is not true" in joined


def test_write_stage_without_approval_language_is_caught(tmp_path):
    path = mutate(
        tmp_path,
        pristine().replace("    approval_language: human approval required\n", ""),
        "approval language removed from the contract",
    )
    joined = "\n".join(violations_for(path))
    assert "declares no approval_language" in joined


def test_approval_language_stripped_from_the_prose_is_caught(tmp_path):
    """The README can be edited to drop the checkpoint it is supposed to honour."""
    original = README.read_text(encoding="utf-8")
    assert APPROVAL_LANGUAGE in original
    scrubbed = original.replace(APPROVAL_LANGUAGE, "applied automatically")
    assert scrubbed != original and APPROVAL_LANGUAGE not in scrubbed
    joined = "\n".join(violations_for(STAGES_YAML, readme_text=scrubbed))
    assert (
        f"approval language {APPROVAL_LANGUAGE!r} is absent from README.md" in joined
    ), joined


def test_approval_language_reworded_in_the_contract_is_caught(tmp_path):
    path = mutate(
        tmp_path,
        pristine().replace(
            "    approval_language: human approval required",
            "    approval_language: automatic writeback with no human step",
        ),
        "approval language reworded",
    )
    joined = "\n".join(violations_for(path))
    assert "is absent from README.md" in joined


def test_readme_title_reworded_is_caught(tmp_path):
    scrubbed = README.read_text(encoding="utf-8").replace(
        "**Deterministic signals**", "**Header heuristics**"
    )
    assert scrubbed != README.read_text(encoding="utf-8")
    joined = "\n".join(violations_for(STAGES_YAML, readme_text=scrubbed))
    assert "stage list does not match stages.yaml" in joined
    assert "Header heuristics" in joined


# --- drift 4: identity and vocabulary break ---------------------------------


def test_duplicate_stage_id_is_caught(tmp_path):
    path = mutate(
        tmp_path,
        pristine().replace("  - id: vision\n", "  - id: intake\n"),
        "duplicate id",
    )
    assert_reports(violations_for(path), "duplicate stage id 'intake'", "duplicate id")


def test_non_kebab_id_is_caught(tmp_path):
    path = mutate(
        tmp_path,
        pristine().replace("  - id: vision\n", "  - id: VisionStage\n"),
        "non-kebab id",
    )
    assert_reports(violations_for(path), "is not kebab-case", "non-kebab id")


def test_unknown_model_tier_is_caught(tmp_path):
    path = mutate(
        tmp_path,
        pristine().replace("    model_tier: vlm", "    model_tier: frontier_api"),
        "unknown model tier",
    )
    assert_reports(
        violations_for(path), "unknown model_tier 'frontier_api'", "unknown model tier"
    )


def test_write_stage_that_calls_a_model_is_caught(tmp_path):
    path = mutate(
        tmp_path,
        pristine().replace(
            "    provider: case_record_writeback\n    access: write\n    optional: true\n    model_tier: null",
            "    provider: case_record_writeback\n    access: write\n    optional: true\n    model_tier: llm",
        ),
        "write stage calling a model",
    )
    assert_reports(violations_for(path), "a write stage must not call a model", "write+model")


def test_no_write_stage_at_all_is_caught(tmp_path):
    """Dropping the write stage silently is also a drift, not a simplification."""
    text = pristine().replace(
        "    provider: case_record_writeback\n    access: write",
        "    provider: case_record_writeback\n    access: read-only",
    )
    path = mutate(tmp_path, text, "no write stage")
    assert_reports(
        violations_for(path),
        "contract declares no write stage",
        "no write stage",
    )


# --- drift 5: malformed input ----------------------------------------------


@pytest.mark.parametrize(
    "fragment,needle",
    [
        ("version: 1\nstages: {}\n", "block list"),
        ("version: abc\nstages:\n", "version must be an integer"),
        ("stages:\n", "no top-level 'version'"),
        ("version: 1\nstagez:\n", "unknown top-level key"),
        ("version: 1\nstages:\n  - id: intake\n    bogus: true\n", "unknown key"),
    ],
    ids=["flow-mapping", "bad-version", "no-version", "bad-root-key", "unknown-field"],
)
def test_malformed_yaml_raises_contract_error(tmp_path, fragment, needle):
    path = mutate(tmp_path, fragment, f"malformed: {needle}", name="malformed.yaml")
    with pytest.raises(ContractError) as excinfo:
        load_contract(path)
    assert needle in str(excinfo.value)
    # The tool reports an unparseable contract as a failure, not a traceback.
    joined = "\n".join(violations_for(path))
    assert "contract does not parse" in joined


def test_a_real_yaml_reader_accepts_what_our_subset_rejects(tmp_path):
    """The boundary of the minimal parser, stated rather than assumed.

    PyYAML reads flow style; our subset does not, and must say so instead of
    mis-parsing. If a real YAML reader and the contract diverged quietly, the
    contract a reviewer reads in the file would not be the contract the tool
    enforces.
    """
    yaml = pytest.importorskip("yaml")
    flow = "version: 1\nstages: [{id: intake}]\n"
    assert isinstance(yaml.safe_load(flow), dict), (
        "PyYAML is expected to accept flow style; this test documents the "
        "divergence, so it is only meaningful while that is true"
    )
    path = mutate(tmp_path, flow, "flow style", name="flow.yaml")
    with pytest.raises(ContractError):
        load_contract(path)
    assert "block list" in "\n".join(violations_for(path))
