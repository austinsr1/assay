"""The stage contract parses, validates, and agrees with a real YAML parser.

Two independent things are proven here.

1. ``stages.yaml`` says what README.md says it says: eight stages, one of which
   writes, and the write stage carries the approval language the prose uses.
2. The **minimal parser** in :mod:`tenable_email.contract` is correct on that
   file. It exists so the shipped core needs no YAML dependency, which is a
   claim the README makes and a reviewer checks -- so correctness is verified
   against PyYAML, held as a test-only extra, field for field. Without this
   cross-check the minimal parser would be an untested translation layer sitting
   between the contract and every consumer of it.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.contract import (  # noqa: E402
    COMPONENT_REGISTRY,
    CONTRACT_VERSION,
    Contract,
    ContractError,
    Stage,
    contract_summary,
    load_contract,
    parse_stage_yaml,
    registry_access,
    validate_contract,
)
from tenable_email.pipeline import (  # noqa: E402
    DETERMINISTIC_STAGES_RUN,
    STAGES_SKIPPED_WITHOUT_CONFIG,
)

STAGES_YAML = REPO / "stages.yaml"
README = REPO / "README.md"

#: The eight stages, in order, as README.md's Design section describes them.
EXPECTED = [
    ("intake", "Intake"),
    ("parse-authenticate", "Parse and authenticate"),
    ("deterministic-signals", "Deterministic signals"),
    ("classifier-cascade", "Classifier cascade"),
    ("vision", "Vision"),
    ("attachment-content", "Attachment structure"),
    ("adjudication", "Adjudication"),
    ("disposition-writeback", "Disposition and writeback"),
]


@pytest.fixture(scope="module")
def contract() -> Contract:
    assert STAGES_YAML.is_file(), "stages.yaml is missing from the repository root"
    return load_contract(STAGES_YAML)


# --- B1: the shape of the contract -----------------------------------------


def test_contract_file_exists_and_parses(contract: Contract):
    assert contract.version == CONTRACT_VERSION
    assert len(contract.stages) == 8


def test_stage_ids_and_titles_match_the_readme_prose(contract: Contract):
    assert [(s.id, s.title) for s in contract.stages] == EXPECTED
    readme = README.read_text(encoding="utf-8")
    for _id, title in EXPECTED:
        assert f"**{title}**" in readme, (
            f"README.md must name the stage '{title}' in its Design list"
        )


def test_capabilities_are_named_not_products(contract: Contract):
    """Providers and capabilities are swappable, so they name abilities.

    A capability called "gmail" or "claude" cannot be substituted without
    editing the chain, which is the property 1st place bought with the same
    design and what the parity matrix means by "capabilities, not products".
    """
    for stage in contract.stages:
        assert stage.capability == stage.capability.lower().replace(" ", "_")
        assert "_" in stage.capability, f"{stage.id}: capability should be a phrase"
        assert stage.provider == stage.provider.lower().replace(" ", "_")


def test_exactly_one_write_stage_and_it_is_the_last(contract: Contract):
    writes = contract.write_stages()
    assert len(writes) == 1
    assert writes[0].id == "disposition-writeback"
    assert contract.stages[-1].access == "write"
    assert all(s.access == "read-only" for s in contract.stages[:-1])


def test_write_stage_declares_an_approval_gate_the_prose_carries(contract: Contract):
    stage = contract.stage("disposition-writeback")
    assert stage.approval_required is True
    language = (stage.approval_language or "").strip()
    assert language, "the write stage must name what a human is approving"
    assert language in README.read_text(encoding="utf-8"), (
        f"approval language {language!r} must appear verbatim in README.md, or "
        f"the prose can promise a checkpoint the contract does not describe"
    )


def test_no_write_stage_calls_a_model(contract: Contract):
    for stage in contract.write_stages():
        assert stage.model_tier is None, (
            f"write stage '{stage.id}' calls a model tier; the stage that "
            f"mutates the outside world must not also interpret the message"
        )


def test_model_tiers_are_only_on_read_only_stages(contract: Contract):
    for stage in contract.stages:
        if stage.model_tier is not None:
            assert stage.access == "read-only"
            assert stage.optional is True or stage.id == "adjudication"


def test_optional_stages_are_the_unconfigured_ones(contract: Contract):
    optional = {s.id for s in contract.stages if s.optional}
    assert optional == set(STAGES_SKIPPED_WITHOUT_CONFIG)


def test_stages_run_by_the_pipeline_are_contract_stages(contract: Contract):
    """The code's stage ids and the file's stage ids are the same ids."""
    known = set(contract.ids())
    assert set(DETERMINISTIC_STAGES_RUN) <= known
    assert set(STAGES_SKIPPED_WITHOUT_CONFIG) <= known
    assert DETERMINISTIC_STAGES_RUN == tuple(
        s.id for s in contract.stages if s.id in DETERMINISTIC_STAGES_RUN
    )


# --- B2: registry and validation -------------------------------------------


def test_every_provider_is_registered_with_matching_access(contract: Contract):
    for stage in contract.stages:
        assert stage.provider in COMPONENT_REGISTRY
        module_path, access = COMPONENT_REGISTRY[stage.provider]
        assert module_path.startswith("tenable_email.")
        assert access == stage.access
        assert registry_access(stage.provider) == access


def test_unmutated_contract_has_no_violations(contract: Contract):
    assert validate_contract(contract) == []


def test_contract_summary_counts_stages_writes_and_gates(contract: Contract):
    assert contract_summary(contract) == "8 stages, 1 write stage, 1 approval gate"


def test_contract_helpers(contract: Contract):
    assert contract.ids()[0] == "intake"
    assert contract.titles()[-1] == "Disposition and writeback"
    assert contract.stage("vision").capability == "image_understanding"
    with pytest.raises(KeyError):
        contract.stage("no-such-stage")


def _patch_stage(stage: Stage, **changes) -> Stage:
    """A copy of one stage with fields replaced."""
    return Stage(**{**stage.as_dict(), **changes})


def _mutate(contract: Contract, stage_id: str, **changes) -> Contract:
    return Contract(
        version=contract.version,
        stages=[
            _patch_stage(s, **changes) if s.id == stage_id else s
            for s in contract.stages
        ],
    )


@pytest.mark.parametrize(
    "stage_id,changes,needle",
    [
        ("disposition-writeback", {"access": "read-only"}, "registered as write"),
        ("vision", {"access": "write"}, "approval_required is not true"),
        ("vision", {"access": "write", "approval_required": True}, "approval_language is"),
        ("vision", {"model_tier": "quantum"}, "unknown model_tier"),
        ("disposition-writeback", {"model_tier": "llm"}, "must not call a model"),
        ("adjudication", {"id": "Adjudication_Id"}, "not kebab-case"),
        ("adjudication", {"id": "intake"}, "duplicate stage id"),
        ("adjudication", {"provider": "ghost_component"}, "not in COMPONENT_REGISTRY"),
        ("vision", {"approval_required": True, "approval_language": "  "}, "approval_language is"),
        ("vision", {"description": ""}, "description is empty"),
        ("vision", {"access": "readwrite"}, "must be one of"),
    ],
)
def test_validate_contract_reports_each_violation(contract, stage_id, changes, needle):
    violations = validate_contract(_mutate(contract, stage_id, **changes))
    assert violations, f"{stage_id} {changes} produced no violation"
    assert any(needle in v for v in violations), f"expected {needle!r} in {violations}"


def test_two_write_stages_are_both_reported(contract):
    """Every violating stage is reported, not just the first one.

    A validator that stops early lets the second bad stage through review.
    """
    stages = []
    for stage in contract.stages:
        if stage.id == "disposition-writeback":
            stage = _patch_stage(stage, approval_required=False)
        elif stage.id == "vision":
            stage = _patch_stage(
                stage, access="write", approval_required=True,
                approval_language="explicit operator approval",
            )
        stages.append(stage)
    violations = validate_contract(Contract(version=contract.version, stages=stages))
    text = "\n".join(violations)
    assert "access is 'write' but approval_required is not true" in text
    assert "is registered as read-only but the stage declares" in text
    assert len([v for v in violations if "write" in v]) >= 2


def test_empty_stage_list_is_a_violation():
    violations = validate_contract(Contract(version=1, stages=[]))
    assert violations == ["contract declares no stages"]


# --- B2: the minimal parser --------------------------------------------------


def test_parser_agrees_with_pyyaml_field_for_field(contract: Contract):
    """The dependency-free parser must not be a slightly different language.

    PyYAML is a test-only extra. If the two disagree on any field of any stage,
    the contract the tools read is not the contract a YAML reader sees -- and
    every enforcement built on top of it would be enforcing a paraphrase.
    """
    declared = yaml.safe_load(STAGES_YAML.read_text(encoding="utf-8"))
    assert declared["version"] == contract.version
    assert len(declared["stages"]) == len(contract.stages)
    for item, parsed in zip(declared["stages"], contract.stages):
        assert parsed == Stage(**item), (
            f"minimal parser and PyYAML disagree on {item.get('id')!r}"
        )


def test_parser_handles_comments_blank_lines_and_quotes():
    text = textwrap.dedent(
        """
        # leading comment
        version: 1

        stages:
          - id: one   # inline comment
            title: "One"
            capability: cap
            provider: eml_directory
            access: read-only
            optional: false
            model_tier: null
            approval_required: false
            approval_language: ~
            description: A stage.
        """
    )
    contract = parse_stage_yaml(text)
    assert contract.version == 1
    assert len(contract.stages) == 1
    stage = contract.stages[0]
    assert stage.title == "One"
    assert stage.model_tier is None
    assert stage.approval_language is None
    assert stage.optional is False


def test_description_may_contain_colons():
    text = (
        "version: 1\nstages:\n"
        "  - id: one\n    title: One\n    capability: cap\n"
        "    provider: eml_directory\n    access: read-only\n"
        "    description: Ratio 2:1 note: still one value.\n"
    )
    assert parse_stage_yaml(text).stages[0].description == "Ratio 2:1 note: still one value."


@pytest.mark.parametrize(
    "text,needle",
    [
        ("", "no top-level 'version'"),
        ("stages:\n", "no top-level 'version'"),
        ("version: two\nstages:\n", "version must be an integer"),
        ("version: 2\nstages:\n", "unsupported contract version"),
        ("version: 1\nwidgets:\n", "unknown top-level key"),
        ("version: 1\nstages: []\n", "block list"),
        ("version: 1\n  stages:\n", "content before the 'stages:' key"),
        ("version: 1\nstages:\n    id: one\n", "before any '- ' list item"),
        ("version: 1\nstages:\n  - \n", "empty list item"),
        ("version: 1\nstages:\n  - id: one\n    id: two\n", "duplicate key"),
        ("version: 1\nstages:\n  - id: one\n    bogus: x\n", "unknown key"),
        ("version: 1\nstages:\n  - id: one\n", "missing required key"),
        ("version: 1\nstages:\n  - id: one\n    title: One\n    capability: c\n"
         "    provider: eml_directory\n    access: read-only\n    optional: yes\n",
         "must be true or false"),
        ("version: 1\nstages:\n  - id: one\n\ttitle: tab\n", "tabs are not indentation"),
        ("version: 1\nstages:\n  - id\n", "expected 'key: value'"),
    ],
)
def test_parser_rejects_what_it_should_not_guess(text, needle):
    with pytest.raises(ContractError) as excinfo:
        parse_stage_yaml(text)
    assert needle in str(excinfo.value), str(excinfo.value)


def test_load_contract_reports_a_missing_file(tmp_path):
    with pytest.raises(ContractError, match="not found"):
        load_contract(tmp_path / "absent.yaml")
