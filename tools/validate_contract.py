#!/usr/bin/env python3
"""Validate the stage contract against the prose that describes it.

Run it directly -- it is stdlib only, so it works in a fresh clone with nothing
installed::

    python3 tools/validate_contract.py

It asserts five things, all of them cross-document rather than in-file:

1. ``stages.yaml`` parses and passes :func:`validate_contract` (unique kebab
   ids, providers registered, write stages gated).
2. The prose documents declare **exactly** the stages of ``stages.yaml``, in the
   same order, under the same titles. The comparison is an equality of two
   ordered lists, not a "every contract stage appears somewhere in the prose"
   subset test: a subset check passes happily when a stage has been dropped from
   the contract, which is the drift that matters.
3. ``SKILL.md``, if it exists, says the same. It is written by Bundle F, so its
   absence is reported and skipped rather than failed.
4. Every provider named by a stage exists in ``COMPONENT_REGISTRY``, and the
   access the registry declares for it agrees with the access the stage claims.
5. Every ``access: write`` stage declares ``approval_required: true`` and its
   ``approval_language`` appears verbatim in the prose, so the words a human has
   to agree to cannot drift away from the words the contract carries.

Exits non-zero with a readable report on any violation.
``tests/test_contract_drift.py`` breaks each of these on purpose and asserts
this tool fails, which is what makes the validator evidence rather than decoration.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.contract import (  # noqa: E402
    COMPONENT_REGISTRY,
    Contract,
    ContractError,
    contract_summary,
    load_contract,
    registry_access,
    validate_contract,
)

CONTRACT_PATH = REPO / "stages.yaml"
README_PATH = REPO / "README.md"
SKILL_PATH = REPO / "SKILL.md"

#: A stage claim in the prose: a numbered list item whose lead phrase is bold,
#: ``1. **Title** (details) - description``. Only the bolded title is compared;
#: everything after it is prose. Deliberately restricted to numbered items --
#: README's known-limitations section uses bulleted bold lead-ins, and those are
#: not stage claims.
_PROSED_STAGE = re.compile(
    r"^\s*(?:[0-9]+[.)])\s+\*\*(?P<title>[^*]+)\*\*", re.MULTILINE
)


def prose_stage_titles(text: str) -> list[str]:
    """Ordered stage titles declared by a markdown document.

    A document that describes the chain uses a numbered list with the stage
    title in bold -- the form README.md's Design section uses, and the form
    SKILL.md is required to use. Anything else in the file (headings, prose,
    bulleted limitation lists, code fences) is not a stage claim.
    """
    return [m.group("title").strip() for m in _PROSED_STAGE.finditer(text)]


def document_violations(
    contract: Contract, text: str, label: str
) -> list[str]:
    """Violations between one prose document and the contract."""
    out: list[str] = []
    declared = contract.titles()
    found = prose_stage_titles(text)

    if not found:
        out.append(
            f"{label}: no stage list found; expected a numbered list whose bold "
            f"titles are exactly {declared}"
        )
    elif found != declared:
        missing = [t for t in declared if t not in found]
        extra = [t for t in found if t not in declared]
        detail = []
        if missing:
            detail.append(f"contract declares but {label} omits: {missing}")
        if extra:
            detail.append(f"{label} declares but contract omits: {extra}")
        if not detail:
            detail.append(
                f"same stages, wrong order: {label} has {found}, contract has "
                f"{declared}"
            )
        out.append(
            f"{label}: stage list does not match stages.yaml "
            f"({'; '.join(detail)})"
        )

    # The approval gate itself is checked by write_stage_violations, which can
    # name the write stage specifically. Nothing here repeats it.
    return out
def provider_violations(contract: Contract) -> list[str]:
    """Registry checks, reported separately from contract-internal checks.

    ``validate_contract`` already covers these; the tool keeps them in their own
    section so a failure names the section that broke rather than presenting one
    undifferentiated list.
    """
    out: list[str] = []
    for stage in contract.stages:
        if stage.provider not in COMPONENT_REGISTRY:
            out.append(
                f"provider {stage.provider!r} (stage '{stage.id}') is not in "
                f"COMPONENT_REGISTRY"
            )
            continue
        registered = registry_access(stage.provider)
        if registered != stage.access:
            out.append(
                f"provider {stage.provider!r} (stage '{stage.id}') is registered "
                f"as {registered} but the stage declares {stage.access}"
            )
    return out


def write_stage_violations(contract: Contract, prose_text: str, label: str) -> list[str]:
    """Every mutating stage needs an approval gate, and the gate must be named."""
    out: list[str] = []
    writes = contract.write_stages()
    if not writes:
        out.append(
            "contract declares no write stage; if nothing mutates an external "
            "system the chain cannot disposition a reported message"
        )
    for stage in writes:
        if not stage.approval_required:
            out.append(
                f"write stage '{stage.id}' does not declare approval_required: true"
            )
        language = (stage.approval_language or "").strip()
        if not language:
            out.append(f"write stage '{stage.id}' declares no approval_language")
        elif language not in prose_text:
            out.append(
                f"write stage '{stage.id}' approval language {language!r} is "
                f"absent from {label}"
            )
    return out


def collect(
    contract_path: Path = CONTRACT_PATH,
    readme_text: str | None = None,
    readme_label: str = "README.md",
    skill_text: str | None = None,
    skill_label: str = "SKILL.md",
) -> tuple[Contract | None, list[str], list[str]]:
    """Run every check. Returns ``(contract, violations, notes)``.

    Text parameters make the drift tests possible without touching the working
    tree: a mutated contract or a scrubbed README is passed in, and the real
    files stay untouched.
    """
    notes: list[str] = []
    try:
        contract = load_contract(contract_path)
    except ContractError as exc:
        return None, [f"{contract_path.name}: contract does not parse: {exc}"], []

    violations = validate_contract(contract)
    violations += provider_violations(contract)

    text = readme_text if readme_text is not None else README_PATH.read_text(
        encoding="utf-8"
    )
    violations += document_violations(contract, text, readme_label)
    violations += write_stage_violations(contract, text, readme_label)

    if skill_text is not None:
        violations += document_violations(contract, skill_text, skill_label)
    elif SKILL_PATH.is_file():
        violations += document_violations(
            contract, SKILL_PATH.read_text(encoding="utf-8"), skill_label
        )
    else:
        notes.append(
            f"{skill_label} is not present (it is written by Bundle F); its "
            f"stage-list check is skipped, not passed"
        )
    return contract, violations, notes


def main(argv: list[str] | None = None) -> int:
    """Validate, report, and return the exit code.

    ``argv`` is the argument list *after* the program name, so the tests can
    drive it directly. With no arguments the repository's own ``stages.yaml`` is
    checked.
    """
    args = list(argv or [])
    contract_path = Path(args[0]) if args else CONTRACT_PATH

    contract, violations, notes = collect(contract_path)
    for note in notes:
        print(f"note: {note}")

    if violations:
        print(f"contract FAILED: {len(violations)} violation(s) in "
              f"{contract_path.name}")
        for i, v in enumerate(violations, 1):
            print(f"  {i}. {v}")
        return 1

    providers = {s.provider for s in contract.stages}
    print(f"contract OK: {contract_summary(contract)}")
    print(
        f"  {len(providers)} provider(s) named by the chain, all present in the "
        f"component registry ({len(COMPONENT_REGISTRY)} registered); "
        f"README.md stage list matches stages.yaml in order and title"
    )
    if SKILL_PATH.is_file():
        print("  SKILL.md stage list matches stages.yaml in order and title")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
