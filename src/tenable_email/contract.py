"""The stage contract: a machine-readable definition of the triage chain.

Following the SWARM Black Hat 1st-place playbook, the chain is not described
only in prose. It is declared once in ``stages.yaml`` and everything else --
README, skill text, the code that runs the stages -- is validated against that
declaration. Prose that is merely *trusted* to stay in sync drifts; prose that
is checked cannot.

Two things this module deliberately does not do:

* **It does not depend on a YAML library.** The contract uses a small, fixed
  subset of YAML -- a top-level scalar, one list, and scalar or null values per
  item -- so the shipped core stays dependency-free. ``tests/test_contract.py``
  parses ``stages.yaml`` with both this parser and PyYAML and asserts the two
  agree field for field, which is how the minimal parser is verified without
  shipping a dependency.
* **It does not ignore what it does not understand.** Unknown keys, wrong types
  and structural surprises raise :class:`ContractError` instead of being
  skipped. A silently dropped field is a contract that reads one way and runs
  another.

Providers are named by *capability*, not by product, so a different scanner,
mail transport or inference host can be substituted without editing the chain.
:meth:`COMPONENT_REGISTRY` is where each provider is declared and classified
read-only or write; the validator refuses a stage whose declared access
disagrees with its provider's classification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: The contract shape this module understands.
CONTRACT_VERSION = 1

#: ``stages.yaml`` lives at the repository root, two directories above this file.
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT_PATH = REPO_ROOT / "stages.yaml"

#: Legal values for :attr:`Stage.access`.
ACCESS_VALUES = frozenset({"read-only", "write"})

#: Legal values for :attr:`Stage.model_tier``. A tier names a class of model, not
#: a product, so the endpoint behind it stays swappable.
MODEL_TIERS = frozenset({"classifier", "llm", "vlm"})

_KEBAB = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


class ContractError(ValueError):
    """Raised when a stage contract cannot be parsed or is structurally invalid."""


@dataclass(frozen=True)
class Stage:
    """One stage of the chain, exactly as declared in ``stages.yaml``.

    The field names are the YAML keys; a parsed stage compares equal to a
    constructed one, which is what makes the PyYAML cross-check possible.
    """

    id: str
    title: str
    capability: str
    provider: str
    access: str
    optional: bool = False
    model_tier: str | None = None
    approval_required: bool = False
    approval_language: str | None = None
    description: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "capability": self.capability,
            "provider": self.provider,
            "access": self.access,
            "optional": self.optional,
            "model_tier": self.model_tier,
            "approval_required": self.approval_required,
            "approval_language": self.approval_language,
            "description": self.description,
        }


#: The YAML keys a stage may declare. Anything else is rejected, not ignored.
STAGE_KEYS: tuple[str, ...] = tuple(Stage.__annotations__)

#: Keys that must be present and non-empty in every stage item.
REQUIRED_STAGE_KEYS = ("id", "title", "capability", "provider", "access")

#: Bool-typed keys, checked at parse time so ``approval_required: "yes"`` cannot
#: quietly become true-by-presence or false-by-accident.
_BOOL_KEYS = ("optional", "approval_required")
_STR_KEYS = ("id", "title", "capability", "provider", "access", "description")
_TIER_KEYS = ("model_tier", "approval_language")


@dataclass
class Contract:
    """The parsed chain definition."""

    version: int = CONTRACT_VERSION
    stages: list[Stage] = field(default_factory=list)

    def ids(self) -> list[str]:
        return [s.id for s in self.stages]

    def titles(self) -> list[str]:
        return [s.title for s in self.stages]

    def write_stages(self) -> list[Stage]:
        """The stages that mutate something outside the system."""
        return [s for s in self.stages if s.access == "write"]

    def stage(self, stage_id: str) -> Stage:
        """Look one stage up by id. Raises :class:`KeyError` if absent."""
        for s in self.stages:
            if s.id == stage_id:
                return s
        raise KeyError(f"no stage with id {stage_id!r}; ids are {self.ids()}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "stages": [s.as_dict() for s in self.stages],
        }


#: Every provider a stage may name, with the module that owns it and whether it
#: reads or writes. An access change here is a contract change: a provider
#: registered ``write`` cannot be used by a stage that claims to be read-only.
#:
#: ``tenable_email.tiers``, ``tenable_email.attachments`` and
#: ``tenable_email.writeback`` are the components the later bundles land; the
#: registry declares them now so the contract is complete and the validator has
#: something to check against. The writeback destination is an open decision, so
#: its provider is a placeholder by design and stays ``optional: true``.
COMPONENT_REGISTRY: dict[str, tuple[str, str]] = {
    "eml_directory": ("tenable_email.parse", "read-only"),
    "header_auth_parser": ("tenable_email.signals", "read-only"),
    "deterministic_signals": ("tenable_email.signals", "read-only"),
    "onnx_classifier": ("tenable_email.tiers", "read-only"),
    "local_vlm": ("tenable_email.tiers", "read-only"),
    "attachment_structure_inspector": ("tenable_email.attachments", "read-only"),
    "deterministic_adjudication": ("tenable_email.pipeline", "read-only"),
    "case_record_writeback": ("tenable_email.writeback", "write"),
}


def registry_access(provider: str) -> str | None:
    """The access classification registered for ``provider``, or ``None``."""
    entry = COMPONENT_REGISTRY.get(provider)
    return entry[1] if entry else None


# --------------------------------------------------------------------------
# minimal parser for the subset stages.yaml uses
# --------------------------------------------------------------------------


def _strip_comment(line: str) -> str:
    """Drop a ``#`` block comment, honouring quoted values.

    A ``#`` is only a comment at the start of a line or after whitespace, which
    keeps a value like ``sha256#1`` intact while ignoring prose comments.
    """
    out: list[str] = []
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out)


def _scalar(raw: str) -> Any:
    """Convert one YAML scalar in the subset we allow."""
    s = raw.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    low = s.lower()
    if low in ("null", "~", ""):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"[-+]?\d+", s):
        return int(s)
    if re.fullmatch(r"[-+]?(?:\d+\.\d*|\.\d+|\d+(?:\.\d*)?[eE][-+]?\d+)", s):
        return float(s)
    return s


def _split_kv(content: str) -> tuple[str, str]:
    """Split ``key: value`` on the first colon.

    Splitting on the *first* colon is what lets a description read like normal
    English, colons and all.
    """
    key, sep, value = content.partition(":")
    if not sep:
        raise ContractError(f"expected 'key: value', got {content!r}")
    return key.strip(), value


def parse_stage_yaml(text: str) -> Contract:
    """Parse the ``stages.yaml`` subset: a version scalar and a list of stages.

    Raises :class:`ContractError` on anything outside the subset -- tabs,
    unexpected indentation, nested mappings, flow lists, unknown keys, a
    non-boolean where a boolean belongs, a missing required key, or a document
    with no ``version``.
    """
    version: int | None = None
    stages: list[Stage] = []
    current: dict[str, Any] | None = None
    in_stages = False

    def flush() -> None:
        nonlocal current
        if current is not None:
            stages.append(_build_stage(current, len(stages) + 1))
            current = None

    for lineno, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith("\t") or "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ContractError(f"line {lineno}: tabs are not indentation in this subset")
        line = _strip_comment(raw)
        if not line.strip():
            continue
        content = line.strip()
        indent = len(line) - len(content)

        try:
            if indent == 0:
                key, value = _split_kv(content)
                if current is not None:
                    flush()
                if key == "version":
                    if in_stages:
                        raise ContractError(
                            f"line {lineno}: 'version' must precede 'stages'"
                        )
                    scalar = _scalar(value)
                    if not isinstance(scalar, int) or isinstance(scalar, bool):
                        raise ContractError(
                            f"line {lineno}: version must be an integer, got {scalar!r}"
                        )
                    version = scalar
                elif key == "stages":
                    in_stages = True
                    if value.strip():
                        raise ContractError(
                            f"line {lineno}: 'stages:' must be followed by a block "
                            f"list, got inline value {value.strip()!r}"
                        )
                else:
                    raise ContractError(
                        f"line {lineno}: unknown top-level key {key!r}; only "
                        f"'version' and 'stages' are allowed"
                    )
                continue

            if not in_stages:
                raise ContractError(
                    f"line {lineno}: content before the 'stages:' key is not allowed"
                )
            if content == "-":
                raise ContractError(f"line {lineno}: empty list item")
            if content.startswith("- "):
                if current is not None:
                    flush()
                current = {}
                key, value = _split_kv(content[2:].strip())
                current[key] = _scalar(value)
                continue
            if current is None:
                raise ContractError(
                    f"line {lineno}: stage field {content.split(':')[0]!r} before "
                    f"any '- ' list item"
                )
            key, value = _split_kv(content)
            if key in current:
                raise ContractError(f"line {lineno}: duplicate key {key!r} in a stage")
            current[key] = _scalar(value)
        except ContractError as exc:
            raise ContractError(f"{exc} (line {lineno})") from None

    flush()

    if version is None:
        raise ContractError("contract has no top-level 'version'")
    if version != CONTRACT_VERSION:
        raise ContractError(
            f"unsupported contract version {version}; this build understands "
            f"version {CONTRACT_VERSION}"
        )
    return Contract(version=version, stages=stages)


def _build_stage(item: dict[str, Any], position: int) -> Stage:
    """Type-check one parsed mapping into a :class:`Stage`."""
    where = f"stage {position}"
    unknown = [k for k in item if k not in STAGE_KEYS]
    if unknown:
        raise ContractError(
            f"{where}: unknown key(s) {unknown}; allowed keys are "
            f"{sorted(STAGE_KEYS)}"
        )
    missing = [k for k in REQUIRED_STAGE_KEYS if k not in item]
    if missing:
        raise ContractError(f"{where}: missing required key(s) {missing}")

    for key in _STR_KEYS:
        if key in item and not isinstance(item[key], str):
            raise ContractError(
                f"{where}: {key!r} must be a string, got {item[key]!r}"
            )
    for key in _BOOL_KEYS:
        if key in item and not isinstance(item[key], bool):
            raise ContractError(
                f"{where}: {key!r} must be true or false, got {item[key]!r}"
            )
    for key in _TIER_KEYS:
        if key in item and item[key] is not None and not isinstance(item[key], str):
            raise ContractError(
                f"{where}: {key!r} must be a string or null, got {item[key]!r}"
            )
    return Stage(
        id=item["id"],
        title=item["title"],
        capability=item["capability"],
        provider=item["provider"],
        access=item["access"],
        optional=item.get("optional", False),
        model_tier=item.get("model_tier"),
        approval_required=item.get("approval_required", False),
        approval_language=item.get("approval_language"),
        description=item.get("description", "") or "",
    )


def load_contract(path: str | Path | None = None) -> Contract:
    """Read and parse a contract. Does not validate -- call
    :func:`validate_contract` for that, so a caller can report every violation
    at once instead of stopping at the first."""
    p = Path(path) if path is not None else DEFAULT_CONTRACT_PATH
    if not p.is_file():
        raise ContractError(f"contract file not found: {p}")
    return parse_stage_yaml(p.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------


def validate_contract(contract: Contract) -> list[str]:
    """Return every contract violation, as human-readable sentences.

    Validation is total rather than failing at the first problem: a reviewer
    fixing a contract wants the whole list. These are the rules that give the
    chain its meaning:

    * ids are unique and kebab-case, because they are what the runner, the
      receipts and the MCP tool names refer to;
    * a ``write`` stage must declare ``approval_required: true`` and carry
      approval language, because no mutation may happen without a human;
    * a ``write`` stage must not name a model tier -- the stage that mutates the
      outside world must not also be the stage that interprets the message, so a
      bad model reading cannot reach an outbound call by itself;
    * every provider exists in :data:`COMPONENT_REGISTRY`, and the access the
      stage claims must match the access the registry declares for it, so
      "read-only" cannot be asserted by the component that writes.
    """
    violations: list[str] = []

    if not contract.stages:
        violations.append("contract declares no stages")
    if contract.version != CONTRACT_VERSION:
        violations.append(
            f"unsupported contract version {contract.version}; expected "
            f"{CONTRACT_VERSION}"
        )

    seen: set[str] = set()
    for position, stage in enumerate(contract.stages, 1):
        where = f"stage {position} ({stage.id or 'no id'}): "

        if not stage.id.strip():
            violations.append(f"{where}id is empty")
        elif stage.id in seen:
            violations.append(f"{where}duplicate stage id {stage.id!r}")
        seen.add(stage.id)

        if stage.id and not _KEBAB.match(stage.id):
            violations.append(
                f"{where}id {stage.id!r} is not kebab-case "
                f"(lowercase words joined by single hyphens)"
            )
        if not stage.title.strip():
            violations.append(f"{where}title is empty")
        if not stage.capability.strip():
            violations.append(f"{where}capability is empty")
        if not stage.description.strip():
            violations.append(f"{where}description is empty")

        if stage.access not in ACCESS_VALUES:
            violations.append(
                f"{where}access {stage.access!r} must be one of "
                f"{sorted(ACCESS_VALUES)}"
            )
        if stage.model_tier is not None and stage.model_tier not in MODEL_TIERS:
            violations.append(
                f"{where}unknown model_tier {stage.model_tier!r}; allowed tiers "
                f"are {sorted(MODEL_TIERS)} or null"
            )
        if stage.access == "write" and stage.model_tier is not None:
            violations.append(
                f"{where}a write stage must not call a model itself "
                f"(model_tier {stage.model_tier!r}); put the model call in a "
                f"read-only stage and gate the mutation behind approval"
            )
        if stage.access == "write" and not stage.approval_required:
            violations.append(
                f"{where}access is 'write' but approval_required is not true; "
                f"every external mutation needs a human checkpoint"
            )
        if stage.approval_required and not (stage.approval_language or "").strip():
            violations.append(
                f"{where}approval_required is true but approval_language is "
                f"empty or missing; the contract must carry the words the "
                f"operator has to agree to"
            )

        if stage.provider not in COMPONENT_REGISTRY:
            violations.append(
                f"{where}provider {stage.provider!r} is not in COMPONENT_REGISTRY"
            )
        else:
            module_path, registered = COMPONENT_REGISTRY[stage.provider]
            if registered != stage.access:
                violations.append(
                    f"{where}provider {stage.provider!r} is registered as "
                    f"{registered} but the stage declares access "
                    f"{stage.access!r}"
                )
            if not module_path:
                violations.append(f"{where}provider {stage.provider!r} has no module path")

    return violations


def contract_summary(contract: Contract) -> str:
    """One-line description of a valid contract, for tool output."""
    writes = contract.write_stages()
    gates = [s for s in contract.stages if s.approval_required]
    return (
        f"{len(contract.stages)} stages, {len(writes)} write stage"
        f"{'' if len(writes) == 1 else 's'}, "
        f"{len(gates)} approval gate{'' if len(gates) == 1 else 's'}"
    )
