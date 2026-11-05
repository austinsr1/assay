"""Optional deep attachment analysis, through a local ``rea`` subprocess.

This is the component :mod:`~tenable_email.contract` reserves as
``attachment_structure_inspector -> tenable_email.attachments, read-only`` and
``stages.yaml`` declares as the ``attachment-content`` stage with capability
``attachment_structure_inspection``. Both names say what it delivers, which the
names this slot carried before did not: the analyzer reports artifact
*structure* -- container entries, sizes, digests, the declared format, its own
coverage and limitations -- and no document text is extracted from anything.
Before it, the engine inventoried an attachment
-- filename, MIME type, size, sha256, ``truncated`` -- and stopped. Inventory is
a fact about the MIME tree; the contents stayed an explicit unknown, and
``docs/PARITY.md`` records that as the genuine capability gap against the
reference playbook.

It is **optional in the strong sense**. Nothing here runs unless an operator
switches it on: the upstream tool is a Node.js CLI with a heavy install and an
engine floor this project does not meet, so the shipped default
(:attr:`tenable_email.config.Config.deep_attachment_analysis`) is ``False``, no
subprocess is spawned, no finding is added, and every measured number in this
repository is unaffected by the existence of this file. See the README's
optional-workflow section for how to turn it on and why it is not for everyone.

Nine rules, each of them tested.

1. **Not a :class:`~tenable_email.tiers.Tier`.** ``Tier`` is built around
   ``endpoint_field``/``url``/``headers``/``api_key_field``: a request/response
   pair over HTTP. This is a local subprocess with no address, so registering it
   as a tier would put a lie in the configuration model. The *result* vocabulary
   is mirrored from :class:`~tenable_email.tiers.TierResult` -- ``available``,
   ``ok``, ``raw``, ``error``, ``source``, ``latency_ms`` -- so a reader who
   knows one recognizes the other.
2. **Failure is a value, never an exception.** Every way this can fail to answer
   returns an :class:`AttachmentResult` with ``ok=False`` and one of
   :data:`ABSTENTION_REASONS`. Raising would turn "the analyzer said nothing"
   into "the message could not be triaged", and would lose the reason, which is
   the only useful part of the answer.
3. **A gate that cannot be read closes.** An unreadable ``capabilities``
   declaration, an operation REA does not declare, output that is not JSON: each
   abstains. Nothing here degrades to "probably fine".
4. **Digest binding.** REA reports ``subject.digest.sha256`` for the file it was
   handed and ``normalized_result.subject.root_sha256`` for the root of the
   artifact graph it analysed. Both must equal the digest this project computed
   itself, or the response is discarded with ``digest_mismatch``. Without that,
   a result could describe different bytes than the ones in this message -- the
   same principle that binds an approval token to a verdict digest.
5. **The safety gate is an intersection.** REA's ``capabilities`` output
   self-declares each operation's side effects; this module holds its own
   hardcoded allowlist. An operation runs only if **both** permit it, so neither
   a REA version change nor an edit here can silently widen what executes. Four
   command families -- ``capture-*``, ``debug-*``, ``*-adb-*``,
   ``analyze-web-bundle`` -- are refused by name whatever they declare, because
   "declares no network" is not the same as "cannot reach one".
6. **The ``available`` flag in ``capabilities`` is not a readiness signal** and
   is not used for policy. Measured on the build host: it reports the ghidra and
   hopper groups available while ``rea inspect`` rejects both as
   ``not_configured``. Policy reads ``effects`` only; a provider that turns out
   to be unusable at run time abstains with ``provider_unavailable``.
7. **Quarantine, with ownership.** Payload bytes are written under a private
   directory created by :func:`tempfile.mkdtemp`, outside the repository and
   outside the working directory, mode 0o700 on the directory and 0o600 on the
   file, named from the digest -- never from the attachment's filename, which is
   attacker-chosen and in one of this repository's fixtures is a path traversal.
   The directory is removed on every path, answer or abstention. If removal
   **fails** the path is reported in the result and in the record: a file nobody
   can find is a file nobody can clean up, and this project's rule is that a
   failed cleanup is stated rather than swallowed.
8. **No bytes and no paths out.** A response is projected through a whitelist
   before it becomes a finding. ``subject.local_path``, ``caller_input_path``,
   ``parameters.input_path`` and the error envelope's ``details`` -- measured on
   this host to carry absolute toolchain paths -- are excluded by construction
   rather than by subtraction, so a field REA adds in a later version cannot
   ride out on a whitelist it was not added to. ``Attachment.data`` never leaves
   the quarantine directory: :meth:`~tenable_email.parse.Attachment.without_data`
   stays the only attachment form that reaches serialization.
9. **Never a vote.** Findings go into the evidence record; no fact the
   adjudication consumes is derived from them, and the rule that a high-risk
   attachment blocks an automatic clearance (``pipeline._Facts.
   dangerous_unexamined``) is deliberately untouched. REA's own limitation says
   why: *"Inspection derives bounded static hypotheses and next probes; it does
   not execute the artifact."* A static read of a container is not a statement
   that its contents are safe, so it cannot make a message cleaner -- it can
   only tell an analyst what is inside.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Mapping, Sequence

from .config import Config
from .evidence import Evidence, Finding, Provenance
from .parse import Attachment, Message

__all__ = [
    "ABSTENTION_REASONS",
    "COMPONENT",
    "DEFAULT_OPERATION",
    "DEFAULT_TIMEOUT_SECONDS",
    "FINDING_KEY",
    "HYPOTHESIS_KEY",
    "PROVIDER",
    "QUARANTINE_KEY",
    "REFUSAL_EFFECTS",
    "REFUSAL_OPERATION_PATTERNS",
    "RETAINED_QUARANTINE_PATHS",
    "SAFE_OPERATIONS",
    "STAGE",
    "AttachmentResult",
    "allowed_operations",
    "analyze_attachment",
    "analyze_message",
    "capabilities",
    "canonical",
    "create_quarantine",
    "digests_match",
    "findings_for",
    "operation_command",
    "operation_permitted",
    "project_analysis",
    "rea_executable",
    "record_findings",
    "remove_quarantine",
    "reset_capabilities_cache",
    "retained_quarantine_paths",
    "run_for_message",
    "sanitize_extension",
    "stage_payload",
    "staged_name",
]

#: The provider name in ``COMPONENT_REGISTRY``.
PROVIDER = "attachment_structure_inspector"

#: The component label, and the finding ``source``. Same string as the
#: ``attachment-content`` stage id in ``stages.yaml``; it is written as a literal
#: rather than imported from :mod:`tenable_email.pipeline`, which imports this
#: module, so there is exactly one direction of dependency here. ``tests/
#: test_attachments.py`` asserts it equals the contract's stage id.
COMPONENT = PROVIDER
STAGE = "attachment-content"

#: The evidence key this component writes, one finding per attachment it was
#: given. Public because :mod:`tenable_email.pipeline` asks whether the stage ran
#: by looking for it in the record, rather than threading a result through three
#: signatures or -- worse -- running the analyzer a second time to find out.
FINDING_KEY = "attachment_deep_analysis"

#: The second key, used only when the analyzer offered hypotheses or pointed out
#: contradictions. Separate from :data:`FINDING_KEY` because it carries a
#: different provenance, and one finding cannot hold two.
HYPOTHESIS_KEY = "attachment_deep_analysis_hypotheses"

#: Written when a quarantine directory survived cleanup.
QUARANTINE_KEY = "attachment_quarantine_retained"

#: The CLI this component shells out to. An operator may pin an absolute path
#: through ``Config.attachment_analysis_command``, which is the difference
#: between "some program named rea" and "this program".
REA_COMMAND = "rea"

#: The operation asked for by default. ``inspect_artifact`` is REA's static
#: container-and-format inventory, and the one operation measured to work on this
#: host with nothing installed beyond REA itself.
DEFAULT_OPERATION = "inspect_artifact"

#: Wall-clock budget for one analysis. Well above the ~1-2 s a benign archive
#: took when measured: this is a hang guard, not a latency target, and a hung
#: child would otherwise stall a whole batch run.
DEFAULT_TIMEOUT_SECONDS = 20.0

#: The capabilities query gets its own, shorter budget. It reads a static
#: declaration; it must never be the thing that times out an attachment.
CAPABILITY_TIMEOUT_SECONDS = 10.0

#: Operations this build is willing to run, whatever REA declares. Hardcoded on
#: purpose: this is the half of the intersection a dependency update cannot
#: move. Each name was checked against ``rea capabilities --json`` for its
#: declared effects and against ``rea --help`` for the dashed CLI command.
SAFE_OPERATIONS = frozenset(
    {
        "inspect_artifact",
        "extract_artifact",
        "inspect_keyed_archive",
        "inspect_managed_artifact",
        "inspect_managed_members",
        "inspect_managed_native_boundaries",
    }
)

#: Side effects that disqualify an operation, read from REA's own declaration.
#: ``launches_process`` and ``may_write_filesystem`` are deliberately **not**
#: here: this component is itself a launched process that writes a temp file, and
#: refusing those would refuse every operation REA has. Network egress, a window
#: on a screen and mutating the artifact under analysis are the three that change
#: what this is allowed to be: a static read that cannot phone home, cannot
#: interact, and cannot touch the bytes it is judging.
REFUSAL_EFFECTS = frozenset({"may_access_network", "may_show_ui", "mutates_artifact"})

#: Command families refused by name, whatever they declare. Matched against a
#: canonical spelling in which ``_`` and ``-`` are the same character, so
#: ``capture_native_ui_scenario`` -- the form REA declares -- is caught by
#: ``capture-*``. A gate that read only one of the two spellings would be a gate
#: with a separator hole in it.
REFUSAL_OPERATION_PATTERNS = (
    "capture-*",
    "debug-*",
    "*-adb-*",
    "analyze-web-bundle",
)

#: Every reason this component can abstain, and the only values ``error`` holds.
#: An analyst reads these, a log groups by them, and the pipeline records the one
#: it got rather than a generic failure.
ABSTENTION_REASONS = (
    "rea_not_installed",
    "rea_timeout",
    "rea_unparsable",
    "digest_mismatch",
    "provider_unavailable",
    "capability_unavailable",
    "disallowed_operation",
    "quarantine_failed",
    "attachment_not_retained",
)

#: Bounds on what is copied out of a response. Entry names and limitation text
#: come from an analyzer reading attacker-chosen bytes, so they are length-
#: limited before they reach a record that a human and a model both read.
MAX_ENTRIES = 24
MAX_LIMITATIONS = 8
MAX_SUBSTEPS = 12
MAX_TEXT_CHARS = 200
MAX_NAME_CHARS = 120

#: Environment the child process gets: an allowlist, not a handover. A
#: deployment's environment holds every configured model API key, and a
#: third-party artifact analyzer has no reason to read them.
_CHILD_ENV_KEYS = ("PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "TZ")

#: The repository root, used only to refuse a quarantine directory inside the
#: source tree. ``src/tenable_email/attachments.py`` -> two levels up.
REPO_ROOT = os.path.realpath(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

_KEEP_IN_EXTENSION = re.compile(r"[a-z0-9]")
_HEXDIGEST = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------
# names, spelling, availability
# --------------------------------------------------------------------------


def canonical(name: str) -> str:
    """One spelling for an operation or command name, for gate comparisons.

    Lowercase, with ``_`` folded onto ``-``. REA declares ``inspect_artifact``
    and names the command ``inspect-artifact``; the two are the same thing to it,
    so they must be the same thing to the denylist as well.
    """
    return (name or "").strip().lower().replace("_", "-")


SAFE_CANONICAL = frozenset(canonical(op) for op in SAFE_OPERATIONS)

#: :data:`REFUSAL_EFFECTS` in the spelling the gate compares in. Effects are
#: canonicalized on both sides, so an effect REA spells ``may-access-network`` is
#: refused as reliably as ``may_access_network``; the verbatim declaration is what
#: gets printed, because a report should quote the tool rather than its own
#: translation of it.
REFUSAL_EFFECTS_CANONICAL = frozenset(canonical(e) for e in REFUSAL_EFFECTS)


def operation_command(operation: str) -> str:
    """The CLI subcommand for an operation name (``inspect_artifact`` ->
    ``inspect-artifact``), which is how REA names them; verified for all six
    allowlisted operations against ``rea --help``."""
    return canonical(operation)


def rea_executable(command: str = REA_COMMAND) -> str | None:
    """The resolved path of the ``rea`` binary, or ``None`` when there is none.

    The answer to "is this installed at all" -- and the reason a host without
    Node.js, or without REA on a host that has it, runs the identical pipeline to
    the one every test here already runs.
    """
    return shutil.which(command)


def sanitize_extension(filename: str, content_type: str = "") -> str:
    """A safe, bounded extension to stage a payload under, else ``.bin``.

    The extension is the only part of a sender-chosen filename that survives,
    and only after two steps: take the final path component (a
    ``Content-Disposition`` filename is not a filesystem path, and treating
    ``a.zip/../../x`` as having no extension is the honest reading), then filter
    to alphanumerics and cap at 12 characters. So ``invoice.zip`` stages as
    ``.zip`` -- which is what lets a format-detecting analyzer see what it is
    looking at -- while ``weird.zip; rm -rf /`` contributes nothing dangerous.
    An empty or wholly filtered result falls back to the MIME subtype and then to
    ``.bin``.
    """
    name = (filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    raw = os.path.splitext(name)[1].lower()
    cleaned = "".join(_KEEP_IN_EXTENSION.findall(raw))[:12]
    if cleaned:
        return f".{cleaned}"
    subtype = (content_type or "").split("/")[-1].strip().lower()
    cleaned = "".join(_KEEP_IN_EXTENSION.findall(subtype))[:12]
    return f".{cleaned}" if cleaned else ".bin"


def staged_name(attachment: Attachment) -> str:
    """The unique filename a payload is staged under, derived from its digest.

    No part of the sender's filename reaches the path. The fixture
    ``attachment_traversal_filename.eml`` carries ``../../../etc/`` in its
    ``Content-Disposition``, which is the case this function exists for: the
    staged name is ``attachment-<sha256[:32]>.txt`` and the traversal is inert.
    """
    digest = (attachment.sha256 or "unknown")[:32]
    return f"attachment-{digest}{sanitize_extension(attachment.filename, attachment.content_type)}"


# --------------------------------------------------------------------------
# the capability query and the safety gate
# --------------------------------------------------------------------------

#: Parsed declarations, cached per process and per resolved binary: operation ->
#: declared effects. Shelling out per attachment would mean an extra subprocess
#: for every part of every message, and the declaration does not change while we
#: are running.
_CAPABILITY_CACHE: dict[str, dict[str, tuple[str, ...]] | None] = {}

#: Quarantine directories this process failed to remove.
RETAINED_QUARANTINE_PATHS: list[str] = []


def reset_capabilities_cache() -> None:
    """Forget the cached declaration. For tests, and for a long-lived server
    that upgraded REA underneath it."""
    _CAPABILITY_CACHE.clear()


def retained_quarantine_paths() -> tuple[str, ...]:
    """Paths left on disk because cleanup failed. Empty is the expected answer."""
    return tuple(RETAINED_QUARANTINE_PATHS)


def declared_operations(
    command: str = REA_COMMAND, timeout: float | None = None
) -> dict[str, tuple[str, ...]] | None:
    """``operation -> declared effects`` from ``rea capabilities --json``.

    ``None`` means the query could not be made or could not be read. The
    ``available`` boolean REA reports per group is **not** consulted, per rule 6:
    measured on this host it says which provider group would be selected, not
    whether one runs.
    """
    executable = rea_executable(command)
    if executable is None:
        return None
    budget = CAPABILITY_TIMEOUT_SECONDS if timeout is None else float(timeout)
    key = f"{executable}|{budget:g}"
    if key in _CAPABILITY_CACHE:
        return _CAPABILITY_CACHE[key]
    parsed = _invoke([executable, "capabilities", "--json"], budget)
    operations = _read_capabilities(parsed) if isinstance(parsed, dict) else None
    _CAPABILITY_CACHE[key] = operations
    return operations


def _read_capabilities(payload: Mapping[str, Any]) -> dict[str, tuple[str, ...]] | None:
    """Flatten REA's provider/group declaration into operation -> effects.

    Shape measured against a real ``rea capabilities --json`` response:
    ``{"capabilities": [{"provider": {"id", "name", "version"},
    "shared_limitations": [...], "groups": [{"operations": [...], "effects":
    [...], "limitations": [...], "available": bool, "reason": str,
    "availability_code": str|null}]}]}``.

    A group that does not declare both ``operations`` and ``effects``, or declares
    either as something other than a list, fails the whole reading rather than
    contributing a partial map: a half-parsed safety declaration would widen the
    gate, which is the one outcome worse than closing it.
    """
    entries = payload.get("capabilities")
    if not isinstance(entries, list):
        return None
    out: dict[str, tuple[str, ...]] = {}
    for provider in entries:
        if not isinstance(provider, Mapping):
            return None
        groups = provider.get("groups")
        if groups is None:
            continue
        if not isinstance(groups, list):
            return None
        for group in groups:
            if not isinstance(group, Mapping):
                return None
            names = group.get("operations")
            effects = group.get("effects")
            if not isinstance(names, list) or not isinstance(effects, list):
                return None
            if not all(isinstance(effect, str) for effect in effects):
                return None
            for name in names:
                if not isinstance(name, str):
                    return None
                out[canonical(name)] = tuple(
                    str(effect).strip() for effect in effects if str(effect).strip()
                )
    return out


def _refused_effects(effects: Iterable[str]) -> list[str]:
    """The declared effects that disqualify an operation, in REA's own spelling."""
    return sorted(
        {effect for effect in effects if canonical(effect) in REFUSAL_EFFECTS_CANONICAL}
    )


def allowed_operations(
    command: str = REA_COMMAND, timeout: float | None = None
) -> frozenset[str] | None:
    """The intersection: REA declares these free of disqualifying effects,
    **and** this build names them, **and** they are not in a refused family.

    ``None`` when the declaration could not be read -- deliberately not an empty
    set, so a caller can tell "nothing is permitted" from "we cannot tell" and
    record the right reason.

    The family denylist is applied here as well as in :func:`operation_permitted`,
    because this function is the answer to "what may run", and a list that an
    edit to the allowlist could add ``capture-*`` to would be a list that lies.
    """
    declared = declared_operations(command, timeout)
    if declared is None:
        return None
    return frozenset(
        name
        for name, effects in declared.items()
        if name in SAFE_CANONICAL
        and not _refused_effects(effects)
        and not any(_matches(name, pattern) for pattern in REFUSAL_OPERATION_PATTERNS)
    )


def operation_permitted(
    operation: str,
    command: str = REA_COMMAND,
    timeout: float | None = None,
) -> tuple[bool, str, str]:
    """Whether one operation may be invoked, plus the reason when it may not.

    The order is the point. The name denylist is consulted **first**, so a
    ``capture-*`` command whose declared effects look benign is refused before
    its effects are ever weighed. Then our own allowlist, then REA's declaration,
    then the intersection of the two.
    """
    name = canonical(operation)
    denied = [pattern for pattern in REFUSAL_OPERATION_PATTERNS if _matches(name, pattern)]
    if denied:
        return False, "disallowed_operation", (
            f"{operation} is in the refused command families ({', '.join(denied)}); "
            "this build never invokes it, whatever side effects it declares"
        )
    if name not in SAFE_CANONICAL:
        return False, "disallowed_operation", (
            f"{operation} is not in this build's hardcoded allowlist "
            f"({', '.join(sorted(SAFE_OPERATIONS))})"
        )
    declared = declared_operations(command, timeout)
    if declared is None:
        return False, "capability_unavailable", (
            "rea capabilities could not be read, so the side effects of "
            f"{operation} are unverified and it is not run"
        )
    if name not in declared:
        return False, "capability_unavailable", (
            f"this REA build does not declare {operation} in its capabilities "
            "output, so it is not part of the permitted intersection"
        )
    refused = _refused_effects(declared[name])
    if refused:
        return False, "disallowed_operation", (
            f"rea declares {operation} with {', '.join(refused)}, which this build "
            "refuses to run"
        )
    return True, "", ""


def _matches(name: str, pattern: str) -> bool:
    """Match one denylist pattern against a canonical command name."""
    if pattern.startswith("*") and pattern.endswith("*"):
        return pattern.strip("*") in name
    if pattern.startswith("*"):
        return name.endswith(pattern.lstrip("*"))
    if pattern.endswith("*"):
        return name.startswith(pattern.rstrip("*"))
    return name == pattern


def capabilities(command: str = REA_COMMAND, timeout: float | None = None) -> dict:
    """The gate as an operator can read it: what is permitted, and on what basis.

    A safety gate whose decisions cannot be listed cannot be reviewed, so this
    reports both halves of the intersection rather than only the result.
    """
    declared = declared_operations(command, timeout)
    permitted = allowed_operations(command, timeout)
    return {
        "component": COMPONENT,
        "provider": PROVIDER,
        "rea_installed": rea_executable(command) is not None,
        "declared_operations": len(declared) if declared is not None else None,
        "permitted_operations": sorted(permitted) if permitted is not None else None,
        "allowlist": sorted(SAFE_OPERATIONS),
        "refused_effects": sorted(REFUSAL_EFFECTS),
        "refused_command_families": list(REFUSAL_OPERATION_PATTERNS),
        "note": (
            "permitted is the intersection of REA's declared side effects and this "
            "build's allowlist; the `available` flag in capabilities is not "
            "consulted, and an unreadable declaration permits nothing"
        ),
    }


# --------------------------------------------------------------------------
# the quarantine directory
# --------------------------------------------------------------------------


class QuarantineError(RuntimeError):
    """A payload could not be staged safely. Never escapes
    :func:`analyze_attachment`, which converts it to ``quarantine_failed``."""


def create_quarantine() -> str:
    """A private directory to stage one payload in.

    ``tempfile.mkdtemp`` creates it atomically with 0o700 -- there is no window
    between create and chmod for another user to open it -- and the mode is
    asserted rather than assumed. The payload file inside is 0o600. A directory
    cannot be 0o600: without the search bit the analyzer could not open the file
    within it, so 0o700 is the strictest mode that does the job, and the file
    carries the tighter one.

    Refuses a location inside the repository or inside the working directory. Not
    tidiness: a quarantine under the source tree is a copy of an untrusted
    payload that ``git add -A`` will offer to commit, and this repository
    publishes its history and is scanned before publication.
    """
    path = tempfile.mkdtemp(prefix="tenable-email-rea-")
    os.chmod(path, 0o700)
    resolved = _real(path)
    for forbidden in (REPO_ROOT, _real(os.getcwd())):
        if _inside(resolved, forbidden):
            shutil.rmtree(path, ignore_errors=True)
            raise QuarantineError(
                "the temp directory resolves inside the repository or the current "
                "working directory, where a staged payload must not be written"
            )
    return path


def stage_payload(path: str, attachment: Attachment) -> str:
    """Write the payload owner-only and return the staged file's path.

    The bytes written are hashed again and compared with the digest the parser
    recorded. If they disagree, the staged file is not this attachment, and the
    analysis would be a statement about something else: that is refused here,
    before a subprocess is spawned, rather than discovered afterwards by the
    response digest check.

    Any ``OSError`` -- a read-only or full temp directory, a name collision -- is
    a ``quarantine_failed`` abstention, not a crash, because those are ordinary
    conditions on ordinary hosts.
    """
    target = os.path.join(path, staged_name(attachment))
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:  # a previous run left the same digest behind
        raise QuarantineError(f"the staged name was already taken: {exc}") from None
    except OSError as exc:
        raise QuarantineError(f"the payload could not be written: {exc}") from None
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(attachment.data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise QuarantineError(f"the payload could not be written: {exc}") from None
    written = _hash_file(target)
    if written is None:
        raise QuarantineError("the staged payload could not be read back")
    if written != (attachment.sha256 or "").lower():
        raise QuarantineError(
            "the staged payload does not hash to the digest the parser recorded"
        )
    return target


def remove_quarantine(path: str) -> str | None:
    """Delete a quarantine directory, returning the path when it survives.

    The failure is *returned*, not raised and not logged-and-forgotten: the
    caller attaches it to the result, and a caller that never looks still has the
    answer in ``ok``.
    """
    try:
        shutil.rmtree(path)
    except OSError:
        pass
    return path if os.path.exists(path) else None


def _hash_file(path: str) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def _real(path: Any) -> str:
    try:
        return os.path.realpath(str(path))
    except OSError:  # pragma: no cover - realpath only fails on syscall errors
        return os.path.abspath(str(path))


def _inside(candidate: str, directory: str) -> bool:
    """Whether ``candidate`` is ``directory`` or below it, on path components."""
    if not directory:
        return False
    a, b = _real(candidate), _real(directory)
    return a == b or a.startswith(b.rstrip(os.sep) + os.sep)


# --------------------------------------------------------------------------
# the subprocess
# --------------------------------------------------------------------------


def child_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment the child gets: an allowlist, not a handover.

    ``PATH``, a home, a temp directory and a locale are enough for a Node CLI.
    The alternative -- inheriting -- would hand a third-party analyzer every
    ``TENABLE_EMAIL_*`` value, including a configured model API key, which the
    README's outbound-data-flow list has no business describing as disclosed to
    an external tool.
    """
    source = os.environ if environ is None else environ
    out: dict[str, str] = {}
    for key in _CHILD_ENV_KEYS:
        value = source.get(key)
        if value:
            out[key] = value
    return out


@dataclass(frozen=True)
class _Outcome:
    """One subprocess result, before any policy is applied to it."""

    ok: bool
    reason: str = ""
    detail: str = ""
    payload: Any = None
    exit_code: int | None = None
    latency_ms: float | None = None
    started: bool = False


def _run(argv: Sequence[str], timeout: float) -> _Outcome:
    """Run one command within ``timeout``, keeping the failure class distinct.

    Every branch is a reason an analyst can read: the binary vanished between
    ``which`` and ``exec``, the clock ran out, the process printed something that
    is not JSON, or it printed an error envelope. None of them raises -- that is
    rule 2, and it is why the caller can put an answer or an abstention in the
    same variable.
    """
    started = time.monotonic()
    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            timeout=timeout,
            check=False,
            env=child_env(),
            text=False,
        )
    except FileNotFoundError:
        return _Outcome(
            False,
            reason="rea_not_installed",
            detail="the rea binary was not on PATH when it was invoked",
        )
    except OSError as exc:
        return _Outcome(
            False,
            reason="rea_not_installed",
            detail=f"rea could not be executed: {type(exc).__name__}: {exc}",
        )
    except subprocess.TimeoutExpired:
        return _Outcome(
            False,
            reason="rea_timeout",
            detail=f"rea did not answer within {timeout:g} seconds and was killed",
        )
    elapsed = (time.monotonic() - started) * 1000.0
    stdout = _text(completed.stdout)
    if not stdout.strip():
        return _Outcome(
            False,
            reason="rea_unparsable",
            detail=f"rea printed no JSON on stdout (exit code {completed.returncode})",
            exit_code=completed.returncode,
            latency_ms=elapsed,
            started=True,
        )
    try:
        payload = json.loads(stdout)
    except ValueError as exc:
        return _Outcome(
            False,
            reason="rea_unparsable",
            detail=f"rea printed something that is not JSON: {exc}",
            exit_code=completed.returncode,
            latency_ms=elapsed,
            started=True,
        )
    return _Outcome(
        True,
        payload=payload,
        exit_code=completed.returncode,
        latency_ms=elapsed,
        started=True,
    )


def _invoke(argv: Sequence[str], timeout: float) -> Any:
    """The capability query's narrower view of :func:`_run`: an object or ``None``."""
    outcome = _run(argv, timeout)
    if not outcome.ok or not isinstance(outcome.payload, Mapping):
        return None
    return outcome.payload


def _text(raw: Any) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return raw or ""


#: ``rea`` error-envelope codes mapped onto this component's reasons. Measured
#: shape: ``{"error": "Analysis failed", "code": "provider_unavailable",
#: "category": "unavailable", "message": "...", "retryable": true, "details":
#: {...}}`` on stdout with exit code 1. Two families, both measured on this host:
#: a provider that is not ready (ghidra rejected as ``not_configured``, code
#: ``provider_unavailable``) and a target the artifact graph will not open (code
#: ``target_unavailable``, category ``unsupported_target``, message "Cannot open
#: artifact: unsupported binary format." -- which is what a plain-text attachment
#: gets). The first is ``provider_unavailable`` here and the second
#: ``capability_unavailable``, because an analyst needs to be told whether the
#: machine is missing a tool or the file is the wrong shape for the tool it has.
#: ``details`` is never copied: measured on this host it carried the absolute
#: path of the staged file and, in the ghidra case, absolute toolchain paths.
_ERROR_CODE_REASONS = {
    "provider_unavailable": "provider_unavailable",
    "provider_not_available": "provider_unavailable",
    "not_configured": "provider_unavailable",
    "provider_not_configured": "provider_unavailable",
    "capability_unavailable": "capability_unavailable",
    "target_unavailable": "capability_unavailable",
    "unsupported_target": "capability_unavailable",
    "unsupported_format": "capability_unavailable",
    "operation_not_supported": "capability_unavailable",
    "timeout": "rea_timeout",
    "etimedout": "rea_timeout",
    "enoent": "rea_not_installed",
    "rea_not_installed": "rea_not_installed",
}

#: Categories mapped when a response carries no recognised code.
_CATEGORY_REASONS = {
    "unavailable": "provider_unavailable",
    "unsupported_target": "capability_unavailable",
    "not_supported": "capability_unavailable",
}


def _classify_envelope(payload: Mapping[str, Any]) -> tuple[str, str]:
    """Read REA's own error envelope into a reason and a sentence.

    Only ``code``, ``category``, ``message``/``error`` and ``retryable`` are
    read. ``details`` is not copied: measured on this host it carried absolute
    toolchain paths (``java_command``, ``java_home``) from the machine doing the
    analysis, which is infrastructure detail and not a finding about a message.
    """
    code = str(payload.get("code") or "").strip().lower()
    category = str(payload.get("category") or "").strip().lower()
    message = _bounded(str(payload.get("message") or payload.get("error") or ""))
    reason = _ERROR_CODE_REASONS.get(code) or _CATEGORY_REASONS.get(category)
    if reason is None:
        # An error envelope means REA could not produce an analysis. Mapping an
        # unrecognised code to provider_unavailable says exactly that;
        # rea_unparsable stays reserved for output that could not be read at all.
        reason = "provider_unavailable"
    detail = f"rea reported {code or category or 'an unspecified error'}"
    if category == "unavailable":
        detail += " (category unavailable)"
    if message:
        detail = f"{detail}: {message}"
    return reason, detail


# --------------------------------------------------------------------------
# digest binding, and the projection that reaches a record
# --------------------------------------------------------------------------


def _digests(payload: Mapping[str, Any]) -> dict[str, str]:
    """Every sha256 a response claims about what it analysed, by field name."""
    out: dict[str, str] = {}
    subject = payload.get("subject")
    if isinstance(subject, Mapping):
        digest = subject.get("digest")
        if isinstance(digest, Mapping) and isinstance(digest.get("sha256"), str):
            out["subject.digest.sha256"] = digest["sha256"].strip().lower()
    normalized = payload.get("normalized_result")
    if isinstance(normalized, Mapping):
        inner = normalized.get("subject")
        if isinstance(inner, Mapping) and isinstance(inner.get("root_sha256"), str):
            out["normalized_result.subject.root_sha256"] = (
                inner["root_sha256"].strip().lower()
            )
    return out


def digests_match(payload: Mapping[str, Any], expected: str) -> tuple[bool, dict[str, str]]:
    """Whether the response binds itself to exactly the bytes we handed over.

    Both digests must be present, well-formed, and equal to ours. A response that
    reports one and omits the other is refused: the claim being verified is "the
    analyzer looked at *this* file", and a half-verifiable claim is not that.
    """
    reported = _digests(payload)
    want = (expected or "").strip().lower()
    if not _HEXDIGEST.match(want) or len(reported) != 2:
        return False, reported
    return all(value == want for value in reported.values()), reported


def _mismatch_detail(reported: Mapping[str, str], expected: str) -> str:
    """The refusal sentence, naming the fields and truncating the digests.

    A digest of bytes we do not have is not message content, so it is safe to
    print and necessary for an analyst to tell "REA read a different file" from
    "REA mis-hashed ours". Nothing else from the response survives this call. The
    short field names keep the sentence inside the length cap in rule 8 rather
    than cutting it off mid-word.
    """
    short = {
        "subject.digest.sha256": "subject.digest",
        "normalized_result.subject.root_sha256": "root_sha256",
    }
    parts = [
        f"{short.get(name, name)}={value[:12] or 'absent'}"
        for name, value in sorted(reported.items())
    ]
    return (
        f"digests differ (ours={(expected or 'absent')[:12]}; "
        f"{'; '.join(parts) or 'no digest fields reported'}); the response is "
        "discarded, not partially used"
    )


def project_analysis(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Whitelist a response into what belongs in a record.

    Every field here is something the analyzer reports *about* the payload:
    declared format, provider identity, its own confidence and authority labels,
    coverage of its own substeps, its own limitations, and the container entry
    inventory. Paths are excluded by construction -- ``subject.local_path``,
    ``caller_input_path`` and ``parameters.input_path`` are simply not on the
    list -- so a field REA adds in a later version cannot leak through a
    whitelist it was never added to.
    """
    normalized = _mapping(payload.get("normalized_result"))
    subject = _mapping(payload.get("subject"))
    inner = _mapping(normalized.get("subject"))
    provider = _mapping(payload.get("provider"))

    analysis: dict[str, Any] = {
        "operation": _bounded(str(payload.get("operation") or ""), 60),
        "evidence_id": _bounded(str(payload.get("evidence_id") or ""), 80),
        "inspection_id": _bounded(str(normalized.get("inspection_id") or ""), 80),
        "provider": {
            "id": _bounded(str(provider.get("id") or ""), 60),
            "name": _bounded(str(provider.get("name") or ""), 120),
            "version": _bounded(str(provider.get("version") or ""), 30),
        },
        "declared_format": _bounded(str(subject.get("format") or ""), 40),
        "root_format": _bounded(str(inner.get("root_format") or ""), 40),
        "architecture": _bounded(str(subject.get("architecture") or ""), 40),
        "confidence": _bounded(str(payload.get("confidence") or ""), 40),
        "authority": _bounded(str(payload.get("authority") or ""), 40),
        "coverage": _scalars(_mapping(normalized.get("coverage"))),
        "limitations": _string_list(payload.get("limitations")),
        "substeps": [
            {
                "operation": _bounded(str(step.get("operation") or ""), 60),
                "status": _bounded(str(step.get("status") or ""), 40),
            }
            for step in _mapping_list(normalized.get("substeps"))[:MAX_SUBSTEPS]
        ],
        "observations": [
            {
                "kind": _bounded(str(obs.get("kind") or ""), 60),
                "subject": _bounded(str(obs.get("subject") or ""), 80),
            }
            for obs in _mapping_list(normalized.get("observations"))[:MAX_SUBSTEPS]
        ],
        "root_sha256": _bounded(str(inner.get("root_sha256") or ""), 64),
        "container_entries": _entries(normalized),
        "hypotheses": _string_list(normalized.get("hypotheses")),
        "contradictions": _string_list(normalized.get("contradictions")),
    }
    analysis["entry_count"] = len(analysis["container_entries"])
    analysis["entries_omitted"] = max(0, _occurrence_count(normalized) - len(
        analysis["container_entries"]
    ))
    return analysis


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _scalars(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """A mapping reduced to its scalar fields, so a nested surprise cannot ride
out of a response into a record with it."""
    return {
        str(key): value
        for key, value in mapping.items()
        if isinstance(value, (str, int, float, bool)) or value is None
    }


def _inventories(normalized: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The artifact-graph inventories nested inside each substep's evidence."""
    out = []
    for step in _mapping_list(normalized.get("substeps")):
        evidence = _mapping(step.get("evidence"))
        inner = _mapping(evidence.get("normalized_result"))
        if inner.get("occurrences") or inner.get("nodes"):
            out.append(inner)
    return out


def _occurrence_count(normalized: Mapping[str, Any]) -> int:
    return sum(len(inner.get("occurrences") or []) for inner in _inventories(normalized))


def _entries(normalized: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The container inventory: entry path, size, digest, and two flags.

    This is what an analyst cannot learn from a filename: that the "invoice.zip"
    holds ``notes/agenda.txt``, how large each member is, which ones REA found
    encrypted or marked executable, and the digest of each. Names are flattened
    and capped because they are attacker-chosen strings about to be read by a
    human and by a model.
    """
    out: list[dict[str, Any]] = []
    for inner in _inventories(normalized):
        nodes = {
            str(node.get("artifact_id")): node
            for node in _mapping_list(inner.get("nodes"))
        }
        for occurrence in _mapping_list(inner.get("occurrences")):
            if len(out) >= MAX_ENTRIES:
                return out
            node = nodes.get(str(occurrence.get("artifact_id") or ""), {})
            out.append(
                {
                    "path": _bounded(
                        str(occurrence.get("logical_path") or ""), MAX_NAME_CHARS
                    ),
                    "size": _as_int(occurrence.get("declared_size")),
                    "sha256": _bounded(str(node.get("sha256") or ""), 64),
                    "format": _bounded(str(node.get("format") or ""), 40),
                    "executable": bool(occurrence.get("executable")),
                    "encrypted": bool(occurrence.get("encrypted")),
                    "hash_status": _bounded(str(occurrence.get("hash_status") or ""), 30),
                }
            )
    return out


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_bounded(str(item)) for item in value[:MAX_LIMITATIONS] if item is not None]


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except ValueError:
        return None


def _bounded(text: str, limit: int = MAX_TEXT_CHARS) -> str:
    """Flatten whitespace and cap one string from an external analyzer."""
    return " ".join((text or "").split())[:limit]


# --------------------------------------------------------------------------
# the result type, and the component itself
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AttachmentResult:
    """One attachment's deep-analysis outcome: an answer or an abstention.

    The field vocabulary is :class:`~tenable_email.tiers.TierResult`'s --
    ``available``, ``ok``, ``raw``, ``error``, ``source``, ``latency_ms`` -- so
    the two kinds of gap in a record read alike, without this being a tier or a
    subclass of one (rule 1).

    ``raw`` is REA's response, kept on the result for a caller to argue with and
    **never serialized**: it carries absolute paths. What reaches a record is
    ``analysis``, the whitelisted projection. Where the response cannot be
    trusted -- ``digest_mismatch``, ``rea_unparsable`` -- ``raw`` is left empty
    rather than partially used.

    ``source`` is ``"none"`` when no subprocess was started (disabled, absent,
    refused at the gate, nothing retained) and ``"live"`` when one was.
    """

    attachment: str
    sha256: str
    component: str = COMPONENT
    operation: str = ""
    available: bool = False
    ok: bool = False
    raw: Mapping[str, Any] = field(default_factory=dict)
    analysis: Mapping[str, Any] = field(default_factory=dict)
    error: str | None = None
    detail: str = ""
    latency_ms: float | None = None
    source: str = "none"
    #: Set only when cleanup failed: the directory still on disk with the payload
    #: inside it. Reported, never dropped.
    cleanup_retained: str | None = None

    @property
    def reason(self) -> str:
        """The abstention reason, or ``""`` when there is an answer."""
        return "" if self.ok else (self.error or "unspecified")

    def as_dict(self) -> dict[str, Any]:
        """Serialization-safe form: the projection only, never ``raw``."""
        return {
            "component": self.component,
            "attachment": self.attachment,
            "sha256": self.sha256,
            "operation": self.operation,
            "available": self.available,
            "ok": self.ok,
            "error": self.error,
            "detail": self.detail,
            "latency_ms": self.latency_ms,
            "source": self.source,
            "analysis": dict(self.analysis),
            "cleanup_retained": self.cleanup_retained,
        }


def analyze_attachment(
    attachment: Attachment,
    config: Config | None = None,
    *,
    operation: str = DEFAULT_OPERATION,
    timeout: float | None = None,
    command: str | None = None,
) -> AttachmentResult:
    """Inspect one attachment with REA, or abstain with a reason.

    Never raises. The order of checks is the order of cost and of risk: is there
    anything retained to analyse, is the tool installed, is this operation
    permitted by both halves of the gate, can the bytes be staged privately, did
    the tool answer, does its answer bind to our bytes. Staging happens last, and
    is undone on every path -- including the refusals after it.

    The configuration only supplies the binary name and the budget here. The
    operator's opt-in flag is checked by :func:`run_for_message`, which is what
    the pipeline calls; an explicit call to this function is an explicit request.
    """
    config = config or Config()
    tool = command or config.attachment_analysis_command or REA_COMMAND
    budget = (
        float(timeout)
        if timeout is not None
        else float(
            config.attachment_analysis_timeout_seconds or DEFAULT_TIMEOUT_SECONDS
        )
    )
    want = operation or DEFAULT_OPERATION

    def refuse(reason: str, detail: str, **extra: Any) -> AttachmentResult:
        return AttachmentResult(
            attachment=attachment.filename,
            sha256=attachment.sha256,
            operation=want,
            available=bool(extra.pop("available", True)),
            ok=False,
            error=reason,
            detail=_bounded(detail),
            source=extra.pop("source", "none"),
            latency_ms=extra.pop("latency_ms", None),
            **extra,
        )

    # 1. Nothing retained. The parser hashed and dropped an oversized part, so
    # the bytes are not in this process. Analysing the empty file that stands in
    # for them would report "an empty container" about a 40 MB attachment: a
    # false statement about this message, so it is refused.
    if attachment.truncated or not attachment.data:
        return refuse(
            "attachment_not_retained",
            "the parser dropped this part's bytes at the retention limit; its "
            f"size ({attachment.size} bytes) and sha256 were kept and its contents "
            "were not, so there is nothing here to hand to an analyzer",
            available=False,
        )

    # 2. The optional dependency.
    if rea_executable(tool) is None:
        return refuse(
            "rea_not_installed",
            f"no {tool} binary on PATH; this component is optional and does nothing "
            "until an operator installs the upstream CLI",
            available=False,
        )

    # 3. Both halves of the safety gate, before anything is written or spawned.
    permitted, reason, detail = operation_permitted(want, tool, budget)
    if not permitted:
        return refuse(reason, detail)

    # 4. Quarantine, analyse, and always clean up.
    quarantine: str | None = None
    staged: str | None = None
    result: AttachmentResult | None = None
    try:
        try:
            quarantine = create_quarantine()
            staged = stage_payload(quarantine, attachment)
        except (QuarantineError, OSError) as exc:
            result = refuse(
                "quarantine_failed",
                f"the payload could not be staged privately: {type(exc).__name__}: {exc}",
                available=True,
            )
        else:
            result = _analyse_staged(attachment, staged, want, tool, budget, refuse)
    finally:
        if quarantine is not None:
            retained = remove_quarantine(quarantine)
            if retained:
                RETAINED_QUARANTINE_PATHS.append(retained)
                if result is not None:
                    result = replace(result, cleanup_retained=retained)
    assert result is not None, "unreachable: every path assigns a result"
    return result


def _analyse_staged(
    attachment: Attachment,
    staged: str | None,
    operation: str,
    tool: str,
    budget: float,
    refuse: Any,
) -> AttachmentResult:
    """Invoke the analyzer on a staged file and read what came back."""
    outcome = _run([tool, operation_command(operation), str(staged), "--json"], budget)
    if not outcome.started:
        # Not installed or timed out: nothing was printed, so there is nothing to
        # bind and nothing to project.
        return refuse(outcome.reason, outcome.detail, source="none")

    payload = outcome.payload
    if not isinstance(payload, Mapping):
        return refuse(
            "rea_unparsable",
            f"rea printed a JSON {type(payload).__name__}, expected an object "
            f"(exit code {outcome.exit_code})",
            latency_ms=outcome.latency_ms,
            source="live",
        )
    if "normalized_result" not in payload:
        reason, detail = _classify_envelope(payload)
        return refuse(
            reason, detail, latency_ms=outcome.latency_ms, source="live"
        )
    matches, reported = digests_match(payload, attachment.sha256)
    if not matches:
        # Discarded, not summarised. An unverified result about attacker-chosen
        # bytes is not even a hypothesis worth recording.
        return refuse(
            "digest_mismatch",
            _mismatch_detail(reported, attachment.sha256),
            latency_ms=outcome.latency_ms,
            source="live",
        )
    analysis = dict(project_analysis(payload))
    analysis["digest_verified"] = True
    analysis["digest_algorithm"] = "sha256"
    analysis["attachment_size"] = attachment.size
    analysis["content_type"] = _bounded(attachment.content_type, 80)
    return AttachmentResult(
        attachment=attachment.filename,
        sha256=attachment.sha256,
        operation=operation,
        available=True,
        ok=True,
        raw=dict(payload),
        analysis=analysis,
        latency_ms=outcome.latency_ms,
        source="live",
    )


def analyze_message(
    msg: Message,
    config: Config | None = None,
    *,
    operation: str = DEFAULT_OPERATION,
    timeout: float | None = None,
    command: str | None = None,
) -> list[AttachmentResult]:
    """Deep-analyse every attachment of one message, in MIME order.

    Inline images are included: they carry bytes, and a Quishing payload arrives
    as one. A message with no attachments produces an empty list and spawns
    nothing -- that is not an abstention, there was nothing to abstain about.
    """
    return [
        analyze_attachment(
            attachment, config, operation=operation, timeout=timeout, command=command
        )
        for attachment in msg.attachments
    ]


def run_for_message(msg: Message, config: Config | None = None) -> list[AttachmentResult]:
    """Analyse this message's attachments **if the operator asked for it**.

    The only function :mod:`tenable_email.pipeline` calls. It returns an empty
    list when :attr:`~tenable_email.config.Config.deep_attachment_analysis` is
    false -- the shipped default -- so a reviewer running the documented offline
    path never spawns a subprocess and never sees a finding from this module.
    """
    config = config or Config()
    if not config.deep_attachment_analysis:
        return []
    return analyze_message(msg, config)


# --------------------------------------------------------------------------
# evidence
# --------------------------------------------------------------------------


def findings_for(result: AttachmentResult) -> list[Finding]:
    """Turn one outcome into findings.

    An answer is ``VERIFIED``, and the claim it makes is deliberately narrow:
    *a named provider reported these structural facts about these exact bytes,
    the bytes were verified by sha256, and here are the analyzer's own
    limitations and coverage status.* Reproducible from the same bytes, which is
    what VERIFIED means here -- and the analyzer's confidence and authority
    labels travel with it so a reader can weigh the claim without editing the
    record to disagree.

    What it is **not** is a statement that the attachment is benign, which is why
    no adjudication fact reads it (rule 9). Hypotheses and contradictions are
    split into a ``MODEL_JUDGMENT`` finding rather than folded into the verified
    one, because an opinion printed by a tool is still an opinion, and one finding
    cannot carry two provenances.

    Any abstention is ``UNAVAILABLE``, with the reason as the first word of the
    detail. Never ``UNKNOWN`` -- "we know which check is missing" is exactly the
    distinction :class:`~tenable_email.evidence.Provenance` exists to draw.
    """
    if not result.ok:
        detail = f"{result.error}: {result.attachment} (sha256 {result.sha256[:12]})"
        if result.detail:
            detail = f"{detail}: {result.detail}"
        return [
            Finding(
                key=FINDING_KEY,
                value=None,
                provenance=Provenance.UNAVAILABLE,
                source=STAGE,
                detail=detail,
            )
        ]
    findings = [
        Finding(
            key=FINDING_KEY,
            value=dict(result.analysis),
            provenance=Provenance.VERIFIED,
            source=STAGE,
            detail=(
                f"{result.attachment} (sha256 {result.sha256[:12]}): "
                f"{_summary_line(result)}"
            ),
        )
    ]
    analysis = result.analysis
    if analysis.get("hypotheses") or analysis.get("contradictions"):
        findings.append(
            Finding(
                key=HYPOTHESIS_KEY,
                value={
                    "hypotheses": list(analysis.get("hypotheses") or []),
                    "contradictions": list(analysis.get("contradictions") or []),
                },
                provenance=Provenance.MODEL_JUDGMENT,
                source=STAGE,
                detail=(
                    f"{result.attachment}: REA's own hypotheses and contradictions; "
                    "an opinion about the contents, not an observation of them"
                ),
            )
        )
    return findings


def _summary_line(result: AttachmentResult) -> str:
    analysis = result.analysis
    provider = str((analysis.get("provider") or {}).get("id") or "unknown")
    pieces = [
        f"declared format {analysis.get('declared_format') or 'unknown'}",
        "sha256 digest verified against the bytes in this message",
        f"provider {provider}",
    ]
    if analysis.get("entry_count"):
        pieces.append(f"{analysis['entry_count']} container entry(ies) inventoried")
    if analysis.get("entries_omitted"):
        pieces.append(f"{analysis['entries_omitted']} entry(ies) not listed")
    if analysis.get("limitations"):
        pieces.append(
            f"{len(analysis['limitations'])} analyzer limitation(s) recorded verbatim"
        )
    pieces.append(
        f"coverage {analysis.get('coverage', {}).get('status') or 'unknown'}"
    )
    pieces.append(
        f"analyzer confidence {analysis.get('confidence') or 'unstated'}, "
        f"authority {analysis.get('authority') or 'unstated'}"
    )
    return ", ".join(pieces)


def record_findings(
    evidence: Evidence, results: Iterable[AttachmentResult]
) -> list[Finding]:
    """Append outcomes to a record, in order, and return what was added.

    Append-only, like everything else in :class:`Evidence`. A cleanup failure is
    recorded after the findings it applies to, *with its path*: an analyst who
    cannot locate a leftover copy of an untrusted payload cannot remove it. That
    makes this the one place in the project where a local path is deliberately
    written into a record, and the exception is stated rather than quietly taken
    -- it is a temp directory on the operator's own host, created by this
    component, not an identity about the deployment.
    """
    added: list[Finding] = []
    for result in results:
        for finding in findings_for(result):
            evidence.findings.append(finding)
            added.append(finding)
        if result.cleanup_retained:
            added.append(
                evidence.add(
                    QUARANTINE_KEY,
                    {"attachment": result.attachment, "sha256": result.sha256},
                    Provenance.VERIFIED,
                    STAGE,
                    (
                        f"a quarantine directory for {result.attachment} (sha256 "
                        f"{result.sha256[:12]}) could not be removed and is still "
                        f"on disk at {result.cleanup_retained}; reported rather than "
                        "dropped, and needing manual removal"
                    ),
                )
            )
    return added
