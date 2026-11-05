"""Where reported mail comes from, and nothing else.

The investigation engine takes RFC 822 bytes and produces a verdict. It has never
known or cared whether those bytes came from a directory of ``.eml`` files, a Gmail
mailbox, an alerting platform, or a string in a test - :func:`~tenable_email.parse.
parse_message` accepts ``raw`` bytes plus a label. This module makes that seam
explicit so a new email platform is an adapter rather than a change to the engine.

Two adapter contracts exist in this project and they are deliberately separate:

``EmailSource`` (here)
    Intake. Read-only by construction. Yields messages to analyse.

``WritebackProvider`` (:mod:`tenable_email.writeback`)
    Remediation. Mutating, gated behind a human approval bound to the verdict digest
    it was granted against. Already implemented, already tested, already the thing
    ``runner.py`` enforces.

Status is not a third contract. It is owned locally by the receipt
(:mod:`tenable_email.receipt`) and the case ledger, because the question "what did
we decide and what did a human do next" is ours to answer, not the email platform's.
Asking a mailbox for investigation status would mean trusting a system we do not
control to remember what we concluded.

Design rules, each of which exists because the alternative is a defect:

*   A source yields **raw bytes**, not a parsed message. Normalization has exactly
    one owner, :func:`~tenable_email.parse.parse_message`. An adapter that parses
    its own way creates a second interpretation of the same input, and the two will
    disagree.
*   Source-specific facts travel in ``metadata`` and are **preserved, never
    reinterpreted**. An adapter that guesses what a field means loses information
    the engine cannot recover.
*   Order must be **stable**. Replay recordings are keyed on message content, but a
    batch run that reorders makes results unreproducible and diffs unreadable.
*   Intake is **read-only**. A source that mutates the thing it reads from - marking
    alerts as seen, moving mail - belongs on the writeback side behind an approval,
    not here. ``mutates`` exists so a violating adapter can be refused rather than
    merely discouraged.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .parse import (
    DEFAULT_MAX_EML_DEPTH,
    DEFAULT_MAX_EML_FILES,
    DirectoryScanError,
    EmlScan,
    parse_message,
    scan_eml_dir,
)

__all__ = [
    "DEFAULT_SOURCE",
    "SourceError",
    "SourceItem",
    "EmailSource",
    "EmlDirectorySource",
    "source_for",
    "register_source",
    "available_sources",
]

#: The source used when a caller does not choose one. It reads a directory of
#: ``.eml`` files, which means the default path needs no credentials, no network and
#: no account on any email platform - the property that lets a reviewer run this with
#: nothing installed.
DEFAULT_SOURCE = "eml-dir"


class SourceError(RuntimeError):
    """A source could not hand over messages. ``reason`` is recordable.

    Raised as a value-bearing error rather than a bare exception so a caller can
    report *why* intake failed instead of only that it did. An unconfigured source
    and an unreachable one are different facts and should not read the same.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason if not detail else f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class SourceItem:
    """One reported message as a source hands it over, before normalization.

    ``raw`` is the whole contract: RFC 822 bytes. Everything else is provenance, so
    the engine can say where a verdict's input came from without asking the source
    to interpret anything.
    """

    #: The source's own identifier - a filename, a mailbox message id, an alert id.
    #: Kept separate from ``Message.message_id``, which is the RFC 822 header and is
    #: routinely absent, duplicated or forged. Conflating the two would make a
    #: lookup key out of attacker-controlled data.
    external_id: str

    #: RFC 822 bytes. The engine's only input.
    raw: bytes

    #: Human-readable label recorded on ``Message.source`` and in evidence. For a
    #: directory source this is the path; for an API source it should name the
    #: platform and the item, e.g. ``gmail:someone@example.com/18f2...``.
    source: str = ""

    #: Who reported the message, when the platform knows. ``None`` is a real answer
    #: and is not the same as an empty string.
    reporter: str | None = None

    #: When the platform received or raised it, as the platform states it. Not
    #: parsed into a datetime here: timezone and format are the platform's business
    #: and guessing loses information.
    received_at: str | None = None

    #: Source-specific facts, preserved as given. Values are strings so this can be
    #: serialized into a receipt without a second representation.
    metadata: Mapping[str, str] = field(default_factory=dict)

    def parse(self, *, body_char_limit: int | None = None) -> Any:
        """Normalize this item into a :class:`~tenable_email.parse.Message`.

        Convenience only, and it delegates rather than reimplementing: there is one
        parser in this project and an adapter does not get a second one.

        ``body_char_limit`` defaults to the parser's own default rather than to a
        number restated here. Callers that have a :class:`~tenable_email.config.
        Config` should pass ``config.thresholds.body_char_limit``, because
        ``triage_file`` does - and a second hardcoded copy of that limit is how the
        two intake paths silently start truncating at different lengths.
        """
        kwargs: dict[str, Any] = {}
        if body_char_limit is not None:
            kwargs["body_char_limit"] = body_char_limit
        return parse_message(
            self.raw, source=self.source or self.external_id, **kwargs
        )


@runtime_checkable
class EmailSource(Protocol):
    """The intake adapter contract.

    Implement this to add an email platform. Nothing else in the engine changes.
    """

    #: Stable identifier used to select the source from configuration or the CLI.
    name: str

    #: Must be ``False`` for an intake source. See the module docstring: a source
    #: that mutates what it reads belongs behind the approval gate instead.
    mutates: bool

    def fetch(
        self, *, limit: int | None = None, since: str | None = None
    ) -> Iterator[SourceItem]:
        """Yield reported messages, in a stable order.

        ``limit`` and ``since`` are advisory filters the source may apply natively -
        an API that can ask the server for fewer or newer items should, because
        fetching a whole mailbox to discard most of it is the expensive mistake. A
        source that cannot filter natively may ignore them, but must not silently
        return a different set than it was asked for without saying so in
        :meth:`describe`.

        Implementations should be lazy. Holding every reported message in memory is
        how an intake path becomes an outage.
        """
        ...

    def describe(self) -> str:
        """One line naming what this source reads and what it needs.

        Returned to operators and recorded in evidence, so it must state the
        requirements honestly - a credential, a network call, a scope - rather than
        only the platform name.
        """
        ...


class EmlDirectorySource:
    """The reference adapter: a directory of ``.eml`` files.

    This is the default, and it is the default on purpose. It needs no credentials,
    no network and no account on any email platform, so the entire pipeline is
    runnable by someone who has never heard of us. Every other adapter has to earn
    the right to be less accessible than this one.
    """

    name = DEFAULT_SOURCE
    mutates = False

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        #: What the most recent :meth:`fetch` actually walked -- the root, the
        #: count, the bounds, and whether a bound bound. ``None`` until a fetch
        #: runs. A source that hands over messages without saying how many it saw
        #: is not auditable, and this is where the scan's record surfaces.
        self.scan: EmlScan | None = None

    def fetch(
        self, *, limit: int | None = None, since: str | None = None
    ) -> Iterator[SourceItem]:
        """Yield the corpus, bounded by the same mechanism the walk is bounded by.

        ``limit`` is passed to :func:`~tenable_email.parse.scan_eml_dir` as its
        ``max_files``: one number, one owner. Asking for five messages therefore
        walks five files rather than the whole tree, and asking for nothing means
        the scan's own safety ceiling applies -- with no ``limit`` the caller has
        not claimed to want a subset, so a bound that binds is a refusal
        (``source_directory_bound``) rather than a short answer presented as a
        complete one.
        """
        if not self.directory.is_dir():
            raise SourceError("source_directory_missing", str(self.directory))
        if since is not None:
            # Filenames carry no received time, so a time filter cannot be applied
            # natively. Saying so beats quietly returning everything and letting a
            # caller believe the filter worked.
            raise SourceError(
                "source_filter_unsupported",
                f"{self.name} cannot filter by time; {self.directory} has no "
                "received-time metadata",
            )
        if limit is not None and limit <= 0:
            # Nothing was asked for, so nothing is walked. A walk is the expensive
            # part of intake and it should never happen to return zero items.
            return
        budget = DEFAULT_MAX_EML_FILES if limit is None else limit
        try:
            scan = scan_eml_dir(
                self.directory,
                max_files=budget,
                # A caller who named a limit asked for a subset; a partial scan is
                # what they opted into, and it is recorded on ``self.scan``.
                allow_partial=limit is not None,
            )
        except DirectoryScanError as exc:
            raise SourceError("source_directory_bound", exc.detail) from exc
        self.scan = scan
        # scan_eml_dir sorts, which is the stability guarantee this module requires.
        for path in scan.paths:
            yield SourceItem(
                external_id=path.name,
                raw=path.read_bytes(),
                source=str(path),
                received_at=None,
            )

    def describe(self) -> str:
        return (
            f"reads .eml files under {self.directory}; a bounded scan of at most "
            f"{DEFAULT_MAX_EML_FILES} files to depth "
            f"{DEFAULT_MAX_EML_DEPTH}, with symlinks not followed; no credentials, "
            "no network, no email platform account"
        )


#: Sources this build can construct, by name. Third-party adapters add themselves
#: with :func:`register_source` rather than editing this module, which is the point
#: of having a contract at all.
_REGISTRY: dict[str, Any] = {}

#: Adapter modules that register themselves on import. Registration is a side effect of
#: importing, so a consumer that never imports the module never sees the source: before
#: this list existed, ``available_sources()`` returned only ``eml-dir`` unless something
#: had already imported the CLI, which meant the MCP server and any library caller saw a
#: different set of sources than the shell did. Importing on demand keeps the registry
#: authoritative for every consumer without a module-level cycle - these modules import
#: this one, so the import has to be deferred into a function.
#:
#: A failure to import is deliberately allowed to propagate. An adapter that silently
#: vanished from the registry would look like a typo'd ``--source`` name at the point of
#: use, which is a much worse place to discover that a module is broken.
_ADAPTER_MODULES = ("google_intake",)

_adapters_loaded = False


def _load_adapters() -> None:
    """Import every adapter module once, so registration has happened."""
    global _adapters_loaded
    if _adapters_loaded:
        return
    import importlib

    for name in _ADAPTER_MODULES:
        importlib.import_module(f"{__name__.rsplit('.', 1)[0]}.{name}")
    _adapters_loaded = True

#: Aliases accepted for the reference adapter. Spelled out rather than normalized by
#: stripping punctuation, so an unrelated name cannot accidentally resolve.
_DIRECTORY_ALIASES = frozenset({DEFAULT_SOURCE, "eml", "eml_dir", "directory"})


def register_source(name: str, factory: Any) -> None:
    """Make a source selectable by name.

    ``factory`` is called as ``factory(path=...)`` and must return an
    :class:`EmailSource`. Registration does not bypass any check: :func:`source_for`
    still refuses a mutating source, so an adapter cannot opt out of the read-only
    rule by registering itself.
    """
    key = name.strip().lower()
    if not key:
        raise SourceError("source_name_empty", "a source name must not be blank")
    if key in _DIRECTORY_ALIASES:
        raise SourceError(
            "source_name_reserved",
            f"{key!r} names the built-in directory adapter; choose another name",
        )
    _REGISTRY[key] = factory


def source_for(name: str | None, *, path: str | Path | None = None) -> EmailSource:
    """Build a source by name.

    Refuses a mutating source, an unknown name, and a source that needs a path it
    was not given - each with a reason naming what is wrong, because a silent
    downgrade to the default would hide a misconfiguration until the results looked
    wrong rather than until the command failed.
    """
    _load_adapters()
    key = (name or DEFAULT_SOURCE).strip().lower()

    if key in _DIRECTORY_ALIASES:
        if path is None:
            raise SourceError(
                "source_path_required",
                f"{DEFAULT_SOURCE} needs a directory; pass one explicitly",
            )
        source: EmailSource = EmlDirectorySource(path)
    elif key in _REGISTRY:
        if path is None:
            raise SourceError(
                "source_path_required",
                f"source {key!r} needs its configuration; pass it explicitly",
            )
        source = _REGISTRY[key](path=path)
    else:
        raise SourceError(
            "unknown_source",
            f"no source named {name!r}; available: {', '.join(available_sources())}. "
            "A platform adapter is a separate implementation of EmailSource - see "
            "docs/ADAPTERS.md",
        )

    if getattr(source, "mutates", False):
        raise SourceError(
            "source_mutates",
            f"{getattr(source, 'name', key)} declares mutates=True; intake must be "
            "read-only. A source that changes what it reads belongs behind the "
            "approval gate in src/tenable_email/writeback.py",
        )
    return source


def available_sources() -> tuple[str, ...]:
    """Names this build can construct, built-in first and the rest sorted.

    A platform adapter that is not registered here is not available, and saying so is
    better than letting a caller discover it from a traceback.
    """
    _load_adapters()
    return (DEFAULT_SOURCE, *sorted(_REGISTRY))
