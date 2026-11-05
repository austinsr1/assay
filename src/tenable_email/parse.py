"""Message intake and parsing.

Stdlib ``email`` only. The reference playbook needed a custom n8n Dockerfile
installing ``mailparser``, ``htmlparser2``, ``domutils`` and ``dom-serializer``
to do this work; Python's standard library does it with no dependency at all.

Two intake paths, both first-class:

* a directory of ``.eml`` files -- offline, no credentials, no network. This is
  the path a reviewer runs. The walk is bounded and it refuses rather than
  truncates: a caller-supplied path must never become a search of the machine
  (see :func:`scan_eml_dir`), and every consumer of this module -- the directory
  source, the CLI, the MCP batch tool -- inherits that bound instead of owning
  its own.
* a single RFC 822 message from bytes or text, which is what a live feed
  adapter hands us.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import os
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Iterator

#: How much of a filesystem one scan is allowed to look at, and the two ways a
#: caller-supplied path can turn into a search of the whole machine.
#:
#: ``analyze_eml_directory("/")`` used to walk every directory on the host. On
#: this build machine that took 44.7 s, crossed a network mount, found 6,297
#: ``.eml`` files belonging to other people's projects, triaged every one of them
#: and returned the rows as though the caller had been shown the corpus it asked
#: for. A bound that is not measured is a guess, so the defaults here are: enough
#: for any real reported-mail corpus (this repository's whole corpus is 14 files
#: in one directory, 54 across ``fixtures/``), small enough that pointing at a
#: filesystem root refuses in milliseconds instead of walking for minutes.
DEFAULT_MAX_EML_FILES = 2000
DEFAULT_MAX_EML_DEPTH = 4

#: Directory trees that are not data. These are refused by name rather than
#: counted against the depth bound, because a bounded walk that spends its whole
#: budget inside ``/proc`` has learned nothing: on this host pruning them cut the
#: depth-4 scan of ``/`` from 2,000 ms to 1,321 ms and the depth-5 scan from
#: 4,266 ms to 1,922 ms, and ``/proc`` can also block a reader outright.
#: Compared against resolved absolute paths, so a corpus directory legitimately
#: named ``dev`` or ``sys`` is walked exactly as any other is.
NON_DATA_TREES = ("/proc", "/sys", "/dev", "/run")

#: Why a scan stopped early. ``complete`` records the reason in the result so a
#: partial reading can never be read as a whole one.
BOUND_FILES = "files"
BOUND_DEPTH = "depth"
BOUND_ROOT = "system-tree"


class DirectoryScanError(ValueError):
    """A directory scan hit a walk bound and therefore refuses to answer.

    Carries ``reason`` (which bound), ``detail`` (the bound, the directory, and
    how to narrow the request) and the partial :class:`EmlScan`. Refusing is the
    point: a silently truncated batch presented as a complete one is the failure
    mode this repository keeps fixing, and the same bound that stops the walk has
    to be the thing the caller is told about."""

    def __init__(self, reason: str, detail: str, scan: "EmlScan | None" = None) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.scan = scan


@dataclass(frozen=True)
class Attachment:
    """One MIME part carrying a file.

    Inline images are also attachments -- they have a filename or a content-id
    and their bytes matter -- but they are marked ``inline`` so the vision tier
    can select them without the caller re-walking the MIME tree.
    """

    filename: str
    content_type: str
    size: int
    sha256: str
    data: bytes
    inline: bool = False
    content_id: str | None = None
    #: Set when the part was too large to retain. The hash and size are still
    #: recorded, so identity survives even when the bytes do not.
    truncated: bool = False

    @property
    def extension(self) -> str:
        return os.path.splitext(self.filename)[1].lower()

    def without_data(self) -> dict:
        """Serializable form that never carries message content.

        Used in evidence records and logs. Attachment bytes are exactly the kind
        of payload that must not leak into a shipped artifact.
        """
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "extension": self.extension,
            "size": self.size,
            "sha256": self.sha256,
            "inline": self.inline,
            "content_id": self.content_id,
            "truncated": self.truncated,
        }


@dataclass
class Message:
    """A parsed message, normalized for the stages downstream.

    Header values are kept as raw strings alongside their parsed forms. Parsing
    loses information -- a malformed ``From`` still deserves to be visible -- so
    the source value is never discarded.
    """

    message_id: str = ""
    date: str = ""
    subject: str = ""
    from_raw: str = ""
    to_raw: str = ""
    reply_to_raw: str = ""
    return_path_raw: str = ""

    #: Every header as ``(name, value)``, in original order, names lowercased.
    headers: list[tuple[str, str]] = field(default_factory=list)

    text_body: str = ""
    html_body: str = ""

    attachments: list[Attachment] = field(default_factory=list)

    #: True when any body part exceeded the retention limit and was cut.
    body_truncated: bool = False
    #: Original character length before truncation, when truncation occurred.
    original_body_length: int | None = None

    #: Where this message came from, for provenance in the evidence record.
    source: str = ""

    def headers_named(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.headers if k == n]

    def header(self, name: str) -> str | None:
        vals = self.headers_named(name)
        return vals[0] if vals else None

    @property
    def inline_images(self) -> list[Attachment]:
        return [
            a
            for a in self.attachments
            if a.inline or a.content_type.lower().startswith("image/")
        ]

    @property
    def body(self) -> str:
        """Best available body text. HTML is retained separately because link
        analysis needs the markup; this is for models and keyword stages."""
        return self.text_body or self.html_body


#: Parts larger than this are hashed and dropped rather than retained. Bounds
#: memory on a message carrying a large attachment without losing its identity.
MAX_RETAINED_PART_BYTES = 8 * 1024 * 1024


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_payload(part: EmailMessage) -> bytes:
    """Best-effort payload bytes for a part, tolerating malformed encoding."""
    try:
        raw = part.get_payload(decode=True)
    except Exception:
        raw = None
    if raw is not None:
        return raw
    try:
        payload = part.get_payload()
    except Exception:
        return b""
    if isinstance(payload, str):
        return payload.encode("utf-8", "replace")
    return b""


def _is_attachment_part(part: EmailMessage) -> bool:
    if part.is_multipart():
        return False
    disposition = (part.get_content_disposition() or "").lower()
    if disposition in ("attachment", "inline"):
        return True
    # A part with a filename is an attachment regardless of disposition; some
    # senders omit the header entirely.
    if part.get_filename():
        return True
    # A content-id bearing image is an inline image referenced by the HTML.
    if part.get("Content-ID") and part.get_content_type().startswith("image/"):
        return True
    return False


def parse_message(
    raw: bytes | str, *, source: str = "inline", body_char_limit: int = 8000
) -> Message:
    """Parse one RFC 822 message.

    ``body_char_limit`` caps retained body text. When it binds, ``body_truncated``
    is set and the original length is preserved, so a downstream stage can mark
    the analysis as partial instead of silently reasoning over half a message.
    The reference playbook signals this to its model with ``<TRUNCATED/>``; the
    engine this replaces cut at 8000 characters and said nothing.
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8", "replace")
    else:
        raw_bytes = raw

    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception:
        # A message we cannot parse is still a message someone reported. Record
        # what we have rather than raising: the caller must be able to report
        # UNKNOWN with a reason.
        m = Message(source=source)
        m.body_truncated = False
        m.text_body = ""
        return m

    out = Message(source=source)
    out.message_id = str(msg.get("Message-ID", "") or "")
    out.date = str(msg.get("Date", "") or "")
    out.subject = str(msg.get("Subject", "") or "")
    out.from_raw = str(msg.get("From", "") or "")
    out.to_raw = str(msg.get("To", "") or "")
    out.reply_to_raw = str(msg.get("Reply-To", "") or "")
    out.return_path_raw = str(msg.get("Return-Path", "") or "")

    out.headers = [
        (str(k).lower(), str(v)) for k, v in msg.items()
    ]

    original_text_len = 0
    original_html_len = 0

    for part in msg.walk():
        if _is_attachment_part(part):
            data = _decode_payload(part)
            too_big = len(data) > MAX_RETAINED_PART_BYTES
            filename = part.get_filename() or "(unnamed)"
            cid = part.get("Content-ID")
            if cid:
                cid = cid.strip().strip("<>")
            out.attachments.append(
                Attachment(
                    filename=str(filename),
                    content_type=part.get_content_type() or "application/octet-stream",
                    size=len(data),
                    sha256=_sha256(data),
                    data=b"" if too_big else data,
                    inline=(part.get_content_disposition() or "").lower() == "inline"
                    or bool(cid),
                    content_id=cid,
                    truncated=too_big,
                )
            )
            continue

        if part.is_multipart():
            continue

        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue

        try:
            text = part.get_content()
        except Exception:
            text = _decode_payload(part).decode("utf-8", "replace")
        if not isinstance(text, str):
            text = str(text)

        if ctype == "text/plain" and not out.text_body:
            original_text_len = len(text)
            out.text_body = text[:body_char_limit]
        elif ctype == "text/html" and not out.html_body:
            original_html_len = len(text)
            out.html_body = text[:body_char_limit]

    # Truncation is tracked per MIME part and aggregated, because
    # `original_text_len or original_html_len` silently discards the HTML
    # alternative's length whenever a plain-text one exists. A message carrying
    # 200 characters of text and 40,000 of HTML therefore reported
    # `truncated = False` while almost all of its content went unexamined -- and
    # an unexamined message that claims to be complete is the failure mode the
    # truncation marker exists to prevent. The reported original length is the
    # largest truncated part, so the record does not understate what was dropped.
    truncated_lengths = [
        length
        for length in (original_text_len, original_html_len)
        if length > body_char_limit
    ]
    if truncated_lengths:
        out.body_truncated = True
        out.original_body_length = max(truncated_lengths)

    return out


def parse_file(path: str | Path, *, body_char_limit: int = 8000) -> Message:
    """Parse one ``.eml`` file."""
    p = Path(path)
    return parse_message(
        p.read_bytes(), source=str(p), body_char_limit=body_char_limit
    )


@dataclass(frozen=True)
class EmlScan:
    """What one bounded directory scan saw, including what it refused to see.

    The scan is the auditable unit: a batch answer that does not say whether it
    looked at everything is not a batch answer, so every consumer gets the same
    record of root, counts, bounds and the reason a bound bound.
    """

    root: str
    paths: tuple[Path, ...]
    max_files: int
    max_depth: int
    directories_visited: int
    symlinks_skipped: int
    #: Non-data trees refused by name (``proc``, ``sys``, ...), recorded without
    #: their full paths so a result can be printed without leaking the host tree.
    trees_pruned: tuple[str, ...]
    #: ``None`` when the walk saw everything below ``root`` within its bounds.
    bound: str | None = None

    @property
    def complete(self) -> bool:
        """True when the walk hit no bound, so the result is not a subset.

        Two things this deliberately does *not* treat as incompleteness, because
        both are policy rather than a limit reached: a pruned ``/proc`` (there is
        no mail there, and refusing it is the correct behaviour) and a skipped
        symlink (leaving the root is not something the walk is ever licensed to
        do). Both are counted in :attr:`trees_pruned` and
        :attr:`symlinks_skipped`, so the record still says what was not looked at.
        """
        return self.bound is None

    @property
    def files_found(self) -> int:
        return len(self.paths)

    def summary(self) -> dict:
        """The scan record a batch result should carry.

        Deliberately free of absolute paths beyond the root the caller itself
        supplied: an agent-facing surface reports what it scanned, not the shape
        of the host's filesystem.
        """
        return {
            "root": self.root,
            "files_found": self.files_found,
            "directories_visited": self.directories_visited,
            "max_files": self.max_files,
            "max_depth": self.max_depth,
            "bound": self.bound,
            "complete": self.complete,
            "symlinks_skipped": self.symlinks_skipped,
            "trees_pruned": list(self.trees_pruned),
        }

    def refusal(self) -> str:
        """Name the bound that bound, the directory, and how to narrow it.

        All three are required. "too many files" without the directory is a
        message about some scan, and a refusal that does not say how to get an
        answer leaves the caller retrying the same call with different punctuation.
        """
        if self.bound == BOUND_ROOT:
            return (
                f"refusing to scan {self.root}: it resolves inside a system tree "
                f"({', '.join(self.trees_pruned)}), which is not a mail corpus. "
                "Point at the directory that holds the reported messages."
            )
        if self.bound == BOUND_FILES:
            hit = f"more .eml files than the {self.max_files}-file bound"
            how = (
                f"narrow the path to the directory you actually mean, raise "
                f"max_files above {self.max_files}, or ask for a bounded partial "
                "scan"
            )
        else:
            hit = f"a directory deeper than the depth-{self.max_depth} bound"
            how = (
                f"narrow the path to the directory holding the mail, raise "
                f"max_depth above {self.max_depth}, or ask for a bounded partial "
                "scan"
            )
        return (
            f"refusing to scan {self.root}: the walk hit {hit}. A partial reading "
            f"returned as a complete one is not an answer, so nothing was triaged. "
            f"To get one: {how}."
        )


def _inside(candidate: str, parent: str) -> bool:
    return candidate == parent or candidate.startswith(parent.rstrip("/") + os.sep)


#: Each non-data tree resolved once, as ``(display name, resolved path)``. A scan
#: of a real corpus visits hundreds of directories, and re-resolving four fixed
#: absolute paths in each one is work with no information in it.
_SYSTEM_TREES_RESOLVED = tuple(
    (tree.lstrip(os.sep) or tree, os.path.realpath(tree)) for tree in NON_DATA_TREES
)


def _system_tree(candidate: str) -> str:
    """The non-data tree ``candidate`` resolves inside, or ``""``.

    Compared against resolved paths so a symlink named ``sys`` inside a corpus
    cannot be walked as ordinary data, and so a corpus directory that merely
    shares the name of a kernel tree is not refused.
    """
    for name, resolved in _SYSTEM_TREES_RESOLVED:
        if _inside(candidate, resolved):
            return name
    return ""


def scan_eml_dir(
    directory: str | Path,
    *,
    max_files: int = DEFAULT_MAX_EML_FILES,
    max_depth: int = DEFAULT_MAX_EML_DEPTH,
    allow_partial: bool = False,
) -> EmlScan:
    """Walk ``directory`` for ``.eml`` files within a bound, and say what happened.

    Four properties, each one measured rather than assumed:

    *   **Bounded by count and by depth.** ``max_files`` and ``max_depth`` are
        refused the moment the walk needs them, not checked at the end, so an
        absurd root costs milliseconds instead of minutes.
    *   **No symlink leaves the root.** Neither a symlinked directory nor a
        symlinked file is followed, and neither is counted as found: a corpus
        that links to a network share is the bounded walk that is still
        unbounded. Skipped links are counted in ``symlinks_skipped``.
    *   **System trees are refused by name.** ``/proc``, ``/sys``, ``/dev`` and
        ``/run`` are never descended even inside the depth bound, and a root that
        resolves inside one is refused outright.
    *   **A hit is loud.** Unless ``allow_partial`` is set, a bound raises
        :class:`DirectoryScanError` carrying this scan; with it set, the bound is
        recorded on the result so a partial reading cannot be mistaken for a
        complete one.

    Order stays deterministic: the paths are sorted exactly as the previous
    ``rglob`` walk sorted them, because a batch run that reorders makes recorded
    replay responses stop matching.
    """
    root = Path(directory)
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    root_text = str(root)
    real_root = os.path.realpath(root_text)

    inside_system_tree = _system_tree(real_root)
    if inside_system_tree:
        partial = EmlScan(
            root=root_text,
            paths=(),
            max_files=max_files,
            max_depth=max_depth,
            directories_visited=0,
            symlinks_skipped=0,
            trees_pruned=(inside_system_tree,),
            bound=BOUND_ROOT,
        )
        if allow_partial:
            return partial
        raise DirectoryScanError(BOUND_ROOT, partial.refusal(), partial)

    found: list[Path] = []
    visited = 0
    symlinks_skipped = 0
    trees_pruned: list[str] = []
    bound: str | None = None

    for dirpath, dirnames, filenames in os.walk(
        root_text, topdown=True, followlinks=False
    ):
        visited += 1
        depth = _depth_of(dirpath, root_text)
        keep: list[str] = []
        for name in sorted(dirnames):
            child = os.path.join(dirpath, name)
            if os.path.islink(child):
                # A symlinked directory is not a directory we own the contents
                # of. os.walk already refuses to follow it; skipping the name
                # keeps the count honest about what was not looked at.
                symlinks_skipped += 1
                continue
            tree = _system_tree(os.path.realpath(child))
            if tree:
                if tree not in trees_pruned:
                    trees_pruned.append(tree)
                continue
            if depth + 1 > max_depth:
                bound = bound or BOUND_DEPTH
                continue
            keep.append(name)
        dirnames[:] = keep

        for name in sorted(filenames):
            if not name.endswith(".eml"):
                continue
            candidate = os.path.join(dirpath, name)
            if os.path.islink(candidate):
                target = os.path.realpath(candidate)
                if not _inside(target, real_root):
                    symlinks_skipped += 1
                    continue
            if not os.path.isfile(candidate):
                continue
            found.append(Path(candidate))
            if len(found) > max_files:
                bound = BOUND_FILES
                break
        if bound is not None:
            break

    scan = EmlScan(
        root=root_text,
        # A file-bound hit counted one past the ceiling to discover it; the scan
        # reports the ceiling's worth, so a partial scan never exceeds the number
        # the caller asked to be bounded by.
        paths=tuple(sorted(found))[:max_files],
        max_files=max_files,
        max_depth=max_depth,
        directories_visited=visited,
        symlinks_skipped=symlinks_skipped,
        trees_pruned=tuple(sorted(set(trees_pruned))),
        bound=bound,
    )
    if scan.bound is not None and not allow_partial:
        raise DirectoryScanError(scan.bound, scan.refusal(), scan)
    return scan


def _depth_of(dirpath: str, root_text: str) -> int:
    """Levels below ``root_text``; the root itself is depth 0."""
    try:
        relative = os.path.relpath(dirpath, root_text)
    except ValueError:  # pragma: no cover - a different drive on Windows
        return 0
    if relative in (".", ""):
        return 0
    return len([part for part in relative.split(os.sep) if part not in ("", ".")])


def iter_eml_dir(
    directory: str | Path,
    *,
    max_files: int = DEFAULT_MAX_EML_FILES,
    max_depth: int = DEFAULT_MAX_EML_DEPTH,
    allow_partial: bool = False,
) -> Iterator[Path]:
    """Yield ``.eml`` files under ``directory``, sorted for determinism, bounded.

    The bound lives here rather than in each caller, so every consumer of the
    walk -- the MCP batch tool, the directory source, the CLI -- inherits the same
    ceiling and the same refusal. ``allow_partial`` is the explicit opt-in: with
    it the walk stops at the bound and returns what it saw, and the caller that
    used it has to say so, because :func:`scan_eml_dir` records the bound on the
    result.
    """
    yield from scan_eml_dir(
        directory, max_files=max_files, max_depth=max_depth, allow_partial=allow_partial
    ).paths
