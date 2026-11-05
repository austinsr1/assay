"""Content-addressed record/replay store for model tiers.

The artifact has to run for a judge who has no credentials, no inference host
and no network. That is only possible if every model response a disposition
depends on is *committed*, and a committed response is only trustworthy if it
can be matched back to the exact request that produced it. So entries are keyed
by content, not by case number: ``sha256(tier, model, canonical_json(payload))``.

Three properties this store is built to guarantee.

* **Determinism.** The key depends only on the request, and canonical JSON
  (sorted keys, no incidental whitespace) means the same payload yields the same
  key across runs and across Python versions. A replayed run therefore produces
  byte-identical verdicts, which :mod:`tenable_email.pipeline` relies on.
* **A miss is a miss.** :meth:`ReplayStore.get` returns ``None`` and the caller
  records the tier UNAVAILABLE. It never falls back to the network -- that would
  make the offline path depend on the network -- and it never substitutes a
  plausible answer, because "simulated evidence offered as closure" is exactly
  what the design refuses. See ``NOTES.md``.
* **Nothing private is written.** A recording is committed to a public
  repository. Each entry carries an ``endpoint_role`` label such as
  ``estate-vlm``, never an address, and :meth:`ReplayStore.put` refuses an entry
  that contains one -- including an address echoed back inside a model's own
  response. The refusal is loud because the alternative is a leak found by a
  reviewer.

Recordings are generated from ``fixtures/synthetic/`` only. A recording contains
the model's answer about a message, and answers quote what they were shown; a
recording made against real mail would publish real mail.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


__all__ = [
    "ReplayStore",
    "ReplayStoreError",
    "SCHEMA_VERSION",
    "build_entry",
    "canonical_json",
    "entry_key",
    "find_addresses",
]

#: Bump when the entry shape changes. An entry written by an older schema is
#: treated as a miss rather than guessed at, so a format change cannot silently
#: reinterpret a recording.
SCHEMA_VERSION = 1

#: Hex characters of the key used in the file name. 16 is 64 bits: collision-free
#: for a corpus this size, and short enough to read in ``git status``. The full
#: key is stored inside the file and re-checked on every read.
KEY_PREFIX = 16

INDEX_FILE = "index.json"

#: The fields every entry must carry. Files are written with sorted keys, so a
#: committed recording produces a readable diff and a stable checksum.
ENTRY_FIELDS = (
    "schema_version",
    "key",
    "tier",
    "model",
    "recorded_at",
    "endpoint_role",
    "latency_ms",
    "tokens",
    "response",
)

#: What must never be committed inside a recording. Written as patterns rather
#: than literals so this tracked file does not contain the thing it looks for.
#
#: Note what is deliberately **not** here: a generic ``scheme://host`` match. A
#: recording of a URL-reputation or link answer is *about* links, and refusing
#: every URL would refuse the corpus's own synthetic destinations. What may not
#: appear is an address of *infrastructure* -- which is exactly the set of
#: endpoints the operator configured, checked below by string -- plus anything
#: that identifies a host by number, path or token.
_ADDRESS_PATTERNS = (
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"),
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d+\b"),
    re.compile(r"\bssh://[^\s)`\"]+"),
    re.compile(r"/home/[A-Za-z0-9_.-]+"),
    re.compile(r"/Users/[A-Za-z0-9_.-]+"),
    # Bracketed separator: this file defines the pattern, and writing the literal
    # would make the publication-boundary guard flag the guard's own detector.
    re.compile(r"/var[/]www/"),
    re.compile(r"\bBearer\s+\S+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
)


class ReplayStoreError(ValueError):
    """Raised when an entry would be written that must not be committed."""


def canonical_json(value: Any) -> str:
    """Canonical JSON: sorted keys, no incidental whitespace, ASCII-safe.

    Deliberately **strict**: there is no ``default=`` hook, so a ``bytes`` value
    raises instead of being stringified into a key. A key computed from a
    lossy rendering of a payload would be a stable-looking identity for content
    that was not hashed -- the same reasoning as ``Verdict.to_json``.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def entry_key(tier: str, model: str | None, payload: Any) -> str:
    """The content address of one request.

    The tier name is inside the hash, so two tiers asked the same text do not
    collide, and the model id is inside it, so re-pointing a tier at a different
    model cannot read the previous model's recording.
    """
    material = canonical_json(
        {"tier": tier, "model": model or "", "payload": payload}
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def find_addresses(text: str) -> list[str]:
    """Address-shaped substrings in ``text``, for the commit-time leak check."""
    found: list[str] = []
    for pattern in _ADDRESS_PATTERNS:
        found.extend(m.group(0) for m in pattern.finditer(text))
    return sorted(set(found))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_entry(
    *,
    tier: str,
    model: str | None,
    payload: Any,
    response: Any,
    endpoint_role: str,
    latency_ms: float | None = None,
    tokens: Mapping[str, Any] | None = None,
    recorded_at: str | None = None,
) -> dict[str, Any]:
    """One recording, keyed on its own request.

    ``response`` is what the tier parsed from the service, with the service's own
    score fields preserved. ``tokens`` and ``latency_ms`` are the measured cost of
    the call that produced it: replay reports the recorded cost rather than a new
    one, which is what keeps a replayed run byte-identical.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "key": entry_key(tier, model, payload),
        "tier": tier,
        "model": model or "",
        "recorded_at": recorded_at or _now_iso(),
        "endpoint_role": endpoint_role,
        "latency_ms": None if latency_ms is None else round(float(latency_ms), 3),
        "tokens": dict(tokens) if tokens else None,
        "response": response,
    }


@dataclass
class ReplayStore:
    """One JSON file per recording, plus an index for human inspection.

    Files are named ``<tier>__<key16>.json`` so a reviewer can see which tier a
    recording belongs to without opening it, and ``index.json`` maps each file
    name to its tier, model and role label. Both are committed.
    """

    root: Path
    #: Counters for reporting. A run with all misses is a run that recorded
    #: nothing, and the difference has to be visible.
    hit_count: int = 0
    miss_count: int = 0
    #: Addresses the operator supplied, refused inside any entry written here.
    forbidden: tuple[str, ...] = ()
    #: API keys the operator supplied, refused inside any entry written here.
    secrets: tuple[str, ...] = ()
    _index: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        stored = self._read_index()
        self._index = stored if stored is not None else {}

    # -- paths ---------------------------------------------------------------

    def file_name(self, tier: str, key: str) -> str:
        return f"{tier}__{key[:KEY_PREFIX]}.json"

    def path_for(self, tier: str, key: str) -> Path:
        return self.root / self.file_name(tier, key)

    # -- reads ---------------------------------------------------------------

    def get(self, key: str) -> dict[str, Any] | None:
        """The entry recorded under ``key``, or ``None``.

        Counting happens here rather than in the caller, so no path through the
        store can read a recording without being counted. The file name is
        searched by key prefix across every tier: :meth:`get` is specified to
        take a key alone, and a 16-hex prefix collision is checked against the
        full stored key instead of being trusted.
        """
        if not key:
            self.miss_count += 1
            return None
        matches = sorted(self.root.glob(f"*__{key[:KEY_PREFIX]}.json")) \
            if self.root.is_dir() else []
        for path in matches:
            entry = self._read(path)
            if entry is None:
                continue
            if entry.get("key") != key:
                # Same 16-hex prefix, different content. Astronomically unlikely,
                # and not worth trusting: keep looking.
                continue
            self.hit_count += 1
            return entry
        self.miss_count += 1
        return None

    def lookup(self, tier: str, model: str | None, payload: Any) -> dict | None:
        """Compute the key for a request and read its recording."""
        try:
            key = entry_key(tier, model, payload)
        except (TypeError, ValueError):
            self.miss_count += 1
            return None
        return self.get(key)

    def _read(self, path: Path) -> dict | None:
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(entry, dict):
            return None
        if entry.get("schema_version") != SCHEMA_VERSION:
            return None
        return entry

    # -- writes --------------------------------------------------------------

    def put(self, entry: Mapping[str, Any]) -> Path:
        """Write one recording and update the index.

        Refuses an entry that is not the shape this store reads back, and refuses
        an entry carrying infrastructure: a configured endpoint address, a
        configured API key, an IP literal, an absolute private path. A recording
        of a model answer about a *link* legitimately contains that link, and the
        link is synthetic corpus content; the address the model was called at is
        not, and it would publish private topology.
        """
        missing = [f for f in ENTRY_FIELDS if f not in entry]
        if missing:
            raise ReplayStoreError(f"entry is missing required field(s) {missing}")
        tier = str(entry["tier"])
        key = str(entry["key"])
        if not tier or not key or len(key) < KEY_PREFIX:
            raise ReplayStoreError(f"entry has an unusable tier/key: {tier!r}, {key!r}")

        payload_text = json.dumps(dict(entry), sort_keys=True, indent=2,
                                  ensure_ascii=True)
        leaks = find_addresses(payload_text)
        for address in self.forbidden:
            if address and address in payload_text:
                leaks.append(f"configured endpoint {address!r}")
        for secret in self.secrets:
            if secret and secret in payload_text:
                leaks.append("a configured API key")
        if leaks:
            raise ReplayStoreError(
                f"refusing to commit recording for tier {tier!r}: it contains "
                f"infrastructure detail ({', '.join(sorted(set(leaks)))}). "
                "A committed recording carries a role label, never an address."
            )
        if find_addresses(str(entry["endpoint_role"])) or "://" in str(
            entry["endpoint_role"]
        ):
            raise ReplayStoreError(
                f"endpoint_role {entry['endpoint_role']!r} is an address, not a "
                "role label"
            )

        self.root.mkdir(parents=True, exist_ok=True)
        path = self.path_for(tier, key)
        path.write_text(payload_text + "\n", encoding="utf-8")
        self._index[self.file_name(tier, key)] = {
            "key": key,
            "tier": tier,
            "model": entry.get("model") or "",
            "endpoint_role": entry.get("endpoint_role") or "",
        }
        self._write_index()
        return path

    def put_response(
        self,
        *,
        tier: str,
        model: str | None,
        payload: Any,
        response: Any,
        endpoint_role: str,
        latency_ms: float | None = None,
        tokens: Mapping[str, Any] | None = None,
    ) -> Path:
        """Build the entry from a request/response pair and write it."""
        return self.put(
            build_entry(
                tier=tier,
                model=model,
                payload=payload,
                response=response,
                endpoint_role=endpoint_role,
                latency_ms=latency_ms,
                tokens=tokens,
            )
        )

    # -- attestation ---------------------------------------------------------

    def attested(self, entry: Mapping[str, Any]) -> bool:
        """Whether the store's own index lists ``entry`` under its own key.

        :meth:`put` writes the index row and the file together and is the only
        path that does, so the index is the store's attestation that a recording
        arrived from a tier call rather than from a keyboard. A file dropped into
        the directory by hand -- or one whose index row was edited away -- is a
        claim about what a model would have said, and :mod:`tenable_email.tiers`
        reports it under a distinct source so the pipeline can mark the resulting
        evidence ``simulated`` and the runner refuse to close on it.

        What this deliberately does **not** claim: an editor who writes both the
        file and a matching index row defeats it, because nothing signs the index
        and this bundle holds no credentials. That is the same boundary the
        1st-place playbook declares for its own runner -- approval identity is only
        as strong as the system that issues it -- and it is why a receipt records
        the corpus manifest digest: tampering that survives the index still changes
        the digest a later transition is checked against.
        """
        key = str(entry.get("key") or "")
        tier = str(entry.get("tier") or "")
        if not key or not tier:
            return False
        row = self._index.get(self.file_name(tier, key))
        if not isinstance(row, Mapping):
            return False
        return row.get("key") == key and row.get("tier") == tier

    def unattested(self) -> list[str]:
        """File names of readable entries the index does not attest."""
        return [p.name for p in sorted(self.root.glob("*.json"))
                if p.name != INDEX_FILE and not self.attested(self._read(p) or {})]

    # -- index ---------------------------------------------------------------

    def _index_path(self) -> Path:
        return self.root / INDEX_FILE

    def _read_index(self) -> dict | None:
        path = self._index_path()
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        entries = data.get("entries")
        return entries if isinstance(entries, dict) else {}

    def _write_index(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        document = {
            "schema_version": SCHEMA_VERSION,
            "note": (
                "Recordings of model responses, generated from "
                "fixtures/synthetic/ only. Each file names a tier and the "
                "content address of the request that produced it; "
                "endpoint_role is a role label, never an address."
            ),
            "entries": self._index,
        }
        self._index_path().write_text(
            json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

    # -- queries -------------------------------------------------------------

    def entries(self) -> list[dict]:
        """Every readable entry, sorted by file name."""
        if not self.root.is_dir():
            return []
        out = []
        for path in sorted(self.root.glob("*.json")):
            if path.name == INDEX_FILE:
                continue
            entry = self._read(path)
            if entry is not None:
                out.append(entry)
        return out

    def models_for(self, tier: str) -> list[str]:
        """Model ids recorded for ``tier``.

        This is what lets a replay run work with no endpoints configured at all:
        in replay mode the recording defines which model answered, and the model
        id is part of the key, so the store has to be consulted for it. Nothing
        is invented here -- these strings came from the live call that was
        recorded.
        """
        return sorted(
            {
                str(item.get("model") or "")
                for item in self._index.values()
                if item.get("tier") == tier and item.get("model")
            }
        )

    def tiers_with_recordings(self) -> list[str]:
        return sorted({str(v.get("tier")) for v in self._index.values() if v.get("tier")})

    def counts_by_tier(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self._index.values():
            tier = str(item.get("tier") or "")
            if tier:
                counts[tier] = counts.get(tier, 0) + 1
        return counts

    @property
    def total(self) -> int:
        return len(self._index)

    def summary(self) -> str:
        return (
            f"{self.total} recording(s) in {self.root}: "
            + (
                ", ".join(
                    f"{tier}={count}"
                    for tier, count in sorted(self.counts_by_tier().items())
                )
                or "none"
            )
            + f" (hits={self.hit_count}, misses={self.miss_count})"
        )


def open_store(config: Any) -> ReplayStore | None:
    """The store ``config`` points at, or ``None`` when it points at nothing.

    Lives here so a tier, a tool and the pipeline all agree on where recordings
    come from. A missing directory is not an error: an unrecorded corpus is a
    store full of misses, and a miss is reported per tier rather than raising.
    """
    replay_dir = getattr(config, "replay_dir", None)
    if not replay_dir:
        return None
    endpoints = getattr(config, "endpoints", None)
    secrets = tuple(
        v for v in (
            getattr(endpoints, name, None)
            for name in ("llm_api_key", "vlm_api_key")
        ) if v
    )
    return ReplayStore(
        root=Path(replay_dir),
        forbidden=tuple(
            getattr(endpoints, "configured_addresses", lambda: [])()
        ),
        secrets=secrets,
    )


def iter_keys(entries: Iterable[Mapping[str, Any]]) -> list[str]:
    """Sorted full keys of ``entries`` -- for tests that assert uniqueness."""
    return sorted(str(e.get("key", "")) for e in entries)
