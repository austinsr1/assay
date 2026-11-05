"""Gmail API client -- read the reported message, then label what we concluded.

The reference workflow fetched the message from a PhishER pre-signed ``rawUrl``.
The Workspace equivalent is ``users.messages.get``, and the alert payload hands us
both arguments: ``GmailMessageInfo.messageId`` and ``GmailMessageInfo.recipient``.
Reading another user's mailbox is what domain-wide delegation buys; without it
every fetch for a mailbox other than the token owner's comes back 403, and this
module reports that as ``not_authorized_or_delegated`` rather than as "no such
message", because the two need different fixes.

Two behaviours are load-bearing and both come from how Gmail actually behaves:

* **Spam and trash are included by default.** A user who reports a message as
  phishing usually moves it to Spam, and ``messages.list`` omits Spam and Trash
  unless told otherwise. Defaulting to ``include_spam_trash=True`` is the
  difference between finding the reported message and concluding there was nothing
  to read. ``messages.get`` by id works regardless of labels.
* **Raw is the format the parser wants.** ``format=raw`` returns the RFC 822
  message base64url-encoded, which is exactly the input
  :func:`tenable_email.parse.parse_message` takes. ``format=metadata`` and
  ``format=full`` are also supported for the header-set path.

This module never parses MIME. Parsing lives in :mod:`tenable_email.parse`; one
parser, one place where a malformed message becomes a finding.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

__all__ = [
    "AI_LABEL_PREFIX",
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT_SECONDS",
    "TOKEN_ENV_VAR",
    "GmailClient",
    "GmailConfigError",
    "GmailError",
    "Message",
    "MessageFetch",
    "MessageList",
    "decode_raw",
    "label_for_disposition",
]

#: Public, universal endpoint -- not an estate address, so a default is honest here.
#: The path segment matters: the Gmail discovery document gives `rootUrl
#: https://gmail.googleapis.com/` with `messages.get` at `gmail/v1/users/{userId}/
#: messages/{id}`, so the API base is `.../gmail/v1`, not `.../v1`. A request to the
#: shorter form is answered with a bare HTML 404 rather than a JSON error, which is
#: easy to mistake for a permissions problem.
DEFAULT_BASE_URL = "https://gmail.googleapis.com/gmail/v1"

#: Where a pre-minted OAuth access token is read from when no provider is given.
#: The same token serves both APIs; the scopes differ
#: (``gmail.readonly`` / ``gmail.modify`` / ``gmail.labels``).
TOKEN_ENV_VAR = "TENABLE_EMAIL_GOOGLE_ACCESS_TOKEN"

DEFAULT_TIMEOUT_SECONDS = 30.0

#: Every label this tool owns, so a previous verdict can be replaced without
#: touching the user's own labels. Mirrors the reference's ``AI:THREAT`` tag,
#: expressed the way Gmail wants it: a user label name.
AI_LABEL_PREFIX = "AI-"

#: The system labels Gmail will not let us add, so a request that asks for one is
#: a bug rather than a permission problem, and is refused before it is sent.
SYSTEM_LABELS = frozenset(
    {"INBOX", "SPAM", "TRASH", "UNREAD", "STARRED", "IMPORTANT", "SENT", "DRAFT", "CATEGORY_PERSONAL",
     "CATEGORY_SOCIAL", "CATEGORY_PROMOTIONS", "CATEGORY_UPDATES", "CATEGORY_FORUMS"}
)

FORMATS = ("minimal", "metadata", "full", "raw")

#: The fields that make a Gmail response a message. A 200 carrying none of them --
#: an empty body, say -- is not a message, and treating it as one is how a blank
#: response becomes a blank verdict.
_MESSAGE_FIELDS = ("id", "threadId", "labelIds", "snippet", "payload", "raw", "sizeEstimate")

#: Checked before decoding: ``base64.b64decode`` on 3.9 silently discards
#: characters outside the alphabet, so ``"!!!!"`` decodes to an empty body there
#: and raises on 3.11+. Validating first gives one answer on every interpreter.
_BASE64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
)


class GmailError(Exception):
    """A call to Gmail did not produce a message. ``reason`` is recordable."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason if not detail else f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


class GmailConfigError(GmailError):
    """The client is not configured; the reason names the field that is empty."""


@dataclass(frozen=True)
class Message:
    """What Gmail returned for one message.

    ``raw`` is populated only for ``format=raw``; ``headers`` only for
    ``metadata``/``full``. Both are kept as returned, not normalised, because the
    authentication findings the pipeline reports come from the header set and must
    be traceable to what the API actually said.
    """

    message_id: str
    thread_id: str | None = None
    label_ids: tuple[str, ...] = ()
    internal_date: str | None = None
    snippet: str | None = None
    size_estimate: int | None = None
    raw: bytes | None = None
    headers: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    raw_response: Mapping[str, Any] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        """First value for ``name``, case-insensitively, or ``None``."""
        target = name.strip().lower()
        for key, values in self.headers.items():
            if key.lower() == target and values:
                return values[0]
        return None

    def header_values(self, name: str) -> tuple[str, ...]:
        target = name.strip().lower()
        for key, values in self.headers.items():
            if key.lower() == target:
                return values
        return ()

    @classmethod
    def from_response(cls, message_id: str, fmt: str, payload: Mapping[str, Any]) -> "Message":
        """Build a Message from a ``messages.get`` body for any requested format.

        ``raw`` is only present when it was asked for; ``headers`` only for
        ``metadata``/``full``. The response body is kept verbatim in
        ``raw_response`` so a finding can be traced back to the exact bytes the API
        returned.
        """
        raw_value = _text(payload.get("raw"))
        raw_bytes = decode_raw(raw_value) if raw_value and fmt == "raw" else None
        return cls(
            message_id=_text(payload.get("id")) or message_id,
            thread_id=_text(payload.get("threadId")),
            label_ids=tuple(
                _text(x) for x in (payload.get("labelIds") or ()) if _text(x)
            ),
            internal_date=_text(payload.get("internalDate")),
            snippet=_text(payload.get("snippet")),
            size_estimate=_int(payload.get("sizeEstimate")),
            raw=raw_bytes,
            headers=_collect_headers(payload) if fmt in ("metadata", "full") else {},
            raw_response=dict(payload),
        )


@dataclass(frozen=True)
class MessageFetch:
    """Failure is a value: ``ok=False`` carries the reason, ``message`` is None."""

    ok: bool
    message: Message | None = None
    error: str = ""

    @classmethod
    def failure(cls, error: str) -> "MessageFetch":
        return cls(ok=False, message=None, error=error)


@dataclass(frozen=True)
class MessageList:
    ids: tuple[str, ...] = ()
    next_page_token: str | None = None
    result_count: int | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)


def decode_raw(value: str) -> bytes:
    """Decode Gmail's base64url body, tolerating the missing padding Gmail sends."""
    if value and not set(value) <= _BASE64URL_ALPHABET:
        raise GmailError("raw_not_decodable", f"{len(value)} characters of base64url")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise GmailError("raw_not_decodable", f"{len(value)} characters of base64url") from None


def label_for_disposition(disposition: Any) -> str | None:
    """The Gmail label a verdict implies, or ``None`` when it implies none.

    ``manual_review`` and ``unknown`` deliberately have no label: labelling a
    message we did not decide about would tell the analyst more than we know.
    """
    name = getattr(disposition, "value", disposition)
    key = str(name).strip().lower() if name is not None else ""
    return {
        "threat": f"{AI_LABEL_PREFIX}THREAT",
        "spam": f"{AI_LABEL_PREFIX}SPAM",
        "clean": f"{AI_LABEL_PREFIX}CLEAN",
    }.get(key)


@dataclass(frozen=True)
class _Response:
    """One HTTP call's outcome, with status, document and reason kept apart.

    Folding "the body was not JSON" together with "the body was this object" into a
    single slot is how a client reports a success it never parsed. Three fields,
    one meaning each, so every caller asks the question it actually means to ask.
    """

    status: int
    document: Mapping[str, Any] | None = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status < 400 and not self.error

    @property
    def reason(self) -> str:
        return f"http_{self.status}" if self.status >= 400 else self.error


def _decode_response(status: int, text: str) -> _Response:
    if status >= 400:
        return _Response(status, None, _error_message(text))
    if not text.strip():
        return _Response(status, {}, "")
    try:
        decoded = json.loads(text)
    except (ValueError, TypeError):
        return _Response(status, None, "malformed_response")
    if isinstance(decoded, Mapping):
        return _Response(status, decoded, "")
    return _Response(status, None, "malformed_response")


class GmailClient:
    """Read, list and label. ``transport`` is injectable; the default is urllib.

    The transport contract is ``(method, url, headers, body_bytes) -> (status,
    body_text)``, which lets a test assert the exact request -- method, URL and
    body -- without a network, and lets the write paths be exercised in dry-run
    before any real mailbox is touched.
    """

    def __init__(
        self,
        *,
        token: str | None = None,
        token_provider: Callable[[], str] | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        transport: Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, str]] | None = None,
    ) -> None:
        if token is None and token_provider is None:
            env_token = os.environ.get(TOKEN_ENV_VAR, "").strip()
            if env_token:
                token = env_token
            else:
                raise GmailConfigError(
                    "no_token",
                    f"pass token=/token_provider= or set {TOKEN_ENV_VAR}",
                )
        if not base_url:
            raise GmailConfigError("no_base_url", "empty base_url for GmailClient")

        self._token = token
        self._token_provider = token_provider
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self._transport = transport or self._default_transport

    # -- plumbing ----------------------------------------------------------

    def _access_token(self) -> str:
        if self._token_provider is not None:
            token = self._token_provider()
            if not token:
                raise GmailConfigError("no_token", "token_provider returned nothing")
            return token
        assert self._token is not None
        return self._token

    def _default_transport(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> tuple[int, str]:
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return int(response.status), response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise GmailError("unreachable", f"{url}: {exc}") from None

    def _call(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> _Response:
        """One HTTP call. A transport failure raises; an HTTP refusal is a value."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {"Authorization": f"Bearer {self._access_token()}", "Accept": "application/json"}
        payload = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(dict(body)).encode("utf-8")
        status, text = self._transport(method, url, headers, payload)
        return _decode_response(status, text)

    # -- reads -------------------------------------------------------------

    def fetch(
        self,
        user: str,
        message_id: str,
        *,
        fmt: str = "raw",
    ) -> MessageFetch:
        """``users.messages.get`` as a value, never as a raised surprise.

        ``user`` is the mailbox the message lives in -- for a reported phish that
        is ``GmailMessageInfo.recipient``. A 404 and a 403 are reported
        differently on purpose: a missing message means the message is gone, a
        refused one means the token does not reach that mailbox, and only the first
        is fixed by re-reading the alert.
        """
        if not user:
            return MessageFetch.failure("no_user")
        if not message_id:
            return MessageFetch.failure("no_message_id")
        if fmt not in FORMATS:
            return MessageFetch.failure(f"invalid_format:{fmt}")

        path = f"users/{_quote(user)}/messages/{_quote(message_id)}"
        response = self._call("GET", f"{path}?format={fmt}")
        if response.status == 404:
            return MessageFetch.failure("message_not_found")
        if response.status == 403:
            return MessageFetch.failure("not_authorized_or_delegated")
        if not response.ok:
            return MessageFetch.failure(response.reason)
        document = response.document or {}
        if not any(field in document for field in _MESSAGE_FIELDS):
            return MessageFetch.failure("malformed_response")
        return MessageFetch(ok=True, message=Message.from_response(message_id, fmt, document))

    def list_messages(
        self,
        user: str,
        *,
        query: str | None = None,
        include_spam_trash: bool = True,
        max_results: int = 100,
        page_token: str | None = None,
        label_ids: tuple[str, ...] = (),
    ) -> MessageList:
        """``users.messages.list``. Spam and Trash are included by default.

        ``query`` cannot be used on the ``gmail.metadata`` scope -- the API says so
        -- so a metadata-only deployment should expect ``http_403`` here rather
        than an empty result.
        """
        if not user:
            return MessageList()
        params: dict[str, str] = {"maxResults": str(int(max_results))}
        if query:
            params["q"] = query
        if include_spam_trash:
            params["includeSpamTrash"] = "true"
        if page_token:
            params["pageToken"] = page_token
        if label_ids:
            params["labelIds"] = ",".join(label_ids)
        response = self._call("GET", f"users/{_quote(user)}/messages?{urllib.parse.urlencode(params)}")
        if not response.ok:
            return MessageList()
        payload = response.document or {}
        messages = payload.get("messages") or ()
        if isinstance(messages, Mapping):
            messages = (messages,)
        return MessageList(
            ids=tuple(_text(m.get("id")) for m in messages if isinstance(m, Mapping) and _text(m.get("id"))),
            next_page_token=_text(payload.get("nextPageToken")),
            result_count=_int(payload.get("resultCount")),
            raw=dict(payload),
        )

    def list_labels(self, user: str) -> tuple[tuple[str, str], ...]:
        """``users.labels.list`` as ``(id, name)`` pairs, system and user labels."""
        if not user:
            return ()
        response = self._call("GET", f"users/{_quote(user)}/labels")
        if not response.ok:
            return ()
        payload = response.document or {}
        labels = payload.get("labels") or ()
        if isinstance(labels, Mapping):
            labels = (labels,)
        return tuple(
            (_text(l.get("id")) or "", _text(l.get("name")) or "")
            for l in labels
            if isinstance(l, Mapping)
        )

    # -- writes ------------------------------------------------------------

    def create_label(self, user: str, name: str) -> str | None:
        """``users.labels.create``. Returns the new label id, or ``None``.

        Every label this tool writes is prefixed (:data:`AI_LABEL_PREFIX`) so a
        reviewer can see and remove exactly what the agent did.
        """
        if not user or not name:
            return None
        if name.upper() in SYSTEM_LABELS:
            return None  # A system label cannot be created; asking is a bug, not a permission gap.
        response = self._call("POST", f"users/{_quote(user)}/labels", {"name": name})
        if not response.ok:
            return None
        return _text((response.document or {}).get("id"))

    def modify_labels(
        self,
        user: str,
        message_id: str,
        *,
        add: tuple[str, ...] = (),
        remove: tuple[str, ...] = (),
    ) -> bool:
        """``users.messages.modify``. Needs ``gmail.modify`` (or ``gmail.labels``)."""
        if not user or not message_id:
            return False
        if not add and not remove:
            return False  # An empty mutation is not a success; it is a caller that decided nothing.
        body: dict[str, list[str]] = {}
        if add:
            body["addLabelIds"] = [a for a in add if a]
        if remove:
            body["removeLabelIds"] = [r for r in remove if r]
        response = self._call(
            "POST", f"users/{_quote(user)}/messages/{_quote(message_id)}/modify", body
        )
        return response.ok


def _quote(value: str) -> str:
    """Percent-encode a mailbox or message id; ``user@x.edu`` is not path-safe."""
    return urllib.parse.quote(value, safe="")


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    return str(value)


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _error_message(text: str) -> str:
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        return text.strip()[:200]
    if isinstance(document, Mapping):
        error = document.get("error")
        if isinstance(error, Mapping):
            return _text(error.get("message")) or _text(error.get("status")) or ""
    return text.strip()[:200]


def _collect_headers(payload: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """Header set from a ``full``/``metadata`` payload, including every MIME part.

    Gmail puts the top-level headers on ``payload.headers`` and per-part headers on
    ``payload.parts[].headers``. Both are collected: the authentication results a
    receiving MTA recorded can appear on either, and dropping the nested ones is
    how a forged ``Authentication-Results`` outranks a real one.
    """
    out: dict[str, list[str]] = {}

    def absorb(raw: Any) -> None:
        if not isinstance(raw, list):
            return
        for entry in raw:
            if not isinstance(entry, Mapping):
                continue
            name = _text(entry.get("name"))
            value = entry.get("value")
            if name is None or value is None:
                continue
            out.setdefault(name, []).append(str(value))

    absorb(payload.get("headers"))
    for part in payload.get("parts") or ():
        if isinstance(part, Mapping):
            absorb(part.get("headers"))
            for sub in part.get("parts") or ():
                if isinstance(sub, Mapping):
                    absorb(sub.get("headers"))
    return {name: tuple(values) for name, values in out.items()}



