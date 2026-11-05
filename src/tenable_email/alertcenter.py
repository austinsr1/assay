"""Google Workspace Alert Center client -- the intake source for reported phish.

This is the module that replaces the reference playbook's PhishER GraphQL query.
Where PhishER answered ``phisherMessages(query: "reported_at:<today>")``, Alert
Center answers a REST query with typed filter fields, and the payload it returns
carries the Gmail message id and recipient that
:func:`tenable_email.gmail.GmailClient` needs in order to read the message.

Three rules, all of them the rules the rest of the package already follows.

1. **Failure is a value.** A call that is refused, unreachable or malformed
   raises :class:`AlertCenterError` carrying a ``reason`` the caller can record,
   and a client with no token raises :class:`AlertCenterConfigError` naming the
   environment field that is empty. Nothing here defaults an address, and nothing
   here invents an alert.
2. **An unknown payload shape is kept, not guessed.** ``Alert.data`` is documented
   as an open object carrying an ``@type`` URL, and its shape depends on the alert
   type. A type this module does not know is returned with ``known_type=False`` and
   the raw payload retained, so a Google-side change becomes a visible gap rather
   than a silently empty field.
3. **The scope is explicit.** The operator's scope is the alert type
   :data:`USER_REPORTED_PHISHING`. That value is the literal string Google uses --
   ``Alert.type`` is a plain string holding the display name, not an enum -- so it
   is a named constant here rather than a string repeated at each call site.

Authentication note. Minting an OAuth access token from a service-account key
requires RSA signing, which the standard library does not provide, and the shipped
core declares ``dependencies = []``. So this client takes a *token provider* and
leaves minting to the operator: an existing token through
:data:`TOKEN_ENV_VAR`, a token file (:func:`token_from_file`), or ``google-auth``
in an optional extra. That keeps the dependency claim true while still letting a
live tenant be queried.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT_SECONDS",
    "GMAIL_PHISHING_SOURCE",
    "MAX_PAGES",
    "TOKEN_ENV_VAR",
    "USER_REPORTED_PHISHING",
    "Alert",
    "AlertCenterClient",
    "AlertCenterConfigError",
    "AlertCenterError",
    "AlertSet",
    "GmailMessageInfo",
    "MailPhishing",
    "decode_alert",
    "feedback_for_disposition",
    "build_filter",
    "token_from_file",
]

#: Public, universal endpoint -- not an estate address, so a default is honest here.
DEFAULT_BASE_URL = "https://alertcenter.googleapis.com/v1beta1"

#: ``Alert.type`` value for the operator's scope, verified against Google's
#: alert-types reference. It is a display string, not an enum member.
USER_REPORTED_PHISHING = "User reported phishing"

#: ``Alert.source`` value for alerts raised by Gmail. Optional in a filter, but
#: the documented example pairs it with the type, and it excludes the same payload
#: raised by other sources.
GMAIL_PHISHING_SOURCE = "Gmail phishing"

#: Where a pre-minted OAuth access token is read from when no provider is given.
TOKEN_ENV_VAR = "TENABLE_EMAIL_GOOGLE_ACCESS_TOKEN"

DEFAULT_TIMEOUT_SECONDS = 30.0

#: Pagination guard. A server that keeps handing back the same token would
#: otherwise spin forever; the reference workflow had the same class of guard
#: written as an explicit ``paginationCompleteWhen`` expression.
MAX_PAGES = 50

#: The only writable annotation on an alert, and it is an enum, not text. This is
#: the constraint that makes the reference's "post a comment" step unimplementable
#: against Alert Center.
FEEDBACK_TYPES = ("ALERT_FEEDBACK_TYPE_UNSPECIFIED", "NOT_USEFUL", "SOMEWHAT_USEFUL", "VERY_USEFUL")


class AlertCenterError(Exception):
    """A call to Alert Center did not produce an alert. ``reason`` is recordable."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason if not detail else f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


class AlertCenterConfigError(AlertCenterError):
    """The client is not configured; the reason names the field that is empty."""


@dataclass(frozen=True)
class GmailMessageInfo:
    """One message inside a Gmail-phishing alert payload.

    Every field is optional at the protocol level. ``subjectText``,
    ``messageBodySnippet`` and the two hashes are documented as available only for
    reported emails -- which is exactly the scope in use here -- so when the Gmail
    fetch itself fails the alert still carries a subject, a body snippet and
    attachment hashes to analyse.
    """

    message_id: str | None = None
    recipient: str | None = None
    subject_text: str | None = None
    message_body_snippet: str | None = None
    md5_hash_subject: str | None = None
    md5_hash_message_body: str | None = None
    attachments_sha256: tuple[str, ...] = ()
    date: str | None = None
    sent_time: str | None = None

    @property
    def has_body_evidence(self) -> bool:
        """True when the alert itself carries analysable content."""
        return bool(self.message_body_snippet or self.md5_hash_message_body)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "GmailMessageInfo":
        hashes = raw.get("attachmentsSha256Hash") or ()
        if isinstance(hashes, str):
            hashes = (hashes,)
        return cls(
            message_id=_text(raw.get("messageId")),
            recipient=_text(raw.get("recipient")),
            subject_text=_text(raw.get("subjectText")),
            message_body_snippet=_text(raw.get("messageBodySnippet")),
            md5_hash_subject=_text(raw.get("md5HashSubject")),
            md5_hash_message_body=_text(raw.get("md5HashMessageBody")),
            attachments_sha256=tuple(h for h in (str(x) for x in hashes) if h),
            date=_text(raw.get("date")),
            sent_time=_text(raw.get("sentTime")),
        )


@dataclass(frozen=True)
class MailPhishing:
    """The ``MailPhishing`` / ``PhishingSpike`` alert payload.

    ``PhishingSpike`` is deprecated and appears only in older alerts, but it
    carries the same fields minus ``systemActionType``, so it decodes here rather
    than becoming an unknown type.
    """

    messages: tuple[GmailMessageInfo, ...] = ()
    is_internal: bool | None = None
    system_action_type: str | None = None
    malicious_from_header: str | None = None
    malicious_display_name: str | None = None
    customer_primary_domain: str | None = None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "MailPhishing":
        messages = raw.get("messages") or ()
        if isinstance(messages, Mapping):
            messages = (messages,)
        entity = raw.get("maliciousEntity") or {}
        domain = raw.get("domainId") or {}
        is_internal = raw.get("isInternal")
        return cls(
            messages=tuple(
                GmailMessageInfo.from_dict(m) for m in messages if isinstance(m, Mapping)
            ),
            is_internal=None if is_internal is None else bool(is_internal),
            system_action_type=_text(raw.get("systemActionType")),
            malicious_from_header=_text(entity.get("fromHeader")) if isinstance(entity, Mapping) else None,
            malicious_display_name=_text(entity.get("displayName")) if isinstance(entity, Mapping) else None,
            customer_primary_domain=_text(domain.get("customerPrimaryDomain")) if isinstance(domain, Mapping) else None,
        )


@dataclass(frozen=True)
class Alert:
    """One alert, decoded as far as the protocol allows.

    ``known_type`` is False when ``data`` carried a type this module does not
    model. The raw payload is kept in ``raw`` either way, so a schema change on
    Google's side is observable instead of lossy.
    """

    alert_id: str
    type: str = ""
    source: str = ""
    create_time: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    etag: str | None = None
    deleted: bool = False
    security_investigation_tool_link: str | None = None
    data_type: str = ""
    mail_phishing: MailPhishing | None = None
    known_type: bool = True
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def messages(self) -> tuple[GmailMessageInfo, ...]:
        return self.mail_phishing.messages if self.mail_phishing is not None else ()

    @property
    def fetchable(self) -> bool:
        """True when at least one message carries a Gmail message id to fetch."""
        return any(m.message_id for m in self.messages)


@dataclass(frozen=True)
class AlertSet:
    """One page of ``alerts.list``, with the token needed to ask for the next."""

    alerts: tuple[Alert, ...] = ()
    next_page_token: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)


_MAILPHISHING_TYPES = ("mailphishing", "phishingspike")


def _text(value: Any) -> str | None:
    """Normalise a JSON value to ``str`` or ``None``; never to the string 'None'."""
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    return str(value)


def _unwrap_data(data: Any) -> tuple[str, Mapping[str, Any]]:
    """Return ``(@type, fields)`` from ``Alert.data``.

    ``data`` is documented as an object containing ``@type`` with a type URL, but
    SDKs and the REST surface have both been observed returning it as a
    JSON-encoded string. Both are accepted; neither is guessed.
    """
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (ValueError, TypeError):
            return "", {}
    if not isinstance(data, Mapping):
        return "", {}
    type_url = _text(data.get("@type")) or ""
    return type_url, data


def _short_type(type_url: str) -> str:
    """``type.googleapis.com/google.apps.alertcenter.type.MailPhishing`` -> ``MailPhishing``.

    The type URL has exactly one slash, so splitting on ``/`` alone leaves the whole
    dotted package name attached. Both the dotted form and a bare ``MailPhishing``
    have to resolve to the same thing, because the REST surface and the generated
    clients have both been seen.
    """
    tail = type_url.rsplit("/", 1)[-1].strip()
    return tail.rsplit(".", 1)[-1] if "." in tail else tail


def decode_alert(payload: Mapping[str, Any]) -> Alert:
    """Decode one alert object from ``alerts.list`` / ``alerts.get``."""
    if not isinstance(payload, Mapping):
        raise AlertCenterError("malformed_response", "alert entry is not an object")

    alert_id = _text(payload.get("alertId"))
    if not alert_id:
        raise AlertCenterError("malformed_response", "alert entry has no alertId")

    type_url, fields = _unwrap_data(payload.get("data"))
    short_type = _short_type(type_url) if type_url else ""
    mail: MailPhishing | None = None
    known = True
    if short_type and short_type.lower() in _MAILPHISHING_TYPES:
        mail = MailPhishing.from_dict(fields)
    elif not short_type and fields:
        # A payload with fields but no @type is a shape change, not an empty alert.
        known = False
    elif not short_type:
        # No data at all is legal (an alert with no payload), so it is not a gap.
        pass
    else:
        known = False

    return Alert(
        alert_id=alert_id,
        type=_text(payload.get("type")) or "",
        source=_text(payload.get("source")) or "",
        create_time=_text(payload.get("createTime")),
        start_time=_text(payload.get("startTime")),
        end_time=_text(payload.get("endTime")),
        etag=_text(payload.get("etag")),
        deleted=bool(payload.get("deleted", False)),
        security_investigation_tool_link=_text(payload.get("securityInvestigationToolLink")),
        data_type=short_type,
        mail_phishing=mail,
        known_type=known,
        raw=dict(payload),
    )


def build_filter(
    alert_type: str = USER_REPORTED_PHISHING,
    source: str | None = GMAIL_PHISHING_SOURCE,
    created_after: str | None = None,
) -> str:
    """Build an ``alerts.list`` filter string.

    The grammar is ``<field> <operator> <value>`` with quoted values. Google's own
    pages show both ``type:"x"`` and ``type="x"``; the reference form is used here
    because it is the one printed on the filter-fields page. ``source`` is optional
    -- pass ``None`` to query the type across every source -- and ``created_after``
    is an RFC 3339 timestamp, which is how the workflow replaces PhishER's
    ``reported_at:<today>`` trick with a real high-water mark.

    The join matters: the documented two-field example is
    ``type:"User reported phishing" source:"Gmail phishing"`` -- space-joined --
    while time ranges use ``AND``. That shape is reproduced rather than guessed at.
    """
    identity = " ".join(
        part for part in (
            f'type:"{alert_type}"' if alert_type else "",
            f'source:"{source}"' if source else "",
        ) if part
    )
    if not identity:
        return f'createTime>="{created_after}"' if created_after else ""
    if not created_after:
        return identity
    return f'{identity} AND createTime>="{created_after}"'


def feedback_for_disposition(disposition: Any) -> str | None:
    """Map a verdict to the one alert annotation Google accepts.

    ``manual_review`` and ``unknown`` deliberately map to ``None``: sending
    ``ALERT_FEEDBACK_TYPE_UNSPECIFIED`` would be an assertion that we did not
    assess it, and an unassessed alert should not be annotated at all.
    """
    name = getattr(disposition, "value", disposition)
    key = str(name).strip().lower() if name is not None else ""
    return {
        "threat": "VERY_USEFUL",
        "spam": "SOMEWHAT_USEFUL",
        "clean": "NOT_USEFUL",
    }.get(key)


def token_from_file(path: str, now: float | None = None) -> str:
    """Read a minted access token from a JSON file and refuse an expired one.

    Accepted shape: ``{"access_token": "...", "expires_at": <epoch seconds>}`` --
    the shape ``google-auth``'s authorized-user files use closely enough that an
    operator can drop either in. ``expires_at`` is optional; when present and past,
    the token is refused rather than sent and failed with a 401.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        raise AlertCenterConfigError("token_file_missing", path) from None
    except (ValueError, OSError) as exc:
        raise AlertCenterConfigError("token_file_unreadable", f"{path}: {exc}") from None

    if not isinstance(document, Mapping):
        raise AlertCenterConfigError("token_file_malformed", path)

    token = _text(document.get("access_token")) or _text(document.get("accessToken"))
    if not token:
        raise AlertCenterConfigError("token_file_malformed", f"{path} has no access_token")

    expires_at = document.get("expires_at") or document.get("expiry")
    if expires_at is not None:
        try:
            if float(expires_at) <= (time.time() if now is None else now):
                raise AlertCenterConfigError("token_expired", path)
        except (TypeError, ValueError):
            pass  # A non-numeric expiry is not something to fail on.
    return token


class AlertCenterClient:
    """Read alerts and send feedback; every call is a value, never a surprise.

    ``transport`` is injectable so the whole client is testable without a network:
    it is any callable ``(method, url, headers, body_bytes) -> (status,
    body_text)``. The default uses ``urllib.request`` and nothing else. One
    transport signature for GET and POST means a test that injects a fake never
    accidentally reaches the network on the write path.
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
                raise AlertCenterConfigError(
                    "no_token",
                    f"pass token=/token_provider= or set {TOKEN_ENV_VAR}",
                )
        if not base_url:
            raise AlertCenterConfigError("no_base_url", f"empty base_url for {self.__class__.__name__}")

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
                raise AlertCenterConfigError("no_token", "token_provider returned nothing")
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
            raise AlertCenterError("unreachable", f"{url}: {exc}") from None

    def _call(
        self, method: str, path: str, body: Mapping[str, Any] | None = None
    ) -> "_Response":
        """One HTTP call. A transport failure raises; an HTTP refusal is a value."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {"Authorization": f"Bearer {self._access_token()}", "Accept": "application/json"}
        payload = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(dict(body)).encode("utf-8")
        status, text = self._transport(method, url, headers, payload)
        return _decode_response(status, text)

    def _request(self, path: str, *, method: str = "GET", body: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        """A call that must yield a JSON object, or raise with the reason why not."""
        response = self._call(method, path, body)
        if response.error:
            raise AlertCenterError(response.reason, response.detail)
        return response.document or {}

    # -- reads -------------------------------------------------------------

    def list_alerts_page(
        self,
        *,
        alert_type: str = USER_REPORTED_PHISHING,
        source: str | None = GMAIL_PHISHING_SOURCE,
        created_after: str | None = None,
        page_size: int = 100,
        page_token: str | None = None,
        order_by: str = "create_time desc",
    ) -> AlertSet:
        """One page of ``alerts.list``. Use :meth:`iter_alerts` for the whole window."""
        params: dict[str, str] = {"pageSize": str(int(page_size))}
        query = build_filter(alert_type, source, created_after)
        if query:
            params["filter"] = query
        if page_token:
            params["pageToken"] = page_token
        if order_by:
            params["orderBy"] = order_by

        document = self._request(f"alerts?{urllib.parse.urlencode(params)}")
        entries = document.get("alerts") or ()
        if isinstance(entries, Mapping):
            entries = (entries,)
        alerts = tuple(decode_alert(entry) for entry in entries)
        return AlertSet(
            alerts=alerts,
            next_page_token=_text(document.get("nextPageToken")),
            raw=dict(document),
        )

    def iter_alerts(
        self,
        *,
        alert_type: str = USER_REPORTED_PHISHING,
        source: str | None = GMAIL_PHISHING_SOURCE,
        created_after: str | None = None,
        page_size: int = 100,
        max_pages: int = MAX_PAGES,
    ) -> Iterable[Alert]:
        """Walk every page of the window, stopping on an empty or repeated token.

        The repeated-token guard is not paranoia: the reference workflow needed an
        explicit completion expression for the same reason, and a server that
        returns the same token forever would otherwise spin.
        """
        seen_tokens: set[str] = set()
        page_token: str | None = None
        for _ in range(max(1, int(max_pages))):
            page = self.list_alerts_page(
                alert_type=alert_type,
                source=source,
                created_after=created_after,
                page_size=page_size,
                page_token=page_token,
            )
            token = page.next_page_token
            # A server repeating a token it already returned is checked before the
            # page is yielded, so a looping server costs one extra request rather
            # than duplicating every alert into the run.
            if token and token in seen_tokens:
                return
            yield from page.alerts
            if not token:
                return
            seen_tokens.add(token)
            page_token = token

    def get_alert(self, alert_id: str) -> Alert:
        if not alert_id:
            raise AlertCenterConfigError("no_alert_id", "empty alert_id")
        return decode_alert(self._request(f"alerts/{urllib.parse.quote(alert_id, safe='')}"))

    def get_metadata(self, alert_id: str) -> Mapping[str, Any]:
        """``alerts.getMetadata``: status, severity, assignee.

        Read-only in v1beta1 -- there is no update method for metadata, which is
        why the reference's tag/assignee writes have no Alert Center equivalent.
        """
        if not alert_id:
            raise AlertCenterConfigError("no_alert_id", "empty alert_id")
        return self._request(f"alerts/{urllib.parse.quote(alert_id, safe='')}/metadata")

    def list_feedback(self, alert_id: str) -> tuple[Mapping[str, Any], ...]:
        if not alert_id:
            raise AlertCenterConfigError("no_alert_id", "empty alert_id")
        document = self._request(f"alerts/{urllib.parse.quote(alert_id, safe='')}/feedback")
        entries = document.get("feedback") or ()
        if isinstance(entries, Mapping):
            entries = (entries,)
        return tuple(e for e in entries if isinstance(e, Mapping))

    # -- the one write -----------------------------------------------------

    def create_feedback(self, alert_id: str, feedback_type: str) -> Mapping[str, Any]:
        """Annotate an alert. This is the only writable annotation in v1beta1.

        It carries an enum and no text, which is the whole reason the reference's
        "post a comment" step has no Alert Center equivalent and why the analysis
        narrative belongs in the case record instead.
        """
        if not alert_id:
            raise AlertCenterConfigError("no_alert_id", "empty alert_id")
        if feedback_type not in FEEDBACK_TYPES:
            raise AlertCenterConfigError(
                "invalid_feedback_type",
                f"{feedback_type!r} not in {', '.join(FEEDBACK_TYPES)}",
            )
        return self._feedback(alert_id, feedback_type)

    def _feedback(self, alert_id: str, feedback_type: str) -> Mapping[str, Any]:
        response = self._call("POST", f"alerts/{urllib.parse.quote(alert_id, safe='')}/feedback", {"type": feedback_type})
        if not response.ok:
            raise AlertCenterError(response.reason, response.detail)
        return response.document or {}


def _first_reason(text: str) -> str:
    """Pull Google's error ``message`` out of an error body, if there is one."""
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        return text.strip()[:200]
    if isinstance(document, Mapping):
        error = document.get("error")
        if isinstance(error, Mapping):
            return _text(error.get("message")) or _text(error.get("status")) or ""
    return text.strip()[:200]


@dataclass(frozen=True)
class _Response:
    """What one HTTP call produced, with status, document and reason kept apart.

    Folding "the body was not JSON" and "the body was the string 'x'" into one slot
    is how a client ends up reporting a success it never parsed. Three fields, one
    meaning each.
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

    @property
    def detail(self) -> str:
        return self.error


def _decode_response(status: int, text: str) -> _Response:
    """Turn ``(status, body)`` into a :class:`_Response` without guessing."""
    if status >= 400:
        return _Response(status, None, _first_reason(text))
    if not text.strip():
        return _Response(status, {}, "")
    try:
        decoded = json.loads(text)
    except (ValueError, TypeError):
        return _Response(status, None, "malformed_response")
    if isinstance(decoded, Mapping):
        return _Response(status, decoded, "")
    return _Response(status, None, "response is not a JSON object")
