"""Google Alert Center + Gmail as a selectable ``EmailSource``.

The two clients (:mod:`tenable_email.alertcenter` and :mod:`tenable_email.gmail`)
existed for a day without being reachable: nothing outside their own tests imported
them, so the CLI could not ask for them and the pipeline could not be handed a
message from them. This module is the missing third piece -- the adapter that turns
"here is an alert" into "here are RFC 822 bytes", which is the only thing the engine
consumes.

Why a file configures it
------------------------
:func:`~tenable_email.sources.source_for` requires every registered source to be
given a ``path``. For the directory adapter that is the directory; here it is a JSON
file, and that choice is deliberate. Everything environment-specific -- the token,
whose mailbox to impersonate, which project's endpoints -- lives in one file an
operator owns. The code carries no organisation identity, and removing somebody's
environment is deleting one file rather than editing a module. The shipped template is
``google-intake.example.json``; the real one stays untracked, the same way
``.scratch/endpoints.env`` does for model endpoints.

Why the token is never minted in the core
-----------------------------------------
``dependencies = []`` is load-bearing, and minting an OAuth token needs
``google-auth``. So the core accepts a token (inline, in a file, or from the
environment) and only reaches for ``google-auth`` when the config names a
``service_account_file``. That import lives inside one function -- the same shape the
``mcp`` extra uses -- so ``pip install .[google]`` adds a capability the code actually
calls instead of one that merely reads as installed.

What this module never does
---------------------------
It never mutates. ``mutates = False``, and the mutating client methods
(``create_label``, ``modify_labels``, ``create_feedback``) are not called here at
all. Labelling a message is a write, and writes belong behind the approval gate in
:mod:`tenable_email.writeback`, not in intake.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional, Tuple

from . import alertcenter as _alertcenter
from . import gmail as _gmail
from .sources import SourceError, SourceItem, register_source

__all__ = [
    "SOURCE_NAME",
    "DEFAULT_SCOPES",
    "DEFAULT_ORDER_BY",
    "DEFAULT_PAGE_SIZE",
    "GoogleIntakeConfig",
    "GoogleAlertsSource",
    "mint_access_token",
]

#: The name ``--source`` takes, and the name :func:`~tenable_email.sources.source_for`
#: resolves. Spelled once so the CLI, the registry and the tests cannot drift.
SOURCE_NAME = "google-alerts"

#: The two scopes the adapter needs: read the alert feed, read the mail it points at.
#: One delegated token carrying both is what a Workspace deployment normally issues,
#: which is why one token serves both clients by default.
DEFAULT_SCOPES = (
    "https://www.googleapis.com/auth/apps.alerts",
    "https://www.googleapis.com/auth/gmail.readonly",
)

#: Alert Center supports exactly three sort orders; newest-first is the only sensible
#: default for "triage what was reported recently".
DEFAULT_ORDER_BY = "create_time desc"

#: Requested page size when a caller asks for more than one page's worth.
DEFAULT_PAGE_SIZE = 100

#: Refuse to walk more pages than this, mirroring the client's own guard.
_MAX_PAGES = _alertcenter.MAX_PAGES


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

#: Every key ``google-intake.json`` may contain. An unknown key is an error rather
#: than something to ignore: a typo in ``token_file`` would otherwise read as "no
#: token configured" on a machine that clearly has one.
_CONFIG_KEYS = frozenset(
    {
        "token",
        "token_file",
        "alert_center_token",
        "gmail_token",
        "service_account_file",
        "subject",
        "scopes",
        "alert_center_base_url",
        "gmail_base_url",
        "alert_type",
        "alert_source",
        "order_by",
        "limit",
        "timeout_seconds",
    }
)


@dataclass(frozen=True)
class GoogleIntakeConfig:
    """One operator's Google intake settings, as read from a JSON file.

    Every field has a default that matches the shipped example, so the only
    required content is a way to obtain a token.
    """

    #: An access token given directly. Wins over every other source.
    token: Optional[str] = None

    #: Path to ``{"access_token": ..., "expires_at": ...}`` -- the shape
    #: ``alertcenter.token_from_file`` reads, and the shape ``google-auth`` writes
    #: closely enough that an operator can drop either in.
    token_file: Optional[str] = None

    #: Per-API overrides for the case where Alert Center and Gmail credentials
    #: differ. Either falls back to ``token``/``token_file``/the environment.
    alert_center_token: Optional[str] = None
    gmail_token: Optional[str] = None

    #: Service-account key. Requires the ``google`` extra to mint, and ``subject``
    #: for domain-wide delegation.
    service_account_file: Optional[str] = None
    subject: Optional[str] = None
    scopes: Tuple[str, ...] = DEFAULT_SCOPES

    alert_center_base_url: str = _alertcenter.DEFAULT_BASE_URL
    gmail_base_url: str = _gmail.DEFAULT_BASE_URL

    #: The alert filter. Both values are display strings, not enum members --
    #: ``alertcenter.build_filter`` documents why that distinction matters.
    alert_type: str = _alertcenter.USER_REPORTED_PHISHING
    alert_source: Optional[str] = _alertcenter.GMAIL_PHISHING_SOURCE
    order_by: str = DEFAULT_ORDER_BY

    #: Default cap on items per fetch, so a run without ``--limit`` still has a
    #: ceiling an operator chose rather than "everything the feed returns".
    limit: Optional[int] = None

    timeout_seconds: float = _alertcenter.DEFAULT_TIMEOUT_SECONDS

    #: The document as parsed, kept so a config change is observable in evidence.
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, path: "str | Path") -> "GoogleIntakeConfig":
        """Parse a config file. Every failure names the file and the field."""
        target = Path(path)
        try:
            text = target.read_text(encoding="utf-8")
        except OSError as exc:
            raise SourceError("config_unreadable", f"{target}: {exc}") from None
        try:
            document = json.loads(text)
        except ValueError as exc:
            raise SourceError("config_malformed", f"{target}: {exc}") from None
        if not isinstance(document, Mapping):
            raise SourceError("config_malformed", f"{target}: expected a JSON object")

        unknown = sorted(set(str(key) for key in document) - set(_CONFIG_KEYS))
        if unknown:
            raise SourceError(
                "config_unknown_key",
                f"{target}: {', '.join(unknown)} is not a setting this adapter has; "
                "a typo here reads as an unconfigured field, so it is refused",
            )

        get = document.get
        scopes = get("scopes")
        if scopes is None:
            scopes_tuple = DEFAULT_SCOPES
        elif isinstance(scopes, str):
            scopes_tuple = (scopes,)
        elif isinstance(scopes, (list, tuple)) and all(
            isinstance(item, str) and item for item in scopes
        ):
            scopes_tuple = tuple(scopes)
        else:
            raise SourceError("config_invalid", f"{target}: scopes must be a string or a list of strings")

        for key, allowed in (("limit", int), ("timeout_seconds", (int, float))):
            value = get(key)
            if value is not None and not isinstance(value, allowed):
                raise SourceError("config_invalid", f"{target}: {key} must be a number")

        for key in ("token", "token_file", "alert_center_token", "gmail_token",
                    "service_account_file", "subject", "alert_center_base_url",
                    "gmail_base_url", "alert_type", "alert_source", "order_by"):
            value = get(key)
            if value is not None and not isinstance(value, str):
                raise SourceError("config_invalid", f"{target}: {key} must be a string")

        return cls(
            token=_clean(get("token")),
            token_file=_clean(get("token_file")),
            alert_center_token=_clean(get("alert_center_token")),
            gmail_token=_clean(get("gmail_token")),
            service_account_file=_clean(get("service_account_file")),
            subject=_clean(get("subject")),
            scopes=scopes_tuple,
            alert_center_base_url=get("alert_center_base_url") or _alertcenter.DEFAULT_BASE_URL,
            gmail_base_url=get("gmail_base_url") or _gmail.DEFAULT_BASE_URL,
            alert_type=get("alert_type") or _alertcenter.USER_REPORTED_PHISHING,
            alert_source=_clean(get("alert_source")) or _alertcenter.GMAIL_PHISHING_SOURCE,
            order_by=get("order_by") or DEFAULT_ORDER_BY,
            limit=None if get("limit") is None else int(get("limit")),
            timeout_seconds=(
                _alertcenter.DEFAULT_TIMEOUT_SECONDS
                if get("timeout_seconds") is None
                else float(get("timeout_seconds"))
            ),
            raw=dict(document),
        )


def _clean(value: Any) -> Optional[str]:
    """Empty and whitespace-only strings are absent, not empty.

    ``"token": ""`` in a config file means "not filled in yet", and treating it as a
    value would produce a request with an empty bearer token instead of telling the
    operator the field is blank.
    """
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def mint_access_token(
    service_account_file: str,
    scopes: "Tuple[str, ...] | str" = DEFAULT_SCOPES,
    subject: Optional[str] = None,
    request: Any = None,
    now: Optional[float] = None,
) -> "Tuple[str, float]":
    """Mint an access token from a service-account key: ``(token, expires_at)``.

    The only place in the package that imports ``google-auth``, and it imports it
    inside the function so the core stays dependency-free. ``request`` is injectable
    for the same reason it is in the two clients: a test must never reach the network.

    ``subject`` is the account being impersonated. With domain-wide delegation that
    is a real user mailbox; without it Google issues a token for the service account
    itself, which the Alert Center API refuses. The code cannot tell those two
    situations apart, so the config states the intent explicitly.
    """
    scope_list = [scopes] if isinstance(scopes, str) else list(scopes)
    if not scope_list or not all(scope_list):
        raise SourceError("mint_no_scopes", str(service_account_file))
    try:
        from google.auth.transport.requests import Request  # type: ignore[import-not-found]
        from google.oauth2 import service_account  # type: ignore[import-not-found]
    except ImportError:
        raise SourceError(
            "google_auth_missing",
            f"{service_account_file}: minting a token needs google-auth; "
            "pip install .[google], or put a pre-minted token in token_file "
            f"or {_alertcenter.TOKEN_ENV_VAR} instead",
        ) from None

    credentials = service_account.Credentials.from_service_account_file(
        service_account_file, scope=scope_list
    )
    if subject:
        credentials = credentials.with_subject(subject)
    credentials.refresh(Request() if request is None else request)

    token = getattr(credentials, "token", None)
    if not token:
        raise SourceError("mint_empty_token", str(service_account_file))

    reference = time.time() if now is None else now
    expiry = getattr(credentials, "expiry", None)
    if expiry is None:
        expires_at = reference + 3600.0
    elif isinstance(expiry, datetime):
        aware = expiry if expiry.tzinfo else expiry.replace(tzinfo=timezone.utc)
        expires_at = aware.timestamp()
    else:
        try:
            expires_at = float(expiry)
        except (TypeError, ValueError):
            expires_at = reference + 3600.0
    return str(token), expires_at


# --------------------------------------------------------------------------
# the adapter
# --------------------------------------------------------------------------


class GoogleAlertsSource:
    """Reported phishing as the engine wants it: alerts in, RFC 822 bytes out.

    ``alert_center`` and ``gmail`` are injectable so the whole adapter is testable
    without a network -- the same convention the two clients use. With nothing
    injected, both are built from the config, and a run cannot accidentally talk to
    one API with the other one's credentials.
    """

    name = SOURCE_NAME
    mutates = False

    def __init__(
        self,
        path: "str | Path | None" = None,
        *,
        config: "GoogleIntakeConfig | None" = None,
        alert_center: Any = None,
        gmail: Any = None,
    ) -> None:
        if config is None:
            if path is None:
                raise SourceError(
                    "source_path_required",
                    f"{SOURCE_NAME} needs a config file; pass one as the path "
                    "(see google-intake.example.json)",
                )
            config = GoogleIntakeConfig.from_json(path)
        elif path is not None and config.raw:
            # Both given is fine; the config object is authoritative and the path is
            # only recorded, so a caller cannot pass one and silently use another.
            pass

        self.config = config
        self.path = str(path) if path is not None else None
        self._minted: "Optional[Tuple[str, float]]" = None
        # Construction talks to the two clients, and both raise their own config error
        # for a missing or unreadable token file. Those types are not SourceError, so
        # left alone they escape the CLI as a traceback: an operator who copies
        # google-intake.example.json and runs it gets a Python stack instead of "the
        # token file the example names does not exist". The adapter owns translating its
        # collaborators' failures into the source contract, at construction as well as at
        # fetch, because __init__ is where the first one actually happens.
        try:
            self._alert_center = (
                alert_center if alert_center is not None else self._build_alert_center()
            )
            self._gmail = gmail if gmail is not None else self._build_gmail()
        except _alertcenter.AlertCenterError as exc:
            # The underlying reason and detail are already specific - missing file,
            # expired token, no token anywhere - and each names its own remedy, so they
            # pass through unchanged. Appending generic advice here was tried and then
            # removed: telling someone whose token file has EXPIRED to "point token_file
            # at a file that exists" contradicts the specific error printed beside it,
            # which is worse than saying nothing at all.
            raise SourceError(
                f"alert_center_{getattr(exc, 'reason', None) or 'config_error'}",
                str(getattr(exc, "detail", None) or exc),
            ) from None
        except _gmail.GmailError as exc:
            raise SourceError(
                f"gmail_{getattr(exc, 'reason', None) or 'config_error'}",
                str(getattr(exc, "detail", None) or exc),
            ) from None

        #: Messages the alert feed named but this run could not read, as
        #: ``{"alert_id", "message_id", "reason"}``. A skipped message is a fact
        #: worth keeping; a silently missing one is not.
        self.fetch_failures: "list[dict[str, str]]" = []

    # -- construction ------------------------------------------------------

    def _token(self, override: Optional[str]) -> Optional[str]:
        """Resolve a token for one API, honouring the per-API override first."""
        if override:
            return override
        if self.config.token:
            return self.config.token
        if self.config.token_file:
            return _alertcenter.token_from_file(self.config.token_file)
        if self.config.service_account_file:
            return self._minted_token()
        return None

    def _minted_token(self) -> str:
        """Mint once and reuse until it expires, so a batch is one mint, not fifty."""
        cached = self._minted
        if cached is not None and cached[1] > time.time() + 60:
            return cached[0]
        assert self.config.service_account_file is not None
        token, expires_at = mint_access_token(
            self.config.service_account_file,
            self.config.scopes,
            self.config.subject,
        )
        self._minted = (token, expires_at)
        return token

    def _build_alert_center(self) -> Any:
        kwargs: "dict[str, Any]" = {
            "base_url": self.config.alert_center_base_url,
            "timeout": self.config.timeout_seconds,
        }
        token = self._token(self.config.alert_center_token)
        if token is not None:
            kwargs["token"] = token
        elif self.config.service_account_file is None:
            # No token anywhere: let the client read the environment variable and
            # raise its own config error naming it, rather than inventing a second
            # message for the same condition.
            pass
        return _alertcenter.AlertCenterClient(**kwargs)

    def _build_gmail(self) -> Any:
        kwargs: "dict[str, Any]" = {
            "base_url": self.config.gmail_base_url,
            "timeout": self.config.timeout_seconds,
        }
        token = self._token(self.config.gmail_token)
        if token is not None:
            kwargs["token"] = token
        return _gmail.GmailClient(**kwargs)

    # -- the contract ------------------------------------------------------

    @property
    def alert_center(self) -> Any:
        return self._alert_center

    @property
    def gmail(self) -> Any:
        return self._gmail

    def describe(self) -> str:
        return (
            f"reads Alert Center alerts matching type {self.config.alert_type!r} "
            f"and source {self.config.alert_source!r} from "
            f"{self.config.alert_center_base_url}, then fetches each message's "
            f"RFC 822 bytes from {self.config.gmail_base_url}; needs an access "
            f"token (config token, token_file, service_account_file with the "
            f"google extra, or {_alertcenter.TOKEN_ENV_VAR}); read-only"
        )

    def fetch(
        self, *, limit: "Optional[int]" = None, since: "Optional[str]" = None
    ) -> "Iterator[SourceItem]":
        """Yield messages from the newest alerts, at most ``limit`` of them.

        ``limit`` counts **messages**, not alerts -- one alert can name several
        messages, and the engine consumes messages. ``since`` maps onto Alert
        Center's ``createTime`` filter, which is why this adapter accepts a time
        filter the directory adapter refuses.
        """
        self.fetch_failures = []
        return self._items(limit=self._effective_limit(limit), since=since)

    def _effective_limit(self, limit: "Optional[int]") -> "Optional[int]":
        return limit if limit is not None else self.config.limit

    # -- internals ---------------------------------------------------------

    def _items(
        self, *, limit: "Optional[int]", since: "Optional[str]"
    ) -> "Iterator[SourceItem]":
        count = 0
        for alert in self._alerts(limit=limit, since=since):
            for info in alert.messages:
                if limit is not None and count >= limit:
                    return
                item = self._item(alert, info)
                if item is None:
                    continue
                yield item
                count += 1

    def _alerts(self, *, limit: "Optional[int]", since: "Optional[str]") -> "Any":
        """Walk the feed with the configured sort order, guarding against a looping page token."""
        page_size = (
            DEFAULT_PAGE_SIZE
            if limit is None
            else max(1, min(int(limit), DEFAULT_PAGE_SIZE))
        )
        seen: "set[str]" = set()
        token: "Optional[str]" = None
        for _ in range(max(1, _MAX_PAGES)):
            try:
                page = self._alert_center.list_alerts_page(
                    alert_type=self.config.alert_type,
                    source=self.config.alert_source,
                    created_after=since,
                    page_size=page_size,
                    page_token=token,
                    order_by=self.config.order_by,
                )
            except _alertcenter.AlertCenterError as exc:
                # The CLI handles a SourceError and reports it; an AlertCenterError
                # would be a traceback for a condition the tool already understands.
                raise SourceError(
                    f"alertcenter_{exc.reason}", exc.detail or ""
                ) from None
            yield from page.alerts
            token = page.next_page_token
            if not token or token in seen:
                return
            seen.add(token)

    def _item(self, alert: Any, info: Any) -> "Optional[SourceItem]":
        """One alert message as a SourceItem, or ``None`` with the reason recorded."""
        if not info.message_id:
            self._record(alert.alert_id, "", "no_message_id")
            return None
        if not info.recipient:
            self._record(alert.alert_id, info.message_id, "no_recipient")
            return None

        external_id = f"{alert.alert_id}:{info.message_id}"
        fetched = self._gmail.fetch(info.recipient, info.message_id, fmt="raw")
        if not fetched.ok or fetched.message is None:
            self._record(alert.alert_id, info.message_id, f"gmail_{fetched.error or 'no_message'}")
            return None
        if fetched.message.raw is None:
            self._record(alert.alert_id, info.message_id, "gmail_empty_raw")
            return None

        return SourceItem(
            external_id=external_id,
            # The bytes Gmail returned, unopened. parse.parse_message is the only
            # parser in this project and an adapter does not get a second one.
            raw=fetched.message.raw,
            source=f"gmail:{info.recipient}/{info.message_id}",
            # Alert Center's MailPhishing payload names a recipient, not a reporter,
            # so this stays None rather than guessing that the recipient reported it.
            reporter=None,
            received_at=alert.create_time,
            metadata={
                "alert_id": alert.alert_id,
                "alert_type": alert.type,
                "alert_source": alert.source,
                "alert_create_time": alert.create_time or "",
                "data_type": alert.data_type,
                "gmail_message_id": info.message_id,
                "recipient": info.recipient,
                "subject": info.subject_text or "",
                "snippet": info.message_body_snippet or "",
                "md5_hash_subject": info.md5_hash_subject or "",
                "md5_hash_message_body": info.md5_hash_message_body or "",
                "attachments_sha256": ",".join(info.attachments_sha256),
                "gmail_internal_date": fetched.message.internal_date or "",
            },
        )

    def _record(self, alert_id: str, message_id: str, reason: str) -> None:
        self.fetch_failures.append(
            {"alert_id": alert_id, "message_id": message_id, "reason": reason}
        )


def build_google_alerts_source(path: "str | Path") -> GoogleAlertsSource:
    """The registry factory: ``factory(path=...)`` -> an :class:`EmailSource`."""
    return GoogleAlertsSource(path)


#: Registration is a module side effect, which is how an adapter becomes selectable
#: without editing sources.py. Importing this module is what opts in.
register_source(SOURCE_NAME, build_google_alerts_source)
