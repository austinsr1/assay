"""Google intake adapter tests -- offline, no network, no credentials.

The adapter's job is to be a faithful pipe: Alert Center says which messages exist,
Gmail hands over the bytes, and the adapter delivers those bytes to the engine with
provenance attached and nothing reinterpreted. Every test here injects a fake
transport into the real clients, so the URLs actually requested are asserted rather
than assumed, and no test can reach the network.

Hermeticity has a second half, and it is about what is *installed*. The ``google``
extra is optional and the build host does not have it, so minting is tested against a
stub of the whole import chain -- see :func:`install_google_auth_stub` -- and the
"the library is absent" refusal is tested by blanking that same chain. Neither half
can depend on which extras happen to be present, because a test that passes only on a
machine where ``pip install .[google]`` was run proves nothing about the core.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import pathlib
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email import alertcenter as ac  # noqa: E402
from tenable_email import gmail as g  # noqa: E402
from tenable_email import sources as _sources  # noqa: E402
from tenable_email import google_intake as gi  # noqa: E402
from tenable_email.sources import SourceError, source_for  # noqa: E402

EXAMPLE = REPO / "google-intake.example.json"
MAILPHISHING_URL = "type.googleapis.com/google.apps.alertcenter.type.MailPhishing"
RAW_BODY = b"From: sender@example.test\r\nSubject: wire transfer\r\n\r\nbody bytes"


class FakeTransport:
    """Queue of ``(status, body)`` responses; records every request made."""

    def __init__(self, *responses) -> None:
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        if not self.responses:
            raise AssertionError(f"unexpected request: {method} {url}")
        return self.responses.pop(0)

    @property
    def last_url(self) -> str:
        return self.calls[-1][1]

    @property
    def query(self) -> dict:
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.last_url).query))


def alert_payload(alert_id="alert-1", message_id="m1", recipient="someone@example.test", **extra):
    """One MailPhishing alert as ``alerts.list`` returns it."""
    message = {"messageId": message_id, "recipient": recipient}
    message.update(extra)
    return {
        "alertId": alert_id,
        "type": "User reported phishing",
        "source": "Gmail phishing",
        "createTime": "2026-11-03T09:00:00Z",
        "data": {"@type": MAILPHISHING_URL, "messages": [message]},
    }


def gmail_raw(message_id="m1", raw=RAW_BODY, internal_date="1762160000"):
    """A ``messages.get?format=raw`` body, encoded the way Gmail encodes it."""
    return json.dumps(
        {
            "id": message_id,
            "internalDate": internal_date,
            "raw": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        }
    )


def write_config(tmp_path, **overrides) -> Path:
    """The shipped example document with ``overrides`` applied, written into ``tmp_path``.

    ``google-intake.example.json`` deliberately ships no credential, so it cannot be
    used to build a working source -- that is a property of the artifact, not a bug,
    and :func:`test_the_shipped_example_refuses_until_its_token_file_exists` pins it.
    Tests that need a constructible source start from the real example document and
    add a token, so they still exercise the settings an operator actually ships rather
    than a hand-written config that happens to be convenient.
    """
    document = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    document.update(overrides)
    path = tmp_path / "google-intake.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def make_source(*alerts, gmail_responses=None, config=None, path=None, alert_pages=1):
    """A source wired to fake transports on both clients.

    ``alerts`` are alert payloads served by the Alert Center client;
    ``gmail_responses`` are the queued ``(status, body)`` pairs for the Gmail client.
    ``alert_pages`` is how many alert-list responses to queue: each call to ``fetch()``
    walks the feed from the beginning, so a test that fetches twice must provision
    twice. The default stays at one so that an unexpected second list request is still
    a hard failure in every other test, rather than something a generous fake swallows.
    """
    page = json.dumps({"alerts": list(alerts)}) if alerts else json.dumps({"alerts": []})
    ac_transport = FakeTransport(*[(200, page)] * max(1, alert_pages))
    alert_center = ac.AlertCenterClient(token="t", transport=ac_transport)

    responses = gmail_responses
    if responses is None and alerts:
        responses = []
        for alert in alerts:
            for message in alert.get("data", {}).get("messages", []):
                responses.append((200, gmail_raw(message.get("message_id", message.get("messageId", "")))))
    gmail_transport = FakeTransport(*responses) if responses else None
    gmail_client = g.GmailClient(token="t", transport=gmail_transport) if gmail_transport else None

    if config is None and path is None:
        config = gi.GoogleIntakeConfig(token="t")
    source = gi.GoogleAlertsSource(
        path,
        config=config,
        alert_center=alert_center,
        gmail=gmail_client,
    )
    return source, ac_transport, gmail_transport


# -- registration and naming -------------------------------------------------


def test_the_source_is_registered_under_the_documented_name() -> None:
    assert gi.SOURCE_NAME == "google-alerts"
    from tenable_email import sources

    assert gi.SOURCE_NAME in sources.available_sources()


def test_source_for_resolves_the_name_to_the_adapter(tmp_path) -> None:
    """The registry lookup, with a credential the test actually supplied.

    The shipped example cannot be constructed as-is (its ``token_file`` does not
    exist), so this starts from that document and fills in a token: the resolution
    being tested is ``name -> class``, and the config still comes from the real
    artifact. ``token_file`` is blanked so the inline token is the only credential
    in play and the result cannot depend on the working directory.
    """
    path = write_config(tmp_path, token="inline-token", token_file="")
    built = source_for("google-alerts", path=str(path))
    assert isinstance(built, gi.GoogleAlertsSource)
    assert built.name == "google-alerts"
    assert built.config.token == "inline-token"


def test_intake_declares_itself_read_only() -> None:
    """``mutates`` is the flag `source_for` refuses on; an intake adapter cannot opt out."""
    assert gi.GoogleAlertsSource.mutates is False


def test_describe_names_every_requirement(tmp_path) -> None:
    path = write_config(tmp_path, token="inline-token", token_file="")
    described = gi.GoogleAlertsSource(path=str(path)).describe()
    for fragment in ("Alert Center", "Gmail", "access", "read-only"):
        assert fragment in described
    # "every requirement" has to mean the ways a token can arrive, too: this sentence
    # is the only place an operator learns that ``token_file`` and the environment
    # variable are alternatives to ``service_account_file``.
    for requirement in ("token", "token_file", "service_account_file", ac.TOKEN_ENV_VAR):
        assert requirement in described


# -- configuration -----------------------------------------------------------


def test_the_shipped_example_parses() -> None:
    config = gi.GoogleIntakeConfig.from_json(EXAMPLE)
    assert config.alert_type == "User reported phishing"
    assert config.alert_source == "Gmail phishing"
    assert config.order_by == "create_time desc"
    assert config.limit == 5
    assert config.gmail_base_url == g.DEFAULT_BASE_URL
    assert config.alert_center_base_url == ac.DEFAULT_BASE_URL
    assert config.scopes == gi.DEFAULT_SCOPES


def test_an_unknown_key_is_refused_rather_than_ignored(tmp_path) -> None:
    """A typo in a setting name would otherwise read as "that setting is unset".

    Written into ``tmp_path``: this used to write the file into the checkout, which a
    read-only working tree refuses and a concurrent test run collides with.
    """
    path = tmp_path / "unused-config.json"
    text = json.dumps({"token": "abc123456789", "timout_seconds": 30})
    path.write_text(text, encoding="utf-8")
    with pytest.raises(SourceError) as excinfo:
        gi.GoogleIntakeConfig.from_json(path)
    assert excinfo.value.reason == "config_unknown_key"
    assert "timout_seconds" in excinfo.value.detail


def test_the_shipped_example_refuses_until_its_token_file_exists(monkeypatch, tmp_path) -> None:
    """Copying ``google-intake.example.json`` verbatim is the first thing an operator does.

    The example names a ``token_file`` that is not shipped, and that is correct -- a
    tracked file must not carry a credential. So the thing worth pinning is that the
    failure is the helpful one, naming the file to be created, at construction time
    rather than as a 401 halfway through a run.

    ``chdir`` into ``tmp_path`` because the example's ``token_file`` is a *relative*
    path: resolved against the checkout it is absent, but a test must not depend on
    nobody having ever dropped a ``google-token.json`` in the working directory.
    """
    monkeypatch.chdir(tmp_path)
    assert not (tmp_path / "google-token.json").exists()

    # A SourceError, not the alertcenter module's own type: the adapter owns translating
    # its collaborators' failures into the source contract, and the CLI only knows how to
    # report a SourceError. Before that translation the same call escaped as a traceback.
    with pytest.raises(_sources.SourceError) as excinfo:
        gi.GoogleAlertsSource(path=str(EXAMPLE))
    assert excinfo.value.reason == "alert_center_token_file_missing"
    # The reason alone would not tell an operator what to do; the detail names the file,
    # and pinning it against the parsed example keeps the two from drifting apart.
    assert excinfo.value.detail == gi.GoogleIntakeConfig.from_json(EXAMPLE).token_file
    assert excinfo.value.detail == "google-token.json"


def test_a_blank_token_is_absent_not_an_empty_value() -> None:
    """``"token": ""`` means "not filled in", and must not become an empty bearer."""
    config = gi.GoogleIntakeConfig.from_json(EXAMPLE)
    assert config.token is None
    assert config.service_account_file is None


def test_malformed_json_names_the_file(tmp_path) -> None:
    bad = tmp_path / "broken.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SourceError) as excinfo:
        gi.GoogleIntakeConfig.from_json(bad)
    assert excinfo.value.reason == "config_malformed"
    assert str(bad) in excinfo.value.detail


def test_a_missing_config_file_is_an_error_not_a_default(tmp_path) -> None:
    with pytest.raises(SourceError) as excinfo:
        gi.GoogleIntakeConfig.from_json(tmp_path / "absent.json")
    assert excinfo.value.reason == "config_unreadable"


def test_no_path_and_no_config_is_refused() -> None:
    with pytest.raises(SourceError) as excinfo:
        gi.GoogleAlertsSource()
    assert excinfo.value.reason == "source_path_required"


# -- the fetch path ----------------------------------------------------------


def test_fetch_yields_exactly_the_bytes_gmail_returned() -> None:
    """The adapter must not re-parse, re-encode or otherwise touch the message."""
    source, ac_transport, gmail_transport = make_source(alert_payload())
    items = list(source.fetch())

    assert len(items) == 1
    item = items[0]
    assert item.raw == RAW_BODY
    assert item.external_id == "alert-1:m1"
    assert item.source == "gmail:someone@example.test/m1"
    assert item.received_at == "2026-11-03T09:00:00Z"
    assert item.metadata["alert_id"] == "alert-1"
    assert item.metadata["gmail_message_id"] == "m1"
    assert item.metadata["recipient"] == "someone@example.test"
    assert item.metadata["alert_create_time"] == "2026-11-03T09:00:00Z"


def test_the_gmail_request_targets_the_recipient_mailbox() -> None:
    """Pins the base URL and the percent-encoding of the mailbox in one assertion."""
    source, _, gmail_transport = make_source(alert_payload())
    list(source.fetch())
    assert (
        gmail_transport.last_url
        == f"{g.DEFAULT_BASE_URL}/users/someone%40example.test/messages/m1?format=raw"
    )


def test_the_alert_request_carries_the_configured_filter_and_order() -> None:
    source, ac_transport, _ = make_source(alert_payload())
    list(source.fetch())
    query = ac_transport.query
    assert query["filter"] == 'type:"User reported phishing" source:"Gmail phishing"'
    assert query["orderBy"] == "create_time desc"


def test_limit_caps_messages_and_shrinks_the_page_requested() -> None:
    """One alert can name several messages; ``limit`` bounds messages, not alerts."""
    payload = alert_payload(
        alert_id="alert-many",
        message_id="m1",
    )
    payload["data"]["messages"] = [
        {"messageId": "m1", "recipient": "someone@example.test"},
        {"messageId": "m2", "recipient": "someone@example.test"},
        {"messageId": "m3", "recipient": "someone@example.test"},
    ]
    source, ac_transport, _ = make_source(
        payload,
        gmail_responses=[
            (200, gmail_raw("m1")),
            (200, gmail_raw("m2")),
            (200, gmail_raw("m3")),
        ],
    )
    items = list(source.fetch(limit=2))

    assert [item.external_id for item in items] == ["alert-many:m1", "alert-many:m2"]
    assert ac_transport.query["pageSize"] == "2"


def test_since_becomes_the_create_time_filter() -> None:
    source, ac_transport, _ = make_source(alert_payload())
    list(source.fetch(since="2026-11-01T00:00:00Z"))
    assert 'createTime>="2026-11-01T00:00:00Z"' in ac_transport.query["filter"]


def test_a_refused_message_is_recorded_and_not_raised() -> None:
    """A 404 from Gmail is a fact about one message, not a failed run."""
    source, _, _ = make_source(
        alert_payload(), gmail_responses=[(404, json.dumps({"error": {"message": "gone"}}))]
    )
    items = list(source.fetch())

    assert items == []
    assert source.fetch_failures == [
        {"alert_id": "alert-1", "message_id": "m1", "reason": "gmail_message_not_found"}
    ]


def test_a_message_without_an_id_is_recorded_not_invented() -> None:
    payload = alert_payload(alert_id="alert-x", message_id="")
    source, _, _ = make_source(payload, gmail_responses=[])
    assert list(source.fetch()) == []
    assert source.fetch_failures[0]["reason"] == "no_message_id"


def test_an_alert_with_no_messages_is_not_silently_empty() -> None:
    payload = alert_payload(alert_id="alert-empty")
    payload["data"]["messages"] = []
    source, _, _ = make_source(payload, gmail_responses=[])
    assert list(source.fetch()) == []
    assert source.fetch_failures == []


def test_fetch_failures_reset_between_fetches() -> None:
    """A second fetch reports what the second fetch found, not the first run's leftovers."""
    source, ac_transport, gmail_transport = make_source(
        alert_payload(),
        gmail_responses=[(404, json.dumps({"error": {}})), (200, gmail_raw("m1"))],
        alert_pages=2,
    )
    list(source.fetch())
    assert source.fetch_failures

    items = list(source.fetch())
    assert source.fetch_failures == []
    assert items and items[0].raw == RAW_BODY
    # Each fetch re-requested the alert list exactly once and read exactly one message.
    # The fake refuses anything it was not provisioned for, so this is what makes the
    # line above mean "the second fetch cleared the list" rather than "it never ran".
    assert len(ac_transport.calls) == 2
    assert len(gmail_transport.calls) == 2


def test_a_repeated_page_token_ends_the_walk() -> None:
    """A server handing back the same token forever must not spin the client."""
    page = json.dumps({"alerts": [alert_payload()], "nextPageToken": "same"})
    transport = FakeTransport((200, page), (200, page), (200, page))
    source = gi.GoogleAlertsSource(
        None,
        config=gi.GoogleIntakeConfig(token="t"),
        alert_center=ac.AlertCenterClient(token="t", transport=transport),
        gmail=g.GmailClient(
            token="t",
            transport=FakeTransport((200, gmail_raw("m1")), (200, gmail_raw("m1"))),
        ),
    )
    items = list(source.fetch())
    assert [item.external_id for item in items] == ["alert-1:m1", "alert-1:m1"]
    assert len(transport.calls) == 2


def test_an_alert_center_refusal_becomes_a_source_error() -> None:
    """The CLI handles SourceError; anything else is a traceback for a known case."""
    transport = FakeTransport((403, json.dumps({"error": {"message": "denied"}})))
    source = gi.GoogleAlertsSource(
        None,
        config=gi.GoogleIntakeConfig(token="t"),
        alert_center=ac.AlertCenterClient(token="t", transport=transport),
        gmail=g.GmailClient(token="t", transport=FakeTransport()),
    )
    with pytest.raises(SourceError) as excinfo:
        list(source.fetch())
    assert excinfo.value.reason.startswith("alertcenter_")


# -- token resolution --------------------------------------------------------


def test_an_inline_token_is_used_for_both_clients() -> None:
    config = gi.GoogleIntakeConfig(token="inline-token")
    source = gi.GoogleAlertsSource(
        None,
        config=config,
        alert_center=ac.AlertCenterClient(token="t", transport=FakeTransport()),
        gmail=g.GmailClient(token="t", transport=FakeTransport()),
    )
    assert source._token(None) == "inline-token"


def test_a_per_api_override_beats_the_shared_token() -> None:
    config = gi.GoogleIntakeConfig(token="shared", gmail_token="gmail-specific")
    source = gi.GoogleAlertsSource(
        None,
        config=config,
        alert_center=ac.AlertCenterClient(token="t", transport=FakeTransport()),
        gmail=g.GmailClient(token="t", transport=FakeTransport()),
    )
    assert source._token(config.gmail_token) == "gmail-specific"
    assert source._token(config.alert_center_token) == "shared"


def test_a_token_file_is_read_and_its_expiry_honoured(tmp_path) -> None:
    token_file = tmp_path / "google-token.json"
    token_file.write_text(
        json.dumps({"access_token": "from-file", "expires_at": 9999999999}),
        encoding="utf-8",
    )
    config = gi.GoogleIntakeConfig(token_file=str(token_file))
    source = gi.GoogleAlertsSource(
        None,
        config=config,
        alert_center=ac.AlertCenterClient(token="t", transport=FakeTransport()),
        gmail=g.GmailClient(token="t", transport=FakeTransport()),
    )
    assert source._token(None) == "from-file"


def test_an_expired_token_file_is_refused_before_it_is_sent(tmp_path) -> None:
    token_file = tmp_path / "google-token.json"
    token_file.write_text(
        json.dumps({"access_token": "stale", "expires_at": 1}), encoding="utf-8"
    )
    config = gi.GoogleIntakeConfig(token_file=str(token_file))
    with pytest.raises(_sources.SourceError) as excinfo:
        gi.GoogleAlertsSource(
            None,
            config=config,
            gmail=g.GmailClient(token="t", transport=FakeTransport()),
        )
    # Expiry must stay distinguish from absence: the remedies are different, and a
    # translation that flattened both into one reason would cost the operator the
    # distinction the underlying client bothered to make.
    assert excinfo.value.reason == "alert_center_token_expired"


def test_no_token_anywhere_is_a_configuration_error(monkeypatch) -> None:
    monkeypatch.delenv(ac.TOKEN_ENV_VAR, raising=False)
    with pytest.raises(_sources.SourceError) as excinfo:
        gi.GoogleAlertsSource(None, config=gi.GoogleIntakeConfig())
    assert excinfo.value.reason == "alert_center_no_token"


def test_the_environment_variable_is_the_fallback(monkeypatch) -> None:
    monkeypatch.setenv(ac.TOKEN_ENV_VAR, "env-token")
    source = gi.GoogleAlertsSource(None, config=gi.GoogleIntakeConfig())
    assert source.alert_center._access_token() == "env-token"
    assert source.gmail._access_token() == "env-token"


# -- minting -----------------------------------------------------------------

#: Every module in the chain ``mint_access_token`` imports, parents included. The
#: stub installs this list and the refusal test blanks it, so the two spellings come
#: from one place and cannot drift away from the import form in the adapter.
_GOOGLE_AUTH_MODULES = (
    "google",
    "google.auth",
    "google.auth.transport",
    "google.auth.transport.requests",
    "google.oauth2",
    "google.oauth2.service_account",
)


class StubRequest:
    """Stand-in for ``google.auth.transport.requests.Request``. Never used for I/O."""


def install_google_auth_stub(monkeypatch, *, token="minted", expiry=None):
    """Register a complete fake ``google-auth`` in ``sys.modules``; return the call log.

    ``mint_access_token`` spells its imports as ``from google.auth.transport.requests
    import Request`` and ``from google.oauth2 import service_account``. Both forms
    resolve through the parent packages, so stubbing only the two leaves -- as an
    earlier revision of this file did -- left ``google`` and ``google.oauth2`` missing
    from ``sys.modules``, the import raised ``ImportError``, and the adapter answered
    ``google_auth_missing``. The tests then passed only on a host that had the extra
    installed, which is exactly what ``dependencies = []`` forbids.

    Every package in the chain is registered here *and* hung off its parent as an
    attribute, so the stub resolves the way the real namespace package does: by name,
    not by luck of what is installed. The same stub takes precedence on a host that
    does have ``google-auth``, so these tests pass either way.

    ``token`` and ``expiry`` are what the stub credentials report after a refresh, so
    one helper covers "mints a token", "reports an expiry" and "mints nothing at all".
    """
    log: list[tuple] = []

    class StubCredentials:
        def __init__(self, minted, reported_expiry):
            self.token = minted
            self.expiry = reported_expiry

        @classmethod
        def from_service_account_file(cls, path, scope=None):
            log.append(("from_service_account_file", str(path), tuple(scope or ())))
            return cls(token, expiry)

        def with_subject(self, subject):
            log.append(("with_subject", subject))
            return self

        def refresh(self, request):
            log.append(("refresh", type(request).__name__))
            return None

    modules = {}
    for name in _GOOGLE_AUTH_MODULES:
        module = type(sys)(name)
        module.__path__ = []
        if "." in name:
            parent_name, _, attribute = name.rpartition(".")
            setattr(modules[parent_name], attribute, module)
        modules[name] = module
        monkeypatch.setitem(sys.modules, name, module)

    modules["google.auth.transport.requests"].Request = StubRequest
    modules["google.oauth2.service_account"].Credentials = StubCredentials
    return log


def test_minting_without_google_auth_says_so(monkeypatch) -> None:
    """The core must not need google-auth; the extra is what unlocks this path.

    The mirror image of :func:`install_google_auth_stub`, and the reason it blanks the
    whole chain rather than the leaves: "the library is missing" has to stay a tested
    branch, not become an artefact of a half-installed stub.
    """
    for name in _GOOGLE_AUTH_MODULES:
        monkeypatch.setitem(sys.modules, name, None)
    with pytest.raises(SourceError) as excinfo:
        gi.mint_access_token("/nowhere/key.json")
    assert excinfo.value.reason == "google_auth_missing"
    assert "[google]" in excinfo.value.detail
    assert "/nowhere/key.json" in excinfo.value.detail


def test_minting_reuses_one_token_until_it_expires(monkeypatch, tmp_path) -> None:
    log = install_google_auth_stub(monkeypatch, token="minted", expiry=None)

    key_path = str(tmp_path / "key.json")
    config = gi.GoogleIntakeConfig(service_account_file=key_path)
    source = gi.GoogleAlertsSource(
        None,
        config=config,
        alert_center=ac.AlertCenterClient(token="t", transport=FakeTransport()),
        gmail=g.GmailClient(token="t", transport=FakeTransport()),
    )
    assert source._token(None) == "minted"
    assert source._token(None) == "minted"
    refreshes = [entry for entry in log if entry[0] == "refresh"]
    assert len(refreshes) == 1, "a batch run should mint once, not once per message"
    # The config reached the library under the right name, with the scopes it declares:
    # a mint that silently used a default scope set would still hand back a token.
    assert log[0] == ("from_service_account_file", key_path, gi.DEFAULT_SCOPES)
    assert refreshes[0] == ("refresh", "StubRequest")


def test_minting_returns_the_expiry_the_library_reports(monkeypatch) -> None:
    install_google_auth_stub(monkeypatch, token="minted", expiry=None)

    token, expires_at = gi.mint_access_token("/nowhere/key.json", now=1_000_000.0)
    assert token == "minted"
    assert expires_at == 1_000_000.0 + 3600.0

    # The name promises more than the fallback above proves. When the library does
    # report an expiry, that value -- not the one-hour guess -- is what the caller
    # caches, or a reuse window would outlive the token and fail mid-run.
    reported = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
    install_google_auth_stub(monkeypatch, token="minted", expiry=reported)
    minted, until = gi.mint_access_token("/nowhere/key.json", now=1_000_000.0)
    assert minted == "minted"
    assert until == reported.timestamp()


def test_an_empty_minted_token_is_refused(monkeypatch) -> None:
    install_google_auth_stub(monkeypatch, token="", expiry=None)

    with pytest.raises(SourceError) as excinfo:
        gi.mint_access_token("/nowhere/key.json")
    assert excinfo.value.reason == "mint_empty_token"
    assert "/nowhere/key.json" in excinfo.value.detail


# -- the parity claim --------------------------------------------------------


def test_the_bytes_parse_the_same_way_as_a_file_on_disk(tmp_path) -> None:
    """The engine's verdict must not depend on which adapter delivered the bytes."""
    from dataclasses import replace

    from tenable_email.parse import parse_message

    eml = tmp_path / "one.eml"
    eml.write_bytes(RAW_BODY)
    file_message = parse_message(eml.read_bytes(), source=str(eml))

    source, _, _ = make_source(alert_payload())
    item = next(iter(source.fetch()))
    item_message = item.parse()

    assert item_message.text_body == file_message.text_body
    assert item_message.subject == file_message.subject
    # Strictly more than those two fields: every normalized field of the message the
    # adapter handed over must equal the one parsed from the same bytes on disk. Only
    # ``source`` is allowed to differ, and it is provenance rather than content -- a
    # path for the file, ``gmail:<mailbox>/<id>`` for the adapter.
    assert item_message == replace(file_message, source=item_message.source)


# -- the registry is complete for every consumer, not only for the CLI -------


def test_the_adapter_is_registered_without_anybody_importing_the_cli() -> None:
    """Registration by import side effect must not depend on which entry point ran.

    Before the adapter list in ``sources.py``, ``available_sources()`` returned only
    ``eml-dir`` unless something had already imported ``tenable_email.cli``. The CLI does
    import it, so the shell worked and the defect was invisible there - but the MCP server
    and any library caller saw a different set of sources than the operator did, and
    ``source_for("google-alerts")`` from those paths failed with ``unknown_source`` while
    the same name worked on the command line. A registry whose contents depend on import
    order is not a registry.

    This test runs in a subprocess so it observes a fresh interpreter with nothing
    imported yet; in-process the module cache would already hold whatever an earlier test
    pulled in, and the assertion would pass for the wrong reason.
    """
    program = (
        "from tenable_email import sources\n"
        "import sys\n"
        "assert 'tenable_email.cli' not in sys.modules, 'the CLI was already imported'\n"
        "print(','.join(sources.available_sources()))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": str(pathlib.Path(gi.__file__).resolve().parents[1])},
    )
    assert result.returncode == 0, result.stderr
    names = result.stdout.strip().split(",")
    assert "google-alerts" in names, names
    assert names[0] == "eml-dir", "the built-in source must still be listed first"


def test_a_construction_failure_is_reportable_by_the_cli_not_a_traceback() -> None:
    """The failure an operator hits first must arrive as a message, not a stack.

    Constructing from the shipped example raises at ``__init__``, which is before
    ``fetch()`` - the only place the adapter had previously translated alertcenter errors.
    So the very first thing an operator does after copying the example produced an
    ``AlertCenterConfigError`` traceback out of ``cli.py``. The point of the assertion is
    not the exception type, it is that the CLI's ``except SourceError`` can catch it.
    """
    config = gi.GoogleIntakeConfig(token_file="/nonexistent/google-token.json")
    with pytest.raises(_sources.SourceError) as excinfo:
        gi.GoogleAlertsSource(None, config=config)
    reason = excinfo.value.reason
    assert reason == "alert_center_token_file_missing", reason
    # The specific file is still named, because "a config error" is not actionable and
    # "this file does not exist" is.
    assert "/nonexistent/google-token.json" in str(excinfo.value.detail)
