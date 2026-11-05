"""Alert Center client tests -- offline, no network, no credentials.

The client's contract is that every outcome is inspectable: a request that can be
asserted on (method, URL, headers, body), a decode that never invents a field, and
a failure that carries a reason. Those are the three things these tests pin.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email import alertcenter as ac  # noqa: E402

MAILPHISHING_URL = "type.googleapis.com/google.apps.alertcenter.type.MailPhishing"


class FakeTransport:
    """Queue of ``(status, body)`` responses; records every request made."""

    def __init__(self, *responses: tuple[int, str]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict, bytes | None]] = []

    def __call__(self, method: str, url: str, headers, body) -> tuple[int, str]:
        self.calls.append((method, url, dict(headers), body))
        if not self.responses:
            raise AssertionError(f"unexpected request: {method} {url}")
        return self.responses.pop(0)

    @property
    def query(self) -> dict[str, str]:
        """Parsed query string of the most recent recorded call."""
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.calls[-1][1]).query))


def make_client(*responses: tuple[int, str]) -> tuple[ac.AlertCenterClient, FakeTransport]:
    transport = FakeTransport(*responses)
    return ac.AlertCenterClient(token="t", transport=transport), transport


# -- scope ------------------------------------------------------------------


def test_scope_constant_is_the_literal_google_value() -> None:
    """``Alert.type`` holds a display string, not an enum member.

    A refactor that "tidies" this into ``USER_REPORTED_PHISHING`` would silently
    match nothing, so the literal is pinned here.
    """
    assert ac.USER_REPORTED_PHISHING == "User reported phishing"
    assert ac.GMAIL_PHISHING_SOURCE == "Gmail phishing"


def test_filter_reproduces_the_documented_shape() -> None:
    assert ac.build_filter() == 'type:"User reported phishing" source:"Gmail phishing"'


def test_filter_without_source_queries_every_source() -> None:
    assert ac.build_filter(source=None) == 'type:"User reported phishing"'


def test_filter_joins_the_time_window_with_and() -> None:
    assert (
        ac.build_filter(created_after="2026-11-02T00:00:00Z")
        == 'type:"User reported phishing" source:"Gmail phishing" '
        'AND createTime>="2026-11-02T00:00:00Z"'
    )


def test_filter_of_only_a_timestamp_is_still_valid() -> None:
    assert ac.build_filter(alert_type="", source=None, created_after="2026-01-01T00:00:00Z") == 'createTime>="2026-01-01T00:00:00Z"'


def test_empty_filter_is_empty() -> None:
    assert ac.build_filter(alert_type="", source=None) == ""


# -- configuration ----------------------------------------------------------


def test_client_without_any_token_names_the_field(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ac.TOKEN_ENV_VAR, raising=False)
    with pytest.raises(ac.AlertCenterConfigError) as excinfo:
        ac.AlertCenterClient()
    assert excinfo.value.reason == "no_token"
    assert ac.TOKEN_ENV_VAR in str(excinfo.value)


def test_token_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ac.TOKEN_ENV_VAR, "env-token")
    transport = FakeTransport((200, '{"alerts": []}'))
    client = ac.AlertCenterClient(transport=transport)
    client.list_alerts_page()
    assert client._access_token() == "env-token"
    assert transport.calls[0][2]["Authorization"] == "Bearer env-token"


def test_blank_env_token_is_not_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ac.TOKEN_ENV_VAR, "   ")
    with pytest.raises(ac.AlertCenterConfigError):
        ac.AlertCenterClient()


def test_empty_base_url_is_refused() -> None:
    with pytest.raises(ac.AlertCenterConfigError) as excinfo:
        ac.AlertCenterClient(token="t", base_url="")
    assert excinfo.value.reason == "no_base_url"


def test_silent_token_provider_is_a_configuration_failure() -> None:
    client = ac.AlertCenterClient(token_provider=lambda: "", transport=FakeTransport())
    with pytest.raises(ac.AlertCenterConfigError) as excinfo:
        client.list_alerts_page()
    assert excinfo.value.reason == "no_token"


def test_token_file_roundtrip(tmp_path) -> None:
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"access_token": "file-token", "expires_at": 9_999_999_999}), encoding="utf-8")
    assert ac.token_from_file(str(path)) == "file-token"


def test_token_file_without_expiry_is_accepted(tmp_path) -> None:
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"accessToken": "alt-shape"}), encoding="utf-8")
    assert ac.token_from_file(str(path)) == "alt-shape"


def test_expired_token_is_refused_rather_than_sent(tmp_path) -> None:
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"access_token": "old", "expires_at": 1}), encoding="utf-8")
    with pytest.raises(ac.AlertCenterConfigError) as excinfo:
        ac.token_from_file(str(path))
    assert excinfo.value.reason == "token_expired"


def test_missing_token_file_is_named(tmp_path) -> None:
    with pytest.raises(ac.AlertCenterConfigError) as excinfo:
        ac.token_from_file(str(tmp_path / "absent.json"))
    assert excinfo.value.reason == "token_file_missing"


def test_unparseable_token_file_is_named(tmp_path) -> None:
    path = tmp_path / "token.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ac.AlertCenterConfigError) as excinfo:
        ac.token_from_file(str(path))
    assert excinfo.value.reason == "token_file_unreadable"


def test_token_file_without_a_token_is_named(tmp_path) -> None:
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"expires_at": 9_999_999_999}), encoding="utf-8")
    with pytest.raises(ac.AlertCenterConfigError) as excinfo:
        ac.token_from_file(str(path))
    assert excinfo.value.reason == "token_file_malformed"


# -- the request ------------------------------------------------------------


def test_list_alerts_page_builds_the_documented_request() -> None:
    client, transport = make_client((200, '{"alerts": [], "nextPageToken": ""}'))
    client.list_alerts_page()
    method, url, headers, body = transport.calls[0]
    assert method == "GET"
    assert url.startswith(f"{ac.DEFAULT_BASE_URL}/alerts?")
    assert body is None
    assert headers["Accept"] == "application/json"
    query = transport.query
    assert query["filter"] == ac.build_filter()
    assert query["pageSize"] == "100"
    assert query["orderBy"] == "create_time desc"


def test_base_url_trailing_slash_does_not_double_up() -> None:
    transport = FakeTransport((200, "{}"))
    ac.AlertCenterClient(token="t", base_url=f"{ac.DEFAULT_BASE_URL}/", transport=transport).list_alerts_page()
    assert "//alerts" not in transport.calls[0][1]


def test_http_error_keeps_googles_message() -> None:
    body = json.dumps({"error": {"message": "The caller does not have permission", "status": "PERMISSION_DENIED"}})
    client, _ = make_client((403, body))
    with pytest.raises(ac.AlertCenterError) as excinfo:
        client.list_alerts_page()
    assert excinfo.value.reason == "http_403"
    assert "permission" in excinfo.value.detail.lower()


def test_non_json_success_is_a_reason_not_a_guess() -> None:
    client, _ = make_client((200, "not json"))
    with pytest.raises(ac.AlertCenterError) as excinfo:
        client.list_alerts_page()
    assert excinfo.value.reason == "malformed_response"


def test_unreachable_is_a_reason() -> None:
    def boom(method, url, headers, body):
        raise ac.AlertCenterError("unreachable", url)

    client = ac.AlertCenterClient(token="t", transport=boom)
    with pytest.raises(ac.AlertCenterError) as excinfo:
        client.list_alerts_page()
    assert excinfo.value.reason == "unreachable"


# -- pagination -------------------------------------------------------------


def test_pagination_walks_every_page() -> None:
    page1 = json.dumps({"alerts": [{"alertId": "a1"}, {"alertId": "a2"}], "nextPageToken": "t1"})
    page2 = json.dumps({"alerts": [{"alertId": "a3"}], "nextPageToken": ""})
    client, transport = make_client((200, page1), (200, page2))
    assert [a.alert_id for a in client.iter_alerts()] == ["a1", "a2", "a3"]
    assert len(transport.calls) == 2
    assert transport.query["pageToken"] == "t1"


def test_a_repeated_token_ends_the_walk_instead_of_spinning() -> None:
    """A server handing back the same token forever must not spin the client."""
    looping = json.dumps({"alerts": [{"alertId": "a1"}], "nextPageToken": "same"})
    client, transport = make_client((200, looping), (200, looping))
    assert [a.alert_id for a in client.iter_alerts()] == ["a1"]
    assert len(transport.calls) == 2  # one extra request, then the guard closes


def test_max_pages_bounds_the_walk() -> None:
    looping = json.dumps({"alerts": [{"alertId": "a1"}], "nextPageToken": "t1"})
    fresh = [
        (200, json.dumps({"alerts": [{"alertId": f"a{i}"}], "nextPageToken": f"t{i + 1}"}))
        for i in range(4)
    ]
    client, transport = make_client(*fresh)
    list(client.iter_alerts(max_pages=2))
    assert len(transport.calls) == 2


# -- decoding ---------------------------------------------------------------


def _alert(alert_id: str, data: object, **extra: object) -> dict:
    payload = {"alertId": alert_id, "type": ac.USER_REPORTED_PHISHING, "source": ac.GMAIL_PHISHING_SOURCE}
    if data is not None:
        payload["data"] = data
    payload.update(extra)
    return payload


def test_mailphishing_object_form_decodes_every_field() -> None:
    data = {
        "@type": MAILPHISHING_URL,
        "messages": [
            {
                "messageId": "m1",
                "recipient": "someone@example.com",
                "subjectText": "Invoice",
                "messageBodySnippet": "see attached",
                "md5HashSubject": "aa",
                "md5HashMessageBody": "bb",
                "attachmentsSha256Hash": ["c1", "c2"],
                "date": "2026-11-02T10:00:00Z",
                "sentTime": "2026-11-02T09:59:00Z",
            }
        ],
        "isInternal": False,
        "systemActionType": "REMOVED_FROM_INBOX",
        "maliciousEntity": {"fromHeader": "billing@example.com", "displayName": "Billing"},
        "domainId": {"customerPrimaryDomain": "example.com"},
    }
    alert = ac.decode_alert(_alert("a1", data, etag="v1", createTime="2026-11-02T10:00:00Z"))
    assert alert.alert_id == "a1" and alert.etag == "v1"
    assert alert.data_type == "MailPhishing" and alert.known_type is True
    message = alert.messages[0]
    assert message.message_id == "m1" and message.recipient == "someone@example.com"
    assert message.subject_text == "Invoice" and message.message_body_snippet == "see attached"
    assert message.attachments_sha256 == ("c1", "c2")
    assert alert.mail_phishing.is_internal is False
    assert alert.mail_phishing.system_action_type == "REMOVED_FROM_INBOX"
    assert alert.mail_phishing.malicious_from_header == "billing@example.com"
    assert alert.mail_phishing.customer_primary_domain == "example.com"
    assert alert.fetchable is True


def test_data_arriving_as_a_json_string_still_decodes() -> None:
    """The REST surface and generated clients differ on whether ``data`` is packed."""
    packed = json.dumps({"@type": MAILPHISHING_URL, "messages": [{"messageId": "m2"}]})
    alert = ac.decode_alert(_alert("a2", packed))
    assert alert.data_type == "MailPhishing" and alert.messages[0].message_id == "m2"


def test_deprecated_phishingspike_is_not_treated_as_unknown() -> None:
    data = {"@type": "type.googleapis.com/google.apps.alertcenter.type.PhishingSpike", "messages": [{"messageId": "m3"}]}
    alert = ac.decode_alert(_alert("a3", data))
    assert alert.known_type is True and alert.data_type == "PhishingSpike"


def test_an_unmodelled_type_is_kept_not_guessed() -> None:
    data = {"@type": "type.googleapis.com/some.new.Thing", "surprise": [1, 2, 3]}
    alert = ac.decode_alert(_alert("a4", data))
    assert alert.known_type is False
    assert alert.messages == ()
    assert alert.raw["data"]["surprise"] == [1, 2, 3]  # type: ignore[index]


def test_an_alert_with_no_payload_is_not_reported_as_a_gap() -> None:
    alert = ac.decode_alert(_alert("a5", None))
    assert alert.known_type is True and alert.messages == () and alert.fetchable is False


def test_a_message_without_an_id_is_visible_but_not_fetchable() -> None:
    data = {"@type": MAILPHISHING_URL, "messages": [{"subjectText": "no id"}]}
    alert = ac.decode_alert(_alert("a6", data))
    assert alert.fetchable is False
    assert alert.messages[0].subject_text == "no id"
    assert alert.messages[0].has_body_evidence is False


def test_a_single_message_object_is_not_iterated_character_by_character() -> None:
    data = {"@type": MAILPHISHING_URL, "messages": {"messageId": "solo"}}
    assert ac.decode_alert(_alert("a7", data)).messages[0].message_id == "solo"


def test_an_entry_without_an_id_is_refused() -> None:
    with pytest.raises(ac.AlertCenterError) as excinfo:
        ac.decode_alert({"type": ac.USER_REPORTED_PHISHING})
    assert excinfo.value.reason == "malformed_response"


def test_a_non_object_entry_is_refused() -> None:
    with pytest.raises(ac.AlertCenterError):
        ac.decode_alert(["not", "an", "alert"])  # type: ignore[arg-type]


# -- the one write ----------------------------------------------------------


@pytest.mark.parametrize(
    "disposition, expected",
    [("threat", "VERY_USEFUL"), ("spam", "SOMEWHAT_USEFUL"), ("clean", "NOT_USEFUL"),
     ("manual_review", None), ("unknown", None), (None, None)],
)
def test_disposition_maps_to_the_only_annotation_google_accepts(disposition: object, expected: str | None) -> None:
    assert ac.feedback_for_disposition(disposition) == expected


def test_feedback_is_posted_to_the_alert_as_an_enum() -> None:
    client, transport = make_client((200, '{"alertId": "a1", "type": "VERY_USEFUL"}'))
    result = client.create_feedback("a1", "VERY_USEFUL")
    method, url, _headers, body = transport.calls[0]
    assert method == "POST"
    assert url.endswith("/alerts/a1/feedback")
    assert json.loads(body) == {"type": "VERY_USEFUL"}  # type: ignore[arg-type]
    assert result["type"] == "VERY_USEFUL"


def test_an_uninvented_feedback_type_is_refused_before_it_is_sent() -> None:
    client, transport = make_client()
    with pytest.raises(ac.AlertCenterConfigError) as excinfo:
        client.create_feedback("a1", "MAYBE")
    assert excinfo.value.reason == "invalid_feedback_type"
    assert transport.calls == []


def test_feedback_for_an_unassessed_alert_is_not_sent_at_all() -> None:
    """An unassessed alert gets no annotation -- ``UNSPECIFIED`` would be a claim."""
    client, transport = make_client()
    assert ac.feedback_for_disposition("manual_review") is None
    assert transport.calls == []


def test_empty_alert_id_is_refused_for_every_read() -> None:
    client = ac.AlertCenterClient(token="t", transport=FakeTransport())
    for call in (lambda: client.get_alert(""), lambda: client.get_metadata(""), lambda: client.list_feedback("")):
        with pytest.raises(ac.AlertCenterConfigError) as excinfo:
            call()
        assert excinfo.value.reason == "no_alert_id"


def test_get_alert_and_metadata_paths() -> None:
    client, transport = make_client((200, '{"alertId": "a/1"}'), (200, '{"status": "UNPROCESSED", "severity": "LOW"}'))
    assert client.get_alert("a/1").alert_id == "a/1"
    assert transport.calls[0][1].endswith("/alerts/a%2F1")
    assert dict(client.get_metadata("a/1"))["status"] == "UNPROCESSED"
    assert transport.calls[1][1].endswith("/alerts/a%2F1/metadata")


def test_list_feedback_returns_entries_without_inventing_any() -> None:
    client, _ = make_client((200, '{"feedback": [{"alertId": "a1", "type": "VERY_USEFUL"}]}'))
    assert client.list_feedback("a1")[0]["type"] == "VERY_USEFUL"


def test_an_empty_success_body_is_an_empty_document() -> None:
    client, _ = make_client((200, "   "))
    assert client.list_alerts_page().alerts == ()
