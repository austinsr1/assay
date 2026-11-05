"""Gmail client tests -- offline, no network, no mailbox.

Two behaviours get more attention than the rest, because both are the difference
between "we read the reported message" and "we concluded there was nothing there":
the 404/403 distinction on ``messages.get``, and ``includeSpamTrash`` defaulting to
true on ``messages.list``. A user who reports a phish usually moves it to Spam, so
a client that forgets that flag reads an empty inbox and calls it clean.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email import gmail as g  # noqa: E402
from tenable_email.verdict import Disposition  # noqa: E402


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
    def last_url(self) -> str:
        return self.calls[-1][1]

    @property
    def query(self) -> dict[str, str]:
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.last_url).query))


def make_client(*responses: tuple[int, str]) -> tuple[g.GmailClient, FakeTransport]:
    transport = FakeTransport(*responses)
    return g.GmailClient(token="t", transport=transport), transport


def error_body(message: str = "The caller does not have permission") -> str:
    return json.dumps({"error": {"message": message, "status": "PERMISSION_DENIED"}})


# -- configuration ----------------------------------------------------------


def test_client_without_any_token_names_the_field(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(g.TOKEN_ENV_VAR, raising=False)
    with pytest.raises(g.GmailConfigError) as excinfo:
        g.GmailClient()
    assert excinfo.value.reason == "no_token"
    assert g.TOKEN_ENV_VAR in str(excinfo.value)


def test_blank_env_token_is_not_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(g.TOKEN_ENV_VAR, "  ")
    with pytest.raises(g.GmailConfigError):
        g.GmailClient()


def test_empty_base_url_is_refused() -> None:
    with pytest.raises(g.GmailConfigError) as excinfo:
        g.GmailClient(token="t", base_url="")
    assert excinfo.value.reason == "no_base_url"


# -- reading a message ------------------------------------------------------


def test_fetch_raw_builds_the_request_and_decodes_the_body() -> None:
    body = json.dumps({"id": "m1", "threadId": "t1", "labelIds": ["SPAM"], "raw": "aGVsbG8=", "sizeEstimate": 5})
    client, transport = make_client((200, body))
    result = client.fetch("someone@example.com", "m1")
    assert result.ok is True and result.error == ""
    assert transport.last_url == f"{g.DEFAULT_BASE_URL}/users/someone%40example.com/messages/m1?format=raw"
    assert transport.calls[0][0] == "GET"
    assert transport.calls[0][2]["Authorization"] == "Bearer t"
    assert result.message is not None
    assert result.message.raw == b"hello"
    assert result.message.label_ids == ("SPAM",)
    assert result.message.size_estimate == 5


def test_a_missing_message_and_an_unreachable_mailbox_are_different_reasons() -> None:
    """404 means the message is gone; 403 means the token does not reach it.

    Only the first is fixed by re-reading the alert, so collapsing them would send
    an operator to the wrong fix.
    """
    missing, _ = make_client((404, error_body("message not found")))
    assert missing.fetch("u@x.com", "m").error == "message_not_found"

    refused, _ = make_client((403, error_body()))
    assert refused.fetch("u@x.com", "m").error == "not_authorized_or_delegated"

    broken, _ = make_client((500, error_body("backend")))
    assert broken.fetch("u@x.com", "m").error.startswith("http_500")


def test_every_failure_path_still_returns_a_value() -> None:
    client, transport = make_client()
    assert client.fetch("", "m").error == "no_user"
    assert client.fetch("u@x.com", "").error == "no_message_id"
    assert client.fetch("u@x.com", "m", fmt="everything").error == "invalid_format:everything"
    assert transport.calls == []  # nothing was sent for a request that cannot work


def test_metadata_and_full_populate_headers_and_never_raw() -> None:
    body = json.dumps(
        {
            "id": "m1",
            "snippet": "hi",
            "headers": [{"name": "From", "value": "sender@example.com"}, {"name": "From", "value": "duplicate"}],
            "parts": [
                {"headers": [{"name": "X-Forged", "value": "dkim=fail"}]},
                {"headers": [{"name": "X-Deep", "value": "nested"}], "parts": [{"headers": [{"name": "X-Deeper", "value": "deepest"}]}]},
            ],
        }
    )
    client, _ = make_client((200, body))
    message = client.fetch("u@x.com", "m1", fmt="full").message
    assert message is not None
    assert message.raw is None  # raw is only ever present when it was asked for
    assert message.header("from") == "sender@example.com"
    assert message.header_values("FROM") == ("sender@example.com", "duplicate")
    assert message.header("x-forged") == "dkim=fail"
    assert message.header("x-deeper") == "deepest"  # nested MIME parts are collected too


def test_an_empty_success_body_is_a_malformed_message() -> None:
    client, _ = make_client((200, "  "))
    assert client.fetch("u@x.com", "m").error == "malformed_response"


def test_a_non_object_success_body_is_a_malformed_message() -> None:
    client, _ = make_client((200, "[1,2,3]"))
    assert client.fetch("u@x.com", "m").error == "malformed_response"


@pytest.mark.parametrize(
    "encoded, expected",
    [("aGVsbG8=", b"hello"), ("aGVsbG8", b"hello"), ("", b""), ("-_8=", b"\xfb\xff")],
)
def test_base64url_padding_is_repaired(encoded: str, expected: bytes) -> None:
    """Gmail omits padding and uses the urlsafe alphabet; both are handled."""
    assert g.decode_raw(encoded) == expected


def test_undecodable_raw_is_a_reason() -> None:
    with pytest.raises(g.GmailError) as excinfo:
        g.decode_raw("!!!!")
    assert excinfo.value.reason == "raw_not_decodable"


# -- listing ----------------------------------------------------------------


def test_list_messages_includes_spam_and_trash_by_default() -> None:
    client, transport = make_client((200, '{"messages": [{"id": "m1"}], "nextPageToken": "p2", "resultCount": 1}'))
    listing = client.list_messages("u@x.com")
    assert transport.query["includeSpamTrash"] == "true"
    assert transport.query["maxResults"] == "100"
    assert listing.ids == ("m1",) and listing.next_page_token == "p2" and listing.result_count == 1


def test_a_reported_message_is_found_even_after_it_moves_to_spam() -> None:
    """The flag is the whole reason a reported phish is still readable via list."""
    client, transport = make_client((200, "{}"))
    client.list_messages("u@x.com", query="label:spam", label_ids=("SPAM",), page_token="tok", max_results=25)
    query = transport.query
    assert query["q"] == "label:spam"
    assert query["labelIds"] == "SPAM"
    assert query["pageToken"] == "tok"
    assert query["maxResults"] == "25"
    assert query["includeSpamTrash"] == "true"


def test_the_flag_can_be_turned_off_when_the_caller_means_it() -> None:
    client, transport = make_client((200, "{}"))
    client.list_messages("u@x.com", include_spam_trash=False)
    assert "includeSpamTrash" not in transport.query


def test_a_refused_list_is_empty_rather_than_an_error() -> None:
    """``gmail.metadata`` cannot use ``q``; that surfaces as an empty list, not a crash."""
    client, _ = make_client((403, error_body()))
    assert client.list_messages("u@x.com") == g.MessageList()


def test_listing_an_unknown_mailbox_sends_nothing() -> None:
    client, transport = make_client()
    assert client.list_messages("") == g.MessageList()
    assert transport.calls == []


# -- labels -----------------------------------------------------------------


def test_labels_are_read_as_id_name_pairs() -> None:
    body = json.dumps({"labels": [{"id": "INBOX", "name": "INBOX"}, {"id": "L1", "name": "AI-THREAT"}]})
    client, _ = make_client((200, body))
    assert client.list_labels("u@x.com") == (("INBOX", "INBOX"), ("L1", "AI-THREAT"))


def test_label_for_disposition_covers_only_what_was_decided() -> None:
    assert g.label_for_disposition(Disposition.THREAT) == "AI-THREAT"
    assert g.label_for_disposition(Disposition.SPAM) == "AI-SPAM"
    assert g.label_for_disposition(Disposition.CLEAN) == "AI-CLEAN"
    assert g.label_for_disposition(Disposition.MANUAL_REVIEW) is None
    assert g.label_for_disposition(Disposition.UNKNOWN) is None
    assert g.label_for_disposition(None) is None


def test_create_label_sends_the_name_and_returns_the_id() -> None:
    client, transport = make_client((200, '{"id": "L1", "name": "AI-THREAT"}'))
    assert client.create_label("u@x.com", "AI-THREAT") == "L1"
    method, url, _headers, body = transport.calls[0]
    assert method == "POST" and url.endswith("/users/u%40x.com/labels")
    assert json.loads(body) == {"name": "AI-THREAT"}  # type: ignore[arg-type]


def test_a_system_label_is_refused_before_it_is_sent() -> None:
    """Gmail owns system labels; asking to create one is a bug, not a permission gap."""
    client, transport = make_client()
    assert client.create_label("u@x.com", "SPAM") is None
    assert client.create_label("u@x.com", "") is None
    assert client.create_label("", "AI-THREAT") is None
    assert transport.calls == []


def test_modify_labels_sends_both_lists() -> None:
    client, transport = make_client((200, "{}"))
    assert client.modify_labels("u@x.com", "m1", add=("L1",), remove=("L2",)) is True
    _method, url, _headers, body = transport.calls[0]
    assert url.endswith("/users/u%40x.com/messages/m1/modify")
    assert json.loads(body) == {"addLabelIds": ["L1"], "removeLabelIds": ["L2"]}  # type: ignore[arg-type]


def test_an_empty_mutation_is_not_reported_as_a_success() -> None:
    """A caller that decided nothing must not look like a completed write."""
    client, transport = make_client()
    assert client.modify_labels("u@x.com", "m1") is False
    assert transport.calls == []


def test_a_refused_mutation_is_false() -> None:
    client, _ = make_client((403, error_body()))
    assert client.modify_labels("u@x.com", "m1", add=("L1",)) is False


def test_writes_need_arguments_before_they_need_a_token() -> None:
    client, transport = make_client()
    assert client.modify_labels("", "m1", add=("L1",)) is False
    assert client.modify_labels("u@x.com", "", add=("L1",)) is False
    assert transport.calls == []


def test_a_transport_failure_is_loud_where_an_http_refusal_is_a_value() -> None:
    """No route to Gmail is not the same answer as Gmail refusing the route.

    ``fetch``/``list_messages``/``modify_labels`` convert HTTP statuses into values
    so a caller can branch on them, but a transport failure propagates: silently
    returning "no such message" because the socket failed would fabricate a
    conclusion about the mailbox.
    """

    def boom(method, url, headers, body):
        raise g.GmailError("unreachable", url)

    client = g.GmailClient(token="t", transport=boom)
    for call in (
        lambda: client.fetch("u@x.com", "m"),
        lambda: client.list_messages("u@x.com"),
        lambda: client.modify_labels("u@x.com", "m", add=("L1",)),
    ):
        with pytest.raises(g.GmailError) as excinfo:
            call()
        assert excinfo.value.reason == "unreachable"
