"""The ledger web view.

The escaping tests come first and are the reason this module exists. Every page
renders attacker-controlled text: the subject, the sender display name, the link
targets quoted inside reasons, and the analysis narrative built from them. A UI for
a phishing triage tool that can be driven by the mail it is displaying is not a
cosmetic bug, it is the tool being weaponized through its own operator's browser.

Two properties are asserted structurally rather than case by case, because a
case-by-case allowlist rots: no script element anywhere in any rendered page, and no
external resource reference of any kind. Both are checked over every route.
"""

from __future__ import annotations

import dataclasses
import pathlib
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email import cli  # noqa: E402
from tenable_email import webui  # noqa: E402
from tenable_email.config import Config  # noqa: E402
from tenable_email.ledger import CaseLedger  # noqa: E402
from tenable_email.parse import parse_message  # noqa: E402
from tenable_email.pipeline import triage_file, triage_message  # noqa: E402
from tenable_email.receipt import Receipt  # noqa: E402
from tenable_email.verdict import Disposition  # noqa: E402
from tenable_email.webui import CSP, TOKEN_COOKIE  # noqa: E402

FIXTURES = REPO / "fixtures" / "synthetic"

#: Payloads that must arrive as inert text. Each one attacks a different context:
#: element, attribute, comment, URI scheme, and nested quoting.
XSS_PAYLOADS = (
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    "javascript:alert(document.cookie)",
    "'-alert(1)-'",
    '<iframe src="//evil.test"></iframe>',
    "<!--<script>alert(1)</script>-->",
    "&lt;script&gt;already-escaped&lt;/script&gt;",
)


#: Matches a real tag opening. Escaped text uses `&lt;`, so this cannot match a
#: payload that arrived as inert text - which is the distinction the first version of
#: these tests got wrong.
_TAG_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>", re.DOTALL)

#: An `src` or `href` attribute pointing somewhere else. Kept as a constant because
#: both the renderer and the CLI-written snapshot file must be checked with it, and a
#: page that fetches anything is an undisclosed outbound call from a tool whose pitch
#: is that nothing leaves the building.
_EXTERNAL_RE = re.compile(
    r'(?:src|href)\s*=\s*"(https?:)?//[^"]*"', re.IGNORECASE
)


def external_resource_references(page: str) -> list[str]:
    """`src`/`href` attributes that name another host. None are permitted."""
    return [m.group(0) for m in _EXTERNAL_RE.finditer(page)]


def live_dangerous(page: str) -> list[str]:
    """Actual executable constructs in the page, not the words that describe them.

    A subject containing `<img src=x onerror=alert(1)>` MUST survive into the page as
    escaped text, because hiding what an attacker wrote is worse than showing it. So
    the assertion is that no live tag is a script, carries an `on*` handler, or points
    at a `javascript:` URI - not that the substring "onerror" is absent. Asserting the
    substring is how a test starts pushing you toward weakening the escaping.
    """
    problems = []
    for match in _TAG_RE.finditer(page):
        tag, attrs = match.group(1).lower(), match.group(2)
        if tag == "script":
            problems.append("a live <script> element")
        if re.search(r"\son[a-z]+\s*=", attrs, re.IGNORECASE):
            problems.append(f"an on* event handler in <{tag}>")
        if re.search(r"(?:src|href)\s*=\s*[\"']?\s*javascript:", attrs, re.IGNORECASE):
            problems.append(f"a javascript: URI in <{tag}>")
        if tag in ("iframe", "object", "embed", "frame"):
            problems.append(f"an embedding <{tag}> element")
    return problems


@pytest.fixture()
def config():
    return Config(replay=True, replay_dir=None)


@pytest.fixture()
def populated(tmp_path, config):
    """A ledger holding the corpus plus one deliberately hostile case."""
    path = tmp_path / "run" / "ledger.sqlite3"
    store = CaseLedger(path, clock=_clock())
    for name in sorted(p.name for p in FIXTURES.glob("*.eml"))[:6]:
        store.record_receipt(
            Receipt.for_verdict(triage_message(_parse(FIXTURES / name), config))
        )

    # A message whose subject and sender are pure attack surface. This is what a real
    # phishing author controls completely and costs nothing to set.
    hostile = parse_message(
        "From: \"<script>alert('sender')</script>\" <attacker@phish.test>\r\n"
        "To: victim@example.test\r\n"
        "Subject: <img src=x onerror=alert('subject')> verify now\r\n"
        "Date: Mon, 3 Nov 2026 09:00:00 +0000\r\n"
        "Message-ID: <hostile@phish.test>\r\n"
        "\r\n"
        "Click javascript:alert(1) or <svg onload=alert(2)> to continue.\r\n",
        source="test:hostile",
    )
    store.record_receipt(Receipt.for_verdict(triage_message(hostile, config)))
    store.close()
    return path


def _parse(path):
    from tenable_email.parse import parse_file

    return parse_file(path)


def _clock(start: float = 1_700_000_000.0, step: float = 60.0):
    state = {"t": start}

    def now() -> float:
        state["t"] += step
        return state["t"]

    return now


# --------------------------------------------------------------------------
# escaping
# --------------------------------------------------------------------------


def test_every_payload_arrives_as_inert_text_in_the_queue(populated):
    store = CaseLedger(populated)
    page = webui.render_queue(store.list_cases())
    store.close()

    assert not live_dangerous(page), live_dangerous(page)
    # The payload characters survive as escaped entities, so the analyst still sees
    # what was in the subject. Redacting it would hide the attack.
    assert "&lt;script&gt;" in page or "&lt;img" in page


def test_every_payload_arrives_as_inert_text_on_a_case_page(populated):
    store = CaseLedger(populated)
    records = store.list_cases()
    hostile = [r for r in records if "phish.test" in r.sender]
    assert hostile, "the hostile case should be in the ledger"
    page = webui.render_case(hostile[0], token="t" * 32)
    store.close()

    assert not live_dangerous(page), live_dangerous(page)
    # The raw payload is still readable as escaped text, which is the point.
    assert "onerror" in page and "&lt;" in page


def test_no_rendered_page_contains_a_script_element(populated):
    """Structural, over every route, so a new page cannot quietly add one."""
    store = CaseLedger(populated)
    records = store.list_cases()
    pages = {
        "queue": webui.render_queue(records),
        "agreement": webui.render_agreement(store.agreement_summary()),
        "case": webui.render_case(records[0], token="t" * 32),
        "shell": webui.render_page("t", "<p>body</p>"),
        "snapshot": webui.render_snapshot(store),
    }
    store.close()
    for name, page in pages.items():
        assert not live_dangerous(page), f"{name}: {live_dangerous(page)}"


def test_no_page_references_an_external_resource(populated):
    """No CDN, webfont, favicon or analytics pixel.

    Two reasons, and both are load-bearing. A page that fetched anything would be an
    undisclosed outbound call from a tool whose pitch is that nothing leaves the
    building. And it would leak which cases an analyst opened to whoever hosts the
    asset.
    """
    store = CaseLedger(populated)
    page = webui.render_snapshot(store)
    store.close()

    offenders = external_resource_references(page)
    # The only permitted absolute URLs are in visible text the analyst should see, and
    # those are escaped, so they cannot appear inside an src/href attribute.
    assert not offenders, f"external resource references: {offenders}"
    assert "<link" not in page.lower(), "no stylesheet or icon link element"
    assert "@import" not in page, "no CSS import"
    assert "fonts.googleapis" not in page


def test_a_disposition_class_cannot_be_used_as_an_injection_point():
    """The pill interpolates into a class attribute, so it is validated not escaped.

    Escaping makes a value safe as text. A class attribute built from unvalidated
    input is a different hole, and the fix is to check the value against the enum.
    """
    for hostile in ('" onmouseover="alert(1)', "d-threat x' onload='", "<script>"):
        rendered = webui._disposition_pill(hostile)
        assert "onmouseover" not in rendered.split(">")[0]
        assert "<script>" not in rendered
        assert 'class="pill d-unknown"' in rendered, (
            f"an unknown disposition must fall back to a known class, got {rendered}"
        )


def test_a_valid_disposition_still_gets_its_own_colour():
    for disposition in ("threat", "spam", "clean", "manual_review", "unknown"):
        assert f'd-{disposition}' in webui._disposition_pill(disposition)


# --------------------------------------------------------------------------
# rendering correctness
# --------------------------------------------------------------------------


def test_the_queue_shows_the_machine_and_human_columns_separately(tmp_path, config):
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "threat_bec_valid_auth.eml"), config))
    )
    case_id = store.list_cases()[0].case_id
    store.resolve(case_id, disposition=Disposition.CLEAN, resolver="analyst")
    page = webui.render_queue(store.list_cases())
    store.close()

    assert "threat" in page and "clean" in page
    assert "analyst" not in page, (
        "the queue shows the human disposition; the resolver belongs on the case page"
    )


def test_an_overturned_verict_is_marked_as_overturned_not_as_agreement(tmp_path, config):
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "threat_bec_valid_auth.eml"), config))
    )
    record = store.list_cases()[0]
    store.resolve(record.case_id, disposition=Disposition.CLEAN, resolver="a")
    page = webui.render_case(store.get_case(record.case_id))
    store.close()

    assert "overturned" in page
    assert "machine said" in page and "human said" in page


def test_a_truncated_case_warns_that_the_analysis_is_partial(tmp_path):
    """Absence of evidence must be visible in the UI, not silently presented as a
    complete read.

    The limit is 40 characters against a 294-character body, so the truncation is
    real and its numbers are asserted rather than assumed: a test that skipped when
    the fixture failed to truncate would pass without asserting anything, which is
    the failure mode this whole project exists to refuse.

    ``Thresholds`` is frozen, like every config object here, so the tight limit is
    built with ``dataclasses.replace``. Assigning the field raises
    ``FrozenInstanceError`` rather than taking effect.
    """
    tight = dataclasses.replace(
        Config(replay=True, replay_dir=None),
        thresholds=dataclasses.replace(
            Config(replay=True, replay_dir=None).thresholds, body_char_limit=40
        ),
    )
    assert tight.thresholds.body_char_limit == 40, "replace must take effect"
    # triage_file parses *and* triages, so the body is cut at the limit the config
    # declares. Parsing at the default 8000 and triaging at 40 would record a partial
    # reading that never happened, and report 294 characters retained of 294.
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    verdict = triage_file(FIXTURES / "threat_bec_valid_auth.eml", tight)
    assert verdict.truncated, "40 of 294 characters must be recorded as truncated"
    receipt = Receipt.for_verdict(verdict)
    assert receipt.truncated, (
        "the receipt is what the ledger row is built from; if truncated does not "
        "survive here then a partial reading is stored as a complete one"
    )
    store.record_receipt(receipt)
    record = store.list_cases()[0]
    assert record.truncated, "the stored case must say it was a partial read"
    page = webui.render_case(record)
    queue = webui.render_queue(store.list_cases())
    store.close()
    assert "partial" in page.lower()
    assert "truncated before it was read" in page.lower()
    # The retained/original figures the verdict reported survive into the page, so an
    # analyst can see how much went unread rather than only that some of it did.
    assert "40 characters were retained of 294" in page
    assert "partial read" in queue.lower(), "the queue must flag it too, not only the case"


def test_agreement_with_no_resolved_cases_says_absent_not_zero(tmp_path, config):
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "clean_delivery_failure.eml"), config))
    )
    page = webui.render_agreement(store.agreement_summary())
    store.close()
    assert "absence of evidence" in page
    assert "not a clean bill of health" in page


def test_agreement_surfaces_a_clearance_a_human_overturned(tmp_path, config):
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "clean_delivery_failure.eml"), config))
    )
    record = store.list_cases()[0]
    # Asserted rather than skipped: the premise of this test is that the machine
    # cleared the message, and if that stops being true the test must say so instead
    # of passing without measuring anything.
    assert record.disposition == Disposition.CLEAN.value, (
        f"this test measures an overturned clearance; the fixture now dispositions "
        f"{record.disposition!r}"
    )
    store.resolve(record.case_id, disposition=Disposition.THREAT, resolver="a")
    page = webui.render_agreement(store.agreement_summary())
    store.close()
    assert "found a threat in mail the machine cleared" in page


def test_the_snapshot_inerts_its_forms_rather_than_leaving_dead_controls(tmp_path, config):
    """A snapshot is a file nobody serves, so a form that posts nowhere is a lie."""
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "threat_bec_valid_auth.eml"), config))
    )
    page = webui.render_snapshot(store)
    store.close()
    assert 'data-inert="1"' in page
    assert "<script" not in page.lower()


# --------------------------------------------------------------------------
# the queue as a readable table, not a dump of columns
#
# These came out of a vision-model inspection of the rendered page rather than out
# of the code: an ISO timestamp breaking across two lines mid-token, a status pill
# that reflowed with the prose of a subject and so landed in a different place in
# every row, and columns narrow enough that the pill was wider than its own header.
# None of that is visible to a test that only checks the text is present, so each
# one is asserted structurally here.
# --------------------------------------------------------------------------


def _cell_map(page: str) -> dict[str, str]:
    """The first queue row as `{cell-class: inner html}`.

    Built from the markup rather than from the renderer's internals, because the
    thing under test is where a value ends up on the page. Scoped to `<tbody>`:
    the header row is a `<tr>` too, and matching it is how the first version of
    this helper found no cells at all.
    """
    body = re.search(r"<tbody>(.*?)</tbody>", page, re.DOTALL)
    assert body, "no queue body rendered"
    row = re.search(r"<tr[^>]*>(.*?)</tr>", body.group(1), re.DOTALL)
    assert row, "no queue row rendered"
    cells = re.findall(
        r'<td class="(cell-[a-z]+)" data-label="([a-z() ]+)"[^>]*>(.*?)</td>',
        row.group(1),
        re.DOTALL,
    )
    return {cls: inner for cls, _label, inner in cells}


def test_the_queue_formats_the_timestamp_and_keeps_the_full_value(tmp_path, config):
    """Q1: a human date and time in the cell, the stored stamp lost nowhere.

    The column used to render `2026-11-03T15:12:01+00:00` and wrap it mid-token.
    Formatting it is only safe if the precision survives somewhere, so both the
    `title` and the machine-readable `datetime` attribute are asserted to carry the
    exact stored value, seconds and offset included.
    """
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "clean_vendor_docusign.eml"), config))
    )
    record = store.list_cases()[0]
    page = webui.render_queue(store.list_cases())
    store.close()

    assert record.opened_at, "the ledger must record when the case opened"
    opened = _cell_map(page)["cell-opened"]
    # Human form in the text: no `T`, no offset, no seconds.
    human = record.opened_at[:10] + " " + record.opened_at[11:16]
    assert human in opened, opened
    assert record.opened_at[11:19] not in opened.split(">", 1)[-1], (
        "the seconds survived into the visible text, which is the wrapping this fixes"
    )
    # And the full value survives, twice: as a tooltip and as a `datetime` attribute.
    assert f'title="{record.opened_at}"' in opened
    assert f'datetime="{record.opened_at}"' in opened
    assert "<time" in opened, "a timestamp should be marked up as a time element"


def test_a_timestamp_that_does_not_parse_is_printed_as_stored(tmp_path):
    """A formatting helper must never become a place where data goes missing."""
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(Receipt.for_verdict(
        triage_message(_parse(FIXTURES / "clean_vendor_docusign.eml"),
                       Config(replay=True, replay_dir=None))
    ))
    assert webui._timestamp("not-a-timestamp") .startswith("<span")
    assert "not-a-timestamp" in webui._timestamp("not-a-timestamp")
    assert webui._timestamp(None) != ""
    store.close()


def test_the_opened_column_header_says_which_timezone_it_prints(tmp_path, config):
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "clean_vendor_docusign.eml"), config))
    )
    page = webui.render_queue(store.list_cases())
    store.close()
    assert "opened (utc)" in page.lower()


def test_a_status_flag_never_shares_a_cell_with_the_subject(tmp_path, config):
    """Q2: the escalated pill used to flow inline with the subject text.

    On one row it landed on its own line, on the next after the last word, so it
    read as part of a subject an attacker wrote. It now has its own column, which
    is asserted by looking at which cell contains it - not by looking for the pill.
    """
    tight = dataclasses.replace(
        Config(replay=True, replay_dir=None),
        thresholds=dataclasses.replace(
            Config(replay=True, replay_dir=None).thresholds, body_char_limit=40
        ),
    )
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(Receipt.for_verdict(
        triage_file(FIXTURES / "threat_bec_valid_auth.eml", tight)
    ))
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "clean_delivery_failure.eml"), config))
    )
    records = store.list_cases()
    assert any(r.escalated for r in records), "fixture must produce an escalated case"
    assert any(r.truncated for r in records), "fixture must produce a partial read"
    page = webui.render_queue(records)
    store.close()

    cells = _cell_map(page)
    subject = cells["cell-subject"]
    assert "pill" not in subject, f"a flag is inline with the subject: {subject}"
    assert "escalated" not in subject

    flagged = [r for r in re.finditer(r"<tr class=\"row-flagged\">(.*?)</tr>", page, re.DOTALL)]
    assert flagged, "a case with a flag should mark its row"
    for row in flagged:
        cells = {
            cls: inner
            for cls, _label, inner in re.findall(
                r'<td class="(cell-[a-z]+)" data-label="([a-z() ]+)"[^>]*>(.*?)</td>',
                row.group(1), re.DOTALL,
            )
        }
        assert "pill" in cells["cell-flags"]
        assert "pill" not in cells["cell-subject"]
        # The row also carries a non-colour cue, so the warning is not carried by
        # the pill's colour alone.
        assert "row-flagged" in row.group(0)


def test_the_queue_table_is_fixed_layout_with_a_width_for_every_column(tmp_path, config):
    """Q3: pills wider than their own header, and 10-17px gutters."""
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "clean_vendor_docusign.eml"), config))
    )
    page = webui.render_queue(store.list_cases())
    store.close()

    assert 'class="queue"' in page
    assert re.search(r"table\.queue\s*\{[^}]*table-layout:\s*fixed", webui._STYLE)
    declared = set(re.findall(r'<col class="(col-[a-z]+)">', page))
    headers = set(re.findall(r'<th>(.*?)</th>', page))
    assert len(declared) == len(headers) == 8, (declared, headers)
    flexible = []
    for cls in declared:
        match = re.search(rf"\.{cls}\s*\{{\s*width:\s*(\d+)px", webui._STYLE)
        if not match:
            flexible.append(cls)
            continue
        assert int(match.group(1)) >= 46, f"{cls} is {match.group(1)}px wide"
    # Exactly one column absorbs the slack, and it is the one that can ellipsise.
    assert flexible == ["col-subject"], flexible


def test_a_long_subject_is_ellipsised_with_the_full_text_still_reachable(tmp_path, config):
    """Q4: ragged two-line rows, and the whole subject still readable.

    Truncation is only acceptable if the full value is reachable, so the cell links
    to the case page and, for a plain-text subject, also carries it as a tooltip.
    """
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "threat_forwarded_by_user.eml"), config))
    )
    record = store.list_cases()[0]
    page = webui.render_queue(store.list_cases())
    case_page = webui.render_case(record, token="t" * 32)
    store.close()

    assert 'class="cell-subject"' in page
    assert re.search(r"\.cell-subject[^{]*\{[^}]*text-overflow:\s*ellipsis", webui._STYLE)
    # Reachable two ways: the cell links to the case, and the case prints it in full.
    assert f'href="/case/{record.case_id[5:]}"' in page
    assert record.subject in case_page
    assert 'title="' in page, "a plain-text subject should carry its full text as a tooltip"


def test_text_that_looks_like_markup_is_never_placed_in_an_attribute(populated):
    """The one compromise the visual pass made, pinned so it cannot silently widen.

    `escape()` makes a value inert inside an attribute, but a subject reading
    `<img src=x onerror=...>` still *looks* like markup to whoever reviews the
    emitted HTML - and to this file's own `live_dangerous()`. So such a value gets
    no tooltip at all rather than a weaker escaping rule.
    """
    store = CaseLedger(populated)
    records = store.list_cases()
    hostile = [r for r in records if "phish.test" in r.sender]
    page = webui.render_queue(records)
    store.close()

    assert hostile, "the hostile case should be in the ledger"
    assert webui._title(hostile[0].subject) == "", (
        "a subject shaped like markup must not be copied into a title attribute"
    )
    assert "onerror=" not in re.sub(r"title=\"[^\"]*\"", "", page).split("<tbody")[0]
    assert not live_dangerous(page), live_dangerous(page)
    # The text is still on the page - as escaped element text, which is the point.
    assert "&lt;img src=x onerror=alert(&#x27;subject&#x27;)&gt;" in page


def test_the_active_tab_is_the_only_one_marked(tmp_path):
    """Q8: both tabs were coloured, one olive and one blue, so neither read as current."""
    queue = webui.render_page("queue", "<p>x</p>", active="queue")
    agreement = webui.render_page("agreement", "<p>x</p>", active="agreement")
    for page, current, other in ((queue, "Queue", "Agreement"),
                                 (agreement, "Agreement", "Queue")):
        nav = re.search(r"<nav>(.*?)</nav>", page, re.DOTALL).group(1)
        assert nav.count('aria-current="page"') == 1, nav
        marked = re.search(r'<a href="[^"]*" aria-current="page">([^<]*)</a>', nav)
        assert marked and marked.group(1) == current, nav
        assert f'>{other}</a>' in nav, "the inactive tab is still a link"
    assert re.search(r"nav a\[aria-current", webui._STYLE)
    assert re.search(r'nav a\[aria-current="page"\]\s*\{[^}]*background:',
                     webui._STYLE), "the current tab is a filled pill, not just a colour"


def test_the_team_name_is_in_the_page_header(tmp_path):
    """N1: confirmed by the operator and previously absent from the UI entirely."""
    page = webui.render_page("queue", "<p>x</p>", active="queue")
    assert "Campus Autonomous Defenders (CAD)" in page
    assert page.count("Campus Autonomous Defenders") == 1, (
        "one line in the header, not repeated on every element"
    )
    assert re.search(r"<header>.*Campus Autonomous Defenders.*</header>", page, re.DOTALL)


def test_the_page_is_anchored_by_a_footer(tmp_path):
    """A6: the view ended in a large empty region below the last card."""
    page = webui.render_page("queue", "<p>x</p>", active="queue")
    assert "<footer>" in page
    assert page.index("<footer>") > page.index("</main>")
    assert re.search(r"body\s*\{[^}]*display:\s*flex", webui._STYLE)
    assert re.search(r"footer\s*\{[^}]*margin-top:\s*auto", webui._STYLE)


# --------------------------------------------------------------------------
# the measurement: the denominators are not the same, and must say so
# --------------------------------------------------------------------------


def _resolve_one(store, name, disposition, resolver, config):
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / name), config))
    )
    case_id = store.list_cases()[-1].case_id
    store.resolve(case_id, disposition=disposition, resolver=resolver)
    return case_id


def test_every_rate_on_the_agreement_page_names_its_denominator(tmp_path, config):
    """A1: the comprehension defect. Agreement ran over 5 cases, the other two
    figures over 2, and nothing on the page said so.
    """
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    _resolve_one(store, "threat_anchor_mismatch.eml", Disposition.THREAT, "shawn", config)
    _resolve_one(store, "clean_delivery_failure.eml", Disposition.CLEAN, "shawn", config)
    _resolve_one(store, "clean_vendor_docusign.eml", Disposition.THREAT, "daniel", config)
    summary = store.agreement_summary()
    page = webui.render_agreement(summary)
    store.close()

    assert summary["resolved_cases"] == 3, summary
    assert summary["machine_cleared_resolved"] == 2, summary
    assert summary["machine_accused_resolved"] == 1, summary
    assert summary["agreement_rate"] != summary["false_negative_rate_among_cleared"]

    # Every figure that is a rate or a count-over-a-set is followed by `of <N>`.
    figures = re.findall(
        r'<div class="metric">([^<]*)</div>\s*<div class="stat-context">([\s\S]*?)</div>',
        page,
    )
    assert len(figures) == 4, figures
    for value, context in figures[1:]:
        assert "of <b>" in context, f"{value!r} has no denominator: {context!r}"
    assert "of <b>3</b> resolved cases" in page
    assert "of <b>2</b> cases the machine cleared" in page
    assert "of <b>1</b> cases the machine accused" in page


def test_the_hero_figure_shares_its_denominator_with_nothing_else(tmp_path, config):
    """A2: the hero used to print its `of 2 (50.0%)` context in the same red as the
    number, so the eye could not tell which of the three red things was the figure.
    """
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    _resolve_one(store, "clean_delivery_failure.eml", Disposition.CLEAN, "a", config)
    _resolve_one(store, "clean_vendor_docusign.eml", Disposition.THREAT, "a", config)
    page = webui.render_agreement(store.agreement_summary())
    store.close()

    hero = re.search(r'<span class="metric-hero">(\d+)</span><span class="hero-context">',
                     page)
    assert hero, page
    assert hero.group(1) == "1", page
    # The number alone is the red thing; its context is a separate, quieter element.
    context = re.search(r'<span class="hero-context">(.*?)</span>', page, re.DOTALL)
    assert context and "of <b>2</b>" in context.group(1)
    assert "metric-hero" not in context.group(1)
    sentence = re.search(r'<p class="prose hero-note">(.*?)</p>', page, re.DOTALL)
    assert sentence and "danger" not in sentence.group(1)


def test_the_agreement_page_explains_what_a_denominator_counts(tmp_path, config):
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    _resolve_one(store, "clean_delivery_failure.eml", Disposition.CLEAN, "a", config)
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "spam_bulk_marketing.eml"), config))
    )
    summary = store.agreement_summary()
    page = webui.render_agreement(summary)
    store.close()

    assert "resolved cases only" in page
    assert "neither agreement nor disagreement" in page
    assert f"{summary['resolved_cases']} of {summary['total_cases']}" in page
    assert f"the other {summary['open_cases']} are open" in page


def test_prose_on_the_agreement_page_is_measured_not_full_width(tmp_path, config):
    """A5: the explanatory paragraphs ran the full ~1100px."""
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    page = webui.render_agreement(store.agreement_summary())
    store.close()
    assert re.search(r"\.prose\s*\{[^}]*max-width:\s*65ch", webui._STYLE)
    assert 'class="prose"' in page or 'class="prose ' in page
    assert "prose-card" in page, "a card holding only prose is measured to its prose"


# --------------------------------------------------------------------------
# narrow screens: a functional requirement, not a nicety
# --------------------------------------------------------------------------


def _media_block(style: str, maximum: int = 2) -> list[tuple[int, str]]:
    """Each `@media (max-width: Npx)` block, with its breakpoint in pixels."""
    found = []
    for match in re.finditer(r"@media\s*\(max-width:\s*(\d+)px\)\s*\{", style):
        depth, start = 1, match.end()
        for i in range(start, len(style)):
            if style[i] == "{":
                depth += 1
            elif style[i] == "}":
                depth -= 1
                if depth == 0:
                    found.append((int(match.group(1)), style[start:i]))
                    break
    return found[:maximum]


def test_the_queue_restacks_into_labelled_cards_below_the_table_minimum():
    """M1/M2: at a phone width the MACHINE badge clipped to `manual_re...`.

    The verdict is the most important field in the row, so a layout that can clip it
    is a functional defect. The fix is a restack, asserted here three ways: a
    breakpoint at or above 768px so a tablet gets it too, every cell becoming its own
    labelled line, and the ellipsis being switched back off because there is room.
    """
    blocks = _media_block(webui._STYLE)
    assert blocks, "no max-width media query in the stylesheet"
    widest = max(px for px, _ in blocks)
    assert widest >= 768, (
        f"the restack breakpoint is {widest}px, so a 768px viewport still gets the "
        f"table and the badge still clips"
    )
    block = dict(blocks)[widest]
    assert re.search(r"table[^{]*\{[^}]*display:\s*block", block), "table not restacked"
    assert re.search(r"td\s*\{[^}]*display:\s*grid", block), "cells are not label/value lines"
    assert 'content: attr(data-label)' in block, "restacked cells have no label"
    assert re.search(r"\.cell-subject[^{]*\{[^}]*white-space:\s*normal", block), (
        "the ellipsis is still on at phone width, so the subject is still hidden"
    )
    assert re.search(r"min-width:\s*0", block), (
        "the table's desktop min-width survives into the card layout and the page "
        "scrolls sideways at 390px - which is the defect this rule exists to fix"
    )


def test_every_queue_cell_carries_the_label_the_card_layout_prints(tmp_path, config):
    """The restack is CSS-only, so the label text has to be in the markup."""
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    store.record_receipt(
        Receipt.for_verdict(triage_message(_parse(FIXTURES / "clean_vendor_docusign.eml"), config))
    )
    page = webui.render_queue(store.list_cases())
    store.close()

    cells = re.findall(r"<td([^>]*)>", page)
    assert cells, "no cells rendered"
    for attrs in cells:
        assert "data-label=" in attrs, f"a cell has no label for the card layout: {attrs}"
    labels = re.findall(r'data-label="([^"]+)"', page)
    assert labels == ["case", "opened", "machine", "conf", "human", "flags", "subject",
                      "sender"], labels


def test_case_page_tables_carry_labels_too(tmp_path, config):
    store = CaseLedger(tmp_path / "l.sqlite3", clock=_clock())
    case_id = _resolve_one(store, "threat_bec_valid_auth.eml", Disposition.THREAT, "shawn", config)
    store.add_note(case_id, "corroborated with the vendor", author="daniel")
    page = webui.render_case(store.get_case(case_id), token="t" * 32)
    store.close()
    for attrs in re.findall(r"<td([^>]*)>", page):
        assert "data-label=" in attrs or "colspan" in attrs, attrs


# --------------------------------------------------------------------------
# contrast: "comfortable" is a number
# --------------------------------------------------------------------------


def _luminance(hex_value: str) -> float:
    h = hex_value.lstrip("#")
    channels = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
              for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(foreground: str, background: str) -> float:
    a, b = _luminance(foreground), _luminance(background)
    return (max(a, b) + 0.05) / (min(a, b) + 0.05)


def test_the_palette_clears_wcag_aa_on_every_surface_it_is_printed_on():
    """Q7: headers and the subtitle were dim grey on near-black.

    The old greys did technically clear AA, which is exactly why nobody noticed: the
    problem was a 5.8:1 grey at 11px uppercase next to a 15:1 white. So the rule here
    is the ratio, measured from the tokens in the stylesheet, and it is set above the
    floor rather than at it.
    """
    tokens = dict(re.findall(r"(--[a-z-]+):\s*(#[0-9a-f]{6})", webui._STYLE))
    surfaces = ["--bg", "--bg-raised", "--bg-band", "--bg-hover", "--bg-inset"]
    inks = ["--ink", "--ink-soft", "--muted", "--head", "--link",
            "--threat", "--spam", "--clean", "--review"]
    assert tokens, "no colour tokens parsed - did the palette change shape?"
    for ink in inks:
        for surface in surfaces:
            ratio = _contrast(tokens[ink], tokens[surface])
            assert ratio >= 4.5, f"{ink} on {surface} is {ratio:.2f}:1, below AA"
    # The active tab is dark ink on the accent, and the accent has to be visible
    # against the bar it sits in.
    assert _contrast(tokens["--accent-ink"], tokens["--accent"]) >= 4.5
    assert _contrast(tokens["--accent"], tokens["--bg-raised"]) >= 3.0


def test_the_queue_and_the_measurement_use_a_type_scale_not_only_colour():
    """Q10: everything was one monospace size distinguished only by grey."""
    style = webui._STYLE
    sizes = {
        "page title": re.search(r"\.page-title\s*\{[^}]*font:\s*\d+ (\d+)px", style),
        "section": re.search(r"\.section-title\s*\{[^}]*font:\s*\d+ (\d+)px", style),
        "body": re.search(r"body\s*\{[^}]*font:\s*400 (\d+(?:\.\d+)?)px", style),
        "table head": re.search(r"thead th\s*\{[^}]*font:\s*\d+ (\d+)px", style),
        "hero figure": re.search(r"\.metric-hero\s*\{[^}]*font:\s*\d+ (\d+)px", style),
        "secondary figure": re.search(r"\.metric\s*\{[^}]*font:\s*\d+ (\d+)px", style),
    }
    found = {k: float(m.group(1)) for k, m in sizes.items()}
    assert len(set(found.values())) >= 4, found
    assert found["page title"] > found["body"], found
    assert found["section"] > found["table head"], found
    # A3: the secondary figures are demoted against the hero, not equal to it.
    assert found["hero figure"] >= found["secondary figure"] * 1.5, found
    # Prose is a sans; anything quoted from a message is monospace.
    assert "--sans:" in style and "--mono:" in style
    assert re.search(r"table\s*\{[^}]*var\(--mono\)", style)
    assert re.search(r"\.prose\s*\{[^}]*var\(--sans\)", style)


def test_no_font_is_fetched():
    """Q10 asked for a system sans, and a webfont would break constraint 2.

    Asserted rather than eyeballed: naming a local family is fine, `@font-face` or
    `url()` is an outbound fetch that tells a third party which cases were opened.
    """
    lowered = webui._STYLE.lower()
    assert "@font-face" not in lowered
    assert "url(" not in lowered
    assert "@import" not in lowered
    assert "system-ui" in lowered and "ui-monospace" in lowered


# --------------------------------------------------------------------------
# the structural claims, over the pages an operator actually serves
#
# The renderer-level assertions above are the fast ones. These drive the real
# HTTP routes, because the artifact a reviewer looks at is what comes off the
# socket, and a stylesheet change that added `url(//cdn...)` would reach the page
# only through the shell.
# --------------------------------------------------------------------------


def test_served_pages_have_no_script_and_no_external_reference(server):
    for path in ("/", "/agreement", "/does-not-exist"):
        status, body, headers = _get(f"{server}{path}")
        assert headers["Content-Security-Policy"] == CSP, path
        lowered = body.lower()
        assert "<script" not in lowered, path
        assert "<link" not in lowered, path
        assert "<img" not in lowered, path
        assert "<iframe" not in lowered, path
        assert "@import" not in lowered, path
        assert "@font-face" not in lowered, path
        assert "url(" not in lowered, path
        assert not external_resource_references(body), (path, external_resource_references(body))
        assert not live_dangerous(body), (path, live_dangerous(body))


def test_the_served_queue_prints_human_timestamps_and_a_flags_column(server):
    status, body, _ = _get(f"{server}/")
    assert status == 200
    assert "opened (utc)" in body.lower()
    assert "<time" in body
    assert 'data-label="flags"' in body
    assert "manual_re" not in body.replace("manual_review", ""), (
        "a truncated disposition badge reached the served page"
    )


def test_the_served_agreement_page_prints_every_denominator(server):
    status, body, _ = _get(f"{server}/agreement")
    assert status == 200
    assert "resolved cases only" in body
    assert "of <b>" in body


# --------------------------------------------------------------------------
# binding policy
# --------------------------------------------------------------------------


def test_binding_a_reachable_address_is_refused_without_an_explicit_flag(tmp_path, populated):
    from tenable_email.ledger import LedgerError

    with pytest.raises(LedgerError) as exc:
        webui.serve(populated, host="0.0.0.0", port=0, block=False)
    assert exc.value.reason == "refusing_to_bind_remote"
    assert "no authentication" in exc.value.detail


def test_loopback_is_accepted_without_the_flag(tmp_path, populated):
    httpd, thread = webui.serve_in_background(populated, host="127.0.0.1", port=0)
    try:
        assert httpd.server_address[0] in ("127.0.0.1", "::1")
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_serving_a_missing_ledger_is_refused_with_a_useful_message(tmp_path):
    from tenable_email.ledger import LedgerError

    with pytest.raises(LedgerError) as exc:
        webui.serve(tmp_path / "nope.sqlite3", port=0, block=False)
    assert exc.value.reason == "ledger_not_found"
    assert "run --provider ledger" in exc.value.detail


# --------------------------------------------------------------------------
# the real HTTP path, including CSRF
# --------------------------------------------------------------------------


@pytest.fixture()
def server(populated):
    httpd, thread = webui.serve_in_background(populated, host="127.0.0.1", port=0)
    host, port = httpd.server_address[0], httpd.server_address[1]
    yield f"http://{host}:{port}"
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def _get(url, cookie=None):
    """GET, returning the response even when it is an error.

    ``urlopen`` raises ``HTTPError`` for any 4xx or 5xx rather than returning it, so
    without the catch a test that expects a 404 crashes before it can assert one -
    and the error page is exactly the thing worth checking, because an error path
    that drops the CSP header is an error path that silently disables the policy.
    """
    request = urllib.request.Request(url)
    if cookie:
        request.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8"), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8"), dict(exc.headers)


def _post(url, fields, cookie=None):
    body = urllib.parse.urlencode(fields).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    if cookie:
        request.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8"), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8"), dict(exc.headers)


def test_every_response_carries_the_security_headers(server):
    status, body, headers = _get(f"{server}/")
    assert status == 200
    assert headers["Content-Security-Policy"] == CSP
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cache-Control"] == "no-store"


def test_a_missing_page_still_carries_the_policy(server):
    """An error path that drops CSP is how the policy stops meaning anything."""
    status, body, headers = _get(f"{server}/does-not-exist")
    assert status == 404
    assert headers["Content-Security-Policy"] == CSP


def test_the_queue_is_served_over_http(server):
    status, body, _ = _get(f"{server}/")
    assert status == 200
    assert "case(s)" in body
    assert "<script" not in body.lower()


def test_a_case_page_is_served_and_the_shortened_id_resolves(server, populated):
    store = CaseLedger(populated)
    short = store.list_cases()[0].case_id[5:]
    store.close()
    status, body, _ = _get(f"{server}/case/{short}")
    assert status == 200
    assert "machine verdict" in body.lower()
    assert "append-only" in body.lower()


def test_an_ambiguous_id_is_refused_rather_than_guessed(server):
    status, body, _ = _get(f"{server}/case/r")
    assert status == 404
    assert "no case matching" in body


def test_a_post_without_a_csrf_token_is_refused(server, populated):
    store = CaseLedger(populated)
    short = store.list_cases()[0].case_id[5:]
    store.close()
    status, body, _ = _post(
        f"{server}/case/{short}/resolve",
        {"disposition": "threat", "resolver": "attacker"},
    )
    assert status == 403
    assert "CSRF" in body

    store = CaseLedger(populated)
    assert store.list_cases()[0].resolution is None, (
        "a cross-site POST must not be able to resolve a case"
    )
    store.close()


def test_a_post_with_the_token_resolves_the_case(server, populated):
    status, body, headers = _get(f"{server}/")
    cookie = headers.get("Set-Cookie", "").split(";")[0]
    assert cookie.startswith(TOKEN_COOKIE), headers.get("Set-Cookie")
    token = cookie.split("=", 1)[1]

    store = CaseLedger(populated)
    record = store.list_cases()[0]
    short = record.case_id[5:]
    machine_before = (record.disposition, record.confidence, record.verdict_digest)
    store.close()

    status, body, _ = _post(
        f"{server}/case/{short}/resolve",
        {"disposition": "threat", "resolver": "shawn", "note": "confirmed",
         "csrf": token},
        cookie=cookie,
    )
    assert status == 200, body
    assert "resolved as threat" in body

    store = CaseLedger(populated)
    after = store.get_case(record.case_id)
    store.close()
    assert after.human_disposition == "threat"
    assert after.resolution.resolver == "shawn"
    assert (after.disposition, after.confidence, after.verdict_digest) == machine_before, (
        "resolving through the UI must not touch the machine verdict"
    )


def test_a_note_can_be_added_through_the_ui(server, populated):
    _, _, headers = _get(f"{server}/")
    cookie = headers.get("Set-Cookie", "").split(";")[0]
    token = cookie.split("=", 1)[1]

    store = CaseLedger(populated)
    short = store.list_cases()[0].case_id[5:]
    store.close()

    status, body, _ = _post(
        f"{server}/case/{short}/note",
        {"body": "<script>alert(1)</script> contacted sender", "author": "daniel",
         "csrf": token},
        cookie=cookie,
    )
    assert status == 200, body
    assert "note added" in body
    assert "<script>" not in body, "a note must be rendered escaped"
    assert "&lt;script&gt;" in body, "the text survives, escaped, so the analyst sees it"

    store = CaseLedger(populated)
    notes = store.get_case(store.list_cases()[0].case_id).notes
    store.close()
    assert any("contacted sender" in n.body for n in notes)


def test_an_empty_note_is_refused_through_the_ui(server, populated):
    _, _, headers = _get(f"{server}/")
    cookie = headers.get("Set-Cookie", "").split(";")[0]
    token = cookie.split("=", 1)[1]
    store = CaseLedger(populated)
    short = store.list_cases()[0].case_id[5:]
    store.close()

    status, body, _ = _post(
        f"{server}/case/{short}/note", {"body": "   ", "csrf": token}, cookie=cookie
    )
    assert status == 400
    assert "empty_note" in body


def test_an_oversized_post_is_refused(server, populated):
    _, _, headers = _get(f"{server}/")
    cookie = headers.get("Set-Cookie", "").split(";")[0]
    token = cookie.split("=", 1)[1]
    store = CaseLedger(populated)
    short = store.list_cases()[0].case_id[5:]
    store.close()

    status, body, _ = _post(
        f"{server}/case/{short}/note",
        {"body": "x" * (128 * 1024), "csrf": token},
        cookie=cookie,
    )
    assert status == 413


def test_a_double_resolution_is_refused_through_the_ui(server, populated):
    _, _, headers = _get(f"{server}/")
    cookie = headers.get("Set-Cookie", "").split(";")[0]
    token = cookie.split("=", 1)[1]
    store = CaseLedger(populated)
    short = store.list_cases()[0].case_id[5:]
    store.close()

    fields = {"disposition": "threat", "resolver": "a", "csrf": token}
    assert _post(f"{server}/case/{short}/resolve", fields, cookie=cookie)[0] == 200
    status, body, _ = _post(f"{server}/case/{short}/resolve", fields, cookie=cookie)
    assert status == 400
    assert "already_resolved" in body


def test_the_agreement_route_is_served(server):
    status, body, _ = _get(f"{server}/agreement")
    assert status == 200
    assert "how to read this" in body.lower()


def test_query_filters_narrow_the_queue(server, populated):
    _, all_body, _ = _get(f"{server}/")
    _, open_body, _ = _get(f"{server}/?state=open")
    _, resolved_body, _ = _get(f"{server}/?state=resolved")
    assert "case(s)" in all_body
    _, _, = None, None
    count = lambda page: int(re.search(r">(\d+) case\(s\)", page).group(1))
    assert count(open_body) == count(all_body)
    assert count(resolved_body) == 0


def test_an_invalid_filter_value_is_a_client_error_not_a_crash(server):
    status, body, _ = _get(f"{server}/?state=banana")
    assert status == 400
    assert "unknown_state" in body


# --------------------------------------------------------------------------
# the CLI verbs that reach this module
#
# `webui.serve` and `webui.render_snapshot` are unreachable from the command
# line unless `ledger serve` and `ledger snapshot` call them, so these tests
# drive `cli.main` rather than the module functions directly: the argument
# plumbing, the exit codes, and the shape of the failure messages are the thing
# an operator actually depends on.
# --------------------------------------------------------------------------


def _wait_for_server(servers, errors, deadline: float = 15.0):
    """Block until `cli.main` has constructed its server, or fail loudly.

    A timeout here means the CLI never got as far as binding, which is a real
    defect and must not read as a flaky test - so the thread's exception, if it
    raised one, is reported rather than swallowed.
    """
    limit = time.monotonic() + deadline
    while time.monotonic() < limit:
        if errors:
            raise AssertionError(f"cli.main raised: {errors[0]!r}")
        if servers:
            return servers[0]
        time.sleep(0.05)
    raise AssertionError("ledger serve never reached ThreadingHTTPServer")


def test_ledger_serve_answers_on_an_ephemeral_port_through_the_cli(
    populated, monkeypatch, capsys
):
    """The whole path: argv, argparse, the ledger open, a bind on port 0, real HTTP.

    `serve_forever` is wrapped rather than replaced so nothing about the server is
    faked - the wrapper only captures the instance the CLI built, which is what
    lets the test shut it down.
    """
    servers: list[ThreadingHTTPServer] = []
    errors: list[BaseException] = []
    real = ThreadingHTTPServer.serve_forever

    def spy(self, *args, **kwargs):
        servers.append(self)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(ThreadingHTTPServer, "serve_forever", spy)

    def run() -> None:
        try:
            cli.main(
                ["ledger", "--root", str(populated.parent), "serve", "--port", "0"]
            )
        except BaseException as exc:  # noqa: BLE001 - re-raised by the assertion
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        httpd = _wait_for_server(servers, errors)
        host, port = httpd.server_address[0], httpd.server_address[1]
        assert host == "127.0.0.1", "the default bind stays loopback"
        assert port != 0, "port 0 must have resolved to a real ephemeral port"
        status, body, headers = _get(f"http://{host}:{port}/")
        assert status == 200
        assert headers["Content-Security-Policy"] == CSP
        assert "case(s)" in body
        assert not live_dangerous(body), live_dangerous(body)
    finally:
        for httpd in servers:
            httpd.shutdown()
        thread.join(timeout=10)
    assert not thread.is_alive(), "serve must return once the server is shut down"


def test_ledger_serve_refuses_a_reachable_bind_at_the_cli_with_no_traceback(
    populated, capsys
):
    """A refusal an operator can act on, not a stack trace on a terminal.

    `serve` checks the bind policy itself, so this is the CLI path reporting the
    module's refusal, with `reason: detail` and exit 1.
    """
    code = cli.main(
        ["ledger", "--root", str(populated.parent), "serve",
         "--host", "0.0.0.0", "--port", "0"]
    )
    captured = capsys.readouterr()
    assert code == cli.EXIT_ERROR
    assert captured.err.startswith("ERROR: refusing_to_bind_remote:"), captured.err
    assert "no authentication" in captured.err
    assert "Traceback" not in captured.err


def test_ledger_verbs_report_a_missing_ledger_without_a_traceback(tmp_path, capsys):
    """Both new verbs reuse `_open_ledger`, so they behave like the other five.

    Nothing is created and nothing is guessed: `--root` with no store under it is
    the same refusal `ledger list` already gives.
    """
    empty = tmp_path / "noruns"
    empty.mkdir()
    for verb, extra in (("serve", []), ("snapshot", ["-o", str(empty / "s.html")])):
        capsys.readouterr()
        code = cli.main(["ledger", "--root", str(empty), verb, *extra])
        captured = capsys.readouterr()
        assert code == cli.EXIT_ERROR, verb
        assert captured.err.startswith("ERROR: ledger_not_found:"), (verb, captured.err)
        assert "Traceback" not in captured.err
        assert not (empty / "ledger.sqlite3").exists(), verb
        assert not (empty / "s.html").exists(), verb


def test_ledger_snapshot_writes_one_self_contained_file(populated, tmp_path, capsys):
    out = tmp_path / "ledger-snapshot.html"
    code = cli.main(
        ["ledger", "--root", str(populated.parent), "snapshot", "-o", str(out)]
    )
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert out.is_file(), captured.err

    page = out.read_text(encoding="utf-8")
    assert "<script" not in page.lower()
    assert not live_dangerous(page), live_dangerous(page)
    assert not external_resource_references(page), external_resource_references(page)
    assert "<link" not in page.lower()
    assert "@import" not in page
    # The queue and the measurement are both in there, so a reviewer who will not
    # run a server still sees the case list and the dangerous number.
    assert "cleared, then found hostile" in page.lower()
    assert "machine verdict" in page.lower()
    # The path and the byte count are printed, because this file is an artifact
    # somebody has to find and attach.
    assert str(out) in captured.out
    assert f"{out.stat().st_size} bytes" in captured.out


def test_ledger_snapshot_refuses_to_overwrite_without_force(populated, tmp_path):
    """A snapshot attached to an incident record is evidence, not scratch output."""
    out = tmp_path / "ledger-snapshot.html"
    assert cli.main(
        ["ledger", "--root", str(populated.parent), "snapshot", "-o", str(out)]
    ) == 0
    original = out.read_text(encoding="utf-8")

    marker = "the record somebody attached to case 12345"
    out.write_text(marker, encoding="utf-8")

    assert cli.main(
        ["ledger", "--root", str(populated.parent), "snapshot", "-o", str(out)]
    ) == cli.EXIT_ERROR
    assert out.read_text(encoding="utf-8") == marker, (
        "a refused overwrite must leave the existing file untouched"
    )

    assert cli.main(
        ["ledger", "--root", str(populated.parent), "snapshot", "-o", str(out),
         "--force"]
    ) == 0
    assert out.read_text(encoding="utf-8") == original


def test_ledger_snapshot_creates_the_directory_it_was_asked_to_write_into(
    populated, tmp_path
):
    """An operator names a path; a missing parent directory is not their error to fix."""
    out = tmp_path / "evidence" / "bundle" / "ledger.html"
    assert cli.main(
        ["ledger", "--root", str(populated.parent), "snapshot", "-o", str(out)]
    ) == 0
    assert out.is_file()
    assert not live_dangerous(out.read_text(encoding="utf-8"))


def test_serve_defaults_come_from_the_module_not_from_the_parser():
    """`--host` and `--port` default to the module's constants.

    Pinned to the constants rather than to literal values, so the default the CLI
    offers and the default `serve()` documents cannot quietly diverge - and so the
    loopback default itself is asserted, not just implied by the help text.
    """
    args = cli.build_parser().parse_args(["ledger", "serve"])
    assert args.host == webui.DEFAULT_HOST == "127.0.0.1"
    assert args.port == webui.DEFAULT_PORT
    assert args.allow_remote is False


def test_the_address_line_survives_a_pipe(populated):
    """`serve` flushes the bound address, so a wrapper can read the port it got.

    This is not cosmetic. `--port 0` asks the operating system for a port, so the
    printed line is the only way to learn which one, and `serve` then blocks forever:
    Python block-buffers stdout whenever it is a pipe rather than a terminal, so
    without a flush the line sits in the process's buffer and anything that started
    the server in the background reads an empty log and no port. Reproduces exactly
    that by reading the pipe, then drives one real request against the port found.
    """
    import select  # local import: the posix-only readiness check is this test's only use

    proc = subprocess.Popen(
        [sys.executable, "-m", "tenable_email", "ledger", "--root",
         str(populated.parent), "serve", "--port", "0"],
        cwd=REPO,
        env={"PYTHONPATH": str(REPO / "src"), "PATH": "/usr/bin:/bin"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready, _, _ = select.select([proc.stdout], [], [], 20)
        assert ready, "serve printed no address line into a pipe within 20 s"
        line = proc.stdout.readline()
        assert line.startswith("case ledger on http://"), line
        match = re.search(r"http://[^:/]+:(\d+)/", line)
        assert match, f"no port in {line!r}"
        port = int(match.group(1))
        assert port != 0, "the OS must report back the port it chose"

        status, body, headers = _get(f"http://127.0.0.1:{port}/")
        assert status == 200
        assert headers["Content-Security-Policy"] == CSP
        assert "case(s)" in body
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - only if shutdown hangs
            proc.kill()
            proc.wait(timeout=10)
