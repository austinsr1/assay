"""A local, read-mostly web view over the case ledger.

Renders the queue, one case in full, and the machine-versus-human measurement, over
``http.server`` from the standard library. No framework, no build step, no runtime
dependency, and **no JavaScript at all**.

The absence of JavaScript is a security decision and not a simplification. Every page
here renders attacker-controlled content: subjects, sender display names, link targets
and the analysis narrative derived from them. A page with no script context has no
script-execution surface, so an escaped ``<script>`` in a subject is inert text rather
than a payload one missed escape away from running. Filtering is done with query
parameters and links, forms post to the same URL, and the whole thing works with
images, fonts and scripts blocked - which is how a cautious SOC runs a browser anyway.

Three further properties, each of which a reviewer should be able to check:

*   **Loopback only by default.** Binding a non-loopback address requires an explicit
    flag, because this view has no authentication and the ledger holds real reported
    mail metadata.
*   **No external resources.** Not one ``http://``, protocol-relative ``//``, CDN,
    webfont or favicon reference. The stylesheet is inline. A page that fetched
    anything would be an undisclosed outbound call from a tool whose whole pitch is
    that nothing leaves the building, and it would also leak which cases an analyst
    opened.
*   **A Content-Security-Policy on every response**, denying everything by default, so
    a future edit that adds a script or an image fails closed rather than quietly
    opening the surface this design closed.

Two visual decisions are worth stating alongside the security ones, because each looks
like a compromise until you read why. Rows restack into labelled cards below 1024px,
because a table of eight monospace columns of identifiers cannot fit a phone and
clipping the machine verdict there would hide the one field in the row that matters.
And tooltips are withheld from some cells rather than given to every truncated one:
``escape()`` already makes a value inert inside an attribute, but a subject that reads
``<img src=x onerror=...>`` still *looks* like markup to whoever reviews the emitted
HTML, and this module's own structural test - correctly - refuses to tell the
difference. Plain-text values get a tooltip; values shaped like markup do not, and
their full text stays reachable one click away on the case page. See ``_title``.

Writes are limited to the ledger: resolving a case and adding a note. Neither touches
a mail system, so neither needs the approval gate - labelling a mailbox does, and that
path is unchanged. Both are CSRF-protected with a token in a cookie mirrored into a
hidden form field, because a localhost port is reachable from any web page the analyst
visits and a cross-site POST would otherwise be able to resolve cases.

The machine verdict is never editable from here. That invariant lives in SQLite
triggers, not in this module, so the UI could not weaken it even if it tried.
"""

from __future__ import annotations

import html
import re
import secrets
import socket
import sys
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, quote, unquote, urlparse

from .ledger import ACTION_OPEN, ACTION_RESOLVED, CaseLedger, CaseRecord, LedgerError
from .verdict import Disposition

__all__ = [
    "CSP",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "TOKEN_COOKIE",
    "LedgerRequestHandler",
    "escape",
    "render_agreement",
    "render_case",
    "render_page",
    "render_queue",
    "render_snapshot",
    "serve",
]

#: Refuse to bind anywhere but loopback unless the caller insists.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

#: Deny everything. No script, no image, no font, no frame, no external anything.
#: Forms may post to this origin only, and links may be followed.
CSP = (
    "default-src 'none'; script-src 'none'; object-src 'none'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'self'; style-src 'unsafe-inline'; img-src 'none'"
)

TOKEN_COOKIE = "tenable_email_ledger_csrf"

_DISPOSITIONS = tuple(d.value for d in Disposition)

_STYLE = """
/* Palette. Every text colour below clears WCAG AA against the surface it sits on;
   tests/test_webui.py recomputes the ratios from these tokens rather than trusting
   the eye, because "comfortable contrast" is not a claim you can leave unmeasured. */
:root {
  color-scheme: dark;
  --bg: #101418; --bg-raised: #161b21; --bg-band: #13181e; --bg-hover: #1b222b;
  --bg-inset: #0d1115; --line: #2b333d; --line-soft: #222a34;
  --ink: #e6edf3; --ink-soft: #c9d2dc; --muted: #9aa6b3; --head: #a3aebb;
  --accent: #58a6ff; --accent-ink: #0b0f14; --link: #79b8ff;
  --threat: #ff7b72; --spam: #e3b341; --clean: #56d364; --review: #9ecbff;
  /* Prose is a system sans; anything quoted *from a message* is monospace, so the
     reader can always tell the tool's own words from the data it is displaying. */
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial,
          "Noto Sans", sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
          "Liberation Mono", "DejaVu Sans Mono", monospace;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; min-height: 100vh; display: flex; flex-direction: column;
       font: 400 13.5px/1.55 var(--sans); background: var(--bg); color: var(--ink); }
header { padding: 15px 24px 13px; border-bottom: 1px solid var(--line);
         background: var(--bg-raised); }
.header-row { display: flex; flex-wrap: wrap; justify-content: space-between;
              align-items: baseline; gap: 4px 24px; }
.page-title { margin: 0; font: 600 19px/1.25 var(--sans); letter-spacing: -.01em;
              color: var(--ink); }
.page-title .dash { color: var(--muted); font-weight: 400; }
.sub { margin-top: 5px; font: 400 12.5px/1.45 var(--sans); color: var(--muted); }
.team { font: 600 12.5px/1.45 var(--sans); color: var(--head); white-space: nowrap; }
nav { padding: 9px 24px; border-bottom: 1px solid var(--line);
      background: var(--bg-raised); }
/* One accent, one treatment: the page you are on is a filled pill, the page you
   are not on is plain text. Colour is never the only signal - the active one also
   carries aria-current. */
nav a { display: inline-block; margin-right: 6px; padding: 5px 13px; border-radius: 7px;
        font: 500 13px/1.45 var(--sans); color: var(--head); text-decoration: none; }
nav a:hover { background: var(--bg-hover); color: var(--ink); }
nav a[aria-current="page"] { background: var(--accent); color: var(--accent-ink);
                             font-weight: 600; }
main { padding: 20px 24px 28px; max-width: 1180px; }
footer { margin-top: auto; padding: 13px 24px 16px; border-top: 1px solid var(--line);
         background: var(--bg-raised); font: 400 12px/1.5 var(--sans);
         color: var(--muted); }
a { color: var(--link); }
a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible,
textarea:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.section-title { margin: 0 0 4px; font: 600 17px/1.3 var(--sans); color: var(--ink);
                 font-variant-numeric: tabular-nums; }
.hint { margin: 0 0 16px; font: 400 12px/1.5 var(--sans); color: var(--muted); }
.prose { max-width: 65ch; margin: 0 0 10px; font: 400 13.5px/1.65 var(--sans);
         color: var(--ink-soft); }
/* A card that holds only prose is measured to the prose, not to the page: a 65ch
   paragraph inside a 1130px card leaves a void that reads as unfinished work. */
.prose-card { max-width: calc(65ch + 40px); }
.prose:last-child { margin-bottom: 0; }

/* --- the queue ---------------------------------------------------------- */
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font: 400 12.5px/1.5 var(--mono); }
table.queue { table-layout: fixed; min-width: 960px; }
.col-case { width: 140px; } .col-opened { width: 132px; } .col-machine { width: 118px; }
.col-conf { width: 58px; } .col-human { width: 118px; } .col-flags { width: 112px; }
.col-sender { width: 156px; } /* subject takes what is left */
th, td { text-align: left; padding: 7px 6px; border-bottom: 1px solid var(--line-soft);
         vertical-align: top; }
thead th { font: 600 11px/1.35 var(--sans); text-transform: uppercase;
           letter-spacing: .07em; color: var(--head); white-space: nowrap;
           border-bottom: 1px solid var(--line); }
tbody tr:nth-child(even) > * { background: var(--bg-band); }
tbody tr:hover > * { background: var(--bg-hover); }
tbody tr:last-child > * { border-bottom: 0; }
/* A case with a caveat gets a coloured spine as well as a flag, so the warning
   survives a colour-blind reader and a narrow column alike. */
tr.row-flagged .cell-id { border-left: 3px solid var(--spam); padding-left: 9px; }
.cell-id a { color: var(--link); text-decoration: none; }
.cell-id a:hover { text-decoration: underline; }
.cell-conf { color: var(--ink-soft); font-variant-numeric: tabular-nums; }
.cell-subject, .cell-sender { white-space: nowrap; overflow: hidden;
                              text-overflow: ellipsis; }
.cell-subject a { display: block; color: var(--link); text-decoration: none;
                  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.cell-subject a:hover { text-decoration: underline; }
/* Flags get their own column, so a status pill can never reflow with the prose of
   a subject and land in a different place in every row. The pills sit inside a
   wrapper rather than flexing the `td` itself: a table cell with `display: flex`
   leaves the table layout, and under `table-layout: fixed` that is how columns end
   up misaligned between one row and the next. */
.flags { display: flex; flex-direction: column; align-items: flex-start; gap: 3px; }
.cell-opened { white-space: nowrap; }

.pill { display: inline-block; padding: 1px 7px; border-radius: 999px;
        font: 500 11px/1.55 var(--mono); border: 1px solid currentColor;
        white-space: nowrap; vertical-align: top; }
.d-threat { color: var(--threat); } .d-spam { color: var(--spam); }
.d-clean { color: var(--clean); } .d-manual_review { color: var(--review); }
.d-unknown { color: var(--muted); }

/* --- case pages and cards ----------------------------------------------- */
.card { border: 1px solid var(--line); border-radius: 8px; padding: 15px 18px;
        margin-bottom: 16px; background: var(--bg-raised); }
.card h2 { margin: 0 0 11px; font: 600 11px/1.4 var(--sans); text-transform: uppercase;
           letter-spacing: .08em; color: var(--head); }
.card h2 + h2 { margin-top: 18px; }
dl { margin: 0; display: grid; grid-template-columns: 130px 1fr; gap: 5px 12px; }
dt { color: var(--muted); font: 500 12.5px/1.5 var(--sans); }
dd { margin: 0; overflow-wrap: anywhere; font: 400 12.5px/1.55 var(--mono);
     color: var(--ink); }
pre { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere;
      font: 400 12.5px/1.55 var(--mono); color: var(--ink); }
ul.reasons { margin: 0; padding-left: 18px; }
ul.reasons li { margin-bottom: 6px; overflow-wrap: anywhere;
                font: 400 12.5px/1.55 var(--mono); }
.warn { border-left: 3px solid var(--spam); padding: 8px 10px 8px 12px;
        margin-bottom: 12px; background: var(--bg-raised); }
.warn strong { color: var(--spam); }
.danger { border-left: 3px solid var(--threat); padding: 9px 12px;
          margin-bottom: 12px; background: var(--bg-raised); color: var(--ink);
          border-radius: 0 6px 6px 0; }
.danger strong { color: var(--threat); }
.good { border-left: 3px solid var(--clean); padding: 9px 12px; margin-bottom: 12px;
        background: var(--bg-raised); color: var(--ink); border-radius: 0 6px 6px 0; }
.good strong { color: var(--clean); }
.muted { color: var(--muted); }
form.inline { display: flex; gap: 8px; flex-wrap: wrap; align-items: center;
              margin-top: 12px; }
/* One gap rule for the whole toolbar: label-to-control and control-to-control are
   each fixed, so the row cannot drift out of alignment as it did when every piece
   of spacing was a margin on a different element. */
.filters { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 12px 18px;
           margin: 0 0 16px; padding: 0; }
.field { display: flex; flex-direction: column; gap: 5px; }
.field > label { font: 600 10.5px/1.3 var(--sans); text-transform: uppercase;
                 letter-spacing: .07em; color: var(--head); }
input, select, textarea, button { font: 400 12.5px/1.4 var(--mono); color: var(--ink);
  background: var(--bg-inset); border: 1px solid var(--line); border-radius: 5px;
  padding: 6px 9px; }
select { font-family: var(--sans); }
textarea { width: 100%; min-height: 62px; resize: vertical; }
button { background: #1f2630; cursor: pointer; font-family: var(--sans);
         font-weight: 500; }
button:hover { background: var(--bg-hover); border-color: var(--accent); }

/* --- the measurement ----------------------------------------------------- */
.grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px;
        align-items: start; margin-bottom: 16px; }
.metric { font: 600 21px/1.15 var(--sans); color: var(--ink-soft);
          font-variant-numeric: tabular-nums; }
.stat-context { margin-top: 7px; font: 400 12.5px/1.55 var(--sans); color: var(--muted); }
.stat-context b { color: var(--ink-soft); font-weight: 600;
                  font-variant-numeric: tabular-nums; }
.hero-card { border-left: 3px solid var(--threat); max-width: calc(65ch + 40px); }
.hero-card.is-zero { border-left-color: var(--clean); }
.hero-card.is-empty { border-left-color: var(--line); }
.hero { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.metric-hero { font: 600 40px/1 var(--sans); color: var(--threat);
               font-variant-numeric: tabular-nums; }
.metric-hero.is-zero { color: var(--clean); }
.metric-hero.is-empty { color: var(--muted); font-size: 19px; font-weight: 600; }
/* Red belongs on the figure alone. The denominator and the sentence beside it are
   deliberately quieter, so the eye lands on the number and then reads its context. */
.hero-context { font: 500 13px/1.5 var(--sans); color: var(--muted);
                font-variant-numeric: tabular-nums; }
.hero-context b { color: var(--ink-soft); font-weight: 600; }
.hero-note { margin: 10px 0 0; }
.denominator-note { border-left: 3px solid var(--accent); padding: 9px 12px;
                    margin-bottom: 16px; background: var(--bg-raised);
                    border-radius: 0 6px 6px 0; max-width: calc(65ch + 40px); }
.denominator-note p { margin: 0; font: 400 13px/1.6 var(--sans); color: var(--ink-soft);
                      max-width: 65ch; }
.flash { padding: 9px 13px; border-radius: 6px; margin-bottom: 14px;
         border: 1px solid var(--line); background: var(--bg-raised);
         font: 400 13px/1.5 var(--sans); }

/* --- narrow screens ------------------------------------------------------ */
/* The fix, not a band-aid: each row becomes a card of labelled fields, so the
   timestamp gets the full width of the screen and the machine badge is a line of
   its own that cannot be clipped by a neighbour. `td::before` reads its text from
   the `data-label` each cell carries, which is why no script is involved. */
@media (max-width: 1023px) {
  main { padding: 16px 14px 22px; }
  header, nav { padding-left: 14px; padding-right: 14px; }
  .table-wrap { overflow: visible; }
  table, table.queue { display: block; width: auto; min-width: 0;
                       table-layout: auto; }
  table { font-size: 13px; }
  thead { display: none; }
  tbody, tr, td { display: block; width: auto; }
  tbody tr { border: 1px solid var(--line); border-radius: 8px;
             background: var(--bg-raised); margin-bottom: 11px; padding: 7px 11px 9px; }
  tbody tr:nth-child(even) > * , tbody tr:hover > * { background: transparent; }
  tbody tr:hover { border-color: var(--accent); }
  td { display: grid; grid-template-columns: 7.2em minmax(0, 1fr); gap: 10px;
       align-items: baseline; padding: 3px 0; border-bottom: 0; }
  td::before { content: attr(data-label); font: 600 10.5px/1.5 var(--sans);
               text-transform: uppercase; letter-spacing: .07em; color: var(--head); }
  /* A cell that carries no label - a colspan placeholder - must not reserve the
     label column for an empty string. */
  td:not([data-label]) { display: block; }
  .cell-id { border-left: 0; padding-left: 0; }
  tr.row-flagged { border-left: 3px solid var(--spam); }
  .cell-subject, .cell-sender, .cell-subject a { white-space: normal; overflow: visible;
                                                 text-overflow: clip; }
  .flags { flex-direction: row; flex-wrap: wrap; }
  /* A row with no caveat has no flags to show, and in the card layout an empty
     labelled line is noise. This is safe only here: in the table layout hiding an
     empty cell would shift every column after it out of alignment with the rows
     beside it. */
  .cell-flags:empty { display: none; }
  .grid { grid-template-columns: 1fr; }
  dl { grid-template-columns: 1fr; gap: 1px 0; }
  dt { margin-top: 9px; }
  dd { margin-bottom: 2px; }
  .metric-hero { font-size: 34px; }
}
"""


def escape(value: Any) -> str:
    """The only way a value reaches the page.

    ``quote=True`` so an attribute cannot be broken out of, which is the case that
    matters most: every field rendered here originates in a message somebody reported,
    and the sender display name is attacker-chosen by definition.
    """
    return html.escape("" if value is None else str(value), quote=True)


def _disposition_pill(value: str) -> str:
    """A disposition as a coloured label.

    The class name is interpolated, so it is validated against the enum rather than
    passed through - an escaped value is safe as text but a class attribute built from
    unvalidated input is how a stylesheet becomes an injection point.
    """
    safe = value if value in _DISPOSITIONS else "unknown"
    label = escape(value or "-")
    return f'<span class="pill d-{safe}">{label}</span>'


#: Text that resembles markup must not be placed inside an attribute value.
_ATTR_UNSAFE = re.compile(r"<|>|\son[a-z]+\s*=|javascript:", re.IGNORECASE)


def _title(value: Any) -> str:
    """A ``title`` attribute carrying the full text, or nothing at all.

    ``escape()`` already makes a value inert inside an attribute - the quotes are
    escaped, so a payload cannot close the attribute it sits in. What escaping cannot
    do is stop a *reader*, or this module's own structural test, from seeing
    `` onerror=`` inside an attacker's subject and reading it as markup, because a
    hostile subject is made of exactly that shape. Rather than weaken the test that
    catches it, the view gives the tooltip only to values that are plain text and
    leaves every other value to the case page, which the truncated cell links to and
    where the full text is rendered as escaped element text. A tooltip is a
    convenience; the full value is never lost.
    """
    escaped = escape(value)
    return "" if _ATTR_UNSAFE.search(escaped) else f' title="{escaped}"'


def _timestamp(value: Any) -> str:
    """An ISO-8601 stamp as ``YYYY-MM-DD HH:MM``, with the stored value preserved.

    The ledger writes UTC at second resolution with an explicit offset, and a queue
    column that breaks ``2026-11-03T15:12:01+00:00`` across two lines mid-token is
    unreadable. So the cell shows the date and the hour and minute, carries the full
    value in a ``title`` and in the machine-readable ``datetime`` attribute, and the
    column header says UTC instead of every row repeating ``+00:00``. Nothing is
    dropped, only deferred. A value that does not parse is printed as it is stored -
    a formatting helper must never become a place where data goes missing.
    """
    raw = "" if value is None else str(value)
    text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return f'<span class="cell-time">{escape(raw)}</span>'
    shown = parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed
    return (
        f'<time class="cell-time" datetime="{escape(raw)}"{_title(raw)}>'
        f"{escape(shown.strftime('%Y-%m-%d %H:%M'))}</time>"
    )


def render_page(title: str, body: str, *, active: str = "", notice: str = "") -> str:
    """The shared shell. No script element, no external reference, nothing to fetch.

    The font stacks name local families only. There is no ``@font-face``, no
    ``@import`` and no ``url()`` anywhere in the stylesheet, because a page that
    fetched a font would be an undisclosed outbound call from a tool whose pitch is
    that nothing leaves the building, and it would tell whoever hosts the asset which
    cases an analyst opened.
    """
    nav = [
        ("/", "queue", "Queue"),
        ("/agreement", "agreement", "Agreement"),
    ]
    links = " ".join(
        f'<a href="{escape(href)}"'
        + (f' aria-current="page"' if key == active else "")
        + f">{escape(label)}</a>"
        for href, key, label in nav
    )
    flash = (
        f'<div class="flash" role="status">{escape(notice)}</div>' if notice else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>{escape(title)}</title>
<style>{_STYLE}</style>
</head>
<body>
<header>
<div class="header-row">
<div>
<h1 class="page-title">tenable-email <span class="dash">&mdash;</span> case ledger</h1>
<div class="sub">local only &middot; machine verdicts are append-only &middot; no
message body is stored</div>
</div>
<div class="team">Campus Autonomous Defenders (CAD)</div>
</div>
</header>
<nav>{links}</nav>
<main>
{flash}
{body}
</main>
<footer>
Nothing here leaves the machine: no script, no external stylesheet, font, image or
favicon is referenced, and the view binds loopback unless told otherwise.
</footer>
</body>
</html>
"""


def _filter_form(state: str | None, disposition: str | None) -> str:
    options = "".join(
        f'<option value="{escape(d)}"'
        + (" selected" if d == disposition else "")
        + f">{escape(d)}</option>"
        for d in _DISPOSITIONS
    )
    return f"""<form class="filters" method="get" action="/">
<div class="field">
<label for="f-state">state</label>
<select id="f-state" name="state">
<option value="">all</option>
<option value="{ACTION_OPEN}"{' selected' if state == ACTION_OPEN else ''}>open</option>
<option value="{ACTION_RESOLVED}"{' selected' if state == ACTION_RESOLVED else ''}>resolved</option>
</select>
</div>
<div class="field">
<label for="f-disp">machine disposition</label>
<select id="f-disp" name="disposition">
<option value="">all</option>
{options}
</select>
</div>
<div class="field">
<button type="submit">filter</button>
</div>
</form>"""


#: The queue's columns, in order, each with the class that fixes its width. `subject`
#: is deliberately unwidthed: under `table-layout: fixed` it takes what the eight
#: identifiers leave, so the one column that can be ellipsised absorbs the slack
#: instead of squeezing the pills that cannot.
_QUEUE_COLUMNS = (
    ("case", "col-case"),
    ("opened (utc)", "col-opened"),
    ("machine", "col-machine"),
    ("conf", "col-conf"),
    ("human", "col-human"),
    ("flags", "col-flags"),
    ("subject", "col-subject"),
    ("sender", "col-sender"),
)


def render_queue(
    records: Iterable[CaseRecord],
    *,
    state: str | None = None,
    disposition: str | None = None,
    token: str = "",
    total: int | None = None,
) -> str:
    """The queue an analyst works from, oldest first."""
    rows = []
    records = list(records)
    for record in records:
        short = record.case_id[5:] if record.case_id.startswith("rcpt-") else record.case_id
        href = f"/case/{quote(short, safe='')}"
        flags = []
        if record.truncated:
            flags.append('<span class="pill d-spam">partial read</span>')
        if record.escalated:
            flags.append('<span class="pill d-manual_review">escalated</span>')
        human_cell = (
            _disposition_pill(record.human_disposition)
            if record.human_disposition
            else '<span class="muted">&mdash;</span>'
        )
        # Empty rather than a placeholder dash: the cell is `:empty` so the card
        # layout can drop the line, and a dash would defeat that.
        flag_cell = f'<span class="flags">{"".join(flags)}</span>' if flags else ""
        row_class = ' class="row-flagged"' if flags else ""
        rows.append(
            # Hoisted out of the f-string: a backslash inside a replacement field is
            # PEP 701 syntax, Python 3.12 and newer only, and this package declares
            # requires-python >=3.10. Found by the second contributor's agent running
            # the suite on a 3.9 interpreter, after an AST feature_version check here
            # reported the file as parsing cleanly - feature_version does not enforce
            # the f-string grammar, so tests/test_portability.py detects the construct
            # directly instead of trusting the interpreter to refuse it.
            f"<tr{row_class}>"
            f'<td class="cell-id" data-label="case"{_title(record.case_id)}>'
            f'<a href="{escape(href)}">{escape(short)}</a></td>'
            f'<td class="cell-opened" data-label="opened">{_timestamp(record.opened_at)}</td>'
            f'<td class="cell-machine" data-label="machine">{_disposition_pill(record.disposition)}</td>'
            f'<td class="cell-conf" data-label="conf">{escape(f"{record.confidence:.2f}")}</td>'
            f'<td class="cell-human" data-label="human">{human_cell}</td>'
            f'<td class="cell-flags" data-label="flags">{flag_cell}</td>'
            f'<td class="cell-subject" data-label="subject">'
            f'<a href="{escape(href)}"{_title(record.subject)}>{escape(record.subject)}</a></td>'
            f'<td class="cell-sender" data-label="sender"{_title(record.sender)}>'
            f"{escape(record.sender)}</td>"
            "</tr>"
        )
    count = total if total is not None else len(records)
    columns = "".join(f'<col class="{cls}">' for _, cls in _QUEUE_COLUMNS)
    head = "".join(f"<th>{escape(label)}</th>" for label, _ in _QUEUE_COLUMNS)
    table = (
        f'<div class="table-wrap"><table class="queue">'
        f"<colgroup>{columns}</colgroup>"
        f"<thead><tr>{head}</tr></thead>"
        f'<tbody>{"".join(rows)}</tbody></table></div>'
        if rows
        else '<p class="muted">No cases match. Record some with '
        "<code>tenable-email run DIR --out RUN --provider ledger</code>.</p>"
    )
    return f"""<h2 class="section-title">{escape(count)} case(s)</h2>
<p class="hint">Subjects and senders are ellipsised here and shown in full on the case
page, which either links to.</p>
{_filter_form(state, disposition)}
{table}"""


def render_case(record: CaseRecord, *, token: str = "", notice: str = "") -> str:
    """One case in full: what the machine decided, what a person decided, and why."""
    reasons = "".join(
        f"<li>{escape(reason)}</li>" for reason in record.reasons
    ) or '<li class="muted">none recorded</li>'

    warnings = []
    if record.truncated:
        warnings.append(
            '<div class="warn">This analysis is <strong>partial</strong>. The message '
            "was truncated before it was read, so absence of evidence here is not "
            "evidence of absence.</div>"
        )
    if record.escalated:
        warnings.append(
            '<div class="warn">A model tier disagreed with the deterministic layer and '
            "escalated this case.</div>"
        )

    if record.resolution:
        res = record.resolution
        human = f"""<dl>
<dt>disposition</dt><dd>{_disposition_pill(res.disposition)}</dd>
<dt>resolved by</dt><dd>{escape(res.resolver or '-')}</dd>
<dt>resolved at</dt><dd>{escape(res.resolved_at)}</dd>
<dt>note</dt><dd><pre>{escape(res.note) or '<span class="muted">-</span>'}</pre></dd>
</dl>"""
        agrees = res.disposition == record.disposition
        banner = (
            '<div class="good">Human agrees with the machine verdict.</div>'
            if agrees
            else '<div class="danger">Human <strong>overturned</strong> the machine '
            f"verdict: machine said {escape(record.disposition)}, human said "
            f"{escape(res.disposition)}.</div>"
        )
    else:
        human = '<p class="muted">Unresolved. No human decision recorded yet.</p>'
        banner = ""

    dispositions = "".join(
        f'<option value="{escape(d)}">{escape(d)}</option>' for d in _DISPOSITIONS
    )
    short = record.case_id[5:] if record.case_id.startswith("rcpt-") else record.case_id
    resolve_form = "" if record.resolution else f"""<form class="inline" method="post"
 action="/case/{quote(short, safe='')}/resolve">
<input type="hidden" name="csrf" value="{escape(token)}">
<label class="muted" for="r-disp">human disposition</label>
<select id="r-disp" name="disposition" required>{dispositions}</select>
<input type="text" name="resolver" placeholder="your name" size="14">
<input type="text" name="note" placeholder="why" size="34">
<button type="submit">resolve</button>
</form>"""

    notes = "".join(
        f'<tr><td class="cell-time" data-label="at">{_timestamp(n.at)}</td>'
        f'<td data-label="author">{escape(n.author or "-")}</td>'
        f'<td data-label="note"><pre>{escape(n.body)}</pre></td></tr>'
        for n in record.notes
    )
    notes_block = (
        f'<div class="table-wrap"><table><thead><tr><th>at</th><th>author</th>'
        f'<th>note</th></tr></thead>'
        f'<tbody>{notes}</tbody></table></div>'
        if notes
        else '<p class="muted">No notes yet.</p>'
    )

    events = "".join(
        f'<tr><td class="cell-time" data-label="at">{_timestamp(e.at)}</td>'
        f'<td data-label="event">{escape(e.event_type)}</td>'
        f'<td data-label="actor">{escape(e.actor or "-")}</td>'
        f'<td data-label="detail">{escape(e.detail)}</td></tr>'
        for e in record.events
    )

    return f"""{banner}{''.join(warnings)}
<div class="card"><h2>case</h2>
<dl>
<dt>case id</dt><dd>{escape(record.case_id)}</dd>
<dt>opened</dt><dd>{escape(record.opened_at)}</dd>
<dt>pipeline</dt><dd>{escape(record.pipeline_status)}</dd>
<dt>action</dt><dd>{escape(record.action_status)}</dd>
<dt>digest</dt><dd class="muted">{escape(record.verdict_digest)}</dd>
</dl></div>

<div class="card"><h2>message metadata</h2>
<dl>
<dt>subject</dt><dd><pre>{escape(record.subject)}</pre></dd>
<dt>sender</dt><dd><pre>{escape(record.sender)}</pre></dd>
<dt>reported by</dt><dd><pre>{escape(record.reported_by) or '<span class="muted">-</span>'}</pre></dd>
<dt>source</dt><dd><pre>{escape(record.source)}</pre></dd>
</dl>
<p class="hint" style="margin-top:10px">Metadata only. No message body and no
attachment byte is stored in the ledger.</p></div>

<div class="card"><h2>machine verdict &mdash; append-only</h2>
<dl>
<dt>disposition</dt><dd>{_disposition_pill(record.disposition)}</dd>
<dt>confidence</dt><dd>{escape(f'{record.confidence:.2f}')}
 <span class="muted">({escape(record.confidence_band)})</span></dd>
<dt>attack type</dt><dd>{escape(record.attack_type or '-')}</dd>
</dl>
<h2>reasons</h2>
<ul class="reasons">{reasons}</ul>
<h2>analysis</h2>
<pre>{escape(record.analysis) or '<span class="muted">-</span>'}</pre>
</div>

<div class="card"><h2>human decision</h2>
{human}
{resolve_form}
</div>

<div class="card"><h2>notes</h2>
{notes_block}
<form class="inline" method="post" action="/case/{quote(short, safe='')}/note">
<input type="hidden" name="csrf" value="{escape(token)}">
<input type="text" name="author" placeholder="your name" size="14">
<textarea name="body" placeholder="add a note" required></textarea>
<button type="submit">add note</button>
</form>
</div>

<div class="card"><h2>event trail</h2>
<div class="table-wrap"><table><thead><tr><th>at</th><th>event</th><th>actor</th>
<th>detail</th></tr></thead>
<tbody>{events or '<tr><td colspan="4" class="muted">none</td></tr>'}</tbody></table>
</div>
</div>"""


def render_agreement(summary: dict[str, Any]) -> str:
    """The measurement, with the dangerous number kept out of every rate.

    An agreement rate can be made to look good by escalating everything, so the
    false-negative count among cleared messages gets its own block and its own
    colour rather than being one cell in a table.

    **Every denominator is printed, because the denominators are not the same.**
    Agreement is measured over every resolved case while the cleared and accused
    figures are measured over the resolved cases that fall in one of those two
    sets - on a real ledger that is 5 against 2, and a reader who compares 60.0%
    with "0 of 2" as though they shared a base will draw a conclusion the data does
    not support. So each card says "of N", and a line above them says what N means
    and that an open case is in none of them.
    """
    def pct(value: Any) -> str:
        return "no resolved cases yet" if value is None else f"{value:.1%}"

    cleared = summary["machine_cleared_resolved"]
    hostile = summary["cleared_then_threat"]
    rate = summary["false_negative_rate_among_cleared"]
    accused = summary["machine_accused_resolved"]
    resolved = summary["resolved_cases"]
    open_cases = summary["open_cases"]

    # Red on the figure alone: the denominator and the sentence beside it are
    # deliberately quieter, so the eye finds the number first and its context second.
    if cleared == 0:
        hero = (
            '<div class="card hero-card is-empty"><h2>cleared, then found hostile</h2>'
            '<div class="hero"><span class="metric-hero is-empty">nothing to measure '
            'yet</span><span class="hero-context">of <b>0</b> cases the machine '
            "cleared</span></div>"
            '<p class="prose hero-note">No message the machine cleared has been '
            "resolved by a human yet, so there is nothing to measure. This is an "
            "absence of evidence, not a clean bill of health.</p></div>"
        )
    else:
        tone = "" if hostile else " is-zero"
        hero = (
            f'<div class="card hero-card{tone}"><h2>cleared, then found hostile</h2>'
            f'<div class="hero"><span class="metric-hero{tone}">'
            f"{escape(hostile)}</span><span class=\"hero-context\">of <b>{escape(cleared)}</b> "
            f"cases the machine cleared and a human resolved &middot; "
            f"{escape(pct(rate))}</span></div>"
            + (
                '<p class="prose hero-note">A human found a threat in mail the '
                "machine cleared. Every one of these is worth reading.</p>"
                if hostile
                else '<p class="prose hero-note">No clearance has been overturned '
                "by a human. This is measured over the cleared cases a person has "
                "looked at, not over everything the machine cleared.</p>"
            )
            + "</div>"
        )

    return f"""{hero}
<div class="denominator-note"><p>Every rate on this page is measured over
<strong>resolved cases only</strong>: {escape(resolved)} of {escape(summary['total_cases'])}
cases here have a human decision, and the other {escape(open_cases)} are open. An open
case counts as neither agreement nor disagreement, so it appears in no denominator -
which is why the bases differ between the cards below and the figures are not
comparable with one another.</p></div>
<div class="grid">
<div class="card"><h2>cases</h2>
<div class="metric">{escape(summary['total_cases'])}</div>
<div class="stat-context">{escape(open_cases)} open &middot;
{escape(resolved)} resolved</div></div>

<div class="card"><h2>agreement</h2>
<div class="metric">{escape(pct(summary['agreement_rate']))}</div>
<div class="stat-context">of <b>{escape(resolved)}</b> resolved cases &middot;
{escape(summary['agree'])} agree &middot; {escape(summary['disagree'])} disagree</div>
</div>

<div class="card"><h2>cleared then spam</h2>
<div class="metric">{escape(summary['cleared_then_spam'])}</div>
<div class="stat-context">of <b>{escape(cleared)}</b> cases the machine cleared and a
human resolved</div></div>

<div class="card"><h2>accused then clean</h2>
<div class="metric">{escape(summary['accused_then_clean'])}</div>
<div class="stat-context">of <b>{escape(accused)}</b> cases the machine accused and a
human resolved &middot; {escape(pct(summary['false_accusation_rate_among_accused']))}
&middot; symmetry matters: only tracking false negatives rewards accusing
everything</div></div>
</div>

<div class="card prose-card"><h2>how to read this</h2>
<p class="prose">The agreement rate alone can be made to look excellent by a pipeline that
escalates everything, which is why the cleared-then-hostile count is reported on its own
and never folded into it. A rate with no denominator is shown as an absence of evidence
rather than as zero, because &ldquo;nothing cleared has been resolved yet&rdquo; and
&ldquo;nothing cleared was ever wrong&rdquo; are different facts and must not read the
same.</p>
<p class="prose muted">These numbers describe the cases in this ledger. They are not an
accuracy estimate for mail in general &mdash; see the measured behaviour section of the
README for what the committed corpora do and do not support.</p></div>"""


def render_snapshot(ledger: CaseLedger, *, title: str = "case ledger snapshot") -> str:
    """One self-contained HTML file: the queue, the measurement, and every case.

    Exists so a reviewer, a judge or a colleague who will not run a server can still
    see the artifact, and so a snapshot can be attached to an incident record. Same
    renderer as the live view, so the two cannot drift apart in what they show.
    """
    records = ledger.list_cases()
    summary = ledger.agreement_summary()
    parts = [
        '<h2 class="section-title">agreement</h2>',
        render_agreement(summary),
        '<h2 class="section-title" style="margin-top:26px">queue</h2>',
        render_queue(records, total=len(records)),
        '<h2 class="section-title" style="margin-top:26px">cases</h2>',
    ]
    for record in records:
        anchor = record.case_id[5:] if record.case_id.startswith("rcpt-") else record.case_id
        parts.append(
            f'<div id="{escape(anchor)}" style="margin-top:22px">'
            + render_case(record)
            + "</div>"
        )
    body = "".join(parts)
    # Forms are meaningless in a file nobody is serving, so they are stripped rather
    # than left as controls that silently do nothing.
    page = render_page(title, body)
    return page.replace("<form", "<form data-inert=\"1\" style=\"display:none\"")


class LedgerRequestHandler(BaseHTTPRequestHandler):
    """Serves the ledger. One handler instance per request, as http.server does."""

    #: Set by serve(); a handler cannot be constructed with arguments.
    ledger_path: Path = Path("ledger.sqlite3")
    allow_remote: bool = False
    server_version = "tenable-email-ledger"
    sys_version = ""

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        """Quieter, and never writes the request line to a shared log unasked."""
        sys.stderr.write(f"[ledger] {self.address_string()} {fmt % args}\n")

    def _send(self, body: str, *, status: int = 200, extra: dict[str, str] | None = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        # CSP on every response, including errors: the policy is what makes a future
        # edit that adds a script fail closed rather than open the surface silently.
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _page(
        self,
        title: str,
        body: str,
        *,
        active: str = "",
        notice: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        """Render and send. `headers` are response headers, not renderer arguments.

        Keeping those two separate is not pedantry: passing a Set-Cookie into the
        renderer is a TypeError that kills the request thread and the client sees a
        closed connection with no explanation, which is what this looked like from
        the outside.
        """
        self._send(
            render_page(title, body, active=active, notice=notice), extra=headers
        )

    def _fail(self, status: int, message: str) -> None:
        """An error page that carries the same headers as a successful one.

        The message is escaped: it interpolates whatever the client put in the URL or
        the case id, which is attacker-controlled by definition here.
        """
        self._send(
            render_page(
                "error",
                f'<div class="danger">{escape(message)}</div>'
                '<p><a href="/">back to the queue</a></p>',
            ),
            status=status,
        )

    def _ledger(self) -> CaseLedger:
        # Opened per request: sqlite connections are not thread-safe by default and
        # this is a threading server. Opening is cheap; sharing is a corruption risk.
        return CaseLedger(self.ledger_path)

    # -- CSRF -------------------------------------------------------------

    def _token(self) -> str:
        """The CSRF token for this client, issued once and held in a cookie.

        A localhost port is reachable from any web page the analyst visits, so a
        cross-site POST could otherwise resolve cases or inject notes. The token is
        mirrored into a hidden field; an attacker's page cannot read our cookie, so it
        cannot fill the field.
        """
        cookie_header = self.headers.get("Cookie") or ""
        jar: SimpleCookie = SimpleCookie()
        try:
            jar.load(cookie_header)
        except Exception:
            jar = SimpleCookie()
        existing = jar.get(TOKEN_COOKIE)
        if existing and existing.value and len(existing.value) >= 32:
            return existing.value
        return secrets.token_urlsafe(32)

    def _token_cookie(self, token: str) -> str:
        # SameSite=Strict and no Secure flag: this is loopback, where Secure would
        # prevent the cookie being set at all over http.
        return (
            f"{TOKEN_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age=86400"
        )

    def _token_valid(self, form_token: str) -> bool:
        return bool(form_token) and secrets.compare_digest(form_token, self._token())

    # -- routes -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        self._route(head=False)

    def do_HEAD(self) -> None:  # noqa: N802
        self._route(head=True)

    def _route(self, *, head: bool) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        token = self._token()
        cookie = {
            "Set-Cookie": self._token_cookie(token)
            if TOKEN_COOKIE not in (self.headers.get("Cookie") or "")
            else ""
        }
        cookie = {k: v for k, v in cookie.items() if v}

        try:
            store = self._ledger()
        except LedgerError as exc:
            self._fail(500, f"cannot open the ledger: {exc}")
            return
        try:
            notice = (query.get("notice", [""])[0])[:200]
            if path == "/":
                state = (query.get("state", [""])[0] or None)
                disposition = (query.get("disposition", [""])[0] or None)
                limit_raw = query.get("limit", [""])[0]
                limit = int(limit_raw) if limit_raw.isdigit() else None
                try:
                    records = store.list_cases(
                        state=state, disposition=disposition, limit=limit
                    )
                except LedgerError as exc:
                    self._fail(400, str(exc))
                    return
                body = "" if head else render_queue(
                    records, state=state, disposition=disposition, token=token
                )
                self._page("queue", body, active="queue", notice=notice,
                           headers=cookie)
                return

            if path == "/agreement":
                self._page(
                    "agreement", render_agreement(store.agreement_summary()),
                    active="agreement", notice=notice, headers=cookie,
                )
                return

            if path.startswith("/case/"):
                remainder = unquote(path[len("/case/"):])
                if not remainder:
                    self._fail(404, "no case id given")
                    return
                record = self._find(store, remainder)
                if record is None:
                    self._fail(404, f"no case matching {remainder!r}")
                    return
                self._page(
                    f"case {record.case_id}",
                    render_case(record, token=token, notice=notice),
                    active="queue", notice=notice, headers=cookie,
                )
                return

            self._fail(404, f"no such page: {path}")
        finally:
            store.close()

    def _find(self, store: CaseLedger, wanted: str) -> CaseRecord | None:
        """Accept the shortened id the queue prints; refuse an ambiguous one."""
        direct = store.get_case(wanted)
        if direct is not None:
            return direct
        matches = [c for c in store.list_cases() if wanted in c.case_id]
        return matches[0] if len(matches) == 1 else None

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        length_header = self.headers.get("Content-Length") or "0"
        try:
            length = int(length_header)
        except ValueError:
            self._fail(400, "malformed Content-Length")
            return
        # A bound, not a guess: this is a local single-analyst tool, and an unbounded
        # read is how a form post becomes a memory problem.
        if length < 0 or length > 64 * 1024:
            self._fail(413, "request body too large")
            return
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        fields = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

        if not self._token_valid(fields.get("csrf", "")):
            self._fail(403, "missing or mismatched CSRF token; reload the page")
            return

        try:
            store = self._ledger()
        except LedgerError as exc:
            self._fail(500, f"cannot open the ledger: {exc}")
            return
        try:
            if path.startswith("/case/") and path.endswith("/resolve"):
                short = unquote(path[len("/case/"):-len("/resolve")])
                record = self._find(store, short)
                if record is None:
                    self._fail(404, f"no case matching {short!r}")
                    return
                try:
                    store.resolve(
                        record.case_id,
                        disposition=fields.get("disposition", ""),
                        note=fields.get("note", ""),
                        resolver=fields.get("resolver", ""),
                    )
                except LedgerError as exc:
                    self._fail(400, f"{exc.reason}: {exc.detail}")
                    return
                self._redirect(f"/case/{quote(short, safe='')}",
                               f"resolved as {fields.get('disposition', '')}")
                return

            if path.startswith("/case/") and path.endswith("/note"):
                short = unquote(path[len("/case/"):-len("/note")])
                record = self._find(store, short)
                if record is None:
                    self._fail(404, f"no case matching {short!r}")
                    return
                try:
                    store.add_note(
                        record.case_id, fields.get("body", ""),
                        author=fields.get("author", ""),
                    )
                except LedgerError as exc:
                    self._fail(400, f"{exc.reason}: {exc.detail}")
                    return
                self._redirect(f"/case/{quote(short, safe='')}", "note added")
                return

            self._fail(404, f"no such action: {path}")
        finally:
            store.close()

    def _redirect(self, location: str, notice: str) -> None:
        """Redirect-after-post, so a refresh cannot re-submit the form."""
        target = f"{location}?notice={quote(notice[:200], safe='')}"
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", target)
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _is_loopback(host: str) -> bool:
    try:
        return socket.getaddrinfo(host, None)[0][4][0] in ("127.0.0.1", "::1")
    except OSError:
        return host in ("localhost", "127.0.0.1", "::1")


def serve(
    ledger_path: str | Path,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    allow_remote: bool = False,
    block: bool = True,
) -> ThreadingHTTPServer:
    """Start the ledger view. Refuses to bind a reachable address unasked.

    This view has no authentication. Binding it to anything but loopback would expose
    real reported-mail metadata to the network, so that requires an explicit flag
    rather than a host argument that happens to resolve outward.
    """
    if not allow_remote and not _is_loopback(host):
        raise LedgerError(
            "refusing_to_bind_remote",
            f"{host} is not loopback and this view has no authentication. Pass "
            "--allow-remote to accept that, or put an authenticating proxy in front.",
        )
    path = Path(ledger_path)
    if not path.exists():
        raise LedgerError(
            "ledger_not_found",
            f"no ledger at {path}. Record cases first with "
            "'run --provider ledger'.",
        )

    class Bound(LedgerRequestHandler):
        pass

    Bound.ledger_path = path
    Bound.allow_remote = allow_remote
    httpd = ThreadingHTTPServer((host, port), Bound)
    httpd.daemon_threads = True
    actual = httpd.server_address
    # Flushed, because this is the last thing printed before blocking forever and it
    # is how anything wrapping the server finds the port it actually bound when asked
    # for 0. stdout is block-buffered when it is a pipe, so without this the line
    # stays in the process and the caller sees an empty log.
    print(f"case ledger on http://{actual[0]}:{actual[1]}/  (Ctrl-C to stop)",
          flush=True)
    if allow_remote:
        print(
            "WARNING: bound to a reachable address with no authentication. "
            "Real reported-mail metadata is exposed to that network.",
            file=sys.stderr,
        )
    if block:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
        finally:
            httpd.server_close()
    return httpd


def serve_in_background(
    ledger_path: str | Path, *, host: str = DEFAULT_HOST, port: int = 0
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Start on an ephemeral port and return the server and its thread.

    For tests and for anything that wants the real HTTP path exercised rather than a
    renderer called directly. Port 0 asks the OS for a free one, so parallel tests do
    not collide.
    """
    httpd = serve(ledger_path, host=host, port=port, block=False)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread
