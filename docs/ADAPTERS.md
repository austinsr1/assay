# Email source adapters

How to connect this engine to an email platform, and what we deliberately do not
ship.

The investigation engine takes RFC 822 bytes and returns a verdict. It has never
known where those bytes came from. This document is about the seam: what an adapter
must provide, what exists, and what is only described here.

---

## Status, plainly

| Adapter | State | Tested |
|---|---|---|
| `eml-dir` — a directory of `.eml` files | **shipped, default** | yes, 33 in `tests/test_sources.py` |
| Gmail + Alert Center | **merged** — `src/tenable_email/gmail.py`, `src/tenable_email/alertcenter.py`; mailbox writeback still unbuilt | yes, 75 tests |
| IMAP (any provider) | described below | no |
| Microsoft 365 / Graph | described below | no |
| KnowBe4 PhishER | described below | no |

The last three are **documentation, not code**. That is a deliberate choice and the
reasoning is at the end of this file, because it is the kind of decision a reviewer
should be able to disagree with informed.

---

## The contract

`src/tenable_email/sources.py`. Three things:

```python
@dataclass(frozen=True)
class SourceItem:
    external_id: str              # the platform's own identifier
    raw: bytes                    # RFC 822 bytes - the engine's only input
    source: str = ""              # provenance label, e.g. "gmail:user@x/18f2..."
    reporter: str | None = None   # who reported it, if the platform knows
    received_at: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

class EmailSource(Protocol):
    name: str
    mutates: bool                 # must be False for intake
    def fetch(self, *, limit=None, since=None) -> Iterator[SourceItem]: ...
    def describe(self) -> str: ...
```

Register it, and it becomes selectable from the CLI:

```python
from tenable_email.sources import register_source
register_source("my-platform", MyPlatformSource)   # factory called as F(path=...)
```

```bash
tenable-email run <config> --source my-platform --limit 50
```

This repository ships one adapter built that way, and it is the worked example of the
contract rather than a special case:

```bash
tenable-email run google-intake.json --source google-alerts --limit 20 --out run-root
```

`src/tenable_email/google_intake.py` registers `google-alerts` on import, sets
`mutates = False`, and reads Google Workspace Alert Center for "User reported phishing"
alerts and then Gmail for each message those alerts name. Two details are worth copying
into any new adapter because both were defects before they were fixed:

* Registration is an import side effect, so `sources.py` imports adapter modules on demand
  from `_ADAPTER_MODULES`. Without that, `available_sources()` listed only `eml-dir` unless
  the CLI happened to have been imported first, and the MCP server saw a different set of
  sources than the shell did. Add a new adapter module to that tuple.
* Translate your own client's exception types into `SourceError` **at construction, not
  only inside `fetch()`**. `__init__` builds the clients, so a missing token file raised
  before `fetch()` was ever reached and escaped the CLI as a traceback. Preserve the
  specific reason through the translation - missing, expired and absent are three different
  remedies.

### Five rules, each of which exists because the alternative is a defect

**Yield raw bytes, not a parsed message.** Normalization has exactly one owner,
`parse.parse_message`. An adapter that parses its own way creates a second
interpretation of the same input, and the two will disagree in ways that only show
up as different verdicts for the same mail. A test asserts the engine's verdict is
identical whether the bytes arrive through the directory adapter or through a
platform adapter written only inside the test.

**Preserve platform facts; do not reinterpret them.** `metadata` carries what the
platform said. Do not convert a timestamp into a datetime, or guess what a field
means, or normalize a value into something more convenient. Loss here is
unrecoverable downstream.

**Order must be stable.** Replay recordings are keyed on message content, but a
batch run that reorders makes results unreproducible and diffs unreadable.
`iter_eml_dir` sorts for exactly this reason.

**A directory is a bounded scan, and the bound belongs to the walk.**
`iter_eml_dir` refuses a tree it cannot read completely: at most
`DEFAULT_MAX_EML_FILES` messages, no deeper than `DEFAULT_MAX_EML_DEPTH` levels,
never out through a symlink, and never into a system tree. That is the whole
reason the default adapter is safe to hand a caller-supplied path: pointing it at
a filesystem root used to walk the machine, cross a network mount and return
other projects' mail as the corpus that was asked for. `EmlDirectorySource.fetch`
gets one mechanism rather than two -- its `limit` **is** the walk's `max_files`, so
the number that stops the scan and the number that caps the answer cannot disagree
-- which is why a platform adapter with its own pagination should express the same
single ceiling instead of capping a full walk afterwards. A source that cannot
filter natively may ignore `limit`, but a source that stopped early has to say so.

**Intake is read-only.** A source that marks alerts seen, moves mail, or deletes
anything belongs on the writeback side behind a human approval, not here.
`source_for` refuses any source declaring `mutates = True`, and registration does
not bypass that check.

### Remediation is a different contract, and already exists

`src/tenable_email/writeback.py` — `WritebackProvider` with `name`, `mutates` and
`execute()`, selected by `provider_for()`, enforced by `runner.py`. Mutations require
a single-use approval token bound to the verdict digest it was granted against. Do
not invent a second remediation abstraction; implement that one.

Status is not a third contract. It is owned locally by the receipt and the case
ledger. Asking a mailbox to remember what we concluded would mean trusting a system
we do not control with our own findings.

---

## Platform notes

Every link below returned HTTP 200 when this was written (2026-11-03). That is the
only claim made about them: a live URL is not a correct one, and endpoints and SDK
shapes move. Verify against the linked page before implementing, and prefer the
vendor's current reference over any example you find in a blog post or in a model's
memory - the `beta` caveat on the Graph surface below is exactly the kind of thing
that goes stale without warning.

### Google Workspace — Gmail API + Alert Center

Reported phishing is **not** in the Gmail API. It arrives as an alert, and the
message body is fetched separately:

1. `alerts.list` on Alert Center, filtered to type `User reported phishing`
   (a display string, not an enum member) and source `Gmail phishing`.
2. Each `MailPhishing` payload carries `messages[]` with `messageId`, `recipient`,
   and — for reported mail only — `subjectText`, `messageBodySnippet`,
   `md5HashSubject`, `md5HashMessageBody`, `attachmentsSha256Hash`.
3. `users.messages.get?format=raw` on the Gmail API for the RFC 822 bytes.

Docs: [Alert Center reference](https://developers.google.com/admin-sdk/alertcenter/reference/rest),
[MailPhishing payload](https://developers.google.com/resources/api-libraries/documentation/alertcenter/v1beta1/java/latest/com/google/api/services/alertcenter/v1beta1/model/MailPhishing.html),
[Gmail API messages.get](https://developers.google.com/gmail/api/reference/rest/v1/users.messages/get).

Traps worth knowing before you write it:

- **Alert Center's only writable annotation is a four-value enum** about whether the
  *alert* was useful — `NOT_USEFUL`, `SOMEWHAT_USEFUL`, `VERY_USEFUL`. There is no
  comment field and no place to record a disposition. A "post our analysis back to
  the platform" step is not implementable here; it needs a local case record.
- **`data` arrives in two shapes.** Documented as an object with `@type`, but the
  REST surface and generated SDKs have both been seen returning it as a
  JSON-encoded string. Accept both; guess neither.
- **The `@type` URL is `type.googleapis.com/google.apps.alertcenter.type.MailPhishing`.** Splitting on `/` alone leaves the dotted package attached.
- **Step 3 can fail while step 2 still has content.** When the Gmail fetch fails the
  alert still carries a subject, a body snippet and attachment hashes, so an alert is
  analysable without the message. Record which you had; do not treat the snippet as
  the message.
- Scopes differ per API (`gmail.readonly` / `gmail.modify` / `gmail.labels` vs the
  Alert Center scope). One token does not imply the other.

**Implementation status:** merged. `src/tenable_email/gmail.py` and
`src/tenable_email/alertcenter.py` are on `main` with 75 passing tests, every one
injecting a fake transport so none can reach the network. The objection that kept
them on `feature/google-intake` is on record and still open: the mutating methods
(`create_label`, `modify_labels`) are not yet wired through the approval gate, so
nothing on `main` calls them and a caller can still mutate a mailbox without an
approval. The gated provider is the remaining piece, not the client.

### Microsoft 365 — Graph

The analogue of a user-reported phish is a **threat submission**:
[`emailThreatSubmission`](https://learn.microsoft.com/en-us/graph/api/resources/security-emailthreatsubmission?view=graph-rest-beta)
under
[`threatSubmission`](https://learn.microsoft.com/en-us/graph/api/resources/security-threatsubmission?view=graph-rest-beta),
with a list operation to enumerate what users have submitted. Message bodies come
from the ordinary Graph mail surface.

**The caveat that should decide whether you build this:** that API is `beta`. Beta
Graph endpoints change shape and get retired without the compatibility guarantees
the `v1.0` surface carries. An adapter frozen against beta in a repository, with no
test that can reach the service, will drift silently. If you implement it, pin the
exact endpoint and date you verified, and add a canned-response test so at least the
decoding is pinned even when the transport cannot be.

Also note the semantic difference from Google: a submission is a report *to
Microsoft*, which is a different object from an alert *from* the platform. Decide
which one you are reading before you write the fetch.

### IMAP — the one we would build next, and why

`imaplib` is in the standard library, so an IMAP adapter keeps
`dependencies = []` true and works against Gmail, Microsoft 365, Fastmail, Zimbra,
and any other server that speaks the protocol. One adapter covers more real
deployments than three vendor-specific ones, and it is the honest answer to
"provider-independent" rather than a collection of skeletons.

Shape: connect, authenticate, `SELECT` the reported-phish mailbox (most
organizations have one — a subaddress, a shared mailbox, or a transport rule
destination), `SEARCH` or `UID`-walk since a watermark, `FETCH (RFC822)` for the
bytes, and use the **UID** as `external_id`. Reference:
[RFC 3501](https://www.rfc-editor.org/rfc/rfc3501) and
[`imaplib`](https://docs.python.org/3/library/imaplib.html).

Traps: use UIDs and never sequence numbers, because sequence numbers are reassigned
when mail is expunged and a watermark built on them silently re-reads or skips
messages. Keep the connection read-only — `EXAMINE` rather than `SELECT` — so the
adapter cannot set `\Seen` flags and change what an analyst sees. That also keeps
`mutates = False` honest rather than aspirational.

This is the highest-value next adapter and it is testable offline against a canned
IMAP transcript.

### KnowBe4 PhishER — GraphQL

The platform the Exchange's own reference playbook is built on. Documented at
[developer.knowbe4.com/graphql/phisher](https://developer.knowbe4.com/graphql/phisher);
the site is JavaScript-rendered, so read it in a browser rather than fetching it.

Worth implementing only if you actually run PhishER, and worth noting that its
remediation surface — comments and classification tags — is richer than Alert
Center's, so a PhishER adapter can write results back in a way Google's cannot.

---

## Why we do not ship untested adapter skeletons

It was proposed, and it is a reasonable instinct: give people a starting point for
each platform, link the docs, and say "not tested." Four reasons we did not.

**The Exchange checks that referenced packages and commands actually exist.** A
skeleton that imports an SDK we do not depend on, or calls an endpoint that has
since moved, is a rejection risk rather than a contribution. We already removed two
declared extras for exactly this defect — installing them succeeded and changed
nothing, which is worse than not having them.

**In this tool a broken adapter fails in the dangerous direction.** A fetch that
silently returns nothing does not error; it produces no verdicts, and an analyst
believes the queue is empty. That is a false-negative factory wearing the clothes of
coverage. Absent is safer than plausible.

**"Untested" is a false choice here.** The tests that matter need no credentials and
no network. Every one of the 75 tests in the Gmail/Alert Center client injects a fake
transport. What they pin is the part that actually breaks: protocol conformance, a
clear refusal when unconfigured, never fabricating success, and correct decoding of a
canned API response. That is roughly forty lines of test per adapter, and it is what
would make a skeleton safe to ship.

**Documentation links rot and nothing fails.** A skeleton with a link goes stale in
months. A test against a canned response at least pins the decoding, so drift shows
up as a red build instead of as a broken integration in someone's SOC.

So the trade we made: one tested reference adapter that needs nothing, one tested
platform adapter waiting on its approval-gate wiring, and precise per-platform notes
with verified links for anyone who wants to write the next one. A working
demonstration rather than a collection of theoretical integrations.

If you do write one, the minimum bar is: satisfies `EmailSource`, `mutates = False`,
refuses clearly when unconfigured, never reports success it did not achieve, keeps
`dependencies = []` empty, and ships with canned-response tests.
