
# tenable-email

**Names, because three of them appear in this repository and they are not synonyms.** The
public repository is `assay` - to assay is to test a sample you were handed and report what
it contains *and what you could not determine*, which is what this does. The Python package
and import name is `tenable-email`, which predates the repository name and was not worth
renaming hours before a deadline. The Exchange listing is titled
**Email-Analyst-in-a-box**, which is the team's name for it and the title to judge it by.

Local-first triage and investigation of user-reported phishing, built for
Tenable SWARM Global 2026 - a **48-hour build-off** - by **Campus Autonomous
Defenders (CAD)**.

**This is a triage layer, not primary detection.** It reads a message a person already
reported, or one your secure email gateway already flagged and handed on - that report is
the primary classification and it is not ours. Nothing sits in the mail flow and nothing
blocks delivery. The job is what happens downstream of the report: settle the majority of
reported mail that turns out to be nothing, escalate the minority that is something, and
defer the rest with evidence an analyst can act on in seconds. So the headline metric is
automation rate at a bounded error rate, not recall on novel campaigns, and the metric
that carries the risk is **false clearances** - a reported threat waved through. Read
every number in this repository inside that boundary; component figures such as "the
phishing classifier caught 0 of 18 adversarial fixtures" describe one input to a triage
decision, not a claim about stopping an attack nobody reported.

## Why this exists: replacing frontier-hours with local compute

The reference implementation this project is measured against - the published KnowBe4
PhishER playbook, and the hospital deployment it was built for - sends **every unresolved
reported message to Claude Sonnet 4**, one message at a time, on a five-minute schedule.
That design works, and it is worth being precise about what it achieved: it replaced
analyst man-hours with frontier API hours, roughly one for one.

Our premise is that most of those frontier-hours are unnecessary. A reported message is
usually nothing, and "nothing" is usually provable from authentication headers, link
structure and two small CPU models in about ninety milliseconds. So this chain spends the
cheap local work first and reserves the expensive tier for the residual that survives it.
**The unit we are optimizing is not accuracy, it is frontier-hours per reported message.**

Two terms are used consistently across this repository and in the measurement artifacts:

* **micromodels** - the small CPU tier. A distilbert-class phishing classifier on ONNX
  runtime and a security-model ensemble for URL reputation and prompt injection. Local,
  cheap, and measured at roughly 90 ms per message for the whole tier.
* **frontier** - any non-micro language model, flash-class and above. In this project the
  frontier tier is a flash-class adjudicator **served on organization-owned hardware**, so
  the escalation path leaves the building never. A remote flash-class API was measured
  alongside it purely as a comparison arm and is labelled `remote` everywhere it appears.

**The measured split.** On 203 real benign business emails the micromodel tier settled
**171 - 84.2% - with zero false accusations**, at ~90 ms a message. The residual is the
~16% that reaches the adjudicator.

**How that compares, and exactly what the comparison is.** The reference published **no
clearance rate, no automation rate and no accuracy figure of any kind** - and on reflection
that is not an omission, it is a consequence of its architecture. **Claude is not a rung in
their ladder; Claude is the disposition.** Their own workflow definition polls KnowBe4 every
five minutes and routes every unresolved reported message to Claude Sonnet 4 on Bedrock at
`batchSize: 1`, tags it Clean, Spam or Threat, and posts the analysis to the ticket. There is
no cheaper step below it that could have settled a message first, so there is nothing that
could be "cleared before the frontier" and no clearance rate to report.

Which means the token spend is unconditional. **A reported email that turns out to be a
legitimate invoice costs exactly the same frontier call as one that turns out to be a
credential harvester**, and once those tokens are spent the cost is sunk whichever way the
tag came out. That is the waste this project exists to remove, and it is why the honest unit
of comparison is not a clearance percentage but **frontier cost per reported message**:
theirs is one multimodal Claude call per message, every message; ours is one flash-class
call on roughly one message in six, served on organization-owned hardware.

What the reference *did* publish is analyst-hours, and those numbers are worth taking
seriously because they are the ones that justified the design: 5-10 minutes per complex
email, ~100 reported emails a day, ~80 hours a month, ~930 hours a year, ~$70,000 in analyst
time, plus a qualitative assessment that Claude "performed remarkably well, resisting prompt
injection and trickery." (A ~$8k/year token figure circulates in a third-party summary and
is **unconfirmed**; it is not used here.) We are not disputing that ROI - replacing analyst
hours was the right call and it worked. We are saying that the frontier spend *inside* it is
largely unnecessary, because the same workflow's own arithmetic shows most of the queue is
routine.

That arithmetic is the strongest independent support for this thesis and it comes from their
numbers, not ours. Reconciling 100 messages a day with 80 hours a month implies **~2.2
minutes per email on average**, not the 5-10 minutes quoted for complex cases - if every
message really took 5-10 minutes the total would exceed a full FTE and contradict their own
80 h/month. A two-minute human average says most of that queue is routine pattern
recognition rather than deep reasoning, and routine pattern recognition is precisely what
ninety milliseconds of local work settles.

So the claim, stated carefully: on 203 real benign business emails our local micromodel tier
settled 84.2% with zero false accusations, which is 84.2% of reported mail that never needs
a frontier call at all - and because our adjudicator is local, the residual does not need a
*paid* one either. Their architecture has no configuration in which that is possible.

One further asymmetry is worth stating plainly, because it is a difference in kind rather
than degree: the reference reports that its model performed well; this repository reports a
measured clearance rate, a measured false-accusation count, a measured selective risk, and
the corpora and licences behind each. We would rather publish an uncomfortable number than
an adjective.

The adjudicator itself was measured two ways over the same 1,327 messages with only the
serving host changing: local **0.800 recall at 0.125 false-positive rate** against remote
**0.831 at 0.145** - a tie, at five times the wall clock locally. So the residual does not
need a remote model either.

**Two limits on that claim, stated before a reviewer finds them.**

* **Neither adjudication arm was Claude Sonnet 4.** Both were flash-class. So "replaces
  Claude" is an *inference* - a local flash-class model matches a remote flash-class model
  on this task, and the task is narrow (adjudicate a message a person already reported),
  not open-ended classification. It is not a head-to-head against a frontier reasoning
  model, and it is not presented as one.
* **The 84/16 split is what the micromodel configuration delivers today.** With the
  adjudicator switched on as currently gated, measured auto-clearance on that same corpus
  falls from 84.2% to 0-2.5%, because clearance requires every consulted tier to clear a
  confidence bar derived from a 6:1 cost ratio - and the bar is applied to each tier's
  *self-reported* confidence, which is uncalibrated and not comparable across models. A
  softmax classifier emits 0.99; a language model hedges. The gate therefore prefers the
  overconfident tier and penalizes the honest one, so adding a more capable model *reduces*
  automation. Diagnosed, reproduced and scoped as **Bundle S**; deliberately not fixed
  hours before a deadline, because it is the safety gate and changing it invalidates every
  committed full-stack number.

The mechanism behind that second limit is confirmed rather than inferred: three real benign business
messages disposition `CLEAN` with the micromodels alone and `MANUAL_REVIEW` once the
adjudicator is reachable, with every tier agreeing the messages are clean in both cases.

**Status: the chain runs, the command line runs, and both run offline.** Every
stage up to adjudication runs over a shipped synthetic corpus, with model responses
replayed from committed recordings, and the stage contract is machine-checked.
`tenable-email demo` dispositions all fourteen fixtures with no
arguments, no configuration, no credentials and no network (see
[How to run](#how-to-run) for the one-step install, and for the no-install
equivalent), and the MCP server and the agent skill are in place too
(see [MCP server](#mcp-server) and `SKILL.md`). What is still missing
is the evaluation harness on public corpora (Bundle E)
and the submission packaging (Bundle G); the outward write destination is an open
operator decision, so the writeback provider shipped here changes nothing by
default. This README stays deliberately honest about which is which, because
the Exchange review checklist verifies that installation instructions are accurate
and that referenced files, packages and commands actually exist.

This is a build-off artifact, not a production deployment. It reports no
production or savings figures. Every measurement it makes is per-email, on
synthetic fixtures and public corpora, and reproducible offline with no
credentials.

---

## Purpose

New here? [`docs/ELI5.md`](docs/ELI5.md) explains the whole system in plain language:
what happens to one reported email, why each design choice was made and what was
rejected instead, the measured results including the number that does not favour us,
and what we did not build. This README is the reference; that document is the argument.

Security teams triage user-reported phishing with a large multimodal model,
sending employee mail to an external inference API. The published reference for
this workflow is the KnowBe4 PhishER Email Analysis playbook, which polls
PhishER every five minutes and sends message content, embedded images and
attachments to Claude on AWS Bedrock, then posts a `Clean` / `Spam` / `Threat`
tag and an analysis comment back to the ticket.

This project implements the same workflow **feature-for-feature** while keeping
every inference call on hardware the organization already owns. The claim is not
that small models reason better than frontier models. It is that most of
reported-phish triage is **evidence assembly and pattern matching rather than
reasoning**, and that this can be measured rather than asserted.

The escalation slot is provider-agnostic: a local model by default, any
OpenAI-compatible endpoint - including Claude - when you have one and want it.

## Design

A staged cascade in which each stage is cheaper than the one after it, and most
messages never reach an LLM at all.

1. **Intake** (read-only) - Google Workspace Alert Center, or a directory of
   `.eml` files with no credentials required
2. **Parse and authenticate** (read-only, deterministic) - MIME, SPF, DKIM,
   DMARC, ARC, Reply-To, Return-Path
3. **Deterministic signals** (read-only) - lookalike domain by edit distance,
   anchor-text versus href mismatch, display-name spoofing, forwarded-message
  unwrapping, redirect unwrapping, attachment inventory, bulk-mail headers and
  injection surface
4. **Classifier cascade** (read-only) - a phishing classifier, a three-way
   fraud/spam/legitimate model, URL reputation per unwrapped destination, and two
  prompt-injection detectors, each optional and each recorded as unavailable when
  it has no endpoint
5. **Vision** (read-only) - embedded image extraction, verbatim transcription and
   brand-impersonation judgment via a local VLM
6. **Attachment structure** (read-only, sandboxed) - the optional `rea` workflow
   reports what a retained attachment is made of - container entries, sizes,
  digests, declared format - and no PDF or Word text is extracted
7. **Adjudication** (read-only) - local LLM for the ambiguous band, then the
   ensemble, which combines the deterministic findings and the tier votes
  asymmetrically; emits the analysis narrative, reasons and confidence
8. **Disposition and writeback** (**write - human approval required**) - mail
   label, case record, analyst notification

Stages 1-7 hold no write tools. Stage 8's individual mutations each require
their own approval, and the provider shipped here performs none of them:
`src/tenable_email/writeback.py` records what *would* have happened, which is the
honest default while the write destination is an open decision. The chain is
defined machine-readably in `stages.yaml`, and the prose, the skill text and the
code are all validated against that file rather than trusted to stay in sync:
`python3 tools/validate_contract.py` (or `tenable-email validate-contract`) fails
when the eight stages described here and the eight stages in the contract stop
being the same eight, in the same order, under the same titles, and when the
approval language the write stage declares stops appearing in this document.

Model tiers are behind one interface (`src/tenable_email/tiers.py`) and are
served from a content-addressed replay store
(`src/tenable_email/replay.py`, `fixtures/replay/`) unless an operator turns
replay off and names live endpoints through the environment. No endpoint has a
default address anywhere, and a replay miss never falls back to the network and
never fabricates an answer - it records the tier unavailable and continues.

Every verdict separates **verified facts** (authentication results, observed
URLs, attachment hashes, sender history) from **model judgments** (apparent
social engineering, suspicious intent, likelihood of impersonation) from
**unknowns** (whether an account was compromised, whether a recipient entered
credentials, whether an unexamined attachment is malicious). No stage may
promote an unknown to a fact.

Dispositions: `THREAT`, `SPAM`, `CLEAN`, `MANUAL_REVIEW`, and `UNKNOWN` when a
message could not be parsed into anything analysable.

## Prerequisites

- Python 3.10 or newer (the suite runs on 3.14), and nothing else: the core has
  **no runtime dependencies**
- No GPU, no credentials and no inference host for the shipped path - stages 4, 5
  and 7 are answered from committed recordings in `fixtures/replay/`
- Optional extras, each degrading gracefully when absent: `pip install
  -e .[vision]` bounds image size before the vision tier sends it, and `.[mcp]`
  runs the MCP server (nothing else in the package imports `mcp`). Those are the
  only two. QR decoding is designed but **not implemented**, so no extra is
  offered for it - an extra that installs a library nothing imports would look
  like a working feature to anyone who ran the install command. Attachment
  *content* is examined by an optional workflow that needs no Python extra at all,
  because it shells out to a separate program: see
  [Optional deep attachment analysis](#optional-deep-attachment-analysis-with-rea).
  See Limitations.
- Optional for live inference instead of replay: any OpenAI-compatible endpoint for
  stages 5 and 7, supplied through `TENABLE_EMAIL_*` environment variables
- Optional: Google Workspace service account with the `apps.alerts` and
  `gmail.readonly` scopes for live intake

Upstream services this project calls but does not manage:

- A phishing ONNX classifier exposing `POST /predict`
- A security model estate exposing `POST /url` and `POST /prompt-injection`
- A three-way fraud/spam/legitimate classifier, and an optional injection
  classifier (`Horizon-Labs/prompt-injection-guard-small` is the intended target)
- A local VLM and a local chat model, both OpenAI-compatible

## How to run

The package has **no runtime dependencies**, so installation is one step and
pulls nothing in:

```bash
pip install -e . --no-deps
```

Then the demo needs no arguments, no configuration and no network:

```bash
tenable-email demo
```

If you would rather not install anything, both of these work from a clone and are
verified by the test suite:

```bash
PYTHONPATH=src python3 -m tenable_email demo
```

`python3 -m tenable_email` on its own, with no install and no `PYTHONPATH`, fails
with `No module named tenable_email` — the package lives under `src/`. That is
stated here rather than left for you to discover, because the Exchange review
checks that documented commands actually run.

The demo dispositions all fourteen synthetic fixtures twice - deterministic layer
alone, then with the committed recordings - prints the disposition table, and
compares each result against `fixtures/synthetic/labels.json`. An escalation on a
threat-labelled fixture is reported as its own count, not folded into agreement and
not counted as a miss: with the shipped corpus it prints 10 agree, 2 escalated,
2 disagreed. These are the next three commands worth running:

```bash
tenable-email run fixtures/synthetic --out /tmp/cases
tenable-email show /tmp/cases/receipts/<receipt-id>.json
tenable-email validate-contract
```

`run` prints one line per message and a summary table of dispositions, and drives
each case through the receipt contract; `--out` writes the durable case records
beside a journal of the transitions. `show` renders one saved record with its
evidence grouped by provenance. Installing the package also gives you the console
script `tenable-email` with the same subcommands, and the suite itself is the other
no-credentials check:

```bash
python3 -m pytest tests/ -q                   # the whole chain, over 14 fixtures
python3 tools/validate_contract.py            # the contract against this README
bash tools/record-replay.sh --dry-run       # which tiers have endpoints configured
```

`--replay-dir` defaults to the committed corpus in `fixtures/replay/`, located from
the package rather than from the working directory, so a reviewer who configures
nothing gets the fifty-two recordings. If the corpus is not there - an installed
wheel carries no fixtures - the run prints one clear `corpus not found` line and
every model tier records itself `UNAVAILABLE`. It does not fail, and it does not
fabricate.

The triage path is also a library. `tenable_email.pipeline.triage_file(path)`
returns a disposition, confidence and band, reasons, an analysis narrative and the
evidence record. With no configuration it is the deterministic chain and every
model tier reports itself unavailable. With the shipped recordings it also produces
model judgments, offline and byte-identically, in two lines:

```python
import tenable_email as te

verdict = te.triage_file(
    "fixtures/synthetic/threat_image_credential_harvest.eml",
   te.Config(replay=True, replay_dir="fixtures/replay"),
)
print(verdict.disposition, verdict.confidence, verdict.attack_type)
for finding in verdict.evidence.by_provenance(te.Provenance.MODEL_JUDGMENT):
    print(finding.key, finding.value["stance"], finding.value["confidence"])
```

Recordings are regenerated from the synthetic corpus only - never from real mail,
because a recording carries the text it was shown - by `tools/record-replay.sh`,
which reads endpoints from the environment and prints per-tier recorded and failed
counts. It writes nothing it could not obtain live: an unreachable tier contributes
no recording and stays unavailable.

## MCP server

The chain is also an MCP server, so an investigating agent can call it instead of
reimplementing header forensics badly. The shape is the one that placed 2nd at
SWARM Black Hat 2026: `runtime: python`, `transport: stdio`, a process that sits
in the background and waits for an external AI to ask, executing the tools locally
and handing structured data back. The external model orchestrates; this server
holds the typed tools.

The server needs one package the core does not, which is why it is an extra and
not a dependency. Both majors are found at call time - `mcp.server.fastmcp.FastMCP`
on 1.x, `mcp.server.mcpserver.MCPServer` on 2.x - and neither is imported until a
server is actually built:

```bash
pip install -e .[mcp]
tenable-email-mcp                     # stdio: starts and waits for the client
```

With the extra **not** installed, the entry point prints the instruction rather
than a `ModuleNotFoundError`, and the advertised surface is still readable, so a
reviewer can check the promise before installing anything:

```bash
PYTHONPATH=src python3 -m tenable_email.mcpserver --list-tools
```

Nine tools, all read-only:

| Tool | What it gives a calling agent |
|---|---|
| `analyze_eml` | the full staged triage of one `.eml`: disposition, confidence and band, attack class, reasons, analysis, stages run, truncation, and the evidence grouped by provenance |
| `analyze_eml_directory` | a batch over a directory: one line per message, counts per disposition, label agreement in three numbers when a `labels.json` is present, and a `scan` block saying what was actually walked -- file count, both bounds, and whether either one bound |
| `explain_verdict` | the provenance-grouped evidence behind a saved case record, with gaps labelled as gaps |
| `check_auth` | SPF/DKIM/DMARC as the receiving MTA recorded them, alignment, and the raw header values truncated - verified facts, with the caveat attached |
| `lookalike_domain` | deterministic lookalike analysis of any domain against the configured profile, thresholds included |
| `analyze_urls` | redirect unwrapping, anchor-versus-href mismatch, IP literals, sender/trusted/neither classification, and URL reputation where an endpoint or a recording answers |
| `classify_local` | each model tier's vote separately, with its own score, source and error - no merged number, because disagreement is the escalation signal |
| `list_contracts` | `stages.yaml` as data: id, title, capability, provider, access, optionality, model tier, approval requirement |
| `get_case_record` | one durable case record as JSON and as Markdown, with its digests and closure blockers |

**No tool mutates anything.** Nothing here writes a file, opens a socket, spends a
credential or advances the write stage: two mechanisms enforce it rather than one
promise. Every tool runs with replay forced on, so a tier reads the committed
recordings and the live transport - and with it the store's write path, which is
only reachable after a live call - is unreachable; and no tool builds a runner
with a root directory. Where an outside action is what the disposition implies,
the response carries `proposed_writeback.actions` with `executed: false`, the
approval language the contract requires, and the command that would actually run
the gate. An MCP client is not a human approver.

Two more properties, both tested rather than asserted in prose here:

- **Errors come back as values.** `{"ok": false, "tool": ..., "error": {"code":
  "not-found", ...}}`. A raising tool would surface to a client as a stripped
  transport failure, which teaches an agent that the server is broken when the
  truth is that the path was wrong.
- **A directory walk is bounded, and a bound that binds is a refusal.**
  `analyze_eml_directory` reads at most `DEFAULT_MAX_EML_FILES` messages no deeper
  than `DEFAULT_MAX_EML_DEPTH` levels, never out of the directory it was given
  through a symlink, and never into a system tree. A directory larger than that
  comes back as an error naming the bound and how to narrow the request; the answer
  carries a `scan` block saying what was walked, so a partial reading cannot be
  mistaken for a complete one. Pointing this tool at a filesystem root used to walk
  the host and return everybody's mail on it.
- **No message content comes back out.** Findings whose value quotes the body -
  anchor text, injection matches, forwarded headers, a vision model's
  transcription, a tier's prose - return a digest and the explanatory detail, and
  never the text. The server is a protocol boundary, and a receipt is citable
  because it holds a digest of the reading rather than the reading.

The tool logic is plain importable Python in `src/tenable_email/mcpserver.py`; the
`mcp` import lives inside one function, so importing that module - for a test, for
the CLI, for a library caller who installed with `--no-deps` - never requires the
dependency. `SKILL.md` is the companion document: the workflow judgment the
tools cannot convey -- when to escalate rather than accept a disposition, how to
read tiers that disagree, and what must never be promoted from unknown to fact.

## Email source adapters

The engine takes RFC 822 bytes and returns a verdict. It has never known where those
bytes came from, and `src/tenable_email/sources.py` makes that seam explicit: an
`EmailSource` yields `SourceItem`s carrying raw bytes plus provenance, and nothing
else in the engine changes when a new platform is added.

The shipped default is `eml-dir`, a directory of `.eml` files. It is the default on
purpose - no credentials, no network, no account on any email platform - so the whole
pipeline stays runnable by someone who has never heard of us. A test asserts the
engine's verdict is identical whether the bytes arrive through that adapter or
through a platform adapter written only inside the test, which is what makes the
portability claim a measurement rather than a module layout.

```bash
tenable-email run fixtures/synthetic                       # default: read the path
tenable-email run <config> --source my-platform --limit 50  # through an adapter
```

Intake is read-only and `source_for` refuses a source declaring `mutates = True`; a
source that marks alerts seen or moves mail belongs behind the approval gate in
`src/tenable_email/writeback.py`, not here.

The directory adapter reads a bounded scan (`src/tenable_email/parse.py`): at most
`DEFAULT_MAX_EML_FILES` messages, no deeper than `DEFAULT_MAX_EML_DEPTH` levels, no
symlink out of the root, and a directory that needs more than that is refused rather
than half-read. `--limit` is the same ceiling, not a second one - the number that
stops the walk is the number that caps the answer - and a run that used it says so on
stdout, because three rows from a directory of three hundred should not read as a
whole corpus.

`docs/ADAPTERS.md` carries the contract, per-platform notes for Google Workspace,
Microsoft 365, IMAP and KnowBe4 PhishER with links that all returned HTTP 200 when
checked, and the reasoning for why no untested adapter skeleton ships. The Gmail and
Alert Center client is now on `main`, covered by `tests/test_alertcenter.py`,
`tests/test_gmail.py` and `tests/test_google_intake.py`; its mutating methods are
not yet wired through the approval gate, so nothing on `main` applies a label yet.
(The count of those tests is deliberately not written here - a hardcoded number rots
the first time a test is added, and it had already rotted once.)

The shipped adapter is selected by name, and the name is `google-alerts`:

```bash
cp google-intake.example.json google-intake.json   # then fill in ONE credential source
tenable-email run google-intake.json --source google-alerts --limit 20 --out run-root
```

Exactly one of these supplies a token, in this order of precedence: `alert_center_token`
and `gmail_token` per API, then `token` for both, then `token_file`, then
`service_account_file` (which needs `pip install .[google]` because minting a token from a
service-account key needs `google-auth`, and the core stays dependency-free), then the
`TENABLE_EMAIL_GOOGLE_ACCESS_TOKEN` environment variable. Copying the example verbatim and
running it fails immediately with `ERROR: alert_center_token_file_missing:` naming the file
to create - at construction, before any request, rather than as a 401 halfway through a run.
The example's `token_file` is a relative path, so it resolves against the working
directory; prefer an absolute one or the inline `token`.

`tenable-email run --help` points here for adapter details, and
`sources.available_sources()` lists what this build can construct. The scopes in the
example are read-only (`apps.alerts`, `gmail.readonly`), which is the point: intake is a
read path, `GoogleAlertsSource.mutates` is `False`, and `source_for` refuses a mutating
source rather than trusting an adapter not to opt out.

## Case ledger

Google Alert Center's only writable annotation is a four-value enum about whether the
*alert* was useful. There is no comment field and no place to record a disposition, so
the reference playbook's "post our analysis back to the platform" step has no
destination here - the platform it targets is a commercial product that provides one.
The ledger is ours: a local SQLite record of what the machine decided beside what a
human finally decided.

```bash
tenable-email run <dir> --out run --provider ledger   # record cases while triaging
tenable-email ledger --root run list --state open      # the queue, oldest first
tenable-email ledger --root run show <case-id>         # one case in full
tenable-email ledger --root run resolve <case-id> --disposition threat --resolver you
tenable-email ledger --root run note <case-id> "waiting on the sender's manager"
tenable-email ledger --root run agreement              # machine versus human
```

Two properties are enforced by the database rather than by convention. **The machine
verdict is append-only**: resolving inserts a row beside it, and SQLite triggers abort
any `UPDATE` or `DELETE` on the `cases` table, so a wrong verdict cannot be quietly
corrected - the wrong ones are the measurement. **No message body or attachment byte
reaches the disk**: digests and metadata only, exactly as receipts do, asserted by a
test that reads the ledger file as raw bytes.

`ledger agreement` reports one number on its own labelled line and never folds it into
a rate: how many messages the machine cleared were then found hostile by a person. An
agreement rate can be made to look good by escalating everything, so the dangerous
count is kept visible. A rate with no denominator is reported as absent rather than as
zero, because "nothing cleared has been resolved yet" and "nothing cleared was ever
wrong" are different facts.

The ledger borrows its shape from PhishER's data model, read out of the reference
workflow's own GraphQL query: two status axes, because "has the machine finished" and
"has a person closed this" are different questions; an append-only event trail with a
causer; and plural notes, because a case accumulates a conversation over days. See
`docs/REFERENCE-BASELINE.md` for what was adopted and what was rejected.

It writes nothing off-box. The provider is selected by name
(`--provider ledger` or `TENABLE_EMAIL_WRITEBACK_PROVIDER`), the default remains the
dry run that changes nothing, and an unconfigured ledger fails fast rather than
writing somewhere the operator did not choose.

### Viewing the ledger: `serve` and `snapshot`

```bash
tenable-email ledger --root run serve                       # the view, on port 8765
tenable-email ledger --root run serve --port 9000           # same, different port
tenable-email ledger --root run snapshot -o run/snapshot.html   # one static file
tenable-email ledger --root run snapshot -o run/snapshot.html --force
```

`serve` is a queue an analyst can work from: filters by state and machine disposition,
one case in full with its reasons, the human decision beside the machine's, the note
thread, the event trail, and the agreement measurement on its own page with the
cleared-then-hostile count kept out of every rate. Resolving a case and adding a note
are the only writes it accepts. `snapshot` writes the same three views - measurement,
queue, and every case - into one file for a reviewer who will not run a server, or for
attaching to an incident record.

Four properties of the view, stated plainly because each one is a security decision:

- **It binds loopback by default** and refuses any other address unless `--allow-remote`
  is passed. It **has no authentication**, so a reachable bind would expose real
  reported-mail metadata to that network, and the flag prints a warning to stderr.
- **It renders no JavaScript at all.** This is the primary defence rather than a
  simplification: every page here displays attacker-controlled subjects, sender display
  names, link targets and the narrative derived from them, so a page with no script
  context has no script-execution surface, and an escaped payload in a subject stays
  inert text instead of becoming a payload one missed escape away from running.
- **It fetches nothing external.** Not one stylesheet link, webfont, favicon, image or
  protocol-relative reference; the CSS is inline and the file is self-contained. A page
  that fetched anything would be an undisclosed outbound call from a tool whose entire
  pitch is that nothing leaves the building, and it would also leak which cases an
  analyst opened to whoever hosted the asset.
- **Every response carries a Content-Security-Policy** that denies everything by
  default, including the 404 and 400 pages, so a future edit that adds a script fails
  closed instead of quietly reopening the surface this design closed.

Both verbs read the store through the same path as the other five, so `--root` and
`--ledger` behave identically, and a missing ledger is one error line on stderr rather
than a traceback. The CSRF token is a cookie mirrored into a hidden form field,
because a localhost port is reachable from any web page the analyst visits and a
cross-site POST would otherwise be able to resolve cases. The machine verdict has no
edit path in the view because it has none in the schema: it is append-only in SQLite,
and a human overturning it is recorded as a resolution beside it.

### What the view looks like

Five screenshots of the running view, taken with a real browser against a ledger of
the fourteen committed synthetic fixtures - RFC 2606 reserved domains only, no real
mail, no real addresses, and no hostname, address or filesystem path anywhere in
them.

![The case queue: fixed-layout columns, a dedicated flags column, human-readable
UTC timestamps and a row spine marking cases with a caveat](docs/images/ledger-queue.png)

The queue. `escalated` and `partial read` sit in their own column rather than flowing
inline with a subject, so a status flag cannot land in a different place in every row;
the opened column prints `2026-11-03 15:12` under a header that says UTC and keeps the
full stored stamp in the element's `datetime` attribute; subjects and senders
ellipsise and link to the case that shows them in full.

![A threat case with its reasons, the analysis narrative, a human resolution, an
analyst note and the append-only event trail](docs/images/ledger-case.png)

One case in full: what the machine decided and why, what a person decided beside it,
the note thread, and the event trail that records both.

![The overturned banner: human overturned the machine verdict, machine said clean,
human said threat](docs/images/ledger-overturned.png)

The case the ledger exists to produce. The machine cleared a DocuSign lookalike on an
SPF pass and a human called it a threat, which is reported as an overturn rather than
quietly corrected - the verdict itself is append-only in the schema, not just in the
UI.

![The agreement view: the cleared-then-hostile figure, an explicit denominator beside
every rate, and a note stating that rates are over resolved cases only](docs/images/ledger-agreement.png)

The measurement. Every figure names its denominator, because they differ: agreement
here runs over 5 resolved cases while the cleared and accused figures run over 2 and
2, and a reader who compared them as though they shared a base would draw a conclusion
the data does not support. The red is on the number alone.

![The queue at a 390 by 844 viewport, restacked into cards with one labelled field
per line](docs/images/ledger-mobile.png)

The queue at a 390 px viewport. Below 1024 px each row restacks into a card of
labelled fields through a CSS media query, so the timestamp gets the full width of the
screen and the machine badge - the most important field in the row - has a line of its
own and cannot be clipped by a neighbour. Nothing is clipped and no horizontal
scrolling is required; the document's `scrollWidth` equals the viewport at 1440, 1280,
1024, 1023, 900, 768, 414, 390, 360 and 320 px.

Two things the styling deliberately does not do. It fetches no font: the type scale is
system sans for the tool's own prose and monospace reserved for data quoted out of a
message, so a reader can always tell the two apart, and naming a local family is the
only way to get that without an outbound request. And it withholds the tooltip from
any value whose text resembles markup. `escape()` already makes such a value inert
inside an attribute, but a subject reading `<img src=x onerror=...>` still *looks*
like markup to whoever reviews the emitted HTML, and the honest fix is to not put it
in an attribute rather than to weaken the test that catches it. Its full text is still
one click away on the case page.

See `src/tenable_email/webui.py` for the renderers and `tests/test_webui.py` for the
60 tests that pin all of the above structurally, over every route, rather than case by
case.

## Outputs

One structured case record per message - a *receipt*, not a copy of the message.
`src/tenable_email/receipt.py` builds it: the disposition, a confidence value and
the derived `high` / `medium` / `low` band, the attack class, the reasons list, the
analysis narrative, the stages that ran and the ones skipped with their reason, and
the evidence record grouped by provenance - each item marked as verified fact,
model judgment, unavailable tier or explicit unknown, with a **digest of its value
rather than the value**. Then two digests of its own: the sha256 over the canonical
JSON of the verdict, which is what an approval binds to, and the sha256 of the
corpus manifest the case was drawn from, which is what stops a case advancing
against a corpus that changed under it. `Verdict.to_dict()` and
`Verdict.to_json()` are the reference-shaped form; JSON and Markdown are both
written by `run --out`, and `show` renders a saved record.

Neither form carries a message body or an attachment byte, and
`tests/test_receipt.py` asserts that against every fixture - body text, every body
line, attachment bytes and their base64 - rather than trusting the constructor. A
receipt is citable because it holds a digest of the reading, not the reading.

## By the numbers

Measured at commit `40c3d53` on 2026-11-04. The commands are given because a count is worth
nothing a reader cannot reproduce, and because these drift with every commit - the exact
digits below are a snapshot, the ratio is the point.

```
# non-blank Python lines per area
for d in src tests eval tools; do
  printf '%s\t%s\n' "$d" "$(git ls-files "$d/*.py" "$d/**/*.py" | xargs -r cat | grep -cvE '^[[:space:]]*$')"
done
# and the same for shell, prose and generated data
git ls-files 'tools/*.sh'  | xargs -r cat | grep -cvE '^[[:space:]]*$'
git ls-files '*.md'        | xargs -r cat | grep -cvE '^[[:space:]]*$'
git ls-files 'eval/*.json' 'fixtures/*' | xargs -r cat | grep -cvE '^[[:space:]]*$'
```

| area | non-blank lines | files |
|---|---|---|
| `src/` | 17,304 | 25 |
| `tests/` | **17,313** | 36 |
| `eval/` harness (`.py`) | 5,359 | 6 |
| `tools/` (`.py`) | 1,200 | 4 |
| `tools/` (`.sh`) | 603 | 5 |
| **code total** | **24,476** | 70 |
| prose (`*.md`) | 6,686 | 20 |
| generated measurement data (`eval/*.json`, `fixtures/`) | 157,455 | 107 |

**Test-to-source is approximately 1:1** - 17,313 non-blank lines of tests against 17,304 of
source. That ratio is the reason several defects in this repository were caught by assertions
rather than by review, including a secret-scanner allowlist that silently blinded a whole
directory and a cross-check whose name claimed to be bidirectional while its body was not.

**Do not quote the total tracked line count as a size.** Generated measurement data is
157,455 of roughly 195,000 non-blank tracked lines - about four fifths. `eval/metrics.json`
and the four `eval/live-ab*.json` artifacts are output the harness wrote, not code anyone
wrote, and a figure that includes them would be technically true and substantively
misleading. The hand-written total is the code and prose rows: about 31,000 lines.

Binary files (6 PNG screenshots of the ledger web UI) are excluded from every count above.

## Known limitations

Stated now and to be kept current:

- **An external red-team review found this pipeline clearing attacker mail, and
  the clearance policy was changed because of it.** The report, every finding and
  what was verified against each is in [`docs/RED-TEAM-RESPONSE.md`](docs/RED-TEAM-RESPONSE.md).
  Previously a message that authenticated correctly and tripped no deterministic
  red flag was dispositioned `CLEAN` at 0.90 with no model consulted, and nothing
  downstream could reopen it. An attacker who registers a domain and publishes SPF
  and DKIM for it satisfies that condition completely. Passing authentication now
  establishes only that somebody controls the sending domain; an automatic
  clearance additionally requires *positive* evidence - the sender is this
  organization or is on the deployer's trust list, and every destination in the
  message is accounted for by that relationship. Everything else is unsettled, so
  the cascade asks the models, and `MANUAL_REVIEW` is the outcome only if nothing
  corroborates a clearance.

  What this did **not** do is make an unrelated destination a threat indicator.
  Legitimate mail links to unrelated services constantly, and treating a mismatch
  as a verdict is the flaw in the reference playbook that `docs/PARITY.md`
  records. The mismatch simply stopped being sufficient to *clear*.

  The measured cost, stated rather than buried: of the five clean-labelled
  fixtures in the shipped corpus, three still clear outright and two now go to a
  human. A test pins that floor, because a tightening whose degenerate solution is
  "escalate everything" is not a safety improvement.
- **One red-team finding remains open, and a corpus in this repository proves
  it.** A *single* forged `Authentication-Results` header with nothing to
  contradict it is indistinguishable from a receiver-added one inside a raw
  `.eml`, so header provenance cannot be established offline at all; closing it
  needs the receiving system's own metadata, which is what a deployed Gmail or
  Alert Center adapter supplies (the R01 residual — contradictory headers now do
  block a clearance, and a forged pass can no longer outrank a genuine fail).
  R04, R05, R06, R08 and R09 were all closed after that review; each is tracked
  with its status in
  [`docs/RED-TEAM-RESPONSE.md`](docs/RED-TEAM-RESPONSE.md), and it has a message
  in `fixtures/adversarial/` marked `open` and asserted under a **strict** xfail:
  fix the defect and the suite goes red until the expectation is consciously
  updated, so it can neither be quietly forgotten nor quietly regress. That
  mechanism has already fired three times in one night, on R04, R05 and R06. It is
  listed here because a limitation nobody published is not a limitation, it is a
  defect.

  Seventeen further hostile messages in that corpus are marked `closed` and
  asserted directly. Fourteen of them were measured dispositioning `CLEAN 0.90`
  with no model consulted before the fixes; the three added afterwards were
  verified at the parser level rather than measured end to end, and
  `docs/RED-TEAM-RESPONSE.md` says which is which.
- **No input-size policy runs before parsing.** A whole `.eml` is read into memory
  before any size check, the retained-part budget is applied per attachment rather
  than to the message or to aggregate decoded bytes, and there is no MIME
  part-count limit or parse timeout. A hostile message can therefore consume CPU
  and memory ahead of any stage-level protection. This matters for a service
  deployment and not for the offline CLI, but it is unaddressed either way.
- **`srcset` destinations are not enumerated.** Link analysis covers anchors,
  form actions, meta refresh, iframes, scripts, objects, embeds, base elements,
  images, CSS `url()` and inline event handlers. `srcset` is the one remaining
  destination-bearing attribute and it needs real parsing rather than a split,
  because its value is a comma-separated list of URLs with density descriptors.
- **The MCP server has no path policy.** `analyze_eml` and `analyze_eml_directory`
  accept any path the server process can read. Stdio MCP assumes a trusted local
  caller, but an agent steered by injected mail content is exactly the caller this
  project exists to worry about, so a read-only corpus root is still needed before
  the server is exposed to an untrusted orchestrator. What is enforced since, and
  what is not, is worth separating: a caller-supplied directory can no longer turn
  into a search of the machine -- the walk is bounded by file count and depth, never
  leaves the root through a symlink, refuses `/proc`, `/sys`, `/dev` and `/run` by
  name, and answers a directory it cannot read completely with an error naming the
  bound rather than a subset presented as the whole corpus. What remains unaddressed
  is the positive half of a path policy: nothing restricts the tools to a configured
  corpus root, so any single directory an operator points them at is still read in
  full, and `analyze_eml` still accepts any one readable file. No leak through
  current response formatting was demonstrated by the review or reproduced here.
- **The confidence numbers are policy labels, not calibrated probabilities.**
  `0.90` on `CLEAN` and `0.80` on `SPAM` are rule priorities chosen so the
  ordering is explicit. The false-negative cost ratio in `ensemble.py` is a
  declared judgment about relative cost, not a measured error rate, and it is a
  parameter for that reason. Nothing here should be read as a probability of
  anything.

- **The outward write destination is undecided, so nothing writes.** Google Alert
  Center has no comment API, so the reference playbook's "post tag + comment" has
  no direct analogue (`NOTES.md` open decision 2). The gate is implemented -
  proposed actions derived from the verdict, per-action approvals bound to a verdict
  digest, single-use tokens, a write stage the contract marks `access: write` - and
  the only provider shipped is `dry-run`, which records the intention and changes
  nothing. A real label or notification provider is configuration behind that
  decision, not an integration this repository invents.
- **A receipt proves structure, not identity.** The runner validates that a case
  record is internally consistent and that an approval matches the verdict it claims
  to approve. It cannot authenticate the approver, and it cannot attest that a tool
  which wrote a dishonest record was told the truth. The replay store's index
  attests to a recording the store itself wrote; an editor who rewrites the index
  too defeats that, and no runner can see it. Stated because the first-place SWARM
  playbook states the same limit, and a claim that outruns its own mechanism is the
  kind a reviewer disbelieves.
- **Approval is not captured interactively.** The CLI never prompts for a yes: a
  reviewer running the demo is not asked to authorize a mutation they cannot inspect
  first. `request_approval()` builds the instrument a human signs, and the MCP
  server deliberately does not sign it either -- it is read-only, so a response
  carries the *proposed* actions and the command that would run the gated stage
  instead of a prompt. How a human actually signs is deployment, and it stays
  inside the CLI/runner path: the approval gate in
  `src/tenable_email/writeback.py` is the thing being honoured, not a dialog.
- **No accuracy claim is currently supportable.** The internal labeled corpus
  has three entries. Any precision, recall or F1 figure in this repository will
  come from public corpora and synthetic fixtures, and will be labeled with its
  source.
- **The classifier tiers are noisy on this corpus, and the record says so.**
  Measured against the synthetic fixtures: the phishing classifier reads a
  mailer-daemon bounce as phishing at 0.99 and a security newsletter as phishing at
  0.98; the injection engine scores the bounce as an injection attempt at 1.00; the
  URL reputation estate flags every destination in the corpus, including a DocuSign
  link and an unsubscribe link, because it aggregates as "flag if any engine
  flags". That is why a tier that read only the body text cannot reopen a
  disposition the deterministic layer settled from headers, links and MIME facts, in
  either direction, and why the adjudication tier - which is shown the verified
  facts alongside the content - is the only one that can escalate a settled
  message. It is also why no accuracy claim is made for any tier here.
- **Image understanding is OCR plus visual judgment, not full multimodal
  parity.** The local VLM transcribes text and identifies brand impersonation
  correctly on tested samples. It will not match a frontier multimodal model on
  subtle layout mimicry.
- **Attachment contents are inventoried by default and read only by an optional
  workflow; QR codes are not read at all.** By default the engine records the
  extension, MIME type, size, sha256 and whether the part was cut, and the
  contents stay an explicit unknown in the evidence record. An operator who
  installs the external analyzer described in
  [Optional deep attachment analysis](#optional-deep-attachment-analysis-with-rea)
  can turn that unknown into a static reading of what a container holds; nothing
  runs until they do, no disposition depends on it, and it reads the formats that
  analyzer reads - which, measured, is containers and binaries and **not** a plain
  text part. The reference playbook extracts PDF and Word text and sends embedded
  images for analysis, so the document-text half of that gap is now conditionally
  closed and the rest is not. Quishing is a real vector and QR decoding remains a
  genuine gap against the reference, stated rather than smoothed: no `.[qr]` extra
  is published because nothing implements it.
- **Prompt-injection resistance is implemented, not yet measured.** The
  reference reports that Claude resisted injection attempts embedded in
  phishing mail. Our engine fences message content as untrusted, detects
  injection attempts deterministically and reports them as a threat class,
  and gates a threat verdict on corroboration so that a security newsletter
  quoting these phrases is escalated instead of flagged. That closes the gap the
  predecessor engine left open. Two model detectors now exist behind the same
  interface - the estate's injection endpoint, which is wired and recorded, and an
  optional injection-classifier tier (`Horizon-Labs/prompt-injection-guard-small`),
  which ships configured to nothing and reports itself unavailable. What is *not*
  done is a measured false-positive rate for either: the deterministic scanner is a
  signal, not a guarantee, the estate engine demonstrably over-fires on this corpus
  (see the paragraph above), and the A/B in Bundle E is what would make the claim a
  number.
- Public corpora are not our mail. Numbers measured on Enron-Spam, Nazario or
  UCI SMS do not transfer without validation on the deployment's own reported
  messages.
- **The repository ships a `.gitleaks.toml`, and what it suppresses is narrow but not
  nothing.** The Exchange screens submissions by scanning the linked repository with
  `gitleaks` across full history, and unconfigured that scan reports 105 findings here -
  all of them the `generic-api-key` rule firing on 64-character lowercase hex strings that
  are SHA-256 digests. The replay store is content-addressed, so those digests are cache
  keys: `fixtures/replay/index.json` maps each recording to the digest of the request that
  produced it, which is how an offline run proves it replayed the response belonging to
  *that* input. The config allowlists exactly two literal shapes - a 64-char lowercase hex
  digest and one obvious fake token in a test - and nothing else. The residual risk is that
  a real secret of exactly that shape would be missed anywhere in the repository; no
  credential format in general use has it (AWS is `AKIA`-prefixed, GitHub `ghp_`, OpenAI
  `sk-`, Google `AIza`, Slack `xox`, Stripe `sk_live_`), but the exposure is not zero. It is
  scoped by shape rather than by path deliberately: an earlier version allowlisted the replay
  directory by path, and because gitleaks ORs the conditions inside one allowlist that
  silently suppressed *every* rule in those files. Planted secrets proved it. The current
  file was verified against identical planted history both ways - 109 findings with the
  default ruleset, 4 with this file, the 4 being the planted credentials including a
  `github-pat` and a `slack-bot-token` inside the replay directory itself.


## Optional deep attachment analysis with `rea`

This is **an optional workflow, not a default and not a recommendation.** The
shipped engine never runs it: with no configuration it starts no subprocess, reads
no attachment contents, and every number in this README is produced without it.
It exists because attachment content was the one genuine capability gap the
reference playbook covers and this engine did not, and because closing that gap
honestly meant borrowing a program that is not ours.

The analyzer is [`morluto/rea`](https://github.com/morluto/rea) (npm `rea-agents`,
MIT), a reverse-engineering CLI whose own `DISCLAIMER.md` names malware and
incident analysis as a use case. It is a Node.js program with a heavy install and
a declared engine floor of `^22.23.4 || ^24.22.1 || >=26.12.1`. That is not a light
dependency to add to a mail triage chain, which is why it is off, why the core
still has no runtime dependency, and why this section is written as *what an
operator may choose* rather than as a feature every deployment has.

### What it adds

One Evidence finding per attachment the engine was able to read, with
`VERIFIED` provenance and the analyzer's own limitations and coverage status
attached. From `fixtures/attachments/attachment_zip_summary.eml`, with the
analyzer installed and switched on, a case record reads:

```text
quarterly-summary.zip (sha256 920186e6d469): declared format zip, sha256 digest
verified against the bytes in this message, provider rea-artifact-graph, 3
container entry(ies) inventoried, 2 analyzer limitation(s) recorded verbatim,
coverage complete-within-substeps, analyzer confidence observed, authority
shipped-artifact
```

The value beside that line carries each container entry's path, size and own
sha256. Nothing in that block came from the filename, which is the point.

### What it does not do

- **It cannot change a disposition.** The adjudication reads facts derived from the
  deterministic signals; no finding from this component is one, and the rule that a
  high-risk attachment blocks an automatic clearance is untouched whatever the
  analyzer reports. Test `test_with_no_rea_no_decision_on_any_fixture_changes`
  runs every fixture in the repository through the chain with the workflow on and
  the decision fields identical to the default run. That is deliberate: REA's own
  first limitation is that *"Inspection derives bounded static hypotheses and next
  probes; it does not execute the artifact."* A static read of a container is not a
  statement that its contents are safe, so it is not allowed to make a message
  cleaner.
- **It is static-only by construction, not by policy.** An operation runs only if
  the intersection of two independent lists permits it: `rea capabilities` must
  declare the operation free of `may_access_network`, `may_show_ui` and
  `mutates_artifact`, **and** `src/tenable_email/attachments.py` must name it in a
  hardcoded allowlist. Four command families - `capture-*`, `debug-*`, `*-adb-*`,
  `analyze-web-bundle` - are refused by name whatever they declare, before their
  declared effects are even read, and that refusal still binds if someone adds such
  a name to the allowlist. Neither list alone can widen what runs.
  The `available` flag in `capabilities` is deliberately ignored: measured on the
  build host it reports decompiler groups as available while `rea inspect` rejects
  the same groups as `not_configured`.
- **The child gets nothing it did not ask for.** It is started with an allowlist
  environment (`PATH`, a home, a temp root, a locale), so no configured model API
  key travels into a third-party program. Its input is a private copy of the
  payload under a directory no other user can open, named from the digest - never
  from the sender's filename, which in this repository's own fixture is a path
  traversal. The directory is removed afterwards; if removal fails, the path is
  reported in the record rather than dropped.
- **A result is trusted only if it binds to these bytes.** Both sha256 values REA
  reports are compared against the digest this engine computed during parsing, and
  a response that disagrees is discarded with `digest_mismatch` rather than partly
  used. Same principle as the approval token being bound to a verdict digest.

### Turning it on

```bash
npm install -g rea-agents            # the operator's decision, not this project's
cd /path/to/tenable-email
TENABLE_EMAIL_DEEP_ATTACHMENT_ANALYSIS=1 \
  PYTHONPATH=src python3 -m tenable_email run fixtures/attachments --out /tmp/cases
```

`TENABLE_EMAIL_ATTACHMENT_ANALYSIS_TIMEOUT_SECONDS` bounds one attachment (20 s by
default) and `TENABLE_EMAIL_ATTACHMENT_ANALYSIS_COMMAND` pins the binary by absolute
path, which is the difference between "a program named `rea`" and "this program".
In library terms it is one field:

```python
from tenable_email import triage_file
from tenable_email.config import Config

verdict = triage_file(path, Config(deep_attachment_analysis=True))
```

To see what the gate will allow before relying on it, ask it directly - this is the
answer an operator should check after any REA upgrade:

```python
from tenable_email.attachments import capabilities

print(capabilities())   # installed? which operations the intersection permits?
```

### What it cannot answer, and how it says so

A component that cannot answer reports why; it does not raise, because raising
would lose the reason. Nine abstentions exist, each recorded as an `UNAVAILABLE`
finding that reads `<reason>: <filename> (sha256 <first 12>): <detail>`:
`rea_not_installed`, `rea_timeout`, `rea_unparsable`, `digest_mismatch`,
`provider_unavailable`, `capability_unavailable`, `disallowed_operation`,
`quarantine_failed` and `attachment_not_retained` (the parser had already dropped a
part that was too large to keep, so there is nothing here to hand over).

Measured limits of the useful range, so nobody has to discover them: `rea
inspect-artifact` reads containers and binaries. A **plain-text attachment is
refused** - on the build host it returns `target_unavailable` with "Cannot open
artifact: unsupported binary format" - and native binary analysis needs a decompiler
that is not installed here, which surfaces as `provider_unavailable`. A `.zip` is
supported; a `.txt` is not. What the workflow buys today is container and artifact
structure, not general document text, and the honest summary is that the gap it
closes is partial. The recordings in `fixtures/rea/` are what these three outcomes
look like from the real CLI, and the test suite is driven by stubs that emit them,
so all of it is verifiable with no Node.js installed.

## Outbound data flows

The Exchange rejects submissions with undisclosed outbound calls. Complete list,
to be kept exhaustive:

- Google Workspace Alert Center API and Gmail API - only when live intake is
  configured; carries message metadata and content
- Local model endpoints on the operator's own network - carries message content
- The optional document analyzer (`rea`) is **not** an outbound call made by this
  engine's own decisions: the safety gate refuses any operation its tool declares
  as `may_access_network`, `may_show_ui` or `mutates_artifact`, refuses
  `capture-*`, `debug-*`, `*-adb-*` and `analyze-web-bundle` by name whatever they
  declare, and the child process is started with an allowlist environment so no
  configured model API key is in it. What it does is read one file on this machine,
  locally, and only when an operator turns the workflow on
- The MCP server makes **no outbound calls of its own**. It is a stdio process:
  the client connects to it, not the other way round, and every tool runs with
  replay forced on, so it reads the committed recordings instead of reaching an
  endpoint and never writes a recording back
- The case-ledger web view and its snapshot export make **no outbound request of any
  kind**. The server listens on loopback by default and connects to nothing; every page
  references no external resource, so **all styling is inline** in the served HTML and
  in the single self-contained snapshot file. Loading a page cannot disclose which
  cases an analyst opened, and `Content-Security-Policy` denies all fetches on every
  response, including the error responses
- No other outbound calls. No telemetry. No third-party inference API unless the
  operator explicitly configures one as the escalation provider. One was configured
  once, by the operator, for measurement rather than for any shipped default: the
  remote comparison arm in `docs/LIVE-AB.md` adjudicated 1,327 messages through a
  third-party flash-class API so the local adjudicator could be scored against
  something. It carried external public-corpus text and no organization mail, it is
  labelled `remote` in every table it appears in, and no default configuration
  reaches it
- **Maintainer tooling under `tools/` is outside that runtime disclosure**, and is named
  here so this section stays exhaustive rather than because any of it runs during triage.
  Three scripts reach the network, all developer-only and none reachable from the package:
  `validate-listing.sh` downloads the upstream `validator.py` from
  `raw.githubusercontent.com`, `sync-trees.sh` runs git over SSH against the operator's own
  integration remote, and `record-replay.sh` calls whatever tier endpoints the operator has
  configured in order to record their responses. Nothing in `src/` imports any of them

## Repository layout

```
README.md                      this file
NOTES.md                       decision log and running notes
TODO_TENABLE-EMAIL             bundle-based work plan and session log
SKILL.md                       the workflow judgment the tools cannot convey
stages.yaml                    the machine-readable stage contract (8 stages)
src/tenable_email/cli.py       the subcommands a reviewer runs
src/tenable_email/mcpserver.py the read-only MCP tools and the stdio server
src/tenable_email/receipt.py   the per-message case record: digests, closure rules
src/tenable_email/runner.py    offline state machine; refuses, transactionally
src/tenable_email/writeback.py proposed actions, single-use approvals, dry-run provider
src/tenable_email/attachments.py optional document extraction through a local analyzer
src/tenable_email/tiers.py     one interface for every inference tier; failure is a value
src/tenable_email/replay.py    content-addressed record/replay store
src/tenable_email/ensemble.py  facts and opinions combined asymmetrically
fixtures/attachments/          generated .eml carrying real attachment bytes, all benign
fixtures/rea/                  recorded analyzer responses; the test stub's canned answers
fixtures/replay/               committed model recordings (synthetic corpus only)
tools/record-replay.sh         records live tier responses into fixtures/replay/
docs/ELI5.md                   the whole system explained, the design choices and what
                                 was rejected, the measured results including the
                                uncomfortable one, and answers to hard questions
docs/LIVE-AB.md                the model tiers measured against live services: per-tier
                                 recall and false-positive rate, in-domain against
                                out-of-domain, and what swapping the adjudicator changed
eval/live_ab.py                runs that measurement; writes eval/live-ab*.json and never
                                 metrics.json, because a committed artifact has to be
                                reproducible with no inference host
docs/RULES.md                  contest and Exchange requirements, from primary sources
docs/PARITY.md                 reference contract and the capability-by-capability gap matrix
docs/RED-TEAM-RESPONSE.md      external red-team findings, their status, what was verified
docs/REFERENCE-BASELINE.md     the published playbook, its numbers, and their provenance
docs/EVIDENCE.md               every measured claim, with date, method and provenance
docs/MODELS.md                 classifier research, verified against source
docs/EVAL-SUITES.md            public eval suites surveyed, with measured overlap
docs/PRIOR-WINNERS.md          what placed at SWARM Black Hat and what we adopt from it
docs/LISTING-VALIDATION.md     Exchange listing shapes tested against the real validator
docs/listing-drafts/           validated draft listing files
docs/results/                  committed test evidence, regenerated by tools/
tools/validate-listing.sh      re-runs the upstream validator against our drafts
tools/validate_contract.py     checks stages.yaml against README.md and SKILL.md
tools/record-results.sh        regenerates docs/results/ and exits non-zero on failure
tools/check-portability.sh     compiles every source file on each interpreter >= the
                               declared floor; the AST test cannot cover quote reuse
tools/sync-trees.sh            verifies the build and shared trees agree; never forces
tools/make_public_export.py    builds a publishable repo with clean, scanned history
LICENSE                        MIT
CONTRIBUTING.md                contributor workflow; read before a first commit
src/tenable_email/ledger.py    local case record: machine verdict beside human verdict
src/tenable_email/webui.py     loopback web view over the ledger, and its static export
docs/ADAPTERS.md               email source adapter contract and platform notes
src/tenable_email/             the package
fixtures/generate.py           synthetic corpus generator
fixtures/synthetic/            generated .eml with known labels, reserved domains
fixtures/adversarial/          generated hostile .eml; open findings are strict xfails
tests/                         test suite
eval/                          evaluation harness: run.py measures, report.py renders,
                               selective.py is the selective-prediction metrics,
                              fetch.py downloads public corpora behind a closed
                              licence gate, external.py wraps their rows in a
                              synthesized .eml envelope and says what that costs,
                              fetch.py --rows reads the Parquet-only corpora as JSON
                              from the datasets-server conversion service - a
                              different object from the pinned file, and both are
                              recorded -,
                              PROVENANCE.json is the committed record of a fetch
                              (digests and revisions, never the data itself),
                              metrics.json is the committed artifact a test pins
```

## Test evidence

`docs/results/latest.md` is a committed artifact, regenerated by
`tools/record-results.sh`, recording the suite's counts, environment and
per-test results alongside the git commit it describes and whether the code tree
was clean at run time. `docs/results/junit.xml` is the machine-readable form.

It cannot go stale silently: a test asserts the recorded totals still equal the
suite as currently collected, and that they agree with the junit XML. Adding a
test without re-recording fails the build. Verified by injecting a canary test.

The artifact records no hostname, username, home path or network address, and a
test enforces that, because it is committed to a public repository.

## Measured behaviour

Everything in this section is measured offline from committed recordings, so a reviewer can
reproduce it with no inference host. The model tiers have additionally been measured against
**live** services over 3,037 external messages; those numbers are in
[`docs/LIVE-AB.md`](docs/LIVE-AB.md) and are kept in separate artifacts, because a live
measurement describes a moment and a set of machines rather than something anyone can replay.
The short version is that the tiers earn their place on precision - the adjudication tier
matches the injection engine's recall at a quarter of its false-positive rate - and that
out of domain they over-accuse badly, which is a measured fact rather than a caveat.

`eval/run.py` measures the pipeline against the two labelled corpora committed to
this repository and `eval/report.py` renders the result - Markdown by default, JSON
with `--json`. It needs no network, no credentials and no inference host, so anyone
can reproduce every number below:

```
python3 eval/run.py                              # markdown report
python3 eval/run.py --json -o eval/metrics.json  # regenerate the committed artifact
```

`eval/metrics.json` is committed and a test asserts it still matches what the code
produces, so the numbers cannot drift from the implementation while looking like
evidence.

Two configurations are measured. **Deterministic-only** makes every model tier
record UNAVAILABLE, which is what a reviewer with no inference host gets.
**Corpus-backed** replays the committed recordings.

### Synthetic corpus, deterministic-only

Fourteen messages with ground-truth labels in `labels.json`.

| | |
|---|---|
| `clean` / `manual_review` / `spam` / `threat` | 3 / 4 / 1 / 6 |
| Auto-clearance rate | 21.4% |
| Escalation rate (a human looks) | 28.6% |
| Dispositioned with no model call | 100% |
| Label agreement / escalated / disagreed | 10 / 4 / 0 |
| **False negatives** (hostile label, cleared) | **0 of 9** |
| **False-negative rate among auto-closed** | **0.0%** |
| **False accusations** (clean label, called threat or spam) | **0 of 5** |

A deferral is counted separately from agreement and from disagreement. It is a
coverage cost, not a wrong answer, and lumping it with either hides something:
counting it as agreement would flatter the tool, counting it as disagreement
would punish it for being honest.

### Adversarial corpus, deterministic-only

Eighteen hostile messages, every one sent from a subdomain of the protected domain
with authentication that genuinely passes. See
[`docs/RED-TEAM-RESPONSE.md`](docs/RED-TEAM-RESPONSE.md).

| | |
|---|---|
| `clean` / `manual_review` / `threat` | 1 / 13 / 1 |
| **Hostile messages cleared** | **1** |
| That one case, by name | `forged_auth_single_header` |
| Declared open in the manifest | `forged_auth_single_header` |
| Cleared despite being declared closed | **none** |

The single message that clears is the one open finding, and it is named rather
than averaged: a *single* forged `Authentication-Results` header with nothing to
contradict it cannot be told apart from a receiver-added one inside a raw `.eml`.
It is asserted under a strict xfail, so fixing it fails the suite until the status
is consciously moved.

### What the corpus-backed run adds, which is the uncomfortable number

The dispositions are **identical** - 3 / 4 / 1 / 6, same false-negative and
false-accusation counts - while 13 of 14 messages consult at least one model.

On this corpus the models change nothing. That is the design working as intended:
a disposition resting only on VERIFIED findings is a floor, and a tier that read
the body text alone cannot reopen it, because these tiers demonstrably over-fire
here (a mailer-daemon bounce read as phishing at 0.9948, a security newsletter at
0.9790, and the URL reputation engine flagging a DocuSign signing link at 0.962).
But it also means the models are cost without measured benefit on this corpus,
and that is reported rather than left for a reader to discover.

It is also why **no accuracy claim appears anywhere in this README**. Fourteen
synthetic fixtures cannot measure accuracy, and a corpus on which the models are
provably inert cannot measure their contribution. Establishing either needs the
public corpora surveyed in [`docs/EVAL-SUITES.md`](docs/EVAL-SUITES.md), which are
fetched at evaluation time and never committed because most are copyleft or
non-commercial.

### Read as a selective prediction: what automates, and at what cost

`eval/selective.py` re-reads the same per-message rows as selective classification,
which is what this pipeline actually is. `manual_review` is **not a fourth label**
beside `clean`, `spam` and `threat` - it is a **deferral** to a person, so it is
neither an error nor an agreement. Counting it as either would be the mistake: as
agreement it flatters the tool, as disagreement it punishes the tool for being
honest. What an operator can actually ask is therefore not "what is the accuracy" but

- **coverage** - the share of the queue settled with no human in the loop, and
- **selective risk** - the error rate *among those automated*, which is what the
  coverage costs.

Sweeping the acceptance threshold over the automated set traces a risk-coverage
curve. **AURC** is the area under it (lower is better) and **E-AURC** is AURC minus
the same curve computed with a perfect ranking, so it measures the quality of the
confidence ordering rather than the number of errors. A message the pipeline already
deferred never reappears as automated when the threshold drops: deferral is a
decision about evidence, not about confidence, so coverage is capped at what the
pipeline is willing to settle at all.

Both numbers below are from `eval/metrics.json` and are the same in both
configurations - the corpus-backed run differs in exactly one field of the selective
block, `deferral_composition.model_assisted` on the synthetic corpus, 0 versus 4.

| | Synthetic | Adversarial |
|---|---|---|
| Messages | 14 | 18 |
| Automated / deferred | 10 / 4 | 2 / 16 |
| **Coverage** | **71.4%** | **11.1%** |
| **Selective risk among the automated** | **0.0%** | **50.0%** |
| Hostile-labelled automated, cleared anyway | 0 of 7 | 1 of 2 |
| Benign-labelled automated, accused anyway | 0 of 3 | no benign message in this corpus |
| AURC / oracle / E-AURC | 0.0000 / 0.0000 / 0.0000 | 0.0417 / 0.0139 / 0.0278 |
| Curve points | 5 | 3 |
| Coverage at a 1% automated-error budget | 71.4% | **no budget in the reported range is achievable** |
| What the deferred slice holds | 4 escalated, 2 labelled `clean` and 2 `threat` | 16 escalated, 1 truncated, all from the adversarial corpus |

**The calibration limit travels with those numbers; it is not a footnote.** The
confidence values in this project are policy labels - 0.90 for a supported
clearance, 0.50 for a deferral - not probabilities. Selective prediction needs only a
*ranking*, so a risk-coverage curve over uncalibrated scores is legitimate, but every
"coverage at a 1% budget" statement above inherits that limit, no threshold here was
chosen with a finite-sample guarantee, and the flag is carried in the artifact as
`calibrated: false` so a renderer cannot lose it. `tests/test_eval.py` asserts the
caveat is printed wherever the flag is false, and that it is the flag printing it
rather than a hardcoded sentence.

What the two columns mean:

- **Synthetic - the method, not the evidence.** The curve is flat at zero risk
  because the deterministic layer already reaches the right disposition on all 14
  messages: of the 10 it automates, 7 carry a hostile label and none was cleared, 3
  carry a benign label and none was accused. A zero E-AURC says the confidence order
  cannot be improved on, not that the ordering is good - there is nothing to order.
  Fourteen self-generated messages demonstrate the measurement; they do not evidence
  it.
- **Adversarial - the result worth having.** 11.1% coverage and 50% risk: of the two
  hostile messages this corpus automates, one is cleared, and it is the disclosed
  open finding `forged_auth_single_header`, named rather than averaged. The curve
  reaches no risk budget in the reported range, which is the honest answer and not a
  gap in the report: **nothing in a corpus of forged mail can be handed over without
  a person at any error budget anyone would operate at.** E-AURC is positive here
  (0.0278) because the wrong decision carries the system's highest confidence, 0.90 -
  which is the documented "these are policy labels" caveat, now measured instead of
  merely stated.

The oracle AURC is computed over the curve's own coverage grid rather than from the
textbook closed form `e0 + (1-e0)ln(1-e0)`, because that form assumes a threshold can
reach full coverage. Comparing an 11.1%-coverage curve against an oracle integrated to
1.0 gave a negative E-AURC, which is impossible: the oracle is the minimum by
construction. The bug was found by reading the number instead of trusting the formula,
and `tests/test_selective.py` now pins E-AURC >= 0 as a property.

### Public corpora, fetched under a licence gate, and what they can show

`docs/EVAL-SUITES.md` established that almost none of the public evaluation corpora can
be committed to an MIT repository: `SetFit/enron_spam` declares no licence at all,
`zefang-liu/phishing-email-dataset` is LGPL-3.0, `geodesic-research/bipia` is
CC-BY-SA-4.0, and the Korean and Mozambican smishing sets are non-commercial or
OpenRAIL. So `eval/fetch.py` ships a **fetch harness and a closed allowlist** rather
than a vendored corpus. It downloads only datasets whose licence was read from the
Hugging Face API's `cardData.license` on a recorded date, re-reads that declaration at
fetch time and refuses if it moved, stores the bytes in a gitignored directory, and
commits only `eval/PROVENANCE.json`: dataset id, pinned 40-character revision, source
URL, observed licence and verification date, byte size, sha256, and the row count with
the method that produced it. Anything not on the list is refused **by name**, including
the unlisted:

```
$ python3 eval/fetch.py --dataset SetFit/enron_spam
REFUSED: SetFit/enron_spam
  observed licence (cardData.license): 'None' as read on 2026-11-03
  reason: No licence is declared. Undeclared does not mean granted: ...
```

That refusal is the point of the gate: the undeclared set is the most convenient benign
English-email corpus available, and it is still refused.

**What the harness can actually measure is narrower than it looks, and the harness says
so.** These corpora are *text*, not RFC 822 messages - LLMail's rows are strings shaped
"Subject of the email: ... Body: ...", the jailbreak set is a CSV column. To run the
pipeline at all, `eval/external.py` wraps each row in a minimal synthesized `.eml`.
That is a transformation, so every external number measures the **text and injection
surfaces and not the authentication layer**: the wrapper carries no
`Authentication-Results` and no `DKIM-Signature`, so SPF, DKIM and DMARC cannot fire,
and the deterministic layer that settles most of the committed corpus has nothing to
settle on. Dispositions therefore skew toward `manual_review` **by construction**. The
exact envelope - headers present, headers absent by construction, RFC 2606 domains, the
constant `Date`, the subject-derivation rule - is recorded per corpus in
`eval/metrics.json` and printed by `eval/report.py` beside the figures it produced, and
`tests/test_external_eval.py` asserts the limitation text is present, not merely that a
field named `limitation` exists.

| External corpus | Licence, revision | Rows measured | **Text surface flagged** | Accused (`threat`/`spam`) | Deferred (`manual_review`) | Cleared |
|---|---|---|---|---|---|---|
| LLMail-Inject false-positive file: 203 benign business emails | MIT, `1063bdf0` | 203 of 203 | 0 - 0.0% | **0 - 0.0%** | 203 - 100.0% | 0 |
| jailbreak-classification test split, benign half | Apache-2.0, `2f2ceeb3` | 259 of 259 | 1 - 0.4% | **0 - 0.0%** | 259 - 100.0% | 0 |
| jailbreak-classification test split, jailbreak half (labelled hostile) | Apache-2.0, `2f2ceeb3` | 141 of 141 | **13 - 9.2%** | 0 | 141 | **0** |
| NotInject, all three splits: benign prompts containing injection trigger words | MIT, `847ae76c` | **339 of 339** | **0 - 0.0%** | 0 | 339 | 0 |
| deepset/prompt-injections, injection-labelled rows of both splits | Apache-2.0 card, cc-by-4.0 conversion, `4f61ecb0` | 263 of 263 | **3 - 1.1%** | 0 | 263 | 0 |
| deepset/prompt-injections, not-injection-labelled rows of both splits | as above | 399 of 399 | 0 - 0.0% | 0 | 399 | 0 |
| Bengali smishing test split, `smish`-labelled half | MIT, `9d7c131c` | 561 of 561 | **0 - 0.0%** | 0 | 561 | 0 |
| Bengali smishing test split, `normal` + `promo` half | MIT, `9d7c131c` | 840 of 840 | 0 - 0.0% | 0 | 840 | 0 |

**The last five rows are new: phase 1 could fetch, pin and not *read* them,** because they
ship only as Parquet. **The "text surface flagged" column is the one that discriminates** -
how many rows of that corpus match the pipeline's own deterministic injection scanner, each
with its denominator. The three disposition columns are **non-discriminating for every
external corpus in the table**: across all **3,005** measured messages, in both
configurations, 0 were cleared, 0 were accused, and all 3,005 went to a person. The number
Bundle N was originally queued for is still the first row - **0 of 203 benign LLMail emails
flagged as threat or spam** - but a false-positive rate of 0.0% printed beside a clearance
rate of 0.0% is one absence described twice, and `eval/report.py` now says so beside every
one of those tables instead of letting 0.0% be read as an achievement.
`tests/test_external_rows.py` asserts the statement is present where it must be, and
asserts it is *not* stamped onto a corpus that decided something.

What the discriminating column says, both sides of it together: the scanner fired on **13
of 141** labelled jailbreak prompts and **1 of 259** benign ones, on **3 of 263** rows
deepset labels as injections and **0 of 399** rows it labels as not-injections, and on **0
of 339** NotInject prompts. That last figure is the over-defense result this phase was
queued for - `docs/EVAL-SUITES.md` predicts small detectors fail exactly here, and names
the deepset model at a false-positive rate of 1.00 - and it must not be quoted alone. The
same surface that stayed silent on 339 benign trigger-word prompts found only 3 of the 263
rows deepset calls an injection, and **0 of the 561** Bengali smishing messages. Low
over-flagging beside low detection is a *narrow* scanner, not a good one; what this project
claims is that the deterministic layer corroborates, and these numbers are the honest shape
of that claim.

What this does **not** show, stated plainly: it does not show the pipeline clears benign
mail, because with no authentication signal nothing can clear; it does not test the model
tiers at all, because the committed recordings are keyed by content address and no
recording exists for text that was never sent to an endpoint, so a `corpus-backed` run
emits **0 model judgments over all 3,005 external messages** and is identical to
`deterministic-only` - a missing recording is a miss, not a call and not an invented
answer. **The model-tier A/B that motivated this whole survey has still not run.** What
this is: a measurement of the deterministic text surface on out-of-domain input, which is
what this phase could honestly produce.

**How the Parquet-only corpora were read without a decoder.** `eval/fetch.py --rows` asks
the Hugging Face datasets-server ROWS API for JSON rows over plain HTTP: no column decoder,
no snappy, no dependency, and the licence gate is the same one - the rows path re-reads
`cardData.license`, refuses a moved declaration, and refuses gated and private repos. The
cost of that road is recorded rather than blurred, because the service serves the dataset's
own **converted** Parquet - different bytes from the repository file, so they do not carry
the pinned sha256. `eval/PROVENANCE.json` and each corpus's `text_origin` block therefore
hold **both** objects: the repository file's revision-pinned URL, size and digest, and the
retrieval's split name, `num_rows_total`, page list, cache digest and timestamp. What is
cross-checked between them is the split name and the row count - 339, 546 + 116, and 1,401,
each equal to the count read out of the pinned file's own Parquet footer by the Thrift
skimmer, no cell truncated by the service - and what is *not* claimed is that the measured
text was hash-verified against the repository file. Each LFS-stored file's sha256 is still
compared against the object id the repository records for it at that revision.

Reproduce it:

```
python3 eval/fetch.py --list                  # the allowlist and the refusals
python3 eval/fetch.py --all                   # fetch what the gate permits
python3 eval/fetch.py --all --rows            # and the JSON rows for the Parquet sets
python3 eval/run.py --json --external -o eval/metrics.json
python3 eval/run.py --external                # the same, as Markdown
```

With nothing fetched - the state of a fresh clone, because downloaded data is never
committed - the external block reports `not-fetched`, names the commands above, and
generates no rows. `tests/test_external_eval.py` asserts it never degrades into a zero,
and the suite is green either way. A corpus whose rows were never retrieved degrades the
same way: it is listed in `unavailable` with its pinned row count and the command that
would fetch it, and it is never measured as zero rows.

### How to read any of it

The auto-clearance rate and the false-negative rate among auto-closed messages
must be read together. A clearance rate reported alone is the same mistake as an
F1 reported without its false-positive rate, and `docs/EVAL-SUITES.md` records a
published prompt-injection model with F1 0.992 whose false-positive rate was
**1.00** - it flagged everything, and reading the headline number alone would have
selected it.

The converse is pinned too: `tests/test_eval.py` asserts at least three benign
fixtures still clear, because a tool that escalates everything satisfies every
safety assertion above and is useless. Safety and coverage are asserted together
or the assertion is advocacy.

## Models

Every model is optional and reached over an OpenAI-compatible or plain HTTP
interface. Names below are as served by the operator's deployment and may be
aliases for an upstream artifact; **no endpoint address is published anywhere in
this repository**, and the recordings carry a role label instead.

### Models that produced the committed recordings

| Role | Model as served | Size | License | Recordings | Measured |
|---|---|---|---|---:|---|
| Phishing classifier | `xanderabim/fraudfoxai-phishing` | 67M DistilBERT | see repo | 14 | ~38 ms, ONNX Runtime CPU |
| Adjudication LLM | `Qwen3.6-27B` | 27B | see repo | 14 | correct structured three-way verdict at 0.90 s / 465 tokens for a 1.2B tier of the same family |
| Vision (VLM) | `unsloth/Qwen3.5-4B-GGUF:Q4_K_XL` | 4B | see repo | 1 | 0.87 s / 18 completion tokens with thinking disabled; verbatim OCR plus correct brand-impersonation judgment |
| URL reputation | security-model estate | small ONNX | see repos | 9 | endpoint does not report a model name |
| Prompt injection | security-model estate | small ONNX | see repos | 14 | endpoint does not report a model name |

Two of the five rows carry no model name because the endpoint does not report
one. That is a real gap rather than an omission here: an unnamed model weakens
replay-key specificity, and `tests/test_offline_default_path.py` pins the
exception to exactly those two tiers so it cannot spread silently.

### Models the code supports but no recording exercises

| Role | Intended model | Size | License | Status |
|---|---|---|---|---|
| Three-way fraud/spam/legitimate | `Horizon-Labs/phishing-scam-detector-base` | 307M, mmBERT-base | Apache-2.0 | client implemented, no endpoint configured, no recording. Would replace the LLM three-way path |
| Injection classifier | `Horizon-Labs/prompt-injection-guard-small` | 141M | Apache-2.0 | client implemented, no endpoint configured, no recording |

Both were selected on verified evidence and are documented with their measured
weaknesses in `docs/MODELS.md`. Neither is claimed as working, because neither
has been run.

### Models evaluated and rejected

Recorded in `docs/MODELS.md` with sources, because the rejections are as
informative as the choices:

- `mrm8488/bert-tiny-finetuned-enron-spam-detection` - **false-positive rate
  0.959** out of domain, measured by a third party. Widely recommended on the
  strength of a 0.986 in-domain accuracy figure.
- `cybersectony/phishing-email-detection-distilbert_v2.4.1` - FPR 0.880.
- `prancyFox/tiny-bert-enron-spam` - spam recall 0.5632.
- `navodPeiris/minilm-toxic-spam-classifier` - two of its four training sets are
  comment-toxicity corpora, not email.
- `bastionsoft/binary-bastion-prompt-protection-deberta-v3-xsmall-v1` -
  **AGPL-3.0**, incompatible with an MIT submission.
- `meta-llama/Prompt-Guard-2-22M` - gated, and LLMail-Inject email recall 0.011.

The pattern worth naming: in-domain accuracy near 1.0 coexists with catastrophic
out-of-domain false positives. Always read the false-positive column.

### What runs with no model at all

Stages 1 to 3 are pure Python on the standard library: MIME parsing,
SPF/DKIM/DMARC extraction, lookalike-domain detection by edit distance,
anchor-text versus href comparison, redirect unwrapping, forwarded-message
unwrapping, attachment inventory, bulk-mail header signals, boilerplate
suppression and a deterministic injection-surface scan. On the shipped corpus
these alone disposition 14 of 14 fixtures without a single model call. That is
the point of the cascade: the models handle the residual, not the bulk.

## Upstream services this project calls

Nothing is bundled and nothing is required. Each tier is optional; a tier with no
configured endpoint records itself `UNAVAILABLE` in the evidence record rather
than failing the message. That is what lets the deterministic stages run, and the
test suite pass, on a machine with no models and no network.

The same is true of email intake, with one correction this section used to get wrong.
The shipped default adapter reads files from disk, and a fresh clone contacts no mail
system - but that is because no credential is configured, **not** because no mail adapter
exists. A Google Workspace adapter now ships and is registered as `google-alerts`
(`src/tenable_email/google_intake.py`, reading Alert Center and Gmail). It is read-only by
scope, `mutates` is `False`, and `source_for` refuses a mutating source rather than trusting
an adapter not to opt out, so it cannot be reached without an operator supplying a token.
This paragraph previously claimed no platform adapter was registered at all, which the
merge of that adapter made false; the outbound calls it can make are listed in
[Outbound data flows](#outbound-data-flows), which is the exhaustive disclosure and the
section to trust.

Endpoints arrive from the environment (`TENABLE_EMAIL_*`, parsed by
`tenable_email.config.ModelEndpoints.from_env`) and have no defaults, so a fresh
clone reaches no network at all: the deterministic stages run, every tier reports
itself unavailable by name, and the model tiers are answered from the committed
recordings instead. The six addressable model endpoints are `fraudfox_url`,
`secmodels_url` (which serves both the URL-reputation and prompt-injection tiers),
`spam_classifier_url`, `injection_classifier_url`, `llm_url` and `vlm_url`. The
operator's own inference inventory documents the specific
endpoints and their measured latencies. It is deliberately not part of this
repository, because it describes private infrastructure; the services themselves are
disclosed by role in [Outbound data flows](#outbound-data-flows).

## License

MIT. The full text is in [`LICENSE`](LICENSE), and the copyright holder is
**Campus Autonomous Defenders (CAD)** - the team, not an individual and not a list of
contributors.

Holding it at team level is a choice rather than an omission. Three people contributed and
the work is joint, so naming any subset would misstate it, and naming all three would
publish two colleagues' identities in a legal notice they have not been asked to appear in.
The team name is already public in both Exchange listing drafts, so it credits everyone the
listings credit and discloses nothing new. `austinsr1` is the account that owns the
repository and the sole `author` field in the listing frontmatter, because the Exchange
requires a personal account there; that is an ownership fact, not a claim about who wrote
what.

`tools/make_public_export.py` refuses to publish without a `LICENSE` or with an unfilled
placeholder in it, so this cannot silently regress.
