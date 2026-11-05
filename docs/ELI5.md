# tenable-email, explained

**Team:** Campus Autonomous Defenders (CAD)
**Written for:** a 5-8 minute pitch followed by questions about knowledge, choices and
design. This is not a slide deck. It is the reasoning behind the system, so that anyone
on the team can answer a question they did not personally write the code for.

Every number in here is measured by `eval/run.py` against fixtures committed to this
repository and recorded in `eval/metrics.json`. Every design claim names the file that
enforces it. Where we do not know something, this document says so rather than
rounding up.

---

## Part 1 - ELI5: what happens to one reported email

Someone in the organisation clicks "report phishing". That is the only human input
required to start. From there the message arrives one of two ways: as a `.eml` file or a
directory of them, or through the Google Workspace adapter, which reads Alert Center for
"User reported phishing" alerts and then fetches each message those alerts name
(`--source google-alerts`, read-only scopes, `mutates = False`).

**Read everything below with one boundary in place: this is a triage layer, not primary
detection.** Somebody - a person, or the mail gateway before them - has already decided
this message is worth a second look. That decision is not ours and we do not repeat it.
Nothing here sits in the mail flow, nothing blocks delivery, and we make no claim about
catching a campaign nobody reported.

What we claim is narrower and, for a helpdesk, more useful: of the mail that gets
reported, most turns out to be nothing, and an analyst's day is consumed proving that one
message at a time. So the job is to settle the obvious ones, escalate the ones that are
something, and hand the genuinely ambiguous ones to a human **with the reasoning already
laid out**. That makes the score "how much did you settle, and how often were you wrong
when you did" - and it makes one mistake far worse than the other. Crying wolf costs an
analyst thirty seconds. **Waving a real threat through costs the organisation.** Every
design choice below follows from that asymmetry.

### The actual thing we are optimizing: frontier-hours

Here is the whole project in one comparison.

The published playbook this is measured against - built for a hospital's IT security team -
sends **every unresolved reported email to Claude Sonnet 4**. One message per call, every
five minutes, around the clock. That design genuinely worked, and what it did was swap
analyst man-hours for frontier API hours, about one for one.

We think most of those API hours are wasted, because **most reported email is nothing**, and
"nothing" is usually provable cheaply: does it authenticate, where do the links actually go,
do two small CPU models think it is a phish. That takes about ninety milliseconds on
hardware you already own.

So the design is a ladder. Cheap local work first, expensive work only for what survives it.

Two words are used the same way everywhere in this repo:

* **micromodels** - the small CPU models. A distilbert-class phishing classifier and an
  ensemble for URL reputation and prompt injection. ~90 ms for the whole tier.
* **frontier** - any language model, flash-class and up. Ours runs **on our own hardware**,
  so even the expensive rung never sends mail outside the building. We measured a remote
  flash API too, but only as a comparison, and it is labelled `remote` everywhere.

**What the ladder measured.** On 203 real benign business emails, the micromodels settled
**171 of them - 84.2% - and falsely accused none**. So about **16% is left for the
frontier**, and since our frontier is local, the number of **paid API calls is zero**.

Now here is the part that makes the comparison fair, because it is easy to get wrong.
**The reference never published a clearance rate, and it could not have.** Claude is not one
rung in their ladder - Claude *is* the ladder's last step. Their workflow polls KnowBe4 every
five minutes, sends every unresolved reported message to Claude Sonnet 4, gets back
Clean/Spam/Threat, and posts it to the ticket. There is no cheaper step underneath that could
have settled a message first, so there is no such thing as "cleared before the frontier" in
that design.

Which means **the token bill is unconditional**. A reported email that turns out to be a
legitimate invoice costs exactly the same Claude call as one that turns out to be a
credential harvester - and once the tokens are spent, they are spent either way. Their
published numbers are all about the analyst hours that design saved (which were real: ~930
hours a year, ~$70,000), and nothing about the frontier cost, because in their architecture
the frontier cost is just a fixed property of every message.

So the honest unit of comparison is not "our clearance rate versus theirs." It is **frontier
cost per reported message**: theirs is one multimodal Claude call, every message, always;
ours is one flash-class call on about one message in six, on hardware we own.

And their own arithmetic backs the thesis without needing anything we measured. If ~100
messages a day really cost ~80 analyst-hours a month, the average is **~2.2 minutes per
email**, not the 5-10 minutes quoted for complex cases - because 5-10 minutes on every
message would add up to more than a full-time person and contradict their own total. A
two-minute human average means most of that queue is routine pattern recognition, not deep
reasoning. **Routine is exactly what ninety milliseconds of local work settles.** The case
for right-sizing comes out of their numbers, not only ours.

And is the local frontier good enough? We ran the same 1,327 messages twice, changing only
where the adjudicator lived. Local: recall 0.800, false-positive rate 0.125. Remote: 0.831
and 0.145. **A tie.** Five times slower locally, and nothing measurable given up.

**Two honest limits, because a judge will ask.**

First, **neither of those was Claude Sonnet 4** - both were flash-class. So "we replace
Claude" is a reasoned inference, not a head-to-head: a local flash model matches a remote
flash model on a narrow task, and adjudicating an already-reported message *is* narrow. We
did not beat a frontier reasoning model and we do not claim to.

Second, and more awkward: **that 84/16 split is what the ladder does with the frontier
switched off.** Switch it on as currently built and auto-clearance on the same mail falls
from 84.2% to between 0% and 2.5%.

The reason is a genuine defect and it is worth understanding, because it is subtle. To clear
a message we require every consulted model to be confident enough - a bar derived from how
much worse a false clearance is than a false accusation. But "confident enough" is read off
each model's **self-reported** confidence, and those numbers do not mean the same thing
across models. A small softmax classifier says 0.99 because that is what a softmax does. A
language model says 0.7 because it hedges the way language models do. We then take the
**weakest** of those numbers.

So the rule rewards the model that shouts and punishes the one that thinks. **Adding a more
capable model made the system automate less.** Confirmed, not theorized: three real benign
business emails come back `clean` with the micromodels alone and `manual_review` once the
adjudicator can be reached - with every model agreeing they are clean in both cases.

That is **Bundle S**. It is diagnosed and reproduced, and we deliberately did not fix it in
the last hours before a deadline, because it is the safety gate and changing it invalidates
every committed number above it. Fixing it properly means re-measuring both arms, and
"ship a known gate defect with a reproduction" is a better place to land than "retune the
safety gate under time pressure and hope."

**Step 1 - Read it properly.** We parse the message as an RFC 822 object, not as text.
That means we keep the MIME structure, the headers, and the difference between the
plain-text part and the HTML part. We also keep how much we read: if a message is longer
than the configured limit, we say so, and "we only read part of this" becomes a visible
flag that travels with the case all the way to the analyst's screen.

**Step 2 - Check the plumbing before asking anyone's opinion.** Did SPF pass? DKIM?
DMARC? Is the address that actually authenticated the same domain the human being
*shown*? These are facts, not judgements, and they are cheap. On our synthetic corpus
this layer alone settles every message that gets settled.

**Step 3 - Look at what the message actually points at.** We extract every link
destination - not just the visible text, and not just `<a href>`: form actions, meta
refreshes, iframes. We unwrap redirectors, because a phishing link that hides behind a
legitimate-looking redirect service is the whole point of the trick. Then we ask which
destinations match neither the sender nor anything on a trusted list.

**Step 4 - Only now, ask a model.** Small specialist models, each with one job: is this
text a classifier-known phishing pattern, does this page screenshot look like a fake
login, is this URL on a reputation list, is the message trying to instruct our own
analysis rather than being analysed. Each one is allowed to say "I don't know", and an
abstention is recorded with its specific reason rather than silently treated as a
negative vote.

**Step 5 - Combine the votes under a rule we wrote down.** This is the part most systems
skip. A specialist does not get to overrule a verified authentication fact by shouting
louder. But - and this was a bug we found and fixed - a *very* confident vision model
saying "that is a fake login page" **does** get to block an automatic clearance. The
distinction is that it can escalate; it cannot accuse on someone else's behalf.

**Step 6 - Decide, and be honest about the confidence.** One of: clean, spam, threat, or
manual review. The confidence value is a **policy number, not a calibrated probability**,
and the evaluation artifact carries `calibrated: false` so nobody can mistake one for
the other.

**Step 7 - Propose an action, but never take it.** Every action goes through an approval
gate bound to a digest of the specific verdict it was approved for. Change the verdict
and the token no longer matches. The default provider is dry-run: it writes receipts and
touches nothing.

**Step 8 - Record the case.** Every message becomes a row in a local SQLite ledger at
the moment the case is opened. The machine's verdict goes in append-only, with database
triggers that make UPDATE and DELETE fail. Later, a human records what they actually
decided. Those two facts side by side are the entire point.

**Step 9 - Measure whether we were right.** `ledger agreement` reports how often the
human agreed, and separately: of the cases the machine *cleared*, how many turned out to
be threats. That second number is the one that matters, and it is the one systems do not
report.

**Step 10 - Escalate the hard ones.** A case a human wants a second opinion on can go to
a frontier model, on demand, recorded as an event against the existing case.

---

## Part 2 - what we actually built

| Component | File | What it is |
|---|---|---|
| Intake | `src/tenable_email/sources.py`, `google_intake.py`, `alertcenter.py`, `gmail.py` | a directory of `.eml`, or Google Alert Center plus Gmail; read-only, adapter contract |
| Parsing | `src/tenable_email/parse.py` | MIME-aware extraction with an explicit truncation flag |
| Deterministic signals | `src/tenable_email/signals.py` | authentication, link destinations, redirect unwrapping, attachment risk |
| Model tiers | `src/tenable_email/tiers.py` | six named roles, each able to abstain |
| Adjudication | `src/tenable_email/ensemble.py` | the voting rule and the clearance veto |
| Verdict | `src/tenable_email/verdict.py` | disposition, confidence, attack type, reasons |
| Approval gate | `src/tenable_email/receipt.py` | single-use tokens bound to a verdict digest |
| Writeback | `src/tenable_email/writeback.py` | dry-run and ledger providers |
| Case ledger | `src/tenable_email/ledger.py` | append-only SQLite, four tables |
| Web view | `src/tenable_email/webui.py` | stdlib `http.server`, **zero JavaScript** |
| Attachment analysis | `src/tenable_email/attachments.py` | optional, off by default; quarantine, digest binding, and a capability-derived safety gate |
| Evaluation | `eval/run.py`, `eval/selective.py` | risk-coverage curves, AURC, class-conditional risk |
| CLI and MCP | `src/tenable_email/cli.py`, `mcpserver.py` | same workflows from a shell or an agent |

Scale: **zero runtime dependencies**, and a test suite whose size roughly equals the source
it covers. The exact line counts live in README's "By the numbers" section, which carries the
reproduce commands and the commit the snapshot was taken at; the suite totals live in
`docs/results/latest.md`, which `tools/record-results.sh` rewrites on every run. Neither is
duplicated here.

That is a deliberate change. This paragraph used to carry its own hard-coded copy - source
lines, test lines, commit count, test totals - and it also claimed that `tools/record-results.sh`
regenerated those figures, which it never did: the script writes `docs/results/latest.md` and
nothing else. So the sentence warned that its own numbers "were stale within a day of being
written" and then went stale again, twice, while asserting a reproducibility it did not have.
Two copies of a number is how a document ends up contradicting the repository it describes, and
the fix is one owner per figure rather than a more careful editor.

What this document does keep is the count that a reader needs in order to trust the offline
claims: **52 recorded model interactions** in `fixtures/replay/` (14 classifier, 14
prompt-injection, 14 LLM, 9 URL-reputation, 1 vision) plus **4 REA analyzer fixtures** in
`fixtures/rea/`. Those are what make the suite runnable with no inference host and no network,
and they change only when a tier's recorded behaviour changes.

That last one is a design constraint, not an accident. `pyproject.toml` declares
`dependencies = []`. Everything in stages 1-3 is standard-library Python. A reviewer can
clone the repo and run the whole suite with no install step and no inference host.

---

## Part 3 - the decisions, and what we rejected

### 3.1 The clearance veto

**Decision:** a verified deterministic CLEAN can be *escalated* by a confident
specialist, but never *overruled into an accusation* by one.

**Why:** authentication is evidence about domain control, not about intent. A perfectly
authenticated attacker domain sending "sign in at attacker.example/login" is a real
attack and passes SPF, DKIM and DMARC.

**What we rejected:** letting the ensemble vote symmetrically. That produced the bug a
red-team review caught - `combine(verified CLEAN, vision THREAT 0.999)` stayed CLEAN, so
a vision model correctly identifying a fake login page could not stop an auto-clearance.
The fix is a `MANUAL_REVIEW` veto on auto-clearance. `tests/test_ensemble.py` now pins
that a text-tier THREAT 0.99 leaves a settled CLEAN untouched while a vision THREAT 0.999
vetoes it, and `tests/test_receipt.py` asserts that if it ever moves back to CLEAN the
gate has been weakened again.

### 3.2 The ledger is append-only at the database level

**Decision:** `cases` has SQLite triggers `cases_no_update` and `cases_no_delete` that
`RAISE(ABORT)`. A revised or erased machine verdict is impossible without deliberately
dropping a trigger.

**Why:** the moment you can edit history, the agreement measurement becomes a claim
rather than a record. If the machine's original verdict can be updated to match what the
human decided, agreement is 100% by construction.

**What we rejected:** enforcing append-only in Python. Application-level discipline is
not an invariant; the next refactor removes it.

The human's decision lives in a separate `resolutions` table with at most one row per
case, because a human resolution is final and we do not model a human changing their
mind about the machine's original judgement.

### 3.3 Record every case, not just the approved ones

**Decision:** the ledger writes when a case is *opened*, not when an action is approved.

**Why:** this was a real bug. Recording originally sat behind the approval gate, so the
first run produced 14 receipts and **zero** cases. Worse, a ledger holding only approved
cases is a biased sample - the careful analyst approves the ones they already looked at -
which makes "false negatives among cleared" meaningless, because the cleared cases that
went wrong are exactly the ones that would never have been recorded.

### 3.4 The receipt is the source of truth, not the verdict

**Decision:** `LedgerProvider` loads the receipt JSON the runner already wrote and
refuses with `receipt_not_found`, `receipt_ambiguous` or `receipt_unreadable` rather
than reconstructing a row from an action summary.

**Why:** the runner's contract is `provider.execute(action, receipt_id, verdict_digest,
approval)`. A provider never receives the verdict object. Reconstructing one from a
summary would create a second, weaker representation of the same fact.

`case_id` **is** the receipt id. One identifier across the receipt, the approval token
and the ledger row, instead of three that must be kept in agreement.

### 3.5 No JavaScript in the web UI

**Decision:** `src/tenable_email/webui.py` uses stdlib `http.server` and renders
server-side HTML with zero script.

**Why:** every page in this UI displays attacker-controlled content. A subject line is
an attack surface. Removing the script-execution surface removes the injection path
entirely rather than relying on escaping being right in every template.

Supporting controls, each pinned by a test: loopback-only binding by default and refusal
to bind outward without an explicit flag; a default-deny CSP header on every response; a
CSRF token in a cookie mirrored into a hidden form field; no external resources at all -
no CDN, no web font, no protocol-relative URL.

We tested this rather than asserting it. A hostile `<img src=x onerror=alert(1)>` subject
renders as inert literal text, and we verified it visually in a real browser as well as
in the test suite.

**One correction to our own testing:** the first version of the XSS test asserted that
the substring `onerror=` did not appear anywhere. That assertion is actively harmful -
a correctly escaped hostile subject *should* still be readable by the analyst, so
`onerror=` appearing as inert text is the desired behaviour. `tests/test_webui.py` now
uses a helper that flags only real executable constructs.

### 3.6 A rate with no denominator is `None`, not `0.0`

Every rate in `agreement_summary()` returns `None` when its denominator is zero. "No
cleared case has been resolved yet" and "no cleared case was ever wrong" are different
facts, and rendering both as 0% would tell an operator the system is perfect when it has
never been tested. The web UI shows the explicit denominator on every rate card.

### 3.7 Uncalibrated confidence, said out loud

The 0.90 CLEAN and 0.80 SPAM confidences are policy thresholds, not probabilities.
`eval/selective.py` writes `calibrated: false` into the artifact and a test pins it.

Selective prediction only needs a *ranking*, which uncalibrated confidences can supply.
A calibrated claim would need Platt scaling or conformal fitting on a held-out split,
which we have not done. We report the risk-coverage curve and say the confidences are
uncalibrated.

### 3.8 Evaluate as a deferral system, not an accuracy claim

**Decision:** the headline metric is coverage at a fixed automated-risk ceiling, not
accuracy.

**Why:** an accuracy number on a small constructed corpus is not evidence about real
mail, and we refuse to imply otherwise. What we *can* measure honestly is how much of a
queue the system can take off a human's desk and what it costs in errors among the
messages it does answer.

This also stops the failure mode where escalating everything looks safe. It is safe and
it is useless, which is why `tests/test_pipeline.py` pins a floor on how many benign
fixtures must still auto-clear. Safety and coverage are reported together or the report
is advocacy.

### 3.9 Cost ladder versus the reference workflow

The reference implementation (KnowBe4 PhishER, `disassembledd/knowbe4-phisher-email-analysis`)
calls its Bedrock node at **batchSize 1 on a five-minute schedule for every unresolved
reported message**, against Claude Sonnet 4, with no cheaper rung. A message that a
header check would settle still goes to a frontier model.

Ours runs deterministic checks first, then small specialist tiers, and reserves the
frontier model for an explicit on-demand escalation. That is a structural difference, and
it is visible in `no_model_call_rate`.

### 3.10 An external analyzer is a subprocess, not a dependency

**Decision:** deep attachment analysis shells out to an optional external Node.js tool
(`morluto/rea`, MIT) instead of adding a Python dependency or writing extraction
ourselves. It is off by default, behind `TENABLE_EMAIL_DEEP_ATTACHMENT_ANALYSIS`.

**Why:** `dependencies = []` survives, so the clone-and-run-with-no-install-step property
is preserved. An absent analyzer is not an error - the component abstains with
`rea_not_installed` and **no verdict on any of the 36 fixtures changes**, which is
asserted per fixture rather than asserted once.

**What we rejected:**

- *Adding `pypdf` / `python-docx` as an extra.* That makes us own extraction for every
  format forever, and it changes the install story for a capability most operators will
  never switch on.
- *Forcing it into the `Tier` abstraction.* `Tier` is HTTP-shaped - `endpoint_field`,
  `url`, `headers`, `api_key_field`. A local subprocess does not fit, and pretending
  otherwise puts a lie in the configuration model that the next reader has to unwind.
- *Making it a voting tier.* It produces Evidence findings and signals for the existing
  adjudication, so the clearance veto keeps working with no new plumbing.

**The safety gate is an intersection, deliberately.** Refuse any operation REA declares
with `may_access_network`, `may_show_ui` or `mutates_artifact`; intersect that with a
hardcoded six-operation allowlist; and denylist `capture-*`, `debug-*` and `*-adb-*` by
name regardless of declared effects. Both halves must agree, so neither a REA version
change nor an edit to our list can silently widen what runs on untrusted bytes.

One thing worth saying in the room, because it is the kind of bug that is invisible in a
green suite: the first draft canonicalised REA's effect names on one side of that
comparison and not the other, so an operation REA spelled `may-access-network` would have
been **permitted**. The fix canonicalises both sides, and the test that catches it was
verified by reintroducing the bug and watching it fail. A safety gate whose tests have
never been seen to fail is decoration.

**Digest binding:** REA reports `subject.digest.sha256` and
`normalized_result.subject.root_sha256`. Both must equal the sha256 we computed from the
message bytes, or the entire response is discarded with `digest_mismatch` and none of its
content reaches a verdict or an evidence record. Half-verifiable is not verified. This is
the same principle as an approval token being bound to a verdict digest.

**The honest limit:** a clean static read is not a safety claim. The analyzer does not
execute the artifact and neither do we, so nothing here speaks to runtime behaviour. And
what it can actually read is containers and binaries, not documents - measured on the
build host, a plain-text attachment returns `target_unavailable`. The name this slot
carried in the contract said otherwise. It promised text out of PDF and Word; the
component never delivered any, so the provider, the capability and the stage title have
been renamed to what the analyzer actually returns - `attachment_structure_inspector`,
`attachment_structure_inspection`, *Attachment structure*. That was a contract change:
`stages.yaml`, the registry in `src/tenable_email/contract.py`, the constant in
`src/tenable_email/attachments.py`, README's and SKILL's stage lists and the two tests
that pin them all move together, with `tools/validate_contract.py` checking that they
still agree. It is worth making at this moment and not later, because nothing outside
this repository reads those names yet. A contract that advertises a capability it does
not deliver is worse than one that advertises less: a reviewer, or the agent integrating
it, plans around the promise.

---

## Part 4 - the measured results, including the uncomfortable one

All figures from `eval/metrics.json`, regenerated at a clean tree and recording the
commit it was measured against.

### Synthetic corpus - 14 labelled messages

| | deterministic-only | with model tiers |
|---|---|---|
| auto-clearance | 21.4% | 21.4% |
| escalation | 28.6% | 28.6% |
| accusation | 50.0% | 50.0% |
| messages needing no model call | 100% | 7.1% |
| messages where a model was consulted | 0 | **13** |
| selective coverage | 71.4% | 71.4% |
| selective risk (error among accepted) | **0.0** | **0.0** |
| false negatives among accepted | 0 | 0 |
| false accusations among accepted | 0 | 0 |
| AURC / excess AURC | 0.0 / 0.0 | 0.0 / 0.0 |

Coverage-at-risk is satisfied at every budget we tested, from 0.1% to 5%: **71.4% of the
corpus can be auto-resolved at zero measured error.**

### Adversarial corpus - 18 messages built specifically to break us

| | deterministic-only | with model tiers |
|---|---|---|
| auto-clearance | 5.6% | 5.6% |
| escalation | 88.9% | 88.9% |
| accusation | 5.6% | 5.6% |
| selective coverage | 11.1% | 11.1% |
| selective risk | **50%** | **50%** |
| false-negative rate among accepted | **0.5 (1 of 2)** | 0.5 |
| false accusation among accepted | n/a - no benign message was accepted | n/a |
| AURC / oracle AURC / excess | 0.0417 / 0.0139 / 0.0278 | same |
| coverage at any risk budget from 0.1% to 5% | **not achievable** | not achievable |

**The one failure:** `forged_auth_single_header`. A hostile case we auto-cleared. It is
carried in the artifact as `declared_open` - not fixed, not hidden, named in the report.

### The uncomfortable number

**On the synthetic corpus, model tiers were consulted for 13 of 14 messages and not one
disposition changed.** Deterministic-only and corpus-backed produce identical
dispositions on both corpora.

We are not going to bury this. What it means:

1. **The deterministic layer is doing the work on this corpus.** That is a good result
   for cost and a limited result for the models.
2. **The corpus is the limitation, not the models.** It is 14 messages we wrote
   ourselves. A detector cannot fail on a corpus its authors designed to be detectable.
3. **The adversarial corpus shows zero model consultations**, because our 52 recorded
   model interactions cover only the synthetic fixtures. So we currently have **no
   evidence either way** about what the model tiers add against adversarial input. That
   is a gap in our measurements, and it is the honest reason the external-corpora work
   exists.

What would change this: benchmarking each tier separately against external corpora with
known labels. That was scoped as Bundle N, and **it has now been run** - against live
services, not recordings. The results are in `docs/LIVE-AB.md` and they changed the story.

### What the live model-tier A/B actually showed

Until tonight every number this project published about its model tiers came from replay
recordings covering `fixtures/synthetic` only. On 2026-11-03 the tiers were measured
against real inference services over **3,037 messages in 14 corpora, 0 errors, 267
seconds**: a distilbert phishing classifier on ONNX runtime, a security-model ensemble for
URL reputation and prompt injection, and a local vLLM for adjudication.

**The best number in the project.** On 203 real benign business emails the pipeline
auto-cleared **171 - 84.2% coverage - accused none, at 0.0 selective risk**, with the
classifier false-flagging 3 (1.5%) and the injection engine 6 (3.0%). This is the only
external corpus whose text is actually email, so it is the only one that generalises, and
it is the number to lead with.

**The worst number in the project.** On the other twelve corpora - Bengali SMS and English
LLM prompts wrapped in a synthesized envelope - the same pipeline accused **1,059
messages**, including 437 of 840 on the benign Bengali set. On `notinject`, the corpus
built specifically to expose over-defense, our tiers flagged between 23% and 75% of benign
trigger-word prompts.

The split is the finding, not either half alone:

| tier | in-domain (real email) FPR | out-of-domain FPR | pooled recall |
|---|---|---|---|
| `classifier` | **0.0148** | **0.416** | 0.650 |
| `prompt_injection` | **0.0296** | **0.592** | 0.843 |

A 28-fold difference on the same model in the same run. Corpus construction dominates the
measurement - which is what our own survey of the published literature concluded, and why
quoting a single pooled accuracy number here would have been misleading in whichever
direction we chose.

Two tiers earned their place and one did not:

* On the project's 18 adversarial messages the phishing classifier caught **zero**. On
  agent-manipulation text the injection engine reached **0.88-0.93 recall** where our
  deterministic scanner reaches 9.2%. That gap is a real capability the rules do not have,
  and it is the honest argument for keeping the tier.
* `url_reputation` scored recall 1.0 **and** false-positive rate 1.0 on the synthetic
  corpus. That is not discrimination, it is a constant, and it should not be described as
  a detector.

**The attribution is clean, and it is the real A/B.** Deterministic-only deferred all
3,005 external messages, because a synthesized envelope carries no `DKIM-Signature` and no
`Authentication-Results`, so the layer that settles most of the synthetic corpus has
nothing to settle on. Every one of the 1,059 accusations and 589 clearances in the live
column is therefore attributable to the model tiers. That is a controlled comparison, not
a correlation.

**What it validated.** The classifier voted `threat` at **0.9948** and the injection engine
at **0.9988** against a correctly-authenticated delivery bounce from a trusted domain, and
the verdict stayed `clean`, with both votes recorded in the reasons as *"recorded and
deliberately not applied"*. Had the ensemble weighted them, that is a false accusation at
near-maximum confidence. In the same run the classifier voted `clean` at 0.62 and 0.60 on
two messages labelled threat, which the deterministic layer caught anyway.

**What it exposed.** The clearance veto protects against a model wrongly *clearing* a
threat. Nothing symmetric protects against a model wrongly *accusing*, because on an
unsettled message there is no verified finding for a veto to defend. On real email this
did not bite - zero false accusations on 203. On out-of-domain text it bit hard. The fix is
not a retuned threshold; it is requiring a verified finding before an accusation, or
refusing to disposition headerless mail at all. Scoped as Bundle R and deliberately **not
implemented** sixteen hours before a deadline: it changes core adjudication, and the
committed synthetic numbers are verified.

**The limitation that survives all of this.** Twelve of the fourteen corpora are not
email. **No external corpus here measures phishing recall on real email**, because the one
real-email set contains no hostile messages. That gap is unchanged, and it is why the raw
`.eml` phishing corpora still matter.

### The head-to-head that answers "do you need a big model?"

The A/B above ran the cheap tiers. The expensive question is whether the top rung of the
cost ladder earns its cost, so the whole ladder was run together - classifier, URL
reputation, injection engine and a language-model adjudicator - over the same seeded sample
of at most 120 messages per corpus, **1,327 messages, twice**, with only the adjudicator
changing. Both arms completed with **0 errors**. One arm adjudicated on a **local** vLLM
host; the other on a **remote** third-party API, which is labelled everywhere it appears
because this project's premise is inference on hardware the organization owns, and mixing
the two up would tell a reader something false about what the local host can do.

| adjudicator | recall | false-positive rate | median latency |
|---|---|---|---|
| **local** (Qwen-flash class, 4 batched slots) | 0.800 | **0.125** | 15.1 s |
| **remote** (`deepseek-v4.1-flash`, third-party API) | 0.831 | 0.145 | 3.0 s |
| small injection engine, for comparison | 0.826 | 0.470 | 0.15 s |

**It is a tie, and a tie is the result we wanted.** The remote model catches marginally
more; the local model cries wolf marginally less. Neither gap is large enough to call a
winner from a single run with no confidence intervals, and both sit at roughly a quarter of
the small injection engine's false-positive rate at the same recall. So the measured case
for the top rung is real, and **the local model is not the compromise** - it costs five
times the wall clock and buys data sovereignty rather than accuracy.

**Then the finding that matters more than either number.** On the 120 real benign business
emails in that sample, every tier individually was near-perfect - classifier 0.008 false
positives, injection engine 0.017, adjudicator 0.000 in both arms. And the pipeline's
auto-clearance was:

| configuration | auto-cleared | coverage | false accusations |
|---|---|---|---|
| fast tiers, no adjudicator | 171 of 203 | **84.2%** | 0 |
| + local adjudicator | 3 of 120 | 2.5% | 0 |
| + remote adjudicator | 0 of 120 | **0.0%** | 0 |

**More accurate components produced less automation.** Nothing broke. Clearance is gated on
a tier's *self-reported confidence band* - `high` above 0.90, `medium` above 0.70, `low`
above 0.40 - against a fixed 0.857 bar. So a tier that honestly says "low confidence, but I
agree this is clean" **blocks** clearance, while a tier that says "high confidence" from a
model we measured at 0.25-0.47 false-positive rate **grants** it.

**The rule rewards overconfidence.** Swapping one adjudicator for another of comparable
accuracy changed auto-clearance fourteen-fold and inverted which mistakes the system makes,
at essentially the same aggregate risk. The fix is not a retuned threshold; it is gating
clearance on measured reliability rather than on how a model phrases its certainty. That is
scoped as **Bundle S and deliberately not implemented** - it would move every committed
number with hours left before a deadline, and the current numbers are verified.

---

## Part 5 - the pitch, 8 minutes including the demo

**The format changed from what this document was written for.** The booking page is more specific
than the selection email: *"plan for 8 minutes of demonstration (what you built, why you built it,
what outcomes it drives, and a live demo of your build) and 5 minutes of Q&A."* It is not 5-8
minutes of talking followed by open grilling, so the script below is cut for talk-plus-demo and
Part 6 now has a five-minute window rather than the rest of the slot.

Four elements are required inside the 8 minutes. Each maps to a beat below, and all four must be
audibly present - a judge working from that sentence is checking them off:

| required element | beat |
|---|---|
| why you built it | 0:00 - 1:05, the problem and the cost shape |
| what you built | 1:05 - 1:45, the pipeline and the refusal to act without approval |
| a live demo of your build | 1:45 - 5:00, four beats over the ledger |
| what outcomes it drives | 5:00 - 6:45 measured results and limits, 6:45 - 8:00 the close |

**The slot is Thursday 2026-11-05 at 1:15pm Eastern**, the second-to-last of the day. Judges will
have heard roughly thirteen pitches by then and it is after lunch. That changes the tactics and not
the content: the hook goes in the first ten seconds rather than building to it, the demo carries
more weight because a live terminal is a change of pace in a tired room, and the margin we have -
856 spoken words against an 8-minute budget - should be spent finishing early rather than filling
time. Running to 7:59 in front of a fatigued panel costs pitch-execution points that the extra
sentence cannot win back.

Judges score **mission impact 40%**, technical execution 20%, innovation 20%, pitch execution
20%. Mission impact is worth twice any other single axis and twice the whole technical score, so
the opening is about the problem and the opening is not where the numbers go. Selection also says
explicitly: start with the problem, then show it working, a live demo is best.

Every figure below sits in a committed artifact and Part 8 says which one. Do not say a number
that is not there - two of the judges are from Anthropic and one of them will know what a
frontier call costs.

---

### 0:00 - 1:05 - The problem (this is the 40%)

Open cold, in the first ten seconds, with the thing nobody else in the room has. Do not build to
it:

*"Every system pitching today will tell you how often a human agreed with it. Ours tells you how
many messages it waved through turned out to be attacks - and I will show you that number, live,
in about three minutes."*

Then the problem. A university helpdesk gets phishing reports from people who are not analysts. Every one of those
reports has to be looked at by someone who is. The workflow we studied handled that by sending
every unresolved reported message to a frontier model, one message at a time, on a five-minute
schedule.

That replaced analyst-hours with model-hours. It did not remove the cost, it moved it to a
different vendor's invoice, and it added something the university did not have before: a standing
outbound data flow carrying staff and student mail to a third party, forever, whether or not
anyone was watching the queue.

And it produced a verdict nobody ever checked. There was no record of whether the machine was
right, so nobody could tell whether the automation was safe to expand. That is the part we think
is actually broken.

### 1:05 - 1:45 - What we built

A local pipeline. Deterministic forensics settle what evidence can settle. Small CPU models
handle the residual. What is left goes to a flash-class adjudicator running on hardware the
organization already owns. Nothing leaves the building, and there are zero runtime dependencies -
clone it and the entire suite runs with no install step and no inference host reachable.

It refuses to act on mail without a single-use approval token bound to that specific verdict's
digest. And it keeps a ledger.

### 1:45 - 5:00 - Demo (about three minutes, do not let it run long)

Say first: *"Everything you are about to see runs offline, from committed recordings. There is no
network call and no inference host, so what I show you is reproducible."* Then run it.

`bash tools/rehearse-pitch.sh` runs this whole sequence, times each step, and verifies every case
id and machine verdict before it resolves anything. Rehearse with it. It fails loudly on all four
of the ways this demo can go wrong, three of which were found by running it rather than by reading
the plan.

**Run the demo with no `TENABLE_EMAIL_*` endpoints exported**, and the harness now enforces that
for you. This matters because the replay result depends on it: in replay, a tier with no
configured endpoint is recorded as UNAVAILABLE, while a configured tier is consulted and its
recording replayed. Measured on the same fixtures and commit, with and without endpoints in the
environment:

| environment | `clean_security_newsletter_discussing_injection` |
|---|---|
| no endpoints exported | **manual_review** 0.40 - the correct deferral |
| endpoints exported | **threat** 0.92 - a false accusation on stage |

That fixture is labelled clean and exists to exercise `injection_false_positive`: it is a security
newsletter that quotes injection phrases while discussing them. With endpoints exported, the
replayed classifier says 0.98 threat, url_reputation 0.92 and prompt_injection 0.99 against an llm
vote of 0.90 clean, and the disagreement resolves the other way. The case ids move with it, so the
ids above stop resolving and the harness refuses to start.

This is the one trap that would have looked like a mystery. Exporting
`.scratch/endpoints.env` to try live mail, then running the demo in the same shell, produces a
false accusation on screen and a harness that will not start, with nothing visibly connecting the
two. The harness unsets those variables itself rather than requiring anyone to remember.

```
cd <repo>
export PYTHONPATH=src
python3 -m tenable_email demo
python3 -m tenable_email run fixtures/synthetic --out /tmp/demo/run --provider ledger
python3 -m tenable_email ledger --root /tmp/demo/run list
python3 -m tenable_email ledger --root /tmp/demo/run show 14193ad949ffb0ac
python3 -m tenable_email ledger --root /tmp/demo/run resolve 14193ad949ffb0ac --disposition threat --resolver shawn
python3 -m tenable_email ledger --root /tmp/demo/run resolve 1d46f676980e569e --disposition clean  --resolver shawn
python3 -m tenable_email ledger --root /tmp/demo/run resolve 1fc9d4457761cf4e --disposition clean  --resolver shawn
python3 -m tenable_email ledger --root /tmp/demo/run resolve ac218fbf3f694c7c --disposition clean  --resolver shawn
python3 -m tenable_email ledger --root /tmp/demo/run agreement
python3 -m tenable_email ledger --root /tmp/demo/run snapshot -o /tmp/demo/snap.html --force
```

Four beats. The case ids are load-bearing and were verified identical across three fresh runs.

1. **`run` then `list`** - fourteen reported messages triaged in about a third of a second. Point
   at the queue: machine verdict, confidence, and an empty HUMAN column. That column is the point.
2. **`show 14193ad949ffb0ac`** - "Quick favor - vendor payment". The machine said
   `manual_review` at 0.50. Say: *"This is a BEC attempt from an authenticated sender with valid
   SPF and DKIM. Passing authentication is evidence of domain control, not of benign intent, so we
   refused to clear it and handed it to a person. We would rather be honest about not knowing."*
3. **Four `resolve` calls, and the mix is the whole trick.** One escalation confirmed as a threat,
   three clearances confirmed as clean. That produces:

   ```
   cases            14 (10 open, 4 resolved)
   agreement        3 agree, 1 disagree (75.0%)
   CLEARED THEN FOUND HOSTILE   0 of 3 (0.0%)
   ```

   Two traps sit on either side of this and both were hit while preparing it. Resolve a case the
   machine *cleared* as a threat, to make the counter move, and it prints `1 of 1 (100.0%)` - true
   of the input, and to a judge it reads as the system waving through an attack. Resolve *only* the
   escalation and the counter prints `0 of 0 (no cleared case has been resolved yet)` with
   agreement at 0.0%, so the differentiating metric has nothing to measure and the headline looks
   broken. Confirming clearances as well as escalations is what gives the safety number a
   denominator.

   If a judge asks about 75%: *"The one disagreement is the case the machine refused to decide. A
   deferral is not a wrong answer, and the ledger does not dress one up as agreement."*
4. **`agreement`** - the payoff. Two lines, in this order. First, name what the room is looking at:
   *"These are fixtures, so I am playing the analyst to show you the mechanism - the 84.2% figure
   comes from 203 real reported messages."* Resolving your own test fixtures without saying so is
   the one thing a technical judge will call out, and calling it out yourself costs one sentence.
   Then the payoff: *"Most systems tell you how often the human agreed. This tells you how many
   messages the machine waved through turned out to be attacks. That is the number that decides
   whether you can automate more of the queue, and it is append-only at the database level, so it
   cannot be quietly edited later."*

If screen share is flaky, `snapshot` produces one self-contained HTML file with no JavaScript and
nothing external to fetch. Open it in a browser. That is the fallback, and it is also the safer
choice - a static file cannot hang on stage.


### 5:00 - 6:45 - The numbers, and the limits in the same breath

On **203 real benign business emails that people had actually reported as phishing**, deterministic
forensics plus the CPU models auto-cleared **171 - 84.2% - with zero false accusations.** Those
never reach a model large enough to bill for. The reference makes one frontier call per unresolved
report, so 203 reports is 203 calls; we escalate 32. **6.34x fewer**, and the residual goes to a
local adjudicator rather than a paid API.

We ran the same 1,327 messages twice to test the premise. The local adjudicator scored **0.800
recall at 0.125 false positives, 15.1 s median**; a remote flash-class API scored **0.831 at
0.145, 3.0 s.** A local model on hardware we already own is a viable replacement at five times the
latency - and on a queue that runs every five minutes, latency was never the binding constraint.
The outbound data flow was.

Now the three things that are wrong with it, because you will find them:

**Adding our own adjudicator destroys the clearance rate.** Wire the LLM tier in and auto-clearance
collapses from 84.2% to about 2%. The gate clears only when the *weakest* self-reported confidence
across consulted tiers beats a bar, so adding a tier can only lower the minimum. The micromodels
emit 0.98 to 1.00 and the local model hedges at 0.6 to 0.8. The bar is keyed to confidence nobody
ever calibrated. We diagnosed it, wrote a three-message reproduction, and shipped it disclosed
rather than re-tuning the threshold until the number looked good.

**There is no head-to-head against Claude Sonnet 4.** We compared against a remote flash-class API,
not the model the reference uses. A corpus we generated ourselves structurally cannot produce that
comparison.

**The 84.2% is benign mail.** It is a false-positive retirement rate, not a detection rate. Real
queues with more malicious traffic escalate more.

### 6:45 - 8:00 - Close on mission, not on engineering

The reason this matters is not that we wrote a fast classifier. It is that 84% of what a helpdesk
gets is noise - people reporting newsletters, vendor invoices, delivery failures - and every one of
those reports currently costs either an analyst's attention or a frontier call with the mail
leaving the building.

We retired 84% of that locally, at zero measured false accusations, with an audit trail that
records whether the machine was wrong. The next thing to fix is the clearance gate, so the
adjudicator can be wired in without collapsing coverage - that is measured work, about two and a
half hours of re-running both arms, and it is the first thing we would do.

Then stop talking. Five minutes of questions is short and Part 6 is what it is for.

---

**Timing, measured rather than guessed.** The spoken script is **847 words: 6.0 minutes at
140 wpm, 6.8 at a deliberate 125**, against an 8-minute budget - so 1.2 to 2.0 minutes of margin.
The commands execute in under two seconds total, so the demo costs presenter talk and pointing
rather than machine wait.

Counted as: prose in every beat except the demo, plus only the quoted `*"..."*` lines inside the
demo beat, stopping at "then stop talking". Everything else in Part 5 is direction.

Three measurement traps produced confident wrong numbers here before being caught, and all three
are worth knowing because they all err toward panic. Counting the whole of Part 5 gives 1,782 words
and reads as thirteen minutes, but most of it is stage direction. Not cutting at "then stop
talking" gives 1,102 and reads as over budget, because these notes are prose paragraphs whose
wrapped continuation lines get counted as speech. And counting the demo beat as prose gives 1,087,
because the beat now carries two paragraphs explaining traps the presenter must *not* say aloud. In
a document that mixes script with direction, the only honest measure is the one that knows which
lines are which.

**If the room is running you long, drop in this order:** the second paragraph of the close (the
clearance-gate fix is already in the numbers section and Part 6 answers it), then the remote-versus-
local latency sentence (the recall and FPR comparison carries the point without it), then beat 2 of
the demo - show the queue and the agreement output and narrate the escalated case instead of opening
it. Do not drop the "cleared then found hostile" line; it is the only thing in the pitch that no
other team is likely to have.

**The demo's case id is stable.** `14193ad949ffb0ac` is content-derived, and three consecutive runs
against a fresh output directory produced it identically, so hardcoding it in the script is safe.
If it ever differs, stop and investigate rather than improvising on stage - a changed id means the
fixture or the id derivation moved.

**Rehearse with the actual commands, out loud, timed.** The failure mode this guards against is not
a wrong number, it is discovering at minute six that the terminal is the wrong size for a screen
share.

---

## Part 6 - the grilling

**Five minutes, not the rest of the slot.** The format gives about 8 minutes to pitch and demo and
5 to questions, so at most three or four of these will be asked. They are ordered so the first five
are the ones most likely to land, and each answer is written to be said in under forty seconds. If a
judge asks something further down, the shorter form is the first sentence of the answer - say that,
then stop and let them pull.

Scoring is mission impact 40%, technical execution 20%, innovation 20%, pitch execution 20%. Every
answer below should therefore return to impact rather than stay in the mechanism: the reason a
technical answer matters is that it decides whether an organization can automate more of its queue
without losing the audit trail.


**"You say 0% error. That's not credible."**
Correct, it is not a claim about real mail. It is 0 errors among 10 accepted messages
out of a 14-message corpus we wrote ourselves. We report it as coverage-at-risk on that
corpus and we say in the README that these are small constructed corpora. The
adversarial number, 50% selective risk, is the one that shows the metric can move.

**"If the models changed nothing, why are they there?"**
That was the honest answer on our own synthetic corpus, and it stopped being honest once we
measured. `docs/LIVE-AB.md` records a live A/B over 3,037 messages against real services.
What it found:

* The adjudication tier **matches** the small injection engine's recall - 0.800 local, 0.831
  remote, against 0.826 - at roughly **a quarter of its false-positive rate**, 0.125-0.145
  against 0.470. That is the measured case for the top rung of the ladder.
* The injection engine reaches 0.88-0.93 recall on agent-manipulation text where our
  deterministic scanner reaches 9.2%. That is a capability the rules do not have.
* The phishing classifier caught **0 of 18** of our adversarial messages, and scored recall
  0.125 with a 0.40 false-positive rate on our synthetic ones. It is the weakest component
  we ship and we say so.
* `url_reputation` answered 38 of 1,327 messages and flagged every one. Recall 1.0 with a
  false-positive rate of 1.0 is not discrimination, it is a constant.

The uncomfortable half is that the models also *cost* us. Out of domain their false-positive
rates run 0.25-0.59, and the pipeline accused 1,059 messages across those corpora where
deterministic-only deferred all of them. And swapping the adjudicator for one of comparable
accuracy changed auto-clearance fourteen-fold and inverted which mistakes the system makes,
because clearance is gated on a self-reported confidence band rather than on measured
reliability. That is scoped as Bundle S and not fixed.

So the honest answer is no longer "they exist for the residual." It is: measured, they add
precision on manipulation text and destroy it out of domain, and our architecture's refusal
to let them rewrite a settled deterministic verdict is what keeps the second fact from being
catastrophic.

**"Why uncalibrated confidence? That's a cop-out."**
Calibration needs a fitting procedure on held-out data. We have 14 synthetic and 18
adversarial messages. Fitting a calibrator on that would produce a number that looks
rigorous and means nothing. Selective prediction needs a ranking, which we have. We ship
`calibrated: false` in the artifact so the limitation travels with the result.

**"Append-only? What if the machine was wrong?"**
The machine being wrong is exactly why it is append-only. The correction goes in
`resolutions`, next to the original, and the disagreement is the measurement. If you can
edit the original, agreement becomes 100% by construction and you have learned nothing.

**"No JavaScript? In 2026?"**
It is a read-mostly local view over a queue. Server-rendered HTML with no script means
there is no injection execution surface in a UI whose entire job is displaying hostile
subject lines. We lose nothing an analyst needs and we tested the escaping in a real
browser as well as in the suite.

**"What did the red team find?"**
Eleven findings. The two most load-bearing: an authentication-rule bug where
sender-alignment facts were computed and then discarded, so SPF/DKIM pass plus DMARC fail
still cleared CLEAN at 0.90; and the missing veto described above. Both were verified in
source and fixed with tests that fail if the gate weakens again. Others we have not
fixed are recorded as declared-open in the artifact.

**"You auto-cleared a forged-authentication phish."**
Yes. `forged_auth_single_header` on the adversarial corpus. It is named in
`eval/metrics.json` under `declared_open`. We would rather ship a named failure than a
clean report - and the reason it is visible at all is that we evaluate class-conditional
risk instead of aggregate accuracy.

**"Zero dependencies - what's the catch?"**
No attachment content extraction. We flag a risky `.docm` from an external sender but we
do not unpack it. The reference workflow does, by passing attachments to Claude. That is
the one genuine capability gap and it is listed as such.

**"Does report volume matter?"**
It should, and right now it does not - we do not deduplicate re-reports, so a message
reported by 40 people re-runs the full chain and the fact that 40 people reported it is
discarded. Scoped as Bundle P: a content digest, an append-only reports table, and volume
surfaced as a **campaign indicator that never changes a disposition**. Not built.

**"Why not just use PhishER?"**
We studied it and cite it as the reference baseline in `docs/REFERENCE-BASELINE.md`,
including the row-by-row comparison. We adopted its campaign-tracking idea in principle.
We differ on three structural points: no frontier model per message, an approval gate
before any mutation, and a measurement of machine-versus-human agreement that the
reference does not produce.

**"Can this replace the Claude workflow?"**
We cannot answer that, and we will not pretend to. There is no head-to-head against Claude
Sonnet 4 in this repository. We compared our local adjudicator against a *remote flash-class
API* on the same 1,327 messages and it held up - 0.800 recall at 0.125 FPR versus 0.831 at
0.145 - which is evidence that a local model can stand in for a paid frontier call, not evidence
about the specific model the reference uses. A self-generated corpus structurally cannot produce
the comparison, because we would be grading against our own fixtures. What we can say is
narrower and true: 84.2% of real reported benign mail never reaches any frontier-class model at
all, so for that majority the question does not arise.

**"Why does adding your own LLM tier make the system worse?"**
Because the clearance gate is wrong, and we found it. Clearance requires the *minimum*
self-reported confidence across all consulted tiers to beat a bar, so adding a tier can only
lower that minimum - it can never help. The micromodels emit 0.98-1.00 and the local adjudicator
hedges at 0.6-0.8, so wiring it in drops auto-clearance from 84.2% to about 2%. The deeper defect
is that the bar is keyed to confidence nobody ever calibrated. We diagnosed it, wrote a
three-message reproduction, and shipped it disclosed with the pre-fix numbers rather than
quietly re-tuning the threshold until the number looked good. The fix is to gate on measured
reliability per tier; it needs a re-measurement of both arms, about 88 minutes local and 66
remote, and we chose not to rush a safety-critical change in the last hours before the deadline.

**"84.2% - on what, exactly?"**
203 real benign business emails that people had reported as phishing. It is a false-positive
retirement rate, not a detection rate: it says how much reported-but-harmless volume we can
settle cheaply. It says nothing about catching phish, and the malicious proportion of a real
queue would push the escalation share up. Two further limits: the external corpora are
synthesized envelopes without SPF/DKIM/DMARC, so the deterministic layer fought with one hand
tied - on authenticated fixtures it settled 9 of 14 with no model call at all. And zero false
accusations means zero *accusations*, on a benign-only set; a benign corpus cannot produce a
false accusation by construction.

**"Your local model is five times slower. Why not just use the API?"**
Because the API is the thing we are trying to stop paying for, and because it is a standing
outbound flow of organization mail to a third party. 15.1s median against 3.0s sounds bad until
you notice the queue runs on a five-minute schedule: at 1,327 messages the local arm took 88
minutes and nobody was waiting on it synchronously. The latency is real and we report it, but it
is not the binding constraint - the data flow and the per-message cost are.

**"Your public repo has two commits."**
It is a fresh squashed history, by design, and the note in the repo says so. The internal
history contains hostnames, internal paths and a colleague's identity, and the Exchange scans
full git history for credentials, so we publish a clean two-commit export rather than a rewrite
that could leave something behind. What is in those two commits is 216 files, about 42,000
hand-written lines, and a test-to-source ratio of roughly 1:1 - 17,313 lines of tests against
17,304 of source. The README has the exact commands and the commit the snapshot was taken at,
because a count nobody can reproduce is an assertion.

---

## Part 7 - what we did not build

Stated plainly, because the questions will come:

- **External-corpus evaluation (Bundle N).** The only route to a real claim about what
  each model tier adds. Scoped, corpora selected with licensing checked, not started.
- **Report deduplication (Bundle P).** Scoped today, not built.
- **On-demand frontier escalation (Bundle K).** Scoped as the top rung of a cost ladder,
  constrained never to bypass the approval gate. Not built.
- **Attachment content extraction.** Was the genuine capability gap; it is now
  *conditionally* closed, and the condition is worth stating rather than smoothing.
  By default the engine still only inventories an attachment, and the contents stay
  an explicit unknown in the evidence record. An operator may install an external
  Node.js analyzer (`rea`) and switch on
  `TENABLE_EMAIL_DEEP_ATTACHMENT_ANALYSIS`; the engine then quarantines the payload,
  verifies the analyzer's own digests against the bytes in the message, and records
  a `VERIFIED` finding describing the container's entries - each with its path, size
  and digest - together with the analyzer's limitations and coverage status. Three
  honest caveats. It is off by default and nothing in the measured results depends
  on it. It cannot move a disposition: no fact the adjudication consumes comes from
  it, and an unread-or-read high-risk attachment still blocks an automatic clearance
  (the tool's first limitation is that it does not execute the artifact, so a clean
  static read is not a safety claim). And what it can actually read is containers
  and binaries, not documents: measured on the build host, a plain-text attachment
  is refused with `target_unavailable` and native binary analysis is refused with
  `provider_unavailable` until a decompiler is installed. So the PDF/Word-text half
  of the reference playbook's capability is still not closed; the "we never look at
  bytes at all" half is, conditionally. See the README's
  [Optional deep attachment analysis](#optional-deep-attachment-analysis-with-rea).
- **Gmail label writeback.** Unbuilt, behind the approval gate by design.
- **QR code decoding.** Cut, not deferred - the README claimed it and nothing
  implemented it, so we removed the claim rather than shipping a feature we could not
  test.
- **Calibrated confidences.** Would need Platt or conformal fitting on held-out data.
- **Authentication on the web UI.** Loopback-only instead, which is a boundary decision
  rather than a solved problem.

---

## Part 8 - where to verify each claim

| Claim | Check it here |
|---|---|
| Every offline evaluation number | `eval/metrics.json`, regenerated by `python3 eval/run.py --json -o eval/metrics.json` |
| The evaluation prose | `eval/report.py` output; it recalculates nothing and fails loudly if the selective block is absent |
| Selective-prediction math | `eval/selective.py`, `tests/test_selective.py` |
| **The live model-tier A/B** | `docs/LIVE-AB.md`, backed by `eval/live-ab.json` (fast tiers) and `eval/live-ab-fullstack-{local,remote}.json` (whole ladder) |
| **Which corpora, and why these** | `docs/EVAL-SUITES.md`, with licences verified at source and the exclusions recorded |
| **The external corpora' provenance** | `eval/PROVENANCE.json` - source URL, revision, licence, sha256, row count, fetch time |
| **Classifier model research** | `docs/MODELS.md`, verified against source including what was rejected and why |
| **Every measured claim, dated** | `docs/EVIDENCE.md` |
| **Capability-by-capability gap vs the reference** | `docs/PARITY.md` |
| Append-only invariant | the triggers in `src/tenable_email/ledger.py`, pinned by `tests/test_ledger.py` |
| Clearance veto | `src/tenable_email/ensemble.py`, `tests/test_ensemble.py` |
| No JavaScript, no external resources | `tests/test_webui.py` |
| Zero runtime dependencies | `pyproject.toml`, `dependencies = []` |
| Reference comparison | `docs/REFERENCE-BASELINE.md` |
| Red-team findings and responses | `docs/RED-TEAM-RESPONSE.md` |
| What the UI looks like | `docs/images/ledger-*.png` |
| Test evidence | `docs/results/latest.md` and `docs/results/junit.xml` |

A note on the two kinds of number in this project. Everything under `eval/metrics.json` is
**replay-backed** and reproduces offline from committed recordings. The live A/B artifacts
are **not** reproducible offline by design - they are measurements of real services at a
moment in time - which is exactly why they live in separate files and are never merged into
`metrics.json`. An offline artifact that quietly absorbed a live number would stop being an
offline artifact.

**Reproducing the whole thing:**

```
git clone <repo> && cd tenable-email
python3 -m pytest tests/ -o addopts= -q        # 1278 tests, no install step
python3 eval/run.py --json -o eval/metrics.json
python3 eval/run.py                            # the readable report
python3 -m tenable_email ledger serve --port 8137
```

The live A/B additionally needs reachable inference endpoints, so it is documented rather
than reproduced; `eval/live_ab.py --help` lists the environment variables that point each
tier at a service, and it refuses to run a requested tier whose endpoint is unset rather
than silently scoring nothing.

---

## Part 9 - a note on how this was built

Worth saying in the room if asked, because it is true and it is interesting.

Two classes of bug shipped during this build and both were caught by verification rather
than by tests passing:

A portability bug where `webui.py` used a backslash inside an f-string replacement field.
That is Python 3.12 syntax and the package declares `>=3.10`. It ran fine on the build
host. Before fixing it we ran `ast.parse(feature_version=(3,10))` over every source file
and it reported that all of them parsed cleanly - **`feature_version` does not enforce the
f-string grammar**. A verification that cannot fail is not a verification. The second
contributor's agent caught the real thing by running the suite on an older interpreter.
We now detect the construct directly from the syntax tree, pinned to the exact line that
shipped, plus `tools/check-portability.sh` which compiles every file with each available
interpreter.

An evidence-integrity bug where the committed evaluation artifact recorded `dirty: true`
against a commit dozens of revisions behind HEAD. Nothing pinned the artifact to the tree
it described, so the published numbers corresponded to no commit at all.

Both are the same lesson and it is the one we would defend hardest: **a green test suite
tells you the assertions you wrote are true. It does not tell you the assertions exist.**
