---
name: local-first-phish-triage
description: >
  Workflow judgment for triaging user-reported phishing with the tenable-email
  tools and MCP server: how to read a disposition and its evidence, what
  disagreement between model tiers means, when to stop and hand the message to a
  human, which facts a lookup may rest on, and what this system cannot prove.
---

# Triaging reported phishing without fooling yourself

This file is the part of the project the tools cannot express. The deterministic
signals, the stage contract and the receipt rules are code, and code that drifts
from `stages.yaml` fails a test. What follows is the judgment an agent needs to
*use* those results rather than merely read them: when a disposition is
actionable, when it is a hole in the record dressed up as an answer, and what
must never be promoted from "we could not tell" to "it is fine".

Assume the reader is an automated analyst with the nine read-only tools of
`src/tenable_email/mcpserver.py` (or the CLI, or the library) and no memory of
how this engine was built.

## The chain, in the order it actually runs

The eight stages are declared once, in `stages.yaml`. Everything below is
validated against that file — this document, README, and the code — so a stage
that disappears from the contract stops this document from validating. Each is
read-only except the last, which is gated: **human approval required** for every
individual mutation it performs.

1. **Intake** (read-only) — acquire the reported message: a directory of `.eml`
   files, or a configured live alert feed. Only the file name is retained.
2. **Parse and authenticate** (read-only) — decode MIME and read the SPF, DKIM,
   DMARC and ARC outcomes *the receiving MTA already recorded*, keeping an
   absent check distinct from a passing one.
3. **Deterministic signals** (read-only) — lookalike domains by edit distance,
   anchor-versus-href mismatch, display-name spoofing, forwarded-message
   unwrapping, redirect unwrapping, attachment inventory, bulk-mail headers,
   boilerplate suppression and the injection-surface scan. No model call.
4. **Classifier cascade** (read-only) — phishing classifier, three-way
   fraud/spam/legitimate, URL reputation per unwrapped destination, and the
   prompt-injection detectors. Each is optional; each one with no endpoint and
   no recording is recorded as unavailable, not as a finding of nothing.
5. **Vision** (read-only) — embedded image extraction, verbatim transcription
   and brand-impersonation judgment from a local vision model.
6. **Attachment structure** (read-only, sandboxed) — what a retained attachment
   is made of, from the optional `rea` analyzer: container entries, sizes, digests
   and declared format. No PDF or Word text is extracted, and with the workflow
   off the contents stay an explicit unknown.
7. **Adjudication** (read-only) — the local language model for the ambiguous
   band, then the ensemble, which combines verified facts and model opinions
   asymmetrically and emits the narrative, the reasons and the confidence.
8. **Disposition and writeback** (**write — human approval required**) — the
   outward half: mail label, case record, analyst notification, each approved on
   its own.

Read that list as a cost curve and as an evidence curve. Stages 1–3 produce
reproducible facts and cost nothing; stage 7 produces an opinion and costs the
most. A message that stage 3 can settle never reaches stage 7 — which is why a
model's disagreement with a settled message is recorded and not applied.

## `MANUAL_REVIEW` is an outcome, not a failure

`manual_review` means: the evidence in hand does not settle this, and the engine
knows the difference between "clean", "threat" and "I cannot tell you which".
It is the correct answer for the ambiguous band, and the escalation is the
finding.

**Do not try to resolve it by asking again.** Re-running the same message through
the same tiers is deterministic: the same bytes produce the same signals, the
same replay keys return the same recordings, and the same ensemble returns the
same answer. Repeated calls until a more comfortable number appears is not
investigation, it is a random search for a permission you did not get. The only
legitimate ways forward from `manual_review` are:

- **add information the record does not have** — was any credential entered?
  does the sender's mail platform show a login anomaly? is this vendor normally
  paid through that account? Those are outside the message, so a human or
  another system has to supply them. Record what you asked and what came back.
- **consult a genuinely different source** — a live adjudication endpoint that
  sees the verified facts alongside the content, not a second copy of the same
  recording. If you do this, say in your report that the shipped corpus did not
  settle it.
- **hand it to a person with the reasons attached.** This is the default. The
  reasons list is the useful part: it names the specific indicators that
  conflict, so the human starts from the argument rather than from the message.

Corollaries: a `low` confidence band on a `threat` is still a threat — send it to
a person, do not downgrade it because the number is small. An `unknown`
disposition means the message could not be read at all; that is a parse failure
to report, not a soft "clean".

## Disagreement between tiers is the signal, not the noise

The tiers see different things. The text classifier is shown the body; the URL
engine is shown one destination; the vision model is shown one image; the
adjudication model is shown the body *and* the verified technical facts. They
disagree routinely, and on the shipped corpus the disagreement is measured: the
phishing classifier reads a mailer-daemon bounce as phishing at 0.99 and a
security newsletter as phishing at 0.98; the estate injection engine scores that
bounce at 1.00. Neither is a fact about the message.

So when `classify_local` returns `classifier: threat 0.99` next to
`llm: clean 0.95`, the correct reading is **"two informed systems looked at
different slices and reached opposite conclusions"**, which is precisely what a
human is for. Three rules follow:

- **Do not average it away.** A mean of 0.99 and 0.95 in opposite directions is
  a number that no fact and no opinion supports, and it hides the only
  interesting thing about the case. The ensemble does not average either: where
  the facts left the band open, unanimity is required, and the *weakest* vote's
  confidence is what gets adopted.
- **A verified finding is a floor.** If the deterministic layer settled the
  disposition from authentication, link and MIME facts, a model opinion cannot
  talk it down — the tier that only saw text does not know that the DKIM passed
  or that the anchor text disagreed with its href. It can raise severity, and
  only the adjudication tier, which was shown the facts, may reopen a settled
  message upward.
- **Abstention is not agreement.** A tier that ran and volunteered nothing
  decidable (`abstain`) is not a vote for either side, and a tier that did not
  run is not an abstention. Keep those three states apart in anything you write
  up.

## An unknown never becomes a fact

Every finding carries one of four provenances, and the difference between them
is the difference between an investigation and a story.

- **`verified`** — observed in the message itself and reproducible: header
  values, authentication outcomes, extracted URLs, attachment hashes. Same bytes,
  same finding, every time.
- **`model_judgment`** — a model's opinion, with its score attached. May be
  wrong. Is never a fact, no matter how confident the score reads.
- **`unknown`** — *not knowable from a message*: whether the sending account was
  compromised, whether a recipient typed credentials, whether an unexamined
  attachment is malicious. Recorded with no value on purpose; giving an unknown
  a value is how it silently becomes a fact.
- **`unavailable`** — the stage that could have answered did not run or failed.
  We know which check is missing, which is a different thing from knowing the
  answer is unknowable.

**`UNAVAILABLE` is not `UNKNOWN`, and neither one is evidence of absence.** "The
vision tier had no endpoint" does not mean "the image is clean"; "whether
credentials were entered is outside this system" does not mean "they were not".
A report that reads a gap as a negative finding is the specific failure this
engine is built to make unrepresentable — the enforcement point is
`Evidence.assert_citable()`, which refuses a verdict that cites a gap, and the
receipt contract refuses to close a case whose disposition rests on one.

Practical instruction: when you write up a result, carry the gap count with the
disposition. "Threat, on two verified findings, with the vision and attachment
stages unrun" is a claim a reader can act on. "Threat" is not.

## Authentication passing does not mean the message is legitimate

Valid SPF, valid DKIM, aligned DMARC means one thing: the receiving MTA is
satisfied that this message came from that domain. It says nothing about whether
the content is honest, because a compromised account at that domain passes every
check, and a legitimate-looking domain can be a lookalike that passes for its
own owner.

The case to hold in mind is business email compromise: mail from a real
colleague or a real supplier, authenticating correctly, containing no link at
all, asking for a payment change or a gift-card purchase or "keep this between
us for now". There is nothing to inspect, so every technical indicator is clean —
and that is the tell, not the clearance. This engine routes that shape to a
person by name, and refuses to let any tier clear it, because the question
"is this account compromised?" is recorded as an `unknown`, and an unknown
cannot be answered by another model's confidence.

The reference playbook this project replaces tells its model that a link
destination matching the sender's domain or a trusted domain is "a strong
indicator of a clean email", and a mismatch "a very strong indicator of a
threat". Both halves are wrong in opposite directions: a compromised account
links to its own real domain, and ordinary legitimate mail links to services
nobody pre-approved. So do not treat a host mismatch as a verdict and do not
treat a host match as a clearance. What *is* a finding is **concealment**: a
URL-rewriting wrapper whose hidden destination belongs to neither the sender nor
a trusted domain, because nobody pays for a proxy except to move the reader's
attention off the real destination. `analyze_urls` reports that as
`concealed_destinations`.

## A newsletter quoting an attack is not an attack

Prompt-injection text in a reported email is a threat class in its own right —
content aimed at the recipient's mail-reading agent rather than at the human
reader is an attack on that agent, and a SOC wants to be told. But the
deterministic scanner is a pattern matcher, and a pattern matcher cannot tell
"contains an instruction aimed at an agent" from "quotes an instruction while
discussing it". `ignore all previous instructions` appears in both, in exactly
the same characters.

So a deterministic hit alone never produces `THREAT`. It is capped and escalated
unless something independent corroborates it — a lookalike domain, a failed
authentication, an anchor that disagrees with its href, a diverging Reply-To, a
high-risk attachment from an external sender. Corroboration means *a second,
different kind of evidence pointing the same way*, not the same evidence counted
twice and not a second scanner in agreement with the first. The security
newsletter that discusses injection payloads is the fixture that pins this
behaviour; if your reading calls it a threat, you have flagged the documentation
of the attack instead of the attack.

When a model tier does fire on injection, check which tier it was and what it was
shown. The estate injection engine over-fires on this corpus by measurement, and
an ONNX classifier shown only the body cannot see that the message is a
newsletter.

## Populate a VIP list from the directory the organization already runs

`protected_persons` — the list whose impersonation deserves a faster queue and a
lower tolerance for doubt — must come from a system that is authoritative and
bounded: the HR record, the identity directory (AD or LDAP group such as
"executives" and "finance"), or the workspace admin API's own notion of roles.
Those have three properties that make them usable as configuration: they have an
owner, they have a defined membership, and they change on their own schedule
rather than on yours. Pull the list on a timer, store it beside the other org
profile values, and record where it came from and when.

Do **not** build it by scraping the organization's public web pages, boards
pages, press releases or conference bios. Four reasons, and they are not
style points:

- **It is the attacker's own targeting technique.** A public "our leadership"
  page is a named, titled, contact-shaped target list, and a pipeline that
  harvests it is running the reconnaissance step of the campaign it is meant to
  defend against. Anything that reads like that is a defect with a dual use.
- **It is an unbounded, undocumented outbound data flow.** This project's rules
  require every outbound call to be enumerated. Scraping is a request to
  arbitrary hosts for content that was never intended as an interface, whose
  shape changes without notice, and which nobody can list in advance.
- **It is non-deterministic, and determinism is the product.** A page redesign
  or an A/B test changes the extracted names between two runs of the same
  message, so verdicts stop being reproducible, cached model recordings stop
  matching their keys, and the replay corpus that lets an outside reviewer run
  the whole chain offline stops being evidence.
- **A shipped skill that enumerates named personnel is dual-use pointed the
  wrong way.** Bundling a person list — even a synthetic-looking one — into a
  public artifact publishes an organization's executives and their
  employer-linked titles to anyone who clones the repository.

Which is why the shipped profile carries **role-based identities** — "IT service
desk", "payroll", "office of the president", "registrar" — and no individual's
name anywhere in the repository. Name-based VIP rules are the operator's own
configuration, behind an authoritative lookup, on their side of the boundary.
Match on the *display name claiming a role the sending domain does not own*
before you match on any individual's name: the claim is the finding.

The same reasoning covers every other "let me go look something up on the public
internet" idea in this workflow: if it is a signal, it must come from a named
provider with a documented call, a bounded result set, and an explicit answer for
what happens when it is unavailable.

## A truncated analysis is never a complete one

When the body exceeds the retention limit, the engine keeps what it can, records
`truncated: true`, and says how much of the original it read. Content that was
not read cannot have been considered, and the difference between "I found nothing"
and "I did not see it" is the whole of an honest report.

The rules the code enforces: a truncated verdict may escalate honestly, but it may
not claim `THREAT`, `SPAM` or `CLEAN` and then close as a case record — the
receipt refuses that closure. If you are summarizing a result, carry
`truncation.warning` into your text instead of dropping it. If a message that
matters arrived truncated, re-run it with a larger `body_char_limit` rather than
reasoning about the half you have.

The same discipline applies to every bounded operation in the chain, not only the
body: the URL reputation lookup is capped per message, the vision tier reads a
bounded number of inline images, and a redirect chain stops when its budget is
exhausted. Each of those writes a gap into the record when the cap binds, because
"the rest were unchecked" is not the same sentence as "the rest are clean".

## Working the tools

Read-only by construction: no tool in `src/tenable_email/mcpserver.py` writes a
file, opens a socket, spends a credential or advances the write stage. Anything
outward comes back as `proposed_writeback.actions` with `executed: false` and the
command that would actually run the gate. Use them in this order:

- `list_contracts` first if you are unsure of the chain's shape — stage ids,
  capabilities, access class and where approval binds.
- `check_auth` before you believe anything about who sent the message.
- `analyze_urls` for anything clickable, and `lookalike_domain` for any domain
  you found somewhere else.
- `analyze_eml` for the whole chain on one message, `analyze_eml_directory` for
  a batch. Read `evidence` by provenance and `gaps` before you read `reasons`.
  A batch answer carries `scan` — the directory, how many `.eml` files it found,
  both bounds, and whether either bound — because a batch that does not say
  whether it saw everything is not auditable. A directory it cannot read
  completely comes back as an error naming the bound, not as a subset of rows
  that looks like the whole corpus; narrow the path rather than retrying it.
- `classify_local` when you specifically want to know that the tiers disagree.
- `explain_verdict` and `get_case_record` for a case that already ran, so your
  answer matches the record a human will audit.

An error comes back as a value: `{"ok": false, "tool": ..., "error": {"code":
..., "type": ..., "message": ...}}`. `not-found` and `bad-request` are yours to
fix. `case-record-unreadable` means the record is from a schema this build does
not reinterpret. No tool raises across the boundary, so a failure you did not
anticipate is information you should read rather than retry.

Message content does not come back out of this surface. Findings whose value
quotes the body — anchor text, injection matches, forwarded headers, a vision
model's transcription, every tier's prose — arrive as digests with the
explanatory detail attached. That is deliberate: this is an agent-facing
protocol, and a receipt is citable because it holds a digest of the reading, not
the reading. If you need the message, you already have it; if you need the
provenance, ask for it by name.

## What this system cannot prove

Say these when you report, because the first-place SWARM playbook says its own
limits and a claim that outruns its mechanism is the kind a reviewer
disbelieves.

- **Structure, not identity.** A case record proves that a verdict, an approval
  and a corpus digest are internally consistent. It cannot authenticate the
  person who approved, and it cannot attest that a tool which wrote a dishonest
  record was told the truth.
- **Replay, not freshness.** A recording is a real model's answer to this exact
  request, captured live and attested by the store's index. It is not a fresh
  reading of today's message, and it is not a claim that the model would say it
  again.
- **Corroboration, not a guard.** Fencing untrusted content and reporting the
  injection surface closes the gap the predecessor engine left open. It is not a
  measured injection-resistance result, and no number in this repository claims
  it is.
- **Synthetic evidence, not accuracy.** Everything shipped here is reproducible
  on RFC 2606 reserved fixtures. That makes the chain verifiable and makes no
  precision, recall or false-positive figure about real mail supportable yet.
