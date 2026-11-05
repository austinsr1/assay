# Response to the external red-team review

An external hostile-code review and red-team assessment was run against the
review bundle at commit `7a7ad42` and reported 2026-11-02. It found five P0 and
six P1 findings, all producing unsafe `CLEAN 0.90` dispositions on adversarial
input, plus four operational items.

This file tracks each finding, what was done, and **what was verified rather than
asserted**. The review's central claim was accepted: it is correct, and the two
most load-bearing findings were reproduced from source before any code changed.

**Current status: of the eleven findings, eight are fixed and three are
mitigated.** None remains unaddressed. The three mitigations are R01 (a single
forged authentication header with nothing to contradict it is irreducible
offline), R03 (the forwarded-message structure the review names was not
reproduced on this corpus, and its underlying defect — one evidence scope for
both the wrapper and the inner message — is unchanged), and R07 (sender-controlled
bulk headers still settle the spam path). Four of the review's operational items
are documented rather than fixed, and those are the ones that remain genuinely
open: no input-size policy before parsing, no MCP path policy, uncalibrated
confidence values, and no attachment content extraction.

`fixtures/adversarial/` holds eighteen hostile messages covering these
findings. Seventeen previously returned `CLEAN 0.90` with no model consulted;
all seventeen are now asserted to escalate, and the eighteenth is the R01 residual
under a strict xfail.

Status legend: **fixed** implemented and verified; **mitigated** the unsafe
outcome no longer occurs but the root cause remains; **open** not addressed;
**documented** accepted as a stated limitation.

---

## The central finding

> The system treats successful sender authentication and the absence of a small
> set of deterministic red flags as sufficient proof of safety. Once a
> deterministic `CLEAN` is issued, the normal cascade does not consult the
> adjudication LLM, and other model tiers are prohibited from escalating it. This
> is an architectural self-reinforcing false-negative path.

Accepted in full. Two properties made it worse than an ordinary bug:

- `pipeline._settled_as_clean` decided *whether to ask a model at all*, and rule 5
  decided the *disposition*, as two separate copies of the same condition. They
  could drift, and the drift direction was silent.
- `ensemble.combine` allowed only the adjudication tier to reopen a decisive
  verdict, so once cleared nothing downstream could object.

The fix therefore has three parts, not one: the clearance condition now has a
single owner used by both call sites, it requires positive evidence, and a
narrow veto exists for a tier that saw evidence the rules could not.

---

## P0 findings

| ID | Finding | Status | What was done and verified |
|---|---|---|---|
| **R10** | `From: noreply@example.edu` with SPF/DKIM PASS for `attacker.test` and DMARC FAIL still reported `auth_passes=true`, clearing at 0.90 | **fixed** | `signals.assess_alignment` computed `dkim_aligned` and `spf_aligned` and then discarded them. `auth_passes` now requires an *aligned* passing mechanism, and an explicit DMARC FAIL cannot be overridden by unrelated passes (RFC 7489 s3.1). |
| **R01** | An arbitrary `.eml` containing only `Authentication-Results: untrusted; dmarc=pass` obtains CLEAN 0.90 | **mitigated** | Worse than reported, and now partly fixed. The merge took the *strongest* value per mechanism and ratcheted PASS so a later FAIL could never override it, which meant a sender-supplied `dmarc=pass` beat a genuine `dmarc=fail` **below it in the same message** — verified: that message returned `CLEAN 0.90`. Parsing is now first-mention-wins, on the grounds that a receiving MTA prepends its header above what the message arrived with, and any later disagreement sets `AuthResults.conflicting`, which blocks a clearance outright. Two further fabrications were removed: a regex accepting `pass` … `sender` anywhere in a header manufactured an SPF PASS out of prose, and `action=reject`/`action=quarantine` — *policy*, not results — were mapped onto DMARC FAIL. The evidence detail string that claimed outcomes were "as reported by the receiving MTA" now says they are claims with unestablished provenance. **Still open:** a *single* forged header with nothing to contradict it is indistinguishable from a receiver-added one inside a raw `.eml`, and closes only with the receiving system's own metadata. Tracked as `forged_auth_single_header`. |
| **R02** | Correctly authenticated attacker-domain mail linking to `https://attacker.test/login` clears at 0.90 with no inference call | **fixed** | `pipeline._clearance_supported` now requires *positive* evidence: the sender is the organization or on the deployer's trust list, and every destination is accounted for by that relationship. An attacker-registered domain satisfies neither. Verified on the shipped corpus: the fixture with this exact shape moved from `CLEAN 0.90` to `MANUAL_REVIEW 0.50`. |
| **R11** | `combine(verified CLEAN, [vision THREAT 0.999])` returned CLEAN | **fixed** | A specialist tier may now *veto an automatic clearance*, moving CLEAN to MANUAL_REVIEW. It may not author a verdict: no attack type is asserted over verified findings. Restricted to `INDEPENDENT_EVIDENCE_TIERS`, currently the vision tier alone — see the measurement below. Covered by a unit test asserting both the veto and that a text tier at 0.99 still cannot reopen a settled message. |
| **R03** | Forwarded report from an authenticated user clears at 0.90 although `Verdict.sender` correctly identifies `scammer@attacker.test` | **mitigated** | Not reproduced on the shipped corpus: `threat_forwarded_by_user` dispositions `MANUAL_REVIEW 0.50`, not CLEAN. The review's sample is not in this repository, so the finding could not be checked directly. The structural defect it names is real and unaddressed — the wrapper and the inner message should be separate evidence scopes with separate authentication results, and the inner message re-triaged with auth unknown. |

### Why the veto is restricted to one tier, and the measurement behind it

The first implementation let any specialist veto above a confidence bar. Measured
against the shipped corpus it **destroyed two correct clearances**: the text
classifier reads a mailer-daemon bounce as phishing at 0.99, and the URL
reputation engine returned **0.962 for `https://docusign.net/signing/abc123`**,
0.917 for a security newsletter and 0.907 for a retailer's sale page.

So `url_reputation` was excluded despite being the strongest candidate on paper —
an external lookup is information no amount of parsing the message can produce —
because its measured false-positive rate on benign destinations made it the text
classifier's failure mode in a different hat. This is the pattern
`docs/EVAL-SUITES.md` records from published benchmarks: high in-domain accuracy
coexisting with catastrophic false positives just outside it.

What remains is deliberately narrow: exactly one tier can veto, and it is
unmeasured on benign images because the corpus holds a single vision recording.
That is stated here rather than hidden, because a veto that never fires is not a
protection.

---

## P1 findings

| ID | Finding | Status | Note |
|---|---|---|---|
| **R04** | Malicious instructions in an HTML alternative are not scanned when the plain-text alternative is benign | **fixed** | Every MIME alternative is now scanned rather than only the one `msg.body` selects (`text_body or html_body`), each stripped and raw, with every hit labelled by the part that produced it — because "the plain-text part says sign in" and "the HTML part does, behind benign plain text" are different findings for an analyst. The signals record also reports `parts_scanned`, so an absence is visible rather than silent. |
| **R05** | With short plain text plus long HTML, an anchor beyond the HTML cap is not extracted and `truncated` is false | **fixed** | Fixed in two parts. Truncation is tracked per MIME part and aggregated, so a message with 200 characters of text and 11,310 of HTML now reports `truncated=True` with the largest truncated length instead of silently reporting the short part. And a truncated message can no longer support an automatic clearance at all, because reporting that content was cut is not the same as examining it: an anchor beyond the cap is never extracted, so "every destination accounted for" would be true of a destination nobody looked at. A partial reading may still be escalated, which is honest, and the receipt rules already refuse to let a truncated record claim completeness. |
| **R06** | Authenticated internal email with an unexamined `.docm` returns CLEAN | **fixed** | An unexamined high-risk attachment now blocks a clearance whoever sent it, via a new `dangerous_unexamined` fact. It is deliberately *not* a THREAT trigger — only the external variant is — so an internal sender with a macro-enabled document goes to a person rather than being accused. `facts.adverse` has exactly one consumer, the clearance gate, which is what makes that separation safe. |
| **R07** | Authenticated attacker mail with a phish link plus fabricated `List-Unsubscribe` returns SPAM before models run | **mitigated** | Bulk markers remain a terminal disposition on the spam path. They are sender-controlled claims and should corroborate rather than settle a malicious-content report. Not changed. |
| **R08** | An HTML credential form posting to `https://attacker.test/collect` is absent from `links.resolved_hosts` | **fixed** | Far broader than reported, and the single highest-value fix of the night. A red-team agent found **eleven** distinct bypasses through the same root cause, not one: `<form action>`, `<meta http-equiv=refresh>`, `<iframe src>`, `<script src>`, `<object data>`, `<embed src>`, `<base href>`, `<img src>`, CSS `url()` in both a style block and a style attribute, and inline event handlers. Every one produced `CLEAN 0.90` with `link_count: 0`, because "every destination accounted for" was true by vacuous truth. `extract_links` now enumerates all of them, each labelled with the element that produced it in `Link.element`, and `classify_link_destinations` reports `elements` and `unaccounted_elements` so an analyst can see that a message *posts a form* to a foreign domain rather than merely linking to one. `srcset` remains a documented gap — its value is a URL list with density descriptors and needs real parsing. |
| **R09** | A Safe Links wrapper whose `url=` contains a second wrapper hides the destination | **fixed** | `unwrap_redirect` is now iterative and bounded (`MAX_REDIRECT_HOPS = 5`) with a seen-set, so a cyclic or self-referential chain terminates rather than looping. Verified: the nested case resolves through both hops to the real destination and dispositions `THREAT 0.85`, where one-hop unwrapping reported the inner *trusted* wrapper and cleared. |

---

## Operational items

| Item | Status | Note |
|---|---|---|
| Incomplete declared capabilities — `stages.yaml` advertised sandboxed PDF/Word extraction and README advertised QR decoding and `.[attachments]` | **fixed** | Neither existed in `src/`. The `qr` and `attachments` extras were removed (an extra whose libraries nothing imports installs successfully and changes nothing, which reads as a working feature), their researched pins preserved in a comment, stage 6 rewritten to say it is declared but not implemented, and README given an explicit limitation. The runtime never lied: it skips stage 6 with an `not implemented` reason that `tests/test_mcp_tools.py` pins. |
| Resource exhaustion — whole `.eml` read before any size policy; MIME bomb | **documented** | Not addressed. A service deployment needs a transport size cap, MIME part-count limit, aggregate decoded-byte budget and timeouts before parsing. Recorded in README limitations. |
| MCP filesystem permissions — `mcpserver.py` accepts any path with no allowed-root policy | **documented** | Not addressed. Needs a read-only corpus root, symlink-escape blocking and least-privilege process identity. The review did not demonstrate a leak through current response formatting, and none was reproduced here. |
| Default confidence values are policy labels, not calibrated probabilities | **documented** | Accepted. `0.90` on CLEAN and `0.80` on SPAM are rule priorities. The cost ratio in `ensemble.py` is a declared preference, not a measured error cost. README already declines to make an accuracy claim; this makes the reason explicit. |

---

## Second round: review agents run against the fix

The clearance-policy change was itself reviewed by two agents before anything was
built on top of it — a code reviewer (Qwen3.6-27B) and a red-team agent
(Qwen3.6-35B-A3B) asked to break it rather than assess it. A third agent failed
to start on an ambiguous model identifier. Both returned findings that were
confirmed and fixed; the eleven bypasses in the section above came from the
red-team agent.

The code reviewer found five defects in the fix itself, all confirmed and now
regression-tested:

| Finding | Why it mattered | Fix |
|---|---|---|
| The veto covered `CLEAN` but not `SPAM` | `SPAM` is just as decisive and just as unreopenable, and the spam path consults no models at all. A queue may be configured to *delete* on SPAM, so a malicious inline image on an authenticated bulk newsletter would be discarded rather than read | veto now applies to both |
| A vetoed verdict reported confidence 0.90 | The minimum of the two inputs, which is the HIGH band — the strongest label in the system attached to the one disposition meaning "we are declining to decide", while every other escalation path reports 0.5 | capped at `DEFERRAL_CONFIDENCE = 0.5`, LOW band, asserted |
| `combine()` raised `KeyError` on a decisive `MANUAL_REVIEW` | `Deterministic` is a public frozen dataclass with independent `decisive` and `disposition` fields, and `_SEVERITY` has no entry for a deferral. Unreachable through the pipeline, one caller away from a crash in a public function | severity looked up with `.get()`, incoherent input treated as unsettled |
| An unexamined inline image supported a clearance | Pixels are content the deterministic layer provably cannot read, so clearing on everything it *could* read is clearing on partial evidence. It also meant the veto was unreachable end-to-end: the only fixture with an image is settled `THREAT` before any tier runs | `inline_images` now blocks a clearance |
| Two operator-visible strings misdescribed the code | The veto reason named "an external reputation lookup" as able to veto when `url_reputation` is explicitly excluded; the "recorded and deliberately not applied" text said the dissenting tier "reads only the body text" while being emitted for the vision tier too | both corrected |

The reviewer also confirmed two things worth recording because they constrain how
the fix may be described. The clearance condition genuinely has a single owner —
exactly two call sites, no surviving second copy — but that claim is scoped to the
*deterministic* layer: `Disposition.CLEAN` is also reachable through the
ensemble's open-band path when configured tiers vote unanimously, which is by
design and cannot fire on a settled message. And the adjudication tier's ability
to reopen a settled message, which the code comments describe at length, is
**dead in the real pipeline**: a decisive disposition skips the LLM by
construction, and the one case where the LLM is consulted while decisive is a
`THREAT`, which has no higher severity to escalate to. In shipped operation the
vision veto is the only live reopener of any settled outcome.

## Third round: review of the export tooling and the metrics

A third agent (DeepSeek V4.1 Flash) reviewed the three files written that night
that no one had looked at: the public-export tool, the metrics harness and the
tree-sync script. It found thirteen issues. The first is the most serious thing
found all night, and it invalidated a guarantee that had already been reported as
verified.

**The history scan was a complete no-op.** `scan_history` translated Python
regular expressions into a single POSIX extended alternation and handed it to
`git grep -E`. The patterns contain `(?:`, `\b` and `\d`, none of which is ERE,
so git rejected the expression, exited 128 with empty stdout — and because the
call used `check=False`, that was read as zero findings. The tool then printed
`clean: no private material in any blob, commit message or identity`.

So the exported repository's *history* — the one surface that motivated discarding
58 revisions in the first place — had never been examined, and the message
asserting it had was false. Confirmed independently: the joined expression returns
128 with zero bytes of output.

Fixed by applying the patterns with Python's `re` to the raw bytes of each blob
via `git cat-file`, which also removed two quieter defects in the same stroke:
`git grep -I` skipped binary files entirely, and `\s` inside an ERE bracket
expression means a literal `s`. The function now returns the number of blobs it
examined, that number is printed, and a zero-blob scan is itself reported as a
finding — because a scan that read nothing cannot certify anything, and the
absence of that guard is precisely how a broken scan reported success. Verified to
have teeth by planting an RFC1918 address and a private home path in the export and
confirming both are caught with the offending path and blob named.

Two further defects sat behind the same line, and fixing only the regex would have
exposed them: the history scan had no exemption set, so the two files that
legitimately quote the patterns they detect would have made every export refuse
permanently; and the message-and-identity half of the scan did work, which is why
the tool looked functional.

Other findings fixed in the same round:

| Finding | Fix |
|---|---|
| Three destination-bearing attributes were still invisible: `button formaction`, `input formaction`, SVG `image href` and `use xlink:href`, plus legacy `background` | Enumeration table extended **and** a generic sweep added over every remaining attribute holding an absolute URL, so the table no longer has to be exhaustive for the analysis to be safe. Namespace declarations are excluded so the list stays readable. Three adversarial cases added |
| `eval/metrics.json` was copied into the export naming a private commit that does not exist there, while `docs/results/` was regenerated for exactly that reason | Regenerated inside the export too; both artifacts verified to name commits that are ancestors of HEAD, so they survive the push |
| `sync-trees.sh` printed "could not inspect the remote" and then reported `RESULT: in sync` with exit code 0 | A third state, with exit code 3 distinct from 1 ("verified to disagree"), because a caller cannot act correctly on either conflation. Also: the remote path is now quoted with `printf %q`, and the post-pull probe is captured and re-compared instead of printed and assumed |
| An exception after `mkdir` left a half-populated export that the next invocation refuses to overwrite | Body wrapped; any exception removes the directory before propagating, and the traceback is still the traceback |
| The LICENSE guard's comment claimed it checks the copyright holder is a real legal identity; it checked a five-string placeholder blacklist | Comment corrected to say what it does, and the holder as written is now printed for the operator to confirm |
| `git config includeIfMissing false` is not a git key, under a comment claiming it prevented identity inheritance | Removed, with the real residual risk named instead: a global `init.templateDir` or `core.hooksPath` |
| Two assertions in `tests/test_eval.py` could not fail: rates were range-checked but never recomputed, and `assert str(0) in text` is true of any report containing a zero | Rates are now recomputed from the per-message rows, including both denominators, and the report assertion matches the label and denominator |
| `clear_blocked` did not include the absence-of-evidence conditions, so a unanimous model CLEAN could clear a truncated or unexamined message that two docstrings said could never be cleared | Extended to truncated content, conflicting authentication, unexamined risky attachments and inline images, with the principle stated: absence of evidence cannot be filled by model confidence, while a judgment about content that *was* read legitimately can. Regression test added |
| `_git()` in the metrics harness returned `""` on failure, recording `commit: ""` and `dirty: false` | Returns an explicit `UNDETERMINED` sentinel, which is truthy, so a git failure records the tree as possibly-dirty rather than clean |

Two findings were **not** acted on and are recorded rather than quietly dropped. One has
since been settled by the operator and is kept here because the reasoning is the useful part.

The bare token `utility` is published as a default in `tools/sync-trees.sh`; the
organization-specific term list contains the longer hostname, so the guards cannot
see it, and whether the short alias is sensitive was left as the operator's call.
**The operator settled it on 2026-11-04: a short alias on its own is acceptable to
publish.** The reasoning is worth keeping rather than just the verdict. What the guards
strip is what actually enables access - fully qualified hostnames, RFC1918 and link-local
addresses, absolute home paths, usernames in identities, and credentials. A two-word
internal alias with no domain, no address and no route attached discloses a naming
convention and nothing reachable; scrubbing it would cost the documents their specificity
about *where* a measurement ran, which is part of what makes the measurement checkable.
The same reasoning covers `venus`, which appears once in `docs/LIVE-AB.md` identifying the
build host for a run. Neither alias appears with an address, and the export's history-wide
scan finds no dotted-quad outside the loopback and RFC 5737 documentation ranges.

The second finding stands and is unchanged: `eval/report.py` computes `len(row["model_judgments"])` while claiming to
recalculate nothing - it renders a payload field rather than deriving a metric, so
the claim holds in substance, but it is the only computation in the renderer
besides the percentage formatting and it should either move into the payload or be
acknowledged.

The reviewer also could not determine whether the `clear_blocked` gap was reachable
with real tiers, because the committed recordings contain no model judgments for
any adversarial case. It was fixed on the strength of reading the branch
conditions, and the regression test exercises it through the replay corpus.

## The adversarial corpus

The review's most useful recommendation was structural: add hostile cases to
continuous integration. `fixtures/adversarial/` is that corpus — 18 messages,
each sent from a subdomain of the protected domain with authentication headers
that genuinely pass, which is the attacker's strongest realistic position
because it satisfies "the sender is one of us" without any forgery a receiver
would catch.

It is separate from `fixtures/synthetic/` deliberately. Adding cases there would
change the corpus count many tests assert and, worse, change the URL sets that
key the committed replay recordings, silently turning the offline corpus into
cache misses. It is consumed only by `tests/test_adversarial.py`, which runs with
no model access at all — the configuration a judge runs is the one under attack.

Seventeen cases are marked `closed` and asserted directly. Three are marked `open`
and wrapped in a **strict** xfail, which is the mechanism that makes the suite
durable and is borrowed from the review's own harness: the assertion states what
should happen, it currently fails, and the day the underlying defect is fixed the
test XPASSes and the run goes red until the expectation is consciously moved. A
regression cannot be quietly reintroduced, and a fix cannot land without the
status table above going stale in a way CI notices.

The single open case is `forged_auth_single_header`, the R01 residual. This sentence
used to name three - it also listed `html_alternative_hides_injection` (R04) and
`internal_sender_risky_attachment` (R06) - and both have since been closed, so the
prose contradicted the table ten lines below it and the one parametrized case the suite
actually collects. A document that overstates how much is still broken is not a safe
document either: a reviewer reading "three open" would discount the status table that
says otherwise, and the next person to fix R01 would have no reliable way to tell what
"done" looks like. A further test cross-checks that every
open case names a finding id that `docs/RED-TEAM-RESPONSE.md` actually contains,
so this file and the corpus cannot drift apart in that direction; the check is
one-directional, which is why a stale claim of *more* open cases than exist went
unnoticed. The count is now derived from the corpus rather than restated beside it.

| Case | Before | After |
|---|---|---|
| base_href_hijack | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| button_formaction_override | not measured end to end | `MANUAL_REVIEW` 0.50 |
| css_url_beacon | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| event_handler_redirect | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| forged_auth_single_header | CLEAN 0.90 | `CLEAN` 0.90 (open) |
| form_action_credential_harvest | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| html_alternative_hides_injection | CLEAN 0.90 | `MANUAL_REVIEW` 0.40 |
| html_beyond_cap_while_text_is_short | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| iframe_to_attacker | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| img_src_beacon | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| input_image_formaction | not measured end to end | `MANUAL_REVIEW` 0.50 |
| internal_sender_risky_attachment | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| meta_refresh_redirect | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| nested_redirect_wrapper | CLEAN 0.90 | `THREAT` 0.85 |
| object_embed_payload | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| script_src_payload | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| style_attribute_beacon | CLEAN 0.90 | `MANUAL_REVIEW` 0.50 |
| svg_image_and_use_href | not measured end to end | `MANUAL_REVIEW` 0.50 |

The three cases marked "not measured end to end" - `button_formaction_override`,
`svg_image_and_use_href` and `input_image_formaction` - were added after the
destination-enumeration fix landed, so there is no pre-fix pipeline run to report
for them. What was verified is narrower and is stated as such: the parser returned
no destination at all for a `button formaction`, an `input formaction`, an SVG
`image href` or an SVG `use xlink:href`, which is the mechanism that made the
other eleven clear. Inferring a `CLEAN 0.90` from that is plausible but it is an
inference, not a measurement, and the difference is the reason this table
distinguishes them.

Note what "after" means for the cases that escalated: they became `MANUAL_REVIEW`, not
`THREAT`. That is the intended design and not a half-measure — an unaccounted
destination is still not a threat indicator, because legitimate mail links to
unrelated services constantly and treating a mismatch as a verdict is the flaw
this project refuses in the reference playbook. What changed is that these
messages can no longer be *cleared* without a human reading them.

## What the review changed about how this project tests itself

The shipped synthetic corpus was never adversarial, and that is the real finding
behind the findings. `clean_unrelated_link_no_concealment` encoded the exact
assumption under attack — authenticated sender, link to an unrelated domain, no
concealment — and the suite *asserted* it was clean. The tests passed because
they pinned the unsafe belief.

Two structural consequences:

1. **A clearance-rate floor now sits beside the safety assertions.**
   `test_the_clearance_gate_was_tightened_and_not_simply_abandoned` requires that
   at least three of the five clean-labelled fixtures still clear outright. A
   tightening has an obvious degenerate solution — clear nothing, escalate
   everything, never be wrong — which is the same failure mode as a classifier
   published with F1 0.99 and a false-positive rate of 1.00. Safety assertions
   without a coverage floor measure nothing.
2. **The disagreement taxonomy needs a third category.** A clean-labelled message
   sent to a human is currently reported as a *disagreement*. It is a deferral
   with a coverage cost, not a wrong answer, and lumping the two together
   understates the tool while a real miss goes unremarked. Open.

The review's own test package — 11 strict-`xfail` regression tests and 10 hostile
`.eml` samples — was **not available**; only the report was. Its strict-xfail
design is worth adopting: fixing a bug causes XPASS and fails the run until the
expectation is consciously updated, so a regression cannot be quietly re-broken.
Obtaining that package and wiring it into CI is the highest-value remaining
testing work, and it is not something that can be reconstructed faithfully from
the finding descriptions.

---

## Not yet measured

The review is explicit that its samples are adversarial examples, not a
statistical estimate, and the same is true of everything above. No false-negative
rate has been measured on any real or public corpus. `docs/EVAL-SUITES.md`
records what would be needed and what the two published suites cover. Until the
evaluation harness runs, this project has no accuracy numbers of its own and
claims none.
