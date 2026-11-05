# Live model-tier A/B - real numbers from real inference hosts

**Run:** 2026-11-03, venus build host.
**Artifact:** `eval/live-ab.json` (fast tiers), `eval/live-ab-llm-local.json` (adjudication tier).
**Runner:** `eval/live_ab.py`.
**Messages measured:** 3,037 across 14 corpora, 0 errors, 267 seconds wall at concurrency 6.

This document exists because until tonight the model tiers had **never been measured**.
Every number in `eval/metrics.json` comes from replay recordings, and those recordings
cover `fixtures/synthetic` only - so all 3,005 external rows were dispositioned with zero
model judgments, and the artifact said so in capitals. The cost-ladder argument in the
README rested on an assumption nobody had tested. It has now been tested, and the result
is not comfortable.

## Endpoints used

| Tier | Service | Host | Model |
|---|---|---|---|
| `classifier` | FraudFoxAI `/predict` | integration host, tunnelled (address withheld) | `xanderabim/fraudfoxai-phishing`, distilbert-base-uncased, onnxruntime |
| `url_reputation` | secmodels `/url` | integration host, tunnelled (address withheld) | ensemble incl. `saidutta69/PhishScout-v2`, `sdmlai/cyber-jev` |
| `prompt_injection` | secmodels `/prompt-injection` | integration host, tunnelled (address withheld) | `sdmlai/cyber-jev` |
| `llm` (local arm) | local vLLM | inference host (address withheld) | Qwen3.8-flash-next class, 4 batched slots |
| `llm` (remote arm) | third-party completions API | remote provider (address withheld) | `deepseek-v4.1-flash` |

Read-only inference calls against services already used for `docs/EVIDENCE.md`. Nothing
was reconfigured. The first four rows are models running on hardware this organization
owns; the last row is **not** - it is a third-party remote API, included only as the
comparison arm in "The adjudication tier, local against remote" and the full-stack A/B,
and every figure from it is labelled `remote` wherever it appears.

This distinction is load-bearing rather than cosmetic. The premise of the project is
inference on organization-owned hardware, so a reader who mistook the remote arm's numbers
for local ones would draw the wrong conclusion about what the local host can do. An earlier
revision of this table listed only the four local rows and closed by asserting that a reader
knows "these are **local** models, not a frontier API" - a true statement about that table
which read as a claim about the whole document, while the document also reported
`deepseek-v4.1-flash` results 130 lines below. The remote row is listed here so the
document's own endpoint inventory cannot contradict its own measurements.

## The headline number, and it is a good one

`microsoft/llmail-inject-challenge`'s `emails_for_fp_tests.json` is 203 **real benign
business emails** (MIT). It is the only external corpus here whose text is actually email
rather than SMS or an LLM prompt, which makes it the only one that generalises.

| | value |
|---|---|
| auto-cleared | **171 of 203 - 84.2% coverage** |
| accused | **0** |
| deferred to a human | 32 |
| frontier calls avoided vs the reference | **203 / 32 = 6.34x fewer** |
| selective risk | **0.0** |
| classifier false-positive rate | **0.0148** (3 of 203) |
| prompt_injection false-positive rate | **0.0296** (6 of 203) |

On real benign business mail the pipeline cleared 84% with zero false accusations, and
both small models stayed under 3% false positives. That is the number to lead with.

## The uncomfortable number, and it is a big one

Every other external corpus is **out-of-domain text** - Bengali SMS and English LLM
prompts - wrapped in a synthesized envelope. On those, the same pipeline over-accuses
massively:

| corpus | n | label | accused | coverage | selective risk |
|---|---|---|---|---|---|
| bengali-test-not-smishing | 840 | benign | **437** | 0.605 | **0.860** |
| notinject-three-benign | 113 | benign | 21 | 0.274 | 0.677 |
| notinject-two-benign | 113 | benign | 23 | 0.487 | 0.418 |
| notinject-one-benign | 113 | benign | 14 | 0.425 | 0.292 |
| jackhhao-test-benign | 259 | benign | 25 | 0.336 | 0.287 |
| deepset-train-not-injection | 343 | benign | 20 | 0.510 | 0.114 |
| bengali-test-smishing | 561 | hostile | 424 | 0.765 | 0.012 |
| jackhhao-test-jailbreak | 141 | hostile | 45 | 0.333 | 0.043 |

`notinject` is the corpus built specifically to expose over-defense: 339 benign prompts
containing trigger words, zero positives by construction. Our model tiers flagged between
23% and 75% of them.

## Per-tier, pooled, and split by domain

Pooled over all 3,005 external messages:

| tier | answered | recall | false-positive rate | tp | fp | tn | fn |
|---|---|---|---|---|---|---|---|
| `classifier` | 3,005 | 0.650 | **0.376** | 627 | 767 | 1,273 | 338 |
| `prompt_injection` | 3,005 | **0.843** | **0.536** | 813 | 1,094 | 946 | 152 |
| `url_reputation` | 176 | 0.923 | 0.550 | 144 | 11 | 9 | 12 |

The pooled figures hide everything that matters, so here they are split:

| tier | corpus group | recall | false-positive rate |
|---|---|---|---|
| `classifier` | llmail (real email, 203 benign) | n/a - no hostile rows | **0.0148** |
| `classifier` | all other corpora (2,802) | 0.650 | **0.416** |
| `prompt_injection` | llmail (real email, 203 benign) | n/a | **0.0296** |
| `prompt_injection` | all other corpora (2,802) | 0.843 | **0.592** |

A 28-fold difference in false-positive rate between in-domain and out-of-domain text, on
the same model, in the same run. **Corpus construction dominates the measurement**, which
is exactly what our own survey of the published literature concluded and exactly why a
single pooled accuracy number would have been misleading.

On the project's own fixtures the tiers are worse still:

| corpus | classifier recall | prompt_injection recall | url_reputation |
|---|---|---|---|
| synthetic (9 hostile / 5 benign) | **0.125** (1 of 8), FPR 0.40 | 0.75, FPR 0.60 | recall 1.0 **and** FPR 1.0 |
| adversarial (18 hostile) | **0.000** (0 of 18) | 0.889 | recall 1.0 (14 of 14) |

The phishing classifier caught **none** of the 18 adversarial messages. `url_reputation`
flagged every URL it saw - recall 1.0 and false-positive rate 1.0 is not discrimination,
it is a constant.

Where the tiers genuinely help: `prompt_injection` reaches 0.88-0.93 recall on
agent-manipulation text (adversarial fixtures, jailbreak prompts, Bengali smishing) where
our deterministic scanner reaches only 9.2%. That is a real capability the rules do not
have, and it is the honest case for keeping the tier.

## The attribution, which is the actual A/B

This is the comparison the bundle existed to make. Same corpora, same messages, two
configurations:

| | deterministic-only (committed, offline) | live model tiers |
|---|---|---|
| accused, all 12 external corpora | **0** | **1,059** |
| cleared, all 12 external corpora | **0** | **589** |
| deferred | **3,005 - all of them** | **1,357** |

(The three live figures sum to 3,005, which is the check that they are counts of the same
messages rather than three unrelated rates. They were first written down from the per-corpus
table by hand and all three were wrong; they are now computed from the artifact.)

Deterministic-only deferred everything, because the synthesized envelope carries no
`DKIM-Signature` and no `Authentication-Results`, so the layer that settles most of our
synthetic corpus has nothing to settle on. Every accusation and every clearance in the
live column is therefore attributable to the model tiers. That is a clean A/B rather than
a correlation.

## What this validates, and what it exposes

**Validated:** the rule that no tier may rewrite a disposition the deterministic layer
settled on verified findings. On the synthetic corpus the classifier voted `threat` at
**0.9948** and the injection engine at **0.9988** against `clean_delivery_failure.eml`,
a correctly-authenticated delivery bounce from a trusted domain - and the verdict stayed
`clean`, with both votes recorded in the reasons as "recorded and deliberately not
applied". Had the ensemble weighted those votes, that message would have been a false
accusation at near-maximum confidence. The same run shows the classifier voting `clean`
at 0.62 and 0.60 on two messages labelled threat, which the deterministic layer caught.

**Exposed:** where the deterministic layer *cannot* settle - and every headerless message
is such a case - the tiers do decide, and out of domain they over-accuse. The clearance
veto protects against a model wrongly clearing a threat. Nothing symmetric protects
against a model wrongly accusing, because on an unsettled message there is no verified
finding for a veto to defend. On real email this did not bite (0 false accusations on
203). On out-of-domain text it bit hard (437 of 840).

**The consequence for the design, stated plainly:** the tiers are only safe where the
deterministic layer is also able to speak. On mail with real headers, the two agree and
the result is strong. On text with no headers, the tiers are the only voice and they are
not reliable enough to accuse on. The correct fix is not to retune a threshold; it is to
require a verified finding before an accusation, symmetric to the clearance veto - or to
refuse to disposition headerless mail at all and defer it.

## The adjudication tier, local against remote

The fast tiers above are small specialist models. The top rung of the cost ladder is a
language model, and it was measured separately over the same corpora with a seeded sample
of at most 120 messages each: once against a **local** vLLM host (Qwen3.8-flash-next class,
4 batched slots) and once against a **remote** API (deepseek-v4.1-flash). The remote arm
completed all 14 sets with **0 errors**; the local arm is **partial and partly invalid**,
for a reason recorded below.

Remote arm, adjudication tier only:

| corpus | n | label | llm recall | llm FPR | fast-tier FPR for comparison | median latency |
|---|---|---|---|---|---|---|
| llmail-fp-tests | 120 | benign | n/a | **0.000** | 0.0148 / 0.0296 | 3.05 s |
| notinject-one | 113 | benign | n/a | **0.071** | 0.230 / 0.478 | 2.88 s |
| notinject-two | 113 | benign | n/a | **0.062** | 0.248 / 0.540 | 2.78 s |
| notinject-three | 113 | benign | n/a | **0.266** | 0.336 / 0.752 | 2.98 s |
| deepset-test-not-injection | 56 | benign | n/a | **0.000** | 0.161 / 0.339 | 2.87 s |
| deepset-train-not-injection | 120 | benign | n/a | **0.033** | 0.108 / 0.394 | 2.79 s |
| jackhhao-test-benign | 120 | benign | n/a | 0.193 | 0.255 / 0.448 | 2.83 s |
| bengali-test-not-smishing | 120 | benign | n/a | 0.408 | 0.667 / 0.736 | 2.93 s |
| jackhhao-test-jailbreak | 120 | hostile | **0.950** | n/a | 0.326 / 0.929 recall | 3.08 s |
| deepset-train-injection | 120 | hostile | 0.658 | n/a | 0.305 / 0.744 recall | 3.16 s |
| deepset-test-injection | 60 | hostile | 0.500 | n/a | 0.200 / 0.617 recall | 3.02 s |
| bengali-test-smishing | 120 | hostile | **1.000** | n/a | 0.904 / 0.881 recall | 3.23 s |
| adversarial (ours) | 18 | hostile | 0.875 | n/a | 0.000 / 0.889 recall | 3.23 s |
| synthetic (ours) | 14 | mixed | 1.000 | 0.000 | 0.125 / 0.750 recall | 3.77 s |

Two columns in that table are the finding. **The adjudication tier is markedly more
precise on benign text than either small specialist** - 0.000 to 0.266 false-positive rate
on the five benign English corpora where the injection engine ran 0.339 to 0.752 - while
matching or beating it on hostile text (0.950 against 0.929 on jailbreak prompts, 1.000
against 0.881 on Bengali smishing, 0.875 against 0.000 on our own adversarial set).

That inverts the assumption the cost ladder is usually justified by. The cheap rungs are
cheap, and on out-of-domain benign text they are also the ones that flood a queue with
false accusations. The expensive rung is the one that declines to accuse. It does not
follow that the frontier model should run on everything - it is still 3 seconds and a
network call against 150 milliseconds locally - but it does mean "cheaper tier first"
needs to be argued on measured precision, not assumed.

**Latency, measured:** the remote API answered in a median of 2.8-3.8 s per message. The
local vLLM host took **14-20 s** for the same work on the corpora where both ran. The
remote service was roughly five times faster than our own hardware on this workload, which
is worth stating plainly in a project whose premise is keeping inference local: local is
the right choice for data-flow and cost reasons, and it was not the faster one here.

### The local arm is partial, and why

The local arm completed 10 of 14 sets and then failed 559 messages outright with
`FileNotFoundError` on paths under `eval/internal/_synthesized/`. The host did not fail.
The synthesized `.eml` files the measurement reads were **removed from under it** by a
concurrent verification step in the same working tree that moved `eval/internal/` aside to
prove the suite passes without fetched data. The measurement and its verification ran in
one tree at one time, and the verification won.

The affected sets are `llmail-fp-tests`, all three `notinject` splits, and 100 of 120 rows
of `jackhhao-test-jailbreak`. Their rows are recorded with `errors` counts in
`eval/live-ab-llm-local.json` rather than dropped, so the artifact shows what was not
measured instead of quietly reporting fewer messages. The local figures quoted above are
drawn only from the sets that completed. This is recorded because the tempting reading -
"the local model failed on those corpora" - is false, and a false operational conclusion
drawn from a corrupted run is worse than no run.

### What this arm does NOT measure

The adjudication runs configured **only** the `llm` tier. The classifier, URL-reputation
and injection tiers were not addressed, so the pipeline dispositions in those runs are not
comparable to the full-stack numbers earlier in this document, and their coverage figures
are low because a single opinion was available rather than because the messages were hard.
A full-stack run - deterministic plus all three fast tiers plus adjudication, on the same
sample - is the comparison that would settle what the top rung adds **on top of** the
cheaper ones, and it has not been run.

## Full stack: the two adjudicators, and what swapping one changed

The arms above measured tiers separately. This one runs the whole ladder together -
classifier, URL reputation, prompt injection and adjudication - over the same seeded
sample of at most 120 messages per corpus, 1,327 messages, twice: once with a **local**
vLLM adjudicator and once with a **remote** API adjudicator. Both arms completed with
**0 errors**. Artifacts: `eval/live-ab-fullstack-local.json`, `eval/live-ab-fullstack-remote.json`.

The three fast tiers are identical across the two arms, as they must be - same services,
same messages:

| tier | answered | recall | false-positive rate | median latency |
|---|---|---|---|---|
| `classifier` | 1,295 | 0.467 | 0.254 | 0.13 s |
| `url_reputation` | 38 | 1.000 | 1.000 | 0.15 s |
| `prompt_injection` | 1,295 | 0.826 | **0.470** | 0.15 s |
| `llm` local | 1,294 | 0.800 | **0.125** | 15.1 s |
| `llm` remote | 1,295 | 0.831 | **0.145** | 3.0 s |

**The adjudication tier matches the injection engine's recall - 0.80-0.83 against 0.826 -
at roughly a quarter of its false-positive rate, 0.125-0.145 against 0.470.** That is the
measured case for the top rung of the ladder, and it is a real one. `url_reputation`
answered only 38 of 1,327 messages and flagged every one of them; on this evidence it is
not a detector and should not be described as one.

Local versus remote adjudication is close on accuracy - the local model is marginally more
precise, the remote marginally more recalling - and the remote was **five times faster**
(3.0 s against 15.1 s median). For a project whose premise is keeping inference local, that
is worth stating without softening: local remains the right choice for data flow and cost,
and it was not the faster option here.

### Swapping the adjudicator changed which mistakes the system makes

| | local adjudicator | remote adjudicator |
|---|---|---|
| messages | 1,327 | 1,327 |
| auto-cleared | **84** (6.3%) | **6** (0.45%) |
| accused | 89 | 141 |
| deferred | 1,154 | 1,180 |
| coverage | 0.130 | 0.111 |
| selective risk | 0.052 | 0.048 |
| false clearances | **8** | **1** |
| false accusations | **1** | **6** |
| false accusations per 1,000 | 0.8 | 4.5 |
| false clearances per 1,000 | 6.0 | 0.8 |

Aggregate risk is essentially the same - 5.2% against 4.8%. **The error type flipped.** The
local adjudicator cleared fourteen times more mail and got eight hostile messages wrong by
clearing them; the remote adjudicator cleared almost nothing and got six benign messages
wrong by accusing them. Same deterministic layer, same three fast tiers, same messages,
same seed.

The mechanism is specific and it is a defect. Clearance requires every consulted tier to
vote clean **at or above a fixed 0.857 bar**, and a tier's confidence is its self-reported
band mapped through `{"high": 0.90, "medium": 0.70, "low": 0.40}`. One adjudicator answers
"high" on a message the other answers "low" on, and the second one's honest uncertainty
breaks unanimity and sends the message to a human. Observed directly on a benign business
email from `llmail-fp-tests`:

* fast tiers alone - classifier clean at 1.00, injection clean at 0.98 - dispositioned
  **CLEAN at 0.98**
* the same message with the adjudicator added, which voted **clean at 0.40** - dispositioned
  **manual_review**, reason *"the consulted tiers agree on clean but are not confident
  enough to act on it"*

So a low-confidence **agreement** blocks clearance, while confident agreement from the two
tiers this document measures at 0.254 and 0.470 false-positive rate produces an
auto-clearance at 0.98. **The rule rewards overconfidence.** Two adjudicators of comparable
measured accuracy produced a fourteen-fold difference in how much mail is automated, and
inverted the error profile, because of how they phrase certainty rather than because of how
often they are right.

This also reframes the earlier headline. The 84.2% coverage at zero risk on 203 real benign
business emails was produced by the fast tiers alone, under a rule that clears when two
small models agree confidently - the same pattern that produced 437 false accusations on the
benign Bengali set. That corpus happened to be in-domain, so it happened to be right. Nothing
in the mechanism is what made it right.

Scoped as **Bundle S**: weight a tier's contribution by its measured reliability rather than
by its self-reported confidence band, now that per-tier reliability is actually measured and
recorded in this document. Deliberately **not implemented** - it changes core adjudication,
it would move the committed synthetic and adversarial numbers, and there were about thirteen
hours to the deadline when it was found. Recorded so the finding outlives the session.

## Limitations - read these before quoting any number above

1. **Twelve of the fourteen corpora are not email.** They are SMS messages and LLM prompts
   wrapped in a synthesized envelope with no authentication headers, no links and no
   attachments. Dispositions on them skew to `manual_review` by construction, and the
   accusations measure the text surface responding to non-mail text. Only
   `llmail-fp-tests` is real email text, and it contains no hostile messages, so **no
   external corpus here measures phishing recall on real email.** That gap is unchanged
   and is the reason Nazario and SpaPhish (raw `.eml`, reportedly CC BY 4.0) still matter.
2. **One run each.** No repeats, no variance estimate, no confidence intervals. A single
   pass over 3,005 messages is far better than zero passes, and it is not a statistical
   claim about the models.
3. **Confidences are not calibrated**, here or anywhere in this project. Recall and
   false-positive rate are threshold-free in the sense that they use each tier's own
   verdict, not a cut we chose.
4. **`url_reputation` answered only 176 of 3,005 messages**, because most corpus rows
   contain no URL. Its pooled figures rest on a small denominator and should not be
   quoted alone.
5. **Not reproducible offline.** These numbers describe services at a moment. The runner,
   the endpoints, the commit and the timestamp are recorded in the artifact so the run can
   be repeated, but a reviewer without those hosts will get different numbers. That is why
   this is `eval/live-ab.json` and not `eval/metrics.json`.
6. **No external-corpus responses were recorded as replay fixtures.** Model responses quote
   their input, and these corpora are third-party data whose licences permit evaluation
   but not redistribution of derived text.

## Reproducing

```
ssh -N -L 18088:127.0.0.1:8088 -L 18089:127.0.0.1:8089 <integration-host>
export TENABLE_EMAIL_FRAUDFOX_URL=http://127.0.0.1:18088
export TENABLE_EMAIL_SECMODELS_URL=http://127.0.0.1:18089
python3 eval/fetch.py --rows                 # licence-gated, nothing committed
python3 eval/live_ab.py --tiers classifier,url_reputation,prompt_injection \
    --corpora synthetic,adversarial,external --concurrency 6 -o eval/live-ab.json
```

`eval/live_ab.py` deliberately writes nothing to `eval/metrics.json`. A committed artifact
has to be reproducible by a reviewer with no inference host; a live run describes a moment
and a set of machines. Keeping them separate is what lets both be true.
