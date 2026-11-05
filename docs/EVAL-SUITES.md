<!-- planned: eval/fetch.py eval/run.py eval/report.py eval/internal/ -->

# Public evaluation suites, their overlap, and where they catch outliers

Two published suites cover the model classes this project uses. Both are
machine-readable, both were retrieved and parsed 2026-11-02, and neither is
ours. All numbers below are taken from the suites' own result files, not
re-derived by us and not quoted from prose.

---

## Suite 1 - phishing / spam / smishing

Source: `Horizon-Labs/phishing-scam-detector-base`, files `eval/baselines.json`
(26,630 bytes, seven comparison models) and `eval/this_model.json` (3,693 bytes,
the author's own model). Scoring code published alongside at
`code/scam/eval_scam.py` and `code/scam/build_evals.py`. Apache-2.0.

Method, per the card: *"Every model is scored the same way: AUC of its 'unwanted'
probability (for this model `P(fraud) + P(spam)`), and F1 and false-positive rate
at 0.5."*

**26 datasets, 17,658 rows per model, 8 models, complete coverage** (verified: no
model has a missing dataset).

| Group | Datasets | Rows | Source | License |
|---|---|---:|---|---|
| English email | `enron_spam` | 995 | `SetFit/enron_spam` test | **not declared** |
| English email | `phish_email` | 964 | `zefang-liu/phishing-email-dataset` | **LGPL-3.0** |
| Real smishing | `smish_bn` | 1,401 | `shariul-islam/bengali-sms-smishing-dataset` | MIT |
| Real smishing | `smish_ko` | 997 | `jmjmjm3/kor-smishing-message` | **CC-BY-NC-SA-4.0** |
| Real smishing | `smish_pt` | 999 | `MOZNLP/MOZ-Smishing` | **CreativeML OpenRAIL-M** |
| SMS, 21 languages | `sms_*` | 583-589 each | `dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset` (UCI SMS Spam, machine-translated) | **GPL** |

Models scored: `ealvaradob/bert-finetuned-phishing` (110M),
`cybersectony/phishing-email-detection-distilbert_v2.4.1` (67M),
`ptouch/phishing-distilbert-cyber207` (67M), `mshenoda/roberta-spam` (125M),
`mrm8488/bert-tiny-finetuned-enron-spam-detection` (4M),
`mrm8488/bert-tiny-finetuned-sms-spam-detection` (4M),
`Horizon-Labs/phishing-scam-detector-base` (307M), and
`Qwen/Qwen3.8-27B` prompted as a teacher reference.

## Suite 2 - prompt injection

Source: `Horizon-Labs/prompt-injection-eval-suite`, 15 parquet configs,
`license: other` / `license_name: mixed-per-config`. Full table in
`docs/MODELS.md`. Row counts verified from the card: `notinject` 339 (zero
positives), `xstest` 450, `orbench_hard` 1,319, `deepset_test` 116,
`jackhhao_test` 262, `simsonsun_jailbreaks` 2,426, `boundary_pairs_test` 240,
`agentic5k_test` 545, `neuralchemy_test` 942, `slabs_test` 2,101, `bipia` 3,178,
`piarena` 1,500, plus `llmail_phase2`, `synthetic_direct_test`,
`synthetic_docs_test`, `synthetic_v2_test`.

Scored against nine detectors including PIGuard (184M), Meta Prompt Guard 2 at
86M and 22M, ProtectAI DeBERTa v2, deepset, Wolf Defender and NeuralTrust small.

A third, independent suite exists: `surajkjai/promptinj_model_evals` on GitHub -
11,085 samples across 11 public datasets, with attacks buried in longer benign
passages specifically to test signal dilution. Not retrieved; its figures are
quoted second-hand in `docs/MODELS.md` and **disagree with Suite 2 by an order of
magnitude about Meta Prompt-Guard-2-22M**, which is itself a finding.

---

## Overlap between the two suites

**Zero shared datasets.** They are complementary rather than redundant, and the
overlap is thematic rather than literal:

| Question | Suite 1 | Suite 2 |
|---|---|---|
| Is this message unwanted or malicious? | yes - `fraud`/`spam`/`legitimate` | no |
| Is this message trying to command an agent? | no | yes - `INJECTION`/`SAFE` |
| Email as an input type | `enron_spam`, `phish_email` | `bipia` (email/table/code contexts), `llmail_phase2` (real adaptive email attacks) |
| Non-English | 24 of 26 datasets | `synthetic_direct_test` covers 30 languages |
| Benign-with-trigger-words | not covered | `notinject` (339, zero positives), `xstest`, `orbench_hard` |

That split maps onto a distinction this project already encodes. A reported
message can be a credential phish **and** carry agent-directed instructions, and
the two questions have different answers: `threat_prompt_injection` is both,
while `clean_security_newsletter_discussing_injection` is neither malicious nor
safe to auto-clear. Suite 1 alone would call the newsletter legitimate; Suite 2
alone would call it an injection. **Running only one produces a wrong answer on
one of those two fixtures.** That is the argument for wiring both, and it is
testable rather than rhetorical.

Coverage gaps neither suite fills, which matter for us:

- **Authentication and header forensics.** Neither suite carries SPF/DKIM/DMARC
  results, Reply-To, Return-Path or List-* headers. Our deterministic layer's
  primary inputs are unrepresented in both.
- **Attachments.** No `.docm`, no PDF, no MIME structure at all. Both suites are
  text-only.
- **Anchor-text versus href mismatch.** Not representable without markup.
- **Forwarded-message unwrapping.** Not covered.
- **Business email compromise with valid authentication.** `llmail_phase2` is the
  closest, being real adaptive email attacks, but it targets agent instruction
  following rather than payment fraud.

So the public suites can validate our **model tiers** and cannot validate our
**deterministic layer**. That layer needs the synthetic corpus, which is why
`fixtures/generate.py` exists and why its fixtures are property-targeted rather
than randomly generated.

---

## Where the suites catch outliers

This is the substantive finding, computed from Suite 1's own result files.

### Mean AUC and FPR by group

| Model | English email AUC | email FPR | Real smishing AUC | smishing FPR | SMS 21-lang AUC |
|---|---:|---:|---:|---:|---:|
| `ealvaradob/bert-finetuned-phishing` | **1.000** | 0.002 | 0.797 | 0.672 | 0.967 |
| `cybersectony/...distilbert_v2.4.1` | **0.999** | 0.006 | 0.606 | 0.880 | 0.669 |
| `Qwen3.8-27B` (teacher, prompted) | 0.996 | 0.045 | **0.945** | 0.128 | 0.970 |
| `mshenoda/roberta-spam` | 0.996 | 0.036 | 0.803 | 0.332 | **0.975** |
| `ptouch/phishing-distilbert-cyber207` | 0.991 | 0.003 | 0.485 | 0.738 | 0.728 |
| `mrm8488/bert-tiny-...enron-spam` | 0.983 | 0.133 | 0.735 | **0.959** | 0.783 |
| `Horizon-Labs/phishing-scam-detector-base` | 0.978 | 0.094 | 0.925 | **0.110** | 0.951 |
| `mrm8488/bert-tiny-...sms-spam` | 0.450 | 0.619 | 0.834 | 0.541 | 0.966 |

### Rank inversion between the two groups

| Model | Email rank | Smishing rank | Inversion |
|---|---:|---:|---:|
| `cybersectony/...distilbert_v2.4.1` | **#2** | **#7** | -5 |
| `ealvaradob/bert-finetuned-phishing` | **#1** | **#5** | -4 |
| `ptouch/phishing-distilbert-cyber207` | #5 | #8 | -3 |
| `mshenoda/roberta-spam` | #4 | #4 | 0 |
| `mrm8488/bert-tiny-...enron-spam` | #6 | #6 | 0 |
| `Qwen3.8-27B` (teacher) | #3 | **#1** | +2 |
| `Horizon-Labs/phishing-scam-detector-base` | **#7** | **#2** | +5 |
| `mrm8488/bert-tiny-...sms-spam` | **#8** | #3 | +5 |

**English-email AUC is close to anti-informative about real-world ranking at the
top of the table.** Five of eight models score ≥0.98 AUC on English email; those
same five span 0.485 to 0.925 on real smishing. The model ranked #1 on email
(AUC **1.000**, FPR 0.002) falls to #5 on real smishing with a **0.672**
false-positive rate. The model ranked #2 on email (AUC 0.999) falls to #7 and
flags **88%** of benign messages. Meanwhile the two worst email performers are
#1-equivalent and #3 on smishing, and the model we are considering for the
three-way tier ranks **#7 of 8 on email and #2 of 8 on real smishing** — a fact
its own author published against itself.

### Worst-case false-positive rate anywhere in the suite

| Model | Worst FPR | On |
|---|---:|---|
| `cybersectony/...distilbert_v2.4.1` | **1.000** | `sms_hi` |
| `mrm8488/bert-tiny-...enron-spam` | **1.000** | `smish_ko` |
| `ptouch/phishing-distilbert-cyber207` | 0.986 | `sms_ur` |
| `ealvaradob/bert-finetuned-phishing` | 0.928 | `smish_pt` |
| `mshenoda/roberta-spam` | 0.882 | `sms_ar` |
| `mrm8488/bert-tiny-...sms-spam` | 0.828 | `smish_ko` |
| `Qwen3.8-27B` (teacher) | 0.378 | `sms_pa` |
| `Horizon-Labs/phishing-scam-detector-base` | **0.341** | `sms_pa` |

An FPR of 1.000 means the model flags every message in that set. Six of eight
models exceed 0.82 somewhere. Only the 27B teacher and the 307M student stay
under 0.40 everywhere — and the student is 88 times smaller.

### What Suite 2 adds that Suite 1 cannot see

From Suite 2's own table (parenthetical values are FPR on that set's benign
examples; `bipia` is 94% positive):

- `deepset` posts F1 0.971 on `bipia` and 0.992 on its own namesake dataset, but
  with **FPR 1.00** on both and accuracy 0.286 on `notinject`. It flags
  everything. Reading F1 without the FPR column selects a useless model.
- Meta `Prompt-Guard-2-22M` has the **best** benign accuracy in Suite 2 (0.994 on
  `notinject`) and the **worst** detection almost everywhere else: LLMail-Inject
  email recall 0.011, agentic-boundary F1 0.080, deepset F1 0.065. A model can be
  excellent at not over-firing and worthless at detecting.
- `Horizon-Labs/prompt-injection-guard-small` leads on agentic boundary pairs
  (F1 0.976) and real adaptive email attacks (recall 0.991) but scores **0.528 on
  `bipia`**, where PIGuard scores 0.963 at FPR 0.00. Two strong models disagree
  sharply on the same input type, and only a suite that contains both
  perspectives reveals it.

**The general lesson, which is the reason to run our own A/B:** a single
benchmark cannot rank these models, because each model's training distribution
determines which benchmark flatters it. Only a suite spanning in-domain,
out-of-domain, benign-with-trigger-words and adversarially-adaptive sets exposes
the inversions. Suite 1 does that for phishing; Suite 2 does it for injection.

---

## What Bundle E should include, and the license constraint

### Redistribution

Almost none of this data can be committed to an MIT repository:

| Dataset | License | Redistributable in our repo? |
|---|---|---|
| `jmjmjm3/kor-smishing-message` | **CC-BY-NC-SA-4.0** | **No** - non-commercial and share-alike |
| `MOZNLP/MOZ-Smishing` | **CreativeML OpenRAIL-M** | **No** - carries use restrictions |
| `zefang-liu/phishing-email-dataset` | **LGPL-3.0** | **No** - copyleft |
| `dbarbedillo/SMS_Spam_Multilingual...` | **GPL** | **No** - copyleft |
| `geodesic-research/bipia` | **CC-BY-SA-4.0** | **No** - share-alike |
| `SetFit/enron_spam` | **not declared** | **No** - undeclared means not granted |
| `shariul-islam/bengali-sms-smishing-dataset` | MIT | Yes, with attribution |
| `leolee99/NotInject`, `S-Labs/...`, `Simsonsun/JailbreakPrompts`, `sleeepeer/PIArena` | MIT | Yes, with attribution |
| `deepset/prompt-injections`, `jackhhao/...`, `neuralchemy/...` | Apache-2.0 | Yes, with attribution |
| `Paul/XSTest`, `bench-llm/or-bench`, `3nesdeniz/...` | CC-BY-4.0 | Yes, with attribution |

The result **files** (`eval/baselines.json`, `eval/this_model.json`) are the
authors' published measurements and are cited here as such; they are not the
datasets.

### Design consequence

Bundle E ships a **fetch-and-evaluate harness**, not a vendored corpus:

- `eval/fetch.py` downloads named public datasets at evaluation time into
  `eval/internal/` (gitignored), recording source, revision and license per set
- `eval/run.py` scores our tiers and any candidate model against them, emitting
  the same metrics both suites use: AUC, F1, **FPR at a stated threshold**, and
  recall at 1% FPR so results are comparable to `marklkelly`'s `eval/metrics.json`
- `eval/report.py` renders the coverage and inversion tables in the shape above
- Nothing downloaded is committed. We publish **our numbers** and cite the
  sources, which is exactly what both suites' authors did
- The synthetic corpus stays the only committed evaluation data, and remains the
  only permitted source for replay recordings

### Priority order for the A/B

1. `notinject` (339, zero positives) - cheapest and most decision-relevant. It is
   the newsletter false-positive question at scale, and every model above shows
   that over-defense is where small models fail.
2. `bipia` email-context subset (3,178) - our exact input type, and the set on
   which the two leading injection detectors disagree most.
3. Suite 1's `enron_spam` + `phish_email` (1,959 rows) - the phishing/spam tier,
   with the explicit caveat that these are the **flattering** sets.
4. Suite 1's `smish_bn` (1,401, MIT, redistributable) - the honest
   out-of-domain check, and the only smishing set we could legally ship.
5. `llmail_phase2` - real adaptive email attacks, if obtainable.
6. `boundary_pairs_test` (240) - small, CC-BY-4.0, isolates agent/human boundary
   understanding from keyword matching.

Reporting both a flattering and an honest set for each tier is the point. A table
with only in-domain numbers is how a 0.959 false-positive rate gets circulated as
a 0.959 recall.

---

## Corrections from the later research passes (2026-11-03)

Two independent deep-research passes were run against the corpora question. They
corrected one thing this file says and left one thing unresolved. Neither was
re-checked at source here: this session has no network access, so the markers
below say exactly how far removed each statement is.

**Provenance markers used in this section.**
**[V]** - retrieved and parsed by an earlier session of this project, from the
primary artifact, the date and file recorded in this document.
**[R]** - reported by a research pass. One step removed from the source. Not
re-verified here, and **not to be quoted as if it were**.

### 1. "Bundles 26 datasets" - not verified, and probably a category error

**What was claimed [R]:** that `Horizon-Labs/phishing-scam-detector-base`
*bundles 26 datasets*, read as 26 ground-truth corpora sitting inside the model
repo and therefore available to us for evaluation.

**What the same pass reported about the model card [R]:** a 307M model trained
mostly on **98,379 synthetic messages plus 59,403 web snippets**, with three
labels, evaluated against several public sets.

**The correction, and it matters for scoping:** a **synthetic training set is not
a ground-truth evaluation corpus**. The training data was generated for the
model; nobody labelled it independently of the thing being measured. Even if the
counts are right, 26 datasets of *training* material buys us no evaluation
coverage, and Bundle N must not count them as available corpora.

**What is NOT being retracted.** The row above this section, in Suite 1, says
**"26 datasets, 17,658 rows per model, 8 models, complete coverage"**, marked
verified 2026-11-02 [V]. That claim is about the **published result files**
`eval/baselines.json` and `eval/this_model.json` - per-dataset scores the authors
measured - and it is internally consistent with this file's own tables: 2 English
email sets, 3 real-smishing sets and 21 machine-translated SMS languages, which is
where "24 of 26 datasets are non-English" comes from. The unverified claim is that
those datasets are *bundled with the model* and *are ground truth we can score
against*.

**Unresolved, and it needs a decision before anyone relies on either number.**
The [V] figure and the [R] description are not the same assertion, but they are
one click from contradicting each other in a reader's mind. Settling it is cheap
and mechanical: re-fetch `eval/baselines.json` and count the dataset keys, then
record here whether those 26 sets are the authors' *evaluation* rows (in which
case the per-dataset scores in this file stand) or are drawn from the synthetic
*training* pool (in which case every comparison in Suite 1 is measuring a model
against its own generated data, and this file's numbers mean something much
narrower than they currently read as). Until then treat the 26 as **evaluation
rows of unknown provenance, not as corpora we can fetch**.

### 2. MiniCPM5-1B's architecture - the two passes disagree, no side is taken

**Claim A [R]:** standard `LlamaForCausalLM`, no custom kernels, official GGUF
support.
**Claim B [R]:** a custom hybrid attention needing custom ONNX operators.

These are not variants of one story; they imply different work. Under A the model
is a drop-in for the llama.cpp path this project already runs. Under B it needs an
operator set nobody has built, which is not a config change but a blocker. That
makes it **the single most decision-relevant fact about adopting it**, and the two
passes cannot both be right.

**Recorded as unresolved deliberately.** Picking the convenient side is worse than
recording the disagreement: an architecture guess that turns out to need custom
ONNX operators wastes a session, and one that turns out to be a stock Llama
invites a claim of compatibility nobody tested. The check is one fetch - the
model card's architecture section and its file list, plus whether a GGUF exists
under the author's own organization rather than a third-party conversion - and it
belongs in `docs/MODELS.md`, which is where the model candidates are kept.
Nothing in this section should be read as having settled it.

---

## What Bundle N phase 1 ran, and what the licences said (2026-11-03)

Everything in this section is **[V] at source**: the licence values were read today
from the Hugging Face API, the row counts were computed from the fetched bytes, and the
dispositions come from `eval/run.py --external` on this host.

### The gate, as built

`eval/fetch.py` carries a closed allowlist. A dataset is fetchable only if it appears
there with the licence value observed in `cardData.license` and the date it was read,
and the declaration is re-read at fetch time and compared - a licence that moved
upstream is a permission that moved, and the tool refuses rather than absorbing it.
Observed today, at the revisions the fetch pinned:

| Dataset | `cardData.license` | Also observed | Gate |
|---|---|---|---|
| `microsoft/llmail-inject-challenge` | mit | - | permitted |
| `leolee99/NotInject` | mit | - | permitted |
| `deepset/prompt-injections` | apache-2.0 | datasets-server conversion reports **cc-by-4.0** | permitted, disagreement recorded in the manifest |
| `jackhhao/jailbreak-classification` | apache-2.0 | - | permitted |
| `shariul-islam/bengali-sms-smishing-dataset` | mit | - | permitted |
| `SetFit/enron_spam` | **None** | - | **refused** - undeclared is not granted |
| `zefang-liu/phishing-email-dataset` | lgpl-3.0 | - | refused - copyleft against an MIT submission |
| `geodesic-research/bipia` | cc-by-sa-4.0 | - | refused by default; `--allow-sharealike` prints the obligation it is accepting, because accepting it is the submission owner's decision and not the tool's |

The refused row that matters is the first one. `SetFit/enron_spam` is the most
convenient benign English-email corpus in this survey - it is in Suite 1 above, and
every comparison table in this file has used it - and it declares no licence at all,
so phase 1 ran without it. Nothing was substituted for it, which is the decision this
gate exists to make.

**A correction to this file's own table.** The redistribution table above lists
`deepset/prompt-injections` under Apache-2.0. That is what `cardData.license` says and
what the gate acted on, but the datasets-server conversion metadata for the same
dataset reports cc-by-4.0. The two fields disagree upstream. Phase 1 recorded both
values in the fetch manifest under the gitignored eval/internal/ directory and printed
the disagreement in the rendered report rather than picking the convenient one, and said
the corpus was fetched and pinned but not evaluated - so no number depended on which was
right. **Phase 1b corrected that state, and it did not correct the licence question.**
The corpus is now measured: 662 rows, 263 labelled injections and 399 labelled
not-injections, reported on the two sides with their own denominators. That makes the
disagreement matter rather than sit harmlessly, for one specific reason - the rows were
read from the conversion service, and it is the conversion service's own metadata that
declares cc-by-4.0. The gate acts on the card, which is the declaration the upstream
author made in the repository; nothing here resolves which is operative, the disagreement
is printed beside every deepset figure in `eval/metrics.json` and in the rendered report,
and a human has to settle it before anything derived from these rows is redistributed.

### What was measured, and what the numbers can and cannot show

The corpora are text. Each row was wrapped in a minimal synthesized `.eml` - headers
present: From, To, Date, Message-ID, MIME-Version, Content-Type,
Content-Transfer-Encoding; absent by construction: Authentication-Results,
DKIM-Signature, ARC headers, Return-Path, Reply-To, List-\* - so **the authentication
layer, which settles most of the committed corpus, cannot fire at all here**. Every
external figure therefore describes the text and injection surfaces only, and the
envelope is recorded per corpus in `eval/metrics.json` and reprinted by `eval/report.py`
next to the numbers it enabled.

Phase 1b raised the sampling cap from 500 to 1,500 (`eval/external.py`'s
`DEFAULT_MAX_MESSAGES`) so that **every corpus in this table is measured whole**. The
keyed rule is unchanged and no phase-1 number moved with it: the rule keeps every row
whenever the cap is at or above the population, and phase 1's largest corpus was 259
rows. It exists now for the sets still to come (BIPIA, LLMail's labelled submissions,
the Bengali train split at 4,903 rows).

| Corpus | Rows measured | Text-surface flags | Accused (threat/spam) | Deferred | Cleared |
|---|---:|---:|---:|---:|---:|
| LLMail false-positive file, benign business emails | 203 of 203 | 0 (0.0%) | **0 (0.0%)** | 203 (100.0%) | 0 |
| jailbreak-classification test split, benign half | 259 of 259 | 1 (0.4%) | 0 (0.0%) | 259 (100.0%) | 0 |
| jailbreak-classification test split, jailbreak half | 141 of 141 | **13 (9.2%)** | 0 | 141 (100.0%) | **0** |
| NotInject, three splits, benign prompts with injection trigger words | 339 of 339 | **0 (0.0%)** | 0 | 339 (100.0%) | 0 |
| deepset train + test, rows labelled injection | 263 of 263 | **3 (1.1%)** | 0 | 263 (100.0%) | 0 |
| deepset train + test, rows labelled not-injection | 399 of 399 | 0 (0.0%) | 0 | 399 (100.0%) | 0 |
| Bengali smishing test split, `smish` | 561 of 561 | **0 (0.0%)** | 0 | 561 (100.0%) | 0 |
| Bengali smishing test split, `normal` + `promo` | 840 of 840 | 0 (0.0%) | 0 | 840 (100.0%) | 0 |

**3,005 external messages, 0 cleared, 0 accused, 3,005 deferred, 0 model judgments.**
The three disposition columns are therefore **non-discriminating for every one of those
corpora**, and this file says so in the same words the report does: with no
authentication signal in the wrapper nothing *can* clear, so a 0.0% false-positive rate
and a 0.0% clearance rate are one absence described twice, not two results. A pipeline
that accused nothing over a corpus it also cleared nothing has been shown neither to
over-fire nor to hold. What separates the corpora is the **text-surface** column: rows
whose text matches the deterministic injection scanner, each over its own denominator.

Read that column in pairs, never alone. **0 of 339** on NotInject is the over-defense
answer this file asked for - the set exists precisely because it is where a small
detector was expected to cry wolf - and the same scanner found only **3 of 263** rows
deepset labels as injections, **13 of 141** labelled jailbreak prompts, and **0 of 561**
Bengali smishing messages. Low over-flagging next to low detection is a
*narrow* scanner, not a good one; the honest reading of this table is that the
deterministic text surface corroborates and rarely fires, on every corpus tried. The
mirror numbers also hold at the disposition level: of 141 messages labelled hostile,
**0 were cleared**, and all 141 went to a person.

The second thing this table cannot show is the model tier. `corpus-backed` emitted **0
model judgments across all 3,005 external messages** and is identical to
`deterministic-only`, because the committed recordings are keyed by content address and
no recording exists for text that was never sent to an endpoint. A miss is a miss.
**The A/B against real model weights - the reason this file argues for running two
suites - has still not been run.** `eval/metrics.json` and the rendered report both
carry that sentence in a required block (`external.model_tier`), and
`tests/test_external_rows.py` fails if it is dropped or softened.

### How the Parquet-only corpora were read, and what that costs

Phase 1 listed three datasets as fetched, pinned and **not evaluated**, because their
text sits behind dictionary-encoded pages in a snappy stream and `dependencies = []`
rules out borrowing a column decoder:

| Dataset | Rows pinned | Licence |
|---|---:|---|
| `leolee99/NotInject` (3 files) | 339 | mit |
| `deepset/prompt-injections` | 546 / 116 | apache-2.0 (card) / cc-by-4.0 (conversion) |
| `shariul-islam/bengali-sms-smishing-dataset` test split | 1,401 | mit |

Phase 1b did not write a Parquet decoder. It read the rows from the **datasets-server
ROWS API** - `splits` first, then `rows` paginated at 100 per request - which answers in
JSON over plain HTTP. Stdlib `json` is the whole dependency, and the same licence gate
applies: the rows path re-reads `cardData.license`, refuses a declaration that moved,
and refuses a gated or private repository before any request.

**What that road costs, stated plainly.** The service does not serve the repository
file. It serves the dataset's own *converted* Parquet, produced by Hugging Face's
converter: different bytes, a different length, and no relationship to the pinned sha256
beyond describing the same rows. So the artifact holds both objects, and says which one
the text came from, per corpus:

| Recorded object | What it is | What it proves |
|---|---|---|
| repository file: revision-pinned download URL, byte size, sha256, footer `num_rows` | the artifact the licence and the digest describe | that this revision contains a file of this size with these bytes, and that its footer says how many rows it holds |
| row retrieval: `api_url_template`, split name, `num_rows_total`, page list with every requested URL, retrieved count, cache path + sha256, `retrieved_at`, truncated-cell count | the bytes the text was measured from | that the retrieval was complete, that it is the cached bytes that were measured, and that it agrees with the pinned file on the split's row count |

The only legitimate comparison between the two is **the split name and the row count**,
and both are checked: every one of the six splits' `num_rows_total` equals the count read
out of the pinned file's own Parquet footer by the Thrift-compact skimmer (339 = 113 × 3,
546, 116, 1,401), no row came back with a truncated cell, and each LFS-stored file's
sha256 still matches the object id the repository records for it at the pinned revision.
**What is not claimed is that the measured text was hash-verified against the repository
file.** It was verified against the retrieval, whose digest is recorded beside it, and
`fetch.ROWS_CONVERSION_NOTE` - reproduced in `eval/PROVENANCE.json`, in the manifest and
in every corpus descriptor - says so in those words. A split whose name or row count
disagrees stops the measurement rather than picking the convenient object, and a corpus
whose rows were never retrieved is listed in `unavailable` with the command that would
fetch it, never measured as zero rows.

Split names are read from the `splits` endpoint and not guessed: NotInject's are
`NotInject_one`/`_two`/`_three`, not `train`/`validation`/`test`. The Bengali
`validation` split and LLMail's 68.6 MB labelled submissions remain unfetched, by file
scope rather than by format, and the licence gate is unchanged: `SetFit/enron_spam`
(licence observed `None`), `zefang-liu/phishing-email-dataset` (lgpl-3.0) and
`geodesic-research/bipia` (cc-by-sa-4.0, behind `--allow-sharealike`) are still refused.

**Phase 2's blocking piece of work is therefore no longer a decoder.** It is N8: run the
model tiers over these same 3,005 wrapped messages, record FPR at a stated threshold, and
give the deterministic numbers above the baseline they were supposed to be compared to.
