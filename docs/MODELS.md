# Classifier model research - verified

All Hugging Face metadata retrieved via `https://huggingface.co/api/models/<id>`
and raw README files, 2026-11-02. Nothing here is taken from a secondary
summary without verification.

---

## Correction to third-party research

A set of spam-classifier recommendations was circulated naming five models. Four
exist; one name was misspelled; and one model's benchmark numbers were
**mis-transcribed in a way that inverts the conclusion**.

### The mis-transcription

Circulated claim for `mrm8488/bert-tiny-finetuned-enron-spam-detection`:
*"ROC-AUC: 0.983, Recall: 0.959, False-positive rate: 0.265."*

Actual row from the comparison table in
`onnx-community/phishing-scam-detector-base-ONNX` README (line 147), transcribed
verbatim [V]:

| model | licence | smishing AUC (3 lang) | F1 @0.5 | **FPR @0.5** | phishing+spam email AUC (EN) | SMS spam AUC (EN) | SMS spam AUC (21 lang) | note |
|---|---|---|---|---|---|---|---|---|
| mrm8488/bert-tiny-finetuned-**enron**-spam-detection (4M) | Apache-2.0 | 0.735 | 0.709 | **0.959** | 0.983 | 0.735 | 0.785 | trained on Enron spam (in-domain) |

- **0.959 is the false-positive rate, not recall.**
- **0.265 does not appear anywhere in that document.**
- 0.983 is the English phishing-and-spam email AUC, not a general ROC-AUC.

At its default threshold this model flags **95.9% of normal messages as
unwanted**. It is unusable as a spam classifier. The circulated assessment said
*"that false-positive rate is concerning"* while describing a different,
much better number than the real one.

Converting this model to ONNX - the recommended next step in that research -
would be well-executed work toward a model that cannot be used. **Rejected.**

### Same trap in the earlier architecture proposal

From the same table [V]: `cybersectony/phishing-email-detection-distilbert_v2.4.1`
(67M, Apache-2.0), previously recommended as a second phishing classifier,
scores **smishing AUC 0.606 and FPR 0.880**. Also rejected.

Other rows from the same table, all [V]:

| model | params | licence | smishing AUC | F1 @0.5 | FPR @0.5 | email AUC |
|---|---|---|---|---|---|---|
| **Horizon-Labs phishing-scam-detector-base** | 307M | Apache-2.0 | **0.925** | 0.768 | **0.110** | 0.978 |
| `mshenoda/roberta-spam` | 125M | MIT | 0.803 | **0.823** | 0.332 | 0.996 |
| `ealvaradob/bert-finetuned-phishing` | 110M | Apache-2.0 | 0.797 | 0.763 | 0.672 | 1.000 |
| `ptouch/phishing-distilbert-cyber207` | 67M | none given | 0.485 | 0.664 | 0.738 | 0.991 |
| `mrm8488/bert-tiny-finetuned-sms-spam-detection` | 4M | none given | 0.834 | 0.779 | 0.541 | 0.450 |
| `Qwen/Qwen3.8-27B` (teacher, prompted) | 27B | Apache-2.0 | 0.945 | 0.878 | 0.128 | 0.996 |

Note how misleading an in-domain email AUC of 1.000 is when the same model has a
0.672 false-positive rate on real smishing. **Always read the FPR column.**

---

## The find: Horizon-Labs/phishing-scam-detector-base

ONNX conversion published as `onnx-community/phishing-scam-detector-base-ONNX`,
last modified **2026-10-10**, Apache-2.0, 209 downloads, 0 likes.

[V] from its README:

- **307M parameters**, built on `jhu-clsp/mmBERT-base`, Apache-2.0
- **Three labels: `fraud`, `spam`, `legitimate`** - this is the reference
  playbook's `threat`/`spam`/`clean` taxonomy exactly. One model supplies the
  three-way verdict that four Enron binaries cannot.
- **Multilingual** - 40+ languages declared
- Trained for *"emails, SMS, chat and social-media messages"*
- Label semantics: `fraud` covers phishing (fake bank/delivery/account/tax with
  links), scams (prizes, investment and crypto, fake jobs, "hi mum new number",
  romance, advance fee), requests for passwords/OTC/payment details, malware
  lures. `spam` is *"unwanted advertising and bulk marketing that is not trying
  to steal anything."* `legitimate` is everything else **including genuine
  notifications that look similar** - real one-time codes, delivery updates,
  bank alerts.
- Scoring guidance: `P(fraud) + P(spam)` for "unwanted", or `P(fraud)` alone if
  marketing is acceptable. Default threshold 0.5, raise to cut false positives.
- Files: `onnx/model.onnx`, `model_quantized.onnx` (int8, **641 MB**),
  `model_int8.onnx`, `model_uint8.onnx`, `model_fp16.onnx`, `model_q4.onnx`,
  `model_q4f16.onnx`, `model_bnb4.onnx`
- [C] `model_quantized.onnx` gives the same top label as fp32 for **99.8% of 520
  benchmark texts** - author's claim, not reproduced
- Its own per-set numbers [V from card]: phishing vs safe emails (EN) AUC 0.978,
  F1 0.916, FPR 0.112, recall 0.943. Enron spam vs ham AUC 0.978, F1 0.934,
  FPR 0.076, recall 0.944. UCI SMS spam AUC 0.978, F1 0.900, FPR 0.063, recall
  0.872. Bengali/Banglish/English SMS AUC 0.979, F1 0.946, FPR 0.112, recall
  0.952. Korean SMS AUC 0.957. Mozambican Portuguese SMS+Facebook AUC 0.840,
  F1 0.450, recall **0.319** - hardest set, misses most messages.
- Two training seeds: real-smishing AUC 0.916 / 0.925, FPR 0.122 / 0.110
- Documented limitation: ~11% of normal messages false-positive on the smishing
  sets at 0.5, especially genuine notifications
- Sibling model `Horizon-Labs/prompt-injection-guard-base` - relevant to the
  missing injection guard in the current engine

### Why this matters beyond being a good spam model

Its teacher was **`Qwen/Qwen3.8-27B`, prompted**: smishing AUC 0.945, F1 0.878,
FPR 0.128. The 307M student reaches AUC 0.925 - within about 2% - at roughly
**1/88th the parameters**, with a **better** false-positive rate (0.110 vs
0.128).

That is the right-sizing thesis measured and published by an unaffiliated third
party, three weeks ago, on this exact task class. It can be cited rather than
argued.

### Caveats

209 downloads and 0 likes - three weeks old, unproven in the wild. Its numbers
are on public test sets, not on our mail. 307M int8 is 641 MB, which is 4.6x
FraudFoxAI's parameter count and must be benchmarked against ~7 GB available RAM
on utility with `fraudfoxai` already resident at ~1.1 GB RSS. **Not downloaded,
not run, not benchmarked. Nothing about its latency or memory on our hardware is
known.**

---

## The other four candidates

### mrm8488/bert-tiny-finetuned-enron-spam-detection

[V] Exists. Apache-2.0. Base `google/bert_uncased_L-2_H-128_A-2` (BERT-Tiny,
2 layers, 128 hidden). Trained on `SetFit/enron_spam`. Last modified
**2023-03-17**. 13,850 downloads, 9 likes. Files include `model.safetensors`,
`pytorch_model.bin`, `tokenizer.json`, `vocab.txt` - **no ONNX**, conversion
would be required.

Card's own evaluation numbers, verified accurate: Loss 0.0593, Precision 0.9851,
Recall 0.9871, Accuracy 0.986, F1 0.9861. The card is auto-generated boilerplate
with "More information needed" under Model description, Intended uses and
limitations, and Training data.

**Rejected.** FPR 0.959 out of domain. Enron is 1998-2002 corporate mail; it
contains no modern SEO spam, no crypto scams, no shared-document abuse, no QR
codes.

### prancyFox/tiny-bert-enron-spam

The circulated name `pranceFox/...` returns **HTTP 401/404 and does not exist**
[V]; the user page `huggingface.co/pranceFox` is 404. The real repository is
**`prancyFox/tiny-bert-enron-spam`** - a spelling error, not a fabrication.

[V] Exists. MIT. Base `huawei-noah/TinyBERT_General_4L_312D` (4 layers, 312
hidden). 107 downloads. Its `model-index` on an Enron-derived CSV test split:
F1 macro **0.7666**, ROC-AUC 0.9977, **Precision(spam) 0.9954**,
**Recall(spam) 0.5632**, Precision(ham) 0.6875, Recall(ham) 0.9973. Card states
it is *"optimized for low false positives by default"* - i.e. the recall figure
is a deliberate operating point, and the threshold is adjustable.

**Rejected for the same Enron reason**, and it misses 44% of spam at the shipped
threshold. Worth remembering only as an example of a precision-optimized
operating point.

### navodPeiris/minilm-toxic-spam-classifier

[V] Exists. Apache-2.0. Has `onnx/model.onnx` - ready-made, no conversion. Base
`nreimers/MiniLMv2-L6-H384-distilled-from-BERT-Large` (~22M, consistent with the
circulated figure). Last modified 2026-03-16. 376 downloads, 2 likes.

Training datasets: `thesofakillers/jigsaw-toxic-comment-classification-challenge`,
`google/civil_comments`, `AbdulHadi806/mail_spam_ham_dataset`,
`SetFit/enron_spam`. **Two of four are comment-toxicity datasets, not email.**
This is substantially a toxicity classifier carrying a spam label. Classes are
`safe`/`toxic`/`spam`, which does not match the reference taxonomy - there is no
fraud/phishing class.

**Rejected.** Domain mismatch and wrong label space. The circulated assessment
called it the "best ready-made ONNX alternative," which overstates it.

### cryptofyre-ai/roberta-spam-onnx

[V] Exists. MIT. Has `model.onnx`. Quantized distillation of
`mshenoda/roberta-spam`. Last modified 2025-08-16. **10 downloads, 1 like.**

Its parent scores F1 0.823 (best F1 in the table) but **FPR 0.332** on real
smishing. The quantized derivative carries no evaluation of its own.

**Not adopted.** Unvalidated derivative of a model with a 33% false-positive
rate.

---

## Adopted design for the `spam` class

1. **`Horizon-Labs/phishing-scam-detector-base` int8 ONNX** as the three-way
   `fraud` / `spam` / `legitimate` classifier. Pending benchmark - see the
   blocking question below.
2. **Keep FraudFoxAI** (67M, ~38 ms) as the fast phishing tier and as an
   independent signal. Disagreement between it and the three-way model is an
   escalation trigger, not an averaged score.
3. **Deterministic bulk-mail header signals** for high-precision spam:
   `List-Unsubscribe` and `List-Unsubscribe-Post` (RFC 8058 one-click),
   `List-Id` / `List-Post` / `List-Subscribe` (RFC 2369), `Precedence: bulk`,
   `Auto-Submitted`, known marketing senders. In a **user-reported** queue most
   "spam" is legitimate marketing that someone over-reported, and header signals
   resolve that at near-zero false-positive cost where every statistical model
   above leaks.
4. **`Horizon-Labs/prompt-injection-guard-base`** to close the untrusted-content
   gap, alongside `secmodels POST /prompt-injection` (Cyber-Jev, which measured
   3/4 on its injection set - a signal, not a guarantee).
5. **QR codes are decoded deterministically** with `zbarimg` / `pyzbar`, never
   handed to the VLM. Small VLMs are unreliable on dense binary patterns and
   quishing is a top vector. This is a place the design exceeds the reference,
   which relies on Claude's vision for everything.

No Enron-trained model is adopted.

## Blocking question

Adopting item 1 requires downloading ~641 MB and running it on utility: 8 vCPU,
~7 GB available RAM, `fraudfoxai` already resident at ~1.1 GB RSS,
`secmodels.service` capped at `MemoryMax=1.5G`. Latency and RSS are unknown and
must be measured before any adoption claim.

A benchmark in an isolated `/tmp` virtualenv touches no service and no config,
but it does consume CPU and memory on a shared production host. **Operator
approval requested before running it.** Installing the result into `secmodels`
afterward is a separate decision.

---

# Prompt-injection detectors - verified 2026-11-02

## The distinction that changes the design

This is **not** primarily about protecting our own adjudication stage from being
steered. It is about classifying a threat **present in the reported message** and
telling the analyst about it.

An email carrying instructions aimed at an AI agent is attacking the *recipient's*
mail-reading agent - Copilot, Gemini for Workspace, a SOC chatbot that ingests
mail - not us. That is a distinct threat class and a university SOC wants to know
it is circulating.

Two consequences follow, and the second is a trap:

1. Output moves from an internal gate to a **reported finding**: an entry in
   `reasons[]`, an `attack_type` value, a line in the `analysis` narrative, and a
   contributor to the `THREAT` disposition under the same asymmetric
   false-negative penalty.
2. **Security newsletters that discuss prompt injection must not be flagged.**
   Horizon-Labs' own README lists as non-injection: documents that contain
   instructions for *humans* ("ignore my previous email"), or that *discuss*
   prompt injection. A university SOC subscribes to exactly those newsletters.

Point 2 breaks our current deterministic scanner. `detect_injection_surface` in
`src/tenable_email/signals.py` matches patterns like
`ignore (all )?previous instructions`, which fires on an article *quoting* that
phrase. Under the defensive framing that was harmless - an extra fence. Under the
classification framing it produces a wrong `THREAT` verdict on legitimate mail.

So the reframing requires distinguishing **"contains an instruction aimed at an
agent"** from **"quotes an instruction while discussing it."** A regex cannot do
that reliably. Either a model tier supplies it, or deterministic-only hits are
capped at low confidence and require corroboration. Both are cheap; picking
neither is not an option.

Note one advantage we already have: the deterministic scanner runs over the full
body, and `Horizon-Labs/prompt-injection-guard-small` takes 8k tokens, so neither
has the 128-token mid-document blind spot that the tiny BERT detector has.

## Verified candidates

All metadata retrieved from the Hugging Face API and raw model files 2026-11-02.

| Model | Params | License | Official ONNX | Downloads | Verdict |
|---|---|---|---|---|---|
| `marklkelly/bert-tiny-injection-detector` | 4.39M | Apache-2.0 | yes, `onnx/opset11/model.int8.onnx` + fp32 | 876 | usable, 128-token limit |
| `Horizon-Labs/prompt-injection-guard-small` | 141M | Apache-2.0, ungated | yes, quantized + `SHA256SUMS` + `quantization_check.json` | 3,287 | **recommended** |
| `Horizon-Labs/prompt-injection-guard-base` | 308M | Apache-2.0 | yes, quantized | 4,236 | larger reference |
| `leolee99/PIGuard` | 184M | MIT | **none** - four third-party mirrors at 0-18 downloads | 25,894 | strong numbers, no supported artifact |
| `bastionsoft/binary-bastion-prompt-protection-deberta-v3-xsmall-v1` | ~70M | **AGPL-3.0** | yes, quantized | 153 | **excluded, license** |
| `meta-llama/Prompt-Guard-2-22M` | 22M | **gated** (API returns 401) | n/a | n/a | **excluded** |
| `ersincivi/mmbert-tiny-inject` | 4.4M | GitHub only, **not an HF model** (404); weights not distributed | no | n/a | **cannot be used** |

### Hard exclusions

**Bastion is AGPL-3.0.** CONTRIBUTING.md recommends MIT and says *"GPL v3 and
other restrictive licenses may be considered in exceptional cases."* AGPL is
stricter than GPL for anything served over a network. Bundling an AGPL model into
an MIT-licensed Exchange submission is a license-compatibility problem, not a
matter for consideration. Excluded regardless of its reported numbers.

**Meta Prompt-Guard-2-22M is gated** - the API returns 401, so it requires
accepting Meta's license before download. It is also near-useless on the
email-relevant sets: LLMail-Inject recall **0.011**, agentic-boundary F1
**0.080**, deepset F1 0.065. Its only strength is benign-accuracy (0.994 on
NotInject). The community benchmark circulated for this model reported F1 76.1%
and recall 62.7%; Horizon-Labs' table reports numbers an order of magnitude
worse on every set except benign-accuracy. Neither source is neutral, and the
discrepancy is large enough that the model should not be selected on published
numbers at all.

**`ersincivi/mmbert-tiny-inject` cannot be used** - it is a GitHub repository,
not a Hugging Face model, and the trained weights are not distributed. The
circulated research flagged this correctly.

## marklkelly/bert-tiny-injection-detector - numbers verified exactly

Unlike the spam-classifier research, **these figures check out**. From the model's
own `eval/metrics.json` [V]:

```
dataset: split=validation, examples=20027, positive_rate=0.4944
overall: pr_auc=0.993, auc_roc=0.99
at_T_block:  threshold=0.9403, precision=0.9894, recall=0.9563, f1=0.9726, fpr=0.01
at_T_review: threshold=0.8692, precision=0.9797, recall=0.9687, f1=0.9742, fpr=0.0197
estimated_at_2pct_prevalence:
  at_T_block:  estimated_ppv=0.6618, estimated_f1=0.7822
  at_T_review: estimated_ppv=0.5015, estimated_f1=0.6608
```

The card is honest about its own weakness: the validation set is **49.44%
attacks**, and at a realistic 2% prevalence positive predictive value falls to
**0.662** (block threshold) or **0.502** (review threshold). It also ships
`deployment/fastly/calibrated_thresholds.json`. There is no separate test set
beyond the held-out validation split.

Limitations that matter for us: **128 tokens maximum**, with a truncation scheme
keeping roughly the first and last 63 content tokens. An instruction planted in
the middle of a long message is missed. Overlapping windows fix that but add
latency and require recalibrating document-level thresholds.

## The email-relevant benchmark, from Horizon-Labs' own card

All numbers computed by Horizon-Labs with one script at threshold 0.5, long
inputs scored with a sliding window (512 tokens for DeBERTa baselines). Their
words: *"Sets marked `*` are held out from our own synthetic generator (same
generator as the training data, so they flatter our model and are shown for
completeness only). Our training data was deduplicated against every eval set."*
**Parenthetical values are the false-positive rate on that set's benign
examples.** BIPIA is 94% positive.

| Eval set | Horizon small | base 308M | PIGuard | deepset | PG2-86M | PG2-22M |
|---|---|---|---|---|---|---|
| **BIPIA** (email/table/code/QA), F1 | 0.528 (0.04) | 0.628 (0.02) | **0.963 (0.00)** | 0.971 (**1.00**) | 0.020 | 0.007 |
| **LLMail-Inject ph2** (real adaptive email attacks), recall | **0.991** | 0.998 | 0.528 | 1.000 | 0.210 | 0.011 |
| **PIArena** (RAG/QA with injected tasks), F1 | 0.937 (0.00) | **0.969** | 0.713 | 0.672 (0.98) | 0.150 | 0.003 |
| NotInject (benign with trigger words), accuracy | 0.962 | 0.944 | 0.885 | 0.286 | 0.953 | **0.994** |
| Agentic boundary pairs (minimal pairs), F1 | **0.976 (0.05)** | 0.971 | 0.650 (0.54) | 0.667 (1.00) | 0.438 | 0.080 |
| Held-out synthetic docs, 45 types, 30 langs \*, F1 | 0.994 | 0.996 | 0.591 | 0.498 | 0.577 | 0.233 |
| Mindgard evaded samples (20 perturbation attacks), recall | 0.768 | 0.799 | 0.462 | 0.921 | 0.249 | 0.072 |

Readings that change the decision:

- **deepset's headline F1 scores come with a false-positive rate of 1.00.** It
  flags everything, and scores 0.286 on NotInject. A naive reading of "F1 0.992
  on prompt-injections" would have selected a useless model. That 0.992 is also
  on deepset's own dataset.
- **For email specifically, PIGuard and Horizon-small disagree sharply.** PIGuard
  wins BIPIA email contexts 0.963 vs 0.528, both at near-zero FPR. Horizon wins
  LLMail-Inject real adaptive email attacks 0.991 vs 0.528. BIPIA is synthetic
  email contexts; LLMail is real adaptive attacks. Which matters more depends on
  the threat model, and for a reported-phish queue it is genuinely ambiguous.
- **Horizon publishes its own weak BIPIA number next to a competitor's strong
  one.** That is a credibility marker, and the reason its card is the most useful
  single source here.
- PIGuard's numbers are strong but there is **no official ONNX artifact**, and
  the four third-party mirrors have 0-18 downloads. For a CPU ONNX stack that is
  a real obstacle, not a detail.

## Recommendation

**Add at most one injection tier, config-gated, defaulting to UNAVAILABLE.** Do
not benchmark three models during a 48-hour build-off.

If one is added, use **`Horizon-Labs/prompt-injection-guard-small`**:
Apache-2.0, ungated, official quantized ONNX with `SHA256SUMS` and a
quantization check, full training and evaluation code published, 8k-token
context (no 128-token blind spot), actively maintained (modified 2026-10-31),
best-in-table agentic-boundary F1 at 0.976, and 0.991 recall on real adaptive
email attacks. Its weak BIPIA score is published by its own author and is the
main argument for keeping PIGuard in mind later.

Record its BIPIA weakness in the README's known-limitations section rather than
discovering it in review.

**Not before the freeze.** The deterministic scanner already ships and is tested;
Bundle B wires it into the verdict as a reason and an `attack_type`, capped at
low confidence unless corroborated, with a fixture asserting that a security
newsletter discussing injection is **not** classified as a threat. The model tier
is a Bundle C or post-contest addition behind the same interface as every other
tier.

---

# Correction: download counts are not a criterion

An earlier version of this file used Hugging Face download counts and like counts
as negative signals - "209 downloads, 0 likes, three weeks old, unproven in the
wild", and "four third-party mirrors with 0-18 downloads". **That was wrong
reasoning and is retracted.**

Download counts measure popularity, not quality. A model published three weeks
ago with verified numbers and an official checksummed artifact is a better choice
than a popular model whose numbers do not survive contact with an independent
test set. Judging by downloads would have favoured exactly the Enron-trained
models this file rejects on measured false-positive rates.

Two distinct concerns were conflated and need separating:

1. **Low download count, on its own - not a signal.** Dropped as a criterion.
2. **An unofficial third-party artifact with no checksums, no quantization check
   and no guarantee the tokenizer is correctly paired - a real risk.** But that
   is a *provenance and verifiability* objection, not a popularity one, and it is
   **empirically testable**: run the artifact against the original and compare
   outputs. The PIGuard ONNX objection was legitimate in substance and sloppily
   framed; the A/B harness below resolves it rather than speculating about it.

The general rule this project already states applies here: measure, do not
assume. Popularity is an assumption.

---

# A/B harness - `Horizon-Labs/prompt-injection-eval-suite`

A ready-made known testing suite exists, so an independent A/B is far cheaper
than assembling one.

Dataset `Horizon-Labs/prompt-injection-eval-suite`, 15 parquet configs,
modified 2026-09-24. `license: other`, `license_name: mixed-per-config` - each
config carries its source dataset's license [V]:

| config | rows | positives | what it tests | source | license |
|---|---:|---:|---|---|---|
| `notinject` | 339 | **0** | over-defense: benign prompts with trigger words | leolee99/NotInject | MIT |
| `xstest` | 450 | 0 | safe and unsafe-but-not-injection | Paul/XSTest | CC-BY-4.0 |
| `orbench_hard` | 1319 | 0 | seemingly toxic but benign | bench-llm/or-bench | CC-BY-4.0 |
| `deepset_test` | 116 | 60 | direct injections, en/de | deepset/prompt-injections | Apache-2.0 |
| `jackhhao_test` | 262 | 139 | jailbreak vs benign | jackhhao/jailbreak-classification | Apache-2.0 |
| `simsonsun_jailbreaks` | 2426 | 2426 | contamination-filtered jailbreaks | Simsonsun/JailbreakPrompts | MIT |
| `boundary_pairs_test` | 240 | 120 | agentic minimal pairs | 3nesdeniz/agentic-prompt-injection-boundary-pairs | CC-BY-4.0 |
| `agentic5k_test` | 545 | 280 | agentic injections and hard negatives | 3nesdeniz/agentic-prompt-injection-5k | CC-BY-4.0 |
| `neuralchemy_test` | 942 | 552 | direct injections and hard negatives | neuralchemy/Prompt-injection-dataset | Apache-2.0 |
| `slabs_test` | 2101 | 1051 | direct injections and hard negatives | S-Labs/prompt-injection-dataset | MIT |
| `bipia` | 3178 | 3000 | **indirect injection in email**/table/code contexts | geodesic-research/bipia (derived) | **CC-BY-SA-4.0** |
| `piarena` | 1500 | 750 | indirect injection in RAG/QA contexts | sleeepeer/PIArena (derived) | MIT |
| `llmail_phase2` | - | - | **real adaptive email attacks** | LLMail-Inject | see config |

**Redistribution constraint:** `bipia` is **CC-BY-SA-4.0**. Share-alike is
incompatible with an MIT repository, so that parquet must not be committed. Run
it locally, cite it, and publish only our own numbers. The same caution applies
to any config whose license is not MIT, Apache-2.0 or CC-BY-4.0.

## Scope - deliberately narrow

**Two models, four configs.** Not six models and fifteen configs.

Models, because these are the two that are actually in contention:

- `marklkelly/bert-tiny-injection-detector` - 4.3 MB int8, 128-token limit, the
  cheap first pass
- `Horizon-Labs/prompt-injection-guard-small` - 141M, 8k context, the
  recommended tier

Configs, because these four answer the decision:

- `notinject` (339 rows, **zero positives**) - does it flag ordinary security
  documentation? This is the fixture-12 question at scale, and the single most
  important number for a university SOC that subscribes to security newsletters.
- `bipia` (3178 rows) - indirect injection in **email** contexts, our exact
  input type.
- `llmail_phase2` - **real adaptive email attacks**, not synthetic.
- `boundary_pairs_test` (240 rows) - minimal pairs, which isolate whether the
  model understands the agent/human boundary rather than matching keywords.

Reported per model: ROC-AUC, F1 and **FPR at a stated threshold**, plus recall at
1% FPR so the numbers are comparable to `marklkelly`'s own `eval/metrics.json`.
Also median latency and peak RSS on the benchmark host, since a CPU-only claim
needs CPU-only evidence.

## What this is for

Our own measured numbers, with the method published, explicitly labelled as ours:
our thresholds, our tokenization, our windowing, CPU-only. They will differ from
both the developer's figures and Horizon-Labs' comparison table, and saying so is
the point - the two published sources already disagree by an order of magnitude
about Meta's Prompt-Guard-2-22M.

**The A/B harness is a development tool, not part of the shipped artifact.**
Judges run the offline pipeline; the harness results become a table in the docs.
The pipeline must never require it.

## Compute

Benchmark on the 16-core build host (AMD Ryzen 9 7940HS, 60 GB RAM, 17 GB
available, 795 GB free), not the 8 vCPU / 11 GB integration host, which already
carries two resident classifier services and is production. Roughly 4-7k rows
across the four configs; minutes for the 4.3 MB model, tens of minutes for the
141M model.

## Gate

**Bundle E1, and only after Bundle D is complete.** A submission that does not
run loses to one that runs and carries a single small verified benchmark. The
tier interface in Bundle C is already optional, config-gated and defaults to
UNAVAILABLE, so the A/B result changes what we *recommend*, not what we *build* -
which is why it can safely come after the pipeline works.

If B, C and D land early, this becomes the highest-value remaining work, because
independent verification of small security models on email-relevant injection is
something none of the prior winners did and it is the same discipline that
produced the corrections earlier in this file.
