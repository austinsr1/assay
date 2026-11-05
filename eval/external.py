#!/usr/bin/env python3
"""Turn fetched external corpora into synthesized ``.eml`` messages, and say what that costs.

``docs/EVAL-SUITES.md`` scoped this: the corpora that can settle whether the detector
over-fires are public datasets that must not be committed here, so ``eval/fetch.py``
downloads them at evaluation time and this module runs the existing pipeline over them.
It does not implement a second set of metrics. Every number it produces comes out of
``eval/run.py::measure_corpus`` and ``eval/selective.py``, from the same per-message row
shape, on purpose: two implementations of a measurement disagree in whichever direction
flatters the result.

**Two roads to the same rows, and the difference is recorded.** The LLMail false-positive
file and the jailbreak CSV are read out of the pinned repository bytes: the sha256 in the
manifest is the digest of the very text measured here. The three Parquet-only corpora -
NotInject, deepset, the Bengali smishing set - are read from the JSON cache
``eval/fetch.py --rows`` wrote from the **datasets-server ROWS API**, which serves
Hugging Face's *converted* Parquet. Those bytes are not the repository file and do not
carry the pinned digest; what is cross-checked between the two objects is the split name
and the row count, and both the pinned file and the retrieval are re-hashed before a
single row is measured. ``text_origin`` on every corpus descriptor says which road a
corpus's text came from, per corpus, so the distinction cannot disappear into a table of
identical-looking provenance rows.

**The structural constraint this module exists to make visible.** These corpora are
*text*, not RFC 822 messages. LLMail's false-positive file is a JSON list of strings
shaped ``"Subject of the email: <subj>.   Body: <body>"``; the jailbreak set is a CSV
with a ``prompt`` column. There are no MIME headers, so **SPF, DKIM and DMARC cannot
fire**, and on the committed corpus the authentication layer is what settles most
messages. To run the pipeline at all, each row is wrapped in a minimal synthesized
envelope - which is legitimate, and is a *transformation*, so:

- every external-corpus number measures the **text and injection surfaces**, not the
  authentication layer;
- dispositions skew toward ``manual_review``, because the deterministic authentication
  signals that the clearance condition asks for are absent by construction and no
  amount of benign content can supply them;
- the exact wrapper is recorded, per corpus, in the output, next to the numbers it made
  possible, and ``eval/report.py`` prints it wherever those numbers appear;
- and where a corpus produced neither a clearance nor an accusation, the report says the
  measurement **does not discriminate on that axis** rather than printing 0.0%
  false positives as if it were a result. ``MODEL_TIER_STATEMENT`` below and
  ``eval/report.py``'s ``NON_DISCRIMINATING_STATEMENT`` exist for that: phase 1 published
  0.0% across three corpora that cleared nothing, which is one fact seen twice and not a
  finding.

That is the whole reason ``LIMITATION`` below is a module constant rather than prose
someone might write: a test asserts this exact text is present next to every external
number in the committed artifact and in the rendered report, so the caveat cannot be
lost by a renderer that forgets to add it - the failure mode ``eval/selective.py``
already guards against for uncalibrated scores.

Stdlib only. No dependencies, same rule as ``eval/fetch.py`` and for the same reason.

Usage is through ``eval/run.py --external``. Run ``eval/fetch.py --list`` to see what
the licence gate permits; nothing here will fetch, and nothing here will evaluate a
corpus it cannot verify on disk.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import pathlib
import sys
from email.message import EmailMessage
from typing import Any, Callable

REPO = pathlib.Path(__file__).resolve().parents[1]
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(HERE))

import fetch  # noqa: E402  (sibling module, loaded by directory like report/selective)
from tenable_email.signals import detect_injection_surface  # noqa: E402

#: Synthesized messages are written here, under ``eval/internal/`` and therefore
#: gitignored like everything else derived from fetched data. They are kept because
#: "here is the exact .eml the pipeline read" is the only answer to a provenance
#: question that does not require re-running anything.
SYNTHESIZED = fetch.INTERNAL / "_synthesized"

#: Fixed seed for the keyed sampling rule below. Reproducibility is the point, so it
#: is a constant in a tracked file and not a per-run random value; changing it is a
#: change to the committed numbers and belongs in a commit that says so.
DEFAULT_SEED = "tenable-email-bundle-n-1"

#: Corpora larger than this are sampled rather than run whole. The cap is set from the
#: largest single-label corpus in the evaluable set - the Bengali smishing test split
#: carries 1,401 rows, and 840 of them are the benign half - so **every** corpus this
#: build can read is measured whole and every denominator in the artifact is the
#: corpus's real size rather than a sample of it. The cap still exists for the corpora
#: phase 2 will add (BIPIA's 3,178 rows, LLMail's labelled submissions, the Bengali
#: train split's 4,903), and so that "how many of N" is always stated with its N.
#: Raising it from 500 changed no phase-1 number: the rule keeps every row when the cap
#: is at or above the population, and the largest phase-1 corpus was 259 rows.
DEFAULT_MAX_MESSAGES = 1500

#: The sampling rule, written out because "seeded" alone does not pin anything.
#: Python's ``random.sample`` is stable in practice but is an implementation of a
#: shuffling algorithm, not a specification; hashing the seed with the row index is a
#: rule a different interpreter, or a different language, reproduces byte for byte.
SAMPLING_RULE = (
    "sort rows by index; keep the rows whose key sha256(seed + ':' + corpus + ':' + "
    "row_index) is among the smallest `size` keys (ties broken by ascending index); "
    "no reservoir, no RNG implementation dependency, and the same seed selects the "
    "same rows on any host"
)

#: The one sentence that must travel with every external number. Kept as a constant
#: so a test can require its presence in the artifact and in the rendered report
#: rather than requiring that somebody remembered to write it.
LIMITATION = (
    "External corpus: the upstream rows are plain text, not RFC 822 messages, so each "
    "was wrapped in a minimal synthesized .eml envelope (recorded below, per corpus). "
    "No DKIM-Signature or Authentication-Results header exists in that envelope, so "
    "SPF, DKIM and DMARC cannot fire and the deterministic authentication layer cannot "
    "settle anything: this measures the text and injection surfaces only, NOT the "
    "authentication layer, and dispositions skew toward manual_review by construction. "
    "A deferral here is not a false positive; a clearance would be a false negative."
)

#: The second thing that must travel with every external number, and the one a
#: disposition table is most likely to hide. `fixtures/replay/` is keyed by content
#: address, so a message that was never sent to an endpoint has no recording, the tiers
#: abstain, and `corpus-backed` measures the same deterministic layer as
#: `deterministic-only`. That is not a finding about the model tiers and must never
#: render as one.
MODEL_TIER_STATEMENT = (
    "THE MODEL-TIER A/B HAS NOT RUN. Every external row in this artifact was "
    "dispositioned with 0 model judgments in both configurations, because the "
    "committed recordings in fixtures/replay/ are keyed by content address and no "
    "recording exists for text that was never sent to an endpoint. A missing recording "
    "is a miss, not a call and not an invented answer: `corpus-backed` and "
    "`deterministic-only` are the same measurement here, and no table in this report "
    "compares a deterministic layer against a model tier. Bundle N phase 2 (N8) is "
    "still open."
)

#: The envelope, in the same field-vs-value shape it is assembled from. Recorded in
#: the artifact and rendered next to the numbers. Local part and domain are separate
#: keys because this artifact is published and a literal address-shaped token in it
#: would be exactly the kind of string the leak guard is there to stop - and because
#: the split is the honest description of two independently chosen fields.
WRAPPER: dict[str, Any] = {
    "assembled_with": "stdlib email.message.EmailMessage.set_content(), text/plain",
    "headers_present": [
        "From", "To", "Date", "Message-ID", "MIME-Version", "Content-Type",
        "Content-Transfer-Encoding",
    ],
    "headers_absent_by_construction": [
        "Authentication-Results", "DKIM-Signature", "ARC-Seal", "ARC-Authentication-Results",
        "Return-Path", "Reply-To", "List-Id", "List-Unsubscribe",
    ],
    "from_local_part": "synthetic-sender",
    "from_domain": "example.com",
    "to_local_part": "recipient",
    "to_domain": "example.com",
    "domain_note": (
        "example.com is reserved by RFC 2606: it resolves nowhere and belongs to no "
        "organization, so the envelope cannot point a reviewer at a live host and "
        "cannot create a lookalike of one. It is not inside the shipped OrgProfile's "
        "protected or trusted domains, so the wrapper neither manufactures an "
        "impersonation signal nor borrows a legitimacy one."
    ),
    "message_id_local_part": "<corpus name>-<row index, zero padded>",
    "message_id_domain": "external.invalid",
    "date": "Mon, 02 Nov 2026 09:00:00 +0000",
    "date_note": (
        "A constant, not the clock: a run must not depend on the day it happens. "
        "The pipeline records no message age as a signal, so this is inert, and it is "
        "stated rather than left to be discovered."
    ),
    "attachments": "none",
    "links": "not added; any URL present is present because the upstream row contains it",
    "subject_rule": (
        "derived from the row only where the row states one; the full row string is "
        "always kept verbatim in the body, so no content is lost to the wrapper"
    ),
}

#: Corpus name -> how its rows are read, labelled and wrapped. ``reader`` returns an
#: iterable of ``(row_index, text, subject, upstream_label)`` from the fetched bytes.
#: The label semantics are the ones ``eval/selective.py`` owns: ``clean`` means "must
#: not be accused", ``hostile`` means "must not be cleared". Nothing here invents a
#: third label, because an unrecognized label is undecidable and a rate computed over
#: an undecidable population is not a measurement.
#:
#: ``source: "rows"`` marks the corpora whose bytes are Parquet: their text is read from
#: the JSON cache ``eval/fetch.py --rows`` wrote, which came from the datasets-server
#: ROWS API rather than from the pinned repository file. Both are verified before a row
#: is measured, and the descriptor records both, because they are different bytes.
CORPUS_DEFS: tuple[dict[str, Any], ...] = (
    {
        "name": "llmail-fp-tests",
        "dataset": "microsoft/llmail-inject-challenge",
        "repo_path": "data/emails_for_fp_tests.json",
        "kind": "labelled",
        "reader": "json-string-list",
        "label": "clean",
        "label_source": (
            "The file carries no per-row label. Its name and the upstream card declare "
            "it a false-positive test set of benign business emails, so the label is "
            "the file's stated purpose rather than a per-row annotation - which is "
            "weaker ground than fixtures/synthetic/labels.json and is recorded as such."
        ),
        "why": "203 benign business emails: the over-defense question, at a scale "
               "larger than the 3 benign fixtures this repository commits.",
    },
    {
        "name": "jackhhao-test-jailbreak",
        "dataset": "jackhhao/jailbreak-classification",
        "repo_path": "default/jailbreak_dataset_test.csv",
        "kind": "hostile",
        "reader": "csv-labelled",
        "label": "hostile",
        "only_label": "jailbreak",
        "label_source": (
            "Upstream per-row column 'type' == 'jailbreak', mapped to this project's "
            "'hostile' (must not be cleared). It is NOT mapped to 'threat', which would "
            "assert a credential-harvest judgment about an email that is only an "
            "agent-manipulation attempt in text."
        ),
        "why": "141 labelled jailbreak prompts: the detection side, on text the "
               "pipeline's own corpus never contains.",
    },
    {
        "name": "jackhhao-test-benign",
        "dataset": "jackhhao/jailbreak-classification",
        "repo_path": "default/jailbreak_dataset_test.csv",
        "kind": "labelled",
        "reader": "csv-labelled",
        "label": "clean",
        "only_label": "benign",
        "label_source": (
            "Upstream per-row column 'type' == 'benign', mapped to 'clean'. These are "
            "benign LLM prompts, not benign email, so they test over-defense against a "
            "different distribution from llmail-fp-tests and are reported separately."
        ),
        "why": "259 benign prompts: a second, independent false-positive denominator.",
    },
    # ---- NotInject: the zero-positive set, one corpus per pinned Parquet file ----
    #
    # Three corpora rather than one over 339 rows, because three repository files are
    # pinned and a single descriptor cannot honestly name one sha256 for three objects.
    # ``eval/run.py`` aggregates them back into the 339-row figure the decision needs.
    {
        "name": "notinject-one-benign",
        "dataset": "leolee99/NotInject",
        "repo_path": "data/NotInject_one-00000-of-00001.parquet",
        "source": "rows",
        "split": "NotInject_one",
        "kind": "labelled",
        "reader": "rows-api-json",
        "label": "clean",
        "label_source": (
            "No label column exists in this dataset: the rows are prompt / word_list / "
            "category, and the upstream card's stated purpose is benign prompts that "
            "contain injection trigger words and are not injections. So every row is "
            "'clean' (must not be accused) by construction, and the corpus carries ZERO "
            "positives: it can measure over-defense and nothing else. A low flag rate "
            "here says the surface did not cry wolf; it says nothing at all about "
            "whether the surface would catch an attack."
        ),
        "why": "113 of the 339 benign trigger-word prompts: the over-defense test at "
               "the scale docs/EVAL-SUITES.md ranks first.",
    },
    {
        "name": "notinject-two-benign",
        "dataset": "leolee99/NotInject",
        "repo_path": "data/NotInject_two-00000-of-00001.parquet",
        "source": "rows",
        "split": "NotInject_two",
        "kind": "labelled",
        "reader": "rows-api-json",
        "label": "clean",
        "label_source": (
            "As notinject-one-benign: no per-row label, benign by the declaring card, "
            "zero positives by construction."
        ),
        "why": "The second 113 rows of the 339-row zero-positive set.",
    },
    {
        "name": "notinject-three-benign",
        "dataset": "leolee99/NotInject",
        "repo_path": "data/NotInject_three-00000-of-00001.parquet",
        "source": "rows",
        "split": "NotInject_three",
        "kind": "labelled",
        "reader": "rows-api-json",
        "label": "clean",
        "label_source": (
            "As notinject-one-benign: no per-row label, benign by the declaring card, "
            "zero positives by construction."
        ),
        "why": "The third 113 rows of the 339-row zero-positive set.",
    },
    # ---- deepset: both classes, reported separately, per split ----
    {
        "name": "deepset-train-injection",
        "dataset": "deepset/prompt-injections",
        "repo_path": "data/train-00000-of-00001-9564e8b05b4757ab.parquet",
        "source": "rows",
        "split": "train",
        "kind": "hostile",
        "reader": "rows-api-json",
        "label": "hostile",
        "label_source": (
            "Upstream column 'label' == 1 (the JSON rows return it as the integer 1, "
            "not the string '1'), mapped to 'hostile': must not be cleared. It is NOT "
            "mapped to 'threat', which would assert a credential-harvest judgement "
            "about a text prompt aimed at an LLM. label == 0 rows of the same split are "
            "measured as deepset-train-not-injection, so no row of the file is dropped "
            "and no row is counted twice."
        ),
        "why": "203 labelled injections from the train split: the recall side, on the "
               "distribution of the detector docs/EVAL-SUITES.md reports at FPR 1.00.",
    },
    {
        "name": "deepset-train-not-injection",
        "dataset": "deepset/prompt-injections",
        "repo_path": "data/train-00000-of-00001-9564e8b05b4757ab.parquet",
        "source": "rows",
        "split": "train",
        "kind": "labelled",
        "reader": "rows-api-json",
        "label": "clean",
        "label_source": (
            "Upstream column 'label' == 0 mapped to 'clean': not an injection, so it "
            "must not be accused. Upstream 'not-injection' is weaker ground than a "
            "benign business email - some of these rows are jailbreak-adjacent text that "
            "the upstream annotator merely did not label as an injection - and the set "
            "is reported separately from llmail-fp-tests for that reason."
        ),
        "why": "343 not-injection rows from the same split: the false-positive side, "
               "with its own denominator.",
    },
    {
        "name": "deepset-test-injection",
        "dataset": "deepset/prompt-injections",
        "repo_path": "data/test-00000-of-00001-701d16158af87368.parquet",
        "source": "rows",
        "split": "test",
        "kind": "hostile",
        "reader": "rows-api-json",
        "label": "hostile",
        "label_source": (
            "Upstream column 'label' == 1 mapped to 'hostile', as in the train split. "
            "The held-out split of the same dataset, and not an independent dataset: "
            "train and test rows of the same corpus are reported as separate corpora "
            "and never averaged into one number."
        ),
        "why": "60 labelled injections from the held-out test split.",
    },
    {
        "name": "deepset-test-not-injection",
        "dataset": "deepset/prompt-injections",
        "repo_path": "data/test-00000-of-00001-701d16158af87368.parquet",
        "source": "rows",
        "split": "test",
        "kind": "labelled",
        "reader": "rows-api-json",
        "label": "clean",
        "label_source": (
            "Upstream column 'label' == 0 mapped to 'clean', as in the train split."
        ),
        "why": "56 not-injection rows from the held-out test split.",
    },
    # ---- Bengali smishing: the honest out-of-domain check ----
    {
        "name": "bengali-test-smishing",
        "dataset": "shariul-islam/bengali-sms-smishing-dataset",
        "repo_path": "data/test-00000-of-00001.parquet",
        "source": "rows",
        "split": "test",
        "kind": "hostile",
        "reader": "rows-api-json",
        "label": "hostile",
        "label_source": (
            "Upstream column 'label' == 'smish' mapped to 'hostile' (must not be "
            "cleared). The other two upstream values, 'normal' and 'promo', map to "
            "'clean' by the corpus default recorded in eval/fetch.py - which reads a "
            "promotional SMS as 'must not be accused of being a phishing attack', a "
            "weaker claim than llmail-fp-tests makes, and is stated rather than hidden."
        ),
        "why": "561 smishing SMS in the held-out split: the only redistributable "
               "smishing set in docs/EVAL-SUITES.md.",
        "measurement_limits": (
            "SMS, not email: no headers, no links, no attachments, no MIME structure, "
            "and the pipeline's link and attachment layers have nothing to read.",
            "Not English. Bengali script, transliterated brands and Latin-digit phone "
            "numbers: a poor result here is about domain and language transfer, not "
            "about this pipeline's email behaviour, and a good one is not evidence "
            "about phishing either.",
        ),
    },
    {
        "name": "bengali-test-not-smishing",
        "dataset": "shariul-islam/bengali-sms-smishing-dataset",
        "repo_path": "data/test-00000-of-00001.parquet",
        "source": "rows",
        "split": "test",
        "kind": "labelled",
        "reader": "rows-api-json",
        "label": "clean",
        "label_source": (
            "Upstream 'normal' and 'promo' mapped to 'clean' by the corpus default. "
            "498 normal + 342 promo = 840 rows, and both upstream values are named in "
            "this corpus's label distribution so the denominator is auditable."
        ),
        "why": "840 non-smishing SMS: the false-positive side of the out-of-domain "
               "check, with its own denominator.",
        "measurement_limits": (
            "SMS, not email: no headers, no links, no attachments, no MIME structure, "
            "and the pipeline's link and attachment layers have nothing to read.",
            "Not English. Bengali script, transliterated brands and Latin-digit phone "
            "numbers: a poor result here is about domain and language transfer, not "
            "about this pipeline's email behaviour, and a good one is not evidence "
            "about phishing either.",
        ),
    },
)

#: Corpora the licence gate permits and ``eval/fetch.py`` can pin, but which this
#: module will not evaluate. Filled from the manifest at run time, so nothing here
#: claims a limitation for a dataset that was never fetched.
UNDECODABLE_FORMATS = {
    "parquet": (
        "Parquet, and its rows were not retrieved. The row count and digest are pinned "
        "from the file itself, but reading its text needs a column decoder - "
        "dictionary-encoded pages behind a snappy-compressed stream - that this "
        "stdlib-only build does not carry, and the datasets-server ROWS retrieval that "
        "stands in for it has not been run for this split. Fetch it with "
        "`python3 eval/fetch.py --dataset <id> --rows`. Fetched and verified, not "
        "evaluated: reported here so the gap is a stated limitation rather than a zero "
        "in a table."
    ),
}


# --------------------------------------------------------------------------
# reading rows out of fetched bytes
# --------------------------------------------------------------------------


def _read_json_string_list(data: bytes) -> list[tuple[int, str, str, str]]:
    loaded = json.loads(data.decode("utf-8", "replace"))
    if not isinstance(loaded, list):
        raise ValueError("expected a JSON list of strings")
    out = []
    for index, item in enumerate(loaded):
        text = item if isinstance(item, str) else json.dumps(item)
        out.append((index, text, _subject_from_llmail(text), ""))
    return out


def _read_csv_labelled(data: bytes, text_field: str, label_field: str
                       ) -> list[tuple[int, str, str, str]]:
    text = data.decode("utf-8", "replace")
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows or text_field not in rows[0]:
        raise ValueError(
            f"CSV has no {text_field!r} column; columns are "
            f"{sorted(rows[0]) if rows else 'nothing'}"
        )
    out = []
    for index, row in enumerate(rows):
        body = str(row.get(text_field) or "")
        out.append((index, body, "", str(row.get(label_field) or "")))
    return out


def _read_rows_api(data: bytes, spec: dict) -> list[tuple[int, str, str, str]]:
    """Rows from the JSON cache ``eval/fetch.py --rows`` wrote.

    The cache has already been re-hashed against the retrieval digest by the caller, so
    these rows are the bytes that retrieval described. What is checked here is the
    *shape*: a row missing its text column raises instead of contributing an empty
    message, because an empty body dispositions as clean-looking and would quietly add
    rows to a denominator that measured nothing. The upstream label is returned as the
    string the JSON carries - the deepset rows come back with the integer 1, and the
    label map is written against "1" - so ``str()`` here is the thing that makes the
    documented mapping actually fire.
    """
    loaded = json.loads(data.decode("utf-8", "replace"))
    if not isinstance(loaded, dict) or not isinstance(loaded.get("rows"), list):
        raise ValueError("the row cache is not a retrieval object with a `rows` list")
    text_field = spec.get("text_field")
    label_field = spec.get("label_field")
    if not text_field:
        raise ValueError("the retrieval records no text column for this corpus")
    out: list[tuple[int, str, str, str]] = []
    for item in loaded["rows"]:
        row = item.get("row") if isinstance(item, dict) else None
        if not isinstance(row, dict):
            raise ValueError(f"a cached row is not an object: {item!r:.80}")
        if text_field not in row:
            raise ValueError(
                f"a cached row has no {text_field!r} column; columns are "
                f"{sorted(row)}"
            )
        index = item.get("row_idx")
        if not isinstance(index, int):
            raise ValueError("a cached row carries no integer row_idx")
        label = str(row.get(label_field)) if label_field and label_field in row else ""
        out.append((index, str(row[text_field]), "", label))
    return out


def _mapped(spec: dict[str, Any], upstream_label: str) -> str:
    """Upstream label -> this project's label, or the upstream value unchanged.

    ``label_default`` is the mapping for an upstream value the table does not name - the
    Bengali corpus's "otherwise clean" - and it exists as data in the allowlist rather
    than as a filter in this module, so the claim "every non-smishing SMS is 'clean'"
    is audited where the licence is audited, and is recorded in the manifest and in
    PROVENANCE.json.
    """
    mapped = (spec.get("label_map") or {}).get(upstream_label)
    if mapped is not None:
        return mapped
    if spec.get("label_default"):
        return str(spec["label_default"])
    return upstream_label


def upstream_labels_seen(rows: list[tuple[int, str, str, str]], spec: dict[str, Any],
                         retrieval: dict[str, Any] | None) -> dict[str, int]:
    """Upstream label value -> count, over every row of the file or retrieval.

    Recorded so a denominator can be audited without re-reading the data: it is how a
    reader checks that deepset-train-injection's 203 and deepset-train-not-injection's
    343 add up to the 546 rows the pinned file's footer reports, and that the Bengali
    "clean" corpus's 840 is 498 normal plus 342 promo. Counts only - no row text.
    """
    if retrieval is None and not (spec.get("label_map") or spec.get("label_default")):
        return {}
    seen: dict[str, int] = {}
    for _index, _text, _subject, upstream in rows:
        key = upstream if upstream else "(no label column)"
        seen[key] = seen.get(key, 0) + 1
    return dict(sorted(seen.items()))


def text_origin(file_entry: dict[str, Any],
                retrieval: dict[str, Any] | None) -> dict[str, Any]:
    """Which bytes the measured text actually came from, stated per corpus.

    The two roads are not interchangeable and the artifact must not let them look
    identical. For a file-read corpus the pinned sha256 is the digest of the measured
    text. For a ROWS-API corpus it is the digest of a Parquet file this build never
    opened: the text came from Hugging Face's conversion service, in a different
    encoding, with a different byte length, and the only thing the two objects are
    checked against each other for is the split name and the row count.
    """
    if retrieval is None:
        return {
            "via": "repository-file",
            "statement": (
                "The measured text was read out of the file at the pinned revision, and "
                "the sha256 recorded for this corpus is the digest of exactly those "
                "bytes - this corpus's provenance is a hash of the text it measured."
            ),
            "repository_file_sha256": file_entry.get("sha256"),
            "rows_read_from_repository_file": file_entry.get("row_count"),
            "conversion_service_used": False,
        }
    return {
        "via": "datasets-server-rows-api",
        "statement": fetch.ROWS_CONVERSION_NOTE,
        "repository_file_sha256": file_entry.get("sha256"),
        "rows_read_from_repository_file": file_entry.get("row_count"),
        "row_cache_sha256": retrieval.get("sha256"),
        "rows_retrieved": retrieval.get("rows_retrieved"),
        "num_rows_total_reported": retrieval.get("num_rows_total"),
        "row_counts_agree": retrieval.get("row_counts_agree"),
        "conversion_service_used": True,
        "retrieved_at": retrieval.get("retrieved_at"),
    }


#: LLMail's rows look like ``"Subject of the email: <subj>.   Body: <body>"``.
LLMAIL_SUBJECT_PREFIX = "Subject of the email: "
LLMAIL_BODY_SEPARATOR = "   Body: "


def _subject_from_llmail(row: str) -> str:
    """The subject half of an LLMail row, or "" when the row does not state one.

    Only used for the ``Subject`` header. The body always keeps the whole row
    verbatim, so this derivation cannot lose content - it can only duplicate a
    subject into a header where the deterministic layer reads it.
    """
    if not row.startswith(LLMAIL_SUBJECT_PREFIX):
        return ""
    remainder = row[len(LLMAIL_SUBJECT_PREFIX):]
    if LLMAIL_BODY_SEPARATOR not in remainder:
        return ""
    head = remainder.split(LLMAIL_BODY_SEPARATOR, 1)[0]
    return head.rstrip(".").strip()


READERS: dict[str, Callable[[bytes, dict], list[tuple[int, str, str, str]]]] = {
    "json-string-list": lambda data, spec: _read_json_string_list(data),
    "csv-labelled": lambda data, spec: _read_csv_labelled(
        data, spec["text_field"], spec["label_field"]
    ),
    "rows-api-json": lambda data, spec: _read_rows_api(data, spec),
}


# --------------------------------------------------------------------------
# the wrapper
# --------------------------------------------------------------------------


def wrap(case_id: str, subject: str, body: str) -> str:
    """The exact synthesized ``.eml`` for one external row.

    Byte-identical for the same input on every host: the Date is a constant, the
    Message-ID comes from the case name, and ``EmailMessage.set_content`` chooses its
    own transfer encoding deterministically. Nothing is added that the row does not
    contain - no link, no attachment, no authentication header pretending to have
    passed.
    """
    message = EmailMessage()
    message["From"] = f"{WRAPPER['from_local_part']}@{WRAPPER['from_domain']}"
    message["To"] = f"{WRAPPER['to_local_part']}@{WRAPPER['to_domain']}"
    message["Date"] = WRAPPER["date"]
    message["Message-ID"] = f"<{case_id}.{WRAPPER['message_id_domain']}>"
    if subject:
        message["Subject"] = subject
    message.set_content(body)
    return message.as_string()


# --------------------------------------------------------------------------
# sampling
# --------------------------------------------------------------------------


def sample_keys(seed: str, corpus: str, indices: list[int], size: int) -> set[int]:
    """The rows the documented rule selects. Pure, so it can be tested directly."""
    if size >= len(indices):
        return set(indices)
    keyed = [
        (hashlib.sha256(f"{seed}:{corpus}:{index}".encode("utf-8")).hexdigest(), index)
        for index in indices
    ]
    keyed.sort()
    return {index for _digest, index in keyed[:size]}


# --------------------------------------------------------------------------
# availability, and the loud degradation
# --------------------------------------------------------------------------


def fetched_manifest() -> dict[str, Any]:
    """The fetch manifest, or an empty one. Never downloads."""
    try:
        return fetch.load_manifest()
    except fetch.IntegrityError as exc:
        return {"datasets": {}, "_error": str(exc)}


def not_fetched_state(manifest: dict[str, Any]) -> dict[str, Any]:
    """What to say when no corpus has been fetched, and why it is not zero rows.

    This is the state a fresh clone is in, because nothing fetched is committed. It
    has to read as "not measured" - a report with external rows at zero would be a
    number invented by absence.
    """
    datasets = sorted(manifest.get("datasets") or {})
    lines = [
        "No external corpus has been fetched on this host, so nothing here was "
        "measured. This is the expected state of a fresh clone: fetched data is "
        "gitignored by policy and only its provenance is committed "
        "(eval/PROVENANCE.json).",
    ]
    if manifest.get("_error"):
        lines.append(f"The manifest that is present could not be read: {manifest['_error']}")
    elif datasets:
        lines.append(
            f"The manifest names {len(datasets)} dataset(s), but none of them has an "
            "evaluable, verified file on disk - see 'unavailable' below for which and why."
        )
    else:
        lines.append("There is no manifest at eval/internal/manifest.json at all.")
    lines.append(
        "To fetch what the licence gate permits: "
        "`python3 eval/fetch.py --all`, plus `--rows` for the corpora that ship only as "
        "Parquet, then re-run `python3 eval/run.py --external`. To see what is refused "
        "and on which observed licence: `python3 eval/fetch.py --list`."
    )
    return {
        "status": "not-fetched",
        "requested": True,
        "measured_here": False,
        "headline": lines[0],
        "detail": lines,
        "commands": ["python3 eval/fetch.py --all",
                     "python3 eval/fetch.py --all --rows",
                     "python3 eval/run.py --external",
                     "python3 eval/fetch.py --list"],
        "limitation": LIMITATION,
        "synthetic_envelope": WRAPPER,
        "results": {},
        "corpora": {},
        "unavailable": [],
        # Present and empty, not absent: the renderer requires both of these, and a
        # state that fails its own contract because nothing was fetched would turn an
        # honest absence into a crash that looks like a bug in the guard.
        "model_tier": {"per_configuration": {}, "has_run": False,
                       "statement": MODEL_TIER_STATEMENT},
        "per_dataset": {},
        "allowlisted": sorted(fetch.PERMITTED),
        "refused": sorted(fetch.REFUSED),
    }


def _declared_file(dataset_id: str, repo_path: str):
    """The FileSpec eval/fetch.py currently declares for this path, or None.

    ``gate()`` is the pure half of the licence decision, so this reads the table with no
    network and without the share-alike flag. A dataset reachable only behind that flag
    returns None here, and the caller treats that as a withdrawn permission - which is
    the right answer for rows whose only grant was a flag this build does not pass.
    """
    spec, _refusal = fetch.gate(dataset_id)
    return spec.file(repo_path) if spec is not None else None


def _rows_retrieval(definition: dict[str, Any], block: dict[str, Any],
                    file_entry: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """The cached ROWS-API retrieval for one corpus, verified or refused.

    Every check here is a reason a measurement would be built on text this harness
    cannot vouch for, so each one returns a sentence rather than a bare False:

    - the split was never retrieved (the run needs ``--rows``);
    - the cache is not on disk, or its bytes are not the digest the manifest recorded;
    - the retrieval did not end up with the number of rows the service claimed, or its
      row count does not agree with the pinned repository file's own footer;
    - the retrieval describes a different revision, or a different pinned file, than the
      corpus is declared against - i.e. the cache is left over from an older fetch.

    A cache that fails any of these is not used, and the corpus goes to ``unavailable``
    with the reason. Silently measuring a stale cache would report numbers about text
    that no longer matches its provenance.
    """
    split = definition.get("split")
    record = (block.get("rows") or {}).get(split)
    if record is None:
        return None, (
            f"Parquet, and its rows were never retrieved from the datasets-server ROWS "
            f"API for split {split!r}. Run "
            f"`python3 eval/fetch.py --dataset {definition['dataset']} --rows`."
        )
    cache = REPO / record.get("local_path", "")
    if not cache.is_file():
        return None, (f"the row retrieval is recorded at {record.get('local_path')} "
                      "and that file is not on disk")
    actual = fetch.sha256_file(cache)
    if actual != record.get("sha256"):
        return None, (
            f"sha256 {actual} of the cached rows does not match the "
            f"{record.get('sha256')} recorded for the retrieval at revision "
            f"{record.get('revision')} - refusing to measure rows whose provenance this "
            "harness cannot vouch for. Run `python3 eval/fetch.py --verify`."
        )
    if record.get("rows_retrieved") != record.get("num_rows_total"):
        return None, (
            f"the retrieval holds {record.get('rows_retrieved')} rows against a "
            f"service-reported num_rows_total of {record.get('num_rows_total')} - an "
            "incomplete retrieval, not a smaller corpus"
        )
    if record.get("row_counts_agree") is not True:
        return None, (
            f"the conversion service reports {record.get('num_rows_total')} rows for "
            f"split {split!r} where the pinned repository file's footer reports "
            f"{record.get('pinned_file_row_count')}: the two objects disagree about "
            "this corpus's size, so no number measured from either is interpretable"
        )
    if record.get("revision") != file_entry.get("revision"):
        return None, (
            f"the rows were retrieved at revision {record.get('revision')} and the "
            f"pinned file is revision {file_entry.get('revision')} - the cache is from "
            "a different fetch"
        )
    if record.get("repo_path") != definition["repo_path"] or \
            record.get("pinned_file_sha256") != file_entry.get("sha256"):
        return None, (
            "the retrieval was cross-checked against a different file than the one this "
            f"corpus is declared against ({record.get('repo_path')} / "
            f"{str(record.get('pinned_file_sha256'))[:12]}... vs "
            f"{definition['repo_path']} / {str(file_entry.get('sha256'))[:12]}...)"
        )
    return record, ""


def _entry(corpus: dict[str, Any], row: tuple[int, str, str, str]) -> dict[str, Any]:
    index, _body, _subject, upstream_label = row
    case = f"{corpus['name']}-{index:05d}"
    return {
        "case": case,
        "path": corpus["messages_dir"] / f"{case}.eml",
        "label": corpus["label"],
        "status": None,
        "upstream_label": upstream_label,
        "row_index": index,
    }


def build_plan(*, seed: str = DEFAULT_SEED,
               max_messages: int = DEFAULT_MAX_MESSAGES,
               write_messages: bool = True) -> dict[str, Any]:
    """Every evaluable external corpus, as entries ``eval/run.py`` can measure.

    An entry list shaped like ``run.corpora()`` on purpose: ``measure_corpus`` then
    does the triage and the metrics, so there is exactly one implementation of every
    number in the artifact.

    Returns a payload-sized dict with ``status``, ``corpora`` (name -> descriptor and
    entries), ``unavailable`` (things permitted but not measurable here, each with the
    reason) and ``results`` left empty for the caller to fill by measuring.
    """
    manifest = fetched_manifest()
    datasets = manifest.get("datasets") or {}
    unavailable: list[dict[str, Any]] = []
    corpora: dict[str, dict[str, Any]] = {}
    #: Which pinned Parquet files this run actually measured rows out of, so
    #: ``_record_undecoded`` can list the ones it did not instead of listing the whole
    #: format. A file that was measured must not also be reported as a gap.
    measured_parquet_files: set[tuple[str, str]] = set()

    if not datasets:
        return not_fetched_state(manifest)

    for definition in CORPUS_DEFS:
        dataset_id = definition["dataset"]
        block = datasets.get(dataset_id)
        if block is None:
            unavailable.append({
                "corpus": definition["name"], "dataset": dataset_id,
                "reason": "not fetched on this host - run "
                          "`python3 eval/fetch.py --dataset " + dataset_id + "`",
                "license_observed": None, "revision": None,
            })
            continue

        file_entry = (block.get("files") or {}).get(definition["repo_path"])
        if file_entry is None:
            unavailable.append({
                "corpus": definition["name"], "dataset": dataset_id,
                "repo_path": definition["repo_path"],
                "reason": "allowlisted for this dataset but not present in the "
                          "manifest, so it was never fetched at this revision",
                "license_observed": block.get("license_observed"),
                "revision": block.get("revision"),
            })
            continue

        local = REPO / file_entry["local_path"]
        if not local.is_file():
            unavailable.append({
                "corpus": definition["name"], "dataset": dataset_id,
                "reason": f"recorded at {file_entry['local_path']} and not on disk",
                "license_observed": block.get("license_observed"),
                "revision": file_entry.get("revision"),
            })
            continue

        # Re-hash rather than trust the manifest: the digest is the claim, and the
        # claim is what the numbers depend on.
        actual = fetch.sha256_file(local)
        if actual != file_entry["sha256"]:
            unavailable.append({
                "corpus": definition["name"], "dataset": dataset_id,
                "reason": (
                    f"sha256 {actual} does not match the {file_entry['sha256']} "
                    "recorded for revision "
                    f"{file_entry.get('revision')} - refusing to measure against "
                    "bytes whose provenance this harness cannot vouch for. Run "
                    "`python3 eval/fetch.py --verify`."
                ),
                "license_observed": block.get("license_observed"),
                "revision": file_entry.get("revision"),
            })
            continue

        retrieval: dict[str, Any] | None = None
        source_bytes = local
        if definition.get("source") == "rows":
            retrieval, reason = _rows_retrieval(definition, block, file_entry)
            if retrieval is None:
                unavailable.append({
                    "corpus": definition["name"], "dataset": dataset_id,
                    "reason": reason,
                    "license_observed": block.get("license_observed"),
                    "revision": file_entry.get("revision"),
                })
                continue
            source_bytes = REPO / retrieval["local_path"]

        spec = {
            "text_field": file_entry.get("text_field"),
            "label_field": file_entry.get("label_field"),
            "label_map": file_entry.get("label_map") or {},
            "label_default": file_entry.get("label_default"),
        }
        if retrieval is not None:
            # The retrieval record and the allowlist table are two descriptions of the
            # same rows, written at different times. If they disagree about which column
            # carries the text or what a label means, measuring would mean picking one,
            # so this refuses. The comparison is against the table in eval/fetch.py - the
            # declaration a reader is asked to trust - and not against the manifest's
            # copy of it, because the manifest records a fetch, and a row-shape amended
            # in the table after that fetch is exactly the drift worth catching.
            declared = _declared_file(dataset_id, definition["repo_path"])
            mismatch = None
            if declared is None:
                mismatch = (
                    f"{definition['repo_path']} is not in the allowlisted file set that "
                    f"eval/fetch.py declares for {dataset_id}, so the rows on disk come "
                    "from a declaration that has been withdrawn"
                )
            else:
                for attribute in ("text_field", "label_field", "label_default"):
                    table_value = getattr(declared, attribute)
                    if table_value != retrieval.get(attribute):
                        mismatch = (
                            f"the row retrieval records {attribute}="
                            f"{retrieval.get(attribute)!r} where eval/fetch.py now says "
                            f"{table_value!r} - the table moved after the retrieval, or "
                            "this cache is not the one this corpus was declared against"
                        )
                        break
                    spec[attribute] = table_value
                if mismatch is None and (dict(declared.label_map)
                                         != (retrieval.get("label_map") or {})):
                    mismatch = (
                        f"the row retrieval maps labels {retrieval.get('label_map')!r} "
                        f"where eval/fetch.py now says {dict(declared.label_map)!r}"
                    )
            if mismatch is not None:
                unavailable.append({
                    "corpus": definition["name"], "dataset": dataset_id,
                    "reason": mismatch,
                    "license_observed": block.get("license_observed"),
                    "revision": file_entry.get("revision"),
                })
                retrieval = None
                continue
            spec["label_map"] = retrieval.get("label_map") or {}
            measured_parquet_files.add((dataset_id, definition["repo_path"]))

        reader = READERS.get(definition["reader"])
        if reader is None:
            unavailable.append({
                "corpus": definition["name"], "dataset": dataset_id,
                "reason": f"no reader named {definition['reader']!r} in this module",
                "license_observed": block.get("license_observed"),
                "revision": file_entry.get("revision"),
            })
            continue
        try:
            rows = reader(source_bytes.read_bytes(), spec)
        except (ValueError, csv.Error, fetch.IntegrityError) as exc:
            unavailable.append({
                "corpus": definition["name"], "dataset": dataset_id,
                "reason": f"could not be read as expected: {exc}",
                "license_observed": block.get("license_observed"),
                "revision": file_entry.get("revision"),
            })
            continue

        only = definition.get("only_label")
        wanted = definition["label"]
        # ``only_label`` is the *upstream* spelling; ``label_map`` turns it into this
        # project's label. A corpus with no ``only_label`` is labelled at corpus level -
        # LLMail's false-positive file carries no per-row label at all - and
        # ``label_source`` says on what authority. Rows whose upstream label maps to
        # something other than this corpus's label are counted and reported, never
        # dropped in silence: a filter that quietly discards rows changes the
        # denominator without telling anyone.
        strays: list[tuple[int, str, str, str]] = []
        if retrieval is not None:
            # A ROWS-API corpus is defined by the label its rows *map to*, not by an
            # upstream spelling: the Bengali "not smishing" corpus is two upstream values
            # ('normal' and 'promo') and one project label. So the split of the file
            # between corpora happens here, and a row whose label maps to neither
            # 'hostile' nor 'clean' is counted as a stray rather than dropped - the same
            # rule the CSV path applies, from the other side.
            if spec.get("label_field"):
                kept = [row for row in rows if _mapped(spec, row[3]) == wanted]
                strays = [row for row in rows
                          if _mapped(spec, row[3]) not in ("hostile", "clean")]
            else:
                # No label column exists at all (NotInject ships prompt / word_list /
                # category), so every row of the retrieval carries this corpus's own
                # label and `label_source` says on whose authority. Filtering by a mapped
                # label here would drop the whole corpus, and a corpus that quietly
                # measures zero rows is worse than one that says it cannot measure.
                kept = list(rows)
        else:
            kept = [row for row in rows if only is None or row[3] == only]
            strays = [
                row for row in kept
                # Only meaningful where the upstream rows carry per-row labels at all.
                # LLMail's file has none, so `_mapped` there returns "" and every row would
                # be reported as a stray - a guard that cries wolf on the benign corpus is
                # a guard that gets read as noise.
                if spec.get("label_map") and _mapped(spec, row[3]) != wanted
            ]

        total = len(kept)
        indices = [row[0] for row in kept]
        keep = sample_keys(seed, definition["name"], indices, max_messages)
        chosen = [row for row in kept if row[0] in keep]

        name = definition["name"]
        messages_dir = SYNTHESIZED / name
        corpus = {
            "name": name,
            "kind": definition["kind"],
            "label": definition["label"],
            "messages_dir": messages_dir,
            "entries": [],
            "descriptor": {
                "corpus": name,
                "dataset": dataset_id,
                "label": definition["label"],
                "slug": block.get("slug"),
                "file": definition["repo_path"],
                "source_url": file_entry.get("source_url"),
                "revision": file_entry.get("revision"),
                "revision_source": block.get("revision_source"),
                "api_url": block.get("api_url"),
                "license_observed": block.get("license_observed"),
                "license_field": block.get("license_field"),
                "license_verified_on": block.get("license_verified_on"),
                "license_observed_at_fetch": block.get("license_observed_at_fetch"),
                "datasets_server_licenses": block.get("datasets_server_licenses", []),
                "license_limits": block.get("license_limits", []),
                "sha256": file_entry.get("sha256"),
                "bytes": file_entry.get("bytes"),
                "row_count_file": file_entry.get("row_count"),
                "row_count_method": file_entry.get("row_count_method"),
                "rows_in_corpus": total,
                "rows_used": len(chosen),
                "upstream_label_kept": only,
                "rows_with_an_unexpected_upstream_label": len(strays),
                "split": definition.get("split"),
                "upstream_labels_seen": upstream_labels_seen(rows, spec, retrieval),
                "text_origin": text_origin(file_entry, retrieval),
                "rows_retrieval": retrieval,
                "sample": {
                    "seed": seed,
                    "size": len(chosen),
                    "population": total,
                    "all_rows": len(chosen) == total,
                    "cap": max_messages,
                    "rule": SAMPLING_RULE,
                },
                "label_source": definition["label_source"],
                "why": definition["why"],
                "kind_of_measurement": definition["kind"],
                "measurement_limits": list(definition.get("measurement_limits") or []),
                "limitation": LIMITATION,
                "synthetic_envelope": WRAPPER,
                "text_surface": {},
            },
        }

        for index, body, subject, upstream in chosen:
            entry = _entry({**corpus, "messages_dir": messages_dir},
                           (index, body, subject, upstream))
            case = entry["case"]
            raw = wrap(case, subject, body)
            if write_messages:
                _write_message(entry["path"], raw)
            corpus["entries"].append(entry)

        flagged = sum(
            1 for _i, body, _s, _u in chosen
            if detect_injection_surface(body)["attempt_detected"]
        )
        corpus["descriptor"]["text_surface"] = {
            "rows": len(chosen),
            "label": definition["label"],
            "injection_indicator_rows": flagged,
            "injection_indicator_rate": (
                round(flagged / len(chosen), 4) if chosen else None
            ),
            "rows_with_a_derived_subject": sum(
                1 for _i, _b, subject, _u in chosen if subject
            ),
            "rows_truncated_by_the_conversion_service": (
                retrieval.get("rows_with_truncated_cells", 0)
                if retrieval is not None else 0
            ),
            "truncated_cells_note": (
                "Counted over the whole retrieved split, not this corpus's label subset: "
                "the datasets-server truncates long cells and says so per row, and a "
                "truncated row means the text measured is a prefix of the text upstream. "
                "0 everywhere here, which is the answer worth having recorded rather than "
                "assumed."
            ) if retrieval is not None else "",
            "note": (
                "Input-side characterisation of the corpus text, measured with the "
                "pipeline's own deterministic injection scanner. It is not a verdict: "
                "it says how much of this corpus contains anything for the text surface "
                "to notice, which is what makes the disposition numbers interpretable. "
                "For a corpus whose every row cleared nothing and accused nothing, THIS "
                "is the number that discriminates, and it is printed with its "
                "denominator."
            ),
        }
        corpora[name] = corpus

    _record_undecoded(datasets, unavailable, measured_parquet_files)

    status = "measured" if corpora else ("no-evaluable-corpus" if unavailable else "empty")
    payload = {
        "status": status,
        "requested": True,
        "measured_here": bool(corpora),
        "headline": (
            f"{len(corpora)} external corpus(corpora) measured on this host; "
            f"{len(unavailable)} fetched permitted file(s) are not evaluable by this "
            "build."
            if corpora else
            "Nothing fetched is evaluable on this host; see 'unavailable'."
        ),
        "manifest_error": manifest.get("_error"),
        "limitation": LIMITATION,
        "synthetic_envelope": WRAPPER,
        "results": {},
        "corpora": {name: corpus["descriptor"] for name, corpus in corpora.items()},
        "unavailable": unavailable,
        "allowlisted": sorted(fetch.PERMITTED),
        "refused": sorted(fetch.REFUSED),
    }
    payload["_corpora"] = corpora
    return payload


def _write_message(path: pathlib.Path, raw: str) -> None:
    """Write one synthesized message, inside ``eval/internal/`` only.

    The containment check is ``fetch``'s, not a second copy of it: this directory and
    that one are the same policy - nothing derived from fetched data may land where a
    commit could find it.
    """
    resolved = path.resolve()
    root = fetch.INTERNAL.resolve()
    if root not in resolved.parents:
        raise fetch.IntegrityError(
            f"refusing to write a synthesized message outside {root}: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.is_file() else None
    if existing != raw:
        path.write_text(raw, encoding="utf-8")


def _record_undecoded(datasets: dict[str, Any], unavailable: list[dict[str, Any]],
                      measured_files: set[tuple[str, str]] | None = None) -> None:
    """Permit-and-fetched corpora this build cannot read, stated per dataset.

    Built from the manifest rather than from a hardcoded list, so a dataset that was
    never fetched is not reported as a limitation of this host, and one that was
    fetched but cannot be decoded cannot disappear from the record.

    ``measured_files`` is the set of (dataset, repo_path) pairs whose rows were measured
    through the ROWS API this run. A pinned Parquet file is only a gap while its rows
    have not been retrieved: listing a corpus as both measured and unreadable is the
    artifact contradicting itself, which is what this parameter exists to prevent.
    """
    measured_files = measured_files or set()
    already = {
        (item.get("dataset"), item.get("file") or item.get("repo_path"))
        for item in unavailable
    }
    for dataset_id, block in sorted(datasets.items()):
        for repo_path, entry in sorted((block.get("files") or {}).items()):
            role = str(entry.get("role") or "")
            if "messages" not in role:
                continue
            if (dataset_id, repo_path) in measured_files:
                continue
            reason = UNDECODABLE_FORMATS.get(str(entry.get("format")))
            if not reason:
                continue
            if (dataset_id, repo_path) in already:
                # The corpus loop already named this file, with the corpus's own name
                # and a more specific reason. Two rows for one gap reads as two gaps.
                continue
            unavailable.append({
                "dataset": dataset_id,
                "file": repo_path,
                "split": entry.get("rows_split"),
                "row_count_file": entry.get("row_count"),
                "sha256": entry.get("sha256"),
                "revision": entry.get("revision"),
                "license_observed": block.get("license_observed"),
                "license_verified_on": block.get("license_verified_on"),
                "reason": reason,
            })


def main(argv: list[str] | None = None) -> int:
    """Report what would be measured, without measuring it. No network access."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--plan", action="store_true",
                        help="print the corpus plan and provenance as JSON")
    parser.add_argument("--no-write", action="store_true",
                        help="do not write the synthesized .eml files")
    parser.add_argument("--max-messages", type=int, default=DEFAULT_MAX_MESSAGES,
                        help=f"sampling cap (default {DEFAULT_MAX_MESSAGES})")
    args = parser.parse_args(argv)

    plan = build_plan(max_messages=args.max_messages,
                      write_messages=not args.no_write)
    if args.plan:
        printable = {k: v for k, v in plan.items() if k != "_corpora"}
        for corpus in plan["_corpora"].values():
            printable.setdefault("entries_per_corpus", {})[corpus["name"]] = len(
                corpus["entries"]
            )
        print(json.dumps(printable, indent=2, sort_keys=True))
    else:
        print(plan["headline"])
        for name, descriptor in sorted((plan.get("corpora") or {}).items()):
            print(f"  {name}: {descriptor['rows_used']} of {descriptor['rows_in_corpus']} "
                  f"rows, licence {descriptor['license_observed']!r} at revision "
                  f"{str(descriptor['revision'])[:12]}")
        for item in plan.get("unavailable") or []:
            print(f"  not evaluated: {item.get('corpus') or item.get('file') or item.get('dataset')}"
                  f" - {item['reason'][:110]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
