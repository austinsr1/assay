#!/usr/bin/env python3
"""Fetch public evaluation corpora into ``eval/internal/`` - and refuse most of them.

This is the fetching half of the external-corpus harness scoped in
``docs/EVAL-SUITES.md``. It exists because the corpora that could actually settle
"does this detector over-fire" are not committed to this repository and must not be:
`docs/EVAL-SUITES.md` records that most of them are copyleft, non-commercial,
share-alike, or declare no licence at all, and this repository is MIT and destined
for a public listing that scans full git history. So the harness ships a fetcher and
a licence gate, publishes **our numbers**, and commits the provenance of the fetch -
never the data.

**The licence gate is closed, not default-deny-with-warnings.** A dataset may be
fetched only if it appears in ``PERMITTED`` with a licence that was read from the
Hugging Face API's ``cardData.license`` field on the recorded verification date.
Anything absent from that list is refused by name, including ``SetFit/enron_spam``,
which declares no licence at all and is the single most convenient benign set
anyone could reach for. Undeclared does not mean granted. A refused dataset prints
the observed licence value and the reason, and exits non-zero.

The gate re-reads ``cardData.license`` from the API at fetch time and refuses if it
no longer matches the value the allowlist recorded: an upstream project that changes
its licence declaration has changed *our* permission to use it, and that is a
decision for a human to re-take, not something a fetcher may absorb silently. The
licence the *datasets-server* reports for the same dataset (``dataset_info.*.license``)
is also recorded when it differs, because for ``deepset/prompt-injections`` the two
disagree - apache-2.0 in the card, cc-by-4.0 in the converted metadata - and a gate
that looked at one field and quietly ignored the other would be a gate that had
already decided the answer.

Stdlib only, like everything else in this repository: ``urllib.request``,
``hashlib``, ``json``, ``csv``, ``struct``. No ``datasets``, no ``huggingface_hub``,
no ``pandas``. Parquet is fetched and counted (the row count comes out of the file's
own footer metadata, read with a small Thrift-compact field skippers) but it is never
*decoded*: reading text out of dictionary-encoded, snappy-compressed column chunks
would need a column reader this build does not carry, and pretending to write one from
the bottom up is how a decoder gets shipped that reports a plausible row count for
bytes it mis-parsed.

So the text of a Parquet-only corpus arrives by a different road, and the difference is
recorded rather than blurred. ``--rows`` reads the **datasets-server ROWS API**, which
serves JSON rows over plain HTTP: no column decoder, no snappy, no dependency. That
service reads Hugging Face's own *converted* Parquet, which is **not the same object as
the file in the repository** - different bytes, therefore a different digest. Both are
kept and both are named: the sha256 pinned in the manifest is the *repository* file's,
the row retrieval record describes the *conversion service*'s output, and the two are
cross-checked against each other by row count, which is the only comparison that is
legitimate across two different encodings of the same rows. Where the counts disagree,
this tool stops rather than measuring whichever one it likes. See ``eval/external.py``.

Nothing here may write outside ``eval/internal/`` except the provenance record the
operator explicitly names with ``--write-provenance``, which is our own metadata and
is meant to be committed.

Usage::

    python3 eval/fetch.py --list
    python3 eval/fetch.py --dataset microsoft/llmail-inject-challenge
    python3 eval/fetch.py --all
    python3 eval/fetch.py --all --rows   # also fetch JSON rows for the Parquet sets
    python3 eval/fetch.py --dataset leolee99/NotInject --rows
    python3 eval/fetch.py --dataset SetFit/enron_spam      # refused, loudly
    python3 eval/fetch.py --verify                          # offline integrity check
    python3 eval/fetch.py --write-provenance eval/PROVENANCE.json

Exit codes: 0 fetched or verified, 1 refused by the licence gate, 2 integrity or
usage error, 3 network or upstream error.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import pathlib
import posixpath
import struct
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone
from typing import Any, Iterable

REPO = pathlib.Path(__file__).resolve().parents[1]
#: Everything this tool downloads lands here, and this directory is gitignored.
#: There is no other writable location: `_destination()` refuses a path that
#: resolves outside it, and `_guard_write()` re-checks after symlink resolution.
INTERNAL = REPO / "eval" / "internal"
MANIFEST = INTERNAL / "manifest.json"

HF_API = "https://huggingface.co/api/datasets/{dataset}"
HF_RESOLVE = "https://huggingface.co/datasets/{dataset}/resolve/{revision}/{path}"
DS_SERVER_INFO = "https://datasets-server.huggingface.co/info?dataset={dataset}"
HF_TREE = "https://huggingface.co/api/datasets/{dataset}/tree/{revision}?recursive=true"

#: The datasets-server endpoints that serve *rows*, as JSON, over plain HTTP.
#: ``/splits`` is authoritative for what a split is called - these corpora are not
#: ``train``/``test`` uniformly (NotInject's are ``NotInject_one``/``_two``/``_three``),
#: so the names are read from the service and recorded, never guessed from a file name.
DS_SERVER_SPLITS = "https://datasets-server.huggingface.co/splits?dataset={dataset}"
#: ``length`` is capped at 100 by the service, so a split is paginated by ``offset``.
#: Recorded in the manifest with the placeholders intact: that string *is* the
#: reproduction instruction, and a reader with curl and no Python can re-drive the
#: whole retrieval from the artifact alone.
DS_SERVER_ROWS = (
    "https://datasets-server.huggingface.co/rows?dataset={dataset}"
    "&config={config}&split={split}&offset={offset}&length={length}"
)
#: The service's own page cap. Asking for more is not faster: the response comes back
#: with fewer rows than asked for, and a reader takes that for the end of the split.
#: A constant so the pagination loop and the manifest name the same number.
ROWS_PAGE_LENGTH = 100
#: The conversion config the rows are read from. ``default`` for every dataset here,
#: and recorded per split rather than assumed.
ROWS_CONFIG = "default"

#: The ROWS API sits behind CloudFront and throttles bursts with a bare HTTP 429 and no
#: ``Retry-After``. Bounded exponential backoff: a fetcher that sleeps forever reads as
#: a hang, and one that gives up at the first 429 reads as an unavailable dataset.
#: Neither is the truth, so the number of attempts is bounded and a give-up says how
#: many it made.
ROWS_MAX_ATTEMPTS = 7
ROWS_BACKOFF_BASE_SECONDS = 5.0
ROWS_BACKOFF_CAP_SECONDS = 90.0
#: Polite pacing *between* successful pages, independent of the backoff above.
ROWS_PAGE_DELAY_SECONDS = 1.0

#: Sleep, as a module attribute so a test can drive the backoff path without spending
#: a minute of suite time per retry.
_time_sleep = time.sleep

#: The sentence that must travel with every ROWS-API retrieval. It exists because the
#: two digests in the record describe different bytes, and a reader who is not told so
#: will assume they are the same file - which would make the pinned digest look like a
#: verification of text that it never verified.
ROWS_CONVERSION_NOTE = (
    "Two different objects, both recorded. The repository file (sha256 pinned in the "
    "manifest, fetched from the /resolve/ URL at the pinned revision) is the artifact "
    "the licence and that digest describe. The text this harness measured came from the "
    "Hugging Face datasets-server ROWS API, which serves the dataset's own CONVERTED "
    "Parquet: those bytes are produced by Hugging Face's converter, are NOT the "
    "repository file, and do not carry the pinned digest. What survives the distinction "
    "is the row count and the split name, cross-checked between the two objects; what "
    "does not is any claim that the measured text was hash-verified against the "
    "repository file. It was verified against the retrieval recorded beside it."
)

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_ERROR = 2
EXIT_NETWORK = 3

USER_AGENT = "tenable-email-eval-fetch/1 (evaluation harness; stdlib urllib)"


class Refused(Exception):
    """A dataset or file the licence gate will not let through.

    Carries the text meant for the operator: the dataset id, the observed licence
    value, and the reason. A refusal that does not name what it observed is not
    auditable.
    """


class IntegrityError(Exception):
    """A file on disk does not match the digest recorded for the same revision."""


class UpstreamError(Exception):
    """The API or the file could not be reached."""


class RateLimited(UpstreamError):
    """A 429 or a 5xx - the request was refused for a moment, not for good.

    Distinguished from :class:`UpstreamError` because the right response differs: a
    throttle is retried with backoff, an unreachable host is not. Collapsing the two
    either retries a real outage until the operator kills the process, or gives up on a
    corpus that would have arrived on the second attempt - and a give-up that reads as
    "this dataset could not be fetched" is a false finding about the dataset.
    """

    def __init__(self, message: str, *, status: int) -> None:
        super().__init__(message)
        self.status = status


# --------------------------------------------------------------------------
# the allowlist
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FileSpec:
    """One file inside a permitted dataset.

    ``text_field`` and ``label_map`` are read by ``eval/external.py``; they live
    here because the row shape is part of what was verified at source, and a
    fetcher that cannot say what it fetched has no provenance to record.

    ``rows_split`` names the datasets-server split whose rows are this file's
    content, for a corpus that only ships as Parquet. It is declared here, beside
    the file, because the pairing is a fact verified at source: ``NotInject_one``
    is the split of ``data/NotInject_one-00000-of-00001.parquet``. The row counts
    of the two objects are then checked against each other at fetch time, and a
    disagreement stops the measurement rather than quietly choosing one.
    """

    path: str                      # path inside the dataset repository
    role: str                      # what it is for
    fmt: str                       # json | jsonl | csv | parquet | text
    rows: str = "unknown"          # how to count rows: list | dict | lines | csv | parquet-footer
    text_field: str | None = None  # field carrying the message text, if a dict/row
    label_field: str | None = None
    label_map: dict[str, str] = dc_field(default_factory=dict)
    label_default: str | None = None  # project label for an upstream value not in label_map
    default: bool = True            # included in `--dataset <id>` without `--file`
    rows_split: str | None = None   # datasets-server split carrying this file's rows
    note: str = ""

    @property
    def basename(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass(frozen=True)
class DatasetSpec:
    id: str
    slug: str
    license: str               # the value observed in cardData.license
    verified_on: str           # the date it was observed, ISO
    files: tuple[FileSpec, ...]
    why: str                   # what it does for this evaluation
    limits: tuple[str, ...] = ()

    @property
    def api_url(self) -> str:
        return HF_API.format(dataset=self.id)

    def source_url(self, spec: FileSpec, revision: str) -> str:
        return HF_RESOLVE.format(dataset=self.id, revision=revision, path=spec.path)

    def file(self, name: str) -> FileSpec | None:
        for spec in self.files:
            if spec.path == name or spec.basename == name:
                return spec
        return None

    def rows_files(self) -> list[FileSpec]:
        """The files whose rows come from the datasets-server ROWS API.

        Only the default ones: a split not fetched by the file fetch is not measured
        either, so ``--rows`` cannot silently widen the corpus. That is the same
        reason the Bengali validation split is excluded from both halves.
        """
        return [f for f in self.files if f.rows_split and f.default]


#: The closed allowlist. Each licence value below was read from
#: `cardData.license` via the Hugging Face API on the recorded date, and each is
#: re-read at fetch time and compared. Adding a dataset to this table is a licence
#: decision, and belongs in a commit a human reviewed.
PERMITTED: dict[str, DatasetSpec] = {
    "microsoft/llmail-inject-challenge": DatasetSpec(
        id="microsoft/llmail-inject-challenge",
        slug="llmail-inject-challenge",
        license="mit",
        verified_on="2026-11-03",
        why="Real adaptive email attacks, and the only permitted corpus that ships "
            "a purpose-built false-positive set: emails_for_fp_tests.json.",
        limits=(
            "The files under data/ are JSON, not RFC 822 messages. There is no MIME "
            "structure, so no authentication layer to evaluate.",
            "emails_for_fp_tests.json carries no per-row label; the set is benign by "
            "the declaring file's stated purpose, which is recorded as label_source.",
        ),
        files=(
            FileSpec(
                path="data/emails_for_fp_tests.json",
                role="benign-false-positive-test-messages",
                fmt="json", rows="list",
                note="A JSON list of 203 strings shaped "
                     "'Subject of the email: <subj>.   Body: <body>'.",
            ),
            FileSpec(
                path="data/labelled_unique_submissions_phase2.json",
                role="labelled-attack-messages",
                fmt="json", rows="list",
                default=False,
                note="68.6 MB. Permitted by licence but outside the default fetch; "
                     "request it with --file data/labelled_unique_submissions_phase2.json.",
            ),
            FileSpec(path="data/levels_descriptions.json", role="challenge-metadata",
                     fmt="json", rows="dict", default=True,
                     note="Describes the two phases. Not messages; fetched for "
                          "completeness of the MIT set and never evaluated."),
            FileSpec(path="data/objectives_descriptions.json", role="challenge-metadata",
                     fmt="json", rows="dict",
                     note="Attack objectives. Not messages."),
            FileSpec(path="data/scenarios.json", role="challenge-metadata",
                     fmt="json", rows="dict",
                     note="The four scenarios. Not messages."),
            FileSpec(path="data/system_prompt.json", role="challenge-metadata",
                     fmt="json", rows="dict",
                     note="The target system prompt. Not messages."),
            FileSpec(path="README.md", role="dataset-card", fmt="text", rows="none",
                     note="The upstream card: the licence text and the statements "
                          "about what each file is. Kept for attribution."),
        ),
    ),
    "leolee99/NotInject": DatasetSpec(
        id="leolee99/NotInject",
        slug="notinject",
        license="mit",
        verified_on="2026-11-03",
        why="339 benign prompts that contain injection trigger words and are not "
            "injections - the over-defense test at scale, and priority 1 in "
            "docs/EVAL-SUITES.md.",
        limits=(
            "Ships only as Parquet, so its text does not come from the repository "
            "file: the rows are read from the datasets-server ROWS API, which serves "
            "Hugging Face's converted Parquet. The pinned sha256 describes the "
            "repository object, the retrieval record describes the converted one, and "
            "the two are cross-checked by row count and split name - not by digest, "
            "because they are different bytes.",
            "No label column of any kind. The set is benign by the upstream card's "
            "stated purpose - prompts that contain injection trigger words and are not "
            "injections - so it carries zero positives by construction and can only "
            "measure over-defense, never coverage.",
            "The three NotInject_* files are the same bytes as train/validation/test "
            "(identical upstream LFS digests); one of each is fetched.",
        ),
        files=(
            FileSpec(path="data/NotInject_one-00000-of-00001.parquet",
                     role="benign-messages", fmt="parquet", rows="parquet-footer",
                     text_field="prompt", rows_split="NotInject_one",
                     note="Split NotInject_one. Duplicate of train-...parquet upstream. "
                          "Columns prompt / word_list / category; only `prompt` is "
                          "wrapped as message text, the other two are row metadata."),
            FileSpec(path="data/NotInject_two-00000-of-00001.parquet",
                     role="benign-messages", fmt="parquet", rows="parquet-footer",
                     text_field="prompt", rows_split="NotInject_two"),
            FileSpec(path="data/NotInject_three-00000-of-00001.parquet",
                     role="benign-messages", fmt="parquet", rows="parquet-footer",
                     text_field="prompt", rows_split="NotInject_three"),
            FileSpec(path="README.md", role="dataset-card", fmt="text", rows="none",
                     note="The upstream card, kept for attribution."),
        ),
    ),
    "deepset/prompt-injections": DatasetSpec(
        id="deepset/prompt-injections",
        slug="deepset-prompt-injections",
        license="apache-2.0",
        verified_on="2026-11-03",
        why="662 labelled injection/not-injection strings - the named detector's own "
            "training distribution, and the set docs/EVAL-SUITES.md reports at FPR 1.00.",
        limits=(
            "cardData.license says apache-2.0 while the datasets-server conversion "
            "metadata reports cc-by-4.0 for the same dataset. The gate acts on the "
            "card, which is the declaration the upstream author made in the "
            "repository, and records the disagreement in the manifest so a reader "
            "sees it rather than discovering it. That disagreement is NOT resolved by "
            "this corpus being measured: if the converted metadata is the operative "
            "licence, an Apache-2.0 MIT submission still cannot ship derived "
            "artifacts of it, and only the rows came from the converter.",
            "Ships only as Parquet, so its text does not come from the repository "
            "file: the rows are read from the datasets-server ROWS API, which serves "
            "Hugging Face's converted Parquet, and it is that conversion which "
            "declares cc-by-4.0. The pinned sha256 describes the repository object; "
            "the two objects are cross-checked by row count and split name.",
            "Upstream labels are the integers 0 and 1 in the JSON rows. 1 maps to "
            "'hostile' (must not be cleared) and 0 to 'clean' (must not be accused); "
            "1 is not mapped to 'threat', which would assert a credential-harvest "
            "judgement about a text prompt.",
        ),
        files=(
            FileSpec(path="data/train-00000-of-00001-9564e8b05b4757ab.parquet",
                     role="labelled-injection-messages", fmt="parquet",
                     rows="parquet-footer", text_field="text", label_field="label",
                     label_map={"1": "hostile", "0": "clean"},
                     rows_split="train",
                     note="Split train: 546 rows, 203 labelled 1 and 343 labelled 0."),
            FileSpec(path="data/test-00000-of-00001-701d16158af87368.parquet",
                     role="labelled-injection-messages", fmt="parquet",
                     rows="parquet-footer", text_field="text", label_field="label",
                     label_map={"1": "hostile", "0": "clean"},
                     rows_split="test",
                     note="Split test: 116 rows, 60 labelled 1 and 56 labelled 0."),
            FileSpec(path="README.md", role="dataset-card", fmt="text", rows="none"),
        ),
    ),
    "jackhhao/jailbreak-classification": DatasetSpec(
        id="jackhhao/jailbreak-classification",
        slug="jackhhao-jailbreak-classification",
        license="apache-2.0",
        verified_on="2026-11-03",
        why="Labelled jailbreak and benign prompts as CSV, which this build can read "
            "without a column decoder, so it is the permitted corpus that actually "
            "gets evaluated on both sides.",
        limits=(
            "Text aimed at an LLM, not email. No headers, no links, no attachments.",
            "Upstream labels are 'jailbreak' and 'benign'. They map to 'hostile' (must "
            "not be cleared) and 'clean' (must not be accused); 'jailbreak' is not a "
            "claim that the message is a credential phish.",
        ),
        files=(
            FileSpec(path="default/jailbreak_dataset_test.csv",
                     role="labelled-jailbreak-messages", fmt="csv", rows="csv",
                     text_field="prompt", label_field="type",
                     label_map={"jailbreak": "hostile", "benign": "clean"},
                     note="The unbalanced test split: 400 records, 141 jailbreak and "
                          "259 benign, counted with csv.reader rather than by lines "
                          "because the quoted fields contain newlines."),
            FileSpec(path="balanced/jailbreak_dataset_test_balanced.csv",
                     role="labelled-jailbreak-messages", fmt="csv", rows="csv",
                     text_field="prompt", label_field="type",
                     label_map={"jailbreak": "hostile", "benign": "clean"},
                     default=False,
                     note="The balanced variant of the same split. Not fetched by "
                          "default: two files with the same rows counted twice would "
                          "double-weight this corpus in every rate."),
            FileSpec(path="README.md", role="dataset-card", fmt="text", rows="none"),
        ),
    ),
    "shariul-islam/bengali-sms-smishing-dataset": DatasetSpec(
        id="shariul-islam/bengali-sms-smishing-dataset",
        slug="bengali-sms-smishing",
        license="mit",
        verified_on="2026-11-03",
        why="The honest out-of-domain check: real smishing in Bengali, and the only "
            "smishing set in docs/EVAL-SUITES.md that is redistributable.",
        limits=(
            "SMS, not email, and not English. A poor result here is information about "
            "domain transfer, not about the pipeline's email behaviour, and a good one "
            "is not evidence about phishing either.",
            "Ships only as Parquet, so its text does not come from the repository "
            "file: the rows are read from the datasets-server ROWS API, which serves "
            "Hugging Face's converted Parquet. The pinned sha256 describes the "
            "repository object and the two are cross-checked by row count.",
            "Upstream labels are 'smish', 'normal' and 'promo'. 'smish' maps to "
            "'hostile'; 'normal' and 'promo' map to 'clean' by the corpus default, "
            "which reads a promotional SMS as 'must not be accused' rather than as a "
            "legitimate business email - a weaker claim than llmail-fp-tests makes, and "
            "recorded as the corpus's own label_source.",
        ),
        files=(
            FileSpec(path="data/test-00000-of-00001.parquet",
                     role="labelled-smishing-messages", fmt="parquet",
                     rows="parquet-footer", text_field="text", label_field="label",
                     label_map={"smish": "hostile"}, label_default="clean",
                     rows_split="test",
                     note="Split test, 1,401 rows. The held-out split; train (4,903) "
                          "and validation (701) exist upstream and are not fetched."),
            FileSpec(path="data/validation-00000-of-00001.parquet",
                     role="labelled-smishing-messages", fmt="parquet",
                     rows="parquet-footer", default=False,
                     note="Not fetched by default: the test split is the held-out one, "
                          "and measuring two splits of the same corpus as if they were "
                          "two independent results would inflate coverage."),
            FileSpec(path="README.md", role="dataset-card", fmt="text", rows="none"),
        ),
    ),
}

#: Refused by the gate, with the licence value observed on the verification date.
#: The text here is what the tool prints; it is written to be quoted in a report.
REFUSED: dict[str, dict[str, str]] = {
    "SetFit/enron_spam": {
        "license": "None",
        "observed_field": "cardData.license",
        "verified_on": "2026-11-03",
        "reason": "No licence is declared. Undeclared does not mean granted: we have "
                  "no permission to redistribute or to ship derived artifacts, so the "
                  "set is refused even though it is the most convenient benign "
                  "English-email corpus available and every other survey in "
                  "docs/EVAL-SUITES.md used it.",
    },
    "zefang-liu/phishing-email-dataset": {
        "license": "lgpl-3.0",
        "observed_field": "cardData.license",
        "verified_on": "2026-11-03",
        "reason": "LGPL-3.0 is copyleft. This repository is MIT and is destined for a "
                  "public listing, so an LGPL corpus cannot be folded into the "
                  "submission's artifacts. Refused on licence, not on quality.",
    },
}

#: Refused by default, permitted only behind --allow-sharealike.
SHAREALIKE: dict[str, dict[str, Any]] = {
    "geodesic-research/bipia": {
        "license": "cc-by-sa-4.0",
        "observed_field": "cardData.license",
        "verified_on": "2026-11-03",
        "reason": "CC-BY-SA-4.0 is share-alike: a derivative of BIPIA must be licensed "
                  "under the same terms, which is incompatible with shipping an MIT "
                  "submission that includes it.",
        "slug": "bipia",
        "files": (
            FileSpec(path="bipia/_provenance.json", role="provenance-metadata",
                     fmt="json", rows="dict"),
            FileSpec(path="bipia/train-00000-of-00001.parquet",
                     role="labelled-injection-messages", fmt="parquet",
                     rows="parquet-footer"),
            FileSpec(path="README.md", role="dataset-card", fmt="text", rows="none"),
        ),
    },
}

#: Named, recorded, and never fetchable. These exist in the upstream repository and
#: are deliberately absent from every allowlisted file set, so a request for one is
#: refused by name rather than silently fetching nothing. The reason is size *and*
#: policy: 1.67 GB and 263 MB of raw challenge submissions, whose labelled, evaluated
#: half is already offered as `labelled_unique_submissions_phase2.json`.
FORBIDDEN_FILES: dict[str, str] = {
    "data/raw_submissions_phase1.jsonl":
        "1.67 GB of raw challenge submissions; not part of any allowlisted file set",
    "data/raw_submissions_phase2.jsonl":
        "263 MB of raw challenge submissions; not part of any allowlisted file set",
}

SHAREALIKE_NOTICE = """\
--allow-sharealike was given, so the gate is standing aside for \
{dataset}, whose declared licence is {license} ({reason}).

Read what that means before the numbers are used anywhere. Share-alike obliges \
derivatives to carry the same licence. This repository is MIT and is submitted to \
a public exchange, so the obligation cannot be discharged inside the submission - \
it can only be accepted or declined by the person who owns the submission. That is \
the operator, not this tool. The tool's job here is to make the decision visible: \
what was accepted, on what date, on which observed licence value, and that a \
downstream artifact derived from these rows may inherit CC-BY-SA.

Nothing fetched under this flag is committed - only its provenance - which is why \
the flag can exist at all. A corpus that had to be committed to be used could not \
be permitted by a command-line flag, and a flag that could grant that would not be \
a gate.
"""


# --------------------------------------------------------------------------
# small HTTP helpers
# --------------------------------------------------------------------------


def _get(url: str, *, timeout: int = 60) -> bytes:
    """Fetch a URL in bounded chunks. Stdlib only, no third-party client."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            buffer = io.BytesIO()
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                buffer.write(chunk)
            return buffer.getvalue()
    except urllib.error.HTTPError as exc:
        if exc.code in (429, 500, 502, 503, 504):
            raise RateLimited(f"HTTP {exc.code} for {url}", status=exc.code) from exc
        raise UpstreamError(f"HTTP {exc.code} for {url}") from exc
    except Exception as exc:  # URLError, socket timeout, DNS, TLS
        raise UpstreamError(f"{type(exc).__name__}: {exc} for {url}") from exc


def _get_json_backoff(url: str, *, attempts: int = ROWS_MAX_ATTEMPTS,
                      timeout: int = 60) -> dict:
    """``_get_json`` with bounded exponential backoff on a throttle.

    Attempts are recorded so the artifact can distinguish "retrieved on the first try"
    from "retrieved on the sixth": a corpus whose rows arrived after four 429s is the
    same corpus, but a reader debugging a failed re-run wants to know the service was
    already unhappy here.
    """
    last_status = "none"
    for attempt in range(attempts):
        try:
            return _get_json(url, timeout=timeout)
        except RateLimited as exc:
            last_status = exc.status
            if attempt + 1 >= attempts:
                break
            delay = min(ROWS_BACKOFF_CAP_SECONDS,
                        ROWS_BACKOFF_BASE_SECONDS * (2 ** attempt))
            print(f"    throttled (HTTP {exc.status}); retry {attempt + 1} of "
                  f"{attempts - 1} in {delay:.0f}s")
            _time_sleep(delay)
    raise UpstreamError(
        f"{url}: still refused after {attempts} attempts (last status {last_status}). "
        "This is recorded as a split that could not be retrieved, not as one with zero "
        "rows."
    )


def _get_json(url: str, *, timeout: int = 60) -> dict:
    raw = _get(url, timeout=timeout)
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError as exc:
        raise UpstreamError(f"{url} is not JSON: {exc}") from exc


def observe_license(dataset_id: str) -> dict[str, Any]:
    """Read the licence declaration and current revision straight from the API.

    Returns the observed ``cardData.license``, the repo ``sha`` used as the pinned
    revision, and the datasets-server licence when it is present and different. The
    gate compares the card value against the allowlist and records the second value
    rather than discarding a disagreement.
    """
    meta = _get_json(HF_API.format(dataset=dataset_id))
    card = meta.get("cardData") or {}
    out: dict[str, Any] = {
        "card_license": card.get("license"),
        "revision": meta.get("sha"),
        "gated": meta.get("gated"),
        "private": meta.get("private"),
    }
    try:
        info = _get_json(DS_SERVER_INFO.format(dataset=dataset_id))
        licenses = sorted({
            str(v.get("license"))
            for v in (info.get("dataset_info") or {}).values()
            if isinstance(v, dict) and v.get("license")
        })
        if licenses:
            out["datasets_server_licenses"] = licenses
    except UpstreamError:
        out["datasets_server_licenses"] = ["UNAVAILABLE"]
    return out


# --------------------------------------------------------------------------
# row counting, including the parquet footer
# --------------------------------------------------------------------------


def repo_tree(dataset_id: str, revision: str) -> dict[str, dict[str, Any]]:
    """Upstream's own record of every file at the pinned revision.

    Used for two cross-checks the fetcher does not perform on itself: the byte size
    the repository reports for the path, and - for LFS-stored files - the sha256 it
    holds as the object id. Where an oid is present it is an independent digest of
    the same bytes, so agreement means the file we computed a digest for is the file
    upstream says that revision contains. Absent is not a failure: a plain git blob
    is recorded by blob sha1, not by content sha256.
    """
    try:
        entries = _get_json(HF_TREE.format(dataset=dataset_id, revision=revision))
    except UpstreamError:
        return {}
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(entries, list):
        return {}
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") != "file":
            continue
        out[str(entry.get("path"))] = {
            "size": entry.get("size"),
            "lfs_sha256": (entry.get("lfs") or {}).get("oid"),
        }
    return out


class _ThriftSkipper:
    """Skip fields of a Thrift compact-protocol struct.

    Parquet's footer is one ``FileMetaData`` struct in compact protocol, and its
    ``num_rows`` field is what this tool needs - nothing else. A full reader is not
    wanted, and 86.6 MB of pyarrow is not available and would not be shipped here.

    Kept deliberately small and total: it walks field headers, tracks the
    delta-encoded field id, and consumes exactly the bytes each type occupies. An
    unhandled type raises rather than guessing, because a guessed offset would
    report a row count for a file this code did not actually read.
    """

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def _byte(self) -> int:
        if self.pos >= len(self.data):
            raise IntegrityError("truncated Thrift compact stream in the parquet footer")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def _varint(self) -> int:
        shift = 0
        result = 0
        while True:
            b = self._byte()
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                return result
            shift += 7
            if shift > 63:
                raise IntegrityError("varint overflow in the parquet footer")

    def _zigzag(self) -> int:
        n = self._varint()
        return (n >> 1) ^ -(n & 1)

    def _take(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise IntegrityError("length field runs past the parquet footer")
        chunk = self.data[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def skip_value(self, type_id: int) -> None:
        if type_id in (1, 2):          # TRUE / FALSE: carried in the field header
            return
        if type_id == 3:               # BYTE
            self._byte()
        elif type_id in (4, 5, 6):     # I16 / I32 / I64
            self._varint()
        elif type_id == 7:             # DOUBLE
            self._take(8)
        elif type_id == 8:             # BINARY / UTF8
            self._take(self._varint())
        elif type_id in (9, 10):       # LIST / SET
            header = self._byte()
            size = (header >> 4) & 0x0F
            element_type = header & 0x0F
            if size == 0x0F:
                size = self._varint()
            for _ in range(size):
                self.skip_value(element_type)
        elif type_id == 11:            # MAP
            size = self._varint()
            if size == 0:
                self._byte()           # the single 0 byte that encodes an empty map
                return
            types = self._byte()
            key_type = (types >> 4) & 0x0F
            value_type = types & 0x0F
            for _ in range(size):
                self.skip_value(key_type)
                self.skip_value(value_type)
        elif type_id == 12:            # STRUCT
            self.skip_struct()
        else:
            raise IntegrityError(f"unknown Thrift compact type {type_id} in footer")

    def skip_struct(self) -> None:
        while True:
            header = self._byte()
            if header == 0:
                return
            delta = (header >> 4) & 0x0F
            if delta == 0:
                self._zigzag()         # explicit field id
            self.skip_value(header & 0x0F)

    def top_level_i64(self, wanted_field: int) -> int | None:
        """The value of one i64 field of the outermost struct, by field id."""
        field_id = 0
        while True:
            header = self._byte()
            if header == 0:
                return None
            delta = (header >> 4) & 0x0F
            type_id = header & 0x0F
            field_id = field_id + delta if delta else self._zigzag()
            if field_id == wanted_field and type_id == 6:
                return self._zigzag()
            self.skip_value(type_id)


def parquet_num_rows(data: bytes) -> int | None:
    """Rows in a Parquet file, read from its footer metadata.

    Layout: magic, column data, footer (Thrift compact ``FileMetaData``), 4-byte
    little-endian footer length, magic. ``FileMetaData`` field 3 is ``num_rows``.
    """
    if len(data) < 12 or data[:4] != b"PAR1" or data[-4:] != b"PAR1":
        return None
    footer_length = struct.unpack("<I", data[-8:-4])[0]
    if footer_length <= 0 or footer_length > len(data) - 8:
        return None
    footer = data[-8 - footer_length:-8]
    return _ThriftSkipper(footer).top_level_i64(3)


def count_rows(data: bytes, method: str, fmt: str) -> tuple[int | None, str]:
    """Row count plus the method that produced it, so the manifest is checkable.

    ``None`` is a real answer and not a zero: a text file has no rows, and a format
    this tool cannot parse must say so instead of reporting an empty corpus.
    """
    if method == "none":
        return None, "not a row-bearing file (dataset card / prose)"
    try:
        if fmt == "json":
            loaded = json.loads(data.decode("utf-8", "replace"))
            if method == "list" and isinstance(loaded, list):
                return len(loaded), f"len() of the decoded JSON list ({method})"
            if method == "dict" and isinstance(loaded, dict):
                return len(loaded), f"len() of the decoded JSON object ({method})"
            if isinstance(loaded, list):
                return len(loaded), "len() of the decoded JSON list"
            if isinstance(loaded, dict):
                return len(loaded), "len() of the decoded JSON object"
            return None, "decoded JSON is a scalar, which has no rows"
        if fmt == "jsonl":
            return (
                sum(1 for line in data.splitlines() if line.strip()),
                "count of non-empty lines",
            )
        if fmt == "csv":
            text = data.decode("utf-8", "replace")
            reader = csv.reader(io.StringIO(text))
            rows = sum(1 for _ in reader)
            # The header is a record but not a row.
            return (max(rows - 1, 0),
                    "csv.reader records minus the header line (quoted fields may "
                    "contain newlines, so this is not a line count)")
        if fmt == "parquet":
            rows = parquet_num_rows(data)
            return (rows,
                    "Parquet FileMetaData num_rows (footer field 3, Thrift compact)"
                    if rows is not None else "not a readable Parquet file")
    except (ValueError, IntegrityError) as exc:
        return None, f"not determinable: {exc}"
    return None, f"not determinable for format {fmt!r}"


# --------------------------------------------------------------------------
# the gate
# --------------------------------------------------------------------------


def gate(dataset_id: str, *, allow_sharealike: bool = False) -> tuple[DatasetSpec | None, str]:
    """Decide whether a dataset may be fetched, without touching the network.

    Returns ``(spec, "")`` when permitted and ``(None, refusal_text)`` otherwise.
    Split out from the fetch so the decision is testable on a machine with no
    network, which is what a licence gate is for.
    """
    spec = PERMITTED.get(dataset_id)
    if spec is not None:
        return spec, ""

    for table, kind in ((REFUSED, "refused"), (SHAREALIKE, "share-alike")):
        entry = table.get(dataset_id)
        if entry is not None:
            if kind == "share-alike" and allow_sharealike:
                spec = DatasetSpec(
                    id=dataset_id, slug=entry["slug"], license=entry["license"],
                    verified_on=entry["verified_on"],
                    why="Fetched under --allow-sharealike. See the notice printed at "
                        "fetch time: share-alike inheritance is the operator's "
                        "decision, and accepting it is not the same as being granted it.",
                    limits=(entry["reason"],),
                    files=tuple(entry["files"]),
                )
                return spec, ""
            return None, (
                f"REFUSED: {dataset_id}\n"
                f"  observed licence ({entry['observed_field']}): "
                f"{entry['license']!r} as read on {entry['verified_on']}\n"
                f"  reason: {entry['reason']}"
            )

    return None, (
        f"REFUSED: {dataset_id} is not on the allowlist.\n"
        "  The list in eval/fetch.py is closed, so an unlisted dataset is refused "
        "rather than fetched with a warning: a default-deny that still downloads is "
        "not a gate, and the licence of anything absent was never verified here.\n"
        f"  Allowlisted: {', '.join(sorted(PERMITTED))}"
    )


def license_drift(spec: DatasetSpec, observed: str | None) -> str:
    """Text explaining a licence value that no longer matches the allowlist."""
    return (
        f"REFUSED: {spec.id} declares licence "
        f"{observed!r} in cardData.license as read today, which is not the "
        f"{spec.license!r} recorded in eval/fetch.py on {spec.verified_on}.\n"
        "  A licence that moved upstream is a permission that moved, so this is not "
        "re-fetched on the strength of a flag. Re-read the declaration, then change "
        "the table in a reviewed commit."
    )


# --------------------------------------------------------------------------
# writing, with the containment check that keeps it inside eval/internal/
# --------------------------------------------------------------------------


def _slug_filename(spec: FileSpec) -> str:
    return spec.basename


def destination(spec_dataset: DatasetSpec, spec_file: FileSpec) -> pathlib.Path:
    """The path a fetched file will occupy, guarded to stay inside ``INTERNAL``.

    The repo path is normalized-checked rather than merely basename-sliced. Taking the
    basename silently turns ``data/../../evil.json`` into ``evil.json`` - still inside,
    but a path with traversal in it has been *accepted*, and two upstream paths that
    differ only in that prefix would then quietly overwrite each other. Refusing is
    the honest answer, and it is what makes the basename assumption safe.
    """
    name = spec_file.basename
    normalized = posixpath.normpath(spec_file.path)
    if (
        not name
        or "/" in name
        or "\\" in name
        or ".." in spec_file.path.split("/")
        or normalized != spec_file.path
    ):
        raise IntegrityError(
            f"unsafe upstream repo path for {spec_dataset.id}: {spec_file.path!r} "
            f"(normalized: {normalized!r})"
        )
    target = (INTERNAL / spec_dataset.slug / name)
    resolved = target.resolve()
    if INTERNAL.resolve() not in resolved.parents:
        raise IntegrityError(f"destination escapes {INTERNAL}: {target}")
    return target


def _guard_write(path: pathlib.Path) -> None:
    """Refuse a write that would land outside ``eval/internal/``.

    Checked after symlink resolution as well as lexically: ``eval/internal`` is
    gitignored, and a link out of it would put downloaded bytes where a future
    ``git add -A`` could find them.
    """
    resolved = path.resolve()
    root = INTERNAL.resolve()
    if root not in resolved.parents and resolved != root:
        raise IntegrityError(
            f"refusing to write outside {INTERNAL}: {path} resolves to {resolved}"
        )


def _relative(path: pathlib.Path) -> str:
    """Repo-relative text for a path.

    Problem strings from this module can end up inside `eval/metrics.json`, which a
    test scans for absolute home-directory paths because the artifact is published.
    An absolute path here would be a leak created by the guard itself.
    """
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return str(path)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# the manifest
# --------------------------------------------------------------------------


def load_manifest() -> dict[str, Any]:
    if not MANIFEST.is_file():
        return {"schema_version": 1, "datasets": {}}
    try:
        loaded = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise IntegrityError(f"{MANIFEST} is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict) or "datasets" not in loaded:
        raise IntegrityError(f"{MANIFEST} has no 'datasets' object")
    return loaded


def save_manifest(manifest: dict[str, Any]) -> None:
    _guard_write(MANIFEST)
    INTERNAL.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def file_entry(manifest: dict[str, Any], dataset_id: str, repo_path: str) -> dict | None:
    return (
        manifest.get("datasets", {}).get(dataset_id, {}).get("files", {}).get(repo_path)
    )


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------


def _record_dataset(manifest: dict, spec: DatasetSpec, observed: dict) -> dict:
    """Refresh the dataset-level *declaration* block and return it.

    Split out of ``_record`` so a run in which every file was already on disk still
    refreshes what the table says the dataset means - its limits, the licence value read
    today, the datasets-server licences. A no-op fetch that left a stale
    ``license_limits`` behind would publish a provenance record stating a limitation the
    code no longer has. Nothing byte-shaped moves here: the revision, sha256 and byte
    counts live on the file entries, which ``fetch_file`` guards separately.
    """
    dataset_block = manifest["datasets"].setdefault(spec.id, {})
    dataset_block.update({
        "dataset": spec.id,
        "slug": spec.slug,
        "license_observed": spec.license,
        "license_field": "cardData.license",
        "license_verified_on": spec.verified_on,
        "license_observed_at_fetch": observed.get("card_license"),
        "datasets_server_licenses": observed.get("datasets_server_licenses", []),
        "revision": observed.get("revision"),
        "revision_source": f"{HF_API.format(dataset=spec.id)} field 'sha'",
        "api_url": HF_API.format(dataset=spec.id),
        "gated": observed.get("gated"),
        "private": observed.get("private"),
    })
    if spec.limits:
        dataset_block["license_limits"] = list(spec.limits)
    dataset_block.setdefault("files", {})
    return dataset_block


def _record(manifest: dict, spec: DatasetSpec, observed: dict, file_entry_body: dict,
            repo_path: str) -> None:
    dataset_block = _record_dataset(manifest, spec, observed)
    dataset_block["files"][repo_path] = file_entry_body


def _record_rows(manifest: dict, spec: DatasetSpec, record: dict, split: str) -> None:
    """Attach one row-retrieval record to its dataset block.

    Kept beside ``files`` rather than merged into it: the two describe different
    objects, and a single ``files`` table would force one of them to look like the
    other - which is exactly the ambiguity the conversion note exists to prevent.
    """
    dataset_block = manifest["datasets"].setdefault(spec.id, {})
    dataset_block["rows_source_note"] = ROWS_CONVERSION_NOTE
    dataset_block.setdefault("rows", {})[split] = record


def fetch_file(spec: DatasetSpec, file_spec: FileSpec, revision: str,
               observed: dict, manifest: dict, *, force: bool = False,
               tree: dict[str, dict] | None = None) -> dict:
    """Download one allowlisted file, or confirm the copy already present is it.

    Idempotent: a file already on disk with the digest the manifest recorded for
    the same revision is a no-op and is not re-downloaded. A file on disk whose
    digest does not match what the manifest recorded for the *same* revision is a
    loud failure - that is corruption or substitution, and overwriting it would
    hide which.
    """
    target = destination(spec, file_spec)
    _guard_write(target)
    entry = file_entry(manifest, spec.id, file_spec.path)
    on_disk = target.is_file()

    if entry and entry.get("revision") == revision and on_disk:
        recorded = entry.get("sha256")
        actual = sha256_file(target)
        if actual == recorded:
            refreshed = _refresh_declaration(entry, file_spec)
            print(f"  = {file_spec.path}: already present and matching "
                  f"({entry.get('bytes')} bytes, sha256 {recorded[:12]}...), no fetch")
            for field in refreshed:
                print(f"      ~ manifest field {field!r} refreshed to match "
                      "eval/fetch.py's declaration; the bytes and the digest did not "
                      "move")
            return entry
        if not force:
            raise IntegrityError(
                f"{_relative(target)} does not match the digest recorded for revision "
                f"{revision} of {spec.id}: manifest says {recorded}, the file is "
                f"{actual}.\n"
                "  Refusing to overwrite. Either the file was modified in place or "
                "the manifest is wrong about it. Check which with "
                "`python3 eval/fetch.py --verify`; --force replaces the record with "
                "what is on disk after re-downloading."
            )

    data = _get(spec.source_url(file_spec, revision))
    digest = sha256_bytes(data)
    rows, rows_method = count_rows(data, file_spec.rows, file_spec.fmt)

    upstream = (tree or {}).get(file_spec.path) or {}
    recorded_size = upstream.get("size")
    if isinstance(recorded_size, int) and recorded_size != len(data):
        raise IntegrityError(
            f"{file_spec.path} at revision {revision}: the repository lists "
            f"{recorded_size} bytes and served {len(data)}"
        )
    lfs_digest = upstream.get("lfs_sha256")
    if lfs_digest and lfs_digest != digest:
        raise IntegrityError(
            f"{file_spec.path}: the sha256 computed from the bytes served "
            f"({digest}) is not the object id the repository records for it "
            f"({lfs_digest}). One of the two is wrong about this revision, and an "
            "evaluation must not be built on which."
        )

    if on_disk and entry is None:
        # A copy someone put there by hand, with no manifest entry to vouch for it.
        existing = sha256_file(target)
        if existing != digest and not force:
            raise IntegrityError(
                f"{_relative(target)} exists but is not what {spec.id}@{revision} serves: "
                f"on disk {existing}, upstream {digest}. Refusing to overwrite a "
                "file whose provenance this tool does not hold; delete it or pass "
                "--force."
            )

    _guard_write(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "dataset": spec.id,
        "repo_path": file_spec.path,
        "local_path": str(target.relative_to(REPO)),
        "source_url": spec.source_url(file_spec, revision),
        "revision": revision,
        "license_observed": spec.license,
        "license_verified_on": spec.verified_on,
        "bytes": len(data),
        "sha256": digest,
        "upstream_size_at_revision": recorded_size,
        "upstream_lfs_sha256": lfs_digest,
        # None, not False, when the file is a plain git blob: "no upstream sha256 to
        # compare against" and "upstream disagrees with us" are opposite facts, and a
        # reader scanning this column for False would see six disagreements that are
        # really six non-LFS files. A mismatch raises, so True/None is the whole range.
        "upstream_digest_match": (lfs_digest == digest) if lfs_digest else None,
        "row_count": rows,
        "row_count_method": rows_method,
        "format": file_spec.fmt,
        "role": file_spec.role,
        "text_field": file_spec.text_field,
        "label_field": file_spec.label_field,
        "label_map": dict(file_spec.label_map),
        "label_default": file_spec.label_default,
        "rows_split": file_spec.rows_split,
        "note": file_spec.note,
        "fetched_at": now_iso(),
    }
    if rows is None and file_spec.role.endswith("messages"):
        body["status"] = "fetched-but-undecoded"
    # Write the file before the manifest: a manifest describing bytes that are not
    # there would be worse than the reverse, and --verify reports the latter.
    target.write_bytes(data)
    _record(manifest, spec, observed, body, file_spec.path)
    print(f"  + {file_spec.path}: {len(data)} bytes, sha256 {digest[:12]}..., "
          f"rows {rows if rows is not None else 'n/a'}")
    return body


def _refresh_declaration(entry: dict, file_spec: FileSpec) -> list[str]:
    """Bring a cached manifest entry's *declaration* fields in line with the table.

    The digest, revision and byte count are a record of bytes and are never touched
    here; ``text_field``, ``label_field``, ``label_map``, ``label_default``,
    ``rows_split``, ``role``, ``format`` and ``note`` are a record of what the table says
    those bytes mean, and the table is edited in commits while the manifest is not.
    Without this, a corpus whose text column was declared after its file was pinned
    would carry a manifest entry saying the column is unknown - the state that made a
    well-founded consistency check fire on perfectly good data.
    """
    declared = {
        "text_field": file_spec.text_field,
        "label_field": file_spec.label_field,
        "label_map": dict(file_spec.label_map),
        "label_default": file_spec.label_default,
        "rows_split": file_spec.rows_split,
        "role": file_spec.role,
        "format": file_spec.fmt,
        "note": file_spec.note,
    }
    changed = []
    for field, value in declared.items():
        if entry.get(field) != value:
            entry[field] = value
            changed.append(field)
    return changed


def choose_files(spec: DatasetSpec, files: Iterable[str] | None = None) -> list[FileSpec]:
    """Which files of a permitted dataset a fetch will write. No network, no disk.

    Split out because the file-scope decision is the part a test must be able to
    exercise: the 1.67 GB raw-submission file is refused by name here, and the only way
    to prove that without downloading 1.67 GB is to call the chooser directly.
    """
    if not files:
        return [f for f in spec.files if f.default]
    chosen: list[FileSpec] = []
    for name in files:
        short = name.rsplit("/", 1)[-1]
        if name in FORBIDDEN_FILES or short in FORBIDDEN_FILES:
            raise Refused(
                "REFUSED by file scope: " + name + " - "
                + FORBIDDEN_FILES.get(name, FORBIDDEN_FILES.get(short, ""))
            )
        found = spec.file(name)
        if found is None:
            raise IntegrityError(
                f"{name} is not in the allowlisted file set for {spec.id}: "
                f"{', '.join(f.path for f in spec.files)}"
            )
        chosen.append(found)
    return chosen


def prepare(dataset_id: str, *, allow_sharealike: bool = False
            ) -> tuple[DatasetSpec, dict, str]:
    """Gate, re-read the licence, and pin the revision. The whole permission decision.

    Split out of ``fetch()`` because the rows path is a second way of getting at the
    same corpora, and it must pass the same gate - same allowlist, same re-read of
    ``cardData.license``, same refusal of a gated or private repository, same pinned
    revision recorded. A second entry point that re-implemented the permission check is
    a second permission check to get wrong, and a rows reader that skipped it would make
    the licence gate advisory.
    """
    spec, refusal = gate(dataset_id, allow_sharealike=allow_sharealike)
    if spec is None:
        raise Refused(refusal)

    if spec.id in SHAREALIKE:
        entry = SHAREALIKE[spec.id]
        print(SHAREALIKE_NOTICE.format(
            dataset=spec.id, license=entry["license"], reason=entry["reason"]))

    observed = observe_license(spec.id)
    current = observed.get("card_license")
    if str(current) != str(spec.license):
        raise Refused(license_drift(spec, current))
    if observed.get("gated"):
        raise Refused(
            f"REFUSED: {spec.id} is gated ({observed['gated']}); access is granted "
            "per-account and this harness has no account, so it cannot fetch it."
        )
    if observed.get("private"):
        raise Refused(f"REFUSED: {spec.id} is private.")

    revision = observed.get("revision")
    if not revision:
        raise UpstreamError(f"the API returned no 'sha' for {spec.id}")

    print(f"{spec.id} @ {revision} (licence {current!r}, verified {spec.verified_on})")
    return spec, observed, revision


def fetch(dataset_id: str, *, files: Iterable[str] | None = None,
          allow_sharealike: bool = False, force: bool = False) -> dict:
    """Fetch every default file of one allowlisted dataset. Raises ``Refused``."""
    spec, observed, revision = prepare(dataset_id, allow_sharealike=allow_sharealike)

    manifest = load_manifest()
    _record_dataset(manifest, spec, observed)
    wanted = choose_files(spec, files)

    written = []
    tree = repo_tree(spec.id, revision)
    for file_spec in wanted:
        written.append(fetch_file(spec, file_spec, revision, observed, manifest,
                                  force=force, tree=tree))
    save_manifest(manifest)
    return {"dataset": spec.id, "revision": revision, "files": written}


# --------------------------------------------------------------------------
# rows, from the datasets-server conversion service
#
# This is how a Parquet-only corpus gets measured without this build growing a column
# decoder: the service reads Hugging Face's converted Parquet and answers in JSON, so
# the stdlib's own ``json`` module is the whole dependency. What it costs is stated by
# ``ROWS_CONVERSION_NOTE`` and recorded in every retrieval: the bytes are not the
# repository file, and the pinned digest does not describe them.
# --------------------------------------------------------------------------


def splits_from_api(dataset_id: str, *, config: str = ROWS_CONFIG) -> list[str]:
    """The split names the service reports for one dataset, in the order it reports them.

    The names come from here and never from a filename: NotInject's are
    ``NotInject_one``/``_two``/``_three``, not ``train``/``validation``/``test``, and a
    fetcher that guessed would have asked the API for splits that do not exist and read
    the empty answer as an empty corpus. An empty or malformed response is therefore an
    error, not zero rows.
    """
    payload = _get_json_backoff(DS_SERVER_SPLITS.format(dataset=dataset_id))
    if not isinstance(payload, dict) or not isinstance(payload.get("splits"), list):
        raise UpstreamError(
            f"{DS_SERVER_SPLITS.format(dataset=dataset_id)} returned no `splits` list "
            f"(keys: {sorted(payload) if isinstance(payload, dict) else type(payload).__name__})"
        )
    names: list[str] = []
    for entry in payload["splits"]:
        if not isinstance(entry, dict):
            raise UpstreamError(f"a split entry is not an object: {entry!r:.120}")
        if str(entry.get("config")) == config and entry.get("split"):
            names.append(str(entry["split"]))
    if not names:
        raise UpstreamError(
            f"{dataset_id} reports no split under config {config!r}; it has "
            f"{sorted({str(e.get('config')) for e in payload['splits'] if isinstance(e, dict)})}"
        )
    return names


def rows_destination(dataset_slug: str, split: str) -> pathlib.Path:
    """``eval/internal/<slug>/rows/<split>.json``, under the same guard as a fetched file.

    The split name is part of a filename, so it is checked as one: the API's own text
    is what lands here, and a name with a separator in it would move the write outside
    the dataset's directory. Split names are simple in practice - and "in practice" is
    not what a write guard is for.
    """
    if not split or split in (".", "..") or not posixpath.normpath(split) == split \
            or "/" in split or "\\" in split or ".." in split:
        raise IntegrityError(f"unsafe split name for a row cache path: {split!r}")
    target = INTERNAL / dataset_slug / "rows" / f"{split}.json"
    resolved = target.resolve()
    if INTERNAL.resolve() not in resolved.parents:
        raise IntegrityError(f"row cache path escapes {INTERNAL}: {target}")
    _guard_write(resolved)
    return target


def _validate_rows_shape(payload: dict, url: str) -> tuple[int, list[dict]]:
    """Pull (num_rows_total, rows) out of one page, or say what the service returned.

    A response that lacks ``num_rows_total`` is refused rather than defaulted: a
    retrieval that cannot state the total it was given has no way to notice that a page
    went missing, and a corpus missing a page is a smaller corpus reported as the same
    one.
    """
    if not isinstance(payload, dict):
        raise UpstreamError(f"{url} returned {type(payload).__name__}, not an object")
    total = payload.get("num_rows_total")
    if not isinstance(total, int) or total < 0:
        raise UpstreamError(f"{url} reported no usable `num_rows_total`: {total!r}")
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise UpstreamError(f"{url} reported no `rows` list")
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get("row"), dict):
            raise UpstreamError(f"{url} returned a row that is not an object: {item!r:.120}")
    return total, rows


def fetch_split(spec: DatasetSpec, file_spec: FileSpec, revision: str, observed: dict,
                manifest: dict, *, force: bool = False, timeout: int = 60) -> dict:
    """Retrieve one split's rows as JSON, cache them, and pin the cache.

    The retrieval is complete or it is an error: the loop runs until it holds
    ``num_rows_total`` rows, the service's own claim about the size of the split is
    re-read on every page and a change mid-retrieval aborts (a split that resizes while
    being paginated cannot be described by one count), and the count finally cached is
    cross-checked against the row count read out of the pinned repository file's own
    footer. Idempotent like ``fetch_file``: a cache with the digest the manifest
    recorded for the same revision is not re-downloaded.
    """
    split = file_spec.rows_split
    if not split:
        raise IntegrityError(f"{file_spec.path} declares no rows_split")
    reported = splits_from_api(spec.id)
    if split not in reported:
        raise IntegrityError(
            f"{spec.id} does not report a split named {split!r}; the service lists "
            f"{reported} for config {ROWS_CONFIG!r}. The declared name is stale, and a "
            "stale split name is a corpus that silently stops being fetched - so this "
            "stops here rather than requesting a split that is not there."
        )
    target = rows_destination(spec.slug, split)

    entry = (manifest.get("datasets", {}).get(spec.id, {}) or {}).get("rows", {}) \
        .get(split)
    pinned = file_entry(manifest, spec.id, file_spec.path)
    on_disk = target.is_file()
    if entry and entry.get("revision") == revision and on_disk:
        recorded = entry.get("sha256")
        actual = sha256_file(target)
        if actual == recorded:
            print(f"  = rows {split}: already cached and matching "
                  f"({entry.get('rows_retrieved')} rows, sha256 {recorded[:12]}...), "
                  "no retrieval")
            return entry
        if not force:
            raise IntegrityError(
                f"{_relative(target)} does not match the row-retrieval digest recorded "
                f"for revision {revision} of {spec.id}: manifest says {recorded}, the "
                f"cache is {actual}. Refusing to overwrite a cache whose provenance "
                "this tool does not hold; re-run with --force."
            )

    # The recorded string keeps its placeholders; the requested URL fills all four.
    # Built by substitution rather than by nesting format calls, because a template
    # whose braces survive a `.format()` is a template that was double-escaped, and the
    # service answers 422 to a URL containing a literal `{offset}`.
    split_filled = DS_SERVER_ROWS.format(dataset=spec.id, config=ROWS_CONFIG,
                                         split=split, offset="{offset}",
                                         length="{length}")

    rows: list[dict] = []
    pages: list[dict] = []
    total: int | None = None
    per_page = None
    features: list[dict] = []
    truncated = 0
    offset = 0
    while total is None or offset < total:
        page_url = DS_SERVER_ROWS.format(dataset=spec.id, config=ROWS_CONFIG,
                                         split=split, offset=offset,
                                         length=ROWS_PAGE_LENGTH)
        payload = _get_json_backoff(page_url, timeout=timeout)
        page_total, page_rows = _validate_rows_shape(payload, page_url)
        if total is None:
            total = page_total
            per_page = payload.get("num_rows_per_page")
            features = [
                {"name": str(f.get("name")),
                 "dtype": str((f.get("type") or {}).get("dtype")
                              if isinstance(f.get("type"), dict)
                              else f.get("type"))}
                for f in (payload.get("features") or []) if isinstance(f, dict)
            ]
        elif page_total != total:
            raise IntegrityError(
                f"{spec.id}:{split}: the service reported {total} rows on the first "
                f"page and {page_total} at offset {offset}. A split that changed size "
                "mid-retrieval cannot be described by one count, so no count is "
                "recorded and nothing is measured from it."
            )
        if not page_rows and offset < total:
            raise UpstreamError(
                f"{spec.id}:{split}: the service returned no rows at offset {offset} "
                f"while still claiming {total} rows in the split. Recorded as a split "
                f"that could not be retrieved, not as one with {offset} rows."
            )
        for position, item in enumerate(page_rows):
            claimed = item.get("row_idx")
            if isinstance(claimed, int) and claimed != offset + position:
                raise IntegrityError(
                    f"{spec.id}:{split}: a row arrived with row_idx {claimed} at "
                    f"offset {offset} + position {position}. The pagination is not the "
                    "documented one, so the cached set cannot be claimed complete."
                )
            if item.get("truncated_cells"):
                truncated += 1
        rows.extend(page_rows)
        pages.append({"offset": offset, "length": ROWS_PAGE_LENGTH,
                      "rows_returned": len(page_rows), "url": page_url})
        offset += len(page_rows)
        if offset < total:
            _time_sleep(ROWS_PAGE_DELAY_SECONDS)

    if total is None or len(rows) != total:
        raise IntegrityError(
            f"{spec.id}:{split}: retrieved {len(rows)} rows against a claimed "
            f"num_rows_total of {total}. An incomplete retrieval is not a smaller "
            "corpus; it is a failed fetch, and it is not cached."
        )

    pinned_rows = (pinned or {}).get("row_count")
    agree = (pinned_rows == total) if isinstance(pinned_rows, int) else None
    if agree is False:
        raise IntegrityError(
            f"{spec.id}:{split}: the repository file {file_spec.path} has "
            f"{pinned_rows} rows by its own Parquet footer and the conversion service "
            f"reports {total} for that split. The two objects disagree about how many "
            "messages there are, so which one the numbers describe is not knowable and "
            "nothing is measured from either until that is settled."
        )
    if agree is None:
        raise IntegrityError(
            f"{spec.id}:{split}: no pinned row count for {file_spec.path} in the "
            "manifest, so the retrieval could not be cross-checked against the "
            "repository file. Fetch the file first (eval/fetch.py --dataset "
            + spec.id + "); a cross-check that is impossible is not a cross-check "
            "that passed."
        )

    body = {
        "schema_version": 1,
        "dataset": spec.id,
        "slug": spec.slug,
        "config": ROWS_CONFIG,
        "split": split,
        "repo_path": file_spec.path,
        "revision": revision,
        "api_url_template": DS_SERVER_ROWS,
        "api_url_for_split": split_filled,
        "splits_endpoint": DS_SERVER_SPLITS.format(dataset=spec.id),
        "pagination": {
            "length": ROWS_PAGE_LENGTH,
            "pages_requested": len(pages),
            "offsets": [page["offset"] for page in pages],
            "num_rows_per_page_reported_by_service": per_page,
        },
        "pages": pages,
        "num_rows_total": total,
        "rows_retrieved": len(rows),
        "pinned_file_row_count": pinned_rows,
        "pinned_file_sha256": (pinned or {}).get("sha256"),
        "row_counts_agree": agree,
        "columns": sorted({key for item in rows for key in item["row"]}),
        "features": features,
        "rows_with_truncated_cells": truncated,
        "text_field": file_spec.text_field,
        "label_field": file_spec.label_field,
        "label_map": dict(file_spec.label_map),
        "label_default": file_spec.label_default,
        "source": ("datasets-server ROWS API - Hugging Face's converted Parquet, NOT "
                   "the repository file at the pinned revision"),
        "conversion_note": ROWS_CONVERSION_NOTE,
        "retrieved_at": now_iso(),
        "rows": rows,
    }
    if truncated:
        print(f"  ! rows {split}: {truncated} row(s) came back with a truncated cell; "
              "the text measured is a prefix of the text upstream")
    data = (json.dumps(body, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8")
    record = {key: value for key, value in body.items() if key != "rows"}
    record.update({
        "local_path": str(target.relative_to(REPO)),
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "cache_contains_row_text": True,
    })
    _guard_write(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    _record_rows(manifest, spec, record, split)
    print(f"  + rows {split}: {len(rows)} of {total} claimed, {len(pages)} page(s) "
          f"of {ROWS_PAGE_LENGTH}, cached at {record['local_path']} "
          f"(sha256 {record['sha256'][:12]}...)")
    return record


def fetch_rows(dataset_id: str, *, allow_sharealike: bool = False,
               force: bool = False) -> dict:
    """Retrieve the rows of every Parquet-only file of one allowlisted dataset.

    The repository file is fetched first, in the same run, so the cross-check between
    the pinned file's footer row count and the service's ``num_rows_total`` always has
    both sides. A rows retrieval that could not be cross-checked is refused rather than
    recorded, because the whole reason to record both objects is to be able to say they
    describe the same number of messages.
    """
    spec, observed, revision = prepare(dataset_id, allow_sharealike=allow_sharealike)
    wanted = spec.rows_files()
    manifest = load_manifest()
    _record_dataset(manifest, spec, observed)
    if not wanted:
        print(f"  {spec.id}: no file declares a rows_split, so nothing to retrieve "
              "- its rows already arrive as JSON, JSONL or CSV")
        save_manifest(manifest)
        return {"dataset": spec.id, "revision": revision, "rows": {}}

    tree = repo_tree(spec.id, revision)
    retrieved: dict[str, dict] = {}
    for file_spec in wanted:
        fetch_file(spec, file_spec, revision, observed, manifest, force=force, tree=tree)
        retrieved[file_spec.rows_split] = fetch_split(
            spec, file_spec, revision, observed, manifest, force=force)
    save_manifest(manifest)
    return {"dataset": spec.id, "revision": revision, "rows": retrieved}


def verify() -> list[str]:
    """Offline integrity check: recompute every digest the manifest claims.

    Returns a list of problems. Empty means every recorded file is present and
    byte-identical to what was fetched at the pinned revision. This is what
    ``eval/external.py`` calls before it will trust a corpus, and it runs with no
    network so a judge can check the artifact.
    """
    problems: list[str] = []
    if not MANIFEST.is_file():
        return [f"no manifest at {_relative(MANIFEST)}: nothing has been fetched "
                "by this harness"]
    manifest = load_manifest()
    for dataset_id, block in sorted(manifest["datasets"].items()):
        for repo_path, entry in sorted((block.get("files") or {}).items()):
            path = REPO / entry.get("local_path", "")
            if not path.is_file():
                problems.append(f"{dataset_id}:{repo_path}: recorded at "
                                f"{entry.get('local_path')} and not present")
                continue
            actual = sha256_file(path)
            if actual != entry.get("sha256"):
                problems.append(
                    f"{dataset_id}:{repo_path}: sha256 {actual[:12]}... does not "
                    f"match the recorded {str(entry.get('sha256'))[:12]}... "
                    f"(revision {entry.get('revision')})"
                )
                continue
            print(f"  ok {dataset_id}:{repo_path} "
                  f"({entry.get('bytes')} bytes, "
                  f"{entry.get('row_count') if entry.get('row_count') is not None else 'no row count'} rows)")
        for split, record in sorted((block.get("rows") or {}).items()):
            problems.extend(_verify_rows(dataset_id, split, record))
    return problems


def _verify_rows(dataset_id: str, split: str, record: dict) -> list[str]:
    """Re-hash a cached row retrieval and re-check the claims recorded with it.

    The digest is not the interesting part - the three counts are. A cache whose row
    count does not equal the service's claimed total, or does not equal the pinned
    repository file's footer count, means the measurement was taken over a set that no
    longer matches the artifact describing it, and that is reported here rather than
    left for a reader of the artifact to work out.
    """
    problems: list[str] = []
    path = REPO / record.get("local_path", "")
    if not path.is_file():
        return [f"{dataset_id}:rows:{split}: recorded at {record.get('local_path')} "
                "and not present"]
    actual = sha256_file(path)
    if actual != record.get("sha256"):
        problems.append(
            f"{dataset_id}:rows:{split}: sha256 {actual[:12]}... does not match the "
            f"{str(record.get('sha256'))[:12]}... recorded for revision "
            f"{record.get('revision')}"
        )
        return problems
    for key in ("num_rows_total", "rows_retrieved", "pinned_file_row_count"):
        if not isinstance(record.get(key), int):
            problems.append(f"{dataset_id}:rows:{split}: {key} is not an int")
    if record.get("rows_retrieved") != record.get("num_rows_total"):
        problems.append(
            f"{dataset_id}:rows:{split}: retrieved {record.get('rows_retrieved')} rows "
            f"against a claimed total of {record.get('num_rows_total')}"
        )
    if record.get("row_counts_agree") is not True:
        problems.append(
            f"{dataset_id}:rows:{split}: the conversion service and the pinned "
            f"repository file do not agree on the row count "
            f"({record.get('num_rows_total')} vs "
            f"{record.get('pinned_file_row_count')})"
        )
    if record.get("rows_with_truncated_cells"):
        print(f"  ! {dataset_id}:rows:{split}: "
              f"{record['rows_with_truncated_cells']} row(s) with a truncated cell")
    if not problems:
        print(f"  ok {dataset_id}:rows:{split} "
              f"({record.get('rows_retrieved')} rows, {record.get('bytes')} bytes)")
    return problems


# --------------------------------------------------------------------------
# the committed provenance record
# --------------------------------------------------------------------------


def _git_rev() -> str:
    """HEAD at write time, or an explicit sentinel.

    The same discipline ``eval/run.py`` applies: recording an empty commit reads as
    "clean tree at no commit" when the truth is "git did not answer", and a provenance
    record that cannot say which commit produced it has lost half its purpose.
    """
    import subprocess
    try:
        done = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO,
                              capture_output=True, text=True, timeout=15)
    except Exception:
        return "UNDETERMINED"
    if done.returncode != 0:
        return "UNDETERMINED"
    return done.stdout.strip()


#: The fields a provenance entry carries per fetched file. Deliberately a closed set,
#: asserted by tests/test_external_eval.py: message text could only arrive in a
#: committed record through a field added to this list, and a test that compares
#: against the list the writer uses cannot drift away from it.
PROVENANCE_FILE_FIELDS = (
    "source_url", "local_path", "bytes", "sha256", "row_count", "row_count_method",
    "format", "role", "fetched_at", "upstream_lfs_sha256", "upstream_digest_match",
)

#: The same discipline for a row retrieval. Note what is *not* here: no `rows`, no
#: `columns` values beyond the names, no text. The cache file's own sha256 is what the
#: committed record pins, so the text stays in the gitignored directory while the claim
#: about it is published.
PROVENANCE_ROWS_FIELDS = (
    "split", "config", "repo_path", "revision", "api_url_template",
    "api_url_for_split", "splits_endpoint", "pagination", "num_rows_total",
    "rows_retrieved", "pinned_file_row_count", "pinned_file_sha256",
    "row_counts_agree", "rows_with_truncated_cells", "local_path", "bytes", "sha256",
    "retrieved_at", "source", "conversion_note", "cache_contains_row_text",
)


def provenance_record(manifest: dict) -> dict:
    """The provenance of a fetch, without the data.

    This is the part that IS committed: dataset id, revision, licence, row count,
    byte size, sha256, source URL, and the sampling spec that turns a large corpus
    into a fixed subset. It contains no message text and no address, so it can go
    in a public repository while the bytes it describes stay gitignored. A digest
    of data we no longer have is still evidence about the measurement that used it.
    """
    datasets: dict[str, Any] = {}
    for dataset_id, block in sorted(manifest.get("datasets", {}).items()):
        files = {}
        for repo_path, entry in sorted((block.get("files") or {}).items()):
            files[repo_path] = {
                key: entry.get(key) for key in PROVENANCE_FILE_FIELDS
            }
        rows = {}
        for split, record in sorted((block.get("rows") or {}).items()):
            rows[split] = {key: record.get(key) for key in PROVENANCE_ROWS_FIELDS}
        datasets[dataset_id] = {
            "slug": block.get("slug"),
            "license_observed": block.get("license_observed"),
            "license_field": block.get("license_field"),
            "license_verified_on": block.get("license_verified_on"),
            "license_observed_at_fetch": block.get("license_observed_at_fetch"),
            "datasets_server_licenses": block.get("datasets_server_licenses", []),
            "revision": block.get("revision"),
            "revision_source": block.get("revision_source"),
            "api_url": block.get("api_url"),
            "license_limits": block.get("license_limits", []),
            "files": files,
            "rows": rows,
        }
        if rows:
            # The distinction is recorded per dataset, next to the two objects it
            # separates, rather than once at the top of the file where a reader of a
            # single table would never meet it.
            datasets[dataset_id]["rows_source_note"] = ROWS_CONVERSION_NOTE
    return {
        "schema_version": 1,
        "written_at": now_iso(),
        "commit": os.environ.get("GIT_COMMIT", "") or _git_rev(),
        "recorded_by": "eval/fetch.py",
        "policy": (
            "The datasets named here are fetched at evaluation time into "
            "eval/internal/, which is gitignored. Nothing downloaded is committed - "
            "this file is, and it is measurements about bytes, not bytes. For a "
            "Parquet-only corpus, two different objects are recorded and they are not "
            "the same bytes: the pinned sha256 is the repository file, and the text "
            "that was measured came from the datasets-server ROWS API's converted "
            "Parquet. See docs/EVAL-SUITES.md and the licence gate in eval/fetch.py."
        ),
        "refused": {
            dataset_id: {
                "license_observed": entry["license"],
                "observed_field": entry["observed_field"],
                "verified_on": entry["verified_on"],
                "reason": entry["reason"],
            }
            for dataset_id, entry in sorted(REFUSED.items())
        },
        "refused_without_the_sharealike_flag": {
            dataset_id: {
                "license_observed": entry["license"],
                "observed_field": entry["observed_field"],
                "verified_on": entry["verified_on"],
                "reason": entry["reason"],
            }
            for dataset_id, entry in sorted(SHAREALIKE.items())
        },
        "datasets": datasets,
    }


# --------------------------------------------------------------------------
# listing
# --------------------------------------------------------------------------


def describe_listing() -> str:
    lines = ["Allowlisted (may be fetched):", ""]
    for dataset_id, spec in sorted(PERMITTED.items()):
        lines.append(f"  {dataset_id}")
        lines.append(f"      licence {spec.license!r} observed on "
                     f"{spec.verified_on}; slug {spec.slug}")
        for file_spec in spec.files:
            mark = "" if file_spec.default else "  (not fetched by default)"
            rows = (f"  [rows via datasets-server: split {file_spec.rows_split}]"
                    if file_spec.rows_split else "")
            lines.append(f"        {file_spec.path} [{file_spec.role}]{mark}{rows}")
    lines += ["", "Refused by the licence gate:", ""]
    for dataset_id, entry in sorted(REFUSED.items()):
        lines.append(f"  {dataset_id} - observed licence "
                     f"{entry['license']!r} on {entry['verified_on']}")
        lines.append(f"      {entry['reason']}")
    lines += ["", "Refused unless --allow-sharealike:", ""]
    for dataset_id, entry in sorted(SHAREALIKE.items()):
        lines.append(f"  {dataset_id} - observed licence "
                     f"{entry['license']!r} on {entry['verified_on']}")
        lines.append(f"      {entry['reason']}")
    lines.append("")
    lines.append("Anything else is refused as unlisted: the allowlist is closed.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dataset", action="append", dest="datasets",
                        help="fetch this dataset id (repeatable); must be allowlisted")
    parser.add_argument("--file", action="append", dest="files",
                        help="restrict the fetch to this file of the dataset "
                             "(repeatable; may name the basename)")
    parser.add_argument("--all", action="store_true",
                        help="fetch every allowlisted dataset's default files")
    parser.add_argument("--rows", action="store_true",
                        help="also retrieve the rows of the Parquet-only files, as "
                             "JSON, from the datasets-server ROWS API, and cache them "
                             "under eval/internal/<slug>/rows/. This is how a corpus "
                             "whose text needs a column decoder gets measured without "
                             "this build growing one - and the cached rows are Hugging "
                             "Face's conversion, not the repository file, which the "
                             "manifest and PROVENANCE.json both say.")
    parser.add_argument("--list", action="store_true", dest="list_datasets",
                        help="print the allowlist and the refusals, and exit")
    parser.add_argument("--verify", action="store_true",
                        help="recompute every recorded digest offline and report "
                             "mismatches; needs no network")
    parser.add_argument("--allow-sharealike", action="store_true",
                        help="accept a share-alike obligation for a dataset listed "
                             "in SHAREALIKE. This is the operator's decision, not "
                             "the tool's; see the notice it prints")
    parser.add_argument("--force", action="store_true",
                        help="replace a file whose digest does not match the "
                             "manifest for the same revision. Off by default: a "
                             "mismatch is a finding, not something to overwrite")
    parser.add_argument("--write-provenance", type=pathlib.Path, metavar="PATH",
                        help="write the provenance record (no data) to PATH, e.g. "
                             "eval/PROVENANCE.json. Explicit only, because this is "
                             "the one file this tool is allowed to put outside "
                             "eval/internal/")
    parser.add_argument("--manifest", action="store_true",
                        help="print the manifest read from eval/internal/ as JSON")
    args = parser.parse_args(argv)

    if args.list_datasets:
        print(describe_listing())
        return EXIT_OK

    if args.verify:
        problems = verify()
        if problems:
            print("INTEGRITY FAILURES:")
            for problem in problems:
                print(f"  {problem}")
            return EXIT_ERROR
        print("every recorded file matches its recorded sha256")
        return EXIT_OK

    if args.manifest:
        print(json.dumps(load_manifest(), indent=2, sort_keys=True))
        return EXIT_OK

    targets = list(args.datasets or [])
    if args.all:
        targets = sorted(PERMITTED)
    if not targets and not args.write_provenance:
        parser.error("nothing to do: pass --dataset, --all, --list, --verify, "
                     "--manifest or --write-provenance")
    if not targets and args.write_provenance:
        # Recording the provenance of a fetch already made must work with no network:
        # the committed record is derived from the manifest, and a judge who has run
        # the fetch offline still wants to write it.
        print("no --dataset/--all given, so nothing was fetched; writing the "
              "provenance record from the manifest on disk")

    refused_seen = False
    fetched: list[dict] = []
    for dataset_id in targets:
        try:
            if args.rows:
                fetched.append(fetch_rows(dataset_id,
                                          allow_sharealike=args.allow_sharealike,
                                          force=args.force))
            else:
                fetched.append(fetch(dataset_id, files=args.files,
                                     allow_sharealike=args.allow_sharealike,
                                     force=args.force))
        except Refused as exc:
            print(exc)
            refused_seen = True
        except IntegrityError as exc:
            print(f"INTEGRITY ERROR: {exc}")
            return EXIT_ERROR
        except UpstreamError as exc:
            print(f"UPSTREAM ERROR: {exc}")
            return EXIT_NETWORK

    if args.write_provenance:
        record = provenance_record(load_manifest())
        path = args.write_provenance
        if path.is_absolute() is False:
            path = REPO / path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
            print(f"wrote {path.relative_to(REPO) if path.is_relative_to(REPO) else path}"
                  f" - provenance only, no message data")
        except OSError as exc:
            print(f"ERROR: could not write {path}: {exc}")
            return EXIT_ERROR

    return EXIT_REFUSED if refused_seen else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
