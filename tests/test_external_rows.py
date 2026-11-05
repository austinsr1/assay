"""Bundle N phase 1b: the ROWS-API reader, and what the newly-measured corpora show.

Phase 1 fetched and pinned six Parquet files and then said plainly that it could not read
them: their text sits behind dictionary-encoded pages in a snappy stream, and
``dependencies = []`` rules out borrowing a column decoder. Everything it could measure
came out 0.0% or 100.0%, because the synthesized envelope makes clearance impossible -
one absence described twice, not a result.

This file asserts the opposite state, and the guards that keep it honest.

1. **The text came from a service, and the digest describes a different object.** The
   datasets-server ROWS API serves Hugging Face's *converted* Parquet; its bytes are not
   the repository file's and do not carry the pinned sha256. So the artifact must name
   which road each corpus's text took, per corpus. A test that only checked "a sha256 is
   present" would pass while that distinction quietly disappeared, so the distinction is
   what is asserted here - and the only legitimate cross-check between the two objects
   is the split name and the row count.
2. **A retrieval is complete or it is an error.** The service's ``num_rows_total``, the
   rows actually retrieved, and the count read out of the pinned file's own footer must
   be one number per split, in the committed provenance - and every failure mode that
   could produce a smaller corpus (a short page, a total that moves mid-retrieval, a
   throttle, a truncation, a stale cache) is tested as code, with the network stubbed.
3. **Each measurement is read for what it can and cannot show.** NotInject is a
   zero-positive set: it can show over-defense and nothing else. Where a corpus produced
   neither a clearance nor an accusation, the report must say the axis does not
   discriminate, and must not print a 0.0% false-positive rate as an achievement.
4. **No row text is committed.** Scanned against the tracked tree, not asserted about it.

Nothing here touches the network: ``fetch._get_json`` and ``fetch._time_sleep`` are the
two seams, and a test that let a real request through would fail on the stub that raises.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "eval"))

import external  # noqa: E402
import fetch  # noqa: E402
import report  # noqa: E402
import run as eval_run  # noqa: E402
import selective  # noqa: E402

METRICS = REPO / "eval" / "metrics.json"
PROVENANCE = REPO / "eval" / "PROVENANCE.json"

#: The three corpora phase 1 could fetch, pin and not read, and the six files they are
#: measured from. Named here rather than rediscovered, so a corpus that silently stopped
#: being measured shows up as a missing name and not as a smaller number.
ROWS_CORPORA = (
    "notinject-one-benign", "notinject-two-benign", "notinject-three-benign",
    "deepset-train-injection", "deepset-train-not-injection",
    "deepset-test-injection", "deepset-test-not-injection",
    "bengali-test-smishing", "bengali-test-not-smishing",
)

BENGALI_LIMITS = (
    "SMS, not email",
    "Not English",
)


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True,
                          text=True, timeout=120)


def in_git_checkout() -> bool:
    return (REPO / ".git").exists()


requires_repo = pytest.mark.skipif(
    not in_git_checkout(),
    reason="not a git checkout: these assertions are about the repository, and an "
           "external review bundle deliberately excludes .git",
)


def committed_metrics() -> dict:
    return json.loads(METRICS.read_text(encoding="utf-8"))


def committed_external() -> dict:
    return committed_metrics()["external"]


def committed_provenance() -> dict:
    return json.loads(PROVENANCE.read_text(encoding="utf-8"))


def rendered(block: dict | None = None) -> str:
    return "\n".join(report._external_section(block or committed_external()))


# --------------------------------------------------------------------------
# 1. the reader: pagination, completeness, and the two objects
#
# A synthetic DatasetSpec with a slug beginning "_" keeps every byte these tests write
# inside the gitignored eval/internal/ tree and out of the way of the real fetch.
# --------------------------------------------------------------------------


def synthetic_spec(split: str = "one") -> fetch.DatasetSpec:
    return fetch.DatasetSpec(
        id="_test/rows-fixture",
        slug="_test-rows-fixture",
        license="mit",
        verified_on="2026-11-03",
        why="test fixture",
        files=(fetch.FileSpec(
            path="data/one-00000-of-00001.parquet", role="benign-messages",
            fmt="parquet", rows="parquet-footer", text_field="prompt",
            label_field=None, rows_split=split,
        ),),
    )


def synthetic_manifest(total: int = 3, split: str = "one") -> dict:
    """A manifest in the state a completed file fetch leaves: pinned count and digest."""
    spec = synthetic_spec(split)
    target = fetch.destination(spec, spec.files[0])
    digest = hashlib.sha256(PINNED_BYTES).hexdigest()
    return {"schema_version": 1, "datasets": {spec.id: {
        "dataset": spec.id, "slug": spec.slug, "revision": "0" * 40,
        "files": {spec.files[0].path: {
            "repo_path": spec.files[0].path, "sha256": digest, "revision": "0" * 40,
            "local_path": str(target.relative_to(REPO)),
            "row_count": total, "format": "parquet", "role": "benign-messages",
            "text_field": "prompt", "label_field": None, "label_map": {},
            "label_default": None, "rows_split": split,
        }},
    }}}


#: The bytes every synthetic pinned file above is made of, so its digest is real and a
#: measurement path that re-hashes it finds what it expects.
PINNED_BYTES = b"not really parquet"


def write_pinned_file(manifest: dict) -> pathlib.Path:
    """Put the pinned file on disk, so build_plan gets past the digest check."""
    block = manifest["datasets"]["_test/rows-fixture"]
    entry = next(iter(block["files"].values()))
    path = REPO / entry["local_path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(PINNED_BYTES)
    return path


def stub_server(monkeypatch, pages: list[list[int]], *, splits=("one",),
                total: int | None = None, truncate: bool = False,
                totals: list[int] | None = None):
    """Replace the transport with canned ROWS/splits answers. No socket is opened.

    ``pages`` is the number of rows the service delivers per page, so a short retrieval
    is expressed as data rather than as a special case in the stub.
    """
    calls: list[str] = []
    state = {"page": 0}
    claimed = total if total is not None else sum(len(p) for p in pages)
    sequence = totals or [claimed] * (len(pages) + 1)

    def fake_get_json(url, **_kwargs):
        calls.append(url)
        if "/splits" in url:
            return {"splits": [{"dataset": "_test/rows-fixture", "config": "default",
                                "split": name} for name in splits]}
        index = state["page"]
        state["page"] += 1
        batch = pages[index] if index < len(pages) else []
        base = sum(len(p) for p in pages[:index])
        return {
            "features": [{"feature_idx": 0, "name": "prompt",
                          "type": {"dtype": "string", "_type": "Value"}}],
            "num_rows_total": sequence[min(index, len(sequence) - 1)],
            "num_rows_per_page": fetch.ROWS_PAGE_LENGTH,
            "rows": [
                {"row_idx": base + position,
                 "row": {"prompt": f"prompt {base + position}"},
                 "truncated_cells": ["prompt"] if truncate else []}
                for position in range(len(batch))
            ],
        }

    monkeypatch.setattr(fetch, "_get_json", fake_get_json)
    monkeypatch.setattr(fetch, "_time_sleep", lambda _seconds: None)
    return calls


def run_fetch_split(monkeypatch, pages, manifest, *, total=None, splits=("one",),
                    truncate=False, totals=None):
    spec = synthetic_spec()
    observed = {"card_license": "mit", "revision": "0" * 40, "gated": False,
                "private": False, "datasets_server_licenses": []}
    stub_server(monkeypatch, pages, splits=splits, total=total, truncate=truncate,
                totals=totals)
    try:
        return fetch.fetch_split(spec, spec.files[0], "0" * 40, observed, manifest)
    finally:
        shutil.rmtree(fetch.INTERNAL / spec.slug, ignore_errors=True)


def test_the_rows_template_is_the_documented_service_and_keeps_its_placeholders():
    assert "datasets-server.huggingface.co/rows" in fetch.DS_SERVER_ROWS
    for placeholder in ("{dataset}", "{config}", "{split}", "{offset}", "{length}"):
        assert placeholder in fetch.DS_SERVER_ROWS
    assert fetch.ROWS_PAGE_LENGTH == 100, "the service's own cap, not an optimisation"
    assert "datasets-server.huggingface.co/splits" in fetch.DS_SERVER_SPLITS


def test_pages_are_requested_at_offset_intervals_until_the_claimed_total_is_reached(
        monkeypatch):
    """The documented shape: length 100, paginate by offset, stop at num_rows_total."""
    manifest = synthetic_manifest(total=250)
    entry = manifest["datasets"]["_test/rows-fixture"]["files"][
        "data/one-00000-of-00001.parquet"]
    entry["row_count"] = 250
    pages = [list(range(100)), list(range(100)), list(range(50))]
    record = run_fetch_split(monkeypatch, pages, manifest)
    assert record["num_rows_total"] == 250 == record["rows_retrieved"]
    assert record["pagination"]["pages_requested"] == 3
    assert record["pagination"]["offsets"] == [0, 100, 200]
    assert record["pagination"]["length"] == 100
    assert record["row_counts_agree"] is True
    assert record["pinned_file_row_count"] == 250
    assert record["pinned_file_sha256"] == entry["sha256"]
    # Every page URL that was actually requested is recorded, placeholders filled.
    urls = [page["url"] for page in record["pages"]]
    assert urls == [
        fetch.DS_SERVER_ROWS.format(dataset="_test/rows-fixture", config="default",
                                    split="one", offset=offset, length=100)
        for offset in (0, 100, 200)
    ]
    # And the recorded template still carries the placeholders, so it is a template.
    assert "{offset}" in record["api_url_template"]
    assert "{offset}" in record["api_url_for_split"]
    assert "_test/rows-fixture" in record["api_url_for_split"]
    assert record["retrieved_at"].endswith("Z")
    assert record["cache_contains_row_text"] is True


def test_a_retrieval_that_stops_short_is_an_error_and_not_a_smaller_corpus(monkeypatch):
    """300 claimed, 250 delivered: the cache is not written and the run fails loudly."""
    manifest = synthetic_manifest(total=300)
    pages = [list(range(100)), list(range(100)), list(range(50))]
    with pytest.raises(fetch.UpstreamError) as raised:
        run_fetch_split(monkeypatch, pages, manifest, total=300)
    assert "could not be retrieved" in str(raised.value)
    assert not (fetch.INTERNAL / "_test-rows-fixture").exists(), (
        "a failed retrieval must not leave a partial cache behind to be mistaken for "
        "a corpus"
    )


def test_a_total_that_moves_mid_retrieval_stops_the_fetch(monkeypatch):
    manifest = synthetic_manifest(total=200)
    pages = [list(range(100)), list(range(100))]
    with pytest.raises(fetch.IntegrityError) as raised:
        run_fetch_split(monkeypatch, pages, manifest, totals=[200, 260])
    assert "260" in str(raised.value) and "200" in str(raised.value)


def test_a_split_the_service_does_not_report_is_refused_before_requesting_it(monkeypatch):
    """The name comes from /splits. Requesting a split that is not there yields an empty
    answer, which a naive reader records as an empty corpus."""
    calls = stub_server(monkeypatch, [], splits=("NotInject_one",))
    spec = synthetic_spec(split="ghost")
    manifest = synthetic_manifest(total=3)
    with pytest.raises(fetch.IntegrityError) as raised:
        fetch.fetch_split(spec, spec.files[0], "0" * 40,
                          {"card_license": "mit", "revision": "0" * 40}, manifest)
    assert "does not report a split named 'ghost'" in str(raised.value)
    assert not any("huggingface.co/rows?" in url for url in calls), (
        "the row request should never have been made"
    )
    shutil.rmtree(fetch.INTERNAL / spec.slug, ignore_errors=True)


def test_a_row_count_disagreement_between_the_two_objects_stops_the_measurement(
        monkeypatch):
    """113 rows in the pinned file's footer, 100 claimed by the conversion service.

    This is the case the conversion note exists for: the two objects are different bytes,
    and the row count is the only comparison that is legitimate across two encodings of
    the same rows. A disagreement means we do not know how many messages there are, so
    no rate over them is a rate over anything.
    """
    manifest = synthetic_manifest(total=113)
    with pytest.raises(fetch.IntegrityError) as raised:
        run_fetch_split(monkeypatch, [list(range(100))], manifest, total=100)
    text = str(raised.value)
    assert "113" in text and "100" in text and "disagree" in text


def test_a_pinned_file_that_was_never_fetched_cannot_be_cross_checked(monkeypatch):
    manifest = synthetic_manifest(total=3)
    block = manifest["datasets"]["_test/rows-fixture"]
    del block["files"]["data/one-00000-of-00001.parquet"]["row_count"]
    with pytest.raises(fetch.IntegrityError) as raised:
        run_fetch_split(monkeypatch, [list(range(3))], manifest, total=3)
    assert "no pinned row count" in str(raised.value)


def test_a_truncated_cell_is_counted_in_the_retrieval_record(monkeypatch):
    manifest = synthetic_manifest(total=2)
    record = run_fetch_split(monkeypatch, [list(range(2))], manifest, total=2,
                             truncate=True)
    assert record["rows_with_truncated_cells"] == 2, (
        "the service said it cut these cells, and the artifact has to say so too"
    )


def test_the_backoff_retries_a_throttle_and_a_give_up_names_its_attempts(monkeypatch):
    """CloudFront answers 429 with no Retry-After. Both halves are asserted: a corpus
    that would have arrived is not reported as unavailable, and a corpus that did not
    arrive is not reported as having zero rows."""
    seen = {"n": 0}
    delays: list[float] = []

    def flaky(url, **_kwargs):
        seen["n"] += 1
        if seen["n"] <= 2:
            raise fetch.RateLimited("HTTP 429", status=429)
        return {"splits": [{"config": "default", "split": "one"}]}

    monkeypatch.setattr(fetch, "_get_json", flaky)
    monkeypatch.setattr(fetch, "_time_sleep", lambda seconds: delays.append(seconds))
    assert fetch.splits_from_api("_test/rows-fixture") == ["one"]
    assert delays == [fetch.ROWS_BACKOFF_BASE_SECONDS,
                      fetch.ROWS_BACKOFF_BASE_SECONDS * 2], "exponential, and bounded"

    def always_throttled(url, **_kwargs):
        raise fetch.RateLimited("HTTP 429", status=429)

    monkeypatch.setattr(fetch, "_get_json", always_throttled)
    attempts = []
    monkeypatch.setattr(fetch, "_time_sleep", lambda seconds: attempts.append(seconds))
    with pytest.raises(fetch.UpstreamError) as raised:
        fetch.splits_from_api("_test/rows-fixture")
    assert f"after {fetch.ROWS_MAX_ATTEMPTS} attempts" in str(raised.value)
    assert "not as one with zero rows" in str(raised.value)
    assert len(attempts) == fetch.ROWS_MAX_ATTEMPTS - 1
    assert max(delays + attempts) <= fetch.ROWS_BACKOFF_CAP_SECONDS


def test_a_404_is_not_a_throttle(monkeypatch):
    """Retrying a refusal is how a fetch hangs. Only the transient codes are retried."""
    def not_found(url, **_kwargs):
        raise fetch.UpstreamError("HTTP 404 for the dataset")

    monkeypatch.setattr(fetch, "_get_json", not_found)
    with pytest.raises(fetch.UpstreamError):
        fetch.splits_from_api("_test/rows-fixture")


def test_the_split_name_is_checked_before_it_becomes_a_path():
    """The split name becomes a filename inside eval/internal/, so it is guarded as one."""
    for hostile in ("../evil", "a/b", "", "..", "x\\y", "./x"):
        with pytest.raises(fetch.IntegrityError):
            fetch.rows_destination("notinject", hostile)
    ok = fetch.rows_destination("notinject", "NotInject_one")
    assert str(ok).startswith(str(fetch.INTERNAL))
    assert ok.name == "NotInject_one.json"


# --------------------------------------------------------------------------
# 2. the same gate, for the second road to the same corpora
# --------------------------------------------------------------------------


def test_the_rows_fetch_refuses_everything_the_file_fetch_refuses():
    for dataset_id in ("SetFit/enron_spam", "zefang-liu/phishing-email-dataset",
                       "geodesic-research/bipia", "not/listed"):
        with pytest.raises(fetch.Refused) as raised:
            fetch.fetch_rows(dataset_id)
        assert "REFUSED" in str(raised.value)
    with pytest.raises(fetch.Refused):
        fetch.fetch_rows("SetFit/enron_spam", allow_sharealike=False)


def test_the_rows_fetch_makes_no_request_when_the_gate_refuses(monkeypatch):
    def explode(*_args, **_kwargs):
        raise AssertionError("the rows path performed a network request before refusing")

    monkeypatch.setattr(fetch, "_get", explode)
    monkeypatch.setattr(fetch, "_get_json", explode)
    with pytest.raises(fetch.Refused):
        fetch.fetch_rows("SetFit/enron_spam")


def test_a_moved_upstream_licence_stops_a_rows_retrieval_too(monkeypatch):
    """The rows path re-reads cardData.license, because the licence is the permission
    and --rows is only a second way of getting at the same corpus."""
    def canned(url, **_kwargs):
        if "/tree/" in url:
            return []
        return {"cardData": {"license": "gpl-3.0"}, "sha": "0" * 40,
                "gated": False, "private": False}

    monkeypatch.setattr(fetch, "_get_json", canned)
    with pytest.raises(fetch.Refused) as raised:
        fetch.fetch_rows("leolee99/NotInject")
    assert "gpl-3.0" in str(raised.value) and "mit" in str(raised.value)


def test_a_gated_dataset_is_refused_on_the_rows_path_too(monkeypatch):
    def canned(url, **_kwargs):
        return {"cardData": {"license": "mit"}, "sha": "0" * 40,
                "gated": "auto", "private": False}

    monkeypatch.setattr(fetch, "_get_json", canned)
    with pytest.raises(fetch.Refused) as raised:
        fetch.fetch_rows("leolee99/NotInject")
    assert "gated" in str(raised.value)


def test_every_rows_split_is_declared_on_a_file_that_is_actually_fetched():
    """A split must belong to a default, pinned, Parquet file with a text column.

    Otherwise --rows would retrieve rows for bytes this harness never pinned, and the
    cross-check between the two objects - the only one that is legitimate - would have
    nothing on one side of it.
    """
    for dataset_id, spec in fetch.PERMITTED.items():
        for file_spec in spec.files:
            if not file_spec.rows_split:
                continue
            assert file_spec.default, f"{dataset_id}:{file_spec.path}"
            assert file_spec.fmt == "parquet", f"{dataset_id}:{file_spec.path}"
            assert "messages" in file_spec.role, f"{dataset_id}:{file_spec.path}"
            assert file_spec.text_field, f"{dataset_id}:{file_spec.path}"
            assert file_spec in spec.rows_files()
            assert spec.file(file_spec.path) is file_spec


def test_the_license_gate_tables_are_the_ones_phase_1_left_behind():
    """B2: nothing added, nothing loosened. Pinned by value, not by count.

    Asserted on the observed licence strings as well as the ids: a table that kept its
    five names and quietly changed a licence value is the same gate having been loosened.
    """
    assert set(fetch.PERMITTED) == {
        "microsoft/llmail-inject-challenge", "leolee99/NotInject",
        "deepset/prompt-injections", "jackhhao/jailbreak-classification",
        "shariul-islam/bengali-sms-smishing-dataset",
    }
    assert {d: s.license for d, s in fetch.PERMITTED.items()} == {
        "microsoft/llmail-inject-challenge": "mit",
        "leolee99/NotInject": "mit",
        "deepset/prompt-injections": "apache-2.0",
        "jackhhao/jailbreak-classification": "apache-2.0",
        "shariul-islam/bengali-sms-smishing-dataset": "mit",
    }
    assert set(fetch.REFUSED) == {"SetFit/enron_spam",
                                  "zefang-liu/phishing-email-dataset"}
    assert fetch.REFUSED["SetFit/enron_spam"]["license"] == "None"
    assert set(fetch.SHAREALIKE) == {"geodesic-research/bipia"}


# --------------------------------------------------------------------------
# 3. label mapping, stated per corpus (B4)
# --------------------------------------------------------------------------


def mapped_labels(dataset_id: str, repo_path: str) -> dict:
    file_spec = fetch.PERMITTED[dataset_id].file(repo_path)
    assert file_spec is not None
    return dict(file_spec.label_map), file_spec.label_default


@pytest.mark.parametrize("dataset_id,repo_path,expected", [
    ("deepset/prompt-injections",
     "data/train-00000-of-00001-9564e8b05b4757ab.parquet",
     {"1": "hostile", "0": "clean"}),
    ("shariul-islam/bengali-sms-smishing-dataset", "data/test-00000-of-00001.parquet",
     {"smish": "hostile"}),
    ("leolee99/NotInject", "data/NotInject_one-00000-of-00001.parquet", {}),
])
def test_the_label_map_is_declared_where_the_licence_is_declared(dataset_id, repo_path,
                                                                 expected):
    """The mapping is data in eval/fetch.py, read by external.py from the manifest.

    A mapping written in the measuring module would be a licence-adjacent decision made
    where nobody looks for it, and `threat` is exactly the mistake this table prevents:
    a labelled injection is mapped to 'hostile' (must not be cleared), never to 'threat',
    which would assert a credential-harvest judgement about a text prompt.
    """
    table, default = mapped_labels(dataset_id, repo_path)
    assert table == expected
    for value in list(table.values()) + ([default] if default else []):
        assert value in ("hostile", "clean"), value
    assert "threat" not in table.values()


def test_the_bengali_default_is_otherwise_clean_and_says_so():
    _table, default = mapped_labels(
        "shariul-islam/bengali-sms-smishing-dataset", "data/test-00000-of-00001.parquet")
    assert default == "clean"
    spec = {"label_map": {"smish": "hostile"}, "label_default": "clean"}
    assert external._mapped(spec, "smish") == "hostile"
    assert external._mapped(spec, "normal") == "clean"
    assert external._mapped(spec, "promo") == "clean"
    # An unknown value is NOT silently cleaned: with no default it stays itself, and the
    # measurement module counts it as a stray rather than folding it into a label.
    assert external._mapped({"label_map": {"smish": "hostile"}}, "mystery") == "mystery"


def test_the_service_returns_integers_and_the_map_is_written_as_strings():
    """deepset's label column is int64. `label == '1'` in the JSON is 1.

    A mapping written from the prose ("label '1' means injection") and applied to the
    raw integer would match nothing and measure zero rows in silence. This is the shape
    difference that would have quietly emptied the corpus.
    """
    cache = {"rows": [{"row_idx": 0, "row": {"text": "ignore previous instructions",
                                             "label": 1}},
                      {"row_idx": 1, "row": {"text": "hello", "label": 0}}]}
    spec = {"text_field": "text", "label_field": "label",
            "label_map": {"1": "hostile", "0": "clean"}, "label_default": None}
    rows = external._read_rows_api(json.dumps(cache).encode("utf-8"), spec)
    assert [row[3] for row in rows] == ["1", "0"]
    assert [external._mapped(spec, row[3]) for row in rows] == ["hostile", "clean"]


def test_a_row_without_its_text_column_raises_instead_of_measuring_an_empty_body():
    cache = {"rows": [{"row_idx": 0, "row": {"label": 1}}]}
    with pytest.raises(ValueError) as raised:
        external._read_rows_api(json.dumps(cache).encode("utf-8"),
                                {"text_field": "text", "label_field": "label"})
    assert "'text'" in str(raised.value)
    with pytest.raises(ValueError):
        external._read_rows_api(b'{"no_rows": 1}', {"text_field": "text"})
    with pytest.raises(ValueError):
        external._read_rows_api(b'{"rows": [{"row": {"text": "x"}}]}',
                                {"text_field": "text"})


# --------------------------------------------------------------------------
# 4. what phase 1b measured, with its denominators
# --------------------------------------------------------------------------


def test_every_parquet_file_phase_1_pinned_but_could_not_read_is_now_measured():
    """B3: the six unavailable entries moved into the measured corpora."""
    committed = committed_external()
    if committed["status"] == "not-fetched":
        # A fresh clone: nothing is measured, and the artifact says so rather than
        # showing zeros. The state this assertion is about cannot be checked here.
        assert committed["corpora"] == {} and committed["results"]
        for config_block in committed["results"].values():
            assert config_block == {}
        return
    for name in ROWS_CORPORA:
        assert name in committed["corpora"], f"{name} was declared and is not measured"
        for per_corpus in committed["results"].values():
            assert name in per_corpus, f"{name} measured for no configuration"
        descriptor = committed["corpora"][name]
        assert descriptor["text_origin"]["repository_file_sha256"], name
        assert descriptor["text_origin"]["conversion_service_used"] is True, name


def test_the_parquet_wall_is_not_back_in_the_unavailable_list():
    """No corpus may be reported both measured and unreadable."""
    committed = committed_external()
    for item in committed["unavailable"]:
        assert "does not carry a column decoder" not in item["reason"], item
    measured = set()
    for descriptor in committed["corpora"].values():
        if descriptor.get("split"):
            measured.add((descriptor["dataset"], descriptor["file"]))
    for item in committed["unavailable"]:
        if item.get("file"):
            assert (item["dataset"], item["file"]) not in measured, item


def test_the_rows_retrieved_equal_num_rows_total_and_the_pinned_file_count():
    """A2, against the committed provenance: one count, three sources.

    The service's claim, the rows actually delivered, and the number read out of the
    pinned repository file's own Parquet footer by the Thrift skimmer. All three are in
    the committed record for every split, and a reader can check them without fetching.
    """
    record = committed_provenance()
    seen_splits = 0
    for dataset_id, block in record["datasets"].items():
        for split, entry in (block.get("rows") or {}).items():
            seen_splits += 1
            assert entry["num_rows_total"] == entry["rows_retrieved"], (dataset_id, split)
            assert entry["row_counts_agree"] is True, (dataset_id, split)
            assert entry["pinned_file_row_count"] == entry["num_rows_total"]
            assert entry["rows_with_truncated_cells"] == 0, (dataset_id, split)
            file_entry = block["files"][entry["repo_path"]]
            assert file_entry["row_count"] == entry["num_rows_total"]
            assert entry["pinned_file_sha256"] == file_entry["sha256"]
            assert entry["revision"] == block["revision"]
            assert block["revision"] in file_entry["source_url"], (
                "the pinned repository file is fetched from a revision-pinned URL"
            )
            assert entry["config"] == fetch.ROWS_CONFIG
            assert entry["pagination"]["length"] == fetch.ROWS_PAGE_LENGTH
            assert entry["pagination"]["pages_requested"] >= 1
            assert len(entry["pagination"]["offsets"]) == \
                entry["pagination"]["pages_requested"]
    assert seen_splits == 6, (
        f"phase 1b unlocked six Parquet files; the provenance names {seen_splits} "
        "retrievals"
    )


def test_the_unlocked_row_counts_match_the_numbers_this_project_published():
    """NotInject 339, deepset 546 + 116, Bengali test 1,401 - through the new road."""
    totals = {
        (dataset_id, entry["split"]): entry["rows_retrieved"]
        for dataset_id, block in committed_provenance()["datasets"].items()
        for entry in (block.get("rows") or {}).values()
    }
    assert sum(v for (d, _s), v in totals.items()
               if d == "leolee99/NotInject") == 339
    assert totals[("deepset/prompt-injections", "train")] == 546
    assert totals[("deepset/prompt-injections", "test")] == 116
    assert totals[("shariul-islam/bengali-sms-smishing-dataset", "test")] == 1401


def test_every_measured_corpus_is_measured_whole_and_not_sampled():
    """The cap is above every population, so no denominator in the artifact is a sample."""
    committed = committed_external()
    for name, descriptor in committed["corpora"].items():
        assert descriptor["sample"]["all_rows"], name
        assert descriptor["rows_used"] == descriptor["rows_in_corpus"], name
        assert descriptor["sample"]["cap"] == external.DEFAULT_MAX_MESSAGES


def test_no_corpus_measures_more_rows_than_the_file_it_came_from_contains():
    committed = committed_external()
    for name, descriptor in committed["corpora"].items():
        assert descriptor["rows_in_corpus"] <= descriptor["row_count_file"], (
            f"{name}: {descriptor['rows_in_corpus']} rows measured from a file holding "
            f"{descriptor['row_count_file']}"
        )


def test_the_two_halves_of_a_labelled_file_add_up_to_the_file_and_do_not_overlap():
    """Hostile + clean = the pinned row count, per split, or a row went missing twice."""
    committed = committed_external()
    pairs = {
        ("deepset-train-injection", "deepset-train-not-injection"): 546,
        ("deepset-test-injection", "deepset-test-not-injection"): 116,
        ("bengali-test-smishing", "bengali-test-not-smishing"): 1401,
        ("jackhhao-test-jailbreak", "jackhhao-test-benign"): 400,
    }
    for (hostile_name, clean_name), expected in pairs.items():
        hostile = committed["corpora"].get(hostile_name)
        clean = committed["corpora"].get(clean_name)
        if committed["status"] == "not-fetched":
            assert hostile is None and clean is None
            continue
        assert hostile is not None and clean is not None, hostile_name
        assert hostile["label"] == "hostile" and clean["label"] == "clean"
        assert hostile["rows_in_corpus"] + clean["rows_in_corpus"] == expected, (
            f"{hostile_name} + {clean_name} = "
            f"{hostile['rows_in_corpus'] + clean['rows_in_corpus']}, expected {expected}"
        )
        assert hostile["row_count_file"] == clean["row_count_file"] == expected
        assert hostile["rows_with_an_unexpected_upstream_label"] == 0
        assert clean["rows_with_an_unexpected_upstream_label"] == 0


def test_notinject_is_measured_as_a_zero_positive_set_and_says_what_that_can_show():
    """A3. The single most decision-relevant number in this bundle, with its denominator."""
    committed = committed_external()
    if committed["status"] == "not-fetched":
        assert "NotInject" in json.dumps(committed["allowlisted"])
        return
    parts = [committed["corpora"][name] for name in
             ("notinject-one-benign", "notinject-two-benign", "notinject-three-benign")]
    assert [p["rows_in_corpus"] for p in parts] == [113, 113, 113]
    assert sum(p["rows_in_corpus"] for p in parts) == 339
    for part in parts:
        assert part["label"] == "clean"
        assert part["kind_of_measurement"] == "labelled"
        # No positive exists in this set to be found: it has no label column at all.
        assert part["upstream_labels_seen"] == {"(no label column)": 113}
        assert part["rows_used"] == 113

    rollup = committed["per_dataset"]["leolee99/NotInject"]
    surface = rollup["text_surface"]
    assert surface["rows"] == 339
    assert surface["clean_rows"] == 339
    assert surface["hostile_rows"] == 0
    assert surface["hostile_rows_flagged_rate"] is None, (
        "a rate over no positives is not zero, it is nothing to measure"
    )
    # THE number: how many of the 339 benign trigger-word prompts our own text surface
    # flags. Over-defense is where a small detector was expected to fail.
    assert surface["clean_rows_flagged"] <= surface["clean_rows"]
    for corpus in rollup["corpora"]:
        assert corpus["rows"] == 113
        assert 0 <= corpus["rows_flagged"] <= 113

    text = rendered()
    assert "339" in text
    assert "no hostile-labelled rows: this set cannot show coverage at all" in text


def test_deepset_reports_both_classes_separately_with_their_own_denominators():
    """A4: the recall side and the false-positive side, never merged into one rate."""
    committed = committed_external()
    if committed["status"] == "not-fetched":
        assert "deepset/prompt-injections" in committed["allowlisted"]
        return
    rollup = committed["per_dataset"]["deepset/prompt-injections"]
    surface = rollup["text_surface"]
    assert surface["hostile_rows"] == 263, "203 train + 60 test"
    assert surface["clean_rows"] == 399, "343 train + 56 test"
    assert surface["rows"] == 662
    assert surface["hostile_rows_flagged"] <= surface["hostile_rows"]
    assert surface["clean_rows_flagged"] <= surface["clean_rows"]
    assert surface["hostile_rows_flagged_rate"] == round(
        surface["hostile_rows_flagged"] / 263, 4)
    assert surface["clean_rows_flagged_rate"] == round(
        surface["clean_rows_flagged"] / 399, 4)
    # And the licence disagreement is printed with the numbers it made possible, not
    # resolved by this report.
    text = rendered()
    assert "cc-by-4.0" in text and "apache-2.0" in text
    assert "the two fields disagree" in text


def test_the_per_dataset_rollup_is_a_sum_of_published_counts_and_nothing_more():
    """The rollup must not become a second measurement. Re-derive it from the corpora."""
    committed = committed_external()
    if committed["status"] == "not-fetched":
        assert committed["per_dataset"] == {}
        return
    rebuilt: dict[str, dict[str, int]] = {}
    for name, descriptor in committed["corpora"].items():
        surface = descriptor["text_surface"]
        side = "hostile" if descriptor["label"] == "hostile" else "clean"
        bucket = rebuilt.setdefault(descriptor["dataset"], {
            "rows": 0, "flagged": 0, "hostile_rows": 0, "hostile_flagged": 0,
            "clean_rows": 0, "clean_flagged": 0, "corpora": 0,
        })
        bucket["rows"] += surface["rows"]
        bucket["flagged"] += surface["injection_indicator_rows"]
        bucket[f"{side}_rows"] += surface["rows"]
        bucket[f"{side}_flagged"] += surface["injection_indicator_rows"]
        bucket["corpora"] += 1
    assert set(rebuilt) == set(committed["per_dataset"])
    for dataset_id, bucket in rebuilt.items():
        item = committed["per_dataset"][dataset_id]
        got = item["text_surface"]
        assert len(item["corpora"]) == bucket["corpora"]
        assert (got["rows"], got["rows_flagged"]) == (bucket["rows"], bucket["flagged"])
        assert (got["hostile_rows"], got["hostile_rows_flagged"]) == (
            bucket["hostile_rows"], bucket["hostile_flagged"])
        assert (got["clean_rows"], got["clean_rows_flagged"]) == (
            bucket["clean_rows"], bucket["clean_flagged"])
        for config_name, counts in item["configurations"].items():
            per_corpus = committed["results"][config_name]
            names = [c["corpus"] for c in item["corpora"]]
            assert counts["messages"] == sum(per_corpus[n]["messages"] for n in names)
            assert counts["cleared"] == sum(
                per_corpus[n]["by_disposition"].get("clean", 0) for n in names)
            assert counts["accused"] == sum(
                sum(per_corpus[n]["by_disposition"].get(d, 0) for d in
                    selective.ACCUSATIONS) for n in names)
            assert counts["deferred"] == sum(
                sum(per_corpus[n]["by_disposition"].get(d, 0) for d in
                    selective.DEFERRALS) for n in names)


def test_the_bengali_limitations_are_asserted_in_the_rendered_report():
    """A5: SMS-not-email and not-English, in the report, and required by a test."""
    committed = committed_external()
    for name in ("bengali-test-smishing", "bengali-test-not-smishing"):
        descriptor = committed["corpora"].get(name)
        if descriptor is None:
            assert committed["status"] == "not-fetched", name
            continue
        limits = " ".join(descriptor["measurement_limits"])
        assert len(descriptor["measurement_limits"]) == 2, name
        for phrase in BENGALI_LIMITS:
            assert phrase in limits, (name, phrase)
        assert "transfer" in limits, "and the framing: domain and language transfer"
        # And the same facts are in the dataset-level limits, so the two places a reader
        # can meet them say the same thing.
        joined = " ".join(descriptor["license_limits"])
        assert "SMS, not email" in joined and "domain transfer" in joined
    text = rendered()
    for phrase in BENGALI_LIMITS:
        assert phrase in text, f"{phrase} must be in the rendered external section"
    assert "out of domain" in text.lower()
    assert "Bengali" in text


def test_the_bengali_hostile_column_is_the_number_that_would_have_to_be_nonzero():
    """Its own assertion, because a 0 there is the finding, not a rounding artefact."""
    committed = committed_external()
    if committed["status"] == "not-fetched":
        return
    rollup = committed["per_dataset"]["shariul-islam/bengali-sms-smishing-dataset"]
    surface = rollup["text_surface"]
    assert surface["hostile_rows"] == 561
    assert surface["clean_rows"] == 840
    assert surface["hostile_rows_flagged"] == 0, (
        "if this changes, the text surface detects smishing in Bengali - re-read the "
        "report's out-of-domain framing before quoting the number"
    )


# --------------------------------------------------------------------------
# 5. the honesty guards
# --------------------------------------------------------------------------


def test_a_corpus_that_neither_cleared_nor_accused_is_called_non_discriminating():
    """A6. 0.0% false positives over a corpus this configuration decided nothing about."""
    committed = committed_external()
    if committed["status"] == "not-fetched":
        return
    vacuous = []
    for per_corpus in committed["results"].values():
        for name, metrics in per_corpus.items():
            if metrics["messages"] and not metrics["auto_clearance_rate"] \
                    and not metrics["accusation_rate"]:
                vacuous.append(name)
    assert vacuous, "phase 1b expected every external corpus to be non-discriminating"
    text = rendered()
    assert text.count(report.NON_DISCRIMINATING_STATEMENT) >= len(set(vacuous)), (
        "the statement has to sit where each 0.0% was printed, not once in a preamble"
    )
    assert not report.non_discriminating({"messages": 0, "auto_clearance_rate": 0.0,
                                          "accusation_rate": 0.0}), (
        "a corpus with no messages is not a corpus that decided nothing - it is no "
        "corpus, and the two must not render the same"
    )


def test_the_non_discriminating_statement_is_not_a_stamp_on_a_real_measurement():
    """The guard must be able to stay silent, or it proves nothing."""
    committed = json.loads(json.dumps(committed_external()))
    config = sorted(committed["results"])[0]
    name = sorted(committed["results"][config])[0]
    metrics = committed["results"][config][name]
    assert report.non_discriminating(metrics) is True
    metrics["auto_clearance_rate"] = 0.25
    metrics["accusation_rate"] = 0.1
    assert report.non_discriminating(metrics) is False
    text = "\n".join(report._corpus_section(name, metrics))
    assert report.NON_DISCRIMINATING_STATEMENT not in text
    assert "25.0%" in text, "the rate itself is still printed, unchanged"


def test_the_rendered_report_cannot_lose_the_non_discriminating_statement():
    """The mutation that would reintroduce phase 1's framing: a corpus section with the
    sentence removed is a renderer bug, so the guard is on the text, not on a field."""
    committed = committed_external()
    text = rendered(committed)
    assert report.NON_DISCRIMINATING_STATEMENT in text
    # A descriptor whose metrics block was regenerated without the statement must not
    # be able to hide it: the sentence is emitted by the renderer from the rates, so
    # emptying the results is the only way to lose it, and that empties the section too.
    emptied = json.loads(json.dumps(committed))
    emptied["results"] = {}
    assert report.NON_DISCRIMINATING_STATEMENT not in rendered(emptied)


def test_the_report_says_the_model_tier_ab_has_not_run():
    committed = committed_external()
    tier = committed["model_tier"]
    assert tier["statement"] == external.MODEL_TIER_STATEMENT
    assert "HAS NOT RUN" in tier["statement"]
    assert tier["has_run"] is False
    text = rendered()
    assert "### The model tier took part in none of this" in text
    assert "THE MODEL-TIER A/B HAS NOT RUN" in text
    for config_name, counts in tier["per_configuration"].items():
        assert counts["model_assisted"] == 0, config_name
        assert config_name in text
    # No committed corpus row claims a model judgment.
    for per_corpus in committed["results"].values():
        for name, metrics in per_corpus.items():
            assert metrics["model_assisted"] == 0, name


def test_the_report_raises_when_the_model_tier_statement_is_gone():
    for mutation in ("drop", "soften"):
        block = json.loads(json.dumps(committed_external()))
        if mutation == "drop":
            del block["model_tier"]
        else:
            block["model_tier"]["statement"] = "The tiers were consulted where possible."
        with pytest.raises(report.MalformedExternalMetrics) as raised:
            report._external_section(block)
        assert "model_tier" in str(raised.value) or "A/B" in str(raised.value)


def test_the_report_raises_when_the_per_dataset_rollup_is_absent():
    block = json.loads(json.dumps(committed_external()))
    del block["per_dataset"]
    with pytest.raises(report.MalformedExternalMetrics) as raised:
        report._external_section(block)
    assert "per_dataset" in str(raised.value)


def test_every_external_descriptor_names_where_its_text_came_from():
    """The conversion-service distinction cannot disappear into a uniform table."""
    committed = committed_external()
    rows_road = file_road = 0
    for name, descriptor in committed["corpora"].items():
        origin = descriptor["text_origin"]
        assert origin["via"] in ("repository-file", "datasets-server-rows-api"), name
        assert origin["statement"], name
        assert origin["repository_file_sha256"] == descriptor["sha256"], name
        if origin["via"] == "datasets-server-rows-api":
            rows_road += 1
            assert origin["conversion_service_used"] is True
            assert origin["rows_retrieved"] == origin["num_rows_total_reported"]
            assert origin["row_counts_agree"] is True
            assert origin["rows_read_from_repository_file"] == origin["rows_retrieved"]
            assert origin["statement"] == fetch.ROWS_CONVERSION_NOTE
            retrieval = descriptor["rows_retrieval"]
            assert retrieval["local_path"].startswith("eval/internal/")
            assert len(retrieval["sha256"]) == 64
            assert "{offset}" in retrieval["api_url_template"]
            assert "rows?" in retrieval["api_url_for_split"]
        else:
            file_road += 1
            assert origin["conversion_service_used"] is False
            assert descriptor.get("rows_retrieval") is None
    assert rows_road == 9 and file_road == 3, (
        f"phase 1b moved nine corpora onto the rows road; got {rows_road}"
    )


def test_the_text_origin_block_is_printed_for_both_roads():
    text = rendered()
    assert "Where the measured text came from" in text
    assert "datasets-server-rows-api" in text
    assert "repository-file" in text
    assert "Hugging Face's converted" in text or "converted Parquet" in text
    assert "num_rows_total" in text
    assert "NOT the bytes the text was read from" in text


# --------------------------------------------------------------------------
# 6. the committed artifacts: provenance of both objects, and no row text
# --------------------------------------------------------------------------


def test_the_provenance_record_carries_the_retrieval_and_names_both_objects():
    record = committed_provenance()
    assert "Nothing downloaded is committed" in record["policy"]
    assert "converted" in record["policy"], (
        "the policy line must say the rows came from a conversion, not from the file"
    )
    for dataset_id, block in record["datasets"].items():
        rows = block.get("rows") or {}
        if not rows:
            assert not any(f.rows_split
                           for f in fetch.PERMITTED[dataset_id].files)
            continue
        assert block["rows_source_note"] == fetch.ROWS_CONVERSION_NOTE
        for split, entry in rows.items():
            assert set(entry) == set(fetch.PROVENANCE_ROWS_FIELDS), (dataset_id, split)
            assert entry["conversion_note"] == fetch.ROWS_CONVERSION_NOTE
            assert entry["source"].startswith("datasets-server ROWS API")
            assert entry["cache_contains_row_text"] is True
            assert entry["local_path"].startswith("eval/internal/")
            assert len(entry["sha256"]) == 64 and len(entry["pinned_file_sha256"]) == 64
            assert entry["sha256"] != entry["pinned_file_sha256"], (
                "the cache and the repository file are different objects; if these "
                "ever match, one of the two records is wrong"
            )
            assert entry["split"] == split
            assert entry["config"] == fetch.ROWS_CONFIG


@pytest.mark.parametrize("key", fetch.PROVENANCE_ROWS_FIELDS)
def test_the_provenance_rows_fields_are_all_short_scalars_or_declared_lists(key):
    """No field in the published retrieval record can carry a message body.

    Checked against the writer's own declared tuple, so adding a field to
    ``provenance_record`` without adding it here (or here without adding it there)
    fails the build.
    """
    record = committed_provenance()
    for dataset_id, block in record["datasets"].items():
        for _split, entry in (block.get("rows") or {}).items():
            value = entry[key]
            if isinstance(value, str):
                assert len(value) <= 1200, (dataset_id, key, len(value))
                assert "\n" not in value
                continue
            if isinstance(value, dict):
                assert key in ("pagination",), key
                continue
            assert isinstance(value, (int, bool, type(None))), (dataset_id, key)


def test_no_row_text_from_a_fetched_corpus_lands_in_a_tracked_file():
    """A11: scan the tracked tree for real sampled text, not for plausible patterns.

    When this host has fetched nothing the content half has nothing to scan for, so what
    is asserted instead is the structural claim that makes the content scan unnecessary:
    every retrieval record points into the gitignored directory and says it holds text,
    and no tracked file may live there. This branch never skips, and never reports zero.
    """
    tracked = [line for line in _git("ls-files", "-z").stdout.split("\0") if line]
    bodies = {}
    for path in tracked:
        candidate = REPO / path
        if not candidate.is_file() or candidate.stat().st_size > 8_000_000:
            continue
        try:
            bodies[path] = candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

    caches = sorted(fetch.INTERNAL.glob("*/rows/*.json")) if fetch.INTERNAL.is_dir() \
        else []
    needles: list[str] = []
    for cache in caches:
        rows = json.loads(cache.read_text(encoding="utf-8"))["rows"]
        step = max(1, len(rows) // 12)
        for item in rows[::step][:12]:
            for value in item["row"].values():
                if isinstance(value, str) and len(value) >= 30:
                    needles.append(value[:70])
    if not needles:
        assert not any(path.startswith("eval/internal/") for path in tracked), (
            "a fetched corpus file is tracked: the only reason the content scan could "
            "have nothing to look for is that nothing is here to find"
        )
        assert committed_provenance()["datasets"], "and the provenance still records it"
        for block in committed_provenance()["datasets"].values():
            for entry in (block.get("rows") or {}).values():
                assert entry["cache_contains_row_text"] is True
        return
    assert len(needles) >= 20, f"sampled only {len(needles)} needles"
    for needle in needles:
        for path, body in bodies.items():
            assert needle not in body, (
                f"corpus text reached {path}: {needle[:40]}..."
            )


def test_the_committed_metrics_still_carry_no_row_text_by_shape():
    """Every per-message row holds only the committed keys, and no free text."""
    committed = committed_external()
    row_keys = set(committed_metrics()["results"]["deterministic-only"]["synthetic"]
                   ["rows"][0])
    for per_corpus in committed["results"].values():
        for name, metrics in per_corpus.items():
            for row in metrics["rows"]:
                assert set(row) == row_keys, name
                for key, value in row.items():
                    if isinstance(value, str):
                        assert len(value) <= 64, (name, key)
                        assert "\n" not in value


# --------------------------------------------------------------------------
# 7. the plan on a host that has not fetched, and the run that measures it
# --------------------------------------------------------------------------


def synthetic_definition(**overrides) -> dict:
    """One CORPUS_DEFS entry pointing at the synthetic dataset, for plan-level tests."""
    base = {
        "name": "fixture-clean", "dataset": "_test/rows-fixture",
        "repo_path": "data/one-00000-of-00001.parquet", "source": "rows",
        "split": "one", "kind": "labelled", "reader": "rows-api-json",
        "label": "clean",
        "label_source": "test fixture: benign by declaration",
        "why": "test fixture",
    }
    base.update(overrides)
    return base


def test_a_host_with_the_files_but_no_row_cache_reports_the_gap_per_corpus(monkeypatch):
    """The degradation for the NEW road specifically: loud, per corpus, never zero rows."""
    manifest = synthetic_manifest(total=113)
    manifest["datasets"]["_test/rows-fixture"]["files"][
        "data/one-00000-of-00001.parquet"]["row_count"] = 113
    write_pinned_file(manifest)
    monkeypatch.setattr(fetch, "load_manifest", lambda: manifest)
    monkeypatch.setattr(fetch, "gate", lambda _d: (synthetic_spec(), ""))
    monkeypatch.setattr(external, "CORPUS_DEFS", (synthetic_definition(),))
    try:
        plan = external.build_plan(write_messages=False)
        assert plan["corpora"] == {}, "nothing was retrieved, so nothing was measured"
        assert not any(block for block in plan["results"].values())
        by_corpus = [item for item in plan["unavailable"] if item.get("corpus")]
        assert len(by_corpus) == 1, plan["unavailable"]
        assert "never retrieved" in by_corpus[0]["reason"]
        assert "--rows" in by_corpus[0]["reason"], "and it must name the way out"
        assert plan["status"] == "no-evaluable-corpus"
        # The pinned Parquet file is reported as a gap too, with its row count, so the
        # absence shows up as a stated limitation and not as a corpus that is small.
        gap = [item for item in plan["unavailable"] if item.get("file")]
        assert gap and gap[0]["row_count_file"] == 113
        assert gap[0]["split"] == "one"
        assert "column decoder" in gap[0]["reason"]
    finally:
        shutil.rmtree(fetch.INTERNAL / "_test-rows-fixture", ignore_errors=True)


def test_a_stale_or_mismatched_row_cache_is_refused_with_a_reason(monkeypatch):
    """Each mutation is a state in which a measurement would be built on the wrong text."""
    definition = {"name": "c", "dataset": "_test/rows-fixture", "split": "one",
                  "repo_path": "data/one-00000-of-00001.parquet"}
    manifest = synthetic_manifest(total=3)
    block = manifest["datasets"]["_test/rows-fixture"]
    file_entry = block["files"][definition["repo_path"]]
    slug = "_test-rows-cache"
    directory = fetch.INTERNAL / slug / "rows"
    directory.mkdir(parents=True, exist_ok=True)
    cache = directory / "one.json"
    try:
        record = {
            "local_path": str(cache.relative_to(REPO)), "sha256": "0" * 64,
            "rows_retrieved": 3, "num_rows_total": 3, "row_counts_agree": True,
            "revision": file_entry["revision"], "repo_path": definition["repo_path"],
            "pinned_file_sha256": file_entry["sha256"],
        }
        # (mutation, expected phrase)
        cases = [
            (None, "never retrieved"),
            ("sha256", "does not match"),
            ("count", "incomplete retrieval"),
            ("agree", "disagree about"),
            ("revision", "a different fetch"),
            ("file", "a different file"),
        ]
        for mutation, phrase in cases:
            block["rows"] = {definition["split"]: dict(record)}
            cache.write_text('{"rows": []}', encoding="utf-8")
            digest = hashlib.sha256(cache.read_bytes()).hexdigest()
            if mutation == "sha256":
                block["rows"]["one"]["sha256"] = "f" * 64
            elif mutation == "count":
                block["rows"]["one"]["rows_retrieved"] = 2
            elif mutation == "agree":
                block["rows"]["one"]["row_counts_agree"] = False
            elif mutation == "revision":
                block["rows"]["one"]["revision"] = "9" * 40
            elif mutation == "file":
                block["rows"]["one"]["pinned_file_sha256"] = "e" * 64
            elif mutation is None:
                block["rows"] = {}
            if mutation == "sha256":
                got, reason = external._rows_retrieval(definition, block, file_entry)
            else:
                block["rows"].get("one", {}).update({"sha256": digest})
                got, reason = external._rows_retrieval(definition, block, file_entry)
            assert got is None, (mutation, reason)
            assert phrase in reason, (mutation, reason)
    finally:
        shutil.rmtree(fetch.INTERNAL / slug, ignore_errors=True)


def test_build_plan_refuses_to_measure_a_corpus_whose_table_and_cache_disagree(
        monkeypatch):
    """The retrieval says the text column is one thing, the table now says another.

    This is the drift the consistency check exists for: ``eval/fetch.py`` is edited in a
    commit, the row cache on disk is not, and a measurement that read the cached rows
    through the *new* column name would silently measure nothing and report a corpus of
    zero rows. The check refuses, and says which of the two moved.
    """
    spec = synthetic_spec()
    moved = fetch.DatasetSpec(
        id=spec.id, slug=spec.slug, license=spec.license,
        verified_on=spec.verified_on, why=spec.why, limits=spec.limits,
        files=(fetch.FileSpec(
            path=spec.files[0].path, role="benign-messages", fmt="parquet",
            rows="parquet-footer", text_field="a_column_that_does_not_exist",
            rows_split="one", default=True),),
    )
    manifest = synthetic_manifest(total=2)
    pinned = write_pinned_file(manifest)
    block = manifest["datasets"][spec.id]
    entry = block["files"][spec.files[0].path]
    cache = fetch.rows_destination(spec.slug, "one")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text('{"rows": []}', encoding="utf-8")
    digest = hashlib.sha256(cache.read_bytes()).hexdigest()
    block["rows"] = {"one": {
        "local_path": str(cache.relative_to(REPO)), "sha256": digest,
        "rows_retrieved": 2, "num_rows_total": 2, "row_counts_agree": True,
        "revision": entry["revision"], "repo_path": entry["repo_path"],
        "pinned_file_sha256": entry["sha256"], "text_field": "prompt",
        "label_field": None, "label_default": None, "label_map": {},
    }}
    monkeypatch.setattr(fetch, "load_manifest", lambda: manifest)
    monkeypatch.setattr(fetch, "gate", lambda _d: (moved, ""))
    monkeypatch.setattr(external, "CORPUS_DEFS", (synthetic_definition(),))
    try:
        plan = external.build_plan(write_messages=False)
        assert plan["corpora"] == {}
        reasons = json.dumps(plan["unavailable"])
        assert "a_column_that_does_not_exist" in reasons, reasons
        assert "the table moved after the retrieval" in reasons, reasons
    finally:
        shutil.rmtree(fetch.INTERNAL / spec.slug, ignore_errors=True)
    assert pinned.name == "one-00000-of-00001.parquet"


def test_a_withdrawn_declaration_stops_a_rows_corpus(monkeypatch):
    """A file that is no longer in the allowlisted set has no declaration to trust."""
    monkeypatch.setattr(fetch, "gate", lambda _d: (None, "REFUSED"))
    assert external._declared_file("_test/rows-fixture", "data/x.parquet") is None
    monkeypatch.setattr(fetch, "gate", lambda _d: (synthetic_spec(), ""))
    assert external._declared_file("_test/rows-fixture",
                                   "data/nope.parquet") is None


def test_the_rollup_functions_sum_published_counts_and_invent_nothing():
    """`per_dataset_rollup` and `model_tier_rollup`, checked on data this test builds.

    A small hand-made corpus set, because the property worth pinning is the arithmetic:
    hostile and clean denominators kept apart, a rate over no positives is None and not
    0.0, and the model-tier count is the sum of what the configurations published.
    """
    corpora = {
        "a-hostile": {"descriptor": {
            "dataset": "x/y", "slug": "y", "label": "hostile", "file": "data/a.parquet",
            "license_observed": "mit", "split": "train",
            "measurement_limits": ["SMS, not email"],
            "text_surface": {"rows": 10, "injection_indicator_rows": 4,
                             "injection_indicator_rate": 0.4},
        }},
        "a-clean": {"descriptor": {
            "dataset": "x/y", "slug": "y", "label": "clean", "file": "data/a.parquet",
            "license_observed": "mit", "split": "train",
            "measurement_limits": ["SMS, not email"],
            "text_surface": {"rows": 10, "injection_indicator_rows": 0,
                             "injection_indicator_rate": 0.0},
        }},
    }
    metrics = {"messages": 20, "model_assisted": 0,
               "by_disposition": {"manual_review": 20}}
    results = {"deterministic-only": {"a-hostile": metrics, "a-clean": metrics}}
    rollup = eval_run.per_dataset_rollup(corpora, results)
    item = rollup["x/y"]
    assert item["text_surface"]["hostile_rows"] == 10
    assert item["text_surface"]["hostile_rows_flagged"] == 4
    assert item["text_surface"]["clean_rows_flagged"] == 0
    assert item["text_surface"]["rows"] == 20
    assert item["configurations"]["deterministic-only"] == {
        "messages": 40, "cleared": 0, "deferred": 40, "accused": 0, "model_assisted": 0,
        "auto_clearance_rate": 0.0, "accusation_rate": 0.0, "escalation_rate": 1.0,
    }
    assert item["measurement_limits"] == ["SMS, not email"]
    tier = eval_run.model_tier_rollup(results)
    assert tier["has_run"] is False
    assert tier["per_configuration"]["deterministic-only"] == {
        "messages": 40, "model_assisted": 0, "model_assisted_rate": 0.0}
    assert tier["statement"] == external.MODEL_TIER_STATEMENT


def test_a_zero_positive_rollup_reports_none_and_not_zero():
    """A rate over no hostile rows is nothing to measure, and must render as that."""
    corpora = {"only-clean": {"descriptor": {
        "dataset": "z/w", "slug": "w", "label": "clean", "file": "f", "split": None,
        "measurement_limits": [],
        "text_surface": {"rows": 5, "injection_indicator_rows": 0,
                         "injection_indicator_rate": 0.0},
    }}}
    surface = eval_run.per_dataset_rollup(
        corpora, {"deterministic-only": {"only-clean": {
            "messages": 5, "model_assisted": 0, "by_disposition": {"clean": 5},
        }}})["z/w"]["text_surface"]
    assert surface["hostile_rows"] == 0
    assert surface["hostile_rows_flagged_rate"] is None
    assert surface["clean_rows_flagged_rate"] == 0.0
    assert report._pct(surface["hostile_rows_flagged_rate"]).startswith("n/a")


def test_the_renderer_still_computes_no_external_number():
    """The new sections obey the rule the whole renderer is built on."""
    block = json.loads(json.dumps(committed_external()))
    config = sorted(block["results"])[0]
    name = sorted(block["results"][config])[0]
    metrics = block["results"][config][name]
    metrics["accusation_rate"] = 0.7777
    metrics["messages"] = 41
    metrics["selective"]["operating_point"]["coverage"] = 0.3333
    text = "\n".join(report._corpus_section(name, metrics))
    assert "77.8%" in text and "41 message(s)" in text
    assert "| Coverage (automated without a human) | 33.3% |" in text
