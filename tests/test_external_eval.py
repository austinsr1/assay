"""The external-corpus harness: the licence gate, the wrapper, and what it costs.

Bundle N phase 1. Three kinds of thing are asserted here, in this order:

1. **The gate refuses without a network.** ``fetch.gate()`` is pure, so the licence
   decision is testable on a machine that cannot reach Hugging Face - which is the
   only kind of machine a licence decision should be made on. A gate that could only
   be exercised online is a gate that stops being exercised.
2. **Nothing downloaded is committed, and the provenance of the fetch is.** The
   data is gitignored by policy; ``eval/PROVENANCE.json`` and the ``external`` block in
   ``eval/metrics.json`` are the committed artifacts, and they are checked for shape,
   for completeness, and for the absence of message text.
3. **Every external number carries its limitation.** Not "has a field for it" - the
   text saying these corpora are plain text rather than RFC 822 messages, so the
   authentication layer cannot fire, must be present, and must survive into the
   rendered report. A number whose provenance is hidden is worse than no number.

Phase 1b - the datasets-server ROWS API that unlocked the three Parquet-only corpora,
and the honesty guards on what they show - is asserted in `tests/test_external_rows.py`.
This file keeps the gate, the wrapper and the artifact checks phase 1 wrote.

Nothing in this file touches the network, and nothing in it requires the corpora to
have been fetched: the suite must stay green on a fresh clone where ``eval/internal/``
is empty (acceptance criterion A7), which is the normal state of this repository
rather than an error condition. Where a check genuinely needs the bytes, it reads the
committed artifact instead, because the committed artifact records what was measured.
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "eval"))

import external  # noqa: E402  (imports fetch, and puts src/ on sys.path itself)
import fetch  # noqa: E402
import report  # noqa: E402
import run as eval_run  # noqa: E402
import selective  # noqa: E402

METRICS = REPO / "eval" / "metrics.json"
PROVENANCE = REPO / "eval" / "PROVENANCE.json"

#: Keys the renderer demands of every corpus descriptor. Imported rather than
#: restated: two copies of a required-field list drift, and the copy that drifts is
#: always the one in the test that was written to check the other.
REQUIRED = report.REQUIRED_EXTERNAL_FIELDS


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True,
                          text=True, timeout=60)


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


# --------------------------------------------------------------------------
# 1. the licence gate, exercised with no network
# --------------------------------------------------------------------------


def test_enron_spam_is_refused_and_names_the_observed_license_value():
    """The case that matters most: the most convenient ham set, still refused.

    `cardData.license` is absent for this dataset, which the gate reads as no
    permission rather than as no problem.
    """
    spec, refusal = fetch.gate("SetFit/enron_spam")
    assert spec is None
    assert "REFUSED" in refusal
    assert "SetFit/enron_spam" in refusal
    assert "None" in refusal, "the refusal must print the observed licence value"
    assert "cardData.license" in refusal, "and where it was observed"
    assert "does not mean granted" in refusal


def test_the_lgpl_phishing_dataset_is_refused_as_copyleft():
    spec, refusal = fetch.gate("zefang-liu/phishing-email-dataset")
    assert spec is None
    assert "lgpl-3.0" in refusal
    assert "copyleft" in refusal


def test_bipia_is_refused_by_default_and_named_as_share_alike():
    spec, refusal = fetch.gate("geodesic-research/bipia")
    assert spec is None
    assert "cc-by-sa-4.0" in refusal
    assert "share-alike" in refusal


def test_bipia_behind_the_flag_is_an_operator_decision_stated_as_one():
    """The flag permits the fetch and does not permit the obligation.

    The notice has to say what is being accepted, that share-alike inheritance is the
    submission owner's problem to accept, and that the tool is only standing aside
    because nothing downloaded is committed.
    """
    spec, refusal = fetch.gate("geodesic-research/bipia", allow_sharealike=True)
    assert spec is not None and refusal == ""
    assert spec.license == "cc-by-sa-4.0"
    notice = fetch.SHAREALIKE_NOTICE.format(
        dataset="geodesic-research/bipia", license=spec.license, reason="share-alike"
    )
    assert "operator" in notice and "not this tool" in notice
    assert "share-alike" in notice.lower()
    assert "--allow-sharealike" in notice, "and it must name the flag that did it"


def test_an_unlisted_dataset_is_refused_rather_than_fetched_with_a_warning():
    for dataset_id in ("some/random-dataset", "enron/emails", "SetFit/enron_spam_v2"):
        spec, refusal = fetch.gate(dataset_id)
        assert spec is None, dataset_id
        assert dataset_id in refusal
        assert "not on the allowlist" in refusal
        assert "closed" in refusal


@pytest.mark.parametrize("dataset_id", sorted(fetch.REFUSED) + sorted(fetch.SHAREALIKE))
def test_every_refusal_names_the_dataset_and_the_license_it_observed(dataset_id):
    _spec, refusal = fetch.gate(dataset_id)
    entry = (fetch.REFUSED | fetch.SHAREALIKE)[dataset_id]
    assert dataset_id in refusal, "a refusal that does not name what it refused is useless"
    assert entry["license"] in refusal, "and must print the value it read"
    assert entry["verified_on"] in refusal, "and the date it read it on"


def test_no_copyleft_share_alike_or_noncommercial_license_is_in_the_allowlist():
    """Structural guard on the table itself.

    A refused licence string appearing in ``PERMITTED`` would mean someone added a
    dataset to the allowlist without the decision that requires. The share-alike set
    has its own table precisely so it can never be reached by editing this one.
    """
    forbidden = ("lgpl", "gpl", "agpl", "cc-by-sa", "cc-by-nc", "openrail",
                 "non-commercial")
    for dataset_id, spec in fetch.PERMITTED.items():
        declared = str(spec.license).lower()
        assert declared, dataset_id
        assert "none" not in declared, dataset_id
        for term in forbidden:
            assert term not in declared, f"{dataset_id} allowlists {spec.license}"
        assert dataset_id not in fetch.REFUSED, dataset_id


def test_every_allowlisted_entry_records_an_observed_value_and_a_date():
    import re
    for dataset_id, spec in fetch.PERMITTED.items():
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", spec.verified_on), (
            f"{dataset_id}: the licence verification date must be explicit"
        )
        assert spec.why, f"{dataset_id}: say what the corpus is for"
        assert spec.limits, f"{dataset_id}: say what it cannot show"
        assert spec.files, dataset_id


@pytest.mark.parametrize("path", [
    "data/raw_submissions_phase1.jsonl", "data/raw_submissions_phase2.jsonl",
])
def test_the_two_hundred_megabyte_raw_submission_files_are_not_fetchable(path):
    """Named and excluded, rather than left out and silently unavailable.

    A request for one is refused by name before any bytes move, so a future session
    cannot conclude the file does not exist. `choose_files` is the pure half of the
    decision - the only way to prove this without downloading 1.67 GB.
    """
    assert path in fetch.FORBIDDEN_FILES
    spec = fetch.PERMITTED["microsoft/llmail-inject-challenge"]
    assert spec.file(path) is None, f"{path} must not be allowlisted"
    with pytest.raises(fetch.Refused) as raised:
        fetch.choose_files(spec, [path])
    assert path in str(raised.value)
    # And it is not in what a default fetch of that dataset would write.
    assert path not in [f.path for f in fetch.choose_files(spec)]


def test_an_unlisted_file_of_a_permitted_dataset_is_an_error_not_a_silent_no_op():
    spec = fetch.PERMITTED["leolee99/NotInject"]
    with pytest.raises(fetch.IntegrityError):
        fetch.choose_files(spec, ["data/does-not-exist.parquet"])
    assert fetch.choose_files(spec) == [f for f in spec.files if f.default]


def test_license_drift_text_names_both_the_observed_and_the_recorded_value():
    spec = fetch.PERMITTED["leolee99/NotInject"]
    text = fetch.license_drift(spec, "gpl-3.0")
    assert "gpl-3.0" in text and spec.license in text and spec.verified_on in text
    assert "Re-read" in text, "and it must say what a human has to do"


def test_a_repo_path_with_traversal_in_it_is_refused():
    """The write guard, not a comment about the write guard.

    ``destination`` derives the local name from the upstream basename, so a traversal
    prefix cannot escape the directory anyway - but it can silently *flatten* two
    upstream paths onto one local file, and the fetched digest would then describe
    whichever arrived last. Refusing the path is the honest answer.
    """
    spec = fetch.PERMITTED["microsoft/llmail-inject-challenge"]
    for hostile in ("data/../../evil.json", "data/..", "./data/x.json",
                   "data//x.json", "data/"):
        with pytest.raises(fetch.IntegrityError):
            fetch.destination(spec, fetch.FileSpec(path=hostile, role="x", fmt="json"))
    with pytest.raises(fetch.IntegrityError):
        fetch._guard_write(REPO / "src" / "tenable_email" / "leak.json")
    with pytest.raises(fetch.IntegrityError):
        fetch._guard_write(pathlib.Path("/tmp/outside-the-repo.json"))
    # And the guarded path really is inside the gitignored directory.
    target = fetch.destination(spec, spec.files[0])
    assert str(target).startswith(str(fetch.INTERNAL))


@pytest.mark.parametrize("dataset_id", sorted(list(fetch.PERMITTED) + list(fetch.SHAREALIKE)))
def test_allowlisted_basenames_are_unique_within_each_dataset(dataset_id: str):
    """Two upstream paths sharing a basename would overwrite each other in silence.

    Files are stored flat under the dataset slug, which is what makes the manifest's
    `local_path` readable. That is only safe if the flattening is injective, and this
    is the check that keeps it that way.
    """
    spec = fetch.PERMITTED.get(dataset_id) or fetch.SHAREALIKE[dataset_id]
    files = spec.files if hasattr(spec, "files") and not isinstance(spec, dict) else spec["files"]
    names = [f.basename for f in files]
    assert len(names) == len(set(names)), f"{dataset_id}: {names}"


@pytest.mark.parametrize("dataset_id", sorted(fetch.PERMITTED))
def test_every_allowlisted_path_is_a_plain_normalized_repo_path(dataset_id: str):
    """The table itself must be free of the shapes the guard above refuses.

    Checked at the data rather than only at the call site: an allowlist entry that the
    fetcher would reject is a bug that waits until someone runs the fetch.
    """
    spec = fetch.PERMITTED[dataset_id]
    for file_spec in spec.files:
        assert fetch.destination(spec, file_spec) is not None, file_spec.path


def test_a_synthesized_message_cannot_be_written_outside_eval_internal():
    outside = REPO / "fixtures" / "synthetic" / "injected.eml"
    with pytest.raises(fetch.IntegrityError):
        external._write_message(outside, "From: x\n\nbody\n")
    assert not outside.exists(), (
        "the guard must reject before writing, not after: a corpus file that lands in "
        "fixtures/ is committed by the next `git add fixtures`"
    )


def test_the_sharealike_notice_prints_before_any_bytes_move(monkeypatch, capsys):
    """The flag's path is exercised without accepting the obligation for real.

    Fetching BIPIA would mean *taking* the share-alike decision, and that is the
    operator's to take - so the test proves the code path instead: the notice is
    printed, and it is printed before any download is attempted, which is what makes
    it a warning rather than a post-hoc explanation. The transport is replaced with one
    that raises, so nothing is fetched and nothing is written.
    """
    def boom(*_args, **_kwargs):
        raise fetch.UpstreamError("no network in this test")

    def canned_json(_url, **_kwargs):
        return {"cardData": {"license": "cc-by-sa-4.0"}, "sha": "0" * 40,
                "gated": False, "private": False}

    monkeypatch.setattr(fetch, "_get", boom)
    monkeypatch.setattr(fetch, "_get_json", canned_json)
    with pytest.raises(fetch.UpstreamError):
        fetch.fetch("geodesic-research/bipia", allow_sharealike=True)
    printed = capsys.readouterr().out
    assert "--allow-sharealike was given" in printed
    assert "cc-by-sa-4.0" in printed
    assert "geodesic-research/bipia" in printed


def test_a_changed_upstream_license_stops_a_permitted_fetch(monkeypatch):
    """The re-read is not decoration: an allowlisted dataset whose declaration moved
    is refused, with both values named.
    """
    def canned_json(url, **_kwargs):
        if "/tree/" in url:
            return []
        return {"cardData": {"license": "gpl-3.0"}, "sha": "0" * 40,
                "gated": False, "private": False}

    monkeypatch.setattr(fetch, "_get_json", canned_json)
    with pytest.raises(fetch.Refused) as raised:
        fetch.fetch("leolee99/NotInject")
    text = str(raised.value)
    assert "gpl-3.0" in text and "mit" in text and "2026-11-03" in text


def test_a_gated_dataset_is_refused_even_when_it_is_allowlisted(monkeypatch):
    """An MIT declaration and a gated repo are different questions, and both gate.

    Nothing here has a Hugging Face account, so a gated dataset cannot be fetched
    whatever its licence says - and the refusal says which of the two it is.
    """
    def canned_json(url, **_kwargs):
        if "/tree/" in url:
            return []
        return {"cardData": {"license": "mit"}, "sha": "0" * 40,
                "gated": "auto", "private": False}

    monkeypatch.setattr(fetch, "_get_json", canned_json)
    with pytest.raises(fetch.Refused) as raised:
        fetch.fetch("leolee99/NotInject")
    assert "gated" in str(raised.value)


# --------------------------------------------------------------------------
# 2. nothing fetched is committed; the provenance of the fetch is


@requires_repo
def test_nothing_under_eval_internal_is_tracked_by_git():
    """A1, as a build failure rather than as a rule in a document.

    `git ls-files` is the index, so this is about tracked bytes rather than about
    whether the directory happens to exist on this host.
    """
    listed = _git("ls-files", "eval/internal").stdout.strip()
    assert listed == "", f"tracked files under eval/internal/: {listed}"
    count = len(listed.splitlines()) if listed else 0
    assert count == 0


@requires_repo
def test_the_working_tree_reports_nothing_under_eval_internal():
    """Untracked files under a gitignored path must not appear either.

    Checked with `--untracked-files=all` so a directory of loose files cannot hide
    behind the collapsed path `git status` prints by default.
    """
    status = _git("status", "--porcelain", "--untracked-files=all", "eval/internal")
    assert status.returncode == 0
    assert status.stdout.strip() == "", status.stdout


@requires_repo
def test_a_file_placed_under_eval_internal_cannot_be_staged_without_forcing():
    """The mechanism that makes A1 survive an agent who runs `git add -A`.

    git refuses an ignored path unless `-f` is used, so the policy is enforced by the
    tool rather than by remembering a rule. The canary is added with --dry-run, which
    cannot touch the index, and removed afterwards.
    """
    created_directory = not fetch.INTERNAL.is_dir()
    fetch.INTERNAL.mkdir(parents=True, exist_ok=True)
    canary = fetch.INTERNAL / "canary-that-must-not-stage.json"
    canary.write_text('["not a real corpus"]', encoding="utf-8")
    try:
        attempt = _git("add", str(canary))
        assert attempt.returncode != 0, (
            "git accepted a file under eval/internal/: the ignore rule is gone, and "
            "downloaded corpora can now be committed"
        )
        assert "ignored" in (attempt.stdout + attempt.stderr).lower()
        assert _git("ls-files", "eval/internal").stdout.strip() == ""
    finally:
        canary.unlink()
        if created_directory:
            fetch.INTERNAL.rmdir()


def test_eval_internal_is_declared_in_gitignore():
    text = (REPO / ".gitignore").read_text(encoding="utf-8")
    assert "eval/internal/" in text
    assert "eval/internal/*" not in text.split("\n"), (
        "the directory itself must be ignored, not only its contents: a negation "
        "pattern would let a subdirectory be added with one extra flag"
    )


def test_the_committed_provenance_record_exists_and_is_ours():
    """N5: the manifest is committed, the data is not.

    The record is measurements *about* bytes - digests, sizes, revisions, licences -
    which is what lets a published artifact describe a fetch it does not contain.
    """
    assert PROVENANCE.is_file(), (
        "eval/PROVENANCE.json is missing: `python3 eval/fetch.py --write-provenance "
        "eval/PROVENANCE.json` writes it from the fetch manifest"
    )
    record = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    assert record["schema_version"] == 1
    assert record["recorded_by"] == "eval/fetch.py"
    assert record["policy"], "and it must state in its own words that no data is committed"
    assert "Nothing downloaded is committed" in record["policy"]
    assert record["commit"] and record["commit"] != "UNDETERMINED"
    assert set(record["refused"]) == set(fetch.REFUSED)
    assert set(record["refused_without_the_sharealike_flag"]) == set(fetch.SHAREALIKE)


def test_every_provenance_file_records_the_fields_a_refetch_needs():
    record = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    assert record["datasets"], "the record exists to describe a fetch"
    for dataset_id, block in record["datasets"].items():
        assert dataset_id in fetch.PERMITTED, f"{dataset_id} is not allowlisted"
        assert block["revision"], dataset_id
        assert block["license_observed"], dataset_id
        assert block["license_verified_on"], dataset_id
        assert block["license_field"] == "cardData.license"
        assert block["api_url"].startswith("https://huggingface.co/api/datasets/")
        assert len(block["revision"]) == 40, "a pinned revision is a commit sha"
        assert block["files"], dataset_id
        for repo_path, entry in block["files"].items():
            assert set(entry) == set(fetch.PROVENANCE_FILE_FIELDS), (
                f"{dataset_id}:{repo_path} carries fields the writer does not declare: "
                f"{sorted(set(entry) - set(fetch.PROVENANCE_FILE_FIELDS))}"
            )
            assert entry["source_url"].startswith("https://huggingface.co/datasets/")
            assert block["revision"] in entry["source_url"], (
                f"{dataset_id}:{repo_path} is fetched from a URL that does not pin "
                "the revision, so re-running the fetch would not reproduce it"
            )
            assert len(entry["sha256"]) == 64, repo_path
            assert isinstance(entry["bytes"], int) and entry["bytes"] > 0
            assert entry["local_path"].startswith("eval/internal/"), (
                "a fetched file must live under the gitignored directory"
            )
            assert entry["row_count"] is None or isinstance(entry["row_count"], int)
            assert entry["row_count_method"], (
                "a missing row count needs the reason it is not determinable"
            )


def test_the_provenance_row_counts_match_numbers_the_project_published_separately():
    """Cross-checks the Parquet footer reader against an independent source.

    ``docs/EVAL-SUITES.md`` recorded notinject 339, deepset_test 116 and smish_bn
    1,401 on 2026-11-02 from the suites' own files. Those counts come out of a
    Thrift-compact field skimmer written for this bundle, so agreement is evidence
    about the skimmer rather than about the corpora.
    """
    record = json.loads(PROVENANCE.read_text(encoding="utf-8"))

    def rows(dataset_id: str, suffix: str) -> int:
        for repo_path, entry in record["datasets"][dataset_id]["files"].items():
            if repo_path.endswith(suffix):
                return entry["row_count"]
        raise AssertionError(f"no {suffix} in {dataset_id}")

    notinject = sum(
        entry["row_count"]
        for path, entry in record["datasets"]["leolee99/NotInject"]["files"].items()
        if path.endswith(".parquet")
    )
    assert notinject == 339, notinject
    assert rows("deepset/prompt-injections",
                "test-00000-of-00001-701d16158af87368.parquet") == 116
    assert rows("deepset/prompt-injections",
                "train-00000-of-00001-9564e8b05b4757ab.parquet") == 546
    assert rows("shariul-islam/bengali-sms-smishing-dataset",
                "test-00000-of-00001.parquet") == 1401
    assert rows("microsoft/llmail-inject-challenge",
                "emails_for_fp_tests.json") == 203


def test_the_parquet_footer_reader_agrees_with_the_count_for_json_and_csv_too():
    """The row-count methods must not be one format that got tested and four guesses.

    A JSON list, a JSON object, a CSV whose quoted fields contain newlines and a
    non-Parquet blob are each counted, and the CSV case is the one a line count gets
    wrong.
    """
    rows, _method = fetch.count_rows(b'["a", "b", "c"]', "list", "json")
    assert rows == 3
    rows, _method = fetch.count_rows(b'{"x": 1, "y": 2}', "dict", "json")
    assert rows == 2
    rows, _method = fetch.count_rows(b'a,b\n"one\\ntwo",3\n', "csv", "csv")
    assert rows == 1, "two physical lines, one record: a line count would say 2"
    rows, _method = fetch.count_rows(b'{"a": 1}\n{"b": 2}\n\n', "lines", "jsonl")
    assert rows == 2
    rows, method = fetch.count_rows(b"just prose", "none", "text")
    assert rows is None and "row-bearing" in method
    rows, _method = fetch.count_rows(b"not a parquet file", "parquet-footer", "parquet")
    assert rows is None, "a footer that is not there must not report zero rows"


def test_artifacts_of_the_fetch_contain_no_message_text():
    """The data is the thing that must not be committed, so test for the data.

    Two guards, both able to fail. Structurally: every provenance file entry holds
    only the declared fields, each a short single-line scalar, and every per-message
    row holds only the committed row keys with short scalar values. By content: three
    strings that occur in the fetched corpora are absent from both artifacts. A guard
    that only checks a field name would pass while carrying a message body in it.
    """
    record = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    for dataset_id, block in record["datasets"].items():
        for repo_path, entry in block["files"].items():
            for key, value in entry.items():
                assert isinstance(value, (str, int, bool, type(None))), (
                    f"{dataset_id}:{repo_path}.{key} is {type(value).__name__}, not a "
                    "scalar: a nested value is where corpus content would ride"
                )
                if isinstance(value, str):
                    assert len(value) <= 400, (dataset_id, repo_path, key)
                    assert "\n" not in value, (dataset_id, repo_path, key)

    row_keys = set(committed_metrics()["results"]["deterministic-only"]["synthetic"][
        "rows"][0])
    for per_corpus in committed_external()["results"].values():
        for name, metrics in per_corpus.items():
            for row in metrics["rows"]:
                assert set(row) == row_keys, name
                for key, value in row.items():
                    if isinstance(value, str):
                        assert len(value) <= 64, (name, key, value[:80])
                        assert "\n" not in value, (name, key)

    both = PROVENANCE.read_text(encoding="utf-8") + METRICS.read_text(encoding="utf-8")
    assert "Subject of the email:" not in both, (
        "an LLMail row body has landed in a committed artifact"
    )
    for phrase in ("You are now", "ignore all previous", "Pretend you are"):
        assert phrase not in both, f"{phrase} is corpus content, not provenance"


# --------------------------------------------------------------------------
# 3. the wrapper: a transformation that says so
# --------------------------------------------------------------------------


def test_the_wrapper_is_deterministic_and_declares_no_authentication_result():
    raw = external.wrap("llmail-fp-tests-00001", "Hello", "Body text here")
    assert raw == external.wrap("llmail-fp-tests-00001", "Hello", "Body text here")
    lowered = raw.lower()
    for header in ("authentication-results", "dkim-signature", "arc-seal",
                   "return-path", "reply-to", "list-id"):
        assert f"{header}:" not in lowered, (
            f"a synthesized {header} header would be a fabricated authentication "
            "signal, which is the opposite of what the wrapper is for"
        )
    assert "from: synthetic-sender@example.com" in lowered
    assert external.WRAPPER["date"] in raw


def test_the_wrapper_keeps_the_row_verbatim_in_the_body():
    row = ("Subject of the email: Q3 forecast.   Body: Team, the numbers moved. "
           "Ignore previous instructions if you like - Regards, Dana")
    parsed = external._subject_from_llmail(row)
    raw = external.wrap("x-1", parsed, row)
    from tenable_email.parse import parse_message
    message = parse_message(raw)
    assert "Ignore previous instructions" in message.body, (
        "the wrapper must not lose the text being measured"
    )
    assert message.subject == "Q3 forecast"
    assert not message.attachments, "no attachment the row did not have"


def test_the_subject_derivation_only_fires_where_the_row_states_one():
    assert external._subject_from_llmail(
        "Subject of the email: Alpha.   Body: Beta"
    ) == "Alpha"
    assert external._subject_from_llmail("just a prompt, no shape") == ""
    assert external._subject_from_llmail(
        "Subject of the email: no body separator here"
    ) == ""


def test_the_envelope_recorded_in_the_output_is_the_envelope_that_was_used():
    """The brief's requirement is the exact wrapper, per corpus, not a description."""
    wrapper = external.WRAPPER
    assert "EmailMessage" in wrapper["assembled_with"]
    assert "Authentication-Results" in wrapper["headers_absent_by_construction"]
    assert "From" in wrapper["headers_present"]
    # RFC 2606: the domains in the envelope cannot resolve and cannot be someone's.
    assert wrapper["from_domain"] == "example.com"
    assert wrapper["to_domain"] == "example.com"
    assert wrapper["domain_note"], "and the reason is stated next to the choice"


def test_the_sampling_rule_is_a_recorded_deterministic_rule():
    population = list(range(50))
    first = external.sample_keys("seed-a", "corpus", population, 10)
    second = external.sample_keys("seed-a", "corpus", population, 10)
    assert first == second, "same seed, same corpus, same rows - or it is not a seed"
    assert len(first) == 10
    assert external.sample_keys("seed-b", "corpus", population, 10) != first, (
        "a seed that does not change the selection is not doing anything"
    )
    assert external.sample_keys("seed-a", "other", population, 10) != first
    assert external.sample_keys("seed-a", "corpus", population, 500) == set(population), (
        "a cap above the population must take all of it and say so"
    )
    assert "sha256" in external.SAMPLING_RULE, "the rule is written down, not implied"


def test_the_pipeline_row_shape_is_reused_not_restated():
    """Every external row has exactly the keys the committed rows have.

    If it gained a field, `selective.py` would be reading a different shape and the
    two measurements would silently mean different things.
    """
    committed = committed_external()
    if not committed["results"]:
        pytest.fail(
            "the committed external block has no measurements, so the row-shape "
            "guard has nothing to check; regenerate with `python3 eval/run.py --json "
            "--external -o eval/metrics.json`"
        )
    offline_rows = committed_metrics()["results"]["deterministic-only"]["synthetic"]["rows"]
    expected = set(offline_rows[0])
    for per_corpus in committed["results"].values():
        for name, metrics in per_corpus.items():
            assert metrics["rows"], name
            assert set(metrics["rows"][0]) == expected, (
                f"{name}: the external row shape drifted from the committed one"
            )


def test_no_external_disposition_can_be_wrong_by_having_no_label():
    """`selective.is_error` returns None for an unrecognized label.

    A corpus whose rows are undecidable produces rates computed over nothing, which
    reads exactly like rates computed over the corpus. This is the bug that hid the
    adversarial corpus for a session.
    """
    committed = committed_external()
    for per_corpus in committed["results"].values():
        for name, metrics in per_corpus.items():
            point = selective.operating_point(metrics["rows"])
            assert point["undecidable"] == 0, (
                f"{name}: {point['undecidable']} undecidable rows"
            )
            assert point["messages"] == metrics["messages"]


# --------------------------------------------------------------------------
# 4. the external block in the committed artifact
# --------------------------------------------------------------------------


def test_the_external_block_names_every_corpus_with_its_license_revision_and_limitation():
    """A6, against the artifact rather than against a fresh measurement."""
    committed = committed_external()
    for name, descriptor in committed["corpora"].items():
        for key in REQUIRED:
            assert descriptor.get(key) not in (None, ""), f"{name} missing {key}"
        for phrase in report.LIMITATION_SENTENCES:
            assert phrase in descriptor["limitation"], f"{name}: {phrase}"
        assert descriptor["source_url"].startswith("https://huggingface.co/datasets/")
        assert descriptor["label_source"], name
        assert descriptor["sample"]["rule"] == external.SAMPLING_RULE
    for per_corpus in committed["results"].values():
        for name, metrics in per_corpus.items():
            descriptor = metrics["external"]
            assert descriptor["limitation"] == committed["limitation"], (
                f"{name}: the per-corpus limitation drifted from the block's"
            )
            for phrase in report.LIMITATION_SENTENCES:
                assert phrase in descriptor["limitation"]


def test_the_external_block_is_measured_by_the_same_code_as_the_committed_corpora():
    """Rerate every external rate from its own rows.

    The rates are recomputed here as a *check on the artifact*, in the same way
    ``tests/test_eval.py`` does for the committed corpora. If the harness ever
    publishes a rate that its rows do not support, this fails.
    """
    committed = committed_external()
    for config, per_corpus in committed["results"].items():
        for name, metrics in per_corpus.items():
            rows = metrics["rows"]
            total = len(rows)
            assert total == metrics["messages"], f"{config}/{name}"
            accused = [r for r in rows if r["disposition"] in selective.ACCUSATIONS]
            deferred = [r for r in rows if r["disposition"] in selective.DEFERRALS]
            assert metrics["accusation_rate"] == round(len(accused) / total, 4)
            assert metrics["escalation_rate"] == round(len(deferred) / total, 4)
            benign = [r for r in rows if r["label"] in selective.BENIGN_LABELS]
            if benign:
                wrongly_accused = [r for r in benign
                                   if r["disposition"] in selective.ACCUSATIONS]
                assert metrics["false_accusation_count"] == len(wrongly_accused)
                assert metrics["false_accusation_rate_among_benign"] == round(
                    len(wrongly_accused) / len(benign), 4
                )


def test_the_llmail_false_positive_measurement_is_recorded_with_its_denominator():
    """A5, pinned in the committed artifact: the number and the population it is over.

    Benign business emails that our pipeline accused of being threat or spam, out of
    all 203 in the file - and the manual_review count kept separate, because deferring
    is not accusing and a report that merges them describes a different tool.
    """
    committed = committed_external()
    for config, per_corpus in committed["results"].items():
        if "llmail-fp-tests" not in per_corpus:
            continue
        metrics = per_corpus["llmail-fp-tests"]
        assert metrics["messages"] == 203
        assert metrics["benign_messages"] == 203
        assert metrics["false_accusation_count"] == 0, metrics["false_accusations"]
        assert metrics["false_accusation_rate_among_benign"] == 0.0
        deferred = metrics["by_disposition"].get("manual_review", 0)
        assert deferred + metrics["false_accusation_count"] <= metrics["messages"]
        assert metrics["escalation_rate"] == round(deferred / 203, 4), (
            "the deferral rate must be its own number, not folded into the "
            "false-positive rate"
        )
        assert metrics["kind"] == "labelled"
        return
    pytest.fail(
        "llmail-fp-tests is not in the committed external block: the false-positive "
        "measurement over the 203 benign LLMail emails is the decision-relevant number "
        "of Bundle N phase 1 and must be published, not re-derivable only"
    )


def test_the_jailbreak_corpus_reports_the_detection_side_separately():
    """Hostile-labelled rows are measured as 'cleared anyway', never as an agreement.

    Mapping upstream `jailbreak` onto `hostile` rather than `threat` is deliberate: a
    jailbreak string in an email is an agent-manipulation attempt, not a claim that the
    message is a credential phish.
    """
    committed = committed_external()
    for per_corpus in committed["results"].values():
        metrics = per_corpus.get("jackhhao-test-jailbreak")
        if metrics is None:
            continue
        assert metrics["kind"] == "hostile"
        assert metrics["messages"] == 141
        assert metrics["hostile_cleared_count"] == 0, metrics["hostile_cleared"]
        assert metrics["hostile_deferred"] + metrics["hostile_accused"] \
            == metrics["messages"]
        labels = {r["label"] for r in metrics["rows"]}
        assert labels == {"hostile"}
        return
    pytest.fail("jackhhao-test-jailbreak is missing from the committed external block")


def test_the_committed_external_numbers_are_reproducible_or_the_artifact_says_so():
    """The external scope of the staleness guard, split by what this host can check.

    With the corpora on disk the block must reproduce byte for byte - the same pin
    ``tests/test_eval.py`` applies to the committed corpora. Without them, the block
    cannot be re-measured here, so what is asserted instead is that the artifact
    states the provenance needed to re-measure it elsewhere: revisions, digests, the
    fetch command, and the fact that it was measured on a host that had fetched.
    """
    committed = committed_external()
    here = eval_run.measure(external=True)["external"]
    if here["status"] == "measured":
        assert here == committed, (
            "eval/metrics.json's external block does not match what the code measures "
            "from the fetched corpora. Regenerate with `python3 eval/run.py --json "
            "--external -o eval/metrics.json`."
        )
        return
    # Nothing fetched on this host: the config axis stays, the corpora do not, and no
    # rows are invented. `run.py` measures each configuration and finds nothing to
    # measure, which is the honest shape - a report of zero corpora per configuration
    # rather than a block that looks unmeasured and is really empty.
    assert here["corpora"] == {}
    assert here["results"], "the config axis is kept"
    assert all(per_corpus == {} for per_corpus in here["results"].values()), (
        f"expected no corpora in any configuration, got {here['results']}"
    )
    assert sum(len(v) for v in here["results"].values()) == 0
    assert here["status"] == "not-fetched"
    assert "fetch.py" in json.dumps(here), "and it must name the way out"
    if committed["status"] == "measured":
        assert committed["measured_here"] is True
        for name, descriptor in committed["corpora"].items():
            assert descriptor["revision"] and descriptor["sha256"], name
            assert descriptor["source_url"], name


def test_a_host_with_nothing_fetched_degrades_to_a_clear_not_fetched_state():
    """A7's mechanism, tested without needing an empty disk.

    Pointing the loader at a manifest that does not exist is exactly the state of a
    fresh clone. It must produce no corpora and no rows, and must not produce a zero
    - a zero is a measurement, and there was none.
    """
    real = fetch.MANIFEST
    try:
        fetch.MANIFEST = fetch.INTERNAL / "absent-manifest-for-tests.json"
        plan = external.build_plan()
        assert plan["status"] == "not-fetched"
        assert plan["results"] == {} and plan["corpora"] == {}
        assert plan["measured_here"] is False
        assert "nothing here was measured" in plan["headline"]
        assert "eval/fetch.py" in json.dumps(plan["detail"])
        assert plan["limitation"] == external.LIMITATION, (
            "even the absence must carry the caveat, or a reader of the report cannot "
            "tell an empty section from an unmeasured one"
        )
        assert plan["allowlisted"] == sorted(fetch.PERMITTED)
        assert plan["refused"] == sorted(fetch.REFUSED)
        # And run.py measures that state without raising and without inventing rows.
        block = eval_run.measure_external(["deterministic-only"], plan=plan)
        assert block["results"] == {"deterministic-only": {}}
    finally:
        fetch.MANIFEST = real


def test_the_unavailable_list_names_what_was_fetched_and_not_evaluated():
    """A permitted file this build cannot read is stated, with its row count.

    Phase 1 wrote this test against six Parquet files it could pin and not read. Phase 1b
    measures them through the datasets-server ROWS API, so the assertion is now the other
    way round: nothing may be listed as unread that is also listed as measured, and any
    entry that does appear must carry a reason, a digest and the row count read off the
    file - the guard that keeps a gap on the record instead of turning it into a smaller
    corpus. Tests for the retrieval mechanism itself are in ``tests/test_external_rows.py``.
    """
    committed = committed_external()
    unavailable = committed["unavailable"]
    for item in unavailable:
        assert item["reason"], item
        if item.get("row_count_file") is not None:
            assert item.get("sha256"), "a pinned row count without a digest is unverified"
    measured = {(d["dataset"], d["file"]) for d in committed["corpora"].values()}
    for item in unavailable:
        if item.get("file"):
            assert (item["dataset"], item["file"]) not in measured, (
                f"{item['file']} is reported both measured and unreadable: "
                f"{item['reason'][:80]}"
            )
    if committed["status"] == "measured":
        assert unavailable == [], (
            f"every permitted file with a rows retrieval should be measured; "
            f"still listed: {[i.get('file') or i.get('corpus') for i in unavailable]}"
        )


# --------------------------------------------------------------------------
# 5. the renderer
# --------------------------------------------------------------------------


def rendered_external(committed: dict | None = None) -> str:
    block = (committed if committed is not None else committed_external())
    return "\n".join(report._external_section(block))


def test_the_report_prints_the_envelope_the_license_and_the_revision_it_read():
    text = rendered_external()
    committed = committed_external()
    assert "## External corpora" in text
    assert "Authentication-Results" in text, "the absent headers are part of the envelope"
    assert "example.com" in text
    assert "plain text, not RFC 822 messages" in text
    assert "NOT the authentication layer" in text
    for descriptor in committed["corpora"].values():
        assert descriptor["revision"] in text
        assert descriptor["sha256"] in text
        assert descriptor["license_observed"] in text
        assert descriptor["source_url"] in text
    for phrase in report.LIMITATION_SENTENCES:
        assert phrase in text


def test_the_limitation_is_printed_for_every_corpus_and_not_once_for_all():
    text = rendered_external()
    committed = committed_external()
    for name in committed["corpora"]:
        assert text.count(f"External corpus `{name}`") >= 1, name
    measured = sum(
        len(per_corpus) for per_corpus in committed["results"].values()
    )
    assert text.count(external.LIMITATION) >= measured, (
        "the limitation is repeated per corpus, not stated once where a reader may "
        "or may not be looking"
    )


def test_the_report_raises_when_an_external_corpus_has_no_provenance():
    """N4's loud failure, one mutation at a time.

    Each mutation is a block that would still render a number, which is the point:
    the guard exists for the case where the number is printable and its provenance
    is not.
    """
    block = json.loads(json.dumps(committed_external()))
    name = sorted(block["corpora"])[0]
    config = sorted(block["results"])[0]
    metrics = block["results"][config][name]

    without_descriptor = json.loads(json.dumps(metrics))
    del without_descriptor["external"]
    mutated = json.loads(json.dumps(block))
    mutated["results"][config][name] = without_descriptor
    with pytest.raises(report.MalformedExternalMetrics) as raised:
        report._external_section(mutated)
    assert name in str(raised.value)

    for field in ("license_observed", "revision", "sha256", "source_url",
                  "rows_used", "label_source", "limitation", "text_origin", "label"):
        mutated = json.loads(json.dumps(block))
        del mutated["results"][config][name]["external"][field]
        with pytest.raises(report.MalformedExternalMetrics) as raised:
            report._external_section(mutated)
        assert field in str(raised.value), field


def test_the_report_raises_when_the_limitation_no_longer_says_what_it_must_say():
    """A field named `limitation` is not the requirement; the sentence is.

    Rewording it into something softer - dropping the authentication-layer statement -
    is the failure this guards, because it looks like compliance in a diff.
    """
    for softened in (
        "These corpora are public datasets.",
        "External corpus: the rows are plain text, not RFC 822 messages.",
        "External corpus: plain text, so this measures the authentication layer well.",
    ):
        block = json.loads(json.dumps(committed_external()))
        config = sorted(block["results"])[0]
        name = sorted(block["results"][config])[0]
        block["limitation"] = external.LIMITATION
        block["results"][config][name]["external"]["limitation"] = softened
        with pytest.raises(report.MalformedExternalMetrics):
            report._external_section(block)


def test_the_report_raises_when_the_block_itself_is_incomplete():
    for field in report.REQUIRED_BLOCK_FIELDS:
        block = json.loads(json.dumps(committed_external()))
        del block[field]
        with pytest.raises(report.MalformedExternalMetrics) as raised:
            report._external_section(block)
        assert field in str(raised.value), field

    with pytest.raises(report.MalformedExternalMetrics):
        report._external_section([])


def test_the_report_recomputes_no_external_number():
    """The renderer's central rule, applied to the new section.

    A payload that contradicts itself must come out contradicting itself. If this
    test ever prints the recomputed value instead, the renderer has become a second
    implementation of the measurement.
    """
    block = json.loads(json.dumps(committed_external()))
    config = sorted(block["results"])[0]
    name = sorted(block["results"][config])[0]
    metrics = block["results"][config][name]
    metrics["accusation_rate"] = 0.7777
    metrics["messages"] = 41
    metrics["selective"]["operating_point"]["coverage"] = 0.3333
    text = "\n".join(report._corpus_section(name, metrics))
    assert "77.8%" in text
    assert "41 message(s)" in text
    assert "| Coverage (automated without a human) | 33.3% |" in text


def test_the_not_fetched_state_is_rendered_as_an_absence_and_never_as_zero_rows():
    real = fetch.MANIFEST
    try:
        fetch.MANIFEST = fetch.INTERNAL / "absent-manifest-for-tests.json"
        block = external.not_fetched_state(external.fetched_manifest())
        block["results"] = {}
        text = "\n".join(report._external_section(block))
        assert "Nothing was measured here" in text
        assert "not a zero" in text
        assert "0 message(s)" not in text
        assert "eval/fetch.py" in text
    finally:
        fetch.MANIFEST = real


def test_an_artifact_generated_without_external_says_that_is_why_it_is_empty():
    """The renderer may not be silent about a section that could have been here."""
    payload = eval_run.measure()
    assert "external" not in payload
    text = report.render_markdown(payload)
    assert "not measured in this artifact" in text
    assert "--external" in text


def test_a_missing_selective_block_in_an_external_corpus_still_raises():
    """The discipline that already guarded the committed corpora covers the new ones.

    Every corpus, committed or fetched, is measured by the same code and rendered by
    the same function - so the same guard has to fire, or the new section would have
    quietly weaker rules than the old one.
    """
    block = json.loads(json.dumps(committed_external()))
    config = sorted(block["results"])[0]
    name = sorted(block["results"][config])[0]
    del block["results"][config][name]["selective"]
    with pytest.raises(report.MissingSelectiveMetrics) as raised:
        report._external_section(block)
    assert name in str(raised.value)


# --------------------------------------------------------------------------
# 6. the dependency rule, for the two new modules specifically
# --------------------------------------------------------------------------

#: Modules from this repository's own tree that the eval scripts may import.
OWN_TREE = {"fetch", "external", "report", "selective", "run", "tenable_email"}


def _imported_roots(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
    return roots


@pytest.mark.parametrize("name", ["eval/fetch.py", "eval/external.py", "eval/run.py",
                                  "eval/report.py", "eval/selective.py"])
def test_the_harness_imports_nothing_outside_the_standard_library(name: str):
    """`dependencies = []` is a claim about these files too.

    `sys.stdlib_module_names` is the interpreter's own list, so the check does not
    depend on a curated allowlist staying current - and there is no third-party
    package on this host that a corpus fetcher could quietly reach for.
    """
    path = REPO / name
    stdlib = set(sys.stdlib_module_names)
    offenders = sorted(_imported_roots(path) - stdlib - OWN_TREE)
    assert not offenders, f"{name} imports non-stdlib: {offenders}"


def test_pyproject_still_declares_no_runtime_dependency():
    """Read from the file rather than parsed with tomllib.

    `tomllib` is 3.11+ and the package floor is 3.10, so a test that imported it would
    be the reason the suite cannot run on a declared-supported interpreter - and this
    test exists to protect the dependency floor, not to move it.
    """
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in text, (
        "the external harness must not become the reason the package gained a "
        "dependency: it fetches with urllib and parses with csv and json"
    )


def test_the_gate_makes_no_network_request_when_it_refuses():
    """A refusal that dialled out first would fetch the thing it refuses to use.

    Patching the HTTP helper to explode proves the refusal path never reaches it -
    the same technique ``tests/test_attachments.py`` uses to prove a refusal started
    no subprocess.
    """
    def explode(*_args, **_kwargs):
        raise AssertionError("the licence gate performed a network request")

    real = fetch._get
    try:
        fetch._get = explode
        for dataset_id in ("SetFit/enron_spam", "zefang-liu/phishing-email-dataset",
                           "geodesic-research/bipia", "not/listed"):
            _spec, refusal = fetch.gate(dataset_id)
            assert "REFUSED" in refusal
        with pytest.raises(fetch.Refused):
            fetch.fetch("SetFit/enron_spam")
    finally:
        fetch._get = real


@requires_repo
def test_the_provenance_record_is_actually_tracked():
    """Committing the manifest is required, so a missing one is a build failure."""
    tracked = set(_git("ls-files").stdout.splitlines())
    assert "eval/PROVENANCE.json" in tracked
    assert "eval/fetch.py" in tracked and "eval/external.py" in tracked
