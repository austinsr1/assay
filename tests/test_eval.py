"""The evaluation harness, and the numbers it commits.

Two things are tested here. That ``eval/run.py`` measures correctly, and that the
committed ``eval/metrics.json`` still matches what the code produces -- the same
pattern ``tests/test_results_evidence.py`` uses for the suite's own results, and
for the same reason: a measurement committed to a repository goes stale the
moment the code moves, and a stale measurement is worse than none because it
looks like evidence.

The invariants pinned below are the ones the project is willing to be judged on.
They are deliberately stated as *safety* properties with a *coverage* floor beside
each, because a safety property alone can be satisfied by a tool that escalates
everything and is therefore useless.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "eval"))

METRICS = REPO / "eval" / "metrics.json"


def _load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run = _load_module("eval_run", REPO / "eval" / "run.py")
report = _load_module("eval_report", REPO / "eval" / "report.py")
selective = _load_module("eval_selective", REPO / "eval" / "selective.py")


@pytest.fixture(scope="module")
def fresh() -> dict:
    """Measured now, from the code as it stands."""
    return run.measure()


@pytest.fixture(scope="module")
def committed() -> dict:
    assert METRICS.is_file(), (
        f"{METRICS} is missing. Generate it with `python3 eval/run.py --json "
        f"-o eval/metrics.json` and commit it."
    )
    return json.loads(METRICS.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# the harness measures what it claims to
# --------------------------------------------------------------------------


def test_both_corpora_and_both_configurations_are_measured(fresh):
    assert set(fresh["results"]) == {"deterministic-only", "corpus-backed"}
    for per_corpus in fresh["results"].values():
        assert set(per_corpus) == {"synthetic", "adversarial"}


def test_labels_come_from_the_manifest_not_from_filenames(fresh):
    """A measurement that read labels off file names could be flattered by a rename."""
    manifest = json.loads(
        (REPO / "fixtures" / "synthetic" / "labels.json").read_text(encoding="utf-8")
    )
    expected = {e["case"]: e["label"] for e in manifest}
    rows = fresh["results"]["deterministic-only"]["synthetic"]["rows"]
    assert {r["case"]: r["label"] for r in rows} == expected


def test_rates_are_consistent_with_the_counts(fresh):
    """Every stored rate is recomputed from the rows it claims to summarise.

    A range check alone would pass with a wrong denominator, which is the failure
    mode that matters here: `0.0 <= value <= 1.0` is satisfied by any plausible
    fraction, so a rate computed over the wrong population looks fine and reads as
    a measurement. Recomputing from the per-message rows is the only check that
    can catch it, and the rows are in the payload precisely so this is possible.
    """
    for config, per_corpus in fresh["results"].items():
        for corpus, metrics in per_corpus.items():
            rows = metrics["rows"]
            total = metrics["messages"]
            assert total == len(rows), f"{config}/{corpus}: count != rows"
            assert sum(metrics["by_disposition"].values()) == total

            def expected(predicate):
                hits = [r for r in rows if predicate(r)]
                return round(len(hits) / total, 4) if total else None

            assert metrics["auto_clearance_rate"] == expected(
                lambda r: r["disposition"] == "clean"
            ), f"{config}/{corpus}: auto_clearance_rate"
            assert metrics["escalation_rate"] == expected(
                lambda r: r["disposition"] in ("manual_review", "unknown")
            ), f"{config}/{corpus}: escalation_rate"
            assert metrics["accusation_rate"] == expected(
                lambda r: r["disposition"] in ("threat", "spam")
            ), f"{config}/{corpus}: accusation_rate"
            assert metrics["no_model_call_rate"] == expected(
                lambda r: not r["model_judgments"]
            ), f"{config}/{corpus}: no_model_call_rate"

            if metrics["kind"] == "labelled":
                cleared = [r for r in rows if r["disposition"] == "clean"]
                hostile_cleared = [
                    r for r in cleared if r["label"] in ("threat", "spam")
                ]
                rate = metrics["false_negative_rate_among_auto_closed"]
                if cleared:
                    assert rate == round(len(hostile_cleared) / len(cleared), 4), (
                        f"{config}/{corpus}: the false-negative rate must be "
                        f"hostile-cleared over all-cleared"
                    )
                else:
                    assert rate is None, "no clearances means no rate, not 0.0"
                benign = [r for r in rows if r["label"] == "clean"]
                accused = [
                    r for r in rows
                    if r["label"] == "clean"
                    and r["disposition"] in ("threat", "spam")
                ]
                assert metrics["false_accusation_count"] == len(accused)
                if benign:
                    assert metrics["false_accusation_rate_among_benign"] == round(
                        len(accused) / len(benign), 4
                    )


def test_an_empty_denominator_is_reported_as_unmeasured_not_as_zero():
    """A rate over nothing is not 0%, and printing 0% would claim a measurement."""
    assert report._pct(None).startswith("n/a")
    assert report._pct(0.0) == "0.0%"


# --------------------------------------------------------------------------
# the safety properties, each with its coverage floor beside it
# --------------------------------------------------------------------------


@pytest.mark.parametrize("config", ["deterministic-only", "corpus-backed"])
def test_no_hostile_message_is_ever_cleared(fresh, config):
    """The number the whole red-team response turned on."""
    metrics = fresh["results"][config]["synthetic"]
    assert metrics["false_negative_count"] == 0, metrics["false_negatives"]
    assert metrics["false_negative_rate_among_auto_closed"] == 0.0
    assert metrics["hostile_auto_cleared"] == 0


@pytest.mark.parametrize("config", ["deterministic-only", "corpus-backed"])
def test_no_benign_message_is_ever_accused(fresh, config):
    """The mirror image, so safety is not bought by accusing everything."""
    metrics = fresh["results"][config]["synthetic"]
    assert metrics["false_accusation_count"] == 0, metrics["false_accusations"]


@pytest.mark.parametrize("config", ["deterministic-only", "corpus-backed"])
def test_benign_messages_still_clear_at_a_pinned_floor(fresh, config):
    """Escalating everything is also safe, and is useless.

    Without this floor the two tests above could be satisfied by a pipeline that
    routes every message to a human, which is the same failure mode as a
    classifier published with F1 0.99 and a false-positive rate of 1.00 - see
    ``docs/EVAL-SUITES.md``. Safety and coverage are asserted together or the
    assertion is advocacy.
    """
    metrics = fresh["results"][config]["synthetic"]
    cleared = metrics["by_disposition"].get("clean", 0)
    assert cleared >= 3, (
        f"only {cleared} of {metrics['benign_messages']} benign fixtures cleared; "
        f"a gate that escalates everything is abdication, not safety"
    )
    assert metrics["auto_clearance_rate"] is not None
    assert metrics["auto_clearance_rate"] > 0.0


@pytest.mark.parametrize("config", ["deterministic-only", "corpus-backed"])
def test_no_adversarial_case_clears_unless_it_is_declared_open(fresh, config):
    """Every hostile message that clears must be a finding we have already named.

    A case that clears while its manifest entry says `closed` is a regression, and
    the strict xfail in ``tests/test_adversarial.py`` would also catch it - this
    catches it in the measurement too, so the committed numbers cannot quietly
    disagree with the test suite.
    """
    metrics = fresh["results"][config]["adversarial"]
    assert metrics["cleared_while_declared_closed"] == [], (
        f"regression: {metrics['cleared_while_declared_closed']} cleared despite "
        f"being declared closed"
    )
    assert set(metrics["hostile_cleared"]) <= set(metrics["declared_open"]), (
        f"{sorted(set(metrics['hostile_cleared']) - set(metrics['declared_open']))} "
        f"cleared but is not declared open"
    )


def test_the_deterministic_configuration_really_uses_no_model(fresh):
    """Otherwise the configuration is not measuring what its name says."""
    metrics = fresh["results"]["deterministic-only"]["synthetic"]
    assert metrics["no_model_call_rate"] == 1.0
    assert metrics["model_assisted"] == 0
    assert all(not r["model_judgments"] for r in metrics["rows"])


def test_the_corpus_backed_configuration_really_does_use_models(fresh):
    """The converse: a configuration that silently degraded to no models would
    make the comparison between the two meaningless."""
    metrics = fresh["results"]["corpus-backed"]["synthetic"]
    assert metrics["model_assisted"] > 0
    assert metrics["no_model_call_rate"] < 1.0


# --------------------------------------------------------------------------
# the committed artifact is not stale
# --------------------------------------------------------------------------


def test_the_committed_metrics_match_what_the_code_produces(fresh, committed):
    """The whole point of committing the numbers, over the offline-reproducible scope.

    Compared without the commit metadata, which necessarily differs, without ordering
    artefacts, and without the ``external`` block - whose rows come out of
    ``eval/internal/``, data this repository must not commit and therefore cannot
    re-measure on a fresh clone. That is not a loophole: the external scope is pinned
    by ``tests/test_external_eval.py``, which asserts exact equality with a
    re-measurement whenever the corpora are on this host, and asserts that the
    artifact states its own provenance when they are not. ``external`` is stripped by
    name and its presence is asserted rather than assumed, so an artifact that quietly
    stopped carrying external numbers fails instead of passing more quietly. If this
    fails the fix is to regenerate and commit, not to edit the artifact.
    """
    def strip(payload: dict) -> dict:
        out = {k: v for k, v in payload.items() if k not in (
            "commit", "commit_short", "branch", "dirty", "external"
        )}
        return out

    assert "external" in committed, (
        "eval/metrics.json carries no `external` block. Regenerate it with "
        "`python3 eval/run.py --json --external -o eval/metrics.json`: the report and "
        "tests/test_external_eval.py read the public-corpus numbers out of this "
        "artifact, and an absent block is not the same thing as an empty one."
    )
    assert strip(committed) == strip(fresh), (
        "eval/metrics.json does not match what eval/run.py produces from the "
        "current code. Regenerate with `python3 eval/run.py --json --external -o "
        "eval/metrics.json` and commit it."
    )


def test_the_committed_metrics_name_the_commit_they_describe(committed):
    assert committed.get("commit"), "the artifact does not name a commit"
    assert committed.get("branch"), "the artifact does not name a branch"
    head = (REPO / ".git" / "HEAD")
    if head.is_file():
        # Only meaningful in a git checkout; the point is that a reader can tell
        # whether the numbers describe the tree they are looking at.
        assert len(committed["commit"]) == 40, committed["commit"]


def test_the_committed_metrics_leak_no_host_identity(committed):
    """This file is committed to a public repository.

    The same rule ``tests/test_results_evidence.py`` applies to the suite's own
    artifact: no hostname, no username, no home path, no network address. The
    measurement reads only fixture paths, but it also shells out to git, and a
    future field could carry a working-tree path with it.
    """
    import re

    text = json.dumps(committed)
    forbidden = [
        r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
        r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
        r"/home/[a-z_][a-z0-9_\-]*",
        r"/Users/[A-Za-z0-9_.\-]+",
        r"[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z]{2,}",
    ]
    for pattern in forbidden:
        matches = re.findall(pattern, text)
        assert not matches, f"{pattern} matched {matches[:3]} in eval/metrics.json"


def test_the_markdown_renderer_recalculates_nothing(fresh):
    """A renderer that recomputes is a second implementation of the measurement.

    Every figure in the prose must come from the payload, so this checks the
    rendered text carries the same numbers rather than plausible ones.
    """
    text = report.render_markdown(fresh)
    synthetic = fresh["results"]["deterministic-only"]["synthetic"]
    assert f"{synthetic['messages']} message(s)" in text
    # Asserting `str(0) in text` is `"0" in text`, which is true of any report
    # containing a digit zero - it could not fail. The label and its denominator
    # are what make the assertion about this number.
    assert (
        f"**{synthetic['false_negative_count']}** of "
        f"{synthetic['hostile_messages']} hostile"
    ) in text
    assert "False-negative rate among auto-closed" in text
    assert "Auto-clearance rate" in text
    # The caveat must survive into the prose, not only live in the JSON.
    assert "not accuracy estimates for real mail" in text
    assert "1.00" in text, (
        "the report must keep naming the F1 0.992 / FPR 1.00 example, because "
        "that is the reason both numbers are printed together"
    )


# --------------------------------------------------------------------------
# the writer must not delete a measurement it was not asked to make
#
# Regression guard for the defect that blocked the public export. `tools/
# make_public_export.py` re-measures `eval/metrics.json` inside the export with no
# `--external`, and `eval/run.py` wrote a payload that simply had no `external` key -
# so the export shipped an artifact with the entire committed external measurement
# deleted, and the 37 tests that read it failed inside the export, which made the
# export refuse to publish at all. The fix is the writer's rule in
# `eval/run.py::carry_forward`, stated over every top-level block rather than as a
# special case for that one key. Each test below is about the writer, and each one
# fails against the pre-fix behaviour.
# --------------------------------------------------------------------------

#: The only two fields a carry-forward may add to a block. Named here rather than
#: imported so a writer that started adding a third one shows up as a failure instead
#: of a wider allowance nobody noticed.
CARRY_FIELDS = ("reproduced_here", "carried_forward")


def _seed(destination: pathlib.Path, payload: dict) -> pathlib.Path:
    """Put an artifact where the writer is about to land on top of it."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return destination


def _written(destination: pathlib.Path, extra: list[str]) -> dict:
    """Run `eval/run.py` as a program and read back the file it wrote."""
    assert run.main(["--json", "-o", str(destination), *extra]) == 0
    return json.loads(destination.read_text(encoding="utf-8"))


def _unmarked(block: dict) -> dict:
    return {key: value for key, value in block.items() if key not in CARRY_FIELDS}


def test_writing_without_external_keeps_the_external_block_it_was_given(committed,
                                                                        tmp_path):
    """The defect, end to end: no `--external` must not mean "delete external".

    Everything that was measured is still there afterwards - the corpora, their rows,
    the per-dataset rollup and the model-tier statement - and the only fields added to
    the block are the two that say it was carried.
    """
    source = json.loads(json.dumps(committed))
    #: The premise of this test is an artifact holding a *fresh* measurement, so the
    #: seed is stripped of the markers before it is used. Inside a public export the
    #: committed artifact is itself a carried block, and seeding from it verbatim would
    #: make the writer restate rather than carry - which is the other test's subject, and
    #: made this one assert that a marked block equals an unmarked one.
    source["external"] = _unmarked(source["external"])
    assert source["external"]["corpora"], (
        "this guard is meaningless against an empty external block: it would pass by "
        "comparing nothing with nothing"
    )
    destination = _seed(tmp_path / "eval" / "metrics.json", source)
    written = _written(destination, [])

    assert "external" in written, (
        "eval/run.py dropped the external block it was not asked to regenerate - the "
        "defect that made the public export unpublishable"
    )
    carried = written["external"]
    assert _unmarked(carried) == source["external"], (
        "a carried block must be the block that was there, apart from the markers"
    )
    assert len(carried["corpora"]) == len(source["external"]["corpora"]), (
        "the corpora count changed"
    )
    assert carried["results"] == source["external"]["results"]
    assert carried["per_dataset"] == source["external"]["per_dataset"]
    assert carried["model_tier"] == source["external"]["model_tier"]
    # Marked, so nobody can read it as a measurement made by this run.
    assert carried["reproduced_here"] is False
    note = carried["carried_forward"]
    assert isinstance(note, dict), "the carried_forward note is required, not optional"
    assert "--external" in json.dumps(note), "and it must name what was not asked for"
    assert note["regenerate_with"].startswith("python3 eval/run.py"), (
        "and the way to make it a real measurement again"
    )
    assert note["carried_from"]["path"], "and where it came from"


def test_a_carried_block_is_carried_again_rather_than_restated(tmp_path):
    """Two runs over the same file write the same bytes.

    The note names the measurement that made the block, so re-writing it on every run
    would make the artifact point at whichever run happened last - and a non-deterministic
    artifact cannot be diffed, which is how an altered measurement would pass unnoticed.
    This is the case a public export is in twice: the artifact it overwrites already
    carries the block, marked.
    """
    source = json.loads(METRICS.read_text(encoding="utf-8"))
    destination = _seed(tmp_path / "metrics.json", source)
    _written(destination, [])
    first = destination.read_text(encoding="utf-8")
    _written(destination, [])
    assert destination.read_text(encoding="utf-8") == first, (
        "re-running the writer changed the artifact without measuring anything"
    )


def test_the_markdown_path_carries_the_block_too(tmp_path):
    """The rule is about what the writer produces, not about one output format.

    A markdown report generated without `--external` over an artifact that had the
    block must render the section, rather than the stated absence that says nothing was
    ever measured. The marker that says *this run did not measure it* lives in the
    artifact (`reproduced_here`), which is where a reviewer reads the numbers from.
    """
    source = json.loads(METRICS.read_text(encoding="utf-8"))
    destination = _seed(tmp_path / "metrics.md", source)
    assert run.main(["-o", str(destination)]) == 0
    text = destination.read_text(encoding="utf-8")
    assert "## External corpora" in text
    assert "not measured in this artifact" not in text, (
        "the report claims no external measurement was made, and one is being "
        "published in the same artifact"
    )


def test_a_requested_external_measurement_replaces_the_carried_block(monkeypatch,
                                                                    tmp_path):
    """Carrying forward must never become a way to keep stale data when the numbers
    were asked for. `--external` wins, markers and all."""
    previous = {"schema_version": 1, "commit": "a" * 40, "results": {},
                "external": {"status": "measured", "headline": "stale",
                             "reproduced_here": False,
                             "carried_forward": {"statement": "carried"}}}
    destination = _seed(tmp_path / "metrics.json", previous)
    fresh_block = {"status": "measured", "headline": "measured just now"}
    monkeypatch.setattr(
        run, "measure",
        lambda *a, **k: {"schema_version": 1, "results": {},
                         "external": fresh_block},
    )
    written = _written(destination, ["--external"])
    assert written["external"] == fresh_block, (
        "a run that measured external must not merge, keep or re-mark the older block"
    )
    assert "carried_forward" not in written["external"]


def test_a_run_local_field_is_never_carried_forward(monkeypatch, tmp_path, capsys):
    """`commit` describes the run that wrote the file.

    Carrying it would make the artifact claim to describe a revision it was not
    measured at, which is the opposite of what the field is for - so it is dropped and
    the drop is stated.
    """
    destination = _seed(tmp_path / "metrics.json", {
        "schema_version": 1, "commit": "b" * 40, "dirty": False, "results": {},
        "external": {"status": "measured"},
    })
    monkeypatch.setattr(run, "measure", lambda *a, **k: {"schema_version": 1,
                                                         "results": {}})
    written = _written(destination, [])
    assert "commit" not in written and "dirty" not in written
    assert "external" in written, "the measurement is still carried"
    said = capsys.readouterr().out
    assert "`commit`" in said, "and the writer says what it did with it"


def test_an_explicit_discard_is_a_stated_removal_not_a_silent_one(monkeypatch,
                                                                 tmp_path, capsys):
    """The second half of "never silent": dropping evidence is allowed, in the open.

    Without the flag the block is carried; with it, it is gone and stdout says so.
    """
    previous = {"schema_version": 1, "results": {},
                "external": {"status": "measured", "headline": "carried or not"}}
    destination = _seed(tmp_path / "metrics.json", previous)
    monkeypatch.setattr(run, "measure",
                        lambda *a, **k: {"schema_version": 1, "results": {}})
    written = _written(destination, ["--discard-stale-blocks"])
    assert "external" not in written
    said = capsys.readouterr().out
    assert "DROPPED" in said and "--discard-stale-blocks" in said, (
        "the removal has to be stated, on the record, by name"
    )


def test_an_unreadable_previous_artifact_is_not_overwritten(tmp_path):
    """A file that exists but is not JSON does not mean "nothing to carry".

    Reading it that way is how a truncated artifact would authorise deleting whatever
    it held, silently. The writer refuses, and the file is left alone.
    """
    destination = tmp_path / "metrics.json"
    destination.write_text("{ 'not': 'json'", encoding="utf-8")
    with pytest.raises(SystemExit) as raised:
        run.main(["--json", "-o", str(destination)])
    assert "--discard-stale-blocks" in str(raised.value)
    assert destination.read_text(encoding="utf-8") == "{ 'not': 'json'", (
        "a refused write must not have happened"
    )


# --------------------------------------------------------------------------
# the selective section, as rendered
# --------------------------------------------------------------------------


def _fragment(name: str, metrics: dict) -> str:
    """One corpus's rendered lines, so an assertion is about this corpus."""
    return "\n".join(report._corpus_section(name, metrics))


def _spelled_pct(value) -> str:
    """The percent formatting written out here rather than called.

    Using ``report._pct`` to check what ``report._pct`` printed would pass for
    any implementation, including a wrong one. Spelling the shape out keeps the
    assertion about the number in the prose.
    """
    return "n/a (nothing to measure over)" if value is None else f"{value * 100:.1f}%"


def test_the_selective_section_is_rendered_for_every_corpus(fresh):
    """Four corpora are measured, so four sections must appear.

    The count is asserted rather than the presence: the defect fixed in this
    bundle was a section that could vanish quietly when the artifact had no
    `selective` block, and a substring check on the heading cannot see that.
    """
    text = report.render_markdown(fresh)
    assert text.count("#### As a selective prediction system") == 4, (
        "both corpora in both configurations must render the section"
    )


def test_the_rendered_coverage_and_risk_are_the_measured_ones(fresh):
    """The prose carries the artifact's numbers, formatted and not re-derived."""
    for corpus in ("synthetic", "adversarial"):
        point = fresh["results"]["deterministic-only"][corpus]["selective"][
            "operating_point"
        ]
        fragment = _fragment(corpus, fresh["results"]["deterministic-only"][corpus])
        assert f"| Coverage (automated without a human) | " \
               f"{_spelled_pct(point['coverage'])} |" in fragment
        assert f"| Selective risk (error rate among automated) | " \
               f"{_spelled_pct(point['selective_risk'])} |" in fragment


def test_the_calibration_caveat_appears_whenever_the_scores_are_uncalibrated(fresh):
    """A renderer that can drop the caveat is how an uncalibrated number starts
    being read as a probability.

    Pinned in both directions: the shipped artifacts are uncalibrated and must
    say so, and the sentence must be driven by the flag rather than hardcoded -
    otherwise it would still print after a calibrated measurement, and a reader
    could not tell the two apart either.
    """
    caveat = "*These scores are not calibrated.*"
    for per_corpus in fresh["results"].values():
        for corpus, metrics in per_corpus.items():
            assert metrics["selective"]["calibrated"] is False, corpus
            assert caveat in _fragment(corpus, metrics), corpus

    mutated = copy.deepcopy(fresh)
    target = mutated["results"]["deterministic-only"]["synthetic"]
    target["selective"]["calibrated"] = True
    fragment = _fragment("synthetic", target)
    assert caveat not in fragment, (
        "the caveat is printed from the flag; if it survives a claim of "
        "calibration it is prose, not a report of the measurement"
    )
    assert caveat in _fragment(
        "adversarial", mutated["results"]["deterministic-only"]["adversarial"]
    ), "flipping one corpus's flag must not silence another corpus's caveat"


def test_a_wrong_automated_decision_is_named_and_its_open_status_is_marked(fresh):
    """The adversarial corpus's single error, by name, as the disclosed finding.

    A rate of 50% among two automated decisions tells an operator nothing; the
    case name and the manifest status tell them whether this is the miss already
    on the record or a new one.
    """
    metrics = fresh["results"]["deterministic-only"]["adversarial"]
    fragment = _fragment("adversarial", metrics)
    assert "`forged_auth_single_header`" in fragment
    assert "**declared open**" in fragment, (
        "a case whose manifest says open must read as declared open, not as an "
        "undiscovered miss"
    )
    assert "Automated decisions that were wrong, named rather than averaged" in fragment


def test_declared_open_is_the_status_talking_and_not_a_default(fresh):
    """The same payload with the status moved to closed must not claim it is open.

    This is the reverse of the assertion above, and the one that makes it
    meaningful: a marker printed unconditionally would pass the first test and
    flatter a regression into looking disclosed.
    """
    metrics = copy.deepcopy(fresh["results"]["deterministic-only"]["adversarial"])
    errors = metrics["selective"]["operating_point"]["errors_among_accepted"]
    assert errors, "the measurement must have the one open finding to mutate"
    errors[0]["status"] = "closed"
    fragment = _fragment("adversarial", metrics)
    assert "`forged_auth_single_header`" in fragment, "still named"
    assert "**declared open**" not in fragment, (
        "a closed case that clears is a regression, and the renderer must not "
        "label it disclosed - the manifest's own 'Declared open' row is capitalised "
        "and is not what this asserts about"
    )


def test_the_adversarial_corpus_says_no_risk_budget_is_achievable(fresh):
    """Where it is the true and important result, not a formatting accident."""
    hostile = _fragment(
        "adversarial", fresh["results"]["deterministic-only"]["adversarial"]
    )
    assert (
        "*No automated-error budget in the reported range is achievable on this "
        "corpus.*" in hostile
    )
    assert "Coverage available at each automated-error budget" not in hostile

    benign = _fragment("synthetic", fresh["results"]["deterministic-only"]["synthetic"])
    assert "Coverage available at each automated-error budget" in benign, (
        "the synthetic corpus does have achievable budgets, so the table must "
        "print there and not the fallback sentence"
    )
    assert "No automated-error budget" not in benign


def test_absent_numbers_render_as_n_a_and_never_blank_or_zero():
    """`None` is a fact about the measurement, and it has to look like one."""
    assert report._num(None) == "n/a"
    assert report._int_or_none(None) == "n/a"
    assert report._pct(None).startswith("n/a")
    for renderer in (report._num, report._int_or_none):
        assert renderer(None) not in ("", "0", "0.0", "0.0000")
    assert report._num(0.0) in ("0.0", "0.0000"), (
        "a measured zero is not an absence and must not print as n/a"
    )
    # The oracle comparison's own inconsistency flag survives into the prose.
    assert report._num({"value": -0.01, "inconsistent": True}) == (
        "-0.0100 (inconsistent)"
    )


def test_a_deferred_adversarial_corpus_renders_its_absent_risk_as_n_a():
    """A corpus where nothing was automated has no risk, and prints no number.

    The rows are built here and passed through the real metrics rather than read
    from the committed artifact: no shipped corpus is entirely deferred, so the
    case only exists as a constructed one.
    """
    rows = [{"case": f"c{i}", "label": "hostile", "disposition": "manual_review",
             "confidence": 0.9, "status": "closed"} for i in range(4)]
    metrics = {"kind": "hostile", "messages": 4,
               "by_disposition": {"manual_review": 4},
               "auto_clearance_rate": 0.0, "escalation_rate": 1.0,
               "accusation_rate": 0.0, "no_model_call_rate": 1.0,
               "model_assisted": 0, "hostile_cleared": [],
               "hostile_cleared_count": 0, "hostile_deferred": 4,
               "hostile_accused": 0, "declared_open": [],
               "cleared_while_declared_closed": [],
               "selective": selective.selective_report(rows)}
    fragment = _fragment("hostile-only", metrics)
    assert "| Selective risk (error rate among automated) | n/a" in fragment
    assert "| AURC (lower is better) | n/a |" in fragment
    assert "| E-AURC (ranking quality, 0 is oracle) | n/a |" in fragment
    assert "No automated-error budget" in fragment


def test_the_renderer_performs_no_arithmetic_even_on_an_impossible_payload(fresh):
    """Feed it a payload that contradicts itself; the contradiction must survive.

    A renderer that "corrected" a number would be re-measuring, and the two
    sources of truth would disagree in whichever direction flatters the result.
    This is the only test that can tell a formatter from a calculator: on a
    correct artifact the two produce identical output.
    """
    metrics = copy.deepcopy(fresh["results"]["deterministic-only"]["synthetic"])
    point = metrics["selective"]["operating_point"]
    point["messages"], point["accepted"], point["deferred"] = 100, 1, 99
    point["coverage"] = 0.5          # 1 of 100 automated is not 50%
    point["selective_risk"] = 0.987654
    metrics["selective"]["aurc"] = 0.123456
    metrics["selective"]["excess_aurc"] = 0.654321
    metrics["selective"]["curve_points"] = 9999
    fragment = _fragment("synthetic", metrics)

    assert "| Coverage (automated without a human) | 50.0% |" in fragment
    assert "| Selective risk (error rate among automated) | 98.8% |" in fragment
    assert "| AURC (lower is better) | 0.1235 |" in fragment
    assert "| E-AURC (ranking quality, 0 is oracle) | 0.6543 |" in fragment
    assert "| Curve points | 9999 |" in fragment
    # What a recomputing renderer would have printed instead: 1 accepted of 100
    # messages recomputes to 1.0% coverage. The budget table legitimately prints
    # "<= 1.0%" as a risk budget, so the assertion is about the coverage row.
    assert "| Coverage (automated without a human) | 1.0% |" not in fragment, (
        "printing the recomputed coverage means the renderer measured rather "
        "than formatted"
    )


def test_the_deferred_slice_does_not_credit_a_model_for_an_escalation(fresh):
    """`escalated` is the ensemble's flag, not evidence that a tier spoke.

    In the deterministic-only configuration no model tier is reachable, so the
    sentence that called every escalation "by a model tier" contradicted the
    model-assisted count printed three words after it. The renderer must not
    assert a cause the payload in the same line says did not happen.
    """
    metrics = fresh["results"]["deterministic-only"]["adversarial"]
    composition = metrics["selective"]["deferral_composition"]
    assert metrics["model_assisted"] == 0, (
        "this test is about a configuration with no model in it at all"
    )
    assert composition["deferred"] > 0
    fragment = _fragment("adversarial", metrics)
    assert f"{composition['escalated']} flagged escalated by the ensemble" in fragment
    assert f"{composition['model_assisted']} model-assisted" in fragment
    assert "escalated by a model tier" not in fragment


def test_a_payload_without_the_selective_block_raises_naming_its_corpus(fresh):
    """The section must not be able to vanish quietly.

    `eval/run.py` attaches the block to every corpus, so its absence means the
    artifact predates those metrics or was edited - and a missing measurement
    rendered as an empty section is indistinguishable from one that found
    nothing, which is the same shape as a check that swallows its own status.
    """
    stripped = copy.deepcopy(fresh)
    del stripped["results"]["deterministic-only"]["adversarial"]["selective"]
    with pytest.raises(report.MissingSelectiveMetrics) as raised:
        report.render_markdown(stripped)
    message = str(raised.value)
    assert "adversarial" in message, "the error must name the corpus it is about"
    assert "eval/run.py --json" in message, "and say how to fix it"


def test_rendering_an_artifact_without_the_block_can_be_asked_for_by_name(fresh):
    """The escape hatch is explicit, and the output still admits the gap."""
    stripped = copy.deepcopy(fresh)
    del stripped["results"]["deterministic-only"]["adversarial"]["selective"]
    text = report.render_markdown(stripped, require_selective=False)
    assert "*Not present in this artifact.*" in text
    assert text.count("#### As a selective prediction system") == 4, (
        "the heading stays so the reader sees that something was expected here"
    )
    for per_corpus in stripped["results"].values():
        for metrics in per_corpus.values():
            if "selective" in metrics:
                assert "*Not present in this artifact.*" not in _fragment(
                    "x", metrics
                )
