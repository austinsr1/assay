"""Selective-prediction metrics.

The property tests matter more than the worked examples here. A risk-coverage
implementation can produce plausible-looking numbers while being wrong in a way that
only shows up as an impossible relationship between them - which is exactly how the
first version of this module shipped a negative E-AURC, since it compared a curve that
stops at 0.11 coverage against an oracle integrated to 1.0.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "eval"))
sys.path.insert(0, str(REPO / "src"))

import selective  # noqa: E402

METRICS = REPO / "eval" / "metrics.json"


def _row(case, label, disposition, confidence=0.9, **extra):
    return {"case": case, "label": label, "disposition": disposition,
            "confidence": confidence, **extra}


# --------------------------------------------------------------------------
# error semantics
# --------------------------------------------------------------------------


def test_clearing_a_hostile_message_is_an_error():
    assert selective.is_error(_row("a", "threat", "clean")) is True
    assert selective.is_error(_row("a", "spam", "clean")) is True
    assert selective.is_error(_row("a", "hostile", "clean")) is True


def test_accusing_a_benign_message_is_an_error():
    assert selective.is_error(_row("a", "clean", "threat")) is True
    assert selective.is_error(_row("a", "clean", "spam")) is True
    assert selective.is_error(_row("a", "clean", "clean")) is False


def test_a_deferral_is_neither_an_error_nor_a_correct_decision():
    """It is not measured at all: it went to a person."""
    for disposition in ("manual_review", "unknown"):
        row = _row("a", "threat", disposition)
        assert selective._decided(row) is False


def test_an_unrecognized_label_is_undecidable_not_correct():
    """Counting an undecidable case as correct is how a measurement flatters itself."""
    assert selective.is_error(_row("a", "mystery", "clean")) is None
    assert selective.is_error(_row("a", "", "clean")) is None


def test_every_label_in_both_committed_corpora_is_decidable():
    """The regression guard for the bug that hid the adversarial corpus entirely.

    The adversarial corpus labels its cases `hostile`. Omitting that from the label
    set made all 18 undecidable and reported a selective risk of None on precisely the
    corpus where the risk is most interesting - and it looked like a legitimate "no
    ground truth" rather than a missing string.
    """
    if not METRICS.is_file():
        pytest.skip("eval/metrics.json is generated; run eval/run.py first")
    data = json.loads(METRICS.read_text())
    for config_name, block in data["results"].items():
        for corpus_name, result in block.items():
            rows = result["rows"]
            point = selective.operating_point(rows)
            assert point["undecidable"] == 0, (
                f"{config_name}/{corpus_name}: {point['undecidable']} of {len(rows)} "
                "rows have a label this module does not recognize, so its rates are "
                "computed over nothing"
            )


# --------------------------------------------------------------------------
# the operating point
# --------------------------------------------------------------------------


def test_coverage_is_the_automated_fraction_and_risk_is_the_error_rate_within_it():
    rows = [
        _row("a", "threat", "threat"),      # automated, correct
        _row("b", "threat", "clean"),       # automated, wrong
        _row("c", "clean", "clean"),        # automated, correct
        _row("d", "threat", "manual_review"),  # deferred
    ]
    point = selective.operating_point(rows)
    assert point["messages"] == 4
    assert point["accepted"] == 3
    assert point["deferred"] == 1
    assert point["coverage"] == 0.75
    assert point["selective_risk"] == pytest.approx(1 / 3, abs=1e-6)


def test_class_conditional_risk_separates_the_two_asymmetric_mistakes():
    rows = [
        _row("a", "threat", "clean"),   # false negative: cleared a phish
        _row("b", "threat", "threat"),
        _row("c", "clean", "threat"),   # false accusation
        _row("d", "clean", "clean"),
    ]
    point = selective.operating_point(rows)
    assert point["hostile_accepted"] == 2
    assert point["hostile_accepted_wrong"] == 1
    assert point["false_negative_rate_among_accepted"] == 0.5
    assert point["benign_accepted"] == 2
    assert point["benign_accepted_wrong"] == 1
    assert point["false_accusation_rate_among_accepted"] == 0.5
    assert point["selective_risk"] == 0.5, (
        "the aggregate hides which side the error fell on; that is why both are reported"
    )


def test_errors_are_named_rather_than_only_counted():
    rows = [_row("forged_auth_single_header", "hostile", "clean", status="open"),
            _row("other", "hostile", "threat")]
    point = selective.operating_point(rows)
    assert len(point["errors_among_accepted"]) == 1
    named = point["errors_among_accepted"][0]
    assert named["case"] == "forged_auth_single_header"
    assert named["status"] == "open", (
        "the status travels with the error so a disclosed finding is distinguishable "
        "from an undiscovered one"
    )


def test_no_risk_is_none_and_not_zero():
    """'Nothing was automated' and 'nothing automated was wrong' differ."""
    rows = [_row("a", "threat", "manual_review"), _row("b", "clean", "unknown")]
    point = selective.operating_point(rows)
    assert point["accepted"] == 0
    assert point["coverage"] == 0.0
    assert point["selective_risk"] is None
    assert point["selective_accuracy"] is None
    assert point["false_negative_rate_among_accepted"] is None


def test_an_empty_corpus_produces_nones_not_zeros():
    point = selective.operating_point([])
    assert point["messages"] == 0
    assert point["coverage"] is None
    assert point["selective_risk"] is None
    assert selective.risk_coverage_curve([]) == []
    assert selective.aurc([]) is None


# --------------------------------------------------------------------------
# the curve and its area
# --------------------------------------------------------------------------


def test_the_curve_is_ordered_by_descending_threshold_and_monotone_in_coverage():
    rows = [
        _row("a", "threat", "threat", 0.9),
        _row("b", "clean", "clean", 0.5),
        _row("c", "threat", "clean", 0.8),
        _row("d", "threat", "manual_review", 0.99),  # deferred: never automated
    ]
    curve = selective.risk_coverage_curve(rows)
    thresholds = [p["threshold"] for p in curve if p["threshold"] is not None]
    assert thresholds == sorted(thresholds, reverse=True)
    coverages = [p["coverage"] for p in curve]
    assert coverages == sorted(coverages)


def test_a_deferred_message_is_never_automated_however_high_its_score():
    """Deferral is a decision about evidence, not about confidence.

    A message the pipeline refused to settle must not reappear as automated because
    an operator lowered a threshold. If it could, the coverage numbers would describe
    a system that does not exist.
    """
    rows = [_row("a", "threat", "manual_review", 0.99),
            _row("b", "threat", "threat", 0.4)]
    curve = selective.risk_coverage_curve(rows)
    assert max(p["coverage"] for p in curve) == 0.5
    assert all(p["accepted"] <= 1 for p in curve)


def test_the_curve_is_coarse_when_the_scores_are_coarse_and_says_so():
    """This project emits a handful of policy values, not a continuous probability.

    Interpolating extra points would invent measurements, so the curve has exactly one
    point per distinct score and the count is reported.
    """
    rows = [_row(f"c{i}", "threat", "threat", 0.9) for i in range(5)]
    curve = selective.risk_coverage_curve(rows)
    real = [p for p in curve if p["threshold"] is not None]
    assert len(real) == 1, "five identical scores are one threshold, not five"


# --------------------------------------------------------------------------
# the oracle comparison - where the first version was wrong
# --------------------------------------------------------------------------


@pytest.mark.parametrize("rows", [
    # no errors at all
    [_row("a", "threat", "threat", 0.9), _row("b", "clean", "clean", 0.8)],
    # the highest-confidence decision is the wrong one
    [_row("a", "hostile", "clean", 0.95), _row("b", "hostile", "threat", 0.6)],
    # heavy structural deferral, so coverage never approaches 1
    [_row("a", "hostile", "clean", 0.9), _row("b", "hostile", "threat", 0.8)]
    + [_row(f"d{i}", "hostile", "manual_review", 0.99) for i in range(20)],
    # a mix at several thresholds
    [_row("a", "threat", "threat", 0.9), _row("b", "clean", "threat", 0.7),
     _row("c", "threat", "clean", 0.5), _row("d", "clean", "clean", 0.3),
     _row("e", "threat", "manual_review", 0.99)],
])
def test_excess_aurc_is_never_negative(rows):
    """The oracle is the minimum by construction, so E-AURC >= 0 always.

    This is the property whose violation exposed the closed-form oracle bug: it
    integrates to full coverage while a structurally-deferring pipeline cannot reach
    it, so the oracle looked better than achievable and the difference went negative.
    """
    curve = selective.risk_coverage_curve(rows)
    result = selective.excess_aurc(curve)
    assert result["aurc"] is not None
    assert result["oracle_aurc"] is not None
    excess = result["excess_aurc"]
    value = excess["value"] if isinstance(excess, dict) else excess
    assert not (isinstance(excess, dict) and excess.get("inconsistent")), result
    assert value >= -1e-9, f"E-AURC was negative: {result}"


def test_a_perfect_ranking_has_zero_excess():
    rows = [_row("a", "threat", "threat", 0.9), _row("b", "threat", "clean", 0.4)]
    result = selective.excess_aurc(selective.risk_coverage_curve(rows))
    assert result["excess_aurc"] == 0.0


def test_putting_the_wrong_decision_first_costs_excess():
    """The same two predictions, ranked the other way round."""
    good = [_row("a", "threat", "threat", 0.9), _row("b", "threat", "clean", 0.4)]
    bad = [_row("a", "threat", "clean", 0.9), _row("b", "threat", "threat", 0.4)]
    g = selective.excess_aurc(selective.risk_coverage_curve(good))
    b = selective.excess_aurc(selective.risk_coverage_curve(bad))
    assert g["excess_aurc"] < b["excess_aurc"], (g, b)


def test_a_single_point_has_no_area_and_is_not_reported_as_zero():
    curve = selective.risk_coverage_curve([_row("a", "threat", "threat", 0.9)])
    real = [p for p in curve if p["risk"] is not None]
    assert len(real) == 1
    assert selective.aurc(curve) is None, (
        "one point has no area; reporting 0.0 would claim a perfect ranking"
    )


# --------------------------------------------------------------------------
# operating-point queries
# --------------------------------------------------------------------------


def test_coverage_at_risk_returns_none_when_no_point_meets_the_budget():
    """A real answer, not a zero: the pipeline cannot be automated that tightly."""
    rows = [_row("a", "hostile", "clean", 0.9)]
    curve = selective.risk_coverage_curve(rows)
    result = selective.coverage_at_risk(curve, 0.01)
    assert result["satisfied"] is False
    assert result["coverage"] is None


def test_coverage_at_risk_picks_the_most_automation_within_the_budget():
    rows = [
        _row("a", "threat", "threat", 0.9),
        _row("b", "clean", "clean", 0.8),
        _row("c", "threat", "clean", 0.3),   # wrong, low score
    ]
    curve = selective.risk_coverage_curve(rows)
    tight = selective.coverage_at_risk(curve, 0.0)
    loose = selective.coverage_at_risk(curve, 0.34)
    assert tight["coverage"] < loose["coverage"]
    assert tight["risk"] == 0.0


def test_risk_at_coverage_reports_the_error_rate_of_automating_that_much():
    rows = [_row("a", "threat", "threat", 0.9), _row("b", "threat", "clean", 0.5)]
    curve = selective.risk_coverage_curve(rows)
    assert selective.risk_at_coverage(curve, 0.5)["risk"] == 0.0
    assert selective.risk_at_coverage(curve, 1.0)["risk"] == 0.5


def test_risk_at_coverage_is_honest_when_the_target_is_unreachable():
    rows = [_row("a", "threat", "manual_review", 0.9)]
    result = selective.risk_at_coverage(selective.risk_coverage_curve(rows), 0.5)
    assert result["reached"] is False
    assert result["risk"] is None


# --------------------------------------------------------------------------
# deferral composition
# --------------------------------------------------------------------------


def test_deferral_composition_reports_what_the_hard_slice_contains():
    rows = [
        _row("a", "threat", "manual_review", truncated=True, escalated=True,
             model_judgments=["llm"]),
        _row("b", "hostile", "manual_review", status="closed"),
        _row("c", "threat", "threat"),
    ]
    composition = selective.deferral_composition(rows)
    assert composition["deferred"] == 2
    assert composition["truncated"] == 1
    assert composition["escalated"] == 1
    assert composition["model_assisted"] == 1
    assert composition["adversarial"] == 1
    assert composition["labels"] == {"hostile": 1, "threat": 1}


def test_no_deferrals_is_reported_as_zero_not_as_an_empty_dict():
    composition = selective.deferral_composition([_row("a", "threat", "threat")])
    assert composition["deferred"] == 0
    assert composition["labels"] == {}


# --------------------------------------------------------------------------
# the assembled report
# --------------------------------------------------------------------------


def test_the_report_carries_the_calibration_caveat_by_default():
    report = selective.selective_report([_row("a", "threat", "threat")])
    assert report["calibrated"] is False, (
        "the confidence values are policy labels; a renderer must not be able to drop "
        "that by forgetting to add it"
    )


def test_the_report_assembles_every_section():
    rows = [_row("a", "threat", "threat", 0.9), _row("b", "clean", "manual_review", 0.5)]
    report = selective.selective_report(rows)
    for key in ("calibrated", "operating_point", "curve", "curve_points", "aurc",
                "oracle_aurc", "excess_aurc", "risk_at_full_coverage",
                "coverage_at_risk", "risk_at_coverage", "deferral_composition"):
        assert key in report, key
    assert len(report["coverage_at_risk"]) == 5
    assert len(report["risk_at_coverage"]) == 5


def test_the_report_is_json_serializable_for_the_committed_artifact():
    rows = [_row("a", "threat", "threat", 0.9), _row("b", "hostile", "clean", 0.9,
                                                     status="open")]
    text = json.dumps(selective.selective_report(rows))
    assert json.loads(text)


# --------------------------------------------------------------------------
# against the committed measurement
# --------------------------------------------------------------------------


def test_the_adversarial_corpus_reports_the_one_open_finding_by_name():
    """The most important output this module produces on the shipped corpora.

    Coverage is low, the automated subset is half wrong, and the single error is the
    disclosed open finding rather than something new. A report that averaged it into a
    rate would read as "50% error" and tell an operator nothing.
    """
    if not METRICS.is_file():
        pytest.skip("eval/metrics.json is generated; run eval/run.py first")
    rows = json.loads(METRICS.read_text())["results"]["deterministic-only"]["adversarial"]["rows"]
    report = selective.selective_report(rows)
    point = report["operating_point"]

    assert point["coverage"] < 0.2, "a hostile corpus should barely be automated"
    assert point["selective_risk"] is not None
    errors = point["errors_among_accepted"]
    assert len(errors) == 1
    assert errors[0]["case"] == "forged_auth_single_header"
    assert errors[0]["status"] == "open"
    assert report["coverage_at_risk"][2]["satisfied"] is False, (
        "a 1% automated-error budget is not achievable on the hostile corpus, and "
        "saying so is the point"
    )


def test_the_confidence_ordering_is_imperfect_and_the_metric_says_so():
    """Direct evidence for a caveat the project already publishes.

    The 0.90 clearance is a policy label rather than a probability, and on the
    adversarial corpus the highest-confidence automated decision is the wrong one.
    E-AURC detects exactly that, so the documented caveat is now measured rather than
    merely stated.
    """
    if not METRICS.is_file():
        pytest.skip("eval/metrics.json is generated; run eval/run.py first")
    rows = json.loads(METRICS.read_text())["results"]["deterministic-only"]["adversarial"]["rows"]
    report = selective.selective_report(rows)
    assert report["excess_aurc"] > 0.0, (
        "the wrong decision carries the highest confidence, so the ranking is not "
        "oracle-optimal and E-AURC must be positive"
    )
