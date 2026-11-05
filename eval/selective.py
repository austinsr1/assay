"""Selective-prediction metrics for a pipeline that is allowed to say "not sure".

This pipeline is a selective classifier. The deterministic layer settles what it can,
model tiers opine on the rest, and anything unsettled becomes ``manual_review`` and
goes to a person. ``manual_review`` is therefore not a fourth label sitting beside
clean, spam and threat - it is a **deferral**, and reporting this system with a
single-threshold accuracy hides the only question an operator actually asks: how much
of the queue can be automated, and what does that automation cost in errors.

The metrics here are orthodox selective classification. A selector ``g`` decides which
predictions are automated; coverage is the fraction automated; selective risk is the
error rate *among the automated ones*. Sweeping the acceptance threshold traces the
risk-coverage curve, and AURC summarizes it in one number that rewards putting
safe-to-automate cases ahead of cases likely to be wrong.

Two things this module refuses to do, both deliberately.

**It does not average a newsletter with a credential harvester.** Risk is reported
class-conditionally as well as in aggregate: the false-negative rate among accepted
hostile messages and the false-positive rate among accepted benign messages, each with
its own coverage. Automatically clearing a phish and automatically accusing a
legitimate invoice are not the same mistake, and a single aggregate risk hides the
worse one. The ledger already refuses to average them; the evaluation must not either.

**It does not pretend the scores are calibrated.** The confidence values in this
project are policy labels - 0.90 for a supported clearance, 0.50 for a deferral - not
probabilities, and that is documented wherever they appear. Selective prediction needs
only a *ranking*, so a risk-coverage curve over uncalibrated scores is legitimate.
E-AURC and any "coverage at risk <= X" statement are still reported with the
calibration limit attached, because a reader who mistakes a policy label for a
probability will over-trust the operating point. `calibrated` is carried in the output
and defaults to False so the report cannot lose it.

Definitions, for the reader who wants to check the arithmetic:

    coverage   phi = E[g(X)]                       fraction automated
    sel. risk  R   = E[loss * g] / phi             error rate among automated
    AURC           = integral of R over coverage   lower is better
    AURC*          = e0 + (1 - e0) * ln(1 - e0)    oracle ranking, e0 = R at full coverage
    E-AURC         = AURC - AURC*                 isolates ranking quality from base error
"""

from __future__ import annotations

import math
from typing import Any, Iterable, Sequence

__all__ = [
    "DEFERRALS",
    "HOSTILE_LABELS",
    "BENIGN_LABELS",
    "is_error",
    "operating_point",
    "risk_coverage_curve",
    "aurc",
    "oracle_aurc",
    "excess_aurc",
    "coverage_at_risk",
    "risk_at_coverage",
    "deferral_composition",
    "selective_report",
]

#: What the pipeline defers to a human. Neither is an error and neither is agreement,
#: and counting them as either is how a tool that escalates everything comes to look
#: either perfect or useless.
DEFERRALS = frozenset({"manual_review", "unknown"})

#: Labels meaning the message must not be cleared. "Hostile" overstates one of them -
#: the synthetic corpus labels a legitimate marketing message `spam`, over-reported by
#: a person - but a CLEAN disposition on any of them is the same class of error:
#: something that should have been looked at was closed without a person.
#:
#: `hostile` is the label the adversarial corpus uses for all 18 of its cases, and
#: omitting it made every one of them undecidable, which reported a selective risk of
#: `None` on precisely the corpus where the risk is most interesting. A label set that
#: silently does not cover a corpus is worse than one that raises, so `undecidable` is
#: reported alongside every rate and a test asserts it is zero on both corpora.
HOSTILE_LABELS = frozenset({"threat", "spam", "hostile", "phishing", "malicious"})

#: Labels meaning the message must not be accused.
BENIGN_LABELS = frozenset({"clean", "legitimate", "ham", "benign"})

ACCUSATIONS = frozenset({"threat", "spam"})


def is_error(row: dict[str, Any]) -> bool | None:
    """Whether this automated decision was wrong, or ``None`` if undecidable.

    ``None`` is not ``False``. A message whose label this module does not recognize,
    or a hostile-labelled corpus case with no declared expectation, has no ground
    truth to be wrong against - and counting an undecidable case as correct is how a
    measurement quietly flatters itself.
    """
    label = str(row.get("label") or "").strip().lower()
    disposition = str(row.get("disposition") or "").strip().lower()
    if not label or not disposition:
        return None
    if label in HOSTILE_LABELS:
        # Clearing something that should not have been cleared.
        return disposition == "clean"
    if label in BENIGN_LABELS:
        # Accusing something that should not have been accused.
        return disposition in ACCUSATIONS
    return None


def _decided(row: dict[str, Any]) -> bool:
    """True when the pipeline automated this message rather than deferring it."""
    return str(row.get("disposition") or "") not in DEFERRALS


def _score(row: dict[str, Any]) -> float:
    try:
        return float(row.get("confidence", 0.0))
    except (TypeError, ValueError):
        return 0.0


def _risk(decisions: Sequence[dict[str, Any]]) -> float | None:
    """Error rate among automated decisions. ``None`` when there are none.

    ``None`` rather than 0.0 throughout: "nothing was automated" and "nothing
    automated was wrong" are different facts and must not read the same.
    """
    judged = [d for d in decisions if is_error(d) is not None]
    if not judged:
        return None
    wrong = sum(1 for d in judged if is_error(d))
    return round(wrong / len(judged), 6)


def _class_conditional(decisions: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Errors split by which side of the asymmetry they fall on.

    Reported separately because the two mistakes have different costs: a cleared phish
    is hours of incident work, an accused invoice is minutes of analyst time.
    """
    hostile = [d for d in decisions
               if str(d.get("label", "")).lower() in HOSTILE_LABELS]
    benign = [d for d in decisions
              if str(d.get("label", "")).lower() in BENIGN_LABELS]

    def wrong(rows: Iterable[dict[str, Any]]) -> int:
        return sum(1 for r in rows if is_error(r))

    hostile = list(hostile)
    benign = list(benign)
    return {
        "hostile_accepted": len(hostile),
        "hostile_accepted_wrong": wrong(hostile),
        "false_negative_rate_among_accepted": (
            round(wrong(hostile) / len(hostile), 6) if hostile else None
        ),
        "benign_accepted": len(benign),
        "benign_accepted_wrong": wrong(benign),
        "false_accusation_rate_among_accepted": (
            round(wrong(benign) / len(benign), 6) if benign else None
        ),
    }


def operating_point(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The deployed operating point: what the pipeline automates as configured.

    No threshold is applied here, so this is the honest "as it ships" number rather
    than the best point on a curve chosen after seeing the answers.
    """
    total = len(rows)
    accepted = [r for r in rows if _decided(r)]
    deferred = [r for r in rows if not _decided(r)]
    decidable = [r for r in rows if is_error(r) is not None]
    # Named rather than only counted. A rate that averages a single known open finding
    # into a denominator of two reads as "50% error" and tells an operator nothing;
    # naming the case tells them exactly which one and whether it is the disclosed one.
    wrong_accepted = [
        {"case": str(r.get("case", "")), "label": str(r.get("label", "")),
         "disposition": str(r.get("disposition", "")),
         "confidence": _score(r), "status": r.get("status")}
        for r in accepted if is_error(r)
    ]
    return {
        "messages": total,
        "decidable": len(decidable),
        "undecidable": total - len(decidable),
        "accepted": len(accepted),
        "deferred": len(deferred),
        "errors_among_accepted": wrong_accepted,
        "coverage": round(len(accepted) / total, 6) if total else None,
        "selective_risk": _risk(accepted),
        "selective_accuracy": (
            None if _risk(accepted) is None else round(1.0 - _risk(accepted), 6)
        ),
        **_class_conditional(accepted),
    }


def risk_coverage_curve(
    rows: Sequence[dict[str, Any]],
    *,
    include_zero_coverage: bool = True,
) -> list[dict[str, Any]]:
    """The curve, as a list of ``{coverage, risk, accepted, threshold}`` points.

    The selector is ``g(x) = automated-by-the-pipeline AND score(x) >= theta``: a
    message the pipeline already deferred is never automated however high its score,
    because deferral is a decision about evidence and not about confidence. Sweeping
    theta therefore describes how much of the *already-automated* set an operator
    could take on at what error rate.

    Points are emitted at each distinct score, highest first, so the curve is
    monotone in coverage. It is coarse wherever the scores are coarse - this project
    emits a handful of policy values, not a continuous probability, and a curve with
    six points has six points. That is stated in the output rather than smoothed away,
    because interpolating a risk-coverage curve would invent measurements.
    """
    accepted_pool = [r for r in rows if _decided(r) and is_error(r) is not None]
    total = len(rows)
    if not total or not accepted_pool:
        return []

    # Descending score; ties broken by case name so the curve is reproducible.
    ordered = sorted(
        accepted_pool, key=lambda r: (-_score(r), str(r.get("case", "")))
    )
    thresholds = sorted({_score(r) for r in ordered}, reverse=True)

    points: list[dict[str, Any]] = []
    if include_zero_coverage:
        points.append({
            "threshold": None, "coverage": 0.0, "risk": None, "accepted": 0,
            "errors": 0,
        })
    for theta in thresholds:
        taken = [r for r in ordered if _score(r) >= theta - 1e-12]
        if not taken:
            continue
        errors = sum(1 for r in taken if is_error(r))
        points.append({
            "threshold": round(theta, 6),
            "coverage": round(len(taken) / total, 6),
            "risk": round(errors / len(taken), 6),
            "accepted": len(taken),
            "errors": errors,
        })
    return points


def aurc(curve: Sequence[dict[str, Any]]) -> float | None:
    """Area under the risk-coverage curve, by trapezoidal integration.

    The zero-coverage point contributes nothing (risk is undefined there, and the
    trapezoid from 0 to the first real point is what carries it), so points with
    ``risk is None`` are skipped rather than treated as zero - treating an undefined
    risk as a perfect one would understate the area.
    """
    usable = [p for p in curve if p.get("risk") is not None]
    if len(usable) < 2:
        # A single point has no area. Returning 0.0 would claim a perfect ranking.
        return None
    area = 0.0
    for previous, current in zip(usable, usable[1:]):
        width = current["coverage"] - previous["coverage"]
        if width <= 0:
            continue
        area += width * (previous["risk"] + current["risk"]) / 2.0
    return round(area, 6)


def oracle_aurc(curve: Sequence[dict[str, Any]]) -> float | None:
    """The best AURC achievable with the same predictions and a perfect ranking.

    Computed over the curve's own coverage grid rather than from the usual closed form
    ``e0 + (1-e0)*ln(1-e0)``. That closed form assumes the selector can reach full
    coverage by lowering a threshold, which is false here: this pipeline defers most
    messages as a matter of evidence rather than confidence, so coverage is capped by
    the number of messages it is willing to settle at all. Comparing a curve that stops
    at 0.11 coverage against an oracle integrated to 1.0 produced a negative E-AURC,
    which is impossible since the oracle is the minimum by construction. The bug was
    found by reading the number rather than trusting the formula.

    The oracle puts every correct prediction before every incorrect one, so at k
    accepted items it has ``max(0, k - correct)`` errors. Integrating that over the
    same coverage points the real curve visits makes the comparison like for like.
    """
    usable = [p for p in curve if p.get("risk") is not None]
    if len(usable) < 2:
        return None
    full = usable[-1]
    errors_total = int(full.get("errors", 0))
    correct_total = int(full.get("accepted", 0)) - errors_total

    area = 0.0
    previous_coverage = 0.0
    previous_risk = 0.0
    for point in usable:
        accepted = int(point.get("accepted", 0))
        oracle_errors = max(0, accepted - correct_total)
        risk = oracle_errors / accepted if accepted else 0.0
        width = point["coverage"] - previous_coverage
        if width > 0:
            area += width * (previous_risk + risk) / 2.0
        previous_coverage = point["coverage"]
        previous_risk = risk
    return round(area, 6)


def excess_aurc(curve: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """AURC minus the oracle, isolating ranking quality from base error.

    E-AURC is zero when the confidence score perfectly orders correct decisions before
    incorrect ones. It says nothing about how many errors the classifier makes - that
    is ``risk_at_full_coverage`` - and the two must be read together.
    """
    value = aurc(curve)
    star = oracle_aurc(curve)
    usable = [p for p in curve if p.get("risk") is not None]
    e0 = usable[-1]["risk"] if usable else None
    excess = (
        round(value - star, 6) if value is not None and star is not None else None
    )
    if excess is not None and excess < -1e-9:
        # Cannot happen with a correct oracle. Reported rather than clamped, because
        # clamping would hide the next time the comparison is wrong.
        excess = {"value": excess, "inconsistent": True}
    return {
        "aurc": value,
        "oracle_aurc": star,
        "excess_aurc": excess,
        "risk_at_full_coverage": e0,
        "max_coverage_reached": usable[-1]["coverage"] if usable else None,
    }


def coverage_at_risk(
    curve: Sequence[dict[str, Any]], target: float
) -> dict[str, Any]:
    """The most automation available without exceeding an error budget.

    This is the operating question for a SOC: "if automated decisions may be wrong at
    most 1% of the time, how much of the queue can I hand over?" Reported as ``None``
    when no point on the curve satisfies the budget, which is a real answer and not a
    zero - it means the pipeline cannot be automated at that risk level on this corpus.
    """
    satisfying = [p for p in curve
                  if p.get("risk") is not None and p["risk"] <= target + 1e-12]
    if not satisfying:
        return {"risk_budget": target, "coverage": None, "threshold": None,
                "satisfied": False}
    best = max(satisfying, key=lambda p: p["coverage"])
    return {
        "risk_budget": target,
        "coverage": best["coverage"],
        "threshold": best["threshold"],
        "risk": best["risk"],
        "accepted": best["accepted"],
        "satisfied": True,
    }


def risk_at_coverage(
    curve: Sequence[dict[str, Any]], target: float
) -> dict[str, Any]:
    """The error rate incurred by automating a given fraction of the queue."""
    reaching = [p for p in curve
                if p.get("risk") is not None and p["coverage"] >= target - 1e-12]
    if not reaching:
        return {"coverage_target": target, "risk": None, "reached": False}
    # The cheapest way to reach the target: the lowest-coverage point that still
    # reaches it, which is the tightest threshold that suffices.
    best = min(reaching, key=lambda p: p["coverage"])
    return {
        "coverage_target": target,
        "coverage": best["coverage"],
        "risk": best["risk"],
        "threshold": best["threshold"],
        "reached": True,
    }


def deferral_composition(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """What the deferred slice contains.

    If the selector is doing its job the deferred set is enriched for the hard cases -
    truncated reads, escalated disagreements, adversarial constructions - and that is
    the design working rather than failing. Composition is reported so the claim can
    be checked instead of asserted.
    """
    deferred = [r for r in rows if not _decided(r)]
    if not deferred:
        return {"deferred": 0, "truncated": 0, "escalated": 0,
                "model_assisted": 0, "adversarial": 0, "labels": {}}
    labels: dict[str, int] = {}
    for row in deferred:
        key = str(row.get("label") or "unlabelled")
        labels[key] = labels.get(key, 0) + 1
    return {
        "deferred": len(deferred),
        "truncated": sum(1 for r in deferred if r.get("truncated")),
        "escalated": sum(1 for r in deferred if r.get("escalated")),
        "model_assisted": sum(1 for r in deferred if r.get("model_judgments")),
        "adversarial": sum(1 for r in deferred if r.get("status") is not None),
        "labels": dict(sorted(labels.items())),
    }


def selective_report(
    rows: Sequence[dict[str, Any]],
    *,
    calibrated: bool = False,
    risk_budgets: Sequence[float] = (0.001, 0.005, 0.01, 0.02, 0.05),
    coverage_targets: Sequence[float] = (0.25, 0.5, 0.75, 0.9, 1.0),
) -> dict[str, Any]:
    """Everything above, assembled for the committed artifact.

    ``calibrated`` is carried into the output and defaults to False, so a renderer
    cannot drop the caveat by forgetting to add it. The confidence values in this
    project are policy labels, and a reader who mistakes one for a probability will
    over-trust every operating point below.
    """
    curve = risk_coverage_curve(rows)
    return {
        "calibrated": calibrated,
        "operating_point": operating_point(rows),
        "curve": curve,
        "curve_points": len(curve),
        **excess_aurc(curve),
        "coverage_at_risk": [coverage_at_risk(curve, b) for b in risk_budgets],
        "risk_at_coverage": [risk_at_coverage(curve, t) for t in coverage_targets],
        "deferral_composition": deferral_composition(rows),
    }
