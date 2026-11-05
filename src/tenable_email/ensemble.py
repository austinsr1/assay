"""Combining a deterministic finding with model opinions.

The deterministic layer produces facts; the tiers produce opinions. The whole
point of keeping them separate in :mod:`~tenable_email.evidence` is that they
cannot be merged by arithmetic. Averaging ``0.95`` from a verified lookalike
domain with ``0.4`` from a small model produces a number that implies a precision
neither of them has, and it lets an opinion drag a fact toward the middle.

So this module does three things instead of averaging.

* **Facts are floors and vetoes.** A disposition the deterministic layer reached
  on VERIFIED findings alone stands. A model may escalate it -- say the attack
  class, say the message is worse than "spam" -- but may not talk it down. That
  is the rule :mod:`~tenable_email.evidence` exists to make representable, and
  the reference playbook's flaw: "destination matches a domain, therefore clean".
* **Opinions vote in the band the facts left open.** Where the deterministic
  layer could not decide, the available tiers decide *unanimously or not at all*.
  Disagreement is a routing outcome (a person), not a number to be split.
* **The bar is not the same in both directions.** :class:`EnsemblePolicy` carries
  the asymmetry as a parameter rather than as a magic comparison.

Clearing a message requires ``clearance_bar`` -- derived from the cost ratio
below, not chosen -- while flagging one requires only ``thresholds.band_medium``.
With a 6:1 cost ratio that is 0.857 to clear against 0.60 to flag: three times as
much agreement, and a higher standard of certainty, before the system says "this
is fine, close it".
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Iterable

from .config import Config
from .tiers import Judgment, LlmTier, Stance, VlmTier
from .verdict import AttackType, Disposition

__all__ = [
    "ADJUDICATION_TIER",
    "DEFERRAL_CONFIDENCE",
    "INDEPENDENT_EVIDENCE_TIERS",
    "DEFAULT_POLICY",
    "Deterministic",
    "EnsembleOutcome",
    "EnsemblePolicy",
    "combine",
]


@dataclass(frozen=True)
class EnsemblePolicy:
    """The numeric shape of the asymmetry, in one place, with its reasoning."""

    #: How much more a false negative costs than a false positive.
    #:
    #: A missed threat stays in every mailbox it was sent to: containment means
    #: recalling mail, resetting credentials and looking at what was entered --
    #: incident work measured in hours, per message, for a phish that a user
    #: already reported once. A false positive costs an analyst one look at a
    #: queue entry: minutes. The ratio is a *judgment about cost*, not a
    #: measurement of accuracy, and it is the one number in this file an operator
    #: may legitimately disagree with, so it is a parameter and not a comparison
    #: buried in a conditional.
    false_negative_cost: float = 6.0

    #: Confidence a model needs before its vote may *flag* a message the
    #: deterministic layer left open. Nothing above :attr:`band_medium` is needed
    #: to send one more message to a human: that is the cheap direction.
    flag_needs: str = "band_medium"

    #: Confidence a *specialist* tier needs before its threat finding vetoes an
    #: automatic clearance. This is not a verdict change and deliberately cannot
    #: become one: the veto moves ``CLEAN`` to ``MANUAL_REVIEW`` and stops there.
    #:
    #: The reason it exists is that a decisive CLEAN is the one outcome nothing
    #: downstream can reopen, so if the deterministic layer's idea of "nothing
    #: adverse" is narrower than the attacker's repertoire, the error is silent
    #: and permanent. An external red-team review found exactly that: a vision
    #: tier reporting a credential-harvesting image at 0.999 could not stop a
    #: clearance, because only the adjudication tier was allowed to.
    #:
    #: The bar is high and the cost is real and known -- see
    #: :data:`INDEPENDENT_EVIDENCE_TIERS` for which tiers may exercise it at all,
    #: and for the measurements that excluded the others. Lower it to buy
    #: coverage, raise it to buy clearance rate, but the trade is explicit and in
    #: one place rather than buried in a conditional.
    specialist_veto_bar: float = 0.95

    @property
    def clearance_bar(self) -> float:
        """Confidence every available tier must reach before a message may be
        cleared (``CLEAN``) rather than flagged.

        Derived from the cost ratio, not picked: clearing is only the better
        expected-cost choice when the odds of harm are at least
        ``1 / (1 + false_negative_cost)``, i.e. the belief in harm must sit below
        that much of the probability mass. At the default 6.0 that is **0.857** --
        so a single tier at "high" (0.90, the band the prompt asks for) clears a
        message, and a tier at 0.7 does not.
        """
        cost = max(1.0, float(self.false_negative_cost))
        return round(cost / (1.0 + cost), 4)


DEFAULT_POLICY = EnsemblePolicy()

#: The one tier allowed to reopen a disposition the deterministic layer settled.
#: It is the tier shown the verified technical facts alongside the fenced content
#: (:func:`tenable_email.prompts.build_classification_prompt`); every other tier
#: on the cascade sees the body text, a single URL or a single image, and so has
#: strictly less information than the finding it would contradict.
ADJUDICATION_TIER = LlmTier.name

#: Confidence reported with any disposition that means "a person must look".
#: Matches the deterministic escalation paths so the band is consistent, and
#: deliberately below ``band_medium`` so a deferral is never labelled MEDIUM or
#: HIGH -- the least decided outcome should not carry the most confident label.
DEFERRAL_CONFIDENCE = 0.5

#: Tiers whose finding is *independent evidence* rather than a second opinion
#: about evidence the deterministic layer already had.
#:
#: A veto on an automatic clearance is only defensible if the tier saw something
#: the rules could not. ``vision`` reads pixels -- an inline credential-harvesting
#: image is invisible to text analysis, which is exactly why
#: ``threat_image_credential_harvest`` exists as a fixture with no link at all for
#: text analysis to find.
#:
#: The text tiers are excluded. ``classifier``, ``prompt_injection``,
#: ``injection_classifier`` and ``spam_three_way`` all read the same body text the
#: deterministic layer already parsed, so what they offer is a different opinion
#: about the same evidence -- and this project has measured that opinion being
#: confidently wrong: 0.99 phishing on a mailer-daemon bounce and 0.98 on a
#: security newsletter.
#:
#: ``url_reputation`` is excluded too, and that was a measurement rather than an
#: assumption. It looked like the strongest candidate -- an external lookup about
#: a destination is information no amount of parsing the message can produce --
#: but the committed recordings for this corpus show the engine returning 0.962
#: for ``https://docusign.net/signing/abc123``, 0.917 for a security newsletter
#: and 0.907 for a retailer's sale page. A veto wired to that would have turned
#: three correct clearances into review queue, which is the same failure mode as
#: the text classifier wearing a different hat. This is the pattern
#: ``docs/EVAL-SUITES.md`` records from the published benchmarks: high in-domain
#: accuracy coexisting with catastrophic false positives just outside it. The
#: tier's votes are still recorded in full and can still move an unsettled
#: message; it may not reopen a settled one until its false-positive rate on
#: benign destinations is measured.
#:
#: The consequence is deliberately narrow: exactly one tier can veto, and it is
#: unmeasured on benign images because the corpus holds a single vision
#: recording. That is stated here rather than hidden, because a veto that never
#: fires is not a protection.
INDEPENDENT_EVIDENCE_TIERS: frozenset[str] = frozenset({VlmTier.name})

#: Escalation order for "may a model raise this?". SPAM above CLEAN because
#: unwanted mail is still a disposition a human should not have to look at;
#: THREAT above both.
_SEVERITY: dict[Disposition, int] = {
    Disposition.CLEAN: 0,
    Disposition.SPAM: 1,
    Disposition.THREAT: 2,
}

_STANCE_DISPOSITION: dict[Stance, Disposition] = {
    Stance.THREAT: Disposition.THREAT,
    Stance.SPAM: Disposition.SPAM,
    Stance.CLEAN: Disposition.CLEAN,
}


@dataclass(frozen=True)
class Deterministic:
    """What the rules layer concluded, and how firmly it was concluded.

    ``decisive`` is the load-bearing flag: it means the disposition was reached
    from VERIFIED findings and nothing else, so a model opinion cannot displace
    it. ``clear_blocked`` is narrower again -- a reason this message may never be
    *cleared* on an opinion, even where the rules themselves did not decide. The
    business-email-compromise shape is in that set precisely because what cannot
    be known (is this account compromised?) is recorded as an UNKNOWN, and an
    unknown may not be answered by a model's confidence.
    """

    disposition: Disposition
    confidence: float
    attack_type: AttackType = AttackType.UNCLASSIFIED
    decisive: bool = False
    clear_blocked: bool = False
    reasons: tuple[str, ...] = ()
    cited: tuple[str, ...] = ()


@dataclass
class EnsembleOutcome:
    """The combined verdict inputs, with the reasoning kept separable."""

    disposition: Disposition = Disposition.UNKNOWN
    confidence: float = 0.0
    attack_type: AttackType = AttackType.UNCLASSIFIED
    reasons: list[str] = field(default_factory=list)
    model_reasons: list[str] = field(default_factory=list)
    cited: list[str] = field(default_factory=list)
    disagreement: bool = False
    escalated: bool = False
    changed_deterministic: bool = False
    #: A specialist tier blocked an automatic clearance. Distinct from
    #: ``changed_deterministic`` because the disposition moved *down* to a human
    #: rather than up to a threat, and nothing was asserted over verified facts.
    clearance_vetoed: bool = False
    # ``contributions`` lived here: one serialized dict per contributing tier. It
    # was written and never read, and it duplicated a record that already has an
    # owner -- ``consult_tiers`` adds one MODEL_JUDGMENT finding per tier that
    # answered, carrying the same normalized judgment including abstentions, and
    # the receipt serializes those findings with their provenance. Two
    # representations of the same votes is how one of them goes stale.


def _bar_for(stance: Stance, config: Config, policy: EnsemblePolicy) -> float:
    """The confidence a stance must reach to be *adopted* from model votes."""
    if stance is Stance.CLEAN:
        return policy.clearance_bar
    return float(getattr(config.thresholds, policy.flag_needs, 0.60))


def _vote_confidence(judgment: Judgment) -> float | None:
    """A tier's own confidence, or ``None`` when it quantified nothing.

    An unquantified opinion can still escalate -- a one-word "injection" label is
    a signal worth routing on -- but it can never satisfy a bar, because there is
    no number to compare. Treating an absent confidence as a high one would be
    the same fabrication in the other direction.
    """
    if judgment.confidence is None:
        return None
    return max(0.0, min(1.0, float(judgment.confidence)))


def _describe(judgment: Judgment, confidence: float | None) -> str:
    score = ""
    if judgment.score_fields:
        parts = ", ".join(
            f"{k}={v:.4f}" if isinstance(v, float) else f"{k}={v}"
            for k, v in sorted(judgment.score_fields.items())
        )
        score = f" scores: {parts}"
    value = "no stated confidence" if confidence is None else f"{confidence:.2f}"
    return (
        f"The {judgment.tier} tier voted {judgment.stance.value} at confidence "
        f"{value}{score}."
        + (f" {judgment.detail}." if judgment.detail else "")
    )


def combine(
    deterministic: Deterministic,
    judgments: Iterable[Judgment],
    config: Config,
    policy: EnsemblePolicy = DEFAULT_POLICY,
) -> EnsembleOutcome:
    """Combine one deterministic outcome with whatever tiers had an opinion.

    Returns an outcome carrying reasons and the finding keys to cite. It never
    touches :class:`~tenable_email.evidence.Evidence`: recording is the
    pipeline's job, and a consumer that cites these keys gets the provenance the
    pipeline attached -- ``MODEL_JUDGMENT`` for every one of them.
    """
    all_judgments = list(judgments)
    outcome = EnsembleOutcome(
        disposition=deterministic.disposition,
        confidence=deterministic.confidence,
        attack_type=deterministic.attack_type,
        reasons=list(deterministic.reasons),
        cited=list(deterministic.cited),
    )
    votes = [
        (j, _vote_confidence(j))
        for j in all_judgments
        if j.stance in _STANCE_DISPOSITION
    ]

    if not votes:
        # Nothing to combine. An abstaining tier or an unavailable one changes no
        # disposition, and the reasons below say so rather than implying silence
        # was agreement.
        for judgment in all_judgments:
            if judgment.stance is Stance.ABSTAIN:
                outcome.model_reasons.append(_describe(judgment, None))
        outcome.escalated = outcome.disposition in (
            Disposition.MANUAL_REVIEW, Disposition.UNKNOWN
        )
        return outcome

    band_medium = float(config.thresholds.band_medium)
    stances = {j.stance for j, _ in votes}

    # -- the facts already settled it ---------------------------------------
    # ``_SEVERITY`` has no entry for MANUAL_REVIEW or UNKNOWN, because nothing is
    # more or less severe than "a person must look". ``Deterministic`` is a public
    # frozen dataclass whose ``decisive`` and ``disposition`` fields are
    # independent, so a caller can set both incoherently; indexing the table
    # directly turned that into a KeyError out of a public function. Treat it as
    # unsettled instead and let the open band handle it.
    settled_severity = _SEVERITY.get(deterministic.disposition)

    if deterministic.decisive and settled_severity is not None:
        dissents = [
            (j, c) for j, c in votes
            if _SEVERITY[_STANCE_DISPOSITION[j.stance]] < settled_severity
        ]
        escalations = [
            (j, c) for j, c in votes
            if _SEVERITY[_STANCE_DISPOSITION[j.stance]] > settled_severity
        ]
        # Only the adjudication tier may reopen a settled message, and only above
        # the clearance bar. The rest of the tiers read the body text alone: they
        # never see the authentication results, the MIME inventory or the link
        # analysis, and on this corpus they demonstrably disagree with verified
        # facts -- the text classifier reads a mailer-daemon bounce as phishing at
        # 0.99 and a security newsletter as phishing at 0.98, and the injection
        # engine scores the bounce as an injection attempt at 1.00. An opinion
        # formed without the facts cannot reopen a finding made from them, in
        # either direction; the adjudication tier is shown the verified facts
        # alongside the fenced content, so it is the one opinion that can.
        eligible = [
            (j, c) for j, c in escalations
            if j.tier == ADJUDICATION_TIER
            and c is not None and c >= policy.clearance_bar
        ]
        if eligible:
            judgment, confidence = max(
                eligible, key=lambda pair: _SEVERITY[_STANCE_DISPOSITION[pair[0].stance]]
            )
            outcome.disposition = _STANCE_DISPOSITION[judgment.stance]
            outcome.confidence = confidence
            outcome.attack_type = judgment.attack_type or outcome.attack_type
            outcome.changed_deterministic = True
            outcome.model_reasons.append(_describe(judgment, confidence))
            outcome.reasons.append(
                "Escalated above the deterministic disposition by the "
                f"adjudication tier at confidence {confidence:.2f}, which is at "
                f"or above the {policy.clearance_bar:.3f} bar: a model may raise "
                "severity, and this one was shown the verified facts as well as "
                "the content."
            )
        elif dissents or escalations:
            unheard = dissents + [
                pair for pair in escalations if pair not in eligible
            ]
            outcome.reasons.append(
                "Recorded and deliberately not applied: "
                + " ".join(_describe(j, c) for j, c in unheard)
                + " This disposition rests on verified findings ("
                + ", ".join(list(deterministic.cited)[:4])
                + "). No tier may rewrite a disposition the deterministic layer "
                  "settled on those findings -- not downward, because a model's "
                  "safe is not evidence that a lookalike domain is not one, and "
                  "not upward either. The single exception is the clearance veto "
                  "above, which is available only to a tier that saw evidence the "
                  "rules could not, and which defers to a human rather than "
                  "asserting a verdict."
            )
        # -- a specialist may veto a clearance, but may not author a verdict ---
        #
        # Applied only to CLEAN, and only ever downward to MANUAL_REVIEW. A
        # specialist is not shown the authentication results, the MIME inventory
        # or the link analysis, so it has no standing to *assert* a threat over
        # verified facts -- but it does have standing to say "do not close this
        # automatically", because the cost of that is one analyst look and the
        # cost of being right and unheard is a compromised account. The veto is
        # recorded with the tier and confidence that caused it so an operator can
        # see the coverage cost and adjust ``specialist_veto_bar``.
        if not eligible and deterministic.disposition in (
            Disposition.CLEAN, Disposition.SPAM,
        ):
            vetoing = [
                (j, c) for j, c in escalations
                if j.tier != ADJUDICATION_TIER
                and j.tier in INDEPENDENT_EVIDENCE_TIERS
                and c is not None and c >= policy.specialist_veto_bar
            ]
            if vetoing:
                judgment, confidence = max(vetoing, key=lambda pair: pair[1])
                outcome.disposition = Disposition.MANUAL_REVIEW
                # A veto is a deferral, and every other deferral in this pipeline
                # reports 0.5 so it lands in the LOW band. Taking the minimum of
                # the two inputs instead produced 0.90 -- the highest band the
                # system has -- attached to the one disposition that means "we are
                # declining to decide". An operator reading the record would see
                # the most confident label on the least decided outcome.
                outcome.confidence = min(
                    deterministic.confidence, confidence, DEFERRAL_CONFIDENCE
                )
                outcome.changed_deterministic = True
                outcome.clearance_vetoed = True
                outcome.model_reasons.append(_describe(judgment, confidence))
                outcome.reasons.append(
                    f"Automatic clearance vetoed by the {judgment.tier} tier at "
                    f"confidence {confidence:.2f}, at or above the "
                    f"{policy.specialist_veto_bar:.3f} specialist veto bar. Only "
                    f"a tier that saw evidence the deterministic layer could not "
                    f"-- currently image content alone -- may veto, and even then "
                    f"this is not a threat finding and is not "
                    f"recorded as one. It can only decline to let the message "
                    f"close without a human reading it, because a decisive "
                    f"clearance is the one outcome nothing downstream is allowed "
                    f"to reopen."
                )
        outcome.escalated = outcome.disposition in (
            Disposition.MANUAL_REVIEW, Disposition.UNKNOWN
        )
        return outcome

    # -- the band the facts left open ---------------------------------------
    if len(stances) > 1:
        outcome.disposition = Disposition.MANUAL_REVIEW
        outcome.confidence = min(
            deterministic.confidence or band_medium, band_medium
        )
        outcome.disagreement = True
        outcome.changed_deterministic = outcome.disposition is not (
            deterministic.disposition
        )
        outcome.reasons.append(
            "The consulted tiers do not agree: "
            + " ".join(_describe(j, c) for j, c in votes)
            + " Disagreement between an ONNX classifier, a reputation engine and "
              "a language model is information, not noise to be averaged away, so "
              "this message is routed to a person."
        )
        outcome.escalated = True
        return outcome

    stance = next(iter(stances))
    confidences = [c for _, c in votes]
    weakest = (
        min((c for c in confidences if c is not None), default=None)
    )
    bar = _bar_for(stance, config, policy)
    proposed = _STANCE_DISPOSITION[stance]

    if stance is Stance.CLEAN and deterministic.clear_blocked:
        outcome.disposition = Disposition.MANUAL_REVIEW
        outcome.confidence = min(deterministic.confidence or band_medium, band_medium)
        outcome.disagreement = True
        outcome.escalated = True
        outcome.reasons.append(
            "The consulted tiers all read this message as legitimate: "
            + " ".join(_describe(j, c) for j, c in votes)
            + " That does not clear it. The deterministic layer found the shape of "
              "an account compromise -- authenticating sender, no destination to "
              "inspect, a request for money -- and whether the sending account is "
              "compromised is recorded as unknowable from the message. Agreeing "
              "with each other is not the same as being able to answer that."
        )
        return outcome

    if weakest is None or weakest < bar:
        outcome.disposition = Disposition.MANUAL_REVIEW
        outcome.confidence = min(
            weakest if weakest is not None else band_medium,
            deterministic.confidence or band_medium,
            band_medium,
        )
        outcome.escalated = True
        outcome.disagreement = weakest is None
        outcome.changed_deterministic = outcome.disposition is not (
            deterministic.disposition
        )
        outcome.reasons.append(
            "The consulted tiers agree on " + stance.value + " but are not "
            f"confident enough to act on it: " + " ".join(
                _describe(j, c) for j, c in votes
            )
            + f" {stance.value} requires {bar:.3f} to be adopted and the weakest "
              f"vote did not reach it, so this is escalated. Confidence below "
              f"{band_medium:.2f} routes to a person by policy, not by taste."
        )
        return outcome

    # Unanimous and over the bar: adopt the models' view with the *weakest*
    # vote's confidence. A minimum is an honest ceiling for a chain of opinions;
    # a mean would manufacture agreement stronger than any tier claimed.
    outcome.disposition = proposed
    outcome.confidence = weakest
    outcome.changed_deterministic = True
    outcome.model_reasons = [_describe(j, c) for j, c in votes]
    if proposed is Disposition.THREAT:
        named = [j for j, _ in votes if j.attack_type is not None]
        outcome.attack_type = (
            named[0].attack_type if named else AttackType.UNCLASSIFIED
        )
        outcome.reasons.append(
            f"Dispositioned THREAT at confidence {weakest:.2f} by unanimous model "
            f"vote ({', '.join(sorted(j.tier for j, _ in votes))}) where the "
            "deterministic layer found nothing decisive. The asymmetric cost of a "
            "missed threat is why a model vote can produce this; the clearance bar "
            f"({policy.clearance_bar:.3f}) is why the reverse is harder."
        )
    elif proposed is Disposition.SPAM:
        outcome.attack_type = AttackType.SPAM
        outcome.reasons.append(
            f"Dispositioned SPAM at confidence {weakest:.2f} by unanimous model "
            f"vote ({', '.join(sorted(j.tier for j, _ in votes))}): unwanted "
            "commercial mail that is not trying to steal anything is a distinct "
            "class, and a queue of it is a filtering problem rather than an "
            "incident."
        )
    else:
        outcome.attack_type = AttackType.NONE
        outcome.reasons.append(
            f"Dispositioned CLEAN at confidence {weakest:.2f}: every consulted "
            f"tier ({', '.join(sorted(j.tier for j, _ in votes))}) cleared the "
            f"message at or above the {policy.clearance_bar:.3f} bar, which is the "
            "clearest the deterministic band can be given an opinion rather than "
            "a fact as support."
        )
    outcome.escalated = False
    return outcome


# ``outcome_reasons()`` lived here and had no callers anywhere in the package,
# the tools or the suite. It rendered ``model_reasons`` into a list of strings,
# which is what the verdict now does directly, so keeping it would have been a
# second rendering of the same votes with nothing to keep the two in step.

