"""The triage path: signals, model tiers, evidence, then a verdict.

With no endpoints configured -- the shipped default, and what every test and
reviewer here runs -- nothing in this module performs network I/O. That is the
point: a judge cloning this repository runs the whole chain with no credentials,
no live mail and no inference host. Model tiers are not silently skipped: each
tier with no endpoint is recorded as an ``UNAVAILABLE`` finding naming the tier
and the config field that is empty, so "the classifier said nothing" can never be
read as "the classifier found nothing". In replay mode the tiers are read from
the committed recordings in :mod:`tenable_email.replay`, and a recording that
does not exist is a miss, not a network call and not an invented answer. Live
calls happen only when an operator both names an endpoint and turns replay off.

Four rules govern what happens here.

1. **A verdict cites findings; it does not invent them.** Every reason is backed
   by a finding already in the evidence record, and ``Evidence.assert_citable()``
   is called before the verdict is returned. An unknown cannot reach a
   disposition, because the only path from a finding to a citation goes through
   that assertion.
2. **Authentication passing is not evidence of legitimacy.** A message from a
   protected domain with valid DKIM, no links and a request for a payment is the
   business-email-compromise shape, and the reference playbook's
   domain-matches-therefore-clean rule gets it wrong. It routes to a human.
3. **A partial reading is never reported as a complete one.** Truncation is
   propagated into the verdict, into the reasons and into the analysis text.
4. **Facts outrank opinions.** A disposition the deterministic layer reached on
   verified findings can be escalated by a model tier but never talked down;
   where the layer did not decide, :mod:`tenable_email.ensemble` combines the
   tier votes asymmetrically, because a missed threat costs orders of magnitude
   more than one extra item in a review queue.

Prompt injection is treated as a **reported threat class**, not only as a guard
on our own adjudication: an email carrying instructions aimed at the recipient's
mail-reading agent is attacking that agent, and a SOC wants to be told. But the
deterministic scanner cannot tell "contains an instruction aimed at an agent"
from "quotes an instruction while discussing it" -- a security newsletter looks
identical to the former. So a deterministic hit alone never produces ``THREAT``:
it must be corroborated by an independent indicator, and when it is not, the
confidence is capped and the message goes to a person. A model tier is what
corroboration looks like here. See ``docs/MODELS.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit

from . import attachments, ensemble, tiers
from .config import Config
from .evidence import Evidence, Finding, Provenance
from .parse import Message, parse_file, parse_message
from .prompts import build_classification_prompt
from .replay import ReplayStore, open_store
from .signals import extract_signals, parse_address
from .verdict import AttackType, Disposition, Verdict

__all__ = [
    "ALL_STAGES_IN_ORDER",
    "DETERMINISTIC_STAGES_RUN",
    "MODEL_TIERS",
    "STAGES_SKIPPED_WITHOUT_CONFIG",
    "build_evidence",
    "consult_tiers",
    "detect_bec_language",
    "derive_facts",
    "tier_requests",
    "triage_bytes",
    "triage_file",
    "triage_message",
]

# --------------------------------------------------------------------------
# stage identity
#
# These are the ids declared in stages.yaml. They are repeated here rather than
# read from the file, so importing the package never depends on a data file
# being present at an unknown location; tests/test_contract.py asserts the two
# sets agree, which is the same enforcement with better failure modes.
# --------------------------------------------------------------------------

STAGE_INTAKE = "intake"
STAGE_PARSE = "parse-authenticate"
STAGE_SIGNALS = "deterministic-signals"
STAGE_CLASSIFIER = "classifier-cascade"
STAGE_VISION = "vision"
STAGE_ATTACHMENTS = "attachment-content"
STAGE_ADJUDICATION = "adjudication"
STAGE_WRITEBACK = "disposition-writeback"

#: The stages this path actually executes.
DETERMINISTIC_STAGES_RUN = (
    STAGE_INTAKE,
    STAGE_PARSE,
    STAGE_SIGNALS,
    STAGE_ADJUDICATION,
)

#: Stages that are skipped -- and recorded UNAVAILABLE -- when unconfigured.
#: ``disposition-writeback`` belongs in this list because it is the write stage
#: and no write happens without a human approval that this path never asks for.
STAGES_SKIPPED_WITHOUT_CONFIG = (
    STAGE_CLASSIFIER,
    STAGE_VISION,
    STAGE_ATTACHMENTS,
    STAGE_WRITEBACK,
)

#: Every contract stage, in contract order. ``stages_run`` on a verdict is drawn
#: from this list rather than from the order results arrived in, so the field
#: reads as the chain a reviewer can follow. ``tests/test_tiers.py`` asserts it
#: equals ``stages.yaml``.
ALL_STAGES_IN_ORDER = (
    STAGE_INTAKE,
    STAGE_PARSE,
    STAGE_SIGNALS,
    STAGE_CLASSIFIER,
    STAGE_VISION,
    STAGE_ATTACHMENTS,
    STAGE_ADJUDICATION,
    STAGE_WRITEBACK,
)

#: ``(tier name, config.endpoints field, owning stage)`` for every model tier.
#: A tier whose endpoint field is ``None`` did not run; that is a fact about our
#: configuration, not a finding about the message. The names are the same ones
#: ``tiers.TIER_REGISTRY`` builds, and ``tests/test_tiers.py`` asserts the two
#: lists agree -- a tier in one and not the other is a tier that silently never
#: runs, or a gap nobody records.
MODEL_TIERS: tuple[tuple[str, str, str], ...] = (
    ("classifier", "fraudfox_url", STAGE_CLASSIFIER),
    ("url_reputation", "secmodels_url", STAGE_CLASSIFIER),
    ("prompt_injection", "secmodels_url", STAGE_CLASSIFIER),
    ("injection_classifier", "injection_classifier_url", STAGE_CLASSIFIER),
    ("spam_three_way", "spam_classifier_url", STAGE_CLASSIFIER),
    ("vision", "vlm_url", STAGE_VISION),
    ("llm", "llm_url", STAGE_ADJUDICATION),
)

#: ``(tier name -> owning stage)`` and ``(tier name -> config field)`` views of
#: the same list, so findings can be attributed without re-deriving the tuples.
_TIER_STAGE: dict[str, str] = {name: stage for name, _field, stage in MODEL_TIERS}
_TIER_FIELD: dict[str, str] = {name: field for name, field, _stage in MODEL_TIERS}

#: Signal keys owned by the parse stage rather than the signal stage, so each
#: finding can be attributed to the stage that produced it.
_PARSE_OWNED_KEYS = frozenset(
    {
        "sender", "reply_to", "return_path", "recipients", "subject", "date",
        "message_id", "auth", "alignment",
    }
)

#: Phrases whose *presence* -- not their meaning -- is a fact about the text.
#: Multi-token wherever a single word would over-match, because the BEC rule is
#: the one place this pipeline refuses to clear a message, and a false trigger
#: there costs a human's time on a legitimate mail.
_PAYMENT_URGENCY_PHRASES = (
    "invoice", "overdue", "remittance", "wire payment", "wire transfer",
    "payment today", "payment request", "process the attached", "bank details",
    "banking details", "new account details", "account is closed",
    "direct deposit", "gift card", "giftcard", "zelle", "bitcoin",
    "crypto wallet", "urgent", "immediate", "asap", "action required",
    "within 24 hours", "permanent loss",
)

#: Concealment requests, which are rare in legitimate mail about money.
_CONCEALMENT_PHRASES = (
    "do not mention", "do not discuss", "keep this between", "just between us",
    "don't mention", "discreet", "not announced",
)

#: Attack classes that describe harm aimed at the human recipient. A
#: prompt-injection attempt does not displace these; it is reported alongside
#: them. SPAM and UNCLASSIFIED deliberately do not appear -- an agent-
#: manipulation attempt outranks both.
_MALICE_ATTACK_TYPES = (
    AttackType.CREDENTIAL_HARVEST,
    AttackType.MALWARE,
    AttackType.BEC,
)

# --------------------------------------------------------------------------
# evidence assembly
# --------------------------------------------------------------------------


def detect_bec_language(msg: Message) -> dict:
    """Which payment/urgency and concealment phrases appear in the text.

    A substring fact, not a judgment about intent: it says the words are
    present. The rule that consumes it also requires passing authentication, a
    claimed protected domain and an absence of links, so no phrase changes a
    disposition on its own.
    """
    text = " \n ".join(filter(None, (msg.subject, msg.body))).lower()
    urgency = [p for p in _PAYMENT_URGENCY_PHRASES if p in text]
    concealment = [p for p in _CONCEALMENT_PHRASES if p in text]
    return {
        "matched": urgency + concealment,
        "payment_urgency": urgency,
        "concealment": concealment,
        "count": len(urgency) + len(concealment),
    }


_SIGNAL_DETAILS = {
    "auth": (
        "SPF, DKIM and DMARC outcomes as claimed in the message headers. Header "
        "provenance is not established from a raw .eml: a sender can supply an "
        "Authentication-Results of their own, so these are treated as usable but "
        "unauthenticated, and contradictory headers block an automatic clearance"
    ),
    "alignment": "which domains authenticated, and whether they match the sender",
    "lookalike": "resemblance between the sender domain and a protected or vendor domain",
    "display_name_spoofing": "a display name asserting an identity the sending domain does not own",
    "reply_to_mismatch": "whether Reply-To points somewhere other than From",
    "links": "link destinations after redirect unwrapping, compared against sender and trusted domains",
    "link_details": "one entry per link: href, visible text, resolved host, mismatch flags",
    "attachments": "attachment inventory from the MIME tree; content is not read here",
    "forwarding": "whether this message wraps another message, and who sent the inner one",
    "bulk": "legitimate-bulk-mail header signals used for the spam class",
    "injection": "deterministic prompt-injection indicator matches",
    "boilerplate_removed": "mail-system boilerplate stripped before text scanning",
    "truncated": "whether the retained body was cut short of the original",
    "original_body_length": "body length before any truncation",
    "body_chars": "characters of body retained for analysis",
    "bec_language": "payment, urgency and concealment phrases present in the text",
    "intake": "message acquisition; only the file name is retained, not its directory",
}


def _tier_can_run(name: str, config: Config, store: ReplayStore | None = None) -> bool:
    """Whether a tier is reachable: an address, or a recording to read."""
    field = _TIER_FIELD.get(name)
    if field and getattr(config.endpoints, field, None) is not None:
        return True
    return bool(
        config.replay and store is not None and name in store.tiers_with_recordings()
    )


def build_evidence(
    msg: Message, signals: dict, config: Config, *, store: ReplayStore | None = None
) -> Evidence:
    """Turn the deterministic layer's output into an append-only record.

    Every signal becomes a VERIFIED finding. Each model tier that cannot run
    becomes an UNAVAILABLE finding naming the tier and why. The things that
    genuinely cannot be known from a message become UNKNOWN findings rather than
    being left blank or, worse, inferred.
    """
    ev = Evidence()
    ev.truncated = bool(signals.get("truncated"))
    ev.original_length = signals.get("original_body_length")

    # Only the file name is recorded, never a directory path: this record is
    # written to shipped output, and a local path is infrastructure detail.
    source = msg.source or "inline"
    source_name = source if source == "inline" else Path(source).name
    ev.verified(
        "intake",
        {
            "source": source_name,
            "header_count": len(msg.headers),
            "attachment_parts": len(msg.attachments),
            "has_text_body": bool(msg.text_body),
            "has_html_body": bool(msg.html_body),
        },
        STAGE_INTAKE,
        _SIGNAL_DETAILS["intake"],
    )

    for key, value in signals.items():
        ev.verified(
            key,
            value,
            STAGE_PARSE if key in _PARSE_OWNED_KEYS else STAGE_SIGNALS,
            _SIGNAL_DETAILS.get(key, ""),
        )

    ev.verified(
        "bec_language",
        detect_bec_language(msg),
        STAGE_SIGNALS,
        _SIGNAL_DETAILS["bec_language"],
    )

    for tier, endpoint_field, stage in MODEL_TIERS:
        if _tier_can_run(tier, config, store):
            # A tier with an address, or one with recordings to read in replay
            # mode, is a tier that will be attempted -- and ``consult_tiers``
            # records the outcome, hit or miss, rather than this loop guessing it.
            continue
        ev.unavailable(tier, stage, f"endpoint not configured ({endpoint_field})")

    ev.unknown(
        "account_compromised",
        STAGE_ADJUDICATION,
        "whether the sending account is compromised cannot be determined from "
        "the message; valid authentication is consistent with both a legitimate "
        "sender and a compromised one",
    )
    ev.unknown(
        "credentials_entered",
        STAGE_ADJUDICATION,
        "whether any recipient followed a link and entered credentials is "
        "outside this system's visibility and must not be assumed either way",
    )

    # The optional deep-analysis component. With the shipped default this call
    # returns an empty list without touching the filesystem or spawning anything,
    # so every fixture in this repository is triaged exactly as it was before this
    # line existed. When an operator turns it on it adds findings about what the
    # attachment *contains*, and nothing else: the facts the rules consume come
    # from ``signals``, no finding here is read by ``derive_facts``, and the veto
    # that an unexamined high-risk attachment puts on a clearance stays in force
    # whatever the analyzer reported -- a static read of a container is not a
    # statement that its contents are safe.
    analyses = attachments.run_for_message(msg, config)
    attachments.record_findings(ev, analyses)
    examined = {a.sha256 for a in analyses if a.ok}
    items = (signals.get("attachments") or {}).get("items") or []
    unexamined = [
        i for i in items
        if not i.get("contents_extracted") and i.get("sha256") not in examined
    ]
    if unexamined:
        ev.unknown(
            "attachment_contents_malicious",
            STAGE_ATTACHMENTS,
            "attachment bytes were inventoried, not read; the extension, size "
            "and hash are facts and the contents are not"
            + (
                f"; {len(unexamined)} of {len(items)} part(s) were not read"
                if examined else ""
            ),
        )
    if signals.get("inline_image_count") and not _tier_can_run(
        "vision", config, store
    ):
        ev.unknown(
            "embedded_image_contents_malicious",
            STAGE_VISION,
            "embedded images are present and were not examined by a vision tier",
        )
    if bool((signals.get("injection") or {}).get("attempt_detected")):
        ev.unknown(
            "injection_aimed_at_agent",
            STAGE_CLASSIFIER,
            "the deterministic scanner cannot distinguish an instruction aimed "
            "at an AI agent from a document quoting one; only a model tier can",
        )

    return ev


# --------------------------------------------------------------------------
# adjudication
# --------------------------------------------------------------------------


def _attachment_stage_attempted(ev: Evidence) -> bool:
    """Whether the optional analysis stage was asked to run for this message.

    Derived from the record rather than returned through three signatures: the
    component writes one finding per attachment it was given, so the presence of
    that key is the evidence that the stage was entered. "Entered" is the same
    bar the classifier tier uses -- a tier with an address is a tier that will be
    attempted, and its outcome hit or miss is what gets recorded -- so a stage
    that abstained still shows as run, and the record says why.
    """
    return bool(ev.all(attachments.FINDING_KEY))


def _recorded(ev: Evidence, key: str) -> Finding | None:
    """The first finding recorded under ``key``, of any provenance.

    Deliberately unfiltered: citing is what the provenance invariant is *for*.
    A rule that cites a gap must be stopped by ``assert_citable``, not quietly
    given a different finding.
    """
    found = ev.all(key)
    return found[0] if found else None


def _fact(ev: Evidence, key: str, default: Any = None) -> Any:
    """Read a recorded value. Values are only taken from citable findings."""
    for f in ev.all(key):
        if f.provenance in (Provenance.VERIFIED, Provenance.MODEL_JUDGMENT):
            return f.value
    return default


@dataclass
class _Facts:
    """The boolean facts the rules consume, derived once from the signals."""

    lookalike: bool = False
    anchor_mismatch: bool = False
    dangerous_external: bool = False
    spoofed: bool = False
    reply_mismatch: bool = False
    unaccounted_hosts: list[str] = field(default_factory=list)
    ip_literal_hosts: list[str] = field(default_factory=list)
    javascript_uris: list[str] = field(default_factory=list)
    #: Redirect wrappers whose hidden destination matches neither the sender nor
    #: a trusted domain. Concealment, in other words: somebody paid for a proxy
    #: so the reader would judge the wrapper's domain instead of the destination.
    concealed_redirects: list[dict] = field(default_factory=list)
    auth_failure: bool = False
    auth_passes: bool = False
    #: Two authentication headers disagreed about an outcome. An ARC chain and a
    #: forgery are indistinguishable inside a raw ``.eml``, so rather than guess
    #: which one this is, the conflict is recorded and blocks a clearance.
    auth_conflicting: bool = False
    #: A high-risk attachment is present and its contents were not read, whoever
    #: sent it. Distinct from ``dangerous_external``, which is a THREAT trigger:
    #: this one only blocks a clearance, because a compromised internal account
    #: is a real sender of malicious documents and "it came from inside" is not
    #: evidence the attachment is safe.
    dangerous_unexamined: bool = False
    #: The sender is on the deployer's explicit trust list. Distinct from
    #: ``claims_protected_domain``, which asks whether the sender *is* the
    #: organization. Both are positive evidence; passing authentication is not.
    trusted_sender: bool = False
    legitimate_bulk: bool = False
    injection: bool = False
    forwarded: bool = False
    bec_language: bool = False
    claims_protected_domain: bool = False
    link_count: int = 0
    attachment_count: int = 0
    inline_images: int = 0
    truncated: bool = False

    @property
    def adverse(self) -> bool:
        """Any indicator that blocks a CLEAN disposition.

        Deliberately wider than the THREAT triggers -- an unexplained combination
        goes to a human instead, because a clean verdict is the one outcome this
        system cannot walk back.

        ``dangerous_unexamined`` is here on purpose and is wider than
        ``dangerous_external``: a high-risk attachment blocks a clearance whoever
        sent it, because a compromised internal account is a real source of
        malicious documents. It is *not* a THREAT trigger -- only the external
        variant is -- so an internal sender with a macro-enabled document goes to
        a person rather than being accused.

        Deliberately narrower than it looks: a link to a domain that matches
        neither the sender nor a trusted domain is **not** here. The reference
        playbook treats a destination mismatch as "a very strong indicator of a
        threat" and a match as "a strong indicator of a clean email", and
        ``docs/PARITY.md`` records both halves of that as the flaw: legitimate
        mail routinely links to unrelated services, and a compromised account
        links to its own domain. What blocks a clearance is something that cannot
        be explained without a human -- an anchor that disagrees with its
        destination, or a wrapper hiding one (``concealed_redirects``) -- not a
        destination that is merely somebody else's.
        """
        return bool(
            self.lookalike
            or self.anchor_mismatch
            or self.dangerous_external
            or self.dangerous_unexamined
            or self.concealed_redirects
            or self.spoofed
            or self.reply_mismatch
            or self.ip_literal_hosts
            or self.javascript_uris
            or self.injection
        )

    @property
    def bec_shape(self) -> bool:
        """The compromise shape: passes everything, asks for money.

        Authentication passing, a claimed protected domain, no link to analyse,
        and either a diverging Reply-To or payment language in the text. Nothing
        here is decisive about fraud -- which is exactly why it cannot be
        cleared.
        """
        return bool(
            self.auth_passes
            and self.claims_protected_domain
            and self.link_count == 0
            and (self.reply_mismatch or self.bec_language)
        )


def _concealed_redirects(links: dict) -> list[dict]:
    """Unwrapped redirects whose real destination belongs to nobody.

    Keyed on **concealment**, not on mismatch. A link to an unrelated service is
    ordinary business email -- the reference playbook's prompt calls a
    destination matching the sender or a trusted domain "a strong indicator of a
    clean email" and a mismatch "a very strong indicator of a threat", and
    ``docs/PARITY.md`` records that as the flaw this project refuses. What is not
    ordinary is a *wrapper*: a URL-rewriting proxy is a deliberate decision to
    hide where a link goes, and if the destination behind it then matches neither
    the sender nor a trusted domain, the concealment has no benign purpose left.
    """
    neither = set(links.get("hosts_matching_neither") or [])
    out = []
    for entry in links.get("unwrapped_redirects") or []:
        host = _host_of(str(entry.get("resolved") or ""))
        if host and host in neither:
            out.append({**entry, "resolved_host": host})
    return out


def _host_of(href: str) -> str:
    """The host of a URL, tolerating the junk a body can contain."""
    try:
        return (urlsplit(href.strip()).hostname or "").lower()
    except ValueError:
        return ""


def derive_facts(s: dict, ev: Evidence) -> _Facts:
    auth = s["auth"]
    align = s["alignment"]
    links = s["links"]
    att = s["attachments"]
    bulk = s["bulk"]
    bec = _fact(ev, "bec_language") or {}
    return _Facts(
        lookalike=bool(s["lookalike"]["is_lookalike"]),
        anchor_mismatch=int(links["anchor_mismatch_count"]) > 0,
        dangerous_external=int(att["dangerous_and_external_count"]) > 0,
        spoofed=bool(s["display_name_spoofing"]["is_spoofed"]),
        reply_mismatch=bool(s["reply_to_mismatch"]["mismatch"]),
        unaccounted_hosts=list(links["hosts_matching_neither"]),
        ip_literal_hosts=list(links["ip_literal_hosts"]),
        javascript_uris=list(links["javascript_uris"]),
        concealed_redirects=_concealed_redirects(links),
        auth_failure=auth["dmarc"] == "FAIL"
        or (auth["spf"] == "FAIL" and auth["dkim"] != "PASS"),
        auth_passes=bool(align["auth_passes"]),
        auth_conflicting=bool(align.get("auth_conflicting")),
        dangerous_unexamined=int(att["dangerous_count"]) > 0,
        trusted_sender=bool(align.get("trusted_sender")),
        legitimate_bulk=bool(
            bulk["rfc8058_one_click"]
            or (bulk["has_list_unsubscribe"] and bulk["precedence_bulk"])
        ),
        injection=bool(s["injection"]["attempt_detected"]),
        forwarded=bool(s["forwarding"]["is_forward"]),
        bec_language=bool(bec.get("matched")),
        claims_protected_domain=bool(align["claims_protected_domain"]),
        link_count=int(links["link_count"]),
        attachment_count=int(att["count"]),
        inline_images=int(s.get("inline_image_count") or 0),
        truncated=bool(s["truncated"]),
    )


def _host_list(links: dict) -> str:
    hosts = links["hosts_matching_neither"]
    return ", ".join(f"'{h}'" for h in hosts[:3])


# --------------------------------------------------------------------------
# the model cascade: which tiers run, and what their answers become
# --------------------------------------------------------------------------


def _settled_as_spam(facts: _Facts) -> bool:
    """The condition under which no model is consulted at all.

    Rule 3's own test, plus one addition: an injection signal. The rule does fire
    on legitimate bulk mail, but the injection overlay afterwards can replace the
    SPAM disposition with an escalation, and a message whose outcome the overlay
    may still change is not settled -- so the bulk fixture
    (``spam_bulk_marketing``) reaches its disposition with zero model calls, while
    a bulk-sending security newsletter that trips the injection scanner still gets
    the tiers, including the one tier that can tell a quoted instruction from a
    planted one.
    """
    return bool(
        facts.legitimate_bulk
        and facts.auth_passes
        and not (facts.lookalike or facts.anchor_mismatch
                 or facts.dangerous_external or facts.concealed_redirects)
        and not facts.injection
    )


def _settled_as_threat(facts: _Facts) -> bool:
    """A verified indicator that decides THREAT without any model help."""
    return bool(
        facts.lookalike
        or facts.anchor_mismatch
        or facts.dangerous_external
        or facts.concealed_redirects
    )


def _clearance_supported(facts: _Facts) -> bool:
    """Whether the deterministic layer may clear this message on its own.

    One definition, deliberately used both by the rule that issues the
    disposition and by the gate that decides whether to ask a model. They must
    not drift apart: if the rule clears on a weaker condition than the gate
    settles on, the pipeline emits a decisive CLEAN that no model was ever asked
    about, and ``ensemble.combine`` will then refuse to let any specialist reopen
    it. That is a self-reinforcing false negative, and an external red-team
    review found this pipeline had exactly one.

    Passing authentication establishes that *somebody controls the sending
    domain*. It does not establish that the message is benign. An attacker who
    registers ``attacker.test`` and publishes SPF and DKIM for it authenticates
    perfectly, and in a **reported**-phishing queue the prior points the other
    way: a human already looked at this message and thought it suspicious.

    So a clearance requires *positive* evidence of legitimacy -- the sender is
    this organization or is on the deployer's trust list -- and every destination
    the message contains must be accounted for by that same relationship. "Every
    destination" means every attribute that can carry one, not only the anchors:
    a form action, an iframe source, a meta refresh, a CSS ``url()`` and an
    inline event handler are all destinations, and a link analysis that reads
    only ``<a href>`` reports an empty list for a page whose entire payload is a
    credential form.

    Authentication the message contradicts itself about is not a basis for
    anything, so ``auth_conflicting`` blocks a clearance outright. Two headers
    disagreeing is either an ARC chain or a forgery and a raw file cannot say
    which.

    Truncated content blocks a clearance outright. Reporting that a message was
    cut is not the same as examining what was cut: an anchor placed beyond the
    body cap is never extracted, so "every destination is accounted for" would be
    true of a destination nobody looked at. A partial reading may still be
    *escalated* -- that is honest, and the receipt rules already refuse to let a
    truncated record claim completeness -- but it may not be cleared.

    An inline image blocks a clearance for the same reason in a different
    direction: pixels are content the deterministic layer provably cannot read,
    so clearing on the strength of everything it *could* read is clearing on
    partial evidence. The message becomes unsettled instead, the vision tier is
    asked, and if no vision tier is configured the honest outcome is a human --
    which also means the clearance veto above is reachable in the real pipeline
    rather than only in a unit test.

    What this does **not** do is make an unaccounted destination a threat
    indicator. Legitimate mail routinely links to unrelated services, and a
    destination mismatch becoming a verdict is the flaw in the reference playbook
    that ``docs/PARITY.md`` records. The mismatch simply stops being sufficient
    for an automatic clearance. Where the sender is not vouched for, the message
    becomes unsettled, the cascade asks the cheap specialist tiers and the
    adjudication model, and MANUAL_REVIEW is the outcome only if nothing
    corroborates a clearance.

    The BEC shape is excluded even though it can satisfy the same test, because
    there the *absence* of adverse indicators is the finding, and it is the one
    thing a model cannot resolve either -- it cannot know whether the sending
    account is compromised.
    """
    return bool(
        facts.auth_passes
        and not facts.auth_conflicting
        and not facts.adverse
        and not facts.legitimate_bulk
        and not facts.bec_shape
        and not facts.unaccounted_hosts
        and not facts.inline_images
        and not facts.truncated
        and (facts.claims_protected_domain or facts.trusted_sender)
    )


def _settled_deterministically(facts: _Facts) -> bool:
    return (
        _settled_as_spam(facts)
        or _settled_as_threat(facts)
        or _clearance_supported(facts)
    )


def _reputation_urls(s: dict) -> tuple[list[str], int]:
    """The destinations to ask a reputation engine about.

    Unwrapped destinations, not wrappers: querying the proxy's own domain is
    querying Microsoft. Returns ``(urls, distinct_destinations)``, so a caller can
    record that a cap bound the check rather than leaving the omission silent.
    """
    unwrapped = {
        str(e.get("href") or ""): str(e.get("resolved") or "")
        for e in (s["links"].get("unwrapped_redirects") or [])
    }
    seen: list[str] = []
    for detail in s.get("link_details") or []:
        href = str(detail.get("href") or "")
        url = unwrapped.get(href) or href
        host = str(detail.get("resolved_host") or "") or _host_of(url)
        if not host:
            continue
        if not url.lower().startswith(("http://", "https://", "//")):
            url = "https://" + url.lstrip("/")
        if url not in seen:
            seen.append(url)
    return seen[: tiers.MAX_URL_LOOKUPS_PER_MESSAGE], len(seen)


def tier_requests(
    msg: Message,
    s: dict,
    facts: _Facts,
    config: Config,
    *,
    record_pass: bool = False,
) -> list[tuple[tiers.Tier, dict]]:
    """Which tiers to consult for this message, in cascade order.

    **The deterministic path comes first for the ``spam`` class, and it comes
    first on purpose.** The order is: bulk-header signals (:func:`tenable_email.
    signals.detect_bulk_signals`), then the three-way classifier tier if one is
    configured, then the language model's three-way verdict. The reason is
    measured, and it is the whole cost argument of this project: the Enron-trained
    spam models other engines reach for carry out-of-domain false-positive rates
    of **0.959** and **0.880** (``docs/MODELS.md``) -- they flag nearly every
    normal message as unwanted -- while ``List-Unsubscribe`` carrying the RFC 8058
    one-click value, or ``List-Unsubscribe`` together with ``Precedence: bulk``, is
    a header a marketing platform adds because a bulk sender without a working
    one-click opt-out gets blocked. In a *user-reported* queue most of the spam
    class is legitimate marketing somebody over-reported, so a near-zero-FP
    deterministic signal resolves the dominant case at zero tokens and zero
    milliseconds and no model is consulted at all. A model is asked only when the
    headers do not settle it.

    The same logic puts the cheap tiers ahead of the expensive ones and keeps the
    language model for the band the facts left open, which is what the stage
    contract says ``adjudication`` is for.

    ``record_pass`` widens it: the recording pass asks every tier for every
    fixture, including the language model on messages the cascade would settle
    without it. The store has to be a superset of what the cascade can ask for, or
    a replay run misses for a reason that has nothing to do with the message.
    """
    requests: list[tuple[tiers.Tier, dict]] = []
    if _settled_as_spam(facts) and not record_pass:
        return requests

    body = msg.body or ""
    text_request = {"text": body}
    requests.append((tiers.FraudFoxTier(), text_request))

    urls, _total = _reputation_urls(s)
    requests.extend((tiers.UrlReputationTier(), {"url": url}) for url in urls)

    requests.append((tiers.PromptInjectionTier(), text_request))
    requests.append((tiers.InjectionClassifierTier(), text_request))
    requests.append((tiers.SpamThreeWayTier(), text_request))

    if facts.inline_images:
        for image in msg.inline_images[: tiers.MAX_IMAGES_PER_MESSAGE]:
            requests.append((
                tiers.VlmTier(),
                {
                    "data": image.data,
                    "content_type": image.content_type,
                    "filename": image.filename,
                },
            ))

    if not _settled_deterministically(facts) or record_pass:
        requests.append((
            tiers.LlmTier(),
            {"prompt": build_classification_prompt(s, body, config)},
        ))
    return requests


def consult_tiers(
    msg: Message,
    s: dict,
    ev: Evidence,
    config: Config,
    store: ReplayStore | None,
    facts: _Facts,
) -> tuple[list[tiers.TierResult], list[tiers.Judgment], list[str]]:
    """Run the cascade, append every outcome to the evidence, return the votes.

    A tier that did not run is recorded, in the same voice the deterministic layer
    uses: ``UNAVAILABLE`` with the reason the tier gave. A tier that ran
    contributes one ``MODEL_JUDGMENT`` finding carrying its normalized answer and
    the raw scores it returned -- never ``VERIFIED``, because an opinion is not a
    fact no matter how confident the opinion is.
    """
    results: list[tiers.TierResult] = []
    judgments: list[tiers.Judgment] = []
    stages: list[str] = []
    _urls, total_links = _reputation_urls(s)
    if total_links > tiers.MAX_URL_LOOKUPS_PER_MESSAGE:
        ev.unknown(
            "url_reputation_incomplete",
            _TIER_STAGE["url_reputation"],
            f"{total_links} distinct link destinations were found and only the "
            f"first {tiers.MAX_URL_LOOKUPS_PER_MESSAGE} were sent to the "
            "reputation tier; the rest are unchecked, not clean",
        )
    if len(msg.inline_images) > tiers.MAX_IMAGES_PER_MESSAGE:
        ev.unknown(
            "vision_incomplete",
            _TIER_STAGE["vision"],
            f"{len(msg.inline_images)} inline images were present and only the "
            f"first {tiers.MAX_IMAGES_PER_MESSAGE} were sent to the vision tier",
        )

    for tier, request in tier_requests(msg, s, facts, config):
        result = tiers.consult(tier, request, config, store)
        stage = _TIER_STAGE[tier.name]
        if result.source not in tiers.OBSERVED_SOURCES:
            # An answer that no live call and no attested recording produced. It
            # is still shown to the adjudication layer -- hiding it would lose the
            # fabrication from the record -- but the evidence is marked simulated
            # and the receipt contract will refuse to close on it.
            ev.mark_simulated(
                stage,
                f"the {tier.name} tier answered from {result.source}: this "
                "response was not produced by a live call and the replay store "
                "does not attest to it, so it is authored content presented as "
                "evidence",
            )
        if not result.available:
            # Already recorded as a configuration gap by build_evidence. Not a
            # finding about the message, so it is not added to the vote either.
            continue
        results.append(result)
        stages.append(stage)
        if result.ok:
            try:
                judgment = tiers.read_judgment(result, config)
            except tiers.TierResponseError as exc:
                ev.unavailable(tier.name, stage, f"response unreadable: {exc}")
                continue
            ev.judgment(
                tier.name,
                judgment.as_dict(),
                stage,
                _judgment_detail(result, judgment),
            )
            judgments.append(judgment)
        else:
            ev.unavailable(tier.name, stage, result.error or "tier did not answer")
    return results, judgments, list(dict.fromkeys(stages))


def _judgment_detail(result: tiers.TierResult, judgment: tiers.Judgment) -> str:
    """Provenance prose that says *how* the opinion arrived.

    ``source=replay`` is stated because a recorded answer is a real model answer
    from the moment it was recorded -- not a simulation -- but it is also not a
    fresh reading of today's message, and the difference matters to whoever closes
    the case.
    """
    bits = [f"source={result.source}", f"tier={result.tier}"]
    if result.model:
        bits.append(f"model={result.model}")
    if result.latency_ms is not None:
        bits.append(f"{result.latency_ms:.1f} ms")
    if result.tokens:
        total = result.tokens.get("total_tokens")
        if total is not None:
            bits.append(f"{total} tokens")
    if judgment.detail:
        bits.append(judgment.detail)
    return (
        " ".join(str(b) for b in bits)
        + "; a model opinion, not a verified fact"
    )


def _dangerous_attachment_line(att: dict) -> str:
    for item in att.get("items") or []:
        if item.get("dangerous_and_external"):
            ext = item["extension"] or "no extension"
            return (
                f"attachment '{item['filename']}' ({ext}, {item['size']} bytes) "
                f"is a high-risk type from a sender outside a protected domain"
            )
    return "a high-risk attachment arrived from a sender outside a protected domain"


def _auth_clause(auth: dict) -> str:
    return f"spf={auth['spf']}, dkim={auth['dkim']}, dmarc={auth['dmarc']}"


def _deterministic_view(
    disposition: Disposition,
    confidence: float,
    attack_type: AttackType,
    reasons: list[str],
    cited: list[Finding],
    facts: _Facts,
) -> ensemble.Deterministic:
    """What the rules concluded, and how firmly the evidence supports it.

    ``decisive`` is computed from the provenance of the findings actually cited,
    not from which branch fired: if every finding a disposition rests on is
    VERIFIED, then a model opinion cannot displace it. That is the same invariant
    :meth:`Evidence.assert_citable` guards, pointed at a different question --
    not "may this be cited" but "may an opinion outrank it".
    """
    verified = bool(cited) and all(
        f.provenance is Provenance.VERIFIED for f in cited
    )
    return ensemble.Deterministic(
        disposition=disposition,
        confidence=confidence,
        attack_type=attack_type,
        decisive=bool(
            verified
            and disposition
            in (Disposition.THREAT, Disposition.SPAM, Disposition.CLEAN)
        ),
        clear_blocked=(
            _settled_as_threat(facts)
            or facts.bec_shape
            # Everything below is *absence of evidence*, which is categorically
            # different from a judgment a model may inform. A truncated body, an
            # inline image nobody read, an attachment whose contents were not
            # extracted and authentication the message contradicts itself about
            # are all things that were not examined, and no amount of model
            # confidence can examine them retrospectively -- the same reasoning
            # that puts the BEC shape in this set, since "is this account
            # compromised?" is recorded as an UNKNOWN.
            #
            # This was missing, and its absence made two docstrings in
            # _clearance_supported false: they said truncated content "may not be
            # cleared" and that an inline image blocks a clearance, but the
            # deterministic layer only refuses to clear on its own authority. A
            # unanimous model CLEAN vote arriving through the ensemble's open band
            # could clear exactly those messages, which is the second path to a
            # disposition and the one the prose did not account for.
            #
            # Deliberately NOT here: unaccounted destinations and a sender nobody
            # vouches for. Whether an unrelated link is benign is a judgment about
            # content that was read, so a model's opinion is relevant to it.
            or facts.truncated
            or facts.auth_conflicting
            or facts.dangerous_unexamined
            or bool(facts.inline_images)
        ),
        reasons=tuple(reasons),
        cited=tuple(f.key for f in cited),
    )


def _adjudicate(
    msg: Message,
    s: dict,
    ev: Evidence,
    config: Config,
    judgments: Sequence[tiers.Judgment] = (),
    tier_stages: Sequence[str] = (),
) -> Verdict:
    facts = derive_facts(s, ev)
    auth = s["auth"]
    align = s["alignment"]
    links = s["links"]
    att = s["attachments"]
    bulk = s["bulk"]
    inj = s["injection"]
    bec = _fact(ev, "bec_language") or {}
    sender_domain = s["sender"]["domain"]

    cited: list[Finding] = []

    def cite(key: str) -> None:
        f = _recorded(ev, key)
        if f is not None and f not in cited:
            cited.append(f)

    # -- nothing analysable ---------------------------------------------------
    if not s["sender"]["address"] and not (msg.body or "").strip() and not msg.subject:
        cite("intake")
        cite("auth")
        return _finish(
            msg, s, ev, config, Disposition.UNKNOWN, 0.0, AttackType.NONE,
            [
                "The message could not be parsed into anything analysable: no "
                "sender address, no subject and no body text. Disposition "
                "UNKNOWN rather than clean, because absence of evidence is not "
                "evidence of absence."
            ],
            cited, facts,
        )

    disposition = Disposition.UNKNOWN
    confidence = 0.0
    attack_type = AttackType.UNCLASSIFIED
    reasons: list[str] = []

    # -- rule 1: the strongest deterministic indicators -----------------------
    if facts.lookalike or facts.anchor_mismatch or facts.dangerous_external:
        disposition = Disposition.THREAT
        confidence = 0.95
        if facts.dangerous_external:
            attack_type = AttackType.MALWARE
            reasons.append(_dangerous_attachment_line(att) + ".")
            cite("attachments")
        elif facts.lookalike or facts.anchor_mismatch:
            attack_type = AttackType.CREDENTIAL_HARVEST
        if facts.lookalike:
            reasons.append(
                f"Sender domain '{sender_domain}' impersonates a protected or "
                f"vendor domain: {s['lookalike']['detail']}."
            )
            cite("lookalike")
        if facts.anchor_mismatch:
            for mismatch in links["anchor_mismatches"][:3]:
                reasons.append(
                    f"Link text advertises '{mismatch['hint']}' but resolves to "
                    f"'{mismatch['actual']}': the visible anchor and the real "
                    f"destination disagree."
                )
            cite("links")

    # -- rule 1b: a redirect wrapper hiding a destination that is nobody's ----
    elif facts.concealed_redirects:
        disposition = Disposition.THREAT
        confidence = 0.85
        attack_type = AttackType.CREDENTIAL_HARVEST
        hidden = "; ".join(
            f"'{entry['resolved_host']}' behind the "
            f"'{entry['wrapper']}' rewriting proxy (link text: "
            f"'{(entry.get('href') or '')[:80]}')"
            for entry in facts.concealed_redirects[:3]
        )
        reasons.append(
            f"A link is wrapped in a URL-rewriting proxy and the destination it "
            f"hides belongs to neither the sender's domain '{sender_domain}' nor "
            f"any trusted domain: {hidden}. The wrapper is the finding, not the "
            f"mismatch: legitimate mail links to unrelated services routinely, "
            f"which is why a bare host mismatch is never decisive here, but a "
            f"proxy that makes a reader judge Microsoft's domain instead of the "
            f"real one has no purpose except to conceal where the link goes. "
            f"Unwrapping and percent-decoding are deterministic, so this "
            f"destination is a verified fact, not a model's reading."
        )
        cite("links")

    # -- rule 2: authentication failure plus an adverse indicator ------------
    elif facts.auth_failure and (
        facts.reply_mismatch or facts.spoofed or facts.unaccounted_hosts
    ):
        disposition = Disposition.THREAT
        confidence = 0.85
        attack_type = AttackType.UNCLASSIFIED
        cite("auth")
        drivers = []
        if facts.reply_mismatch:
            drivers.append(
                f"Reply-To is '{s['reply_to_mismatch']['reply_to_domain']}', a "
                f"different domain from the sender's '{sender_domain}'"
            )
            cite("reply_to_mismatch")
        if facts.spoofed:
            drivers.append(
                f"the display name claims "
                f"'{s['display_name_spoofing']['claimed_identity']}' from a "
                f"domain that does not own it"
            )
            cite("display_name_spoofing")
        if facts.unaccounted_hosts:
            drivers.append(
                f"link(s) lead to {_host_list(links)}, matching neither the "
                f"sender's domain nor a trusted domain"
            )
            cite("links")
        reasons.append(
            f"Authentication failed at the receiving MTA ({_auth_clause(auth)}) "
            f"and {'; '.join(drivers)}."
        )
        if align["spf_domain"] or align["dkim_domain"]:
            reasons.append(
                f"Envelope MAILFROM '{align['spf_domain'] or 'not recorded'}' and "
                f"DKIM domain '{align['dkim_domain'] or 'not recorded'}' produce "
                f"no DMARC pass for the claimed sender domain '{sender_domain}'."
            )

    # -- rule 3: legitimate bulk mail -----------------------------------------
    elif facts.legitimate_bulk and facts.auth_passes and not (
        facts.lookalike or facts.anchor_mismatch or facts.dangerous_external
    ):
        disposition = Disposition.SPAM
        confidence = 0.8
        attack_type = AttackType.SPAM
        markers = []
        if bulk["rfc8058_one_click"]:
            markers.append("an RFC 8058 one-click unsubscribe")
        elif bulk["has_list_unsubscribe"]:
            markers.append("a List-Unsubscribe header")
        if bulk["precedence"]:
            markers.append(f"Precedence: {bulk['precedence']}")
        if bulk["auto_submitted"]:
            markers.append(f"Auto-Submitted: {bulk['auto_submitted']}")
        reasons.append(
            f"Carries {', '.join(markers)} and authenticates "
            f"({_auth_clause(auth)}), with no lookalike domain, no anchor "
            f"mismatch and no high-risk attachment. Unsolicited commercial mail "
            f"is spam, not a threat."
        )
        cite("bulk")
        cite("auth")

    # -- rule 4: the BEC shape, checked before anything may be cleared --------
    elif facts.bec_shape:
        disposition = Disposition.MANUAL_REVIEW
        confidence = 0.5
        attack_type = AttackType.BEC
        drivers = []
        if facts.reply_mismatch:
            drivers.append(
                f"Reply-To points to '{s['reply_to_mismatch']['reply_to_domain']}', "
                f"outside the sender's domain '{sender_domain}'"
            )
            cite("reply_to_mismatch")
        if bec.get("matched"):
            drivers.append(
                "the text contains payment, urgency or concealment phrasing ("
                + ", ".join(repr(m) for m in bec["matched"][:5]) + ")"
            )
            cite("bec_language")
        reasons.append(
            f"Authentication passes ({_auth_clause(auth)}) and there is no link "
            f"to analyse, but that does not establish legitimacy: "
            f"{'; '.join(drivers)}. This is the business-email-compromise shape "
            f"-- mail from an account that authenticates correctly, where the "
            f"request itself is the only evidence. Passing authentication is "
            f"equally consistent with a compromised legitimate account, so this "
            f"is routed to a person rather than cleared."
        )
        cite("alignment")

    # -- rule 5: everything checked out ---------------------------------------
    #
    # Passing authentication establishes that somebody controls the sending
    # domain. It does not establish that the message is benign, and in a
    # *reported*-phishing queue the prior is the opposite: a human already looked
    # at this message and thought it suspicious. An attacker who registers
    # attacker.test, publishes SPF and DKIM for it and sends a correctly
    # authenticated credential-harvesting mail satisfies "auth passes and nothing
    # looks bad" completely. Treating the absence of indicators as proof of
    # legitimacy is the single most dangerous thing this pipeline could do, and
    # it is what an external red-team review found it doing.
    #
    # So a clearance now requires *positive* evidence: the sender is the
    # organization or is on the deployer's trust list, and every destination in
    # the message is accounted for by that same relationship. Note what this does
    # NOT do -- an unaccounted destination is still not treated as a threat
    # indicator, because legitimate mail routinely links to unrelated services
    # and the reference playbook's "destination mismatch means threat" is still
    # the flaw docs/PARITY.md records. It simply stops being sufficient for an
    # automatic clearance.
    elif _clearance_supported(facts):
        disposition = Disposition.CLEAN
        confidence = 0.9
        attack_type = AttackType.NONE
        reasons.append(
            f"Authentication passed at the receiving MTA ({_auth_clause(auth)}), "
            f"the sending domain is {'this organization' if facts.claims_protected_domain else 'on the configured trust list'}, "
            f"every destination in the message is accounted for by that "
            f"relationship, and no adverse indicator was found: no lookalike "
            f"domain, no link whose anchor text disagrees with its destination, "
            f"no redirect wrapper hiding a destination that belongs to nobody, no "
            f"display name claiming an identity the sending domain does not own, "
            f"no Reply-To divergence, no high-risk attachment from an external "
            f"sender and no link to an IP literal or a non-http scheme."
        )
        cite("auth")
        cite("alignment")
        cite("links")
        cite("attachments")

    # -- rule 6: anything else -------------------------------------------------
    else:
        disposition = Disposition.MANUAL_REVIEW
        confidence = 0.5
        attack_type = AttackType.UNCLASSIFIED
        open_items = []
        if facts.auth_failure:
            open_items.append(
                f"authentication failed ({_auth_clause(auth)}) but no "
                f"corroborating indicator completes a known threat pattern"
            )
            cite("auth")
        elif not facts.auth_passes:
            open_items.append(
                f"authentication is inconclusive ({_auth_clause(auth)})"
            )
            cite("auth")
        elif facts.legitimate_bulk:
            open_items.append(
                "bulk-mail headers are present but authentication does not "
                "confirm a legitimate sender"
            )
            cite("bulk")
        else:
            open_items.append(
                "authentication passes, yet the message is neither bulk mail nor "
                "from a domain this organization owns or explicitly trusts. "
                "Passing authentication proves only that somebody controls the "
                "sending domain, which is equally true of an attacker who "
                "registered it, so on its own it is not a reason to clear a "
                "message a human already reported"
            )
            cite("auth")
        if facts.spoofed:
            open_items.append(
                f"the display name claims "
                f"'{s['display_name_spoofing']['claimed_identity']}' from a "
                f"foreign domain"
            )
            cite("display_name_spoofing")
        if facts.unaccounted_hosts:
            open_items.append(
                f"link(s) to {_host_list(links)} match neither the sender's "
                f"domain nor a trusted domain"
            )
            cite("links")
        if facts.ip_literal_hosts or facts.javascript_uris:
            open_items.append(
                "a link uses an IP literal or a non-http scheme"
            )
            cite("links")
        if facts.reply_mismatch:
            open_items.append(
                f"Reply-To points to '{s['reply_to_mismatch']['reply_to_domain']}'"
            )
            cite("reply_to_mismatch")
        if facts.attachment_count:
            open_items.append(
                f"{facts.attachment_count} attachment(s) whose contents were not read"
            )
            cite("attachments")
        reasons.append(
            "No deterministic rule settles this message: "
            + ", ".join(open_items)
            + ". Escalating is the correct outcome for the ambiguous band; the "
            "classifier, vision and language-model tiers would each be consulted "
            "before a person were asked."
        )

    # -- overlay: prompt injection as a reported threat class -----------------
    injection_analysis_line = ""
    if facts.injection:
        hits = int(inj["hit_count"])
        # The hit count is recorded as a finding in its own right, so the
        # reported threat class is backed by an enumerable fact rather than by
        # prose in a reason list. Append-only: it adds, it does not rewrite the
        # scanner's own finding.
        ev.verified(
            "injection_indicator_count",
            hits,
            STAGE_SIGNALS,
            "number of deterministic prompt-injection pattern matches in the body",
        )
        corroborated_by = []
        if facts.lookalike:
            corroborated_by.append("a lookalike of a protected or vendor domain")
        if facts.auth_failure:
            corroborated_by.append(f"failed authentication ({_auth_clause(auth)})")
        if facts.anchor_mismatch:
            corroborated_by.append(
                f"{links['anchor_mismatch_count']} anchor-versus-href mismatch(es)"
            )
        if facts.reply_mismatch:
            corroborated_by.append(
                f"a Reply-To pointing to "
                f"'{s['reply_to_mismatch']['reply_to_domain']}'"
            )
        if facts.dangerous_external:
            corroborated_by.append(
                "a high-risk attachment from an external sender"
            )
        cite("injection")
        cite("injection_indicator_count")
        # An agent-manipulation attempt is a reported class in its own right, so
        # it is claimed whenever the scanner fires -- unless the message already
        # carries a stronger, human-directed attack class. "stronger" means
        # malware, credential harvesting or compromise: SPAM and UNCLASSIFIED do
        # not outrank it.
        if attack_type not in _MALICE_ATTACK_TYPES:
            attack_type = AttackType.AGENT_MANIPULATION

        if corroborated_by:
            disposition = Disposition.THREAT
            confidence = max(confidence, 0.9)
            reasons.append(
                f"The body carries {hits} deterministic prompt-injection "
                f"indicator(s): text addressed to an automated analyst rather "
                f"than to the human reader, such as an instruction to reclassify "
                f"the message or to suppress a flag. That targets the "
                f"recipient's mail-reading agent and is reported as a threat "
                f"class in its own right. Here it is corroborated by "
                f"{', '.join(corroborated_by)}."
            )
            injection_analysis_line = (
                "The message also attempts to manipulate whatever agent reads "
                "it, which is reported as a threat class rather than only "
                "resisted."
            )
        else:
            disposition = Disposition.MANUAL_REVIEW
            confidence = min(confidence, 0.4)
            reasons.append(
                f"The message contains {hits} deterministic prompt-injection "
                f"indicator(s) but nothing else corroborates malicious intent: "
                f"authentication passes, the sender domain is not a lookalike, "
                f"no link's anchor text disagrees with its destination, Reply-To "
                f"matches the sender and no high-risk attachment is present. A "
                f"security newsletter that quotes these phrases while discussing "
                f"them looks identical to a real attempt, because a regex cannot "
                f"tell 'contains an instruction aimed at an agent' from 'quotes "
                f"an instruction while discussing it'. Confidence is capped and "
                f"the message is escalated instead of dispositioned as a threat."
            )
            injection_analysis_line = (
                "The injection indicators are reported but are uncorroborated, "
                "so they cap the confidence and force a human decision instead of "
                "producing a threat verdict from a pattern match alone."
            )

    # -- ensemble: opinions vote in the band the facts left open --------------
    outcome: ensemble.EnsembleOutcome | None = None
    if judgments:
        outcome = ensemble.combine(
            _deterministic_view(
                disposition, confidence, attack_type, reasons, cited, facts
            ),
            judgments,
            config,
        )
        disposition = outcome.disposition
        confidence = outcome.confidence
        attack_type = outcome.attack_type
        reasons = list(outcome.reasons)
        # The per-tier votes are prose an analyst reads, and until now they were
        # written and never surfaced: ``outcome.reasons`` carries the ensemble's
        # narrative about what it *decided*, not what each tier *said*. An
        # abstention in particular reached neither, so a tier that ran and could
        # not answer was invisible in the verdict even though its structured
        # finding was in the evidence record. Deduplicated, because the ensemble
        # narrative already quotes the votes it acted on or refused.
        reasons.extend(r for r in outcome.model_reasons if r not in reasons)
        for judgment in judgments:
            cite(judgment.tier)

    # -- overlay: a partial reading is never a complete one -------------------
    if facts.truncated:
        original = s.get("original_body_length") or s["body_chars"]
        reasons.insert(
            0,
            f"The body was truncated for analysis: {s['body_chars']} characters "
            f"were retained of {original}. This is a partial reading and must "
            f"not be reported as a complete one.",
        )
        cite("truncated")

    return _finish(
        msg, s, ev, config, disposition, confidence, attack_type, reasons, cited,
        facts, injection_analysis_line, tier_stages=tier_stages, outcome=outcome,
    )


def _identity(msg: Message, s: dict) -> tuple[str, str, str]:
    """Return ``(sender, reported_by, note)``.

    For a forwarded report the outer From is the person who reported the message
    and the inner From is the message actually being triaged. Reporting the
    reporting user as the sender would put an innocent colleague in the subject
    line of a threat verdict.
    """
    outer = s["sender"]["address"] or s["sender"]["raw"]
    if not s["forwarding"]["is_forward"]:
        return outer, "", ""
    inner_from = s["forwarding"]["inner_from"]
    inner = parse_address(inner_from) if inner_from else None
    sender = inner.address if inner is not None and inner.has_address else outer
    note = ""
    if inner is not None and inner.has_address and inner.address != outer:
        note = (
            f"The reported message is a forward: the outer From '{outer}' is the "
            f"reporting user and the inner sender being triaged is "
            f"'{inner.address}'. Authentication results were recorded for the "
            f"outer envelope only and say nothing about the inner sender's "
            f"infrastructure."
        )
    return sender, outer, note


def _finish(
    msg: Message,
    s: dict,
    ev: Evidence,
    config: Config,
    disposition: Disposition,
    confidence: float,
    attack_type: AttackType,
    reasons: list[str],
    cited: list[Finding],
    facts: _Facts,
    injection_analysis_line: str = "",
    tier_stages: Sequence[str] = (),
    outcome: ensemble.EnsembleOutcome | None = None,
) -> Verdict:
    sender, reported_by, forward_note = _identity(msg, s)
    if forward_note:
        reasons.append(forward_note)
        f = _recorded(ev, "forwarding")
        if f is not None and f not in cited:
            cited.append(f)

    case_id = ""
    if msg.source and msg.source != "inline":
        case_id = Path(msg.source).stem
    elif s.get("message_id"):
        case_id = str(s["message_id"]).strip().strip("<>")

    verdict = Verdict(
        id=case_id,
        subject=s["subject"],
        sender=sender,
        reported_by=reported_by,
        disposition=disposition,
        attack_type=attack_type,
        reasons=reasons,
        evidence=ev,
        truncated=facts.truncated,
        escalated=disposition in (Disposition.MANUAL_REVIEW, Disposition.UNKNOWN),
        stages_run=_stages_that_ran(tier_stages),
    )
    verdict.set_confidence(confidence, config.thresholds)
    verdict.cite(cited)

    # The enforcement point for "an unknown never becomes a fact". If a rule
    # ever cites a gap, this raises instead of quietly returning a verdict.
    ev.assert_citable(cited)

    verdict.analysis = _narrative(
        verdict, s, facts, injection_analysis_line, outcome
    )
    return verdict


def _stages_that_ran(tier_stages: Sequence[str]) -> list[str]:
    """Contract-ordered stage ids that actually contributed to this verdict.

    A stage is listed because it ran, not because it is configured somewhere: the
    classifier stage appears when a classifier tier answered or failed, and never
    when the deterministic layer settled the message first -- which is the
    measurement this project's pitch rests on, the fraction of a reported queue
    dispositioned without a model call at all.
    """
    ran = set(DETERMINISTIC_STAGES_RUN) | set(tier_stages)
    return [stage for stage in ALL_STAGES_IN_ORDER if stage in ran]


def _narrative(
    verdict: Verdict,
    s: dict,
    facts: _Facts,
    injection_analysis_line: str = "",
    outcome: ensemble.EnsembleOutcome | None = None,
) -> str:
    unavailable = [
        f
        for f in verdict.evidence.by_provenance(Provenance.UNAVAILABLE)
        if f.key != attachments.FINDING_KEY
    ]
    # The optional attachment analyzer records its own gaps, and it is not a model
    # tier: counting it among "model tier(s) had no configured endpoint" would be
    # a false sentence about the configuration, so tier gaps are counted by key.
    analyzer_gaps = [
        f
        for f in verdict.evidence.by_provenance(Provenance.UNAVAILABLE)
        if f.key == attachments.FINDING_KEY
    ]
    unknowns = verdict.evidence.by_provenance(Provenance.UNKNOWN)
    judgments = verdict.evidence.by_provenance(Provenance.MODEL_JUDGMENT)
    gaps = verdict.evidence.gaps()

    if judgments:
        tiers_named = sorted({f.key for f in judgments})
        opening = (
            f"{len(judgments)} model judgment(s) from tier(s) "
            f"{', '.join(tiers_named)} were consulted and combined with the "
            f"deterministic findings; each is recorded with MODEL_JUDGMENT "
            f"provenance and none of them is a verified fact. "
            f"{len(unavailable)} tier(s) did not run and are recorded as "
            f"unavailable rather than as findings of absence."
        )
    else:
        opening = (
            f"Deterministic triage only: {len(unavailable)} model tier(s) had no "
            f"configured endpoint and did not run, so their findings are recorded "
            f"as unavailable rather than absent, and no language model was "
            f"called. This disposition rests solely on facts observed in the "
            f"message."
        )

    parts = [
        opening,
        (
            "The decisive evidence: "
            + (verdict.reasons[0] if verdict.reasons else "none recorded.")
        ),
        (
            f"Disposition {verdict.disposition.value.upper()} with attack class "
            f"{verdict.attack_type.value} at confidence "
            f"{verdict.confidence:.2f} ({verdict.confidence_band.value})."
        ),
    ]
    if outcome is not None and outcome.changed_deterministic:
        parts.append(
            "The ensemble changed this disposition from what the deterministic "
            "layer alone concluded. Each tier's vote and its confidence is in the "
            "record as a MODEL_JUDGMENT finding, so the change is auditable rather "
            "than a number with no source; a verified finding, by contrast, was "
            "never available to it -- a model can escalate a verified threat and "
            "cannot talk one down."
        )
    if outcome is not None and outcome.disagreement:
        parts.append(
            "The consulted tiers did not agree with each other, or were not "
            "confident enough to be acted on, so this is routed to a person "
            "instead of averaged into a number that would imply a precision "
            "neither a fact nor an opinion has."
        )
    if verdict.escalated:
        parts.append(
            "This message is escalated: the deterministic layer cannot settle it, "
            "and a low-confidence verdict is not an action."
        )
    if injection_analysis_line:
        parts.append(injection_analysis_line)
    if facts.forwarded:
        parts.append(
            "Because this is a forwarded report, the authenticated sender is the "
            "user who reported the message, not the author of the inner one."
        )
    if unknowns:
        parts.append(
            f"{len(unknowns)} item(s) are recorded as not knowable from the "
            f"message ({', '.join(f.key for f in unknowns)}); they stay unknown "
            f"and none of them supports this disposition."
        )
    if analyzer_gaps:
        reasons = sorted({f.detail.split(": ", 1)[0] for f in analyzer_gaps})
        parts.append(
            f"The optional document extractor was asked about "
            f"{len(analyzer_gaps)} attachment part(s) and did not answer "
            f"({', '.join(reasons)}); its absence is recorded as a gap in the "
            f"record, not as a finding about the message, and it supports nothing."
        )
    parts.append(
        f"{len(verdict.cited_findings)} finding(s) support the disposition; each "
        f"was checked against the provenance invariant before it was issued, and "
        f"{len(gaps)} gap finding(s) remain in the record."
    )
    if verdict.truncated:
        original = s.get("original_body_length") or s["body_chars"]
        parts.append(
            f"WARNING: this analysis is PARTIAL. The body was cut to "
            f"{s['body_chars']} characters of {original}, so content that was not "
            f"read cannot have been considered, and this record must not be "
            f"reported as a complete reading of the message."
        )
    return " ".join(parts)


# --------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------


def triage_message(
    msg: Message, config: Config | None = None, *, store: ReplayStore | None = None
) -> Verdict:
    """Run the full chain over one parsed message and disposition it.

    With no endpoints configured this is the deterministic chain and nothing
    else: every tier reports itself unavailable. With ``config.replay`` true the
    tiers are answered from the recordings in ``config.replay_dir``, with no
    network at all, and a missing recording is a miss rather than a call.
    """
    config = config or Config()
    signals = extract_signals(msg, config.profile, config.thresholds)
    store = open_store(config) if store is None else store
    evidence = build_evidence(msg, signals, config, store=store)
    facts = derive_facts(signals, evidence)
    _results, judgments, tier_stages = consult_tiers(
        msg, signals, evidence, config, store, facts
    )
    if _attachment_stage_attempted(evidence):
        # The optional stage ran, so the record lists it as run rather than
        # skipping it with a reason that no longer applies. This is the only
        # effect the component can have on a verdict -- one entry in a field that
        # says which stages contributed -- and it changes no disposition: no fact
        # the rules consume is derived from an attachment finding.
        tier_stages = [*tier_stages, STAGE_ATTACHMENTS]
    return _adjudicate(
        msg, signals, evidence, config,
        judgments=judgments, tier_stages=tier_stages,
    )


def triage_file(path: Any, config: Config | None = None) -> Verdict:
    """Parse one ``.eml`` file and triage it. The path a reviewer runs."""
    config = config or Config()
    msg = parse_file(path, body_char_limit=config.thresholds.body_char_limit)
    return triage_message(msg, config)


def triage_bytes(
    raw: bytes | str, config: Config | None = None, *, source: str = "inline"
) -> Verdict:
    """Triage a single RFC 822 message supplied as bytes or text."""
    config = config or Config()
    msg = parse_message(
        raw, source=source, body_char_limit=config.thresholds.body_char_limit
    )
    return triage_message(msg, config)