"""The write side of the chain: proposed actions, approvals, providers.

``stages.yaml`` declares exactly one stage with ``access: write``
(``disposition-writeback``), and :func:`tenable_email.contract.validate_contract`
refuses a contract whose write stage does not carry ``approval_required: true``
and approval language. That makes the *declaration* of the gate machine-checked.
This module is the gate itself: the action a verdict would take outward, the
human instrument that authorizes it, and the provider interface that either
performs it or records that it was not performed.

Four rules, and the first one is the reason the module exists.

1. **Nothing is executed without a matching approval.** An approval binds an
   approver to one verdict digest, one set of messages and one set of action
   kinds, and it is single-use. An action whose digest does not match, whose
   token is already spent, or which was never approved is refused -- by
   :class:`~tenable_email.runner.OfflineRunner`, transactionally, before any
   provider is called.
2. **Each mutation is approved separately.** Not "approve the batch of stages":
   ``Approval.actions`` is a list of action kinds, and applying a kind that is
   not on it is a refusal. The first-place SWARM playbook opens a ticket, notifies
   the SOC and launches a rescan as four separate approvals, and a mail label is
   a different act from an analyst notification.
3. **The default provider does nothing.** :class:`DryRunProvider` is the only
   provider this bundle ships, it records what *would* have happened and changes
   nothing, and it is selected by default. A reviewer running the shipped path
   therefore mutates no external system, holds no credential, and can still see
   the exact action the chain intended.
4. **No real write destination is invented here.** The reference playbook posts a
   tag and a comment back to PhishER. Our feed is Google Alert Center, which has
   no comment API, so the outward destination is an open operator decision
   (``NOTES.md``, open decision 2) and is *not* resolved by this module. The
   action kinds below are the capabilities a destination would have to provide;
   a provider that actually performs them is configuration, and there is nothing
   here to configure yet. ``post_comment`` is in the vocabulary for parity with
   the reference and is deliberately never generated, because no comment target
   exists to receive one.

Serialization note: an action carries a *summary* and a rationale, never a
message body or attachment bytes, because :class:`~tenable_email.receipt.Receipt`
embeds these records and a receipt is written to disk for a reviewer to read.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from .replay import canonical_json
from .verdict import Disposition, Verdict

__all__ = [
    "ACTION_KINDS",
    "DEFAULT_PROVIDER",
    "PROVIDER_ENV",
    "Approval",
    "DryRunProvider",
    "ProviderResult",
    "ProposedAction",
    "WritebackError",
    "WritebackProvider",
    "approval_language",
    "issue_approval",
    "provider_names",
    "summarize_actions",
    "label_for",
    "proposed_actions",
    "provider_for",
    "token_for",
]

#: The environment variable that selects a writeback provider. It selects a
#: *name*, never a credential: there is no credential to select and this module
#: reads no key, token or path from anywhere else.
PROVIDER_ENV = "TENABLE_EMAIL_WRITEBACK_PROVIDER"

#: The default, and the only provider implemented in this bundle.
DEFAULT_PROVIDER = "dry-run"

#: The mutations a disposition could want to make, named as capabilities rather
#: than as products, so a different mail system can provide them.
ACTION_KINDS: tuple[str, ...] = (
    "record_case",
    "apply_label",
    "notify_analyst",
    "post_comment",
)

#: Reference-parity note. ``post_comment`` is declared above because the
#: reference playbook posts an analysis comment, and a reviewer comparing the two
#: should be able to see that we know the difference. It is *not* produced by
#: :func:`proposed_actions`: the feed this project reads has no comment endpoint,
#: and proposing an action that no destination can receive would be a fiction.
GENERATED_ACTION_KINDS: tuple[str, ...] = (
    "record_case",
    "apply_label",
    "notify_analyst",
)

#: Label vocabulary a mail system would receive. Namespaced and neutral: no
#: employer taxonomy is encoded here, and the reference's three verdicts are the
#: reference's, not a customer's.
_LABELS: dict[Disposition, str] = {
    Disposition.THREAT: "triage/threat",
    Disposition.SPAM: "triage/spam",
    Disposition.CLEAN: "triage/clean",
    Disposition.MANUAL_REVIEW: "triage/needs-review",
    Disposition.UNKNOWN: "triage/unreadable",
}


class WritebackError(RuntimeError):
    """Raised for a programming error in the write path, never for a refusal.

    A missing approval, a spent token or a widened target set is a *refusal*,
    returned as a value by the runner. This type is for being asked to do
    something that cannot be done at all -- naming a provider that does not
    exist, say -- so that a caller can tell an expected "no" from a bug.
    """


def label_for(disposition: Disposition) -> str:
    return _LABELS.get(disposition, "triage/unreadable")


def _digest(*parts: Any) -> str:
    return hashlib.sha256(
        canonical_json(list(parts)).encode("utf-8")
    ).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# proposed actions
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ProposedAction:
    """One outward mutation a disposition implies, pending human approval.

    ``target`` is an identifier a human already knows -- a message's file name or
    case id -- and never a path. ``summary`` is the payload described, not
    carried: "label triage/threat" says what would change without embedding the
    message it would change it on.
    """

    kind: str
    target: str
    summary: str
    rationale: str

    def __post_init__(self) -> None:
        if self.kind not in ACTION_KINDS:
            raise WritebackError(
                f"unknown action kind {self.kind!r}; the contract knows "
                f"{', '.join(ACTION_KINDS)}"
            )
        if not self.target:
            raise WritebackError("a proposed action must name the target it acts on")

    @property
    def binding(self) -> str:
        """What an approval binds to: the mutation, on the message."""
        return f"{self.kind}:{self.target}"

    def digest(self) -> str:
        return _digest(self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "summary": self.summary,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProposedAction":
        return cls(
            kind=str(data.get("kind") or ""),
            target=str(data.get("target") or ""),
            summary=str(data.get("summary") or ""),
            rationale=str(data.get("rationale") or ""),
        )


def proposed_actions(verdict: Verdict, *, target: str | None = None) -> list[ProposedAction]:
    """Every mutation this disposition would like, each one a separate approval.

    The set is derived from the verdict, so it cannot quietly grow between the
    approval and the execution: the runner compares each action's kind against
    what the human actually agreed to.
    """
    who = target or verdict.id or "message"
    actions = [
        ProposedAction(
            kind="record_case",
            target=who,
            summary=(
                f"case record for {who}: {verdict.disposition.value} at "
                f"{verdict.confidence:.2f} ({verdict.confidence_band.value}), "
                f"attack class {verdict.attack_type.value}"
            ),
            rationale=(
                "the durable record is the artifact an analyst and an auditor "
                "both read; it carries a verdict digest, not the message"
            ),
        )
    ]
    if verdict.disposition is not Disposition.UNKNOWN:
        actions.append(
            ProposedAction(
                kind="apply_label",
                target=who,
                summary=f"label {who} as {label_for(verdict.disposition)}",
                rationale=(
                    "a label is how the reporting user learns the outcome and how "
                    "the queue gets filtered; it is reversible, and it is still "
                    "an outbound mutation, so it is approved on its own"
                ),
            )
        )
    if verdict.escalated:
        actions.append(
            ProposedAction(
                kind="notify_analyst",
                target=who,
                summary=(
                    f"queue {who} for human review "
                    f"({len(verdict.reasons)} reason(s) recorded)"
                ),
                rationale=(
                    "the engine could not settle this on the evidence it has, and "
                    "an escalation that nobody is told about is not an escalation"
                ),
            )
        )
    return actions


# --------------------------------------------------------------------------
# approval
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Approval:
    """A human's yes, bound to one verdict digest, one target set, one action set.

    The binding is the whole point. An approval that authorized
    ``threat/0.95/CREDENTIAL_HARVEST`` must not be reusable against a record whose
    verdict changed under it, and a yes for three messages must not be spendable
    on five. ``token`` is single-use: the runner records the ones it has spent and
    refuses a presentation of a spent token.

    What this cannot do is stated plainly, because the first-place playbook states
    its own limit and so must we: the token authenticates nothing. It makes a
    replay detectable, not an approver trustworthy. Identity is only as strong as
    the system that issues the approval, and no runner -- this one included --
    can attest that a human meant what the record says they meant.
    """

    approver: str
    verdict_digest: str
    token: str
    targets: tuple[str, ...] = ()
    actions: tuple[str, ...] = GENERATED_ACTION_KINDS
    granted_at: str = ""
    note: str = ""

    def covers(self, receipt_id: str) -> bool:
        return receipt_id in self.targets

    def covers_action(self, kind: str) -> bool:
        return kind in self.actions

    def matches(self, verdict_digest: str) -> bool:
        return bool(self.verdict_digest) and self.verdict_digest == verdict_digest

    def as_dict(self) -> dict[str, Any]:
        return {
            "approver": self.approver,
            "verdict_digest": self.verdict_digest,
            "token": self.token,
            "targets": list(self.targets),
            "actions": list(self.actions),
            "granted_at": self.granted_at,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Approval":
        return cls(
            approver=str(data.get("approver") or ""),
            verdict_digest=str(data.get("verdict_digest") or ""),
            token=str(data.get("token") or ""),
            targets=tuple(str(t) for t in data.get("targets") or ()),
            actions=tuple(str(a) for a in data.get("actions") or ()),
            granted_at=str(data.get("granted_at") or ""),
            note=str(data.get("note") or ""),
        )


def token_for(
    *,
    approver: str,
    verdict_digest: str,
    targets: Sequence[str],
    actions: Sequence[str],
    nonce: str = "",
) -> str:
    """A deterministic single-use token for one approval.

    Derived from what is being approved rather than from randomness, so the same
    approval presented again is *recognizably* the same approval: the runner's
    replay check works on the token, and a random uuid would make a replayed
    grant look like a fresh one. A ``nonce`` (or a timestamp from the caller)
    produces a genuinely new authorization when an operator wants to re-approve a
    changed verdict deliberately.
    """
    return _digest(
        "approval", approver, verdict_digest, sorted(targets), sorted(actions), nonce
    )[:24]


def issue_approval(
    *,
    approver: str,
    verdict_digest: str,
    targets: Sequence[str],
    actions: Sequence[str] = GENERATED_ACTION_KINDS,
    nonce: str = "",
    granted_at: str | None = None,
    note: str = "",
) -> Approval:
    """Construct an approval an operator would sign.

    No UI asks the question here: how a human is presented the record and how
    their yes is captured is deployment (Bundle F's MCP server can do it
    interactively; the CLI deliberately does not, because a reviewer running the
    offline demo should never be prompted to authorize a mutation they cannot
    inspect first).
    """
    if not approver.strip():
        raise WritebackError("an approval must name its approver")
    if not verdict_digest:
        raise WritebackError("an approval must bind a verdict digest")
    target_set = tuple(dict.fromkeys(str(t) for t in targets))
    if not target_set:
        raise WritebackError("an approval must name the message(s) it covers")
    action_set = tuple(dict.fromkeys(str(a) for a in actions))
    unknown = [a for a in action_set if a not in ACTION_KINDS]
    if unknown:
        raise WritebackError(f"approval covers unknown action(s) {unknown}")
    return Approval(
        approver=approver.strip(),
        verdict_digest=verdict_digest,
        token=token_for(
            approver=approver, verdict_digest=verdict_digest,
            targets=target_set, actions=action_set, nonce=nonce,
        ),
        targets=target_set,
        actions=action_set,
        granted_at=granted_at or _now_iso(),
        note=note,
    )


# --------------------------------------------------------------------------
# providers
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderResult:
    """What a provider did -- or, for the default provider, would have done."""

    kind: str
    target: str
    provider: str
    performed: bool
    detail: str
    at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "provider": self.provider,
            "performed": self.performed,
            "detail": self.detail,
            "at": self.at,
        }


class WritebackProvider:
    """The capability interface a write destination implements.

    ``mutates`` is a declaration the runner can check: a provider that says it
    does not mutate cannot be used to satisfy a write stage that does. Capability
    rather than product, as everywhere else in this contract -- a Gmail label
    provider, a ticketing provider and a webhook provider all fit this shape, and
    none of them belongs in a repository that holds no credentials.
    """

    name: str = ""
    mutates: bool = False

    def execute(
        self,
        action: ProposedAction,
        *,
        receipt_id: str,
        verdict_digest: str,
        approval: Approval,
    ) -> ProviderResult:
        raise NotImplementedError(f"{type(self).__name__} has no execute()")

    def describe(self) -> str:
        return f"{self.name or type(self).__name__} ({'mutating' if self.mutates else 'non-mutating'})"


class DryRunProvider(WritebackProvider):
    """The default provider: records the intent, changes nothing, holds nothing.

    Every call appends to :attr:`log` so a reviewer can see the precise action
    that was gated, with its target, the approving identity and the verdict digest
    it was bound to. There is no transport in this class -- no socket, no file
    write, no subprocess -- which is what lets the whole bundle run with the
    network blocked at the transport seam.
    """

    name = DEFAULT_PROVIDER
    mutates = False

    def __init__(self) -> None:
        self.log: list[ProviderResult] = []

    def execute(
        self,
        action: ProposedAction,
        *,
        receipt_id: str,
        verdict_digest: str,
        approval: Approval,
    ) -> ProviderResult:
        result = ProviderResult(
            kind=action.kind,
            target=action.target,
            provider=self.name,
            performed=False,
            detail=(
                f"would have performed '{action.kind}' on {action.target}: "
                f"{action.summary} -- recorded, not executed (dry-run provider; "
                f"approved by {approval.approver} against verdict "
                f"{verdict_digest[:12]}..., receipt {receipt_id})"
            ),
            at=_now_iso(),
        )
        self.log.append(result)
        return result

    def entries(self) -> list[dict[str, Any]]:
        return [r.as_dict() for r in self.log]


#: Every provider this bundle can select by name. A real destination would be
#: registered here once ``NOTES.md`` open decision 2 is made, behind config, and
#: would still be opt-in: the default below is non-mutating.
PROVIDERS: dict[str, type[WritebackProvider]] = {
    DEFAULT_PROVIDER: DryRunProvider,
    # Resolved lazily by _resolve(): ledger.py imports this module for the provider
    # interface, so importing it here would be circular. The name is listed so
    # provider_names() and the error text are honest about what this build can
    # construct before anything has imported the class.
    "ledger": None,  # type: ignore[dict-item]
}


def _resolve(name: str) -> type[WritebackProvider]:
    """The provider class for a registered name, importing it if deferred."""
    cls = PROVIDERS.get(name)
    if cls is None and name == "ledger":
        from .ledger import LedgerProvider

        PROVIDERS[name] = LedgerProvider
        cls = LedgerProvider
    if cls is None:
        raise WritebackError(f"no writeback provider named {name!r}")
    return cls


def provider_for(
    name: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> WritebackProvider:
    """The provider selected by ``name``, else by the environment, else dry-run.

    Anything other than a registered name is a :class:`WritebackError`, not a
    silent downgrade to dry-run: an operator who believes they configured a label
    provider and is quietly given a no-op has been told something false about
    their own queue.
    """
    selected = name
    if selected is None:
        env = os.environ if environ is None else environ
        selected = (env.get(PROVIDER_ENV) or "").strip() or DEFAULT_PROVIDER
    if selected not in PROVIDERS:
        raise WritebackError(
            f"no writeback provider named {selected!r}. This build ships "
            f"{DEFAULT_PROVIDER!r}, which changes nothing, and 'ledger', which "
            "writes a local case record and touches no external system. A "
            "mail-system destination is still an open operator decision (NOTES.md "
            "open decision 2) and nothing here invents one. Set "
            f"{PROVIDER_ENV} only to a name in "
            f"{', '.join(sorted(PROVIDERS))}."
        )
    return _resolve(selected)()


def provider_names() -> tuple[str, ...]:
    return tuple(sorted(PROVIDERS))


def approval_language() -> str:
    """The contract's approval wording, for prompts and receipts."""
    return "human approval required"


def summarize_actions(actions: Iterable[ProposedAction]) -> str:
    items = list(actions)
    if not items:
        return "no outbound action proposed"
    return "; ".join(f"{a.kind} -> {a.target}" for a in items)
