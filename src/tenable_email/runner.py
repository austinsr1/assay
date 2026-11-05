"""The offline state-machine runner: it enforces the contract, and calls nothing.

This is the mechanism the SWARM Black Hat first-place playbook is built on, and the
reason a contract file is worth having at all. ``stages.yaml`` says what order the
chain runs in and which stage may write; a pipeline that ignores that is a
suggestion. The runner is the enforcement, and it enforces it *offline*: no live
system, no endpoint, no credential. There is a test that runs the whole fourteen-
fixture corpus with ``socket.create_connection`` replaced by a raiser, which is
the only proof of that claim that means anything.

It refuses, with a specific reason:

``skipped-stage``
    a non-optional stage of the contract was never completed, and the case wants
    to close anyway.
``out-of-order-stage``
    a later stage was presented while an earlier non-optional stage is still open,
    or a stage was presented *before* the position the case has already reached.
``altered-manifest``
    the corpus manifest digest now differs from the one the receipt recorded. The
    case was made against a different corpus than the one on disk.
``widened-target-set``
    an approval granted for N messages is presented against N+k, or against a
    message that is not in the set it names.
``replayed-approval``
    a token that has already been granted or spent is presented again.
``stale-approval`` / ``mismatched-approval``
    the approval's verdict digest is not the receipt's, so what was agreed to is
    not what is being acted on.
``absent-approval``
    a write stage was reached with no approval at all.
``closure-refused``
    the receipt's own closure blockers -- simulated evidence, a cited gap, an
    UNKNOWN disposition, a truncated verdict claiming completeness -- forbid it.
    The specifics are in the reason, because "cannot close" is not actionable.

**Refusals are transactional.** Every check runs before any mutation, and a
refusal returns a :class:`Refusal` value: no receipt is written, no journal line
is appended, no stage pointer moves, no token is spent, and the run stays
resumable. ``tests/test_runner.py`` proves that by snapshotting the run directory
byte-for-byte around a refusal. Exceptions here are reserved for programmer error
(:class:`RunnerError`), because an expected "no" that unwinds a caller's state is
how a partial case record gets left behind.

What the runner cannot prove, stated because the first-place runner states it: it
validates receipt *structure and consistency*. It does not authenticate the
approver, and it cannot attest that a tool which wrote a dishonest record was
told the truth. A token is replay evidence, not identity.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .contract import Contract, Stage, load_contract, validate_contract
from .receipt import (
    APPROVAL_CONSUMED,
    APPROVAL_GRANTED,
    Receipt,
    corpus_manifest,
)
from .writeback import (
    Approval,
    DryRunProvider,
    ProviderResult,
    WritebackProvider,
    issue_approval,
)

__all__ = [
    "JOURNAL_FILE",
    "RECEIPTS_DIR",
    "REFUSAL_CODES",
    "OfflineRunner",
    "Refusal",
    "RunnerError",
    "Transition",
]

#: Directory and file names under a run root. A run root is caller-chosen; the
#: runner creates it lazily, only when it has something to write, so a refused
#: transition can be shown to have touched nothing at all.
RECEIPTS_DIR = "receipts"
JOURNAL_FILE = "journal.jsonl"

#: Every code this runner can refuse with. Declared so a consumer -- the CLI, the
#: MCP server in Bundle F -- can branch on it instead of pattern-matching prose.
REFUSAL_CODES: tuple[str, ...] = (
    "skipped-stage",
    "out-of-order-stage",
    "stage-already-completed",
    "altered-manifest",
    "widened-target-set",
    "replayed-approval",
    "mismatched-approval",
    "absent-approval",
    "unapproved-action",
    "write-stage-requires-execution",
    "closure-refused",
    "unknown-stage",
    "unknown-receipt",
    "already-closed",
)


class RunnerError(RuntimeError):
    """Programmer error in the runner's use, never an expected refusal.

    Refusals are values. If this escapes a call, the caller handed the runner
    something it cannot be asked about -- a non-receipt, an empty contract, a
    provider that claims to mutate while the runner holds only a non-mutating one.
    """


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Refusal:
    """A transition that did not happen, and exactly why.

    Carries the ``stage`` it was about and the ``receipt_id`` it was about, so a
    log line is enough to find the case again. It is a value, not an exception:
    the caller's state is untouched by being returned one.
    """

    code: str
    reason: str
    stage: str = ""
    receipt_id: str = ""

    def __post_init__(self) -> None:
        if self.code not in REFUSAL_CODES:
            raise RunnerError(
                f"unknown refusal code {self.code!r}; declared codes are "
                f"{', '.join(REFUSAL_CODES)}"
            )
        if not self.reason.strip():
            raise RunnerError("a refusal must say why; refusals are read by humans")

    def as_dict(self) -> dict[str, Any]:
        return {
            "refused": True,
            "code": self.code,
            "reason": self.reason,
            "stage": self.stage,
            "receipt_id": self.receipt_id,
        }

    def __str__(self) -> str:
        where = f" [{self.stage}]" if self.stage else ""
        return f"REFUSED{where} ({self.code}): {self.reason}"


@dataclass(frozen=True)
class Transition:
    """The outcome of one attempted transition.

    ``receipt`` is the *new* state on success and ``None`` on refusal -- there is
    no "partially applied" receipt to hand back, because nothing was applied.
    """

    receipt: Receipt | None = None
    refusal: Refusal | None = None
    event: str = ""
    results: tuple[ProviderResult, ...] = ()

    @property
    def ok(self) -> bool:
        return self.refusal is None

    def __bool__(self) -> bool:
        return self.ok

    def reason(self) -> str:
        return self.refusal.reason if self.refusal else ""

    def as_dict(self) -> dict[str, Any]:
        if self.refusal is not None:
            return {"ok": False, "event": self.event, **self.refusal.as_dict()}
        return {
            "ok": True,
            "event": self.event,
            "receipt_id": self.receipt.receipt_id if self.receipt else "",
            "state": self.receipt.state if self.receipt else "",
            "provider_results": [r.as_dict() for r in self.results],
        }


@dataclass
class OfflineRunner:
    """Enforces the stage contract over a set of receipts, offline.

    ``root`` is where the durable record goes. ``None`` means in-memory only,
    which is what the demo uses; a directory means every accepted transition is
    written as a receipt file plus one journal line, and a runner pointed at the
    same directory can resume it.
    """

    contract: Contract = field(default_factory=load_contract)
    root: str | Path | None = None
    manifest_path: str | Path | None = None
    corpus_dir: str | Path | None = None
    provider: WritebackProvider = field(default_factory=DryRunProvider)
    clock: Callable[[], str] = _now_iso

    _receipts: dict[str, Receipt] = field(default_factory=dict, repr=False)
    _granted: dict[str, str] = field(default_factory=dict, repr=False)
    _spent: set[str] = field(default_factory=set, repr=False)

    def __post_init__(self) -> None:
        if not self.contract.stages:
            raise RunnerError(
                "the contract has no stages, so there is no order to enforce"
            )
        violations = validate_contract(self.contract)
        if violations:
            raise RunnerError(
                "refusing to run against an invalid contract: "
                + "; ".join(violations[:4])
            )
        if not self.stage_ids():
            raise RunnerError("contract stage ids are empty")
        self.root = Path(self.root) if self.root is not None else None
        if self.root is not None:
            self.resume()

    # -- contract view -------------------------------------------------------

    def stage_ids(self) -> list[str]:
        return self.contract.ids()

    def stage(self, stage_id: str) -> Stage:
        return self.contract.stage(stage_id)

    def position(self, stage_id: str) -> int:
        return self.stage_ids().index(stage_id)

    @property
    def write_stage(self) -> Stage:
        writes = self.contract.write_stages()
        if len(writes) != 1:
            raise RunnerError(
                f"expected exactly one write stage, the contract declares "
                f"{len(writes)}"
            )
        return writes[0]

    def open_stages(self, receipt: Receipt) -> list[Stage]:
        """Non-optional stages the contract requires that this case has not settled."""
        return [
            stage
            for stage in self.contract.stages
            if not stage.optional and not receipt.stage_is_done(stage.id)
        ]

    def incomplete_optional(self, receipt: Receipt) -> list[str]:
        return [
            stage.id
            for stage in self.contract.stages
            if stage.optional and not receipt.stage_is_done(stage.id)
        ]

    # -- corpus identity -----------------------------------------------------

    def current_manifest(self) -> tuple[str, str]:
        return corpus_manifest(self.manifest_path, self.corpus_dir)

    def _manifest_refusal(self, receipt: Receipt, stage: str) -> Refusal | None:
        label, digest = self.current_manifest()
        if receipt.manifest_matches(label, digest):
            return None
        return Refusal(
            code="altered-manifest",
            stage=stage,
            receipt_id=receipt.receipt_id,
            reason=(
                f"the corpus manifest no longer matches the one this receipt "
                f"recorded: it was made against {receipt.corpus_manifest} at "
                f"{receipt.corpus_manifest_digest[:16]}... and the corpus now "
                f"reports {label} at {digest[:16]}... . A case cannot advance "
                f"against a corpus that changed under it -- the labels are the "
                f"ground truth the verdict was checked against."
            ),
        )

    # -- lookup --------------------------------------------------------------

    def get(self, receipt_id: str) -> Receipt | None:
        return self._receipts.get(receipt_id)

    def receipts(self) -> list[Receipt]:
        return [self._receipts[rid] for rid in sorted(self._receipts)]

    def _require(self, receipt_id: str) -> Receipt | Refusal:
        receipt = self._receipts.get(receipt_id)
        if receipt is None:
            return Refusal(
                code="unknown-receipt",
                receipt_id=receipt_id,
                reason=(
                    f"no receipt {receipt_id!r} is open in this run; nothing was "
                    f"written or changed"
                ),
            )
        return receipt

    # -- intake --------------------------------------------------------------

    def begin(self, receipt: Receipt) -> Transition:
        """Open a case. The only transition that introduces a receipt.

        Idempotent by receipt id: re-opening the same case with the same verdict
        and the same corpus returns the record already open rather than duplicating
        it, because a resumable run must not accumulate two journals for one
        message.
        """
        if not isinstance(receipt, Receipt):
            raise RunnerError(
                f"begin() takes a Receipt, got {type(receipt).__name__}"
            )
        if not receipt.receipt_id:
            raise RunnerError("a receipt must carry an id before it can be opened")
        if Path(receipt.source).is_absolute():
            raise RunnerError(
                "a receipt source must be a file name, never an absolute path"
            )
        existing = self._receipts.get(receipt.receipt_id)
        if existing is not None:
            return Transition(receipt=existing, event="already-opened")
        if receipt.state == "closed":
            return Transition(
                receipt=None,
                event="begin",
                refusal=Refusal(
                    code="already-closed",
                    receipt_id=receipt.receipt_id,
                    reason=(
                        "a closed record is not re-opened; open a new case or "
                        "invalidate the approval that closed this one"
                    ),
                ),
            )
        started = _clone(receipt)
        started.completed_stages = []
        started.skipped_stages = []
        started.state = "opened"
        self._receipts[started.receipt_id] = started
        self._commit(started, {"event": "opened", "receipt_id": started.receipt_id})
        return Transition(receipt=started, event="opened")

    # -- stage transitions ---------------------------------------------------

    def complete_stage(self, receipt_id: str, stage_id: str) -> Transition:
        """Record that one stage ran and produced its findings.

        Order is checked against the contract, not against the caller's claim: the
        stage may be recorded only when every non-optional stage before it is
        already settled, and never after the case has reached a later one.
        """
        found = self._require(receipt_id)
        if isinstance(found, Refusal):
            return Transition(receipt=None, event="complete-stage", refusal=found)
        receipt = found
        if stage_id not in self.stage_ids():
            return Transition(
                receipt=None,
                event="complete-stage",
                refusal=Refusal(
                    code="unknown-stage",
                    stage=stage_id,
                    receipt_id=receipt_id,
                    reason=(
                        f"{stage_id!r} is not a stage of the contract "
                        f"({', '.join(self.stage_ids())}); a stage nobody "
                        f"declared cannot be completed"
                    ),
                ),
            )
        if stage_id in receipt.completed_stages:
            return Transition(
                receipt=None,
                event="complete-stage",
                refusal=Refusal(
                    code="stage-already-completed",
                    stage=stage_id,
                    receipt_id=receipt_id,
                    reason=(
                        f"stage {stage_id!r} is already settled for this case; "
                        f"completing it twice would rewrite its history"
                    ),
                ),
            )
        if receipt.state == "closed":
            return Transition(
                receipt=None,
                event="complete-stage",
                refusal=Refusal(
                    code="already-closed",
                    stage=stage_id,
                    receipt_id=receipt_id,
                    reason=(
                        f"receipt {receipt_id} is closed; a closed record "
                        f"accepts no further transitions"
                    ),
                ),
            )
        if stage_id == self.write_stage.id:
            return Transition(
                receipt=None,
                event="complete-stage",
                refusal=Refusal(
                    code="write-stage-requires-execution",
                    stage=stage_id,
                    receipt_id=receipt_id,
                    reason=(
                        f"{stage_id!r} is the contract's write stage and is not "
                        f"completed by assertion; it is completed by execute(), "
                        f"which requires a matching single-use human approval "
                        f"({self.write_stage.approval_language})"
                    ),
                ),
            )
        blocked = self._manifest_refusal(receipt, stage_id)
        if blocked is not None:
            return Transition(receipt=None, event="complete-stage", refusal=blocked)
        refused = self._order_refusal(receipt, stage_id, "complete-stage")
        if refused is not None:
            return Transition(receipt=None, event="complete-stage", refusal=refused)

        updated = _clone(receipt)
        updated.completed_stages = list(receipt.completed_stages) + [stage_id]
        updated.touch(self.clock())
        self._receipts[receipt_id] = updated
        self._commit(
            updated,
            {
                "event": "stage-completed",
                "receipt_id": receipt_id,
                "stage": stage_id,
                "at": updated.updated_at,
            },
        )
        return Transition(receipt=updated, event="stage-completed")

    def skip(self, receipt_id: str, stage_id: str, reason: str) -> Transition:
        """Record that an optional stage deliberately did not run.

        Optional means it may be absent, never that it may be *silent*: the reason
        is stored on the receipt and printed by ``show``, because "the vision stage
        did not run" is a fact about the deployment that a reviewer is entitled to.
        A non-optional stage cannot be skipped -- that is the ``skipped-stage``
        refusal, and it is what makes the ordering rule bite.
        """
        found = self._require(receipt_id)
        if isinstance(found, Refusal):
            return Transition(receipt=None, event="skip", refusal=found)
        receipt = found
        if stage_id not in self.stage_ids():
            return Transition(
                receipt=None,
                event="skip",
                refusal=Refusal(
                    code="unknown-stage",
                    stage=stage_id,
                    receipt_id=receipt_id,
                    reason=f"{stage_id!r} is not a stage of the contract",
                ),
            )
        stage = self.stage(stage_id)
        if not stage.optional:
            return Transition(
                receipt=None,
                event="skip",
                refusal=Refusal(
                    code="skipped-stage",
                    stage=stage_id,
                    receipt_id=receipt_id,
                    reason=(
                        f"stage {stage_id!r} is not optional in the contract "
                        f"({stage.capability}); it cannot be skipped, and this "
                        f"case cannot close without it"
                    ),
                ),
            )
        if receipt.state == "closed" or receipt.stage_is_done(stage_id):
            return Transition(
                receipt=None,
                event="skip",
                refusal=Refusal(
                    code="stage-already-completed",
                    stage=stage_id,
                    receipt_id=receipt_id,
                    reason=(
                        f"stage {stage_id!r} is already settled for this case; "
                        f"a skip would rewrite how it got there"
                    ),
                ),
            )
        blocked = self._manifest_refusal(receipt, stage_id)
        if blocked is not None:
            return Transition(receipt=None, event="skip", refusal=blocked)

        updated = _clone(receipt)
        updated.skipped_stages = list(receipt.skipped_stages) + [
            {"id": stage_id, "reason": reason}
        ]
        updated.touch(self.clock())
        self._receipts[receipt_id] = updated
        self._commit(
            updated,
            {
                "event": "stage-skipped",
                "receipt_id": receipt_id,
                "stage": stage_id,
                "reason": reason,
                "at": updated.updated_at,
            },
        )
        return Transition(receipt=updated, event="stage-skipped")

    def _order_refusal(
        self, receipt: Receipt, stage_id: str, event: str
    ) -> Refusal | None:
        """The ordering rule, in one place.

        Two directions are refused. A *forward* jump past a non-optional stage
        that has not been settled: the later stage's findings would rest on an
        earlier stage's output that nobody produced. And a *backward* presentation:
        once the case has reached stage k, claiming stage k-1 means the record of
        stage k was made without it.
        """
        ids = self.stage_ids()
        index = ids.index(stage_id)
        blocking = [
            earlier for earlier in ids[:index]
            if earlier != self.write_stage.id
            and not receipt.stage_is_done(earlier)
            and not self.stage(earlier).optional
        ]
        if blocking:
            return Refusal(
                code="out-of-order-stage",
                stage=stage_id,
                receipt_id=receipt.receipt_id,
                reason=(
                    f"stage {stage_id!r} cannot be recorded while the "
                    f"non-optional stage(s) "
                    f"{', '.join(repr(s) for s in blocking)} "
                    f"{'is' if len(blocking) == 1 else 'are'} still open: the "
                    f"contract runs {blocking[0]} first, so findings claimed now "
                    f"would have nothing to build on"
                ),
            )
        settled = [
            ids.index(s) for s in receipt.completed_stages if s in ids
        ]
        if settled and index < max(settled):
            later = [
                s for s in receipt.completed_stages
                if s in ids and ids.index(s) > index
            ]
            return Refusal(
                code="out-of-order-stage",
                stage=stage_id,
                receipt_id=receipt.receipt_id,
                reason=(
                    f"stage {stage_id!r} was presented after "
                    f"{', '.join(sorted(later))} had already completed; going "
                    f"backwards means the later record was made without the "
                    f"findings this one would have produced"
                ),
            )
        return None

    def drive(self, receipt_id: str) -> list[Transition]:
        """Walk the contract in order for one case.

        Stages the record claims ran are completed; optional stages that did not
        run are skipped with the reason this configuration actually produces (an
        unconfigured model tier, an optional provider that was not enabled or is
        not installed, or -- for the write stage -- no approval granted).
        The first refusal stops the walk: a runner that carried on past a refusal
        would be enforcing nothing.
        """
        found = self._require(receipt_id)
        if isinstance(found, Refusal):
            return [Transition(receipt=None, event="drive", refusal=found)]
        receipt = found
        claimed = set(receipt.stages_run)
        transitions: list[Transition] = []
        for stage in self.contract.stages:
            if stage.id in claimed:
                step = self.complete_stage(receipt.receipt_id, stage.id)
            else:
                step = self.skip(
                    receipt.receipt_id,
                    stage.id,
                    reason=_skip_reason(stage),
                )
            transitions.append(step)
            if not step.ok:
                break
        return transitions

    # -- approval gate -------------------------------------------------------

    def request_approval(
        self,
        receipt_id: str,
        *,
        approver: str,
        actions: Sequence[str] | None = None,
        nonce: str = "",
    ) -> Approval:
        """The approval an operator should be asked to sign for this case.

        Bound to the receipt's verdict digest and to the action kinds the record
        proposes, so signing it means agreeing to *those* mutations on *that*
        reading. Nothing here contacts a human: this builds the instrument, the
        caller presents it.
        """
        found = self._require(receipt_id)
        if isinstance(found, Refusal):
            raise RunnerError(f"cannot request approval: {found.reason}")
        receipt = found
        kinds = tuple(actions) if actions is not None else tuple(
            a.kind for a in receipt.proposed_actions
        )
        if not kinds:
            raise RunnerError(
                f"receipt {receipt_id} proposes no mutations, so there is "
                f"nothing to approve"
            )
        return issue_approval(
            approver=approver,
            verdict_digest=receipt.verdict_digest,
            targets=[receipt.receipt_id],
            actions=list(kinds),
            nonce=nonce or receipt.receipt_id,
        )

    def grant(
        self,
        receipt_id: str,
        approval: Approval,
        *,
        targets: Sequence[str] | None = None,
    ) -> Transition:
        """Accept a human approval for one case.

        Checked before anything is recorded, in this order: the corpus still
        matches, the approval names this verdict, the token is fresh, and the set
        of messages presented is the set that was approved -- no larger. A failure
        in any of them records nothing.
        """
        if not isinstance(approval, Approval):
            raise RunnerError("grant() takes an Approval")
        found = self._require(receipt_id)
        if isinstance(found, Refusal):
            return Transition(receipt=None, event="grant", refusal=found)
        receipt = found
        stage = self.write_stage.id
        blocked = self._manifest_refusal(receipt, stage)
        if blocked is not None:
            return Transition(receipt=None, event="grant", refusal=blocked)
        replayed = self._token_refusal(approval, receipt_id, stage)
        if replayed is not None:
            return Transition(receipt=None, event="grant", refusal=replayed)
        mismatched = self._digest_refusal(approval, receipt, stage)
        if mismatched is not None:
            return Transition(receipt=None, event="grant", refusal=mismatched)
        presented = list(targets) if targets is not None else [receipt_id]
        widened = self._target_refusal(approval, presented, receipt, stage)
        if widened is not None:
            return Transition(receipt=None, event="grant", refusal=widened)
        if receipt.state == "closed":
            return Transition(
                receipt=None,
                event="grant",
                refusal=Refusal(
                    code="already-closed",
                    stage=stage,
                    receipt_id=receipt_id,
                    reason=f"receipt {receipt_id} is closed",
                ),
            )

        updated = _clone(receipt)
        updated.approval = approval
        updated.approval_state = APPROVAL_GRANTED
        updated.touch(self.clock())
        self._receipts[receipt_id] = updated
        self._granted[approval.token] = receipt_id
        self._commit(
            updated,
            {
                "event": "approval-granted",
                "receipt_id": receipt_id,
                "stage": stage,
                "approver": approval.approver,
                "token": approval.token,
                "targets": list(approval.targets),
                "actions": list(approval.actions),
                "at": updated.updated_at,
            },
        )
        return Transition(receipt=updated, event="approval-granted")

    def _token_refusal(
        self, approval: Approval, receipt_id: str, stage: str
    ) -> Refusal | None:
        if not approval.token:
            return Refusal(
                code="absent-approval",
                stage=stage,
                receipt_id=receipt_id,
                reason=(
                    "the approval carries no token, so its single use cannot be "
                    "enforced and it is not an approval"
                ),
            )
        if approval.token in self._spent:
            return Refusal(
                code="replayed-approval",
                stage=stage,
                receipt_id=receipt_id,
                reason=(
                    f"approval token {approval.token} has already been spent; a "
                    f"second presentation is a replay, and one yes cannot "
                    f"authorize two mutations"
                ),
            )
        holder = self._granted.get(approval.token)
        if holder is not None:
            return Refusal(
                code="replayed-approval",
                stage=stage,
                receipt_id=receipt_id,
                reason=(
                    f"approval token {approval.token} was already granted for "
                    f"receipt {holder!r}; presenting it again for {receipt_id!r} "
                    f"is the widened-target-set shape -- one yes, more cases"
                ),
            )
        return None

    def _digest_refusal(
        self, approval: Approval, receipt: Receipt, stage: str
    ) -> Refusal | None:
        if approval.verdict_digest == receipt.verdict_digest:
            return None
        return Refusal(
            code="mismatched-approval",
            stage=stage,
            receipt_id=receipt.receipt_id,
            reason=(
                f"the approval binds verdict "
                f"{approval.verdict_digest[:16]}... but this receipt records "
                f"{receipt.verdict_digest[:16]}... ; what was agreed to is not "
                f"what is being acted on, so this approval is stale or belongs "
                f"to another case"
            ),
        )

    def _target_refusal(
        self,
        approval: Approval,
        presented: Sequence[str],
        receipt: Receipt,
        stage: str,
    ) -> Refusal | None:
        approved = list(approval.targets)
        extra = [t for t in presented if t not in approved]
        if extra or len(presented) > len(approved):
            return Refusal(
                code="widened-target-set",
                stage=stage,
                receipt_id=receipt.receipt_id,
                reason=(
                    f"this approval was granted for {len(approved)} message(s) "
                    f"({', '.join(approved)}) and this transition presents "
                    f"{len(presented)}"
                    + (f", of which {', '.join(extra)} were never approved" if extra else "")
                    + "; a target set may be honoured, not widened"
                ),
            )
        return None

    # -- execution -----------------------------------------------------------

    def execute(self, receipt_id: str) -> Transition:
        """Run the approved mutations through the provider, and consume the token.

        The provider is called only after every check passes, and the record is
        written only after the provider returns, so an accepted transition is a
        complete one. With the shipped non-mutating provider the results describe
        intentions and nothing leaves the process -- which is the point of the
        default, not an accident of it.
        """
        found = self._require(receipt_id)
        if isinstance(found, Refusal):
            return Transition(receipt=None, event="execute", refusal=found)
        receipt = found
        stage = self.write_stage.id
        blocked = self._manifest_refusal(receipt, stage)
        if blocked is not None:
            return Transition(receipt=None, event="execute", refusal=blocked)
        if receipt.state == "closed":
            return Transition(
                receipt=None,
                event="execute",
                refusal=Refusal(
                    code="already-closed",
                    stage=stage,
                    receipt_id=receipt_id,
                    reason=f"receipt {receipt_id} is closed",
                ),
            )
        approval = receipt.approval
        if approval is not None and receipt.approval_state == APPROVAL_CONSUMED:
            return Transition(
                receipt=None,
                event="execute",
                refusal=Refusal(
                    code="replayed-approval",
                    stage=stage,
                    receipt_id=receipt_id,
                    reason=(
                        f"approval token {approval.token} is already spent on "
                        f"this receipt ({len(receipt.execution)} action(s) "
                        f"recorded); a single-use approval does not authorize a "
                        f"second execution of the same mutations"
                    ),
                ),
            )
        if approval is None or receipt.approval_state != APPROVAL_GRANTED:
            return Transition(
                receipt=None,
                event="execute",
                refusal=Refusal(
                    code="absent-approval",
                    stage=stage,
                    receipt_id=receipt_id,
                    reason=(
                        f"{stage!r} is the contract's write stage and its access "
                        f"is '{self.write_stage.access}'; the stage requires "
                        f"{self.write_stage.approval_language} before any action, "
                        f"and this receipt has none recorded (approval state "
                        f"{receipt.approval_state!r})"
                    ),
                ),
            )
        mismatched = self._digest_refusal(approval, receipt, stage)
        if mismatched is not None:
            return Transition(receipt=None, event="execute", refusal=mismatched)
        if approval.token in self._spent:
            return Transition(
                receipt=None,
                event="execute",
                refusal=Refusal(
                    code="replayed-approval",
                    stage=stage,
                    receipt_id=receipt_id,
                    reason=(
                        f"approval token {approval.token} was already spent; the "
                        f"mutations it authorized have been recorded once and "
                        f"will not be recorded twice"
                    ),
                ),
            )
        widened = self._target_refusal(approval, [receipt_id], receipt, stage)
        if widened is not None:
            return Transition(receipt=None, event="execute", refusal=widened)
        refused = self._order_refusal(receipt, stage, "execute")
        if refused is not None:
            return Transition(receipt=None, event="execute", refusal=refused)

        unapproved = [
            action for action in receipt.proposed_actions
            if not approval.covers_action(action.kind)
        ]
        if unapproved:
            return Transition(
                receipt=None,
                event="execute",
                refusal=Refusal(
                    code="unapproved-action",
                    stage=stage,
                    receipt_id=receipt_id,
                    reason=(
                        f"the approval authorizes {', '.join(approval.actions)} "
                        f"and this record also proposes "
                        f"{', '.join(a.kind for a in unapproved)}; each mutation "
                        f"is approved separately, so nothing was executed"
                    ),
                ),
            )

        results: list[ProviderResult] = []
        for action in receipt.proposed_actions:
            results.append(
                self.provider.execute(
                    action,
                    receipt_id=receipt_id,
                    verdict_digest=receipt.verdict_digest,
                    approval=approval,
                )
            )

        updated = _clone(receipt)
        updated.execution = list(receipt.execution) + [r.as_dict() for r in results]
        updated.approval_state = APPROVAL_CONSUMED
        updated.completed_stages = list(receipt.completed_stages) + [stage]
        updated.touch(self.clock())
        self._receipts[receipt_id] = updated
        self._spent.add(approval.token)
        self._commit(
            updated,
            {
                "event": "executed",
                "receipt_id": receipt_id,
                "stage": stage,
                "token": approval.token,
                "provider": self.provider.name,
                "actions": [r.kind for r in results],
                "performed": [r.performed for r in results],
                "at": updated.updated_at,
            },
        )
        return Transition(receipt=updated, event="executed", results=tuple(results))

    # -- closure -------------------------------------------------------------

    def close(self, receipt_id: str) -> Transition:
        """Close a case, if the receipt contract permits it.

        Both halves, in order: the chain must actually have run (no non-optional
        stage left open), and the record must be closable (:meth:`
        tenable_email.receipt.Receipt.closure_blockers` -- simulated evidence, a
        cited gap, an UNKNOWN disposition, a truncated verdict claiming complete).
        Nothing is written when either fails.
        """
        found = self._require(receipt_id)
        if isinstance(found, Refusal):
            return Transition(receipt=None, event="close", refusal=found)
        receipt = found
        blocked = self._manifest_refusal(receipt, "close")
        if blocked is not None:
            return Transition(receipt=None, event="close", refusal=blocked)
        if receipt.state == "closed":
            return Transition(
                receipt=None,
                event="close",
                refusal=Refusal(
                    code="already-closed",
                    receipt_id=receipt_id,
                    reason=f"receipt {receipt_id} is already closed",
                ),
            )
        missing = self.open_stages(receipt)
        if missing:
            return Transition(
                receipt=None,
                event="close",
                refusal=Refusal(
                    code="skipped-stage",
                    stage=missing[0].id,
                    receipt_id=receipt_id,
                    reason=(
                        f"cannot close: the contract's non-optional stage(s) "
                        f"{', '.join(s.id for s in missing)} "
                        f"({', '.join(s.capability for s in missing)}) never "
                        f"completed for this case; a skipped stage is a gap in "
                        f"the chain, not a shortcut through it"
                    ),
                ),
            )
        blockers = receipt.closure_blockers()
        if blockers:
            return Transition(
                receipt=None,
                event="close",
                refusal=Refusal(
                    code="closure-refused",
                    receipt_id=receipt_id,
                    reason=" | ".join(blockers),
                ),
            )

        updated = _clone(receipt)
        updated.state = "closed"
        updated.closed_at = self.clock()
        updated.touch(updated.closed_at)
        self._receipts[receipt_id] = updated
        self._commit(
            updated,
            {
                "event": "closed",
                "receipt_id": receipt_id,
                "at": updated.closed_at,
                "disposition": updated.disposition,
            },
        )
        return Transition(receipt=updated, event="closed")

    # -- persistence ---------------------------------------------------------

    def _paths(self) -> tuple[Path, Path]:
        assert self.root is not None
        return self.root / RECEIPTS_DIR, self.root / JOURNAL_FILE

    def _commit(self, receipt: Receipt, event: Mapping[str, Any]) -> None:
        """Write the receipt and append the journal line -- only on success.

        Every mutation of runner state happens before this is called, and nothing
        calls it on a refusal path, so "a refused transition changes no state" is
        a property of the call graph rather than of discipline in the caller.
        """
        if self.root is None:
            return
        receipts_dir, journal = self._paths()
        receipts_dir.mkdir(parents=True, exist_ok=True)
        (receipts_dir / f"{receipt.receipt_id}.json").write_text(
            receipt.to_json(), encoding="utf-8"
        )
        with journal.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(event), sort_keys=True) + "\n")

    def resume(self) -> "OfflineRunner":
        """Re-read a run directory. A refused transition leaves a run resumable.

        The journal is the authority on spent tokens, so an approval consumed in
        an earlier process cannot be replayed by this one, and receipts already
        written come back with their stage positions intact.
        """
        if self.root is None:
            return self
        receipts_dir, journal = self._paths()
        if receipts_dir.is_dir():
            for path in sorted(receipts_dir.glob("*.json")):
                try:
                    receipt = Receipt.load(path)
                except Exception:  # a corrupt record is not a state to half-load
                    continue
                self._receipts[receipt.receipt_id] = receipt
        if journal.is_file():
            for line in journal.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                token = str(event.get("token") or "")
                if not token:
                    continue
                if event.get("event") == "approval-granted":
                    self._granted.setdefault(token, str(event.get("receipt_id") or ""))
                elif event.get("event") == "executed":
                    self._spent.add(token)
                    self._granted.pop(token, None)
        return self

    def journal(self) -> list[dict[str, Any]]:
        if self.root is None:
            return []
        _, journal = self._paths()
        if not journal.is_file():
            return []
        out = []
        for line in journal.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out

    def summary(self) -> str:
        closed = sum(1 for r in self._receipts.values() if r.state == "closed")
        return (
            f"{len(self._receipts)} case(s) in the run, {closed} closed, "
            f"{len(self._receipts) - closed} open, "
            f"{len(self._spent)} approval(s) spent, provider "
            f"{self.provider.describe()}"
        )


def _clone(receipt: Receipt) -> Receipt:
    """A copy for a transition, so a refusal cannot have touched the original.

    The runner never mutates a receipt in place. Every accepted transition builds
    the next record from the last one, which is what makes "the caller's receipt
    object is unchanged after a refusal" true rather than a hope.
    """
    return Receipt.from_dict(receipt.to_dict())


def _skip_reason(stage: Stage) -> str:
    if stage.access == "write":
        return (
            "no human approval was presented for this run; the write stage is "
            "gated and the case record itself is the artifact"
        )
    if stage.model_tier:
        return (
            f"no {stage.model_tier}-tier endpoint was configured and no attested "
            f"recording answered, so this stage recorded its absence instead of a "
            f"finding"
        )
    # Not a claim that the capability is missing - it is implemented. Which of
    # the two reasons applies is not knowable from inside a receipt, so both are
    # named rather than one guessed.
    return (
        f"the contract declares this stage optional, and its provider "
        f"({stage.provider}) is implemented but was not enabled in this "
        f"configuration or is not installed on this host; it is skipped with "
        f"this reason rather than passing silently"
    )
