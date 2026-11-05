"""Local-first triage of user-reported phishing.

See README.md. Nothing in this package performs network I/O at import time, and
no model endpoint has a default address: with no configuration the deterministic
stages run and every model tier records itself UNAVAILABLE rather than failing.
With ``replay`` on -- the default -- the tiers are answered from the recordings in
``fixtures/replay/``, so the whole chain runs offline, deterministically, and a
missing recording is reported as a gap rather than fetched or invented.

The public surface is the stage contract, the chain, and the verdict it emits:

* :mod:`tenable_email.contract` -- ``stages.yaml`` parsed and validated, with a
  component registry that classifies every provider read-only or write.
* :mod:`tenable_email.pipeline` -- signals to model tiers to evidence to
  disposition, with the provenance of every item kept distinct.
* :mod:`tenable_email.verdict` -- the reference-shaped output: disposition,
  confidence and band, reasons, analysis, and the evidence record behind it.
* :mod:`tenable_email.prompts` -- the untrusted-content fence every model tier
  is called through.
* :mod:`tenable_email.tiers` -- one interface for the classifier, vision and
  language-model tiers, with failure returning a value rather than raising.
* :mod:`tenable_email.replay` -- the content-addressed record/replay store.
* :mod:`tenable_email.ensemble` -- combining facts and opinions asymmetrically,
  because a false negative costs more than a false positive.
* :mod:`tenable_email.receipt` -- the durable per-message record: digests, stage
  state, proposed actions, approval state, and the closure rules.
* :mod:`tenable_email.runner` -- the offline state machine that enforces
  ``stages.yaml`` and refuses, transactionally, without calling anything.
* :mod:`tenable_email.writeback` -- proposed actions, single-use approvals, and
  the non-mutating provider that is the default.
* :mod:`tenable_email.cli` -- ``tenable-email`` / ``python3 -m tenable_email``.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .config import (
    Config,
    ModelEndpoints,
    OrgProfile,
    Thresholds,
    EXAMPLE_PROFILE,
    DEFAULT_THRESHOLDS,
)
from .contract import (
    COMPONENT_REGISTRY,
    Contract,
    ContractError,
    Stage,
    load_contract,
    parse_stage_yaml,
    validate_contract,
)
from .ensemble import Deterministic, EnsembleOutcome, EnsemblePolicy, combine
from .evidence import Evidence, Finding, Provenance, EvidenceError
from .parse import (
    DEFAULT_MAX_EML_DEPTH,
    DEFAULT_MAX_EML_FILES,
    Attachment,
    DirectoryScanError,
    EmlScan,
    Message,
    iter_eml_dir,
    parse_file,
    parse_message,
    scan_eml_dir,
)
from .pipeline import build_evidence, triage_bytes, triage_file, triage_message
from .prompts import build_classification_prompt
from .receipt import (
    Receipt,
    ReceiptError,
    corpus_manifest,
    verdict_digest,
)
from .replay import ReplayStore, canonical_json, entry_key, open_store
from .runner import OfflineRunner, Refusal, RunnerError, Transition
from .signals import extract_signals
from .writeback import (
    Approval,
    DryRunProvider,
    ProposedAction,
    WritebackError,
    WritebackProvider,
    issue_approval,
    proposed_actions,
    provider_for,
)
from .tiers import (
    Judgment,
    Stance,
    TIER_REGISTRY,
    Tier,
    TierResult,
    consult,
    tier_by_name,
)
from .verdict import (
    AttackType,
    ConfidenceBand,
    Disposition,
    Verdict,
    band_for,
)

__all__ = [
    "__version__",
    # configuration
    "Config",
    "ModelEndpoints",
    "OrgProfile",
    "Thresholds",
    "EXAMPLE_PROFILE",
    "DEFAULT_THRESHOLDS",
    # evidence model
    "Evidence",
    "Finding",
    "Provenance",
    "EvidenceError",
    # intake and parsing
    "Attachment",
    "Message",
    "iter_eml_dir",
    "scan_eml_dir",
    "EmlScan",
    "DirectoryScanError",
    "DEFAULT_MAX_EML_FILES",
    "DEFAULT_MAX_EML_DEPTH",
    "parse_file",
    "parse_message",
    # deterministic signals
    "extract_signals",
    # stage contract
    "COMPONENT_REGISTRY",
    "Contract",
    "ContractError",
    "Stage",
    "load_contract",
    "parse_stage_yaml",
    "validate_contract",
    # verdict assembly
    "AttackType",
    "ConfidenceBand",
    "Disposition",
    "Verdict",
    "band_for",
    # receipt contract, offline runner and the write gate
    "Receipt",
    "ReceiptError",
    "corpus_manifest",
    "verdict_digest",
    "OfflineRunner",
    "Refusal",
    "RunnerError",
    "Transition",
    "ProposedAction",
    "Approval",
    "DryRunProvider",
    "WritebackProvider",
    "WritebackError",
    "issue_approval",
    "proposed_actions",
    "provider_for",
    # the chain itself
    "build_evidence",
    "triage_bytes",
    "triage_file",
    "triage_message",
    # prompt assembly
    "build_classification_prompt",
    # inference tiers, replay store and ensemble
    "Tier",
    "TierResult",
    "Judgment",
    "Stance",
    "TIER_REGISTRY",
    "tier_by_name",
    "consult",
    "ReplayStore",
    "canonical_json",
    "entry_key",
    "open_store",
    "Deterministic",
    "EnsembleOutcome",
    "EnsemblePolicy",
    "combine",
]
