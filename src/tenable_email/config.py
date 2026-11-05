"""Configuration.

Everything organization-specific lives here and nowhere else. Hard rule: no
employer domain, no named individual, no endpoint address and no allowlist entry
may appear in any other module. The shipped artifact must run for a stranger
with no knowledge of the deploying organization.

The predecessor engine hardcoded a specific university domain, a list of named
university officers, and specific vendor domains directly into its detection
functions and prompt exemplars. That made it unpublishable and unportable. These
are the same knobs, externalized.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class OrgProfile:
    """The deploying organization's identity, as far as triage cares."""

    #: Domains owned by the organization. A message claiming this identity from
    #: outside these domains is impersonation.
    protected_domains: tuple[str, ...] = ()

    #: Display-name strings that assert organizational identity. Matched
    #: case-insensitively as substrings. Keep these role-based, never
    #: person-based: "IT Service Desk" generalizes, a named officer does not.
    protected_identities: tuple[str, ...] = ()

    #: Third-party domains legitimately operated on the organization's behalf,
    #: e.g. mail filtering or e-signature services. Links to these are not by
    #: themselves a mismatch signal.
    trusted_domains: tuple[str, ...] = ()

    #: Senders that should be treated as clean absent compromise indicators.
    #: The reference playbook calls this its ALLOWLIST.
    allowlist: tuple[str, ...] = ()

    #: Modifier tokens that, combined with a protected label in a foreign
    #: domain's second-level label, indicate impersonation rather than an
    #: unrelated organization that happens to share a word. ``example-login.com``
    #: and ``example-portal-verify.com`` are impersonation;
    #: ``example-outfitters.com`` is a company named Example.
    #:
    #: This is a fact about the domain string, not a verdict. Kept in
    #: configuration for the same reason as everything else here.
    lookalike_modifiers: tuple[str, ...] = (
        "login", "logon", "signin", "sign-in", "auth", "authenticate",
        "verify", "verification", "validate", "confirm", "confirmation",
        "secure", "security", "account", "accounts", "portal", "webmail",
        "mail", "email", "sso", "password", "credential", "credentials",
        "update", "billing", "payment", "payments", "invoice", "support",
        "helpdesk", "help-desk", "service", "services", "desk", "online",
        "my", "app", "apps", "connect", "hub", "center", "centre",
    )

    #: URL-rewriting proxies whose ``?url=`` parameter hides the real
    #: destination. The reference handles ``safelinks.protection.outlook.com``;
    #: this is the same mechanism generalized so Proofpoint and Mimecast
    #: deployments work too.
    redirect_wrappers: tuple[str, ...] = (
        "safelinks.protection.outlook.com",
        "urldefense.proofpoint.com",
        "urldefense.com",
        "mimecast.com",
        "googleusercontent.com",
    )

    #: Boilerplate injected by mail systems that must not be read as a threat
    #: signal. The reference suppresses Outlook's "You don't often get email
    #: from {SENDER}"; these are the equivalents.
    benign_boilerplate: tuple[str, ...] = (
        "you don't often get email from",
        "this message was created automatically by mail delivery software",
        "delivery status notification",
        "caution: this message originated from outside the organization",
    )

    def owns_domain(self, domain: str) -> bool:
        """Whether ``domain`` is, or is a subdomain of, a protected domain."""
        if not domain:
            return False
        d = domain.lower().strip(".")
        return any(d == p or d.endswith("." + p) for p in self.protected_domains)


#: A neutral profile used by fixtures, tests and the shipped defaults. It uses
#: RFC 2606 reserved domains so no real organization is referenced, and no
#: example can resolve to a live host.
EXAMPLE_PROFILE = OrgProfile(
    protected_domains=("example.edu",),
    protected_identities=(
        "example university",
        "it service desk",
        "office of the president",
        "registrar",
        "payroll",
        "human resources",
        "financial aid",
        "help desk",
    ),
    trusted_domains=(
        "google.com",
        "googlemail.com",
        "outlook.office365.com",
        "go.microsoft.com",
        "protection.outlook.com",
        "docusign.net",
        "docusign.com",
    ),
    allowlist=(),
)


@dataclass(frozen=True)
class Thresholds:
    """Tunable decision points. Kept separate from logic so the cascade
    threshold can be selected against a measured accuracy target -- the BARGAIN
    method -- without editing detection code."""

    #: Edit distance at which a second-level domain is treated as a lookalike of
    #: a protected domain's label.
    lookalike_max_distance: int = 1
    #: A wider distance is tolerated for short labels, where one substitution is
    #: a larger proportional change.
    lookalike_short_label_len: int = 7
    lookalike_short_max_distance: int = 2
    #: Minimum vendor label length before edit-distance matching applies, to
    #: avoid flagging short common words.
    vendor_min_label_len: int = 5

    #: Body characters passed to a model before truncation is recorded.
    body_char_limit: int = 8000

    #: Confidence at or above which a verdict is reported as high.
    band_high: float = 0.85
    #: Confidence at or above which a verdict is reported as medium. Below this,
    #: low. A low-confidence verdict routes to manual review rather than being
    #: acted on.
    band_medium: float = 0.60

    #: Longest image edge, in pixels, sent to the vision tier. Bounds prompt
    #: tokens; measured cost was 73-117 tokens for a 420x120 image.
    image_max_dimension: int = 1024

    #: Attachments whose extension marks them high-risk from an external sender.
    dangerous_extensions: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                # executables and scripts
                ".exe", ".dll", ".scr", ".pif", ".com", ".bat", ".cmd", ".ps1",
                ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msi",
                ".msp", ".hta", ".sh", ".jar", ".apk",
                # macro-bearing documents
                ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xll",
                # containers and images used to smuggle the above
                ".iso", ".img", ".vhd", ".vhdx", ".zip", ".rar", ".7z", ".gz",
                # credential-harvesting documents rendered locally
                ".html", ".htm", ".shtml", ".svg", ".url", ".lnk", ".onetoc2",
            }
        )
    )

    #: Extensions whose contents are worth extracting and reading, per the
    #: reference playbook's requirement to review actual document contents.
    readable_extensions: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".txt", ".csv",
             ".rtf", ".odt", ".ods"}
        )
    )


DEFAULT_THRESHOLDS = Thresholds()


def default_replay_dir() -> str | None:
    """Locate the committed replay corpus by walking up from this file.

    The recordings are a repository artifact rather than package data, so an
    installed wheel will not carry them. Returning ``None`` in that case is the
    correct degradation: every model tier records itself UNAVAILABLE and the
    deterministic stages still run.

    Without this, ``Config(replay=True)`` with no explicit directory silently
    produces a deterministic-only pipeline even though a corpus is committed -
    which is what a reviewer running the documented offline path would hit.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "fixtures" / "replay"
        if candidate.is_dir() and any(candidate.glob("*.json")):
            return str(candidate)
    return None


@dataclass(frozen=True)
class ModelEndpoints:
    """Where each inference tier lives. All optional.

    Every field defaults to ``None`` so that a judge cloning this repository
    gets a working pipeline with no endpoints configured: the deterministic
    stages run, and any tier without an endpoint records itself UNAVAILABLE in
    the evidence rather than failing the message.

    Nothing here may carry a default address. Not one: a default endpoint is a
    private network detail shipped into a public artifact, and it also turns
    "this tier did not run" into "this tier called somewhere". Addresses and
    model ids arrive from the environment through :meth:`from_env`, and in
    replay mode they are not needed at all -- the recording store defines what
    ran. See ``NOTES.md`` hard rule 2.

    ``endpoint_roles`` maps a tier name to the *role label* written into each
    recording (``"estate-vlm"``, ``"onnx-classifier"``). The label is what gets
    committed; the address it stands for never leaves the environment.
    """

    #: FraudFoxAI-compatible ``POST /predict`` taking ``{"text": ...}``.
    fraudfox_url: str | None = None
    #: secmodels-compatible base URL, providing ``/url`` and
    #: ``/prompt-injection``.
    secmodels_url: str | None = None
    #: Three-way fraud/spam/legitimate classifier, ONNX over HTTP.
    spam_classifier_url: str | None = None
    #: Optional injection classifier (ONNX-over-HTTP or OpenAI-compatible).
    #: ``Horizon-Labs/prompt-injection-guard-small`` is the intended target --
    #: see ``docs/MODELS.md``. Defaults to absent, so the tier is UNAVAILABLE.
    injection_classifier_url: str | None = None
    #: Model id to name when calling the injection classifier.
    injection_classifier_model: str | None = None
    #: OpenAI-compatible chat endpoint for the adjudication tier.
    llm_url: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = None
    #: OpenAI-compatible multimodal endpoint for the vision tier.
    vlm_url: str | None = None
    vlm_model: str | None = None
    vlm_api_key: str | None = None

    # -- connection policy -------------------------------------------------
    # ``None`` means "use the tier's own default", which is 30 seconds. A
    # timeout is a policy, not a location, so it is allowed to have a default.
    timeout_seconds: float | None = None
    #: Retries per tier call on a transport error. ``None`` -> one retry.
    retries: int | None = None
    #: Model id sent to a three-way ONNX classifier, if it needs one.
    spam_classifier_model: str | None = None

    # -- thinking budgets ---------------------------------------------------
    # Measured on this estate (``docs/EVIDENCE.md``): Qwen3.5/3.6 endpoints are
    # thinking models, and ``chat_template_kwargs`` is the only suppression
    # mechanism that works on both llama.cpp and vLLM. It cut one call from
    # 4.23 s / 210 completion tokens to 0.87 s / 18. So suppression is the
    # default, and each flag below says whether *this* endpoint understands the
    # argument. An endpoint that does not understand it gets the budget floor
    # instead -- measured failure at ``max_tokens: 400`` burned 393 tokens on
    # reasoning and returned the content "**Transcription:**".
    #: The chat endpoint accepts ``chat_template_kwargs``.
    llm_supports_chat_template_kwargs: bool = True
    #: Leave reasoning enabled for the adjudication tier (costs a large budget).
    llm_thinking_enabled: bool = False
    #: Completion budget for the adjudication tier.
    llm_max_tokens: int | None = None
    #: The vision endpoint accepts ``chat_template_kwargs``.
    vlm_supports_chat_template_kwargs: bool = True
    #: Leave reasoning enabled for the vision tier.
    vlm_thinking_enabled: bool = False
    #: Completion budget for the vision tier.
    vlm_max_tokens: int | None = None

    #: ``(tier name -> role label)`` recorded in each replay entry, so a
    #: committed recording names a role and never an address.
    endpoint_roles: Mapping[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Endpoints with secrets redacted, for logging and evidence records."""
        d = {k: v for k, v in self.__dict__.items()}
        for secret in ("llm_api_key", "vlm_api_key"):
            if d.get(secret):
                d[secret] = "[redacted]"
        return d

    def configured_addresses(self) -> list[str]:
        """Every address an operator supplied, for leak checking at the store.

        A recording is committed to a public repository. If a response echoed
        the URL it was posted to, that address would be published; the replay
        store refuses such an entry rather than discovering it in review.
        """
        fields = (
            "fraudfox_url", "secmodels_url", "spam_classifier_url",
            "injection_classifier_url", "llm_url", "vlm_url",
        )
        return [v for v in (getattr(self, f, None) for f in fields) if v]

    def role_for(self, tier: str, default: str) -> str:
        """The role label to write into recordings for ``tier``."""
        return self.endpoint_roles.get(tier, default)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "ModelEndpoints":
        """Build the endpoint set from the environment, with no defaults.

        The only way an address reaches this process. Everything unset stays
        ``None``, which is a tier recorded UNAVAILABLE rather than a tier that
        silently called something.
        """
        env = os.environ if environ is None else environ
        values: dict[str, Any] = {}
        for attr, var in ENV_KEYS:
            values[attr] = _env_value(var, env)
        for attr, var in ENV_FLAGS:
            raw = _env_value(var, env)
            if raw is None:
                continue
            if attr in ("timeout_seconds", "llm_max_tokens", "vlm_max_tokens"):
                try:
                    number: Any = float(raw)
                except ValueError:
                    number = None
                values[attr] = int(number) if attr.endswith("max_tokens") else number
            elif attr == "retries":
                try:
                    values[attr] = int(raw)
                except ValueError:
                    values[attr] = None
            else:
                values[attr] = _env_flag(raw)
        roles = {
            tier: raw
            for tier, var in ENV_ROLES
            if (raw := _env_value(var, env)) is not None
        }
        if roles:
            values["endpoint_roles"] = roles
        return cls(**values)


#: ``(config attribute -> environment variable)`` for :meth:
#: ``ModelEndpoints.from_env``. Addresses have no defaults anywhere, so an
#: unset variable leaves the matching tier UNAVAILABLE.
ENV_KEYS: tuple[tuple[str, str], ...] = (
    ("fraudfox_url", "TENABLE_EMAIL_FRAUDFOX_URL"),
    ("secmodels_url", "TENABLE_EMAIL_SECMODELS_URL"),
    ("spam_classifier_url", "TENABLE_EMAIL_SPAM_CLASSIFIER_URL"),
    ("spam_classifier_model", "TENABLE_EMAIL_SPAM_CLASSIFIER_MODEL"),
    ("injection_classifier_url", "TENABLE_EMAIL_INJECTION_CLASSIFIER_URL"),
    ("injection_classifier_model", "TENABLE_EMAIL_INJECTION_CLASSIFIER_MODEL"),
    ("llm_url", "TENABLE_EMAIL_LLM_URL"),
    ("llm_model", "TENABLE_EMAIL_LLM_MODEL"),
    ("llm_api_key", "TENABLE_EMAIL_LLM_API_KEY"),
    ("vlm_url", "TENABLE_EMAIL_VLM_URL"),
    ("vlm_model", "TENABLE_EMAIL_VLM_MODEL"),
    ("vlm_api_key", "TENABLE_EMAIL_VLM_API_KEY"),
)

#: ``(config attribute -> environment variable)`` for the boolean/int knobs.
#: Parsing is permissive about ``0/false/no`` because shell quoting is not.
ENV_FLAGS: tuple[tuple[str, str], ...] = (
    ("timeout_seconds", "TENABLE_EMAIL_TIMEOUT_SECONDS"),
    ("retries", "TENABLE_EMAIL_RETRIES"),
    ("llm_max_tokens", "TENABLE_EMAIL_LLM_MAX_TOKENS"),
    ("vlm_max_tokens", "TENABLE_EMAIL_VLM_MAX_TOKENS"),
    ("llm_supports_chat_template_kwargs", "TENABLE_EMAIL_LLM_CHAT_TEMPLATE_KWARGS"),
    ("llm_thinking_enabled", "TENABLE_EMAIL_LLM_THINKING"),
    ("vlm_supports_chat_template_kwargs", "TENABLE_EMAIL_VLM_CHAT_TEMPLATE_KWARGS"),
    ("vlm_thinking_enabled", "TENABLE_EMAIL_VLM_THINKING"),
)

#: ``(tier name -> environment variable)`` for recording role labels.
ENV_ROLES: tuple[tuple[str, str], ...] = (
    ("classifier", "TENABLE_EMAIL_CLASSIFIER_ROLE"),
    ("url_reputation", "TENABLE_EMAIL_URL_ROLE"),
    ("prompt_injection", "TENABLE_EMAIL_INJECTION_ROLE"),
    ("injection_classifier", "TENABLE_EMAIL_INJECTION_CLASSIFIER_ROLE"),
    ("spam_three_way", "TENABLE_EMAIL_SPAM_ROLE"),
    ("vision", "TENABLE_EMAIL_VISION_ROLE"),
    ("llm", "TENABLE_EMAIL_LLM_ROLE"),
)


def _env_value(name: str, environ: Mapping[str, str]) -> str | None:
    value = environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _env_flag(value: str) -> bool:
    return value.strip().lower() not in ("0", "false", "no", "off")


@dataclass(frozen=True)
class Config:
    """Top-level configuration."""

    profile: OrgProfile = EXAMPLE_PROFILE
    thresholds: Thresholds = DEFAULT_THRESHOLDS
    endpoints: ModelEndpoints = ModelEndpoints()

    #: When true, model tiers are served from recorded responses instead of
    #: live calls. The default path for judges, tests and CI: no credentials, no
    #: network, no inference host required.
    replay: bool = True
    #: Directory of recorded model responses. In replay mode a tier with no
    #: store to read from did not run, and says so; in record mode this is where
    #: each response is written. ``None`` means "no store on purpose".
    replay_dir: str | None = None

    # -- optional deep attachment analysis ---------------------------------
    # Off by default, and the default is the only thing a reviewer has to trust.
    # The component is :mod:`tenable_email.attachments`: it shells out to the
    # local ``rea`` CLI, which is a Node.js program with a heavy install and an
    # engine floor this project does not meet. With this false no subprocess is
    # started, no capability query is made and no finding from that module is
    # added, so the shipped behaviour -- and every measured number in this
    # repository -- does not depend on it. Turning it on adds static findings
    # about attachment contents; it changes no disposition, by design.
    #: Analyse retained attachment contents with ``rea``, when it is installed.
    deep_attachment_analysis: bool = False
    #: The analyzer binary. ``None`` means "``rea`` found on ``PATH``"; an
    #: operator who wants to pin *which* program runs sets an absolute path.
    attachment_analysis_command: str | None = None
    #: Per-attachment wall-clock budget. ``None`` means the component's own
    #: default. A timeout is a policy, not a location, so it may have a default.
    attachment_analysis_timeout_seconds: float | None = None

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        profile: OrgProfile | None = None,
        thresholds: Thresholds | None = None,
    ) -> "Config":
        """Configuration from the environment: endpoints, replay mode, store.

        ``TENABLE_EMAIL_REPLAY=0`` selects record mode; the replay store
        directory is ``TENABLE_EMAIL_REPLAY_DIR``. Nothing about an inference
        host has a default, so a fresh clone runs the deterministic chain and
        reports every tier as it actually is -- unavailable.

        The optional deep attachment analysis is off unless
        ``TENABLE_EMAIL_DEEP_ATTACHMENT_ANALYSIS`` says otherwise. It is read
        here and nowhere else, because the alternative -- a component that
        decides for itself whether to spawn a subprocess -- is a third-party
        program running on a machine because a file happened to be on ``PATH``.
        """
        env = os.environ if environ is None else environ
        replay_raw = _env_value("TENABLE_EMAIL_REPLAY", env)
        analysis_raw = _env_value("TENABLE_EMAIL_DEEP_ATTACHMENT_ANALYSIS", env)
        timeout_raw = _env_value(
            "TENABLE_EMAIL_ATTACHMENT_ANALYSIS_TIMEOUT_SECONDS", env
        )
        try:
            analysis_timeout: float | None = (
                None if timeout_raw is None else float(timeout_raw)
            )
        except ValueError:
            analysis_timeout = None
        return cls(
            profile=profile or EXAMPLE_PROFILE,
            thresholds=thresholds or DEFAULT_THRESHOLDS,
            endpoints=ModelEndpoints.from_env(env),
            replay=True if replay_raw is None else _env_flag(replay_raw),
            replay_dir=_env_value("TENABLE_EMAIL_REPLAY_DIR", env),
            deep_attachment_analysis=(
                False if analysis_raw is None else _env_flag(analysis_raw)
            ),
            attachment_analysis_command=_env_value(
                "TENABLE_EMAIL_ATTACHMENT_ANALYSIS_COMMAND", env
            ),
            attachment_analysis_timeout_seconds=analysis_timeout,
        )
