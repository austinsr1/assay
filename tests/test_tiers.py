"""The tier interface: one shape for every way an inference call can fail.

No test here touches a network. Transport is monkeypatched at its single seam
(:func:`tenable_email.tiers.post_json`), which is also how the "replay never calls
the network" guarantee is provable rather than asserted.

The behaviour that matters most in this module is the boring one: **a failure
returns a value**. A tier that raised would turn "the classifier did not answer"
into "the message could not be triaged", and the evidence record would lose the
distinction between a gap and a finding.
"""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config, ModelEndpoints, Thresholds  # noqa: E402
from tenable_email.evidence import Provenance  # noqa: E402
from tenable_email.parse import parse_message  # noqa: E402
from tenable_email.pipeline import MODEL_TIERS, triage_message  # noqa: E402
from tenable_email.replay import ReplayStore, build_entry, open_store  # noqa: E402
from tenable_email.tiers import (  # noqa: E402
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT_SECONDS,
    MIN_THINKING_TOKENS,
    REPLAY_MISS,
    REPLAY_MISS_NO_STORE,
    TIER_REGISTRY,
    FraudFoxTier,
    InjectionClassifierTier,
    LlmTier,
    PromptInjectionTier,
    SpamThreeWayTier,
    Stance,
    Tier,
    TierConfigError,
    TierResult,
    TierResponseError,
    UrlReputationTier,
    VlmTier,
    chat_content,
    consult,
    downscale,
    enforce_thinking_budget,
    extract_json_object,
    post_json,
    read_judgment,
    tier_by_name,
)

NO_ENDPOINTS = Config()


class FakeTransport:
    """Records calls and answers with a canned response or a fault."""

    def __init__(self, response=None, fault=None):
        self.response = response if response is not None else {"ok": True}
        self.fault = fault
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url, body, *, headers=None, timeout=None):
        self.calls.append((url, dict(body)))
        self.last_headers = dict(headers or {})
        self.last_timeout = timeout
        if self.fault is not None:
            raise self.fault
        return self.response, 12.5


def store(tmp_path) -> ReplayStore:
    return ReplayStore(root=tmp_path / "recordings")


# --- C1: the interface itself ----------------------------------------------


def test_every_tier_declares_the_three_things_the_interface_requires():
    """A tier is a name, a config gate and a call. Nothing else is allowed to vary."""
    for tier in TIER_REGISTRY:
        assert isinstance(tier, Tier)
        assert tier.name and isinstance(tier.configured(NO_ENDPOINTS), bool)
        result = tier.call({"text": "x"}, NO_ENDPOINTS, None)
        assert isinstance(result, TierResult)
        assert result.tier == tier.name


def test_tier_registry_and_pipeline_model_tiers_agree():
    """The two lists of tiers are one list.

    A tier in the registry but not in ``MODEL_TIERS`` is a tier whose absence is
    never recorded; a tier in ``MODEL_TIERS`` but not the registry is a gap
    reported for something that does not exist. Either way the evidence record
    stops being the truth about what ran.
    """
    names = {tier.name for tier in TIER_REGISTRY}
    assert {name for name, _f, _s in MODEL_TIERS} == names
    assert len(MODEL_TIERS) == len(names), "a tier name repeated would collapse a gap"
    for name, field, _stage in MODEL_TIERS:
        assert tier_by_name(name).endpoint_field == field
        assert hasattr(ModelEndpoints(), field), f"{field} is not a config field"


def test_an_unconfigured_tier_is_unavailable_and_names_the_field():
    for tier in TIER_REGISTRY:
        result = tier.call({"text": "anything"}, NO_ENDPOINTS, None)
        assert result.available is False, tier.name
        assert result.ok is False, tier.name
        assert result.error == f"endpoint not configured ({tier.endpoint_field})"
        assert result.model is None


def test_no_endpoint_field_has_a_default_address_anywhere():
    """Not one. A default endpoint would ship private topology and make an
    unconfigured tier into a tier that silently called somewhere."""
    endpoints = ModelEndpoints()
    for field in ("fraudfox_url", "secmodels_url", "spam_classifier_url",
                  "injection_classifier_url", "llm_url", "vlm_url",
                  "llm_model", "vlm_model", "llm_api_key", "vlm_api_key",
                  "injection_classifier_model", "spam_classifier_model"):
        assert getattr(endpoints, field) is None, field
    assert ModelEndpoints.from_env({}).configured_addresses() == []


def test_timeout_defaults_to_thirty_seconds_and_is_configurable():
    config = Config(endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1"))
    assert FraudFoxTier().timeout(config) == DEFAULT_TIMEOUT_SECONDS == 30.0
    configured = Config(
        endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1",
                                 timeout_seconds=2.5)
    )
    assert FraudFoxTier().timeout(configured) == 2.5


def test_a_transport_error_is_retried_once_and_then_reported(monkeypatch):
    transport = FakeTransport(fault=urllib.error.URLError("no route to host"))
    monkeypatch.setattr("tenable_email.tiers.post_json", transport)
    config = Config(endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1"),
                    replay=False)
    result = consult(FraudFoxTier(), {"text": "hello"}, config, None)
    assert len(transport.calls) == 1 + DEFAULT_RETRIES == 2
    assert result.available is True and result.ok is False
    assert "unreachable after 2 attempt(s)" in result.error


def test_retry_count_is_configurable_and_never_negative(monkeypatch):
    transport = FakeTransport(fault=OSError("closed"))
    monkeypatch.setattr("tenable_email.tiers.post_json", transport)
    config = Config(
        endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1", retries=0),
        replay=False,
    )
    result = consult(FraudFoxTier(), {"text": "hello"}, config, None)
    assert len(transport.calls) == 1
    assert result.ok is False and "unreachable after 1 attempt" in result.error


def test_a_failure_never_raises_from_consult(monkeypatch):
    """Every failure mode arrives as a value, including the exotic ones."""
    config = Config(endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1"),
                    replay=False)
    for fault in (
        urllib.error.HTTPError("http://x", 503, "down", {}, None),
        TimeoutError("timed out"),
        TierConfigError("bad"),
    ):
        monkeypatch.setattr(
            "tenable_email.tiers.post_json", FakeTransport(fault=fault)
        )
        result = consult(FraudFoxTier(), {"text": "x"}, config, None)
        assert isinstance(result, TierResult) and result.ok is False, fault


def test_post_json_sends_json_and_returns_measured_latency():
    """The one place bytes cross the boundary, checked without a socket."""
    import io

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()
            return False

    sent = {}

    def fake_urlopen(request, timeout=None):
        sent["body"] = json.loads(request.data.decode())
        sent["headers"] = dict(request.headers)
        sent["timeout"] = timeout
        return Response(b'{"verdict":"SAFE"}')

    import urllib.request

    original = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        parsed, latency = post_json(
            "http://tier.invalid/predict", {"text": "hi"},
            headers={"Authorization": "Bearer x"}, timeout=7.5,
        )
    finally:
        urllib.request.urlopen = original
    assert parsed == {"verdict": "SAFE"}
    assert isinstance(latency, float) and latency >= 0.0
    assert sent["body"] == {"text": "hi"}
    assert sent["timeout"] == 7.5
    assert sent["headers"]["Authorization"] == "Bearer x"
    assert sent["headers"]["Content-type"] == "application/json"


def test_api_key_is_only_sent_when_configured_and_never_leaks_into_as_dict():
    config = Config(
        endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1", llm_api_key="sekrit")
    )
    assert LlmTier().headers(config) == {"Authorization": "Bearer sekrit"}
    assert LlmTier().headers(Config()) == {}
    assert "sekrit" not in str(config.endpoints.as_dict())
    assert "[redacted]" in str(config.endpoints.as_dict())


def test_base_url_and_path_join_without_losing_the_base_path():
    """``/v1`` is part of the endpoint. urljoin would drop it; this does not."""
    config = Config(endpoints=ModelEndpoints(llm_url="http://tier.invalid:8000/v1"))
    assert LlmTier().url(config) == "http://tier.invalid:8000/v1/chat/completions"
    classifier = Config(endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:8088"))
    assert FraudFoxTier().url(classifier) == "http://tier.invalid:8088/predict"


# --- C2: the classifier tiers ----------------------------------------------


def test_fraudfox_body_is_limited_to_the_configured_char_budget(monkeypatch):
    transport = FakeTransport({"verdict": "SAFE", "safe_score": 0.9})
    monkeypatch.setattr("tenable_email.tiers.post_json", transport)
    config = Config(
        endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1"),
        thresholds=Thresholds(body_char_limit=100),
        replay=False,
    )
    consult(FraudFoxTier(), {"text": "y" * 5000}, config, None)
    assert len(transport.calls[0][1]["text"]) == 100


def test_fraudfox_response_is_normalized_and_keeps_its_own_scores():
    tier = FraudFoxTier()
    raw = {
        "verdict": "PHISHING", "is_phishing": True, "phishing_score": 0.999974,
        "safe_score": 2.6e-05, "confidence": 0.999974,
        "processing_time_ms": 29.88, "model": "xanderabim/fraudfoxai-phishing",
        "runtime": "onnxruntime",
    }
    result = TierResult(tier=tier.name, available=True, ok=True, raw=raw)
    judgment = tier.normalize(result, Config())
    assert judgment.stance is Stance.THREAT
    assert judgment.confidence == pytest.approx(0.999974)
    # Nothing lost at the boundary: the service's fields are still there verbatim.
    assert result.raw == raw
    assert judgment.score_fields["phishing_score"] == 0.999974
    assert judgment.score_fields["processing_time_ms"] == 29.88


def test_a_classifier_answer_with_no_verdict_and_no_score_is_a_failure(monkeypatch):
    monkeypatch.setattr(
        "tenable_email.tiers.post_json", FakeTransport({"unexpected": 1})
    )
    config = Config(endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1"),
                    replay=False)
    result = consult(FraudFoxTier(), {"text": "x"}, config, None)
    assert result.available is True and result.ok is False
    assert "neither a verdict nor a phishing score" in result.error


def test_url_reputation_is_queried_per_destination_and_reads_every_engine():
    tier = UrlReputationTier()
    raw = {
        "domain": "url", "verdict": "flag",
        "signals": [
            {"model": "phishscout", "verdict": "phishing", "probability": 0.9997,
             "threshold": 0.52},
            {"model": "cyberjev", "verdict": "legitimate",
             "probabilities": {"legitimate": 0.85, "phishing": 0.15}},
        ],
    }
    judgment = tier.normalize(
        TierResult(tier=tier.name, available=True, ok=True, raw=raw), Config()
    )
    assert judgment.stance is Stance.THREAT
    # The confidence is the probability of the class reported, from the engine
    # that reported it -- not the disagreeing engine's number.
    assert judgment.confidence == pytest.approx(0.9997)
    assert "the engines disagree" in judgment.detail
    assert judgment.score_fields["cyberjev_legitimate"] == 0.85


def test_prompt_injection_confidence_is_the_probability_of_the_class_reported():
    tier = PromptInjectionTier()
    injected = {
        "domain": "prompt_injection", "verdict": "injection",
        "signals": [{"model": "cyberjev", "verdict": "injection",
                     "probabilities": {"injection": 0.908329, "safe": 0.091671}}],
    }
    judgment = tier.normalize(
        TierResult(tier=tier.name, available=True, ok=True, raw=injected), Config()
    )
    assert judgment.stance is Stance.THREAT
    assert judgment.confidence == pytest.approx(0.908329)
    safe = {
        "domain": "prompt_injection", "verdict": "safe",
        "signals": [{"model": "cyberjev", "verdict": "safe",
                     "probabilities": {"injection": 0.091671, "safe": 0.908329}}],
    }
    judgment = tier.normalize(
        TierResult(tier=tier.name, available=True, ok=True, raw=safe), Config()
    )
    assert judgment.stance is Stance.CLEAN
    assert judgment.confidence == pytest.approx(0.908329)
    assert judgment.attack_type is None


def test_injection_tier_reports_the_agent_manipulation_class():
    tier = PromptInjectionTier()
    raw = {"verdict": "injection", "signals": []}
    judgment = tier.normalize(
        TierResult(tier=tier.name, available=True, ok=True, raw=raw), Config()
    )
    assert judgment.attack_type == "AGENT_MANIPULATION"
    assert any("automated analyst" in r for r in judgment.reasons)


# --- C2b: the optional injection classifier --------------------------------


def test_injection_classifier_defaults_to_unavailable():
    """Config-gated and absent by default: no model is downloaded or claimed."""
    result = InjectionClassifierTier().call({"text": "x"}, NO_ENDPOINTS, None)
    assert result.available is False
    assert result.error == "endpoint not configured (injection_classifier_url)"
    assert NO_ENDPOINTS.endpoints.injection_classifier_url is None


def test_injection_classifier_reads_an_onnx_http_label_and_scores():
    tier = InjectionClassifierTier()
    raw = {"label": "injection", "scores": {"injection": 0.93, "benign": 0.07}}
    judgment = tier.normalize(
        TierResult(tier=tier.name, available=True, ok=True, raw=raw), Config()
    )
    assert judgment.stance is Stance.THREAT
    assert judgment.confidence == pytest.approx(0.93)
    assert judgment.attack_type == "AGENT_MANIPULATION"


def test_injection_classifier_reads_a_chat_shaped_deployment():
    tier = InjectionClassifierTier()
    raw = {"choices": [{"message": {"role": "assistant", "content": "injection"}}]}
    judgment = tier.normalize(
        TierResult(tier=tier.name, available=True, ok=True, raw=raw), Config()
    )
    assert judgment.stance is Stance.THREAT
    # A one-word label carries no score, and inventing one would be a precision
    # the answer does not have.
    assert judgment.confidence is None


def test_injection_classifier_refuses_an_answer_it_cannot_read(monkeypatch):
    monkeypatch.setattr(
        "tenable_email.tiers.post_json", FakeTransport({"nonsense": True})
    )
    config = Config(
        endpoints=ModelEndpoints(injection_classifier_url="http://tier.invalid:1"),
        replay=False,
    )
    result = consult(InjectionClassifierTier(), {"text": "x"}, config, None)
    assert result.ok is False
    assert "neither chat choices nor a label/score block" in result.error


def test_spam_three_way_maps_fraud_spam_legitimate_onto_the_reference_taxonomy():
    tier = SpamThreeWayTier()
    for label, stance in (("fraud", Stance.THREAT), ("spam", Stance.SPAM),
                          ("legitimate", Stance.CLEAN)):
        judgment = tier.normalize(
            TierResult(
                tier=tier.name, available=True, ok=True,
                raw={"label": label, "scores": {label: 0.8, "other": 0.2}},
            ),
            Config(),
        )
        assert judgment.stance is stance, label
        assert judgment.confidence == pytest.approx(0.8)


# --- C3: the adjudication tier ---------------------------------------------


def chat_response(content):
    return {
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 353, "completion_tokens": 112,
                  "total_tokens": 465},
        "model": "some-model",
    }


def test_chat_payload_suppresses_thinking_and_pins_temperature_zero():
    config = Config(endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1"))
    payload = LlmTier().prepare({"prompt": "P"}, config)
    assert payload["chat_template_kwargs"] == {"enable_thinking": False}
    assert payload["temperature"] == 0
    assert payload["messages"][0]["content"] == "P"


def test_the_thinking_switch_is_a_per_endpoint_flag_defaulting_to_on():
    """Default: suppressed, because it is measured to work on both server types.

    An operator who wants reasoning, or who points at a server that does not
    understand the argument, gets the budget floor instead of a truncated answer.
    """
    default = Config(endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1"))
    assert LlmTier().suppresses_thinking(default) is True
    thinking = Config(
        endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1",
                                 llm_thinking_enabled=True)
    )
    assert LlmTier().suppresses_thinking(thinking) is False
    assert "chat_template_kwargs" not in LlmTier().prepare({"prompt": "P"}, thinking)
    unsupported = Config(
        endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1",
                                 llm_supports_chat_template_kwargs=False)
    )
    assert LlmTier().suppresses_thinking(unsupported) is False


def test_max_tokens_at_least_1024_is_enforced_in_code_not_in_a_comment():
    assert enforce_thinking_budget(MIN_THINKING_TOKENS, True) == MIN_THINKING_TOKENS
    with pytest.raises(TierConfigError) as excinfo:
        enforce_thinking_budget(400, thinking_left_on=True)
    assert "393" in str(excinfo.value)
    # Suppressed thinking needs no such floor, and the tier refuses to send the
    # doomed request rather than discovering the truncation in the answer.
    config = Config(
        endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1",
                                 llm_thinking_enabled=True, llm_max_tokens=400)
    )
    result = consult(LlmTier(), {"prompt": "P"}, config, None)
    assert result.available is True and result.ok is False
    assert "request could not be built" in result.error
    assert "below 1024" in result.error


def test_unparseable_model_output_is_a_failure_not_a_defaulted_verdict(monkeypatch):
    monkeypatch.setattr(
        "tenable_email.tiers.post_json",
        FakeTransport(chat_response("I cannot decide, sorry.")),
    )
    config = Config(endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1"),
                    replay=False)
    result = consult(LlmTier(), {"prompt": "P"}, config, None)
    assert result.available is True and result.ok is False
    assert "not with a JSON object" in result.error
    assert "no verdict was inferred" in result.error
    with pytest.raises(TierResponseError) as raised:
        read_judgment(result, config)
    assert "no verdict" in str(raised.value).lower()


@pytest.mark.parametrize(
    "content,expected",
    [
        ('{"verdict":"threat","confidence":0.95}', Stance.THREAT),
        ('```json\n{"verdict":"spam","confidence":"medium"}\n```', Stance.SPAM),
        ('Sure! {"verdict": "clean", "confidence": "high"} -- done', Stance.CLEAN),
        ('{"verdict":"phishing","confidence":95}', Stance.THREAT),
        ('{"verdict":"legitimate","confidence":0.99}', Stance.CLEAN),
    ],
)
def test_the_parser_is_json_first_fence_tolerant_and_band_tolerant(content, expected):
    tier = LlmTier()
    judgment = tier.normalize(
        TierResult(tier=tier.name, available=True, ok=True,
                   raw=chat_response(content)), Config()
    )
    assert judgment.stance is expected


def test_a_verdict_word_this_project_does_not_read_is_refused(monkeypatch):
    monkeypatch.setattr(
        "tenable_email.tiers.post_json",
        FakeTransport(chat_response('{"verdict":"suspicious","confidence":0.9}')),
    )
    config = Config(endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1"),
                    replay=False)
    result = consult(LlmTier(), {"prompt": "P"}, config, None)
    assert result.ok is False
    assert "is not one of threat/spam/clean" in result.error


def test_a_missing_confidence_is_refused_rather_than_assumed_certain(monkeypatch):
    monkeypatch.setattr(
        "tenable_email.tiers.post_json",
        FakeTransport(chat_response('{"verdict":"threat"}')),
    )
    config = Config(endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1"),
                    replay=False)
    result = consult(LlmTier(), {"prompt": "P"}, config, None)
    assert result.ok is False and "no readable confidence" in result.error


def test_an_empty_completion_is_reported_with_its_finish_reason(monkeypatch):
    """The measured truncation failure, as a distinct error rather than a blank."""
    empty = {"choices": [{"message": {"role": "assistant", "content": ""},
                          "finish_reason": "length"}]}
    monkeypatch.setattr("tenable_email.tiers.post_json", FakeTransport(empty))
    config = Config(endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1"),
                    replay=False)
    result = consult(LlmTier(), {"prompt": "P"}, config, None)
    assert result.ok is False
    assert "empty content" in result.error and "finish_reason=length" in result.error


def test_the_adjudication_prompt_is_the_fenced_one():
    """The tier must not assemble its own prompt: that is where the fence lives."""
    from tenable_email.prompts import FENCE_START, build_classification_prompt

    config = Config(endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1"))
    msg = parse_message(
        "From: a@example.edu\r\nSubject: hi\r\n"
        "Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n\r\n"
        "hello\r\n"
    )
    from tenable_email.signals import extract_signals

    signals = extract_signals(msg, config.profile, config.thresholds)
    expected = build_classification_prompt(signals, msg.body, config)
    payload = LlmTier().prepare({"prompt": expected}, config)
    assert FENCE_START in payload["messages"][0]["content"]
    assert "UNTRUSTED DATA" in payload["messages"][0]["content"]


# --- C4: the vision tier ---------------------------------------------------


def test_vision_payload_carries_a_base64_data_url_and_no_thinking():
    config = Config(endpoints=ModelEndpoints(vlm_url="http://tier.invalid:8085"))
    png = png_bytes()
    payload = VlmTier().prepare(
        {"data": png, "content_type": "image/png", "filename": "x.png"}, config
    )
    parts = payload["messages"][0]["content"]
    assert parts[0]["type"] == "text"
    assert "transcribe" in parts[0]["text"].lower()
    url = parts[1]["image_url"]["url"]
    assert url.startswith("data:image/png;base64,")
    assert payload["chat_template_kwargs"] == {"enable_thinking": False}
    assert payload["temperature"] == 0


def test_downscale_bounds_the_long_edge_when_pillow_is_available():
    PIL = pytest.importorskip("PIL", reason="pillow is an optional extra")
    import io as _io

    from PIL import Image

    buffer = _io.BytesIO()
    Image.new("RGB", (4000, 900), "white").save(buffer, format="PNG")
    data = buffer.getvalue()
    resized, media, note = downscale(data, 1024)
    with Image.open(_io.BytesIO(resized)) as image:
        assert max(image.size) == 1024
    assert media == "image/png"
    assert "downscaled 4000x900 to 1024x230" in note
    # A small image is sent as it is, and the note says so.
    same, media, note = downscale(png_bytes(), 1024)
    assert same == png_bytes() and "native size" in note


def png_bytes() -> bytes:
    path = REPO / "fixtures" / "assets" / "fake_login_page.png"
    if not path.is_file():
        pytest.skip("the synthetic image asset is not present")
    return path.read_bytes()


def test_without_pillow_the_image_is_sent_as_is_and_the_skip_is_recorded(monkeypatch):
    """Graceful degradation, because the core ships with zero dependencies."""
    monkeypatch.setitem(sys.modules, "PIL", None)
    monkeypatch.setitem(sys.modules, "PIL.Image", None)
    data, media, note = downscale(png_bytes(), 128, "image/png")
    assert data == png_bytes()
    assert media == "image/png"
    assert note == "downscaling skipped: Pillow is not installed"

    config = Config(endpoints=ModelEndpoints(vlm_url="http://tier.invalid:8085"))
    payload = VlmTier().prepare(
        {"data": data, "content_type": "image/png"}, config
    )
    assert payload["image_detail"] == note


def test_vision_output_is_a_judgment_and_its_urls_go_back_through_the_rules():
    tier = VlmTier()
    content = json.dumps({
        "transcribed_text": "Verify now http://example-portal-verify.test/auth",
        "urls": ["http://example-portal-verify.test/auth"],
        "impersonates": "Example University",
        "brand_impersonation": True,
        "verdict": "threat",
        "confidence": 0.95,
        "reasons": ["the domain is not the one it imitates"],
    })
    judgment = tier.normalize(
        TierResult(tier=tier.name, available=True, ok=True,
                   raw=chat_response(content)), Config()
    )
    assert judgment.stance is Stance.THREAT
    assert judgment.facts["brand_impersonation"] is True
    analysis = judgment.facts["link_analysis"]
    assert analysis and analysis[0]["is_lookalike"] is True
    assert "example" in (analysis[0]["detail"] or "")


def test_unparseable_vision_output_keeps_the_transcript_and_invents_no_verdict():
    tier = VlmTier()
    judgment = tier.normalize(
        TierResult(tier=tier.name, available=True, ok=True,
                   raw=chat_response("A login page asking for a password.")),
        Config(),
    )
    assert judgment.stance is Stance.ABSTAIN
    assert judgment.confidence is None
    assert "no verdict" in judgment.detail
    assert "login page" in judgment.facts["transcript_head"]


def test_chat_content_names_the_tier_that_failed_to_answer():
    with pytest.raises(TierResponseError) as excinfo:
        chat_content({"nope": 1}, tier="vision")
    assert "vision tier returned no choices" in str(excinfo.value)


# --- replay integration at the tier boundary -------------------------------


def test_replay_mode_never_calls_the_network(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("a network call happened in replay mode")

    monkeypatch.setattr("tenable_email.tiers.post_json", explode)
    config = Config(
        endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1"),
        replay=True, replay_dir=None,
    )
    result = consult(FraudFoxTier(), {"text": "x"}, config, None)
    assert result.ok is False
    assert result.error == REPLAY_MISS_NO_STORE
    store_config = Config(
        endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1"),
        replay=True, replay_dir=str(tmp_path_unused := "."),
    )
    missing = consult(FraudFoxTier(), {"text": "x"}, store_config,
                      ReplayStore(root="fixtures/replay-does-not-exist"))
    assert missing.error == REPLAY_MISS


def test_a_replay_hit_reports_the_recorded_cost_not_a_new_one(tmp_path):
    tier = FraudFoxTier()
    payload = tier.prepare({"text": "hello"}, Config())
    recorder = ReplayStore(root=tmp_path)
    recorder.put_response(
        tier=tier.name, model=tier.model_id(Config()), payload=payload,
        response={"verdict": "SAFE", "safe_score": 0.9},
        endpoint_role="onnx-classifier", latency_ms=33.5,
        tokens={"total_tokens": 7},
    )
    config = Config(
        endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1"),
        replay=True, replay_dir=str(tmp_path),
    )
    result = consult(tier, {"text": "hello"}, config, ReplayStore(root=tmp_path))
    assert result.source == "replay" and result.ok is True
    assert result.latency_ms == 33.5
    assert result.tokens == {"total_tokens": 7}


def test_record_mode_writes_the_recording_and_replay_reads_it_back(tmp_path, monkeypatch):
    transport = FakeTransport({"verdict": "PHISHING", "phishing_score": 0.7,
                               "confidence": 0.7})
    monkeypatch.setattr("tenable_email.tiers.post_json", transport)
    endpoints = ModelEndpoints(fraudfox_url="http://tier.invalid:1")
    recorded = Config(endpoints=endpoints, replay=False, replay_dir=str(tmp_path))
    result = consult(FraudFoxTier(), {"text": "click to verify"}, recorded,
                     ReplayStore(root=tmp_path))
    assert result.ok is True and result.source == "live"
    assert len(list(tmp_path.glob("classifier__*.json"))) == 1

    replayed = Config(endpoints=endpoints, replay=True, replay_dir=str(tmp_path))
    again = consult(FraudFoxTier(), {"text": "click to verify"}, replayed,
                    ReplayStore(root=tmp_path))
    assert again.ok is True and again.source == "replay"
    assert again.raw == result.raw


def test_a_live_answer_that_cannot_be_recorded_is_not_silently_used(tmp_path, monkeypatch):
    """In record mode an unrecordable answer means the run is not reproducible.

    The leak vector is the endpoint's own address echoed back inside the service
    response -- which is why the store is opened through ``open_store``: it is the
    only place that knows which addresses must never reach a committed file.
    """
    config = Config(
        endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1"),
        replay=False, replay_dir=str(tmp_path),
    )
    monkeypatch.setattr(
        "tenable_email.tiers.post_json",
        FakeTransport({"verdict": "SAFE", "upstream": config.endpoints.fraudfox_url}),
    )
    result = consult(FraudFoxTier(), {"text": "x"}, config, open_store(config))
    assert result.ok is False
    assert "recording refused" in result.error
    assert list(tmp_path.glob("classifier__*.json")) == []


def test_a_tier_with_recordings_but_no_endpoint_can_still_answer(tmp_path):
    """The judge's path: no credentials, no address, and still a model opinion."""
    tier = FraudFoxTier()
    payload = tier.prepare({"text": "hello"}, Config())
    from tenable_email.replay import build_entry

    recorder = ReplayStore(root=tmp_path)
    recorder.put(build_entry(
        tier=tier.name, model=tier.model_id(Config()), payload=payload,
        response={"verdict": "SAFE", "safe_score": 0.8},
        endpoint_role="onnx-classifier",
    ))
    result = consult(tier, {"text": "hello"}, Config(replay_dir=str(tmp_path)),
                     ReplayStore(root=tmp_path))
    assert result.available is True and result.ok is True
    assert result.source == "replay"


def test_consult_reports_an_ambiguous_replay_store_rather_than_choosing(tmp_path):
    """Two models recorded for one service tier, and config names neither.

    Picking one silently would mean presenting a recording as the answer of a
    model that may not have produced it.
    """
    tier = PromptInjectionTier()
    recorder = ReplayStore(root=tmp_path)
    payload = tier.prepare({"text": "hello"}, Config())
    for model in ("model-a", "model-b"):
        recorder.put(build_entry(
            tier=tier.name, model=model, payload=payload,
            response={"verdict": "safe"}, endpoint_role="security-model-estate",
        ))
    config = Config(replay=True, replay_dir=str(tmp_path))
    result = consult(tier, {"text": "hello"}, config, ReplayStore(root=tmp_path))
    assert result.ok is False and result.available is True
    assert "2 models are recorded" in result.error


def test_tier_findings_reach_evidence_as_model_judgments(tmp_path):
    """The provenance rule, end to end: an opinion is never a verified fact."""
    tier = FraudFoxTier()
    recorder = ReplayStore(root=tmp_path)
    recorder.put_response(
        tier=tier.name, model=tier.model_id(Config()),
        payload=tier.prepare({"text": "hello"}, Config()),
        response={"verdict": "PHISHING", "phishing_score": 0.9,
                  "confidence": 0.9},
        endpoint_role="onnx-classifier",
    )
    config = Config(replay=True, replay_dir=str(tmp_path))
    raw = (
        "From: a@example.edu\r\nSubject: hi\r\n"
        "Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n\r\n"
        "hello\r\n"
    )
    # The payload has to be the one the pipeline will compute, byte for byte:
    # the body keeps its trailing newline, and the key covers exactly what was
    # sent. Recording a different payload is a miss, not a hit with a typo.
    recorder.put_response(
        tier=tier.name, model=tier.model_id(Config()),
        payload=tier.prepare(
            {"text": parse_message(raw).body}, Config(replay_dir=str(tmp_path))
        ),
        response={"verdict": "PHISHING", "phishing_score": 0.9,
                  "confidence": 0.9},
        endpoint_role="onnx-classifier",
    )
    verdict = triage_message(parse_message(raw), config)
    findings = verdict.evidence.by_provenance(Provenance.MODEL_JUDGMENT)
    assert [f.key for f in findings] == ["classifier"]
    assert findings[0].provenance is Provenance.MODEL_JUDGMENT
    assert "not a verified fact" in findings[0].detail
    assert verdict.evidence.has_verified("classifier") is False
    verdict.assert_citable()


def test_extract_json_object_refuses_to_guess():
    assert extract_json_object("nothing structured here") is None
    assert extract_json_object("") is None
    assert extract_json_object('{"a": 1}') == {"a": 1}
