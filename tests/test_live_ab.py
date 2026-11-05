"""The live A/B runner must measure the tiers it says it measured.

Everything else in ``eval/`` is replay-backed and therefore reproducible from committed
recordings. ``eval/live_ab.py`` is the one runner that talks to real inference services,
and its artifacts are the project's only evidence about what the model tiers contribute.
An arm that silently consulted a tier it never named would not be a slightly noisy
measurement - it would be a different experiment wearing the label of the one described in
``docs/LIVE-AB.md``.

This file covers the isolation guarantee only. It does not contact any service, so it
runs offline with no endpoints configured.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "eval"))


def _load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


live_ab = _load_module("eval_live_ab", REPO / "eval" / "live_ab.py")


@pytest.fixture
def every_endpoint_exported(monkeypatch):
    """An environment where every tier looks configured, as on a real run host."""
    monkeypatch.setenv("TENABLE_EMAIL_FRAUDFOX_URL", "http://classifier.invalid:9")
    monkeypatch.setenv("TENABLE_EMAIL_SECMODELS_URL", "http://secmodels.invalid:9")
    monkeypatch.setenv("TENABLE_EMAIL_LLM_URL", "http://adjudicator.invalid:9/v1")
    monkeypatch.setenv("TENABLE_EMAIL_LLM_MODEL", "some-flash-model")
    monkeypatch.setenv("TENABLE_EMAIL_LLM_MAX_TOKENS", "400")
    monkeypatch.setenv("TENABLE_EMAIL_VLM_URL", "http://vision.invalid:9/v1")
    monkeypatch.setenv("TENABLE_EMAIL_SPAM_CLASSIFIER_URL", "http://spam.invalid:9")
    monkeypatch.setenv("TENABLE_EMAIL_INJECTION_CLASSIFIER_URL", "http://inject.invalid:9")


def test_an_unrequested_tier_is_not_addressed_even_when_the_environment_offers_it(
    every_endpoint_exported,
) -> None:
    """The regression this file exists for.

    ``build_config`` starts from ``Config.from_env()``, which reads every tier endpoint
    from the environment. It used to overwrite only the fields belonging to the tiers it
    was asked for and leave the rest inherited, so ``["classifier", "prompt_injection"]``
    quietly produced a config that could also reach the adjudication tier whenever
    ``TENABLE_EMAIL_LLM_URL`` happened to be exported.

    That is not a theoretical leak. The clearance gate takes the weakest self-reported
    confidence across every consulted tier, and a language model hedges where a softmax
    classifier emits 0.99 - so with the adjudicator reachable, three real benign business
    messages that disposition CLEAN drop to MANUAL_REVIEW. The arm's label would still have
    said "fast tiers only".
    """
    cfg = live_ab.build_config(["classifier", "prompt_injection"])

    assert cfg.endpoints.fraudfox_url, "the requested classifier tier must be addressed"
    assert cfg.endpoints.secmodels_url, "the requested injection tier must be addressed"

    assert not cfg.endpoints.llm_url, "the adjudicator was never requested"
    assert not cfg.endpoints.llm_model
    assert not cfg.endpoints.vlm_url, "nor was vision"
    assert not cfg.endpoints.spam_classifier_url
    assert not cfg.endpoints.injection_classifier_url


def test_a_requested_adjudicator_is_still_addressed(every_endpoint_exported) -> None:
    """Isolation must not become amputation.

    The fix clears what was not asked for; it must leave what was. Both routes into the
    adjudication tier are exercised because the runner uses both - the ``llm`` argument for
    the sampled adjudication pass and the ``tiers`` list for a whole-ladder arm.
    """
    via_argument = live_ab.build_config(
        ["classifier"], llm={"llm_url": "http://adjudicator.invalid:9/v1", "llm_model": "m"}
    )
    assert via_argument.endpoints.llm_url == "http://adjudicator.invalid:9/v1"
    assert via_argument.endpoints.llm_model == "m"

    via_tiers = live_ab.build_config(["llm"])
    assert via_tiers.endpoints.llm_url == "http://adjudicator.invalid:9/v1"


def test_a_shared_endpoint_survives_when_either_of_its_tiers_is_requested(
    every_endpoint_exported,
) -> None:
    """``url_reputation`` and ``prompt_injection`` are two tiers over one service.

    Clearing per tier rather than per field would drop ``secmodels_url`` when only one of
    the two was requested, and the requested tier would then fail to run.
    """
    cfg = live_ab.build_config(["url_reputation"])
    assert cfg.endpoints.secmodels_url == "http://secmodels.invalid:9"


def test_a_tier_whose_endpoint_is_not_exported_is_refused_not_silently_dropped(
    monkeypatch,
) -> None:
    """Fail closed, and name the variable.

    An arm that quietly measured nothing would report zeros that look like a result. The
    runner exits instead, naming the exact environment variable to set.
    """
    monkeypatch.delenv("TENABLE_EMAIL_FRAUDFOX_URL", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        live_ab.build_config(["classifier"])
    message = str(excinfo.value)
    assert "TENABLE_EMAIL_FRAUDFOX_URL" in message


def test_non_tier_transport_settings_are_preserved(every_endpoint_exported) -> None:
    """Isolation is about which tiers are reachable, not about discarding transport config.

    Compared against the environment rather than against a literal, because the default is
    ``None`` here and asserting a positive number would test the fixture, not the runner.
    """
    from tenable_email.config import Config

    expected = Config.from_env().endpoints.timeout_seconds
    cfg = live_ab.build_config(["classifier"])
    assert cfg.endpoints.timeout_seconds == expected
    assert cfg.replay is False, "a live arm must never read replay recordings"


def test_every_tier_the_runner_knows_is_accounted_for_in_the_isolation_map() -> None:
    """The two tables must not drift.

    ``TIER_ENDPOINT_FIELD`` decides what gets addressed and ``_TIER_ENDPOINT_FIELDS``
    decides what gets cleared. A tier added to one and not the other would either be
    unreachable when requested or leak when not, and neither failure is visible in a
    passing run.
    """
    known = set(live_ab.TIER_ENDPOINT_FIELD)
    mapped = set(live_ab._TIER_ENDPOINT_FIELDS)
    assert known == mapped, f"in TIER_ENDPOINT_FIELD only: {known - mapped}; in the isolation map only: {mapped - known}"
    for tier, field in live_ab.TIER_ENDPOINT_FIELD.items():
        assert field in live_ab._TIER_ENDPOINT_FIELDS[tier], (
            f"tier {tier!r} addresses {field!r}, which its isolation group does not cover"
        )
