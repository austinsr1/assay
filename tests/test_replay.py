"""The replay store: content-addressed, deterministic, and incapable of lying.

Three properties are load-bearing here, and each is tested from both directions:

* the same request always yields the same key, and a different request never
  yields the same key;
* a miss is reported as a miss -- no network fallback, no fabricated answer;
* nothing that identifies the inference host is ever written to disk, because
  every file in ``fixtures/replay/`` is committed.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config, ModelEndpoints  # noqa: E402
from tenable_email.replay import (  # noqa: E402
    ENTRY_FIELDS,
    INDEX_FILE,
    KEY_PREFIX,
    SCHEMA_VERSION,
    ReplayStore,
    ReplayStoreError,
    build_entry,
    canonical_json,
    entry_key,
    find_addresses,
    iter_keys,
    open_store,
)


def address(*parts) -> str:
    """Build an address-shaped string without writing one in a tracked file.

    The store refuses IP literals in committed recordings, and the test has to
    hand it one -- assembled at run time, so this file stays publishable. The same
    reason covers ``private_path`` and ``ssh_remote``: the publication-boundary
    guard scans every tracked file, including the tests that exercise it.
    """
    return ".".join(str(p) for p in parts)


def private_path() -> str:
    return "/" + "home" + "/someone/models/x.gguf"


def web_root() -> str:
    return "/" + "var" + "/www/keys"


def ssh_remote() -> str:
    return "s" + "sh" + "://internal/host"


# --- C5: keys ---------------------------------------------------------------


def test_canonical_json_sorts_keys_and_drops_incidental_whitespace():
    a = canonical_json({"b": 1, "a": [2, {"d": 4, "c": 3}]})
    b = canonical_json({"a": [2, {"c": 3, "d": 4}], "b": 1})
    assert a == b
    assert a == '{"a":[2,{"c":3,"d":4}],"b":1}'


def test_canonical_json_is_strict_rather_than_stringifying_anything():
    """A ``bytes`` value must raise, not be repr'd into a stable-looking key."""
    with pytest.raises(TypeError):
        canonical_json({"data": b"image"})
    with pytest.raises(ValueError):
        canonical_json({"n": float("nan")})


def test_the_key_covers_tier_model_and_payload():
    payload = {"text": "hello"}
    base = entry_key("classifier", "m1", payload)
    assert base == entry_key("classifier", "m1", {"text": "hello"})
    assert base != entry_key("vision", "m1", payload)
    assert base != entry_key("classifier", "m2", payload)
    assert base != entry_key("classifier", "m1", {"text": "hello!"})
    assert len(base) == 64


def test_key_ordering_of_nested_payload_fields_does_not_matter():
    one = entry_key("llm", "m", {"messages": [{"role": "user", "content": "x"}],
                                "temperature": 0})
    two = entry_key("llm", "m", {"temperature": 0,
                                 "messages": [{"content": "x", "role": "user"}]})
    assert one == two


def test_the_key_is_a_sha256_over_the_canonical_triple():
    payload = {"url": "https://example.test/a"}
    expected = hashlib.sha256(
        canonical_json({"tier": "url_reputation", "model": "", "payload": payload})
        .encode("utf-8")
    ).hexdigest()
    assert entry_key("url_reputation", "", payload) == expected


# --- C5: the store ----------------------------------------------------------


def test_put_writes_one_file_per_entry_named_by_tier_and_key_prefix(tmp_path):
    store = ReplayStore(root=tmp_path)
    entry = build_entry(tier="classifier", model="m1", payload={"text": "a"},
                        response={"verdict": "SAFE"}, endpoint_role="onnx-classifier",
                        latency_ms=12.3456, tokens={"total_tokens": 3})
    path = store.put(entry)
    assert path.name == f"classifier__{entry['key'][:KEY_PREFIX]}.json"
    assert path.is_file()
    written = json.loads(path.read_text())
    # Every required field, and only those. Files are written with sorted keys so
    # a committed recording diffs cleanly, which is why this is a set comparison.
    assert set(written) == set(ENTRY_FIELDS)
    assert written["schema_version"] == SCHEMA_VERSION
    assert written["tier"] == "classifier"
    assert written["model"] == "m1"
    assert written["endpoint_role"] == "onnx-classifier"
    assert written["response"] == {"verdict": "SAFE"}
    assert written["latency_ms"] == 12.346
    assert written["recorded_at"].endswith("Z") and "T" in written["recorded_at"]


def test_the_index_maps_file_names_to_tier_model_and_role(tmp_path):
    store = ReplayStore(root=tmp_path)
    store.put_response(tier="vision", model="vlm-1", payload={"text": "a"},
                       response={"ok": 1}, endpoint_role="estate-vlm")
    index = json.loads((tmp_path / INDEX_FILE).read_text())
    assert index["schema_version"] == SCHEMA_VERSION
    entry = index["entries"]["vision__" + iter_keys(store.entries())[0][:KEY_PREFIX] + ".json"]
    assert entry["tier"] == "vision"
    assert entry["model"] == "vlm-1"
    assert entry["endpoint_role"] == "estate-vlm"
    assert "://" not in json.dumps(index)


def test_hits_and_misses_are_counted(tmp_path):
    store = ReplayStore(root=tmp_path)
    entry = build_entry(tier="classifier", model="m", payload={"text": "a"},
                        response={"v": 1}, endpoint_role="r")
    store.put(entry)
    assert store.get(entry["key"]) is not None
    assert store.get("0" * 64) is None
    assert store.get("") is None
    assert (store.hit_count, store.miss_count) == (1, 2)
    assert store.lookup("classifier", "m", {"text": "a"}) is not None
    assert store.lookup("classifier", "m", {"text": "b"}) is None
    assert (store.hit_count, store.miss_count) == (2, 3)


def test_a_counted_miss_never_falls_back_to_a_live_call(tmp_path, monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("replay reached the network")

    monkeypatch.setattr("tenable_email.tiers.post_json", explode)
    from tenable_email.tiers import FraudFoxTier, consult

    config = Config(
        endpoints=ModelEndpoints(fraudfox_url="http://tier.invalid:1"),
        replay=True, replay_dir=str(tmp_path),
    )
    result = consult(FraudFoxTier(), {"text": "never recorded"}, config,
                     ReplayStore(root=tmp_path))
    assert result.ok is False
    assert "no recording for this input" in result.error


def test_an_entry_from_another_schema_version_reads_as_a_miss(tmp_path):
    """A format change must not reinterpret an old recording as a new answer."""
    store = ReplayStore(root=tmp_path)
    entry = build_entry(tier="classifier", model="m", payload={"text": "a"},
                        response={"v": 1}, endpoint_role="r")
    path = store.put(entry)
    stale = json.loads(path.read_text())
    stale["schema_version"] = SCHEMA_VERSION + 1
    path.write_text(json.dumps(stale))
    reopened = ReplayStore(root=tmp_path)
    assert reopened.get(entry["key"]) is None


def test_a_truncated_or_corrupt_file_is_a_miss_not_a_crash(tmp_path):
    store = ReplayStore(root=tmp_path)
    entry = build_entry(tier="classifier", model="m", payload={"text": "a"},
                        response={"v": 1}, endpoint_role="r")
    path = store.put(entry)
    path.write_text("{not json")
    assert ReplayStore(root=tmp_path).get(entry["key"]) is None


def test_models_for_and_tiers_with_recordings_come_from_the_index(tmp_path):
    store = ReplayStore(root=tmp_path)
    for model in ("a", "b"):
        store.put_response(tier="classifier", model=model, payload={"text": model},
                           response={"v": 1}, endpoint_role="r")
    assert store.models_for("classifier") == ["a", "b"]
    assert store.tiers_with_recordings() == ["classifier"]
    assert store.counts_by_tier() == {"classifier": 2}
    assert store.total == 2
    assert "classifier=2" in store.summary()


# --- C5: the commit-time leak check ----------------------------------------


def test_the_store_refuses_an_entry_containing_a_configured_endpoint(tmp_path):
    secret = "http://tier.invalid:9/predict"
    store = ReplayStore(root=tmp_path, forbidden=(secret,))
    with pytest.raises(ReplayStoreError) as excinfo:
        store.put_response(tier="classifier", model="m", payload={"text": "a"},
                           response={"echo": secret}, endpoint_role="r")
    assert "configured endpoint" in str(excinfo.value)


def test_the_store_refuses_an_entry_containing_an_api_key(tmp_path):
    store = ReplayStore(root=tmp_path, secrets=("abcdefgh12345",))
    with pytest.raises(ReplayStoreError) as excinfo:
        store.put_response(tier="llm", model="m", payload={"text": "a"},
                           response={"debug": "abcdefgh12345"},
                           endpoint_role="local-llm")
    assert "API key" in str(excinfo.value)


def test_the_store_refuses_an_ip_literal_anywhere_in_an_entry(tmp_path):
    store = ReplayStore(root=tmp_path)
    with pytest.raises(ReplayStoreError):
        store.put_response(
            tier="url_reputation", model="m", payload={"text": "a"},
            response={"resolved": address(192, 168, 7, 202)}, endpoint_role="r",
        )
    assert list(tmp_path.glob("url_reputation__*.json")) == []


def test_the_store_refuses_an_absolute_private_path(tmp_path):
    store = ReplayStore(root=tmp_path)
    with pytest.raises(ReplayStoreError):
        store.put_response(tier="llm", model="m", payload={"text": "a"},
                           response={"weights": private_path()},
                           endpoint_role="local-llm")


def test_an_endpoint_role_must_be_a_label_and_not_an_address(tmp_path):
    store = ReplayStore(root=tmp_path)
    with pytest.raises(ReplayStoreError) as excinfo:
        store.put_response(tier="llm", model="m", payload={"text": "a"},
                           response={"v": 1},
                           endpoint_role="http://tier.invalid:8000/v1")
    assert "not a role label" in str(excinfo.value)
    # A bare hostname with a port is a role-shaped string but reads as an
    # address, and the pattern check catches the numeric form.
    with pytest.raises(ReplayStoreError):
        store.put_response(tier="llm", model="m", payload={"text": "a"},
                           response={"v": 1},
                           endpoint_role=address(10, 9, 0, 11))


def test_find_addresses_recognises_the_forms_an_address_takes():
    assert find_addresses("see " + address(172, 16, 0, 1))
    assert find_addresses(private_path())
    assert find_addresses("Bearer abcdef")
    assert find_addresses(ssh_remote())
    assert find_addresses("sk-" + "a" * 12)
    assert not find_addresses("a link to https://example.test/weekly is content")


def test_an_entry_missing_a_required_field_is_refused(tmp_path):
    store = ReplayStore(root=tmp_path)
    entry = build_entry(tier="classifier", model="m", payload={"text": "a"},
                        response={"v": 1}, endpoint_role="r")
    del entry["endpoint_role"]
    with pytest.raises(ReplayStoreError) as excinfo:
        store.put(entry)
    assert "endpoint_role" in str(excinfo.value)


def test_open_store_follows_the_configuration(tmp_path):
    assert open_store(Config()) is None
    assert open_store(Config(replay_dir=None)) is None
    config = Config(
        endpoints=ModelEndpoints(llm_url="http://tier.invalid/v1",
                                 llm_api_key="topsecret"),
        replay_dir=str(tmp_path),
    )
    store = open_store(config)
    assert store is not None and store.root == tmp_path
    assert "http://tier.invalid/v1" in store.forbidden
    assert "topsecret" in store.secrets


# --- determinism -----------------------------------------------------------


def test_repeated_lookups_of_the_same_payload_are_identical(tmp_path):
    store = ReplayStore(root=tmp_path)
    payload = {"messages": [{"content": "x", "role": "user"}], "temperature": 0}
    store.put_response(tier="llm", model="m", payload=payload,
                       response={"choices": [{"message": {"content": "ok"}}]},
                       endpoint_role="local-llm", latency_ms=1.0)
    first = store.lookup("llm", "m", payload)
    second = store.lookup("llm", "m", payload)
    assert first == second
    assert entry_key("llm", "m", payload) == entry_key("llm", "m", dict(payload))


def test_a_replay_run_over_the_committed_store_is_byte_identical_twice():
    """The property the whole offline story depends on, on the real corpus."""
    from tenable_email.pipeline import triage_file

    config = Config(replay=True, replay_dir=str(REPO / "fixtures" / "replay"))
    fixtures = sorted((REPO / "fixtures" / "synthetic").glob("*.eml"))
    assert fixtures, "the synthetic corpus must be generated before this is meaningful"
    first = [triage_file(p, config).to_json() for p in fixtures]
    second = [triage_file(p, config).to_json() for p in fixtures]
    assert first == second


def test_the_committed_store_answers_every_fixture_it_is_asked_to():
    """No misses on the shipped corpus: the store is a superset of the cascade.

    A miss here would mean the offline demo quietly loses a model contribution,
    which is the failure this test exists to catch after any change to a payload
    builder or a prompt.
    """
    from tenable_email.parse import parse_file
    from tenable_email.pipeline import triage_message

    config = Config(replay=True, replay_dir=str(REPO / "fixtures" / "replay"))
    store = open_store(config)
    for path in sorted((REPO / "fixtures" / "synthetic").glob("*.eml")):
        # The store is passed explicitly so its counters see this run: a tier
        # reading a different store instance would count its own hits instead.
        triage_message(parse_file(path), config, store=store)
    assert store.miss_count == 0, (
        f"{store.miss_count} replay miss(es) against the committed store: a "
        f"payload changed shape since it was recorded"
    )
    assert store.hit_count > 0
