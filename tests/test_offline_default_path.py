"""The offline path a reviewer runs must actually engage the model tiers.

The whole reproducibility claim rests on this: clone the repository, configure no
endpoints, reach no network, and the committed replay corpus answers the model
tiers. A defect here is invisible to a test suite that always passes
``replay_dir`` explicitly, which is why it gets its own module.

Design note, because it was contested: ``Config(replay=True, replay_dir=None)``
deliberately means **no store**, and every tier records itself UNAVAILABLE rather
than silently degrading. That contract is asserted in ``test_replay.py`` and
``test_pipeline.py`` and is not weakened here. Resolving the committed corpus is
therefore the **entry point's** job, via ``default_replay_dir()``, not the
library's - walking up from ``__file__`` is magic that breaks in an installed
wheel. Bundle D's CLI must default to it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config, default_replay_dir  # noqa: E402
from tenable_email.evidence import Provenance  # noqa: E402
from tenable_email.pipeline import triage_file  # noqa: E402

FIXTURES = REPO / "fixtures" / "synthetic"
CORPUS = REPO / "fixtures" / "replay"

#: Domains the synthetic corpus is allowed to contain. RFC 2606 reserved names
#: plus the vendor and redirect-wrapper domains the fixtures deliberately use for
#: realism - the reference playbook's own TRUSTED DOMAINS list names
#: outlook.office365.com and friends, so illustrative public vendor domains are
#: normal and are not a leak.
ANY_URL_RE = re.compile(r"https?://([^/\"'\s\\)]+)")


def _fixture_hosts() -> set[str]:
    """Every host derivable from the synthetic corpus, redirect wrappers undone.

    The invariant that matters is not "only reserved domains" - the fixtures
    legitimately name real vendors - but "a recording may only ever contain
    content derived from the synthetic corpus". Deriving the allowlist from the
    fixtures keeps it self-maintaining: add a fixture and its hosts are permitted
    automatically; leak anything else and this fails.

    Percent-decoding is essential. ``threat_redirect_wrapped`` carries its true
    destination only as ``https%3A%2F%2Fdeposit-confirm.test%2Fverify`` inside a
    Safe Links wrapper, and the url-reputation tier records the *unwrapped* host.
    Without decoding, correct behaviour looks like a leak.
    """
    hosts: set[str] = set()
    for path in sorted(FIXTURES.glob("*.eml")):
        raw = path.read_text(encoding="utf-8", errors="replace")
        # Both the literal text and its percent-decoded form, so wrapped
        # destinations are covered.
        for text in (raw, unquote(raw)):
            low = text.lower()
            for host in ANY_URL_RE.findall(text):
                hosts.add(host.rstrip(".").split("@")[-1])
            # Sender and Reply-To domains are not URLs but do reach tier payloads.
            for m in re.finditer(r"@([a-z0-9.-]+\.[a-z]{2,})", low):
                hosts.add(m.group(1))
    return hosts


def _replay_config() -> Config:
    """The configuration the CLI must default to."""
    return Config(replay=True, replay_dir=default_replay_dir())


def test_committed_replay_corpus_is_present():
    assert CORPUS.is_dir(), (
        "fixtures/replay/ is missing - the offline path has nothing to replay"
    )
    entries = [p for p in CORPUS.glob("*.json") if p.name != "index.json"]
    assert entries, "fixtures/replay/ contains no recordings"
    assert (CORPUS / "index.json").is_file()


def test_default_replay_dir_resolves_to_the_committed_corpus():
    resolved = default_replay_dir()
    assert resolved is not None, (
        "default_replay_dir() could not locate fixtures/replay by walking up from "
        "the package. An installed wheel without fixtures is the only expected "
        "None case, and the CLI must handle it by degrading to UNAVAILABLE."
    )
    assert Path(resolved).resolve() == CORPUS.resolve()


def test_the_cli_default_configuration_engages_model_tiers():
    """With the corpus resolved, tiers must answer - no endpoints, no network."""
    cfg = _replay_config()
    assert cfg.endpoints.configured_addresses() == []

    verdict = triage_file(FIXTURES / "threat_lookalike_credential_harvest.eml", cfg)

    assert verdict.evidence.by_provenance(Provenance.MODEL_JUDGMENT), (
        "the corpus-backed configuration produced no model judgments, so the "
        "committed recordings are inert on the path a reviewer will take"
    )
    assert len(verdict.stages_run) > 4, (
        f"only deterministic stages ran: {verdict.stages_run}"
    )


def test_unset_replay_dir_still_degrades_honestly():
    """The contested contract, pinned so it is not silently changed again.

    No directory means no store. Tiers record UNAVAILABLE with a reason; nothing
    is fabricated and nothing reaches the network.
    """
    cfg = Config(replay=True, replay_dir=None)
    verdict = triage_file(FIXTURES / "threat_lookalike_credential_harvest.eml", cfg)
    unavailable = verdict.evidence.by_provenance(Provenance.UNAVAILABLE)
    assert unavailable, "an unset replay_dir must record the tiers as UNAVAILABLE"
    assert verdict.evidence.by_provenance(Provenance.MODEL_JUDGMENT) == []


def test_offline_run_never_touches_the_network(monkeypatch):
    import socket

    def _blocked(*args, **kwargs):
        raise AssertionError("a network call was attempted during a replay-mode triage")

    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:1")

    cfg = _replay_config()
    for path in sorted(FIXTURES.glob("*.eml")):
        triage_file(path, cfg)


def test_every_fixture_triages_under_the_reviewer_configuration():
    cfg = _replay_config()
    paths = sorted(FIXTURES.glob("*.eml"))
    assert len(paths) >= 12, f"expected a full corpus, found {len(paths)}"
    for path in paths:
        verdict = triage_file(path, cfg)
        assert verdict.disposition is not None
        assert verdict.id or verdict.subject, f"{path.name} produced an empty verdict"


def _org_markers() -> list[str]:
    """Organization-specific markers, loaded from a gitignored file.

    Hardcoding them here was tried first and the publication-boundary guard
    correctly failed the build: this file is public-bound, and so is
    ``docs/results/junit.xml``, which captures assertion text. A guard that names
    what it forbids leaks it. Same mechanism ``test_doc_references.py`` uses.
    """
    path = REPO / ".scratch" / "forbidden-terms.txt"
    if not path.is_file():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


#: Generic markers only. Anything organization-specific comes from the gitignored
#: file above, so neither this file nor a junit capture can publish it.
GENERIC_PRIVATE_MARKERS = (
    "Bearer ", "192.168.", "10.9.0.", "172.16.",
    "/home/", "/Users/", "/var/www",
)


def test_recordings_leak_no_endpoint_or_host_identity():
    """The corpus is committed to a public repository.

    Recordings legitimately contain URLs - the url-reputation tier's *input* is a
    URL, and the injection tier's input is email text quoting links. What they
    must not contain is an endpoint, a credential, a private address or a host
    path, nor any host that did not come from the synthetic fixtures.
    """
    private_markers = (*GENERIC_PRIVATE_MARKERS, *_org_markers())
    allowed = _fixture_hosts()
    assert allowed, "could not derive hosts from the fixture corpus"

    offenders: list[str] = []
    foreign: list[str] = []

    for path in sorted(CORPUS.glob("*.json")):
        text = path.read_text(encoding="utf-8")
        for marker in private_markers:
            if marker in text:
                offenders.append(f"{path.name}: {marker!r}")
        for host in ANY_URL_RE.findall(text):
            host = host.lower().rstrip(".")
            if host not in allowed:
                foreign.append(f"{path.name}: {host}")

    assert not offenders, f"recordings leak private infrastructure: {offenders[:10]}"
    assert not foreign, (
        f"recordings reference hosts that do not appear in the synthetic corpus, "
        f"so they were not produced from fixtures alone: {foreign[:10]}"
    )


def test_every_recording_names_a_role_not_an_address():
    """Provenance must identify the tier by role, never by endpoint.

    ``model`` may be empty for exactly two tiers, because the security-model-estate
    routes do not report a model name. That is a real quality gap - an empty model
    field weakens replay-key specificity - so it is pinned by tier name rather than
    tolerated by a count: if a classifier, LLM or vision recording ever loses its
    model name, this fails instead of drifting.
    """
    tolerated = {"prompt_injection", "url_reputation"}
    unexpected: list[str] = []
    for path in sorted(CORPUS.glob("*.json")):
        if path.name == "index.json":
            continue
        entry = json.loads(path.read_text(encoding="utf-8"))
        role = entry.get("endpoint_role")
        assert isinstance(role, str) and role, f"{path.name} has no endpoint_role"
        assert "://" not in role, f"{path.name} endpoint_role is an address: {role}"
        assert entry.get("schema_version") == 1, f"{path.name} has no schema_version"
        tier = entry.get("tier")
        assert tier, f"{path.name} has no tier"
        assert entry.get("key"), f"{path.name} has no key"
        if not entry.get("model") and tier not in tolerated:
            unexpected.append(f"{path.name} (tier={tier})")
    assert not unexpected, (
        f"recordings for tiers that DO report a model name are missing it: "
        f"{unexpected[:8]}. Only {sorted(tolerated)} may omit it."
    )


def test_index_covers_every_recording():
    index = json.loads((CORPUS / "index.json").read_text(encoding="utf-8"))
    entries = index if isinstance(index, list) else index.get("entries", list(index.values()))
    files = {p.name for p in CORPUS.glob("*.json") if p.name != "index.json"}
    assert entries, "index.json is empty"
    assert len(entries) == len(files), (
        f"index.json lists {len(entries)} entries but {len(files)} recordings exist"
    )
