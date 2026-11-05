"""The intake adapter contract.

The tests that matter here are not the ones that exercise the reference adapter.
They are the two that prove the abstraction is real: that a source nobody wrote yet
can be implemented without touching the engine, and that the engine produces the
same verdict regardless of which source handed it the bytes. An adapter layer that
only ever has one implementation is a wrapper, and a wrapper is a claim about
portability that nothing has tested.
"""

from __future__ import annotations

import pathlib
import shutil
import socket
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email.config import Config  # noqa: E402
from tenable_email.parse import (  # noqa: E402
    DEFAULT_MAX_EML_DEPTH,
    DEFAULT_MAX_EML_FILES,
    iter_eml_dir,
    parse_file,
)
from tenable_email.pipeline import triage_file, triage_message  # noqa: E402
import tenable_email.sources as sources  # noqa: E402
from tenable_email.sources import (  # noqa: E402
    DEFAULT_SOURCE,
    EmailSource,
    EmlDirectorySource,
    SourceError,
    SourceItem,
    available_sources,
    register_source,
    source_for,
)

SYNTHETIC = REPO / "fixtures" / "synthetic"


# --------------------------------------------------------------------------
# the reference adapter
# --------------------------------------------------------------------------


def test_the_default_source_is_the_one_that_needs_no_credentials():
    """Deliberate, and worth pinning: the default is the accessible one.

    If a platform adapter ever became the default, the project would stop being
    runnable by a reviewer with nothing installed, which is the property the whole
    offline story rests on.
    """
    assert DEFAULT_SOURCE == "eml-dir"
    assert DEFAULT_SOURCE in available_sources()


def test_the_reference_source_yields_the_whole_corpus_in_a_stable_order():
    source = EmlDirectorySource(SYNTHETIC)
    first = [item.external_id for item in source.fetch()]
    second = [item.external_id for item in source.fetch()]

    assert first == second, "intake order must be stable or results are not reproducible"
    assert len(first) == 14, (
        f"expected the 14 synthetic fixtures, got {len(first)}; if the corpus grew, "
        "update this count deliberately"
    )
    assert first == sorted(first)
    assert all(name.endswith(".eml") for name in first)


def test_the_reference_source_opens_no_socket():
    """No credentials, no network, no platform account - asserted, not described."""

    def refuse(*args, **kwargs):
        raise AssertionError(
            "the reference intake source attempted a network connection"
        )

    original = socket.create_connection
    socket.create_connection = refuse  # type: ignore[assignment]
    try:
        items = list(EmlDirectorySource(SYNTHETIC).fetch())
    finally:
        socket.create_connection = original  # type: ignore[assignment]
    assert len(items) == 14


def test_a_missing_directory_reports_a_reason_not_a_traceback():
    with pytest.raises(SourceError) as exc:
        list(EmlDirectorySource(REPO / "no-such-directory").fetch())
    assert exc.value.reason == "source_directory_missing"


def test_a_time_filter_is_refused_rather_than_silently_ignored():
    """The honest failure.

    A directory has no received-time metadata, so `since` cannot be applied.
    Returning everything and letting the caller believe the filter worked is the
    defect; naming what could not be done is the fix.
    """
    with pytest.raises(SourceError) as exc:
        list(EmlDirectorySource(SYNTHETIC).fetch(since="2026-01-01T00:00:00Z"))
    assert exc.value.reason == "source_filter_unsupported"
    assert "received-time" in exc.value.detail


def test_limit_stops_early_without_reading_the_whole_corpus():
    """Intake must be lazy; holding every reported message is how it becomes an outage.

    Asserted on the scan the source recorded, not on the length of the answer: a
    limit that stopped delivering but still walked the tree would pass a count
    check and leave the defect in place.
    """
    source = EmlDirectorySource(SYNTHETIC)
    iterator = source.fetch(limit=2)
    taken = [item.external_id for item in iterator]
    assert len(taken) == 2
    assert source.scan is not None, "a fetch that saw nothing is not an auditable fetch"
    assert source.scan.files_found == 2, (
        f"limit=2 walked {source.scan.files_found} files; the limit is supposed to "
        "be the walk's ceiling, not a number applied after it"
    )
    assert source.scan.max_files == 2
    assert source.scan.bound == "files", "stopping at the caller's cap is recorded"


def test_the_sources_limit_and_the_walks_bound_are_one_mechanism(tmp_path):
    """One ceiling, two spellings of it, and no way for them to disagree.

    The brittleness this removes was real: ``EmlDirectorySource`` bounded delivery
    while the walk underneath it ran unbounded, and the MCP tool had no bound at
    all -- two mechanisms that could, and did, disagree. Now ``limit`` is handed to
    the scan as its ``max_files``, so the same number stops the walk and caps the
    answer, and the pair is compared directly here.
    """
    names = []
    for index in range(5):
        name = f"mail_{index}.eml"
        shutil.copyfile(SYNTHETIC / "clean_internal_registrar.eml", tmp_path / name)
        names.append(name)

    for limit in (1, 3, 5):
        source = EmlDirectorySource(tmp_path)
        delivered = [item.external_id for item in source.fetch(limit=limit)]
        walked = [
            path.name
            for path in iter_eml_dir(tmp_path, max_files=limit, allow_partial=True)
        ][:limit]
        assert delivered == sorted(walked)[:limit], (
            f"limit={limit}: the source delivered {delivered}, the walk offered "
            f"{walked}; those are two bounds again"
        )
        assert len(delivered) == limit
        assert source.scan.max_files == limit
        assert source.scan.files_found <= limit


def test_a_limit_larger_than_the_default_bound_is_an_explicit_larger_walk(tmp_path):
    """Asking for more than the safety ceiling is honoured, and it is opt-in.

    A caller who names a number gets that number of files looked for. The default
    bound exists for callers who did not name one, and refusing a request that
    explicitly stated its own size would be the tool overruling its operator.
    """
    source = EmlDirectorySource(SYNTHETIC)
    asked = DEFAULT_MAX_EML_FILES + 500
    items = list(source.fetch(limit=asked))
    assert len(items) == 14
    assert source.scan.max_files == asked
    assert source.scan.bound is None, "a complete scan of a small corpus is complete"


def test_an_unbounded_fetch_of_an_overwhelming_directory_refuses(
    tmp_path, monkeypatch
):
    """No limit named, more files than the ceiling: a refusal, not a short answer.

    The reason is ``source_directory_bound`` -- recordable, like every other reason
    this contract emits -- and the detail names the bound, the directory and how to
    narrow it, because "0 messages" would read as an empty corpus.

    The ceiling is lowered rather than the corpus raised: what is under test is that
    ``fetch`` uses the module's own default as the walk's budget, and shipping 2,001
    files to prove that would cost more than the defect did.
    """
    monkeypatch.setattr(sources, "DEFAULT_MAX_EML_FILES", 4)
    for index in range(6):
        shutil.copyfile(
            SYNTHETIC / "clean_internal_registrar.eml",
            tmp_path / f"mail_{index}.eml",
        )
    with pytest.raises(SourceError) as exc:
        list(EmlDirectorySource(tmp_path).fetch(limit=None))
    assert exc.value.reason == "source_directory_bound"
    assert str(tmp_path) in exc.value.detail
    assert "bound" in exc.value.detail
    assert "4" in exc.value.detail, "the refusal names the ceiling it hit"
    assert "narrow" in exc.value.detail


def test_an_unbounded_fetch_of_a_deeper_directory_refuses(tmp_path):
    nested = tmp_path / "tree"
    target = nested
    for level in range(DEFAULT_MAX_EML_DEPTH + 1):
        target = target / f"l{level}"
    target.mkdir(parents=True)
    shutil.copyfile(
        SYNTHETIC / "clean_internal_registrar.eml", target / "buried.eml"
    )
    with pytest.raises(SourceError) as exc:
        list(EmlDirectorySource(nested).fetch())
    assert exc.value.reason == "source_directory_bound"
    assert "depth" in exc.value.detail


def test_a_zero_limit_walks_nothing_at_all():
    """Nothing asked for, nothing read: no walk, no scan, no items.

    A walk is the expensive part of intake. Running one to return zero items is the
    same shape of defect as running one to return the first two.
    """
    source = EmlDirectorySource(SYNTHETIC)
    assert list(source.fetch(limit=0)) == []
    assert source.scan is None


def test_a_fetch_records_what_it_saw_so_a_caller_can_audit_it():
    """``EmlDirectorySource.scan`` is the directory source's part of the audit trail.

    ``None`` before anything has been fetched: a caller must be able to tell "this
    source saw a complete corpus" from "this source never ran", and an empty scan
    object would blur exactly that line.
    """
    source = EmlDirectorySource(SYNTHETIC)
    assert source.scan is None
    list(source.fetch())
    assert source.scan is not None
    assert source.scan.complete is True
    assert source.scan.files_found == 14


def test_describe_states_the_requirements_not_just_the_platform():
    text = EmlDirectorySource(SYNTHETIC).describe()
    assert "no credentials" in text and "no network" in text


def test_describe_states_the_walk_bound_a_caller_is_bounded_by():
    """``EmailSource.describe`` owes the operator an honest account of its limits.

    The contract says a source must not silently return a different set than it was
    asked for without saying so here, so the two ceilings -- files and depth -- are
    in the sentence a caller reads before it calls.
    """
    text = EmlDirectorySource(SYNTHETIC).describe()
    assert "bounded" in text
    assert str(DEFAULT_MAX_EML_FILES) in text
    assert str(DEFAULT_MAX_EML_DEPTH) in text
    assert "symlink" in text


# --------------------------------------------------------------------------
# selection and refusal
# --------------------------------------------------------------------------


def test_an_unknown_source_names_what_is_available_and_where_to_look():
    with pytest.raises(SourceError) as exc:
        source_for("gmail")
    assert exc.value.reason == "unknown_source"
    assert DEFAULT_SOURCE in exc.value.detail
    assert "docs/ADAPTERS.md" in exc.value.detail, (
        "an operator asking for a platform we do not ship must be pointed at how to "
        "add it, not only told it is missing"
    )


def test_the_reference_source_requires_a_path_and_says_so():
    with pytest.raises(SourceError) as exc:
        source_for(DEFAULT_SOURCE)
    assert exc.value.reason == "source_path_required"


def test_selection_accepts_the_documented_aliases():
    for alias in ("eml-dir", "eml", "eml_dir", "directory", "EML-DIR"):
        source = source_for(alias, path=SYNTHETIC)
        assert isinstance(source, EmlDirectorySource)


def test_a_mutating_source_is_refused_at_selection_time():
    """Intake is read-only, and the guard is the real one.

    Driven through `register_source` and `source_for` rather than a restated copy of
    the check, because a test that reimplements the guard proves nothing about it.
    Registration deliberately does not bypass the rule: an adapter cannot opt out of
    read-only intake by registering itself.
    """

    class MarkingSource:
        name = "marks-what-it-reads"
        mutates = True

        def __init__(self, *, path=None):
            self.path = path

        def fetch(self, *, limit=None, since=None):
            yield SourceItem(external_id="x", raw=b"From: a@b.test\n\nbody\n")

        def describe(self) -> str:
            return "marks alerts as seen while reading them"

    register_source("marks-what-it-reads", MarkingSource)
    try:
        assert "marks-what-it-reads" in available_sources()
        with pytest.raises(SourceError) as exc:
            source_for("marks-what-it-reads", path="/tmp")
        assert exc.value.reason == "source_mutates"
        assert "approval gate" in exc.value.detail
        assert "marks-what-it-reads" in exc.value.detail
    finally:
        sources._REGISTRY.pop("marks-what-it-reads", None)


def test_registering_a_source_cannot_steal_a_builtin_name():
    for reserved in ("eml-dir", "eml", "directory"):
        with pytest.raises(SourceError) as exc:
            register_source(reserved, lambda *, path=None: None)
        assert exc.value.reason == "source_name_reserved"


def test_a_blank_source_name_is_refused():
    with pytest.raises(SourceError) as exc:
        register_source("   ", lambda *, path=None: None)
    assert exc.value.reason == "source_name_empty"


def test_a_registered_source_is_selectable_and_usable_end_to_end():
    """Proves registration is a real extension point, not decoration."""

    class OneMessageSource:
        name = "one-message"
        mutates = False

        def __init__(self, *, path=None):
            self.path = path

        def fetch(self, *, limit=None, since=None):
            yield SourceItem(
                external_id="only",
                raw=(REPO / "fixtures" / "synthetic" / sorted(
                    p.name for p in SYNTHETIC.glob("*.eml")
                )[0]).read_bytes(),
                source="one-message:only",
            )

        def describe(self) -> str:
            return "a registered source that yields one corpus message"

    register_source("one-message", OneMessageSource)
    try:
        source = source_for("one-message", path="ignored")
        assert isinstance(source, OneMessageSource)
        items = list(source.fetch())
        assert len(items) == 1
        assert triage_message(items[0].parse(), Config(replay=True, replay_dir=None))
    finally:
        sources._REGISTRY.pop("one-message", None)


def test_an_item_honours_a_configured_body_limit_instead_of_a_hardcoded_one():
    """The two intake paths must truncate at the same length.

    `triage_file` passes `config.thresholds.body_char_limit`. An adapter that
    restated 8000 would silently diverge the moment a deployment changed the
    threshold, and the divergence would show up as different verdicts for the same
    message depending on how it arrived.
    """
    raw = (SYNTHETIC / sorted(p.name for p in SYNTHETIC.glob("*.eml"))[0]).read_bytes()
    item = SourceItem(external_id="x", raw=raw, source="test:x")

    default_message = item.parse()
    tight_message = item.parse(body_char_limit=40)
    assert not default_message.body_truncated, (
        "the default limit should not truncate this fixture, or the test proves nothing"
    )
    # Nothing was cut, so there is no original length to report. Asserting equality
    # with the truncated case would be asserting that an omission was recorded when
    # nothing was omitted.
    assert default_message.original_body_length is None
    assert tight_message.body_truncated is True
    assert tight_message.original_body_length == len(default_message.text_body), (
        "a truncated parse must preserve the length it cut from, so a downstream "
        "stage can mark the analysis partial instead of reasoning over half a message"
    )


# --------------------------------------------------------------------------
# the contract is implementable by someone who is not us
# --------------------------------------------------------------------------


class InMemoryPlatformSource:
    """A source for a platform that does not exist, written only in this test.

    This is the test that decides whether `EmailSource` is an abstraction or a
    wrapper. It touches no engine code, imports no platform SDK, and cannot reach
    the network. If the engine's verdicts are identical through it and through the
    directory source, the seam is real.
    """

    name = "imaginary-platform"
    mutates = False

    def __init__(self, items):
        self._items = items

    def fetch(self, *, limit=None, since=None):
        for index, item in enumerate(self._items):
            if limit is not None and index >= limit:
                return
            yield item

    def describe(self) -> str:
        return "an in-memory platform used to prove the contract is implementable"


def _corpus_items():
    return [
        SourceItem(
            external_id=path.name,
            raw=path.read_bytes(),
            source=f"imaginary-platform:{path.name}",
            reporter="analyst@example.test",
            received_at="2026-11-01T09:00:00Z",
            metadata={"queue": "reported-phish", "platform_alert_id": f"al-{path.stem}"},
        )
        for path in sorted(SYNTHETIC.glob("*.eml"))
    ]


def test_a_third_party_source_satisfies_the_protocol_without_touching_the_engine():
    source = InMemoryPlatformSource(_corpus_items())
    assert isinstance(source, EmailSource), (
        "an implementation written outside the package must satisfy the protocol as "
        "declared, or the contract is not actually a contract"
    )
    assert source.mutates is False
    assert len(list(source.fetch())) == 14


def test_the_engine_verdict_does_not_depend_on_which_source_supplied_the_bytes():
    """The portability claim, measured rather than asserted.

    Same 14 messages through two different sources must produce the same
    disposition and confidence for every one. If a source could influence a verdict,
    the engine would not be provider-independent whatever the module layout said.
    """
    directory = {i.external_id: i for i in EmlDirectorySource(SYNTHETIC).fetch()}
    platform = {i.external_id: i for i in InMemoryPlatformSource(_corpus_items()).fetch()}

    assert set(directory) == set(platform)

    config = Config(replay=True, replay_dir=None)
    disagreements = []
    for external_id in sorted(directory):
        via_directory = triage_message(directory[external_id].parse(), config=config)
        via_platform = triage_message(platform[external_id].parse(), config=config)
        if (via_directory.disposition, via_directory.confidence) != (
            via_platform.disposition,
            via_platform.confidence,
        ):
            disagreements.append(
                f"{external_id}: {via_directory.disposition}/{via_directory.confidence} "
                f"vs {via_platform.disposition}/{via_platform.confidence}"
            )

    assert not disagreements, (
        "the verdict changed with the source, so the engine is not "
        "provider-independent:\n  " + "\n  ".join(disagreements)
    )


def test_the_source_verdicts_match_what_the_existing_file_path_produces():
    """Guards against the adapter quietly becoming a second intake implementation."""
    config = Config(replay=True, replay_dir=None)
    for item in EmlDirectorySource(SYNTHETIC).fetch():
        through_source = triage_message(item.parse(), config=config)
        through_file = triage_file(SYNTHETIC / item.external_id, config=config)
        assert through_source.disposition == through_file.disposition
        assert through_source.confidence == through_file.confidence


# --------------------------------------------------------------------------
# provenance is preserved, not reinterpreted
# --------------------------------------------------------------------------


def test_source_metadata_survives_onto_the_item_unchanged():
    items = _corpus_items()
    first = items[0]
    assert first.metadata["queue"] == "reported-phish"
    assert first.reporter == "analyst@example.test"
    assert first.received_at == "2026-11-01T09:00:00Z"


def test_external_id_is_not_the_rfc_822_message_id():
    """Conflating them would make a lookup key out of attacker-controlled data.

    The header is routinely absent, duplicated or forged; the source's own
    identifier is not. They are separate fields for that reason, and a source with
    no usable header must still be addressable.
    """
    raw = b"Subject: no message-id header here\r\n\r\nbody\r\n"
    item = SourceItem(external_id="platform-42", raw=raw, source="test:platform-42")
    message = item.parse()
    assert item.external_id == "platform-42"
    assert message.message_id == ""
    assert message.source == "test:platform-42"


def test_an_unparseable_message_is_still_an_item_the_engine_can_report_on():
    """A message we cannot parse is still a message someone reported.

    The parser does not raise on garbage - it treats an unstructured blob as a body,
    which is what RFC 5322 leaves room for. What matters here is that intake hands
    the engine something it can disposition rather than an exception, and that the
    provenance label survives so the result can still say where it came from.
    """
    item = SourceItem(external_id="garbage", raw=b"\x00\x01not a message", source="t:g")
    message = item.parse()
    assert message.source == "t:g"
    assert message.body_truncated is False

    verdict = triage_message(message, Config(replay=True, replay_dir=None))
    assert verdict is not None
    assert verdict.disposition is not None, (
        "an unparseable report must still produce a disposition, even if it is only "
        "manual_review - raising here would drop a message someone reported"
    )


def test_the_item_is_immutable_so_provenance_cannot_be_edited_downstream():
    item = SourceItem(external_id="x", raw=b"From: a@b.test\n\nbody\n")
    with pytest.raises(Exception):
        item.external_id = "y"  # type: ignore[misc]


# --------------------------------------------------------------------------
# reachable from the CLI, because an abstraction nothing can call is dead code
# --------------------------------------------------------------------------


def _run(argv):
    from tenable_email import cli

    return cli.main(argv)


def test_the_cli_source_path_produces_the_same_dispositions_as_the_default_path():
    """The wiring must not change an answer.

    `run PATH` and `run PATH --source eml-dir` are the same intake reached two ways,
    so they must agree message for message. If they ever diverge, one of the two paths
    has grown its own behaviour.
    """
    import io
    import contextlib

    def capture(argv):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = _run(argv)
        return code, buffer.getvalue()

    default_code, default_out = capture(["run", str(SYNTHETIC)])
    source_code, source_out = capture(["run", str(SYNTHETIC), "--source", "eml-dir"])

    assert default_code == source_code == 0
    assert default_out == source_out, (
        "the same corpus through the adapter contract produced different output than "
        "the default path"
    )


def test_the_cli_refuses_a_source_it_does_not_have_and_points_at_the_guide():
    import io
    import contextlib

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        code = _run(["run", str(SYNTHETIC), "--source", "microsoft-365"])
    text = buffer.getvalue()

    assert code != 0
    assert "unknown_source" in text
    assert "docs/ADAPTERS.md" in text, (
        "an operator asking for a platform we do not ship must be sent to how to add "
        "it, not only told it is missing"
    )


def test_the_cli_limit_bounds_how_many_messages_are_triaged():
    import io
    import contextlib

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        code = _run(["run", str(SYNTHETIC), "--limit", "3"])
    text = buffer.getvalue()

    assert code == 0
    assert "total                 3" in text, text


def test_a_registered_source_is_reachable_from_the_cli():
    """Registration is a real extension point: name it and the CLI will use it."""
    import io
    import contextlib

    class RegisteredSource:
        name = "registered-demo"
        mutates = False

        def __init__(self, *, path=None):
            self.path = path

        def fetch(self, *, limit=None, since=None):
            first = sorted(SYNTHETIC.glob("*.eml"))[0]
            yield SourceItem(
                external_id=first.name,
                raw=first.read_bytes(),
                source=f"registered-demo:{first.name}",
            )

        def describe(self) -> str:
            return "a source registered from a test"

    register_source("registered-demo", RegisteredSource)
    try:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = _run(["run", str(SYNTHETIC), "--source", "registered-demo"])
        text = buffer.getvalue()
        assert code == 0
        assert "total                 1" in text, text
    finally:
        sources._REGISTRY.pop("registered-demo", None)
