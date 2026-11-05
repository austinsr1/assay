"""The CLI: what a reviewer types, and what it must never need (D0, D1, D7).

Everything here is driven through :func:`tenable_email.cli.main` -- the same
callable the declared console script points at -- and the assertions are about the
contract a stranger experiences: ``demo`` with no arguments and no network prints
fourteen rows and honest agreement; ``--replay-dir`` defaults to the committed
corpus; a missing corpus is announced rather than silently deterministic; each
subcommand's ``--help`` works; the wrappers call the tools instead of copying them;
and ``--strict`` fails a timer run that an operator would otherwise read as clean.

The no-network assertions are made at the transport seam, the same way
``tests/test_offline_default_path.py`` makes them, because a CLI that reaches for
a host a judge cannot resolve is a CLI whose demo does not run.
"""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email import cli  # noqa: E402
from tenable_email.config import Config, default_replay_dir  # noqa: E402
from tenable_email.parse import (  # noqa: E402
    DEFAULT_MAX_EML_DEPTH,
    DirectoryScanError,
    parse_file,
)
from tenable_email.receipt import Receipt  # noqa: E402
from tenable_email.replay import ReplayStore, build_entry  # noqa: E402
from tenable_email.tiers import FraudFoxTier  # noqa: E402

FIXTURES = REPO / "fixtures" / "synthetic"
LABELS = FIXTURES / "labels.json"
THREAT_FIXTURE = FIXTURES / "threat_lookalike_credential_harvest.eml"
COMMANDS = ("run", "show", "record", "validate-contract", "demo")


def block_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("the offline CLI reached the network")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:1")


# --- D1: the entry point exists and resolves --------------------------------


def test_the_declared_console_script_resolves_to_a_callable():
    """pyproject names ``tenable_email.cli:main``; that attribute must be real.

    Checked on the declaration and on the import, not on an installed script, so
    a rename of either half fails here rather than in a reviewer's shell.
    """
    declared = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert 'tenable-email = "tenable_email.cli:main"' in declared
    assert callable(cli.main)
    assert cli.main.__module__ == "tenable_email.cli"


def test_the_module_entry_point_runs(tmp_path):
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "tenable_email", "run", str(THREAT_FIXTURE),
         "--out", str(tmp_path)],
        cwd=REPO, capture_output=True, text=True,
        env={"PYTHONPATH": str(REPO / "src"), "PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr[-400:]
    assert "threat" in result.stdout
    assert "closed" in result.stdout


def test_every_subcommand_documents_itself(capsys):
    """Each subcommand's --help works: a reviewer can explore without a README.

    argparse raises SystemExit(0) on --help rather than returning, which is the
    behaviour a shell expects, so that is what is asserted here.
    """
    with pytest.raises(SystemExit) as top:
        cli.main(["--help"])
    assert top.value.code == cli.EXIT_OK
    help_text = capsys.readouterr().out
    assert "usage" in help_text.lower()
    for command in COMMANDS:
        with pytest.raises(SystemExit) as exitinfo:
            cli.main([command, "--help"])
        assert exitinfo.value.code == cli.EXIT_OK
        body = capsys.readouterr().out
        assert "usage" in body.lower(), f"{command} --help printed no usage line"
        assert command in body.lower(), f"{command} --help lost its own name"


# --- D0: the corpus is the default, and its absence is announced ------------


def test_replay_dir_defaults_to_the_committed_corpus(monkeypatch):
    calls = []

    def resolver():
        calls.append(1)
        return "the/resolved/corpus"

    corpus = cli.resolve_corpus(None, resolver=resolver)
    assert corpus.replay_dir == "the/resolved/corpus"
    assert corpus.resolved_by_default and not corpus.note
    assert calls == [1], "the default must come from the resolver, once"
    assert cli.resolve_corpus(str(FIXTURES), resolver=resolver).replay_dir == str(
        FIXTURES
    ), "an explicit --replay-dir is honoured, not overridden"
    assert cli.resolve_corpus(None, live=True).replay_dir is None


def test_the_default_the_parser_hands_over_is_the_repository_corpus():
    """The flag default is ``None``, which *means* "use the resolver".

    A literal default baked into the parser would be a second place to be wrong;
    ``resolve_corpus`` is the only place the resolution happens.
    """
    parser = cli.build_parser()
    args = parser.parse_args(["demo"])
    assert args.replay_dir is None
    corpus = cli.resolve_corpus(args.replay_dir)
    assert Path(corpus.replay_dir).resolve() == (REPO / "fixtures" / "replay").resolve()
    assert corpus.replay_dir == default_replay_dir()


def test_a_missing_corpus_prints_one_clear_line_and_records_unavailable(
    tmp_path, capsys, monkeypatch
):
    """Installed-wheel degradation: no fixtures, no failure, no fabrication."""
    monkeypatch.setattr(cli, "default_replay_dir", lambda: None)
    target = tmp_path / "messages"
    target.mkdir()
    for path in sorted(FIXTURES.glob("*.eml"))[:3]:
        (target / path.name).write_bytes(path.read_bytes())

    out = tmp_path / "out"
    code = cli.main(["run", str(target), "--out", str(out)])
    printed = capsys.readouterr()
    assert code == cli.EXIT_OK, "a missing corpus is a degraded run, not an error"
    assert "corpus not found" in printed.err + printed.out
    assert "UNAVAILABLE" in printed.err + printed.out
    records = sorted((out / "receipts").glob("*.json"))
    assert len(records) == 3
    for path in records:
        receipt = Receipt.load(path)
        assert receipt.counts()["model_judgment"] == 0, (
            f"{path.name}: model opinions with no corpus means invented answers"
        )
        assert receipt.counts()["unavailable"] > 0, (
            f"{path.name}: the tiers that did not run must be recorded as such"
        )


def test_a_missing_corpus_does_not_change_a_deterministic_disposition(
    capsys, monkeypatch, tmp_path
):
    monkeypatch.setattr(cli, "default_replay_dir", lambda: None)
    code = cli.main(["demo", "--fixtures", str(FIXTURES), "--out", str(tmp_path)])
    printed = capsys.readouterr()
    assert code == cli.EXIT_OK
    assert "corpus not found" in printed.err + printed.out
    assert "no corpus" in printed.out, "both columns are still printed and labelled"


# --- D1/D7: demo ------------------------------------------------------------


def test_demo_needs_no_arguments_and_prints_the_corpus_table(capsys):
    assert cli.main(["demo"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    cases = [
        line for line in out.splitlines()
        if line.startswith("  ") and any(
            line.strip().startswith(f"{fixture.stem} ")
            for fixture in FIXTURES.glob("*.eml")
        )
    ]
    assert len(cases) == 14, f"expected 14 rows, found {len(cases)}\n{out}"
    assert "label agreement" in out
    assert "dispositions" in out
    assert "escalated" in out, "the separate escalation count must be printed"


def test_demo_reports_an_escalation_on_a_threat_label_as_its_own_count(capsys):
    """manual_review on a threat fixture: not agreement, not a miss.

    The corpus contains two of them, so the separate count is exercised by real
    cases rather than by a stub, and the sum of the three buckets still equals the
    corpus.
    """
    assert cli.main(["demo"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    agreement = next(line for line in out.splitlines() if line.startswith("label agreement"))
    escalated = int(agreement.split("escalated")[0].split()[-1])
    assert escalated >= 1, (
        "the corpus is expected to produce escalations on threat labels; if it "
        "stopped, that is the news and this assertion should move with an argument"
    )
    agree = int(agreement.split("agree,")[0].split(":")[1].split("/")[0])
    disagreed = int(agreement.split("disagree")[0].split(",")[-1].strip().split()[0])
    assert agree + escalated + disagreed == 14, (
        f"{agree} agree + {escalated} escalated + {disagreed} disagreed must be "
        f"the whole corpus"
    )
    assert "not counted as agreement" in agreement


def test_demo_runs_with_no_network_and_no_configuration(capsys, monkeypatch):
    block_network(monkeypatch)
    assert cli.main(["demo"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "no endpoints, no network, no credentials" in out
    assert out.count("REFUSED") == 0, "the corpus cases must all close"


def test_demo_json_output_is_machine_readable(capsys):
    assert cli.main(["demo", "--format", "json"]) == cli.EXIT_OK
    printed = capsys.readouterr()
    payload = json.loads(printed.out)
    assert len(payload["rows"]) == 14
    counts = payload["agreement"]
    assert counts["agree"] + counts["escalated_on_threat_label"] + counts["disagree"] == 14
    assert counts["agree"] == 10, (
        "the shipped corpus agrees on ten of fourteen; if this moved, the "
        "recordings or the rules moved with it"
    )
    assert payload["refusals"] == []
    assert "corpus not found" not in printed.out
    assert "corpus not found" not in printed.err


def test_demo_labels_come_from_the_manifest_not_from_the_code(capsys):
    """The label column is read off labels.json, so the demo cannot flatter itself."""
    assert cli.main(["demo"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    manifest = {row["file"]: row["label"] for row in json.loads(LABELS.read_text())}
    shown = 0
    for line in out.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        fields = stripped.split()
        if len(fields) < 4 or fields[0] == "case":
            continue
        case = fields[0]
        for name, label in manifest.items():
            if name[:-len(".eml")] == case:
                assert fields[1] == label, f"{case}: printed {fields[1]}, manifest {label}"
                shown += 1
    assert shown == 14, f"only {shown} rows were matched to the manifest"
    assert list(manifest.values()).count("threat") == 8


# --- D1: run ----------------------------------------------------------------


def test_run_over_a_directory_prints_a_line_per_message_and_a_summary(
    capsys, monkeypatch
):
    block_network(monkeypatch)
    assert cli.main(["run", str(FIXTURES)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "summary by disposition" in out
    for disposition in ("threat", "spam", "clean", "manual_review", "unknown"):
        assert disposition in out
    per_message = [
        line for line in out.splitlines()
        if line.strip().endswith("closed") and "case(s)" not in line
    ]
    assert len(per_message) == 14, out
    assert all("judgment" in line for line in per_message), (
        "each line has to say how much of the answer came from the recordings"
    )


def test_run_over_a_single_file_reports_the_disposition(capsys):
    assert cli.main(["run", str(THREAT_FIXTURE)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "threat" in out and "CREDENTIAL_HARVEST" in out
    assert "replay corpus:" in out, "the run must say which corpus answered"


def test_run_out_writes_one_case_record_per_message_and_show_reads_them(capsys, tmp_path):
    out_dir = tmp_path / "records"
    assert cli.main(["run", str(FIXTURES), "--out", str(out_dir)]) == cli.EXIT_OK
    records = sorted((out_dir / "receipts").glob("*.json"))
    assert len(records) == 14
    assert (out_dir / "journal.jsonl").is_file(), "the run must be resumable"
    markdown = sorted((out_dir / "receipts").glob("*.md"))
    assert len(markdown) == 14

    capsys.readouterr()
    assert cli.main(["show", str(records[0])]) == cli.EXIT_OK
    shown = capsys.readouterr().out
    for heading in ("Case record", "Verified facts", "Model judgments", "Unknowns"):
        assert heading in shown


def test_show_reads_a_record_back_without_the_message_being_present(tmp_path, capsys):
    assert cli.main(["run", str(THREAT_FIXTURE), "--out", str(tmp_path)]) == 0
    record = next((tmp_path / "receipts").glob("*.json"))
    capsys.readouterr()
    assert cli.main(["show", str(record), "--json"]) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["receipt_id"] == record.stem
    assert payload["digests"]["corpus_manifest_digest"]
    body = " ".join(parse_file(THREAT_FIXTURE).body.split())
    assert body not in json.dumps(payload)


def test_show_reports_a_missing_or_unreadable_record(tmp_path, capsys):
    assert cli.main(["show", str(tmp_path / "nope.json")]) == cli.EXIT_ERROR
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert cli.main(["show", str(broken)]) == cli.EXIT_ERROR
    rendered = tmp_path / "case.md"
    rendered.write_text("# markdown", encoding="utf-8")
    assert cli.main(["show", str(rendered)]) == cli.EXIT_ERROR
    assert "already" in capsys.readouterr().err


def test_run_json_mode_prints_only_json(capsys):
    assert cli.main(["run", str(FIXTURES), "--format", "json"]) == cli.EXIT_OK
    printed = capsys.readouterr()
    payload = json.loads(printed.out)
    assert len(payload["records"]) == 14
    assert payload["summary"]["closed"] == 14
    assert "replay corpus" not in printed.out, "notes belong on stderr"
    assert "replay corpus" in printed.err


def test_run_fails_clearly_on_a_path_that_is_not_there(capsys, tmp_path):
    assert cli.main(["run", str(tmp_path / "absent")]) == cli.EXIT_ERROR
    assert "ERROR" in capsys.readouterr().err


def test_run_on_an_empty_directory_reports_nothing_to_do(capsys, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.main(["run", str(empty)]) == cli.EXIT_ERROR
    assert "no .eml files" in capsys.readouterr().err


# --- strict mode -----------------------------------------------------------


def test_strict_exits_two_when_a_message_could_not_be_read(tmp_path, capsys):
    unreadable = tmp_path / "messages"
    unreadable.mkdir()
    (unreadable / "nothing.eml").write_bytes(b"\r\n")
    code = cli.main(["run", str(unreadable), "--strict"])
    printed = capsys.readouterr()
    assert code == cli.EXIT_STRICT
    assert "UNKNOWN" in printed.err
    # Without --strict the same run succeeds: a reviewer still gets the answer.
    assert cli.main(["run", str(unreadable)]) == cli.EXIT_OK


def test_strict_exits_two_when_the_runner_refuses_a_receipt(tmp_path, capsys):
    """A fabricated recording makes the case unclosable; --strict must say so."""
    store = ReplayStore(root=tmp_path / "corpus")
    tier = FraudFoxTier()
    config = Config()
    model = tier.model_id(config)
    store.put_response(
        tier=tier.name, model=model, payload=tier.prepare({"text": "seed"}, config),
        response={"verdict": "SAFE", "safe_score": 0.9},
        endpoint_role="onnx-classifier",
    )
    entry = build_entry(
        tier=tier.name,
        model=model,
        payload=tier.prepare({"text": parse_file(THREAT_FIXTURE).body}, config),
        response={"verdict": "SAFE", "safe_score": 0.99},
        endpoint_role="hand-written",
    )
    (tmp_path / "corpus" / store.file_name(tier.name, entry["key"])).write_text(
        json.dumps(entry, sort_keys=True), encoding="utf-8"
    )

    code = cli.main(
        ["run", str(THREAT_FIXTURE), "--replay-dir", str(tmp_path / "corpus"),
         "--strict", "--out", str(tmp_path / "out")]
    )
    printed = capsys.readouterr()
    assert code == cli.EXIT_STRICT, printed.out + printed.err
    assert "closure-refused" in printed.out
    assert "simulated" in printed.out


# --- the wrappers call the tools -------------------------------------------


def test_validate_contract_wrapper_reports_a_valid_contract(capsys):
    assert cli.main(["validate-contract"]) == cli.EXIT_OK
    assert "contract OK" in capsys.readouterr().out


def test_record_wrapper_delegates_rather_than_duplicating(capsys, monkeypatch):
    """A wrapper that reimplemented recording would drift from it in silence.

    The tool is replaced by a recorder here, so what is asserted is the delegation
    itself: the exit code is the tool's, and the arguments arrive at the tool.
    """
    seen: list[list[str]] = []

    def fake_main(argv=None):
        seen.append(list(argv or []))
        return 7

    monkeypatch.setattr(cli, "_tool_main", lambda name: fake_main)
    assert cli.main(["record", "--dry-run", "--quiet"]) == 7
    assert seen == [["--dry-run", "--quiet"]], "the flags must reach the tool"

    seen.clear()
    assert cli.main(["record", "--store", "my/corpus"]) == 7
    assert seen == [["--store", "my/corpus"]], (
        "--store has to be translated into the tool's own flag"
    )


def test_record_wrapper_degrades_when_the_tool_is_absent(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_tool_main", lambda name: None)
    assert cli.main(["record"]) == cli.EXIT_ERROR
    assert "not present" in capsys.readouterr().err
    assert cli.main(["validate-contract"]) == cli.EXIT_ERROR


def test_the_record_tool_itself_reports_the_dry_run(capsys, monkeypatch):
    """A real invocation with no endpoints: nothing recorded, nothing invented."""
    for name in list(monkeypatch.__dict__ or []):
        pass
    for variable in (
        "TENABLE_EMAIL_FRAUDFOX_URL", "TENABLE_EMAIL_SECMODELS_URL",
        "TENABLE_EMAIL_LLM_URL", "TENABLE_EMAIL_VLM_URL",
    ):
        monkeypatch.delenv(variable, raising=False)
    block_network(monkeypatch)
    assert cli.main(["record", "--dry-run"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "unconfigured tiers" in out, (
        "the wrapper has to reach the tool's own report, not a summary of it"
    )


# --- provider selection from the CLI --------------------------------------


def test_an_unknown_writeback_provider_is_refused_not_downgraded(capsys):
    assert cli.main(["run", str(THREAT_FIXTURE), "--provider", "gmail-labels"]) == 1
    assert "open decision 2" in capsys.readouterr().err


def test_no_args_prints_help_and_exits_nonzero(capsys):
    assert cli.main([]) == cli.EXIT_ERROR
    assert "usage" in capsys.readouterr().out.lower()


def test_version_flag(capsys):
    assert cli.main(["--version"]) == cli.EXIT_OK
    assert "tenable-email" in capsys.readouterr().out


def test_the_cli_does_not_reach_the_network_in_its_default_mode(monkeypatch, capsys, tmp_path):
    block_network(monkeypatch)
    assert cli.main(["run", str(FIXTURES), "--out", str(tmp_path)]) == cli.EXIT_OK
    assert cli.main(["demo"]) == cli.EXIT_OK
    assert cli.main(["validate-contract"]) == cli.EXIT_OK
    capsys.readouterr()




# --- the bounded directory walk -------------------------------------------


def _corpus(tmp_path, count=2, name="corpus"):
    """A directory of copied fixture messages, so a test owns its own corpus."""
    directory = tmp_path / name
    directory.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        (directory / f"mail_{index:03d}.eml").write_bytes(
            (FIXTURES / "clean_internal_registrar.eml").read_bytes()
        )
    return directory


def _deep_corpus(tmp_path, levels=None):
    """A corpus whose only message sits below the depth bound, plus one above it."""
    levels = levels if levels is not None else DEFAULT_MAX_EML_DEPTH
    directory = tmp_path / "deep"
    target = directory
    for level in range(levels + 1):
        target = target / f"level_{level}"
    target.mkdir(parents=True)
    (directory / "top.eml").write_bytes(
        (FIXTURES / "clean_internal_registrar.eml").read_bytes()
    )
    (target / "buried.eml").write_bytes(
        (FIXTURES / "clean_internal_registrar.eml").read_bytes()
    )
    return directory


def test_messages_in_is_the_bounded_walk_and_not_a_second_ceiling(tmp_path):
    """The CLI's own view of a corpus goes through the same bound as intake's.

    Two walkers of one directory -- one bounded, one not -- is how a fixed defect
    comes back: this one asserts the counts agree with the source's.
    """
    directory = _corpus(tmp_path, 3)
    assert [p.name for p in cli.messages_in(directory)] == [
        "mail_000.eml",
        "mail_001.eml",
        "mail_002.eml",
    ]
    assert [p.name for p in cli.messages_in(directory, limit=2)] == [
        "mail_000.eml",
        "mail_001.eml",
    ]
    assert cli.messages_in(directory, limit=0) == []
    single = directory / "mail_000.eml"
    assert cli.messages_in(single) == [single], "a file argument is one message"


def test_messages_in_refuses_a_directory_it_cannot_fully_read(tmp_path):
    directory = _deep_corpus(tmp_path)
    with pytest.raises(DirectoryScanError) as caught:
        cli.messages_in(directory)
    assert "bound" in str(caught.value)
    assert str(directory) in str(caught.value)


def test_run_refuses_a_directory_deeper_than_the_bound_loudly(capsys, tmp_path):
    """ERROR, a non-zero exit, and the bound in the sentence -- not zero rows.

    The defect this replaces was quieter than it looks: a caller could point
    ``run`` at a filesystem root and get an answer for mail in other people's
    directories. Refusing is only safe if it is legible, so the message has to
    name the bound, the directory and how to narrow.
    """
    directory = _deep_corpus(tmp_path)
    assert cli.main(["run", str(directory)]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "ERROR" in err
    assert "bound" in err, err
    assert str(directory) in err, err
    assert "narrow" in err, err
    assert "buried" not in err, "a refused scan must not have triaged the deep file"


def test_run_reports_that_a_limited_run_is_a_partial_reading(capsys, tmp_path):
    """``--limit`` is the explicit opt-in to a bounded scan, so it is stated.

    A cap that is not mentioned reads as a whole corpus of three messages, which
    is the same defect as a silently truncated walk: the run has to say which of
    the two it was.
    """
    directory = _corpus(tmp_path, 4)
    assert cli.main(["run", str(directory), "--limit", "2"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "partial reading" in out, out
    assert "--limit 2" in out, out


def test_run_without_a_limit_does_not_claim_a_partial_reading(capsys, tmp_path):
    directory = _corpus(tmp_path, 2)
    assert cli.main(["run", str(directory)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "partial reading" not in out, (
        "a complete scan must not be labelled as a partial one"
    )


def test_demo_refuses_a_fixtures_directory_it_cannot_fully_read(capsys, tmp_path):
    """``demo --fixtures`` takes an operator path, so it takes the same bound."""
    directory = _deep_corpus(tmp_path)
    assert cli.main(["demo", "--fixtures", str(directory)]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "ERROR" in err and "bound" in err and str(directory) in err
