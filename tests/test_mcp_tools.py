"""Every MCP tool function, tested as plain Python with nothing installed.

These tests never import ``mcp``. That is the point of the split in
``src/tenable_email/mcpserver.py``: if the tool logic could only be exercised
with the optional extra present, then the claim that the core has **no runtime
dependencies** would be unfalsifiable -- and the question a reviewer asks about
any zero-dependency claim is "says who". So this module checks the shape of each
tool's answer, its behaviour with no endpoints and no network, its error
handling, and the two properties that make the surface safe to hand to an agent:
nothing leaves with the message inside it, and nothing it does changes state.

The mutation check is a snapshot rather than a source inspection. The tools are
called against a working directory, the replay corpus, the fixture corpus and the
committed evidence artifacts, all four hashed before and after with sockets
blocked at the transport seam -- which is the same proof
``tests/test_runner.py`` accepts for the runner and the only one that means
something about a function that *looks* read-only.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import inspect
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
FIXTURES = REPO / "fixtures" / "synthetic"
REPLAY = REPO / "fixtures" / "replay"
EVIDENCE = REPO / "docs" / "results"
SKILL = REPO / "SKILL.md"
LISTING = REPO / "docs" / "listing-drafts" / "mcp-server.md"
STAGES = REPO / "stages.yaml"
PYPROJECT = REPO / "pyproject.toml"
README = REPO / "README.md"
TOOL_SOURCE = SRC / "tenable_email" / "mcpserver.py"

sys.path.insert(0, str(SRC))

from tenable_email import cli, mcpserver  # noqa: E402
from tenable_email.config import Config  # noqa: E402
from tenable_email.contract import load_contract  # noqa: E402
from tenable_email.parse import (  # noqa: E402
    DEFAULT_MAX_EML_DEPTH,
    DEFAULT_MAX_EML_FILES,
    parse_file,
)
from tenable_email.pipeline import triage_file  # noqa: E402
from tenable_email.receipt import Receipt  # noqa: E402
from tenable_email.replay import canonical_json  # noqa: E402

FIXTURE_PATHS = sorted(FIXTURES.glob("*.eml"))
SAMPLE = FIXTURES / "threat_lookalike_credential_harvest.eml"
BEC = FIXTURES / "threat_bec_valid_auth.eml"
FORWARDED = FIXTURES / "threat_image_credential_harvest.eml"

#: Characters of a body line that count as message content rather than as prose
#: *about* the content. The same bound ``tests/test_receipt.py`` holds a case
#: record to, so the two surfaces are judged by one standard and not by two that
#: happen to differ.
BODY_FRAGMENT = 30

#: The tools that take a message, and so are the ones a body could leave through.
MESSAGE_TOOLS = ("analyze_eml", "check_auth", "classify_local")
DIRECTORY_TOOL = "analyze_eml_directory"

#: A Safe Links wrapper around a destination that belongs to nobody, in the shape
#: a reported message carries it: percent-encoded, with the wrapper's own query
#: parameters.
SAFE_LINKS = (
    "https://safelinks.protection.outlook.com/?url=https%3A%2F%2F"
    "deposit-confirm.test%2Fverify&data=05%7C01%7Cnope&reserved=x"
)

#: ``(tool name -> positional arguments)`` for the sweep tests.
CASES: dict[str, tuple] = {
    "analyze_eml": (str(SAMPLE),),
    "analyze_eml_directory": (str(FIXTURES),),
    "check_auth": (str(SAMPLE),),
    "lookalike_domain": ("example-portal-verify.com",),
    "analyze_urls": ([SAFE_LINKS], "mail.example.edu"),
    "classify_local": (str(SAMPLE),),
    "list_contracts": (),
}


def call(name: str, *args, **kwargs) -> dict:
    """Invoke a tool by its advertised name, the way a client would."""
    function = getattr(mcpserver, name)
    assert callable(function), f"{name} is advertised but is not callable"
    return function(*args, **kwargs)


def walk_keys(value, depth: int = 0) -> set[str]:
    """Every mapping key at any depth, so a leak cannot hide in a sub-object."""
    keys: set[str] = set()
    if depth > 12:
        return keys
    if isinstance(value, dict):
        for key, nested in value.items():
            keys.add(str(key))
            keys |= walk_keys(nested, depth + 1)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            keys |= walk_keys(nested, depth + 1)
    return keys


def assert_envelope(result: dict, name: str) -> dict:
    """The one response shape, in both directions.

    ``canonical_json`` is used rather than ``json.dumps``: it is strict, so a
    ``bytes`` value raises instead of being stringified into a response, and it
    refuses ``NaN``, so a score that was never a number cannot travel as one.
    """
    assert isinstance(result, dict), f"{name} returned {type(result).__name__}"
    for key in ("ok", "tool", "error"):
        assert key in result, f"{name} is missing envelope key {key!r}"
    assert result["tool"] == name
    if result["ok"]:
        assert result["error"] is None, "a success cannot carry an error"
    else:
        error = result["error"]
        assert isinstance(error, dict), "errors are structured, not strings"
        assert {"code", "type", "message"} <= set(error)
        assert error["message"], "an error has to say what went wrong"
    text = canonical_json(result)
    assert text, f"{name} serialized to nothing"
    return result


def run_a_case(tmp_path: Path, name: str = "threat_bec_valid_auth.eml"):
    """Produce a real case record through the real CLI, in a tmp directory.

    stdout is swallowed rather than printed: this exercises ``run --out``, and the
    report it emits is not this test's claim.
    """
    directory = tmp_path / "run"
    directory.mkdir(parents=True, exist_ok=True)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        code = cli.main(["run", str(FIXTURES / name), "--out", str(directory)])
    assert code == 0, buffer.getvalue()[-600:]
    records = sorted((directory / "receipts").glob("*.json"))
    assert records, "the CLI wrote no case record"
    return records[0].name[: -len(".json")], records[0], directory


# --------------------------------------------------------------------------
# the surface: nine tools, plain functions, no dependency required
# --------------------------------------------------------------------------


def test_every_advertised_tool_is_a_plain_python_function():
    assert len(mcpserver.TOOL_ORDER) == 9
    assert len(set(mcpserver.TOOL_ORDER)) == 9, "duplicate tool name"
    assert set(mcpserver.TOOL_ORDER) == set(mcpserver.TOOL_DESCRIPTIONS)
    assert set(mcpserver.TOOL_ORDER) == set(mcpserver.MCP_WRAPPERS)
    assert set(CASES) <= set(mcpserver.TOOL_ORDER), (
        "CASES names a tool that is not advertised"
    )
    for name in mcpserver.TOOL_ORDER:
        function = getattr(mcpserver, name, None)
        assert callable(function), f"{name} is not importable without mcp"
        assert function.__module__ == "tenable_email.mcpserver"
        assert mcpserver.TOOL_DESCRIPTIONS[name], f"{name} has no description"


def test_wrapper_signatures_match_the_advertised_arguments():
    """The schema a client is given has to be the function that exists.

    ``TOOL_ARGUMENTS`` is what README and the listing describe, the wrapper is
    what FastMCP validates against, and the tool is what does the work. All
    three are compared here, because a parameter added to one of them and not the
    others is exactly the drift nobody notices until a client's call fails.
    """
    for name, arguments in mcpserver.TOOL_ARGUMENTS.items():
        function = getattr(mcpserver, name)
        wrapper = mcpserver.MCP_WRAPPERS[name]
        for target in (function, wrapper):
            parameters = inspect.signature(target).parameters
            assert list(parameters) == list(arguments), (
                f"{name}: {target.__name__} takes {list(parameters)}, "
                f"advertised as {list(arguments)}"
            )
            for parameter, label in parameters.items():
                assert str(label.annotation) == arguments[parameter], (
                    f"{name}.{parameter} is advertised as "
                    f"{arguments[parameter]!r}, annotated {label.annotation!r}"
                )
        assert str(inspect.signature(wrapper).return_annotation) in (
            "dict", "<class 'dict'>"
        ), (
            f"{name}: a wrapper must return a dict, which is what the boundary "
            "promises a client"
        )


def test_the_extra_is_imported_inside_one_function_and_nowhere_at_module_scope():
    """``dependencies = []`` is only honest if nothing needs the package to import.

    Checked as syntax rather than as a grep, because an import inside a function
    is precisely what the design requires and a line-matching test would either
    forbid it or miss it depending on how the pattern was written today.
    """
    tree = ast.parse(TOOL_SOURCE.read_text(encoding="utf-8"))

    def is_mcp(node) -> bool:
        if isinstance(node, ast.Import):
            return any(a.name.split(".")[0] == "mcp" for a in node.names)
        if isinstance(node, ast.ImportFrom):
            return bool(node.module) and node.module.split(".")[0] == "mcp"
        return False

    assert not [n for n in tree.body if is_mcp(n)], (
        "mcp must not be imported at module scope"
    )
    nested = {
        (node.name, getattr(n, "module", None) or ",".join(
            a.name for a in getattr(n, "names", [])
        ))
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        for n in ast.walk(node)
        if is_mcp(n)
    }
    assert {name for name, _module in nested} == {"_fastmcp_class"}, (
        f"mcp is imported inside {sorted({name for name, _ in nested})}; the "
        "dependency may be touched in exactly one place"
    )
    assert {module for _name, module in nested} == {
        "mcp.server.fastmcp", "mcp.server.mcpserver"
    }, (
        "the wrapper resolves the class where 1.x and 2.x each keep it; a third "
        "location means the compatibility shim is being guessed at"
    )

    allowed = {
        "__future__", "argparse", "html", "json", "pathlib", "sys", "typing",
        "urllib.parse",
    }
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.level:
            continue  # relative imports are this package's own modules
        modules = (
            [a.name for a in node.names]
            if isinstance(node, ast.Import)
            else [node.module or ""]
            if isinstance(node, ast.ImportFrom)
            else []
        )
        for module in modules:
            assert module in allowed, (
                f"mcpserver imports {module!r} at module scope: the server must "
                "not add a runtime dependency to a dependency-free package"
            )


def test_pyproject_declares_the_script_and_keeps_the_core_dependency_free():
    text = PYPROJECT.read_text(encoding="utf-8")
    assert 'tenable-email-mcp = "tenable_email.mcpserver:main"' in text, (
        "the documented console script must be declared"
    )
    assert 'tenable-email = "tenable_email.cli:main"' in text
    assert "dependencies = []" in text, "the runtime dependency list stays empty"
    before_extras = text.split("[project.optional-dependencies]")[0]
    assert not re.search(r"^\s*mcp\s*=", before_extras, re.MULTILINE), (
        "mcp belongs under the extra only"
    )
    extras = text.split("[project.optional-dependencies]")[1].split(
        "[project.scripts]"
    )[0]
    assert re.search(r'^mcp = \["mcp', extras, re.MULTILINE), (
        "the mcp extra must declare the package the server imports"
    )


def test_the_console_script_target_is_callable_from_the_package_root():
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "import tenable_email, tenable_email.mcpserver as m\n"
        "assert callable(m.main), 'main must be a console-script entry point'\n"
        "pull = [k for k in sys.modules if k.split('.')[0] in "
        "('mcp','yaml','PIL','requests','pydantic')]\n"
        "print(pull)\n" % str(SRC)
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO, capture_output=True, text=True,
        env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
    )
    assert out.returncode == 0, out.stderr[-700:]
    assert out.stdout.strip() == "[]", (
        "importing the package pulled in an optional dependency: "
        f"{out.stdout.strip()}"
    )


def test_the_missing_extra_is_reported_as_the_extra_that_is_missing(monkeypatch):
    """The operator-facing shape of "mcp is not installed".

    ``_fastmcp_class`` is the single place that import happens, so substituting
    it exercises the failure the operator sees without depending on whether this
    particular machine happens to have the extra.
    """
    def unavailable():
        raise mcpserver.McpUnavailable(
            "the MCP server needs the `mcp` package (No module named 'mcp').\n\n"
            + mcpserver.INSTALL_HINT
        )

    buffer = io.StringIO()
    errors = io.StringIO()
    monkeypatch.setattr(mcpserver, "_fastmcp_class", unavailable)
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(errors):
        code = mcpserver.main([])
    assert code == 1, "a server that cannot start must not report success"
    assert buffer.getvalue() == ""
    assert "pip install -e .[mcp]" in errors.getvalue()
    assert "Traceback" not in errors.getvalue()
    assert "mcp" in errors.getvalue()


def test_build_server_names_the_package_when_the_extra_is_absent():
    """The real import path, both ways, with no skip and no assumption.

    A machine that installed ``.[mcp]`` must be able to build a server; a machine
    that installed ``--no-deps`` must get the instruction. Both are the same
    assertion about one function, so neither branch is decorative.
    """
    try:
        import mcp  # noqa: F401
    except ImportError:
        with pytest.raises(mcpserver.McpUnavailable) as excinfo:
            mcpserver._fastmcp_class()
        assert "pip install -e .[mcp]" in str(excinfo.value)
        assert "optional extra" in str(excinfo.value)
    else:
        assert callable(mcpserver._fastmcp_class())


def test_list_tools_advertises_the_surface_without_the_extra_installed():
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = mcpserver.main(["--list-tools"])
    assert code == 0
    payload = json.loads(buffer.getvalue())
    assert [t["name"] for t in payload["tools"]] == list(mcpserver.TOOL_ORDER)
    assert payload["transport"] == "stdio"
    assert payload["server"] == mcpserver.SERVER_NAME
    for tool in payload["tools"]:
        assert tool["mutates"] is False
        assert tool["description"]
        assert set(tool["arguments"]) == set(
            mcpserver.TOOL_ARGUMENTS[tool["name"]]
        )


def test_the_version_flag_reports_the_package_version():
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        assert mcpserver.main(["--version"]) == 0
    assert buffer.getvalue().startswith("tenable-email ")


def test_the_listing_tools_exposed_are_the_tools_the_server_ships():
    """The Exchange listing is a promise; this is where it is kept.

    Parsed rather than imported: the frontmatter belongs to an upstream validator
    this repository does not run, and a reviewer reading the listing should not
    have to install anything to find out whether the list is true.
    """
    text = LISTING.read_text(encoding="utf-8")
    block = text.split("tools_exposed:")[1].split("resources_exposed:")[0]
    declared = re.findall(r'^\s*-\s*name:\s*"?([A-Za-z0-9_]+)"?', block,
                          re.MULTILINE)
    assert declared == list(mcpserver.TOOL_ORDER), (
        f"the listing advertises {declared}, the server ships "
        f"{list(mcpserver.TOOL_ORDER)}"
    )
    assert 'transport: "stdio"' in text and 'runtime: "python"' in text


def test_readme_documents_the_server_and_every_tool():
    text = README.read_text(encoding="utf-8")
    assert "pip install -e .[mcp]" in text
    assert "tenable-email-mcp" in text
    assert "--list-tools" in text
    for name in mcpserver.TOOL_ORDER:
        assert f"`{name}`" in text, f"README does not document the {name} tool"
    assert "No tool mutates anything" in text, (
        "the read-only property belongs where a user will read it"
    )
    assert "SKILL.md" in text


# --------------------------------------------------------------------------
# analyze_eml
# --------------------------------------------------------------------------


def test_analyze_eml_returns_the_decision_and_the_provenance_groups():
    result = assert_envelope(call("analyze_eml", str(SAMPLE)), "analyze_eml")
    assert result["disposition"] == "threat"
    assert result["verdict"] == result["disposition"], "reference-shape parity"
    assert isinstance(result["confidence"], float)
    assert result["confidence"] == 0.95
    assert result["confidence_band"] == "high"
    assert result["attack_type"] == "CREDENTIAL_HARVEST"
    assert result["reasons"] and isinstance(result["reasons"][0], str)
    assert result["analysis"]
    assert result["stages_run"] == [
        "intake", "parse-authenticate", "deterministic-signals",
        "classifier-cascade", "adjudication",
    ]
    assert result["truncated"] is False
    assert result["escalated"] is False
    assert result["source"] == SAMPLE.name
    grouped = result["evidence"]
    assert set(grouped) == {
        "verified", "model_judgment", "unknown", "unavailable"
    }
    assert grouped["verified"], "a deterministic finding must be present"
    assert grouped["model_judgment"], "the committed recordings must appear"
    assert grouped["unknown"], "an unknowable question must stay in the record"
    assert result["evidence_counts"]["verified"] >= 20
    assert result["gaps"]["count"] == (
        len(grouped["unknown"]) + len(grouped["unavailable"])
    )
    assert result["cited_findings"], "a disposition has to name what it rests on"
    for finding in grouped["verified"]:
        assert finding["value_digest"] or finding["value"] is not None


def test_analyze_eml_groups_the_gaps_as_gaps():
    """The two kinds of hole, named differently, because they instruct
    differently: one is about the deployment, the other about the message."""
    result = call("analyze_eml", str(SAMPLE))
    gaps = result["gaps"]
    assert "not evidence that" in gaps["tier_did_not_run"][0]["means"]
    assert "no amount of analysis" in (
        gaps["not_knowable_from_the_message"][0]["means"]
    )
    kinds = {g["kind"] for g in gaps["tier_did_not_run"]} | {
        g["kind"] for g in gaps["not_knowable_from_the_message"]
    }
    assert kinds <= {"unavailable", "unknown"}
    assert "never that nothing was found" in gaps["note"]


def test_analyze_eml_names_the_stages_that_did_not_run_and_why():
    result = call("analyze_eml", str(SAMPLE))
    skipped = {s["stage"]: s["reason"] for s in result["stages_not_run"]}
    assert "disposition-writeback" in skipped
    assert "human approval" in skipped["disposition-writeback"]
    assert "attachment-content" in skipped
    assert "not enabled" in skipped["attachment-content"], (
        "the stage is implemented, so the reason a caller gets must name the "
        "configuration that left it off"
    )
    assert "not implemented" not in skipped["attachment-content"], (
        "this is the overstated claim the attachment-structure rename removed; "
        "a skip reason that resurrects it is a contract lie, not a skip reason"
    )
    assert "disposition-writeback" not in result["stages_run"]
    contract_ids = set(load_contract().ids())
    assert set(skipped) | set(result["stages_run"]) == contract_ids, (
        "every contract stage is either reported as run or as absent, with a "
        "reason: a stage that is silently missing is the drift this project "
        "refuses"
    )


def test_analyze_eml_proposes_the_write_and_does_not_perform_it():
    result = call("analyze_eml", str(SAMPLE))
    proposal = result["proposed_writeback"]
    assert proposal["executed"] is False
    kinds = [a["kind"] for a in proposal["actions"]]
    assert "record_case" in kinds and "apply_label" in kinds
    assert "post_comment" not in kinds, (
        "no destination can receive a comment, so proposing one is a fiction"
    )
    assert "human approval required" in proposal["gate"]
    assert "tenable-email run" in proposal["how_to_act"]
    for action in proposal["actions"]:
        assert action["target"] == SAMPLE.name, "an action names the message"


def test_analyze_eml_advises_escalation_rather_than_re_asking():
    result = call("analyze_eml", str(BEC))
    assert result["disposition"] == "manual_review"
    assert result["escalated"] is True
    assert "re-asking" in result["reading"]
    assert "human" in result["reading"]
    assert "unknown" in result["gaps"]["not_knowable_from_the_message"][0][
        "key"
    ] or result["gaps"]["not_knowable_from_the_message"]


def test_manual_review_survives_being_asked_again():
    """Determinism, on the surface an agent uses.

    The skill tells a caller not to re-roll an escalation; the reason it can say
    that is that the chain is deterministic and the recordings are keyed on the
    request. Pinning it here also pins the replay path, which would otherwise
    only drift visibly in a verdict nobody compares.
    """
    first = call("analyze_eml", str(BEC))
    repeats = [call("analyze_eml", str(BEC)) for _ in range(3)]
    assert all(repeated["disposition"] == first["disposition"]
               for repeated in repeats)
    assert all(canonical_json(repeated) == canonical_json(first)
               for repeated in repeats), (
        "the same bytes must produce the same answer, or a recording stops "
        "meaning what it says about the message it was made from"
    )


def test_analyze_eml_reports_a_partial_reading_as_partial(tmp_path):
    long_body = "".join(
        f"Line {n} of a very long reported message about invoices. "
        for n in range(400)
    )
    path = tmp_path / "truncated_case.eml"
    path.write_text(
        "From: notices@example-outfitters.com\r\n"
        "To: it@recipient.test\r\n"
        "Subject: Monthly statement\r\n"
        "Message-ID: <trunc-1@recipient.test>\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"{long_body}\r\n",
        encoding="utf-8",
    )
    result = call("analyze_eml", str(path))
    assert result["ok"] is True
    assert result["truncated"] is True
    truncation = result["truncation"]
    assert truncation["truncated"] is True
    assert truncation["body_chars_retained"] == 8000
    assert truncation["original_body_length"] > truncation["body_chars_retained"]
    assert "PARTIAL READING" in truncation["warning"]
    assert "complete" in truncation["warning"]
    assert any("truncated" in reason.lower() for reason in result["reasons"])


def test_analyze_eml_shape_projection_is_numbers_hosts_and_mechanisms():
    result = call("analyze_eml", str(SAMPLE))
    shape = result["shape"]
    assert shape["link_count"] >= 1
    assert shape["auth_results"]["spf"] in (
        "PASS", "FAIL", "SOFTFAIL", "NONE", "unknown"
    )
    assert isinstance(shape["attachment_count"], int)
    assert isinstance(shape["is_forwarded"], bool)
    assert isinstance(shape["injection_indicator_count"], int)
    assert isinstance(shape["rfc8058_one_click"], bool)
    for host in shape["resolved_hosts"] + shape["hosts_matching_neither"]:
        assert " " not in host and "<" not in host, (
            "a host field carrying markup would be body text in disguise"
        )


# --------------------------------------------------------------------------
# analyze_eml_directory
# --------------------------------------------------------------------------


def test_analyze_eml_directory_reports_lines_counts_and_agreement():
    result = assert_envelope(
        call("analyze_eml_directory", str(FIXTURES)), "analyze_eml_directory"
    )
    assert result["directory"] == "synthetic"
    assert result["messages"] == len(FIXTURE_PATHS) == 14
    assert sum(result["counts_by_disposition"].values()) == 14
    assert result["totals"]["escalated_to_a_human"] == 4
    assert all(row["line"] and row["source"] for row in result["results"])
    assert all("/" not in row["source"] for row in result["results"])
    agreement = result["label_agreement"]
    assert agreement["present"] is True
    assert agreement["manifest"] == "labels.json"
    assert agreement["agree"] == 10
    assert agreement["escalated"] == 2
    assert agreement["disagree"] == 2
    assert agreement["unlabelled"] == 0
    assert "10 agree, 2 escalated" in agreement["summary"]
    assert "neither correct nor" in agreement["note"], (
        "escalation must be described as the separate outcome it is"
    )
    assert result["case_records"]["written"] is False


def test_analyze_eml_directory_agrees_with_the_library_over_the_same_corpus():
    """One implementation, two surfaces.

    A batch tool that disagreed with ``triage_file`` would be a second engine
    that nobody notices drifting, which is the failure the stage validator exists
    to prevent elsewhere in this project.
    """
    batch = call("analyze_eml_directory", str(FIXTURES))
    config = Config(replay=True, replay_dir=str(REPLAY))
    for row in batch["results"]:
        verdict = triage_file(FIXTURES / row["source"], config)
        assert row["disposition"] == verdict.disposition.value
        assert row["confidence"] == pytest.approx(float(verdict.confidence))
        assert row["attack_type"] == verdict.attack_type.value
        assert row["confidence_band"] == verdict.confidence_band.value
        assert row["truncated"] == bool(verdict.truncated)


def test_analyze_eml_directory_without_a_manifest_refuses_to_claim_ground_truth(
    tmp_path
):
    for name in ("clean_internal_registrar.eml", "spam_bulk_marketing.eml"):
        (tmp_path / name).write_text(
            (FIXTURES / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    result = call("analyze_eml_directory", str(tmp_path))
    assert result["ok"] is True
    assert result["messages"] == 2
    agreement = result["label_agreement"]
    assert agreement["present"] is False
    assert agreement["manifest"] is None
    assert agreement["summary"] == ""
    assert agreement["unlabelled"] == 2
    assert all(row["agreement"] == "unlabelled" for row in result["results"])
    assert "ground truth" in agreement["note"]


def test_analyze_eml_directory_over_an_empty_directory_is_a_structured_error(
    tmp_path
):
    empty = tmp_path / "no_mail_here"
    empty.mkdir()
    result = assert_envelope(
        call("analyze_eml_directory", str(empty)), "analyze_eml_directory"
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "bad-request"
    assert ".eml" in result["error"]["message"]


def test_analyze_eml_directory_rejects_a_file(tmp_path):
    result = call("analyze_eml_directory", str(SAMPLE))
    assert result["ok"] is False
    assert result["error"]["code"] == "bad-request"
    assert "not a directory" in result["error"]["message"]


def test_analyze_eml_directory_refuses_the_root_instead_of_walking_the_host():
    """A caller-supplied path must not become a search of the machine.

    This call used to walk every directory on the host, cross a network mount,
    find 6,297 ``.eml`` files belonging to other projects, triage all of them and
    return rows as a reading of the directory the caller named. Measured before:
    44,731 ms. The envelope has to say which bound bound, name the directory, and
    tell the caller how to narrow -- an error that only says "too much" is a
    second fuzz round waiting to happen.

    The timing assertion is deliberately two orders of magnitude above what the
    refusal costs (~10 ms here), so it cannot flake on a loaded machine and still
    catches the regression it exists to catch.
    """
    started = time.perf_counter()
    result = assert_envelope(
        call("analyze_eml_directory", "///"), "analyze_eml_directory"
    )
    elapsed = time.perf_counter() - started
    assert elapsed < 5.0, f"the refusal took {elapsed * 1000:.1f} ms"
    assert result["ok"] is False
    error = result["error"]
    assert error["code"] == "bad-request"
    assert error["type"] == "DirectoryScanError"
    assert "bound" in error["message"], error["message"]
    assert "/" in error["message"], f"a refusal has to name the directory: {error}"
    assert "narrow" in error["message"], f"a refusal has to say how: {error}"
    assert "partial" in error["message"], (
        f"a refusal has to point at the opt-in it refused: {error}"
    )
    assert "results" not in result, "a refused scan returns no rows"
    assert "scan" not in result, "a refused scan returns no partial summary"


def test_analyze_eml_directory_reports_what_it_scanned():
    """A batch answer has to say whether it saw everything.

    ``scan`` is the audit block: the root as the caller named it, how many
    ``.eml`` files were actually found, both ceilings, and whether either bound.
    Without it a fourteen-message answer and a two-thousand-message answer from a
    directory with eighty thousand messages read the same.
    """
    result = assert_envelope(
        call("analyze_eml_directory", str(FIXTURES)), "analyze_eml_directory"
    )
    scan = result["scan"]
    assert scan["root"] == str(FIXTURES)
    assert scan["files_found"] == result["messages"] == len(result["results"])
    assert scan["bound"] is None
    assert scan["complete"] is True
    assert scan["max_files"] == DEFAULT_MAX_EML_FILES
    assert scan["max_depth"] == DEFAULT_MAX_EML_DEPTH
    assert scan["directories_visited"] >= 1
    assert scan["symlinks_skipped"] == 0
    assert scan["trees_pruned"] == []


def test_analyze_eml_directory_does_not_follow_a_symlink_out_of_its_root(tmp_path):
    """The escape the ceiling alone could not close, tested at the tool boundary.

    A directory holding a link to somebody else's mail used to be answered with
    that mail in it, because ``rglob`` yielded symlinked files. The caller asked
    about one directory and got another one's contents; here the row set is
    checked against the outside corpus by name and by count.
    """
    outside = tmp_path / "other-projects"
    outside.mkdir()
    shutil.copyfile(FIXTURES / "threat_bec_valid_auth.eml", outside / "private.eml")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    shutil.copyfile(FIXTURES / "clean_internal_registrar.eml", corpus / "mine.eml")
    os.symlink(outside / "private.eml", corpus / "looks_local.eml")
    shutil.copyfile(FIXTURES / "labels.json", corpus / "labels.json")

    result = assert_envelope(call(DIRECTORY_TOOL, str(corpus)), DIRECTORY_TOOL)
    assert result["ok"] is True, result["error"]
    assert [row["source"] for row in result["results"]] == ["mine.eml"], (
        f"the batch read mail outside the directory it was pointed at: "
        f"{[row['source'] for row in result['results']]}"
    )
    assert "private" not in canonical_json(result)
    assert result["scan"]["symlinks_skipped"] == 1
    assert result["scan"]["files_found"] == 1


def test_analyze_eml_directory_refuses_a_directory_beyond_its_depth_bound(tmp_path):
    """Depth is a bound too, and a pruned subtree is not a complete answer.

    The top-level message would have been triaged and reported; a reading of part
    of a corpus presented as a reading of the corpus is the failure this refuses,
    so nothing is triaged and the caller is told which ceiling to raise.
    """
    nested = tmp_path / "deep"
    target = nested
    for level in range(DEFAULT_MAX_EML_DEPTH + 1):
        target = target / f"level_{level}"
    target.mkdir(parents=True)
    shutil.copyfile(
        FIXTURES / "clean_internal_registrar.eml", target / "buried.eml"
    )
    shutil.copyfile(FIXTURES / "clean_internal_registrar.eml", nested / "top.eml")

    result = assert_envelope(call(DIRECTORY_TOOL, str(nested)), DIRECTORY_TOOL)
    assert result["ok"] is False
    assert result["error"]["code"] == "bad-request"
    assert "depth" in result["error"]["message"]
    assert str(nested) in result["error"]["message"]
    assert "results" not in result


# --------------------------------------------------------------------------
# check_auth
# --------------------------------------------------------------------------


def test_check_auth_returns_the_recorded_outcomes_and_alignment():
    result = assert_envelope(
        call("check_auth", str(BEC)), "check_auth"
    )
    assert result["provenance"] == "verified"
    assert result["auth"]["spf"] == "PASS"
    assert result["auth"]["dkim"] == "PASS"
    assert result["auth"]["dmarc"] == "PASS"
    assert result["alignment"]["auth_passes"] is True
    assert result["alignment"]["claims_protected_domain"] is True
    assert result["alignment"]["sender_domain"] == "example.edu"
    assert result["auth_headers_seen"] == ["authentication-results"]
    assert "arc-authentication-results" in result["auth_headers_absent"]
    assert result["mechanisms_with_no_recorded_result"] == []
    for raw in result["auth"]["raw"]:
        assert len(raw) <= 240, "raw header values are truncated, as documented"


def test_check_auth_refuses_to_imply_legitimacy():
    """The lesson the reference playbook gets wrong, shipped with the answer."""
    result = call("check_auth", str(BEC))
    interpretation = result["interpretation"]
    assert interpretation["authenticated_at_the_receiving_mta"] is True
    assert "legitimacy" in interpretation["does_not_establish"]
    assert "compromised" in interpretation["does_not_establish"]


def test_check_auth_keeps_an_absent_check_apart_from_a_passing_one(tmp_path):
    path = tmp_path / "no_auth_headers.eml"
    path.write_text(
        "From: accounts@example-review-portal.com\r\n"
        "To: it@recipient.test\r\n"
        "Subject: Your invoice is overdue\r\n"
        "\r\n"
        "Please review the attached invoice and remit today.\r\n",
        encoding="utf-8",
    )
    result = call("check_auth", str(path))
    assert result["ok"] is True
    assert result["auth"]["spf"] == "unknown"
    assert result["auth"]["dkim"] == "unknown"
    assert result["auth"]["dmarc"] == "unknown"
    assert result["alignment"]["auth_passes"] is False
    assert result["mechanisms_with_no_recorded_result"] == ["dkim", "dmarc",
                                                           "spf"]
    assert "not a pass" in result["absent_is_not_passing"]
    assert set(result["auth_headers_absent"]) == {
        "authentication-results", "arc-authentication-results", "received-spf",
        "x-google-dkim-signature",
    }


def test_check_auth_reports_the_sender_identity_it_read():
    result = call("check_auth", str(FIXTURES / "threat_forwarded_by_user.eml"))
    assert result["sender"]["domain"]
    assert "@" in result["sender"]["address"]


# --------------------------------------------------------------------------
# lookalike_domain
# --------------------------------------------------------------------------


def test_lookalike_domain_flags_the_impersonation_shape():
    result = assert_envelope(
        call("lookalike_domain", "example-portal-verify.com"), "lookalike_domain"
    )
    assert result["lookalike"]["is_lookalike"] is True
    assert result["lookalike"]["target"] == "example"
    assert set(result["lookalike"]["modifiers_found"]) == {"portal", "verify"}
    assert result["owned_by_the_profile"] is False
    assert result["trusted_by_the_profile"] is False
    assert result["provenance"] == "verified"
    assert result["domain"] == "example-portal-verify.com"


def test_lookalike_domain_clears_a_shared_word_and_an_owned_domain():
    """The false positive this project fixed, pinned on the tool surface."""
    unrelated = call("lookalike_domain", "example-outfitters.com")
    assert unrelated["lookalike"]["is_lookalike"] is False
    assert unrelated["lookalike"]["contains_protected_label"] is True
    assert unrelated["second_level_label"] == "example-outfitters"

    owned = call("lookalike_domain", "mail.example.edu")
    assert owned["lookalike"]["is_lookalike"] is False
    assert owned["owned_by_the_profile"] is True

    trusted = call("lookalike_domain", "www.docusign.net")
    assert trusted["trusted_by_the_profile"] is True
    assert trusted["lookalike"]["is_lookalike"] is False


def test_lookalike_domain_accepts_a_url_and_says_which_domain_it_used():
    result = call("lookalike_domain", "https://examp1e.edu/login?next=1")
    assert result["domain"] == "examp1e.edu"
    assert result["second_level_label"] == "examp1e"
    assert result["lookalike"]["is_lookalike"] is True
    assert result["lookalike"]["edit_distance_match"] is True
    assert result["input"] == "https://examp1e.edu/login?next=1"


def test_lookalike_domain_reports_the_thresholds_the_answer_depends_on():
    result = call("lookalike_domain", "example-verify.com")
    assert result["thresholds"]["lookalike_max_distance"] == 1
    assert "example.edu" in result["profile"]["protected_domains"]
    assert result["reading"].startswith("is_lookalike is the impersonation")
    assert "Public Suffix List" in result["reading"], (
        "the naive registrable_domain() limitation is documented in README and "
        "must stay visible where a caller can see it"
    )


def test_lookalike_domain_rejects_an_empty_input():
    for bad in ("", "   ", None):
        result = call("lookalike_domain", bad)
        assert result["ok"] is False
        assert result["error"]["code"] == "bad-request"


# --------------------------------------------------------------------------
# analyze_urls
# --------------------------------------------------------------------------


def test_analyze_urls_unwraps_the_redirect_and_names_the_wrapper():
    result = assert_envelope(
        call("analyze_urls", [SAFE_LINKS], "mail.example.edu"), "analyze_urls"
    )
    entry = result["links"][0]
    assert entry["unwrapped_by"] == "safelinks.protection.outlook.com"
    assert entry["resolved_host"] == "deposit-confirm.test"
    assert entry["resolved_href"] == "https://deposit-confirm.test/verify"
    assert entry["destination_class"] == "neither"
    assert entry["concealment"] is True
    assert result["summary"]["concealed_destinations"] == ["deposit-confirm.test"]
    assert result["summary"]["destinations_queried"] == 1
    assert result["sender_domain"] == "mail.example.edu"


def test_analyze_urls_reports_anchor_mismatch_and_ip_literals():
    result = call(
        "analyze_urls",
        [
            {"href": "http://192.0.2.77/login",
             "anchor_text": "https://example.edu/pay"},
            {"href": "https://example.edu/secure",
             "anchor_text": "example.edu/secure"},
        ],
        "example.edu",
    )
    mismatched, aligned = result["links"]
    assert mismatched["anchor_mismatch"] is True
    assert mismatched["anchor_claim"] == "example.edu"
    assert mismatched["is_ip_literal"] is True
    assert mismatched["destination_class"] == "neither"
    assert aligned["anchor_mismatch"] is False
    assert aligned["destination_class"] == "sender"
    assert result["summary"]["ip_literal_hosts"] == ["192.0.2.77"]
    assert result["summary"]["anchor_mismatches"] == 1


def test_analyze_urls_classifies_a_trusted_destination():
    result = call("analyze_urls", ["https://www.docusign.net/signing/1234"],
                  "example.edu")
    entry = result["links"][0]
    assert entry["destination_class"] == "trusted"
    assert entry["concealment"] is False
    assert result["summary"]["hosts_matching_trusted"] == ["www.docusign.net"]


def test_analyze_urls_refuses_to_call_something_neither_when_no_sender_is_given():
    """``neither`` is a claim about the sender; with no sender there is no claim.

    A calling agent that omits ``sender_domain`` gets an honest
    ``unclassified`` rather than a word that sounds like a finding.
    """
    result = call("analyze_urls", [SAFE_LINKS])
    entry = result["links"][0]
    assert result["sender_domain"] is None
    assert result["summary"]["no_reference_point"] is True
    assert entry["destination_class"] == "unclassified"
    assert result["summary"]["hosts_matching_neither"] == []


def test_analyze_urls_reaches_the_reputation_tier_through_a_recording():
    """A committed recording answers a link an agent asked about cold.

    This is the tier integration: the destination the corpus's own redirect
    hides is recorded, so the answer arrives with the engine scores attached and
    no endpoint configured.
    """
    result = call("analyze_urls", ["https://deposit-confirm.test/verify"],
                  "mail.example.edu")
    reputation = result["links"][0]["reputation"]
    assert reputation["tier"] == "url_reputation"
    assert reputation["available"] is True
    assert reputation["ok"] is True, reputation["error"]
    assert reputation["source"] == "replay"
    assert reputation["stance"] == "threat"
    assert isinstance(reputation["confidence"], float)
    assert reputation["scores"], "the engine's own scores must survive"
    assert reputation["error"] is None


def test_analyze_urls_records_a_replay_miss_instead_of_calling_or_guessing():
    result = call("analyze_urls", ["https://never-recorded.example.invalid/x"],
                  "mail.example.edu")
    reputation = result["links"][0]["reputation"]
    assert reputation["ok"] is False
    assert "replay miss" in reputation["error"]
    assert reputation["stance"] is None
    assert reputation["confidence"] is None


def test_analyze_urls_caps_the_lookups_and_marks_the_links_it_did_not_check():
    urls = [f"https://cap-test-{n}.invalid/" for n in range(12)]
    result = call("analyze_urls", urls, "mail.example.edu")
    assert result["summary"]["destinations_queried"] == 8
    assert result["summary"]["lookup_cap"] == 8
    unasked = [e for e in result["links"] if e["reputation"]["queried"] is False]
    assert len(unasked) == 4, "the four beyond the cap must be visibly unasked"
    for entry in unasked:
        assert "not the same as their being clean" in entry["reputation"]["reason"]
        assert entry["reputation"]["ok"] is False
        assert entry["reputation"]["stance"] is None
    checked = [e for e in result["links"] if e["reputation"]["queried"] is True]
    assert len(checked) == 8
    for entry in result["links"]:
        assert set(entry["reputation"]) >= {
            "tier", "stage", "queried", "available", "ok", "source", "stance",
            "confidence", "scores", "error"
        }, (
            "an unasked lookup has to have the same shape as an asked one, or a "
            "client reading the list meets two response types for one field"
        )
    deduplicated = call(
        "analyze_urls",
        ["https://cap-test-1.invalid/", "https://cap-test-1.invalid/"],
        "mail.example.edu",
    )
    assert deduplicated["summary"]["destinations_queried"] == 1
    second = deduplicated["links"][1]["reputation"]
    assert second["queried"] is False and "already queried" in second["reason"]
    for entry in unasked:
        assert "not the same as their being clean" in entry["reputation"]["reason"]


def test_analyze_urls_accepts_strings_objects_and_one_value():
    result = call(
        "analyze_urls",
        ["https://example.edu/a", {"url": "https://b.example.edu/c",
                                   "text": "x"}],
    )
    assert result["ok"] is True
    assert result["summary"]["requested_links"] == 2
    assert result["summary"]["anchor_text_supplied"] is True
    single = call("analyze_urls", "https://example.edu/a")
    assert single["ok"] is True
    assert single["summary"]["requested_links"] == 1


def test_analyze_urls_rejects_an_empty_or_malformed_request():
    for bad in ([], "", ["   "], {"nope": 1}, 42, None):
        result = call("analyze_urls", bad)
        assert result["ok"] is False, f"{bad!r} should not have been accepted"
        assert result["error"]["code"] == "bad-request"
        assert "analyze_urls" in result["error"]["message"] or "URL" in (
            result["error"]["message"]
        )


# --------------------------------------------------------------------------
# classify_local
# --------------------------------------------------------------------------


def test_classify_local_gives_each_tier_separately_and_merges_nothing():
    result = assert_envelope(
        call("classify_local", str(SAMPLE)), "classify_local"
    )
    assert "disposition" not in result, (
        "this tool is the opinions, not the conclusion"
    )
    assert "confidence" not in result, "no merged number may be returned"
    assert "verdict" not in result
    assert [e["tier"] for e in result["tiers"]] == [
        "classifier", "url_reputation", "prompt_injection",
        "injection_classifier", "spam_three_way", "vision", "llm",
    ], "every tier the pipeline knows, in cascade order"
    for entry in result["tiers"]:
        assert {
            "tier", "stage", "available", "ok", "source", "model", "error",
            "stance", "confidence", "attack_type", "scores", "endpoint_field",
        } <= set(entry)
    answered = [e for e in result["tiers"] if e["ok"]]
    assert answered, "the committed recordings must answer something"
    for entry in answered:
        assert entry["source"] == "replay"
        assert entry["stance"] in ("threat", "spam", "clean", "abstain")
    assert result["provenance"] == "model_judgment"


def test_classify_local_makes_disagreement_visible_rather_than_resolved():
    """At least one fixture has tiers that said opposite things.

    Asserted across the corpus, with a guard that the corpus still contains such
    a case: a loop that finds no disagreement would otherwise pass silently, and
    "the tool surfaces disagreement" would be a claim with nothing behind it.
    """
    disagreeing = []
    for path in FIXTURE_PATHS:
        result = call("classify_local", str(path))
        assert result["ok"] is True
        stances = {e["stance"] for e in result["tiers"] if e["stance"]}
        if len(stances) > 1:
            disagreeing.append(path.stem)
            assert result["disagreement"] is True
            assert "weighted mean" in result["reading"]
        else:
            assert result["disagreement"] is False
    assert disagreeing, (
        "no fixture produced tier disagreement, so this test would be asserting "
        "nothing about the property it exists to protect"
    )


def test_classify_local_separates_a_missing_capability_from_an_unasked_tier():
    """Three states, not two: did not run, could not run, nothing to ask.

    ``build_evidence`` records a gap for every tier with neither an endpoint nor
    a recording, so a tier with no gap and no answer was simply not consulted --
    which is a different sentence, and conflating them would turn a cascade
    decision into a deployment defect on an agent's screen.
    """
    result = call("classify_local", str(FORWARDED))
    unasked = next(e for e in result["tiers"] if e["tier"] == "url_reputation")
    assert unasked["available"] is False
    assert "nothing to ask" in unasked["error"]

    missing = next(e for e in result["tiers"] if e["tier"] == "spam_three_way")
    assert missing["available"] is False
    assert "spam_classifier_url" in missing["error"], (
        "a gap names the configuration field that is empty"
    )
    assert missing["source"] is None


def test_classify_local_carries_no_model_prose_and_no_body_text():
    result = call("classify_local", str(SAMPLE))
    for key in ("analysis", "reasons", "raw", "detail", "facts", "transcript",
                "body", "text_body", "html_body"):
        assert key not in walk_keys(result), f"{key} would carry content"
    assert content_of(parse_file(SAMPLE)) not in canonical_json(result)
    for entry in result["tiers"]:
        if entry["ok"]:
            assert entry["scores"] is not None


def test_classify_local_flags_an_answer_nobody_observed():
    """``source`` is the boundary between "the model said this" and "someone
    wrote this down", so it is carried per tier and warned about."""
    result = call("classify_local", str(SAMPLE))
    sources = {e["source"] for e in result["tiers"] if e["source"]}
    assert sources <= {"replay", "live", "unattested-recording", "stub"}
    assert "replay" in sources
    for entry in result["tiers"]:
        if entry["source"] in ("live", "replay"):
            assert "provenance_warning" not in entry
        if entry["source"] is None:
            assert entry["available"] is False


# --------------------------------------------------------------------------
# explain_verdict / get_case_record
# --------------------------------------------------------------------------


def test_get_case_record_returns_json_and_markdown(tmp_path):
    receipt_id, path, directory = run_a_case(tmp_path)
    result = assert_envelope(
        call("get_case_record", receipt_id, str(directory)), "get_case_record"
    )
    assert result["receipt_id"] == receipt_id
    assert result["loaded_from"] == path.name
    assert "/" not in result["loaded_from"], "a file name, never a directory"
    assert result["markdown"].startswith(f"# Case record {receipt_id}")
    assert result["receipt"]["receipt_id"] == receipt_id
    assert result["receipt"]["verdict"]["disposition"] == "manual_review"
    assert result["receipt"]["digests"]["verdict"] == (
        Receipt.load(path).verdict_digest
    )
    assert isinstance(result["closure_blockers"], list)
    assert "digests of findings" in result["contains_no_message_content"]


def test_get_case_record_accepts_a_path_and_a_receipt_id(tmp_path):
    receipt_id, path, directory = run_a_case(tmp_path)
    from_path = call("get_case_record", str(path))
    assert from_path["ok"] is True
    assert from_path["receipt_id"] == receipt_id
    by_id = call("get_case_record", receipt_id, str(directory))
    assert canonical_json(by_id["receipt"]) == canonical_json(
        from_path["receipt"]
    )


def test_explain_verdict_groups_by_provenance_and_labels_the_gaps(tmp_path):
    receipt_id, _path, directory = run_a_case(tmp_path)
    result = assert_envelope(
        call("explain_verdict", receipt_id, str(directory)), "explain_verdict"
    )
    grouped = result["evidence"]
    assert set(grouped) == {
        "verified", "model_judgment", "unknown", "unavailable"
    }
    assert grouped["verified"] and grouped["unknown"]
    for item in grouped["unknown"] + grouped["unavailable"]:
        assert item["gap"] is True
        assert item["means"]
        assert item["value_digest"], "a gap still has to be citable"
        assert "value" not in item, (
            "a case record stores a digest of each finding's value and never "
            "the value, so a gap cannot carry one either"
        )
    for item in grouped["verified"]:
        assert "gap" not in item
        assert item["value_digest"]
        assert item["cited_by_disposition"] in (True, False)
    assert result["gaps"]["count"] == len(grouped["unknown"]) + len(
        grouped["unavailable"]
    )
    assert "not a finding" in result["gaps"]["note"]
    assert result["disposition"] == "manual_review"
    assert result["escalated"] is True
    assert result["simulated"] is False
    assert result["closure"]["can_close"] is True, result["closure"]["blockers"]
    assert "may not be advanced" in result["closure"]["note"]
    assert result["chain"]["skipped_stages"], (
        "the stages that did not run are part of the record"
    )
    assert result["digests"]["corpus_manifest"] == "labels.json"
    assert result["writeback"]["executed_here"] is False


def test_explain_verdict_reads_the_same_digest_the_receipt_wrote(tmp_path):
    """Cross-surface citability: an MCP answer and the durable record agree."""
    receipt_id, path, directory = run_a_case(tmp_path)
    explained = call("explain_verdict", receipt_id, str(directory))
    record = Receipt.load(path)
    by_key = {item.key: item.value_digest for item in record.evidence}
    for items in explained["evidence"].values():
        for item in items:
            assert item["value_digest"] == by_key[item["key"]], (
                f"{item['key']} is digested differently by the two surfaces, so "
                "a finding cannot be cited from one in the other"
            )
    assert explained["digests"]["verdict"] == record.verdict_digest


def test_explain_verdict_tells_a_caller_to_use_the_other_tool_for_a_message(
    tmp_path
):
    result = call("explain_verdict", str(FIXTURES / "clean_internal_registrar.eml"))
    assert result["ok"] is False
    assert result["error"]["code"] == "bad-request"
    assert "analyze_eml" in result["error"]["message"]


def test_explain_verdict_for_an_unknown_reference_reports_what_it_tried(tmp_path):
    result = assert_envelope(
        call("explain_verdict", "rcpt-not-a-case", str(tmp_path)),
        "explain_verdict",
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "case-record-unreadable"
    assert "Searched for" in result["error"]["message"]
    assert str(tmp_path) not in result["error"]["message"], (
        "the error names the files it tried, not a directory on someone's disk"
    )


def test_explain_verdict_on_a_missing_case_directory_is_a_not_found_error():
    result = call("explain_verdict", "rcpt-anything", "no/such/case/directory")
    assert result["ok"] is False
    assert result["error"]["code"] == "not-found"


def test_explain_verdict_refuses_to_reinterpret_another_schema(tmp_path):
    path = tmp_path / "from-the-future.receipt.json"
    path.write_text(
        json.dumps({"schema_version": 99, "receipt_id": "rcpt-x"}),
        encoding="utf-8",
    )
    result = call("explain_verdict", str(path))
    assert result["ok"] is False
    assert result["error"]["code"] == "case-record-unreadable"
    assert "schema_version" in result["error"]["message"]


def test_explain_verdict_requires_an_argument():
    for bad in ("", None):
        result = call("explain_verdict", bad)
        assert result["ok"] is False
        assert result["error"]["code"] == "bad-request"


# --------------------------------------------------------------------------
# list_contracts
# --------------------------------------------------------------------------


def test_list_contracts_agrees_with_stages_yaml_field_for_field():
    result = assert_envelope(call("list_contracts"), "list_contracts")
    contract = load_contract()
    assert result["stages"] == [s.as_dict() for s in contract.stages]
    assert result["stage_ids"] == contract.ids()
    assert result["stage_titles"] == contract.titles()
    assert result["version"] == contract.version
    assert result["stage_count"] == 8
    assert result["summary"] == "8 stages, 1 write stage, 1 approval gate"
    for stage in result["stages"]:
        assert set(stage) == {
            "id", "title", "capability", "provider", "access", "optional",
            "model_tier", "approval_required", "approval_language",
            "description",
        }


def test_list_contracts_matches_the_file_it_claims_to_read():
    """Compared against the raw text, not only against the parser that read it.

    A tool checked against its own parser could report a contract the file does
    not contain. The ``title:``, ``access:`` and ``approval_required:`` lines are
    taken out of ``stages.yaml`` and have to line up in order.
    """
    raw = STAGES.read_text(encoding="utf-8")
    pairs = re.findall(r"^  - id: (\S+)\n    title: (.+)$", raw, re.MULTILINE)
    accesses = re.findall(r"^    access: (\S+)$", raw, re.MULTILINE)
    approvals = re.findall(r"^    approval_required: (\S+)$", raw, re.MULTILINE)
    tiers = re.findall(r"^    model_tier: (\S+)$", raw, re.MULTILINE)
    providers = re.findall(r"^    provider: (\S+)$", raw, re.MULTILINE)

    stages = call("list_contracts")["stages"]
    assert [(s["id"], s["title"]) for s in stages] == pairs
    assert [s["access"] for s in stages] == accesses
    assert [str(s["approval_required"]).lower() for s in stages] == approvals
    assert [s["model_tier"] for s in stages] == [
        None if raw_tier == "null" else raw_tier for raw_tier in tiers
    ]
    assert [s["provider"] for s in stages] == providers


def test_list_contracts_shows_where_the_approval_gate_is():
    result = call("list_contracts")
    gates = result["approval_gates"]
    assert len(gates) == 1, "exactly one write stage in this contract"
    assert gates[0]["stage"] == "disposition-writeback"
    assert gates[0]["required"] is True
    assert gates[0]["language"] == "human approval required"
    assert result["this_surface"]["mutates"] is False
    assert "disposition-writeback" not in result["read_only_stages"]
    assert len(result["read_only_stages"]) == 7
    assert len(result["providers"]) == 8


def test_list_contracts_reports_a_missing_contract_as_an_error(monkeypatch):
    def broken(*args, **kwargs):
        raise mcpserver.ContractError("contract file not found: stages.yaml")

    monkeypatch.setattr(mcpserver, "load_contract", broken)
    result = mcpserver.list_contracts()
    assert result["ok"] is False
    assert result["error"]["code"] == "contract-unreadable"
    assert "stages.yaml" in result["error"]["message"]


# --------------------------------------------------------------------------
# structured errors, never an exception across the boundary
# --------------------------------------------------------------------------


def test_a_missing_file_is_a_structured_error_naming_the_file():
    result = assert_envelope(
        call("analyze_eml", "fixtures/synthetic/no-such-message.eml"),
        "analyze_eml",
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "not-found"
    assert result["error"]["type"] == "FileNotFoundError"
    assert "no-such-message.eml" in result["error"]["message"]
    assert "/" not in result["error"]["message"].split(":")[-1], (
        "the message names the file, not the path it was not found at"
    )


@pytest.mark.parametrize(
    "name", ["analyze_eml", "check_auth", "classify_local"]
)
def test_a_directory_where_a_file_belongs_is_a_structured_error(name):
    result = call(name, str(FIXTURES))
    assert result["ok"] is False
    assert result["error"]["code"] == "bad-request"
    assert "directory" in result["error"]["message"]


@pytest.mark.parametrize(
    "name", ["analyze_eml", "check_auth", "classify_local"]
)
def test_an_empty_path_is_a_structured_error(name):
    result = call(name, "   ")
    assert result["ok"] is False
    assert result["error"]["code"] == "bad-request"
    assert name in result["error"]["message"]


def test_a_malformed_message_is_a_disposition_and_not_an_exception(tmp_path):
    """A message nobody can read is reported, never raised and never cleared.

    Two shapes of unreadable: bytes that are not a message at all, and an empty
    file. The first arrives in the ambiguous band, the second as ``UNKNOWN`` with
    the parse failure attached -- and neither one is ``CLEAN``, which is the
    failure mode the disposition vocabulary exists to prevent.
    """
    garbage = tmp_path / "garbage.eml"
    garbage.write_bytes(b"\x00\x01\x02not an email at all\xff\xfe" * 4)
    result = call("analyze_eml", str(garbage))
    assert result["ok"] is True, f"a malformed message failed the call: {result}"
    assert result["disposition"] in ("unknown", "manual_review")
    assert result["disposition"] != "clean"
    assert result["escalated"] is True
    assert result["gaps"]["count"] >= 1

    empty = tmp_path / "empty.eml"
    empty.write_bytes(b"")
    second = call("analyze_eml", str(empty))
    assert second["ok"] is True
    assert second["disposition"] == "unknown"
    assert "could not be parsed" in " ".join(second["reasons"])
    assert "absence of evidence" in " ".join(second["reasons"])


def test_a_broken_record_in_a_directory_is_reported_not_raised(tmp_path):
    directory = tmp_path / "receipts"
    directory.mkdir()
    (directory / "rcpt-broken.json").write_text("{ not json", encoding="utf-8")
    result = call("get_case_record", "rcpt-broken", str(tmp_path))
    assert result["ok"] is False
    assert result["error"]["code"] in ("case-record-unreadable", "not-found")


def test_every_tool_returns_the_envelope_and_serializes(tmp_path):
    """The sweep: nine tools, one shape, all JSON, called with valid input."""
    receipt_id, _path, directory = run_a_case(tmp_path)
    extra = dict(CASES)
    extra["explain_verdict"] = (receipt_id, str(directory))
    extra["get_case_record"] = (receipt_id, str(directory))
    assert set(extra) == set(mcpserver.TOOL_ORDER)
    for name, args in extra.items():
        result = call(name, *args)
        assert_envelope(result, name)
        assert result["ok"] is True, f"{name}: {result['error']}"


def test_no_tool_raises_even_when_handed_absurd_arguments():
    """Fuzz-ish input discipline: the boundary converts, it does not propagate."""
    absurd = [None, 0, [], {}, object(), float("nan"), "///", b"bytes".decode()]
    for name in mcpserver.TOOL_ORDER:
        for value in absurd:
            try:
                if name == "analyze_urls":
                    result = call(name, value, value)
                elif name == "list_contracts":
                    result = call(name)
                else:
                    result = call(name, value)
            except Exception as exc:  # noqa: BLE001 - the point of the test
                raise AssertionError(
                    f"{name}({value!r}) raised {type(exc).__name__}: {exc}"
                ) from exc
            assert_envelope(result, name)


# --------------------------------------------------------------------------
# nothing leaves with the message inside it
# --------------------------------------------------------------------------


def content_of(message) -> str:
    return " ".join((message.text_body or message.html_body or "").split())


def body_fragments(message) -> list[str]:
    """The pieces of a message that must never appear in a response.

    The whole body, every body line long enough to be content rather than
    prose about content, the attachment bytes and their base64 form: searched
    for in the serialized answer, not assumed absent because the constructor
    looked careful.
    """
    found: list[str] = []
    body = content_of(message)
    if body:
        found.append(body)
    for line in (message.text_body + "\n" + message.html_body).splitlines():
        flat = " ".join(line.split())
        if len(flat) >= BODY_FRAGMENT:
            found.append(flat[:BODY_FRAGMENT])
    for attachment in message.attachments:
        if not attachment.data:
            continue
        found.append(base64.b64encode(attachment.data).decode("ascii"))
        found.append(
            base64.b64encode(attachment.data).decode("ascii")[:120]
        )
    return found


def assert_no_content(text: str, fragments: list[str], message, where: str):
    for fragment in fragments:
        assert fragment not in text, (
            f"{where} returned message content from {message.source}: "
            f"{fragment[:40]!r}..."
        )
    for attachment in message.attachments:
        assert not attachment.data or attachment.data not in text.encode(
            "utf-8", "ignore"
        ), f"{where} returned raw attachment bytes"


@pytest.mark.parametrize("path", FIXTURE_PATHS, ids=lambda p: p.stem)
def test_no_tool_response_carries_a_body_line_or_attachment_bytes(path):
    message = parse_file(path)
    fragments = body_fragments(message)
    assert fragments, f"{path.name} has no body content to leak: the test is vacuous"
    for tool_name in MESSAGE_TOOLS:
        result = call(tool_name, str(path))
        assert result["ok"] is True, f"{tool_name}: {result['error']}"
        text = canonical_json(result)
        assert_no_content(text, fragments, message, tool_name)
        assert "data" not in walk_keys(result), (
            f"{tool_name} returned a 'data' key, which is where bytes would be"
        )
        assert b"\x00" not in text.encode("utf-8", "ignore")


def test_the_batch_tool_carries_no_body_for_any_message_it_read():
    """One batch call, checked against every message inside it.

    Checked as one call rather than fourteen: the directory tool reads the whole
    corpus each time it is pointed at it, so looping it per fixture would run
    196 triages to prove one property, and the property is about the aggregate
    answer anyway.
    """
    result = call(DIRECTORY_TOOL, str(FIXTURES))
    assert result["ok"] is True, result["error"]
    text = canonical_json(result)
    assert result["messages"] == len(FIXTURE_PATHS)
    for path in FIXTURE_PATHS:
        message = parse_file(path)
        assert_no_content(text, body_fragments(message), message, DIRECTORY_TOOL)
    assert "data" not in walk_keys(result)


def test_withheld_values_come_back_as_digests_with_a_reason():
    result = call("analyze_eml", str(FIXTURES / "threat_prompt_injection.eml"))
    withheld = [
        item
        for items in result["evidence"].values()
        for item in items
        if "value_note" in item
    ]
    keys = {item["key"] for item in withheld}
    assert {"injection", "link_details", "bec_language"} <= keys, (
        "these are the findings that quote the body, and they must be withheld"
    )
    for item in withheld:
        assert item["value_digest"], "a withheld value still has to be citable"
        assert "withheld" in item["value_note"]
    assert not keys & mcpserver.CARRIABLE_VALUE_KEYS, (
        "a key cannot be inlined and withheld at the same time"
    )


def test_model_judgment_values_are_withheld_in_every_group():
    for path in FIXTURE_PATHS[:4]:
        result = call("analyze_eml", str(path))
        for item in result["evidence"]["model_judgment"]:
            assert item["value"] is None, (
                f"a tier's prose about the content left through {path.name}"
            )
            assert item["value_digest"]
            assert "withheld" in item["value_note"]
        votes = result["model_votes"]["votes"]
        for vote in votes:
            assert set(vote) == {
                "tier", "stance", "confidence", "attack_type", "scores",
                "stage", "value_digest",
            }


def test_carriable_keys_are_a_documented_subset_of_what_the_pipeline_emits():
    """The allowlist is checked against the findings the corpus can produce.

    A key nobody ever emits would advertise a value that no response can carry,
    and a value the pipeline emits that is not in the allowlist is a decision made
    by accident rather than by review.
    """
    emitted: set[str] = set()
    for path in FIXTURE_PATHS:
        verdict = triage_file(path, Config(replay=True, replay_dir=str(REPLAY)))
        emitted |= {f.key for f in verdict.evidence.findings}
    assert mcpserver.CARRIABLE_VALUE_KEYS <= emitted, (
        "the allowlist names keys no fixture produces: it has drifted from the "
        "pipeline it filters"
    )
    assert "injection" not in mcpserver.CARRIABLE_VALUE_KEYS
    assert "link_details" not in mcpserver.CARRIABLE_VALUE_KEYS
    assert "forwarding" not in mcpserver.CARRIABLE_VALUE_KEYS
    assert "bec_language" not in mcpserver.CARRIABLE_VALUE_KEYS


def test_case_records_returned_to_a_caller_carry_no_body(tmp_path):
    """The same standard, applied to the record path rather than the triage one."""
    receipt_id, path, directory = run_a_case(tmp_path)
    message = parse_file(BEC)
    body = content_of(message)
    for name in ("explain_verdict", "get_case_record"):
        for args in ((receipt_id, str(directory)), (str(path),)):
            result = call(name, *args)
            assert result["ok"] is True, result["error"]
            text = canonical_json(result)
            assert body not in text
            assert not any(
                line[:BODY_FRAGMENT] in text
                for line in (message.text_body + "\n" + message.html_body)
                .splitlines()
                if len(" ".join(line.split())) >= BODY_FRAGMENT
            )
            assert "data" not in walk_keys(result)


# --------------------------------------------------------------------------
# no mutation, no network: asserted by snapshot
# --------------------------------------------------------------------------


def snapshot(*roots: Path) -> dict[str, tuple[int, str]]:
    """``(name -> (size, sha256))`` for every file under each root."""
    state: dict[str, tuple[int, str]] = {}
    for root in roots:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix == ".pyc":
                continue
            state[f"{root.name}/{path.relative_to(root)}"] = (
                path.stat().st_size,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
    return state


def block_network(monkeypatch) -> list[str]:
    """Make any outbound attempt loud, and remember whether one happened."""
    attempts: list[str] = []

    def refuse(via: str):
        def inner(*args, **kwargs):
            attempts.append(via)
            raise AssertionError(f"a tool attempted a network call via {via}")

        return inner

    import socket
    import urllib.request

    for module, attribute in (
        (socket, "socket"),
        (socket, "create_connection"),
        (socket, "getaddrinfo"),
        (urllib.request, "urlopen"),
    ):
        monkeypatch.setattr(
            module, attribute, refuse(f"{module.__name__}.{attribute}")
        )
    return attempts


def test_no_tool_writes_anything_or_reaches_the_network(tmp_path, monkeypatch):
    workdir = tmp_path / "work"
    workdir.mkdir()
    marker = workdir / "untouched.txt"
    marker.write_text("do not touch me\n", encoding="utf-8")

    # The case record this test needs is produced *before* the snapshot, by the
    # CLI, which is allowed to write: that is the boundary being tested.
    receipt_id, _record, case_dir = run_a_case(tmp_path)
    monkeypatch.chdir(workdir)
    attempts = block_network(monkeypatch)
    before = snapshot(workdir, REPLAY, FIXTURES, EVIDENCE)

    responses = [
        (name, call(name, *args)) for name, args in ordered_cases(receipt_id,
                                                                 case_dir)
    ]

    after = snapshot(workdir, REPLAY, FIXTURES, EVIDENCE)
    assert attempts == [], f"tools reached for the network: {attempts}"
    assert after == before, "a tool changed a file on disk"
    assert marker.read_text(encoding="utf-8") == "do not touch me\n"
    assert list(workdir.iterdir()) == [marker], (
        "a tool wrote into the directory it was called from"
    )
    for name, response in responses:
        assert response["ok"] is True, f"{name} failed: {response['error']}"


def ordered_cases(receipt_id: str, case_dir: Path) -> list[tuple]:
    cases = [(name, CASES[name]) for name in mcpserver.TOOL_ORDER
             if name in CASES]
    cases.append(("explain_verdict", (receipt_id, str(case_dir))))
    cases.append(("get_case_record", (receipt_id, str(case_dir))))
    return sorted(cases, key=lambda pair: pair[0])


def test_the_tools_never_build_a_runner_that_could_commit(tmp_path, monkeypatch):
    """A second, structural guard on the same claim.

    :class:`~tenable_email.runner.OfflineRunner` is what writes receipts and
    journals, and it refuses ``begin`` on a ``root`` it never creates lazily. If
    any tool ever constructs one, the write path is reachable from a call a
    client makes -- so the class is replaced here with something that says so.
    """
    import tenable_email.runner as runner_module

    def exploding(*args, **kwargs):
        raise AssertionError("a tool constructed an OfflineRunner")

    monkeypatch.setattr(runner_module, "OfflineRunner", exploding)
    monkeypatch.setattr(mcpserver, "OfflineRunner", exploding, raising=False)
    for name, args in list(CASES.items()):
        if name == "analyze_eml_directory":
            args = (str(FIXTURES),)
        result = call(name, *args)
        assert result["ok"] is True, f"{name}: {result['error']}"
    assert not list(tmp_path.iterdir())


def test_tools_say_which_route_their_model_answers_took():
    """The caller is told where the opinions came from, on every message tool."""
    for name, args in (
        ("analyze_eml", (str(SAMPLE),)),
        ("analyze_eml_directory", (str(FIXTURES),)),
        ("classify_local", (str(SAMPLE),)),
        ("analyze_urls", ([SAFE_LINKS],)),
    ):
        offline = call(name, *args)["offline"]
        assert offline["mode"].startswith("offline")
        assert offline["replay_corpus"] == "replay"
        assert offline["recordings"] > 0
        assert offline["live_calls"].startswith("never")
        assert "://" not in canonical_json(offline), (
            "a configured endpoint address must never be echoed to a client"
        )
        for tier in offline["tiers_with_recordings"]:
            assert tier in {name for name, _f, _s in mcpserver.MODEL_TIERS}


def test_the_corpus_note_is_honest_when_no_recordings_can_be_found(
    tmp_path, monkeypatch
):
    """An installed wheel carries no fixtures: that must read as a limitation."""
    monkeypatch.setattr(mcpserver, "default_replay_dir", lambda: None)
    result = call("analyze_eml", str(SAMPLE))
    assert result["ok"] is True
    offline = result["offline"]
    assert offline["replay_corpus"] is None
    assert offline["recordings"] == 0
    assert "corpus" in offline["corpus_note"] or "deterministic-only" in (
        offline["corpus_note"]
    )
    unavailable = {
        item["key"] for item in result["evidence"]["unavailable"]
    }
    assert unavailable, "every tier must record itself unavailable, by name"
    assert len(result["evidence"]["model_judgment"]) == 0, (
        "with no corpus and no endpoints there are no opinions, and pretending "
        "otherwise is the fabrication this project refuses"
    )


# --------------------------------------------------------------------------
# SKILL.md: the contract's eight stages, and the judgment around them
# --------------------------------------------------------------------------


def load_validator():
    import importlib.util

    path = REPO / "tools" / "validate_contract.py"
    spec = importlib.util.spec_from_file_location(
        "validate_contract_for_skill_tests", path
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_skill_md_carries_the_eight_stage_titles_in_order():
    """The check ``tools/validate_contract.py`` used to skip.

    Run through the validator's own extractor, so this is the same comparison a
    reviewer's command makes -- two implementations of "read the stage list out
    of a markdown document" would be a drift nobody noticed.
    """
    validator = load_validator()
    text = SKILL.read_text(encoding="utf-8")
    titles = validator.prose_stage_titles(text)
    contract = load_contract()
    assert titles == contract.titles(), (
        f"SKILL.md says {titles}, the contract says {contract.titles()}"
    )
    assert len(titles) == 8
    assert titles == [
        "Intake", "Parse and authenticate", "Deterministic signals",
        "Classifier cascade", "Vision", "Attachment structure", "Adjudication",
        "Disposition and writeback",
    ]
    assert validator.document_violations(contract, text, "SKILL.md") == []
    assert "human approval required" in text


def test_skill_md_covers_the_judgment_the_tools_cannot_encode():
    """Every F3 promise, asserted against the document rather than assumed.

    The text is flattened and de-marked before searching: prose is line-wrapped,
    and an emphasis marker inside a phrase must not be able to hide its absence.
    """
    text = SKILL.read_text(encoding="utf-8")
    flat = " ".join(
        text.lower().replace("`", "").replace("*", "").split()
    )
    for promise, needle in (
        ("manual review is an outcome", "manual_review is an outcome"),
        ("do not resolve it by asking again", "do not try to resolve it"),
        ("disagreement is the signal", "disagreement between tiers is the"),
        ("averaging it away is the failure", "do not average it away"),
        ("unanimity takes the weakest vote", "weakest vote's confidence"),
        ("a verified finding is a floor", "is a floor"),
        ("an unknown never becomes a fact", "an unknown never becomes a fact"),
        ("the four provenances", "model_judgment"),
        ("unavailable is not unknown", "unavailable is not unknown"),
        ("neither gap is evidence of absence", "evidence of absence"),
        ("authentication is not legitimacy",
         "does not mean the message is legitimate"),
        ("the business-email-compromise case", "business email compromise"),
        ("the reference rule that is wrong", "strong indicator of a clean"),
        ("a newsletter quoting a payload", "newsletter quoting an attack"),
        ("what corroboration means", "corroboration means"),
        ("a vip list from an authoritative directory", "identity directory"),
        ("and not from scraping public pages", "scraping the organization"),
        ("scraping is the attacker's own technique", "targeting technique"),
        ("scraping is an undocumented data flow", "outbound data flow"),
        ("scraping breaks reproducibility", "stop being reproducible"),
        ("a shipped person list is dual-use", "dual-use"),
        ("role-based identities ship, names do not", "no individual's name"),
        ("a truncated analysis is never a complete one",
         "truncated analysis is never a complete one"),
        ("unchecked links are not clean links", "not the same sentence"),
        ("what the system cannot prove", "cannot prove"),
    ):
        assert needle in flat, f"SKILL.md must cover {promise}: {needle!r}"
    assert flat.count("unavailable") >= 2 and flat.count("unknown") >= 3, (
        "the provenance vocabulary has to be used, not named once"
    )
    assert text.count("\n") < 400, (
        "the skill is meant to be read by an agent inside a context window, "
        "not scrolled through"
    )


def test_server_instructions_do_not_contradict_the_skill():
    """The text a client is handed at connect time has to carry the same three
    refusals, or the skill is documentation nobody reads."""
    text = mcpserver.SERVER_INSTRUCTIONS
    assert "manual_review" in text
    assert "UNAVAILABLE is not UNKNOWN" in text
    assert "re-ask" in text
    assert "business-email-compromise" in text
    assert "truncated: true" in text
    lowered = text.lower()
    assert "no tool here writes" in lowered
    assert "averaging" in lowered


def test_tool_descriptions_state_the_read_only_property_where_it_matters():
    for name in ("analyze_eml", "analyze_eml_directory", "get_case_record"):
        assert "ead-only" in mcpserver.TOOL_DESCRIPTIONS[name] or (
            "Read-only" in mcpserver.TOOL_DESCRIPTIONS[name]
        ), f"{name} must tell a client it changes nothing"
    assert "no message body" in mcpserver.TOOL_DESCRIPTIONS["analyze_eml"]
    for name in mcpserver.TOOL_ORDER:
        assert "write" not in mcpserver.TOOL_DESCRIPTIONS[name].lower().replace(
            "writes nothing", ""
        ).replace("read-only", ""), f"{name} advertises a write"


# --------------------------------------------------------------------------
# the wrapper, exercised against a stand-in server object
# --------------------------------------------------------------------------


class FakeTool:
    def __init__(self, name, description, function):
        self.name = name
        self.description = description
        self.function = function


class FakeManager:
    """The shape FastMCP's tool manager has, as this helper reads it."""

    def __init__(self):
        self.tools: list[FakeTool] = []

    def list_tools(self):
        return list(self.tools)


class FakeFastMCP:
    def __init__(self, name, instructions=None):
        self.name = name
        self.instructions = instructions
        self._tool_manager = FakeManager()
        self.transports: list[str] = []

    def tool(self, name=None, description=None):
        def register(function):
            self._tool_manager.tools.append(
                FakeTool(name, description, function)
            )
            return function

        return register

    def run(self, transport=None):
        self.transports.append(str(transport))


def test_build_server_registers_every_advertised_tool(monkeypatch):
    """Registration checked without the extra installed.

    ``build_server`` takes the class it wraps as a function call, so a stand-in
    server proves the same invariant a reviewer would: the nine names advertised
    are the nine names served, with the descriptions and the callables that were
    written for them.
    """
    monkeypatch.setattr(mcpserver, "_fastmcp_class", lambda: FakeFastMCP)
    app = mcpserver.build_server()

    assert isinstance(app, FakeFastMCP)
    assert app.name == mcpserver.SERVER_NAME
    assert app.instructions == mcpserver.SERVER_INSTRUCTIONS, (
        "a server that drops its instructions documents nothing to the agent "
        "that uses it"
    )
    served = mcpserver.registered_tool_names(app)
    assert served == mcpserver.TOOL_ORDER, (
        f"served {served}, advertised {mcpserver.TOOL_ORDER}"
    )
    for tool in app._tool_manager.tools:
        assert tool.description == mcpserver.TOOL_DESCRIPTIONS[tool.name]
        assert tool.function is mcpserver.MCP_WRAPPERS[tool.name]


def test_build_server_refuses_to_serve_a_partial_surface(monkeypatch):
    """A missing wrapper is a crash at startup, not a client's surprise later."""
    monkeypatch.setattr(mcpserver, "_fastmcp_class", lambda: FakeFastMCP)
    truncated = dict(mcpserver.MCP_WRAPPERS)
    truncated.pop("analyze_urls")
    monkeypatch.setattr(mcpserver, "MCP_WRAPPERS", truncated)
    with pytest.raises(mcpserver.McpUnavailable) as excinfo:
        mcpserver.build_server()
    assert "analyze_urls" in str(excinfo.value)
    assert "partial surface" in str(excinfo.value)


def test_a_registered_surface_that_disagrees_with_the_advertised_one_is_refused(
    monkeypatch
):
    """The served set is compared to the advertised set when it can be read."""
    class Overstated(FakeFastMCP):
        def tool(self, name=None, description=None):
            register = super().tool(name="extra-tool", description="not ours")
            return register

    monkeypatch.setattr(mcpserver, "_fastmcp_class", lambda: Overstated)
    with pytest.raises(mcpserver.McpUnavailable) as excinfo:
        mcpserver.build_server()
    assert "must be the same set" in str(excinfo.value)


def test_the_entry_point_starts_a_stdio_server_and_no_other_transport(
    monkeypatch
):
    """`transport: stdio` in the listing is what the code actually asks for."""
    started = FakeFastMCP("tenable-email")
    monkeypatch.setattr(mcpserver, "build_server", lambda **kwargs: started)
    assert mcpserver.main([]) == 0
    assert started.transports == ["stdio"], (
        "the declared transport and the started one must be the same thing"
    )


def test_a_server_that_cannot_start_never_reports_success(monkeypatch):
    def refuse(**kwargs):
        raise mcpserver.McpUnavailable(mcpserver.INSTALL_HINT)

    monkeypatch.setattr(mcpserver, "build_server", refuse)
    assert mcpserver.main([]) == 1


def test_registered_tool_names_returns_empty_for_an_unknown_shape():
    """The helper degrades to "nothing readable", so callers can branch on it."""
    assert mcpserver.registered_tool_names(object()) == ()
    assert mcpserver.registered_tool_names(FakeFastMCP("x")) == ()
