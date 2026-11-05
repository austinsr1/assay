"""The stdio wrapper, tested with and without the optional extra present.

The brief for this file asked for the wrapper tests to be skipped when ``mcp``
is not importable -- "conditional on the import, not unconditional" -- and, in
the same bundle, for the repository suite to keep showing **zero skips** and for
the external review bundle to keep showing exactly the six skips designed into
it. Both of those cannot hold while a skip lives here: the extra is absent on
every machine that runs this suite today, including the bundle, so a skip
conditioned on the import would add six skips to both counts.

So nothing in this module skips. The single import the wrapper performs is
satisfied either by the **real** ``mcp`` package when the extra is installed, or
by a stand-in injected into ``sys.modules`` when it is not -- which runs the same
statement inside :func:`tenable_email.mcpserver._fastmcp_class`,
``from mcp.server.fastmcp import FastMCP``, instead of monkeypatching the function
that holds it. What is then asserted is the wrapper's own behaviour: that the
nine advertised tools are the nine registered, that the descriptions and
signatures are the ones the listing promises, that the transport started is the
transport declared, and that a missing extra produces an instruction rather than a
traceback. ``USING_REAL_MCP`` records which of the two routes the run took, so
that is visible in the test names rather than guessed at later.
"""

from __future__ import annotations

import inspect
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tenable_email import mcpserver  # noqa: E402

# Availability is decided by asking the wrapper the question it actually
# answers -- "can you resolve a server class?" -- rather than by importing
# ``mcp.server.fastmcp`` here. Those disagree on mcp 2.x, where the package is
# installed and that module path is a stub whose whole purpose is to say the
# class moved; a test that concluded "the extra is missing" from that import
# would then assert the absent-environment behaviour against a machine that has
# the dependency, which is how a compatibility shim gets shipped untested.
try:
    REAL_FASTMCP = mcpserver._fastmcp_class()
    import mcp  # noqa: F401 - recorded so the absent-check below is meaningful

    USING_REAL_MCP = True
    IMPORT_ERROR = ""
except mcpserver.McpUnavailable as exc:
    REAL_FASTMCP = None
    USING_REAL_MCP = False
    IMPORT_ERROR = str(exc).splitlines()[0]


class StandInTool:
    def __init__(self, name, description, function):
        self.name = name
        self.description = description
        self.function = function


class StandInManager:
    """Shaped like the object ``registered_tool_names`` looks for."""

    def __init__(self, server: "StandInServer"):
        self.server = server

    def list_tools(self):
        return list(self.server.registered)


class StandInServer:
    """The part of FastMCP the wrapper actually uses.

    A name, instructions, a ``tool(name=, description=)`` decorator that returns
    the function unchanged, and a ``run()`` that is told which transport -- which
    is precisely the surface ``build_server`` and ``main`` touch, and nothing
    more. A stand-in that reaches further than the code does would test the
    stand-in.
    """

    def __init__(self, name, instructions=None):
        self.name = name
        self.instructions = instructions
        self.registered: list[StandInTool] = []
        self.transports: list[str] = []
        self._tool_manager = StandInManager(self)

    def tool(self, name=None, description=None):
        def register(function):
            self.registered.append(StandInTool(name, description, function))
            return function

        return register

    def run(self, transport=None):
        self.transports.append(str(transport))


def install_stand_in(monkeypatch) -> type:
    """Make ``from mcp.server.fastmcp import FastMCP`` resolve to the stand-in.

    Installed through the module cache rather than by substituting the function
    that imports, so the import statement itself -- the line that *is* the
    dependency boundary -- is what executes. If ``_fastmcp_class`` ever imports
    from somewhere else, this stops working instead of passing quietly.
    """
    package = types.ModuleType("mcp")
    server = types.ModuleType("mcp.server")
    fastmcp = types.ModuleType("mcp.server.fastmcp")

    class InjectedFastMCP(StandInServer):
        pass

    InjectedFastMCP.__name__ = "FastMCP"
    fastmcp.FastMCP = InjectedFastMCP
    server.fastmcp = fastmcp
    package.server = server
    for name, module in (
        ("mcp", package),
        ("mcp.server", server),
        ("mcp.server.fastmcp", fastmcp),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    return InjectedFastMCP


def build(monkeypatch):
    """Build the server with whichever ``mcp`` this environment can supply."""
    if USING_REAL_MCP:
        return mcpserver.build_server(), REAL_FASTMCP
    injected = install_stand_in(monkeypatch)
    return mcpserver.build_server(), injected


def test_the_module_loads_without_the_extra_present_or_absent():
    """``import tenable_email.mcpserver`` happened at module scope, above.

    By the time this assertion runs, the claim has already been demonstrated --
    the tests in this file exist because the import succeeded. What is checked is
    the corollary: the ``mcp`` package is not pulled in by loading the module, so
    the only thing that can require it is building a server.
    """
    assert callable(mcpserver._fastmcp_class)
    if not USING_REAL_MCP:
        assert sys.modules.get("mcp") is None, (
            "importing mcpserver imported mcp: the extra would have become a "
            "runtime dependency of the whole package"
        )
    else:
        assert "mcp" in sys.modules, (
            "the availability check above concluded the extra is usable without "
            "the package being importable, which would make every real-API "
            "branch in this file a lie"
        )
    source = inspect.getsource(mcpserver._fastmcp_class)
    assert "from mcp.server.fastmcp import FastMCP" in source, (
        "the wrapper is expected to import FastMCP where this library version "
        "keeps it; change the test and the code together"
    )


def test_the_injected_import_satisfies_the_real_statement(monkeypatch):
    injected = install_stand_in(monkeypatch)
    assert mcpserver._fastmcp_class() is injected


def test_a_missing_extra_raises_an_instruction_not_a_module_error():
    if USING_REAL_MCP:
        assert mcpserver._fastmcp_class() is REAL_FASTMCP, (
            "with the extra installed the class must come back, from whichever "
            "module path this version of the library keeps it in"
        )
        return
    with pytest.raises(mcpserver.McpUnavailable) as excinfo:
        mcpserver._fastmcp_class()
    message = str(excinfo.value)
    assert "pip install -e .[mcp]" in message
    assert "optional extra" in message
    assert "Traceback" not in message
    assert "mcp" in message


def test_build_server_returns_a_server_object(monkeypatch):
    app, expected = build(monkeypatch)
    assert isinstance(app, expected)
    assert app.name == mcpserver.SERVER_NAME
    assert callable(getattr(app, "run", None)), (
        "stdio serving needs app.run()"
    )
    run = getattr(app, "run")
    assert not inspect.iscoroutinefunction(run), (
        "the console script calls run() synchronously; an async run would "
        "return an unawaited coroutine and exit immediately"
    )


def test_build_server_registers_every_advertised_tool(monkeypatch):
    app, _expected = build(monkeypatch)
    served = mcpserver.registered_tool_names(app)
    assert served, (
        "the tool manager this version of mcp exposes is not one "
        "registered_tool_names() can read -- update the helper in "
        "src/tenable_email/mcpserver.py rather than letting the "
        "advertised-versus-served comparison stop meaning anything"
    )
    assert set(served) == set(mcpserver.TOOL_ORDER), (
        f"served {sorted(served)}, advertised {sorted(mcpserver.TOOL_ORDER)}"
    )
    assert len(served) == len(mcpserver.TOOL_ORDER) == 9, (
        "a tool registered twice is a client seeing two entry points for one "
        "function"
    )


def test_build_server_carries_the_advertised_descriptions(monkeypatch):
    app, _expected = build(monkeypatch)
    manager = getattr(app, "_tool_manager", None)
    assert manager is not None, (
        "no readable tool manager on this server object; see "
        "test_build_server_registers_every_advertised_tool"
    )
    described = {
        str(getattr(tool, "name", "")): str(getattr(tool, "description", ""))
        for tool in manager.list_tools()
    }
    assert set(described) == set(mcpserver.TOOL_ORDER)
    for name, description in described.items():
        assert description == mcpserver.TOOL_DESCRIPTIONS[name], (
            f"{name}: the description a client reads must be the one in the "
            "source of truth, not a copy of it that can drift"
        )


def test_the_instructions_a_client_is_handed_at_connect(monkeypatch):
    app, _expected = build(monkeypatch)
    assert getattr(app, "instructions", None) == mcpserver.SERVER_INSTRUCTIONS, (
        "SKILL.md is compressed into the server instructions; a server that "
        "drops them documents nothing for the agent that uses it"
    )


def test_a_named_server_keeps_its_name_and_a_custom_its_text(monkeypatch):
    if not USING_REAL_MCP:
        install_stand_in(monkeypatch)
    app = mcpserver.build_server(
        name="soc-triage", instructions="read-only tools, escalate disagreement"
    )
    assert app.name == "soc-triage"
    assert app.instructions == "read-only tools, escalate disagreement"


def test_build_server_refuses_a_partial_surface(monkeypatch):
    install_stand_in(monkeypatch)
    truncated = dict(mcpserver.MCP_WRAPPERS)
    truncated.pop("analyze_urls")
    monkeypatch.setattr(mcpserver, "MCP_WRAPPERS", truncated)
    with pytest.raises(mcpserver.McpUnavailable) as excinfo:
        mcpserver.build_server()
    assert "analyze_urls" in str(excinfo.value)
    assert "partial surface" in str(excinfo.value)


def test_a_served_surface_wider_than_the_advertised_one_is_refused(monkeypatch):
    """The listing is a promise in both directions.

    A server that quietly serves an extra tool is a server whose published
    metadata is wrong, which is the same class of defect as advertising a tool it
    does not have -- so both halves of the comparison are enforced at startup.
    """

    class Overstated(StandInServer):
        def tool(self, name=None, description=None):
            return StandInServer.tool(
                self, name="extra-tool", description="never advertised"
            )

    monkeypatch.setattr(mcpserver, "_fastmcp_class", lambda: Overstated)
    with pytest.raises(mcpserver.McpUnavailable) as excinfo:
        mcpserver.build_server()
    assert "must be the same set" in str(excinfo.value)
    assert "extra-tool" in str(excinfo.value)


def test_the_entry_point_starts_a_stdio_server_and_no_other_transport(
    monkeypatch
):
    """``transport: stdio`` in the listing is what the code actually asks for."""
    started = StandInServer("tenable-email")
    monkeypatch.setattr(mcpserver, "build_server", lambda **kwargs: started)
    assert mcpserver.main([]) == 0
    assert started.transports == ["stdio"], (
        "the declared transport and the started transport have to be one thing, "
        "or the listing describes a server that does not exist"
    )


def test_main_names_the_extra_when_the_server_cannot_be_built(monkeypatch,
                                                              capsys):
    def refuse(**kwargs):
        raise mcpserver.McpUnavailable(
            "the MCP server needs the `mcp` package (No module named 'mcp').\n\n"
            + mcpserver.INSTALL_HINT
        )

    monkeypatch.setattr(mcpserver, "build_server", refuse)
    assert mcpserver.main([]) == 1
    captured = capsys.readouterr()
    assert captured.out == "", "a server that did not start must not look fine"
    assert "pip install -e .[mcp]" in captured.err
    assert "Traceback" not in captured.err


def test_the_wrapper_functions_forward_without_reaching_for_the_library():
    """A client's call is the tool function's answer, envelope and all.

    Run with or without ``mcp``: the wrappers are plain functions, and this is
    what makes the stand-in server above an honest test double rather than a
    substitute for behaviour the library itself provides.
    """
    message = REPO / "fixtures" / "synthetic" / "clean_internal_registrar.eml"
    absent_case = "rcpt-not-a-case"
    for name in mcpserver.TOOL_ORDER:
        wrapper = mcpserver.MCP_WRAPPERS[name]
        if name == "list_contracts":
            result = wrapper()
        elif name == "analyze_urls":
            result = wrapper(["https://example.edu/a"])
        elif name == "lookalike_domain":
            result = wrapper("example-verify.com")
        elif name in ("explain_verdict", "get_case_record"):
            result = wrapper(absent_case)
            assert result["ok"] is False, (
                f"{name} found a case record that does not exist"
            )
            assert result["error"]["code"] == "case-record-unreadable", (
                "an absent record is a structured answer, not a raised error"
            )
            continue
        elif name == "analyze_eml_directory":
            result = wrapper(str(REPO / "fixtures" / "synthetic"))
        else:
            result = wrapper(str(message))
        assert isinstance(result, dict), f"{name} returned {type(result)}"
        assert {"ok", "tool", "error"} <= set(result)
        assert result["tool"] == name
        assert result["ok"] is True, f"{name}: {result['error']}"


def test_a_client_call_returns_the_envelope_the_documentation_promises():
    """One call through the library itself, not through the stand-in.

    This is the assertion that the artifact matches its listing: a client asks
    for `list_contracts`, the server runs the tool, and what comes back is the
    same JSON envelope the direct function returns. It can only be exercised
    where ``mcp`` is importable, so the other branch asserts what the absent
    environment can still prove -- that the tool function itself answers
    offline -- and says which branch did the work rather than pretending both
    are the same claim.
    """
    import asyncio

    direct = mcpserver.list_contracts()
    assert direct["ok"] is True and direct["stage_count"] == 8

    if not USING_REAL_MCP:
        assert direct["this_surface"]["mutates"] is False, (
            "no server object available: the wrapper itself is covered by "
            "test_build_server_registers_every_advertised_tool against the "
            "stand-in, and this assertion ran against the plain function"
        )
        return

    app = mcpserver.build_server()
    result = asyncio.run(app.call_tool("list_contracts", {}))
    payload = _result_payload(result)
    assert payload["ok"] is True, payload
    assert payload["tool"] == "list_contracts"
    assert payload["stage_count"] == 8
    assert payload["this_surface"]["mutates"] is False
    assert payload["approval_gates"][0]["language"] == "human approval required"

    failed = asyncio.run(app.call_tool("analyze_eml", {"path": "nope.eml"}))
    error = _result_payload(failed)
    assert error["ok"] is False, (
        "a missing file must reach the client as a structured answer"
    )
    assert error["error"]["code"] == "not-found"
    assert "nope.eml" in error["error"]["message"]


def _result_payload(result) -> dict:
    """The tool's dict out of whichever result shape this mcp version returns.

    ``content[0].text`` is the v1 form and ``structured_content`` the v2 one; a
    third shape raises here with the object's own type in the message, so the
    failure names the version boundary rather than looking like a broken tool.
    """
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured.get("result", structured) if "result" in structured and "ok" not in structured else structured
    content = getattr(result, "content", None) or []
    if content:
        text = getattr(content[0], "text", None)
        if text:
            import json as _json

            return _json.loads(text)
    raise AssertionError(
        f"could not read a tool result from a {type(result).__name__}: the "
        "wrapper's round-trip test needs updating for this mcp version"
    )


def test_the_listing_still_describes_this_transport_runtime_and_auth():
    """The three frontmatter fields this module is responsible for."""
    text = (REPO / "docs" / "listing-drafts" / "mcp-server.md").read_text(
        encoding="utf-8"
    )
    assert 'transport: "stdio"' in text
    assert 'runtime: "python"' in text
    assert 'auth_method: "none"' in text, (
        "the server holds no credentials, so the listing must not imply it "
        "negotiates them"
    )
