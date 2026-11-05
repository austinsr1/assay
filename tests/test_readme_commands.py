"""The commands README documents must actually run.

The Exchange review checklist verifies that *"installation instructions are
accurate - referenced files, packages, and commands actually exist."* A README
whose headline command fails on a fresh clone is a reviewer finding, and this
project shipped one: `python3 -m tenable_email demo` needs the package installed
or `PYTHONPATH=src`, because the layout is `src/`.

These tests pin the documented invocation forms and the accuracy of the
surrounding claims. They were added after manually verifying all six in a
throwaway venv, with and without Pillow.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
README = REPO / "README.md"
PYPROJECT = REPO / "pyproject.toml"


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def test_console_script_is_declared_and_resolves():
    text = PYPROJECT.read_text(encoding="utf-8")
    assert 'tenable-email = "tenable_email.cli:main"' in text, (
        "pyproject.toml must declare the console script the README documents"
    )
    sys.path.insert(0, str(REPO / "src"))
    from tenable_email.cli import main  # noqa: F401

    assert callable(main)


def test_module_entry_point_exists():
    assert (REPO / "src" / "tenable_email" / "__main__.py").is_file(), (
        "python3 -m tenable_email requires __main__.py"
    )


def test_readme_documents_the_install_step_before_the_module_form():
    """The src/ layout means the bare module form needs help. Say so."""
    text = _readme()
    assert "pip install -e . --no-deps" in text, (
        "README must give the zero-dependency install command"
    )
    assert "PYTHONPATH=src" in text, (
        "README must document the no-install invocation, because the package "
        "lives under src/ and `python3 -m tenable_email` alone fails"
    )
    assert "No module named tenable_email" in text, (
        "README should state the failure mode plainly rather than let a reviewer "
        "discover it"
    )
    # The install command must come first.
    assert text.index("pip install -e . --no-deps") < text.index("PYTHONPATH=src")


def test_every_documented_subcommand_exists():
    """Each subcommand named in README must be a real argparse choice."""
    sys.path.insert(0, str(REPO / "src"))
    from tenable_email import cli

    text = _readme()
    documented = set(re.findall(r"tenable-email (\w[\w-]*)", text))
    # Ignore prose that is not a command invocation.
    documented -= {"demo\b"}
    assert documented, "README documents no subcommands"

    parser = cli.build_parser() if hasattr(cli, "build_parser") else None
    if parser is None:
        # Fall back to asking argparse for the real thing.
        out = subprocess.run(
            [sys.executable, "-m", "tenable_email", "--help"],
            cwd=REPO, capture_output=True, text=True,
            env={"PYTHONPATH": str(REPO / "src"), "PATH": "/usr/bin:/bin"},
        )
        help_text = out.stdout + out.stderr
        missing = [c for c in documented if c not in help_text]
        assert not missing, f"README documents subcommands that do not exist: {missing}"
        return

    choices = set()
    for action in parser._actions:
        if getattr(action, "choices", None):
            choices |= {str(c) for c in action.choices}
    missing = documented - choices
    assert not missing, f"README documents subcommands that do not exist: {missing}"


def test_demo_runs_with_no_arguments_no_config_and_no_network():
    """The single most important reviewer experience."""
    code = (
        "import socket\n"
        "socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(\n"
        "    AssertionError('network access during demo'))\n"
        "import sys\n"
        "from tenable_email.cli import main\n"
        "sys.argv = ['tenable-email', 'demo']\n"
        "sys.exit(main())\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO, capture_output=True, text=True,
        env={"PYTHONPATH": str(REPO / "src"), "PATH": "/usr/bin:/bin"},
    )
    assert out.returncode == 0, f"demo failed:\n{out.stdout[-800:]}\n{out.stderr[-800:]}"
    assert "label agreement" in out.stdout
    assert "14 case(s)" in out.stdout


def test_readme_does_not_claim_a_command_that_fails():
    """Regression guard for the specific defect this module exists for.

    README once opened with "One command, no arguments, no configuration, no
    network: python3 -m tenable_email demo". Without an install or PYTHONPATH
    that command exits non-zero. If the bare form is presented as self-sufficient
    again, this fails.
    """
    text = _readme()
    bare = "python3 -m tenable_email"
    hits = [m.start() for m in re.finditer(re.escape(bare), text)]
    for pos in hits:
        window = text[max(0, pos - 700): pos + 700]
        assert "PYTHONPATH" in window or "No module named" in window, (
            f"README presents `{bare} ...` as self-sufficient at offset {pos}, "
            f"but it needs an install or PYTHONPATH=src. Every mention must sit "
            f"near the caveat."
        )


def test_documented_commands_name_an_interpreter_the_script_accepts():
    """Every documented `python3 x.sh` / `bash x.py` is a command that cannot run.

    README told reviewers to run ``python3 tools/record-replay.sh --dry-run``. That file is a
    bash script, so the command dies with a SyntaxError on its ``set -euo pipefail`` line.
    It sat in the section a reviewer reads to check which tiers are configured, which is to
    say it was on the path of anyone verifying the offline story, and the Exchange baseline
    review found it before this suite did.

    The existing guard in this module covers one historical defect - the bare
    ``python3 -m tenable_email`` form presented as self-sufficient - and cannot generalise,
    because the failure it pins is about a missing PYTHONPATH rather than a command that is
    wrong as typed. This closes the wider class: a documented invocation whose interpreter
    does not match the file it points at. Extension decides, and the shebang is cross-checked
    where there is one, so a ``.sh`` file with a Python shebang is caught rather than waved
    through.
    """
    root = Path(__file__).resolve().parent.parent
    pat = re.compile(r"\b(python3|python|bash|sh)\s+((?:tools|eval|src)/[A-Za-z0-9_./-]+\.(?:sh|py))\b")
    py_interp = {"python3", "python"}
    checked = 0
    for doc in sorted(root.glob("*.md")) + sorted((root / "docs").glob("*.md")):
        text = doc.read_text(encoding="utf-8")
        for interp, rel in pat.findall(text):
            target = root / rel
            rel_name = f"{doc.name}: {interp} {rel}"
            if not target.exists():
                continue  # dangling paths are test_doc_references.py's job, not this one's
            checked += 1
            ext_wants_py = rel.endswith(".py")
            assert (interp in py_interp) == ext_wants_py, (
                f"{rel_name} names the wrong interpreter: the file is "
                f"{'Python' if ext_wants_py else 'a shell script'} by extension."
            )
            head = target.read_text(encoding="utf-8", errors="replace").split("\n", 1)[0]
            if head.startswith("#!"):
                shebang_is_py = "python" in head
                assert shebang_is_py == ext_wants_py, (
                    f"{rel} has extension {'py' if ext_wants_py else 'sh'} but shebang {head!r}"
                )
    assert checked >= 5, (
        f"only {checked} documented interpreter+script pairs were found; the pattern has "
        f"stopped matching, so this test would pass while checking nothing"
    )
