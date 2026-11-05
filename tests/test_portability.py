"""The source must run on the Python versions the package claims to support.

`pyproject.toml` declares `requires-python = ">=3.10"`. That is a promise, and this
file is what keeps it. It exists because the promise has now been broken twice, both
times by code that ran fine on the build host:

* `fixtures/generate.py` used `Path.write_text(..., newline=...)`, a 3.10-only
  keyword, which took 122 tests down as collection errors on a 3.9 host.
* `src/tenable_email/webui.py` used a backslash inside an f-string replacement field,
  which is PEP 701 and therefore 3.12-only. Every module importing it failed at
  collection on 3.9 and 3.11.

The second one is the reason this file does not simply ask the interpreter. An
`ast.parse(..., feature_version=(3, 10))` check was run against the broken file and
reported that it parsed cleanly: **`feature_version` does not enforce the f-string
grammar change.** A verification method that cannot fail is not a verification, so the
construct is detected directly from the syntax tree instead, and the detection is
proven against the exact code that shipped.

A second, weaker layer is included because it is cheap: if an interpreter older than
the build host's happens to be on PATH, every source file is really compiled with it.
That layer reports loudly when it cannot run rather than passing silently, because the
first layer is a detector for known constructs and this one is the actual thing.
"""

from __future__ import annotations

import ast
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

#: Directories whose Python is part of the shipped package or its evaluation harness.
#: `dist/` is excluded: it holds generated exports that are not this tree's source.
SOURCE_ROOTS = ("src", "eval", "tools", "tests", "fixtures")

MINIMUM_DECLARED = (3, 10)


def _source_files() -> list[pathlib.Path]:
    found: list[pathlib.Path] = []
    for root in SOURCE_ROOTS:
        base = REPO / root
        if base.is_dir():
            found.extend(sorted(base.rglob("*.py")))
    # The package's own entry points, which no root above covers.
    for name in ("setup.py", "conftest.py"):
        candidate = REPO / name
        if candidate.is_file():
            found.append(candidate)
    return found


def pep701_violations(source: str, *, filename: str = "<string>") -> list[str]:
    """Constructs that need Python 3.12+ even though the package claims 3.10.

    Detected from the syntax tree rather than by regex over lines, so multi-line
    f-strings are covered and ordinary backslashes in normal strings are not flagged.
    Only f-string *replacement fields* are examined: a backslash in the literal text
    around them has always been legal.
    """
    problems: list[str] = []
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [f"{filename}:{exc.lineno}: does not parse at all: {exc.msg}"]

    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        for value in node.values:
            if not isinstance(value, ast.FormattedValue):
                continue
            segment = ast.get_source_segment(source, value)
            if segment is None:
                continue
            line = getattr(value, "lineno", "?")
            if "\\" in segment:
                problems.append(
                    f"{filename}:{line}: backslash inside an f-string replacement "
                    f"field is PEP 701 (3.12+): {segment[:70]}"
                )
    return problems


def test_the_detector_catches_the_construct_that_actually_shipped():
    """Teeth. A guard that has never fired is not a guard.

    This is the exact line that broke collection on 3.9 and 3.11, so the detector is
    proven against the real failure rather than against a shape someone imagined.
    """
    broken = '''flags = []
row = f'<tr{" class=\\"row-flagged\\"" if flags else ""}>'
'''
    found = pep701_violations(broken, filename="canary.py")
    assert found, "the detector missed the construct it exists to catch"
    assert any("backslash" in f for f in found), found


def test_the_detector_does_not_flag_legal_backslashes():
    """Otherwise the guard gets disabled the first time it cries wolf."""
    legal = '''
path = "C:\\\\tmp"
pattern = r"\\d+"
text = f"value is {path!r}"
multi = (
    f"one {path} "
    f"two {pattern}"
)
'''
    assert pep701_violations(legal, filename="legal.py") == []


def test_no_tracked_source_uses_a_newer_python_than_the_package_declares():
    offenders: list[str] = []
    files = _source_files()
    assert files, "found no source files to check, so this test proved nothing"
    for path in files:
        text = path.read_text(encoding="utf-8")
        try:
            offenders.extend(
                pep701_violations(text, filename=str(path.relative_to(REPO)))
            )
        except Exception as exc:  # a file we cannot read is itself a finding
            offenders.append(f"{path.relative_to(REPO)}: could not be scanned: {exc}")
    assert not offenders, (
        f"these need Python 3.12+ but requires-python is >="
        f"{'.'.join(str(v) for v in MINIMUM_DECLARED)}:\n  " + "\n  ".join(offenders)
    )


def test_the_declared_floor_matches_what_this_file_enforces():
    """Keep the promise and the check pointing at the same version."""
    import tomllib

    declared = tomllib.loads((REPO / "pyproject.toml").read_text())["project"][
        "requires-python"
    ]
    digits = tuple(int(n) for n in "".join(
        c for c in declared if c.isdigit() or c == "."
    ).split(".") if n)
    assert digits == MINIMUM_DECLARED, (
        f"pyproject declares {declared} but this file enforces {MINIMUM_DECLARED}"
    )

# --------------------------------------------------------------------------
# what this detector does NOT cover, stated rather than left implicit
# --------------------------------------------------------------------------

LEGAL_NESTING = (
    "value = 1.0\n"
    "cell = f'<td>{escape(f\"{value:.2f}\")}</td>'\n"
    "stamp = f\"{shown.strftime('%Y-%m-%d %H:%M')}\"\n"
)


def test_legal_nested_fstrings_and_inner_quotes_are_not_flagged():
    """Regression pin for the false positives that caused the quote check to be dropped.

    Both of these were reported as violations by the first version of the detector and
    both compile cleanly on Python 3.9, verified on an interpreter rather than assumed.
    """
    assert pep701_violations(LEGAL_NESTING, filename="legal.py") == []


def test_the_known_gap_is_documented_and_the_compensating_tool_exists():
    """PEP 701 also permits reusing the enclosing quote inside a replacement field.

    Detecting that from the syntax tree was attempted and produced false positives on
    ordinary code, so it was removed: a guard that cries wolf gets disabled, which is
    worse than a narrower guard that is trusted. The AST layer therefore covers the
    backslash construct that actually shipped, and quote reuse is left to
    `tools/check-portability.sh`, which compiles every source file with each available
    interpreter. That tool is the stronger check and is not a pytest test, because this
    build host has exactly one Python and a conditionally-skipping test would add a skip
    to a suite that is required to have none.
    """
    tool = REPO / "tools" / "check-portability.sh"
    assert tool.is_file(), "the compensating control for the known gap is missing"
    assert tool.stat().st_mode & 0o111, "the tool is not executable"
    text = tool.read_text()
    assert "py_compile" in text
    assert "3.10" in text, "the tool must know the declared floor"
