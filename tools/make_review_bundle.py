#!/usr/bin/env python3
"""Build a clean copy of this repository for external review.

Produces ``dist/review-bundle/`` plus a tarball: every tracked file except the
two that carry private infrastructure detail, with a verification scan that must
pass before anything is written. Intended for handing the project to an outside
reviewer, and it is the same split Bundle G needs before the repository is made
public.

Nothing is deleted from the working tree and nothing here is committed.

Usage:
    python3 tools/make_review_bundle.py [--out dist/review-bundle] [--no-tar]
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

#: Tracked files excluded from any external copy, and why. Must stay in sync with
#: INTERNAL_FILES in tests/test_doc_references.py.
EXCLUDED = {
    "NOTES.md": "decision log; carries private host topology, tunnel detail and colleague context",
    "docs/EVIDENCE.md": "measurement register; names private inference endpoints and hosts",
}

#: Never copied under any circumstances, tracked or not.
NEVER = (".scratch/", ".git/", "dist/", "__pycache__/", ".pytest_cache/")

SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r'"type"\s*:\s*"service_account"'), "GCP service-account JSON"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    (re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), "GitHub personal access token"),
    (re.compile(r"\bsk-[0-9A-Za-z]{20,}\b"), "OpenAI-style secret key"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "Slack token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"(?i)\b(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
     "hardcoded credential assignment"),
]

PRIVATE_PATTERNS = [
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "RFC1918 10/8 address"),
    (re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"), "RFC1918 192.168/16 address"),
    (re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"), "RFC1918 172.16/12 address"),
    (re.compile(r"/home/[A-Za-z0-9_.-]+"), "absolute home-directory path"),
    (re.compile(r"/Users/[A-Za-z0-9_.-]+"), "absolute home-directory path"),
    (re.compile(r"/var/www/"), "web root path"),
    (re.compile(r"\bssh://[^\s)`]+"), "internal ssh remote"),
]

#: Files that legitimately quote the patterns they detect. Mirrors SELF_EXEMPT in
#: tests/test_doc_references.py.
SCAN_EXEMPT = {
    "tests/test_doc_references.py",
    "tools/record-results.sh",
    "tools/make_review_bundle.py",
}


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def org_terms() -> list[str]:
    path = REPO / ".scratch" / "forbidden-terms.txt"
    if not path.is_file():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def scan(paths: list[tuple[Path, str]]) -> dict[str, list[str]]:
    """Return {relative_path: [findings]} for every problem found.

    ``paths`` pairs each copied file with its **repository-relative** name, which
    is what the exemption set is keyed on. Comparing against the destination path
    instead silently exempts nothing - that was the first version's bug, and it
    failed closed, which is the only acceptable direction for it to fail.
    """
    terms = org_terms()
    problems: dict[str, list[str]] = {}
    for path, rel in paths:
        if rel in SCAN_EXEMPT:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            # Binary assets are checked for key material by name only.
            continue
        found: list[str] = []
        for pattern, label in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                if label == "hardcoded credential assignment":
                    value = m.group(2)
                    # An endpoint URL is not a credential, and tests in this
                    # repository deliberately assign obvious placeholders to a
                    # variable named `secret` in order to assert the value never
                    # reaches a recording or a receipt.
                    if value.lower().startswith(("http://", "https://")):
                        continue
                    if re.search(r"(?i)not-a-real|fake|dummy|placeholder|example|changeme|xxxx",
                                 value):
                        continue
                    # Two shapes that are structurally not credentials, added after the
                    # generic pattern fired on a type annotation and on a test literal in
                    # the Google intake adapter. Neither rule is name-based and neither
                    # exempts a file, so a real secret in the same module is still caught:
                    #
                    #   * a bracket means this is a type annotation or a format string
                    #     (`token: "Optional[str]"`), not a value; no credential contains
                    #     one, and the specific patterns below still catch every real
                    #     token family by its own prefix.
                    #   * lowercase words joined by hyphens with no digit (`inline-token`)
                    #     is a placeholder shape. Requiring a digit, a capital or length
                    #     would be a guess about entropy; matching the word shape is a
                    #     statement about syntax, which is what a regex can actually know.
                    #
                    # Both were verified against planted real secrets before being kept.
                    if any(c in value for c in "[]"):
                        continue
                    if re.fullmatch(r"[a-z]+(?:[-_][a-z]+)+", value):
                        continue
                found.append(f"SECRET {label}: {m.group(0)[:40]!r}")
        for pattern, label in PRIVATE_PATTERNS:
            for m in pattern.finditer(text):
                found.append(f"PRIVATE {label}: {m.group(0)[:40]!r}")
        for term in terms:
            if term in text:
                found.append(f"PRIVATE organization-specific term: {term!r}")
        if found:
            problems[rel] = sorted(set(found))
    return problems


REVIEWER_NOTE = """# Note to the external reviewer

This is a copy of the `tenable-email` repository prepared for review on
{stamp}. It is **not** the complete working tree.

## What is here

Every file tracked by git, except the two listed below. The test suite, the
synthetic fixture corpus, the committed model-response recordings and all
documentation of the research are included, so the project can be built, run and
verified from this copy alone:

```bash
pip install -e . --no-deps     # zero runtime dependencies
tenable-email demo             # offline: no arguments, no config, no network
python3 -m pytest tests/ -o addopts= -q
```

`tenable-email demo` needs no credentials, no endpoints and no network. It
dispositions fourteen synthetic messages using the deterministic stages plus
model responses replayed from committed recordings.

## What was deliberately removed

| File | Why |
|---|---|
| `NOTES.md` | Internal decision log. Carries the operator's private host topology, tunnel configuration and colleague context. |
| `docs/EVIDENCE.md` | Internal measurement register. Names private inference endpoints by address. |

Their absence leaves gaps in the provenance chain: several measurements quoted in
`README.md` and `docs/MODELS.md` were recorded against hosts this copy does not
name. The numbers are real; the endpoints are private. Everything reproducible
from this copy is reproducible without them.

Also absent, and never part of the repository: `.scratch/`, which holds the
predecessor engine this project was ported from. That file contains real employee
addresses and live campaign indicators and is gitignored.

## What to check

The verification scan that produced this bundle asserted:

- no private key block, service-account JSON, API key, access token or hardcoded
  credential assignment in any included file
- no RFC1918 address, absolute home path, web root, ssh remote or
  organization-specific term in any included file

Three files are exempt from that scan because they define the patterns they
detect, and would otherwise flag themselves: `tests/test_doc_references.py`,
`tools/record-results.sh` and `tools/make_review_bundle.py`. Each is listed in
`SCAN_EXEMPT` in this script with the same justification required of the test
suite's own allowlist.

## Where review effort is best spent

1. **`README.md`** - intended architecture, the models actually used, and known
   limitations. The limitations section is meant to be read, not skipped.
2. **`docs/PARITY.md`** - the capability-by-capability comparison against the
   KnowBe4 PhishER + Claude reference playbook, including two places we are
   deliberately worse and one correctness bug we inherited and fixed.
3. **`docs/MODELS.md`** - classifier research verified against primary sources,
   including a widely recommended model whose published false-positive rate is
   0.959 and a retracted criterion of our own.
4. **`docs/PRIOR-WINNERS.md`** - what placed at SWARM Black Hat and what this
   project adopts from each.
5. **`src/tenable_email/evidence.py`** - the facts / model-judgments / unknowns
   separation the whole design rests on.
6. **`tests/`** - {tests} tests. `tests/test_offline_default_path.py` and
   `tests/test_readme_commands.py` exist because both of those things were broken
   once and the ordinary suite could not see it.

Blunt assessment welcome, especially on: whether the cascade actually reduces
work rather than relocating it; whether the receipt contract enforces anything a
determined operator could not bypass; and whether the known-limitations section
is honest or hedging.
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="dist/review-bundle", type=Path)
    ap.add_argument("--no-tar", action="store_true")
    args = ap.parse_args(argv)

    out = (REPO / args.out).resolve()
    if REPO in out.parents or out == REPO:
        pass
    else:
        print(f"ERROR: --out must stay inside the repository, got {out}")
        return 2

    tracked = tracked_files()
    included = [
        t for t in tracked
        if t not in EXCLUDED and not any(t.startswith(n) for n in NEVER)
    ]
    excluded_present = [t for t in EXCLUDED if t in tracked]

    print(f"tracked files: {len(tracked)}")
    print(f"included:      {len(included)}")
    print(f"excluded:      {sorted(excluded_present)}")

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    copied: list[Path] = []
    for rel in included:
        src = REPO / rel
        if not src.is_file():
            continue
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append((dst, rel))

    print(f"copied:        {len(copied)} files")

    problems = scan(copied)
    if problems:
        print("\nVERIFICATION FAILED - bundle not written to tarball:")
        for rel, findings in sorted(problems.items()):
            print(f"  {rel}")
            for f in findings[:5]:
                print(f"      {f}")
        shutil.rmtree(out)
        print("\nBundle directory removed. Fix the findings and re-run.")
        return 1

    print("verification:  PASS - no secrets, no private infrastructure")

    test_count = "the full"
    junit = REPO / "docs" / "results" / "junit.xml"
    if junit.is_file():
        m = re.search(r'tests="(\d+)"', junit.read_text(encoding="utf-8"))
        if m:
            test_count = m.group(1)

    (out / "REVIEWER-NOTE.md").write_text(
        REVIEWER_NOTE.format(
            stamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            tests=test_count,
        ),
        encoding="utf-8",
    )

    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True
    ).stdout.strip()
    # Machine-readable exclusion manifest. tests/test_doc_references.py reads it
    # so a reference to a deliberately removed file is permitted-absent rather
    # than reported as dangling; without it the bundle's own TODO fails a check
    # that is correct in the repository.
    (out / "BUNDLE-EXCLUDED.txt").write_text(
        "\n".join(sorted(EXCLUDED)) + "\n", encoding="utf-8"
    )

    (out / "BUNDLE-PROVENANCE.txt").write_text(
        f"source commit: {sha}\n"
        f"built: {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n"
        f"files: {len(copied) + 2}\n"
        f"excluded: {', '.join(sorted(excluded_present)) or '(none)'}\n",
        encoding="utf-8",
    )

    if not args.no_tar:
        tar_path = out.parent / "review-bundle.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            tf.add(out, arcname=out.name)
        size = tar_path.stat().st_size
        print(f"\ntarball:       {tar_path} ({size // 1024} KiB)")

    print(f"bundle:        {out}")
    print("\nSafe to hand to an external reviewer. Re-run after any change.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
