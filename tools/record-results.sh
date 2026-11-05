#!/usr/bin/env bash
# Regenerate the committed test-evidence artifacts.
#
# Run this after any change to src/ or tests/ and commit the result. The
# recorded output names the commit it describes, so a reviewer can tell whether
# the evidence still matches the code they are reading.
#
# Deliberately records no hostname, username, home path or network address: this
# file's output is committed to a public repository, and tests enforce that.
#
# Usage: tools/record-results.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="docs/results"
mkdir -p "$OUT_DIR"

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || { echo "ERROR: $PY not found"; exit 2; }

SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
SHORT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
# Dirty check excludes docs/results/ : the artifacts being written are always
# uncommitted at run time, so including them would make this field permanently
# "yes" and therefore meaningless. What it reports is whether *code* was dirty.
if [ -n "$(git status --porcelain -- . ':(exclude)docs/results' 2>/dev/null)" ]; then
  DIRTY="yes - code had uncommitted changes; these results may describe code that is not in $SHORT"
else
  DIRTY="no - results describe $SHORT exactly"
fi
STAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

echo "== running full suite =="
# junit xml for machine reading; text captured for the human artifact.
set +e
# Runs write to a temporary junit file and the committed pair is only replaced at
# the very end, atomically enough for this purpose. Writing straight into
# docs/results/ meant that when the suite ran twice -- which the staleness
# bootstrap below requires -- the first run overwrote junit.xml while latest.md
# still described an older run, so the two committed artifacts described
# different runs and the cross-check between them failed. That turned a
# self-healing re-run into a worse one: 2 failures became 3.
JUNIT="$(mktemp "${TMPDIR:-/tmp}/tenable-email-junit.XXXXXX")"
trap 'rm -f "$JUNIT"' EXIT
TEXT="$("$PY" -m pytest tests/ -v -o addopts= --junitxml="$JUNIT" 2>&1)"
RC=$?
set -e

# Whether every failure is one of the artifact's own guards. These are the only
# tests that can bootstrap: they read what the previous run wrote, so after any
# change to the test count the first run necessarily fails against a stale
# artifact, and the run that would fix it is the one being complained about.
# Leaving that to operator discipline is what produced a committed artifact
# recording a red run (a1cb399), because a piped invocation hides the exit code.
# The criterion is "every failure is an evidence guard" rather than "exactly one
# failure", because a stale latest.md trips both the staleness check and the
# cross-check against junit.xml.
FAILED_LINES="$(printf '%s\n' "$TEXT" | grep -c '^FAILED' || true)"
STALE_LINES="$(printf '%s\n' "$TEXT" | grep '^FAILED' | grep -c 'test_results_evidence' || true)"

SUMMARY="$(printf '%s\n' "$TEXT" | tail -1)"

# Counts come from the junit XML, not from grepping pytest's text output. The
# project's pyproject.toml sets addopts = "-q", which collapses per-test lines
# into dots, so a PASSED/FAILED grep silently yields zero. The XML is
# authoritative and immune to verbosity settings.
read -r TOTAL PASSED FAILED SKIPPED XFAILED <<EOF2
$("$PY" - "$JUNIT" <<'PYEOF'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
suites = root.findall("testsuite") or [root]
t = f = e = 0
for su in suites:
    t += int(su.get("tests", 0)); f += int(su.get("failures", 0))
    e += int(su.get("errors", 0))
# The suite-level `skipped` attribute lumps expected failures in with real skips,
# and the two mean close to opposite things: a skip did not run at all, while an
# xfail ran and failed exactly as the test declared it would. Reporting xfails as
# skips would quietly contradict this project's stated zero-skip property, so they
# are counted from the per-case elements by type instead.
x = s = 0
for tc in root.iter("testcase"):
    for ch in tc:
        if ch.tag == "skipped":
            if ch.get("type") == "pytest.xfail":
                x += 1
            else:
                s += 1
print(t, t - (f + e) - s - x, f + e, s, x)
PYEOF
)
EOF2

FIXTURES="$(find fixtures/synthetic -name '*.eml' 2>/dev/null | wc -l | tr -d ' ')"

# junit.xml records absolute test paths, which would publish the build account's
# home directory in a committed artifact. Rewrite them to repository-relative
# form, redact any absolute home path that still survives, and drop the machine
# hostname pytest writes onto the <testsuite> element entirely - on a build host
# that value is the build account's name plus the device model, so it is a
# username and a hostname inside a file destined for a public repository. The
# attribute is removed rather than given a placeholder value: this is XML, and a
# `<redacted>` inside an attribute value is not well-formed, which takes the
# artifact's own parser with it. The publication-boundary guard in
# tests/test_doc_references.py scans this file, so an unsanitized artifact fails
# the build - deliberately, because the alternative is shipping the path.
"$PY" - "$JUNIT" "$REPO_ROOT" <<'PYEOF'
import re, sys
from pathlib import Path
p = Path(sys.argv[1]); root = Path(sys.argv[2]).resolve()
if not p.is_file():
    sys.exit(0)
t = p.read_text(encoding="utf-8")
t = t.replace(str(root), ".")
t = re.sub(r"/home/[A-Za-z0-9_.-]+", "<redacted-home>", t)
t = re.sub(r"/Users/[A-Za-z0-9_.-]+", "<redacted-home>", t)
t = re.sub(r'\s+hostname="[^"]*"', "", t)
p.write_text(t, encoding="utf-8")
PYEOF

# Both committed files are replaced together so they always describe one run.
cp "$JUNIT" "$OUT_DIR/junit.xml"
cat > "$OUT_DIR/latest.md" <<EOF
<!-- generated by tools/record-results.sh -- do not edit by hand -->

# Test evidence

| | |
|---|---|
| Generated (UTC) | $STAMP |
| Describes commit | \`$SHA\` |
| Branch | \`$BRANCH\` |
| Uncommitted changes at run time | $DIRTY |
| Command | \`python3 -m pytest tests/ -v -o addopts= --junitxml=docs/results/junit.xml\` |
| Exit code | $RC |
| Collected | $TOTAL |
| Passed | $PASSED |
| Failed | $FAILED |
| Skipped | $SKIPPED |
| Expected failures (xfail) | $XFAILED |
| Synthetic fixtures | $FIXTURES |
| Python | $("$PY" -c 'import platform,sys; print(platform.python_version())') |
| pytest | $("$PY" -m pytest --version 2>&1 | head -1 | awk '{print $2}') |
| Platform | $("$PY" -c 'import platform; print(platform.system(), platform.release(), platform.machine())') |

**These results describe the commit named above.** Re-run
\`tools/record-results.sh\` and commit after any change to \`src/\` or \`tests/\`.
A test asserts that the recorded totals still match the suite that is actually
collected, so adding a test without re-recording fails the build.

Host identity is deliberately not recorded: this file is committed to a public
repository.

## Summary line

\`\`\`
$SUMMARY
\`\`\`

## Per-test results

\`\`\`
$(printf '%s\n' "$TEXT" | grep -E '^(tests/|FAILED|ERROR|PASSED)' | head -400)
\`\`\`

## Fixture corpus

Generated by \`fixtures/generate.py\` from source, never hand-edited, so labels
cannot drift from the generator. Reserved domains only; no real mail.

\`\`\`
$(if [ -f fixtures/synthetic/labels.json ]; then
    "$PY" -c "
import json,collections
rows=json.load(open('fixtures/synthetic/labels.json'))
c=collections.Counter(r['label'] for r in rows)
print('total:',len(rows),'|',' '.join(f'{k}={v}' for k,v in sorted(c.items())))
for r in rows: print(f\"  {r['label']:7} {r['file']}\")
"
  else
    echo "labels.json not present - run: python3 fixtures/generate.py --out fixtures/synthetic --manifest"
  fi)
\`\`\`
EOF

echo "== wrote $OUT_DIR/latest.md and $OUT_DIR/junit.xml =="
echo "   collected=$TOTAL passed=$PASSED failed=$FAILED skipped=$SKIPPED xfailed=$XFAILED"
printf '%s\n' "$SUMMARY"

if [ "$RC" -ne 0 ]; then
  echo
  echo "SUITE FAILED (exit $RC). The artifact records the failure; do not commit"
  echo "as if it were a passing run."
  if [ "$FAILED_LINES" -gt 0 ] && [ "$FAILED_LINES" -eq "$STALE_LINES" ] \
     && [ -z "${_RESULTS_SECOND_PASS:-}" ]; then
    echo
    echo "== Every failure was the artifact's own staleness guard, and the =="
    echo "== artifact on disk is now current, so a second pass should be clean. =="
    echo "== Re-running once rather than leaving a red record to be committed. =="
    rm -f "$JUNIT"
    _RESULTS_SECOND_PASS=1 exec "$0" "$@"
  fi
fi
exit "$RC"
