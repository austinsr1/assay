#!/usr/bin/env bash
# Compile every source file with each interpreter between the declared floor and the
# current one. This is the stronger half of the portability guarantee: the AST detector
# in tests/test_portability.py catches the construct that actually shipped (a backslash
# inside an f-string replacement field), and this catches everything else, including
# quote reuse inside a replacement field and any future syntax that only a newer
# interpreter accepts.
#
# Not a pytest test, because the build host has exactly one Python and a conditionally
# skipping test would add a skip to a suite required to have none. Run it on a host that
# has the older interpreters - the integration host has 3.9, 3.11 and 3.12.
#
# What has actually been verified, as of 2026-11-04: all 72 source files compile on 3.11
# and 3.12 (integration host) and on 3.14 (build host). 3.9 is below the declared floor so
# it is correctly not consulted. **No host available to this project runs 3.10**, so the
# floor declared in pyproject.toml has never been compiled against - the guarantee that
# holds is "compiles on 3.11 and newer plus the AST detector in tests/test_portability.py
# finds no 3.12-only construct", which is narrower than requires-python claims. Either
# install a 3.10 somewhere and run this, or raise the floor to 3.11 and say why.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

MINIMUM="3.10"
status=0
checked=0
# Versions already compiled, so two names for one interpreter count once. Without this
# `python3.14` and `python3` are two "interpreters", the single-interpreter warning never
# fires, and the script reads as though it had verified a spread of versions when it had
# verified one version twice and never touched the declared floor at all.
seen_versions=""

mapfile -t FILES < <(find src eval tools tests fixtures -name '*.py' -type f | sort)
echo "source files: ${#FILES[@]}   declared floor: >=${MINIMUM}"

for name in python3.10 python3.11 python3.12 python3.13 python3.14 python3; do
  command -v "$name" >/dev/null 2>&1 || continue
  ver="$("$name" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)" || continue
  # Skip anything below the floor: unsupported, and its failures are not our bug.
  if python3 - "$ver" "$MINIMUM" <<'PY' 2>/dev/null; then :; else continue; fi
import sys
have = tuple(int(n) for n in sys.argv[1].split("."))
need = tuple(int(n) for n in sys.argv[2].split("."))
sys.exit(0 if have >= need else 1)
PY
  case " $seen_versions " in
    *" $ver "*)
      printf '%-12s (%s) ... same version as an interpreter already compiled; skipped\n' "$name" "$ver"
      continue
      ;;
  esac
  seen_versions="$seen_versions $ver"
  checked=$((checked + 1))
  printf '%-12s (%s) ... ' "$name" "$ver"
  # py_compile refuses /dev/null as a target ("non-regular file"), so discard the
  # bytecode into a throwaway directory instead of trying to suppress it.
  discard="$(mktemp -d)"
  trap 'rm -rf "$discard"' EXIT
  bad="$("$name" -c '
import py_compile, sys, os
target = sys.argv[1]
bad = []
for path in sys.argv[2:]:
    try:
        py_compile.compile(path, doraise=True,
                           cfile=os.path.join(target, os.path.basename(path) + "c"))
    except Exception as exc:
        bad.append(f"  {path}: {exc}")
print("\n".join(bad))
sys.exit(1 if bad else 0)
' "$discard" "${FILES[@]}" 2>&1)"
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "all ${#FILES[@]} files compile"
  else
    echo "FAILED"
    echo "$bad"
    status=1
  fi
done

if [ "$checked" -eq 0 ]; then
  echo "NO interpreter at or above ${MINIMUM} was found besides this one - nothing verified."
  echo "This is not a pass. Run it on a host that has the older interpreters."
  exit 2
fi
if [ "$checked" -eq 1 ]; then
  echo
  echo "WARNING: only one qualifying interpreter was found, so this run proves the source"
  echo "compiles on that one version and says nothing about the declared floor of ${MINIMUM}."
fi
exit $status
