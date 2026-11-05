#!/usr/bin/env bash
# Validate our Exchange listing drafts against the REAL validator.py from
# tenable/cyberagents-exchange. Run after any frontmatter edit, and again
# immediately before opening the PR - upstream vocabularies can change.
#
# Usage: tools/validate-listing.sh [draft-name]
#   draft-name: mcp-server | playbook | both (default: both)
#
# Exit 0 only if every selected draft passes.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRAFTS="$REPO_ROOT/docs/listing-drafts"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

TARGET="${1:-both}"

command -v uv >/dev/null || { echo "ERROR: uv is required (https://docs.astral.sh/uv/)"; exit 2; }

echo "== fetching current validator.py =="
curl -fsSL -o "$WORK/validator.py" \
  https://raw.githubusercontent.com/tenable/cyberagents-exchange/main/validator.py
echo "   $(wc -c < "$WORK/validator.py") bytes"

echo "== building isolated venv =="
uv venv "$WORK/.venv" -q
# python-frontmatter, NOT the PyPI package named 'frontmatter' - the latter
# shadows it and breaks validator.py with "module 'frontmatter' has no
# attribute 'load'". See docs/LISTING-VALIDATION.md.
uv pip install -q --python "$WORK/.venv/bin/python" \
  python-frontmatter pydantic rich typer

# The validator requires all four listing directories to exist and to contain
# nothing but .md listings. A stray .gitkeep is a hard error.
mkdir -p "$WORK/root/agents" "$WORK/root/mcp-servers" "$WORK/root/skills" "$WORK/root/playbooks"

rc=0
check() { # <subdir> <draft-file> <label>
  local sub="$1" src="$2" label="$3"
  rm -f "$WORK/root/$sub/"*.md
  cp "$src" "$WORK/root/$sub/"
  printf '\n== %s ==\n' "$label"
  if "$WORK/.venv/bin/python" "$WORK/validator.py" --path "$WORK/root"; then
    echo "   -> PASS"
  else
    echo "   -> FAIL"
    rc=1
  fi
}

case "$TARGET" in
  mcp-server) check mcp-servers "$DRAFTS/mcp-server.md" "MCP server listing" ;;
  playbook)   check playbooks   "$DRAFTS/playbook.md"   "Playbook listing" ;;
  both)
    check mcp-servers "$DRAFTS/mcp-server.md" "MCP server listing"
    check playbooks   "$DRAFTS/playbook.md"   "Playbook listing"
    ;;
  *) echo "ERROR: unknown target '$TARGET' (use mcp-server|playbook|both)"; exit 2 ;;
esac

echo
if [ "$rc" -eq 0 ]; then
  echo "All selected drafts pass the current upstream validator."
  echo "Reminder: PLACEHOLDER-handle and PLACEHOLDER in github_url/ref must be"
  echo "replaced with the real personal GitHub account before submission, and"
  echo "compatible_clients must list only clients actually tested."
else
  echo "One or more drafts FAILED. Do not open the PR."
fi
exit "$rc"
