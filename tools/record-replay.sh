#!/usr/bin/env bash
# Record real model responses for the synthetic corpus into fixtures/replay/.
#
# Endpoints come from the environment and from nowhere else. If
# `.scratch/endpoints.env` exists (gitignored, along with everything in
# `.scratch/`) it is sourced first; shell variables already set win. No address,
# host name, port or API key appears in this file, because it is tracked and the
# repository it belongs to is destined to be public -- and a test fails any
# tracked file that contains one.
#
# A tier with no endpoint in the environment is reported as not configured and
# contributes no recording. Nothing here fabricates an answer: an unreachable
# service leaves its tier UNAVAILABLE in the evidence record, which is the
# honest outcome and the one the design requires.
#
# Usage:
#   tools/record-replay.sh                 # record everything reachable
#   tools/record-replay.sh --dry-run       # show which tiers are configured
#   tools/record-replay.sh --quiet         # totals only
#
# Services that only listen on another host's localhost (the ONNX classifier and
# the security-model estate) are reached through a tunnel this script opens when
# both of these are set, and closes on exit:
#
#   TENABLE_EMAIL_TUNNEL_HOST   the ssh host to tunnel through
#   TENABLE_EMAIL_TUNNEL_MAPS   one or more ssh -L forward specs, space
#                               separated, each "<local-port>:<remote-host>:<remote-port>"
#   TENABLE_EMAIL_SSH_OPTIONS   optional extra ssh flags
#
# Then point the tier at the local end of the tunnel: its URL is the local port
# you chose, and no address of the service host ever reaches a tracked file --
# including this one, which is why no example values are printed here.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || { echo "ERROR: $PY not found"; exit 2; }

ENV_FILE="${TENABLE_EMAIL_ENV_FILE:-.scratch/endpoints.env}"
if [ -f "$ENV_FILE" ]; then
  echo "== loading endpoints from $ENV_FILE (gitignored) =="
  # Existing environment wins, so a one-off override on the command line works.
  # Parsed rather than sourced: this file holds credentials, and a parse cannot
  # execute whatever a stray line turns out to contain.
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*) continue ;; esac
    key="${line%%=*}"
    value="${line#*=}"
    [ "$key" != "$line" ] || continue
    key="${key// /}"
    value="${value%\"}"; value="${value#\"}"
    case "$key" in TENABLE_EMAIL_*) ;; *) continue ;; esac
    export "${key}=${!key:-$value}"
  done < "$ENV_FILE"
fi

TUNNEL_PIDS=()
cleanup() {
  for pid in "${TUNNEL_PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

if [ -n "${TENABLE_EMAIL_TUNNEL_HOST:-}" ] && [ -n "${TENABLE_EMAIL_TUNNEL_MAPS:-}" ]; then
  SSH_ARGS=( -o BatchMode=yes -o ExitOnForwardFailure=yes -o ConnectTimeout=15 )
  if [ -n "${TENABLE_EMAIL_SSH_OPTIONS:-}" ]; then
    # shellcheck disable=SC2206
    SSH_ARGS=( "${SSH_ARGS[@]}" ${TENABLE_EMAIL_SSH_OPTIONS} )
  fi
  echo "== opening tunnel through ${TENABLE_EMAIL_TUNNEL_HOST} =="
  # shellcheck disable=SC2086
  ssh "${SSH_ARGS[@]}" -N -L "${TENABLE_EMAIL_TUNNEL_MAPS// / -L }" \
    "$TENABLE_EMAIL_TUNNEL_HOST" >/dev/null 2>&1 &
  TUNNEL_PIDS+=( $! )
  sleep 2
fi

set +e
"$PY" tools/record_replay.py "$@"
STATUS=$?
set -e
if [ "$STATUS" -ne 0 ]; then
  echo "ERROR: recording failed (exit $STATUS). Nothing was written for the tiers"
  echo "that could not be reached; do not commit a store that was not recorded."
fi

echo
echo "== store contents =="
"$PY" - <<'PYEOF'
import sys, pathlib
sys.path.insert(0, "src")
from tenable_email.replay import ReplayStore

store = ReplayStore(root=pathlib.Path("fixtures/replay"))
print(store.summary())
for tier, count in sorted(store.counts_by_tier().items()):
    models = ", ".join(store.models_for(tier)) or "(no model id recorded)"
    print(f"  {tier:22} {count:>3} recording(s)  model={models}")
PYEOF

exit "$STATUS"
