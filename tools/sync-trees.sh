#!/usr/bin/env bash
# Keep the build tree and the shared tree in sync, and say so honestly when they
# are not.
#
# Topology (see NOTES.md "Build topology" for the authoritative version):
#
#   this working copy  --push-->  shared bare repository  <--pull--  remote working copy
#
# The shared repository is a *bare* repo, so pushing to it never touches anyone's
# working tree. That is the point: the previous arrangement pushed directly into
# a checked-out copy, which is fine for one writer and silently dangerous for
# two, because a push either fails or clobbers whatever the other person had not
# committed yet.
#
# This script is safe to run repeatedly and safe to run when nothing has changed.
# It never discards uncommitted work in either tree. If the remote working copy
# is dirty it reports that and leaves it alone rather than pulling over it.
#
# Usage:
#   tools/sync-trees.sh            verify, and push this tree if it is ahead
#   tools/sync-trees.sh --pull     also fast-forward the remote working copy
#   tools/sync-trees.sh --check    verify only; exit non-zero on any divergence
#
# The remote working copy's path is not hardcoded here, because this file is
# tracked and public and the path names a private account home directory. Set
# REMOTE_WORKTREE (or put it in .scratch/sync.conf, which is gitignored) and the
# --pull and remote-state checks light up; without it they are skipped with a
# message rather than guessed at.

set -euo pipefail

REMOTE="${SYNC_REMOTE:-utility}"
BRANCH="${SYNC_BRANCH:-main}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$REPO_ROOT/.scratch/sync.conf"
MODE="sync"

for arg in "$@"; do
    case "$arg" in
        --pull)  MODE="pull" ;;
        --check) MODE="check" ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [[ -r "$CONF" ]]; then
    # shellcheck disable=SC1090
    . "$CONF"
fi

cd "$REPO_ROOT"

# BatchMode so a missing key or an unreachable host fails immediately instead of
# hanging on a password prompt nobody is watching.
export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o BatchMode=yes}"

say() { printf '%-28s %s\n' "$1" "$2"; }

LOCAL_HEAD="$(git rev-parse HEAD)"
LOCAL_DIRTY="$(git status --porcelain | wc -l | tr -d ' ')"
say "local tree" "$REPO_ROOT"
say "local HEAD" "$(git rev-parse --short HEAD)"
say "local branch" "$(git rev-parse --abbrev-ref HEAD)"
say "local uncommitted files" "$LOCAL_DIRTY"

if ! git rev-parse --verify "$REMOTE/$BRANCH" >/dev/null 2>&1; then
    echo "fetching $REMOTE..."
    git fetch -q "$REMOTE" "$BRANCH"
fi
SHARED_HEAD="$(git rev-parse "$REMOTE/$BRANCH")"
say "shared HEAD ($REMOTE/$BRANCH)" "$(git rev-parse --short "$REMOTE/$BRANCH")"

AHEAD="$(git rev-list --count "$REMOTE/$BRANCH..HEAD")"
BEHIND="$(git rev-list --count "HEAD..$REMOTE/$BRANCH")"
say "local ahead of shared" "$AHEAD commit(s)"
say "local behind shared" "$BEHIND commit(s)"

DIVERGED=0
REMOTE_LAGS=0
# "Could not verify" is a third state, and it must not be reported as "in sync".
# The first version printed an explanatory line and then fell through to a success
# result with exit code 0, so an unreachable remote working copy -- or one that was
# never configured -- looked identical to three trees agreeing. A verifier that
# cannot verify has to say so in its exit status, or nothing downstream can rely
# on it.
REMOTE_UNKNOWN=0
if [[ "$AHEAD" -gt 0 && "$BEHIND" -gt 0 ]]; then
    DIVERGED=1
    echo
    echo "DIVERGED: the shared repository has $BEHIND commit(s) this tree does not,"
    echo "and this tree has $AHEAD commit(s) the shared one does not. Someone else"
    echo "has pushed. Do not force anything. Fetch and rebase or merge first:"
    echo "    git fetch $REMOTE && git log --oneline HEAD..$REMOTE/$BRANCH"
fi

if [[ "$BEHIND" -gt 0 ]]; then
    # Someone else has pushed. Reporting this in every mode is the point of the
    # script: --check that only compared local against its own last fetch would
    # pass while the shared tree moved on.
    DIVERGED=1
    echo
    echo "BEHIND: the shared repository has $BEHIND commit(s) this tree does not."
    echo "Someone else has pushed. Do not force anything. Inspect first:"
    echo "    git fetch $REMOTE && git log --oneline HEAD..$REMOTE/$BRANCH"
fi

if [[ "$MODE" != "check" && "$AHEAD" -gt 0 && "$DIVERGED" -eq 0 ]]; then
    echo
    echo "pushing $AHEAD commit(s) to $REMOTE/$BRANCH..."
    git push "$REMOTE" "$BRANCH"
    git fetch -q "$REMOTE" "$BRANCH"
    SHARED_HEAD="$(git rev-parse "$REMOTE/$BRANCH")"
    say "shared HEAD after push" "$(git rev-parse --short "$REMOTE/$BRANCH")"
fi

if [[ -z "${REMOTE_WORKTREE:-}" ]]; then
    REMOTE_UNKNOWN=1
    echo
    echo "remote working copy: NOT VERIFIED (REMOTE_WORKTREE unset)"
    echo "  Set it, or put REMOTE_WORKTREE=/path/to/tree in .scratch/sync.conf,"
    echo "  to include the remote working copy in the sync check and --pull."
else
    # Quoted for the remote shell. Interpolating the raw path into a
    # single-quoted cd meant one apostrophe in it produced a remote syntax error,
    # which the `|| echo UNREACHABLE` fallback then absorbed -- so a malformed
    # path reported "could not inspect" rather than "your path is broken".
    REMOTE_WORKTREE_Q="$(printf '%q' "$REMOTE_WORKTREE")"
    echo
    say "remote working copy" "$REMOTE_WORKTREE"
    # A host alias is not a command, so this must go through ssh explicitly.
    # GIT_SSH_COMMAND only affects git, hence BatchMode is restated here.
    REMOTE_STATE="$(ssh -o BatchMode=yes "$REMOTE" "cd $REMOTE_WORKTREE_Q 2>/dev/null \
        && printf '%s %s\n' \"\$(git rev-parse --short HEAD)\" \"\$(git status --porcelain | wc -l | tr -d ' ')\" \
        || echo 'UNREACHABLE 0'" 2>/dev/null || echo 'UNREACHABLE 0')"
    REMOTE_HEAD="${REMOTE_STATE%% *}"
    REMOTE_DIRTY="${REMOTE_STATE##* }"
    say "remote HEAD" "$REMOTE_HEAD"
    say "remote uncommitted files" "$REMOTE_DIRTY"

    if [[ "$REMOTE_HEAD" == "UNREACHABLE" ]]; then
        REMOTE_UNKNOWN=1
        echo "  could not inspect the remote working copy; NOT VERIFIED rather than assumed in sync"
    elif [[ "$REMOTE_HEAD" != "$(git rev-parse --short "$REMOTE/$BRANCH")" ]]; then
        if [[ "$MODE" == "pull" ]]; then
            if [[ "$REMOTE_DIRTY" != "0" ]]; then
                echo
                echo "NOT PULLING: the remote working copy has $REMOTE_DIRTY uncommitted"
                echo "change(s). Someone may be mid-edit. Pulling could destroy their"
                echo "work. Commit or stash there first, then re-run."
                DIVERGED=1
            else
                echo "  fast-forwarding remote working copy..."
                # A failing command substitution inside an argument to `say` does
                # not trip set -e, so the post-pull probe is captured and checked
                # explicitly rather than printed and hoped for.
                ssh -o BatchMode=yes "$REMOTE" \
                    "cd $REMOTE_WORKTREE_Q && git pull --ff-only -q origin '$BRANCH'"
                AFTER_PULL="$(ssh -o BatchMode=yes "$REMOTE" \
                    "cd $REMOTE_WORKTREE_Q && git rev-parse --short HEAD" 2>/dev/null || echo UNREACHABLE)"
                say "remote HEAD after pull" "$AFTER_PULL"
                EXPECTED="$(git rev-parse --short "$REMOTE/$BRANCH")"
                if [[ "$AFTER_PULL" != "$EXPECTED" ]]; then
                    REMOTE_UNKNOWN=1
                    echo "  remote is at '$AFTER_PULL' but the shared repository is at"
                    echo "  '$EXPECTED', so the pull did not land. NOT VERIFIED."
                fi
            fi
        else
            REMOTE_LAGS=1
            echo "  remote working copy is behind the shared repository, so the"
            echo "  trees are NOT all in sync. Re-run with --pull to fast-forward"
            echo "  it (only if it is clean)."
        fi
    else
        say "remote state" "in sync with shared"
    fi
fi

echo
if [[ "$DIVERGED" -eq 1 || "$REMOTE_LAGS" -eq 1 ]]; then
    echo "RESULT: not in sync - see above. Nothing was forced."
    exit 1
fi
if [[ "$REMOTE_UNKNOWN" -eq 1 ]]; then
    # Distinct exit code: 1 means "verified to disagree", 3 means "could not
    # verify". Conflating them would make an unreachable tree look like a
    # conflict, and a caller cannot act on that correctly either way.
    echo "RESULT: COULD NOT VERIFY every tree - local and shared agree at"
    echo "        $(git rev-parse --short "$REMOTE/$BRANCH"), but the remote working copy was not checked."
    exit 3
fi
echo "RESULT: in sync at $(git rev-parse --short "$REMOTE/$BRANCH")"
