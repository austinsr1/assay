#!/usr/bin/env bash
# Rehearse the Pitch Day demo exactly as docs/ELI5.md Part 5 scripts it.
#
# Why this exists: the live demo is one of the four elements the judges are told to expect, and
# it is the only part of the pitch that can fail in a way talking cannot recover from. Three
# separate failure modes were found while building it, and this script checks all three.
#
# 1. THE FALSE-MISS TRAP. `ledger agreement` reports cleared-then-found-hostile, which is the
#    differentiator, so the instinct is to resolve a case the machine CLEARED as a threat and
#    watch that counter move. That prints "CLEARED THEN FOUND HOSTILE 1 of 1 (100.0%)" - true of
#    the input, and to a judge it reads as the system waving through an attack.
#
# 2. THE EMPTY-DENOMINATOR TRAP. Avoiding (1) by resolving only the escalated case gives
#    "0 of 0 (no cleared case has been resolved yet)" and "agreement 0.0%". The differentiating
#    metric then has nothing to measure and the headline number looks broken. The fix is to
#    confirm clearances as well as escalations, so the counter has a real denominator.
#
# 3. THE MOVED-ID TRAP. Case ids are content-derived and were verified identical across three
#    fresh runs, but if a fixture or the derivation ever changes, a hardcoded id fails on a
#    screen share with no recovery. Every id below is checked against the machine verdict it is
#    supposed to have before anything resolves it.
#
# Usage: bash tools/rehearse-pitch.sh [--keep] [--live]
#   --keep   leave the run directory in place so the ledger view can be opened afterwards
#   --live   rehearse the LIVE path instead (keeps TENABLE_EMAIL_* endpoints, and expects the
#            live case ids rather than the committed ones - see the scrub block below)
set -euo pipefail

cd "$(dirname "$0")/.."
export PYTHONPATH=src

# SCRUB THE MODEL-ENDPOINT ENVIRONMENT. This is not tidiness; it decides whether the demo
# accuses a benign message.
#
# In replay mode a tier with no configured endpoint is recorded as UNAVAILABLE, while a
# configured tier is consulted and its recording replayed. So the *replay result* depends on
# whether TENABLE_EMAIL_* endpoints happen to be exported. Measured on 2026-11-04 over the
# same fixtures and the same commit:
#
#   no endpoints exported : clean_security_newsletter_discussing_injection -> manual_review
#   endpoints exported    : the same fixture                              -> threat 0.92
#
# That fixture is labelled clean and exists to exercise injection_false_positive - a security
# newsletter that quotes injection phrases while discussing them. With endpoints exported the
# classifier replays 0.98 threat, url_reputation 0.92 and prompt_injection 0.99 against an
# llm vote of 0.90 clean, and the disagreement resolves the other way.
#
# Case ids move with it, so the ids below stop resolving. Anyone who exports
# .scratch/endpoints.env to try live mail and then runs the demo would get a false accusation
# on screen and a harness that refuses to start, with no obvious link between the two.
#
# Unsetting is the fix rather than documenting a ritual: the demo is supposed to be the
# committed offline artefact, and this makes it that regardless of the shell it is launched
# from. Use tools/rehearse-pitch.sh --live to rehearse the live path deliberately.
LIVE=0
[ "${1:-}" = "--live" ] && LIVE=1
if [ "$LIVE" = 0 ]; then
  for v in $(env | sed -n 's/^\(TENABLE_EMAIL_[A-Z_]*\)=.*/\1/p'); do
    case "$v" in
      TENABLE_EMAIL_LEDGER|TENABLE_EMAIL_TIMEOUT_SECONDS) ;;  # harmless, keep
      *) unset "$v" ;;
    esac
  done
fi

KEEP=0
for a in "$@"; do [ "$a" = "--keep" ] && KEEP=1; done

RUN="$(mktemp -d)"
trap '[ "$KEEP" = 1 ] || rm -rf "$RUN"' EXIT

# id:expected-machine-verdict:human-resolution. The escalated BEC case is resolved as a threat,
# which shows a correct deferral; the three clean cases are resolved as clean, which shows the
# clearances holding and gives the safety counter a denominator.
STEPS=(
  "14193ad949ffb0ac:manual_review:threat"
  "1d46f676980e569e:clean:clean"
  "1fc9d4457761cf4e:clean:clean"
  "ac218fbf3f694c7c:clean:clean"
)
BEC_CASE="14193ad949ffb0ac"
BEC_SUBJECT="Quick favor - vendor payment"

run() {  # timed step, printed the way the presenter will type it
  printf '\n\033[1m$ %s\033[0m\n' "$*"
  local t0 t1
  t0=$(date +%s.%N)
  "$@"
  t1=$(date +%s.%N)
  printf '\033[2m   [%.2fs]\033[0m\n' "$(echo "$t1 - $t0" | bc)"
}

echo "=========================================================================="
echo " Pitch Day demo rehearsal - Thursday 2026-11-05, 1:15pm Eastern"
echo " 8 minutes: what we built, why, what outcomes, live demo. Then 5 min Q&A."
echo " Run root: $RUN"
echo "=========================================================================="

run python3 -m tenable_email demo
run python3 -m tenable_email run fixtures/synthetic --out "$RUN/run" --provider ledger
run python3 -m tenable_email ledger --root "$RUN/run" list

LIST="$(python3 -m tenable_email ledger --root "$RUN/run" list 2>/dev/null)"

# --- verify every hardcoded id before the presenter relies on any of them ---
echo
for step in "${STEPS[@]}"; do
  id="${step%%:*}"; rest="${step#*:}"; want="${rest%%:*}"
  if ! printf '%s' "$LIST" | grep -q "$id"; then
    echo "STOP: case $id is not in the queue." >&2
    echo "A fixture or the case-id derivation moved. Do not improvise this on stage -" >&2
    echo "find the new ids and update both this script and Part 5 of docs/ELI5.md." >&2
    printf '%s\n' "$LIST" >&2
    exit 1
  fi
  got="$(printf '%s' "$LIST" | grep "$id" | awk '{print $3}')"
  if [ "$got" != "$want" ]; then
    echo "STOP: case $id is '$got', the demo expects '$want'." >&2
    echo "The choreography depends on the machine verdicts being what the script says:" >&2
    echo "the BEC case must have been DEFERRED and the clean cases must have been CLEARED." >&2
    exit 1
  fi
  printf '  verified: %s  machine=%s\n' "$id" "$got"
done
if ! printf '%s' "$LIST" | grep "$BEC_CASE" | grep -q "$BEC_SUBJECT"; then
  echo "note: $BEC_CASE is present and escalated but its subject differs from"
  echo "      '$BEC_SUBJECT'. Check the fixture before narrating it as a BEC attempt."
fi

# --- the demo proper ---
run python3 -m tenable_email ledger --root "$RUN/run" show "$BEC_CASE"
for step in "${STEPS[@]}"; do
  id="${step%%:*}"; rest="${step#*:}"; human="${rest#*:}"
  run python3 -m tenable_email ledger --root "$RUN/run" resolve "$id" \
        --disposition "$human" --resolver shawn
done
run python3 -m tenable_email ledger --root "$RUN/run" agreement
run python3 -m tenable_email ledger --root "$RUN/run" snapshot -o "$RUN/snap.html" --force

# --- the payoff must say what the script claims it says ---
AGREE="$(python3 -m tenable_email ledger --root "$RUN/run" agreement 2>/dev/null)"
printf '%s' "$AGREE" | grep -qi "CLEARED THEN FOUND HOSTILE" || {
  echo "STOP: the agreement output no longer reports cleared-then-found-hostile." >&2; exit 1; }
LINE="$(printf '%s' "$AGREE" | grep -i "CLEARED THEN FOUND HOSTILE")"
case "$LINE" in
  *"0 of 0"*)
    echo "STOP: the safety counter has no denominator ('$LINE')." >&2
    echo "That is the empty-denominator trap - no cleared case was resolved, so the" >&2
    echo "differentiating metric measures nothing and agreement reads 0%." >&2; exit 1 ;;
  *"0 of "*)
    echo "good: $LINE"
    echo "      the machine cleared cases the human confirmed, and none was hostile" ;;
  *)
    echo "STOP: a cleared case was later found hostile: $LINE" >&2
    echo "Investigate before pitching - either the choreography resolved the wrong" >&2
    echo "case or the pipeline cleared something it should not have." >&2; exit 1 ;;
esac

echo
echo "=========================================================================="
echo " Demo path OK. Two lines to say out loud, in this order:"
echo
echo '   1. "These are fixtures, so I am playing the analyst to show you the'
echo '       mechanism - the 84.2% figure comes from 203 real reported messages."'
echo '      (Say this. Resolving your own test fixtures without naming it is the'
echo '       one thing a technical judge will call out.)'
echo
echo '   2. "Most systems tell you how often the human agreed. This tells you how'
echo '       many messages the machine waved through turned out to be attacks -'
echo '       and it is append-only at the database level, so it cannot be edited'
echo '       quietly later."'
echo
echo " If asked about the 75% agreement: the one disagreement is the case the"
echo " machine REFUSED to decide. A deferral is not a wrong answer, and the"
echo " ledger does not dress one up as agreement."
echo
echo " Snapshot fallback (no JavaScript, nothing to fetch, cannot hang on a"
echo " screen share): $RUN/snap.html"
echo
echo " Spoken script is 847 words: 6.0 min at 140 wpm, 6.8 at 125, against an"
echo " 8-minute budget. Finish early - the panel will have heard thirteen pitches."
[ "$KEEP" = 1 ] && echo " Run directory kept: $RUN"
echo "=========================================================================="
