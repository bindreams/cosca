#!/usr/bin/env bash
# THROWAWAY (PR #377): each COSCA_UH_MUTANT against the tests that must catch it. One line per
# pair: "MUTANT <name> <test> RED-ASSERT|RED-HANG|SURVIVED". Non-zero if any survived or hung.
set -u
P=test_support::tracer::tracer_tests
LOGS="${RUNNER_TEMP:-/tmp}/mutant-logs"
mkdir -p "$LOGS"
pairs=(
  "d1 s2_an_ignored_stop_signal_keeps_a_pending_sigcont"
  "d2 s2_holds_a_caught_stop_signal_and_keeps_a_pending_sigcont"
  "d2 s3_holds_a_caught_stop_signal_until_after_the_detach"
  "d2 s4_holds_a_caught_stop_signal_until_after_the_detach"
  "d3 a_disposition_read_on_an_exiting_process_answers_caught"
  "h1 s3_keeps_a_stop_signal_until_after_the_detach"
  "h1 s2_holds_a_caught_stop_signal_and_keeps_a_pending_sigcont"
  "sigtstp s3_reads_the_disposition_of_the_stopping_signal"
  "cont_keeps_held s3_a_sigcont_drops_a_caught_stop_signal_that_came_while_stopped"
  "cont_drops_held s2_holds_a_caught_stop_signal_and_keeps_a_pending_sigcont"
  "held_not_resent s3_holds_a_caught_stop_signal_until_after_the_detach"
  "held_not_resent s4_holds_a_caught_stop_signal_until_after_the_detach"
  "disp_err_default s2_a_failed_disposition_read_fails"
  "disp_err_default s3_a_failed_disposition_read_fails"
  "disp_err_default s4_a_failed_disposition_read_fails"
  "carry_none s4_a_failed_resend_fails"
  "detach_from_sigstop s4_keeps_a_stop_signal_until_after_the_detach"
  "detach_from_sigstop s4_holds_a_caught_stop_signal_until_after_the_detach"
)
bad=0
for pair in "${pairs[@]}"; do
  read -r mutant test <<<"$pair"
  log="$LOGS/$mutant-$test.log"
  COSCA_UH_MUTANT="$mutant" cargo nextest run --locked --lib --profile ci --no-fail-fast \
    -E "test(=$P::$test)" >"$log" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    verdict=SURVIVED; bad=1
  elif grep -q "TIMEOUT" "$log"; then
    verdict=RED-HANG; bad=1
  else
    verdict=RED-ASSERT
  fi
  echo "MUTANT $mutant $test $verdict"
  grep -aE "panicked at|TIMEOUT|assertion|left:|right:|does not lead|orphaned|both ignored" "$log" | head -6 | sed 's/^/    /'
done
exit "$bad"
