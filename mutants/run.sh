#!/usr/bin/env bash
# THROWAWAY (uh-caught-stop): run each COSCA_UH_MUTANT against the test(s) that must catch it.
# One line per pair: "MUTANT <name> <test> RED-ASSERT|RED-HANG|SURVIVED". Exits non-zero if any
# pair survived or hung.
set -u
P=test_support::tracer::tracer_tests
LOGS="${RUNNER_TEMP:-/tmp}/mutant-logs"
mkdir -p "$LOGS"
pairs=(
  "caught_keeps s3_passes_a_caught_stop_signal_through"
  "caught_keeps s2_passes_a_caught_stop_signal_through"
  "caught_keeps s4_passes_a_caught_stop_signal_through"
  "ignored_keeps s3_passes_an_ignored_stop_signal_through"
  "always_keep s3_passes_a_caught_stop_signal_through"
  "always_keep s2_passes_a_caught_stop_signal_through"
  "always_keep s4_passes_a_caught_stop_signal_through"
  "always_keep s3_passes_an_ignored_stop_signal_through"
  "always_pass s3_keeps_a_stop_signal_until_after_the_detach"
  "always_pass s2_keeps_a_stop_signal_until_after_the_detach"
  "always_pass s4_keeps_a_stop_signal_until_after_the_detach"
  "always_pass s3_keeps_only_the_first_stop_signal"
  "disp_err_default s3_a_failed_disposition_read_fails"
  "disp_esrch_fails s3_a_disposition_read_on_an_exiting_tracee_waits_for_note_exit"
  "disp_default sigcatch_and_sigignore_are_populated_for_another_process"
  "disp_default s3_passes_a_caught_stop_signal_through"
  "disp_swap sigcatch_and_sigignore_are_populated_for_another_process"
  "disp_bit_off sigcatch_and_sigignore_are_populated_for_another_process"
  "disp_ignored_from_catch sigcatch_and_sigignore_are_populated_for_another_process"
  "disp_ignored_from_catch s3_passes_an_ignored_stop_signal_through"
)
bad=0
for pair in "${pairs[@]}"; do
  read -r mutant test <<<"$pair"
  log="$LOGS/$mutant-$test.log"
  COSCA_UH_MUTANT="$mutant" cargo nextest run --locked --lib --profile ci --no-fail-fast \
    -E "test(=$P::$test)" >"$log" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    verdict=SURVIVED
    bad=1
  elif grep -q "TIMEOUT" "$log"; then
    verdict=RED-HANG
    bad=1
  else
    verdict=RED-ASSERT
  fi
  echo "MUTANT $mutant $test $verdict"
  if [ "$verdict" != SURVIVED ]; then
    grep -aE "panicked at|TIMEOUT|assertion|left:|right:" "$log" | head -4 | sed 's/^/    /'
  fi
done
exit "$bad"
