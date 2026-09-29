#!/usr/bin/env bash
# THROWAWAY (PR #310): run each COSCA_UH_MUTANT against the test(s) that must catch it.
# One line per pair: "MUTANT <name> <test> RED-ASSERT|RED-HANG|SURVIVED". Exits non-zero if any
# pair survived or hung.
set -u
P=test_support::tracer::tracer_tests
LOGS="${RUNNER_TEMP:-/tmp}/mutant-logs"
mkdir -p "$LOGS"
pairs=(
  "sm1_eof s_minus_1_eof_exits_without_a_report"
  "sm1_partial_line s_minus_1_eof_inside_the_line_is_malformed"
  "sm1_pid_zero s_minus_1_pid_0_is_malformed"
  "sm1_pid_negative s_minus_1_a_negative_pid_is_malformed"
  "sm1_malformed_as_eof s_minus_1_a_stray_line_is_malformed"
  "sm1_malformed_as_eof s_minus_1_a_non_numeric_pid_is_malformed"
  "sm1_malformed_as_eof s_minus_1_an_empty_pid_is_malformed"
  "sm1_malformed_as_eof s_minus_1_non_utf8_is_malformed"
  "s0_ignore s0_a_receipt_error_fails"
  "s1_ignore s1_an_attach_error_fails"
  "s1h_sig_to_s3 s1h_a_signal_byte_goes_to_release"
  "s1h_eof_to_s2 s1h_eof_exits_and_xnu_kills_the_tracee"
  "s1h_note_to_s2 s1h_note_exit_goes_to_reap"
  "s1h_peek_retry_any s1h_a_failed_stop_peek_fails"
  "s1h_none_holds s1h_a_tracee_not_stopped_yet_backs_off"
  "s1h_settling_holds s1h_a_settling_stop_backs_off"
  "s2_settling_acts s2_a_settling_stop_backs_off"
  "s4_settling_acts s4_a_settling_stop_backs_off"
  "s3_settling_as_running s3_a_settling_stop_peeks_again"
  "s2_ebusy_fails s2_ebusy_backs_off_then_retries"
  "s2_none_acts s2_a_tracee_not_stopped_yet_backs_off"
  "s2_none_fails s2_a_tracee_not_stopped_yet_backs_off"
  "s2_no_passthrough s2_passes_a_stopping_signal_through"
  "s2_passthru_zero s2_passes_a_stopping_signal_through"
  "keep_passthru s2_keeps_a_stop_signal_until_after_the_detach"
  "s2_peek_err_ignored s2_a_failed_stop_peek_fails"
  "s2_cont_err_ignored s2_a_failed_pass_through_fails"
  "s2_einval_as_ebusy s2_another_errno_fails"
  "s2b_note_retries s2b_note_exit_fails"
  "s2b_sig_retries s2b_a_signal_byte_fails"
  "s2b_eof_retries s2b_eof_fails"
  "lone_sigchld_as_signal s2b_a_lone_sigchld_reads_as_the_timeout"
  "lone_sigchld_as_signal s1h_a_lone_sigchld_reads_as_the_timeout"
  "s3_auto_note_to_s4 s3_auto_note_exit_goes_to_reap"
  "reap_noop s3_auto_note_exit_goes_to_reap"
  "s3_auto_signal_first s3_auto_note_exit_wins_over_a_signal_byte_in_the_same_batch"
  "s3_auto_sig_to_s5 s3_auto_a_signal_byte_goes_to_detach"
  "detach_noop s3_auto_a_signal_byte_goes_to_detach"
  "s3_eof_as_note s3_auto_eof_goes_to_detach"
  "detach_noop s3_auto_eof_goes_to_detach"
  "s5_eintr_fails s5_eintr_retries"
  "s5_retry_any s5_another_errno_fails"
  "reap_accepts_stop s5_a_stop_is_not_a_reap"
  "s3_hold_reap_at_once s3_hold_note_exit_reports_exited_then_a_signal_byte_reaps"
  "reap_noop s3_hold_note_exit_reports_exited_then_a_signal_byte_reaps"
  "s3x_ignore_eof s3x_eof_reaps"
  "s3x_ignore_signal s3x_an_injected_signal_byte_reaps"
  "s3x_ignore_eof s3x_an_injected_eof_reaps"
  "s3x_note_releases s3x_note_exit_fails"
  "lone_sigchld_as_signal s3x_a_lone_sigchld_is_ignored"
  "zombie_no_check s3_hold_a_zombie_wait_that_finds_no_exit_fails"
  "s3_hold_sig_to_s3x s3_hold_a_signal_byte_without_note_exit_goes_to_detach"
  "detach_noop s3_hold_a_signal_byte_without_note_exit_goes_to_detach"
  "s3_hold_eof_waits s3_hold_eof_without_note_exit_goes_to_detach"
  "s3_hold_drop_batch_sig s3_hold_note_exit_and_a_signal_byte_in_one_batch_pass_s3x_to_reap"
  "s3_hold_release_signal_only s3_hold_note_exit_and_eof_in_one_batch_pass_s3x_to_reap"
  "s4_ebusy_fails s4_ebusy_backs_off_then_retries"
  "s4_none_acts s4_a_tracee_not_stopped_yet_backs_off"
  "s4_none_fails s4_a_tracee_not_stopped_yet_backs_off"
  "s4b_ignore_note s4b_note_exit_goes_to_reap"
  "s4b_sig_fails s4b_a_signal_byte_is_ignored"
  "s4b_eof_fails s4b_eof_is_ignored"
  "lone_sigchld_as_note_exit s4b_a_lone_sigchld_is_ignored"
  "s4_esrch_fails s4_esrch_goes_to_exiting"
  "s4_ignore_stop_result s4_a_sigstop_esrch_goes_to_exiting"
  "s4_ignore_stop_result s4_a_sigstop_error_fails"
  "s4_cont_esrch_fails s4_a_pass_through_on_an_exiting_tracee_goes_to_exiting"
  "s4_esrch_ignores_seen s4_esrch_after_note_exit_goes_to_reap"
  "s4_eperm_esrch s4_eperm_fails"
  "s4_einval_as_ebusy s4_another_errno_fails"
  "s4_peek_err_as_running s4_a_failed_stop_peek_fails"
  "s4_cont_err_ignored s4_a_failed_pass_through_fails"
  "s6_sig_to_s5 s6_a_signal_byte_is_ignored"
  "s6_eof_exits s6_eof_is_ignored"
  "lone_sigchld_as_signal s6_a_lone_sigchld_is_ignored"
  "s3_passthru_zero s3_passes_a_stopping_signal_through"
  "keep_passthru s3_keeps_a_stop_signal_until_after_the_detach"
  "resend_none s3_keeps_a_stop_signal_until_after_the_detach"
  "resend_silent s3_keeps_a_stop_signal_until_after_the_detach"
  "keep_last s3_keeps_only_the_first_stop_signal"
  "sigcont_keeps s3_a_sigcont_drops_a_kept_stop_signal"
  "keep_passthru s4_keeps_a_stop_signal_until_after_the_detach"
  "resend_err_ignored s4_a_failed_resend_fails"
  "s3_sigchld_to_s4 s3_a_sigchld_without_a_stop_changes_nothing"
  "s3_cont_esrch_fails s3_a_pass_through_on_an_exiting_tracee_waits_for_note_exit"
  "s3_peek_err_ignored s3_a_failed_stop_peek_fails"
  "s3_cont_err_ignored s3_a_failed_pass_through_fails"
  "s4_detach_any_stop s4_passes_a_stopping_signal_through_before_detaching"
  "ignore_epipe a_failed_report_write_exits"
  "report_then_ignores_gone a_failed_attached_write_ends_the_run"
  "report_then_ignores_gone a_failed_exited_write_ends_the_run"
  "report_then_ignores_gone a_failed_reaped_write_ends_the_run"
  "report_then_ignores_gone a_failed_detached_write_ends_the_run"
  "pass_on_trace_ignores_gone a_failed_pass_through_trace_write_ends_the_run"
  "pass_on_trace_ignores_gone a_failed_s3_pass_through_trace_write_ends_the_run"
  "block_ignores_gone a_failed_blocking_write_ends_the_run"
  "done_exits_on_byte done_ignores_a_signal_byte_and_holds"
  "attach_no_check attach_refuses_a_reaped_tracee"
  "drop_drains_stuck dropping_a_helper_that_awaits_the_tracees_exit_kills_it_and_fails"
  "start_traces a_client_helper_reports_only_the_protocol"
  "recv_keeps_blocking a_client_helper_reports_only_the_protocol"
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
