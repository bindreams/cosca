#!/bin/bash
# THROWAWAY (#346 adversarial review): tracer tests, mutants and probe; never fails the job.
set -u
F='test(/^child::shared::shared_tests::tracer::/)'
run() { # $1 label, $2 mutant, $3 filter
  echo "::group::$1 (ADV346_MUT=$2)"
  local start=$(date +%s)
  ADV346_MUT="$2" cargo nextest run --locked --lib --profile ci --no-fail-fast -E "$3" > "out-$1.log" 2>&1
  local rc=$?
  cat "out-$1.log"
  echo "::endgroup::"
  echo "RESULT $1 mut=$2 rc=$rc secs=$(( $(date +%s) - start ))"
  grep -E "WATCHDOG|PROBE:|panicked at|^\s+(PASS|FAIL|TIMEOUT|SIGABRT|SIGKILL)" "out-$1.log" | sed "s/^/  $1: /"
}
cargo nextest run --locked --lib --profile ci --no-run > build.log 2>&1 || { cat build.log; exit 1; }
for i in 1 2 3 4 5 6 7 8 9 10; do run "baseline$i" "" "$F & !test(/probe_/)"; done
run probe "" 'test(/probe_sigkill/)'
run mut-a a 'test(/try_wait_on_a_child_this_process_traces/)'
run mut-b b 'test(/a_child_this_process_traces_is_reaped_fully/)'
run mut-c c 'test(/a_failed_start_read_in_the_second_reap/)'
run mut-d d "$F & !test(/probe_/)"
run mut-w w 'test(/try_wait_on_a_child_this_process_traces/)'
exit 0
