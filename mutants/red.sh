#!/usr/bin/env bash
# THROWAWAY (PR #377): RED tests on a RED commit's tree. Each must fail by assertion, never by
# timeout. Non-zero if any passed or hung. Usage: red.sh <test>...
set -u
P=test_support::tracer::tracer_tests
LOGS="${RUNNER_TEMP:-/tmp}/red-logs"
mkdir -p "$LOGS"
tests=("$@")
bad=0
for test in "${tests[@]}"; do
  log="$LOGS/$test.log"
  cargo nextest run --locked --lib --profile ci --no-fail-fast -E "test(=$P::$test)" >"$log" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    verdict=PASSED; bad=1
  elif grep -q "TIMEOUT" "$log"; then
    verdict=RED-HANG; bad=1
  else
    verdict=RED-ASSERT
  fi
  echo "RED $test $verdict"
  grep -aE "panicked at|TIMEOUT|assertion|left:|right:|both ignored" "$log" | head -6 | sed 's/^/    /'
done
exit "$bad"
