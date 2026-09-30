#!/usr/bin/env bash
# THROWAWAY (PR #377): the full tracer group, N times. Prints the failure count; keeps failed logs.
set -u
n="${1:?iterations}"
LOGS="${RUNNER_TEMP:-/tmp}/loop-logs"
mkdir -p "$LOGS"
failed=0
for i in $(seq 1 "$n"); do
  log="$LOGS/iter-$i.log"
  if cargo nextest run --locked --lib --profile ci --no-fail-fast -E 'test(/^test_support::tracer::/)' >"$log" 2>&1; then
    rm -f "$log"
  else
    failed=$((failed + 1))
    echo "iteration $i FAILED:"
    grep -aE "^\s+(FAIL|TIMEOUT|SIGSEGV|SIGABRT) \[|panicked at|left:|right:" "$log" | head -20 | sed 's/^/    /'
    if [ "${LOOP_DUMP:-0}" = 1 ]; then echo "----- full log of iteration $i"; cat "$log"; echo "----- end"; fi
  fi
done
echo "failed iterations: $failed of $n"
[ "$failed" -eq 0 ]
