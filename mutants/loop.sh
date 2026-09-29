#!/usr/bin/env bash
# THROWAWAY (PR #310): repeat the tracer suite; print each failed iteration's failures.
set -u +e
set +o pipefail
fails=0
for i in $(seq 1 "$1"); do
  log="$RUNNER_TEMP/iter-$i.log"
  if ! cargo nextest run --locked --lib --profile ci --no-fail-fast --color never \
      --failure-output final -E 'test(/^test_support::tracer::/)' > "$log" 2>&1; then
    fails=$((fails+1))
    echo "=== iteration $i failed"
    grep -aE "^ +(FAIL|TIMEOUT|SIGSEGV|SIGABRT|LEAK)" "$log" | sort -u
    awk '/^ *(FAIL|TIMEOUT) \[/ {n++} n' "$log" | grep -avE "^\s*$" | head -150
  fi
done
echo "failed iterations: $fails of $1"
