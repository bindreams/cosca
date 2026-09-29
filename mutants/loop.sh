#!/usr/bin/env bash
# THROWAWAY (PR #310): repeat the tracer suite; report failed iterations and hang dumps.
set -u +e
set +o pipefail
fails=0
for i in $(seq 1 "$1"); do
  log="$RUNNER_TEMP/iter-$i.log"
  if ! cargo nextest run --locked --lib --profile ci --no-fail-fast -E 'test(/^test_support::tracer::/)' > "$log" 2>&1; then
    fails=$((fails+1))
    echo "=== iteration $i failed"
    grep -aE "FAIL \[|TIMEOUT \[" "$log" | sort -u
    grep -a "@@HANG@@" -A6 "$log" | head -60
  fi
done
echo "failed iterations: $fails of $1"
