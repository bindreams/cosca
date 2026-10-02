#!/bin/bash
# Args: mutant names. Env: SUITES, REPEAT.
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
for m in "$@"; do
  d="$RUNNER_TEMP/mut/$m"; mkdir -p "$d"; cp "$here"/*.py "$d/"
  python3 "$here/probe/mutants.py" "$m" "$d" || { echo "$m APPLY-FAIL"; continue; }
  fails=0; s=$(date +%s)
  for _ in $(seq "${REPEAT:-1}"); do
    (cd "$d" && python3 -c "import subprocess,sys; sys.exit(subprocess.run(sys.argv[1:], timeout=900).returncode)" python3 -m unittest ${SUITES:-forward_tests run_nextest_tests} > "$d/log" 2>&1) || fails=$((fails+1))
  done
  echo "$m: failed $fails/${REPEAT:-1} in $(( $(date +%s) - s ))s; last: $(tail -1 "$d/log") $(grep -E '^(FAIL|ERROR):' "$d/log" | head -4 | tr '\n' ' ')"
done
