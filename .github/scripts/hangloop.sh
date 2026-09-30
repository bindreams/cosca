#!/usr/bin/env bash
# THROWAWAY: loop the macOS tests, dumping process state when one iteration overruns.
set -uo pipefail
N="${1:?}"; FEATURES="${2:-}"; FILTER="${3:-}"; LIM="${4:-300}"
mkdir -p logs
args=(nextest run --locked --profile ci --no-fail-fast)
[ -n "$FEATURES" ] && args+=(--features "$FEATURES")
[ -n "$FILTER" ] && args+=(-E "$FILTER")
cargo nextest run --locked --no-run ${FEATURES:+--features "$FEATURES"} >logs/build.log 2>&1 || { cat logs/build.log; exit 1; }
fail=0; hang=0
for i in $(seq 1 "$N"); do
  cargo "${args[@]}" >"logs/iter-$i.log" 2>&1 &
  pid=$!
  (
    sleep "$LIM"
    if kill -0 "$pid" 2>/dev/null; then
      echo "HANG iter $i" >"logs/hang-$i.flag"
      ps -axo pid,ppid,pgid,stat,etime,command >"logs/hang-$i.ps" 2>&1
      for p in $(pgrep -f cosca_unit_tests; pgrep -f 'cosca-[0-9a-f]+' ); do
        sudo sample "$p" 3 -file "logs/hang-$i.sample.$p.txt" >/dev/null 2>&1
      done
      ps -axo pid,ppid,pgid,stat,etime,command | grep -E 'nextest|cosca' | awk '{print $1}' | while read -r p; do
        sudo sample "$p" 3 -file "logs/hang-$i.sample2.$p.txt" >/dev/null 2>&1
      done
      pkill -P "$pid" 2>/dev/null; kill "$pid" 2>/dev/null
    fi
  ) &
  wpid=$!
  wait "$pid"; rc=$?
  kill "$wpid" 2>/dev/null; wait "$wpid" 2>/dev/null
  if [ -e "logs/hang-$i.flag" ]; then hang=$((hang+1)); echo "iter $i: HANG"
  elif [ "$rc" -ne 0 ]; then fail=$((fail+1)); echo "iter $i: FAIL rc=$rc"; grep -E 'FAIL|TIMEOUT|SIGABRT|WATCHDOG|LEAK' "logs/iter-$i.log" | head -10
  else rm -f "logs/iter-$i.log"; echo "iter $i: ok"; fi
done
echo "SUMMARY iterations=$N fail=$fail hang=$hang"
echo "SUMMARY iterations=$N fail=$fail hang=$hang" >logs/summary.txt
[ "$fail" -eq 0 ] && [ "$hang" -eq 0 ]
