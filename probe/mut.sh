#!/bin/bash
# Revision-12 macOS mutants (THROWAWAY). Each must FAIL its target scenario by assertion.
set -u
cp -r probe /tmp/pristine
mutate() { # name old new scenario
  local name=$1 old=$2 new=$3 scen=$4
  rm -rf probe; cp -r /tmp/pristine probe
  python3 - probe/shim12.c "$old" "$new" <<'PY' || { echo "MUTANT $name: pattern not found"; return; }
import sys; p, a, b = sys.argv[1:]; s = open(p).read(); assert a in s, a; open(p, "w").write(s.replace(a, b, 1))
PY
  cc -o probe/shim12 probe/shim12.c probe/hostobjc.m -framework Foundation || { echo "MUTANT $name: does not compile"; return; }
  local o=/tmp/mut-$name.out
  python3 probe/scenarios.py $scen > $o 2>&1; local rc=$?
  echo "MUTANT $name: rc=$rc $(grep -c ' FAIL ' $o) FAIL / $(grep -c ' PASS ' $o) PASS"
  grep -E "^RESULT" $o | sed 's/^/    /' | cut -c1-240
}
mutate signal-by-pid '    if (!ch->confirmed) return ESRCH;
    for (;;) {' '    return kill(ch->pid, sig);
    for (;;) {' macos_reaper_race
mutate status-from-waitpid '    if (!ch->knote_fired) return -1;
    *ws = ch->knote_ws; return 0;' '    int r; while ((r = (int)waitpid(ch->pid, ws, 0)) < 0 && errno == EINTR) {}
    return r == ch->pid ? 0 : -1;' threads_refused
mutate unconfirmed-guesses-status '        goto status_lost;
    }
#endif' '        { int x; if (waitpid(ch.pid, &x, 0) == ch.pid) { ws = x; reaped = 1; goto finish; } }
        goto status_lost;
    }
#endif' status_lost_before_identity
rm -rf probe; cp -r /tmp/pristine probe
