#!/bin/bash
# macOS mutants (THROWAWAY): each must make its target scenario FAIL.
set -u
cd probe
rc=0
mutate() { local name=$1 file=$2 old=$3 new=$4; shift 4
  git checkout -q -- shim5.c cosca_proto.py
  python3 - "$file" "$old" "$new" <<'PY' || { echo "MUTANT $name: pattern not found"; rc=1; return; }
import sys; p, a, b = sys.argv[1:]; s = open(p).read(); assert a in s, a; open(p, "w").write(s.replace(a, b, 1))
PY
  cc -o shim5 shim5.c
  if python3 scenarios.py "$@" > /tmp/mut-$name.out 2>&1; then echo "MUTANT $name: SURVIVED"; rc=1; else echo "MUTANT $name: KILLED"; fi
  grep '^RESULT' /tmp/mut-$name.out | sed 's/^/    /' | cut -c1-200
}
mutate owner-watch-absent shim5.c "if (out[i].filter == EVFILT_PROC && (pid_t)out[i].ident == peer) owner_gone = owner_ok;" "" owner_fork_copy
mutate owner-identity-unchecked shim5.c " || ui.p_uniqueid != ident)" ")" wrong_identity
mutate nosigpipe-unset cosca_proto.py "tmp=None, sigpipe_safe=True, accept_hook=None)" "tmp=None, sigpipe_safe=False, accept_hook=None)" nosigpipe_getsockopt
mutate kill-epipe-ok cosca_proto.py '                        raise ShimLost("K could not be delivered (%s) and no status was sent: the program may still be running" % e.strerror)' '                        return "already-exited"' kill_after_shim_death
git checkout -q -- shim5.c cosca_proto.py
exit $rc
