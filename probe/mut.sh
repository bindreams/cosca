#!/bin/bash
# macOS mutants (THROWAWAY): each must make its target scenario FAIL.
set -u
cd probe
rc=0
mutate() { local name=$1 file=$2 old=$3 new=$4; shift 4
  git checkout -q -- shim8.c cosca_proto.py
  python3 - "$file" "$old" "$new" <<'PY' || { echo "MUTANT $name: pattern not found"; rc=1; return; }
import sys; p, a, b = sys.argv[1:]; s = open(p).read(); assert a in s, a; open(p, "w").write(s.replace(a, b, 1))
PY
  cc -o shim8 shim8.c
  if python3 scenarios.py "$@" > /tmp/mut-$name.out 2>&1; then echo "MUTANT $name: SURVIVED"; rc=1; else echo "MUTANT $name: KILLED"; fi
  grep '^RESULT' /tmp/mut-$name.out | sed 's/^/    /' | cut -c1-200
}
mutate owner-watch-absent shim8.c "if (out[i].filter == EVFILT_PROC && (pid_t)out[i].ident == cosca) owner_gone = owner_ok;" "" owner_fork_copy
mutate token-pidversion-unchecked shim8.c " || tok.val[7] != pver)" ")" wrong_identity_parts
mutate uniqueid-unchecked shim8.c " || ui.p_uniqueid != uniq)" ")" wrong_identity_parts
mutate peer-uid-unchecked shim8.c " || tok.val[1] != ceuid" "" wrong_euid
mutate nosigpipe-unset cosca_proto.py "tmp=None, sigpipe_safe=True, accept_hook=None)" "tmp=None, sigpipe_safe=False, accept_hook=None)" nosigpipe_getsockopt
mutate kill-epipe-ok cosca_proto.py '                        raise ShimLost("K could not be delivered (%s) and no status was sent: the program may still be running" % e.strerror)' '                        return "already-exited"' kill_after_shim_death
mutate f-on-lost shim8.c "    if (open_) frame('L', ws);" "    if (open_) frame('F', lost_errno);" fail_pidfd
mutate exec-fail-as-status shim8.c "    if (exec_errno) { /* positive evidence" "    if (0) { /* positive evidence" exec_failure
mutate not-started-from-absence shim8.c "    if (exec_errno) { /* positive evidence" "    if (exec_errno || WIFSIGNALED(ws)) { /* positive evidence" preexec_sigkill
mutate owner-recheck-after-a-missing shim8.c '      for (int i = 0; i < k; i++) if (out[i].filter == EVFILT_PROC) return refuse(E_OWNER_GONE, "cosca exited before the start"); }' '      (void)k; }' code_123_after_a
mutate getppid-check-missing shim8.c "        if (getppid() != me) {" "        if (0) {" code_119
mutate front-esrch-unhandled cosca_proto.py "            except ProcessLookupError:
                watch = lambda: None" "            except OverflowError:
                watch = lambda: None" wait_started_late_shim
mutate noop-handlers-missing shim8.c "            sigaction(s, &nop, 0);
        }" "            signal(s, SIG_DFL);
        }" preexec_sigint
mutate status-fabricated shim8.c "            if (reap(pid, &ws) != 0) goto status_lost;
#endif
            reaped = 1;" "            reap(pid, &ws);
#endif
            reaped = 1;" status_stolen
mutate threads-unchecked shim8.c "      if (n != 1) {" "      if (0) {" threads_refused
mutate hello-before-verification shim8.c '    gate("SHIM_GATE_BEFORE_ID");' '    (void)!send(sock, "H", 1, NOSIG); hello_sent = 1; gate("SHIM_GATE_BEFORE_ID");' wrong_identity
mutate u-as-shim-lost cosca_proto.py '            raise StatusLost("the program has exited, but its status was collected by someone else")' '            raise ShimLost("status lost")' u_frame status_stolen
mutate u-missing-from-peek cosca_proto.py '                        if isinstance(f, tuple) and f[0] in ("S", "F", "L", "R", "U"):' '                        if isinstance(f, tuple) and f[0] in ("S", "F", "L", "R"):' u_frame
git checkout -q -- shim8.c cosca_proto.py
exit $rc
