#!/bin/bash
# macOS mutants of the revision-9 prototype (THROWAWAY): each must make its target FAIL by assertion.
set -u
cd probe
rc=0
mutate() { local name=$1 file=$2 old=$3 new=$4; shift 4
  git checkout -q -- shim9.c shimloop.h cosca_proto.py
  python3 - "$file" "$old" "$new" <<'PY' || { echo "MUTANT $name: pattern not found"; rc=1; return; }
import sys; p, a, b = sys.argv[1:]; s = open(p).read(); assert a in s, a; open(p, "w").write(s.replace(a, b, 1))
PY
  cc -o shim9 shim9.c && cc -o decide_test decide_test.c || { echo "MUTANT $name: does not compile"; rc=1; return; }
  local r
  if [ "$1" = "@decide" ]; then ./decide_test > /tmp/mut-$name.out 2>&1; r=$?
  else python3 scenarios.py "$@" > /tmp/mut-$name.out 2>&1; r=$?; fi
  if [ $r = 0 ]; then echo "MUTANT $name: SURVIVED"; rc=1; else echo "MUTANT $name: KILLED rc=$r $(grep -c ' FAIL ' /tmp/mut-$name.out) FAIL / $(grep -c ' PASS ' /tmp/mut-$name.out) PASS"; fi
  grep '^RESULT' /tmp/mut-$name.out | sed 's/^/    /' | cut -c1-200
}
mutate owner-watch-absent shim9.c "(pid_t)out[i].ident == cosca) evs.owner_exited = st.owner_watched;" "(pid_t)out[i].ident == cosca) (void)0;" owner_fork_copy
mutate token-pidversion-unchecked shim9.c " || tok.val[7] != pver)" ")" wrong_identity_parts
mutate uniqueid-unchecked shim9.c " || ui.p_uniqueid != uniq)" ")" wrong_identity_parts
mutate peer-uid-unchecked shim9.c " || tok.val[1] != ceuid" "" wrong_euid
mutate nosigpipe-unset cosca_proto.py "tmp=None, sigpipe_safe=True, accept_hook=None, answer_hook=None)" "tmp=None, sigpipe_safe=False, accept_hook=None, answer_hook=None)" nosigpipe_getsockopt
mutate kill-epipe-ok cosca_proto.py '                        raise ShimLost("K could not be delivered (%s) and no status was sent: the program may still be running" % e.strerror)' '                        return "already-exited"' kill_after_shim_death
mutate f-on-lost shim9.c "    if (st.conn_open) frame('L', ws);" "    if (st.conn_open) frame('F', 1);" fail_loop
mutate exec-fail-as-status shim9.c "    if (report) { /* positive evidence: it never ran */" "    if (0) { /* positive evidence: it never ran */" exec_failure
mutate not-started-from-absence shim9.c "    if (report) { /* positive evidence: it never ran */" "    if (report || WIFSIGNALED(ws)) { /* positive evidence: it never ran */" preexec_sigkill
mutate owner-recheck-after-a-missing shim9.c '      for (int i = 0; i < k; i++) if (out[i].filter == EVFILT_PROC) return refuse(E_OWNER_GONE, "cosca exited before the start"); }' '      (void)k; }' code_123_after_a
mutate getppid-check-missing shim9.c "        if (getppid() != me) {" "        if (0) {" code_119
mutate front-esrch-unhandled cosca_proto.py "            except ProcessLookupError:
                watch = lambda: None" "            except OverflowError:
                watch = lambda: None" wait_started_late_shim
mutate term-not-recorded shim9.c "            sigaction(s, is_term(s) ? &rt : &nop, 0);" "            sigaction(s, &nop, 0);" t_before_exec preexec_sigint
mutate status-fabricated shim9.c "    return r == ch->pid ? 0 : -1;" "    return 0;" status_stolen
mutate threads-unchecked shim9.c "    if (nthreads != 1) {" "    if (0) {" threads_refused threads_r114
mutate hello-before-verification shim9.c '    gate("SHIM_GATE_BEFORE_ID");' '    (void)!send(sock, "H", 1, NOSIG); hello_sent = 1; gate("SHIM_GATE_BEFORE_ID");' wrong_identity
mutate u-as-shim-lost cosca_proto.py '            raise StatusLost("the program has exited, but its status was collected by someone else")' '            raise ShimLost("status lost")' u_frame status_stolen
mutate u-missing-from-peek cosca_proto.py '                        if isinstance(f, tuple) and f[0] in ("S", "F", "L", "R", "U"):' '                        if isinstance(f, tuple) and f[0] in ("S", "F", "L", "R"):' u_frame
mutate garbled-sets-final cosca_proto.py '        if tag in (b"S", b"F", b"L", b"R", b"U"):
            self.final = tag' '        if True:
            self.final = tag' garbled_then_kill
mutate host-executable-allowed cosca_proto.py '    if MACOS and mode == "host-executable":' '    if False:' host_executable_macos
mutate r114-hidden shim9.c "    if (hello_sent) frame('R', code);" "    (void)0;" threads_r114
mutate r114-before-a shim9.c '    lg("hello sent; awaiting the answer\n");' '    if (nthreads != 1) return refuse(E_THREADS, "threads"); lg("hello sent; awaiting the answer\n");' threads_r114
mutate decide-ignores-control-while-exec-pending shimloop.h "    switch (ev->control) {" "    switch (st->exec_pending ? 0 : ev->control) {" @decide
git checkout -q -- shim9.c shimloop.h cosca_proto.py
exit $rc
