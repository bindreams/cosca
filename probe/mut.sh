#!/bin/bash
# macOS mutants of the revision-10 prototype (THROWAWAY): each must make its target FAIL by assertion.
set -u
cd probe
rc=0
mutate() { local name=$1 file=$2 old=$3 new=$4; shift 4
  git checkout -q -- shim10.c shimloop.h cosca_proto.py
  python3 - "$file" "$old" "$new" <<'PY' || { echo "MUTANT $name: pattern not found"; rc=1; return; }
import sys; p, a, b = sys.argv[1:]; s = open(p).read(); assert a in s, a; open(p, "w").write(s.replace(a, b, 1))
PY
  cc -o shim10 shim10.c && cc -o decide_test decide_test.c || { echo "MUTANT $name: does not compile"; rc=1; return; }
  local r
  if [ "$1" = "@decide" ]; then ./decide_test > /tmp/mut-$name.out 2>&1; r=$?
  else python3 scenarios.py "$@" > /tmp/mut-$name.out 2>&1; r=$?; fi
  if [ $r = 0 ]; then echo "MUTANT $name: SURVIVED"; rc=1; else echo "MUTANT $name: KILLED rc=$r $(grep -c ' FAIL ' /tmp/mut-$name.out) FAIL / $(grep -c ' PASS ' /tmp/mut-$name.out) PASS"; fi
  grep '^RESULT' /tmp/mut-$name.out | sed 's/^/    /' | cut -c1-200
}
mutate owner-watch-absent shim10.c "(pid_t)out[i].ident == cosca) evs.owner_exited = st.owner_watched;" "(pid_t)out[i].ident == cosca) (void)0;" owner_fork_copy
mutate token-pidversion-unchecked shim10.c " || tok.val[7] != pver)" ")" wrong_identity_parts
mutate uniqueid-unchecked shim10.c " || ui.p_uniqueid != uniq)" ")" wrong_identity_parts
mutate peer-uid-unchecked shim10.c " || tok.val[1] != ceuid" "" wrong_euid
mutate nosigpipe-unset cosca_proto.py "tmp=None, sigpipe_safe=True, accept_hook=None, answer_hook=None)" "tmp=None, sigpipe_safe=False, accept_hook=None, answer_hook=None)" nosigpipe_getsockopt
mutate kill-epipe-ok cosca_proto.py '                        raise ShimLost("K could not be delivered (%s) and no status was sent: the program may still be running" % e.strerror)' '                        return "already-exited"' kill_after_shim_death
mutate f-on-lost shimloop.h "    if (lost) { v.tag = 'L';" "    if (lost) { v.tag = 'F';" fail_loop
mutate exec-fail-as-status shimloop.h "    if (report) { v.tag = 'F';" "    if (0) { v.tag = 'F';" exec_failure
mutate not-started-from-absence shimloop.h "    if (report) { v.tag = 'F';" "    if (report || (reaped && (ws & 0x7f))) { v.tag = 'F';" preexec_sigkill
mutate owner-recheck-after-a-missing shim10.c '      for (int i = 0; i < k; i++) if (out[i].filter == EVFILT_PROC) return refuse(E_OWNER_GONE, "cosca exited before the start"); }' '      (void)k; }' code_123_after_a
mutate getppid-check-missing shim10.c "        if (getppid() != me) {" "        if (0) {" code_119
mutate front-esrch-unhandled cosca_proto.py "            except ProcessLookupError:
                watch = lambda: None" "            except OverflowError:
                watch = lambda: None" wait_started_late_shim
mutate term-not-recorded shim10.c "            sigaction(s, is_term(s) ? &rt : &nop, 0);" "            sigaction(s, &nop, 0);" t_before_exec preexec_sigint
mutate fault-signals-caught shim10.c "            if (is_fault(s)) { sigaction(s, &dfl, 0); continue; }" "            if (0) {}" fault_before_exec
mutate status-fabricated shim10.c "    return r == ch->pid ? 0 : -1;" "    return 0;" status_stolen
mutate threads-unchecked shim10.c "    if (nthreads != 1) {" "    if (0) {" threads_refused threads_r114
mutate hello-before-verification shim10.c '    gate("SHIM_GATE_BEFORE_ID");' '    (void)!send(sock, "H", 1, NOSIG); hello_sent = 1; gate("SHIM_GATE_BEFORE_ID");' wrong_identity
mutate u-as-shim-lost cosca_proto.py '            raise StatusLost("the program has exited, but its status was collected by someone else")' '            raise ShimLost("status lost")' u_frame status_stolen
mutate u-missing-from-peek cosca_proto.py '                        if isinstance(f, tuple) and f[0] in ("S", "F", "L", "R", "U"):' '                        if isinstance(f, tuple) and f[0] in ("S", "F", "L", "R"):' u_frame
mutate garbled-sets-final cosca_proto.py '        if tag in (b"S", b"L", b"R", b"U") or f_cause:
            self.final = tag' '        if True:
            self.final = tag' garbled_then_kill
mutate f-kind-unvalidated cosca_proto.py '        if tag == b"F" and f_cause:' '        if tag == b"F":' frames
mutate f-kind-fork-as-exec shim10.c "frame('F', NX(NX_FORK, e))" "frame('F', NX(NX_EXEC, e))" fail_fork
mutate f-kind-setup-as-exec shim10.c "pipe(sp) != 0 || pipe(ep) != 0) { int e = errno; frame('F', NX(NX_SETUP, e))" "pipe(sp) != 0 || pipe(ep) != 0) { int e = errno; frame('F', NX(NX_EXEC, e))" fail_pipe
mutate unknown-byte-ignored-e2e shimloop.h "    default: out->signal = SIGKILL; out->violation = 1; break;" "    default: break;" unknown_control_byte
mutate host-executable-allowed cosca_proto.py '    if MACOS and mode == "host-executable":' '    if False:' host_executable_macos
mutate r114-hidden shim10.c "    if (hello_sent) frame('R', code);" "    (void)0;" threads_r114
mutate r114-before-a shim10.c '    lg("hello sent; awaiting the answer\n");' '    if (nthreads != 1) return refuse(E_THREADS, "threads"); lg("hello sent; awaiting the answer\n");' threads_r114
mutate decide-ignores-control-while-exec-pending shimloop.h "    switch (ev->control) {" "    switch (st->exec_pending ? CTL_NONE : ev->control) {" @decide
mutate nul-byte-ignored shimloop.h "#define CTL_NONE (-2)" "#define CTL_NONE 0" @decide
mutate owner-exit-ignores-disarm shimloop.h "        if (st->armed) out->signal = SIGKILL;
    }" "        out->signal = SIGKILL;
    }" @decide
mutate exec-pending-never-cleared shimloop.h "    if (ev->exec_report) st->exec_pending = 0;
" "" @decide
mutate lost-path-f-dropped shimloop.h "    if (report) { v.tag = 'F';" "    if (report && !lost) { v.tag = 'F';" @decide
git checkout -q -- shim10.c shimloop.h cosca_proto.py
exit $rc
