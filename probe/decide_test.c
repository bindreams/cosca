/* Unit tests of the pure supervision step and verdict (THROWAWAY). Each case fails by assertion, never by a hang. */
#include <stdio.h>
#include <string.h>
#include "shimloop.h"

static int fails = 0;
#define CHECK(name, cond) do { if (cond) printf("RESULT %-48s PASS  pure\n", name); else { printf("RESULT %-48s FAIL  pure\n", name); fails++; } } while (0)

static struct loopstate fresh(int exec_pending) {
    return (struct loopstate){ .armed = 1, .conn_open = 1, .owner_watched = 1, .exec_pending = exec_pending, .test_hooks = 0 };
}
static struct events none(void) { struct events e; memset(&e, 0, sizeof e); e.control = CTL_NONE; return e; }

int main(void) {
    struct loopstate st; struct events ev; struct actions a; struct verdict v;

    /* --- decide() --- */
    st = fresh(1); ev = none(); ev.control = 'K'; decide(&st, &ev, &a);
    CHECK("k_with_exec_pending_signals_the_child", a.signal == SIGKILL);

    st = fresh(1); ev = none(); ev.control = 'T'; decide(&st, &ev, &a);
    CHECK("t_with_exec_pending_signals_the_child", a.signal == SIGTERM);

    st = fresh(1); ev = none(); ev.owner_exited = 1; decide(&st, &ev, &a);
    CHECK("owner_exit_with_exec_pending_kills", a.signal == SIGKILL);

    st = fresh(0); ev = none(); ev.control = 'D'; decide(&st, &ev, &a);
    ev = none(); ev.owner_exited = 1; decide(&st, &ev, &a);
    CHECK("owner_exit_after_disarm_leaves_the_program", a.signal == 0 && st.owner_watched == 0);

    st = fresh(0); ev = none(); ev.control = 'D'; decide(&st, &ev, &a);
    ev = none(); ev.control = -1; decide(&st, &ev, &a);
    CHECK("eof_after_disarm_leaves_the_program", a.signal == 0 && st.conn_open == 0);

    st = fresh(0); ev = none(); ev.control = -1; decide(&st, &ev, &a);
    CHECK("eof_while_armed_kills", a.signal == SIGKILL);

    st = fresh(1); ev = none(); ev.control = 'T'; ev.owner_exited = 1; decide(&st, &ev, &a);
    CHECK("kill_wins_over_terminate_in_one_step", a.signal == SIGKILL);

    st = fresh(0); ev = none(); ev.child_exited = 1; decide(&st, &ev, &a);
    CHECK("child_exit_reaps", a.reap == 1 && a.signal == 0);

    st = fresh(1); ev = none(); ev.exec_report = 1; decide(&st, &ev, &a);
    CHECK("status_pipe_eof_clears_exec_pending", st.exec_pending == 0);
    st = fresh(1); ev = none(); ev.exec_report = 2; decide(&st, &ev, &a);
    CHECK("status_pipe_report_clears_exec_pending", st.exec_pending == 0);

    st = fresh(0); ev = none(); ev.control = 'X'; decide(&st, &ev, &a);
    CHECK("unknown_byte_is_a_violation_and_kills", a.violation == 1 && a.signal == SIGKILL);
    st = fresh(0); st.armed = 0; ev = none(); ev.control = 0x00; decide(&st, &ev, &a);
    CHECK("nul_byte_after_disarm_is_still_a_violation", a.violation == 1 && a.signal == SIGKILL);
    st = fresh(0); ev = none(); ev.control = 'P'; decide(&st, &ev, &a);
    CHECK("ping_without_test_hooks_is_a_violation", a.violation == 1 && a.signal == SIGKILL && a.pong == 0);
    st = fresh(0); st.test_hooks = 1; ev = none(); ev.control = 'P'; decide(&st, &ev, &a);
    CHECK("ping_with_test_hooks_pongs_only", a.pong == 1 && a.signal == 0 && a.violation == 0);

    /* --- conclude(): F > U > L > S --- */
    v = conclude(NX(NX_EXEC, 2), 1, 0x7f00, 0);
    CHECK("report_with_status_is_f", v.tag == 'F' && v.value == NX(NX_EXEC, 2) && v.code == 117);
    v = conclude(NX(NX_EXEC, 2), 0, 0, 0);
    CHECK("report_with_stolen_reap_is_f_not_u", v.tag == 'F' && v.code == 117);
    v = conclude(NX(NX_TERM, 15), 1, 9, 1);
    CHECK("report_on_the_lost_path_is_f_not_l", v.tag == 'F' && v.value == NX(NX_TERM, 15));
    v = conclude(NX(NX_EXEC, 2), 0, 0, 1);
    CHECK("report_on_the_lost_path_with_stolen_reap_is_f", v.tag == 'F');
    v = conclude(0, 0, 0, 0);
    CHECK("no_report_stolen_reap_is_u_112", v.tag == 'U' && v.code == 112);
    v = conclude(0, 0, 0, 1);
    CHECK("no_report_lost_and_stolen_is_u", v.tag == 'U' && v.code == 112);
    v = conclude(0, 1, 9, 1);
    CHECK("lost_with_status_is_l_118", v.tag == 'L' && v.value == 9 && v.code == 118);
    v = conclude(0, 1, 42 << 8, 0);
    CHECK("exit_42_is_s_and_code_42", v.tag == 'S' && v.value == (42 << 8) && v.code == 42);
    v = conclude(0, 1, 15, 0);
    CHECK("signal_15_is_s_and_code_143", v.tag == 'S' && v.value == 15 && v.code == 143);
    return fails ? 1 : 0;
}
