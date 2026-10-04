/* Unit tests of the pure supervision step (THROWAWAY). Each case fails by assertion, never by a hang. */
#include <stdio.h>
#include <string.h>
#include "shimloop.h"

static int fails = 0;
#define CHECK(name, cond) do { if (cond) printf("RESULT %-44s PASS  pure decide\n", name); else { printf("RESULT %-44s FAIL  pure decide\n", name); fails++; } } while (0)

int main(void) {
    struct loopstate st; struct events ev; struct actions a;

    /* k_with_exec_pending_signals_the_child: the status pipe is still open (exec not reported) and K arrives */
    st = (struct loopstate){ .armed = 1, .conn_open = 1, .owner_watched = 1, .exec_pending = 1 };
    memset(&ev, 0, sizeof ev); ev.control = 'K';
    decide(&st, &ev, &a);
    CHECK("k_with_exec_pending_signals_the_child", a.signal == SIGKILL);

    st = (struct loopstate){ .armed = 1, .conn_open = 1, .owner_watched = 1, .exec_pending = 1 };
    memset(&ev, 0, sizeof ev); ev.control = 'T';
    decide(&st, &ev, &a);
    CHECK("t_with_exec_pending_signals_the_child", a.signal == SIGTERM);

    st = (struct loopstate){ .armed = 1, .conn_open = 1, .owner_watched = 1, .exec_pending = 1 };
    memset(&ev, 0, sizeof ev); ev.owner_exited = 1;
    decide(&st, &ev, &a);
    CHECK("owner_exit_with_exec_pending_kills", a.signal == SIGKILL);

    st = (struct loopstate){ .armed = 1, .conn_open = 1, .owner_watched = 1, .exec_pending = 0 };
    memset(&ev, 0, sizeof ev); ev.control = 'D';
    decide(&st, &ev, &a);
    memset(&ev, 0, sizeof ev); ev.control = -1;
    decide(&st, &ev, &a);
    CHECK("eof_after_disarm_leaves_the_program", a.signal == 0 && st.conn_open == 0);

    st = (struct loopstate){ .armed = 1, .conn_open = 1, .owner_watched = 1, .exec_pending = 0 };
    memset(&ev, 0, sizeof ev); ev.control = -1;
    decide(&st, &ev, &a);
    CHECK("eof_while_armed_kills", a.signal == SIGKILL);

    st = (struct loopstate){ .armed = 1, .conn_open = 1, .owner_watched = 1, .exec_pending = 1 };
    memset(&ev, 0, sizeof ev); ev.control = 'T'; ev.owner_exited = 1;
    decide(&st, &ev, &a);
    CHECK("kill_wins_over_terminate_in_one_step", a.signal == SIGKILL);

    st = (struct loopstate){ .armed = 1, .conn_open = 1, .owner_watched = 1, .exec_pending = 0 };
    memset(&ev, 0, sizeof ev); ev.child_exited = 1;
    decide(&st, &ev, &a);
    CHECK("child_exit_reaps", a.reap == 1 && a.signal == 0);
    return fails ? 1 : 0;
}
