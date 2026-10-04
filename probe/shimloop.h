/* The shim's supervision step as a pure function (THROWAWAY prototype, plan F revision 9).
 * The event loop only polls, gathers ready events into `struct events`, calls decide(), and performs the
 * returned actions. No blocking call lives anywhere else in the loop. */
#ifndef SHIMLOOP_H
#define SHIMLOOP_H
#include <signal.h>

struct loopstate { int armed, conn_open, owner_watched, exec_pending; };
struct events {
    int control;        /* 0 none, 'K' 'T' 'D' 'P', or -1 for EOF on cosca's connection */
    int owner_exited;   /* cosca's process ended */
    int child_exited;   /* the child's pidfd/kqueue fired */
    int exec_report;    /* 0 nothing, 1 the status pipe gave EOF, 2 it gave a report (errno or -signal) */
    int forced_failure; /* test hook: supervision forced to fail */
};
struct actions {
    int signal;         /* 0, SIGKILL or SIGTERM: to the child, through its handle */
    int reap;           /* collect the child's status through its handle */
    int lost;           /* supervision failed: kill, reap, report L/F */
    int pong;           /* test hook */
};

/* Pure: reads only its arguments, writes only *st and *out. Control is acted on whatever the exec state. */
static inline void decide(struct loopstate *st, const struct events *ev, struct actions *out) {
    out->signal = 0; out->reap = 0; out->lost = 0; out->pong = 0;
    if (ev->forced_failure) { out->lost = 1; return; }
    if (ev->exec_report) st->exec_pending = 0;
    if (ev->owner_exited && st->owner_watched) {
        st->owner_watched = 0;
        if (st->armed) out->signal = SIGKILL;
    }
    switch (ev->control) {
    case 'K': out->signal = SIGKILL; break;
    case 'T': if (out->signal != SIGKILL) out->signal = SIGTERM; break;
    case 'D': st->armed = 0; break;
    case 'P': out->pong = 1; break;
    case -1: st->conn_open = 0; if (st->armed) out->signal = SIGKILL; break;
    default: break;
    }
    if (ev->child_exited) out->reap = 1;
}
#endif
