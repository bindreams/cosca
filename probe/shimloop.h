/* The shim's supervision step and its final verdict as pure functions (THROWAWAY prototype, plan F revision 10).
 * No I/O and no system calls here: the run loop polls, gathers ready events into `struct events`, calls
 * decide(), and performs the returned actions; at the end it calls conclude() and writes the one frame. */
#ifndef SHIMLOOP_H
#define SHIMLOOP_H
#include <signal.h>

struct loopstate { int armed, conn_open, owner_watched, exec_pending, test_hooks; };
struct events {
    int control;        /* CTL_NONE, a byte 0-255 from cosca, or -1 for EOF on cosca's connection */
    int owner_exited;   /* cosca's process ended */
    int child_exited;   /* the child's pidfd/kqueue fired */
    int exec_report;    /* 0 nothing, 1 the status pipe gave EOF, 2 it gave a report */
    int forced_failure; /* test hook: supervision forced to fail */
};
#define CTL_NONE (-2) /* not 0: a NUL byte from cosca is a byte like any other */
struct actions {
    int signal;         /* 0, SIGKILL or SIGTERM: to the child, through its handle */
    int reap;           /* collect the child's status through its handle */
    int lost;           /* supervision failed: kill, reap, conclude */
    int pong;           /* test hook */
    int violation;      /* cosca sent a byte outside the protocol: logged, and the child is killed */
};

/* F's value: kind in bits 16-23, errno or signal number in bits 0-15. */
enum { NX_FORK = 1, NX_EXEC = 2, NX_SETUP = 3, NX_TERM = 4 };
#define NX(kind, n) (((kind) << 16) | ((n) & 0xffff))

static inline void decide(struct loopstate *st, const struct events *ev, struct actions *out) {
    out->signal = 0; out->reap = 0; out->lost = 0; out->pong = 0; out->violation = 0;
    if (ev->forced_failure) { out->lost = 1; return; }
    if (ev->exec_report) st->exec_pending = 0;
    if (ev->owner_exited && st->owner_watched) {
        st->owner_watched = 0;
        if (st->armed) out->signal = SIGKILL;
    }
    switch (ev->control) {
    case CTL_NONE: break;
    case 'K': out->signal = SIGKILL; break;
    case 'T': if (out->signal != SIGKILL) out->signal = SIGTERM; break;
    case 'D': st->armed = 0; break;
    case 'P': /* a test-build byte only; otherwise a violation like any unknown byte */
        if (st->test_hooks) { out->pong = 1; break; }
        /* fall through */
    default: out->signal = SIGKILL; out->violation = 1; break;
    case -1: st->conn_open = 0; if (st->armed) out->signal = SIGKILL; break;
    }
    if (ev->child_exited) out->reap = 1;
}

/* The one frame and the shim's exit code, from what the shim knows at the end:
 *   report  -- the status pipe's report (NX value), or 0
 *   reaped  -- 1 the child's status was collected (ws valid), 0 it was collected by someone else
 *   lost    -- supervision failed (the shim killed the child itself) */
struct verdict { char tag; int value; int code; };
static inline struct verdict conclude(int report, int reaped, int ws, int lost) {
    struct verdict v;
    if (report) { v.tag = 'F'; v.value = report; v.code = 117; return v; }  /* positive evidence wins */
    if (!reaped) { v.tag = 'U'; v.value = 0; v.code = 112; return v; }
    if (lost) { v.tag = 'L'; v.value = ws; v.code = 118; return v; }
    v.tag = 'S'; v.value = ws;
    v.code = (ws & 0x7f) == 0 ? (ws >> 8) & 0xff : 128 + (ws & 0x7f);
    return v;
}
#endif
