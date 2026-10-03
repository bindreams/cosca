/* Plan F prototype shim, revision 4 (THROWAWAY). Linux and macOS.
 *
 * argv: shim --cosca-elevation-shim=1 <dir> <cosca-pid> <cosca-uid> -- prog args...
 *
 * Start: connect <dir>/s, check the listener's pid, block on the first byte.
 *   'A' start supervised; 'N' never start (125); 'R' run unsupervised (exec).
 *   No answer (connect ENOENT/ECONNREFUSED, EOF/ECONNRESET first): detach marker check, else 125.
 * Supervised: K SIGKILL, T SIGTERM, D disarm, EOF while armed SIGKILL; frame 'S'+i32 LE.
 * Linux relay (R*, revision 4): the handler writes {signo, si_code, si_pid, parent_alive} to a
 *   self-pipe; parent_alive is a zero-timeout poll of a pidfd on the parent, opened at start and
 *   proven to be the parent by re-reading getppid() afterwards. The loop relays iff si_pid == the
 *   recorded parent, the parent was alive when the handler ran, the parent shared our process group
 *   at start, si_code is SI_USER/SI_QUEUE, and the program is unreaped.
 * macOS (owner question A, option a): no relay; the shim ignores HUP INT QUIT TERM USR1 USR2 and
 *   the program gets the dispositions the shim inherited.
 * Both: SIGPIPE never kills the shim (MSG_NOSIGNAL / SO_NOSIGPIPE). The shim deletes nothing.
 * Prototype-only seams (env): SHIM_LOG, SHIM_GATE, SHIM_HOLD (see shim3.c). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#define NOSIG MSG_NOSIGNAL
#else
#include <sys/event.h>
#include <sys/ucred.h>
#define NOSIG 0
#endif
#define NOT_STARTED 125

static int logfd = -1;
static void lg(const char *fmt, ...) {
    if (logfd < 0) return;
    char b[512]; va_list ap; va_start(ap, fmt); int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n > 0) (void)!write(logfd, b, (size_t)n < sizeof b ? (size_t)n : sizeof b - 1);
}
static void gate(const char *env) {
    const char *p = getenv(env); if (!p) return;
    int fd = open(p, O_RDONLY | O_CLOEXEC); char c; (void)!read(fd, &c, 1); close(fd);
}
static const int RELAYED[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2 };
#define NREL (sizeof RELAYED / sizeof RELAYED[0])

static void run_unsupervised(char **prog) {
    lg("unsupervised exec %s\n", prog[0]);
    execvp(prog[0], prog);
    fprintf(stderr, "shim: exec %s: %s\n", prog[0], strerror(errno)); _exit(127);
}
static int marker_present(const char *dir, uid_t uid) {
    int d = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (d < 0) { lg("marker: dir open: %s\n", strerror(errno)); return 0; }
    struct stat st, m;
    int dir_ok = fstat(d, &st) == 0 && st.st_uid == uid && (st.st_mode & 0777) == 0700;
    int mk = fstatat(d, "start", &m, AT_SYMLINK_NOFOLLOW) == 0;
    int mk_ok = mk && S_ISREG(m.st_mode) && m.st_uid == uid;
    close(d);
    lg("marker: %s (dir owner/mode %s, marker %s)\n", dir_ok && mk_ok ? "present" : "absent",
       dir_ok ? "ok" : "rejected", !mk ? "missing" : mk_ok ? "ok" : "rejected");
    return dir_ok && mk_ok;
}

struct rec { int signo, code, pid, parent_alive; };
static int sigw = -1, ppfd = -1;
static void on_sig(int s, siginfo_t *i, void *u) {
    (void)u; int e = errno;
    struct pollfd p = { ppfd, POLLIN, 0 };
    int alive = ppfd >= 0 && poll(&p, 1, 0) == 0; /* poll is async-signal-safe */
    struct rec r = { s, i->si_code, i->si_pid, alive };
    (void)!write(sigw, &r, sizeof r);
    errno = e;
}

int main(int argc, char **argv) {
    if (argc < 8 || strcmp(argv[1], "--cosca-elevation-shim=1") != 0 || strcmp(argv[5], "--") != 0) {
        fprintf(stderr, "shim: unknown invocation\n"); return NOT_STARTED;
    }
#ifdef __APPLE__
    if (issetugid()) { fprintf(stderr, "shim: refusing a setuid/setgid context\n"); return NOT_STARTED; }
#else
    if (getuid() != geteuid() || getgid() != getegid()) { fprintf(stderr, "shim: refusing a setuid/setgid context\n"); return NOT_STARTED; }
#endif
    const char *dir = argv[2]; long cosca = strtol(argv[3], 0, 10); uid_t cuid = (uid_t)strtol(argv[4], 0, 10);
    char **prog = &argv[6];
    if (getenv("SHIM_LOG")) logfd = open(getenv("SHIM_LOG"), O_WRONLY | O_APPEND | O_CLOEXEC);
    lg("shim pid=%d ppid=%d pgrp=%d\n", getpid(), getppid(), getpgrp());
    gate("SHIM_GATE");

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    fcntl(s, F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
    { int one = 1; setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one); }
#endif
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s/s", dir);
    char c = 0; ssize_t n;
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) != 0) {
        lg("connect: %s\n", strerror(errno));
        if (errno != ENOENT && errno != ECONNREFUSED) return NOT_STARTED;
        goto no_answer;
    }
    long peer = -1;
#ifdef __linux__
    struct ucred cr; socklen_t cl = sizeof cr;
    if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0) peer = cr.pid;
#else
    pid_t pp; socklen_t pl = sizeof pp;
    if (getsockopt(s, SOL_LOCAL, LOCAL_PEERPID, &pp, &pl) == 0) peer = pp;
#endif
    if (peer != cosca) { lg("listener pid %ld is not cosca's %ld: refused, nothing written\n", peer, cosca); return NOT_STARTED; }
    do n = read(s, &c, 1); while (n < 0 && errno == EINTR);
    lg("first byte: %s\n", n == 1 ? (char[]){ c, 0 } : n == 0 ? "EOF" : strerror(errno));
    if (n == 1 && c == 'A') goto supervised;
    if (n == 1 && c == 'R') { close(s); run_unsupervised(prog); }
    if (n == 1) return NOT_STARTED;
    if (n < 0 && errno != ECONNRESET) return NOT_STARTED;
no_answer:
    close(s);
    if (marker_present(dir, cuid)) run_unsupervised(prog);
    lg("not started\n");
    return NOT_STARTED;

supervised:;
    sigset_t rel, old; sigemptyset(&rel);
    for (size_t i = 0; i < NREL; i++) sigaddset(&rel, RELAYED[i]);
    sigprocmask(SIG_BLOCK, &rel, &old);
    struct sigaction saved[NREL];
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], 0, &saved[i]);
#ifdef __linux__
    pid_t ppid0 = getppid();
    pid_t relay_from = 0;
    ppfd = (int)syscall(SYS_pidfd_open, ppid0, 0);
    if (ppfd >= 0 && getppid() == ppid0 && getpgid(ppid0) == getpgrp()) relay_from = ppid0;
    else if (ppfd >= 0 && getppid() != ppid0) { close(ppfd); ppfd = -1; }
    lg("relay_from=%d (parent %d, parent pgrp %d, my pgrp %d, parent pidfd %d)\n", relay_from, ppid0, getpgid(ppid0), getpgrp(), ppfd);
    int sp[2]; if (pipe2(sp, O_NONBLOCK | O_CLOEXEC) != 0) return NOT_STARTED;
    sigw = sp[1];
    struct sigaction h; memset(&h, 0, sizeof h);
    h.sa_sigaction = on_sig; h.sa_flags = SA_SIGINFO | SA_RESTART; sigemptyset(&h.sa_mask);
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], &h, 0);
#else
    int sp[2]; if (pipe(sp) != 0) return NOT_STARTED;
    for (int i = 0; i < 2; i++) { fcntl(sp[i], F_SETFD, FD_CLOEXEC); fcntl(sp[i], F_SETFL, O_NONBLOCK); }
    sigw = sp[1];
    struct sigaction h; memset(&h, 0, sizeof h);
    h.sa_sigaction = on_sig; h.sa_flags = SA_SIGINFO | SA_RESTART; sigemptyset(&h.sa_mask);
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], &h, 0);
    lg("relay: none (macOS); the shim records and swallows HUP INT QUIT TERM USR1 USR2\n");
#endif
    signal(SIGCHLD, SIG_DFL);
    pid_t me = getpid(), pid = fork();
    if (pid == 0) {
#ifdef __linux__
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != me) _exit(127);
#endif
        (void)me;
        for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], &saved[i], 0);
        sigprocmask(SIG_SETMASK, &old, 0);
        execvp(prog[0], prog);
        fprintf(stderr, "shim: exec %s: %s\n", prog[0], strerror(errno)); _exit(127);
    }
#ifdef __linux__
    int pfd = (int)syscall(SYS_pidfd_open, pid, 0);
#else
    int kq = kqueue();
    struct kevent ev[3];
    EV_SET(&ev[0], pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0);
    EV_SET(&ev[1], s, EVFILT_READ, EV_ADD, 0, 0, 0);
    EV_SET(&ev[2], sp[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    int exited_early = 0;
    if (kevent(kq, &ev[0], 1, 0, 0, 0) < 0) { if (errno == ESRCH) exited_early = 1; else return NOT_STARTED; }
    kevent(kq, &ev[1], 2, 0, 0, 0);
#endif
    sigprocmask(SIG_SETMASK, &old, 0);
    lg("program pid=%d\n", pid);
    int null = open("/dev/null", O_RDWR); dup2(null, 0); dup2(null, 1); dup2(null, 2); close(null);
    gate("SHIM_HOLD");

    int armed = 1, open_ = 1, reaped = 0, ws = 0;
    while (!reaped) {
        int exited = 0, readable = 0;
#ifdef __linux__
        struct pollfd p[3] = { { sp[0], POLLIN, 0 }, { pfd, POLLIN, 0 }, { open_ ? s : -1, POLLIN, 0 } };
        if (poll(p, 3, -1) < 0) { if (errno == EINTR) continue; return NOT_STARTED; }
        struct rec r;
        while (read(sp[0], &r, sizeof r) == sizeof r) {
            int user = r.code == SI_USER || r.code == SI_QUEUE;
            const char *why = !user ? "not process-sent" : !relay_from ? "parent not in my pgrp"
                            : r.pid != relay_from ? "not from parent" : !r.parent_alive ? "parent had exited" : 0;
            if (!why) {
                int rc = (int)syscall(SYS_pidfd_send_signal, pfd, r.signo, NULL, 0);
                lg("sig %d code %d from %d: RELAY rc=%d\n", r.signo, r.code, r.pid, rc);
            } else
                lg("sig %d code %d from %d: DROP (%s)\n", r.signo, r.code, r.pid, why);
        }
        exited = p[1].revents != 0; readable = open_ && p[2].revents;
#else
        struct kevent out[3];
        int k = exited_early ? 0 : kevent(kq, 0, 0, out, 3, 0);
        if (k < 0) { if (errno == EINTR) continue; return NOT_STARTED; }
        exited = exited_early;
        for (int i = 0; i < k; i++) {
            if (out[i].filter == EVFILT_PROC) exited = 1;
            if (out[i].filter == EVFILT_READ && (int)out[i].ident == s) readable = open_;
        }
        struct rec r;
        while (read(sp[0], &r, sizeof r) == sizeof r)
            lg("sig %d code %d from %d: DROP (no relay on macOS)\n", r.signo, r.code, r.pid);
#endif
        if (readable) {
            do n = read(s, &c, 1); while (n < 0 && errno == EINTR);
            int sig = 0;
            if (n == 1 && c == 'K') sig = SIGKILL;
            else if (n == 1 && c == 'T') sig = SIGTERM;
            else if (n == 1 && c == 'D') { armed = 0; lg("disarmed\n"); }
            else if (n <= 0) {
                open_ = 0; lg("EOF (armed=%d)\n", armed); if (armed) sig = SIGKILL;
#ifdef __APPLE__
                EV_SET(&ev[1], s, EVFILT_READ, EV_DELETE, 0, 0, 0); kevent(kq, &ev[1], 1, 0, 0, 0);
#endif
            }
            if (sig) {
#ifdef __linux__
                int rc = (int)syscall(SYS_pidfd_send_signal, pfd, sig, NULL, 0);
#else
                int rc = kill(pid, sig); /* unreaped child: only this loop reaps */
#endif
                lg("control %c: signal %d rc=%d\n", n == 1 ? c : '-', sig, rc);
            }
        }
        if (exited) {
#ifdef __linux__
            siginfo_t si; memset(&si, 0, sizeof si);
            if (waitid(P_PIDFD, (id_t)pfd, &si, WEXITED) != 0) return NOT_STARTED;
            ws = si.si_code == CLD_EXITED ? (si.si_status & 0xff) << 8 : (si.si_status | (si.si_code == CLD_DUMPED ? 0x80 : 0));
#else
            if (waitpid(pid, &ws, 0) != pid) return NOT_STARTED;
#endif
            reaped = 1;
            lg("reaped status %d\n", ws);
        }
    }
    unsigned char f[5] = { 'S', ws & 0xff, (ws >> 8) & 0xff, (ws >> 16) & 0xff, (ws >> 24) & 0xff };
    if (open_) (void)!send(s, f, 5, NOSIG);
    return WIFEXITED(ws) ? WEXITSTATUS(ws) : 128 + WTERMSIG(ws);
}
