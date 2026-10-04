/* Plan F prototype shim, revision 6 (THROWAWAY). Linux and macOS.
 *
 * argv: shim --cosca-elevation-shim=1 <dir> <cosca-pid> <cosca-identity> <cosca-euid> -- prog args...
 *       (=1x: every argument after the flag except "--" is hex, for osascript)
 *   identity: Linux the pidfs inode of cosca's process; macOS "<p_uniqueid>:<p_idversion>".
 *
 * Who is cosca (all must hold, else 122):
 *   Linux: SO_PEERCRED pid == argv pid and uid == argv euid; SO_PEERPIDFD (the listener's creator, even if
 *     it has exited) has argv's inode; the first byte arrives with SCM_CREDENTIALS (SO_PASSCRED) of
 *     argv's pid and euid, so a process merely holding a copy of the listener cannot answer.
 *   macOS: LOCAL_PEERTOKEN pid, euid and pidversion match argv; after NOTE_EXIT is registered on that pid,
 *     its p_uniqueid matches. (No per-message credentials on macOS: owner question [6/6].)
 * Owner watch: the verified handle is polled before the first byte, re-checked after reading 'A' and
 *   before fork, and kept in the event loop (owner exit = EOF).
 * Frames shim -> cosca, exactly one: 'S'+status (program exited), 'F'+errno (exec provably did not
 *   happen), 'L'+status (the program ran, supervision failed, the shim killed and reaped it).
 * Exec is proven by a CLOEXEC status pipe: EOF = exec'd, 4 bytes = exec's errno.
 * Exit codes before the program runs: 116 owner watch could not be set up, 117 exec failed,
 *   118 could not fork/start, 119 (child) shim died before exec, 120 invocation, 121 set-id,
 *   122 not cosca, 123 cosca exited before the start, 124 no answer, 125 told N.
 * Prototype-only seams (env): SHIM_LOG, SHIM_GATE, SHIM_GATE_READ, SHIM_HOLD, SHIM_FAIL_FORK, SHIM_FAIL_PIDFD,
 *   SHIM_FAIL_LOOP (a FIFO; readable = force the lost path), SHIM_DIE_AFTER_FORK, SHIM_CHILD_GATE,
 *   SHIM_NO_PEERPIDFD, SHIM_FAIL_OWNERFD. Relay code is unchanged from revision 5 (on hold). */
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
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
#define NOSIG MSG_NOSIGNAL
#else
#include <libproc.h>
#include <mach/message.h>
#include <sys/event.h>
#include <sys/proc_info.h>
#include <sys/ucred.h>
#define NOSIG 0
#define PROC_PIDUNIQIDENTIFIERINFO 17
struct proc_uniqidentifierinfo { uint8_t p_uuid[16]; uint64_t p_uniqueid; uint64_t p_puniqueid; int32_t p_idversion;
                                 uint32_t p_reserve2; uint64_t p_reserve3; uint64_t p_reserve4; };
#endif

enum { E_OWNERFD = 116, E_EXEC = 117, E_SPAWN = 118, E_NOPARENT = 119, E_INVOCATION = 120, E_SETID = 121,
       E_NOT_COSCA = 122, E_OWNER_GONE = 123, E_NO_ANSWER = 124, E_TOLD_N = 125 };

static int logfd = -1;
static void lg(const char *fmt, ...) {
    if (logfd < 0) return;
    char b[512]; va_list ap; va_start(ap, fmt); int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n > 0) (void)!write(logfd, b, (size_t)n < sizeof b ? (size_t)n : sizeof b - 1);
}
static int refuse(int code, const char *why) {
    fprintf(stderr, "cosca-elevation-shim: %s; the program was not started (exit %d)\n", why, code);
    lg("refused %d: %s\n", code, why);
    return code;
}
static void gate(const char *env) {
    const char *p = getenv(env); if (!p) return;
    int fd = open(p, O_RDONLY | O_CLOEXEC); char c; (void)!read(fd, &c, 1); close(fd);
}
static int unhex(char *a) {
    size_t n = strlen(a); if (n % 2) return -1;
    for (size_t i = 0; i < n; i += 2) { unsigned v; if (sscanf(a + i, "%2x", &v) != 1) return -1; a[i / 2] = (char)v; }
    a[n / 2] = 0; return 0;
}
static const int RELAYED[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2 };
#define NREL (sizeof RELAYED / sizeof RELAYED[0])
struct rec { int signo, code, pid, parent_alive; };
static int sigw = -1, ppfd = -1;
static void on_sig(int s, siginfo_t *i, void *u) {
    (void)u; int e = errno;
    struct pollfd p = { ppfd, POLLIN, 0 };
    int alive = ppfd >= 0 && poll(&p, 1, 0) == 0;
    struct rec r = { s, i->si_code, i->si_pid, alive };
    (void)!write(sigw, &r, sizeof r);
    errno = e;
}
static void frame(int s, char tag, int32_t v) {
    unsigned char f[5] = { (unsigned char)tag, v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff };
    (void)!send(s, f, 5, NOSIG);
}
/* Reap a child that is ours and unreaped (only this thread reaps); return its raw wait status. */
static int reap(pid_t pid) { int ws = 0; while (waitpid(pid, &ws, 0) < 0 && errno == EINTR) {} return ws; }

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--cosca-elevation-shim=1x") == 0) {
        for (int i = 2; i < argc; i++)
            if (strcmp(argv[i], "--") != 0 && unhex(argv[i]) != 0) return refuse(E_INVOCATION, "malformed hex argument");
        argv[1] = "--cosca-elevation-shim=1";
    }
    if (argc < 8 || strcmp(argv[1], "--cosca-elevation-shim=1") != 0 || strcmp(argv[6], "--") != 0)
        return refuse(E_INVOCATION, "unknown invocation or protocol version");
#ifdef __APPLE__
    if (issetugid()) return refuse(E_SETID, "refusing a set-id context");
#else
    if (getuid() != geteuid() || getgid() != getegid()) return refuse(E_SETID, "refusing a set-id context");
#endif
    const char *dir = argv[2]; pid_t cosca = (pid_t)strtol(argv[3], 0, 10);
    const char *ident = argv[4]; uid_t ceuid = (uid_t)strtoul(argv[5], 0, 10);
    char **prog = &argv[7];
    if (getenv("SHIM_LOG")) logfd = open(getenv("SHIM_LOG"), O_WRONLY | O_APPEND | O_CLOEXEC);
    lg("shim pid=%d ppid=%d pgrp=%d\n", getpid(), getppid(), getpgrp());
    gate("SHIM_GATE");

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    fcntl(s, F_SETFD, FD_CLOEXEC); /* the shim is single-threaded */
#ifdef __linux__
    { int one = 1; setsockopt(s, SOL_SOCKET, SO_PASSCRED, &one, sizeof one); }
#endif
#ifdef SO_NOSIGPIPE
    { int one = 1; setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
      int v = 0; socklen_t vl = sizeof v; getsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &v, &vl); lg("nosigpipe=%d\n", v); }
#endif
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s/s", dir);
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) != 0) { lg("connect: %s\n", strerror(errno)); return refuse(E_NO_ANSWER, "could not reach cosca"); }
    gate("SHIM_GATE_BEFORE_ID"); /* seam: order the identity read against a leaked listener's accept */

    /* --- who is cosca --- */
#ifdef __linux__
    struct ucred cr; socklen_t cl = sizeof cr;
    if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0 || cr.pid != cosca || cr.uid != ceuid)
        return refuse(E_NOT_COSCA, "the listener's pid or uid is not cosca's");
    int ofd = -1; socklen_t ol = sizeof ofd;
    if (getenv("SHIM_FAIL_OWNERFD")) return refuse(E_OWNERFD, "could not watch cosca's process");
    int pr = getenv("SHIM_NO_PEERPIDFD") ? (errno = ENOPROTOOPT, -1) : getsockopt(s, SOL_SOCKET, SO_PEERPIDFD, &ofd, &ol);
    if (pr == 0) {
        lg("owner handle: SO_PEERPIDFD\n");
    } else if (errno != ENOPROTOOPT && errno != EOPNOTSUPP) { /* the listener's creator is gone: not cosca */
        lg("SO_PEERPIDFD: %s\n", strerror(errno));
        return refuse(E_NOT_COSCA, "the listener's creator has exited");
    } else { /* pre-6.5 kernels (and below 6.9 the identity is UNMEASURED): the per-message credentials carry the proof */
        ofd = (int)syscall(SYS_pidfd_open, cosca, 0);
        if (ofd < 0) return errno == ESRCH ? refuse(E_OWNER_GONE, "cosca exited before the start") : refuse(E_OWNERFD, "could not watch cosca's process");
        lg("owner handle: pidfd_open\n");
    }
    struct stat ost;
    if (fstat(ofd, &ost) != 0 || strtoull(ident, 0, 10) != (unsigned long long)ost.st_ino)
        return refuse(E_NOT_COSCA, "the listener's process identity does not match cosca's");
#else
    audit_token_t tok; socklen_t tl = sizeof tok;
    unsigned long long uniq = strtoull(ident, 0, 10); const char *colon = strchr(ident, ':');
    unsigned pver = colon ? (unsigned)strtoul(colon + 1, 0, 10) : 0;
    if (getsockopt(s, SOL_LOCAL, LOCAL_PEERTOKEN, &tok, &tl) != 0 || (pid_t)tok.val[5] != cosca || tok.val[1] != ceuid || tok.val[7] != pver)
        return refuse(E_NOT_COSCA, "the listener's token is not cosca's");
    int kq = kqueue();
    if (getenv("SHIM_FAIL_OWNERFD") || kq < 0) return refuse(E_OWNERFD, "could not watch cosca's process");
    struct kevent oev; EV_SET(&oev, cosca, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0);
    if (kevent(kq, &oev, 1, 0, 0, 0) < 0) return errno == ESRCH ? refuse(E_OWNER_GONE, "cosca exited before the start") : refuse(E_OWNERFD, "could not watch cosca's process");
    struct proc_uniqidentifierinfo ui;
    if (proc_pidinfo(cosca, PROC_PIDUNIQIDENTIFIERINFO, 0, &ui, sizeof ui) != (int)sizeof ui || ui.p_uniqueid != uniq)
        return refuse(E_NOT_COSCA, "the listener's process identity does not match cosca's");
    struct kevent sev; EV_SET(&sev, s, EVFILT_READ, EV_ADD, 0, 0, 0); kevent(kq, &sev, 1, 0, 0, 0);
#endif
    lg("owner verified pid=%d\n", cosca);
    /* --- first byte, owner exit first --- */
    for (;;) {
#ifdef __linux__
        struct pollfd p[2] = { { ofd, POLLIN, 0 }, { s, POLLIN, 0 } };
        if (poll(p, 2, -1) < 0) { if (errno == EINTR) continue; return refuse(E_NO_ANSWER, "poll failed"); }
        if (p[0].revents) return refuse(E_OWNER_GONE, "cosca exited before the start");
        if (p[1].revents) break;
#else
        struct kevent out[2]; int k = kevent(kq, 0, 0, out, 2, 0);
        if (k < 0) { if (errno == EINTR) continue; return refuse(E_NO_ANSWER, "kevent failed"); }
        for (int i = 0; i < k; i++) if (out[i].filter == EVFILT_PROC) return refuse(E_OWNER_GONE, "cosca exited before the start");
        break;
#endif
    }
    char c = 0; ssize_t n;
#ifdef __linux__
    char cbuf[CMSG_SPACE(sizeof(struct ucred))]; struct iovec iov = { &c, 1 };
    struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf };
    do n = recvmsg(s, &mh, 0); while (n < 0 && errno == EINTR);
    if (n == 1) {
        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); struct ucred mc = { 0, (uid_t)-1, (gid_t)-1 };
        if (cm && cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_CREDENTIALS) memcpy(&mc, CMSG_DATA(cm), sizeof mc);
        lg("first byte from pid %d uid %d\n", mc.pid, mc.uid);
        if (mc.pid != cosca || mc.uid != ceuid) return refuse(E_NOT_COSCA, "the answer was not written by cosca");
    }
#else
    do n = read(s, &c, 1); while (n < 0 && errno == EINTR);
#endif
    lg("first byte: %s\n", n == 1 ? (char[]){ c, 0 } : n == 0 ? "EOF" : strerror(errno));
    if (n == 1 && c == 'N') return refuse(E_TOLD_N, "cosca refused the start");
    if (!(n == 1 && c == 'A')) return refuse(E_NO_ANSWER, "no answer from cosca");
    gate("SHIM_GATE_AFTER_A");
    /* 'A' may have been buffered by a cosca that has since exited: re-check before anything starts. */
#ifdef __linux__
    { struct pollfd p = { ofd, POLLIN, 0 }; if (poll(&p, 1, 0) > 0) return refuse(E_OWNER_GONE, "cosca exited before the start"); }
#else
    { struct kevent out[2]; struct timespec z = { 0, 0 }; int k = kevent(kq, 0, 0, out, 2, &z);
      for (int i = 0; i < k; i++) if (out[i].filter == EVFILT_PROC) return refuse(E_OWNER_GONE, "cosca exited before the start"); }
#endif

    sigset_t rel, old; sigemptyset(&rel);
    for (size_t i = 0; i < NREL; i++) sigaddset(&rel, RELAYED[i]);
    sigprocmask(SIG_BLOCK, &rel, &old);
    struct sigaction saved[NREL];
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], 0, &saved[i]);
    int sp[2], ep[2];
#ifdef __linux__
    pid_t ppid0 = getppid(), relay_from = 0;
    ppfd = (int)syscall(SYS_pidfd_open, ppid0, 0);
    if (ppfd >= 0 && getppid() == ppid0 && getpgid(ppid0) == getpgrp()) relay_from = ppid0;
    else if (ppfd >= 0 && getppid() != ppid0) { close(ppfd); ppfd = -1; }
    if (pipe2(sp, O_NONBLOCK | O_CLOEXEC) != 0 || pipe2(ep, O_CLOEXEC) != 0) { frame(s, 'F', errno); return refuse(E_SPAWN, "pipe failed"); }
#else
    if (pipe(sp) != 0 || pipe(ep) != 0) { frame(s, 'F', errno); return refuse(E_SPAWN, "pipe failed"); }
    for (int i = 0; i < 2; i++) { fcntl(sp[i], F_SETFD, FD_CLOEXEC); fcntl(sp[i], F_SETFL, O_NONBLOCK); fcntl(ep[i], F_SETFD, FD_CLOEXEC); }
#endif
    sigw = sp[1];
    struct sigaction h; memset(&h, 0, sizeof h);
    h.sa_sigaction = on_sig; h.sa_flags = SA_SIGINFO | SA_RESTART; sigemptyset(&h.sa_mask);
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], &h, 0);
    signal(SIGCHLD, SIG_DFL);
    pid_t me = getpid(), pid = getenv("SHIM_FAIL_FORK") ? (errno = EAGAIN, -1) : fork();
    if (pid < 0) { int e = errno; frame(s, 'F', e); return refuse(E_SPAWN, "could not fork: the program never ran"); }
    if (pid == 0) {
        close(ep[0]);
        gate("SHIM_CHILD_GATE"); /* seam: hold the child before PDEATHSIG is armed */
#ifdef __linux__
        prctl(PR_SET_PDEATHSIG, SIGKILL);
#endif
        if (getppid() != me) { lg("child: the shim is gone before exec; exit 119\n"); _exit(E_NOPARENT); }
        for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], &saved[i], 0);
        sigprocmask(SIG_SETMASK, &old, 0);
        execvp(prog[0], prog);
        int e = errno; (void)!write(ep[1], &e, sizeof e); _exit(127);
    }
    close(ep[1]);
    if (getenv("SHIM_DIE_AFTER_FORK")) { lg("seam: shim exits after fork\n"); _exit(118); }
    /* Exec proven or disproven before anything else is reported. */
    int ee = 0; ssize_t en;
    do en = read(ep[0], &ee, sizeof ee); while (en < 0 && errno == EINTR);
    close(ep[0]);
    if (en == (ssize_t)sizeof ee) {
        int ws = reap(pid); (void)ws;
        lg("exec failed: %s\n", strerror(ee));
        frame(s, 'F', ee);
        fprintf(stderr, "cosca-elevation-shim: exec %s: %s\n", prog[0], strerror(ee));
        return refuse(E_EXEC, "the program could not be executed");
    }
    lg("exec confirmed pid=%d\n", pid);
    int open_ = 1, ws = 0, lost_errno = 0;
#ifdef __linux__
    int pfd = getenv("SHIM_FAIL_PIDFD") ? (errno = EMFILE, -1) : (int)syscall(SYS_pidfd_open, pid, 0);
    if (pfd < 0) { lost_errno = errno; lg("pidfd_open: %s\n", strerror(errno)); kill(pid, SIGKILL); goto lost_unwatched; }
#else
    struct kevent ev[2];
    EV_SET(&ev[0], pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0);
    EV_SET(&ev[1], sp[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    int exited_early = 0;
    if (getenv("SHIM_FAIL_PIDFD")) { lost_errno = EMFILE; kill(pid, SIGKILL); goto lost_unwatched; }
    if (kevent(kq, &ev[0], 1, 0, 0, 0) < 0) { if (errno == ESRCH) exited_early = 1; else { lost_errno = errno; kill(pid, SIGKILL); goto lost_unwatched; } }
    kevent(kq, &ev[1], 1, 0, 0, 0);
#endif
    sigprocmask(SIG_SETMASK, &old, 0);
    lg("program pid=%d\n", pid);
    int failfd = getenv("SHIM_FAIL_LOOP") ? open(getenv("SHIM_FAIL_LOOP"), O_RDONLY | O_NONBLOCK | O_CLOEXEC) : -1;
    int null = open("/dev/null", O_RDWR); dup2(null, 0); dup2(null, 1); dup2(null, 2); close(null);
    gate("SHIM_HOLD");
#ifdef __APPLE__
    if (failfd >= 0) { struct kevent fe; EV_SET(&fe, failfd, EVFILT_READ, EV_ADD, 0, 0, 0); kevent(kq, &fe, 1, 0, 0, 0); }
#endif

    int armed = 1, owner_ok = 1, reaped = 0;
    while (!reaped) {
        int exited = 0, readable = 0, owner_gone = 0, fail = 0;
#ifdef __linux__
        struct pollfd p[5] = { { sp[0], POLLIN, 0 }, { pfd, POLLIN, 0 }, { open_ ? s : -1, POLLIN, 0 }, { owner_ok ? ofd : -1, POLLIN, 0 }, { failfd, POLLIN, 0 } };
        if (poll(p, 5, -1) < 0) { if (errno == EINTR) continue; lost_errno = errno; goto lost; }
        struct rec r;
        while (read(sp[0], &r, sizeof r) == sizeof r) {
            int user = r.code == SI_USER || r.code == SI_QUEUE;
            const char *why = !user ? "not process-sent" : !relay_from ? "parent not in my pgrp"
                            : r.pid != relay_from ? "not from parent" : !r.parent_alive ? "parent had exited" : 0;
            if (!why) lg("sig %d code %d from %d: RELAY rc=%d\n", r.signo, r.code, r.pid, (int)syscall(SYS_pidfd_send_signal, pfd, r.signo, NULL, 0));
            else lg("sig %d code %d from %d: DROP (%s)\n", r.signo, r.code, r.pid, why);
        }
        exited = p[1].revents != 0; readable = open_ && p[2].revents; owner_gone = owner_ok && p[3].revents; fail = failfd >= 0 && p[4].revents;
#else
        struct kevent out[5];
        int k = exited_early ? 0 : kevent(kq, 0, 0, out, 5, 0);
        if (k < 0) { if (errno == EINTR) continue; lost_errno = errno; goto lost; }
        exited = exited_early;
        for (int i = 0; i < k; i++) {
            if (out[i].filter == EVFILT_PROC && (pid_t)out[i].ident == pid) exited = 1;
            if (out[i].filter == EVFILT_PROC && (pid_t)out[i].ident == cosca) owner_gone = owner_ok;
            if (out[i].filter == EVFILT_READ && (int)out[i].ident == s) readable = open_;
            if (out[i].filter == EVFILT_READ && (int)out[i].ident == failfd) fail = 1;
        }
        struct rec r;
        while (read(sp[0], &r, sizeof r) == sizeof r) lg("sig %d code %d from %d: DROP (no relay on macOS)\n", r.signo, r.code, r.pid);
#endif
        if (fail) { lost_errno = EIO; lg("seam: supervision forced to fail\n"); goto lost; }
        int sig = 0;
        if (owner_gone) { owner_ok = 0; lg("owner exited (armed=%d)\n", armed); if (armed) sig = SIGKILL; }
        if (readable) {
            do n = read(s, &c, 1); while (n < 0 && errno == EINTR);
            if (n == 1 && c == 'P' && logfd >= 0) lg("pong\n");
            else if (n == 1 && c == 'K') sig = SIGKILL;
            else if (n == 1 && c == 'T') sig = SIGTERM;
            else if (n == 1 && c == 'D') { armed = 0; lg("disarmed\n"); }
            else if (n <= 0) {
                open_ = 0; lg("EOF (armed=%d)\n", armed); if (armed) sig = SIGKILL;
#ifdef __APPLE__
                struct kevent d; EV_SET(&d, s, EVFILT_READ, EV_DELETE, 0, 0, 0); kevent(kq, &d, 1, 0, 0, 0);
#endif
            }
        }
        if (sig) {
#ifdef __linux__
            int rc = (int)syscall(SYS_pidfd_send_signal, pfd, sig, NULL, 0);
#else
            int rc = kill(pid, sig);
#endif
            lg("control: signal %d rc=%d\n", sig, rc);
        }
        if (exited) {
#ifdef __linux__
            siginfo_t si; memset(&si, 0, sizeof si);
            if (waitid(P_PIDFD, (id_t)pfd, &si, WEXITED) != 0) { lost_errno = errno; goto lost; }
            ws = si.si_code == CLD_EXITED ? (si.si_status & 0xff) << 8 : (si.si_status | (si.si_code == CLD_DUMPED ? 0x80 : 0));
#else
            ws = reap(pid);
#endif
            reaped = 1; lg("reaped status %d\n", ws);
        }
    }
    if (open_) frame(s, 'S', ws);
    return WIFEXITED(ws) ? WEXITSTATUS(ws) : 128 + WTERMSIG(ws);
lost: /* the program ran (exec confirmed); supervision cannot continue: kill it, reap it, say so */
#ifdef __linux__
    syscall(SYS_pidfd_send_signal, pfd, SIGKILL, NULL, 0);
#else
    kill(pid, SIGKILL);
#endif
lost_unwatched:
    ws = reap(pid);
    lg("lost (%s): the program ran and was killed, status %d\n", strerror(lost_errno), ws);
    if (open_) frame(s, 'L', ws);
    fprintf(stderr, "cosca-elevation-shim: supervision failed (%s); the program was killed\n", strerror(lost_errno));
    return E_SPAWN;
}
