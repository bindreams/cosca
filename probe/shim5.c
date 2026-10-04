/* Plan F prototype shim, revision 5 (THROWAWAY). Linux and macOS.
 *
 * argv: shim --cosca-elevation-shim=1 <dir> <cosca-pid> <cosca-identity> -- prog args...
 *   <cosca-identity>: Linux the pidfs inode of cosca's process (fstat of a pidfd; kernel 6.9+),
 *   macOS its p_uniqueid (proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO). Neither is ever reused.
 *
 * Owner watch: after connect the shim takes an exit handle on the listener's pid (Linux pidfd, macOS
 * kqueue NOTE_EXIT), THEN checks that the process behind it has <cosca-identity>, so the handle is
 * proven to watch cosca. The listener lives in cosca's fresh private dir, so a cosca alive at that pid
 * bound it. Owner exit before the answer = never start; after A = like EOF (SIGKILL unless disarmed).
 *
 * Exit codes before the program starts (each with one stderr line on the front's stderr):
 *   120 unknown invocation/version   121 set-id context           122 listener is not cosca
 *   123 cosca exited before answering 124 no answer (connect failed, EOF/reset)   125 told N
 * After A: 118 the program could not be started (fork/pidfd failed; frame 'F'+errno sent);
 *   the program's child _exits 119 if its parent (the shim) died before exec (PDEATHSIG check).
 * Frames shim -> cosca: 'S'+i32 LE wait status, or 'F'+i32 LE errno. Nothing else.
 * Linux relay (R*, unchanged from revision 4); macOS records and swallows (owner question).
 * Prototype-only seams (env), absent from a shipped shim: SHIM_LOG, SHIM_GATE, SHIM_HOLD, SHIM_FAIL_FORK. */
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
#include <libproc.h>
#include <sys/event.h>
#include <sys/proc_info.h>
#include <sys/ucred.h>
#define NOSIG 0
/* Private flavour 17 (owner decision: private OS calls are allowed for exactness, CI-pinned). */
#define PROC_PIDUNIQIDENTIFIERINFO 17
struct proc_uniqidentifierinfo { uint8_t p_uuid[16]; uint64_t p_uniqueid; uint64_t p_puniqueid; int32_t p_idversion;
                                 uint32_t p_reserve2; uint64_t p_reserve3; uint64_t p_reserve4; };
#endif

enum { E_SPAWN = 118, E_NOPARENT = 119, E_INVOCATION = 120, E_SETID = 121, E_NOT_COSCA = 122,
       E_OWNER_GONE = 123, E_NO_ANSWER = 124, E_TOLD_N = 125 };

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

/* "--cosca-elevation-shim=1x": every argument after the flag except "--" is lowercase hex. osascript's
 * script text is not byte-transparent (measured: 0xff 0xfe arrived as Mac Roman re-encoded to UTF-8). */
static int unhex(char *a) {
    size_t n = strlen(a); if (n % 2) return -1;
    for (size_t i = 0; i < n; i += 2) {
        unsigned v; if (sscanf(a + i, "%2x", &v) != 1) return -1;
        a[i / 2] = (char)v;
    }
    a[n / 2] = 0; return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--cosca-elevation-shim=1x") == 0) {
        for (int i = 2; i < argc; i++)
            if (strcmp(argv[i], "--") != 0 && unhex(argv[i]) != 0) return refuse(E_INVOCATION, "malformed hex argument");
        argv[1] = "--cosca-elevation-shim=1";
    }
    if (argc < 8 || strcmp(argv[1], "--cosca-elevation-shim=1") != 0 || strcmp(argv[5], "--") != 0)
        return refuse(E_INVOCATION, "unknown invocation or protocol version");
#ifdef __APPLE__
    if (issetugid()) return refuse(E_SETID, "refusing a set-id context");
#else
    if (getuid() != geteuid() || getgid() != getegid()) return refuse(E_SETID, "refusing a set-id context");
#endif
    const char *dir = argv[2]; pid_t cosca = (pid_t)strtol(argv[3], 0, 10);
    unsigned long long ident = strtoull(argv[4], 0, 10);
    char **prog = &argv[6];
    if (getenv("SHIM_LOG")) logfd = open(getenv("SHIM_LOG"), O_WRONLY | O_APPEND | O_CLOEXEC);
    lg("shim pid=%d ppid=%d pgrp=%d\n", getpid(), getppid(), getpgrp());
    gate("SHIM_GATE");

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    fcntl(s, F_SETFD, FD_CLOEXEC); /* the shim is single-threaded: nothing can exec in between */
#ifdef SO_NOSIGPIPE
    { int one = 1; setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
      int v = 0; socklen_t vl = sizeof v; getsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &v, &vl); lg("nosigpipe=%d\n", v); }
#endif
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s/s", dir);
    char c = 0; ssize_t n;
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) != 0) {
        lg("connect: %s\n", strerror(errno));
        return refuse(E_NO_ANSWER, "could not reach cosca");
    }
    /* Owner watch, then identity: the handle is taken before the check, so a passing check proves it. */
    pid_t peer = -1;
#ifdef __linux__
    struct ucred cr; socklen_t cl = sizeof cr;
    if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0) peer = cr.pid;
    if (peer != cosca) return refuse(E_NOT_COSCA, "the listener is not the cosca process in argv");
    int ofd = (int)syscall(SYS_pidfd_open, peer, 0);
    struct stat ost;
    if (ofd < 0 || fstat(ofd, &ost) != 0 || (unsigned long long)ost.st_ino != ident)
        return refuse(E_NOT_COSCA, "the listener's process identity does not match cosca's");
#else
    pid_t pp; socklen_t pl = sizeof pp;
    if (getsockopt(s, SOL_LOCAL, LOCAL_PEERPID, &pp, &pl) == 0) peer = pp;
    if (peer != cosca) return refuse(E_NOT_COSCA, "the listener is not the cosca process in argv");
    int kq = kqueue();
    struct kevent oev; EV_SET(&oev, peer, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0);
    if (kevent(kq, &oev, 1, 0, 0, 0) < 0) return refuse(E_OWNER_GONE, "cosca exited before answering");
    struct proc_uniqidentifierinfo ui;
    if (proc_pidinfo(peer, PROC_PIDUNIQIDENTIFIERINFO, 0, &ui, sizeof ui) != (int)sizeof ui || ui.p_uniqueid != ident)
        return refuse(E_NOT_COSCA, "the listener's process identity does not match cosca's");
    struct kevent sev; EV_SET(&sev, s, EVFILT_READ, EV_ADD, 0, 0, 0); kevent(kq, &sev, 1, 0, 0, 0);
#endif
    lg("owner verified pid=%d identity=%llu\n", peer, ident);
    /* First byte, or the owner's exit, whichever comes first. */
    for (;;) {
#ifdef __linux__
        struct pollfd p[2] = { { s, POLLIN, 0 }, { ofd, POLLIN, 0 } };
        if (poll(p, 2, -1) < 0) { if (errno == EINTR) continue; return refuse(E_NO_ANSWER, "poll failed"); }
        if (p[0].revents) break;
        if (p[1].revents) return refuse(E_OWNER_GONE, "cosca exited before answering");
#else
        struct kevent out;
        if (kevent(kq, 0, 0, &out, 1, 0) < 0) { if (errno == EINTR) continue; return refuse(E_NO_ANSWER, "kevent failed"); }
        if (out.filter == EVFILT_READ) break;
        return refuse(E_OWNER_GONE, "cosca exited before answering");
#endif
    }
    do n = read(s, &c, 1); while (n < 0 && errno == EINTR);
    lg("first byte: %s\n", n == 1 ? (char[]){ c, 0 } : n == 0 ? "EOF" : strerror(errno));
    if (n == 1 && c == 'N') return refuse(E_TOLD_N, "cosca refused the start");
    if (!(n == 1 && c == 'A')) return refuse(E_NO_ANSWER, "no answer from cosca");

    sigset_t rel, old; sigemptyset(&rel);
    for (size_t i = 0; i < NREL; i++) sigaddset(&rel, RELAYED[i]);
    sigprocmask(SIG_BLOCK, &rel, &old);
    struct sigaction saved[NREL];
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], 0, &saved[i]);
    int sp[2];
#ifdef __linux__
    pid_t ppid0 = getppid(), relay_from = 0;
    ppfd = (int)syscall(SYS_pidfd_open, ppid0, 0);
    if (ppfd >= 0 && getppid() == ppid0 && getpgid(ppid0) == getpgrp()) relay_from = ppid0;
    else if (ppfd >= 0 && getppid() != ppid0) { close(ppfd); ppfd = -1; }
    lg("relay_from=%d\n", relay_from);
    if (pipe2(sp, O_NONBLOCK | O_CLOEXEC) != 0) { frame(s, 'F', errno); return refuse(E_SPAWN, "pipe failed"); }
#else
    if (pipe(sp) != 0) { frame(s, 'F', errno); return refuse(E_SPAWN, "pipe failed"); }
    for (int i = 0; i < 2; i++) { fcntl(sp[i], F_SETFD, FD_CLOEXEC); fcntl(sp[i], F_SETFL, O_NONBLOCK); }
#endif
    sigw = sp[1];
    struct sigaction h; memset(&h, 0, sizeof h);
    h.sa_sigaction = on_sig; h.sa_flags = SA_SIGINFO | SA_RESTART; sigemptyset(&h.sa_mask);
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], &h, 0);
    signal(SIGCHLD, SIG_DFL);
    pid_t me = getpid(), pid = getenv("SHIM_FAIL_FORK") ? (errno = EAGAIN, -1) : fork();
    if (pid < 0) { int e = errno; frame(s, 'F', e); return refuse(E_SPAWN, "could not start the program"); }
    if (pid == 0) {
#ifdef __linux__
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != me) _exit(E_NOPARENT); /* the shim died before exec: never run unsupervised */
#endif
        (void)me;
        for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], &saved[i], 0);
        sigprocmask(SIG_SETMASK, &old, 0);
        execvp(prog[0], prog);
        fprintf(stderr, "cosca-elevation-shim: exec %s: %s\n", prog[0], strerror(errno)); _exit(127);
    }
#ifdef __linux__
    int pfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pfd < 0) { int e = errno; kill(pid, SIGKILL); waitpid(pid, 0, 0); frame(s, 'F', e); return refuse(E_SPAWN, "pidfd_open failed"); }
#else
    struct kevent ev[2];
    EV_SET(&ev[0], pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0);
    EV_SET(&ev[1], sp[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    int exited_early = 0;
    if (kevent(kq, &ev[0], 1, 0, 0, 0) < 0) { if (errno == ESRCH) exited_early = 1; else { int e = errno; kill(pid, SIGKILL); waitpid(pid, 0, 0); frame(s, 'F', e); return refuse(E_SPAWN, "kevent failed"); } }
    kevent(kq, &ev[1], 1, 0, 0, 0);
#endif
    sigprocmask(SIG_SETMASK, &old, 0);
    lg("program pid=%d\n", pid);
    int null = open("/dev/null", O_RDWR); dup2(null, 0); dup2(null, 1); dup2(null, 2); close(null);
    gate("SHIM_HOLD");

    int armed = 1, open_ = 1, owner_ok = 1, reaped = 0, ws = 0;
    while (!reaped) {
        int exited = 0, readable = 0, owner_gone = 0;
#ifdef __linux__
        struct pollfd p[4] = { { sp[0], POLLIN, 0 }, { pfd, POLLIN, 0 }, { open_ ? s : -1, POLLIN, 0 }, { owner_ok ? ofd : -1, POLLIN, 0 } };
        if (poll(p, 4, -1) < 0) { if (errno == EINTR) continue; lg("poll: %s\n", strerror(errno)); goto lost; }
        struct rec r;
        while (read(sp[0], &r, sizeof r) == sizeof r) {
            int user = r.code == SI_USER || r.code == SI_QUEUE;
            const char *why = !user ? "not process-sent" : !relay_from ? "parent not in my pgrp"
                            : r.pid != relay_from ? "not from parent" : !r.parent_alive ? "parent had exited" : 0;
            if (!why) lg("sig %d code %d from %d: RELAY rc=%d\n", r.signo, r.code, r.pid, (int)syscall(SYS_pidfd_send_signal, pfd, r.signo, NULL, 0));
            else lg("sig %d code %d from %d: DROP (%s)\n", r.signo, r.code, r.pid, why);
        }
        exited = p[1].revents != 0; readable = open_ && p[2].revents; owner_gone = owner_ok && p[3].revents;
#else
        struct kevent out[4];
        int k = exited_early ? 0 : kevent(kq, 0, 0, out, 4, 0);
        if (k < 0) { if (errno == EINTR) continue; lg("kevent: %s\n", strerror(errno)); goto lost; }
        exited = exited_early;
        for (int i = 0; i < k; i++) {
            if (out[i].filter == EVFILT_PROC && (pid_t)out[i].ident == pid) exited = 1;
            if (out[i].filter == EVFILT_PROC && (pid_t)out[i].ident == peer) owner_gone = owner_ok;
            if (out[i].filter == EVFILT_READ && (int)out[i].ident == s) readable = open_;
        }
        struct rec r;
        while (read(sp[0], &r, sizeof r) == sizeof r) lg("sig %d code %d from %d: DROP (no relay on macOS)\n", r.signo, r.code, r.pid);
#endif
        int sig = 0;
        if (owner_gone) { owner_ok = 0; lg("owner exited (armed=%d)\n", armed); if (armed) sig = SIGKILL; }
        if (readable) {
            do n = read(s, &c, 1); while (n < 0 && errno == EINTR);
            if (n == 1 && c == 'P' && logfd >= 0) lg("pong\n"); /* seam: ordering probe for tests */
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
            if (waitid(P_PIDFD, (id_t)pfd, &si, WEXITED) != 0) goto lost;
            ws = si.si_code == CLD_EXITED ? (si.si_status & 0xff) << 8 : (si.si_status | (si.si_code == CLD_DUMPED ? 0x80 : 0));
#else
            if (waitpid(pid, &ws, 0) != pid) goto lost;
#endif
            reaped = 1; lg("reaped status %d\n", ws);
        }
    }
    if (open_) frame(s, 'S', ws);
    return WIFEXITED(ws) ? WEXITSTATUS(ws) : 128 + WTERMSIG(ws);
lost: /* the supervision loop cannot continue: never leave the program running unsupervised */
    {
        int e = errno;
#ifdef __linux__
        syscall(SYS_pidfd_send_signal, pfd, SIGKILL, NULL, 0);
#else
        kill(pid, SIGKILL);
#endif
        waitpid(pid, &ws, 0);
        if (open_) frame(s, 'F', e);
        return refuse(E_SPAWN, "supervision failed; the program was killed");
    }
}
