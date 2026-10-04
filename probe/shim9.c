/* Plan F prototype shim, revision 9 (THROWAWAY). Linux and macOS.
 *
 * argv: shim --cosca-elevation-shim=1 <dir> <cosca-pid> <cosca-identity> <cosca-euid> -- prog args...
 *       (=1x: every argument after the flag except "--" is hex)
 *
 * Identity (unchanged since revision 7): Linux pidfs required (115); SO_PEERCRED pid/euid; SO_PEERPIDFD inode
 *   (ESRCH 122, ENOPROTOOPT/EOPNOTSUPP/EINVAL 115, else 116); then hello 'H'; the answer must carry
 *   SCM_CREDENTIALS of cosca's pid and euid. macOS: LOCAL_PEERTOKEN pid/euid/pidversion, p_uniqueid.
 * Frames after hello, exactly one: S status | L status (possibly started, supervision failed, killed and
 *   reaped) | U (possibly started, status reaped by someone else) | F n (positive evidence it never ran:
 *   n > 0 exec/fork errno, n < 0 it was terminated by signal -n before exec) | R code (refused).
 * The child: Linux clone3(CLONE_PIDFD) -- the handle exists from the child's first instant, so no step ever
 *   names the child by a bare pid; every signal is pidfd_send_signal, every reap waitid(P_PIDFD).
 *   macOS: fork, pid-based, sound only because the shim is single-threaded (114 otherwise, sent as R).
 * Before exec, in the child: HUP INT QUIT TERM (default disposition) are recorded by a handler; other
 *   catchable defaults run a no-op. Then all signals are blocked; a recorded termination aborts the exec and
 *   is reported on the status pipe (-signo, positive evidence); otherwise HUP INT QUIT TERM go back to
 *   SIG_DFL, the mask is restored (a pending one now terminates the child), and execve runs.
 * The supervision step is the pure decide() in shimloop.h; the loop's only blocking call is poll/kevent.
 * Seams (prototype only, env): SHIM_LOG SHIM_GATE SHIM_GATE_BEFORE_ID SHIM_GATE_AFTER_A SHIM_HOLD
 *   SHIM_HOLD_AFTER_FORK SHIM_FAIL_FORK SHIM_FAIL_LOOP SHIM_DIE_AFTER_FORK SHIM_CHILD_GATE SHIM_RLIMIT_NOFILE
 *   SHIM_FAKE_NO_PIDFS SHIM_SPAWN_THREAD SHIM_STEAL_REAP. Relay code unchanged (on hold). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include "shimloop.h"
#ifdef __linux__
#include <linux/sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif
#define PIDFS_MAGIC 0x50494446
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

enum { E_STATUS_LOST = 112, E_THREADS = 114, E_NOPIDFS = 115, E_OWNERFD = 116, E_NOT_EXECUTED = 117, E_SUPERVISION = 118,
       E_NOPARENT = 119, E_INVOCATION = 120, E_SETID = 121, E_NOT_COSCA = 122, E_OWNER_GONE = 123,
       E_NO_ANSWER = 124, E_TOLD_N = 125 };

static int logfd = -1, sock = -1, hello_sent = 0;
static void lg(const char *fmt, ...) {
    if (logfd < 0) return;
    char b[512]; va_list ap; va_start(ap, fmt); int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n > 0) (void)!write(logfd, b, (size_t)n < sizeof b ? (size_t)n : sizeof b - 1);
}
static void frame(char tag, int32_t v) {
    unsigned char f[5] = { (unsigned char)tag, v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff };
    (void)!send(sock, f, 5, NOSIG);
}
static int refuse(int code, const char *why) {
    fprintf(stderr, "cosca-elevation-shim: %s; the program was not started (exit %d)\n", why, code);
    lg("refused %d: %s\n", code, why);
    if (hello_sent) frame('R', code);
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
#ifdef __APPLE__
static int thread_count(void) {
    struct proc_taskinfo ti;
    if (proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &ti, sizeof ti) != (int)sizeof ti) return -1;
    return ti.pti_threadnum;
}
#endif
static int reaper_go[2] = { -1, -1 }, reaper_done[2] = { -1, -1 };
static void *host_thread(void *a) { /* seam: a host thread that reaps whatever child it can (wait()) */
    (void)a; char g; (void)!read(reaper_go[0], &g, 1);
    for (;;) { int st; pid_t r = waitpid(-1, &st, 0);
        if (r > 0) { lg("host thread: reaped pid %d\n", r); (void)!write(reaper_done[1], "r", 1); } else if (errno == ECHILD) pause(); }
    return 0;
}
static void noop(int s) { (void)s; }
static volatile sig_atomic_t term_seen = 0;
static void record_term(int s) { if (!term_seen) term_seen = s; }
static int is_term(int s) { return s == SIGHUP || s == SIGINT || s == SIGQUIT || s == SIGTERM; }

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
/* The status pipe without blocking: 1 a report (errno > 0, or -signo), 0 EOF, -1 nothing yet. */
static int drain_exec(int fd, int *rep) {
    int v; ssize_t n;
    do n = read(fd, &v, sizeof v); while (n < 0 && errno == EINTR);
    if (n == (ssize_t)sizeof v) { *rep = v; return 1; }
    if (n == 0) return 0;
    return -1;
}

/* --- the child's handle: signal and reap only through it --- */
struct child { pid_t pid; int pfd; };
static int child_signal(const struct child *ch, int sig) {
#ifdef __linux__
    return (int)syscall(SYS_pidfd_send_signal, ch->pfd, sig, NULL, 0);
#else
    return kill(ch->pid, sig); /* macOS: single-threaded shim, only this thread reaps (114) */
#endif
}
static int child_reap(const struct child *ch, int *ws) { /* -1: the status is gone (someone else reaped it) */
#ifdef __linux__
    siginfo_t si; memset(&si, 0, sizeof si); int r;
    while ((r = waitid(P_PIDFD, (id_t)ch->pfd, &si, WEXITED)) != 0 && errno == EINTR) {}
    if (r != 0 || si.si_pid == 0) return -1;
    *ws = si.si_code == CLD_EXITED ? (si.si_status & 0xff) << 8 : (si.si_status | (si.si_code == CLD_DUMPED ? 0x80 : 0));
    return 0;
#else
    int r; while ((r = (int)waitpid(ch->pid, ws, 0)) < 0 && errno == EINTR) {}
    return r == ch->pid ? 0 : -1;
#endif
}

int main(int argc, char **argv) {
    if (getenv("SHIM_SPAWN_THREAD")) { pthread_t t; (void)!pipe(reaper_go); (void)!pipe(reaper_done); pthread_create(&t, 0, host_thread, 0); }
#ifdef __APPLE__
    int nthreads = thread_count(); /* refused after A, so cosca gets the reason (R 114) */
#endif
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
    {
        int self = (int)syscall(SYS_pidfd_open, getpid(), 0); struct statfs sf;
        int pidfs = self >= 0 && fstatfs(self, &sf) == 0 && (unsigned long)sf.f_type == PIDFS_MAGIC && !getenv("SHIM_FAKE_NO_PIDFS");
        if (self >= 0) close(self);
        if (!pidfs) return refuse(E_NOPIDFS, "this kernel has no pidfs (Linux 6.9+ is required)");
    }
#endif
    const char *dir = argv[2]; pid_t cosca = (pid_t)strtol(argv[3], 0, 10);
    const char *ident = argv[4]; uid_t ceuid = (uid_t)strtoul(argv[5], 0, 10);
    char **prog = &argv[7];
    if (getenv("SHIM_LOG")) logfd = open(getenv("SHIM_LOG"), O_WRONLY | O_APPEND | O_CLOEXEC);
    lg("shim pid=%d ppid=%d pgrp=%d\n", getpid(), getppid(), getpgrp());
    gate("SHIM_GATE");
#ifdef __linux__
    sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    { int one = 1; setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &one, sizeof one); }
#else
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif
#ifdef SO_NOSIGPIPE
    { int one = 1; setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
      int v = 0; socklen_t vl = sizeof v; getsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &v, &vl); lg("nosigpipe=%d\n", v); }
#endif
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s/s", dir);
    if (connect(sock, (struct sockaddr *)&sa, sizeof sa) != 0) { lg("connect: %s\n", strerror(errno)); return refuse(E_NO_ANSWER, "could not reach cosca"); }
    gate("SHIM_GATE_BEFORE_ID");

    /* --- who is cosca (nothing written until this passes) --- */
#ifdef __linux__
    struct ucred cr; socklen_t cl = sizeof cr;
    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0 || cr.pid != cosca || cr.uid != ceuid)
        return refuse(E_NOT_COSCA, "the listener's pid or euid is not cosca's");
    if (getenv("SHIM_RLIMIT_NOFILE")) { struct rlimit rl; getrlimit(RLIMIT_NOFILE, &rl); rl.rlim_cur = (rlim_t)strtoul(getenv("SHIM_RLIMIT_NOFILE"), 0, 10); setrlimit(RLIMIT_NOFILE, &rl); }
    int ofd = -1; socklen_t ol = sizeof ofd;
    if (getsockopt(sock, SOL_SOCKET, SO_PEERPIDFD, &ofd, &ol) != 0) {
        int e = errno; lg("SO_PEERPIDFD: %s\n", strerror(e));
        if (e == ESRCH) return refuse(E_NOT_COSCA, "the listener's creator has exited");
        if (e == ENOPROTOOPT || e == EOPNOTSUPP || e == EINVAL) return refuse(E_NOPIDFS, "this kernel cannot name the listener's creator");
        return refuse(E_OWNERFD, "could not watch cosca's process");
    }
    if (getenv("SHIM_RLIMIT_NOFILE")) { struct rlimit rl; getrlimit(RLIMIT_NOFILE, &rl); rl.rlim_cur = rl.rlim_max; setrlimit(RLIMIT_NOFILE, &rl); }
    struct stat ost;
    if (fstat(ofd, &ost) != 0 || strtoull(ident, 0, 10) != (unsigned long long)ost.st_ino)
        return refuse(E_NOT_COSCA, "the listener's process identity does not match cosca's");
#else
    audit_token_t tok; socklen_t tl = sizeof tok;
    unsigned long long uniq = strtoull(ident, 0, 10); const char *colon = strchr(ident, ':');
    unsigned pver = colon ? (unsigned)strtoul(colon + 1, 0, 10) : 0;
    if (getsockopt(sock, SOL_LOCAL, LOCAL_PEERTOKEN, &tok, &tl) != 0 || (pid_t)tok.val[5] != cosca || tok.val[1] != ceuid || tok.val[7] != pver)
        return refuse(E_NOT_COSCA, "the listener's token is not cosca's");
    int kq = kqueue();
    if (kq < 0) return refuse(E_OWNERFD, "could not watch cosca's process");
    struct kevent oev; EV_SET(&oev, cosca, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0);
    if (kevent(kq, &oev, 1, 0, 0, 0) < 0) return errno == ESRCH ? refuse(E_NOT_COSCA, "cosca's process is gone") : refuse(E_OWNERFD, "could not watch cosca's process");
    struct proc_uniqidentifierinfo ui;
    if (proc_pidinfo(cosca, PROC_PIDUNIQIDENTIFIERINFO, 0, &ui, sizeof ui) != (int)sizeof ui || ui.p_uniqueid != uniq)
        return refuse(E_NOT_COSCA, "the listener's process identity does not match cosca's");
    struct kevent sev; EV_SET(&sev, sock, EVFILT_READ, EV_ADD, 0, 0, 0); kevent(kq, &sev, 1, 0, 0, 0);
#endif
    lg("owner verified pid=%d\n", cosca);
    (void)!send(sock, "H", 1, NOSIG); hello_sent = 1;
    lg("hello sent; awaiting the answer\n");
    for (;;) {
#ifdef __linux__
        struct pollfd p[2] = { { ofd, POLLIN, 0 }, { sock, POLLIN, 0 } };
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
    do n = recvmsg(sock, &mh, 0); while (n < 0 && errno == EINTR);
    if (n == 1) {
        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); struct ucred mc = { 0, (uid_t)-1, (gid_t)-1 };
        if (cm && cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_CREDENTIALS) memcpy(&mc, CMSG_DATA(cm), sizeof mc);
        if (mc.pid != cosca || mc.uid != ceuid) return refuse(E_NOT_COSCA, "the answer was not written by cosca");
    }
#else
    do n = read(sock, &c, 1); while (n < 0 && errno == EINTR);
#endif
    lg("first byte: %s\n", n == 1 ? (char[]){ c, 0 } : n == 0 ? "EOF" : strerror(errno));
    if (n == 1 && c == 'N') return refuse(E_TOLD_N, "cosca refused the start");
    if (!(n == 1 && c == 'A')) return refuse(E_NO_ANSWER, "no answer from cosca");
    gate("SHIM_GATE_AFTER_A");
#ifdef __linux__
    { struct pollfd p = { ofd, POLLIN, 0 }; if (poll(&p, 1, 0) > 0) return refuse(E_OWNER_GONE, "cosca exited before the start"); }
#else
    { struct kevent out[2]; struct timespec z = { 0, 0 }; int k = kevent(kq, 0, 0, out, 2, &z);
      for (int i = 0; i < k; i++) if (out[i].filter == EVFILT_PROC) return refuse(E_OWNER_GONE, "cosca exited before the start"); }
#endif
#ifdef __APPLE__
    /* After A, so cosca is Live and reads this R: the caller gets the reason (a refusal between H and A could
     * race cosca's answer, and a failed answer leaves cosca Refused with the frame unread). Nothing before
     * this point names the child by pid, so checking here is still before the only pid-based step. */
    if (nthreads != 1) {
        char m[200]; snprintf(m, sizeof m, "the shim process has %d threads; macOS shim mode needs the dedicated single-threaded shim binary", nthreads);
        return refuse(E_THREADS, m);
    }
#endif

    sigset_t all, old; sigfillset(&all);
    sigprocmask(SIG_BLOCK, &all, &old);
    struct sigaction saved[NREL];
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], 0, &saved[i]);
    int sp[2], ep[2];
#ifdef __linux__
    pid_t ppid0 = getppid(), relay_from = 0;
    ppfd = (int)syscall(SYS_pidfd_open, ppid0, 0);
    if (ppfd >= 0 && getppid() == ppid0 && getpgid(ppid0) == getpgrp()) relay_from = ppid0;
    else if (ppfd >= 0 && getppid() != ppid0) { close(ppfd); ppfd = -1; }
    if (pipe2(sp, O_NONBLOCK | O_CLOEXEC) != 0 || pipe2(ep, O_CLOEXEC) != 0) { int e = errno; frame('F', e); return E_NOT_EXECUTED; }
#else
    if (pipe(sp) != 0 || pipe(ep) != 0) { int e = errno; frame('F', e); return E_NOT_EXECUTED; }
    for (int i = 0; i < 2; i++) { fcntl(sp[i], F_SETFD, FD_CLOEXEC); fcntl(sp[i], F_SETFL, O_NONBLOCK); fcntl(ep[i], F_SETFD, FD_CLOEXEC); }
#endif
    sigw = sp[1];
    struct sigaction h; memset(&h, 0, sizeof h);
    h.sa_sigaction = on_sig; h.sa_flags = SA_SIGINFO | SA_RESTART; sigemptyset(&h.sa_mask);
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], &h, 0);
    signal(SIGCHLD, SIG_DFL);

    /* --- the child, with its handle from the first instant --- */
    struct child ch = { -1, -1 };
    pid_t me = getpid();
    if (getenv("SHIM_FAIL_FORK")) { errno = EAGAIN; ch.pid = -1; }
    else {
#ifdef __linux__
        struct clone_args ca; memset(&ca, 0, sizeof ca);
        ca.flags = CLONE_PIDFD; ca.pidfd = (uint64_t)(uintptr_t)&ch.pfd; ca.exit_signal = SIGCHLD;
        ch.pid = (pid_t)syscall(SYS_clone3, &ca, sizeof ca);
        if (ch.pid < 0 && errno == ENOSYS) { /* e.g. Docker's default seccomp: legacy clone, same atomic pidfd */
            lg("clone3: ENOSYS, using clone(CLONE_PIDFD)\n");
            ch.pid = (pid_t)syscall(SYS_clone, (unsigned long)(CLONE_PIDFD | SIGCHLD), 0UL, &ch.pfd, 0UL, 0UL);
        }
#else
        ch.pid = fork();
#endif
    }
    if (ch.pid < 0) { int e = errno; frame('F', e); lg("refused %d: could not create the child (%s)\n", E_NOT_EXECUTED, strerror(e));
                      fprintf(stderr, "cosca-elevation-shim: fork: %s; the program was not started (exit %d)\n", strerror(e), E_NOT_EXECUTED); return E_NOT_EXECUTED; }
    if (ch.pid == 0) {
        close(ep[0]);
        /* Termination requests before exec are recorded; other catchable defaults are absorbed. */
        struct sigaction rt; memset(&rt, 0, sizeof rt); rt.sa_handler = record_term; rt.sa_flags = SA_RESTART; sigfillset(&rt.sa_mask);
        struct sigaction nop; memset(&nop, 0, sizeof nop); nop.sa_handler = noop; nop.sa_flags = SA_RESTART; sigemptyset(&nop.sa_mask);
        for (int s = 1; s < NSIG; s++) {
            if (s == SIGKILL || s == SIGSTOP) continue;
            int relayed = -1;
            for (size_t i = 0; i < NREL; i++) if (RELAYED[i] == s) relayed = (int)i;
            struct sigaction cur;
            if (relayed >= 0) cur = saved[relayed]; else if (sigaction(s, 0, &cur) != 0) continue;
            if (cur.sa_handler == SIG_IGN) { if (relayed >= 0) sigaction(s, &cur, 0); continue; }
            sigaction(s, is_term(s) ? &rt : &nop, 0);
        }
        sigprocmask(SIG_SETMASK, &old, 0);
        if (getenv("SHIM_CHILD_GATE")) lg("child: waiting at gate (handlers ready)\n");
        gate("SHIM_CHILD_GATE");
#ifdef __linux__
        prctl(PR_SET_PDEATHSIG, SIGKILL);
#endif
        if (getppid() != me) { lg("child: the shim is gone before exec; exit 119\n"); _exit(E_NOPARENT); }
        sigprocmask(SIG_BLOCK, &all, 0);
        if (term_seen) { int v = -(int)term_seen; (void)!write(ep[1], &v, sizeof v); _exit(E_NOT_EXECUTED); }
        for (int s = 1; s < NSIG; s++) if (is_term(s)) { struct sigaction cur; sigaction(s, 0, &cur); if (cur.sa_handler == record_term) signal(s, SIG_DFL); }
        sigprocmask(SIG_SETMASK, &old, 0); /* a termination that arrived since the check now ends the child */
        if (strchr(prog[0], '/')) execv(prog[0], prog); else execvp(prog[0], prog);
        int e = errno; (void)!write(ep[1], &e, sizeof e); _exit(127);
    }
    close(ep[1]);
    lg("forked child pid=%d\n", ch.pid);
    if (reaper_go[1] >= 0) (void)!write(reaper_go[1], "g", 1);
    gate("SHIM_HOLD_AFTER_FORK");
    if (getenv("SHIM_DIE_AFTER_FORK")) { lg("seam: shim exits after fork\n"); _exit(E_SUPERVISION); }
    fcntl(ep[0], F_SETFL, O_NONBLOCK);
    int ws = 0, report = 0;
#ifdef __APPLE__
    struct kevent ev2[3];
    EV_SET(&ev2[0], ch.pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0);
    EV_SET(&ev2[1], sp[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    EV_SET(&ev2[2], ep[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    int exited_early = 0;
    if (kevent(kq, &ev2[0], 1, 0, 0, 0) < 0) { if (errno == ESRCH) exited_early = 1; else { kill(ch.pid, SIGKILL); goto lost_reap; } }
    kevent(kq, &ev2[1], 2, 0, 0, 0);
#endif
    sigprocmask(SIG_SETMASK, &old, 0);
    lg("program pid=%d (possibly started)\n", ch.pid);
    if (getenv("SHIM_STEAL_REAP")) { int x; waitpid(ch.pid, &x, 0); lg("seam: reaped elsewhere\n"); }
    int failfd = getenv("SHIM_FAIL_LOOP") ? open(getenv("SHIM_FAIL_LOOP"), O_RDONLY | O_NONBLOCK | O_CLOEXEC) : -1;
    int null = open("/dev/null", O_RDWR); dup2(null, 0); dup2(null, 1); dup2(null, 2); close(null);
    gate("SHIM_HOLD");
#ifdef __APPLE__
    if (failfd >= 0) { struct kevent fe; EV_SET(&fe, failfd, EVFILT_READ, EV_ADD, 0, 0, 0); kevent(kq, &fe, 1, 0, 0, 0); }
#endif
    struct loopstate st = { .armed = 1, .conn_open = 1, .owner_watched = 1, .exec_pending = 1 };
    for (;;) {
        struct events evs; memset(&evs, 0, sizeof evs);
        /* the loop's single blocking call */
#ifdef __linux__
        struct pollfd p[6] = { { sp[0], POLLIN, 0 }, { ch.pfd, POLLIN, 0 }, { st.conn_open ? sock : -1, POLLIN, 0 },
                               { st.owner_watched ? ofd : -1, POLLIN, 0 }, { failfd, POLLIN, 0 }, { st.exec_pending ? ep[0] : -1, POLLIN, 0 } };
        if (poll(p, 6, -1) < 0) { if (errno == EINTR) continue; goto lost; }
        struct rec r;
        while (read(sp[0], &r, sizeof r) == sizeof r) {
            int user = r.code == SI_USER || r.code == SI_QUEUE;
            const char *why = !user ? "not process-sent" : !relay_from ? "parent not in my pgrp"
                            : r.pid != relay_from ? "not from parent" : !r.parent_alive ? "parent had exited" : 0;
            if (!why) lg("sig %d code %d from %d: RELAY rc=%d\n", r.signo, r.code, r.pid, child_signal(&ch, r.signo));
            else lg("sig %d code %d from %d: DROP (%s)\n", r.signo, r.code, r.pid, why);
        }
        evs.child_exited = p[1].revents != 0; evs.owner_exited = st.owner_watched && p[3].revents; evs.forced_failure = failfd >= 0 && p[4].revents;
        int sock_ready = st.conn_open && p[2].revents, ep_ready = st.exec_pending && p[5].revents;
#else
        struct kevent out[6];
        int k = exited_early ? 0 : kevent(kq, 0, 0, out, 6, 0);
        if (k < 0) { if (errno == EINTR) continue; goto lost; }
        int sock_ready = 0, ep_ready = 0;
        evs.child_exited = exited_early;
        for (int i = 0; i < k; i++) {
            if (out[i].filter == EVFILT_PROC && (pid_t)out[i].ident == ch.pid) evs.child_exited = 1;
            if (out[i].filter == EVFILT_PROC && (pid_t)out[i].ident == cosca) evs.owner_exited = st.owner_watched;
            if (out[i].filter == EVFILT_READ && (int)out[i].ident == sock) sock_ready = st.conn_open;
            if (out[i].filter == EVFILT_READ && (int)out[i].ident == failfd) evs.forced_failure = 1;
            if (out[i].filter == EVFILT_READ && (int)out[i].ident == ep[0]) ep_ready = st.exec_pending;
        }
        struct rec r;
        while (read(sp[0], &r, sizeof r) == sizeof r) lg("sig %d code %d from %d: DROP (no relay on macOS)\n", r.signo, r.code, r.pid);
#endif
        if (ep_ready || (evs.child_exited && st.exec_pending)) {
            int d = drain_exec(ep[0], &report);
            if (d >= 0) { evs.exec_report = d ? 2 : 1; lg(d ? "status pipe: report %d\n" : "status pipe: EOF%.0d\n", report); }
        }
        if (sock_ready) {
            do n = read(sock, &c, 1); while (n < 0 && errno == EINTR);
            evs.control = n == 1 ? (unsigned char)c : (n <= 0 ? -1 : 0);
        }
        struct actions a;
        decide(&st, &evs, &a);
        if (a.lost) { lg("seam: supervision forced to fail\n"); goto lost; }
        if (a.pong && logfd >= 0) lg("pong\n");
        if (evs.control == 'D') lg("disarmed\n");
        if (evs.control == -1) {
            lg("EOF (armed=%d)\n", st.armed);
#ifdef __APPLE__
            struct kevent d; EV_SET(&d, sock, EVFILT_READ, EV_DELETE, 0, 0, 0); kevent(kq, &d, 1, 0, 0, 0);
#endif
        }
        if (evs.owner_exited) lg("owner exited (armed=%d)\n", st.armed);
        if (a.signal) lg("control: signal %d rc=%d\n", a.signal, child_signal(&ch, a.signal));
        if (a.reap) {
            if (reaper_done[0] >= 0) { char rr; (void)!read(reaper_done[0], &rr, 1); }
            if (child_reap(&ch, &ws) != 0) goto status_lost;
            lg("reaped status %d\n", ws);
            break;
        }
    }
    if (st.exec_pending && drain_exec(ep[0], &report) == 1) st.exec_pending = 0;
    if (report) { /* positive evidence: it never ran */
        if (st.conn_open) frame('F', report);
        lg("refused %d: the program was not executed (%d)\n", E_NOT_EXECUTED, report);
        return E_NOT_EXECUTED;
    }
    if (st.conn_open) frame('S', ws);
    return WIFEXITED(ws) ? WEXITSTATUS(ws) : 128 + WTERMSIG(ws);
lost:
    child_signal(&ch, SIGKILL);
#ifdef __APPLE__
lost_reap:
#endif
    if (child_reap(&ch, &ws) != 0) goto status_lost;
    if (report || (drain_exec(ep[0], &report) == 1 && report)) { if (st.conn_open) frame('F', report); return E_NOT_EXECUTED; }
    lg("lost: the possibly-started program was killed, status %d\n", ws);
    if (st.conn_open) frame('L', ws);
    fprintf(stderr, "cosca-elevation-shim: supervision failed; the program was killed\n");
    return E_SUPERVISION;
status_lost: /* someone else reaped the child: a drained report still proves it never ran */
    if (report || (drain_exec(ep[0], &report) == 1 && report)) { /* already drained, or drainable now */
        lg("status lost, but the child reported it never ran (%d)\n", report);
        if (st.conn_open) frame('F', report);
        return E_NOT_EXECUTED;
    }
    lg("status lost: the possibly-started program's status was collected by someone else\n");
    if (st.conn_open) frame('U', 0);
    return E_STATUS_LOST;
}
