/* Plan F prototype shim, revision 11 (THROWAWAY). Linux and macOS.
 *
 * argv: shim --cosca-elevation-shim=1 <dir> <cosca-pid> <cosca-identity> <cosca-euid> -- prog args...
 *       (=1x: every argument after the flag except "--" is hex)
 *
 * REVISION 12 (owner decisions 2026-10-04): same-uid code is trusted, and HostExecutable runs on macOS.
 * Identity, Linux (no pidfs needed; every call exists by 5.4): SO_PEERCRED pid/euid; the owner watch is
 *   pidfd_open(listener pid) opened BEFORE hello (ESRCH/EINVAL 123, else 116); the answer must carry
 *   SCM_CREDENTIALS of cosca's pid and euid. cosca writes it only after reading the hello, so cosca was alive
 *   after the pidfd was opened, and the pidfd names cosca. macOS: LOCAL_PEERTOKEN pid/euid/pidversion, p_uniqueid.
 * macOS child (any number of host threads): the child's first act reports its own p_uniqueid on a pipe; the
 *   shim attached NOTE_EXIT|NOTE_EXITSTATUS to the pid and then read flavor 17; equal ids confirm both. Signals
 *   go through proc_signal_with_audittoken keyed by that uniqueid; the status comes from NOTE_EXITSTATUS; the
 *   shim never reaps by pid on macOS. Not confirmable -> the child died first: 'U'.
 * Frames after hello, exactly one, chosen by the pure conclude() (shimloop.h): S status | L status | U |
 *   F kind<<16|n (kind: 1 fork errno, 2 exec errno, 3 setup errno, 4 terminated by signal n before exec) | R code.
 * The child: Linux clone3(CLONE_PIDFD), or clone(CLONE_PIDFD) on ENOSYS -- the handle exists from the child's
 *   first instant; every signal is pidfd_send_signal, every reap waitid(P_PIDFD). macOS: fork, see above.
 * In the child, raw system calls only until execve (no allocation, no stdio, no getenv, nothing that reads
 *   libc's cached thread id): a raw clone runs no atfork handlers. Synchronous fault signals stay SIG_DFL so a
 *   fault before exec kills the child; HUP INT QUIT TERM are recorded and reported (F kind 4); other catchable
 *   defaults run a no-op until exec resets them.
 * The supervision step is the pure decide(); the loop's only blocking call is poll/kevent, except the reap of a
 *   zombie only a tracer can see yet, and the reap after the shim's own SIGKILL.
 * Seams (prototype only, env): SHIM_LOG SHIM_GATE SHIM_GATE_BEFORE_ID SHIM_GATE_AFTER_A SHIM_HOLD
 *   SHIM_HOLD_AFTER_FORK SHIM_FAIL_FORK SHIM_FAIL_PIPE SHIM_FAIL_LOOP SHIM_DIE_AFTER_FORK SHIM_CHILD_GATE
 *   SHIM_CHILD_FAULT SHIM_FORCE_CLONE_FALLBACK SHIM_RLIMIT_NOFILE SHIM_SPAWN_THREAD SHIM_IDLE_THREADS SHIM_OBJC_INIT_THREAD SHIM_CHILD_DIE_BEFORE_ID
 *   SHIM_STEAL_REAP. Relay code unchanged (on hold; its pidfd_open of the shim's parent is the only one). */
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
extern char **environ;
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
int proc_signal_with_audittoken(audit_token_t *audittoken, int sig);
#ifndef NOTE_EXITSTATUS
#define NOTE_EXITSTATUS 0x04000000
#endif
static int uniq_of(pid_t pid, struct proc_uniqidentifierinfo *u) { return proc_pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO, 1, u, sizeof *u) == (int)sizeof *u; }
void start_objc_initialize_thread(void); /* hostobjc.m: a thread left inside a class's +initialize */
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
static void *idle_thread(void *a) { (void)a; for (;;) pause(); return 0; }
static void noop(int s) { (void)s; }
static volatile sig_atomic_t term_seen = 0;
static void record_term(int s) { if (!term_seen) term_seen = s; }
static int is_term(int s) { return s == SIGHUP || s == SIGINT || s == SIGQUIT || s == SIGTERM; }
static int is_fault(int s) { return s == SIGSEGV || s == SIGBUS || s == SIGILL || s == SIGFPE || s == SIGABRT || s == SIGTRAP || s == SIGSYS; }
/* Resolve the program before the child exists (D11): the child only calls execve. Returns 0 with an absolute
 * path in buf for a bare name, or the errno to report as F(exec) before any fork. Never returns a slash-less
 * path, so execve can never resolve a bare name against the cwd. Empty and relative PATH elements are skipped
 * (they name the cwd); directories and non-executables are skipped and remembered as EACCES, as execvp does. */
static int resolve(const char *name, const char *path, char *buf, size_t n) {
    if (strchr(name, '/')) { if (strlen(name) >= n) return ENAMETOOLONG; strcpy(buf, name); return 0; }
    if (!*name) return ENOENT;
    char defpath[1024];
    if (!path) { size_t k = confstr(_CS_PATH, defpath, sizeof defpath); path = k > 0 && k <= sizeof defpath ? defpath : "/usr/bin:/bin"; }
    int eacces = 0;
    for (const char *p = path; ; ) {
        const char *e = strchr(p, ':'); size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l > 0 && p[0] == '/' && l + 1 + strlen(name) < n) {
            snprintf(buf, n, "%.*s/%s", (int)l, p, name);
            struct stat st;
            if (stat(buf, &st) == 0) {
                if (!S_ISDIR(st.st_mode) && faccessat(AT_FDCWD, buf, X_OK, AT_EACCESS) == 0) return 0;
                eacces = 1;
            }
        }
        if (!e) return eacces ? EACCES : ENOENT;
        p = e + 1;
    }
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
/* The status pipe without blocking: 1 a report (errno > 0, or -signo), 0 EOF, -1 nothing yet. */
static int drain_exec(int fd, int *rep) {
    int v; ssize_t n;
    do n = read(fd, &v, sizeof v); while (n < 0 && errno == EINTR);
    if (n == (ssize_t)sizeof v) { *rep = v; return 1; }
    if (n == 0) return 0;
    return -1;
}

/* --- the child's handle: signal and reap only through it --- */
struct child { pid_t pid; int pfd; uint64_t uniq; int confirmed; int knote_fired, knote_ws; };
static int child_signal(const struct child *ch, int sig) {
#ifdef __linux__
    return (int)syscall(SYS_pidfd_send_signal, ch->pfd, sig, NULL, 0);
#else
    /* macOS: by token, keyed by the confirmed p_uniqueid (memory macos-exact-signal: ESRCH re-reads). */
    if (!ch->confirmed) return ESRCH;
    for (;;) {
        struct proc_uniqidentifierinfo u, u2;
        if (!uniq_of(ch->pid, &u) || u.p_uniqueid != ch->uniq) { lg("token: pid %d no longer names the child; nothing sent\n", ch->pid); return ESRCH; }
        audit_token_t t; memset(&t, 0, sizeof t); t.val[5] = (unsigned)ch->pid; t.val[7] = (unsigned)u.p_idversion;
        int r = proc_signal_with_audittoken(&t, sig);
        if (r != ESRCH) { lg("token: signal %d to pid %d (idversion %u) rc=%d\n", sig, ch->pid, (unsigned)u.p_idversion, r); return r; }
        if (!uniq_of(ch->pid, &u2) || u2.p_uniqueid != ch->uniq || u2.p_idversion == u.p_idversion) { lg("token: ESRCH and no exec since: the child has exited\n"); return ESRCH; }
        /* it exec'd between the read and the call: read again */
    }
#endif
}
static void lg(const char *fmt, ...);
/* 0 and *ws: the status; -1: the status is gone (someone else reaped it). `ready`: the handle fired. */
static int child_reap(const struct child *ch, int *ws, int ready) {
#ifdef __linux__
    siginfo_t si; memset(&si, 0, sizeof si); int r;
    while ((r = waitid(P_PIDFD, (id_t)ch->pfd, &si, WEXITED | (ready ? WNOHANG : 0))) != 0 && errno == EINTR) {}
    if (r != 0) return -1; /* ECHILD: collected by someone else */
    if (si.si_pid == 0) {  /* it has exited (the pidfd fired), but its zombie is visible only to a tracer */
        lg("exited, but only its tracer can see it yet: waiting for its status\n");
        memset(&si, 0, sizeof si);
        while ((r = waitid(P_PIDFD, (id_t)ch->pfd, &si, WEXITED)) != 0 && errno == EINTR) {}
        if (r != 0 || si.si_pid == 0) return -1;
    }
    *ws = si.si_code == CLD_EXITED ? (si.si_status & 0xff) << 8 : (si.si_status | (si.si_code == CLD_DUMPED ? 0x80 : 0));
    return 0;
#else
    (void)ready; /* never a reap by pid: the status is NOTE_EXITSTATUS's, the zombie is left to whoever reaps it */
    if (!ch->knote_fired) return -1;
    *ws = ch->knote_ws; return 0;
#endif
}

int main(int argc, char **argv) {
    if (getenv("SHIM_SPAWN_THREAD")) { pthread_t t; (void)!pipe(reaper_go); (void)!pipe(reaper_done); pthread_create(&t, 0, host_thread, 0); }
    if (getenv("SHIM_IDLE_THREADS")) for (int i = atoi(getenv("SHIM_IDLE_THREADS")); i > 0; i--) { pthread_t t; pthread_create(&t, 0, idle_thread, 0); }
#ifdef __APPLE__
    if (getenv("SHIM_OBJC_INIT_THREAD")) start_objc_initialize_thread();
#endif
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
#endif
    const char *dir = argv[2]; pid_t cosca = (pid_t)strtol(argv[3], 0, 10);
    const char *ident = argv[4]; uid_t ceuid = (uid_t)strtoul(argv[5], 0, 10);
    char **prog = &argv[7];
    if (getenv("SHIM_LOG")) logfd = open(getenv("SHIM_LOG"), O_WRONLY | O_APPEND | O_CLOEXEC);
    lg("shim pid=%d ppid=%d pgrp=%d\n", getpid(), getppid(), getpgrp());
#ifdef __APPLE__
    lg("threads at entry: %d\n", nthreads);
#endif
    { struct sigaction cur; sigaction(SIGPIPE, 0, &cur); lg("sigpipe at entry: %s\n", cur.sa_handler == SIG_IGN ? "ignored" : "default-or-caught"); }
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
    (void)ident; /* Linux: no identity beyond pid and euid (same-uid code is trusted) */
    /* The owner watch, opened BEFORE hello. Confirmed by the answer's SCM_CREDENTIALS below: cosca writes the
     * answer only after reading the hello, so it was alive after this open, and the pidfd names it. */
    int ofd = (int)syscall(SYS_pidfd_open, cosca, 0);
    if (ofd < 0) {
        int e = errno; lg("pidfd_open(owner): %s\n", strerror(e));
        if (e == ESRCH || e == EINVAL) return refuse(E_OWNER_GONE, "cosca's process is gone");
        return refuse(E_OWNERFD, "could not watch cosca's process");
    }
    if (getenv("SHIM_RLIMIT_NOFILE")) { struct rlimit rl; getrlimit(RLIMIT_NOFILE, &rl); rl.rlim_cur = rl.rlim_max; setrlimit(RLIMIT_NOFILE, &rl); }
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
        lg("owner pidfd confirmed by the answer's credentials\n");
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
    if ((getenv("SHIM_FAIL_PIPE") && (errno = EMFILE)) || pipe2(sp, O_NONBLOCK | O_CLOEXEC) != 0 || pipe2(ep, O_CLOEXEC) != 0) { int e = errno; frame('F', NX(NX_SETUP, e)); lg("refused 117: setup failed (%d)\n", e); return E_NOT_EXECUTED; }
#else
    int ip[2];
    if ((getenv("SHIM_FAIL_PIPE") && (errno = EMFILE)) || pipe(sp) != 0 || pipe(ep) != 0 || pipe(ip) != 0) { int e = errno; frame('F', NX(NX_SETUP, e)); lg("refused 117: setup failed (%d)\n", e); return E_NOT_EXECUTED; }
    for (int i = 0; i < 2; i++) { fcntl(sp[i], F_SETFD, FD_CLOEXEC); fcntl(sp[i], F_SETFL, O_NONBLOCK); fcntl(ep[i], F_SETFD, FD_CLOEXEC); fcntl(ip[i], F_SETFD, FD_CLOEXEC); }
#endif
    sigw = sp[1];
    struct sigaction h; memset(&h, 0, sizeof h);
    h.sa_sigaction = on_sig; h.sa_flags = SA_SIGINFO | SA_RESTART; sigemptyset(&h.sa_mask);
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], &h, 0);
    signal(SIGCHLD, SIG_DFL);

    /* --- the child, with its handle from the first instant --- */
    char exebuf[4096]; const char *exe = exebuf;
    { int re = resolve(prog[0], getenv("PATH"), exebuf, sizeof exebuf);
      if (re) { frame('F', NX(NX_EXEC, re)); lg("refused 117: no program to execute: %s (resolved before any fork)\n", strerror(re));
                fprintf(stderr, "cosca-elevation-shim: %s: %s; the program was not started (exit %d)\n", prog[0], strerror(re), E_NOT_EXECUTED);
                return E_NOT_EXECUTED; } }
    /* The ENOEXEC fallback's argv, as execvp, sudo and doas run a script without "#!": /bin/sh <path> args... */
    int pargc = 0; while (prog[pargc]) pargc++;
    char **sh_argv = calloc((size_t)pargc + 2, sizeof *sh_argv);
    if (!sh_argv) { frame('F', NX(NX_SETUP, ENOMEM)); return E_NOT_EXECUTED; }
    sh_argv[0] = "/bin/sh"; sh_argv[1] = exebuf; for (int i = 1; i < pargc; i++) sh_argv[i + 1] = prog[i];
    char **envp = environ;
    const char *child_gate = getenv("SHIM_CHILD_GATE"); int child_fault = getenv("SHIM_CHILD_FAULT") != 0;
    static const char msg_gate[] = "child: waiting at gate (handlers ready)\n", msg_119[] = "child: the shim is gone before exec; exit 119\n";
    int ws = 0, report = 0, reaped = 0, lost = 0;
    struct loopstate st = { .armed = 1, .conn_open = 1, .owner_watched = 1, .exec_pending = 1, .test_hooks = logfd >= 0 };
    struct child ch = { -1, -1, 0, 0, 0, 0 };
#ifdef __APPLE__
    int die_before_id = getenv("SHIM_CHILD_DIE_BEFORE_ID") != 0;
#endif
    pid_t me = getpid();
    if (getenv("SHIM_FAIL_FORK")) { errno = EAGAIN; ch.pid = -1; }
    else {
#ifdef __linux__
        struct clone_args ca; memset(&ca, 0, sizeof ca);
        ca.flags = CLONE_PIDFD; ca.pidfd = (uint64_t)(uintptr_t)&ch.pfd; ca.exit_signal = SIGCHLD;
        if (getenv("SHIM_FORCE_CLONE_FALLBACK")) { ch.pid = -1; errno = ENOSYS; }
        else ch.pid = (pid_t)syscall(SYS_clone3, &ca, sizeof ca);
        if (ch.pid < 0 && errno == ENOSYS) { /* e.g. Docker's default seccomp: legacy clone, same atomic pidfd */
            lg("clone3: ENOSYS, using clone(CLONE_PIDFD)\n");
            ch.pid = (pid_t)syscall(SYS_clone, (unsigned long)(CLONE_PIDFD | SIGCHLD), 0UL, &ch.pfd, 0UL, 0UL);
        }
#else
        ch.pid = fork();
#endif
    }
    if (ch.pid < 0) { int e = errno; frame('F', NX(NX_FORK, e)); lg("refused %d: could not create the child (%s)\n", E_NOT_EXECUTED, strerror(e));
                      fprintf(stderr, "cosca-elevation-shim: fork: %s; the program was not started (exit %d)\n", strerror(e), E_NOT_EXECUTED); return E_NOT_EXECUTED; }
    if (ch.pid == 0) {
        /* Raw system calls only from here to execve (see the header). */
#ifdef __APPLE__
        if (die_before_id) _exit(3); /* seam: the child ends before it reports its identity */
        { struct proc_uniqidentifierinfo me_u; if (uniq_of(getpid(), &me_u)) (void)!write(ip[1], &me_u.p_uniqueid, sizeof me_u.p_uniqueid); }
        close(ip[1]);
#endif
        close(ep[0]);
        struct sigaction rt; memset(&rt, 0, sizeof rt); rt.sa_handler = record_term; rt.sa_flags = SA_RESTART; sigfillset(&rt.sa_mask);
        struct sigaction nop; memset(&nop, 0, sizeof nop); nop.sa_handler = noop; nop.sa_flags = SA_RESTART; sigemptyset(&nop.sa_mask);
        struct sigaction dfl; memset(&dfl, 0, sizeof dfl); dfl.sa_handler = SIG_DFL; sigemptyset(&dfl.sa_mask);
        for (int s = 1; s < NSIG; s++) {
            if (s == SIGKILL || s == SIGSTOP) continue;
            if (is_fault(s)) { sigaction(s, &dfl, 0); continue; } /* a fault before exec kills; a no-op would refault forever */
            int relayed = -1;
            for (size_t i = 0; i < NREL; i++) if (RELAYED[i] == s) relayed = (int)i;
            struct sigaction cur;
            if (relayed >= 0) cur = saved[relayed]; else if (sigaction(s, 0, &cur) != 0) continue;
            if (cur.sa_handler == SIG_IGN && s != SIGPIPE) { if (relayed >= 0) sigaction(s, &cur, 0); continue; } /* SIGPIPE: SIG_DFL at exec, as std */
            sigaction(s, is_term(s) ? &rt : &nop, 0);
        }
        sigprocmask(SIG_SETMASK, &old, 0);
        if (child_gate) {
            if (logfd >= 0) (void)!write(logfd, msg_gate, sizeof msg_gate - 1);
            int g = open(child_gate, O_RDONLY | O_CLOEXEC); char gc; if (g >= 0) { (void)!read(g, &gc, 1); close(g); }
        }
        if (child_fault) { volatile uintptr_t bad = 8; *(volatile int *)bad = 0; } /* seam: a real fault before exec */
#ifdef __linux__
        prctl(PR_SET_PDEATHSIG, SIGKILL);
#endif
        if (getppid() != me) { if (logfd >= 0) (void)!write(logfd, msg_119, sizeof msg_119 - 1); _exit(E_NOPARENT); }
        sigprocmask(SIG_BLOCK, &all, 0);
        if (term_seen) { int v = NX(NX_TERM, term_seen); (void)!write(ep[1], &v, sizeof v); _exit(E_NOT_EXECUTED); }
        for (int s = 1; s < NSIG; s++) if (is_term(s)) { struct sigaction cur; sigaction(s, 0, &cur); if (cur.sa_handler == record_term) sigaction(s, &dfl, 0); }
        sigprocmask(SIG_SETMASK, &old, 0); /* a termination that arrived since the check now ends the child */
        execve(exe, prog, envp);
        if (errno == ENOEXEC) execve("/bin/sh", sh_argv, envp);
        int v = NX(NX_EXEC, errno); (void)!write(ep[1], &v, sizeof v); _exit(127);
    }
    close(ep[1]);
    fcntl(ep[0], F_SETFL, O_NONBLOCK);
    lg("forked child pid=%d\n", ch.pid);
#ifdef __APPLE__
    close(ip[1]);
    int attach_err;
    { struct kevent ka, kr; EV_SET(&ka, ch.pid, EVFILT_PROC, EV_ADD | EV_RECEIPT, NOTE_EXIT | NOTE_EXITSTATUS, 0, 0);
      attach_err = kevent(kq, &ka, 1, &kr, 1, 0) == 1 && (kr.flags & EV_ERROR) ? (int)kr.data : (errno ? errno : EIO);
    }
    struct proc_uniqidentifierinfo seen; int seen_ok = uniq_of(ch.pid, &seen);
    uint64_t reported = 0; ssize_t rn;
    do rn = read(ip[0], &reported, sizeof reported); while (rn < 0 && errno == EINTR);
    close(ip[0]);
    if (attach_err == 0 && seen_ok && rn == (ssize_t)sizeof reported && seen.p_uniqueid == reported) {
        ch.uniq = reported; ch.confirmed = 1; lg("identity confirmed: uniqueid=%llu\n", (unsigned long long)reported);
    } else {
        lg("identity unconfirmed (attach=%d, read=%d, reported=%zd bytes): the child ended before it was confirmed\n", attach_err, seen_ok, rn);
        goto status_lost;
    }
#endif
    if (reaper_go[1] >= 0) (void)!write(reaper_go[1], "g", 1);
    gate("SHIM_HOLD_AFTER_FORK");
    if (getenv("SHIM_DIE_AFTER_FORK")) { lg("seam: shim exits after fork\n"); _exit(E_SUPERVISION); }
#ifdef __APPLE__
    struct kevent ev2[2];
    EV_SET(&ev2[0], sp[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    EV_SET(&ev2[1], ep[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    int exited_early = 0;
    kevent(kq, ev2, 2, 0, 0, 0);
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
    for (;;) {
        struct events evs; memset(&evs, 0, sizeof evs); evs.control = CTL_NONE;
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
            if (out[i].filter == EVFILT_PROC && (pid_t)out[i].ident == ch.pid && (out[i].fflags & NOTE_EXIT)) {
                evs.child_exited = 1; ch.knote_fired = 1; ch.knote_ws = (int)out[i].data;
                lg("NOTE_EXITSTATUS: status %d (fflags 0x%x)\n", ch.knote_ws, (unsigned)out[i].fflags);
            }
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
            evs.control = n == 1 ? (unsigned char)c : -1;
        }
        struct actions a;
        decide(&st, &evs, &a);
        if (a.lost) { lg("seam: supervision forced to fail\n"); goto lost; }
        if (a.violation) lg("protocol violation: byte 0x%02x from cosca; the program is killed\n", evs.control & 0xff);
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
            if (child_reap(&ch, &ws, 1) != 0) goto status_lost;
            lg("reaped status %d\n", ws);
            break;
        }
    }
    reaped = 1;
    goto finish;
lost:
    child_signal(&ch, SIGKILL);
    lost = 1;
#ifdef __APPLE__
    while (!ch.knote_fired) { /* the knote is the only status source: wait for it alone */
        struct kevent o; int k = kevent(kq, 0, 0, &o, 1, 0);
        if (k < 0 && errno != EINTR) break;
        if (k == 1 && o.filter == EVFILT_PROC && (pid_t)o.ident == ch.pid && (o.fflags & NOTE_EXIT)) { ch.knote_fired = 1; ch.knote_ws = (int)o.data; }
    }
#endif
    reaped = child_reap(&ch, &ws, 0) == 0;
    goto finish;
status_lost: /* someone else reaped the child */
    reaped = 0;
finish:
    if (!report) drain_exec(ep[0], &report); /* a report already written is positive evidence, whatever the reap gave */
    {
        struct verdict v = conclude(report, reaped, ws, lost);
        if (v.tag == 'F') lg("refused 117: the program was not executed (kind %d, %d)\n", report >> 16, report & 0xffff);
        else if (v.tag == 'U') lg("status lost: the possibly-started program's status was collected by someone else\n");
        else if (v.tag == 'L') lg("lost: the possibly-started program was killed, status %d\n", ws);
        if (st.conn_open) frame(v.tag, v.value);
        return v.code;
    }
}
