/* Plan F prototype shim, revision 8 (THROWAWAY). Linux and macOS.
 *
 * argv: shim --cosca-elevation-shim=1 <dir> <cosca-pid> <cosca-identity> <cosca-euid> -- prog args...
 *       (=1x: every argument after the flag except "--" is hex)
 *
 * Preconditions, checked first: the shim process is single-threaded (114); Linux has pidfs (115, 6.9+).
 * Who is cosca (122 otherwise; nothing is written): Linux SO_PEERCRED pid/euid, SO_PEERPIDFD inode;
 *   macOS LOCAL_PEERTOKEN pid/euid/pidversion and p_uniqueid. SO_PEERPIDFD errors: ESRCH -> 122,
 *   ENOPROTOOPT/EOPNOTSUPP/EINVAL -> 115, anything else -> 116.
 * Then the shim says hello ('H'); cosca answers only a hello. The first byte must carry SCM_CREDENTIALS
 *   (sent explicitly by cosca with its euid) of cosca's pid and euid (Linux).
 * Frames shim -> cosca after 'H', exactly one, on every exit path:
 *   'S'+status  the program exited          'L'+status  it ran, supervision failed, killed and reaped
 *   'U'+0       it ran, its status is lost  'F'+errno   fork or exec failed: it never ran
 *   'R'+code    refused after hello (123 owner gone, 113 the child died before exec): it never ran
 * Exec: the shim never concludes "not started" from an absence. Only a positive report -- exec's errno on
 *   the CLOEXEC status pipe, or a failed fork -- gives 'F'. Every other end of the child, including a
 *   SIGKILL before exec, is reported as the possibly-started program's status. The status pipe is one more
 *   source in the event loop, so K, T and the owner watch act before exec too. Between restoring the mask
 *   and execve, catchable default-disposition signals hit a no-op handler (exec resets it).
 * Threads: Linux does not depend on them (atomic CLOEXEC; pidfd signals; a stolen reap is 'U'). macOS signals
 *   by pid while the child is unreaped, so it requires a single-threaded shim: the dedicated binary; 114
 *   otherwise.
 * Seams (prototype only, env): SHIM_LOG SHIM_GATE SHIM_GATE_BEFORE_ID SHIM_GATE_AFTER_A SHIM_HOLD
 *   SHIM_FAIL_FORK SHIM_FAIL_PIDFD SHIM_FAIL_LOOP SHIM_DIE_AFTER_FORK SHIM_CHILD_GATE SHIM_RLIMIT_NOFILE
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
#include <dirent.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
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

enum { E_THREADS = 114, E_NOPIDFS = 115, E_OWNERFD = 116, E_EXEC = 117, E_SPAWN = 118,
       E_NOPARENT = 119, E_INVOCATION = 120, E_SETID = 121, E_NOT_COSCA = 122, E_OWNER_GONE = 123,
       E_NO_ANSWER = 124, E_TOLD_N = 125, E_STATUS_LOST = 112 };

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
/* Before hello: nothing is written (the listener may not be cosca). After hello: an 'R' frame first. */
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
static int thread_count(void) {
#ifdef __linux__
    DIR *d = opendir("/proc/self/task"); if (!d) return -1;
    int n = 0; struct dirent *e; while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d); return n;
#else
    struct proc_taskinfo ti;
    if (proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &ti, sizeof ti) != (int)sizeof ti) return -1;
    return ti.pti_threadnum;
#endif
}
static int reaper_go[2] = { -1, -1 }, reaper_done[2] = { -1, -1 };
static void *idle(void *a) { /* seam: a host thread that reaps any child once there is one (wait()) */
    (void)a; char g; (void)!read(reaper_go[0], &g, 1);
    for (;;) { int st; if (waitpid(-1, &st, 0) > 0) (void)!write(reaper_done[1], "r", 1); else if (errno == ECHILD) pause(); }
    return 0; }
static void noop(int s) { (void)s; }

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
/* Drain the exec-status pipe without blocking: 1 = errno read, 0 = EOF, -1 = nothing yet. */
static int drain_exec(int fd, int *err) {
    int v; ssize_t n;
    do n = read(fd, &v, sizeof v); while (n < 0 && errno == EINTR);
    if (n == (ssize_t)sizeof v) { *err = v; return 1; }
    if (n == 0) return 0;
    return -1;
}
/* Reap our unreaped child. -1 when the status is lost (someone else reaped it): never fabricate one. */
static int reap(pid_t pid, int *ws) {
    int r; while ((r = (int)waitpid(pid, ws, 0)) < 0 && errno == EINTR) {}
    return r == pid ? 0 : -1;
}

int main(int argc, char **argv) {
    if (getenv("SHIM_SPAWN_THREAD")) { pthread_t t; (void)!pipe(reaper_go); (void)!pipe(reaper_done); pthread_create(&t, 0, idle, 0); }
#ifdef __APPLE__
    { int n = thread_count();
      if (n != 1) { char m[160]; snprintf(m, sizeof m, "the shim process has %d threads; macOS shim mode needs the dedicated single-threaded shim binary", n); return refuse(E_THREADS, m); } }
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
    { const char *b = strrchr(argv[7], '/'); b = b ? b + 1 : argv[7];
      if (strcmp(b, "cosca-preexec") == 0) return refuse(E_INVOCATION, "a program named cosca-preexec cannot be told apart from the pre-exec child"); }
    const char *dir = argv[2]; pid_t cosca = (pid_t)strtol(argv[3], 0, 10);
    const char *ident = argv[4]; uid_t ceuid = (uid_t)strtoul(argv[5], 0, 10);
    char **prog = &argv[7];
    if (getenv("SHIM_LOG")) logfd = open(getenv("SHIM_LOG"), O_WRONLY | O_APPEND | O_CLOEXEC);
    lg("shim pid=%d ppid=%d pgrp=%d\n", getpid(), getppid(), getpgrp());
    gate("SHIM_GATE");

#ifdef __linux__
    sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    fcntl(sock, F_SETFD, FD_CLOEXEC); /* macOS: the shim is single-threaded (114), nothing execs in between */
#endif
#ifdef __linux__
    { int one = 1; setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &one, sizeof one); }
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
    (void)!send(sock, "H", 1, NOSIG); hello_sent = 1;  /* from here every exit path sends a frame */
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
        lg("first byte from pid %d uid %d\n", mc.pid, mc.uid);
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

    sigset_t all, old; sigfillset(&all);
    sigprocmask(SIG_BLOCK, &all, &old); /* nothing runs a handler in the child before it is ready */
    struct sigaction saved[NREL];
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], 0, &saved[i]);
    int sp[2], ep[2];
#ifdef __linux__
    pid_t ppid0 = getppid(), relay_from = 0;
    ppfd = (int)syscall(SYS_pidfd_open, ppid0, 0);
    if (ppfd >= 0 && getppid() == ppid0 && getpgid(ppid0) == getpgrp()) relay_from = ppid0;
    else if (ppfd >= 0 && getppid() != ppid0) { close(ppfd); ppfd = -1; }
    if (pipe2(sp, O_NONBLOCK | O_CLOEXEC) != 0 || pipe2(ep, O_CLOEXEC) != 0) { int e = errno; frame('F', e); return E_SPAWN; }
#else
    if (pipe(sp) != 0 || pipe(ep) != 0) { int e = errno; frame('F', e); return E_SPAWN; }
    for (int i = 0; i < 2; i++) { fcntl(sp[i], F_SETFD, FD_CLOEXEC); fcntl(sp[i], F_SETFL, O_NONBLOCK); fcntl(ep[i], F_SETFD, FD_CLOEXEC); }
#endif
    sigw = sp[1];
    struct sigaction h; memset(&h, 0, sizeof h);
    h.sa_sigaction = on_sig; h.sa_flags = SA_SIGINFO | SA_RESTART; sigemptyset(&h.sa_mask);
    for (size_t i = 0; i < NREL; i++) sigaction(RELAYED[i], &h, 0);
    signal(SIGCHLD, SIG_DFL);
    pid_t me = getpid(), pid = getenv("SHIM_FAIL_FORK") ? (errno = EAGAIN, -1) : fork();
    if (pid < 0) { int e = errno; frame('F', e); lg("refused %d: could not fork (%s)\n", E_SPAWN, strerror(e));
                   fprintf(stderr, "cosca-elevation-shim: fork: %s; the program was not started (exit %d)\n", strerror(e), E_SPAWN); return E_SPAWN; }
    if (pid == 0) {
        close(ep[0]);
        /* A catchable signal that lands before exec must not kill the child: a no-op handler, which exec
         * resets to SIG_DFL. SIG_IGN dispositions the program inherited stay SIG_IGN. */
        struct sigaction nop; memset(&nop, 0, sizeof nop); nop.sa_handler = noop; nop.sa_flags = SA_RESTART; sigemptyset(&nop.sa_mask);
        for (int s = 1; s < NSIG; s++) {
            if (s == SIGKILL || s == SIGSTOP) continue;
            int relayed = -1;
            for (size_t i = 0; i < NREL; i++) if (RELAYED[i] == s) relayed = (int)i;
            struct sigaction cur;
            if (relayed >= 0) cur = saved[relayed]; else if (sigaction(s, 0, &cur) != 0) continue;
            if (cur.sa_handler == SIG_IGN) { if (relayed >= 0) sigaction(s, &cur, 0); continue; }
            sigaction(s, &nop, 0);
        }
        sigprocmask(SIG_SETMASK, &old, 0);
        if (getenv("SHIM_CHILD_GATE")) lg("child: waiting at gate (handlers ready)\n");
        gate("SHIM_CHILD_GATE");
#ifdef __linux__
        prctl(PR_SET_PDEATHSIG, SIGKILL);
#endif
        if (getppid() != me) { lg("child: the shim is gone before exec; exit 119\n"); _exit(E_NOPARENT); }
        if (strchr(prog[0], '/')) execv(prog[0], prog); else execvp(prog[0], prog); /* D11: resolved before the fork */
        int e = errno; (void)!write(ep[1], &e, sizeof e); _exit(127);
    }
    close(ep[1]);
    lg("forked child pid=%d\n", pid);
    if (reaper_go[1] >= 0) (void)!write(reaper_go[1], "g", 1); /* seam: the host thread may now reap */
    if (getenv("SHIM_DIE_AFTER_FORK")) { lg("seam: shim exits after fork\n"); _exit(E_SPAWN); }
    fcntl(ep[0], F_SETFL, O_NONBLOCK);
    int ws = 0, exec_errno = 0, ep_open = 1;
    int open_ = 1, lost_errno = 0;
#ifdef __linux__
    int pfd = getenv("SHIM_FAIL_PIDFD") ? (errno = EMFILE, -1) : (int)syscall(SYS_pidfd_open, pid, 0);
    if (pfd < 0) { lost_errno = errno; kill(pid, SIGKILL); goto lost_unwatched; }
#else
    struct kevent ev[2];
    EV_SET(&ev[0], pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0);
    EV_SET(&ev[1], sp[0], EVFILT_READ, EV_ADD, 0, 0, 0);
    int exited_early = 0;
    { struct kevent ee; EV_SET(&ee, ep[0], EVFILT_READ, EV_ADD, 0, 0, 0); kevent(kq, &ee, 1, 0, 0, 0); }
    if (getenv("SHIM_FAIL_PIDFD")) { lost_errno = EMFILE; kill(pid, SIGKILL); goto lost_unwatched; }
    if (kevent(kq, &ev[0], 1, 0, 0, 0) < 0) { if (errno == ESRCH) exited_early = 1; else { lost_errno = errno; kill(pid, SIGKILL); goto lost_unwatched; } }
    kevent(kq, &ev[1], 1, 0, 0, 0);
#endif
    sigprocmask(SIG_SETMASK, &old, 0);
    lg("program pid=%d (exec not yet known)\n", pid);
    if (getenv("SHIM_STEAL_REAP")) { int x; waitpid(pid, &x, 0); lg("seam: reaped elsewhere\n"); }
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
        struct pollfd p[6] = { { sp[0], POLLIN, 0 }, { pfd, POLLIN, 0 }, { open_ ? sock : -1, POLLIN, 0 }, { owner_ok ? ofd : -1, POLLIN, 0 }, { failfd, POLLIN, 0 }, { ep_open ? ep[0] : -1, POLLIN, 0 } };
        if (poll(p, 6, -1) < 0) { if (errno == EINTR) continue; lost_errno = errno; goto lost; }
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
            if (out[i].filter == EVFILT_READ && (int)out[i].ident == sock) readable = open_;
            if (out[i].filter == EVFILT_READ && (int)out[i].ident == failfd) fail = 1;
        }
        struct rec r;
        while (read(sp[0], &r, sizeof r) == sizeof r) lg("sig %d code %d from %d: DROP (no relay on macOS)\n", r.signo, r.code, r.pid);
#endif
        if (ep_open) { /* exec's errno, or EOF (exec'd or died: no conclusion is drawn from it) */
            int r2 = drain_exec(ep[0], &exec_errno);
            if (r2 >= 0) { ep_open = 0; close(ep[0]); lg(r2 ? "status pipe: exec failed (%s)\n" : "status pipe: EOF%s\n", r2 ? strerror(exec_errno) : "");
#ifdef __APPLE__
                struct kevent d; EV_SET(&d, ep[0], EVFILT_READ, EV_DELETE, 0, 0, 0); kevent(kq, &d, 1, 0, 0, 0);
#endif
            }
        }
        if (fail) { lost_errno = EIO; lg("seam: supervision forced to fail\n"); goto lost; }
        int sig = 0;
        if (owner_gone) { owner_ok = 0; lg("owner exited (armed=%d)\n", armed); if (armed) sig = SIGKILL; }
        if (readable) {
            do n = read(sock, &c, 1); while (n < 0 && errno == EINTR);
            if (n == 1 && c == 'P' && logfd >= 0) lg("pong\n");
            else if (n == 1 && c == 'K') sig = SIGKILL;
            else if (n == 1 && c == 'T') sig = SIGTERM;
            else if (n == 1 && c == 'D') { armed = 0; lg("disarmed\n"); }
            else if (n <= 0) {
                open_ = 0; lg("EOF (armed=%d)\n", armed); if (armed) sig = SIGKILL;
#ifdef __APPLE__
                struct kevent d; EV_SET(&d, sock, EVFILT_READ, EV_DELETE, 0, 0, 0); kevent(kq, &d, 1, 0, 0, 0);
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
            if (reaper_done[0] >= 0) { char r; (void)!read(reaper_done[0], &r, 1); } /* seam: the host thread reaps first */
#ifdef __linux__
            siginfo_t si; memset(&si, 0, sizeof si);
            if (waitid(P_PIDFD, (id_t)pfd, &si, WEXITED) != 0) { lg("waitid: %s\n", strerror(errno)); goto status_lost; }
            ws = si.si_code == CLD_EXITED ? (si.si_status & 0xff) << 8 : (si.si_status | (si.si_code == CLD_DUMPED ? 0x80 : 0));
#else
            if (reap(pid, &ws) != 0) goto status_lost;
#endif
            reaped = 1; lg("reaped status %d\n", ws);
        }
    }
    if (ep_open && drain_exec(ep[0], &exec_errno) == 1) ep_open = 0; /* the errno is written before _exit */
    if (exec_errno) { /* positive evidence: exec failed, the program never ran */
        if (open_) frame('F', exec_errno);
        lg("refused %d: the program could not be executed (%s)\n", E_EXEC, strerror(exec_errno));
        fprintf(stderr, "cosca-elevation-shim: exec %s: %s; the program was not started (exit %d)\n", prog[0], strerror(exec_errno), E_EXEC);
        return E_EXEC;
    }
    if (open_) frame('S', ws); /* the possibly-started program's status (only exec's errno proves otherwise) */
    return WIFEXITED(ws) ? WEXITSTATUS(ws) : 128 + WTERMSIG(ws);
lost:
#ifdef __linux__
    syscall(SYS_pidfd_send_signal, pfd, SIGKILL, NULL, 0);
#else
    kill(pid, SIGKILL);
#endif
lost_unwatched:
    if (reap(pid, &ws) != 0) goto status_lost;
    if (drain_exec(ep[0], &exec_errno) == 1) { /* reaped, so the errno (if any) is already in the pipe */
        if (open_) frame('F', exec_errno);
        lg("refused %d: the program could not be executed (%s)\n", E_EXEC, strerror(exec_errno));
        return E_EXEC;
    }
    lg("lost (%s): the possibly-started program was killed, status %d\n", strerror(lost_errno), ws);
    if (open_) frame('L', ws);
    fprintf(stderr, "cosca-elevation-shim: supervision failed (%s); the program was killed\n", strerror(lost_errno));
    return E_SPAWN;
status_lost: /* someone else reaped the program: its status is gone; never fabricate one */
    lg("status lost: the program ran; its status could not be collected\n");
    if (open_) frame('U', 0);
    return E_STATUS_LOST;
}
