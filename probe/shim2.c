/* Socket-protocol prototype of the elevated shim.
 * argv: shim2 <sockaddr> <cosca-pid> <armed:0|1> -- prog args...
 *   sockaddr "@name" = Linux abstract socket, else a filesystem path.
 * The shim connects, checks the LISTENER's pid is cosca's, and only then starts the payload.
 * Control bytes from cosca: 'K' kill, 'T' SIGTERM, 'D' disarm. EOF while armed = kill.
 * On payload exit it sends the raw wait status (decimal line) to cosca, then exits. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
#else
#include <sys/event.h>
#include <sys/ucred.h>
#endif
#define NOT_STARTED 125
static void die(const char *m) { fprintf(stderr, "shim: %s: %s\n", m, strerror(errno)); _exit(NOT_STARTED); }

int main(int argc, char **argv) {
    if (argc < 6 || strcmp(argv[4], "--") != 0) { fprintf(stderr, "usage\n"); return NOT_STARTED; }
    const char *addr = argv[1]; long cosca = strtol(argv[2], 0, 10); int armed = argv[3][0] == '1';
    int s = socket(AF_UNIX, SOCK_STREAM, 0); if (s < 0) die("socket");
    fcntl(s, F_SETFD, FD_CLOEXEC);
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
    socklen_t len;
    if (addr[0] == '@') { memcpy(sa.sun_path + 1, addr + 1, strlen(addr) - 1); len = offsetof(struct sockaddr_un, sun_path) + strlen(addr); }
    else { strncpy(sa.sun_path, addr, sizeof sa.sun_path - 1); len = sizeof sa; }
    if (connect(s, (struct sockaddr *)&sa, len) != 0) { fprintf(stderr, "shim: connect failed (%s): cosca is gone or refused the start; payload NOT started\n", strerror(errno)); return NOT_STARTED; }
    long peer = -1;
#ifdef __linux__
    struct ucred cr; socklen_t cl = sizeof cr;
    if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0) peer = cr.pid;
#else
    pid_t pp; socklen_t pl = sizeof pp;
    if (getsockopt(s, SOL_LOCAL, LOCAL_PEERPID, &pp, &pl) == 0) peer = pp;
#endif
    if (peer != cosca) { fprintf(stderr, "shim: listener pid %ld is not cosca's %ld; payload NOT started\n", peer, cosca); return NOT_STARTED; }
    fprintf(stderr, "shim: uid=%d euid=%d pid=%d ppid=%d armed=%d listener-pid-ok=%ld\n", getuid(), geteuid(), getpid(), getppid(), armed, peer);
    pid_t parent = getpid(), pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
#ifdef __linux__
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != parent) _exit(127);
#endif
        execvp(argv[5], &argv[5]);
        fprintf(stderr, "shim: exec %s: %s\n", argv[5], strerror(errno)); _exit(127);
    }
    int ws = 0, open_ = 1; char c; ssize_t n;
#ifdef __linux__
    int pfd = (int)syscall(SYS_pidfd_open, pid, 0); if (pfd < 0) die("pidfd_open");
#else
    int kq = kqueue(); if (kq < 0) die("kqueue");
    struct kevent ev[2];
    EV_SET(&ev[0], pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, 0);
    EV_SET(&ev[1], s, EVFILT_READ, EV_ADD, 0, 0, 0);
    if (kevent(kq, ev, 2, 0, 0, 0) < 0) die("kevent add");
#endif
    for (;;) {
        int exited = 0, readable = 0;
#ifdef __linux__
        struct pollfd p[2] = {{pfd, POLLIN, 0}, {s, POLLIN, 0}};
        if (poll(p, open_ ? 2 : 1, -1) < 0) { if (errno == EINTR) continue; die("poll"); }
        exited = p[0].revents != 0; readable = open_ && p[1].revents;
#else
        struct kevent out;
        if (kevent(kq, 0, 0, &out, 1, 0) < 0) { if (errno == EINTR) continue; die("kevent"); }
        exited = out.filter == EVFILT_PROC; readable = out.filter == EVFILT_READ;
#endif
        if (exited) break;
        if (!readable) continue;
        n = read(s, &c, 1);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        int sig = 0;
        if (n == 1 && c == 'D') { armed = 0; fprintf(stderr, "shim: disarmed\n"); continue; }
        if (n == 1 && c == 'K') sig = SIGKILL;
        else if (n == 1 && c == 'T') sig = SIGTERM;
        else if (n <= 0) {
            open_ = 0;
#ifndef __linux__
            EV_SET(&ev[1], s, EVFILT_READ, EV_DELETE, 0, 0, 0); kevent(kq, &ev[1], 1, 0, 0, 0);
#endif
            if (armed) sig = SIGKILL; else { fprintf(stderr, "shim: EOF while disarmed; payload left running\n"); continue; }
        }
#ifdef __linux__
        if (sig && syscall(SYS_pidfd_send_signal, pfd, sig, NULL, 0) != 0) perror("shim: pidfd_send_signal");
#else
        if (sig && kill(pid, sig) != 0) perror("shim: kill"); /* pid is our unreaped child */
#endif
        fprintf(stderr, "shim: sent signal %d to payload (%s)\n", sig, n <= 0 ? "EOF" : "message");
    }
#ifdef __linux__
    siginfo_t si; memset(&si, 0, sizeof si);
    if (waitid(P_PIDFD, pfd, &si, WEXITED) != 0) die("waitid");
    ws = si.si_code == CLD_EXITED ? (si.si_status << 8) : (si.si_status | (si.si_code == CLD_DUMPED ? 0x80 : 0));
#else
    if (waitpid(pid, &ws, 0) != pid) die("waitpid");
#endif
    signal(SIGPIPE, SIG_IGN);
    dprintf(s, "%d\n", ws);
    fprintf(stderr, "shim: payload wait status %d\n", ws);
    return WIFEXITED(ws) ? WEXITSTATUS(ws) : 128 + WTERMSIG(ws);
}
