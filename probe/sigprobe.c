/* sigprobe <ready-fifo>: reports the siginfo of the first SIGTERM it receives, plus its
 * parent/pgrp relationship (the inputs of plan F's relay rule). */
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static volatile sig_atomic_t got;
static siginfo_t info;
static void h(int s, siginfo_t *i, void *u) { (void)s; (void)u; info = *i; got = 1; }
int main(int argc, char **argv) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = h; sa.sa_flags = SA_SIGINFO; sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, 0);
    sigset_t blk, old; sigemptyset(&blk); sigaddset(&blk, SIGTERM); sigprocmask(SIG_BLOCK, &blk, &old);
    pid_t pp = getppid();
    printf("sigprobe: pid=%d ppid=%d pgrp=%d parent-pgrp=%d sid=%d euid=%d issetugid=%d\n", (int)getpid(), (int)pp,
           (int)getpgrp(), (int)getpgid(pp), (int)getsid(0), (int)geteuid(), issetugid());
    fflush(stdout);
    int fd = open(argv[1], O_WRONLY); dprintf(fd, "%d %d\n", (int)getpid(), (int)pp); close(fd);
    while (!got) sigsuspend(&old);
    printf("sigprobe: SIGTERM si_code=%d (SI_USER=%d) si_pid=%d; from-parent=%d parent-in-my-pgrp=%d\n",
           info.si_code, SI_USER, (int)info.si_pid, info.si_pid == pp, getpgid(pp) == getpgrp());
    return 0;
}
