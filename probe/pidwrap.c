/* pidwrap <target> <path> <argv...> (THROWAWAY, plan F revision 12): fork until a child gets pid <target>; that
 * child execs <path> <argv...>; every other child exits at once and is reaped. Prints "got <pid>", or "missed"
 * when the pid counter wrapped and then passed <target> without handing it to us (taken by someone else). */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    pid_t t = (pid_t)atoi(argv[1]), prev = 0; int wrapped = 0; long forks = 0;
    for (;;) {
        pid_t p = fork();
        if (p == 0) {
            if (getpid() == t) { /* the stranger keeps none of our stdio (the caller reads our stdout to EOF) */
                int n = open("/dev/null", O_RDWR); dup2(n, 0); dup2(n, 1); dup2(n, 2); execv(argv[2], argv + 3); _exit(127); }
            _exit(0);
        }
        if (p < 0) { perror("fork"); return 2; }
        if (p == t) { printf("got %d\n", (int)p); return 0; }
        waitpid(p, 0, 0);
        if (++forks % 10000 == 0) fprintf(stderr, "pidwrap: %ld forks, last pid %d\n", forks, (int)p);
        if (prev && p < prev) wrapped = 1;
        if (wrapped && p > t) { printf("missed\n"); return 1; }
        prev = p;
    }
}
