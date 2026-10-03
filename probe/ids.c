#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    printf("%s: uid=%d euid=%d gid=%d egid=%d issetugid=%d pid=%d ppid=%d\n", argc > 1 ? argv[1] : "ids",
           (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid(), issetugid(), (int)getpid(), (int)getppid());
    return 0;
}
