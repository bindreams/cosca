// macOS: does PROC_PIDTBSDINFO report pbi_start for a zombie child / a reaped pid?
#include <errno.h>
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <unistd.h>
static void q(pid_t p, const char *label) {
	struct proc_bsdinfo bi; memset(&bi, 0, sizeof bi); errno = 0;
	int r = proc_pidinfo(p, PROC_PIDTBSDINFO, 0, &bi, sizeof bi);
	int e = errno;
	printf("%-28s PROC_PIDTBSDINFO ret=%d (want %zu) errno=%d(%s) status=%u start=%llu.%06llu comm=%s\n", label, r,
	       sizeof bi, e, strerror(e), bi.pbi_status, (unsigned long long)bi.pbi_start_tvsec, (unsigned long long)bi.pbi_start_tvusec, bi.pbi_comm);
	struct proc_bsdshortinfo si; memset(&si, 0, sizeof si); errno = 0;
	r = proc_pidinfo(p, PROC_PIDT_SHORTBSDINFO, 0, &si, sizeof si); e = errno;
	printf("%-28s PROC_PIDT_SHORTBSDINFO ret=%d errno=%d(%s) status=%u\n", label, r, e, strerror(e), si.pbsi_status);
	errno = 0; r = kill(p, 0); e = errno;
	printf("%-28s kill(pid,0)=%d errno=%d(%s)\n", label, r, e, strerror(e));
	fflush(stdout);
}
int main(void) {
	int pp[2]; pipe(pp);
	pid_t c = fork();
	if (c == 0) { close(pp[1]); char b; read(pp[0], &b, 1); _exit(7); }
	close(pp[0]);
	printf("child pid=%d (SZOMB=%d)\n", c, SZOMB);
	q(c, "alive");
	close(pp[1]);
	siginfo_t si; if (waitid(P_PID, c, &si, WEXITED | WNOWAIT)) { perror("waitid WNOWAIT"); return 1; }
	printf("waitid WNOWAIT: child exited, status=%d (not reaped)\n", si.si_status);
	q(c, "zombie");
	int st; pid_t w = waitpid(c, &st, 0);
	printf("reaped %d\n", w);
	q(c, "reaped");
	return 0;
}
