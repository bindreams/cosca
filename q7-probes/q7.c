// Q7 probe: is a held /proc/<pid> dirfd a stable identity for our own child?
// Scratch code. Every scenario synchronises through pipes / wait, never time.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <grp.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

static const char *self_exe;

#define DIE(...) do { fprintf(stderr, "FATAL: " __VA_ARGS__); fprintf(stderr, " (errno=%s)\n", strerror(errno)); exit(99); } while (0)

// stat parsing ------------------------------------------------------------

struct st { int ok; int err; char state; char comm[64]; long ppid; unsigned long long start; };

static struct st parse_stat_fd(int fd) {
	struct st r = {0};
	char buf[4096];
	ssize_t n = read(fd, buf, sizeof buf - 1);
	if (n < 0) { r.err = errno; return r; }
	buf[n] = 0;
	char *lp = strchr(buf, '('), *rp = strrchr(buf, ')');
	if (!lp || !rp) { r.err = EINVAL; return r; }
	size_t cl = rp - lp - 1; if (cl > 63) cl = 63;
	memcpy(r.comm, lp + 1, cl); r.comm[cl] = 0;
	// fields after ')' : 3=state 4=ppid ... 22=starttime
	char *p = rp + 2; int field = 3;
	char *save; char *tok = strtok_r(p, " ", &save);
	while (tok) {
		if (field == 3) r.state = tok[0];
		if (field == 4) r.ppid = atol(tok);
		if (field == 22) { r.start = strtoull(tok, 0, 10); break; }
		tok = strtok_r(0, " ", &save); field++;
	}
	r.ok = 1; return r;
}

static void print_st(const char *label, struct st s) {
	if (s.ok) printf("  %-34s OK state=%c comm=%s ppid=%ld starttime=%llu\n", label, s.state, s.comm, s.ppid, s.start);
	else printf("  %-34s FAIL %s\n", label, strerrorname_np(s.err));
}

static struct st stat_via_dirfd(int d) {
	struct st r = {0};
	int fd = openat(d, "stat", O_RDONLY | O_CLOEXEC);
	if (fd < 0) { r.err = errno; return r; }
	r = parse_stat_fd(fd); close(fd); return r;
}

static struct st stat_via_path(pid_t pid) {
	char p[64]; snprintf(p, sizeof p, "/proc/%d/stat", pid);
	struct st r = {0};
	int fd = open(p, O_RDONLY | O_CLOEXEC);
	if (fd < 0) { r.err = errno; return r; }
	r = parse_stat_fd(fd); close(fd); return r;
}

static int open_dirfd(pid_t pid) {
	char p[64]; snprintf(p, sizeof p, "/proc/%d", pid);
	return open(p, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
}

// Every operation we might use at Drop time, through the held dirfd.
static void probe_all(int d, const char *label) {
	printf(" [%s]\n", label);
	print_st("openat(D,\"stat\")+read", stat_via_dirfd(d));
	struct stat sb;
	if (fstatat(d, "stat", &sb, 0) == 0) printf("  %-34s OK\n", "fstatat(D,\"stat\") (no new fd)");
	else printf("  %-34s FAIL %s\n", "fstatat(D,\"stat\") (no new fd)", strerrorname_np(errno));
	if (fstat(d, &sb) == 0) printf("  %-34s OK uid=%u ino=%lu\n", "fstat(D)", sb.st_uid, (unsigned long)sb.st_ino);
	else printf("  %-34s FAIL %s\n", "fstat(D)", strerrorname_np(errno));
	char exe[512]; ssize_t n = readlinkat(d, "exe", exe, sizeof exe - 1);
	if (n >= 0) { exe[n] = 0; printf("  %-34s OK %s\n", "readlinkat(D,\"exe\")", exe); }
	else printf("  %-34s FAIL %s\n", "readlinkat(D,\"exe\")", strerrorname_np(errno));
	char dents[4096]; lseek(d, 0, SEEK_SET);
	long g = syscall(SYS_getdents64, d, dents, sizeof dents);
	if (g >= 0) printf("  %-34s OK %ld bytes\n", "getdents64(D) (no new fd)", g);
	else printf("  %-34s FAIL %s\n", "getdents64(D) (no new fd)", strerrorname_np(errno));
	long ps = syscall(SYS_pidfd_send_signal, d, 0, NULL, 0);
	if (ps == 0) printf("  %-34s OK\n", "pidfd_send_signal(D,0)");
	else printf("  %-34s FAIL %s\n", "pidfd_send_signal(D,0)", strerrorname_np(errno));
	siginfo_t si; memset(&si, 0, sizeof si);
	long wi = syscall(SYS_waitid, 3 /*P_PIDFD*/, d, &si, WEXITED | WNOHANG | WNOWAIT, NULL);
	if (wi == 0) printf("  %-34s OK si_pid=%d\n", "waitid(P_PIDFD,D,WNOHANG|WNOWAIT)", si.si_pid);
	else printf("  %-34s FAIL %s\n", "waitid(P_PIDFD,D,WNOHANG|WNOWAIT)", strerrorname_np(errno));
	fflush(stdout);
}

// child helpers -----------------------------------------------------------

// Child that blocks reading `rfd` until the parent closes the write end or kills it.
static pid_t spawn_blocker(int *release_w) {
	int p[2]; if (pipe2(p, O_CLOEXEC)) DIE("pipe");
	pid_t c = fork();
	if (c < 0) DIE("fork");
	if (c == 0) { close(p[1]); char b; while (read(p[0], &b, 1) < 0 && errno == EINTR); _exit(0); }
	close(p[0]);
	if (release_w) *release_w = p[1]; else close(p[1]);
	return c;
}

static void wait_zombie(pid_t c) {
	siginfo_t si; if (waitid(P_PID, c, &si, WEXITED | WNOWAIT)) DIE("waitid WNOWAIT");
}

static void reap(pid_t c) { int st; if (waitpid(c, &st, 0) != c) DIE("waitpid"); }

// Make the next fork() in this pid namespace return `target`.
static int force_pid_ns_last_pid(pid_t target) {
	int fd = open("/proc/sys/kernel/ns_last_pid", O_WRONLY);
	if (fd < 0) return -1;
	char b[32]; int n = snprintf(b, sizeof b, "%d", target - 1);
	int r = write(fd, b, n); close(fd);
	return r == n ? 0 : -1;
}

// 1 / 2: reuse and zombie ------------------------------------------------

static int cmd_reuse(int natural) {
	if (natural) {
		// After wraparound the kernel allocates from RESERVED_PIDS (300) up, so C must sit above it.
		for (;;) { int r; pid_t x = spawn_blocker(&r); close(r); reap(x); if (x > 400) break; }
	}
	int rel; pid_t c = spawn_blocker(&rel);
	int d = open_dirfd(c); if (d < 0) DIE("open dirfd");
	printf("child C pid=%d\n", c);
	probe_all(d, "C alive");
	unsigned long long start_c = stat_via_dirfd(d).start;
	close(rel); wait_zombie(c);
	probe_all(d, "C zombie (exited, not reaped)");
	print_st("path /proc/C/stat (zombie)", stat_via_path(c));
	reap(c);
	probe_all(d, "C reaped, pid not reused");
	print_st("path /proc/C/stat (reaped)", stat_via_path(c));
	// force reuse
	int rel2; pid_t n;
	if (!natural) {
		if (force_pid_ns_last_pid(c)) DIE("ns_last_pid");
		n = spawn_blocker(&rel2);
		printf("reuse via ns_last_pid: new child N pid=%d (C was %d)\n", n, c);
	} else {
		unsigned long forks = 0;
		for (;;) {
			n = spawn_blocker(&rel2);
			if (n == c) break;
			close(rel2); reap(n); forks++;
		}
		printf("reuse via natural wraparound after %lu forks: N pid=%d\n", forks, n);
	}
	if (n != c) { printf("  REUSE NOT ACHIEVED\n"); return 1; }
	print_st("path /proc/<pid>/stat now (=N)", stat_via_path(n));
	probe_all(d, "C reaped, pid REUSED by N");
	struct st via = stat_via_dirfd(d);
	printf("  VERDICT: D resolves to N? %s (C start=%llu)\n", via.ok ? "YES (D reads a live process)" : "no", start_c);
	close(rel2); reap(n);
	return 0;
}

// 3a: hidepid -------------------------------------------------------------

// Orchestrator (root) forks P, P drops to uid, P spawns C, opens D; root remounts; P re-probes.
static int cmd_hidepid(const char *opt, int nondumpable, uid_t uid) {
	int ready[2], go[2]; if (pipe(ready) || pipe(go)) DIE("pipe");
	pid_t p = fork();
	if (p == 0) {
		close(ready[0]); close(go[1]);
		if (setgroups(0, NULL) || setresgid(uid, uid, uid) || setresuid(uid, uid, uid)) DIE("setresuid");
		// setresuid from root resets the mm dumpable flag; restore so nondumpable=0 means dumpable.
		if (prctl(PR_SET_DUMPABLE, 1)) DIE("dumpable1");
		int cp[2], cr[2]; if (pipe(cp) || pipe(cr)) DIE("pipe");
		pid_t c = fork();
		if (c == 0) {
			close(cp[1]);
			if (nondumpable && prctl(PR_SET_DUMPABLE, 0)) DIE("dumpable");
			write(cr[1], "d", 1);
			char b; read(cp[0], &b, 1); _exit(0);
		}
		close(cp[0]);
		{ char b; if (read(cr[0], &b, 1) != 1) DIE("child ready"); }
		int d = open_dirfd(c);
		printf("P uid=%d groups=%d child C pid=%d C dumpable=%d\n", getuid(), getgroups(0, NULL), c, !nondumpable);
		if (d < 0) DIE("open dirfd");
		probe_all(d, "before remount");
		write(ready[1], "r", 1);
		char b; read(go[0], &b, 1);
		probe_all(d, "after remount");
		print_st("path /proc/C/stat after remount", stat_via_path(c));
		close(cp[1]); reap(c); _exit(0);
	}
	close(ready[1]); close(go[0]);
	char b; if (read(ready[0], &b, 1) != 1) DIE("ready");
	if (mount("proc", "/proc", "proc", MS_REMOUNT, opt)) DIE("remount %s", opt);
	printf("root: remounted /proc with %s\n", opt); fflush(stdout);
	write(go[1], "g", 1);
	reap(p);
	mount("proc", "/proc", "proc", MS_REMOUNT, "hidepid=0");
	return 0;
}


// hidepid already in effect; C is dumpable when D is opened, then loses dumpability
// (prctl, or exec of a setuid-root binary). Caller runs as `uid`.
static int cmd_hidepid_late(const char *opt, const char *how, uid_t uid) {
	if (mount("proc", "/proc", "proc", MS_REMOUNT, opt)) DIE("remount %s", opt);
	printf("root: /proc already mounted with %s\n", opt);
	pid_t p = fork();
	if (p == 0) {
		if (setgroups(0, NULL) || setresgid(uid, uid, uid) || setresuid(uid, uid, uid)) DIE("setresuid");
		if (prctl(PR_SET_DUMPABLE, 1)) DIE("dumpable1");
		int gate[2], ready[2], blk[2]; if (pipe(gate) || pipe(ready) || pipe(blk)) DIE("pipe");
		pid_t c = fork();
		if (c == 0) {
			close(gate[1]); close(ready[0]); close(blk[1]);
			char b; read(gate[0], &b, 1);
			if (!strcmp(how, "prctl")) { prctl(PR_SET_DUMPABLE, 0); write(ready[1], "d", 1); read(blk[0], &b, 1); _exit(0); }
			char r[16], w[16]; snprintf(r, sizeof r, "%d", ready[1]); snprintf(w, sizeof w, "%d", blk[0]);
			execl(how, how, "sleeper", r, w, (char *)0); _exit(98);
		}
		close(gate[0]); close(ready[1]); close(blk[0]);
		int d = open_dirfd(c);
		printf("P uid=%d child C pid=%d; open(/proc/C) %s\n", getuid(), c, d >= 0 ? "OK" : strerrorname_np(errno));
		if (d < 0) _exit(1);
		probe_all(d, "C dumpable, same uid");
		write(gate[1], "g", 1);
		char b; if (read(ready[0], &b, 1) != 1) DIE("ready");
		probe_all(d, !strcmp(how, "prctl") ? "C did prctl(PR_SET_DUMPABLE,0)" : "C exec'd setuid-root binary");
		print_st("path /proc/C/stat", stat_via_path(c));
		close(blk[1]); wait_zombie(c);
		probe_all(d, "C zombie");
		reap(c);
		probe_all(d, "C reaped");
		_exit(0);
	}
	reap(p);
	return 0;
}

// 3b: unmount / overmount /proc ------------------------------------------

static int cmd_umount(int overmount) {
	int rel; pid_t c = spawn_blocker(&rel);
	int d = open_dirfd(c); if (d < 0) DIE("open dirfd");
	probe_all(d, "before");
	if (overmount) {
		if (mount("tmpfs", "/proc", "tmpfs", 0, "size=1m")) DIE("overmount");
		printf("overmounted /proc with tmpfs\n");
	} else {
		if (umount2("/proc", MNT_DETACH)) DIE("umount");
		printf("lazily unmounted /proc (MNT_DETACH)\n");
	}
	print_st("path /proc/C/stat", stat_via_path(c));
	probe_all(d, "after");
	close(rel); wait_zombie(c);
	probe_all(d, "after, C zombie");
	reap(c);
	probe_all(d, "after, C reaped");
	return 0;
}

// 3c: different pid namespace ---------------------------------------------

static int cmd_pidns(void) {
	int rel; pid_t c = spawn_blocker(&rel);
	int d = open_dirfd(c); if (d < 0) DIE("open dirfd");
	probe_all(d, "caller in original pidns");
	// Grandchild G lives in a NEW pid namespace, inherits D (clear CLOEXEC), probes from there.
	if (unshare(CLONE_NEWPID)) DIE("unshare pid");
	int fl = fcntl(d, F_GETFD); fcntl(d, F_SETFD, fl & ~FD_CLOEXEC);
	pid_t g = fork();
	if (g == 0) {
		printf("G: getpid()=%d (in new pidns; C is not visible here)\n", getpid());
		probe_all(d, "from G in child pidns (D inherited)");
		_exit(0);
	}
	reap(g);
	close(rel); wait_zombie(c); reap(c);
	return 0;
}

// Spawn-time hazard: /proc belongs to a different pid namespace than the caller.
static int cmd_procns_mismatch(pid_t target) {
	int rel; pid_t c;
	for (;;) { c = spawn_blocker(&rel); if (target <= 0 || c == target) break; close(rel); reap(c); }
	printf("fork() returned C pid=%d (our active pidns); getpid()=%d\n", c, getpid());
	char self[64]; ssize_t n = readlink("/proc/self", self, sizeof self - 1);
	if (n >= 0) { self[n] = 0; printf("readlink(/proc/self)=%s\n", self); } else printf("readlink(/proc/self) FAIL %s\n", strerrorname_np(errno));
	int d = open_dirfd(c);
	if (d < 0) printf("open(/proc/%d) FAIL %s\n", c, strerrorname_np(errno));
	else probe_all(d, "D = open(/proc/<C pid>) with foreign-ns /proc");
	close(rel); reap(c);
	return 0;
}

// 3d: EMFILE ---------------------------------------------------------------

static int cmd_emfile(void) {
	int rel; pid_t c = spawn_blocker(&rel);
	int d = open_dirfd(c); if (d < 0) DIE("open dirfd");
	struct rlimit rl = { 64, 64 }; if (setrlimit(RLIMIT_NOFILE, &rl)) DIE("rlimit");
	int filled = 0; while (dup(0) >= 0) filled++;
	printf("fd table full (filled %d, last errno=%s)\n", filled, strerrorname_np(errno));
	probe_all(d, "fd table full, C alive");
	close(rel);
	// close(rel) freed one slot; take it again
	dup(0);
	wait_zombie(c);
	probe_all(d, "fd table full, C zombie");
	reap(c);
	probe_all(d, "fd table full, C reaped");
	return 0;
}

// 4: threads / exec -------------------------------------------------------

static int leader_rfd, leader_wfd;
static pthread_t main_thr;
static void *leader_exit_worker(void *a) {
	(void)a;
	pthread_join(main_thr, NULL);  // futex on main's tid, cleared by kernel at main's exit
	write(leader_wfd, "L", 1);     // tell parent: leader has exited
	char b; read(leader_rfd, &b, 1);
	_exit(0);
}

static int cmd_leader_exit(void) {
	int toP[2], toC[2]; if (pipe(toP) || pipe(toC)) DIE("pipe");
	pid_t c = fork();
	if (c == 0) {
		close(toP[0]); close(toC[1]);
		leader_wfd = toP[1]; leader_rfd = toC[0]; main_thr = pthread_self();
		pthread_t t; pthread_create(&t, 0, leader_exit_worker, 0);
		pthread_exit(NULL);
	}
	close(toP[1]); close(toC[0]);
	int d = open_dirfd(c); if (d < 0) DIE("open dirfd");
	unsigned long long s0 = stat_via_dirfd(d).start;
	char b; if (read(toP[0], &b, 1) != 1) DIE("leader signal");
	// Leader's tid was cleared; wait (deterministic re-check, no timeout) for leader state Z.
	struct st s; do { s = stat_via_dirfd(d); if (!s.ok) break; if (s.state != 'Z') sched_yield(); } while (s.state != 'Z');
	probe_all(d, "leader exited (zombie leader), worker thread alive");
	struct st s1 = stat_via_dirfd(d);
	printf("  starttime before=%llu now=%llu same=%d\n", s0, s1.start, s0 == s1.start);
	close(toC[1]); wait_zombie(c);
	probe_all(d, "whole group exited, not reaped");
	reap(c);
	probe_all(d, "reaped");
	return 0;
}

// exec'd image: report ready on fd given in argv, then block on another fd.
static int cmd_sleeper(int readyfd, int blockfd) {
	write(readyfd, "E", 1);
	char b; read(blockfd, &b, 1); _exit(0);
}

static int exec_rfd, exec_wfd;
static void *exec_thread(void *a) {
	(void)a;
	char r[16], w[16]; snprintf(r, sizeof r, "%d", exec_wfd); snprintf(w, sizeof w, "%d", exec_rfd);
	printf("  (thread tid=%ld execing)\n", (long)syscall(SYS_gettid)); fflush(stdout);
	execl(self_exe, self_exe, "sleeper", r, w, (char *)0);
	_exit(98);
}

static int cmd_exec(int from_thread) {
	int toP[2], toC[2]; if (pipe(toP) || pipe(toC)) DIE("pipe");
	int gate[2]; if (pipe(gate)) DIE("pipe");
	pid_t c = fork();
	if (c == 0) {
		close(toP[0]); close(toC[1]); close(gate[1]);
		exec_wfd = toP[1]; exec_rfd = toC[0];
		char b; read(gate[0], &b, 1);  // wait until parent has D and baseline
		if (from_thread) {
			pthread_t t; pthread_create(&t, 0, exec_thread, 0);
			for (;;) pause();  // leader just waits; de_thread kills it
		}
		exec_thread(0);
	}
	close(toP[1]); close(toC[0]); close(gate[0]);
	int d = open_dirfd(c); if (d < 0) DIE("open dirfd");
	probe_all(d, "before exec");
	unsigned long long s0 = stat_via_dirfd(d).start;
	write(gate[1], "g", 1);
	char b; if (read(toP[0], &b, 1) != 1) DIE("exec ready");
	probe_all(d, from_thread ? "after exec by NON-LEADER thread" : "after exec");
	struct st s1 = stat_via_dirfd(d);
	printf("  starttime before=%llu after=%llu same=%d\n", s0, s1.start, s0 == s1.start);
	close(toC[1]); wait_zombie(c); reap(c);
	probe_all(d, "reaped");
	return 0;
}

static void *spin_block(void *a) { char b; read((int)(long)a, &b, 1); return 0; }
static int cmd_multithread(void) {
	int toC[2], ready[2]; if (pipe(toC) || pipe(ready)) DIE("pipe");
	pid_t c = fork();
	if (c == 0) {
		close(toC[1]);
		pthread_t t[3]; for (int i = 0; i < 3; i++) pthread_create(&t[i], 0, spin_block, (void *)(long)toC[0]);
		write(ready[1], "r", 1);
		char b; read(toC[0], &b, 1); _exit(0);
	}
	char b; read(ready[0], &b, 1);
	int d = open_dirfd(c); if (d < 0) DIE("open dirfd");
	probe_all(d, "C with 4 threads");
	close(toC[1]); wait_zombie(c);
	probe_all(d, "C zombie");
	reap(c);
	probe_all(d, "C reaped");
	return 0;
}


// SIGCHLD=SIG_IGN: kernel auto-reaps; show the check-then-waitpid(pid) window.
static int cmd_sigign(void) {
	signal(SIGCHLD, SIG_IGN);
	int rel; pid_t c = spawn_blocker(&rel);
	int d = open_dirfd(c); if (d < 0) DIE("open dirfd");
	probe_all(d, "SIG_IGN: C alive (Drop-time check would say: ours, unreaped)");
	close(rel);
	int st; pid_t w = waitpid(c, &st, 0);  // with SIG_IGN: blocks until C gone, then ECHILD
	printf("waitpid(C) under SIG_IGN -> %d %s\n", w, w < 0 ? strerrorname_np(errno) : "");
	probe_all(d, "SIG_IGN: C exited, auto-reaped by kernel");
	signal(SIGCHLD, SIG_DFL);
	if (force_pid_ns_last_pid(c)) DIE("ns_last_pid");
	int rel2; pid_t n = spawn_blocker(&rel2);
	printf("our own new child N pid=%d (C was %d)\n", n, c);
	close(rel2);
	w = waitpid(c, &st, 0);
	printf("waitpid(C's pid) reaped pid=%d -> that is N, a different child of ours\n", w);
	return 0;
}

// 6: seccomp ---------------------------------------------------------------

static int cmd_seccomp(void) {
	int rel; pid_t c = spawn_blocker(&rel);
	long pf = syscall(SYS_pidfd_open, c, 0);
	if (pf >= 0) printf("pidfd_open(C) OK fd=%ld\n", pf); else printf("pidfd_open(C) FAIL %s\n", strerrorname_np(errno));
	int d = open_dirfd(c);
	if (d >= 0) printf("open(/proc/C, O_DIRECTORY) OK fd=%d\n", d); else printf("open(/proc/C) FAIL %s\n", strerrorname_np(errno));
	if (d >= 0) probe_all(d, "under this seccomp profile");
	close(rel); reap(c);
	return 0;
}

int main(int argc, char **argv) {
	self_exe = "/proc/self/exe";
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2) { fprintf(stderr, "usage\n"); return 2; }
	const char *m = argv[1];
	if (!strcmp(m, "reuse")) return cmd_reuse(0);
	if (!strcmp(m, "reuse-natural")) return cmd_reuse(1);
	if (!strcmp(m, "hidepid")) return cmd_hidepid(argv[2], atoi(argv[3]), atoi(argv[4]));
	if (!strcmp(m, "hidepid-late")) return cmd_hidepid_late(argv[2], argv[3], atoi(argv[4]));
	if (!strcmp(m, "umount")) return cmd_umount(0);
	if (!strcmp(m, "overmount")) return cmd_umount(1);
	if (!strcmp(m, "pidns")) return cmd_pidns();
	if (!strcmp(m, "procns-mismatch")) return cmd_procns_mismatch(argc > 2 ? atoi(argv[2]) : 0);
	if (!strcmp(m, "emfile")) return cmd_emfile();
	if (!strcmp(m, "leader-exit")) return cmd_leader_exit();
	if (!strcmp(m, "exec")) return cmd_exec(0);
	if (!strcmp(m, "thread-exec")) return cmd_exec(1);
	if (!strcmp(m, "multithread")) return cmd_multithread();
	if (!strcmp(m, "sleeper")) return cmd_sleeper(atoi(argv[2]), atoi(argv[3]));
	if (!strcmp(m, "sigign")) return cmd_sigign();
	if (!strcmp(m, "seccomp")) return cmd_seccomp();
	fprintf(stderr, "unknown %s\n", m); return 2;
}
