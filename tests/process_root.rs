//! `foreign_kill_surfaces_permission_denied`: a genuinely foreign, unprivileged caller's `kill`
//! on a genuinely foreign, unprivileged target must surface `EPERM` as `Err`, never swallow it
//! into `Ok`. Split out of `tests/process.rs` (which keeps the ordinary, non-root foreign-process
//! tests): the uid-switching/re-exec machinery and the `ROOT` label/precondition CI keys its root
//! step on are a separate concern, and living in their own binary lets a future root test reuse
//! `tests/common/`'s pieces without dragging this one in. Unix-only, like the test itself.

#[path = "common/mod.rs"]
mod common;

/// Set on this binary's own re-exec of itself, routing `fn main` (bottom of this file) to
/// [`foreign_kill_helper_main`] instead of the skuld harness — checked before skuld ever parses
/// argv, so the re-exec'd process never itself becomes a skuld test run.
#[cfg(unix)]
const ENV_TARGET_PID: &str = "COSCA_FOREIGN_KILL_TARGET_PID";

/// Blocks until either `listener` gets an incoming connection, or `dead_watch` (the target's own
/// stdout pipe, which it never writes to) reaches EOF or errors — meaning the target died before
/// connecting. A plain blocking `accept()` would hang forever in that case instead of failing.
#[cfg(unix)]
fn accept_or_die(listener: &std::net::TcpListener, dead_watch: &mut std::process::ChildStdout) -> std::net::TcpStream {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    let mut fds = [
        libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: dead_watch.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `fds` is a valid, correctly-sized array for the call's duration.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            panic!("poll while waiting for the target's control connection: {e}");
        }
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let mut buf = [0u8; 1];
            match dead_watch.read(&mut buf) {
                Ok(0) => panic!("the target died (its stdout EOF'd) before it connected"),
                Ok(n) => panic!("the target wrote {n} unexpected byte(s) to stdout before connecting"),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {} // spurious wakeup
                Err(e) => panic!("reading the target's death-watch pipe: {e}"),
            }
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let (sock, _) = listener.accept().expect("accept the target's control connection");
            return sock;
        }
    }
}

/// Regression test for `accept_or_die`'s reason to exist: a dead-before-connecting target must
/// panic, not hang the caller forever. Runs unprivileged — `true` needs no uid drop to exit
/// immediately, so this needs no root and no label.
#[cfg(unix)]
#[skuld::test]
fn accept_or_die_panics_loudly_when_the_target_dies_first() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut child = std::process::Command::new("true")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn a child that exits immediately");
    let mut dead_watch = child.stdout.take().expect("piped stdout");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        accept_or_die(&listener, &mut dead_watch)
    }));
    assert!(
        result.is_err(),
        "accept_or_die must panic, not hang, when the target dies before connecting"
    );
    let _ = child.wait();
}

/// See the module doc. Runs only as root (`common::preconditions::root`, label `ROOT`): the test
/// needs `CAP_SETUID`/`CAP_SETGID` to drop into two DIFFERENT unprivileged identities of its own
/// choosing, rather than depending on whatever uid CI happens to run tests as.
///
/// Both the target and the actual caller under test run as ordinary child PROCESSES of this
/// (root) one — never as this process itself — so root can always name and clean up the target
/// regardless of what the assertions below do.
///
/// The target crosses to the reader as a bare pid: this process holds its unreaped
/// `std::process::Child`, so the kernel cannot recycle the pid before the reader reports back.
#[cfg(unix)]
#[skuld::test(requires = [common::preconditions::root], labels = [common::ROOT])]
fn foreign_kill_surfaces_permission_denied() {
    use std::io::Read;
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    use common::KillOnDrop;

    // Guards direct invocation that bypasses skuld's `requires` (e.g. --run-ignored): fail
    // clearly, not with a later EPERM.
    // SAFETY: geteuid() takes no arguments and has no preconditions.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "foreign_kill_surfaces_permission_denied requires root"
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();

    // execve as another uid needs o+x on every ancestor directory, and $HOME (Linux) or the
    // per-user $TMPDIR (macOS) commonly lacks it. Copy both binaries into a 0755 dir directly
    // under /tmp, which both platforms keep traversable.
    let scratch = tempfile::Builder::new()
        .tempdir_in("/tmp")
        .expect("scratch directory for world-executable copies");
    std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the scratch directory world-traversable");
    let target_bin = common::world_executable_copy(std::path::Path::new(common::testbin()), scratch.path());

    // The target. `cosca::Command` has no uid()/gid() (a cross-platform builder — Windows has no
    // such concept), so this one spawn uses `std::process::Command` directly. It gets a piped
    // stdout it never writes to, purely as a death-watch: see `accept_or_die`.
    let target = std::process::Command::new(&target_bin)
        .args(["control-block", &addr, "R"])
        .uid(common::TARGET_UID)
        .gid(common::TARGET_UID)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the target under an unprivileged uid");
    // Guard immediately, before anything below gets a chance to panic and orphan it.
    let mut target = KillOnDrop::new(target);
    let target_pid = target.id();
    let mut dead_watch = target.take_stdout().expect("target was spawned with a piped stdout");

    let mut sock = accept_or_die(&listener, &mut dead_watch);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the target's ready tag");
    drop(dead_watch); // no longer needed

    // The actual caller under test: re-exec THIS SAME test binary (another world-executable
    // copy — see above) as READER_UID. Its result crosses back as an exit code ONLY (never
    // parsed text) — see `foreign_kill_helper_main`'s doc for the exact mapping.
    let exe = std::env::current_exe().expect("this test binary's own path");
    let reader_bin = common::world_executable_copy(&exe, scratch.path());
    let status = std::process::Command::new(&reader_bin)
        .uid(common::READER_UID)
        .gid(common::READER_UID)
        .env(ENV_TARGET_PID, target_pid.to_string())
        .status()
        .expect("re-exec this binary as the unprivileged reader");

    assert_eq!(
        status.code(),
        Some(0),
        "the unprivileged reader did not confirm EPERM (see its stderr, above, for which check \
         failed) — got exit code {:?}",
        status.code()
    );

    // Restores the "must not kill" half of the contract: a kill that both delivers the signal
    // AND returns Err(EPERM) would otherwise still pass the assertion above.
    assert_eq!(
        target.try_wait().expect("try_wait on our own child must not error"),
        None,
        "the denied kill must not have reached the target"
    );
}

/// [`foreign_kill_surfaces_permission_denied`]'s re-exec'd helper mode — dispatched from `fn
/// main` (bottom of this file) via `ENV_TARGET_PID`, before skuld ever sees argv. Reports its
/// verdict PURELY via the process exit code:
/// - `0`: `Process::kill` on the target surfaced `EPERM` as `Err` — the expected outcome.
/// - `10`: `kill` unexpectedly returned `Ok(())`.
/// - `11`: `kill` returned an `Err` other than `Io(EPERM)`.
/// - `12`: the target pid is `Gone` (no such process — a test bug, not an OS refusal).
/// - `13`: the target pid's identity is `Unknown` (the OS refused the query).
#[cfg(unix)]
fn foreign_kill_helper_main() -> i32 {
    // The caller's `Command::uid()/gid()` already runs setuid/setgid in its pre-exec child; a
    // failed drop would have made THAT spawn() return Err, which the caller `.expect()`s. So by
    // the time this process exists at all, the drop must have already succeeded.
    // SAFETY: geteuid() takes no arguments and has no preconditions.
    debug_assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "reached foreign_kill_helper_main still euid 0 — the caller's own Command::uid()/gid() \
         should have failed spawn() first if the drop to READER_UID failed"
    );
    let pid_str = std::env::var(ENV_TARGET_PID).expect("ENV_TARGET_PID set by the caller");
    let pid: cosca::identity::RawPid = pid_str.parse().expect("ENV_TARGET_PID is a valid pid");
    let target = match cosca::Process::from_pid(pid) {
        cosca::identity::Resolved::Found(p) => p,
        cosca::identity::Resolved::Gone => {
            eprintln!("foreign_kill_helper: target pid {pid} is gone");
            return 12;
        }
        cosca::identity::Resolved::Unknown => {
            eprintln!("foreign_kill_helper: target pid {pid}'s identity query was refused by the OS");
            return 13;
        }
    };
    match target.kill() {
        Err(cosca::error::Error::Io(e)) if e.raw_os_error() == Some(libc::EPERM) => 0,
        Ok(()) => {
            eprintln!("foreign_kill_helper: kill() unexpectedly succeeded");
            10
        }
        other => {
            eprintln!("foreign_kill_helper: kill() returned an unexpected result: {other:?}");
            11
        }
    }
}

fn main() {
    // Helper re-exec must bypass skuld (see ENV_TARGET_PID).
    #[cfg(unix)]
    if std::env::var_os(ENV_TARGET_PID).is_some() {
        std::process::exit(foreign_kill_helper_main());
    }
    skuld::run_all();
}
