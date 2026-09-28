//! Test isolation for a test that mutates process-wide state (closes fd 0/1/2, lowers
//! `RLIMIT_NOFILE`): the mutation and its restore must run alone in a process, or a concurrently
//! running, unrelated test thread can be corrupted by it. This is ONE file, included by both of
//! this crate's separate compilation units:
//! - `tests/common/mod.rs` (`mod isolation;`), for every integration test binary.
//! - `src/lib.rs` (`#[cfg(test)] #[path = "../tests/common/isolation.rs"] mod test_isolation;`),
//!   for the lib's own `#[cfg(test)]` unit tests (e.g. `child::spawn::fd_map::fd_map_tests`).
//!
//! `crate::` resolves differently at each mount point (the lib itself, vs. whichever integration
//! test binary this is compiled into), so every reference to this crate's own public API below
//! goes through the crate name `cosca` — made self-referential for the lib's own mount point by
//! `extern crate self as cosca;` in `src/lib.rs` — which resolves identically at both.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The re-exec args [`alone`] passes after the test name; [`alone_marker_matches`] demands this
/// process's own argv match this shape before trusting a `COSCA_TEST_ALONE` env var.
pub const ALONE_ARGS: [&str; 4] = ["--exact", "--include-ignored", "--nocapture", "--test-threads=1"];

/// True only if `value` is `Some` AND this process's own argv (skipping argv[0], the binary path)
/// is exactly `[value, ALONE_ARGS...]` — proof that libtest was invoked to run exactly one named
/// test, not merely that some env var happens to be set.
///
/// `COSCA_TEST_ALONE` alone is not proof: it is inherited by children and can leak from a shell or
/// outer re-exec into an ordinary many-threads run. Argv is set by whoever invoked this process,
/// so a genuine isolated child (invoked by [`alone`]) is the only one that matches.
fn alone_marker_matches(value: Option<&str>, argv: &[String]) -> bool {
    let Some(value) = value else { return false };
    argv.len() == ALONE_ARGS.len() + 1
        && argv[0] == value
        && argv[1..].iter().map(String::as_str).eq(ALONE_ARGS.iter().copied())
}

/// Run the test `name` (its full path, as libtest reports it) alone, in a fresh copy of this test
/// binary, and assert it passed. `true` in the copy, which must then run the test's real body;
/// `false` in the original caller, which must return immediately.
///
/// Spawns under `cosca::test_spawn_lock()` (see `cosca::test_spawn_lock`'s own doc), waits via
/// [`wait_bounded`] outside the lock: a hung re-exec must fail this call, not the whole suite.
/// Non-reentrant: call `alone` first, holding nothing else.
pub fn alone(name: &str) -> bool {
    const ALONE: &str = "COSCA_TEST_ALONE";
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if alone_marker_matches(Some(name), &argv) {
        return true;
    }
    let child = {
        let _guard = cosca::test_spawn_lock();
        std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args(std::iter::once(name).chain(ALONE_ARGS))
            .env(ALONE, name)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the test alone")
    };
    let out = wait_bounded(child, PROBE_TIMEOUT);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    false
}

/// Require that this test is running alone in its own process, via [`alone`], before any caller
/// touches a process-wide resource. Fails loudly and immediately, before touching anything.
pub fn require_process_per_test(what: &str) {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let alone = alone_marker_matches(std::env::var("COSCA_TEST_ALONE").ok().as_deref(), &argv);
    assert!(alone, "{what}; call this from inside alone()");
}

/// Real fd 2 to `dup2` back before the panic hook's chained write runs, if a [`RestoreStdio`] is
/// currently holding fd 2 closed — `None` otherwise. Read only by the ONE process-wide hook
/// [`ensure_stderr_panic_hook`] installs; written only by [`RestoreStdio::close`] (sets) and its
/// `Drop` (clears). Only one `RestoreStdio` may hold fd 2 at a time — `close`'s own `assert!`
/// enforces that before this slot is ever touched — so a set always starts from `None` and a
/// clear always clears this guard's own entry.
///
/// `Drop` only ever clears this slot and never calls [`std::panic::set_hook`]: calling it while
/// unwinding panics, and a panic during unwind aborts the process (`SIGABRT`). The hook is
/// installed once, process-wide, and reads this slot at panic time instead.
static SAVED_STDERR: std::sync::Mutex<Option<libc::c_int>> = std::sync::Mutex::new(None);

/// Lock [`SAVED_STDERR`], recovering from poison rather than panicking: read from inside a panic
/// hook and written from `Drop` during unwind, both places where panicking again must never happen.
fn saved_stderr() -> std::sync::MutexGuard<'static, Option<libc::c_int>> {
    SAVED_STDERR.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install the ONE, process-wide panic hook that restores real fd 2 from [`SAVED_STDERR`] (if
/// occupied) before chaining to whatever hook was previously installed — so a panic while a
/// [`RestoreStdio`] holds fd 2 closed still reaches somewhere readable. Idempotent via `Once`.
fn ensure_stderr_panic_hook() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Some(real_stderr) = *saved_stderr() {
                // SAFETY: `real_stderr` is a live dup of the original fd 2, owned by whichever
                // `RestoreStdio` currently occupies `SAVED_STDERR` — its `Drop` clears the slot
                // before that dup closes, so a `Some` read here is always still valid.
                unsafe { libc::dup2(real_stderr, 2) };
            }
            previous(info);
        }));
    });
}

/// Duplicate each of `fds` aside and close it, restoring all of them on drop (even if the test
/// panics), so the CURRENT process's own low-numbered descriptors are free for a test to reuse.
///
/// `close` asserts [`require_process_per_test`] before touching anything, and — for fd 2 — that no
/// other `RestoreStdio` already holds it: two guards on fd 2 at once would each think they own
/// [`SAVED_STDERR`]'s slot, corrupting whichever one the panic hook restores from. This check runs
/// before anything is closed and before the slot is touched, so a violation leaves the first
/// guard's registration intact and its own panic message reaching real stderr.
pub struct RestoreStdio {
    saved: Vec<(libc::c_int, OwnedFd)>,
}

impl RestoreStdio {
    pub fn close(fds: &[libc::c_int]) -> RestoreStdio {
        let listed = fds.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(", ");
        require_process_per_test(&format!(
            "closes process-wide fd{} {listed}",
            if fds.len() == 1 { "" } else { "s" }
        ));
        // A repeated fd (e.g. `&[2, 2]`) would dup an already-closed fd on the second pass.
        debug_assert!(
            {
                let mut sorted: Vec<libc::c_int> = fds.to_vec();
                sorted.sort_unstable();
                sorted.dedup();
                sorted.len() == fds.len()
            },
            "RestoreStdio::close: fds must be distinct, got {fds:?}"
        );
        // Built incrementally, and returned as this same `RestoreStdio` all the way through — a
        // panic partway through the loop still drops a `RestoreStdio` whose `saved` holds exactly
        // the fds closed so far, so `Drop` restores those.
        let mut guard = RestoreStdio {
            saved: Vec::with_capacity(fds.len()),
        };
        for &fd in fds {
            // SAFETY: F_DUPFD_CLOEXEC(fd, 3) duplicates fd to a fresh number >= 3, checked below.
            let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            assert!(
                dup >= 0,
                "dup fd {fd} aside before closing it: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: `dup` was just returned by a successful F_DUPFD_CLOEXEC.
            let dup = unsafe { OwnedFd::from_raw_fd(dup) };
            let dup_fd = dup.as_raw_fd();
            // Push into the guard, and (for fd 2) publish to `SAVED_STDERR`, BEFORE `close` below:
            // Linux frees a fd from the table even when `close` itself reports failure (EINTR,
            // EIO, ...), so a panic from the `close` assert below must find the guard and the
            // slot already armed.
            guard.saved.push((fd, dup));
            if fd == 2 {
                ensure_stderr_panic_hook();
                // Not held across the assert below: the temporary guard from `*saved_stderr()`
                // drops at the end of ITS OWN statement. Holding it across the assert would
                // self-deadlock — the panic hook this call just armed locks this SAME mutex, on
                // this SAME thread, as the first thing it does when the assert panics (a hook
                // runs before any unwinding), and a plain `Mutex` is not reentrant.
                let prev = *saved_stderr();
                assert!(
                    prev.is_none(),
                    "RestoreStdio::close: SAVED_STDERR already occupied (by fd {prev:?}) — two \
                     guards overlap on fd 2"
                );
                *saved_stderr() = Some(dup_fd);
            }
            assert_eq!(
                unsafe { libc::close(fd) },
                0,
                "close the test process' fd {fd}: {}",
                std::io::Error::last_os_error()
            );
        }
        guard
    }
}

impl Drop for RestoreStdio {
    fn drop(&mut self) {
        // Restore every fd WITHOUT panicking mid-loop — collecting failures instead — so this
        // function never panics TWICE: once here, and (if this `Drop` runs as part of unwinding an
        // earlier panic) a second panic during unwind is not caught — the process aborts. Reported
        // once, below.
        let mut failures: Vec<String> = Vec::new();
        for (fd, dup) in &self.saved {
            // SAFETY: dup2 back onto `fd`; `dup` stays valid (closed normally by its own Drop,
            // right after) regardless of this call's outcome. Retries EINTR the same way
            // `fd_map::dup2_onto` does.
            let ret = loop {
                let ret = unsafe { libc::dup2(dup.as_raw_fd(), *fd) };
                if ret != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break ret;
                }
            };
            if ret != *fd {
                failures.push(format!(
                    "dup2({}, {fd}) while restoring a guarded fd failed: {}",
                    dup.as_raw_fd(),
                    std::io::Error::last_os_error()
                ));
            }
        }
        // Report BEFORE clearing the slot: if fd 2's own restore above failed, the slot still
        // holds this guard's dup, so a panic here still reaches real stderr through the hook.
        // Clearing first would leave the hook nothing to restore, and the report would be written
        // to a closed fd 2 and silently dropped.
        if !failures.is_empty() {
            let msg = failures.join("; ");
            // A NEW panic here, while this `Drop` is ALREADY unwinding an earlier panic, would
            // abort the process — worse than the failure it reports. Report without panicking in
            // that case; panic normally otherwise, so an ordinary restore failure still fails its
            // test.
            if std::thread::panicking() {
                eprintln!("RestoreStdio::drop: {msg} (not panicking: already unwinding)");
            } else {
                panic!("RestoreStdio::drop: {msg}");
            }
        }
        if self.saved.iter().any(|(fd, _)| *fd == 2) {
            *saved_stderr() = None;
        }
    }
}

/// Lower this process' own `RLIMIT_NOFILE` soft limit to `to`, for the life of the guard,
/// restoring the original soft limit on drop (even if the test panics).
///
/// A forked child inherits its parent's rlimits at fork time, before any `pre_exec` hook runs — so
/// lowering the limit HERE, in the process that calls `spawn()`, makes an ordinary child fd number
/// deterministically exceed the CHILD's own limit and fail its `dup2` with `EBADF`, regardless of
/// the host's real `ulimit -n`.
///
/// `lower_to` asserts [`require_process_per_test`] before touching anything: this is exactly as
/// process-wide, and exactly as unsafe outside a call wrapped in [`alone`], as `RestoreStdio::close`.
pub struct RestoreRlimitNofile {
    original: libc::rlimit,
}

impl RestoreRlimitNofile {
    pub fn lower_to(to: libc::rlim_t) -> RestoreRlimitNofile {
        require_process_per_test("lowers this process's own RLIMIT_NOFILE, process-wide");
        let mut original: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `original` is a valid, correctly-sized out-param.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) },
            0,
            "getrlimit(RLIMIT_NOFILE): {}",
            std::io::Error::last_os_error()
        );
        let lowered = libc::rlimit {
            rlim_cur: to,
            rlim_max: original.rlim_max,
        };
        // SAFETY: `lowered` only ever lowers `rlim_cur`; `rlim_max` is passed through unchanged,
        // so this cannot raise the process' hard ceiling.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) },
            0,
            "setrlimit(RLIMIT_NOFILE, {{cur: {to}, max: {}}}): {}",
            original.rlim_max,
            std::io::Error::last_os_error()
        );
        RestoreRlimitNofile { original }
    }
}

impl Drop for RestoreRlimitNofile {
    fn drop(&mut self) {
        // SAFETY: restores exactly the limit `getrlimit` reported before this guard lowered it.
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.original) };
        if ret != 0 {
            let msg = format!(
                "setrlimit(RLIMIT_NOFILE, restore to {{cur: {}, max: {}}}) failed: {}",
                self.original.rlim_cur,
                self.original.rlim_max,
                std::io::Error::last_os_error()
            );
            // Same collect-and-report convention as `RestoreStdio::drop`: a second panic during
            // an unwind already in progress would abort the process instead of failing a test.
            if std::thread::panicking() {
                eprintln!("RestoreRlimitNofile::drop: {msg} (not panicking: already unwinding)");
            } else {
                panic!("RestoreRlimitNofile::drop: {msg}");
            }
        }
    }
}

/// Wait for `child` to exit, bounded by `timeout` — killing it and failing loudly if it does not,
/// rather than blocking forever. A failure bound for a child that may hang forever (e.g. a
/// self-deadlock), not synchronization: the wait itself is a blocking read on another thread, woken
/// the instant the child exits.
///
/// `child` stays owned by the caller's thread and is reaped only there. The background thread gets
/// only the pipes, plus a non-reaping `waitid(WEXITED | WNOWAIT)` to learn of exit; an unreaped
/// child's pid cannot be recycled, so `kill`/`wait` below — on timeout, or if the drain thread dies
/// without a result — are race-free regardless of which branch runs.
///
/// Drains stdout and stderr CONCURRENTLY, each on its own thread, not one after the other: a child
/// that writes more than one pipe buffer to stderr while producing little or no stdout would
/// otherwise deadlock this function, since reading stdout to EOF blocks until the child exits while
/// the child is itself blocked writing to the undrained stderr pipe.
type DrainResult = Result<(Vec<u8>, Vec<u8>), String>;

/// The post-drain half of [`wait_bounded`]: given `child` and a channel some drain mechanism will
/// eventually send a [`DrainResult`] to, wait bounded by `timeout` and turn every outcome into
/// either an `Output` or a loud, kill-and-reap-first panic. Split out from `wait_bounded` as a
/// seam: a test can drive this directly with a synthetic channel, to prove the `Timeout` and
/// `Disconnected` arms without needing a real drain thread to fail.
fn wait_on_channel(
    mut child: std::process::Child,
    timeout: std::time::Duration,
    rx: std::sync::mpsc::Receiver<DrainResult>,
) -> std::process::Output {
    let pid = child.id();
    match rx.recv_timeout(timeout) {
        Ok(Ok((stdout, stderr))) => {
            let status = child.wait().expect("reap the child, already confirmed exited");
            std::process::Output { status, stdout, stderr }
        }
        Ok(Err(msg)) => {
            let _ = child.kill();
            let status = child.wait().expect("reap the child after a drain failure");
            panic!("child pid {pid}: {msg}; killed and reaped, exit status {status:?}");
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let _ = child.kill();
            let status = child.wait().expect("reap the child after killing it");
            panic!(
                "child pid {pid} did not exit within {timeout:?} — it hung instead of exiting, \
                 which is itself the regression under test. Killed it and reaped exit status \
                 {status:?}."
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            // The drain thread died (e.g. its own panic) without sending a result: kill and reap
            // exactly like the other failure arms, so the child is never left running unreaped.
            let _ = child.kill();
            let status = child.wait().expect("reap the child after the drain thread died");
            panic!(
                "child pid {pid}'s wait thread died without sending a result; killed and reaped, \
                 exit status {status:?}."
            );
        }
    }
}

/// Wait for `child` to exit, bounded by `timeout` — killing it and failing loudly if it does not,
/// rather than blocking forever. A failure bound for a child that may hang forever (e.g. a
/// self-deadlock), not synchronization: the wait itself is a blocking read on another thread, woken
/// the instant the child exits.
///
/// `child` stays owned by the caller's thread and is reaped only there ([`wait_on_channel`]). The
/// background thread gets only the pipes, plus a non-reaping `waitid(WEXITED | WNOWAIT)` to learn
/// of exit; an unreaped child's pid cannot be recycled, so `kill`/`wait` on timeout or drain
/// failure are race-free regardless of which branch runs.
///
/// Drains stdout and stderr CONCURRENTLY, each on its own thread, not one after the other: a child
/// that writes more than one pipe buffer to stderr while producing little or no stdout would
/// otherwise deadlock this function, since reading stdout to EOF blocks until the child exits while
/// the child is itself blocked writing to the undrained stderr pipe.
pub fn wait_bounded(mut child: std::process::Child, timeout: std::time::Duration) -> std::process::Output {
    let pid = child.id();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let stdout_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let result = stdout_pipe.take().map_or(Ok(0), |mut p| p.read_to_end(&mut buf));
            (buf, result)
        });
        let mut stderr = Vec::new();
        let stderr_result = stderr_pipe.take().map_or(Ok(0), |mut p| p.read_to_end(&mut stderr));
        let (stdout, stdout_result) = stdout_thread.join().expect("join the stdout-draining thread");
        // Surface a read failure instead of returning silently-truncated output, which the
        // caller's assertions would otherwise run against as if it were complete.
        if let Err(e) = stdout_result {
            let _ = tx.send(Err(format!("reading the child's stdout failed: {e}")));
            return;
        }
        if let Err(e) = stderr_result {
            let _ = tx.send(Err(format!("reading the child's stderr failed: {e}")));
            return;
        }
        // Confirm the child has exited WITHOUT reaping it (`WNOWAIT`) — reaping stays on the
        // caller's thread below, the only place allowed to touch the `Child` it still owns.
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: `si` is a valid, correctly-sized out-param; `pid` is our own unreaped child.
            let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED | libc::WNOWAIT) };
            if rc == 0 {
                break;
            }
            // Any other error (e.g. already reaped after a timeout): nothing left to confirm.
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                break;
            }
        }
        let _ = tx.send(Ok((stdout, stderr)));
    });
    wait_on_channel(child, timeout, rx)
}

/// Run `probe_name` — a `#[test]` in THIS SAME test binary — directly with the exact
/// `alone()`-isolated shape (`COSCA_TEST_ALONE` set to `probe_name`, plus [`ALONE_ARGS`]), with
/// `extra_env` also set, and return its captured output.
///
/// "Directly" is load bearing: it makes `probe_name`'s own `alone()` call match immediately
/// instead of re-execing a second layer, which would turn a process ABORT (no exit code, commonly
/// 134/`SIGABRT`) into that layer's own ordinary panic (a clean exit 101) one level up.
///
/// Spawns under `cosca::test_spawn_lock()`, waits via [`wait_bounded`].
pub fn run_probe_directly(probe_name: &str, extra_env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("this test binary"));
    cmd.arg(probe_name)
        .args(ALONE_ARGS)
        .env("COSCA_TEST_ALONE", probe_name)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for &(k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = {
        let _guard = cosca::test_spawn_lock();
        cmd.spawn().expect("spawn the probe")
    };
    wait_bounded(child, PROBE_TIMEOUT)
}

/// Tests for this file's own mechanism — probes, provers, and `wait_bounded`'s seam. Written ONCE
/// here rather than once per compilation unit: `module_path!()` reflects wherever THIS module
/// actually landed (`test_isolation::isolation_tests` in the lib, `isolation::isolation_tests` in
/// each integration test binary via `common`), so a probe naming itself needs no per-copy
/// adjustment.
#[cfg(test)]
mod isolation_tests {
    use super::{alone, run_probe_directly, wait_bounded, wait_on_channel, RestoreRlimitNofile, RestoreStdio};

    fn qualified(name: &str) -> String {
        // `module_path!()` includes the crate name as its first segment (e.g. "cosca::..." here,
        // "spawn_io::..." in an integration test binary); libtest's own test names never do.
        let path = module_path!();
        let without_crate_name = path.split_once("::").map_or(path, |(_, rest)| rest);
        format!("{without_crate_name}::{name}")
    }

    // Overlap contract: a hard assert, before anything is closed =====

    /// Opens a SECOND `RestoreStdio` on fd 2 while the first is still alive. Must panic
    /// immediately — before the second guard closes or registers anything — with the fix's own
    /// message reaching stderr, in every build profile (a plain `assert!`, not `debug_assert!`).
    ///
    /// The intervening `tempfile::tempfile()` matters: without it, the second `close(&[2])` would
    /// dup an ALREADY-CLOSED fd 2 (closed by the first guard) and panic on THAT `fcntl` failure
    /// instead — a different failure than the one this probe exists to trigger. Opening a
    /// throwaway file first lands something valid back at the freed fd 2, so the second
    /// `close(&[2])` reaches the overlap check.
    #[test]
    #[ignore = "probe"]
    fn two_overlapping_fd2_closes_probe() {
        assert!(
            std::env::var_os("COSCA_TEST_TRIGGER_TWO_OVERLAPPING_FD2_CLOSES_PROBE").is_some(),
            "this probe must only be invoked via two_overlapping_fd2_closes_panics_cleanly — a \
             bare --include-ignored sweep that reaches here without it must not pass vacuously"
        );
        if !alone(&qualified("two_overlapping_fd2_closes_probe")) {
            return;
        }
        let _first = RestoreStdio::close(&[2]);
        let _file = tempfile::tempfile().expect("open a file that lands at the freed fd 2");
        let _second = RestoreStdio::close(&[2]); // must panic cleanly, not deadlock or overwrite
    }

    /// Proves the overlap contract: exit 101 and the fix's own message on stderr, in every build
    /// profile — no debug/release split, since the check is now a hard `assert!`.
    #[test]
    fn two_overlapping_fd2_closes_panics_cleanly() {
        const TRIGGER: &str = "COSCA_TEST_TRIGGER_TWO_OVERLAPPING_FD2_CLOSES_PROBE";
        let out = run_probe_directly(&qualified("two_overlapping_fd2_closes_probe"), &[(TRIGGER, "1")]);
        assert_eq!(
            out.status.code(),
            Some(101),
            "the second, overlapping RestoreStdio::close(&[2]) must panic cleanly (exit 101), not \
             hang, abort, or silently succeed — got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("SAVED_STDERR already occupied"),
            "the overlap panic's own message must reach stderr — got:\n{combined}"
        );
    }

    // Panic-hook mechanism =====

    /// A deliberate, always-panicking probe for `RestoreStdio::close`'s panic-hook fix: before it,
    /// a panic while fd 2 was held closed had its message silently swallowed (the default hook's
    /// write to a closed fd 2 fails, and the hook drops that failure).
    #[test]
    #[ignore = "probe"]
    fn panic_while_fd2_closed_probe() {
        assert!(
            std::env::var_os("COSCA_TEST_TRIGGER_PANIC_WHILE_FD2_CLOSED_PROBE").is_some(),
            "this probe must only be invoked via a_panic_while_fd2_is_closed_still_reaches_stderr \
             — a bare --include-ignored sweep that reaches here without it must not pass vacuously"
        );
        if !alone(&qualified("panic_while_fd2_closed_probe")) {
            return;
        }
        let _restore = RestoreStdio::close(&[2]);
        panic!("PANIC_WHILE_FD2_CLOSED_PROBE_MARKER: this message must survive fd 2 being closed");
    }

    /// Proves `RestoreStdio::close`'s panic-hook fix. Asserts the probe's own exit code is EXACTLY
    /// `101`: an abort has no defined exit code (commonly reported as 134/`SIGABRT`), and
    /// `run_probe_directly`'s "directly" invocation is what stops a second `alone()` layer from
    /// masking that as an ordinary 101 one level up.
    #[test]
    fn a_panic_while_fd2_is_closed_still_reaches_stderr() {
        const TRIGGER: &str = "COSCA_TEST_TRIGGER_PANIC_WHILE_FD2_CLOSED_PROBE";
        let out = run_probe_directly(&qualified("panic_while_fd2_closed_probe"), &[(TRIGGER, "1")]);
        assert_eq!(
            out.status.code(),
            Some(101),
            "the probe must fail with an ordinary libtest panic exit (101), not an abort — got \
             {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("PANIC_WHILE_FD2_CLOSED_PROBE_MARKER"),
            "the probe's own panic message must survive fd 2 being closed while it panicked — \
             got:\n{combined}"
        );
    }

    // require_process_per_test's gate =====

    /// Calls `RestoreStdio::close(&[2])` directly, deliberately NOT wrapped in `alone()` first.
    #[test]
    #[ignore = "probe"]
    fn close_without_alone_probe() {
        assert!(
            std::env::var_os("COSCA_TEST_TRIGGER_CLOSE_WITHOUT_ALONE_PROBE").is_some(),
            "this probe must only be invoked via gate_rejects_a_non_alone_process — a bare \
             --include-ignored sweep that reaches here without it must not pass vacuously"
        );
        let _restore = RestoreStdio::close(&[2]);
    }

    /// Proves `require_process_per_test`'s own gate: a process that calls `RestoreStdio::close`
    /// without first going through `alone()` must panic with the gate's own message, not silently
    /// proceed to touch process-wide fd state. Spawns the probe directly — not via
    /// `run_probe_directly`, which always sets up the full `alone()` shape — with neither
    /// `COSCA_TEST_ALONE` set nor `ALONE_ARGS` as its argv.
    #[test]
    fn gate_rejects_a_non_alone_process() {
        let probe = qualified("close_without_alone_probe");
        let child = {
            let _guard = cosca::test_spawn_lock();
            std::process::Command::new(std::env::current_exe().expect("this test binary"))
                .args([
                    probe.as_str(),
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("COSCA_TEST_TRIGGER_CLOSE_WITHOUT_ALONE_PROBE", "1")
                .env_remove("COSCA_TEST_ALONE")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn the probe")
        };
        let out = wait_bounded(child, super::PROBE_TIMEOUT);
        assert_eq!(
            out.status.code(),
            Some(101),
            "a process not running under alone() must have RestoreStdio::close panic (exit 101) \
             — got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("call this from inside alone()"),
            "the gate's own panic message must reach stderr — got:\n{combined}"
        );
    }

    /// The gate must reject a FORGED-BUT-MATCHING `COSCA_TEST_ALONE` too, not just a missing one:
    /// an env-presence-only check would pass [`gate_rejects_a_non_alone_process`] just as well as
    /// the real, argv-checking one, since that prover never sets the env var at all.
    #[test]
    fn gate_rejects_a_matching_env_var_with_a_non_alone_argv() {
        let probe = qualified("close_without_alone_probe");
        let child = {
            let _guard = cosca::test_spawn_lock();
            std::process::Command::new(std::env::current_exe().expect("this test binary"))
                .args([
                    probe.as_str(),
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("COSCA_TEST_TRIGGER_CLOSE_WITHOUT_ALONE_PROBE", "1")
                .env("COSCA_TEST_ALONE", &probe)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn the probe")
        };
        let out = wait_bounded(child, super::PROBE_TIMEOUT);
        assert_eq!(
            out.status.code(),
            Some(101),
            "a matching COSCA_TEST_ALONE with the WRONG argv shape must still be rejected (exit \
             101) — got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("call this from inside alone()"),
            "the gate's own panic message must reach stderr — got:\n{combined}"
        );
    }

    // RestoreStdio: duplicate fd, mid-loop restore, no double panic (c4586e0f) =====

    /// `RestoreStdio::close` rejects a repeated fd. In debug, the `debug_assert!` fires first
    /// ("fds must be distinct"); in release it no-ops, but the second pass then tries to dup an
    /// ALREADY-CLOSED fd 2 and panics on THAT `fcntl` failure instead — so this panics, with a
    /// different message, in every build profile.
    #[test]
    #[ignore = "probe"]
    fn close_with_a_duplicate_fd_probe() {
        assert!(
            std::env::var_os("COSCA_TEST_TRIGGER_CLOSE_WITH_A_DUPLICATE_FD_PROBE").is_some(),
            "this probe must only be invoked via close_rejects_a_duplicate_fd — a bare \
             --include-ignored sweep that reaches here without it must not pass vacuously"
        );
        if !alone(&qualified("close_with_a_duplicate_fd_probe")) {
            return;
        }
        let _guard = RestoreStdio::close(&[2, 2]);
    }

    #[test]
    fn close_rejects_a_duplicate_fd() {
        const TRIGGER: &str = "COSCA_TEST_TRIGGER_CLOSE_WITH_A_DUPLICATE_FD_PROBE";
        let out = run_probe_directly(&qualified("close_with_a_duplicate_fd_probe"), &[(TRIGGER, "1")]);
        assert_eq!(
            out.status.code(),
            Some(101),
            "close(&[2, 2]) must panic in every build profile — got {:?}\n--- stdout ---\n{}\n--- \
             stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let expected = if cfg!(debug_assertions) {
            "fds must be distinct"
        } else {
            "dup fd 2 aside before closing it"
        };
        assert!(
            combined.contains(expected),
            "expected {expected:?} in the panic reachable in this build profile — got:\n{combined}"
        );
    }

    /// When a later fd in the list fails, the guard built so far must still restore the EARLIER
    /// fds it already closed — proving `close`'s incremental-guard construction, not just its
    /// existence. Fd 999 is never open, so its own `fcntl` dup-aside fails after fd 2 has already
    /// been closed and pushed into the guard.
    #[test]
    #[ignore = "probe"]
    fn close_mid_loop_failure_restores_earlier_fds_probe() {
        assert!(
            std::env::var_os("COSCA_TEST_TRIGGER_CLOSE_MID_LOOP_FAILURE_PROBE").is_some(),
            "this probe must only be invoked via close_mid_loop_failure_restores_earlier_fds — a \
             bare --include-ignored sweep that reaches here without it must not pass vacuously"
        );
        if !alone(&qualified("close_mid_loop_failure_restores_earlier_fds_probe")) {
            return;
        }
        let result = std::panic::catch_unwind(|| {
            let _guard = RestoreStdio::close(&[2, 999]);
        });
        assert!(result.is_err(), "close(&[2, 999]) must panic: fd 999 is never open");
        // The guard (holding only fd 2, since 999 never got pushed) dropped during unwind and
        // restored fd 2. A closed fd fails F_GETFD with EBADF; the real fd 2 here (piped by
        // `run_probe_directly`) accepts it once restored.
        // SAFETY: F_GETFD reads flags only, no ownership implications.
        let flags = unsafe { libc::fcntl(2, libc::F_GETFD) };
        assert_ne!(
            flags,
            -1,
            "fd 2 must be restored after the mid-loop panic unwound the guard: {}",
            std::io::Error::last_os_error()
        );
        eprintln!("CLOSE_MID_LOOP_RESTORE_PROBE_MARKER: fd 2 is usable again");
    }

    #[test]
    fn close_mid_loop_failure_restores_earlier_fds() {
        const TRIGGER: &str = "COSCA_TEST_TRIGGER_CLOSE_MID_LOOP_FAILURE_PROBE";
        let out = run_probe_directly(
            &qualified("close_mid_loop_failure_restores_earlier_fds_probe"),
            &[(TRIGGER, "1")],
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "the probe catches its own panic and must finish normally — got {:?}\n--- stdout \
             ---\n{}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("CLOSE_MID_LOOP_RESTORE_PROBE_MARKER"),
            "the probe must observe fd 2 restored after the mid-loop panic — got:\n{combined}"
        );
    }

    /// `Drop` must not panic a SECOND time while already unwinding an earlier panic (which would
    /// abort the process, `SIGABRT`): sabotages the guard's own saved dup (closing it out from
    /// under the guard) so its eventual restore fails, then panics for an unrelated reason while
    /// the guard is still alive. `Drop` must report the sabotaged restore without panicking again.
    #[test]
    #[ignore = "probe"]
    fn drop_does_not_double_panic_probe() {
        assert!(
            std::env::var_os("COSCA_TEST_TRIGGER_DROP_DOES_NOT_DOUBLE_PANIC_PROBE").is_some(),
            "this probe must only be invoked via drop_does_not_double_panic — a bare \
             --include-ignored sweep that reaches here without it must not pass vacuously"
        );
        if !alone(&qualified("drop_does_not_double_panic_probe")) {
            return;
        }
        let _restore_stdio = RestoreStdio::close(&[2]);
        // Sabotage: lower RLIMIT_NOFILE to 1 (below fd 2) AFTER fd 2 is already dup'd aside and
        // closed, so ONLY `_restore_stdio`'s own eventual `dup2(dup, 2)` restore fails (the
        // kernel rejects a `dup2` target at or past the limit) — everything up to here still ran
        // under the normal limit. A raw `setrlimit`, not `RestoreRlimitNofile`: that guard's own
        // restore-on-drop would need to run AFTER `_restore_stdio`'s, but Rust drops locals in
        // reverse declaration order, so the two guards' constructor/destructor order can't both
        // be what this probe needs at once. Sabotaging the guard's OWN saved dup instead (closing
        // it out from under the guard) would make std's OWN `OwnedFd::drop` trip its own
        // double-close debug assertion when that dup is later dropped — a different abort than
        // the one this probe exists to trigger. This process exits right after the panic below,
        // so never restoring the limit here is harmless.
        let tight = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 65536,
        };
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &tight) },
            0,
            "tighten RLIMIT_NOFILE for the probe: {}",
            std::io::Error::last_os_error()
        );
        panic!("triggering an unwind while RestoreStdio::drop's own restore is sabotaged");
    }

    #[test]
    fn drop_does_not_double_panic() {
        const TRIGGER: &str = "COSCA_TEST_TRIGGER_DROP_DOES_NOT_DOUBLE_PANIC_PROBE";
        let out = run_probe_directly(&qualified("drop_does_not_double_panic_probe"), &[(TRIGGER, "1")]);
        assert_eq!(
            out.status.code(),
            Some(101),
            "an ordinary panic while the guard's restore is sabotaged must exit 101 (Drop's own \
             report, not a second panic) — an abort (no code, commonly 134/SIGABRT) means Drop \
             panicked again while already unwinding. got {:?}\n--- stdout ---\n{}\n--- stderr \
             ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // RestoreRlimitNofile: gate and Drop reporting (757129d8) =====

    #[test]
    #[ignore = "probe"]
    fn lower_to_without_alone_probe() {
        assert!(
            std::env::var_os("COSCA_TEST_TRIGGER_LOWER_TO_WITHOUT_ALONE_PROBE").is_some(),
            "this probe must only be invoked via gate_rejects_a_non_alone_process_for_rlimit — a \
             bare --include-ignored sweep that reaches here without it must not pass vacuously"
        );
        let _guard = RestoreRlimitNofile::lower_to(64);
    }

    /// Proves `RestoreRlimitNofile::lower_to`'s own gate, the same way
    /// [`gate_rejects_a_non_alone_process`] proves `RestoreStdio::close`'s.
    #[test]
    fn gate_rejects_a_non_alone_process_for_rlimit() {
        let probe = qualified("lower_to_without_alone_probe");
        let child = {
            let _guard = cosca::test_spawn_lock();
            std::process::Command::new(std::env::current_exe().expect("this test binary"))
                .args([
                    probe.as_str(),
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("COSCA_TEST_TRIGGER_LOWER_TO_WITHOUT_ALONE_PROBE", "1")
                .env_remove("COSCA_TEST_ALONE")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn the probe")
        };
        let out = wait_bounded(child, super::PROBE_TIMEOUT);
        assert_eq!(
            out.status.code(),
            Some(101),
            "a process not running under alone() must have lower_to panic (exit 101) — got \
             {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("call this from inside alone()"),
            "the gate's own panic message must reach stderr — got:\n{combined}"
        );
    }

    /// `RestoreRlimitNofile::drop`'s restore can fail (e.g. `rlim_max` lowered further from
    /// outside between `lower_to` and drop) — it must report that loudly, matching
    /// `RestoreStdio::drop`'s convention, not panic unconditionally with no `panicking()` guard.
    #[test]
    #[ignore = "probe"]
    fn rlimit_restore_failure_probe() {
        assert!(
            std::env::var_os("COSCA_TEST_TRIGGER_RLIMIT_RESTORE_FAILURE_PROBE").is_some(),
            "this probe must only be invoked via rlimit_restore_failure_reports_loudly — a bare \
             --include-ignored sweep that reaches here without it must not pass vacuously"
        );
        if !alone(&qualified("rlimit_restore_failure_probe")) {
            return;
        }
        let guard = RestoreRlimitNofile::lower_to(64);
        // Tighten rlim_max further, so the guard's own restore-to-original rlim_cur fails.
        let tighter = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &tighter) },
            0,
            "tighten rlim_max for the probe: {}",
            std::io::Error::last_os_error()
        );
        drop(guard); // must panic here, loudly — not abort
    }

    #[test]
    fn rlimit_restore_failure_reports_loudly() {
        const TRIGGER: &str = "COSCA_TEST_TRIGGER_RLIMIT_RESTORE_FAILURE_PROBE";
        let out = run_probe_directly(&qualified("rlimit_restore_failure_probe"), &[(TRIGGER, "1")]);
        assert_eq!(
            out.status.code(),
            Some(101),
            "a restore failure in Drop must panic cleanly (exit 101), not abort — got {:?}\n--- \
             stdout ---\n{}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("setrlimit(RLIMIT_NOFILE, restore to"),
            "the restore failure must be reported — got:\n{combined}"
        );
    }

    // wait_bounded's real drain thread =====

    /// `wait_bounded` must drain stdout and stderr CONCURRENTLY, not one after the other: a child
    /// that writes more than one pipe buffer to stderr while producing little or no stdout would
    /// otherwise deadlock it, since reading stdout to EOF blocks until the child exits while the
    /// child is itself blocked writing to the undrained stderr pipe. Exercises the real drain
    /// thread `wait_bounded` spawns — [`wait_on_channel_timeout_kills_and_reaps`] and
    /// [`wait_on_channel_disconnected_kills_and_reaps`] bypass it with a synthetic channel.
    #[test]
    fn wait_bounded_drains_stdout_and_stderr_concurrently() {
        const STDERR_BYTES: usize = 200_000;
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("head -c {STDERR_BYTES} /dev/zero | tr '\\0' 'x' 1>&2"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = {
            let _guard = cosca::test_spawn_lock();
            cmd.spawn().expect("spawn the child")
        };
        let out = wait_bounded(child, super::PROBE_TIMEOUT);
        assert!(out.status.success(), "the child must exit cleanly: {:?}", out.status);
        assert_eq!(
            out.stderr.len(),
            STDERR_BYTES,
            "must drain all of stderr, not hang or truncate it while stdout sits empty"
        );
    }

    // wait_bounded's Timeout/Disconnected arms (665960be) =====

    /// A trivial, fast-exiting child, so the test itself stays fast: the synthetic channel below
    /// — not the real child — is what drives which arm of `wait_on_channel` runs.
    fn trivial_child() -> std::process::Child {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 5") // outlives the short bound below, unless killed
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn a trivial child")
    }

    /// `wait_on_channel`'s `Timeout` arm must kill and reap a still-running child, not merely
    /// panic and leave it running. Uses a channel nothing ever sends on, so the bound reliably
    /// fires without depending on any real drain thread.
    #[test]
    fn wait_on_channel_timeout_kills_and_reaps() {
        let child = trivial_child();
        let pid = child.id();
        let (_tx, rx) = std::sync::mpsc::channel::<super::DrainResult>();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wait_on_channel(child, std::time::Duration::from_millis(200), rx)
        }));
        assert!(result.is_err(), "a timeout must panic");
        // SAFETY: a plain, side-effect-free liveness probe (signal 0 sends nothing).
        let still_alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
        assert!(
            !still_alive,
            "the child must be killed, not left running, after a timeout"
        );
    }

    /// `wait_on_channel`'s `Disconnected` arm (the drain side died without a result) must ALSO
    /// kill and reap, exactly like `Timeout` — not just panic and leave the child running. Drops
    /// the sender immediately, so `recv_timeout` observes `Disconnected` right away.
    #[test]
    fn wait_on_channel_disconnected_kills_and_reaps() {
        let child = trivial_child();
        let pid = child.id();
        let (tx, rx) = std::sync::mpsc::channel::<super::DrainResult>();
        drop(tx);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wait_on_channel(child, std::time::Duration::from_secs(10), rx)
        }));
        assert!(result.is_err(), "a disconnected channel must panic");
        // SAFETY: as above.
        let still_alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
        assert!(
            !still_alive,
            "the child must be killed, not left running, after a disconnect"
        );
    }
}

#[cfg(test)]
mod alone_marker_tests {
    use super::{alone_marker_matches, ALONE_ARGS};

    fn genuine_argv(name: &str) -> Vec<String> {
        std::iter::once(name.to_string())
            .chain(ALONE_ARGS.iter().map(|s| s.to_string()))
            .collect()
    }

    #[test]
    fn the_genuine_re_exec_shape_matches() {
        assert!(alone_marker_matches(Some("some_test"), &genuine_argv("some_test")));
    }

    #[test]
    fn no_env_value_never_matches() {
        assert!(!alone_marker_matches(None, &genuine_argv("some_test")));
    }

    #[test]
    fn an_inherited_env_value_with_the_ordinary_suites_own_argv_does_not_match() {
        // The exact corruption measured: `COSCA_TEST_ALONE` set (e.g. leaked from an outer shell
        // or re-exec) to some real test's name, but THIS process's own argv is whatever an
        // ordinary `cargo test` run passes — never the isolated one-test-exact shape.
        assert!(!alone_marker_matches(Some("some_test"), &[]));
        assert!(!alone_marker_matches(Some("some_test"), &["some_test".to_string()]));
    }

    #[test]
    fn a_name_mismatch_does_not_match_even_with_the_right_shape() {
        let mut argv = genuine_argv("some_test");
        argv[0] = "other_test".to_string();
        assert!(!alone_marker_matches(Some("some_test"), &argv));
    }

    #[test]
    fn a_trailing_extra_argument_does_not_match() {
        let mut argv = genuine_argv("some_test");
        argv.push("--extra".to_string());
        assert!(!alone_marker_matches(Some("some_test"), &argv));
    }
}
