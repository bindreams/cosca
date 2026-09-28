//! Test isolation for a test that mutates process-wide state (closes fd 0/1/2, lowers
//! `RLIMIT_NOFILE`): the mutation and its restore must run alone in a process, or a concurrently
//! running, unrelated test thread can be corrupted by it. This is ONE file, included by both of
//! this crate's separate compilation units:
//! - `src/lib.rs`: a normal `mod test_isolation;` (this file lives under `src/`, so no `#[path]`
//!   or crate self-alias is needed — `crate::` already means `cosca` here).
//! - `tests/common/mod.rs`: `#[path = "../../src/test_isolation.rs"] mod isolation;`, for every
//!   integration test binary. `super::test_spawn_lock` is how this file reaches
//!   `cosca::test_spawn_lock` from that mount point — `tests/common/mod.rs` re-exports it under
//!   that name for exactly this.
//!
//! `crate::` is NOT used anywhere below for that reason: it resolves to `cosca` at the lib mount
//! point but to whichever integration test binary is compiling at the other, and this file cannot
//! know which. `super::` is: at the lib mount point, `super::test_spawn_lock` is `crate::
//! test_spawn_lock` (defined right there in `src/lib.rs`); at the integration mount point, it is
//! `common::test_spawn_lock`, the re-export.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Builds the fully-qualified libtest `--exact` path of the `#[test] fn` named `$name`, the same
/// way `crate::test_child::fixture_path!` does (that macro cannot be reused directly: it names
/// `crate::test_child`, a lib-only module invisible to the integration-test mount point). Ties the
/// call site to the fixture so they cannot drift into two independently hand-typed strings — see
/// `strip_crate_prefix`'s doc for the two checks this performs.
macro_rules! fixture_path {
    ($name:ident) => {{
        let _: fn() = $name;
        // Strips the crate-name segment `module_path!()` always carries as its own first
        // component (e.g. `"cosca::test_isolation"` or `"spawn_io::common::isolation"`), since
        // libtest's `--exact` filter never includes it. Inlined rather than a named helper
        // function: this macro is used from a nested module (`isolation_tests`) at a DIFFERENT
        // mount point than where it is defined, and macro hygiene does not resolve a bare
        // function call across that gap the way a fully local expression does.
        let path: &'static str = concat!(module_path!(), "::", stringify!($name));
        match path.split_once("::") {
            Some((_, rest)) => rest,
            None => path,
        }
    }};
}
pub(crate) use fixture_path;

/// The re-exec args [`alone`]/[`alone_capturing`] pass after the test name; [`alone_marker_matches`]
/// demands this process's own argv match this shape before trusting a `COSCA_TEST_ALONE` env var.
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

/// A completion token a re-exec'd child writes to an inherited pipe right before its own test body
/// returns normally — proof the body ran to completion, not merely that the process exited zero
/// (which a premature, silent `_exit` could also produce). [`alone`]/[`alone_capturing`] decide
/// pass/fail from this token plus the exit status, never by scanning libtest's own stdout banner
/// for human text like `"1 passed"` — this repo's own convention against parsing human text
/// applies to reading OUR OWN child's output just as much as any external tool's.
///
/// The write end's `CLOEXEC` flag is cleared so it survives into the child at the SAME fd number,
/// which the child is told via [`TOKEN_FD_ENV`] — clearing it happens while this process holds
/// `test_spawn_lock()`, the same lock that already serializes every raw fork here, so no
/// concurrent, unrelated spawn can observe the momentarily-inheritable fd.
const TOKEN_FD_ENV: &str = "COSCA_TEST_ALONE_TOKEN_FD";

/// Write the completion token to the fd [`TOKEN_FD_ENV`] names, if set (unset when this process
/// was not re-exec'd by [`alone`]/[`alone_capturing`] — an ordinary suite run must not try to
/// write to a nonexistent fd). Called once, by [`alone`]/[`alone_capturing`] themselves, right
/// before they return control to the child's real test body — NOT at the end of the body, so a
/// body that never returns (a probe whose whole point is to panic) does not need to remember to
/// call it, and correctly never produces a token in exactly that case.
fn write_completion_token_if_child() {
    let Some(fd) = std::env::var_os(TOKEN_FD_ENV) else {
        return;
    };
    let fd: i32 = fd.to_str().and_then(|s| s.parse().ok()).expect("valid fd number");
    // Defense in depth against [`clear_inherited_completion_token`]'s own hazard (see there): a
    // caller that fans out further `ALONE_ARGS`-shaped children without clearing `TOKEN_FD_ENV`
    // first leaves a STALE fd number in that grandchild's environment, meaning nothing in its own
    // fd table. Refuse to touch it unless it is actually a pipe — nothing this process opens
    // before this point (libtest's own startup, argv/env parsing) is one, so a real, intended
    // token fd (freshly inherited from `spawn_alone`, never yet touched by this process) always
    // passes this check, and a stale/coincidental number essentially never does.
    // SAFETY: `fstat` on a caller-supplied fd number; reads only, never touches ownership.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 || stat.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return;
    }
    // SAFETY: `fd` was made inheritable by this exact process's own parent (see TOKEN_FD_ENV's
    // doc), specifically for this write; confirmed a pipe just above; owned exclusively from here.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    use std::io::Write;
    let _ = file.write_all(b"1");
}

/// Strip this process's own [`TOKEN_FD_ENV`] from `cmd`'s environment before spawning it.
///
/// For a caller that reuses the [`ALONE_ARGS`] re-exec SHAPE to fan out ITS OWN further children
/// (each one also matching [`alone_marker_matches`], so each also runs through
/// [`write_completion_token_if_child`] when it starts) — not for an ordinary, single-level
/// `alone()`/`alone_capturing()` caller, which never needs this.
///
/// Without this, such a grandchild inherits `TOKEN_FD_ENV` from ITS parent (an ordinary env var,
/// unaffected by the parent's own copy of the pipe fd having already been closed) naming a fd
/// number that means nothing in the grandchild's own, freshly-forked fd table —
/// [`write_completion_token_if_child`] would trust it anyway, per its SAFETY comment's own
/// precondition ("made inheritable by this exact process's own parent, specifically for this
/// write"), which this exact call path violates: the fd number is stale, coincidental, and may
/// alias something the grandchild's own code already owns. Writing into it, then closing it via
/// the `File`'s `Drop`, races that real owner's own later close of the SAME number — observed as
/// `std`'s `OwnedFd`/`File` double-close abort ("IO Safety violation: owned file descriptor
/// already closed").
pub fn clear_inherited_completion_token(cmd: &mut std::process::Command) {
    cmd.env_remove(TOKEN_FD_ENV);
}

/// Spawn a fresh copy of this test binary against `name` with the isolated `alone()` shape
/// (`COSCA_TEST_ALONE=name`, argv [`ALONE_ARGS`]), give it a token pipe (see [`TOKEN_FD_ENV`]),
/// and wait for it — the shared spawn machinery [`alone`] and [`alone_capturing`] both build on.
/// Returns the captured `Output` plus whether the completion token arrived.
fn spawn_alone(name: &str) -> (std::process::Output, bool) {
    let (mut read_end, write_end) = std::io::pipe().expect("open completion-token pipe");
    let write_fd = write_end.as_raw_fd();
    let child = {
        let _guard = super::test_spawn_lock();
        // SAFETY: clears FD_CLOEXEC on our own pipe write end so it survives into the child at
        // the same fd number; held under `test_spawn_lock()`, so no concurrent, unrelated spawn
        // in this process can observe it inheritable.
        unsafe {
            let flags = libc::fcntl(write_fd, libc::F_GETFD);
            assert_ne!(
                flags,
                -1,
                "fcntl(F_GETFD) on the token pipe: {}",
                std::io::Error::last_os_error()
            );
            assert_eq!(
                libc::fcntl(write_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
                0,
                "fcntl(F_SETFD) to make the token pipe inheritable: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("this test binary"));
        cmd.args(std::iter::once(name).chain(ALONE_ARGS))
            .env("COSCA_TEST_ALONE", name)
            .env(TOKEN_FD_ENV, write_fd.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // SAFETY: async-signal-safe; puts the child in its OWN new process group (pgid == its own
        // pid) before it execs, so a later bounded-wait timeout can kill that WHOLE group — not
        // just this direct child — reaching any grandchildren it spawned into that same group
        // before hanging (e.g. a three-level tree under a cgroup-lane test run as root).
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.spawn().expect("spawn the test alone")
    };
    // Our own copy of the write end must close so EOF on `read_end` is observable once every
    // child copy closes too (on exit, whether or not it wrote — see `write_completion_token_if_child`).
    drop(write_end);
    let out = wait_bounded(child, PROBE_TIMEOUT, true);
    let mut token = Vec::new();
    use std::io::Read;
    let _ = read_end.read_to_end(&mut token);
    (out, token == b"1")
}

/// Run the test `name` (its full path, as libtest reports it) alone, in a fresh copy of this test
/// binary, and assert it passed. `true` in the copy, which must then run the test's real body;
/// `false` in the original caller, which must return immediately.
///
/// Pass/fail is decided from the re-exec'd child's exit status AND its completion token (see
/// [`TOKEN_FD_ENV`]), never by scanning its stdout for libtest's own banner text.
#[must_use = "the caller must return immediately when this is false — the real work already ran, \
              in isolation, in the re-exec'd child"]
pub fn alone(name: &str) -> bool {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if alone_marker_matches(Some(name), &argv) {
        write_completion_token_if_child();
        return true;
    }
    let (out, completed) = spawn_alone(name);
    assert!(
        out.status.success() && completed,
        "{}{}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        if completed {
            ""
        } else {
            " (no completion token: the body did not return normally)"
        },
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    false
}

/// Like [`alone`], but the parent gets the re-exec'd child's captured `Output` instead of a
/// pass/fail assertion — for a prover whose body must inspect the child's exit code and stderr
/// content (e.g. a fixture that is SUPPOSED to panic), not just "did it pass."
///
/// Returns `None` in the child (proceed with the real body); `Some(output)` in the parent. Unlike
/// `alone`, does not itself assert anything about `output` — a body that panics never reaches
/// [`write_completion_token_if_child`], so this function does not read the token either; the
/// caller decides what `output` means.
pub fn alone_capturing(name: &str) -> Option<std::process::Output> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if alone_marker_matches(Some(name), &argv) {
        return None;
    }
    let (out, _completed) = spawn_alone(name);
    Some(out)
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
/// enforces that before the dup, the push, or the slot are ever touched, so a REJECTED guard never
/// has an entry for fd 2 in its own `saved` at all, and its `Drop` has nothing to restore or clear.
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
/// other `RestoreStdio` already holds it, BEFORE duplicating fd 2 aside or pushing into the guard:
/// a violation this way leaves the first guard's registration completely untouched (nothing to
/// restore, nothing to clear) and its own panic message reaching real stderr — see [`SAVED_STDERR`]'s
/// doc for why an earlier version that checked only after the push let a rejected second guard's
/// own `Drop` clear the first guard's still-live registration.
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
        let mut guard = RestoreStdio {
            saved: Vec::with_capacity(fds.len()),
        };
        for &fd in fds {
            if fd == 2 {
                ensure_stderr_panic_hook();
                // Checked BEFORE the dup-aside and the push below: a rejected guard must end up
                // with NO entry for fd 2 in `saved` at all, so its own `Drop` later has nothing to
                // restore or clear. NOT held across the assert: the temporary guard from
                // `*saved_stderr()` drops at the end of ITS OWN statement — holding it across the
                // assert would self-deadlock (the panic hook this scope is about to arm locks this
                // SAME mutex, on this SAME thread, as the first thing it does when the assert
                // panics, and a plain `Mutex` is not reentrant).
                let prev = *saved_stderr();
                assert!(
                    prev.is_none(),
                    "RestoreStdio::close: SAVED_STDERR already occupied (by fd {prev:?}) — two \
                     guards overlap on fd 2"
                );
            }
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
        if !failures.is_empty() {
            let msg = format!("RestoreStdio::drop: {}", failures.join("; "));
            // Write the report DIRECTLY to this guard's own saved fd-2 dup, if it has one — not to
            // real fd 2 (via the panic hook or a plain `eprintln!`), which is exactly what a fd-2
            // restore failure calls into question. The dup is a copy of this process's REAL
            // stderr from before this guard closed it, so a direct write reaches it (the same
            // underlying pipe/file a caller captures as this process's stderr) regardless of what
            // real fd 2 currently holds.
            if let Some((_, dup)) = self.saved.iter().find(|(fd, _)| *fd == 2) {
                let line = format!("{msg}\n");
                // SAFETY: `dup` is a valid, still-open fd this guard owns exclusively until it
                // drops just below.
                unsafe { libc::write(dup.as_raw_fd(), line.as_ptr().cast(), line.len()) };
            }
            // Clear the slot only if it still holds THIS guard's own dup — a guard whose own
            // registration was rejected in `close` never has an fd-2 entry to reach this branch
            // at all, but the check costs nothing and documents the invariant directly.
            if let Some((_, dup)) = self.saved.iter().find(|(fd, _)| *fd == 2) {
                let my_fd = dup.as_raw_fd();
                let mut slot = saved_stderr();
                if *slot == Some(my_fd) {
                    *slot = None;
                }
            }
            // A NEW panic here, while this `Drop` is ALREADY unwinding an earlier panic, would
            // abort the process — worse than the failure it reports. Report without panicking in
            // that case; panic normally otherwise, so an ordinary restore failure still fails its
            // test.
            if std::thread::panicking() {
                eprintln!("{msg} (not panicking: already unwinding)");
            } else {
                panic!("{msg}");
            }
        } else if let Some((_, dup)) = self.saved.iter().find(|(fd, _)| *fd == 2) {
            let my_fd = dup.as_raw_fd();
            let mut slot = saved_stderr();
            if *slot == Some(my_fd) {
                *slot = None;
            }
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
                "RestoreRlimitNofile::drop: setrlimit(RLIMIT_NOFILE, restore to {{cur: {}, max: {}}}) failed: {}",
                self.original.rlim_cur,
                self.original.rlim_max,
                std::io::Error::last_os_error()
            );
            // Same collect-and-report convention as `RestoreStdio::drop`: a second panic during
            // an unwind already in progress would abort the process instead of failing a test.
            if std::thread::panicking() {
                eprintln!("{msg} (not panicking: already unwinding)");
            } else {
                panic!("{msg}");
            }
        }
    }
}

type DrainResult = Result<(Vec<u8>, Vec<u8>), String>;

/// Kill `child` — by process GROUP if `own_process_group` (negative pid), else just its own pid —
/// and reap it, returning the resulting `ExitStatus`. Killing the group while the leader is still
/// an unreaped zombie (the OS has not yet let its pid, and so its pgid, be recycled) reaches any
/// grandchildren the leader may have spawned into its own group before it hung — e.g. a three-level
/// tree under one of #210's cgroup-lane tests, run as root.
fn kill_and_reap(mut child: std::process::Child, own_process_group: bool) -> std::process::ExitStatus {
    let pid = child.id() as libc::pid_t;
    if own_process_group {
        // SAFETY: a plain signal to this process's own re-exec'd child's group; the child is still
        // unreaped (owned exclusively by `child` until `wait()` below), so its pid — and this
        // pgid, which the leader set to equal its own pid — cannot yet have been recycled.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    } else {
        let _ = child.kill();
    }
    child.wait().expect("reap the child after killing it")
}

/// The post-drain half of [`wait_bounded`]: given `child` and a channel some drain mechanism will
/// eventually send a [`DrainResult`] to, wait bounded by `timeout` and turn every outcome into
/// either an `Output` or a loud, kill-and-reap-first panic. Split out from `wait_bounded` as a
/// seam: a test can drive this directly with a synthetic channel, to prove the `Timeout` and
/// `Disconnected` arms without needing a real drain thread to fail.
///
/// `own_process_group`: see [`kill_and_reap`]. The caller — not this function — is responsible for
/// having put `child` in its own group before spawning it, if it passes `true` here.
fn wait_on_channel(
    child: std::process::Child,
    timeout: std::time::Duration,
    rx: std::sync::mpsc::Receiver<DrainResult>,
    own_process_group: bool,
) -> std::process::Output {
    let pid = child.id();
    match rx.recv_timeout(timeout) {
        Ok(Ok((stdout, stderr))) => {
            let mut child = child;
            let status = child.wait().expect("reap the child, already confirmed exited");
            std::process::Output { status, stdout, stderr }
        }
        Ok(Err(msg)) => {
            let status = kill_and_reap(child, own_process_group);
            panic!(
                "waiting for child pid {pid} failed: {msg}; killed and reaped, exit status \
                 {status:?} (signal {:?})",
                std::os::unix::process::ExitStatusExt::signal(&status)
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let status = kill_and_reap(child, own_process_group);
            panic!(
                "child pid {pid} did not exit within {timeout:?} — it hung instead of exiting, \
                 which is itself a regression somewhere upstream of this wait. Killed it and \
                 reaped exit status {status:?} (signal {:?}).",
                std::os::unix::process::ExitStatusExt::signal(&status)
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            // The drain thread died (e.g. its own panic) without sending a result: kill and reap
            // exactly like the other failure arms, so the child is never left running unreaped.
            let status = kill_and_reap(child, own_process_group);
            panic!(
                "child pid {pid}'s wait thread died without sending a result; killed and reaped, \
                 exit status {status:?} (signal {:?}).",
                std::os::unix::process::ExitStatusExt::signal(&status)
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
///
/// `own_process_group`: see [`kill_and_reap`].
fn wait_bounded(
    mut child: std::process::Child,
    timeout: std::time::Duration,
    own_process_group: bool,
) -> std::process::Output {
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
    wait_on_channel(child, timeout, rx, own_process_group)
}

/// Spawn a fresh copy of this test binary directly against `fixture` — WITHOUT `alone()`'s own
/// isolated shape (`COSCA_TEST_ALONE` per `alone_env`, argv NOT [`ALONE_ARGS`]) — with `extra_env`
/// also set, and return its captured output. Shared by every prover of a gate that must reject
/// exactly this non-isolated shape, not the isolated one every other caller uses (both in this
/// file's own tests and in #210's `spawn_with_std_slots_closed` provers).
pub fn spawn_without_alone_shape(
    fixture: &str,
    alone_env: Option<&str>,
    extra_env: &[(&str, &str)],
) -> std::process::Output {
    let child = {
        let _guard = super::test_spawn_lock();
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("this test binary"));
        cmd.args([fixture, "--exact", "--nocapture", "--test-threads=1"]);
        match alone_env {
            Some(name) => {
                cmd.env("COSCA_TEST_ALONE", name);
            }
            None => {
                cmd.env_remove("COSCA_TEST_ALONE");
            }
        }
        for &(k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the probe")
    };
    wait_bounded(child, PROBE_TIMEOUT, false)
}

#[cfg(test)]
mod isolation_tests {
    use super::{alone_capturing, kill_and_reap, wait_bounded, wait_on_channel, RestoreRlimitNofile, RestoreStdio};
    // `fixture_path!` IS used throughout this module (every folded probe/prover below); the
    // `unused_imports` lint just cannot see through a macro import the way it does an ordinary
    // item.
    #[allow(unused_imports)]
    use super::fixture_path;
    use super::spawn_without_alone_shape;

    // Overlap contract: a hard assert, before anything is closed =====

    /// Opens a SECOND `RestoreStdio` on fd 2 while the first is still alive. Must panic
    /// immediately — before the second guard closes or registers anything — with the fix's own
    /// message reaching stderr, in every build profile (a plain `assert!`, not `debug_assert!`).
    ///
    /// The intervening `tempfile::tempfile()` matters: without it, the second `close(&[2])` would
    /// dup an ALREADY-CLOSED fd 2 (closed by the first guard) and panic on THAT `fcntl` failure
    /// instead — a different failure than the one this proves. Opening a throwaway file first
    /// lands something valid back at the freed fd 2, so the second `close(&[2])` reaches the
    /// overlap check.
    #[test]
    fn two_overlapping_fd2_closes_panics_cleanly() {
        let Some(out) = alone_capturing(fixture_path!(two_overlapping_fd2_closes_panics_cleanly)) else {
            let _first = RestoreStdio::close(&[2]);
            let _file = tempfile::tempfile().expect("open a file that lands at the freed fd 2");
            let _second = RestoreStdio::close(&[2]); // must panic cleanly, not deadlock or overwrite
            return;
        };
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

    /// A rejected second guard must not clear the FIRST guard's still-live registration. The
    /// panic hook fires synchronously at the SECOND guard's own panic (before any unwinding, so
    /// before either guard's `Drop` runs), which is why [`two_overlapping_fd2_closes_panics_cleanly`]
    /// passes even if the overlap check runs AFTER the push (that panic's own message is
    /// delivered through the FIRST guard's still-untouched registration regardless). This test
    /// instead CATCHES that first panic, so a LATER, separate panic — while the first guard is
    /// still alive — is what proves whether the rejected second guard's own `Drop` corrupted
    /// `SAVED_STDERR` on its way out.
    #[test]
    fn a_rejected_second_guard_does_not_clear_the_first_guards_slot() {
        let Some(out) = alone_capturing(fixture_path!(
            a_rejected_second_guard_does_not_clear_the_first_guards_slot
        )) else {
            let _first = RestoreStdio::close(&[2]);
            let _file = tempfile::tempfile().expect("open a file that lands at the freed fd 2");
            let result = std::panic::catch_unwind(|| {
                let _second = RestoreStdio::close(&[2]); // rejected; caught, not propagated
            });
            assert!(result.is_err(), "the second, overlapping close must panic");
            drop(_file);
            // `_first` is STILL alive here — this is the whole point: does ITS registration
            // survive the rejected second guard's own unwind?
            panic!(
                "REJECTED_SECOND_GUARD_MARKER: this message must reach real stderr via the \
                 FIRST guard's still-live registration"
            );
        };
        assert_eq!(
            out.status.code(),
            Some(101),
            "the deliberate panic after the caught overlap must exit 101 — got {:?}\n--- stdout \
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
            combined.contains("REJECTED_SECOND_GUARD_MARKER"),
            "the first guard's registration must survive the rejected second guard's own Drop — \
             got:\n{combined}"
        );
    }

    // Panic-hook mechanism =====

    /// A panic while `RestoreStdio` holds fd 2 closed must still reach stderr: before the fix, the
    /// default hook's write to a closed fd 2 failed, and the hook dropped that failure rather than
    /// panicking again.
    #[test]
    fn a_panic_while_fd2_is_closed_still_reaches_stderr() {
        let Some(out) = alone_capturing(fixture_path!(a_panic_while_fd2_is_closed_still_reaches_stderr)) else {
            let _restore = RestoreStdio::close(&[2]);
            panic!("PANIC_WHILE_FD2_CLOSED_MARKER: this message must survive fd 2 being closed");
        };
        // Exit code EXACTLY 101 (an ordinary libtest panic), not merely nonzero: an abort has no
        // defined exit code (commonly reported as 134/SIGABRT).
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
            combined.contains("PANIC_WHILE_FD2_CLOSED_MARKER"),
            "the probe's own panic message must survive fd 2 being closed while it panicked — \
             got:\n{combined}"
        );
    }

    // require_process_per_test's gate =====

    #[test]
    fn gate_rejects_a_non_alone_process() {
        const TRIGGER: &str = "COSCA_TEST_TRIGGER_GATE_REJECTS_A_NON_ALONE_PROCESS";
        if std::env::var_os(TRIGGER).is_some() {
            // The deliberately-spawned, non-alone child: call the gated operation directly.
            let _ = RestoreStdio::close(&[2]);
            return;
        }
        let out = spawn_without_alone_shape(fixture_path!(gate_rejects_a_non_alone_process), None, &[(TRIGGER, "1")]);
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

    #[test]
    fn gate_rejects_a_matching_env_var_with_a_non_alone_argv() {
        const TRIGGER: &str = "COSCA_TEST_TRIGGER_GATE_REJECTS_A_MATCHING_ENV_VAR_WITH_A_NON_ALONE_ARGV";
        if std::env::var_os(TRIGGER).is_some() {
            let _ = RestoreStdio::close(&[2]);
            return;
        }
        let fixture = fixture_path!(gate_rejects_a_matching_env_var_with_a_non_alone_argv);
        let out = spawn_without_alone_shape(fixture, Some(fixture), &[(TRIGGER, "1")]);
        assert_eq!(
            out.status.code(),
            Some(101),
            "a matching COSCA_TEST_ALONE with the WRONG argv shape must still be rejected (exit \
             101) — an env-var-only gate would wrongly accept this. got {:?}\n--- stdout ---\n{}\n\
             --- stderr ---\n{}",
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

    // write_completion_token_if_child: fan-out safety =====

    /// A caller that fans out its OWN further `ALONE_ARGS`-shaped children (like
    /// `linux_cgroup_v2_closed_stdio_slots_cannot_misplace_or_misreport_the_child` in
    /// `tests/spawn_io.rs`) must call [`clear_inherited_completion_token`] on each one, or that
    /// grandchild inherits a stale [`TOKEN_FD_ENV`] naming a fd number that means nothing in its
    /// own fd table. This proves the fallback for a caller that does NOT: forges exactly that
    /// situation directly (a re-exec'd child, shaped like `alone()`'s own, but with `TOKEN_FD_ENV`
    /// pointing at a REGULAR FILE instead of a real pipe — indistinguishable, from an env var
    /// alone, from a stale inherited one) and asserts the child neither aborts nor writes into it.
    #[test]
    fn a_stale_token_fd_pointing_at_a_non_pipe_is_not_touched() {
        use std::os::fd::AsRawFd;

        let name = fixture_path!(a_stale_token_fd_pointing_at_a_non_pipe_is_not_touched);
        const MARKER_PATH_ENV: &str = "COSCA_TEST_STALE_FD_MARKER_PATH";
        let argv: Vec<String> = std::env::args().skip(1).collect();
        if super::alone_marker_matches(Some(name), &argv) {
            // The forged child: `alone(name)` below runs the exact same dispatch a real fixture's
            // does, including `write_completion_token_if_child` — against the FORGED, non-pipe
            // `TOKEN_FD_ENV` our own (non-`spawn_alone`) parent below set up.
            assert!(
                super::alone(name),
                "alone() must recognize this re-exec'd process as its own child"
            );
            let path = std::env::var(MARKER_PATH_ENV).expect("marker path env var");
            let contents = std::fs::read_to_string(&path).expect("read the marker file back");
            assert_eq!(
                contents, "untouched",
                "write_completion_token_if_child must never write into a fd that is not a pipe"
            );
            return;
        }

        let path = std::env::temp_dir().join(format!("cosca-stale-fd-marker-{}", std::process::id()));
        std::fs::write(&path, "untouched").expect("write the marker file");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("reopen the marker file");
        let file_fd = file.as_raw_fd();
        let child = {
            let _guard = super::super::test_spawn_lock();
            // SAFETY: clears FD_CLOEXEC on `file`'s own fd so it survives into the child at the
            // same number — exactly what a REAL stale inheritance would also do, and exactly what
            // `spawn_alone` does for its own, real pipe; held under `test_spawn_lock()` for the
            // same reason.
            unsafe {
                let flags = libc::fcntl(file_fd, libc::F_GETFD);
                assert_ne!(
                    flags,
                    -1,
                    "fcntl(F_GETFD) on the marker file: {}",
                    std::io::Error::last_os_error()
                );
                assert_eq!(
                    libc::fcntl(file_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
                    0,
                    "fcntl(F_SETFD) to make the marker file inheritable: {}",
                    std::io::Error::last_os_error()
                );
            }
            std::process::Command::new(std::env::current_exe().expect("this test binary"))
                .args(std::iter::once(name).chain(super::ALONE_ARGS))
                .env("COSCA_TEST_ALONE", name)
                .env(super::TOKEN_FD_ENV, file_fd.to_string())
                .env(MARKER_PATH_ENV, &path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn the forged child")
        };
        drop(file);
        let out = wait_bounded(child, super::PROBE_TIMEOUT, false);
        let _ = std::fs::remove_file(&path);
        assert!(
            out.status.success(),
            "a stale, non-pipe TOKEN_FD_ENV must never abort or panic the child — got {:?}\n--- \
             stdout ---\n{}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// [`clear_inherited_completion_token`] must actually remove [`TOKEN_FD_ENV`] from the
    /// `Command` it is given — not merely leave the inherited value in place — or a fan-out
    /// caller using it gets no protection at all.
    #[test]
    fn clear_inherited_completion_token_removes_the_env_var() {
        let mut cmd = std::process::Command::new("/bin/true");
        cmd.env(super::TOKEN_FD_ENV, "3");
        super::clear_inherited_completion_token(&mut cmd);
        let removed = cmd
            .get_envs()
            .any(|(key, value)| key == std::ffi::OsStr::new(super::TOKEN_FD_ENV) && value.is_none());
        assert!(
            removed,
            "clear_inherited_completion_token must remove {}, not merely leave it set",
            super::TOKEN_FD_ENV
        );
    }

    // RestoreStdio: duplicate fd, mid-loop restore, no double panic (c4586e0f) =====

    /// `RestoreStdio::close` rejects a repeated fd. In debug, the `debug_assert!` fires first
    /// ("fds must be distinct"); in release it no-ops, but the second pass then tries to dup an
    /// ALREADY-CLOSED fd 2 and panics on THAT `fcntl` failure instead — so this panics, with a
    /// different message, in every build profile.
    #[test]
    fn close_rejects_a_duplicate_fd() {
        let Some(out) = alone_capturing(fixture_path!(close_rejects_a_duplicate_fd)) else {
            let _guard = RestoreStdio::close(&[2, 2]);
            return;
        };
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
        // In debug, the upfront `debug_assert!` ("fds must be distinct") fires before the loop
        // even starts. In release that's a no-op, so the loop runs: the first `2` registers
        // `SAVED_STDERR`, and the SECOND `2` now hits the overlap check — moved BEFORE the dup and
        // the push by finding 1's fix — which sees ITS OWN prior registration as "already
        // occupied" and rejects it the same way a genuinely different second guard would, before
        // ever reaching the dup-aside step.
        let expected = if cfg!(debug_assertions) {
            "fds must be distinct"
        } else {
            "SAVED_STDERR already occupied"
        };
        assert!(
            combined.contains(expected),
            "expected {expected:?} in the panic reachable in this build profile — got:\n{combined}"
        );
    }

    /// When a later fd in the list fails, the guard built so far must still restore the EARLIER
    /// fds it already closed — proving `close`'s incremental-guard construction, not just its
    /// existence. -1 is never a valid fd, so its own `fcntl` dup-aside fails immediately after fd
    /// 2 has already been closed and pushed into the guard, with no dependence on what happens to
    /// be open at any particular number.
    #[test]
    fn close_mid_loop_failure_restores_earlier_fds() {
        let Some(out) = alone_capturing(fixture_path!(close_mid_loop_failure_restores_earlier_fds)) else {
            // SAFETY: -1 is never a valid fd; confirm it is rejected the expected way before
            // relying on that failure to drive the guard's own mid-loop restore below.
            let probe = unsafe { libc::fcntl(-1, libc::F_GETFD) };
            assert_eq!(
                probe, -1,
                "fd -1 must already be invalid before this probe relies on that"
            );
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::Error::from_raw_os_error(libc::EBADF).kind(),
                "fd -1 must fail with EBADF specifically"
            );
            let result = std::panic::catch_unwind(|| {
                let _guard = RestoreStdio::close(&[2, -1]);
            });
            assert!(result.is_err(), "close(&[2, -1]) must panic: fd -1 is never valid");
            // The guard (holding only fd 2, since -1 never got pushed) dropped during unwind and
            // restored fd 2. A closed fd fails F_GETFD with EBADF; the real fd 2 here (piped by
            // `alone_capturing`) accepts it once restored.
            // SAFETY: F_GETFD reads flags only, no ownership implications.
            let flags = unsafe { libc::fcntl(2, libc::F_GETFD) };
            assert_ne!(
                flags,
                -1,
                "fd 2 must be restored after the mid-loop panic unwound the guard: {}",
                std::io::Error::last_os_error()
            );
            eprintln!("CLOSE_MID_LOOP_RESTORE_MARKER: fd 2 is usable again");
            return;
        };
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
            combined.contains("CLOSE_MID_LOOP_RESTORE_MARKER"),
            "the probe must observe fd 2 restored after the mid-loop panic — got:\n{combined}"
        );
    }

    /// `Drop` must not panic a SECOND time while already unwinding an earlier panic (which would
    /// abort the process, `SIGABRT`): sabotages the guard's own restore by tightening
    /// `RLIMIT_NOFILE` to 1 AFTER fd 2 is already closed and dup'd aside — `dup2`ing anything onto
    /// fd 2 (>= the new limit) then fails — then panics for an unrelated reason while the guard is
    /// still alive. `Drop` must report the sabotaged restore without panicking again.
    ///
    /// `rlim_max` comes from a real `getrlimit`, never a hand-picked constant: hardcoding it below
    /// the host's actual hard limit would make `setrlimit` merely LOWER `rlim_max` too (fine on
    /// its own), but hardcoding it ABOVE a LOWER real hard limit would fail outright trying to
    /// RAISE it — passing vacuously either way, since this probe's own setup assert would panic
    /// for a reason that has nothing to do with the scenario under test.
    #[test]
    fn drop_does_not_double_panic() {
        let Some(out) = alone_capturing(fixture_path!(drop_does_not_double_panic)) else {
            let _restore_stdio = RestoreStdio::close(&[2]);
            let mut original: libc::rlimit = unsafe { std::mem::zeroed() };
            // SAFETY: `original` is a valid, correctly-sized out-param.
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) },
                0,
                "getrlimit(RLIMIT_NOFILE): {}",
                std::io::Error::last_os_error()
            );
            #[cfg(target_os = "linux")]
            drop_cap_sys_resource(); // a root probe must sabotage itself too — see finding 11
            let tight = libc::rlimit {
                rlim_cur: 1,
                rlim_max: original.rlim_max,
            };
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &tight) },
                0,
                "tighten RLIMIT_NOFILE for the probe: {}",
                std::io::Error::last_os_error()
            );
            // No `eprintln!` marker here: fd 2 is ALREADY closed by `_restore_stdio` at this
            // point, so an ordinary write to it (which is what `eprintln!` does) would be
            // silently dropped — exactly the failure mode `RestoreStdio::drop`'s own direct
            // write-to-dup exists to avoid. The prover below checks for THAT report instead,
            // which doubles as proving this probe reached its sabotage and as finding 2's own
            // "assert its text in the prover" requirement.
            panic!("triggering an unwind while RestoreStdio::drop's own restore is sabotaged");
        };
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
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        // `RestoreStdio::drop`'s own report of the sabotaged restore must reach stderr — written
        // directly to the guard's saved dup, not through real fd 2 (which is exactly what the
        // sabotage broke). This is also finding 2's own required check: a mutant that deletes
        // that report must fail THIS assertion even though it would leave the exit code alone.
        assert!(
            combined.contains("RestoreStdio::drop:") && combined.contains("while restoring a guarded fd failed"),
            "the guard's own restore-failure report must reach stderr, proving both that the \
             probe reached its sabotage (not an earlier, unrelated failure) and that the report \
             itself was not silently dropped — got:\n{combined}"
        );
    }

    /// Drop CAP_SYS_RESOURCE from this process's own effective/permitted/inheritable sets. As
    /// root (the cgroup lane's own uid), `dup2`'s rlimit check is unaffected by capabilities, but
    /// `setrlimit`'s own — raising `rlim_cur` back past a lowered value — is not, so a root probe
    /// process must strip its own privilege before relying on a tightened rlimit to hold. No
    /// wrapper exists in the `libc` crate for `capget`/`capset`; both are plain syscalls.
    #[cfg(target_os = "linux")]
    fn drop_cap_sys_resource() {
        #[repr(C)]
        struct CapHeader {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct CapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
        const CAP_SYS_RESOURCE: u32 = 24;
        let mut header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        // SAFETY: `header`/`data` are correctly-sized, valid out-params for this process's own
        // capability sets (pid 0 means "self").
        let ret = unsafe { libc::syscall(libc::SYS_capget, std::ptr::addr_of_mut!(header), data.as_mut_ptr()) };
        assert_eq!(ret, 0, "capget: {}", std::io::Error::last_os_error());
        let idx = (CAP_SYS_RESOURCE / 32) as usize;
        let bit = 1u32 << (CAP_SYS_RESOURCE % 32);
        data[idx].effective &= !bit;
        data[idx].permitted &= !bit;
        data[idx].inheritable &= !bit;
        // SAFETY: as above; `header` is the SAME struct capget just filled in (same version).
        let ret = unsafe { libc::syscall(libc::SYS_capset, std::ptr::addr_of_mut!(header), data.as_ptr()) };
        assert_eq!(ret, 0, "capset: {}", std::io::Error::last_os_error());
    }

    // RestoreRlimitNofile: gate (757129d8) =====

    #[test]
    fn gate_rejects_a_non_alone_process_for_rlimit() {
        const TRIGGER: &str = "COSCA_TEST_TRIGGER_GATE_REJECTS_A_NON_ALONE_PROCESS_FOR_RLIMIT";
        if std::env::var_os(TRIGGER).is_some() {
            let _guard = RestoreRlimitNofile::lower_to(64);
            return;
        }
        let out = spawn_without_alone_shape(
            fixture_path!(gate_rejects_a_non_alone_process_for_rlimit),
            None,
            &[(TRIGGER, "1")],
        );
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

    // wait_bounded's real drain thread =====

    /// `wait_bounded` must drain stdout and stderr CONCURRENTLY, not one after the other: a child
    /// that writes more than one pipe buffer to stderr while producing little or no stdout would
    /// otherwise deadlock it, since reading stdout to EOF blocks until the child exits while the
    /// child is itself blocked writing to the undrained stderr pipe. Exercises the real drain
    /// thread `wait_bounded` spawns — the `wait_on_channel_*` tests below bypass it with a
    /// synthetic channel.
    #[test]
    fn wait_bounded_drains_stdout_and_stderr_concurrently() {
        const STDERR_BYTES: usize = 200_000;
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("head -c {STDERR_BYTES} /dev/zero | tr '\\0' 'x' 1>&2"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = {
            let _guard = super::super::test_spawn_lock();
            cmd.spawn().expect("spawn the child")
        };
        let out = wait_bounded(child, super::PROBE_TIMEOUT, false);
        assert!(out.status.success(), "the child must exit cleanly: {:?}", out.status);
        assert_eq!(
            out.stderr.len(),
            STDERR_BYTES,
            "must drain all of stderr, not hang or truncate it while stdout sits empty"
        );
    }

    // wait_on_channel's Timeout/Disconnected arms, and the kill they must perform (665960be) =====

    /// A child that exits ONLY when killed — blocked forever reading `stdin`, whose write end THIS
    /// test holds open — not a timed sleep: a mutant that deletes the kill call must make these
    /// tests hang or fail, not silently pass a few seconds late because the fixture's own lifetime
    /// happened to end anyway.
    fn child_blocked_until_killed() -> (std::process::Child, std::io::PipeWriter) {
        let (read_end, write_end) = std::io::pipe().expect("open blocking pipe");
        let child = {
            let _guard = super::super::test_spawn_lock();
            std::process::Command::new("cat")
                .stdin(read_end)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn a child blocked on stdin")
        };
        (child, write_end)
    }

    /// Proves [`kill_and_reap`] actually terminates a child that would otherwise never exit, via
    /// the exit status's own signal — not `kill(pid, 0)` after the reap, which would test whether
    /// SOME process currently holds this pid, quite possibly a different, later, unrelated one the
    /// OS has already recycled the number for.
    #[test]
    fn kill_and_reap_sends_sigkill() {
        let (child, _write_end_keeps_it_blocked) = child_blocked_until_killed();
        let status = kill_and_reap(child, false);
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL),
            "a child that only exits when killed must show SIGKILL in its own exit status: {status:?}"
        );
    }

    /// `wait_on_channel`'s `Timeout` arm must actually invoke the kill-and-reap path promptly,
    /// rather than hang forever waiting for a child that would otherwise never exit. The SIGKILL
    /// mechanism itself is proven directly by [`kill_and_reap_sends_sigkill`]; downcasting this
    /// panic's own payload lets this test also confirm the signal is the one THIS call path
    /// reports, not merely that some panic occurred.
    #[test]
    fn wait_on_channel_timeout_kills_and_reaps() {
        let (child, _write_end_keeps_it_blocked) = child_blocked_until_killed();
        let (_tx, rx) = std::sync::mpsc::channel::<super::DrainResult>();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wait_on_channel(child, std::time::Duration::from_millis(200), rx, false)
        }));
        let payload = result.expect_err("a blocked-forever child must still make this panic");
        let message = payload
            .downcast_ref::<String>()
            .expect("wait_on_channel's panic payload must be a String");
        assert!(
            message.contains(&format!("signal {:?}", Some(libc::SIGKILL))),
            "the panic message must report the child's own SIGKILL exit status — got: {message}"
        );
    }

    /// `wait_on_channel`'s `Disconnected` arm (the drain side died without a result) must ALSO
    /// kill and reap, exactly like `Timeout` — not just panic and leave the child running. Drops
    /// the sender immediately, so `recv_timeout` observes `Disconnected` right away.
    #[test]
    fn wait_on_channel_disconnected_kills_and_reaps() {
        let (child, _write_end_keeps_it_blocked) = child_blocked_until_killed();
        let (tx, rx) = std::sync::mpsc::channel::<super::DrainResult>();
        drop(tx);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wait_on_channel(child, std::time::Duration::from_secs(10), rx, false)
        }));
        let payload = result.expect_err("a disconnected channel must still make this panic");
        let message = payload
            .downcast_ref::<String>()
            .expect("wait_on_channel's panic payload must be a String");
        assert!(
            message.contains(&format!("signal {:?}", Some(libc::SIGKILL))),
            "the panic message must report the child's own SIGKILL exit status — got: {message}"
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
