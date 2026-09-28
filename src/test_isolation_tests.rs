//! Unit tests for [`crate::test_isolation`]. Lib-only, and NOT nested inside `test_isolation.rs`
//! itself (unlike an ordinary `foo_tests.rs`) — that file is `#[path]`-shared into every
//! integration test binary too (see its own module doc), and `cfg(test)` is true for an
//! integration test binary's own compilation just as it is for `cargo test --lib`'s. A `mod`
//! declared FROM WITHIN the shared file would have compiled and RUN this whole module's real
//! child-process-spawning tests again in every one of those binaries — redundant work, multiplied
//! by however many integration test binaries this crate has. Declaring it here instead, as an
//! ordinary sibling `mod test_isolation_tests;` in `src/lib.rs` (never `#[path]`-shared anywhere),
//! confines it to the one compilation unit it was written for.
//!
//! Being a sibling rather than a child of `test_isolation` (which stays nested exactly where
//! `#[path]`-shared code expects it) means everything this file reaches from there has to be at
//! least `pub(crate)`, not merely private — see the imports below.

use crate::test_isolation::{
    alone, alone_capturing, alone_marker_matches, alone_with_env, kill_and_reap, wait_bounded, wait_on_channel,
    DrainResult, RestoreRlimitNofile, RestoreStdio, ALONE_ARGS, PROBE_TIMEOUT, TOKEN_FD_ENV, TOKEN_PARENT_ENV,
};
// `fixture_path!` IS used throughout this module (every folded probe/prover below); the
// `unused_imports` lint just cannot see through a macro import the way it does an ordinary item.
#[allow(unused_imports)]
use crate::test_isolation::fixture_path;
use crate::test_isolation::spawn_without_alone_shape;

// Overlap contract: a hard assert, before anything is closed =====

/// Opens a SECOND `RestoreStdio` on fd 2 while the first is still alive. Must panic immediately —
/// before the second guard closes or registers anything — with the fix's own message reaching
/// stderr, in every build profile (a plain `assert!`, not `debug_assert!`).
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

// Completion: only a normal return writes the token, never a bare zero exit =====

/// A body that calls `std::process::exit(0)` partway through must NOT produce a completion
/// token, even though its own exit status is a plain, ordinary success — `std::process::exit`
/// skips every live value's `Drop`, the `Completion` guard `alone()` handed the child included.
/// Before this fix, the token was written the moment `alone()` recognized the child, BEFORE the
/// real body even started, so this exact case reported as a full pass.
///
/// Dispatches manually rather than through `alone()` itself: `alone()`'s own parent branch
/// already asserts pass-and-completed internally and would panic on this deliberately-incomplete
/// child before this test got the chance to inspect `completed` itself. `alone_with_env` is the
/// lower-level primitive that hands both back without asserting anything.
#[test]
fn a_body_that_exits_early_produces_no_token() {
    let name = fixture_path!(a_body_that_exits_early_produces_no_token);
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if alone_marker_matches(std::env::var("COSCA_TEST_ALONE").ok().as_deref(), &argv) {
        // The re-exec'd child: get a REAL Completion (installs the REAL lifeline watcher too —
        // same as any other alone() child) but never let it drop normally.
        let _completion = alone(name);
        std::process::exit(0);
    }
    let (out, completed) = alone_with_env(name, &[]);
    assert!(
        out.status.success(),
        "the probe's own deliberate std::process::exit(0) must itself report success — got {:?}\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !completed,
        "a body that exits early (std::process::exit(0), skipping every live value's Drop) must \
         NOT produce a completion token even though its own exit status is a plain success"
    );
}

// write_completion_token_if_child: fan-out safety (N5) =====

/// A caller that fans out its OWN further `ALONE_ARGS`-shaped children (like the closed-std-slots
/// sweep in `tests/spawn_io.rs`) has each one inherit `TOKEN_FD_ENV`/`TOKEN_PARENT_ENV` from ITS
/// parent, naming a fd number and an expected-parent pid that mean nothing to the grandchild's
/// own, freshly-forked identity. This proves the fallback that matters regardless of what the
/// leaked fd number happens to alias: forges exactly that situation directly — a re-exec'd child,
/// shaped like `alone()`'s own, given a REAL, valid pipe for `TOKEN_FD_ENV`, but a
/// `TOKEN_PARENT_ENV` that does NOT match this process's real, immediate parent (its actual
/// parent is this test itself, not the forged pid) — and asserts the child never writes into it.
#[test]
fn a_ppid_mismatch_is_never_honored_even_with_a_real_pipe() {
    use std::os::fd::AsRawFd;

    let name = fixture_path!(a_ppid_mismatch_is_never_honored_even_with_a_real_pipe);
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if alone_marker_matches(Some(name), &argv) {
        // The forged child: `alone(name)` below runs the exact same dispatch a real fixture's
        // does, including the eventual `Completion`-triggered write — against the FORGED
        // `TOKEN_PARENT_ENV` our own (non-`spawn_alone`) parent below set up.
        let Some(_completion) = alone(name) else {
            unreachable!("alone_marker_matches just confirmed this process is the child");
        };
        return;
    }

    let (mut token_read, token_write) = std::io::pipe().expect("open a real completion-token pipe");
    let token_write_fd = token_write.as_raw_fd();
    // Never a real pid, under any process: `getppid()` always returns a positive value, so `-1`
    // can never match it regardless of what process this test happens to run as (a small pid,
    // even 1, is a real possibility inside a container's own pid namespace, and would have made
    // this forgery accidentally correct instead of wrong).
    const DEFINITELY_WRONG_PARENT: &str = "-1";
    let child = {
        let _guard = super::test_spawn_lock();
        // SAFETY: clears FD_CLOEXEC on our own token pipe's write end so it survives into the
        // child at the same fd number — exactly what `spawn_alone` itself does for a genuine
        // child; held under `test_spawn_lock()` for the same reason.
        unsafe {
            let flags = libc::fcntl(token_write_fd, libc::F_GETFD);
            assert_ne!(
                flags,
                -1,
                "fcntl(F_GETFD) on the token pipe: {}",
                std::io::Error::last_os_error()
            );
            assert_eq!(
                libc::fcntl(token_write_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
                0,
                "fcntl(F_SETFD) to make the token pipe inheritable: {}",
                std::io::Error::last_os_error()
            );
        }
        let child = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args(std::iter::once(name).chain(ALONE_ARGS))
            .env("COSCA_TEST_ALONE", name)
            .env(TOKEN_FD_ENV, token_write_fd.to_string())
            .env(TOKEN_PARENT_ENV, DEFINITELY_WRONG_PARENT)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the forged child");
        drop(token_write);
        child
    };
    let out = wait_bounded(child, PROBE_TIMEOUT, false);
    let mut token = Vec::new();
    use std::io::Read;
    let _ = token_read.read_to_end(&mut token);
    assert!(
        out.status.success(),
        "a ppid-mismatched TOKEN_PARENT_ENV must never abort or panic the child, only skip the \
         write — got {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        token.is_empty(),
        "write_completion_token_if_child must never write into a real, valid pipe when \
         TOKEN_PARENT_ENV does not match this process's real, immediate parent — got {token:?}"
    );
}

/// [`crate::test_isolation::write_completion_token_if_child`]'s OTHER, complementary defense: even
/// with a MATCHING `TOKEN_PARENT_ENV` (this test's own pid — the forged child's real, immediate
/// parent), a `TOKEN_FD_ENV` that names a REGULAR FILE instead of a pipe must still never be
/// written to.
///
/// The marker file is read back by THE PARENT, after `wait_bounded` — never by the child itself.
/// An earlier version of this test read it back inside the child, right after `alone(name)`
/// returned — before the child's own body had even finished, let alone before `Completion::drop`
/// (which is what would actually perform the write, per N1) had run. That version passed even
/// with the `fstat` guard deleted outright (round 7 review, confirmed: `OBSERVED_MARKER_CONTENTS
/// = Ok("1ntouched")` — the write DID land, the assertion just ran before it, every time). Reading
/// the file back only after the WHOLE child process has exited — guaranteeing `Completion::drop`
/// already ran, whichever way — is what actually exercises the guard.
#[test]
fn a_non_pipe_fd_is_never_touched_even_with_a_matching_ppid() {
    use std::os::fd::AsRawFd;

    let name = fixture_path!(a_non_pipe_fd_is_never_touched_even_with_a_matching_ppid);
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if alone_marker_matches(Some(name), &argv) {
        let Some(_completion) = alone(name) else {
            unreachable!("alone_marker_matches just confirmed this process is the child");
        };
        // No in-child check at all — see the doc above for why: the parent is the only place
        // that can observe the outcome of this process's own `Completion::drop`, which runs
        // AFTER this function returns, not before.
        return;
    }

    let path = std::env::temp_dir().join(format!("cosca-stale-fd-marker-{}", std::process::id()));
    std::fs::write(&path, "untouched").expect("write the marker file");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("reopen the marker file");
    let file_fd = file.as_raw_fd();
    let this_pid = std::process::id().to_string();
    let child = {
        let _guard = super::test_spawn_lock();
        // SAFETY: clears FD_CLOEXEC on `file`'s own fd so it survives into the child at the
        // same number — exactly what a real, valid token pipe would too; held under
        // `test_spawn_lock()` for the same reason.
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
        let child = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args(std::iter::once(name).chain(ALONE_ARGS))
            .env("COSCA_TEST_ALONE", name)
            .env(TOKEN_FD_ENV, file_fd.to_string())
            .env(TOKEN_PARENT_ENV, &this_pid)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the forged child");
        drop(file);
        child
    };
    // The child has now fully exited — its own `Completion::drop` (whichever way it resolved)
    // has already run. ONLY NOW is the marker file's content meaningful.
    let out = wait_bounded(child, PROBE_TIMEOUT, false);
    let contents = std::fs::read_to_string(&path).expect("read the marker file back");
    let _ = std::fs::remove_file(&path);
    assert!(
        out.status.success(),
        "a stale, non-pipe TOKEN_FD_ENV must never abort or panic the child — got {:?}\n--- \
         stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        contents, "untouched",
        "write_completion_token_if_child must never write into a fd that is not a pipe — got {contents:?}"
    );
}

// The lifeline: a dead harness process must not leave a re-exec'd child (or its own further
// grandchild) running (N2) =====

const LIFELINE_TRIGGER_ENV: &str = "COSCA_TEST_TRIGGER_LIFELINE_SURROGATE_PARENT";
const LIFELINE_READY_ADDR_ENV: &str = "COSCA_TEST_LIFELINE_READY_ADDR";
const LIFELINE_CHILD_CANARY_FD_ENV: &str = "COSCA_TEST_LIFELINE_CHILD_CANARY_FD";
const LIFELINE_GRANDCHILD_CANARY_FD_ENV: &str = "COSCA_TEST_LIFELINE_GRANDCHILD_CANARY_FD";
/// Bounds every wait this prover itself performs (the readiness accept, the two canary reads) —
/// distinct from [`PROBE_TIMEOUT`] only so a regression here reads as "the lifeline tree never
/// came up / never died", not conflated with `spawn_alone`'s own, unrelated bound.
const LIFELINE_WAIT: std::time::Duration = PROBE_TIMEOUT;

/// N2's own prover, in ONE `#[test] fn` playing all three roles by dispatching on env triggers —
/// like every other prover in this file, NOT three separate `#[test] fn`s. An earlier version had
/// the surrogate-parent and lifeline-child bodies as their own, separately-named `#[test] fn`s,
/// each guarded by "return immediately if my own trigger env var is absent" — meaning both showed
/// up in an ordinary `cargo test`/`nextest run` listing and reported PASS on every normal run,
/// having tested nothing: exactly the silent-pass shape `docs/principles.md`'s principle 9
/// ("tests fail loudly and never silently skip") forbids. Folding them here removes the two
/// always-passing entries entirely.
///
/// Three real processes: this test (never killed) spawns the SURROGATE PARENT — the ONE process
/// the test kills directly, standing in for a nextest-managed single-test process the runner
/// itself kills on a timeout — as a raw, manually-argv'd re-exec (NOT through `spawn_alone`, which
/// would itself wait for it to exit, defeating the point of killing it mid-flight). The surrogate
/// parent's own job is to become a REAL `spawn_alone` PARENT for the LIFELINE CHILD via an
/// ordinary `alone_with_env` call, so the child's lifeline is tied to it for real, not simulated.
/// The lifeline child spawns its OWN grandchild (a plain, long-blocked process — inherits both
/// canary fds automatically, non-`CLOEXEC`, the same way any child does), closes its own
/// now-redundant copy of the grandchild's canary immediately (so that canary's EOF proves the
/// GRANDCHILD's death specifically, not merely this process's own), signals the test that the
/// whole tree is up, then blocks on the grandchild itself — never returning normally in the
/// scenario this proves: the surrogate parent is killed before either of these two processes get
/// the chance to exit on their own.
///
/// Killing the direct process a re-exec'd `alone()` child's lifeline is tied to must kill that
/// child AND a grandchild it spawned into its own process group — not leave either running,
/// orphaned under init, immune to the group-kill mechanism that already covers a hang THIS process
/// notices (see `spawn_alone`'s own `setpgid(0, 0)`; measured without the lifeline: a real nextest
/// TIMEOUT left the child alive with parent pid 1).
#[test]
fn a_dead_parent_kills_its_lifeline_child_and_grandchild() {
    use std::os::fd::AsRawFd;

    let name = fixture_path!(a_dead_parent_kills_its_lifeline_child_and_grandchild);
    let argv: Vec<String> = std::env::args().skip(1).collect();

    // Level 2: the lifeline child — recognized by `alone()`'s own argv/env shape, since this
    // process is what a REAL `spawn_alone` call (made below, by level 1) launches.
    if alone_marker_matches(Some(name), &argv) {
        let Some(_completion) = alone(name) else {
            unreachable!("alone_marker_matches just confirmed this process is the child");
        };
        let addr = std::env::var(LIFELINE_READY_ADDR_ENV).expect("ready addr env var");
        let grandchild_canary_fd: i32 = std::env::var(LIFELINE_GRANDCHILD_CANARY_FD_ENV)
            .expect("grandchild canary fd env var")
            .parse()
            .expect("valid fd number");

        // The grandchild: `spawn_alone`'s own `setpgid(0, 0)` already made this process the
        // leader of a fresh group, and an ordinary child inherits its parent's pgid at fork time
        // — no further setpgid call is needed for it to land in the SAME group this fixture's
        // own lifeline watcher (installed by `alone()` above) will `kill(0, SIGKILL)` on EOF.
        let mut grandchild = {
            let _guard = super::test_spawn_lock();
            std::process::Command::new("sleep")
                .arg("1000")
                .spawn()
                .expect("spawn the grandchild")
        };
        // SAFETY: closes our own, now-redundant copy of the grandchild's canary fd — the
        // grandchild's own inherited copy, made just above, is unaffected. Without this, the
        // canary's EOF would require BOTH this process and the grandchild to exit, instead of
        // proving the grandchild's death specifically.
        unsafe {
            libc::close(grandchild_canary_fd);
        }

        let mut sock = std::net::TcpStream::connect(&addr).expect("connect back to the test");
        use std::io::Write;
        sock.write_all(b"1").expect("signal readiness");

        // Blocks until the grandchild exits — which, in the scenario this proves, happens only
        // once the group-kill this process's own watcher thread issues (on its lifeline's EOF)
        // reaches it too. If this ever returns normally instead, nothing here asserts on it:
        // this whole process is expected to be SIGKILL'd well before reaching this point in the
        // run this test drives.
        let _ = grandchild.wait();
        return;
    }

    // Level 1: the surrogate parent — recognized by its OWN trigger env var, never `alone()`'s
    // shape (this process must stay under the TEST's manual `Child` control below, killable
    // directly; going through `alone()`/`spawn_alone` here would hand that control to an
    // internal, auto-waiting call instead).
    if std::env::var_os(LIFELINE_TRIGGER_ENV).is_some() {
        let addr = std::env::var(LIFELINE_READY_ADDR_ENV).expect("ready addr env var");
        let child_canary_fd = std::env::var(LIFELINE_CHILD_CANARY_FD_ENV).expect("child canary fd env var");
        let grandchild_canary_fd =
            std::env::var(LIFELINE_GRANDCHILD_CANARY_FD_ENV).expect("grandchild canary fd env var");
        // Blocks until the child (and, transitively, its own grandchild) exits — which, in the
        // scenario this proves, never happens through this call at all: the test kills THIS
        // process first. `alone_with_env`'s own bounded wait is a safety net for anything else
        // going wrong, not what this prover relies on.
        let _ = alone_with_env(
            name,
            &[
                (LIFELINE_READY_ADDR_ENV, addr.as_str()),
                (LIFELINE_CHILD_CANARY_FD_ENV, child_canary_fd.as_str()),
                (LIFELINE_GRANDCHILD_CANARY_FD_ENV, grandchild_canary_fd.as_str()),
            ],
        );
        return;
    }

    // Level 0: the test itself.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = listener.local_addr().expect("listener local addr").to_string();

    let (child_canary_read, child_canary_write) = std::io::pipe().expect("open child canary pipe");
    let (grandchild_canary_read, grandchild_canary_write) = std::io::pipe().expect("open grandchild canary pipe");
    let child_canary_fd = child_canary_write.as_raw_fd();
    let grandchild_canary_fd = grandchild_canary_write.as_raw_fd();

    let mut surrogate = {
        let _guard = super::test_spawn_lock();
        // SAFETY: clears FD_CLOEXEC on both canary write ends so they survive exec into the
        // surrogate parent, and from there plain fork+exec inheritance carries them further down
        // through the child to the grandchild — untouched by any of `spawn_alone`'s own machinery,
        // which only ever clears CLOEXEC on ITS OWN token/lifeline fds, never an unrelated one.
        for fd in [child_canary_fd, grandchild_canary_fd] {
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                assert_ne!(
                    flags,
                    -1,
                    "fcntl(F_GETFD) on fd {fd}: {}",
                    std::io::Error::last_os_error()
                );
                assert_eq!(
                    libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
                    0,
                    "fcntl(F_SETFD) to make fd {fd} inheritable: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        let child = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([name, "--exact", "--nocapture", "--test-threads=1"])
            .env(LIFELINE_TRIGGER_ENV, "1")
            .env(LIFELINE_READY_ADDR_ENV, &addr)
            .env(LIFELINE_CHILD_CANARY_FD_ENV, child_canary_fd.to_string())
            .env(LIFELINE_GRANDCHILD_CANARY_FD_ENV, grandchild_canary_fd.to_string())
            // Never read (this test observes the tree only through the readiness connection and
            // the two canary pipes below) — `null()`, not `piped()`, so libtest's own banner text
            // can never fill a pipe buffer nobody drains.
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn the surrogate parent");
        drop(child_canary_write);
        drop(grandchild_canary_write);
        child
    };

    // Blocks until the whole tree (surrogate parent -> child -> grandchild) is confirmed up —
    // never a sleep-then-check: accepting the real event, the child's own connect-back — but
    // bounded: if the tree never comes up (a regression upstream of what this prover itself
    // covers), this must read as "it hung", not hang the whole run indefinitely alongside it.
    let (accept_tx, accept_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let accepted = listener.accept();
        let _ = accept_tx.send(accepted);
    });
    let mut sock = match accept_rx.recv_timeout(LIFELINE_WAIT) {
        Ok(Ok((sock, _))) => sock,
        Ok(Err(e)) => panic!("accepting the readiness connection failed: {e}"),
        Err(_) => panic!(
            "the surrogate parent -> lifeline child -> grandchild tree never signalled \
             readiness within {LIFELINE_WAIT:?}"
        ),
    };
    let mut tag = [0u8; 1];
    use std::io::Read;
    sock.read_exact(&mut tag).expect("read the readiness tag");

    // The scenario under test: kill ONLY the direct surrogate parent process — exactly what a
    // nextest TIMEOUT does to the one process it manages — never the child, which is a different
    // process group entirely (`spawn_alone`'s own `setpgid(0, 0)`).
    surrogate.kill().expect("kill the surrogate parent");
    let _ = surrogate.wait();

    // Bounded reads, not a bare blocking one: a regression here means the tree survives forever,
    // so this failure must read as "it hung", not silently hang the whole test suite along with it.
    for (label, mut read_end) in [("child", child_canary_read), ("grandchild", grandchild_canary_read)] {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = read_end.read_to_end(&mut buf);
            let _ = tx.send(());
        });
        rx.recv_timeout(LIFELINE_WAIT).unwrap_or_else(|_| {
            panic!(
                "the {label} must die (its own canary pipe must EOF) once the surrogate parent \
                 that launched it is killed out from under it — the lifeline watcher thread must \
                 self-destruct this process's own group on EOF, reaching every process in it, not \
                 just the direct child"
            )
        });
    }
}

// spawn_alone's OWN whole-group timeout kill (N3/N4) =====

const HANGING_CANARY_FD_ENV: &str = "COSCA_TEST_HANGING_CANARY_FD";

/// `spawn_alone`'s own `wait_bounded(child, PROBE_TIMEOUT, true)` — the bounded wait EVERY
/// `alone()`/`alone_capturing()`/`alone_with_env` call goes through — had no direct prover:
/// changing that call's `true` to `false` (own_process_group) left every other test in this file
/// passing (measured, round 7 review). This is that prover: a fixture whose body, once recognized
/// as `alone()`'s own child, spawns a grandchild holding the only remaining copy of a canary
/// pipe's write end and then hangs forever (blocks on that same grandchild, which itself never
/// exits on its own) — never returning, so `spawn_alone`'s real, hardcoded `PROBE_TIMEOUT` (30s,
/// not a shorter one this test picks) genuinely elapses and its real `wait_on_channel` `Timeout`
/// arm fires `kill_and_reap(child, true)`, the exact call under test, before panicking (expected,
/// caught below — `kill_and_reap` has already run by the time that panic unwinds out).
///
/// Same one-`#[test]`-fn, dispatch-on-recognition shape as every other prover here, not a
/// separately-named, always-passing fixture fn (principle 9).
#[test]
fn spawn_alones_own_timeout_kill_reaches_a_grandchild() {
    use std::os::fd::AsRawFd;

    let name = fixture_path!(spawn_alones_own_timeout_kill_reaches_a_grandchild);
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if alone_marker_matches(Some(name), &argv) {
        let Some(_completion) = alone(name) else {
            unreachable!("alone_marker_matches just confirmed this process is the child");
        };
        let canary_fd: i32 = std::env::var(HANGING_CANARY_FD_ENV)
            .expect("canary fd env var")
            .parse()
            .expect("valid fd number");
        // The grandchild: same reasoning as the lifeline prover above — this process is already
        // the leader of its own fresh group (`spawn_alone`'s own `setpgid(0, 0)`), so an ordinary
        // child inherits that group at fork time, with no further setpgid call needed.
        let mut grandchild = {
            let _guard = super::test_spawn_lock();
            std::process::Command::new("sleep")
                .arg("1000")
                .spawn()
                .expect("spawn the grandchild")
        };
        // SAFETY: closes our own, now-redundant copy — the grandchild's own inherited copy, made
        // just above, is unaffected. Without this, the canary's EOF would require BOTH this
        // process and the grandchild to exit, instead of proving the grandchild's death
        // specifically (which is what the group kill under test must reach).
        unsafe {
            libc::close(canary_fd);
        }
        // Hangs forever — the point. `wait()` on the equally-hanging grandchild rather than an
        // arbitrary blocking read: this process must never return normally, and the grandchild
        // never exits on its own either, so this blocks for as long as this process itself
        // survives — which, in the run this test drives, ends only when the group kill under
        // test reaches it.
        let _ = grandchild.wait();
        return;
    }

    use std::io::Read;
    let (mut canary_read, canary_write) = std::io::pipe().expect("open canary pipe");
    let canary_fd = canary_write.as_raw_fd();
    {
        let _guard = super::test_spawn_lock();
        // SAFETY: clears FD_CLOEXEC on the canary's write end so it survives exec into the
        // fixture, and from there plain fork inheritance carries it into the grandchild — held
        // under `test_spawn_lock()` for the same reason `spawn_alone` itself does this.
        unsafe {
            let flags = libc::fcntl(canary_fd, libc::F_GETFD);
            assert_ne!(
                flags,
                -1,
                "fcntl(F_GETFD) on the canary pipe: {}",
                std::io::Error::last_os_error()
            );
            assert_eq!(
                libc::fcntl(canary_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
                0,
                "fcntl(F_SETFD) to make the canary pipe inheritable: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    // `alone_with_env` panics when its own `spawn_alone` call's `wait_bounded` times out (an
    // ordinary, expected outcome of THIS SPECIFIC scenario — every OTHER caller in this file
    // treats that panic as a genuine failure, which is exactly why this one must be the only
    // place that deliberately catches it): `kill_and_reap` has already run, synchronously,
    // before that panic unwinds out to here, so the group kill under test has already happened
    // by the time this returns.
    let canary_write_fd_str = canary_fd.to_string();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        alone_with_env(name, &[(HANGING_CANARY_FD_ENV, canary_write_fd_str.as_str())])
    }));
    drop(canary_write);
    assert!(
        result.is_err(),
        "a hanging alone body must make spawn_alone's own wait_bounded time out and panic — a \
         silent return here would mean the real PROBE_TIMEOUT never elapsed, or elapsed without \
         reaching the Timeout arm under test"
    );

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = canary_read.read_to_end(&mut buf);
        let _ = tx.send(());
    });
    rx.recv_timeout(PROBE_TIMEOUT).unwrap_or_else(|_| {
        panic!(
            "spawn_alone's own timeout-triggered kill_and_reap(child, true) must reach the \
             grandchild too, via the group kill — its own canary pipe must EOF, not stay open \
             forever"
        )
    });
}

// RestoreStdio: duplicate fd, mid-loop restore, no double panic =====

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
    // `SAVED_STDERR`, and the SECOND `2` now hits the overlap check — checked BEFORE the dup and
    // the push — which sees ITS OWN prior registration as "already occupied" and rejects it the
    // same way a genuinely different second guard would, before ever reaching the dup-aside step.
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
        // which doubles as proving this probe reached its sabotage.
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
    // sabotage broke). A mutant that deletes that report must fail THIS assertion even though it
    // would leave the exit code alone.
    assert!(
        combined.contains("RestoreStdio::drop:") && combined.contains("while restoring a guarded fd failed"),
        "the guard's own restore-failure report must reach stderr, proving both that the \
         probe reached its sabotage (not an earlier, unrelated failure) and that the report \
         itself was not silently dropped — got:\n{combined}"
    );
}

// RestoreRlimitNofile: gate =====

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
        let _guard = super::test_spawn_lock();
        cmd.spawn().expect("spawn the child")
    };
    let out = wait_bounded(child, PROBE_TIMEOUT, false);
    assert!(out.status.success(), "the child must exit cleanly: {:?}", out.status);
    assert_eq!(
        out.stderr.len(),
        STDERR_BYTES,
        "must drain all of stderr, not hang or truncate it while stdout sits empty"
    );
}

// wait_on_channel's Timeout/Disconnected arms, and the kill they must perform =====

/// A child that exits ONLY when killed — blocked forever reading `stdin`, whose write end THIS
/// test holds open — not a timed sleep: a mutant that deletes the kill call must make these
/// tests hang or fail, not silently pass a few seconds late because the fixture's own lifetime
/// happened to end anyway.
fn child_blocked_until_killed() -> (std::process::Child, std::io::PipeWriter) {
    let (read_end, write_end) = std::io::pipe().expect("open blocking pipe");
    let child = {
        let _guard = super::test_spawn_lock();
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

/// `kill_and_reap(_, true)` — the own-process-group path — is what `wait_on_channel`'s
/// timeout/disconnect arms use for an `alone()`-shaped child, but neither of those tests below
/// actually puts its own blocked child in a separate group, so neither exercises it. This does,
/// directly: a leader (its own new group, `setpgid(0, 0)` via `pre_exec`, the same call
/// `spawn_alone` itself makes) plus a grandchild it spawns into that SAME group, both blocked
/// until killed. The grandchild's own death is observed through a canary pipe only IT holds — its
/// own copy closed by the leader immediately after spawning it — so EOF proves the GROUP kill
/// reached the grandchild specifically, not merely that the direct leader died (which
/// `kill_and_reap`'s own `child.wait()` already confirms, trivially, for every call).
#[test]
fn kill_and_reap_with_own_process_group_reaches_a_grandchild() {
    run_kill_and_reap_own_process_group_scenario();
}

/// The same scenario as [`kill_and_reap_with_own_process_group_reaches_a_grandchild`], but with
/// fds 3 through 12 deliberately occupied first — a direct regression test for the exact bug
/// round 7's review found and reported a deterministic repro for: this test's own pipes, and
/// hence the fixed targets `dup2` moves them to inside the leader, are chosen independently of
/// whatever else happens to be open in the CURRENT process — under a shared, long-running test
/// binary (or, as measured, plain `cargo test` specifically, which shares one process across many
/// tests, unlike nextest's one-process-per-test) they can land anywhere. Occupying a wide,
/// contiguous low range first is what actually forces the pipes themselves above it, proving the
/// fix holds regardless of this process's own ambient fd usage, not merely in whatever state this
/// binary happens to start a test run in.
#[test]
fn kill_and_reap_with_own_process_group_reaches_a_grandchild_with_high_fds_occupied() {
    let _occupied: Vec<std::fs::File> = (3..=12)
        .map(|_| std::fs::File::open("/dev/null").expect("open /dev/null"))
        .collect();
    run_kill_and_reap_own_process_group_scenario();
}

fn run_kill_and_reap_own_process_group_scenario() {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    let (mut canary_read, canary_write) = std::io::pipe().expect("open canary pipe");
    let canary_fd = canary_write.as_raw_fd();
    // A SEPARATE readiness pipe, read for exactly one byte before this test ever calls
    // `kill_and_reap` — without it, killing the leader races its own script: nothing guarantees
    // the leader has reached `sleep 1000 &` (spawning the grandchild at all) before this test's
    // own kill lands, and a leader killed that early leaves no grandchild for the canary to have
    // ever proven anything about, passing vacuously. The leader writes to this only AFTER both
    // backgrounding the grandchild and closing its own canary copy — a real, ordered event, not a
    // sleep guessing at how long that takes.
    let (mut ready_read, ready_write) = std::io::pipe().expect("open readiness pipe");
    let ready_fd = ready_write.as_raw_fd();
    // Fixed, single-digit targets for the shell script below to reference — NOT `canary_fd`
    // and `ready_fd`'s own, dynamically-allocated numbers. `dash` (Debian/Ubuntu's `/bin/sh`)
    // only parses a SINGLE digit after `>&`/before `>&-` in these redirections; this test's own
    // pipes can otherwise land at fd 10 or higher (measured, round 7 review: under a shared test
    // process with enough already open, they routinely do), which `dash` then rejects with exit
    // 127 — silently, well before the leader ever reaches the readiness write, leaving `sleep
    // 1000` backgrounded and this test's own readiness read blocked for however long whatever
    // else eventually bounds it (measured: 655s, then `UnexpectedEof`). `dup2`ing onto fixed,
    // known-single-digit numbers in `pre_exec` sidesteps `dash`'s own parsing limit entirely,
    // regardless of what this process's own pipe fds happen to number.
    const FIXED_CANARY_FD: libc::c_int = 3;
    const FIXED_READY_FD: libc::c_int = 4;
    let leader = {
        let _guard = super::test_spawn_lock();
        // SAFETY: clears FD_CLOEXEC on both pipes' write ends so they survive exec into the
        // leader, and from there plain fork inheritance carries the canary further down into
        // whatever the leader itself spawns — held under `test_spawn_lock()` for the same reason
        // `spawn_alone` does. Belt-and-suspenders with the `pre_exec` `dup2` below: if `dup2`'s
        // own source and target numbers ever happened to coincide (a same-fd `dup2` is a no-op
        // per POSIX, including for `FD_CLOEXEC`), this is what would still guarantee the fd
        // survives the exec.
        for fd in [canary_fd, ready_fd] {
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                assert_ne!(
                    flags,
                    -1,
                    "fcntl(F_GETFD) on fd {fd}: {}",
                    std::io::Error::last_os_error()
                );
                assert_eq!(
                    libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
                    0,
                    "fcntl(F_SETFD) to make fd {fd} inheritable: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg(
            // Backgrounds the grandchild (inherits both fixed fds, still open at this point),
            // closes THIS process's own copy of the canary (so only the grandchild is left
            // holding it), THEN signals readiness and closes that fd too, before blocking in
            // `wait` — the write can only happen after both prior steps completed.
            format!("sleep 1000 & exec {FIXED_CANARY_FD}>&- ; printf r >&{FIXED_READY_FD} ; exec {FIXED_READY_FD}>&- ; wait"),
        )
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
        // SAFETY: async-signal-safe; `setpgid` is the exact same technique `spawn_alone` itself
        // uses. The two `dup2`s move the pipe ends to `FIXED_CANARY_FD`/`FIXED_READY_FD`
        // regardless of their own original numbers, then close whichever original number is
        // left over (a `dup2(fd, fd)` no-op leaves nothing to close, hence the guard) — this
        // runs in the FORKED CHILD, after `fork` and before `exec`, so it can never affect this
        // test's own fd table.
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(canary_fd, FIXED_CANARY_FD) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(ready_fd, FIXED_READY_FD) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if canary_fd != FIXED_CANARY_FD && canary_fd != FIXED_READY_FD {
                    libc::close(canary_fd);
                }
                if ready_fd != FIXED_CANARY_FD && ready_fd != FIXED_READY_FD {
                    libc::close(ready_fd);
                }
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn the leader");
        drop(canary_write);
        drop(ready_write);
        child
    };

    // Blocks until the leader confirms it has ALREADY backgrounded the grandchild and closed its
    // own canary copy — but bounded: a leader that never reaches the readiness write (this
    // exact test's own round-7 regression, before the `dup2`-onto-fixed-numbers fix above) must
    // read as "it hung", not hang the whole run indefinitely alongside it.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut ready = [0u8; 1];
        let result = ready_read.read_exact(&mut ready);
        let _ = ready_tx.send(result);
    });
    match ready_rx.recv_timeout(PROBE_TIMEOUT) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("reading the leader's readiness byte failed: {e}"),
        Err(_) => panic!("the leader never signalled readiness within {PROBE_TIMEOUT:?}"),
    }

    kill_and_reap(leader, true);

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = canary_read.read_to_end(&mut buf);
        let _ = tx.send(());
    });
    rx.recv_timeout(PROBE_TIMEOUT).unwrap_or_else(|_| {
        panic!(
            "kill_and_reap(_, true) must reach the grandchild too, via the group kill — its own \
             canary pipe must EOF, not stay open forever"
        )
    });
}

/// `wait_on_channel`'s `Timeout` arm must actually invoke the kill-and-reap path promptly,
/// rather than hang forever waiting for a child that would otherwise never exit. The SIGKILL
/// mechanism itself is proven directly by [`kill_and_reap_sends_sigkill`]; downcasting this
/// panic's own payload lets this test also confirm the signal is the one THIS call path
/// reports, not merely that some panic occurred.
#[test]
fn wait_on_channel_timeout_kills_and_reaps() {
    let (child, _write_end_keeps_it_blocked) = child_blocked_until_killed();
    let (_tx, rx) = std::sync::mpsc::channel::<DrainResult>();
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
    let (tx, rx) = std::sync::mpsc::channel::<DrainResult>();
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
