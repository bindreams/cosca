//! Unit tests for the sync spawn path: error-path teardown (driven by the shared `fault` seam,
//! defined in `super` and also used by `src/tokio/spawn_tests.rs`), the elevation branch, and the
//! Windows backend router, and that a refused spawn refuses before it touches our handle
//! inheritance. In the library (not `tests/`) because the seam is `pub(crate)`/`#[cfg(test)]` and
//! only reachable from within the crate. The batch gate's tests are in `spawn/batch_gate_tests.rs`.

use super::fault;
use crate::command::Command;
use crate::error::Error;

// A long-lived child, so a teardown leak would show as an alive process at the assert rather than
// self-exiting.
fn blocker() -> Command {
    let mut cmd = Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd
}

// A failed sync spawn must fully reap its child, not leak it. Each error arm is forced via the seam
// (which records the child's real identity); `fault::assert_child_reaped` then proves it was reaped.

#[test]
fn identity_failure_reaps_the_spawned_child() {
    fault::set_force_identity_vanished(true);
    let mut cmd = blocker();
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);

    let err = err.expect("forced identity-vanish must make spawn return Err");
    assert!(
        matches!(err, Error::Io(_)),
        "identity-vanish surfaces as an Io error, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

#[test]
fn attach_failure_reaps_the_spawned_child() {
    fault::set_force_attach_failure(true);
    let mut cmd = blocker();
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);

    let err = err.expect("forced attach failure must make spawn return Err");
    assert!(
        matches!(err, Error::Containment { .. }),
        "a real attach failure surfaces as Error::Containment, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// A reap that FAILS during teardown must leave a trace in a release build, where the
/// `debug_assert` beside it is compiled out: a `log::warn!` naming the error. Both teardown arms —
/// attach failure and unresolved identity — share the one teardown, and each is driven here.
///
/// Each leg's forced error carries its own marker, and records are scanned from a mark taken just
/// before, so a concurrent test's warning cannot satisfy this one.
#[test]
fn a_failed_teardown_reap_is_logged_on_both_arms() {
    a_failed_teardown_step_is_logged_on_both_arms(
        ["cosca-reap-fail-attach-7c1e", "cosca-reap-fail-identity-b93d"],
        fault::set_force_reap_failure,
        fault::take_force_reap_failure,
    );
}

/// A KILL that fails is logged, and the teardown does NOT go on to a blocking reap: a child it
/// could not kill may still be running (EPERM from a setuid child), and `wait()` would hang the
/// spawn for as long as it runs. The reap fault is armed as a tripwire — left unconsumed, it proves
/// the reap step was never reached. Any failure but EPERM is also `debug_assert`ed; EPERM is
/// reachable without a bug.
#[test]
fn a_failed_teardown_kill_is_logged_and_skips_the_blocking_reap_on_both_arms() {
    use std::io::ErrorKind;
    crate::log_capture::install();
    let force_arms: [fn(bool); 2] = [fault::set_force_attach_failure, fault::set_force_identity_vanished];
    let cases = [
        ("cosca-kill-fail-attach-4e02", ErrorKind::Other, true),
        ("cosca-kill-eperm-attach-61c7", ErrorKind::PermissionDenied, false),
        ("cosca-kill-fail-identity-d51a", ErrorKind::Other, true),
        ("cosca-kill-eperm-identity-0a8b", ErrorKind::PermissionDenied, false),
    ];
    for (index, (marker, kind, asserted)) in cases.into_iter().enumerate() {
        let force_arm = force_arms[index / 2];
        let mark = crate::log_capture::mark();
        force_arm(true);
        fault::set_force_kill_failure(marker, kind);
        fault::set_force_reap_failure("cosca-reap-tripwire-9f31");
        let outcome = std::panic::catch_unwind(|| blocker().spawn().err());
        force_arm(false);
        assert_eq!(
            fault::take_force_kill_failure(),
            None,
            "{marker}: the kill failure must be consumed"
        );
        assert_eq!(
            fault::take_force_reap_failure(),
            Some("cosca-reap-tripwire-9f31"),
            "{marker}: a failed kill must not be followed by a blocking reap"
        );
        assert_eq!(
            outcome.is_err(),
            asserted && cfg!(debug_assertions),
            "{marker}: the debug_assert fires for {kind:?} in exactly the builds that keep it"
        );
        if let Ok(err) = outcome {
            err.expect("the forced arm must fail the spawn");
        }
        assert!(
            crate::log_capture::contains_since(mark, marker),
            "{marker}: a failed teardown kill must be logged"
        );
        fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    }
}

/// A child the teardown could not kill is not left a zombie: it is handed to a detached thread
/// that reaps it once it exits on its own. Here it is blocked reading stdin, and exits when the
/// failed spawn drops the pipe's parent end; the thread signals the reap on a channel.
#[test]
fn a_child_the_teardown_cannot_kill_is_reaped_once_it_exits() {
    use crate::stdio::Stdio;
    let mut cmd = Command::new();
    #[cfg(unix)]
    cmd.args(["cat"]);
    #[cfg(windows)]
    cmd.args(["findstr", "x"]);
    cmd.stdin(Stdio::pipe_in()).unwrap().stdout(Stdio::null()).unwrap();
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive("cosca-kill-fail-alive-3b7e");
    fault::set_background_reap_notifier(reaped_tx);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || cmd.spawn().err()));
    fault::set_force_attach_failure(false);
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    assert!(
        fault::take_background_reap_notifier().is_none(),
        "the teardown must take the notifier"
    );
    // `Other` is asserted in debug builds; the handoff must already have happened by then.
    assert_eq!(outcome.is_err(), cfg!(debug_assertions));
    // Blocks until the child exits and the thread has reaped it.
    let reaped = reaped_rx.recv().expect("the reaper thread must report");
    reaped.expect("the background wait must succeed");
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// Force one teardown step to fail with each marker, once per teardown arm, and check the failure
/// is consumed, logged, `debug_assert`ed in exactly the builds that keep it, and leaks no child.
fn a_failed_teardown_step_is_logged_on_both_arms(
    markers: [&'static str; 2],
    set_failure: fn(&'static str),
    take_failure: fn() -> Option<&'static str>,
) {
    crate::log_capture::install();
    let force_arms: [fn(bool); 2] = [fault::set_force_attach_failure, fault::set_force_identity_vanished];
    for (marker, force_arm) in markers.into_iter().zip(force_arms) {
        let mark = crate::log_capture::mark();
        force_arm(true);
        set_failure(marker);
        let outcome = std::panic::catch_unwind(|| blocker().spawn().err());
        force_arm(false);
        assert_eq!(
            take_failure(),
            None,
            "{marker}: the teardown must consume the forced failure"
        );
        // Debug builds also trip the `debug_assert`; release builds must not panic at all.
        assert_eq!(
            outcome.is_err(),
            cfg!(debug_assertions),
            "{marker}: the debug_assert fires in exactly the builds that keep it"
        );
        if let Ok(err) = outcome {
            err.expect("the forced arm must fail the spawn");
        }
        assert!(
            crate::log_capture::contains_since(mark, marker),
            "{marker}: a failed teardown step must be logged"
        );
        fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    }
}

/// A child that exited before the teardown's kill, and whose kill still failed — a setuid zombie
/// keeps its credentials, so `kill(2)` refuses it with EPERM — is reaped, not left a zombie: an
/// exited child is reaped at once, and one not yet exited is handed to the background reaper.
/// Either way it ends reaped.
#[test]
fn a_child_whose_kill_failed_after_it_exited_is_reaped() {
    let mut cmd = Command::new();
    #[cfg(unix)]
    cmd.args(["true"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "exit 0"]);
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-kill-eperm-exited-8e41",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_background_reap_notifier(reaped_tx);
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);
    err.expect("the forced arm must fail the spawn");
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    // Still set: the child had exited, so the teardown reaped it without the background reaper.
    // Taken: it had not, and the reaper reports once it has.
    if fault::take_background_reap_notifier().is_none() {
        let reaped = reaped_rx.recv().expect("the reaper thread must report");
        reaped.expect("the background wait must succeed");
    }
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

#[test]
fn spawn_unelevated_runs_a_plain_child() {
    let mut c = crate::command::Command::new();
    #[cfg(unix)]
    c.args(["true"]);
    #[cfg(windows)]
    c.args(["cmd", "/C", "exit 0"]);
    let kill_on_drop = c.kill_on_drop_flag();
    let child = super::spawn_unelevated(&mut c, kill_on_drop).expect("spawn");
    assert!(child.wait().expect("wait").success());
}

// A NON-elevated command must reach spawn_unelevated unchanged: the elevation branch
// is gated on `elevation_request().enabled`, so a plain command never routes through it.
#[test]
fn non_elevated_spawn_skips_the_elevation_branch() {
    let mut c = crate::command::Command::new();
    #[cfg(unix)]
    c.args(["true"]);
    #[cfg(windows)]
    c.args(["cmd", "/C", "exit 0"]);
    let child = super::spawn(&mut c).expect("non-elevated spawn");
    assert!(child.wait().expect("wait").success());
}

#[cfg(windows)]
#[test]
fn elevated_pipe_is_rejected_deterministically_regardless_of_privilege() {
    // DETERMINISTIC (no ambient-privilege branch): the honest config gate now runs BEFORE
    // the already-elevated short-circuit, so a piped elevated child is
    // Unsupported whether or not the runner is elevated — never a UAC prompt, never a hang.
    let mut c = crate::command::Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(crate::stdio::Stdio::pipe()).unwrap();
    assert!(matches!(
        super::spawn(&mut c),
        Err(crate::error::Error::Unsupported { .. })
    ));
}

// ===== Windows backend routing =====

/// The rule both Windows routers read, in both directions and for all four shapes.
///
/// `tests/windows_creation_flags.rs` names a backend in every test name; its `executable()` legs
/// carry their own behavioural proof (the child's `argv[0]`), but its argv legs have none — an
/// argv-only command would report the same `argv[0]` whichever backend spawned it. Their
/// std-path claim rests on this rule, which is now one function rather than two copies.
///
/// The **high-descriptor-only** shape is the branch with no coverage anywhere today: every
/// shipped Windows high-descriptor test also sets an explicit `executable()`, which
/// short-circuits the rule before the fd term is ever evaluated.
#[cfg(windows)]
#[test]
fn routes_to_raw_backend_answers_for_executables_and_high_descriptors() {
    use crate::stdio::Stdio;

    let mut argv_only = Command::new();
    argv_only.args(["cmd", "/C", "exit 0"]);
    assert!(
        !super::routes_to_raw_backend(&argv_only),
        "an argv-only command stays on the std path"
    );

    let mut exe_only = Command::new();
    exe_only.executable("cmd").args(["cmd", "/C", "exit 0"]);
    assert!(super::routes_to_raw_backend(&exe_only), "an executable() routes to raw");

    // BOTH setters must route here. The rule reads `executable_path()`, which is deliberately
    // variant-agnostic, so this holds today — the case exists to stop it being "tightened" to
    // `Search` only. That would send `raw_executable()` down the std path, where std resolves a
    // bare name itself, breaking the no-resolution contract at the one backend that honours it.
    let mut raw_exe_only = Command::new();
    raw_exe_only.raw_executable("cmd").args(["cmd", "/C", "exit 0"]);
    assert!(
        super::routes_to_raw_backend(&raw_exe_only),
        "a raw_executable() routes to raw too"
    );

    let mut high_fd_only = Command::new();
    high_fd_only.args(["cmd", "/C", "exit 0"]);
    high_fd_only.fd(3, Stdio::pipe_out()).unwrap();
    assert!(
        super::routes_to_raw_backend(&high_fd_only),
        "a descriptor >= 3 routes to raw even with no executable(): std cannot carry it, and the \
         std path's fd >= 3 collection is unix-only, so it would be dropped in silence"
    );

    let mut both = Command::new();
    both.executable("cmd").args(["cmd", "/C", "exit 0"]);
    both.fd(3, Stdio::pipe_out()).unwrap();
    assert!(super::routes_to_raw_backend(&both));
}
/// A sync spawn whose verdict fails closed while its child is still held at its hook — here one
/// that refuses the kill — writes nothing into the child's stdio. With fds 1 and 2 closed, `std`'s
/// error channel takes them, the child's stdio `dup2` closes its end, and `spawn` returns before the
/// hook runs; the child, released once its report has been read, finds the exchange shut and exits
/// with `ABANDONED_EXIT` rather than return an error `std` would write to that channel's fd number —
/// by now the child's stderr.
///
/// The sync path's only abandonment of a live child: `std` fails a spawn only once it has reaped
/// the child, and every later failure takes the verdict with the child in hand.
///
/// Runs in a copy of this test binary: closing 1 and 2 is process-wide.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_a_sync_spawn_failed_closed_writes_nothing_into_the_childs_stdio() {
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsRawFd;

    use crate::containment::cgroup::fault as cgroup_fault;

    const NAME: &str =
        "child::spawn::spawn_tests::cgroup_a_sync_spawn_failed_closed_writes_nothing_into_the_childs_stdio";
    const INNER: &str = "COSCA_TEST_FAILED_CLOSED_STDIO_INNER";
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    if std::env::var_os(INNER).is_none() {
        let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([NAME, "--exact", "--include-ignored", "--nocapture", "--test-threads=1"])
            .env(INNER, "1")
            .output()
            .expect("run the case");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    let mut file = tempfile::tempfile().expect("tempfile");
    let (gate_read, mut gate_write) = std::io::pipe().expect("open the gate");
    let mut release = gate_write.try_clone().expect("dup the gate");
    let mut cmd = blocker();
    for slot in [1, 2] {
        cmd.fd(
            slot,
            crate::stdio::Stdio::from_file(file.try_clone().expect("clone the file")),
        )
        .expect("wire the slot to the file");
    }
    cmd.contain();
    // The verdict cannot wait (no pidfd) and finds the leaf busy with something not the child, so
    // it fails closed; the child refuses its kill.
    cgroup_fault::set_force_pidfd_failure(true);
    cgroup_fault::set_force_leaf_busy(true);
    cgroup_fault::set_force_signal_denied(true);
    let status = std::rc::Rc::new(std::cell::Cell::new(None));
    let seen = status.clone();
    cgroup_fault::set_after_final_read(move |pid| {
        release.write_all(b"x").expect("release the child");
        // Its exit, not its reaping: the spawn's teardown reaps it.
        let pid = rustix::process::Pid::from_raw(pid as i32).expect("a positive pid");
        let exited = loop {
            match rustix::process::waitid(
                rustix::process::WaitId::Pid(pid),
                rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
            ) {
                Err(rustix::io::Errno::INTR) => continue,
                other => break other.expect("wait for the child").expect("it exited"),
            }
        };
        seen.set(Some(exited.exit_status()));
    });
    // SAFETY: this process's own std slots, closed only across the spawn and restored from copies
    // above 2 before anything else runs.
    let saved: Vec<(i32, i32)> = [1, 2]
        .into_iter()
        .map(|slot| unsafe { (slot, libc::fcntl(slot, libc::F_DUPFD_CLOEXEC, 3)) })
        .collect();
    for &(slot, _) in &saved {
        // SAFETY: as above.
        unsafe { libc::close(slot) };
    }
    // Inherited by the child, which waits on it at its hook; this thread's copy is cleared.
    cgroup_fault::set_hook_gate(gate_read.as_raw_fd());
    let spawned = cmd.spawn();
    let _ = cgroup_fault::take_hook_gate();
    for &(slot, saved) in &saved {
        // SAFETY: as above.
        unsafe {
            libc::dup2(saved, slot);
            libc::close(saved);
        }
    }
    // Released whatever happened, before any assert: a child held forever holds this process's
    // stdout, and would hang the outer run.
    gate_write.write_all(b"x").expect("release the child");
    let leftover = (
        cgroup_fault::take_force_leaf_busy(),
        cgroup_fault::take_force_signal_denied(),
    );

    let Err(err) = spawned else {
        panic!("a verdict failed closed must fail the spawn");
    };
    assert!(err.to_string().contains("could not be signalled"), "got {err}");
    assert_eq!(leftover, (false, false), "the verdict must take its seams");
    assert_eq!(
        status.get(),
        Some(Some(crate::containment::cgroup::ABANDONED_EXIT)),
        "the child must exit from its hook"
    );
    let mut written = Vec::new();
    file.rewind().expect("rewind the file");
    file.read_to_end(&mut written).expect("read the file");
    assert_eq!(written, b"", "nothing reached the child's stdio");
}

// ===== A refused spawn leaves our handle inheritance alone =====

/// A refused spawn must not have mutated this process first. `clear_std_handle_inheritance` is a
/// real, process-global, un-undone `SetHandleInformation` on our own std handles, so running it
/// before the refusal would leave a disposition-less side effect behind.
///
/// The two legs differ by one bit and are one `#[test]` so their order is guaranteed; `cargo
/// test` gives each test its own thread, so the thread-local seam starts clean. The positive leg
/// is what stops the negative one passing on a seam that was never wired.
///
/// The real handle flags are deliberately NOT measured instead: the mutation is process-global
/// and permanent, so any earlier contained spawn in this binary would already have made that
/// observation meaningless.
#[cfg(windows)]
#[test]
fn a_refused_raw_spawn_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("a reserved bit must be refused");
    assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );

    let mut allowed = Command::new();
    allowed.executable("cmd").args(["cmd", "/C", "exit 0"]).contain();
    let child = allowed
        .spawn()
        .expect("the same command without the reserved bit spawns");
    assert!(
        observe::take_inheritance_cleared(),
        "the seam must record a real call, else the negative leg above proves nothing"
    );
    child.wait().expect("reap");
}

/// An environment key with an embedded NUL is refused before the process-global handle mutation
/// too. The seam's wiring is proven by the positive leg of the test above.
#[cfg(windows)]
#[test]
fn a_raw_spawn_refusing_an_env_nul_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .env("A\0B", "x");
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("an embedded NUL must be refused");
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidInput),
        "got {err:?}"
    );
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );
}

/// The std-path counterpart of the test above. The std backend reaches the same process-global
/// mutation through `containment::prepare`, which composes and validates the creation-flag word
/// at its top — a separate ordering the raw backends' tests cannot see.
///
/// Argv-only and no `executable()`, asserted through `routes_to_raw_backend` so a future routing
/// change cannot quietly turn this into a third raw-backend test.
#[cfg(windows)]
#[test]
fn a_refused_std_spawn_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    assert!(
        !crate::child::spawn::routes_to_raw_backend(&refused),
        "this leg is only a std-path proof while the command stays off the raw backend"
    );
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("a reserved bit must be refused");
    assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );

    let mut allowed = Command::new();
    allowed.args(["cmd", "/C", "exit 0"]).contain();
    let child = allowed
        .spawn()
        .expect("the same command without the reserved bit spawns");
    assert!(
        observe::take_inheritance_cleared(),
        "the seam must record a real call, else the negative leg above proves nothing"
    );
    child.wait().expect("reap");
}
