//! Unit tests for the sync spawn path: error-path teardown (driven by the shared `fault` seam,
//! defined in `super` and also used by `src/tokio/spawn_tests.rs`), the elevation branch, and the
//! Windows backend router, and that a refused spawn refuses before it touches our handle
//! inheritance. In the library (not `tests/`) because the seam is `pub(crate)`/`#[cfg(test)]` and
//! only reachable from within the crate. The batch gate's tests are in `spawn/batch_gate_tests.rs`.

use super::failure::{expect_may_have_started_with, expect_not_started};
use super::fault;
use crate::command::Command;
use crate::error::ChildFate;
use crate::error::Error;
#[cfg(target_os = "linux")]
use crate::test_groups::{cgroup, Group};

// A child only a real kill ends, so a teardown leak shows as an alive process at the assert
// rather than a self-exit, and a mutant that skips the kill hangs instead of passing. See
// `test_child::BLOCKER_ARGV` for why, and `leaked_writer_stdin` for the stdin.
fn blocker() -> Command {
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::test_child::leaked_writer_stdin())
        .expect("set stdin pipe");
    cmd
}

/// [`blocker`] for a test that drives a kill-then-reap; see [`fault::teardown_blocker_stdin`].
pub(super) fn teardown_blocker() -> (Command, fault::TeardownBlocker) {
    let fault::TeardownBlockerParts {
        argv,
        stdin,
        stdout,
        guard,
    } = fault::teardown_blocker_parts();
    let mut cmd = Command::new();
    cmd.args(argv);
    cmd.stdin(stdin).expect("set stdin pipe");
    if let Some(stdout) = stdout {
        cmd.stdout(stdout).expect("set stdout");
    }
    (cmd, guard)
}

/// [`blocker`] whose stdin writer the caller keeps: for a test where only its own kill may end
/// the child.
#[cfg(unix)]
fn blocker_with_held_stdin() -> (Command, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin pipe");
    (cmd, writer)
}

/// An arbitrary status, told apart from another by its raw value.
#[cfg(unix)]
fn raw_status(raw: u32) -> std::process::ExitStatus {
    std::os::unix::process::ExitStatusExt::from_raw(raw as i32)
}
#[cfg(windows)]
fn raw_status(raw: u32) -> std::process::ExitStatus {
    std::os::windows::process::ExitStatusExt::from_raw(raw)
}

#[skuld::test]
fn a_teardown_reap_is_recorded_only_while_its_recorder_lives() {
    fault::record_teardown_reap(1, raw_status(9));
    let recorder = fault::record_teardown_reaps();
    assert_eq!(recorder.recorded(), vec![], "a reap from before arming is not recorded");
    fault::record_teardown_reap(2, raw_status(9));
    assert_eq!(recorder.recorded(), vec![(2, raw_status(9))]);
    drop(recorder);
    let later = fault::record_teardown_reaps();
    assert_eq!(later.recorded(), vec![], "a dropped recorder leaves nothing behind");
}

// Off macOS, a failed sync spawn must fully reap its child, not leak it. Each error arm is forced via
// the seam (which records the child's real identity); `fault::assert_child_reaped` then proves it
// was reaped. On macOS those arms leave the child alone instead (see `macos_*` below).

#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn identity_failure_reaps_the_spawned_child() {
    let (mut cmd, teardown) = teardown_blocker();
    fault::set_force_identity_vanished(true);
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);

    let (err, fate) = expect_may_have_started_with(err.expect("forced identity-vanish must make spawn return Err"));
    assert!(
        matches!(err, Error::Io(_)),
        "identity-vanish surfaces as an Io error, got {err:?}"
    );
    assert_eq!(fate, ChildFate::Reaped, "the teardown killed and reaped the child");
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    teardown.assert_killed();
}

/// An identity the OS refuses to report fails the spawn as `Unassessable`, and the child is still
/// killed and reaped: a refusal says nothing against the child.
///
/// Mutant: the arm leaves the child running.
#[cfg(target_os = "linux")]
#[skuld::test]
fn identity_refusal_reaps_the_spawned_child() {
    let (mut cmd, teardown) = teardown_blocker();
    fault::set_force_identity_unknown(true);
    let err = cmd.spawn().err();
    fault::set_force_identity_unknown(false);

    let (err, fate) = expect_may_have_started_with(err.expect("a refused identity read must make spawn return Err"));
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        fate,
        ChildFate::Reaped,
        "the pidfd pins the child, so the teardown reaps it"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    teardown.assert_killed();
}

#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn attach_failure_reaps_the_spawned_child() {
    let (mut cmd, teardown) = teardown_blocker();
    fault::set_force_attach_failure(true);
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);

    let (err, fate) = expect_may_have_started_with(err.expect("forced attach failure must make spawn return Err"));
    assert_eq!(fate, ChildFate::Reaped, "the teardown killed and reaped the child");
    assert!(
        matches!(err, Error::Containment { .. }),
        "a real attach failure surfaces as Error::Containment, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    teardown.assert_killed();
}

/// A `kill` that fails for a child that has already exited is not a failure: the teardown goes on
/// to reap it, as it does after any successful kill. The child here exits by itself (its stdin is
/// already closed), so nothing but the reap can account for it in the recorder.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn a_kill_error_for_an_already_exited_child_still_reaps_it() {
    let mut cmd = Command::new();
    #[cfg(unix)]
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    #[cfg(windows)]
    cmd.args([crate::test_child::windows_more()]);
    let (reader, writer) = std::io::pipe().expect("pipe");
    #[cfg(unix)]
    let reader = std::fs::File::from(std::os::fd::OwnedFd::from(reader));
    #[cfg(windows)]
    let reader = std::fs::File::from(std::os::windows::io::OwnedHandle::from(reader));
    cmd.stdin(crate::stdio::Stdio::from_file(reader))
        .expect("set stdin pipe");
    cmd.stdout(crate::stdio::Stdio::null()).expect("null stdout");
    drop(writer);
    let reaps = fault::record_teardown_reaps();
    fault::set_force_identity_vanished(true);
    fault::set_force_kill_error_after_exit("cosca-kill-error-after-exit-2f6a", std::io::ErrorKind::PermissionDenied);
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);

    err.expect("forced identity-vanish must make spawn return Err");
    let recorded = reaps.recorded();
    assert_eq!(
        recorded.len(),
        1,
        "the teardown must reap the exited child, got {recorded:?}"
    );
    assert!(
        recorded[0].1.success(),
        "the child exited by itself, got {:?}",
        recorded[0].1
    );
}

/// A reap that FAILS during teardown must leave a trace in a release build, where the
/// `debug_assert` beside it is compiled out: a `log::warn!` naming the error. Both teardown arms —
/// attach failure and unresolved identity — share the one teardown, and each is driven here.
///
/// Each leg's forced error carries its own marker, and records are scanned from a mark taken just
/// before, so a concurrent test's warning cannot satisfy this one.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
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
#[cfg(not(target_os = "macos"))]
#[skuld::test]
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
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn a_child_the_teardown_cannot_kill_is_reaped_once_it_exits() {
    use crate::stdio::Stdio;
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
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

/// A child whose teardown kill is refused (as a setuid child refuses it, `EPERM`) may still be
/// running, and the error says so, naming it; it is reaped in the background once it exits.
///
/// Mutant: a refused kill reports the child reaped.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn a_child_whose_teardown_kill_is_refused_may_still_be_running() {
    use crate::stdio::Stdio;
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(Stdio::pipe_in()).unwrap().stdout(Stdio::null()).unwrap();
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-kill-refused-142",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_background_reap_notifier(reaped_tx);
    let err = cmd.spawn().expect_err("the forced attach failure fails the spawn");
    fault::set_force_attach_failure(false);
    let Some(crate::identity::Resolved::Found(id)) = fault::take_captured() else {
        panic!("the seam captured the child's identity");
    };
    let (_, fate) = expect_may_have_started_with(err);
    // The attach comes after the identity read, so the child is named by it.
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    // The failed spawn closed the child's stdin, so it exits, and the background reap reports.
    reaped_rx
        .recv()
        .expect("the reaper thread must report")
        .expect("the background wait must succeed");
}

/// Force one teardown step to fail with each marker, once per teardown arm, and check the failure
/// is consumed, logged, `debug_assert`ed in exactly the builds that keep it, and leaks no child.
#[cfg(not(target_os = "macos"))]
fn a_failed_teardown_step_is_logged_on_both_arms(
    markers: [&'static str; 2],
    set_failure: fn(&'static str),
    take_failure: fn() -> Option<&'static str>,
) {
    crate::log_capture::install();
    let force_arms: [fn(bool); 2] = [fault::set_force_attach_failure, fault::set_force_identity_vanished];
    for (marker, force_arm) in markers.into_iter().zip(force_arms) {
        let mark = crate::log_capture::mark();
        let (mut cmd, teardown) = teardown_blocker();
        force_arm(true);
        set_failure(marker);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cmd.spawn().err()));
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
        teardown.assert_killed();
    }
}

/// A child that exited before the teardown's kill, and whose kill still failed — a setuid zombie
/// keeps its credentials, so `kill(2)` refuses it with EPERM — is reaped, not left a zombie: an
/// exited child is reaped at once, and one not yet exited is handed to the background reaper.
/// Either way it ends reaped.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
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

#[skuld::test]
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
#[skuld::test]
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
#[skuld::test]
fn elevated_pipe_is_rejected_deterministically_regardless_of_privilege() {
    // DETERMINISTIC (no ambient-privilege branch): the honest config gate now runs BEFORE
    // the already-elevated short-circuit, so a piped elevated child is
    // Unsupported whether or not the runner is elevated — never a UAC prompt, never a hang.
    let mut c = crate::command::Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(crate::stdio::Stdio::pipe()).unwrap();
    assert!(matches!(
        super::spawn(&mut c),
        Err(super::SpawnFailure::NotStarted(crate::error::Error::Unsupported { .. }))
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
#[skuld::test]
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

/// A spawn whose identity check fails ends the leaf's placement exchange before it kills the child:
/// the leaf then answers only for the tree, as it does after an attach failure, and the kill never
/// races the exchange's reads.
///
/// Mutant: the identity-failure arm settles the verdict after the kill, or not at all.
#[cfg(target_os = "linux")]
#[skuld::test]
fn cgroup_sync_identity_failure_settles_the_leaf_verdict_before_the_kill(#[fixture(cgroup)] _group: &Group) {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::containment::cgroup::fault as cgroup_fault;
    use crate::send_log::Capture;
    use crate::signal::Sig;

    let (mut cmd, teardown) = teardown_blocker();
    cmd.contain();
    let capture = Rc::new(Capture::start());
    let sends_at_settle = Rc::new(Cell::new(None));
    let _hook = cgroup_fault::set_on_take_placement({
        let (capture, sends_at_settle) = (Rc::clone(&capture), Rc::clone(&sends_at_settle));
        move || sends_at_settle.set(Some(capture.entries().len()))
    });
    fault::set_force_identity_vanished(true);
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);
    err.expect("a vanished identity must fail the spawn");

    let Some(crate::identity::Resolved::Found(child)) = fault::take_captured() else {
        panic!("the seam must capture the child's identity");
    };
    assert_eq!(
        sends_at_settle.get(),
        Some(0),
        "the verdict must be settled, and before anything is sent to the child"
    );
    assert!(
        capture
            .entries()
            .iter()
            .any(|&(pid, sig, _)| pid == child.pid() && sig == Sig::Kill),
        "the child must be killed after the verdict: {:?}",
        capture.entries()
    );
    teardown.assert_killed();
}

// ===== A refused spawn leaves our handle inheritance alone =====

/// A refused spawn must not have mutated this process first. `clear_std_handle_inheritance` is a
/// real, process-global, un-undone `SetHandleInformation` on our own std handles, so running it
/// before the refusal would leave a disposition-less side effect behind.
///
/// The two legs differ by one bit and are one `#[skuld::test]` so their order is guaranteed; each
/// test runs on its own thread, so the thread-local seam starts clean. The positive leg is what
/// stops the negative one passing on a seam that was never wired.
///
/// The real handle flags are deliberately NOT measured instead: the mutation is process-global
/// and permanent, so any earlier contained spawn in this binary would already have made that
/// observation meaningless.
#[cfg(windows)]
#[skuld::test]
fn a_refused_raw_spawn_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    observe::take_inheritance_cleared();
    let err = expect_not_started(refused.spawn().expect_err("a reserved bit must be refused"));
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
#[skuld::test]
fn a_raw_spawn_refusing_an_env_nul_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .env("A\0B", "x");
    observe::take_inheritance_cleared();
    let err = expect_not_started(refused.spawn().expect_err("an embedded NUL must be refused"));
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
#[skuld::test]
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
    let err = expect_not_started(refused.spawn().expect_err("a reserved bit must be refused"));
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

// kill_on_drop(false) commits only with the spawn -----
// The containment resource is disarmed when `spawn` hands the handle over, never before: a spawn
// that fails after its `Child` exists (the POSIX password write) still owns the tree it started.

/// An occupied temp leaf whose child entered it, attached to the next spawn on this thread.
#[cfg(target_os = "linux")]
fn attach_entered_leaf(leaf_path: &std::path::Path) {
    std::fs::create_dir(leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.to_path_buf(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
}

/// Until the spawn commits, a `kill_on_drop(false)` handle's leaf still kills on drop; once
/// committed, it does not.
#[cfg(target_os = "linux")]
#[skuld::test]
fn kill_on_drop_false_disarms_the_leaf_only_when_the_spawn_commits() {
    for commit in [false, true] {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf_path = dir.path().join("cosca-commit-leaf");
        attach_entered_leaf(&leaf_path);
        let (mut cmd, stdin) = blocker_with_held_stdin();
        cmd.kill_on_drop(false);
        let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
        if commit {
            child.commit_kill_on_drop();
        }
        child.kill().expect("end the stand-in root");
        // Released only after the kill, so a child that exits 0 was not killed.
        drop(stdin);
        let status = child.wait().expect("reap the stand-in root");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL),
            "the stand-in root must die of the kill, got {status:?}"
        );
        drop(child);

        let expected: &[u8] = if commit { b"" } else { b"1" };
        assert_eq!(
            std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
            expected,
            "committed: {commit}"
        );
    }
}

/// A failed password write tears the tree down through the leaf, even when the leaf's own `Drop`
/// would not: the root alone is not the tree.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_password_write_kills_the_contained_tree() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-password-leaf");
    attach_entered_leaf(&leaf_path);
    let (mut cmd, teardown) = teardown_blocker();
    cmd.kill_on_drop(false);
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    // Rule out the leaf's `Drop`: only the failure path itself may kill.
    child.attached.disarm();

    let written = Err(Error::Elevation {
        kind: crate::error::ElevationErrorKind::AuthFailed,
        detail: "forced password-write failure".into(),
    });
    let mark = crate::log_capture::mark();
    let (err, fate) = super::finish_elevated(child, written)
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
    assert_eq!(fate, ChildFate::Reaped);
    teardown.assert_killed();

    assert!(
        matches!(
            err,
            Error::Elevation {
                kind: crate::error::ElevationErrorKind::AuthFailed,
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        crate::containment::cgroup::KILL_PAYLOAD,
        "the failed spawn must kill its tree through the leaf"
    );
    // A teardown that worked is not warned about.
    assert_eq!(
        crate::log_capture::levels_since(mark, &super::teardown_warn_marker(&leaf_path)),
        Vec::<log::Level>::new(),
        "a successful tree kill must not warn"
    );
}

/// Sync twin of the async `a_failed_password_write_removes_the_leaf_once_the_tree_drains`: after
/// the failed write the handle's blocking `Drop` waits for the killed tree to drain and removes
/// the leaf, warning of nothing. The members of the fake leaf exit when the wait is about to
/// block, not before.
///
/// Mutant: the leaf's `Drop` does not wait for the drain (`block_until_drained` returns at once).
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_password_write_removes_the_leaf_once_the_tree_drains() {
    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};

    crate::log_capture::install();
    let name = "cosca-password-drains-leaf";
    let fake = FakeLeaf::new(name, true);
    let (path, events) = (fake.leaf.clone(), fake.events.clone());
    leaf_fault::set_rmdir_hook(move |_| FakeLeaf::rmdir(&path, &events));
    let (blocking, wait_reached) = std::sync::mpsc::channel();
    leaf_fault::set_drain_blocking_notifier(blocking);
    let members = fake.events.clone();
    let exiting = std::thread::spawn(move || {
        // A closed channel means the wait never blocked: nothing to release.
        if wait_reached.recv().is_ok() {
            FakeLeaf::set_populated(&members, false);
        }
    });
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(entered_leaf_at(fake.leaf.clone())),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let (mut cmd, teardown) = teardown_blocker();
    cmd.kill_on_drop(false);
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");

    let mark = crate::log_capture::mark();
    let (err, fate) = super::finish_elevated(child, failed_write())
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
    assert_eq!(fate, ChildFate::Reaped);
    teardown.assert_killed();
    leaf_fault::take_drain_blocking_notifier();
    exiting.join().expect("the exiting thread");
    leaf_fault::take_rmdir_hook();

    assert!(matches!(err, Error::Elevation { .. }), "got {err:?}");
    assert!(
        !fake.leaf.exists(),
        "the drained leaf must be removed by the handle's drop"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, name),
        Vec::<log::Level>::new(),
        "a leaf that was removed must not be warned about"
    );
}

/// A tree-teardown failure during a failed password write is logged at `warn`, naming the leaf
/// and the OS reason, like other teardown-mechanism failures (e.g. `warn_leaf_left_behind`).
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_password_write_warns_when_the_tree_kill_fails() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-password-kill-fail-leaf");
    attach_entered_leaf(&leaf_path);
    let (mut cmd, teardown) = teardown_blocker();
    cmd.kill_on_drop(false);
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    // Rule out the leaf's `Drop`: only the failure path itself may kill.
    child.attached.disarm();

    // Not ENOENT/ENODEV, so `hard_kill` treats it as a real failure: `open(O_WRONLY)` on a
    // directory fails EISDIR.
    std::fs::remove_file(leaf_path.join("cgroup.kill")).expect("remove the fixture's cgroup.kill file");
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill a directory");
    let mark = crate::log_capture::mark();
    let (err, fate) = super::finish_elevated(child, failed_write())
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
    assert_eq!(fate, ChildFate::Reaped);
    teardown.assert_killed();
    assert!(
        matches!(
            err,
            Error::Elevation {
                kind: crate::error::ElevationErrorKind::AuthFailed,
                ..
            }
        ),
        "got {err:?}"
    );
    let marker = super::teardown_warn_marker(&leaf_path);
    assert_eq!(
        crate::log_capture::levels_since(mark, &marker),
        [log::Level::Warn],
        "a forced tree-kill failure must be logged at warn"
    );
    let errno_text = std::io::Error::from_raw_os_error(libc::EISDIR).to_string();
    let records = crate::log_capture::records_since(mark, &marker);
    assert!(
        records[0].contains(&errno_text),
        "the warning must name the OS reason the write failed, got {records:?}"
    );
}

/// A root that was killed but whose reap failed is not reported as terminated: the failure is
/// logged at `warn` naming the pid, and the note says it was not reaped.
#[cfg(unix)]
#[skuld::test]
fn a_failed_password_write_reports_a_failed_root_reap() {
    crate::log_capture::install();
    let (mut cmd, teardown) = teardown_blocker();
    let child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    fault::set_force_reap_failure("cosca-finish-elevated-reap-4c1e");
    let mark = crate::log_capture::mark();
    let (err, fate) = super::finish_elevated(child, failed_write())
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
    assert_eq!(fate, ChildFate::Killed, "killed, but not reaped");

    let Error::Elevation { detail, .. } = &err else {
        panic!("got {err:?}");
    };
    assert!(
        detail.contains("killed but could not be reaped") && detail.contains("cosca-finish-elevated-reap-4c1e"),
        "the note must say the reap failed, got {detail:?}"
    );
    assert!(
        !detail.contains("was terminated"),
        "a child that was not reaped is not reported as terminated: {detail:?}"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, &format!("could not reap the killed elevated child pid {pid}")),
        [log::Level::Warn]
    );
    assert_eq!(teardown.recorded(), vec![], "a failed reap is not recorded");
    assert!(
        fault::take_force_reap_failure().is_none(),
        "the teardown consumed the forced failure"
    );
}

/// `report_tree_teardown` (shared by both `finish_elevated` variants) reports a failed teardown
/// at `warn` and in the returned note, and nothing when the teardown worked or was not tried.
#[cfg(unix)]
#[skuld::test]
fn report_tree_teardown_reports_only_a_failed_teardown() {
    crate::log_capture::install();
    let failed = || Some(Err(Error::Io(std::io::Error::from_raw_os_error(libc::EISDIR))));
    for (name, tree, reported) in [
        ("cosca-report-failed", failed(), true),
        ("cosca-report-worked", Some(Ok(())), false),
        ("cosca-report-not-tried", None, false),
    ] {
        let mark = crate::log_capture::mark();
        let note = super::report_tree_teardown(tree, &name);
        assert_eq!(
            note.contains("its contained tree could not be killed"),
            reported,
            "{name}: {note:?}"
        );
        assert_eq!(
            note.contains(name),
            reported,
            "{name}: the note names the subject, got {note:?}"
        );
        assert_eq!(
            crate::log_capture::levels_since(mark, name),
            if reported { vec![log::Level::Warn] } else { vec![] },
            "{name}"
        );
    }
}

/// Whether `pid`, a child of this process, has been reaped: `waitpid` no longer knows it.
#[cfg(target_os = "linux")]
fn reaped(pid: u32) -> bool {
    let mut status = 0;
    // SAFETY: a non-blocking query on a pid this process spawned; `status` is a valid int.
    let r = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
    r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
}

/// The error a failed password write returns.
#[cfg(unix)]
fn failed_write() -> Result<(), Error> {
    Err(Error::Elevation {
        kind: crate::error::ElevationErrorKind::AuthFailed,
        detail: "forced password-write failure".into(),
    })
}

/// A `Delegated` spawn has no tree teardown of its own, but its root is still this spawn's child:
/// a failed password write kills and reaps it.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_password_write_kills_and_reaps_a_delegated_root() {
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::Delegated,
        attached: crate::containment::Attached::Delegated,
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let (mut cmd, teardown) = teardown_blocker();
    cmd.kill_on_drop(false);
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    let pid = child.id().pid();

    let (err, fate) = super::finish_elevated(child, failed_write())
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
    assert_eq!(fate, ChildFate::Reaped);
    teardown.assert_killed();

    let reaped = reaped(pid);
    if !reaped {
        // SAFETY: `pid` is this process's own unreaped child; do not leak it past the test.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    assert!(reaped, "the root must be killed and reaped, got {err:?}");
    assert!(err.to_string().contains("was terminated"), "got {err:?}");
}

/// A tree kill that fails does not stop the root's own kill and reap: the two are separate.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_password_write_reaps_the_root_when_the_tree_kill_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-unkillable-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    // A directory: writing `cgroup.kill` fails with EISDIR, as a refused kill would.
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill unwritable");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let (mut cmd, teardown) = teardown_blocker();
    cmd.kill_on_drop(false);
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    let pid = child.id().pid();

    let (err, fate) = super::finish_elevated(child, failed_write())
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
    assert_eq!(fate, ChildFate::Reaped);
    teardown.assert_killed();

    assert!(reaped(pid), "the root was killed, so it must be reaped, got {err:?}");
    let detail = err.to_string();
    assert!(detail.contains("was terminated"), "the root was killed, got {detail}");
    assert!(
        detail.contains("its contained tree could not be killed"),
        "the tree's failure is reported, got {detail}"
    );
}

// A failed adoption tears the child down like any other failed spawn step =====

/// Windows: a failed `DuplicateHandle` fails the spawn, and the child is torn down.
///
/// Mutant: an `adopt` that `.expect()`s the duplication (the test panics instead of getting
/// `Err((e, child))` and a torn-down child).
#[cfg(windows)]
#[skuld::test]
fn adopt_on_a_failed_handle_duplication_tears_the_child_down() {
    let (mut cmd, teardown) = teardown_blocker();
    let forced = crate::child::shared::seams::force_duplicate_handle_error_once();
    let err = cmd.spawn().err();
    drop(forced);

    let (err, fate) = expect_may_have_started_with(err.expect("a failed adoption fails the spawn"));
    assert!(matches!(err, Error::Io(_)), "{err:?}");
    assert_eq!(
        fate,
        ChildFate::Reaped,
        "the handle still pins the process, so the teardown reaps it"
    );
    fault::assert_child_reaped(fault::take_captured().expect("the failed adoption captured the child"));
    teardown.assert_killed();
}

/// macOS: a unique-id read the child itself is refused fails the spawn as `Unassessable`, naming
/// the errno, and the hook stops the child before `exec`: the program did not run, and there is no
/// child to leave behind.
///
/// Mutant: the hook execs anyway (a child is left running); `Unassessable` mapped to `Io`; a spawn
/// that succeeds with no identity.
#[cfg(target_os = "macos")]
#[skuld::test]
fn a_refused_own_identity_read_is_unassessable_and_the_program_does_not_run() {
    use crate::child::spawn::identity_macos_tests::{ran_marker, RAN_ARGV};
    let (stdout, reader) = ran_marker();
    let mut cmd = Command::new();
    cmd.args(RAN_ARGV);
    cmd.stdout(stdout).expect("set stdout");
    let forced = crate::child::spawn::unique_report::seams::force_child_read_errno(libc::EPERM);
    let err = cmd.spawn().err();
    drop(forced);

    match expect_not_started(err.expect("a refused identity read must fail the spawn")) {
        Error::Unassessable { detail, source } => {
            assert!(detail.contains("did not start"), "{detail}");
            assert_eq!(source.and_then(|e| e.raw_os_error()), Some(libc::EPERM));
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
    crate::child::spawn::identity_macos_tests::assert_program_did_not_run(cmd, reader);
}

/// macOS: the child a failed spawn left behind. Dropping it kills and reaps it, so a failing
/// assertion cannot leak a process.
#[cfg(target_os = "macos")]
struct LeftChild(crate::identity::ProcessId);

#[cfg(target_os = "macos")]
impl Drop for LeftChild {
    fn drop(&mut self) {
        let pid = self.0.pid() as libc::pid_t;
        // SAFETY: `pid` is this test's own unreaped child, left behind by the failed spawn.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
    }
}

/// macOS: takes the identity the failed spawn captured. Call it right after the spawn, before any
/// assertion, so the child is cleaned up whatever follows.
#[cfg(target_os = "macos")]
fn captured_child() -> LeftChild {
    let Some(crate::identity::Resolved::Found(id)) = fault::take_captured() else {
        panic!("the failed spawn captured the child's identity");
    };
    LeftChild(id)
}

/// macOS: asserts `left` is still running and unreaped, and that a warning containing `warning` and
/// its pid was logged since `mark`.
#[cfg(target_os = "macos")]
fn assert_left_alone(mark: usize, warning: &str, left: &LeftChild) {
    let pid = left.0.pid();
    assert!(
        crate::log_capture::contains_since(mark, &format!("child {pid} {warning}")),
        "the warning must name the child"
    );
    assert_eq!(
        left.0.is_alive(),
        crate::identity::Liveness::Alive,
        "the child must not have been killed"
    );
    // SAFETY: an all-zero `siginfo_t` is valid, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: a non-blocking look at this process's own child; `WNOWAIT` consumes nothing.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
    // SAFETY: `info` was filled by the successful call above.
    assert_eq!(unsafe { info.si_pid() }, 0, "the child must still be running");
}

/// How many descriptors this process has open, from `/dev/fd`.
#[cfg(target_os = "macos")]
fn open_fd_count() -> usize {
    std::fs::read_dir("/dev/fd").expect("read /dev/fd").count()
}

/// macOS: a spawn that fails on the identity arms leaves no descriptor of ours
/// behind: dropping the abandoned `std` `Child` closes our ends of its pipes (a piped stdin here).
/// The count is of this process's own, in a test that runs alone in its process under nextest.
///
/// Mutant: the arm forgets the child (`mem::forget`), which leaks its pipe ends.
#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_identity_gone_closes_our_pipe_ends() {
    macos_failed_spawn_closes_our_pipe_ends(
        || fault::set_force_identity_vanished(true),
        || fault::set_force_identity_vanished(false),
        false,
        ChildFate::Gone,
    );
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_identity_unknown_closes_our_pipe_ends() {
    macos_failed_spawn_closes_our_pipe_ends(
        || fault::set_force_identity_unknown(true),
        || fault::set_force_identity_unknown(false),
        false,
        ChildFate::Running { id: None },
    );
}

/// As above for the attach arm (which only a seam makes a macOS spawn take): the teardown kills the
/// child through its verified id and drops it, which closes our ends of its pipes.
///
/// Mutant: the arm forgets the child (`mem::forget`), which leaks its pipe ends.
#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_attach_failure_closes_our_pipe_ends() {
    macos_failed_spawn_closes_our_pipe_ends(
        || fault::set_force_attach_failure(true),
        || fault::set_force_attach_failure(false),
        false,
        ChildFate::Reaped,
    );
}

#[cfg(target_os = "macos")]
fn macos_failed_spawn_closes_our_pipe_ends(
    arm: impl FnOnce(),
    disarm: impl FnOnce(),
    tree_walk: bool,
    expected: ChildFate,
) {
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::stdio::Stdio::pipe_in()).expect("piped stdin");
    if tree_walk {
        cmd.contain_with(crate::ContainMode::TreeWalk);
    }
    let before = open_fd_count();
    arm();
    let err = cmd.spawn().err();
    disarm();
    let _left = captured_child();
    drop(cmd);

    // Each forced arm comes after `exec`.
    let (_err, fate) = expect_may_have_started_with(err.expect("the forced failure must fail the spawn"));
    assert_eq!(fate, expected);
    assert_eq!(open_fd_count(), before, "the failed spawn must close our pipe ends");
}

/// A foreign-reaped child was never signalled, so the teardown error says it could not be terminated, not that it was killed.
///
/// Mutant: `kill`'s `Ok` for a gone child is read as "killed" (the detail says "killed but could not
/// be reaped (ECHILD)"), or the `Gone` outcome falls into the `Err` arm.
#[cfg(unix)]
#[skuld::test]
fn finish_elevated_after_a_foreign_reap_does_not_claim_a_kill() {
    let (mut cmd, writer) = blocker_with_held_stdin();
    let child = cmd.spawn().expect("spawn");
    foreign_reap(&child, writer);

    let (detail, fate) = finish_elevated_detail_and_fate(child);
    assert!(detail.contains("could not be terminated"), "{detail}");
    assert!(detail.contains("it was already reaped"), "{detail}");
    assert!(!detail.contains("was killed"), "{detail}");
    assert_eq!(fate, ChildFate::Gone, "reaped by someone else");
}

/// A process-group child that someone else reaped is never `killpg`ed by the failure teardown: its
/// group number may name another group by now, and the error says the tree kill was skipped.
///
/// Mutant: `finish_elevated` runs `hard_kill_marking` before it learns the root was reaped.
#[cfg(unix)]
#[skuld::test]
fn finish_elevated_after_a_foreign_reap_sends_no_killpg_to_a_process_group() {
    let recorder = crate::containment::unix::fault::record_kill_group();
    let (mut cmd, writer) = blocker_with_held_stdin();
    cmd.contain_with(crate::containment::ContainMode::Session);
    let child = cmd.spawn().expect("spawn");
    assert!(
        child.attached.carries_recyclable_pgid(),
        "the test needs a number-named group kill"
    );
    foreign_reap(&child, writer);

    let detail = finish_elevated_detail(child);
    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "a reaped root's group number may name another group: no killpg ({detail})"
    );
    assert!(detail.contains("process group"), "{detail}");
    assert!(detail.contains("already reaped"), "{detail}");
}

/// End `child` and reap it behind its handle's back, as an application that owns SIGCHLD would.
#[cfg(unix)]
fn foreign_reap(child: &crate::Child, writer: std::io::PipeWriter) {
    let pid = child.id().pid();
    drop(writer);
    crate::test_child::wait_until_zombie(pid);
    let mut status = 0;
    // SAFETY: `pid` is this test's own zombie child.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
}

/// The `detail` of the error `finish_elevated` returns for `child` after a failed password write.
#[cfg(unix)]
fn finish_elevated_detail(child: crate::Child) -> String {
    finish_elevated_detail_and_fate(child).0
}

/// [`finish_elevated_detail`], and the fate the failure reports.
#[cfg(unix)]
fn finish_elevated_detail_and_fate(child: crate::Child) -> (String, ChildFate) {
    let (err, fate) = super::finish_elevated(
        child,
        Err(Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("the spawn fails")
    .expect_may_have_started_with();
    let Error::Elevation { detail, .. } = err else {
        panic!("expected an Elevation error, got {err:?}");
    };
    (detail, fate)
}

/// macOS: an identity that is gone means someone else reaped the child, so its pid may be reused: a
/// by-pid kill or reap could hit a stranger. The spawn fails (`Io`, as for any vanish) and the child
/// is forgotten, with a warning naming it. The seam leaves the real child running, so the test sees
/// that nothing was signalled or reaped.
///
/// Mutant: the arm tears the child down by pid.
#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_identity_gone_forgets_the_child_and_signals_nothing() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let mut cmd = blocker();
    fault::set_force_identity_vanished(true);
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);
    let left = captured_child();

    let (err, fate) = expect_may_have_started_with(err.expect("a vanished identity fails the spawn"));
    assert!(matches!(err, Error::Io(_)), "{err:?}");
    assert_eq!(fate, ChildFate::Gone, "the check found it reaped by someone else");
    assert_left_alone(mark, "was reaped by someone else", &left);
}

/// macOS: an identity that cannot be read (`Unknown`) fails the spawn as `Unassessable` and leaves
/// the child running and unreaped, with a warning naming it.
///
/// Mutant: the arm tears the child down by pid.
#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_identity_unknown_leaves_the_child_alone() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let mut cmd = blocker();
    fault::set_force_identity_unknown(true);
    let err = cmd.spawn().err();
    fault::set_force_identity_unknown(false);
    let left = captured_child();

    let (err, fate) = expect_may_have_started_with(err.expect("a refused identity fails the spawn"));
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    // Its identity is what could not be read.
    assert_eq!(fate, ChildFate::Running { id: None }, "left running, unreaped");
    assert_left_alone(mark, "cannot be shown to be ours", &left);
}

/// The spawn pid is readable only inside a hook: a stale one from an earlier spawn must not answer.
#[skuld::test]
fn spawn_pid_is_cleared_once_the_hook_has_run() {
    fault::run_at(fault::SpawnPoint::BeforeIdentity, 4242);
    assert!(
        std::panic::catch_unwind(fault::spawn_pid).is_err(),
        "spawn_pid must panic outside a hook"
    );
}

// Whether the program could have started =====

/// A bare program name no `PATH` holds.
const MISSING_PROGRAM: &str = "cosca-no-such-program-142";

/// A program that cannot be executed fails the spawn before it could start: std collected the
/// child whose `exec` failed.
///
/// Mutant: a failed `std` spawn answers that the program may have started.
#[skuld::test]
fn a_failed_exec_did_not_start_the_program() {
    let mut cmd = Command::new();
    cmd.args([MISSING_PROGRAM]);
    let err = expect_not_started(cmd.spawn().expect_err("a missing program fails the spawn"));
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound),
        "{err:?}"
    );
}

/// A refusal before the fork, here of a merge into a merge, did not start the program.
///
/// Mutant: stdio resolution answers that the program may have started.
#[skuld::test]
fn a_refused_stdio_setup_did_not_start_the_program() {
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdout(crate::stdio::Stdio::merge(crate::stdio::Fd::STDERR))
        .expect("stdout");
    cmd.stderr(crate::stdio::Stdio::merge(crate::stdio::Fd::STDOUT))
        .expect("stderr");
    let err = expect_not_started(cmd.spawn().expect_err("a merge into a merge is refused"));
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
}

/// `output`, `status` and `read` answer like `spawn` for a failed spawn, and say the program may
/// have started for any failure after it: here `read`'s invalid UTF-8.
///
/// Mutant: a failure after the spawn returns its cause bare.
#[cfg(unix)]
#[skuld::test]
fn run_to_completion_failures_after_the_spawn_may_have_started() {
    let mut missing = Command::new();
    missing.args([MISSING_PROGRAM]);
    expect_not_started(missing.read().expect_err("a missing program fails"));
    expect_not_started(missing.output().expect_err("a missing program fails"));
    expect_not_started(missing.status().expect_err("a missing program fails"));

    let mut cmd = Command::new();
    cmd.args(["printf", "\\377"]);
    let (err, fate) = expect_may_have_started_with(cmd.read().expect_err("invalid UTF-8 fails `read`"));
    assert_eq!(fate, ChildFate::Reaped, "`read` collected the exit");
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData),
        "{err:?}"
    );
}

/// A command with no program is refused before anything is made.
///
/// Mutant: building the `std` command answers that the program may have started.
#[skuld::test]
fn a_command_with_no_program_did_not_start() {
    let err = expect_not_started(Command::new().spawn().expect_err("no program, no spawn"));
    assert!(matches!(err, Error::Io(_)), "{err:?}");
}

/// An elevated spawn its backend cannot express is refused before any backend runs.
///
/// Mutant: the elevation rewrite answers that the program may have started.
#[cfg(unix)]
#[skuld::test]
fn an_elevation_refused_for_its_shape_did_not_start() {
    let mut cmd = Command::new();
    cmd.args(["/bin/sh", "-c", "true"]).elevate();
    cmd.fd(3, crate::stdio::Stdio::null()).expect("fd 3");
    let err = expect_not_started(cmd.spawn().expect_err("fd >= 3 is refused under elevation"));
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
}

/// Linux: a pidfd handshake whose channel cannot be made fails before the fork.
///
/// Mutant: the handshake's `open` answers that the program may have started.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_handshake_that_cannot_open_did_not_start() {
    let _armed = super::pidfd_handshake::fault::fail_done_fd(rustix::io::Errno::MFILE);
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    let err = expect_not_started(cmd.spawn().expect_err("a failed open fails the spawn"));
    assert!(
        matches!(err, Error::Io(ref e) if e.to_string() == format!("eventfd: {}", std::io::Error::from_raw_os_error(libc::EMFILE))),
        "{err:?}"
    );
}

// One OS situation, one fate =====

/// A child reaped behind the spawn's back after the teardown's kill was delivered is `Killed`: the
/// kill went first, and someone else collected the exit. (A child already reaped when the teardown
/// came to it is `Gone`: `identity_failure_after_a_foreign_reap_*`.)
///
/// Mutant: the teardown's `ECHILD` arm answers `Gone` whatever the kill did.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_child_reaped_elsewhere_after_the_teardowns_kill_is_killed() {
    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    // The hook reaps the zombie the kill made, so the teardown's own reap finds `ECHILD`.
    let pid = std::rc::Rc::new(std::cell::Cell::new(0));
    let _noted = fault::set_at(fault::SpawnPoint::BeforeIdentity, {
        let pid = std::rc::Rc::clone(&pid);
        move || pid.set(fault::spawn_pid())
    });
    let _foreign_reap = fault::set_between_kill_and_wait(move || {
        let pid = pid.get();
        assert_ne!(pid, 0, "the spawn noted the child's pid");
        crate::test_child::wait_until_zombie(pid);
        let mut status = 0;
        // SAFETY: `pid` is this test's own zombie child; this plays the application that reaps it.
        let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
    });
    fault::set_force_identity_vanished(true);
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);
    let (_err, fate) = expect_may_have_started_with(err.expect("the forced vanish fails the spawn"));
    assert_eq!(fate, ChildFate::Killed);
}

/// Every foreign verdict is one fate, decided by whether cosca's kill was delivered: `Killed` if it
/// was, `Gone` if cosca delivered nothing.
///
/// Mutant: either answer is swapped, or a verdict ignores the kill.
#[skuld::test]
fn a_foreign_verdict_is_killed_after_a_delivered_kill_and_gone_otherwise() {
    use crate::wait::exit_only::Foreign;
    #[cfg(target_os = "macos")]
    let all = [Foreign::Gone, Foreign::Other, Foreign::Orphaned];
    #[cfg(not(target_os = "macos"))]
    let all = [Foreign::Gone];
    for foreign in all {
        assert_eq!(foreign.fate(true), ChildFate::Killed, "{foreign:?}");
        assert_eq!(foreign.fate(false), ChildFate::Gone, "{foreign:?}");
    }
}
