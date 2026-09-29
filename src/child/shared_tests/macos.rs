//! macOS-only `SharedChild` tests: the kqueue wait under `SIG_IGN`, and the by-pid reaps.
//! The cases that change the process-wide `SIGCHLD` disposition each run in a fresh re-exec of the
//! test binary.

use std::time::{Duration, Instant};

use super::fixtures::{spawn_std_blocker, Blocker};
use crate::child::shared::SharedChild;
use crate::identity::{quiet_fault, ReadPurpose, Resolved};
use crate::wait::backend::test_hooks::{self, ForcedOnce};
use crate::wait::exit_only::seams::{self as exit_seams, ForcedReap, HolderStep};
use crate::wait::exit_only::{self, Foreign, Peek, Target};

fn far() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

fn is_echild(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ECHILD)
}

// S11m: a reap that finds nothing after `Reapable` =====

/// S11m: a consuming reap that finds nothing right after the wait saw a zombie means the pid
/// names something else now. It takes the `ECHILD` path, with no assert in any build, and the
/// state goes back to `N`.
///
/// Mutant: a `debug_assert!` on the by-pid target.
#[test]
fn a_reap_that_finds_none_after_reapable_takes_the_echild_path() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let none = exit_seams::force_reap_once(ForcedReap::None);
    let err = b.shared.wait().expect_err("the forced empty reap");
    drop(none);
    assert!(is_echild(&err), "{err}");
    assert!(format!("{:?}", b.shared).contains("N"), "{:?}", b.shared);
    // The zombie was never consumed (the reap was forced empty): a real wait reaps it.
    b.shared.wait().expect("the zombie is still there");
}

// S2g: a start read that says the pid is gone =====

/// S2g: a start-checked peek whose start read says the pid is `Gone` answers `Foreign(Gone)`.
///
/// Mutant: `Gone` treated as a match: the peek returns `Exit`.
#[test]
fn a_start_read_gone_takes_the_echild_path() {
    let (child, stdin) = spawn_std_blocker();
    let start = crate::identity::StartToken::from_raw(1);
    drop(stdin);
    let mut child = child;
    // The child's exit, seen without consuming it.
    let target = Target::pid(child.id(), Some(start));
    let forced = quiet_fault::force_quiet_read_error_once(ReadPurpose::Peek, Resolved::Gone);
    let peeked = loop {
        match exit_only::peek(&target).expect("peek") {
            Peek::Running => confirm_exit_of(&child),
            other => break other,
        }
    };
    drop(forced);
    assert_eq!(peeked, Peek::Foreign(Foreign::Gone));
    child.wait().expect("reap");
}

/// Block until `child`'s exit is visible, without consuming it.
fn confirm_exit_of(child: &std::process::Child) {
    // SAFETY: an all-zero `siginfo_t` is a valid value, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT,
        )
    };
    assert_eq!(r, 0, "waitid(WNOWAIT): {}", std::io::Error::last_os_error());
}

// S10r: the second reap =====

/// The second reap of an exited, unreaped child, whose start reads as `read`.
fn second_reap_with_start(read: Resolved<crate::identity::StartToken>) -> std::process::Child {
    let (mut child, stdin) = spawn_std_blocker();
    drop(stdin);
    confirm_exit_of(&child);
    let start = crate::identity::StartToken::from_raw(7);
    let forced = quiet_fault::force_quiet_read_error_once(ReadPurpose::SecondPeek, read);
    crate::wait::exit_only::second_reap(child.id(), Some(start));
    drop(forced);
    let _ = &mut child;
    child
}

/// S10r: a second reap whose start no longer matches is skipped: nothing is consumed.
///
/// Mutant: a second consume without the start check.
#[test]
fn a_second_reap_with_a_start_mismatch_is_skipped() {
    let mut child = second_reap_with_start(Resolved::Found(crate::identity::StartToken::from_raw(99)));
    let status = child
        .wait()
        .expect("the zombie must still be there: the mismatch skipped the consume");
    assert!(status.success());
}

/// S10r: a second reap whose start matches consumes the leftover zombie.
///
/// Mutant: the start check inverted.
#[test]
fn a_second_reap_with_a_matching_start_consumes_the_leftover() {
    let child = second_reap_with_start(Resolved::Found(crate::identity::StartToken::from_raw(7)));
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer.
    let r = unsafe { libc::waitpid(child.id() as i32, &mut status, libc::WNOHANG) };
    assert_eq!(r, -1, "the matching second reap must have consumed the zombie");
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
    std::mem::forget(child);
}

/// S10r: a second peek that meets `ECHILD` is skipped quietly, not logged as a foreign reap or a
/// warning.
///
/// Mutant: the `ECHILD` logged at `warn`.
#[test]
fn a_second_reap_that_meets_echild_is_skipped() {
    crate::log_capture::install();
    let (mut child, stdin) = spawn_std_blocker();
    drop(stdin);
    confirm_exit_of(&child);
    let marker = format!("second reap of pid {}", child.id());
    let mark = crate::log_capture::mark();
    let forced = exit_seams::force_peek_once(Err(std::io::Error::from_raw_os_error(libc::ECHILD)));
    crate::wait::exit_only::second_reap(child.id(), None);
    drop(forced);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(
        !levels.contains(&log::Level::Warn),
        "an ECHILD must not warn: {levels:?}"
    );
    child.wait().expect("the zombie was never consumed");
}

/// S10r: a second consume that finds nothing is skipped quietly.
///
/// Mutant: a `debug_assert!` on the by-pid consume.
#[test]
fn a_second_reap_that_finds_nothing_is_skipped() {
    crate::log_capture::install();
    let (mut child, stdin) = spawn_std_blocker();
    drop(stdin);
    confirm_exit_of(&child);
    let marker = format!("second reap of pid {}", child.id());
    let mark = crate::log_capture::mark();
    let none = exit_seams::force_reap_once(ForcedReap::None);
    crate::wait::exit_only::second_reap(child.id(), None);
    drop(none);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(
        !levels.contains(&log::Level::Warn),
        "finding nothing must not warn: {levels:?}"
    );
    child.wait().expect("the zombie was never consumed");
}

/// S10r: the second peek runs after every first reap, traced or not. For an untraced child it
/// answers `ECHILD` and is skipped quietly.
///
/// Mutant: a second peek gated on `p_oppid`: no `SecondPeek` step for an untraced child.
#[test]
fn a_second_peek_runs_after_every_first_reap() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    exit_seams::holder_steps();
    b.shared.wait().expect("wait");
    assert_eq!(exit_seams::holder_steps(), [HolderStep::Reap, HolderStep::SecondPeek]);
}

/// `pbi_start_quiet`'s test seam hits only its purpose: arming one of `Peek`, `PreReap` and
/// `SecondPeek` leaves the other two reads untouched.
///
/// Mutant: a purpose-blind seam.
#[test]
fn force_quiet_read_error_once_hits_only_its_purpose() {
    let pid = std::process::id();
    let real = crate::identity::pbi_start_quiet(pid, ReadPurpose::Peek);
    assert!(matches!(real, Resolved::Found(_)), "{real:?}");
    let all = [ReadPurpose::Peek, ReadPurpose::PreReap, ReadPurpose::SecondPeek];
    for armed in all {
        let forced = quiet_fault::force_quiet_read_error_once(armed, Resolved::Unknown);
        for other in all.into_iter().filter(|p| *p != armed) {
            assert_eq!(
                crate::identity::pbi_start_quiet(pid, other),
                real,
                "{other:?} read while {armed:?} was armed"
            );
        }
        assert_eq!(crate::identity::pbi_start_quiet(pid, armed), Resolved::Unknown);
        assert_eq!(
            crate::identity::pbi_start_quiet(pid, armed),
            real,
            "the force is taken once"
        );
        drop(forced);
    }
}

// Task 2b: the `SIG_IGN` hang =====

const MARKER: &str = "COSCA_TEST_SHARED_SIGIGN";
const CASE_ENV: &str = "COSCA_TEST_SHARED_SIGIGN_CASE";

fn run_case(path: &str, case: &str) {
    crate::test_child::run_fixture_case(path, MARKER, CASE_ENV, case);
}

/// A root child adopted into a `SharedChild`, under `SIGCHLD` set to `SIG_IGN` with a live
/// sibling blocked on its stdin, so the kernel reaps the root itself and a blocking `waitid`
/// would sleep until the sibling is gone. The root's stdin closes from inside the holder's first
/// blocking `kevent` round, so the waiter is known to be asleep first.
fn ignoring_sigchld_with_a_sibling() -> (SharedChild, std::process::Child, std::process::ChildStdin, ForcedOnce) {
    crate::test_child::set_sigchld_ignored(true);
    let (sibling, sibling_stdin) = spawn_std_blocker();
    let (root, root_stdin) = spawn_std_blocker();
    let id = super::fixtures::identity_of(&root);
    let shared = SharedChild::adopt(root, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let mut root_stdin = Some(root_stdin);
    let end = test_hooks::on_kevent_round(0, move || drop(root_stdin.take()));
    (shared, sibling, sibling_stdin, end)
}

/// The holder's wait on macOS is the kqueue wait, never a blocking `waitid`. Structural, and
/// under the default disposition: the exit is confirmed first (a zombie is there), so a
/// `waitid` would return at once and only the kevent request tells the two apart. This is what
/// the `SIG_IGN` cases below prove by hanging.
///
/// Mutant: the holder's platform wait is a blocking `waitid(WNOWAIT)`.
#[test]
fn the_holder_waits_on_the_kqueue_not_in_waitid() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let _hooks = test_hooks::HookGuard::install(|_, _| {});
    b.shared.wait().expect("wait");
    assert!(
        !test_hooks::await_requested_timeouts().is_empty(),
        "the holder never asked the kqueue"
    );
}

/// A `wait` on a child the kernel reaped returns `ECHILD` while a sibling lives.
///
/// Mutant: a blocking `waitid` instead of the kqueue form, which sleeps until the child list
/// empties.
#[test]
fn a_wait_on_a_child_the_kernel_reaped_returns_while_a_sibling_lives() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_wait_on_a_child_the_kernel_reaped_returns_while_a_sibling_lives),
            "",
        );
    }
    let (shared, _sibling, _stdin, _end) = ignoring_sigchld_with_a_sibling();
    let err = shared.wait().expect_err("the kernel reaped the root");
    assert!(is_echild(&err), "{err}");
}

/// A `wait_deadline` far past the bound returns `ECHILD`, not `Ok(None)`.
///
/// Mutant: the same.
#[test]
fn a_wait_timeout_far_past_the_bound_returns_echild() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_wait_timeout_far_past_the_bound_returns_echild),
            "",
        );
    }
    let (shared, _sibling, _stdin, _end) = ignoring_sigchld_with_a_sibling();
    let err = shared.wait_deadline(far()).expect_err("the kernel reaped the root");
    assert!(is_echild(&err), "{err}");
}

/// A sync drop of a child the kernel reaped returns: its wait after a successful kill answers
/// `ECHILD` instead of sleeping.
///
/// Mutant: the same.
#[test]
fn a_sync_drop_of_a_child_the_kernel_reaped_returns() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_sync_drop_of_a_child_the_kernel_reaped_returns),
            "",
        );
    }
    crate::test_child::set_sigchld_ignored(true);
    let (_sibling, _sibling_stdin) = spawn_std_blocker();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::test_child::leaked_writer_stdin()).expect("stdin");
    cmd.stdout(crate::Stdio::null()).expect("stdout");
    let child = cmd.spawn().expect("spawn");
    drop(child);
}
