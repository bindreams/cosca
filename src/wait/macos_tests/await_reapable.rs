//! Tests for the macOS wait (`await_reapable`): its own `kevent` loop, the self-registration, the
//! backoff and the deadline. Every test that blocks on a real kqueue is covered by the nextest
//! override in `.config/nextest.toml`.
//!
//! The cases that change the process-wide `SIGCHLD` disposition each run in a fresh re-exec of
//! this test binary (`run_case`), so they cannot affect the other tests.

use std::process::{Child, ChildStdin};
use std::time::Duration;

use nix::sys::event::Kqueue;

use crate::wait::backend::{await_reapable, await_reapable_on, test_hooks, Waited};
use crate::wait::exit_only::seams as exit_seams;
use crate::wait::exit_only::seams::HolderStep;
use crate::wait::exit_only::Peek;

fn spawn_blocker() -> (Child, ChildStdin) {
    let _guard = crate::child::spawn::spawn_lock();
    let mut child = crate::test_child::held_std_blocker(std::process::Stdio::null())
        .spawn()
        .expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    (child, stdin)
}

/// Block until `child`'s exit is visible, without consuming it.
fn confirm_exit(child: &Child) {
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

// Reapable, and never reaping =====

/// A zombie is `Reapable`, and the wait leaves it reapable: the caller's own `wait` then reaps the
/// root with its status.
///
/// Mutant: the peek consumes (drops `WNOWAIT`), so the caller's `wait` finds nothing.
#[test]
fn await_reapable_reports_a_zombie_and_leaves_it_reapable() {
    let (mut child, stdin) = spawn_blocker();
    drop(stdin);
    assert_eq!(await_reapable(child.id(), None).expect("wait"), Waited::Reapable);
    let status = child.wait().expect("the zombie must still be there to reap");
    assert!(status.success(), "{status:?}");
}

// The deadline contract =====

/// A deadline already past still takes its final peek, and a zombie it finds is `Reapable`.
///
/// Mutant: no final peek at expiry: `DeadlinePassed`.
#[test]
fn await_reapable_at_a_past_deadline_takes_its_final_peek() {
    let (child, stdin) = spawn_blocker();
    drop(stdin);
    confirm_exit(&child);
    let _running = exit_seams::force_peek_once(Ok(Peek::Running));
    let waited = await_reapable(child.id(), Some(std::time::Instant::now())).expect("wait");
    assert_eq!(waited, Waited::Reapable);
    let mut child = child;
    child.wait().expect("reap");
}

/// Principle 13 for the kqueue wait: with the clock frozen, every `kevent` is armed with at most
/// the time remaining (the drains with none), and an expired wait takes one final peek and starts
/// no further round.
///
/// Mutant: an unbounded `kevent` under a deadline (its `debug_assert!` fires); a round after the
/// deadline (an extra zero-timeout call).
#[test]
fn a_deadline_kevent_backoff_is_clamped_and_ends_with_one_peek() {
    let (mut child, stdin) = spawn_blocker();
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    let limit = Duration::from_millis(30);
    let _hooks = test_hooks::HookGuard::install(|_, _| {});
    // Only round 0 may block: a second one would start after the deadline.
    test_hooks::on_kevent_round(1, || panic!("a round started after the deadline"));
    exit_seams::holder_steps();
    let waited = await_reapable(child.id(), Some(at + limit)).expect("wait");
    assert_eq!(waited, Waited::DeadlinePassed);
    let timeouts = test_hooks::await_requested_timeouts();
    // drain, the one blocking round, drain; nothing after the deadline.
    assert_eq!(timeouts.len(), 3, "{timeouts:?}");
    assert_eq!(timeouts[0], Some(Duration::ZERO));
    let blocking = timeouts[1].expect("a deadline wait arms a bounded kevent");
    assert!(blocking <= limit, "armed {blocking:?} with only {limit:?} remaining");
    assert_eq!(timeouts[2], Some(Duration::ZERO));
    assert_eq!(exit_seams::holder_steps(), [HolderStep::FinalPeek]);
    assert!(crate::wait::now() >= at + limit);
    drop(stdin);
    child.wait().expect("reap");
}

// EV_CLEAR =====

const MARKER_KNOTE: &str = "COSCA_TEST_AWAIT_KNOTE";

/// After the round that delivered `NOTE_EXIT`, no `EVFILT_PROC` event arrives again: the knote is
/// registered with `EV_CLEAR`, so a backoff `kevent` blocks for its interval rather than
/// re-activating at once. (An `EVFILT_SIGNAL` event may legitimately land later: `NOTE_EXIT`
/// posts before `SZOMB` and the `SIGCHLD`, `kern_exit.c:2562` against `:2631`, `:2637`.)
///
/// Mutant: the knote registered without `EV_CLEAR`.
#[test]
fn no_evfilt_proc_event_arrives_after_the_round_that_delivered_note_exit() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER_KNOTE) {
        return run_case(
            crate::test_child::fixture_path!(no_evfilt_proc_event_arrives_after_the_round_that_delivered_note_exit),
            MARKER_KNOTE,
            "",
        );
    }
    let (mut child, stdin) = spawn_blocker();
    let _hooks = test_hooks::HookGuard::install(|_, _| {});
    let mut stdin = Some(stdin);
    // The child exits only after `EVFILT_PROC` is registered and the wait is about to block.
    test_hooks::on_kevent_round(0, move || drop(stdin.take()));
    // At least one more round after the one that delivers `NOTE_EXIT`.
    test_hooks::on_before_repeek(|| {
        std::mem::forget(exit_seams::force_peek_once(Ok(Peek::Running)));
    });
    assert_eq!(await_reapable(child.id(), None).expect("wait"), Waited::Reapable);
    child.wait().expect("reap");

    let events = test_hooks::take_events();
    let proc_filter = nix::sys::event::EventFilter::EVFILT_PROC as i16;
    let first_exit = events
        .iter()
        .position(|&(filter, fflags)| filter == proc_filter && fflags & libc::NOTE_EXIT != 0)
        .unwrap_or_else(|| panic!("a NOTE_EXIT must have been recorded: {events:?}"));
    let later: Vec<_> = events[first_exit + 1..]
        .iter()
        .filter(|&&(filter, _)| filter == proc_filter)
        .collect();
    assert!(later.is_empty(), "EVFILT_PROC re-delivered after NOTE_EXIT: {events:?}");
}

// Subprocess plumbing =====

/// Run the fixture `path` in a fresh re-exec of this binary with `marker` set and `case` in
/// [`CASE_ENV`].
fn run_case(path: &str, marker: &str, case: &str) {
    crate::test_child::run_fixture_case(path, marker, CASE_ENV, case);
}

const CASE_ENV: &str = "COSCA_TEST_AWAIT_CASE";

fn case() -> String {
    std::env::var(CASE_ENV).expect("the driver sets the case")
}

/// Whether `pid` can still be reaped by number: `Some(status)` if so, `None` on `ECHILD`.
fn reap_by_number(pid: u32) -> Option<i32> {
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer.
    let r = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    if r == pid as i32 {
        return Some(status);
    }
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD),
        "waitpid({pid})"
    );
    None
}

// The ESRCH paths =====

const MARKER_ESRCH: &str = "COSCA_TEST_AWAIT_ESRCH";

/// A registration that got `ESRCH` sends the wait to its backoff, and the backoff follows the
/// kernel, not the `SIGCHLD` disposition: the disposition is flipped between re-peeks (default to
/// `SIG_IGN`, and back), and the wait ends with whichever verdict the kernel produced, `Reapable`
/// if the zombie is there and `Gone` if XNU reaped the child itself (`kern_exit.c:2577`).
///
/// Mutant: a wait that decides from the disposition it saw when it started.
#[test]
fn a_macos_esrch_wait_follows_the_kernel_not_the_disposition() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER_ESRCH) {
        for case in ["dfl_then_ign", "ign_then_dfl"] {
            run_case(
                crate::test_child::fixture_path!(a_macos_esrch_wait_follows_the_kernel_not_the_disposition),
                MARKER_ESRCH,
                case,
            );
        }
        return;
    }
    let case = case();
    let (flip_to_ignored, expect_gone) = match case.as_str() {
        "dfl_then_ign" => (true, true),
        "ign_then_dfl" => {
            crate::test_child::set_sigchld_ignored(true);
            (false, false)
        }
        other => panic!("unknown case {other}"),
    };
    let (mut child, stdin) = spawn_blocker();
    let pid = child.id();
    let _esrch = test_hooks::force_proc_registration_esrch_once();
    let mut stdin = Some(stdin);
    // Between re-peeks: flip the disposition, then let the child exit.
    test_hooks::on_esrch_repeek(move || {
        crate::test_child::set_sigchld_ignored(flip_to_ignored);
        drop(stdin.take());
    });
    let waited = await_reapable(pid, None).expect("wait");
    if expect_gone {
        assert_eq!(waited, Waited::Gone, "XNU reaped the child itself under SIG_IGN");
        assert_eq!(reap_by_number(pid), None, "there is nothing left to reap");
    } else {
        assert_eq!(
            waited,
            Waited::Reapable,
            "the zombie stays under the default disposition"
        );
        assert!(reap_by_number(pid).is_some(), "the zombie is there to reap");
    }
    // The std `Child` owns nothing more: it was reaped (or auto-reaped) above.
    std::mem::forget(child.stdout.take());
    let _ = &mut child;
}

/// The wait registers `EVFILT_PROC` itself, so a caller whose own registration got `ESRCH` (a
/// failed spawn's normal path) still waits for a real `NOTE_EXIT`: under `SIG_IGN` with a live
/// sibling XNU sends no `SIGCHLD`, and nothing else would wake the kqueue.
///
/// Mutant: no self-registration: the wait blocks on a `NOTE_EXIT` that never comes.
#[test]
fn await_reapable_on_waits_out_a_caller_registration_that_got_esrch() {
    const MARKER: &str = "COSCA_TEST_AWAIT_CALLER_ESRCH";
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(await_reapable_on_waits_out_a_caller_registration_that_got_esrch),
            MARKER,
            "",
        );
    }
    crate::test_child::set_sigchld_ignored(true);
    let (_sibling, _sibling_stdin) = spawn_blocker();
    let (child, stdin) = spawn_blocker();
    let pid = child.id();
    // The caller's own registration, on the kqueue it hands in, "got ESRCH": it registered nothing.
    let kq = Kqueue::new().expect("kqueue");
    let mut stdin = Some(stdin);
    // The child exits only from inside the first blocking round, once the wait is about to sleep.
    test_hooks::on_kevent_round(0, move || drop(stdin.take()));
    // The first peek finds the child running (it is): the wait must then block, not spin.
    let waited = await_reapable_on(&kq, pid, None).expect("wait");
    assert_eq!(waited, Waited::Gone, "XNU reaped the child itself under SIG_IGN");
    std::mem::forget(child);
}
