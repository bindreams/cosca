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
    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
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

/// A short-lived child that starts and exits inside the wait: its `SIGCHLD` wakes the kqueue with
/// no event the wait is looking for, exactly as a sibling's exit would.
fn spurious_wake() {
    let mut child =
        crate::test_spawn::spawn(&mut std::process::Command::new("/usr/bin/true")).expect("spawn /usr/bin/true");
    child.wait().expect("reap /usr/bin/true");
}

/// Principle 13 for the kqueue wait: with the clock frozen, every blocking `kevent` is armed with
/// at most the time remaining when it starts, no round starts at or after the deadline, and the
/// expired wait takes one final peek. Round 0 is woken by a real `SIGCHLD` before the deadline, so
/// the wait must go round again, and the test tells that wake from a round after the deadline by
/// the frozen clock, not by counting rounds (another test's child may wake this one too).
///
/// Mutant: an unbounded `kevent` under a deadline (its `debug_assert!` fires); a round after the
/// deadline (no expiry check before the block); a timeout above the time remaining; no final peek.
#[test]
fn a_deadline_kevent_backoff_is_clamped_and_ends_with_one_peek() {
    let (mut child, stdin) = spawn_blocker();
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    let limit = Duration::from_millis(30);
    let deadline = at + limit;
    let _hooks = test_hooks::HookGuard::install(|_, _| {});
    let remainings = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let _rounds = test_hooks::on_every_kevent_round({
        let remainings = std::rc::Rc::clone(&remainings);
        move |round| {
            let left = deadline.saturating_duration_since(crate::wait::now());
            assert!(!left.is_zero(), "round {round} started at or after the deadline");
            remainings.borrow_mut().push(left);
            if round == 0 {
                spurious_wake();
            }
        }
    });
    exit_seams::holder_steps();
    let waited = await_reapable(child.id(), Some(deadline)).expect("wait");
    assert_eq!(waited, Waited::DeadlinePassed);
    let timeouts = test_hooks::await_requested_timeouts();
    let blocking: Vec<Duration> = timeouts
        .iter()
        .filter(|t| **t != Some(Duration::ZERO))
        .map(|t| t.expect("a deadline wait arms a bounded kevent"))
        .collect();
    let remainings = remainings.borrow();
    assert!(
        remainings.len() >= 2,
        "the wake must send the wait round again: {remainings:?}"
    );
    assert_eq!(blocking.len(), remainings.len(), "{timeouts:?}");
    for (armed, left) in blocking.iter().zip(remainings.iter()) {
        assert!(armed <= left, "armed {armed:?} with only {left:?} remaining");
    }
    assert_eq!(exit_seams::holder_steps(), [HolderStep::FinalPeek]);
    assert!(crate::wait::now() >= deadline);
    drop(stdin);
    child.wait().expect("reap");
}

/// A `kevent` interrupted by a signal is retried with the time remaining now, not the time
/// remaining when the interrupted call started. The interrupted call is made to spend 10 ms of
/// the frozen clock.
///
/// Mutant: the timeout computed once, before the retry loop.
#[test]
fn an_interrupted_kevent_is_retried_with_the_time_remaining_now() {
    let (mut child, stdin) = spawn_blocker();
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    let spent = Duration::from_millis(10);
    let _hooks = test_hooks::HookGuard::install(|_, _| {});
    let _eintr = test_hooks::force_eintr_once(spent);
    let waited = await_reapable(child.id(), Some(at + Duration::from_millis(30))).expect("wait");
    assert_eq!(waited, Waited::DeadlinePassed);
    let timeouts = test_hooks::await_requested_timeouts();
    // The drain, the interrupted call, its retry, then the drain after expiry.
    let first = timeouts[1].expect("bounded");
    let retry = timeouts[2].expect("bounded");
    assert!(
        retry + spent <= first,
        "the retry was armed with {retry:?} after {spent:?} of {first:?} was spent"
    );
    drop(stdin);
    child.wait().expect("reap");
}

/// A deadline beyond XNU's `kevent` `tv_sec` limit still returns the child's exit, and no call is
/// armed with more than `i32::MAX` seconds. The child is ended from the round hook, so the exit
/// is imminent when the first `kevent` is called.
///
/// Mutant: no clamp in `kevent_timeout`: `EINVAL` from the first call.
#[test]
fn await_reapable_with_a_deadline_beyond_the_kevent_limit_returns_the_exit() {
    let (mut child, stdin) = spawn_blocker();
    let mut stdin = Some(stdin);
    let _end = test_hooks::on_kevent_round(0, move || drop(stdin.take()));
    let deadline = crate::wait::deadline_from(Duration::from_secs(u64::from(u32::MAX)))
        .and_then(|d| d)
        .expect("a deadline this far is still finite");
    let waited = await_reapable(child.id(), Some(deadline)).expect("a far deadline is not an error");
    assert_eq!(waited, Waited::Reapable);
    for armed in test_hooks::await_requested_timeouts() {
        let armed = armed.expect("a deadline wait arms a bounded kevent");
        assert!(armed <= Duration::from_secs(i32::MAX as u64), "armed {armed:?}");
    }
    child.wait().expect("reap");
}

/// The wait's own rounds honour the clamp seam: with the clamp lowered to 10 ms, a 50 ms
/// deadline is covered by several calls, none longer than the clamp, and the wait still ends only
/// at the deadline.
///
/// Mutant: `kevent_round` arms its `kevent` without `kevent_timeout`: one call carries the whole
/// remaining time.
#[test]
fn await_reapable_rearms_a_remaining_time_above_the_clamp_in_pieces() {
    let (mut child, stdin) = spawn_blocker();
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    let _hooks = test_hooks::HookGuard::install(|_, _| {});
    let clamp = Duration::from_millis(10);
    test_hooks::set_clamp_override(clamp);
    let waited = await_reapable(child.id(), Some(at + Duration::from_millis(50))).expect("wait");
    assert_eq!(waited, Waited::DeadlinePassed);
    let timeouts = test_hooks::await_requested_timeouts();
    let blocking = timeouts.iter().filter(|t| **t != Some(Duration::ZERO)).count();
    assert!(
        blocking >= 2,
        "one call cannot cover 50 ms under a 10 ms clamp: {timeouts:?}"
    );
    assert!(
        timeouts.iter().all(|t| t.is_some_and(|t| t <= clamp)),
        "every call is capped: {timeouts:?}"
    );
    drop(stdin);
    child.wait().expect("reap");
}

// The test hooks =====

/// A dropped hook guard takes its unfired hook with it.
///
/// Mutant: a guard whose `Drop` does nothing.
#[test]
fn dropped_hook_guards_remove_their_hooks() {
    let fired = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let count = |fired: &std::rc::Rc<std::cell::Cell<u32>>| {
        let fired = std::rc::Rc::clone(fired);
        move || fired.set(fired.get() + 1)
    };
    drop(test_hooks::on_before_repeek(count(&fired)));
    drop(test_hooks::on_esrch_repeek(count(&fired)));
    drop(test_hooks::on_kevent_round(0, count(&fired)));
    drop(test_hooks::on_every_kevent_round({
        let fired = std::rc::Rc::clone(&fired);
        move |_| fired.set(fired.get() + 1)
    }));
    test_hooks::fire_before_repeek();
    test_hooks::fire_esrch_repeek();
    test_hooks::fire_kevent_round(0);
    assert_eq!(fired.get(), 0, "a hook outlived its guard");
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
    let _end = test_hooks::on_kevent_round(0, move || drop(stdin.take()));
    // At least one more round after the one that delivers `NOTE_EXIT`.
    let _repeek = test_hooks::on_before_repeek(|| {
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
    let _flip = test_hooks::on_esrch_repeek(move || {
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
    let _end = test_hooks::on_kevent_round(0, move || drop(stdin.take()));
    // The first peek finds the child running (it is): the wait must then block, not spin.
    let waited = await_reapable_on(&kq, pid, None).expect("wait");
    assert_eq!(waited, Waited::Gone, "XNU reaped the child itself under SIG_IGN");
    std::mem::forget(child);
}
