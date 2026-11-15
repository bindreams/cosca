//! Tests for the macOS wait (`await_reapable`): its own `kevent` loop, the self-registration, the
//! backoff and the deadline. A test that blocks on a real kqueue ends its wait from a
//! [`block_probe`](crate::wait::block_probe) hook, at the block, through the event the wait
//! watches.
//!
//! The cases that change the process-wide `SIGCHLD` disposition each run in a fresh re-exec of
//! this test binary (`run_case`), so they cannot affect the other tests.

use std::process::{Child, ChildStdin};
use std::time::Duration;

use crate::identity::{FakeKernel, HostKernel};
use crate::os_process::macos::kqueue::{test_hooks, Kqueue, Subscription};
use crate::wait::block_probe::{self, on_blocking, on_each_block};
use crate::wait::macos::{await_reapable, await_reapable_on, reap_registration, Waited};

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
#[skuld::test]
fn await_reapable_reports_a_zombie_and_leaves_it_reapable() {
    let (mut child, stdin) = spawn_blocker();
    drop(stdin);
    assert_eq!(
        await_reapable(&HostKernel, child.id(), None, None).expect("wait"),
        Waited::Reapable
    );
    let status = child.wait().expect("the zombie must still be there to reap");
    assert!(status.success(), "{status:?}");
}

// The deadline contract =====

/// A deadline already past still takes its final peek, and a zombie it finds is `Reapable`.
///
/// Mutant: no final peek at expiry: `DeadlinePassed`.
#[skuld::test]
fn await_reapable_at_a_past_deadline_takes_its_final_peek() {
    let (child, stdin) = spawn_blocker();
    drop(stdin);
    confirm_exit(&child);
    let waited = await_reapable(&HostKernel, child.id(), None, Some(std::time::Instant::now())).expect("wait");
    assert_eq!(waited, Waited::Reapable);
    let mut child = child;
    child.wait().expect("reap");
}

/// What a runner that deschedules this thread for `d` inside a `kevent` call does to the frozen
/// clock: the wait advances it by the call's measured elapsed time (#488).
fn stall(d: Duration) {
    crate::wait::test_clock::advance_by_elapsed_if_frozen(d);
}

/// Runs `hook` with the index of each blocking round of the wait (0 for the first), and holds the
/// frozen clock until the end of round `round`'s hook: the calls before it take no clock time,
/// however long the runner stalls them. From the end of that hook on, measured time drives the clock
/// again and runs the deadline out. A `kevent` the OS interrupts is a round of its own.
fn hold_the_clock_until_round(round: u32, mut hook: impl FnMut(u32) + 'static) -> block_probe::Armed {
    let mut held = Some(crate::wait::test_clock::ZeroElapsedGuard::install());
    on_each_block(move |block| {
        // Another waiter's `Condvar` block has no number and is no round of this wait.
        let Some(n) = block.n else { return };
        let index = n - 1;
        hook(index);
        if index == round {
            drop(held.take());
        }
    })
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
/// the frozen clock, not by counting rounds (another test's child may wake this one too). The
/// clock is held until round 1, so a runner stall before it cannot run the deadline out first;
/// round 0 spends 1 ms of it explicitly, so round 1 has less left than round 0. The child runs and
/// the kernel says so to every peek, which counts the ones at or after the deadline: the wait is
/// `DeadlinePassed` after exactly one.
///
/// Mutant: an unbounded `kevent` under a deadline (its `debug_assert!` fires); a round after the
/// deadline (no expiry check before the block: the round-start assertion fires; none before the
/// round's peek: a peek at or after the deadline besides the final one makes two); a
/// timeout above the time remaining, or computed once per wait; no final peek (none at or after
/// the deadline); a second final peek; the clock not held (the stall at round 0 ends the wait
/// there).
#[skuld::test]
fn a_deadline_kevent_backoff_is_clamped_and_ends_with_one_peek() {
    let (mut child, stdin) = spawn_blocker();
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    let limit = Duration::from_millis(30);
    let deadline = at + limit;
    let remainings = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let _rounds = hold_the_clock_until_round(1, {
        let remainings = std::rc::Rc::clone(&remainings);
        move |round| {
            let left = deadline.saturating_duration_since(crate::wait::now());
            assert!(!left.is_zero(), "round {round} started at or after the deadline");
            remainings.borrow_mut().push(left);
            if round == 0 {
                stall(limit);
                crate::wait::test_clock::advance(Duration::from_millis(1));
                spurious_wake();
            }
        }
    });
    let late_peeks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let kernel = FakeKernel::over(&HostKernel).on_every_peek(child.id(), {
        let late_peeks = std::sync::Arc::clone(&late_peeks);
        move || {
            if crate::wait::now() >= deadline {
                late_peeks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Ok(None)
        }
    });
    block_probe::take();
    let waited = await_reapable(&kernel, child.id(), None, Some(deadline)).expect("wait");
    assert_eq!(waited, Waited::DeadlinePassed);
    assert_eq!(
        late_peeks.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "exactly one peek at or after the deadline: the final peek"
    );
    let timeouts = block_probe::take();
    let blocking: Vec<Duration> = timeouts
        .iter()
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
    assert!(crate::wait::now() >= deadline);
    drop(stdin);
    child.wait().expect("reap");
}

/// A `kevent` interrupted by a signal is retried with the time remaining now, not the time
/// remaining when the interrupted call started. The interrupted call is made to spend 10 ms of
/// the frozen clock, which is held until round 0 so a runner stall before it changes nothing: the
/// retry is armed with exactly what the interrupted call was armed with, less what it spent.
///
/// Mutant: the timeout computed once, before the retry loop (the retry is armed with `first`); the
/// clock not held (the 25 ms stall also comes off the retry's time, which is armed with nothing,
/// or with less than `first - spent`).
#[skuld::test]
fn an_interrupted_kevent_is_retried_with_the_time_remaining_now() {
    let (mut child, stdin) = spawn_blocker();
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    let spent = Duration::from_millis(10);
    let _eintr = test_hooks::force_eintr_once(spent);
    let _stall = hold_the_clock_until_round(0, |round| {
        if round == 0 {
            stall(Duration::from_millis(25));
        }
    });
    block_probe::take();
    let waited = await_reapable(&HostKernel, child.id(), None, Some(at + Duration::from_millis(30))).expect("wait");
    assert_eq!(waited, Waited::DeadlinePassed);
    let timeouts = block_probe::take();
    // The interrupted call, then its retry: a retry armed with nothing left is recorded too.
    assert!(
        timeouts.len() >= 2,
        "the interrupted call must be retried: {timeouts:?}"
    );
    let first = timeouts[0].expect("bounded");
    let retry = timeouts[1].expect("bounded");
    assert_eq!(
        retry + spent,
        first,
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
#[skuld::test]
fn await_reapable_with_a_deadline_beyond_the_kevent_limit_returns_the_exit() {
    let (mut child, stdin) = spawn_blocker();
    let mut stdin = Some(stdin);
    let _end = on_blocking(move || drop(stdin.take()));
    let deadline = crate::wait::deadline_from(Duration::from_secs(u64::from(u32::MAX)))
        .expect("a deadline this far is still finite");
    block_probe::take();
    let waited = await_reapable(&HostKernel, child.id(), None, Some(deadline)).expect("a far deadline is not an error");
    assert_eq!(waited, Waited::Reapable);
    for armed in block_probe::take() {
        let armed = armed.expect("a deadline wait arms a bounded kevent");
        assert!(armed <= Duration::from_secs(i32::MAX as u64), "armed {armed:?}");
    }
    child.wait().expect("reap");
}

// The test hooks =====

/// A dropped hook guard takes its unfired hook with it.
///
/// Mutant: a guard whose `Drop` does nothing.
#[skuld::test]
fn dropped_hook_guards_remove_their_hooks() {
    let fired = std::rc::Rc::new(std::cell::Cell::new(0u32));
    drop(test_hooks::on_esrch_repeek({
        let fired = std::rc::Rc::clone(&fired);
        move || fired.set(fired.get() + 1)
    }));
    test_hooks::fire_esrch_repeek();
    assert_eq!(fired.get(), 0, "a hook outlived its guard");
}

// EV_CLEAR =====

const MARKER_KNOTE: &str = "COSCA_TESTCFG_AWAIT_KNOTE";

/// After the round that delivered `NOTE_EXIT`, no `EVFILT_PROC` event arrives again: the knote is
/// registered with `EV_CLEAR`, so a backoff `kevent` blocks for its interval rather than
/// re-activating at once. (An `EVFILT_SIGNAL` event may legitimately land later: `NOTE_EXIT`
/// posts before `SZOMB` and the `SIGCHLD`.)
///
/// Mutant: the knote registered without `EV_CLEAR`.
#[skuld::test]
fn no_evfilt_proc_event_arrives_after_the_round_that_delivered_note_exit() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER_KNOTE) {
        return run_case(
            crate::test_child::fixture_path!(no_evfilt_proc_event_arrives_after_the_round_that_delivered_note_exit),
            MARKER_KNOTE,
            "",
        );
    }
    let (mut child, stdin) = spawn_blocker();
    let mut stdin = Some(stdin);
    // The child exits only after `EVFILT_PROC` is registered and the wait is about to block.
    let _end = on_blocking(move || drop(stdin.take()));
    // At least one more round after the one that delivers `NOTE_EXIT`: the first peek, before the
    // round that blocks, and the one after it, which the exit is not yet visible to, find no record.
    let kernel = FakeKernel::over(&HostKernel)
        .on_peek(child.id(), Ok(None))
        .on_peek(child.id(), Ok(None));
    assert_eq!(
        await_reapable(&kernel, child.id(), None, None).expect("wait"),
        Waited::Reapable
    );
    assert!(kernel.all_rows_taken(), "both peeks before the exit must have happened");
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

const CASE_ENV: &str = "COSCA_TESTCFG_AWAIT_CASE";

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

const MARKER_ESRCH: &str = "COSCA_TESTCFG_AWAIT_ESRCH";

/// A registration that got `ESRCH` sends the wait to its backoff, and the backoff follows the
/// kernel, not the `SIGCHLD` disposition: the disposition is flipped between re-peeks (default to
/// `SIG_IGN`, and back), and the wait ends with whichever verdict the kernel produced, `Reapable`
/// if the zombie is there and `Gone` if XNU reaped the child itself.
///
/// Mutant: a wait that decides from the disposition it saw when it started.
#[skuld::test]
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
            crate::test_child::set_signal_ignored(libc::SIGCHLD, true);
            (false, false)
        }
        other => panic!("unknown case {other}"),
    };
    let (mut child, stdin) = spawn_blocker();
    let pid = child.id();
    let kernel = FakeKernel::over(&HostKernel).on_subscribe_refused(reap_registration(pid), libc::ESRCH);
    let mut stdin = Some(stdin);
    // Between re-peeks: flip the disposition, then let the child exit.
    let _flip = test_hooks::on_esrch_repeek(move || {
        crate::test_child::set_signal_ignored(libc::SIGCHLD, flip_to_ignored);
        drop(stdin.take());
    });
    let waited = await_reapable(&kernel, pid, None, None).expect("wait");
    assert!(
        kernel.all_rows_taken(),
        "the wait's registration must have been refused"
    );
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
/// The block's hook ends the child, waits until the kernel has reaped it itself (`NOTE_EXIT` is
/// posted before that reap), and looks at the wait's kqueue:
/// the `NOTE_EXIT` must be on it. A look that finds nothing is ended by a byte on a pipe the test
/// registered on the same kqueue, so the assertion on the look fails instead of the wait blocking.
///
/// Mutant: no self-registration: the look finds nothing, as the wait would have blocked on a
/// `NOTE_EXIT` that never comes.
#[skuld::test]
fn await_reapable_on_waits_out_a_caller_registration_that_got_esrch() {
    const MARKER: &str = "COSCA_TESTCFG_AWAIT_CALLER_ESRCH";
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(await_reapable_on_waits_out_a_caller_registration_that_got_esrch),
            MARKER,
            "",
        );
    }
    crate::test_child::set_signal_ignored(libc::SIGCHLD, true);
    let (_sibling, _sibling_stdin) = spawn_blocker();
    let (child, stdin) = spawn_blocker();
    let pid = child.id();
    // The caller's own registration, on the kqueue it hands in, "got ESRCH": it registered nothing.
    let kq = Kqueue::new().expect("kqueue");
    // The backstop: a byte on this pipe wakes the wait if the look finds nothing.
    let (backstop, mut backstop_writer) = std::io::pipe().expect("pipe");
    kq.subscribe(Subscription::Readable {
        fd: std::os::fd::AsRawFd::as_raw_fd(&backstop),
        low_water: 1,
    })
    .expect("watch the backstop pipe");
    let looked = std::rc::Rc::new(std::cell::Cell::new(None));
    let mut stdin = Some(stdin);
    // The child exits only from inside the first blocking round, once the wait is about to sleep.
    let _end = on_each_block({
        let looked = std::rc::Rc::clone(&looked);
        move |block| {
            if block.n != Some(1) {
                return;
            }
            drop(stdin.take());
            // A re-check of the real condition, with no end of its own: the child is the one ending.
            let mut pause = Duration::from_millis(1);
            while crate::test_child::is_unreaped_child(pid) {
                std::thread::sleep(pause);
                pause = pause.saturating_mul(2);
            }
            looked.set(block.ready());
            if looked.get() != Some(true) {
                std::io::Write::write_all(&mut backstop_writer, &[1]).expect("write the backstop byte");
            }
        }
    });
    // The first peek finds the child running (it is): the wait must then block, not spin.
    let waited = await_reapable_on(&HostKernel, &kq, pid, None, None).expect("wait");
    assert_eq!(
        looked.get(),
        Some(true),
        "the wait's own registration must have put the child's exit on its kqueue"
    );
    assert_eq!(waited, Waited::Gone, "XNU reaped the child itself under SIG_IGN");
    std::mem::forget(child);
}
