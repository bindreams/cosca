use std::time::Duration;

use super::{absolute, drive};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::fake::{Answer, FakeProcess};
use crate::wait::{block_probe, fault, test_clock};

fn fake(exits: impl IntoIterator<Item = Answer>) -> FakeProcess {
    FakeProcess::new(ProcessId::current(), exits)
}

#[skuld::test]
fn zero_timeout_looks_once_and_never_blocks() {
    block_probe::take();
    let mut p = fake([Answer::Running]);
    assert!(!drive(&mut p, absolute(Some(Duration::ZERO))).unwrap());
    assert_eq!(p.looks(), 1);
    assert!(block_probe::take().is_empty(), "a zero timeout must not block");
}

/// Mutant: swallow a failed look as a wake, or block before returning it.
#[skuld::test]
fn a_failed_look_is_returned_without_blocking() {
    block_probe::take();
    let mut p = fake([Answer::Err(std::io::ErrorKind::PermissionDenied)]);
    let err = drive(&mut p, absolute(None)).unwrap_err();
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{err:?}"
    );
    assert_eq!(p.looks(), 1);
    assert!(block_probe::take().is_empty());
}

#[skuld::test]
fn exited_before_first_look_returns_true_without_blocking() {
    block_probe::take();
    let mut p = fake([Answer::Exited]);
    assert!(drive(&mut p, absolute(None)).unwrap());
    assert_eq!(p.looks(), 1);
    assert!(block_probe::take().is_empty());
}

#[skuld::test]
fn wakes_and_looks_again() {
    block_probe::take();
    let mut p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(drive(&mut p, absolute(Some(Duration::from_secs(60)))).unwrap());
    assert_eq!(p.looks(), 2);
    assert_eq!(block_probe::take().len(), 1, "one wait, between the two looks");
}

#[skuld::test]
fn expiry_ends_in_one_final_look() {
    block_probe::take();
    let (_clock, start) = test_clock::FrozenClockGuard::install();
    let timeout = Duration::from_secs(10);
    let mut p = fake([Answer::Running, Answer::Running]);
    // The deadline passes while the first look is being made.
    p.on_look(|n| {
        if n == 0 {
            test_clock::advance(Duration::from_secs(11));
        }
    });
    assert!(!drive(&mut p, absolute(Some(timeout))).unwrap());
    assert_eq!(p.looks(), 2);
    let last = *p.look_times().last().unwrap();
    assert!(last > start + timeout, "the final look must come after the deadline");
    assert!(
        block_probe::take().is_empty(),
        "nothing is armed at or after the deadline"
    );
}

/// Mutant: let `Duration::MAX` overflow the deadline sum.
#[skuld::test]
fn duration_max_is_unbounded() {
    block_probe::take();
    let mut p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(drive(&mut p, absolute(Some(Duration::MAX))).unwrap());
    assert_eq!(
        block_probe::take(),
        [None],
        "an overflowing timeout arms an unbounded wait"
    );
}

#[cfg(windows)]
mod windows {
    //! The Windows arm of the blocking wait: it never reports "still alive" before the real
    //! deadline. Seams are documented in `crate::wait`.

    use std::time::{Duration, Instant};

    use super::{absolute, drive};
    use crate::os_process::drive::exited_by_id;
    use crate::os_process::{open, Op};
    use crate::test_child::live_blocker as blocker;
    use crate::wait::test_clock::FrozenClockGuard;
    use crate::wait::{block_probe, wait_ms_probe};
    use crate::wait::{remaining_override_seam, wait_clamp_seam};

    /// A never-exiting target armed with a sub-millisecond remainder rounds up to 1ms, still reports
    /// alive at the deadline, and derives its argument from the site's own deadline.
    ///
    /// Mutant: truncate in `win32_timeout_ms` (`d.as_millis()`) -> `ms` is 0. Mutant: add slack ->
    /// `ms` is above 1. Mutant: ignore the site's deadline -> `requested` is not 5ms.
    #[skuld::test]
    fn exited_by_arms_the_ceiling_of_the_remaining_duration() {
        let (child, stdin, id) = blocker();
        let mut process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let (_clock, at) = FrozenClockGuard::install();
        wait_ms_probe::take();
        let _override = remaining_override_seam::set(Duration::from_micros(500));
        let deadline = at + Duration::from_millis(5);
        let result = drive(&mut *process, absolute(Some(Duration::from_millis(5))));
        let reached = Instant::now() >= deadline;
        let arms = wait_ms_probe::take();
        drop(stdin);
        child.wait().expect("reap the blocker");
        assert!(
            !result.expect("a live never-exiting child must not report a wait failure"),
            "a never-exiting child is still alive at the deadline"
        );
        assert!(reached, "the call returned before the real deadline");
        let first = arms.first().expect("at least one armed wait");
        assert_eq!(first.remaining, Duration::from_micros(500));
        assert_eq!(first.ms, 1);
        assert_eq!(
            first.requested,
            Duration::from_millis(5),
            "the site must pass the time left to its own deadline (clock frozen at the deadline's origin)"
        );
    }

    /// `exited_by_id` arms its first wait with the whole timeout it was given, on a live process.
    ///
    /// Mutant: the timeout is dropped on the way to the loop (the wait is unbounded, or zero).
    #[skuld::test]
    fn exited_by_id_arms_the_wait_from_its_timeout() {
        let (child, stdin, id) = blocker();
        let (_clock, _at) = FrozenClockGuard::install();
        block_probe::take();
        let result = exited_by_id(id, Some(Duration::from_millis(50)));
        let armed = block_probe::take();
        drop(stdin);
        child.wait().expect("reap the blocker");
        assert!(!result.expect("a live never-exiting child must not report a wait failure"));
        assert_eq!(armed.first(), Some(&Some(Duration::from_millis(50))), "{armed:?}");
    }

    /// An early, unclamped `WAIT_TIMEOUT` hours before the deadline is not trusted: the site re-arms.
    ///
    /// Mutant: return on the first `WAIT_TIMEOUT` (no recheck, or one conditioned on the clamp) ->
    /// one arm, wrongly reports alive.
    #[skuld::test]
    fn exited_by_never_reports_still_alive_before_the_deadline() {
        let (child, stdin, id) = blocker();
        let mut process = open(id, Op::Wait).unwrap().expect("a live process opens");
        wait_ms_probe::take();
        let _override = remaining_override_seam::set(Duration::from_micros(500));
        wait_ms_probe::on_second_arm(move || drop(stdin)); // EOF -> the blocker exits for real
        let result = drive(&mut *process, absolute(Some(Duration::from_secs(3600))));
        let arms = wait_ms_probe::take();
        let exited = result.expect("a genuinely-terminated child must not report a wait failure");
        child.wait().expect("reap the child after it exits");
        assert!(exited, "an early WAIT_TIMEOUT was trusted");
        assert!(arms.len() >= 2, "expected a re-arm, got {} arm(s)", arms.len());
    }

    /// A wait clamped below the deadline re-arms, recomputing `remaining` each round.
    ///
    /// Mutant: drop the re-arm loop -> one arm, wrongly reports alive. Mutant: hoist `remaining`
    /// above the loop -> `remaining` does not shrink.
    #[skuld::test]
    fn exited_by_re_arms_past_a_clamped_timeout() {
        let (child, stdin, id) = blocker();
        let mut process = open(id, Op::Wait).unwrap().expect("a live process opens");
        wait_ms_probe::take();
        let _clamp = wait_clamp_seam::set(5);
        wait_ms_probe::on_second_arm(move || drop(stdin));
        let result = drive(&mut *process, absolute(Some(Duration::from_secs(3600))));
        let arms = wait_ms_probe::take();
        let exited = result.expect("a genuinely-terminated child must not report a wait failure");
        child.wait().expect("reap the child after it exits");
        assert!(exited, "a clamped WAIT_TIMEOUT was trusted");
        wait_ms_probe::assert_rearmed_with_fresh_remaining(&arms, 5);
    }

    /// Under a frozen test clock a finite deadline still ends: each real wait advances the clock.
    ///
    /// Mutant: drop `advance_by_elapsed_if_frozen` from `wait_until` -> `remaining` never shrinks
    /// and the call re-arms forever.
    #[skuld::test]
    fn exited_by_terminates_under_a_frozen_clock() {
        let (child, stdin, id) = blocker();
        let mut process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let (_clock, at) = FrozenClockGuard::install();
        let deadline = at + Duration::from_millis(50);
        let result = drive(&mut *process, absolute(Some(Duration::from_millis(50))));
        let reached = Instant::now() >= deadline;
        drop(stdin);
        child.wait().expect("reap the blocker");
        assert!(!result.expect("a live never-exiting child must not report a wait failure"));
        assert!(reached, "the call returned before the real deadline");
    }
}

/// An identity naming a live pid under a start token it never had: `open` is `None` for it.
fn gone_id() -> ProcessId {
    let current = ProcessId::current();
    ProcessId::from_parts_for_test(current.pid(), current.start_token_raw() ^ 1)
}

/// Mutant: `exited_by_id` takes the seam only after `open`, so a gone id never reaches it.
#[skuld::test]
fn exited_by_id_returns_a_forced_watch_error_for_a_gone_id() {
    fault::set_force_watch_error(true);
    assert!(super::exited_by_id(gone_id(), None).is_err());
    assert!(!fault::armed(), "the seam is consumed");
}

/// Mutant: `exited_by_id` asserts only after `open`, so a gone id may block inside a section.
#[cfg(feature = "tokio")]
#[skuld::test]
#[should_panic(expected = "would block inside an async Drop")]
fn exited_by_id_refuses_a_gone_id_inside_a_bounded_section() {
    let _section = crate::bounded::Section::enter();
    _ = super::exited_by_id(gone_id(), Some(Duration::ZERO));
}
