use std::time::Duration;

use super::exited_by;
use crate::identity::ProcessId;
use crate::os_process::fake::{Answer, FakeProcess};
use crate::wait::{block_probe, fault, test_clock};

fn fake(exits: impl IntoIterator<Item = Answer>) -> FakeProcess {
    FakeProcess::new(ProcessId::current(), exits, [])
}

/// Mutant: block at a zero timeout, or look a second time.
#[skuld::test]
fn zero_timeout_looks_once_and_never_blocks() {
    block_probe::take();
    let mut p = fake([Answer::Running]);
    assert!(!exited_by(&mut p, Some(Duration::ZERO)).unwrap());
    assert_eq!(p.looks(), 1);
    assert!(block_probe::take().is_empty(), "a zero timeout must not block");
}

/// Mutant: block before looking, or after an `Exited` look.
#[skuld::test]
fn exited_before_first_look_returns_true_without_blocking() {
    block_probe::take();
    let mut p = fake([Answer::Exited]);
    assert!(exited_by(&mut p, None).unwrap());
    assert_eq!(p.looks(), 1);
    assert!(block_probe::take().is_empty());
}

/// Mutant: trust the wake as the answer instead of looking again.
#[skuld::test]
fn wakes_and_looks_again() {
    block_probe::take();
    let mut p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(exited_by(&mut p, Some(Duration::from_secs(60))).unwrap());
    assert_eq!(p.looks(), 2);
    assert_eq!(block_probe::take().len(), 1, "one wait, between the two looks");
}

/// Mutant: answer `false` on the expiry itself, without a look after the deadline.
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
    assert!(!exited_by(&mut p, Some(timeout)).unwrap());
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
    assert!(exited_by(&mut p, Some(Duration::MAX)).unwrap());
    assert_eq!(
        block_probe::take(),
        [None],
        "an overflowing timeout arms an unbounded wait"
    );
}

/// Mutant: look before taking the seam.
#[skuld::test]
fn forced_watch_error_is_returned_before_looking() {
    let mut p = fake([Answer::Exited]);
    fault::set_force_watch_error(true);
    assert!(exited_by(&mut p, None).is_err());
    assert_eq!(p.looks(), 0);
    assert!(!fault::armed(), "the seam is consumed");
}

/// Mutant: drop the assert from `exited_by`.
#[cfg(feature = "tokio")]
#[skuld::test]
#[should_panic(expected = "would block inside an async Drop")]
fn refuses_inside_a_bounded_section() {
    let _section = crate::bounded::Section::enter();
    let mut p = fake([Answer::Exited]);
    _ = exited_by(&mut p, Some(Duration::ZERO));
}
