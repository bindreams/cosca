use std::io::Write;
use std::os::fd::AsFd;
use std::time::Duration;

use super::{is_readable, poll_readable};

#[skuld::test]
fn is_readable_follows_the_descriptor() {
    let (rx, mut tx) = std::io::pipe().unwrap();
    assert!(!is_readable(rx.as_fd()).unwrap());
    tx.write_all(&[1]).unwrap();
    assert!(is_readable(rx.as_fd()).unwrap());
    // A look reads nothing: the descriptor stays readable.
    assert!(is_readable(rx.as_fd()).unwrap());
}

#[skuld::test]
fn poll_readable_returns_when_the_descriptor_is_readable() {
    let (rx, mut tx) = std::io::pipe().unwrap();
    tx.write_all(&[1]).unwrap();
    assert!(poll_readable(rx.as_fd(), None).unwrap());
}

/// A wait that is really armed is a block: the probe sees it.
#[skuld::test]
fn poll_readable_records_the_wait_it_arms() {
    let (rx, _tx) = std::io::pipe().unwrap();
    crate::wait::block_probe::take();
    assert!(!poll_readable(rx.as_fd(), Some(crate::wait::now())).unwrap());
    assert_eq!(crate::wait::block_probe::take().len(), 1);
}

#[skuld::test]
fn poll_readable_with_a_passed_deadline_says_not_readable() {
    let (rx, _tx) = std::io::pipe().unwrap();
    assert!(!poll_readable(rx.as_fd(), Some(crate::wait::now())).unwrap());
}

/// `poll(2)` takes `int` milliseconds: a deadline further off than that is armed in pieces, and the
/// longest piece is not an `EINVAL` (macOS, where rustix converts the timeout to `int`).
///
/// Mutant: arm the whole distance (or only `clamp_block`'s ~49 days) -> `EINVAL` on macOS, and an
/// armed block above `i32::MAX` ms everywhere.
#[skuld::test]
fn poll_readable_arms_no_block_longer_than_poll_takes() {
    let (rx, mut tx) = std::io::pipe().unwrap();
    tx.write_all(&[1]).unwrap();
    let far = crate::wait::now() + Duration::from_secs(100 * 24 * 3600);
    crate::wait::block_probe::take();
    assert!(poll_readable(rx.as_fd(), Some(far)).unwrap());
    let armed = crate::wait::block_probe::take();
    assert!(!armed.is_empty(), "the wait must have been armed");
    for a in armed {
        let a = a.expect("a deadline wait arms a bounded block");
        assert!(a <= Duration::from_millis(i32::MAX as u64), "armed {a:?}");
    }
}
