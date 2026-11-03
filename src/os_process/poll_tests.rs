use std::io::Write;
use std::os::fd::AsFd;

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
