//! A parent pipe end that tokio refuses to register (here: a regular file, which is not a FIFO)
//! is a real OS outcome, not a contract violation: each taker must return `None` and warn, in
//! every build, never `debug_assert!`. Each test plants a non-FIFO end through the `os` fields
//! (reachable from this descendant module) and keys its log assertion on a fd number no other
//! test uses, so a concurrent test's warn cannot satisfy it.

use std::os::fd::OwnedFd;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::child::ParentEnd;
use crate::stdio::Fd;

fn a_regular_file_fd() -> OwnedFd {
    let file = tempfile::tempfile().expect("tempfile");
    OwnedFd::from(file)
}

fn reader() -> ParentEnd {
    ParentEnd::Reader(std::io::PipeReader::from(a_regular_file_fd()))
}

fn writer() -> ParentEnd {
    ParentEnd::Writer(std::io::PipeWriter::from(a_regular_file_fd()))
}

async fn a_child() -> super::Child {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sleep", "30"]);
    cmd.spawn().expect("spawn")
}

/// Runs `take` (which must return `None`), asserts it did not panic, and that exactly one `warn`
/// containing `marker` was logged (the marker embeds a fd number unique to the calling test).
fn assert_warns_and_returns_none(marker: &str, take: impl FnOnce() -> bool) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let outcome = catch_unwind(AssertUnwindSafe(take));
    assert!(
        matches!(outcome, Ok(true)),
        "a failed tokio pipe conversion must return None without panicking: {outcome:?}"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, marker),
        [log::Level::Warn],
        "a failed conversion must be logged once, at warn"
    );
}

#[tokio::test]
async fn fd_read_end_warns_instead_of_asserting_on_a_failed_conversion() {
    let mut child = a_child().await;
    child.os.pipes.insert(Fd::from(91), reader());
    assert_warns_and_returns_none("fd 91 read end dropped", || child.fd_read_end(91).is_none());
}

#[tokio::test]
async fn fd_write_end_warns_instead_of_asserting_on_a_failed_conversion() {
    let mut child = a_child().await;
    child.os.pipes.insert(Fd::from(92), writer());
    assert_warns_and_returns_none("fd 92 write end dropped", || child.fd_write_end(92).is_none());
}

#[tokio::test]
async fn take_owned_out_warns_instead_of_asserting_on_a_failed_conversion() {
    let mut child = a_child().await;
    child.os.owned_std.insert(Fd::from(93), reader());
    assert_warns_and_returns_none("fd 93 merge-target read end dropped", || {
        child.take_owned_out(Fd::from(93)).is_none()
    });
}

#[tokio::test]
async fn take_owned_in_warns_instead_of_asserting_on_a_failed_conversion() {
    let mut child = a_child().await;
    child.os.owned_std.insert(Fd::from(94), writer());
    assert_warns_and_returns_none("fd 94 merge-target write end dropped", || {
        child.take_owned_in(Fd::from(94)).is_none()
    });
}
