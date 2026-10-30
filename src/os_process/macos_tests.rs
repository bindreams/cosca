use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::time::Duration;

use super::ExitWatch;

/// A watch on a pipe's read end, and the two ends.
fn pipe_watch() -> (std::io::PipeReader, std::io::PipeWriter, ExitWatch) {
    let (rx, tx) = std::io::pipe().unwrap();
    let watch = ExitWatch::readable(rx.as_fd()).unwrap();
    (rx, tx, watch)
}

/// An already-passed deadline: one non-blocking pass.
fn expired() -> Option<Option<std::time::Instant>> {
    crate::wait::deadline_from(Duration::ZERO)
}

#[skuld::test]
fn an_unfired_watch_reads_nothing() {
    let (_rx, _tx, watch) = pipe_watch();
    assert!(!watch.drain().unwrap());
    assert!(!watch.block(expired()).unwrap());
}

/// Mutant: `block` forgets the event it read.
#[skuld::test]
fn block_remembers_the_event_it_read() {
    let (mut rx, mut tx, watch) = pipe_watch();
    tx.write_all(&[1]).unwrap();
    assert!(watch.block(None).unwrap());
    // The pipe is empty again, so only `seen` can answer.
    rx.read_exact(&mut [0]).unwrap();
    assert!(watch.drain().unwrap());
}

/// Mutant: `drain` forgets the event it read.
#[skuld::test]
fn drain_remembers_the_event_it_read() {
    let (mut rx, mut tx, watch) = pipe_watch();
    tx.write_all(&[1]).unwrap();
    assert!(watch.drain().unwrap());
    rx.read_exact(&mut [0]).unwrap();
    assert!(watch.block(expired()).unwrap());
}
