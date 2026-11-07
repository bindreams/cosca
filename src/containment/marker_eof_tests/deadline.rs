//! The deadline contract of `block_until_drained` (never early, no drain at or past expiry), and
//! the drain-suppression and `EV_CLEAR` properties it rests on. "Never early" is proved against the
//! real clock; "no drain past expiry" against a pipe that is already full, so no writer races it.

use std::os::fd::AsFd;

use crate::test_child::Console;
use std::time::{Duration, Instant};

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

use super::{fill_pipe_to_capacity, fionread, kill_release_reap, marker_pipe, spawn_marker_holder};
use crate::containment::marker_eof::{arm, block_until_drained, drain_test_hooks, interpret_read_event, probe};
use crate::containment::TreeDrain;
use crate::os_process::macos::kqueue::Event;

/// This system's real pipe buffer capacity, MEASURED rather than assumed: fill a throwaway,
/// non-blocking, in-process pipe until `write` reports `EAGAIN`, and sum what fit. A writer
/// told to write precisely this many bytes, then stop, fills the marker pipe to at least the
/// ready threshold — no concurrent reader required to avoid deadlock. Used only to pick how
/// much a test's OWN writer script should write; never compared directly against a value
/// measured on the marker pipe itself (a SEPARATE kernel object: XNU grows each pipe's buffer
/// independently, by its own write history).
fn measure_pipe_capacity() -> usize {
    let (_r, w) = marker_pipe();
    let flags = rustix::fs::fcntl_getfl(&w).unwrap_or_else(|e| panic!("fcntl F_GETFL failed: {e}"));
    rustix::fs::fcntl_setfl(&w, flags | rustix::fs::OFlags::NONBLOCK)
        .unwrap_or_else(|e| panic!("fcntl F_SETFL O_NONBLOCK failed: {e}"));
    let chunk = [0u8; 4096];
    let mut total = 0usize;
    loop {
        match nix::unistd::write(&w, &chunk) {
            Ok(got) => total += got,
            Err(nix::errno::Errno::EAGAIN) => return total, // full — this is the capacity
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => panic!("scratch pipe write failed: {e}"),
        }
    }
}

#[skuld::test]
fn block_until_drained_never_returns_before_a_real_deadline() {
    // The never-early half of the deadline contract: cosca promises it never reports a
    // verdict before the deadline (a `now >= deadline` check on a monotonic clock), and never
    // promises an upper bound on how late — so this asserts the lower bound EXACTLY, no slack,
    // against a REAL clock (no mock needed: scheduling can only push a return later, never
    // earlier). `yes` keeps the descriptor continuously ready, so this can only terminate via
    // the deadline path, not a real EOF.
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.executable("/bin/sh").args(["sh", "-c", "exec yes >&3"]);
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    let mut child = cmd.spawn().expect("spawn yes");
    let marker = child.fd_read_end(3.into()).expect("marker read end");

    let deadline = Instant::now()
        .checked_add(Duration::from_millis(300))
        .expect("deadline");
    let verdict = block_until_drained(marker.as_fd(), Some(deadline)).expect("bounded wait");
    let now = Instant::now();

    assert_eq!(
        verdict,
        TreeDrain::MembersRemain,
        "a sustained writer must still report MembersRemain"
    );
    assert!(
        now >= deadline,
        "must never return before the deadline: now={now:?}, deadline={deadline:?}"
    );

    // `yes` blocks writing to the full pipe; closing its read end is what ends it after the kill.
    kill_release_reap(child, marker);
}

#[skuld::test]
fn arm_sets_ev_clear_so_a_repeated_poll_without_a_new_edge_reports_nothing() {
    // White-box proof `arm` requests `EV_CLEAR`: a level that crossed the clamp once and has
    // stayed there ever since, unchanged and undrained, must not re-fire.
    let cap = measure_pipe_capacity();
    let (child, marker, stdin) = spawn_marker_holder(&format!("yes | head -c {cap} >&3; exec cat >/dev/null"));
    let kq = arm(marker.as_fd(), false).expect("arm");
    let mut events = [KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    )];

    let n = kq
        .native()
        .kevent(&[], &mut events, None)
        .expect("initial blocking poll");
    assert_eq!(n, 1, "expected the initial crossing to be ready");
    assert!(
        !events[0].flags().contains(EvFlags::EV_EOF),
        "the writer is still alive and holding the descriptor — this must not be EOF"
    );

    let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let n2 = kq
        .native()
        .kevent(&[], &mut events, Some(zero))
        .expect("second, zero-timeout poll");
    assert_eq!(
        n2, 0,
        "EV_CLEAR must suppress a re-poll of an unchanged level — got {n2} events"
    );

    kill_release_reap(child, stdin);
}

#[skuld::test]
fn interpret_read_event_suppresses_drain_when_told_to() {
    // White-box: `suppress_drain = true` must never consume bytes, exercised with a real event.
    let cap = measure_pipe_capacity();
    let (child, marker, stdin) = spawn_marker_holder(&format!("yes | head -c {cap} >&3; exec cat >/dev/null"));
    let kq = arm(marker.as_fd(), true).expect("arm");
    let mut events = [KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    )];
    let n = kq.native().kevent(&[], &mut events, None).expect("blocking poll");
    assert_eq!(n, 1, "expected the crossing to be ready");

    let before = fionread(marker.as_fd());
    let event = Event::from_kevent(&events[0]).expect("a readable event");
    let verdict = interpret_read_event(event, marker.as_fd(), true).expect("interpret with suppress_drain=true");
    let after = fionread(marker.as_fd());

    assert_eq!(
        verdict, None,
        "a non-EOF event with drain suppressed must stay inconclusive"
    );
    assert_eq!(after, before, "suppress_drain=true must never consume any bytes");

    kill_release_reap(child, stdin);
}

/// A marker pipe filled to capacity in this process BEFORE its holder exists, so no external
/// writer races the test, and a live holder of its write end. Returns the holder, its stdin write
/// end, the marker's read end and the bytes queued.
fn full_marker_with_a_live_holder() -> (crate::Child, crate::PipeWriter, std::io::PipeReader, i32) {
    let (marker_r, marker_w) = std::io::pipe().expect("pipe");
    let queued = fill_pipe_to_capacity(marker_r.as_fd(), marker_w.as_fd());
    assert!(
        queued > 0,
        "the pipe must be full before the test can prove nothing drains it"
    );

    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.executable("/bin/sh").args(["sh", "-c", "exec cat >/dev/null"]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    // Moves `marker_w` in — this test's own copy is gone from here on, before the wait ever
    // runs, so `arm`'s write-end-retained check sees a clean `Clear`, not `HeldByUs`.
    cmd.fd(
        3,
        crate::Stdio::from_file(std::fs::File::from(std::os::fd::OwnedFd::from(marker_w))),
    )
    .expect("marker pipe");
    let mut child = cmd.spawn().expect("spawn /bin/sh");
    let stdin = child.fd_write_end(crate::Fd::STDIN).expect("stdin write end");
    assert_eq!(
        child.try_wait().expect("try_wait"),
        None,
        "the holder already exited before this test could observe it"
    );
    (child, stdin, marker_r, queued)
}

#[skuld::test]
fn probe_never_drains_even_past_the_low_water_clamp() {
    // `probe` is itself a check AT expiry (principle 13).
    let (child, stdin, marker_r, queued_before) = full_marker_with_a_live_holder();
    let fd = marker_r.as_fd();

    let baseline = drain_test_hooks::drained_bytes();
    let verdict = probe(fd).expect("probe");
    let queued_after = fionread(fd);

    assert_eq!(
        verdict,
        TreeDrain::MembersRemain,
        "the writer is still alive and holding the descriptor — the event was non-EOF"
    );
    assert_eq!(
        queued_after, queued_before,
        "probe must not consume any bytes from the pipe"
    );
    assert_eq!(
        drain_test_hooks::drained_bytes(),
        baseline,
        "probe is a check at expiry (principle 13) and must never drain"
    );

    kill_release_reap(child, stdin);
}

/// A non-EOF event read at or after the deadline funds no drain: the deadline is elapsed before
/// the call, the pipe is full, and the event is there to be read.
///
/// Mutant: `block_until_drained` drains an event it read after the deadline passed.
#[skuld::test]
fn block_until_drained_with_an_elapsed_deadline_does_not_drain_a_full_pipe() {
    let (child, stdin, marker_r, queued_before) = full_marker_with_a_live_holder();
    let fd = marker_r.as_fd();

    let baseline = drain_test_hooks::drained_bytes();
    let verdict = block_until_drained(fd, Some(Instant::now())).expect("block_until_drained");
    let queued_after = fionread(fd);

    assert_eq!(
        verdict,
        TreeDrain::MembersRemain,
        "the writer is still alive and holding the descriptor — the event was non-EOF"
    );
    assert_eq!(
        queued_after, queued_before,
        "an event read at or after the deadline must not consume any bytes from the pipe"
    );
    assert_eq!(
        drain_test_hooks::drained_bytes(),
        baseline,
        "an event read at or after the deadline funds no drain (principle 13)"
    );

    kill_release_reap(child, stdin);
}
