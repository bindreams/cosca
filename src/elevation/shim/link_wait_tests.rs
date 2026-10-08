//! The one outcome: `wait`, `try_wait`, `observe` and the frames they decode.

use super::super::fake_shim::Rig;
use super::super::outcome::classify;
use super::super::probe::LinkEvent;
use super::super::{KillError, KillOutcome, LinkOutcome, NotStarted, NotStartedCause, StartState, WaitError};
use crate::elevation::shim::protocol::{Errno, Frame, NotExecuted, Refusal, Signal};

#[skuld::test]
fn front_exit_while_pending_is_not_started() {
    let rig = Rig::new();
    // A pending start has no connection to read; a `wait` that tries panics, and that is the failure.
    let waited = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rig.link.wait().unwrap()));
    assert!(
        waited.is_ok(),
        "wait on a pending start must refuse it, not read a connection"
    );
    assert_eq!(
        waited.unwrap(),
        LinkOutcome::NotStarted(NotStarted {
            shim_connected: false,
            cause: NotStartedCause::Withheld,
        })
    );
    assert_eq!(rig.link.observe().unwrap().start, StartState::Refused);
    assert!(!rig.link.dir().join(super::super::SOCKET_NAME).exists());
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::RefusedStart);
}

/// A live shim writes `bytes` and closes, then the link waits for its outcome.
fn wait_after(bytes: &[u8]) -> LinkOutcome {
    let rig = Rig::new();
    let mut shim = rig.live();
    shim.send(bytes);
    shim.close();
    rig.link.wait().unwrap()
}

#[skuld::test]
fn truncated_and_garbled_frames_are_shim_lost() {
    let cases: [(&str, &[u8]); 8] = [
        ("EOF with nothing", b""),
        ("a tag alone", b"S"),
        ("a truncated status", b"S\x01\x02"),
        ("an unknown tag", b"X\x00\x00\x00\x00"),
        ("an F with a zero value", b"F\x00\x00\x02\x00"),
        ("an F of an unknown kind", b"F\x01\x00\x09\x00"),
        ("an R of an unknown code", b"R\x07\x00\x00\x00"),
        ("a second hello", b"H"),
    ];
    for (name, bytes) in cases {
        assert_eq!(wait_after(bytes), LinkOutcome::ShimLost, "{name}");
    }
}

#[skuld::test]
fn f_frame_is_not_started() {
    let kinds = [
        NotExecuted::ForkFailed(Errno(11)),
        NotExecuted::ExecFailed(Errno(2)),
        NotExecuted::SetupFailed(Errno(24)),
        NotExecuted::TerminatedBeforeExec(Signal(15)),
    ];
    for kind in kinds {
        assert_eq!(
            wait_after(&Frame::NotExecuted(kind).encode()),
            LinkOutcome::NotStarted(NotStarted {
                shim_connected: true,
                cause: NotStartedCause::NotExecuted(kind),
            })
        );
    }
}

#[skuld::test]
fn l_frame_is_supervision_lost() {
    assert_eq!(
        wait_after(&Frame::Lost(0x0900).encode()),
        LinkOutcome::SupervisionLost(0x0900)
    );
}

#[skuld::test]
fn s_u_and_r_frames_map_to_their_outcomes() {
    assert_eq!(wait_after(&Frame::Status(0x2a00).encode()), LinkOutcome::Exited(0x2a00));
    assert_eq!(wait_after(&Frame::StatusLost.encode()), LinkOutcome::StatusLost);
    assert_eq!(
        wait_after(&Frame::Refused(Refusal::Denied).encode()),
        LinkOutcome::NotStarted(NotStarted {
            shim_connected: true,
            cause: NotStartedCause::ShimRefused(Refusal::Denied),
        })
    );
}

#[skuld::test]
fn classify_settles_a_prefix_only_when_no_continuation_could_complete_it() {
    assert_eq!(classify(b"S\x01", false), None);
    assert_eq!(classify(b"S\x01", true), Some(LinkOutcome::ShimLost));
    assert_eq!(classify(b"", false), None);
    assert_eq!(classify(b"", true), Some(LinkOutcome::ShimLost));
    assert_eq!(classify(b"Q", false), Some(LinkOutcome::ShimLost));
}

#[skuld::test]
fn garbled_frame_is_shim_lost_and_kill_does_not_claim_gone() {
    let rig = Rig::new();
    let mut shim = rig.live();
    // The shim stays connected: the garbled frame alone settles the outcome.
    shim.send(b"Zzzzz");
    assert_eq!(rig.link.wait().unwrap(), LinkOutcome::ShimLost);
    assert!(matches!(rig.link.kill(), Err(KillError::ShimLost)));

    let truncated = Rig::new();
    let mut shim = truncated.live();
    shim.send(b"S\x01");
    shim.close();
    assert_eq!(truncated.link.wait().unwrap(), LinkOutcome::ShimLost);
    assert!(matches!(truncated.link.kill(), Err(KillError::ShimLost)));
}

#[skuld::test]
fn u_frame_is_status_lost_and_kill_is_ok() {
    // `kill` first: its failed send is what reads the frame.
    let rig = Rig::new();
    let mut shim = rig.live();
    shim.send_frame(Frame::StatusLost);
    shim.close();
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::AlreadyEnded);
    assert_eq!(rig.link.wait().unwrap(), LinkOutcome::StatusLost);

    // `wait` first: `kill` then sees the cached outcome.
    let rig = Rig::new();
    let mut shim = rig.live();
    shim.send_frame(Frame::StatusLost);
    shim.close();
    assert_eq!(rig.link.wait().unwrap(), LinkOutcome::StatusLost);
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::AlreadyEnded);
}

#[skuld::test]
fn try_wait_then_wait_return_the_same_outcome() {
    let rig = Rig::new();
    let mut shim = rig.live();
    assert_eq!(rig.link.try_wait().unwrap(), None, "no frame yet");
    shim.send_frame(Frame::Status(0x0100));
    shim.close();
    let first = rig.link.try_wait().unwrap();
    assert_eq!(first, Some(LinkOutcome::Exited(0x0100)));
    assert_eq!(rig.link.wait().unwrap(), LinkOutcome::Exited(0x0100));
    assert_eq!(rig.link.try_wait().unwrap(), first);
    assert_eq!(rig.link.observe().unwrap().outcome, first);
}

#[skuld::test]
fn two_threads_waiting_concurrently_get_the_same_outcome() {
    let rig = Rig::new();
    let mut shim = rig.live();
    let (a, b) = std::thread::scope(|scope| {
        let a = scope.spawn(|| rig.link.wait().unwrap());
        let b = scope.spawn(|| rig.link.wait().unwrap());
        // Both are about to block for the frame before a byte of it exists.
        for _ in 0..2 {
            while !matches!(rig.events.recv().unwrap(), LinkEvent::Parked(_)) {}
        }
        let frame = Frame::Status(0x2a00).encode();
        shim.send(&frame[..3]);
        // One of them has read the first part before the rest exists.
        let reader = loop {
            if let LinkEvent::Read(3, thread) = rig.events.recv().unwrap() {
                break thread;
            }
        };
        // That waiter ends its read call and parks again, so the rest is read by a later call.
        while rig.events.recv().unwrap() != LinkEvent::Parked(reader) {}
        shim.send(&frame[3..]);
        shim.close();
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_eq!(a, LinkOutcome::Exited(0x2a00));
    assert_eq!(b, LinkOutcome::Exited(0x2a00));
}

#[skuld::test]
fn observe_reads_but_never_moves_the_state() {
    let rig = Rig::new();
    let seen = rig.link.observe().unwrap();
    assert_eq!((seen.start, seen.outcome), (StartState::Pending, None));
    assert_eq!(
        rig.link.observe().unwrap().start,
        StartState::Pending,
        "observe refuses nothing"
    );
    let mut shim = rig.live();
    assert_eq!(rig.link.observe().unwrap().outcome, None);
    shim.send_frame(Frame::Status(0));
    assert_eq!(rig.link.observe().unwrap().outcome, Some(LinkOutcome::Exited(0)));
}

#[skuld::test]
fn a_frame_sent_before_the_shim_closed_with_k_unread_is_still_read() {
    let rig = Rig::new();
    let mut shim = rig.live();
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::Delivered);
    // The shim answers with its status and exits without ever reading the K: its close then resets
    // the connection, which must not cost the frame.
    shim.send_frame(Frame::Status(0x0900));
    shim.close();
    assert_eq!(rig.link.wait().unwrap(), LinkOutcome::Exited(0x0900));
}

#[skuld::test]
fn waiters_whose_frame_went_to_another_reader_wake_on_the_outcome() {
    let rig = Rig::new();
    let mut shim = rig.live();
    rig.probe.hold_waiters();
    let (polls, first, second) = std::thread::scope(|scope| {
        let a = scope.spawn(|| rig.link.wait().unwrap());
        let b = scope.spawn(|| rig.link.wait().unwrap());
        // Both found no outcome and are held before they poll.
        for _ in 0..2 {
            while !matches!(rig.events.recv().unwrap(), LinkEvent::Parked(_)) {}
        }
        // The shim keeps its end open after the frame; a reader in the waiters' position takes it.
        shim.send_frame(Frame::Status(0x2a00));
        assert_eq!(rig.link.try_wait().unwrap(), Some(LinkOutcome::Exited(0x2a00)));
        rig.probe.release_waiters();
        let mut polls = Vec::new();
        while polls.len() < 2 {
            if let event @ LinkEvent::Polling { .. } = rig.events.recv().unwrap() {
                polls.push(event);
            }
        }
        // Closing the shim ends a waiter that nothing else would wake, so a failure below is an
        // assertion and not a hang.
        shim.close();
        (polls, a.join().unwrap(), b.join().unwrap())
    });
    let expected = LinkEvent::Polling {
        fds: 2,
        settled_readable: true,
    };
    assert_eq!(
        polls,
        [expected, expected],
        "each waiter polls the settled signal, already raised"
    );
    assert_eq!(first, LinkOutcome::Exited(0x2a00));
    assert_eq!(second, LinkOutcome::Exited(0x2a00));
}

/// A failure to wait here is not the shim's loss: it is reported, nothing is settled, and the frame
/// is still read by the next call.
#[skuld::test]
fn a_local_poll_error_in_wait_settles_nothing() {
    let rig = Rig::new();
    let mut shim = rig.live();
    rig.probe.fail_next_wait_poll(rustix::io::Errno::NOMEM);
    match rig.link.wait() {
        Err(WaitError::Poll(e)) => assert_eq!(e.raw_os_error(), Some(libc::ENOMEM)),
        other => panic!("expected a poll error, got {other:?}"),
    }
    assert_eq!(rig.link.observe().unwrap().outcome, None);
    shim.send_frame(Frame::Status(0x2a00));
    assert_eq!(rig.link.wait().unwrap(), LinkOutcome::Exited(0x2a00));
}
