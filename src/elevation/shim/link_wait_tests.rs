//! The one outcome (D7): `wait`, `try_wait`, `observe` and the frames they decode.

use super::super::fake_shim::Rig;
use super::super::outcome::classify;
use super::super::probe::LinkEvent;
use super::super::{KillError, KillOutcome, LinkOutcome, NotStarted, NotStartedCause, StartState};
use crate::elevation::shim::protocol::{Errno, Frame, NotExecuted, Refusal, Signal};

#[skuld::test]
fn front_exit_while_pending_is_not_started() {
    let rig = Rig::new();
    assert_eq!(
        rig.link.wait().unwrap(),
        LinkOutcome::NotStarted(NotStarted {
            shim_connected: false,
            cause: NotStartedCause::Withheld,
        })
    );
    assert_eq!(rig.link.observe().unwrap().start, StartState::Refused);
    assert!(!rig.link.dir().join(super::super::SOCKET_NAME).exists());
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::RefusedStart);
}

/// The wire bytes of a frame, as a shim would write them.
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
            loop {
                if rig.events.recv().unwrap() == LinkEvent::Parked {
                    break;
                }
            }
        }
        let frame = Frame::Status(0x2a00).encode();
        shim.send(&frame[..3]);
        // One of them has read the first part before the rest exists.
        loop {
            if rig.events.recv().unwrap() == LinkEvent::Read(3) {
                break;
            }
        }
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
