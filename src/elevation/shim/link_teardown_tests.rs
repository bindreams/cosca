//! Teardown (D14) and the pid that owns the link (D21).

use super::super::fake_shim::Rig;
use super::super::probe::LinkEvent;
use super::super::{KillOutcome, LinkOutcome, StartState};
use crate::elevation::shim::protocol::{Command, Frame};

#[skuld::test]
fn teardown_unlinks_before_the_final_drain() {
    let Rig {
        link,
        probe,
        events,
        tmp: _tmp,
    } = Rig::new();
    probe.hold_acceptor();
    let mut queued = super::super::fake_shim::FakeShim::connect(link.dir()).unwrap();
    queued.hello();
    drop(link);
    let drain = events
        .try_iter()
        .find(|e| matches!(e, LinkEvent::DrainStarted { .. }))
        .expect("teardown joined the acceptor, so its drain ran");
    assert_eq!(drain, LinkEvent::DrainStarted { path_exists: false });
    assert_eq!(queued.read_byte(), Some(b'N'), "the backlog is answered N");
}

#[skuld::test]
fn wait_then_drop_does_not_report_shim_lost() {
    let rig = Rig::new();
    let marker = rig.log_marker();
    let Rig {
        link,
        probe: _probe,
        events: _events,
        tmp: _tmp,
    } = rig;
    let mut shim = super::super::fake_shim::FakeShim::connect(link.dir()).unwrap();
    shim.hello();
    shim.send_frame(Frame::Status(0));
    // Ensure the answer was read first.
    assert_eq!(shim.read_byte(), Some(b'A'));
    shim.close();
    assert_eq!(link.wait().unwrap(), LinkOutcome::Exited(0));
    let mark = crate::log_capture::mark();
    drop(link);
    let problems: Vec<_> = crate::log_capture::levels_since(mark, &marker)
        .into_iter()
        .filter(|l| *l <= log::Level::Warn)
        .collect();
    assert!(
        problems.is_empty(),
        "teardown logged {problems:?} after a clean outcome"
    );
}

#[skuld::test]
fn teardown_removes_the_directory_and_closes_the_connection() {
    let rig = Rig::new();
    let dir = rig.link.dir().to_owned();
    let mut shim = rig.live();
    let Rig { link, tmp: _tmp, .. } = rig;
    drop(link);
    assert!(!dir.exists(), "the private directory is removed");
    assert_eq!(shim.read_byte(), None, "the connection is closed");
}

#[skuld::test]
fn fork_copy_drop_leaves_the_owner_intact() {
    let rig = Rig::new();
    let socket = rig.link.dir().join(super::super::SOCKET_NAME);
    assert!(socket.exists());
    let Rig {
        mut link,
        probe,
        events,
        tmp: _tmp,
    } = rig;
    // As a fork copy would drop it: some other pid.
    link.release(std::process::id() + 1);
    assert!(socket.exists(), "a fork copy does not unlink the path");
    assert!(link.dir().exists(), "a fork copy does not remove the directory");
    let mut shim = super::super::fake_shim::FakeShim::connect(link.dir()).unwrap();
    shim.hello();
    loop {
        match events.recv().unwrap() {
            LinkEvent::Answered(Command::Allow) => break,
            LinkEvent::AcceptorExited | LinkEvent::Dropped(_) => panic!("the owner's acceptor stopped"),
            _ => {}
        }
    }
    assert_eq!(shim.read_byte(), Some(b'A'));
    assert_eq!(link.observe().unwrap().start, StartState::Live);
    assert_eq!(link.kill().unwrap(), KillOutcome::Delivered);
    let _ = probe;
}
