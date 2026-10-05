//! Teardown (D14) and the pid that owns the link (D21).

use super::super::fake_shim::{next_acceptor_event, FakeShim, Rig};
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

/// A fork copy's real `Drop` leaves the owner's link as it was.
#[skuld::test]
fn fork_copy_drop_leaves_the_owner_intact() {
    let rig = Rig::new();
    let socket = rig.link.dir().join(super::super::SOCKET_NAME);
    assert!(socket.exists());
    let Rig {
        link,
        probe,
        events,
        tmp: _tmp,
    } = rig;
    // SAFETY: the child only drops the copy and `_exit`s; nothing unwinds out of it.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(link)));
        // SAFETY: `_exit` is async-signal-safe and never returns.
        unsafe { libc::_exit(if dropped.is_ok() { 0 } else { 101 }) };
    }
    let waiter = {
        let probe = probe.clone();
        std::thread::spawn(move || {
            let mut status = 0;
            // SAFETY: `pid` is this test's own unreaped child.
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            probe.inject(LinkEvent::ChildExited);
            status
        })
    };
    // A copy that tore the owner's link down would stop the owner's acceptor first (and hang in its
    // join, in a thread that does not exist there).
    let first = next_acceptor_event(&events);
    if first != LinkEvent::ChildExited {
        // SAFETY: as above.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        waiter.join().unwrap();
        panic!("the copy's drop disturbed the owner: {first:?}");
    }
    let status = waiter.join().unwrap();
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child status {status:#x}"
    );
    assert!(socket.exists(), "a fork copy does not unlink the path");
    let mut shim = FakeShim::connect(link.dir()).unwrap();
    shim.hello();
    assert_eq!(next_acceptor_event(&events), LinkEvent::Accepted);
    assert_eq!(next_acceptor_event(&events), LinkEvent::Answered(Command::Allow));
    assert_eq!(shim.read_byte(), Some(b'A'));
    assert_eq!(link.observe().unwrap().start, StartState::Live);
    assert_eq!(link.kill().unwrap(), KillOutcome::Delivered);
    // `link` drops here, in its owner: the acceptor is joined.
}
