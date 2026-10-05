//! The acceptor and the start state (D4), against a fake shim.

use rustix::io::Errno;

use super::fake_shim::{my_euid, FakeShim, Rig};
use super::probe::{DropReason, LinkEvent};
use super::{AcceptorFailure, KillOutcome, LinkOutcome, NotStarted, NotStartedCause, StartState};
use crate::elevation::shim::protocol::Command;

#[path = "link_kill_tests.rs"]
mod link_kill_tests;
#[path = "link_teardown_tests.rs"]
mod link_teardown_tests;
#[path = "link_wait_tests.rs"]
mod link_wait_tests;

fn socket_exists(rig: &Rig) -> bool {
    rig.link.dir().join(super::SOCKET_NAME).exists()
}

fn connect_error(rig: &Rig) -> std::io::ErrorKind {
    FakeShim::connect(rig.link.dir())
        .err()
        .expect("no shim can connect")
        .kind()
}

#[skuld::test]
fn acceptor_answers_without_caller_action() {
    let rig = Rig::new();
    let mut shim = rig.connect();
    shim.hello();
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Answered(Command::Allow));
    assert_eq!(shim.read_byte(), Some(b'A'));
    assert_eq!(rig.link.observe().unwrap().start, StartState::Live);
}

#[skuld::test]
fn refused_state_answers_n_to_a_held_connection() {
    let rig = Rig::new();
    rig.probe.hold_acceptor();
    let mut shim = rig.connect();
    shim.hello();
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::RefusedStart);
    rig.probe.release_acceptor();
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Answered(Command::Deny));
    assert_eq!(shim.read_byte(), Some(b'N'));
    assert_eq!(rig.link.observe().unwrap().start, StartState::Refused);
}

#[skuld::test]
fn accept_emfile_fails_closed_while_pending() {
    let rig = Rig::new();
    rig.probe.fail_next_accept(Errno::MFILE);
    let mut queued = rig.connect();
    rig.expect_event(LinkEvent::AcceptorExited);
    let seen = rig.link.observe().unwrap();
    assert_eq!(seen.start, StartState::Refused);
    assert_eq!(seen.acceptor_failure, Some(AcceptorFailure::Errno(libc::EMFILE)));
    assert!(!socket_exists(&rig), "a failed acceptor removes the path");
    assert_eq!(
        queued.read_byte(),
        None,
        "a shim queued at the failure sees the listener close"
    );
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::RefusedStart);
    assert_eq!(
        rig.link.wait().unwrap(),
        LinkOutcome::NotStarted(NotStarted {
            shim_connected: false,
            cause: NotStartedCause::AcceptorFailed(AcceptorFailure::Errno(libc::EMFILE)),
        })
    );
}

#[skuld::test]
fn accept_failure_while_live_keeps_control() {
    let rig = Rig::new();
    // Queued before the start, so the failure can come after it.
    let mut first = rig.connect();
    let mut second = rig.connect();
    first.hello();
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Answered(Command::Allow));
    assert_eq!(first.read_byte(), Some(b'A'));
    rig.probe.fail_next_poll(Errno::NOMEM);
    second.send(b"H");
    rig.expect_event(LinkEvent::AcceptorExited);
    assert_eq!(rig.link.observe().unwrap().start, StartState::Live);
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::Delivered);
    assert_eq!(first.read_byte(), Some(b'K'));
    first.send_frame(crate::elevation::shim::protocol::Frame::Status(0x2a00));
    assert_eq!(rig.link.wait().unwrap(), LinkOutcome::Exited(0x2a00));
}

#[skuld::test]
fn acceptor_panic_fails_closed() {
    let mut rig = Rig::new();
    rig.probe.panic_acceptor();
    let _wakes_the_acceptor = rig.connect();
    // Joined directly: a thread that dies without the guard still ends, so this cannot hang.
    let thread = rig.link.acceptor.take().expect("the acceptor thread");
    assert!(thread.join().is_err(), "the acceptor panicked");
    let seen = rig.link.observe().unwrap();
    assert_eq!(seen.start, StartState::Refused);
    assert_eq!(seen.acceptor_failure, Some(AcceptorFailure::Panicked));
    assert!(!socket_exists(&rig));
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::RefusedStart);
}

#[skuld::test]
fn the_final_drain_answers_the_backlog_even_when_accept_fails_at_stop() {
    let rig = Rig::new();
    let marker = rig.log_marker();
    // Held, silent: the drain answers it N hello or not.
    let mut held = rig.connect();
    rig.expect_event(LinkEvent::Accepted);
    rig.probe.fail_accept_at_stop(Errno::MFILE);
    let mark = crate::log_capture::mark();
    let super::fake_shim::Rig { link, .. } = rig;
    drop(link);
    assert_eq!(held.read_byte(), Some(b'N'));
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(
        levels.contains(&log::Level::Warn),
        "the failed accept at teardown is reported: {levels:?}"
    );
    assert!(
        !levels.contains(&log::Level::Error),
        "a teardown-time accept error is not an acceptor failure: {levels:?}"
    );
}

#[skuld::test]
fn second_root_peer_is_closed_and_warned() {
    let rig = Rig::new();
    let mut first = rig.connect();
    let mut second = rig.connect();
    first.hello();
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Answered(Command::Allow));
    assert_eq!(first.read_byte(), Some(b'A'));
    let mark = crate::log_capture::mark();
    second.hello();
    rig.expect_event(LinkEvent::Answered(Command::Deny));
    assert_eq!(second.read_byte(), Some(b'N'));
    assert_eq!(second.read_byte(), None, "the second peer's connection is closed");
    assert!(crate::log_capture::levels_since(mark, &rig.log_marker()).contains(&log::Level::Warn));
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::Delivered);
    assert_eq!(first.read_byte(), Some(b'K'), "the first peer keeps the link");
}

#[skuld::test]
fn non_root_peer_is_closed_and_warned() {
    // This process is not "root" for this link, so its fake shim is a non-root peer.
    let rig = Rig::with_peer_euid(my_euid() + 1);
    let mark = crate::log_capture::mark();
    let mut shim = rig.connect();
    rig.expect_event(LinkEvent::Dropped(DropReason::NonRoot));
    assert_eq!(shim.read_byte(), None, "closed unanswered");
    assert!(crate::log_capture::levels_since(mark, &rig.log_marker()).contains(&log::Level::Warn));
    assert_eq!(rig.link.observe().unwrap().start, StartState::Pending);
}

#[skuld::test]
fn leaving_pending_for_refused_unlinks_the_path_and_answers_the_backlog_n() {
    let rig = Rig::new();
    rig.probe.hold_acceptor();
    let mut queued = rig.connect();
    queued.hello();
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::RefusedStart);
    assert_eq!(connect_error(&rig), std::io::ErrorKind::NotFound);
    rig.probe.release_acceptor();
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Answered(Command::Deny));
    assert_eq!(queued.read_byte(), Some(b'N'));
}

#[skuld::test]
fn leaving_pending_for_live_unlinks_the_path_and_answers_the_backlog_n() {
    let rig = Rig::new();
    rig.probe.hold_acceptor();
    let mut first = rig.connect();
    let mut queued = rig.connect();
    first.hello();
    queued.hello();
    rig.probe.release_acceptor();
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Answered(Command::Allow));
    assert_eq!(connect_error(&rig), std::io::ErrorKind::NotFound);
    rig.expect_event(LinkEvent::Answered(Command::Deny));
    assert_eq!(first.read_byte(), Some(b'A'));
    assert_eq!(queued.read_byte(), Some(b'N'));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn so_nosigpipe_is_set_on_accepted_connections() {
    use std::os::fd::AsFd;

    let rig = Rig::new();
    let _shim = rig.live();
    let conn = rig.link.shared.conn.get().expect("Live has a connection");
    assert!(rustix::net::sockopt::socket_nosigpipe(conn.as_fd()).unwrap());
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_fds_are_created_under_spawn_lock() {
    let rig = Rig::new();
    let _shim = rig.live();
    let creations = rig.probe.fd_creations();
    // The listener, the wake pipe, the settled pipe, and the accepted connection.
    assert!(creations.len() >= 4, "{creations:?}");
    assert!(creations.iter().all(|held| *held), "{creations:?}");
}

#[skuld::test]
fn a_peer_that_closes_before_hello_is_dropped_and_the_next_is_served() {
    let rig = Rig::new();
    let shim = rig.connect();
    // Closed only once accepted: a peer that is gone already has no credentials to read on macOS.
    rig.expect_event(LinkEvent::Accepted);
    shim.close();
    rig.expect_event(LinkEvent::Dropped(DropReason::ClosedBeforeHello));
    let _shim = rig.live();
}

#[skuld::test]
fn a_first_byte_that_is_not_hello_is_dropped() {
    let rig = Rig::new();
    let mut shim = rig.connect();
    shim.send(b"X");
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Dropped(DropReason::NotHello));
    assert_eq!(shim.read_byte(), None);
    assert_eq!(rig.link.observe().unwrap().start, StartState::Pending);
}

/// Linux keeps a connection's credentials after the peer is gone, so the hello is read and the answer
/// to it fails; macOS cannot read them, and drops the peer before hello.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_answer_refuses_the_start() {
    let rig = Rig::new();
    rig.probe.hold_acceptor();
    let mut shim = rig.connect();
    shim.hello();
    shim.close();
    rig.probe.release_acceptor();
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Dropped(DropReason::AnswerFailed));
    assert_eq!(rig.link.observe().unwrap().start, StartState::Refused);
    assert!(!socket_exists(&rig));
}
