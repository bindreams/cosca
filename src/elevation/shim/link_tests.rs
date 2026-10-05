//! The acceptor and the start state, against a fake shim.

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
    assert_eq!(creations.len(), 4, "{creations:?}");
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

/// A peer whose credentials cannot be prepared or read is closed unanswered, and the acceptor
/// serves the next one.
#[skuld::test]
fn unreadable_credentials_drop_the_peer_and_the_next_is_served() {
    let rig = Rig::new();
    rig.probe.fail_next_credentials();
    let mut unreadable = rig.connect();
    rig.expect_event(LinkEvent::Dropped(DropReason::Unreadable));
    assert_eq!(unreadable.read_byte(), None);
    let _next = rig.live();
}

/// A failure of the acceptor's `poll` while `Pending` refuses the start and says why.
#[skuld::test]
fn a_poll_failure_while_pending_refuses_the_start() {
    let rig = Rig::new();
    rig.probe.fail_next_poll(Errno::NOMEM);
    let _wakes = rig.connect();
    rig.expect_event(LinkEvent::AcceptorExited);
    let seen = rig.link.observe().unwrap();
    assert_eq!(seen.start, StartState::Refused);
    assert_eq!(seen.acceptor_failure, Some(AcceptorFailure::Errno(libc::ENOMEM)));
    assert_eq!(
        rig.link.wait().unwrap(),
        LinkOutcome::NotStarted(NotStarted {
            shim_connected: false,
            cause: NotStartedCause::AcceptorFailed(AcceptorFailure::Errno(libc::ENOMEM)),
        })
    );
}

/// The socket is bound relative to the directory's descriptor, so a `TMPDIR` far longer than
/// `sun_path` still works. Mutant: bind by full path.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_tmpdir_deeper_than_200_bytes_binds_and_accepts() {
    let rig = Rig::deep(200);
    assert!(rig.link.dir().as_os_str().len() > 200, "{}", rig.link.dir().display());
    let _shim = rig.live();
    assert_eq!(rig.link.observe().unwrap().start, StartState::Live);
}

/// Where `/proc` is not usable the bind is refused, naming `TMPDIR`, with no fallback to the long
/// path and nothing left behind.
#[cfg(target_os = "linux")]
#[skuld::test]
fn an_unusable_proc_is_refused_naming_tmpdir() {
    use super::super::link::BindError;
    crate::log_capture::install();
    let tmp = tempfile::tempdir().unwrap();
    let (probe, _events) = super::probe::Probe::new();
    probe.use_proc_root(tmp.path().join("no-proc-here"));
    let Err(error @ BindError::ProcUnusable { .. }) = super::ShimLink::bind_probed(tmp.path(), my_euid(), probe) else {
        panic!("an unusable /proc must refuse the bind");
    };
    let text = error.to_string();
    assert!(
        text.contains("TMPDIR") && text.contains(&tmp.path().display().to_string()),
        "{text}"
    );
    assert_eq!(
        std::fs::read_dir(tmp.path()).unwrap().count(),
        0,
        "nothing is left behind"
    );
}

/// macOS binds by full path, so a `TMPDIR` that would overflow `sun_path` is refused before the
/// directory is made, naming `TMPDIR` and the limit. Mutant: no length check.
#[cfg(target_os = "macos")]
#[skuld::test]
fn a_tmpdir_too_long_for_sun_path_is_refused_before_anything_is_made() {
    use super::super::link::BindError;
    crate::log_capture::install();
    let tmp = tempfile::tempdir().unwrap();
    let mut nested = tmp.path().to_owned();
    while nested.as_os_str().len() < 90 {
        nested.push("n".repeat(20));
    }
    std::fs::create_dir_all(&nested).unwrap();
    let (probe, _events) = super::probe::Probe::new();
    let Err(error @ BindError::TmpdirTooLong { .. }) = super::ShimLink::bind_probed(&nested, my_euid(), probe) else {
        panic!("a TMPDIR that cannot hold the socket path must be refused up front");
    };
    let text = error.to_string();
    assert!(text.contains("TMPDIR") && text.contains("103"), "{text}");
    assert_eq!(std::fs::read_dir(&nested).unwrap().count(), 0, "nothing is made");
}

/// The socket path limit is exact on every platform: a real temp path 25 bytes shorter than it is
/// accepted, and one byte more is refused, by the real length and not the given one.
#[skuld::test]
fn the_socket_path_limit_is_exact() {
    use super::super::link::BindError;
    use super::fake_shim::nested_of_len;
    use super::sys::{full_path_fits, socket_path_limit};
    use crate::elevation::shim::private_dir::NAME_LEN;
    let limit = socket_path_limit();
    let fixed = NAME_LEN + 3; // two separators, and the one-byte socket name
    let path_of = |n: usize| std::path::PathBuf::from(format!("/{}", "a".repeat(n - 1)));
    assert_eq!(full_path_fits(&path_of(limit - fixed), super::SOCKET_NAME), Ok(()));
    assert_eq!(
        full_path_fits(&path_of(limit - fixed + 1), super::SOCKET_NAME),
        Err((limit + 1, limit))
    );

    // Through `bind`: the boundary, a short given path to a long real one, and a long given path to
    // a short real one.
    crate::log_capture::install();
    let tmp = tempfile::tempdir().unwrap();
    let base = crate::elevation::shim::private_dir::PrivateDir::resolve(tmp.path()).unwrap();
    let bind = |at: &std::path::Path| {
        let (probe, events) = super::probe::Probe::new();
        let bound = super::ShimLink::bind_probed(at, my_euid(), probe);
        (bound, events)
    };
    let fits = nested_of_len(&base, limit - fixed);
    let (bound, _events) = bind(&fits);
    drop(bound.expect("a real path at the limit binds"));
    let over = nested_of_len(&base, limit - fixed + 1);
    let (refused, _events) = bind(&over);
    assert!(
        matches!(refused, Err(BindError::TmpdirTooLong { .. })),
        "a real path over the limit"
    );
    // Short given, long real: refused.
    let link = base.join("short");
    std::os::unix::fs::symlink(&over, &link).unwrap();
    assert!(link.as_os_str().len() < limit - fixed);
    let (refused, _events) = bind(&link);
    assert!(
        matches!(refused, Err(BindError::TmpdirTooLong { .. })),
        "the real path decides, not the given one"
    );
    // Long given, short real: accepted.
    let mut given = fits.clone();
    while given.as_os_str().len() <= limit {
        given.push(".");
    }
    let (bound, _events) = bind(&given);
    drop(bound.expect("the real path decides, not the given one"));
    // A relative TMPDIR is reported as that, before any length.
    let (relative, _events) = bind(std::path::Path::new("relative/tmp"));
    assert!(matches!(
        relative,
        Err(BindError::Dir(
            crate::elevation::shim::private_dir::PrivateDirError::TmpdirNotAbsolute(_)
        ))
    ));
}

/// Linux: at the longest path that works the socket binds, accepts, and is removed through the
/// directory's descriptor.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_real_path_at_the_limit_binds_accepts_and_unlinks() {
    use super::sys::socket_path_limit;
    let rig = Rig::at_real_len(socket_path_limit() - 25);
    let _shim = rig.live();
    assert!(!rig.link.dir().join(super::SOCKET_NAME).exists(), "unlinked once Live");
}

/// `/proc` must really be this process's: a `thread-self/fd/N` that names another directory is
/// refused. Mutant: the device and inode are not compared.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_proc_whose_descriptor_names_another_directory_is_refused() {
    use super::super::link::BindError;
    crate::log_capture::install();
    let tmp = tempfile::tempdir().unwrap();
    let decoy = tmp.path().join("decoy");
    std::fs::create_dir(&decoy).unwrap();
    let fds = tmp.path().join("fake-proc/thread-self/fd");
    std::fs::create_dir_all(&fds).unwrap();
    for n in 0..1024 {
        std::os::unix::fs::symlink(&decoy, fds.join(n.to_string())).unwrap();
    }
    let (probe, _events) = super::probe::Probe::new();
    probe.use_proc_root(tmp.path().join("fake-proc"));
    let Err(error @ BindError::ProcUnusable { .. }) = super::ShimLink::bind_probed(tmp.path(), my_euid(), probe) else {
        panic!("a /proc that names another directory must refuse the bind");
    };
    assert!(error.to_string().contains("/proc must be mounted"), "{error}");
    assert_eq!(
        std::fs::read_dir(&decoy).unwrap().count(),
        0,
        "nothing was bound in the decoy"
    );
}

/// `/proc/self` is the main thread's, so it is wrong in a thread that has its own descriptor table;
/// `/proc/thread-self` is right. Mutant: `/proc/self`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_thread_with_its_own_fd_table_binds_and_accepts() {
    std::thread::spawn(|| {
        // SAFETY: this thread's own descriptor table is copied; no other thread's state changes.
        unsafe { rustix::thread::unshare_unsafe(rustix::thread::UnshareFlags::FILES) }.expect("unshare(CLONE_FILES)");
        // Descriptors the main thread has open and this table also has make the numbers ambiguous.
        let rig = Rig::new();
        let _shim = rig.live();
        assert_eq!(rig.link.observe().unwrap().start, StartState::Live);
    })
    .join()
    .unwrap();
}

/// The socket is removed through the directory's descriptor, not its path: with the directory moved
/// under another name, the socket inside it is still the one removed. Mutant: removal by path.
#[skuld::test]
fn the_socket_is_removed_through_the_directory_descriptor() {
    let rig = Rig::new();
    rig.probe.hold_acceptor();
    let mut shim = rig.connect();
    shim.hello();
    let moved = rig.tmp.path().join("moved");
    std::fs::rename(rig.link.dir(), &moved).unwrap();
    rig.probe.release_acceptor();
    rig.expect_event(LinkEvent::Accepted);
    rig.expect_event(LinkEvent::Answered(Command::Allow));
    assert!(
        !moved.join(super::SOCKET_NAME).exists(),
        "the socket under its new name is removed"
    );
    assert_eq!(shim.read_byte(), Some(b'A'));
}
