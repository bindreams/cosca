//! Teardown and the process that owns the link.

use super::super::fake_shim::{next_acceptor_event, FakeShim, Rig};
use super::super::probe::LinkEvent;
use super::super::{KillError, KillOutcome, LinkOutcome, NotOwner, StartState, WaitError};
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

/// Forks, runs `in_copy` on the child's copy of `link`, and checks that the owner's link is as it was:
/// the path is there, the acceptor still answers `A`, and `kill` reaches the shim. A copy that tore
/// the owner's link down would stop the owner's acceptor first (and hang in a join, in a thread that
/// does not exist there); the test sees that through the owner's events, and kills the child itself.
fn owner_survives_a_fork_copy(in_copy: fn(super::super::ShimLink)) {
    let rig = Rig::new();
    let socket = rig.link.dir().join(super::super::SOCKET_NAME);
    assert!(socket.exists());
    let Rig {
        link,
        probe,
        events,
        tmp: _tmp,
    } = rig;
    // SAFETY: the child only runs `in_copy` on its copy of the link and `_exit`s; nothing unwinds out
    // of it. The locks it can take are malloc's, which glibc and libmalloc reset across `fork`; the
    // link's state mutex, only through `try_lock`, which never blocks; and the probe channel's, which
    // `send` takes only when a receiver is blocked in `recv`, and no thread is at the fork. The
    // acceptor thread does not exist in the child.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| in_copy(link)));
        // SAFETY: `_exit` is async-signal-safe and never returns.
        unsafe { libc::_exit(if ran.is_ok() { 0 } else { 101 }) };
    }
    // The waiter only observes the exit (`WNOWAIT` leaves the zombie), so the child stays unreaped
    // and its pid stays ours until this thread reaps it.
    let waiter = {
        let probe = probe.clone();
        std::thread::spawn(move || {
            // SAFETY: an all-zero `siginfo_t` is valid.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: `pid` is this test's own unreaped child.
            let waited =
                unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
            assert_eq!(waited, 0, "waitid");
            probe.inject(LinkEvent::ChildExited);
        })
    };
    let reap = || {
        let mut status = 0;
        // SAFETY: `pid` is this test's own child, reaped here and only here.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        status
    };
    let first = next_acceptor_event(&events);
    if first != LinkEvent::ChildExited {
        // SAFETY: the child is unreaped, so its pid is still ours.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        waiter.join().unwrap();
        reap();
        panic!("the copy's drop disturbed the owner: {first:?}");
    }
    waiter.join().unwrap();
    let status = reap();
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

/// A fork copy's real `Drop` leaves the owner's link as it was.
#[skuld::test]
fn fork_copy_drop_leaves_the_owner_intact() {
    owner_survives_a_fork_copy(drop);
}

/// A copy whose guard cannot say who it is stops its own acceptor handling and writes the stop byte,
/// which the owner's acceptor must consume and ignore: it has not been asked to stop.
#[skuld::test]
fn unknown_origin_in_a_fork_copy_leaves_the_owner_intact() {
    owner_survives_a_fork_copy(|link| {
        link.owner.make_unreadable();
        drop(link);
    });
}

/// In the original, an origin that cannot be told still refuses the pending start and stops the
/// acceptor, and removes nothing.
#[skuld::test]
fn unknown_origin_in_the_original_stops_the_acceptor_and_removes_nothing() {
    let Rig {
        link,
        probe: _probe,
        events,
        tmp: _tmp,
    } = Rig::new();
    let dir = link.dir().to_owned();
    link.owner.make_unreadable();
    drop(link);
    // `drop` has returned, so its own event is already queued. Check it before waiting for the
    // acceptor, which a missing stop byte would leave waiting for ever. The acceptor runs
    // concurrently, so its events may come before or after.
    let mut seen = Vec::new();
    while !seen.iter().any(|e| matches!(e, LinkEvent::UnknownOriginHandled { .. })) {
        seen.push(next_acceptor_event(&events));
    }
    assert!(
        seen.contains(&LinkEvent::UnknownOriginHandled {
            refused: true,
            stop_written: true
        }),
        "{seen:?}"
    );
    while !seen.contains(&LinkEvent::AcceptorExited) {
        seen.push(next_acceptor_event(&events));
    }
    assert!(
        seen.contains(&LinkEvent::DrainStarted { path_exists: true }),
        "{seen:?}"
    );
    assert!(dir.join(super::super::SOCKET_NAME).exists(), "nothing is unlinked");
    assert!(dir.is_dir(), "nothing is removed");
}

/// With no descriptor to spare, the owner check, every control call and `Drop` neither panic nor
/// leak the acceptor: none of them opens a descriptor. A panic in `Drop` during an unwind aborts.
#[skuld::test]
fn control_and_drop_with_a_full_fd_table_do_not_panic() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(control_and_drop_with_a_full_fd_table_do_not_panic),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let rig = Rig::new();
    let marker = rig.log_marker();
    let mut shim = rig.live();
    let dir = rig.link.dir().to_owned();
    let Rig { link, tmp: _tmp, .. } = rig;
    let _restore = crate::test_child::exhaust_fds(&done);
    assert!(
        std::fs::File::open("/dev/null").is_err(),
        "the precondition: no descriptor can be opened"
    );
    assert_eq!(link.observe().unwrap().start, StartState::Live);
    assert_eq!(link.try_wait().unwrap(), None);
    assert_eq!(link.kill().unwrap(), KillOutcome::Delivered);
    assert_eq!(shim.read_byte(), Some(b'K'));
    let mark = crate::log_capture::mark();
    drop(link);
    assert!(!dir.exists(), "teardown still removed the directory");
    // The final drain accepts once more. On Linux `accept4` reserves a descriptor before it looks at
    // the queue, so a full table is `EMFILE` there, reported at teardown; on macOS an empty queue is
    // `EAGAIN`, and nothing is reported.
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(!levels.contains(&log::Level::Error), "{levels:?}");
    assert_eq!(
        levels.contains(&log::Level::Warn),
        cfg!(target_os = "linux"),
        "the accept at teardown: {levels:?}"
    );
}

/// A fork copy calling a control method gets an error, not a panic or an effect.
#[skuld::test]
fn control_calls_from_a_fork_copy_are_refused() {
    owner_survives_a_fork_copy(|link| {
        assert!(matches!(link.kill(), Err(KillError::NotOwner(_))));
        assert!(matches!(link.wait(), Err(WaitError::NotOwner(_))));
        assert!(matches!(link.try_wait(), Err(NotOwner)));
        assert!(matches!(link.observe(), Err(NotOwner)));
    });
}

fn at_capacity(writer: &std::io::PipeWriter) {
    use std::os::fd::AsFd;
    while super::super::sys::write_byte(writer.as_fd()).is_ok() {}
}

fn is_nonblocking(fd: impl std::os::fd::AsFd) -> bool {
    rustix::fs::fcntl_getfl(fd)
        .unwrap()
        .contains(rustix::fs::OFlags::NONBLOCK)
}

/// Both pipes' write ends are nonblocking, so a full pipe cannot block teardown or the outcome. The
/// acceptor is held while the wake pipe fills, so it cannot drain it.
#[skuld::test]
fn teardown_completes_with_the_wake_pipe_full() {
    let rig = Rig::new();
    assert!(is_nonblocking(&rig.link.wake.writer), "the wake pipe's write end");
    assert!(
        is_nonblocking(&rig.link.shared.settled.1),
        "the settled pipe's write end"
    );
    rig.probe.hold_acceptor();
    let _wakes = rig.connect();
    at_capacity(&rig.link.wake.writer);
    let Rig { link, tmp: _tmp, .. } = rig;
    drop(link);
}

#[skuld::test]
fn the_outcome_settles_with_the_settled_pipe_full() {
    let rig = Rig::new();
    let mut shim = rig.live();
    assert!(
        is_nonblocking(&rig.link.shared.settled.1),
        "the settled pipe's write end"
    );
    at_capacity(&rig.link.shared.settled.1);
    shim.send_frame(Frame::Status(0x2a00));
    assert_eq!(rig.link.wait().unwrap(), LinkOutcome::Exited(0x2a00));
}

/// Every descriptor the link makes is `CLOEXEC`: the listener, both pipes, and an accepted
/// connection.
#[skuld::test]
fn every_descriptor_is_close_on_exec() {
    use std::os::fd::AsFd;
    let cloexec = |fd: std::os::fd::BorrowedFd<'_>| {
        rustix::io::fcntl_getfd(fd)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    };
    let rig = Rig::new();
    let _shim = rig.live();
    assert_eq!(rig.probe.listener_cloexec(), Some(true), "the listener");
    assert!(cloexec(rig.link.wake.reader.as_fd()), "the wake pipe's read end");
    assert!(cloexec(rig.link.wake.writer.as_fd()), "the wake pipe's write end");
    assert!(
        cloexec(rig.link.shared.settled.0.as_fd()),
        "the settled pipe's read end"
    );
    assert!(
        cloexec(rig.link.shared.settled.1.as_fd()),
        "the settled pipe's write end"
    );
    let conn = rig.link.shared.conn.get().expect("Live has a connection");
    assert!(cloexec(conn.as_fd()), "the accepted connection");
}

/// A stop byte that cannot be written leaves the acceptor and the directory alone (joining would
/// hang), and is a contract violation: an assertion in debug builds.
#[skuld::test]
fn a_failed_stop_write_leaks_instead_of_joining() {
    let Rig {
        link,
        probe,
        events,
        tmp: _tmp,
    } = Rig::new();
    let dir = link.dir().to_owned();
    let wake = link.wake.clone();
    probe.fail_next_stop_write(rustix::io::Errno::IO);
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(link)));
    assert_eq!(dropped.is_err(), cfg!(debug_assertions), "the debug assertion");
    assert!(dir.is_dir(), "nothing is removed");
    // The stop flag was set, so the byte the failed write did not deliver still stops the acceptor.
    super::super::sys::write_byte(std::os::fd::AsFd::as_fd(&wake.writer)).unwrap();
    assert_eq!(
        next_acceptor_event(&events),
        LinkEvent::DrainStarted { path_exists: false }
    );
    assert_eq!(next_acceptor_event(&events), LinkEvent::AcceptorExited);
}

/// A settled byte that cannot be written is a contract violation too, but the outcome is set first.
#[skuld::test]
fn a_failed_settled_write_still_settles_the_outcome() {
    let rig = Rig::new();
    let mut shim = rig.live();
    rig.probe.fail_next_settled_write(rustix::io::Errno::IO);
    shim.send_frame(Frame::Status(0x2a00));
    let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rig.link.try_wait()));
    assert_eq!(polled.is_err(), cfg!(debug_assertions), "the debug assertion");
    assert_eq!(rig.link.observe().unwrap().outcome, Some(LinkOutcome::Exited(0x2a00)));
}
