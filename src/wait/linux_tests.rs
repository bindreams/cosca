//! Tests for `open_verified`'s `EINVAL`/`ENOENT` arm (reaped process-group leader). On >= 6.16 the
//! real syscall returns `ESRCH` for that case and never reaches the arm, so each real-syscall test
//! has a forced-errno twin. The live non-leader tid case lives in `tests/linux_pidfd_wait.rs`.

use std::os::fd::AsRawFd;

use crate::error::Error;
use crate::identity::{Existence, Liveness, ProcessId};

#[path = "linux_tests/fixture.rs"]
mod fixture;

use fixture::{
    build_reaped_pgid_leader, force_l_close_range_failure, force_panic_after_fixture, try_build_reaped_pgid_leader,
    ChildStep,
};

/// Spawn a parked thread and return its tid, with a channel that releases it.
fn spawn_parked_worker() -> (ProcessId, std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        // SAFETY: SYS_gettid takes no arguments and always succeeds.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
        tid_tx.send(tid).expect("send tid to the test thread");
        let _ = stop_rx.recv();
    });
    let tid = tid_rx.recv().expect("recv tid from the worker thread");
    let id = ProcessId::of(tid as u32)
        .found()
        .expect("the live worker thread's tid resolves to an identity");
    assert_ne!(
        id.pid(),
        std::process::id(),
        "the tid must not be this process's own thread-group leader pid"
    );
    (id, stop_tx, worker)
}

/// A reaped process-group leader whose group lives on reports exited. Real syscall: `EINVAL` on
/// < 6.16, `ESRCH` on >= 6.16 (the arm is then not reached; see the forced twin).
#[test]
fn block_until_exit_reports_exited_for_a_reaped_pgid_leader() {
    let _guard = crate::child::spawn::spawn_lock();
    let (l_id, fixture) = build_reaped_pgid_leader();
    assert_eq!(
        l_id.exists(),
        Existence::Gone,
        "a reaped leader must read Gone even while its pid number stays a live PGID"
    );

    let result = super::block_until_exit(l_id, None);
    assert!(
        matches!(result, Ok(true)),
        "block_until_exit on a reaped group leader whose group lives on must report exited \
         (Ok(true)), not {result:?}"
    );

    fixture.release_and_confirm_m_exited();
}

/// Twin of the test above with `pidfd_open` forced to `EINVAL`, so the `INVAL`/`NOENT` arm runs on
/// any kernel.
#[test]
fn block_until_exit_reports_exited_for_a_reaped_pgid_leader_with_forced_einval() {
    let _guard = crate::child::spawn::spawn_lock();
    let (l_id, fixture) = build_reaped_pgid_leader();
    assert_eq!(
        l_id.exists(),
        Existence::Gone,
        "a reaped leader must read Gone even while its pid number stays a live PGID"
    );

    let forced = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::INVAL);
    let result = super::block_until_exit(l_id, None);
    drop(forced);
    assert!(
        matches!(result, Ok(true)),
        "a forced EINVAL on a reaped group leader whose group lives on must report exited \
         (Ok(true)), not {result:?}"
    );

    fixture.release_and_confirm_m_exited();
}

/// A live non-leader tid with `pidfd_open` forced to `ENOENT` is `NotThreadGroupLeader` carrying
/// the pid and the errno, not exited.
#[test]
fn block_until_exit_on_a_live_non_leader_tid_is_an_error_with_forced_enoent() {
    let (id, stop_tx, worker) = spawn_parked_worker();

    let forced = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::NOENT);
    let result = super::block_until_exit(id, None);
    drop(forced);
    match result {
        Err(Error::NotThreadGroupLeader { pid, source, .. }) => {
            assert_eq!(pid, id.pid());
            assert_eq!(source.raw_os_error(), Some(libc::ENOENT));
        }
        other => panic!("a forced ENOENT on a live non-leader tid must be NotThreadGroupLeader, got {other:?}"),
    }

    let _ = stop_tx.send(());
    worker.join().expect("join the worker thread");
}

/// A non-leader tid that has exited but is not yet reaped (a ptraced zombie thread) reads
/// `Present` but `Dead`: exited, not an error. Both answers are forced here; the real ptrace
/// fixture is in `tests/linux_pidfd_wait.rs`.
#[test]
fn block_until_exit_on_a_dead_non_leader_tid_is_exited_with_forced_enoent() {
    let (id, stop_tx, worker) = spawn_parked_worker();

    let forced_errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::NOENT);
    let forced_alive = super::fault::force_alive_once(Liveness::Dead);
    let result = super::block_until_exit(id, None);
    drop(forced_alive);
    drop(forced_errno);
    assert!(
        matches!(result, Ok(true)),
        "a Present but Dead non-leader tid must report exited (Ok(true)), not {result:?}"
    );

    let _ = stop_tx.send(());
    worker.join().expect("join the worker thread");
}

/// The `INVAL`/`NOENT` arm's liveness check refused: `Unassessable` carrying the errno and one
/// `warn`, never exited.
#[test]
fn block_until_exit_is_unassessable_when_the_einval_arms_liveness_is_unknown() {
    crate::log_capture::install();
    let (id, stop_tx, worker) = spawn_parked_worker();
    let marker = format!("pid {} identity could not be confirmed", id.pid());
    let mark = crate::log_capture::mark();

    let forced_errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::INVAL);
    let forced_alive = super::fault::force_alive_once(Liveness::Unknown);
    let result = super::block_until_exit(id, None);
    drop(forced_alive);
    drop(forced_errno);
    match result {
        Err(Error::Unassessable {
            source: Some(source), ..
        }) => {
            assert_eq!(source.raw_os_error(), Some(libc::EINVAL));
        }
        other => panic!("Liveness::Unknown on the EINVAL/ENOENT arm must be Unassessable, got {other:?}"),
    }
    assert_eq!(
        crate::log_capture::levels_since(mark, &marker),
        vec![log::Level::Warn],
        "the Unassessable verdict must be logged once, at warn"
    );

    let _ = stop_tx.send(());
    worker.join().expect("join the worker thread");
}

/// The `Unknown` branch of the `INVAL`/`NOENT` arm can't be produced for real, so both the errno
/// and the exists() answer are forced. Unknown must be `Unassessable` carrying the errno + one
/// warn, never exited.
#[test]
fn block_until_exit_is_unassessable_when_the_einval_arms_exists_is_unknown() {
    crate::log_capture::install();
    let id = ProcessId::current();
    let marker = format!("pid {} identity could not be confirmed", id.pid());
    let mark = crate::log_capture::mark();
    let forced_errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::INVAL);
    let forced_exists = super::fault::force_exists_once(Existence::Unknown);
    let result = super::block_until_exit(id, None);
    drop(forced_exists);
    drop(forced_errno);
    match result {
        Err(Error::Unassessable {
            source: Some(source), ..
        }) => {
            assert_eq!(source.raw_os_error(), Some(libc::EINVAL));
        }
        other => panic!("Existence::Unknown on the EINVAL/ENOENT arm must be Unassessable, got {other:?}"),
    }
    assert_eq!(
        crate::log_capture::levels_since(mark, &marker),
        vec![log::Level::Warn],
        "the Unassessable verdict must be logged once, at warn"
    );
}

/// Twin for the post-open re-verify: a real pidfd on a live child, `exists()` forced `Unknown`.
/// `Unassessable` with no errno (`pidfd_open` succeeded) + one warn, never exited.
#[test]
fn block_until_exit_is_unassessable_when_the_post_open_exists_is_unknown() {
    use crate::containment::cgroup::test_support::{block_on, fork_running};

    crate::log_capture::install();
    let _guard = crate::child::spawn::spawn_lock();
    let (gate_r, gate_w) = std::io::pipe().expect("pipe");
    let gate_r_fd = gate_r.as_raw_fd();
    let child = fork_running(|| block_on(gate_r_fd));
    let id = ProcessId::of(child.pid()).found().expect("the live child resolves");
    let marker = format!("pid {} identity could not be confirmed", id.pid());
    let mark = crate::log_capture::mark();

    let forced_exists = super::fault::force_exists_once(Existence::Unknown);
    let result = super::block_until_exit(id, None);
    drop(forced_exists);
    assert!(
        matches!(result, Err(Error::Unassessable { source: None, .. })),
        "Existence::Unknown after a successful pidfd_open must be Unassessable, not {result:?}"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, &marker),
        vec![log::Level::Warn],
        "the Unassessable verdict must be logged once, at warn"
    );

    drop(gate_w); // EOF releases the child; `child` then kills and reaps it
}

/// A panic between building the fixture and releasing it must still tear down `L` and `M`.
/// `catch_unwind`, not a subprocess: the fixture's `Drop` runs on this thread's unwind, the path a
/// real assertion failure takes.
#[test]
fn a_panic_before_release_still_tears_down_l_and_m() {
    let _guard = crate::child::spawn::spawn_lock();
    let probe: std::cell::RefCell<Option<rustix::fd::OwnedFd>> = std::cell::RefCell::new(None);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (_l_id, fixture) = build_reaped_pgid_leader();
        let m_pid = rustix::process::Pid::from_raw(fixture.m_pid).expect("M's pid is positive");
        *probe.borrow_mut() = Some(
            rustix::process::pidfd_open(m_pid, rustix::process::PidfdFlags::empty()).expect("open a probe pidfd on M"),
        );
        panic!("forced panic between building the fixture and releasing it");
    }));
    assert!(unwound.is_err(), "the forced panic must actually unwind");

    // M is not this process's child, so its exit is observable only through the pidfd. Wait for
    // that event (no timeout: teardown has completed, M's exit is in flight), then require the
    // probe to be readable without blocking.
    let probe = probe.into_inner().expect("the probe pidfd was opened before the panic");
    let mut fds = [rustix::event::PollFd::new(&probe, rustix::event::PollFlags::IN)];
    rustix::event::poll(&mut fds, None).expect("wait for M's exit");
    let zero = rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 };
    let ready = rustix::event::poll(&mut fds, Some(&zero)).expect("poll the probe pidfd");
    assert_eq!(
        ready, 1,
        "M must have exited once the panicking fixture unwound and dropped"
    );
    assert!(fds[0].revents().contains(rustix::event::PollFlags::IN));
}

/// A panic inside `build_reaped_pgid_leader` while `L` is still blocked must tear `L` down:
/// afterwards `L` is reaped, so `waitpid(L)` answers `ECHILD`.
#[test]
fn a_panic_mid_handshake_before_release_reaps_l() {
    let _guard = crate::child::spawn::spawn_lock();
    let forced = force_panic_after_fixture();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(build_reaped_pgid_leader));
    assert!(unwound.is_err(), "the forced panic must actually unwind");
    let l_pid = forced.fired_l_pid().expect("the forced panic fired inside the build");

    let mut status = 0;
    // SAFETY: `status` is a valid out-param. If L was not reaped this waits for it, which exits on
    // the EOF the unwound fixture's fds gave it.
    let r = unsafe { libc::waitpid(l_pid, &mut status, 0) };
    assert_eq!(
        (r, std::io::Error::last_os_error().raw_os_error()),
        (-1, Some(libc::ECHILD)),
        "L must already have been reaped by the unwound fixture"
    );
}

/// `L` failing its `close_range` step (Linux < 5.9) is reported as that step, not as an opaque
/// short read.
#[test]
fn a_failed_close_range_in_l_is_reported_as_that_step() {
    let _guard = crate::child::spawn::spawn_lock();
    let forced = force_l_close_range_failure();
    let result = try_build_reaped_pgid_leader();
    drop(forced);
    match result {
        Err(e) => assert_eq!(e.l_step(), Some(ChildStep::CloseRange), "{e}"),
        Ok(_) => panic!("the forced close_range failure must fail the build"),
    }
}

/// Every step has its own exit code, and the code maps back to the step.
#[test]
fn child_step_exit_codes_round_trip_and_are_distinct() {
    for (i, a) in ChildStep::ALL.into_iter().enumerate() {
        assert_eq!(ChildStep::from_exit_code(a.exit_code()), Some(a));
        for b in ChildStep::ALL[i + 1..].iter() {
            assert_ne!(a.exit_code(), b.exit_code(), "{a:?} vs {b:?}");
        }
    }
}
