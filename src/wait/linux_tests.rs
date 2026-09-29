//! Tests for `open_verified`'s `EINVAL`/`ENOENT` arm (reaped process-group leader). On >= 6.16 the
//! real syscall returns `ESRCH` for that case and never reaches the arm, so each real-syscall test
//! has a forced-errno twin. The live non-leader tid case lives in `tests/linux_pidfd_wait.rs`.

use std::os::fd::AsRawFd;

use crate::error::Error;
use crate::identity::{Existence, Liveness, PidfdTarget, ProcessId};

#[path = "linux_tests/fixture.rs"]
mod fixture;

use fixture::{
    build_reaped_pgid_leader, force_l_close_range_failure, force_panic_after_fixture, try_build_reaped_pgid_leader,
    ChildStep,
};

/// A tid that is live but not a thread-group leader, for as long as this value lives.
pub(super) struct LiveNonLeaderTid {
    pub(super) id: ProcessId,
    stop_tx: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl LiveNonLeaderTid {
    pub(super) fn spawn() -> Self {
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            // SAFETY: SYS_gettid takes no arguments and always succeeds.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
            tid_tx.send(tid).expect("send tid to the test thread");
            _ = stop_rx.recv();
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
        LiveNonLeaderTid {
            id,
            stop_tx: Some(stop_tx),
            worker: Some(worker),
        }
    }
}

impl Drop for LiveNonLeaderTid {
    fn drop(&mut self) {
        drop(self.stop_tx.take());
        if let Some(worker) = self.worker.take() {
            _ = worker.join();
        }
    }
}

/// A reaped process-group leader whose group lives on reports exited. Real syscall: `EINVAL` on
/// < 6.16, `ESRCH` on >= 6.16 (the arm is then not reached; see the forced twin).
#[test]
fn block_until_exit_reports_exited_for_a_reaped_pgid_leader() {
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

/// A reaped leader is exited whatever `/proc` view this process has: `kill(pid, 0)` answering
/// `ESRCH` needs no `/proc`.
#[test]
fn block_until_exit_reports_exited_for_a_reaped_pgid_leader_whatever_the_proc_view() {
    use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};

    let (l_id, fixture) = build_reaped_pgid_leader();
    for view in [ForcedView::Diverged, ForcedView::Unassessable] {
        let forced_errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::INVAL);
        let forced_view = force_proc_view_once(view);
        let result = super::block_until_exit(l_id, None);
        drop(forced_view);
        drop(forced_errno);
        assert!(
            matches!(result, Ok(true)),
            "a reaped leader is exited under a {view:?} view, got {result:?}"
        );
    }

    fixture.release_and_confirm_m_exited();
}

/// A live non-leader tid with `pidfd_open` forced to `ENOENT` is `NotThreadGroupLeader` carrying
/// the pid and the errno, not exited.
#[test]
fn block_until_exit_on_a_live_non_leader_tid_is_an_error_with_forced_enoent() {
    let worker = LiveNonLeaderTid::spawn();
    let id = worker.id;

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
}

/// `Unassessable` carrying `needles` in its message, with an OS error as `source()` iff
/// `expect_source`, logged once at `warn` (`marker` finds the record).
fn assert_unassessable_with_cause(
    result: Result<bool, crate::error::Error>,
    needles: &[&str],
    expect_source: bool,
    marker: &str,
    mark: usize,
) {
    use std::error::Error as _;

    let err = match result {
        Err(e @ crate::error::Error::Unassessable { .. }) => e,
        other => panic!("expected Unassessable, got {other:?}"),
    };
    let text = err.to_string();
    for needle in needles {
        assert!(text.contains(needle), "{needle:?} missing from the message: {text}");
    }
    assert_eq!(
        err.source().is_some(),
        expect_source,
        "source() must be the OS error behind the cause, when there is one: {text}"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, marker),
        vec![log::Level::Warn],
        "the verdict must be logged once, at warn: {text}"
    );
}

/// A live non-leader tid under a DIVERGED view: `Unassessable` naming the view and the
/// `pidfd_open` errno, never a raw errno (a bare `NotFound` from `ENOENT` on 6.16+ reads as "gone").
#[test]
fn block_until_exit_on_a_live_non_leader_tid_is_unassessable_when_the_proc_view_is_diverged() {
    use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};

    crate::log_capture::install();
    let worker = LiveNonLeaderTid::spawn();
    let marker = format!("pid {} identity could not be confirmed", worker.id.pid());
    let mark = crate::log_capture::mark();
    let forced_errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::NOENT);
    let forced_view = force_proc_view_once(ForcedView::Diverged);
    let result = super::block_until_exit(worker.id, None);
    drop(forced_view);
    drop(forced_errno);
    assert_unassessable_with_cause(result, &["outer pid namespace", "pidfd_open: "], true, &marker, mark);
}

/// Twin for a view that could not be established: the reason is in the message.
#[test]
fn block_until_exit_on_a_live_non_leader_tid_is_unassessable_when_the_proc_view_is_unreadable() {
    use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};

    crate::log_capture::install();
    let worker = LiveNonLeaderTid::spawn();
    let marker = format!("pid {} identity could not be confirmed", worker.id.pid());
    let mark = crate::log_capture::mark();
    let forced_errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::INVAL);
    let forced_view = force_proc_view_once(ForcedView::Unassessable);
    let result = super::block_until_exit(worker.id, None);
    drop(forced_view);
    drop(forced_errno);
    assert_unassessable_with_cause(result, &["forced by a test", "pidfd_open: "], true, &marker, mark);
}

/// A non-leader tid that has exited but is not yet reaped (a ptraced zombie thread) reads
/// `Present` but `Dead`: exited, not an error. Both answers are forced here; the real ptrace
/// fixture is in `tests/linux_pidfd_wait.rs`.
#[test]
fn block_until_exit_on_a_dead_non_leader_tid_is_exited_with_forced_enoent() {
    let worker = LiveNonLeaderTid::spawn();
    let id = worker.id;

    let forced_errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::NOENT);
    let forced_alive = super::fault::force_alive_once(Liveness::Dead);
    let result = super::block_until_exit(id, None);
    drop(forced_alive);
    drop(forced_errno);
    assert!(
        matches!(result, Ok(true)),
        "a Present but Dead non-leader tid must report exited (Ok(true)), not {result:?}"
    );
}

/// The `INVAL`/`NOENT` arm's liveness check refused: `Unassessable` carrying the errno and one
/// `warn`, never exited.
#[test]
fn block_until_exit_is_unassessable_when_the_einval_arms_liveness_is_unknown() {
    crate::log_capture::install();
    let worker = LiveNonLeaderTid::spawn();
    let id = worker.id;
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
}

/// The `Unknown` branch of the `INVAL`/`NOENT` arm can't be produced for real, so both the errno
/// and the exists() answer are forced. Unknown must be `Unassessable` carrying the errno + one
/// warn, never exited.
#[test]
fn open_verified_is_unassessable_when_the_einval_arms_exists_is_unknown() {
    crate::log_capture::install();
    let what = "einval-arm-exists-unknown probe";
    let mark = crate::log_capture::mark();
    let forced_errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::INVAL);
    let forced_exists = super::fault::force_exists_once(Existence::Unknown);
    let result = super::open_verified(ProcessId::current(), "foreign process wait", what);
    drop(forced_exists);
    drop(forced_errno);
    assert_unassessable_with_cause(result.map(|fd| fd.is_some()), &["existence query"], true, what, mark);
}

/// Twin for the post-open re-verify: a real pidfd on a live child, `exists()` forced `Unknown`.
/// `Unassessable` with no errno (`pidfd_open` succeeded) + one warn, never exited.
#[test]
fn block_until_exit_is_unassessable_when_the_post_open_exists_is_unknown() {
    use crate::containment::cgroup::test_support::{block_on, fork_running};

    crate::log_capture::install();
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

/// While the fixture's `block_w` is open, no other `fork_running` can fork: a fork now would let
/// the child inherit `block_w` and hold `M` back from EOF. The forking thread reports over one
/// channel, in order: first that it found `spawn_lock` held (`Contended`, sent before it blocks),
/// then that it forked (`Forked`). It cannot fork while this thread holds the lock, so the first
/// event is `Contended` and the channel is empty until the fixture releases; a fixture that left
/// the lock free would make the first event `Forked` instead of hanging.
#[test]
fn a_concurrent_fork_running_waits_until_the_fixture_releases_block_w() {
    use crate::containment::cgroup::fault::{set_after_fork_still_locked, set_fork_running_lock_contended};
    use crate::containment::cgroup::test_support::{fork_running, reap};

    #[derive(Debug, PartialEq)]
    enum Event {
        Contended,
        Forked,
    }

    let (l_id, fixture) = build_reaped_pgid_leader();
    let _ = l_id;
    let (tx, rx) = std::sync::mpsc::channel();
    let (tx_contended, tx_forked) = (tx.clone(), tx);
    let forker = std::thread::spawn(move || {
        let _contended = set_fork_running_lock_contended(move || tx_contended.send(Event::Contended).unwrap());
        let _forked = set_after_fork_still_locked(move || tx_forked.send(Event::Forked).unwrap());
        fork_running(|| {}).defuse()
    });

    assert_eq!(
        rx.recv().expect("the forking thread reports"),
        Event::Contended,
        "fork_running must find spawn_lock held by the fixture, not fork past it"
    );
    assert_eq!(
        rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty),
        "no fork may happen while the fixture's block_w is open"
    );

    fixture.release_and_confirm_m_exited();
    let child = forker
        .join()
        .expect("the forking thread finishes once the lock is free");
    assert_eq!(rx.recv().expect("the forking thread reports its fork"), Event::Forked);
    reap(child);
}

/// The SUCCESS path with the pidfd's fdinfo `Pid:` forced: the target's pid as the mounted
/// procfs numbers it. `ProcessId::current()` is a live target, so `pidfd_open` really succeeds.
///
/// `what` is unique per test: it is the marker a test finds its own log record by, since every
/// test using `ProcessId::current()` shares one pid.
fn open_verified_current_with_fdinfo(
    answer: Result<PidfdTarget, i32>,
    what: &'static str,
) -> Result<Option<rustix::fd::OwnedFd>, crate::error::Error> {
    let forced = crate::identity::proc_view_fault::force_fdinfo_once(answer);
    let result = super::open_verified(ProcessId::current(), "foreign process wait", what);
    drop(forced);
    result
}

/// A pidfd whose fdinfo `Pid:` is not `id.pid()` (another pid, or `0` = invisible) describes a
/// `/proc` that is not the target's namespace: `Unassessable`, never a stat comparison.
#[test]
fn open_verified_is_unassessable_when_the_pidfds_fdinfo_names_another_pid() {
    crate::log_capture::install();
    let own = std::process::id();
    for (named, what) in [
        (0, "fdinfo-names-pid-0 probe"),
        (own + 1, "fdinfo-names-other-pid probe"),
    ] {
        let mark = crate::log_capture::mark();
        let result = open_verified_current_with_fdinfo(Ok(PidfdTarget::Pid(named)), what);
        assert_unassessable_with_cause(
            result.map(|fd| fd.is_some()),
            &["outer pid namespace", &format!("numbers the target {named}")],
            false,
            what,
            mark,
        );
    }
}

/// An fdinfo that cannot be read is `Unassessable` naming the OS error as its cause.
#[test]
fn open_verified_is_unassessable_when_the_pidfds_fdinfo_is_unreadable() {
    crate::log_capture::install();
    let what = "fdinfo-unreadable probe";
    let mark = crate::log_capture::mark();
    let result = open_verified_current_with_fdinfo(Err(libc::EACCES), what);
    assert_unassessable_with_cause(
        result.map(|fd| fd.is_some()),
        &["fdinfo could not be read"],
        true,
        what,
        mark,
    );
}

/// The match case: an fdinfo `Pid:` equal to `id.pid()` proceeds to the start-token comparison
/// through the same `/proc` dirfd.
#[test]
fn open_verified_accepts_a_live_target_whose_fdinfo_pid_matches() {
    let forced = open_verified_current_with_fdinfo(Ok(PidfdTarget::Pid(std::process::id())), "fdinfo-matches probe");
    assert!(matches!(forced, Ok(Some(_))), "got {forced:?}");
    let unforced = super::open_verified(ProcessId::current(), "foreign process wait", "test probe");
    assert!(
        matches!(unforced, Ok(Some(_))),
        "the real fdinfo must match too, got {unforced:?}"
    );
}

/// A pidfd whose fdinfo says `Reaped` (forced): the target is gone, so `Ok(None)`, not `Unassessable`.
/// Mutant: "`Reaped` is `Unassessable`".
#[test]
fn open_verified_reports_gone_when_the_pidfds_fdinfo_says_the_target_was_reaped() {
    let result = open_verified_current_with_fdinfo(Ok(PidfdTarget::Reaped), "fdinfo-reaped probe");
    assert!(matches!(result, Ok(None)), "got {result:?}");
}

/// The real race: the target is reaped after `pidfd_open` succeeded and before the fdinfo read.
#[test]
fn verify_pidfd_target_reports_gone_for_a_target_reaped_after_pidfd_open() {
    let mut child = crate::test_spawn::spawn(&mut std::process::Command::new("true")).expect("spawn true");
    let pid = rustix::process::Pid::from_raw(child.id() as i32).expect("child pid is nonzero");
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open");
    let id = ProcessId::of(child.id())
        .found()
        .expect("the unreaped child has an identity");
    child.wait().expect("reap the child");
    let result = super::verify_pidfd_target(id, pidfd, "reaped-after-open probe");
    assert!(matches!(result, Ok(None)), "got {result:?}");
}

/// The success path's own `Existence::Unknown` (the OS refused the stat read) is `Unassessable`,
/// never `Gone`.
#[test]
fn open_verified_is_unassessable_when_the_success_paths_exists_is_unknown() {
    crate::log_capture::install();
    let what = "success-path-exists-unknown probe";
    let mark = crate::log_capture::mark();
    let forced = super::fault::force_exists_once(Existence::Unknown);
    let result = super::open_verified(ProcessId::current(), "foreign process wait", what);
    drop(forced);
    assert_unassessable_with_cause(result.map(|fd| fd.is_some()), &["existence query"], false, what, mark);
}

// `pidfd_open` refusals that mean "this environment cannot do it" =====

/// The `Unsupported` an `open_verified` call answers when `pidfd_open` is forced to `errno`.
fn unsupported_for(errno: rustix::io::Errno, open: impl FnOnce(ProcessId) -> Result<(), Error>) -> Error {
    let forced = super::fault::force_pidfd_open_errno_once(errno);
    let result = open(ProcessId::current());
    drop(forced);
    match result {
        Err(e @ Error::Unsupported { .. }) => e,
        other => panic!("a pidfd_open answering {errno} must be Unsupported, got {other:?}"),
    }
}

fn assert_unsupported_naming(err: &Error, op: &str, errno_name: &str) {
    match err {
        Error::Unsupported {
            op: got,
            platform,
            detail,
        } => {
            assert_eq!(got, op, "the op must name the caller");
            assert_eq!(*platform, "linux");
            assert!(
                detail.contains("pidfd_open") && detail.contains(errno_name),
                "the detail must name pidfd_open and {errno_name}: {detail}"
            );
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// A sandbox filter that answers `EPERM` or `ENODEV` to `pidfd_open` is as unsupported as one
/// that answers `ENOSYS`: the spawn path can never work there, and no other route exists.
///
/// Mutant: `EPERM`/`ENODEV` fall through to `Io`.
#[test]
fn a_pidfd_open_refused_with_eperm_or_enodev_is_unsupported_naming_the_errno() {
    for (errno, name) in [
        (rustix::io::Errno::PERM, "EPERM"),
        (rustix::io::Errno::NODEV, "ENODEV"),
        (rustix::io::Errno::NOSYS, "ENOSYS"),
    ] {
        let err = unsupported_for(errno, |id| {
            super::open_verified(id, "foreign process wait", "test probe").map(drop)
        });
        assert_unsupported_naming(&err, "foreign process wait", name);
    }
}

/// Any other errno stays `Io`: `EMFILE` is a resource limit, not a missing capability.
///
/// Mutant: every errno is `Unsupported`.
#[test]
fn a_pidfd_open_refused_with_emfile_stays_io() {
    let forced = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::MFILE);
    let result = super::open_verified(ProcessId::current(), "foreign process wait", "test probe");
    drop(forced);
    match result {
        Err(Error::Io(e)) => assert_eq!(e.raw_os_error(), Some(libc::EMFILE)),
        other => panic!("EMFILE must stay Io, got {other:?}"),
    }
}

/// Each foreign operation names itself in the `Unsupported` it answers, not one fixed
/// "wait/kill" for all three.
///
/// Mutant: the op is a fixed string.
#[test]
fn each_foreign_operation_names_itself_when_pidfd_open_is_refused() {
    let wait = unsupported_for(rustix::io::Errno::PERM, |id| {
        super::block_until_exit(id, None).map(drop)
    });
    assert_unsupported_naming(&wait, "foreign process wait", "EPERM");
    let kill = unsupported_for(rustix::io::Errno::PERM, super::kill);
    assert_unsupported_naming(&kill, "foreign process kill", "EPERM");
    let terminate = unsupported_for(rustix::io::Errno::PERM, super::terminate);
    assert_unsupported_naming(&terminate, "foreign process terminate", "EPERM");
}
