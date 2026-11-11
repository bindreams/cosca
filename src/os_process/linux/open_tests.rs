//! Tests for `open_verified_with`. On >= 6.16 the real syscall answers `ESRCH` for a reaped
//! process-group leader and never reaches the `EINVAL`/`ENOENT` arm, so each real-syscall test has a
//! twin that states the `pidfd_open` answer on a `FakeKernel`. The real live non-leader tid case lives
//! in `tests/linux_pidfd_wait.rs`.

use std::os::fd::{AsRawFd, OwnedFd};

use rustix::io::Errno;
use rustix::process::{getpid, pidfd_open, PidfdFlags};

use super::open_verified_error_with;
use crate::error::Error;
use crate::identity::stat_parse::stat_fixture;
use crate::identity::{Existence, FakeKernel, HostKernel, Key, ProcessId, UNREADABLE_STATUS_REASON};

/// A pid that no live process is expected to hold; only its `pidfd_open` row exists.
const FABRICATED: u32 = 4242;

fn fabricated_id() -> ProcessId {
    ProcessId::from_parts_for_test(FABRICATED, Key::for_test(1))
}

#[path = "open_tests/fixture.rs"]
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
        // The `/proc` path: the rows that use it state a host before Linux 6.9, where a thread's
        // identity is its `starttime`.
        let id = crate::identity::ticks_id(tid as u32);
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
#[skuld::test]
fn exited_through_open_reports_exited_for_a_reaped_pgid_leader() {
    let (l_id, fixture) = build_reaped_pgid_leader();
    assert_eq!(
        l_id.exists(),
        Existence::Gone,
        "a reaped leader must read Gone even while its pid number stays a live PGID"
    );

    let result = crate::test_child::exited_through_open(l_id, None);
    assert!(
        matches!(result, Ok(true)),
        "exited_through_open on a reaped group leader whose group lives on must report exited \
         (Ok(true)), not {result:?}"
    );

    fixture.release_and_confirm_m_exited();
}

/// Twin of the test above with `pidfd_open` stated to answer `EINVAL`, so the `INVAL`/`NOENT` arm
/// runs on any kernel.
#[skuld::test]
fn open_verified_is_gone_for_a_reaped_pgid_leader_when_pidfd_open_says_einval() {
    let (l_id, fixture) = build_reaped_pgid_leader();
    assert_eq!(
        l_id.exists(),
        Existence::Gone,
        "a reaped leader must read Gone even while its pid number stays a live PGID"
    );

    let kernel = FakeKernel::over(&HostKernel).on_pidfd_open(l_id.pid(), Err(Errno::INVAL));
    let result = open_verified_error_with(&kernel, l_id);
    assert!(
        matches!(result, Ok(None)),
        "an EINVAL on a reaped group leader whose group lives on must be gone (Ok(None)), not {result:?}"
    );

    fixture.release_and_confirm_m_exited();
}

/// A reaped leader is gone whatever `/proc` view this process has: `kill(pid, 0)` answering `ESRCH`
/// needs no `/proc`.
#[skuld::test]
fn open_verified_is_gone_for_a_reaped_pgid_leader_whatever_the_proc_view() {
    let (l_id, fixture) = build_reaped_pgid_leader();
    let refused = || FakeKernel::over(&HostKernel).on_pidfd_open(l_id.pid(), Err(Errno::INVAL));
    for (view, kernel) in [
        ("diverged", refused().diverged_view()),
        ("unreadable", refused().unreadable_view()),
    ] {
        let result = open_verified_error_with(&kernel, l_id);
        assert!(
            matches!(result, Ok(None)),
            "a reaped leader is gone under a {view} view, got {result:?}"
        );
    }

    fixture.release_and_confirm_m_exited();
}

/// A live non-leader tid whose `pidfd_open` answers `EINVAL` (< 6.16) or `ENOENT` (>= 6.16) is
/// `NotThreadGroupLeader` carrying the pid and the errno, not gone.
#[skuld::test]
fn open_verified_on_a_live_non_leader_tid_is_not_thread_group_leader_whichever_errno() {
    let worker = LiveNonLeaderTid::spawn();
    let id = worker.id;

    for errno in [Errno::INVAL, Errno::NOENT] {
        let kernel = FakeKernel::over(&HostKernel).on_pidfd_open(id.pid(), Err(errno));
        match open_verified_error_with(&kernel, id) {
            Err(Error::NotThreadGroupLeader { pid, source, .. }) => {
                assert_eq!(pid, id.pid());
                assert_eq!(source.raw_os_error(), Some(errno.raw_os_error()));
            }
            other => panic!("{errno} on a live non-leader tid must be NotThreadGroupLeader, got {other:?}"),
        }
    }
}

/// The start of every `Unassessable` message.
const UNASSESSABLE: &str = "identity could not be confirmed";

/// `Unassessable` carrying `needles` in its message, with an OS error as `source()` iff
/// `expect_source`, logged once at `warn` on this thread (`marker` finds the record).
fn assert_unassessable_with_cause(
    result: Result<bool, crate::error::Error>,
    needles: &[&str],
    expect_source: bool,
    marker: &str,
    mark: usize,
) -> crate::error::Error {
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
    let levels: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, marker)
        .into_iter()
        .map(|(level, _)| level)
        .collect();
    assert_eq!(
        levels,
        vec![log::Level::Warn],
        "the verdict must be logged once, at warn: {text}"
    );
    err
}

/// A live non-leader tid under a DIVERGED view: `Unassessable` naming the view and the
/// `pidfd_open` errno, never a raw errno (a bare `NotFound` from `ENOENT` on 6.16+ reads as "gone").
#[skuld::test]
fn open_verified_on_a_live_non_leader_tid_is_unassessable_when_the_proc_view_is_diverged() {
    crate::log_capture::install();
    let worker = LiveNonLeaderTid::spawn();
    let marker = format!("pid {} identity could not be confirmed", worker.id.pid());
    let mark = crate::log_capture::mark();
    let kernel = FakeKernel::over(&HostKernel)
        .on_pidfd_open(worker.id.pid(), Err(Errno::NOENT))
        .diverged_view();
    let result = open_verified_error_with(&kernel, worker.id).map(|fd| fd.is_some());
    let err = assert_unassessable_with_cause(result, &["outer pid namespace"], true, &marker, mark);
    // The `pidfd_open` errno is the source, not part of the message, and the Report names the call.
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT), "{err:?}");
    assert!(!err.to_string().contains("pidfd_open"), "{err}");
    let report = crate::error::Report(&err).to_string();
    assert!(report.contains("pidfd_open"), "{report}");
}

/// Twin for a view that could not be established: the reason is in the message.
#[skuld::test]
fn open_verified_on_a_live_non_leader_tid_is_unassessable_when_the_proc_view_is_unreadable() {
    crate::log_capture::install();
    let worker = LiveNonLeaderTid::spawn();
    let marker = format!("pid {} identity could not be confirmed", worker.id.pid());
    let mark = crate::log_capture::mark();
    let kernel = FakeKernel::over(&HostKernel)
        .on_pidfd_open(worker.id.pid(), Err(Errno::INVAL))
        .unreadable_view();
    let result = open_verified_error_with(&kernel, worker.id).map(|fd| fd.is_some());
    assert_unassessable_with_cause(result, &[UNREADABLE_STATUS_REASON, "pidfd_open: "], true, &marker, mark);
}

/// A non-leader tid that has exited but is not yet reaped (a ptraced zombie thread) reads
/// `Present` but `Dead`: gone, not an error. Its `stat` is stated here; the real ptrace fixture is
/// in `tests/linux_pidfd_wait.rs`.
#[skuld::test]
fn open_verified_on_a_dead_non_leader_tid_is_gone() {
    let worker = LiveNonLeaderTid::spawn();
    let id = worker.id;

    let kernel = FakeKernel::over(&HostKernel)
        .on_pidfd_open(id.pid(), Err(Errno::NOENT))
        .on_read(&format!("{}/stat", id.pid()), Ok(&stat_fixture("Z", id.key().ticks())));
    let result = open_verified_error_with(&kernel, id);
    assert!(
        matches!(result, Ok(None)),
        "a Present but Dead non-leader tid must be gone (Ok(None)), not {result:?}"
    );
}

/// The `INVAL`/`NOENT` arm's liveness check refused: `Unassessable` carrying the errno and one
/// `warn`, never gone. The existence check reads the `stat` first and finds the process; the
/// liveness check's read, the second, is refused.
#[skuld::test]
fn open_verified_is_unassessable_when_the_einval_arms_liveness_is_unknown() {
    crate::log_capture::install();
    let worker = LiveNonLeaderTid::spawn();
    let id = worker.id;
    let marker = format!("pid {} identity could not be confirmed", id.pid());
    let mark = crate::log_capture::mark();

    let stat = format!("{}/stat", id.pid());
    let kernel = FakeKernel::over(&HostKernel)
        .on_pidfd_open(id.pid(), Err(Errno::INVAL))
        .on_read(&stat, Ok(&stat_fixture("S", id.key().ticks())))
        .on_read_after(&stat, 1, Err(libc::EACCES));
    let result = open_verified_error_with(&kernel, id);
    match result {
        Err(
            ref e @ Error::Unassessable {
                source: Some(ref source),
                ..
            },
        ) => {
            assert_eq!(source.raw_os_error(), Some(libc::EINVAL));
            let report = crate::error::Report(e).to_string();
            assert!(report.contains("pidfd_open"), "{report}");
        }
        other => panic!("Liveness::Unknown on the EINVAL/ENOENT arm must be Unassessable, got {other:?}"),
    }
    assert_eq!(
        crate::log_capture::levels_since(mark, &marker),
        vec![log::Level::Warn],
        "the Unassessable verdict must be logged once, at warn"
    );
}

/// The `Unknown` branch of the `INVAL`/`NOENT` arm can't be produced for real, so the errno and the
/// refused `stat` are stated. Unknown must be `Unassessable` carrying the errno + one warn, never
/// gone.
#[skuld::test]
fn open_verified_is_unassessable_when_the_einval_arms_exists_is_unknown() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let own = crate::identity::ticks_id(std::process::id());
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_pidfd_open(own.pid(), Err(Errno::INVAL))
        .on_read(&format!("{}/stat", own.pid()), Err(libc::EACCES));
    let result = open_verified_error_with(&kernel, own);
    let err = assert_unassessable_with_cause(
        result.map(|fd| fd.is_some()),
        &["existence query"],
        true,
        UNASSESSABLE,
        mark,
    );
    let report = crate::error::Report(&err).to_string();
    assert!(report.contains("pidfd_open"), "{report}");
}

/// A panic between building the fixture and releasing it must still tear down `L` and `M`.
/// `catch_unwind`, not a subprocess: the fixture's `Drop` runs on this thread's unwind, the path a
/// real assertion failure takes.
#[skuld::test]
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
    crate::wait::poll_ready(&mut fds).expect("wait for M's exit");
    assert!(
        crate::wait::any_ready_now(&mut fds).expect("poll the probe pidfd"),
        "M must have exited once the panicking fixture unwound and dropped"
    );
    assert!(fds[0].revents().contains(rustix::event::PollFlags::IN));
}

/// A panic inside `build_reaped_pgid_leader` while `L` is still blocked must tear `L` down:
/// afterwards `L` is reaped, so `waitpid(L)` answers `ECHILD`.
#[skuld::test]
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
#[skuld::test]
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
#[skuld::test]
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
#[skuld::test]
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
        fork_running(&[], || {}).defuse()
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

/// The SUCCESS path with the fdinfo of this process's own pidfd stated: its `Pid:` is the target as
/// the mounted procfs numbers it. `ProcessId::current()` is a live target, so the pidfd is real;
/// the fake hands it out as `pidfd_open`'s answer, so that the stated path names its number.
fn open_verified_current_with_fdinfo(fdinfo: Result<&[u8], i32>) -> Result<Option<OwnedFd>, Error> {
    let own = crate::identity::ticks_id(std::process::id());
    let pidfd = pidfd_open(getpid(), PidfdFlags::empty()).expect("pidfd_open of this process");
    let path = format!("thread-self/fdinfo/{}", pidfd.as_raw_fd());
    let kernel = FakeKernel::over(&HostKernel)
        .on_pidfd_open(own.pid(), Ok(pidfd))
        .on_read(&path, fdinfo);
    open_verified_error_with(&kernel, own)
}

/// An fdinfo whose `Pid:` line says `pid` (`-1`: the target was reaped).
fn fdinfo_naming(pid: i64) -> Vec<u8> {
    format!("Pid:\t{pid}\n").into_bytes()
}

/// A pidfd whose fdinfo `Pid:` is not `id.pid()` (another pid, or `0` = invisible) describes a
/// `/proc` that is not the target's namespace: `Unassessable`, never a stat comparison.
#[skuld::test]
fn open_verified_is_unassessable_when_the_pidfds_fdinfo_names_another_pid() {
    crate::log_capture::install();
    let own = std::process::id();
    for named in [0, own + 1] {
        let mark = crate::log_capture::mark();
        let result = open_verified_current_with_fdinfo(Ok(&fdinfo_naming(i64::from(named))));
        assert_unassessable_with_cause(
            result.map(|fd| fd.is_some()),
            &["outer pid namespace", &format!("numbers the target {named}")],
            false,
            UNASSESSABLE,
            mark,
        );
    }
}

/// An `Unassessable` verdict ends with what the open left undone.
///
/// Mutant: the consequence dropped from the message.
#[skuld::test]
fn an_unassessable_verdict_ends_with_what_the_open_left_undone() {
    crate::log_capture::install();
    let result = open_verified_current_with_fdinfo(Ok(&fdinfo_naming(0)));
    match result {
        Err(e @ Error::Unassessable { .. }) => assert!(
            e.to_string()
                .ends_with("; its exit cannot be observed and no signal was sent"),
            "{e}"
        ),
        other => panic!("expected Unassessable, got {other:?}"),
    }
}

/// An fdinfo that cannot be read is `Unassessable` naming the OS error as its cause.
#[skuld::test]
fn open_verified_is_unassessable_when_the_pidfds_fdinfo_is_unreadable() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let result = open_verified_current_with_fdinfo(Err(libc::EACCES));
    assert_unassessable_with_cause(
        result.map(|fd| fd.is_some()),
        &["fdinfo could not be read"],
        true,
        UNASSESSABLE,
        mark,
    );
}

/// The match case: an fdinfo `Pid:` equal to `id.pid()` proceeds to the start-token comparison
/// through the same `/proc` dirfd.
#[skuld::test]
fn open_verified_accepts_a_live_target_whose_fdinfo_pid_matches() {
    let stated = open_verified_current_with_fdinfo(Ok(&fdinfo_naming(i64::from(std::process::id()))));
    assert!(matches!(stated, Ok(Some(_))), "got {stated:?}");
    let real = open_verified_error_with(&HostKernel, crate::identity::ticks_id(std::process::id()));
    assert!(
        matches!(real, Ok(Some(_))),
        "the real fdinfo must match too, got {real:?}"
    );
}

/// A pidfd whose fdinfo says `Reaped`: the target is gone, so `Ok(None)`, not `Unassessable`.
/// Mutant: "`Reaped` is `Unassessable`".
#[skuld::test]
fn open_verified_reports_gone_when_the_pidfds_fdinfo_says_the_target_was_reaped() {
    let result = open_verified_current_with_fdinfo(Ok(&fdinfo_naming(-1)));
    assert!(matches!(result, Ok(None)), "got {result:?}");
}

/// The real race: the target is reaped after `pidfd_open` succeeded and before the fdinfo read.
#[skuld::test]
fn verify_pidfd_target_reports_gone_for_a_target_reaped_after_pidfd_open() {
    let mut child = crate::test_spawn::spawn(&mut std::process::Command::new("true")).expect("spawn true");
    let pid = rustix::process::Pid::from_raw(child.id() as i32).expect("child pid is nonzero");
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open");
    let id = crate::identity::ticks_id(child.id());
    child.wait().expect("reap the child");
    let result = super::verify_pidfd_target(&HostKernel, id, pidfd);
    assert!(matches!(result, Ok(None)), "got {result:?}");
}

/// The success path's own `Existence::Unknown` (the OS refused the stat read) is `Unassessable`,
/// never `Gone`.
#[skuld::test]
fn open_verified_is_unassessable_when_the_success_paths_exists_is_unknown() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let own = crate::identity::ticks_id(std::process::id());
    let pidfd = pidfd_open(getpid(), PidfdFlags::empty()).expect("pidfd_open of this process");
    let fdinfo = format!("thread-self/fdinfo/{}", pidfd.as_raw_fd());
    let kernel = FakeKernel::over(&HostKernel)
        .on_pidfd_open(own.pid(), Ok(pidfd))
        .on_read(&fdinfo, Ok(&fdinfo_naming(i64::from(own.pid()))))
        .on_read(&format!("{}/stat", own.pid()), Err(libc::EACCES));
    let result = open_verified_error_with(&kernel, own);
    assert_unassessable_with_cause(
        result.map(|fd| fd.is_some()),
        &["existence query"],
        false,
        UNASSESSABLE,
        mark,
    );
}

// `pidfd_open` answers =====
//
// A fake with only a `pidfd_open` row, and a fabricated id: an answer that decides the open on its
// own reads nothing else, and a fake with no other row panics if it does.

/// `ESRCH` is the answer for a reaped process (6.16 and later also for a reaped process-group
/// leader): gone, with nothing else read.
#[skuld::test]
fn open_verified_is_gone_when_pidfd_open_says_esrch() {
    let id = fabricated_id();
    let kernel = FakeKernel::new().on_pidfd_open(id.pid(), Err(Errno::SRCH));
    let result = open_verified_error_with(&kernel, id);
    assert!(matches!(result, Ok(None)), "got {result:?}");
}

/// The error `open_verified_with` answers when `pidfd_open` answers `errno`.
fn refused_with(errno: Errno) -> Error {
    let id = fabricated_id();
    let kernel = FakeKernel::new().on_pidfd_open(id.pid(), Err(errno));
    match open_verified_error_with(&kernel, id) {
        Err(e) => e,
        Ok(_) => panic!("a pidfd_open answering {errno} must fail the open, but it succeeded"),
    }
}

/// Every refusal is `Unsupported` in the policy's message shape.
///
/// Mutants: `EACCES` (or any other) missing from `FailedCall::refusal`; the detail carries a guessed
/// cause; a different `Errno` name.
#[skuld::test]
fn a_refused_pidfd_open_is_unsupported_in_the_policys_message_shape() {
    for (errno, name) in [
        (Errno::NOSYS, "ENOSYS"),
        (Errno::PERM, "EPERM"),
        (Errno::ACCESS, "EACCES"),
        (Errno::NODEV, "ENODEV"),
    ] {
        let err = refused_with(errno);
        assert!(matches!(&err, Error::Unsupported { platform: "linux", .. }), "{err:?}");
        assert_eq!(
            err.to_string(),
            format!(
                "process open is not supported on linux: cosca requires pidfd_open (Linux \u{2265} 5.3), \
                 refused here: pidfd_open answered {name}"
            )
        );
    }
}

/// The open names itself as the operation: every act by id goes through it, so none keeps a name
/// of its own (`tests/linux_pidfd_refused.rs` drives the acts).
///
/// Mutant: the open names another operation.
#[skuld::test]
fn an_unsupported_open_names_process_open() {
    match refused_with(Errno::PERM) {
        Error::Unsupported { op, .. } => assert_eq!(op, "process open"),
        other => panic!("a refused pidfd_open must be Unsupported, got {other:?}"),
    }
}

/// A transient or resource errno is not a refusal: `Io`, naming the syscall, keeping the OS
/// error as its source.
///
/// Mutants: every errno is `Unsupported`; the `pidfd_open:` context is dropped.
#[skuld::test]
fn a_transient_pidfd_open_failure_stays_io_naming_the_syscall() {
    for (errno, text, code) in [
        (Errno::MFILE, "Too many open files", libc::EMFILE),
        (Errno::NFILE, "Too many open files in system", libc::ENFILE),
        (Errno::NOMEM, "Cannot allocate memory", libc::ENOMEM),
    ] {
        match refused_with(errno) {
            Error::Io(e) => {
                assert_eq!(e.to_string(), format!("pidfd_open: {text} (os error {code})"));
                let source = std::error::Error::source(&e).expect("the OS error is kept as the source");
                let source = source.downcast_ref::<std::io::Error>().expect("an io::Error source");
                assert_eq!(source.raw_os_error(), Some(code));
            }
            other => panic!("{errno} must stay Io, got {other:?}"),
        }
    }
}
