//! The identity reads (`ProcessId::of`, `exists`, `is_alive`) go through the checked `/proc`
//! view: on a `/proc` that is not this process's own namespace's, they answer `Unknown`, never
//! a `Found`, `Gone` or `Dead` read off another process. `ProcessId::current()` does not use
//! the view at all.

use rustix::io::Errno;
use rustix::process::Pid;

use super::signal_probe;
use crate::error::Error;
use crate::identity::probe::SignalProbe;
use crate::identity::stat_parse::stat_fixture;
use crate::identity::{ticks_host, ticks_id, Existence, FakeKernel, Key, Liveness, ProcessId, Resolved};

/// Above `PID_MAX_LIMIT` (2^22) yet a valid positive `kill` target, so `kill(pid, 0)` answers `ESRCH`.
pub(super) const NO_PROCESS_CAN_HOLD: u32 = i32::MAX as u32;

/// [`NO_PROCESS_CAN_HOLD`] as the kill target the kernel is asked about.
const NO_PROCESS_CAN_HOLD_TARGET: Pid = Pid::from_raw(i32::MAX).unwrap();

/// The kernels that leave live `pid` unanswerable on a host before Linux 6.9, where `/proc` tells
/// the process: a diverged view, a `self/status` that cannot be read, and no `/proc` to open
/// (descriptor exhaustion). (On pidfs the pidfd tells, and no view is asked.)
fn unavailable_views(pid: u32) -> [(&'static str, FakeKernel<'static>); 3] {
    [
        ("diverged", ticks_host(pid).diverged_view()),
        ("unassessable", ticks_host(pid).unreadable_view()),
        ("no /proc", ticks_host(pid).open_proc_fails(Errno::MFILE)),
    ]
}

/// Mutant: "read `stat` by path whatever the view" - the unavailable view is ignored and the
/// live process resolves.
#[skuld::test]
fn of_a_live_pid_is_unknown_when_the_view_is_unavailable() {
    for (name, kernel) in unavailable_views(std::process::id()) {
        let (got, cause) = ProcessId::of_with(&kernel, std::process::id());
        assert!(matches!(got, Resolved::Unknown), "{name}: got {got:?}");
        assert!(
            cause.into_error("the process").is_some(),
            "{name}: the view is the cause"
        );
    }
}

/// The debug line of a read left `Unknown` by a `/proc` that cannot be opened carries the OS error.
#[skuld::test]
fn the_line_of_an_unavailable_view_says_the_os_error() {
    crate::log_capture::install();
    let pid = std::process::id();
    let kernel = ticks_host(pid).open_proc_fails(Errno::MFILE);
    let mark = crate::log_capture::mark();

    let (got, _) = ProcessId::of_with(&kernel, pid);

    assert!(matches!(got, Resolved::Unknown), "{got:?}");
    let records = crate::log_capture::records_since_on_current_thread(mark, &format!("/proc/{pid}/stat not read"));
    let os_error = std::io::Error::from(Errno::MFILE).to_string();
    assert!(records.iter().any(|(_, line)| line.contains(&os_error)), "{records:?}");
}

/// `kill(pid, 0)` answering `ESRCH` resolves the pid in this process's own namespace, so it is
/// `Gone` whatever `/proc` shows. Mutant: "an unavailable view is always Unknown".
#[skuld::test]
fn of_a_pid_no_process_can_hold_is_gone_whatever_the_view() {
    for (name, kernel) in unavailable_views(NO_PROCESS_CAN_HOLD) {
        let kernel = kernel.on_signal_probe(NO_PROCESS_CAN_HOLD_TARGET, Err(Errno::SRCH));
        let got = ProcessId::of_with(&kernel, NO_PROCESS_CAN_HOLD).0;
        assert!(matches!(got, Resolved::Gone), "{name}: got {got:?}");
    }
}

/// Mutant: "`exists`/`is_alive` map an unavailable view to `Gone`/`Dead`".
#[skuld::test]
fn exists_and_is_alive_are_unknown_for_a_live_process_when_the_view_is_unavailable() {
    let id = ticks_id(std::process::id());
    for (name, kernel) in unavailable_views(std::process::id()) {
        assert_eq!(id.exists_with(&kernel).0, Existence::Unknown, "{name}");
        assert_eq!(id.is_alive_with(&kernel), Liveness::Unknown, "{name}");
    }
}

/// Mutant: "`exists`/`is_alive` ask `/proc` only, so an unavailable view hides an `ESRCH`".
#[skuld::test]
fn exists_and_is_alive_are_gone_and_dead_for_a_pid_no_process_can_hold_whatever_the_view() {
    let id = ProcessId::from_parts_for_test(NO_PROCESS_CAN_HOLD, Key::for_test(1));
    for (name, kernel) in unavailable_views(NO_PROCESS_CAN_HOLD) {
        let kernel = kernel.on_signal_probe(NO_PROCESS_CAN_HOLD_TARGET, Err(Errno::SRCH));
        assert_eq!(id.exists_with(&kernel).0, Existence::Gone, "{name}");
        assert_eq!(id.is_alive_with(&kernel), Liveness::Dead, "{name}");
    }
}

/// The ordinary view still resolves this process.
#[skuld::test]
fn a_live_process_is_present_and_alive_under_the_ordinary_view() {
    let id = ProcessId::current();
    assert_eq!(id.exists(), Existence::Present);
    assert_eq!(id.is_alive(), Liveness::Alive);
}

/// A `stat` that cannot be read is `Gone` only when `kill(pid, 0)` says `ESRCH`: under `hidepid`
/// a live process's `stat` is `ENOENT` or `EACCES`. Mutant: "an unreadable `stat` is `Gone`".
#[skuld::test]
fn a_stat_that_cannot_be_read_is_gone_only_when_kill_says_esrch() {
    const PID: u32 = 4242;
    let cases: [(i32, Result<(), Errno>, bool); 3] = [
        (libc::ENOENT, Ok(()), false),
        (libc::ENOENT, Err(Errno::SRCH), true),
        (libc::EACCES, Err(Errno::PERM), false),
    ];
    for (errno, probe, gone) in cases {
        let kernel = ticks_host(PID)
            .same_view()
            .on_read(&format!("{PID}/stat"), Err(errno))
            .on_signal_probe(Pid::from_raw(PID as i32).unwrap(), probe);
        let got = ProcessId::of_with(&kernel, PID).0;
        match (gone, &got) {
            (true, Resolved::Gone) | (false, Resolved::Unknown) => {}
            _ => panic!("stat {errno}, kill {probe:?}: got {got:?}"),
        }
    }
    let found = ticks_host(PID)
        .same_view()
        .on_read(&format!("{PID}/stat"), Ok(&stat_fixture("S", 424242)));
    match ProcessId::of_with(&found, PID).0 {
        Resolved::Found(id) => assert_eq!(id.key(), Key::for_test(424242)),
        other => panic!("a readable stat must resolve, got {other:?}"),
    }
}

/// The caller decides what is a kill target: a number that is none is `NotAPid` without the kernel
/// being asked (a `FakeKernel` with no row panics on any `signal_probe`). Mutant: "the check moves
/// into the kernel, and the caller passes anything on".
#[skuld::test]
fn a_number_that_is_no_kill_target_is_never_probed() {
    let kernel = FakeKernel::new();
    for pid in [0, i32::MAX as u32 + 1, u32::MAX] {
        assert_eq!(signal_probe(&kernel, pid), SignalProbe::NotAPid, "{pid}");
    }
}

/// The error a caller sees for a live process's `Unknown` read of `kernel`: the read's own cause.
fn cause_error_of_live_read(kernel: &FakeKernel<'_>) -> Option<Error> {
    let (got, cause) = ProcessId::of_with(kernel, std::process::id());
    assert!(matches!(got, Resolved::Unknown), "got {got:?}");
    cause.into_error("the spawned child")
}

/// The exact text a caller sees when `openat2` is missing. Mutant: "the errno is dropped from
/// the reason".
#[skuld::test]
fn the_error_for_a_host_without_openat2_names_the_requirement_and_the_errno() {
    let kernel = ticks_host(std::process::id()).open_proc_fails(Errno::NOSYS);
    let err = cause_error_of_live_read(&kernel).expect("no openat2 is an error");
    assert_eq!(
        err.to_string(),
        format!(
            "identifying the spawned child is not supported on linux: {}",
            crate::identity::openat2_refused_message("ENOSYS")
        )
    );
}

/// A diverged view keeps `Unassessable` and carries the view's reason, not the OS refusing.
/// Mutant: "the cause is replaced by the generic refusal".
#[skuld::test]
fn the_error_for_a_diverged_view_carries_the_view() {
    let kernel = ticks_host(std::process::id()).diverged_view();
    let err = cause_error_of_live_read(&kernel).expect("a diverged view is an error");
    assert!(
        matches!(&err, Error::Unassessable { detail, .. }
            if detail == "the spawned child identity could not be read: this process's /proc is an outer pid namespace's"),
        "{err:?}"
    );
}

/// With a fine view, an `Unknown` is the OS's (`hidepid`, a racing exit) and has no view to blame.
#[skuld::test]
fn no_error_is_blamed_on_a_fine_view() {
    let kernel = ticks_host(4242)
        .same_view()
        .on_read("4242/stat", Err(libc::ENOENT))
        .on_signal_probe(Pid::from_raw(4242).unwrap(), Ok(()));
    let (got, cause) = ProcessId::of_with(&kernel, 4242);
    assert!(matches!(got, Resolved::Unknown), "got {got:?}");
    assert!(cause.into_error("the spawned child").is_none());
}
