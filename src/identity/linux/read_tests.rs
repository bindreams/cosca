//! The identity reads (`ProcessId::of`, `exists`, `is_alive`) go through the checked `/proc`
//! view: on a `/proc` that is not this process's own namespace's, they answer `Unknown`, never
//! a `Found`, `Gone` or `Dead` read off another process. `ProcessId::current()` does not use
//! the view at all.

use rustix::io::Errno;

use super::proc_view::fault::force_openat2_errno;
use super::unknown_identity_error_with;
use crate::error::Error;
use crate::identity::{Existence, FakeKernel, HostKernel, Liveness, ProcessId, Resolved};

/// Above `PID_MAX_LIMIT` (2^22) yet a valid positive `kill` target, so `kill(pid, 0)` answers `ESRCH`.
pub(super) const NO_PROCESS_CAN_HOLD: u32 = i32::MAX as u32;

/// `stat` of a process whose `starttime` (field 22) is 424242.
const STAT_STARTED_AT_424242: &[u8] = b"4242 (x) S 1 4242 4242 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 424242 0 0";

/// A `self/status` with the pid in two namespaces: `/proc` is an outer namespace's.
const DIVERGED_STATUS: &[u8] = b"NSpid:\t4242\t1\n";

/// A `self/status` with the pid in one namespace: `/proc` is this namespace's own.
const SAME_STATUS: &[u8] = b"NSpid:\t4242\n";

/// The kernels that leave a live pid unanswerable, over the real one: a diverged view, a
/// `self/status` that cannot be read, and no `/proc` to open (descriptor exhaustion).
fn unavailable_views() -> [(&'static str, FakeKernel<'static>); 3] {
    [
        (
            "diverged",
            FakeKernel::over(&HostKernel).on_read("self/status", Ok(DIVERGED_STATUS)),
        ),
        (
            "unassessable",
            FakeKernel::over(&HostKernel).on_read("self/status", Err(libc::EIO)),
        ),
        ("no /proc", FakeKernel::over(&HostKernel).open_proc_fails(Errno::MFILE)),
    ]
}

/// A kernel whose view is this namespace's own, over the real one.
fn same_view() -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel).on_read("self/status", Ok(SAME_STATUS))
}

/// Mutant: "read `stat` by path whatever the view" - the unavailable view is ignored and the
/// live process resolves. The `no /proc` view: descriptor exhaustion is `Unknown` with a cause,
/// never `Gone`.
#[skuld::test]
fn of_a_live_pid_is_unknown_when_the_view_is_unavailable() {
    for (name, kernel) in unavailable_views() {
        let (got, cause) = ProcessId::of_with(&kernel, std::process::id());
        assert!(matches!(got, Resolved::Unknown), "{name}: got {got:?}");
        assert!(
            cause.into_error("the process").is_some(),
            "{name}: the view is the cause"
        );
    }
}

/// `kill(pid, 0)` answering `ESRCH` resolves the pid in this process's own namespace, so it is
/// `Gone` whatever `/proc` shows. Mutant: "an unavailable view is always Unknown".
#[skuld::test]
fn of_a_pid_no_process_can_hold_is_gone_whatever_the_view() {
    for (name, kernel) in unavailable_views() {
        let kernel = kernel.on_signal_probe(NO_PROCESS_CAN_HOLD, Err(Errno::SRCH));
        let got = ProcessId::of_with(&kernel, NO_PROCESS_CAN_HOLD).0;
        assert!(matches!(got, Resolved::Gone), "{name}: got {got:?}");
    }
}

/// Mutant: "`exists`/`is_alive` map an unavailable view to `Gone`/`Dead`".
#[skuld::test]
fn exists_and_is_alive_are_unknown_for_a_live_process_when_the_view_is_unavailable() {
    let id = ProcessId::current();
    for (name, kernel) in unavailable_views() {
        assert_eq!(id.exists_with(&kernel).0, Existence::Unknown, "{name}");
        assert_eq!(id.is_alive_with(&kernel), Liveness::Unknown, "{name}");
    }
}

/// Mutant: "`exists`/`is_alive` ask `/proc` only, so an unavailable view hides an `ESRCH`".
#[skuld::test]
fn exists_and_is_alive_are_gone_and_dead_for_a_pid_no_process_can_hold_whatever_the_view() {
    let id = ProcessId::from_parts_for_test(NO_PROCESS_CAN_HOLD, 1);
    for (name, kernel) in unavailable_views() {
        let kernel = kernel.on_signal_probe(NO_PROCESS_CAN_HOLD, Err(Errno::SRCH));
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
        let kernel = same_view().on_read("4242/stat", Err(errno)).on_signal_probe(PID, probe);
        let got = ProcessId::of_with(&kernel, PID).0;
        match (gone, &got) {
            (true, Resolved::Gone) | (false, Resolved::Unknown) => {}
            _ => panic!("stat {errno}, kill {probe:?}: got {got:?}"),
        }
    }
    let found = same_view().on_read("4242/stat", Ok(STAT_STARTED_AT_424242));
    match ProcessId::of_with(&found, PID).0 {
        Resolved::Found(id) => assert_eq!(id.start_token_raw(), 424242),
        other => panic!("a readable stat must resolve, got {other:?}"),
    }
}

/// A host where `openat2` answers `ENOSYS` (kernel before 5.6) or `EPERM` (a seccomp filter): no
/// view can be established, yet `/proc` is mounted and `current()` must still work.
/// Mutant: "`current_token` opens the checked `/proc` when the view is not `Same`".
#[skuld::test]
fn current_works_where_openat2_is_unavailable() {
    let ordinary = ProcessId::current();
    for errno in [rustix::io::Errno::NOSYS, rustix::io::Errno::PERM] {
        let _forced = force_openat2_errno(errno);
        assert_eq!(ProcessId::current(), ordinary, "{errno}");
    }
}

/// Without `openat2` there is no view, so a by-pid read of a live pid is `Unknown`, and a pid
/// no process can hold is still `Gone`.
#[skuld::test]
fn by_pid_reads_are_unknown_or_gone_where_openat2_is_unavailable() {
    let id = ProcessId::current();
    let _forced = force_openat2_errno(rustix::io::Errno::NOSYS);
    assert!(matches!(ProcessId::of(std::process::id()), Resolved::Unknown));
    assert_eq!(id.exists(), Existence::Unknown);
    assert_eq!(id.is_alive(), Liveness::Unknown);
    assert!(matches!(ProcessId::of(NO_PROCESS_CAN_HOLD), Resolved::Gone));
}

/// The exact text a caller sees when `openat2` is missing. Mutant: "the errno is dropped from
/// the reason".
#[skuld::test]
fn the_error_for_a_host_without_openat2_names_the_requirement_and_the_errno() {
    let kernel = FakeKernel::new().open_proc_fails(Errno::NOSYS);
    let err = unknown_identity_error_with(&kernel, "the spawned child").expect("no openat2 is an error");
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
    let kernel = FakeKernel::over(&HostKernel).on_read("self/status", Ok(DIVERGED_STATUS));
    let err = unknown_identity_error_with(&kernel, "the spawned child").expect("a diverged view is an error");
    assert!(
        matches!(&err, Error::Unassessable { detail, .. }
            if detail == "the spawned child identity could not be read: this process's /proc is an outer pid namespace's"),
        "{err:?}"
    );
}

/// With a fine view, an `Unknown` is the OS's (`hidepid`, a racing exit) and has no view to blame.
#[skuld::test]
fn no_error_is_blamed_on_a_fine_view() {
    assert!(unknown_identity_error_with(&HostKernel, "the spawned child").is_none());
}

/// An armed alias answers only a read that found a `stat`: it never turns `Gone` into `Found`.
#[skuld::test]
fn alias_token_aliases_only_a_found_stat() {
    use super::fault::alias_token;
    use super::start_token_from;
    use crate::identity::StartToken;

    const PID: u32 = 4242;
    let aliased = StartToken::from_raw(7);
    let _armed = alias_token(PID, aliased);

    assert!(matches!(start_token_from(PID, Resolved::Gone), Resolved::Gone));
    assert!(matches!(start_token_from(PID, Resolved::Unknown), Resolved::Unknown));
    match start_token_from(PID, Resolved::Found(STAT_STARTED_AT_424242.to_vec())) {
        Resolved::Found(t) => assert_eq!(t, aliased, "a found stat answers the alias"),
        other => panic!("a found stat must resolve, got {other:?}"),
    }
    // Another pid is untouched.
    match start_token_from(PID + 1, Resolved::Found(STAT_STARTED_AT_424242.to_vec())) {
        Resolved::Found(t) => assert_eq!(t, StartToken::from_raw(424242)),
        other => panic!("got {other:?}"),
    }
}

/// Dropping the guard ends the alias, and only its own pid's. Mutant: `AliasGuard::drop` removes
/// nothing, or every pid's alias.
#[skuld::test]
fn dropping_the_alias_guard_ends_that_alias_only() {
    use super::fault::alias_token;
    use super::start_token_from;
    use crate::identity::StartToken;

    let read = |pid| match start_token_from(pid, Resolved::Found(STAT_STARTED_AT_424242.to_vec())) {
        Resolved::Found(t) => t,
        other => panic!("a found stat must resolve, got {other:?}"),
    };
    let first = alias_token(4343, StartToken::from_raw(1));
    let _second = alias_token(4344, StartToken::from_raw(2));
    assert_eq!(read(4343), StartToken::from_raw(1));
    drop(first);
    assert_eq!(
        read(4343),
        StartToken::from_raw(424242),
        "the dropped guard's alias is gone"
    );
    assert_eq!(read(4344), StartToken::from_raw(2), "another pid's alias stays armed");
}
