//! The identity reads (`ProcessId::of`, `exists`, `is_alive`) go through the checked `/proc`
//! view: on a `/proc` that is not this process's own namespace's, they answer `Unknown`, never
//! a `Found`, `Gone` or `Dead` read off another process. `ProcessId::current()` does not use
//! the view at all.

use super::proc_view::fault::{force_openat2_errno, force_proc_view_once, force_self_stat_once, ForcedView};
use crate::error::Error;
use crate::identity::{unknown_identity_error, Existence, Liveness, ProcessId, Resolved};

/// Above `PID_MAX_LIMIT` (2^22) yet a valid positive `kill` target, so `kill(pid, 0)` answers `ESRCH`.
pub(super) const NO_PROCESS_CAN_HOLD: u32 = i32::MAX as u32;

/// The views that leave a live pid unanswerable.
const UNAVAILABLE_VIEWS: [ForcedView; 2] = [ForcedView::Diverged, ForcedView::Unassessable];

/// `stat` of a process whose `starttime` (field 22) is 424242.
const STAT_STARTED_AT_424242: &[u8] = b"4242 (x) S 1 4242 4242 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 424242 0 0";

/// Mutant: "read `stat` by path whatever the view" - the unavailable view is ignored and the
/// live process resolves.
#[skuld::test]
fn of_a_live_pid_is_unknown_when_the_view_is_unavailable() {
    for view in UNAVAILABLE_VIEWS {
        let _forced = force_proc_view_once(view);
        let got = ProcessId::of(std::process::id());
        assert!(matches!(got, Resolved::Unknown), "{view:?}: got {got:?}");
    }
}

/// `kill(pid, 0)` answering `ESRCH` resolves the pid in this process's own namespace, so it is
/// `Gone` whatever `/proc` shows. Mutant: "an unavailable view is always Unknown".
#[skuld::test]
fn of_a_pid_no_process_can_hold_is_gone_whatever_the_view() {
    for view in UNAVAILABLE_VIEWS {
        let _forced = force_proc_view_once(view);
        let got = ProcessId::of(NO_PROCESS_CAN_HOLD);
        assert!(matches!(got, Resolved::Gone), "{view:?}: got {got:?}");
    }
}

/// Mutant: "`exists`/`is_alive` map an unavailable view to `Gone`/`Dead`".
#[skuld::test]
fn exists_and_is_alive_are_unknown_for_a_live_process_when_the_view_is_unavailable() {
    let id = ProcessId::current();
    for view in UNAVAILABLE_VIEWS {
        {
            let _forced = force_proc_view_once(view);
            assert_eq!(id.exists(), Existence::Unknown, "{view:?}");
        }
        let _forced = force_proc_view_once(view);
        assert_eq!(id.is_alive(), Liveness::Unknown, "{view:?}");
    }
}

/// Mutant: "`exists`/`is_alive` ask `/proc` only, so an unavailable view hides an `ESRCH`".
#[skuld::test]
fn exists_and_is_alive_are_gone_and_dead_for_a_pid_no_process_can_hold_whatever_the_view() {
    let id = ProcessId::from_parts_for_test(NO_PROCESS_CAN_HOLD, 1);
    for view in UNAVAILABLE_VIEWS {
        {
            let _forced = force_proc_view_once(view);
            assert_eq!(id.exists(), Existence::Gone, "{view:?}");
        }
        let _forced = force_proc_view_once(view);
        assert_eq!(id.is_alive(), Liveness::Dead, "{view:?}");
    }
}

/// The ordinary view still resolves this process.
#[skuld::test]
fn a_live_process_is_present_and_alive_under_the_ordinary_view() {
    let id = ProcessId::current();
    assert_eq!(id.exists(), Existence::Present);
    assert_eq!(id.is_alive(), Liveness::Alive);
}

/// `current()` takes its token from the read of `self/stat`, not through the view: the token
/// the seam feeds that read is the one it carries, under every view.
/// Mutants: "`current_token` reads by pid through the view" (`Unknown` under an unavailable
/// view, so `current()` panics); "`current_token` reads `/proc` some other way" (ignores the seam).
#[skuld::test]
fn current_carries_the_token_read_from_self_under_every_view() {
    for view in UNAVAILABLE_VIEWS.map(Some).into_iter().chain([None]) {
        let _self_stat = force_self_stat_once(STAT_STARTED_AT_424242);
        let _view = view.map(force_proc_view_once);
        let current = ProcessId::current();
        assert_eq!(current.start_token_raw(), 424242, "{view:?}");
        assert_eq!(current.pid(), std::process::id(), "{view:?}");
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
    let _forced = force_openat2_errno(rustix::io::Errno::NOSYS);
    let err = unknown_identity_error("the spawned child").expect("no openat2 is an error");
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
    let _forced = force_proc_view_once(ForcedView::Diverged);
    let err = unknown_identity_error("the spawned child").expect("a diverged view is an error");
    assert!(
        matches!(&err, Error::Unassessable { detail, .. }
            if detail == "the spawned child identity could not be read: this process's /proc is an outer pid namespace's"),
        "{err:?}"
    );
}

/// With a fine view, an `Unknown` is the OS's (`hidepid`, a racing exit) and has no view to blame.
#[skuld::test]
fn no_error_is_blamed_on_a_fine_view() {
    assert!(unknown_identity_error("the spawned child").is_none());
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
