//! The identity reads (`ProcessId::of`, `exists`, `is_alive`) go through the checked `/proc`
//! view: on a `/proc` that is not this process's own namespace's, they answer `Unknown`, never
//! a `Found`, `Gone` or `Dead` read off another process.

use super::proc_view::fault::{force_proc_view_once, ForcedView};
use crate::identity::{Existence, Liveness, ProcessId, Resolved};

/// No process can hold this pid: above `PID_MAX_LIMIT`, and above `i32::MAX`'s kernel range.
const NO_PROCESS_CAN_HOLD: u32 = i32::MAX as u32;

/// Mutant: "read `stat` by path whatever the view" — the diverged view is ignored and the
/// live process resolves.
#[test]
fn of_a_live_pid_is_unknown_when_the_view_is_diverged() {
    let _forced = force_proc_view_once(ForcedView::Diverged);
    let got = ProcessId::of(std::process::id());
    assert!(matches!(got, Resolved::Unknown), "got {got:?}");
}

#[test]
fn of_a_live_pid_is_unknown_when_the_view_is_unassessable() {
    let _forced = force_proc_view_once(ForcedView::Unassessable);
    let got = ProcessId::of(std::process::id());
    assert!(matches!(got, Resolved::Unknown), "got {got:?}");
}

/// `kill(pid, 0)` answering `ESRCH` resolves the pid in this process's own namespace, so it is
/// `Gone` whatever `/proc` shows. Mutant: "an unavailable view is always Unknown".
#[test]
fn of_a_pid_no_process_can_hold_is_gone_whatever_the_view() {
    for view in [ForcedView::Diverged, ForcedView::Unassessable] {
        let _forced = force_proc_view_once(view);
        let got = ProcessId::of(NO_PROCESS_CAN_HOLD);
        assert!(matches!(got, Resolved::Gone), "{view:?}: got {got:?}");
    }
}

#[test]
fn exists_and_is_alive_are_unknown_for_a_live_process_when_the_view_is_diverged() {
    let id = ProcessId::current();
    {
        let _forced = force_proc_view_once(ForcedView::Diverged);
        assert_eq!(id.exists(), Existence::Unknown);
    }
    let _forced = force_proc_view_once(ForcedView::Diverged);
    assert_eq!(id.is_alive(), Liveness::Unknown);
}

/// The ordinary view still resolves this process.
#[test]
fn a_live_process_is_present_and_alive_under_the_ordinary_view() {
    let id = ProcessId::current();
    assert_eq!(id.exists(), Existence::Present);
    assert_eq!(id.is_alive(), Liveness::Alive);
}

/// `current()` never panics on an unavailable view: its token comes from `self`.
/// Mutant: "`current_token` reads by pid through the view like any other pid".
#[test]
fn current_is_the_real_token_when_the_view_is_diverged() {
    let ordinary = ProcessId::current();
    let _forced = force_proc_view_once(ForcedView::Diverged);
    let current = ProcessId::current();
    assert_eq!(current, ordinary);
}
