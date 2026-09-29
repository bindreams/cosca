use std::io;

use super::fault::{force_proc_view_once, ForcedView};
use super::{classify_status, parse_fdinfo_pid, proc_view, ProcView, Verdict};

fn ns_pid(exists: io::Result<bool>) -> impl FnOnce() -> io::Result<bool> {
    move || exists
}

fn unreachable_ns_pid() -> io::Result<bool> {
    panic!("self/ns/pid must be consulted only when NSpid is absent")
}

/// This test binary runs in the SAME pid namespace `/proc` is mounted from, so its own view
/// must read `Same`.
#[test]
fn proc_view_is_same_for_this_ordinary_process() {
    assert!(matches!(proc_view(), ProcView::Same(_)), "got {:?}", proc_view());
}

#[test]
fn one_nspid_entry_is_same() {
    let verdict = classify_status("Name:\tcosca\nNSpid:\t1234\nState:\tR\n", unreachable_ns_pid);
    assert!(matches!(verdict, Verdict::Same), "got {verdict:?}");
}

#[test]
fn several_nspid_entries_are_diverged() {
    let verdict = classify_status("NSpid:\t99\t5\t1\n", unreachable_ns_pid);
    assert!(matches!(verdict, Verdict::Diverged), "got {verdict:?}");
}

#[test]
fn an_empty_nspid_line_is_unassessable() {
    let verdict = classify_status("NSpid:\t\n", unreachable_ns_pid);
    assert!(matches!(verdict, Verdict::Unassessable(_)), "got {verdict:?}");
}

/// A kernel without `CONFIG_PID_NS` has no `NSpid` and no `self/ns/pid`: no namespace to
/// diverge into, so `Same`. Mutant: "an absent NSpid is always Unassessable" (the regression
/// that made every live foreign wait fail on such kernels).
#[test]
fn no_nspid_and_no_ns_pid_is_same() {
    let verdict = classify_status("Name:\tcosca\nState:\tR\n", ns_pid(Ok(false)));
    assert!(matches!(verdict, Verdict::Same), "got {verdict:?}");
}

/// gVisor: no `NSpid` but pid namespaces exist, so the status file cannot rule out an outer
/// namespace's `/proc`. Mutant: "an absent NSpid is always Same".
#[test]
fn no_nspid_but_ns_pid_exists_is_unassessable_and_says_why() {
    let Verdict::Unassessable(why) = classify_status("Name:\tcosca\n", ns_pid(Ok(true))) else {
        panic!("expected Unassessable");
    };
    assert!(why.reason.contains("NSpid"), "{why}");
}

#[test]
fn no_nspid_and_an_unreadable_ns_pid_is_unassessable_with_the_cause() {
    let Verdict::Unassessable(why) = classify_status(
        "Name:\tcosca\n",
        ns_pid(Err(io::Error::from_raw_os_error(libc::EACCES))),
    ) else {
        panic!("expected Unassessable");
    };
    assert!(why.source.is_some(), "the OS error must be carried: {why}");
    assert!(why.to_string().contains("could not be checked"), "{why}");
}

#[test]
fn fdinfo_pid_is_parsed() {
    assert_eq!(
        parse_fdinfo_pid("pos:\t0\nflags:\t02000000\nPid:\t4321\nNSpid:\t4321\n"),
        Some(4321)
    );
    assert_eq!(parse_fdinfo_pid("Pid:\t0\n"), Some(0));
    assert_eq!(parse_fdinfo_pid("pos:\t0\n"), None);
    assert_eq!(parse_fdinfo_pid("Pid:\t-1\n"), None);
    assert_eq!(parse_fdinfo_pid("Pid:\tx\n"), None);
}

/// A forced `Same` still opens the real `/proc`, so the dirfd it carries is usable.
#[test]
fn a_forced_same_view_carries_the_real_proc_dirfd() {
    let forced = force_proc_view_once(ForcedView::Same);
    let ProcView::Same(dir) = proc_view() else {
        panic!("a forced Same must be Same");
    };
    drop(forced);
    let status = super::read_at(std::os::fd::AsFd::as_fd(&dir), "self/status").expect("read through the dirfd");
    assert!(status.contains("Name:"), "{status}");
}

/// The forced seam overrides the real read exactly once, then falls back to it.
#[test]
fn a_forced_view_is_consumed_once() {
    let forced = force_proc_view_once(ForcedView::Diverged);
    assert!(matches!(proc_view(), ProcView::Diverged));
    assert!(
        matches!(proc_view(), ProcView::Same(_)),
        "a second call must reach the real read again"
    );
    drop(forced);
}

/// The guard disarms on drop even if the forced view was never consumed.
#[test]
fn a_forced_view_disarms_on_drop_even_if_unconsumed() {
    drop(force_proc_view_once(ForcedView::Unassessable));
    assert!(
        matches!(proc_view(), ProcView::Same(_)),
        "the forced view must not survive an unconsumed drop"
    );
}
