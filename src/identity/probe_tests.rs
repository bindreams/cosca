use super::{classify_unreadable, signal_target, SignalProbe};
use crate::identity::Resolved;

#[test]
fn only_no_such_process_means_gone() {
    assert_eq!(classify_unreadable(SignalProbe::NoSuchProcess), Resolved::Gone);
}

#[test]
fn a_signalable_pid_is_live_but_unreadable() {
    // hidepid: /proc/<pid> is invisible to us, yet the process answers a signal probe.
    assert_eq!(classify_unreadable(SignalProbe::Signalable), Resolved::Unknown);
}

#[test]
fn a_denied_probe_is_unknown_not_gone() {
    // EPERM: someone else's live process — must read as Unknown, not Gone.
    assert_eq!(classify_unreadable(SignalProbe::Denied), Resolved::Unknown);
}

#[test]
fn a_value_that_is_not_a_pid_is_gone() {
    assert_eq!(classify_unreadable(SignalProbe::NotAPid), Resolved::Gone);
}

#[test]
fn signal_target_rejects_every_non_single_process_value() {
    assert_eq!(signal_target(0), None);
    assert_eq!(signal_target(u32::MAX), None);
    assert_eq!(signal_target(i32::MAX as u32 + 1), None);
    assert_eq!(signal_target(1), Some(1));
    assert_eq!(signal_target(i32::MAX as u32), Some(i32::MAX));
}

#[test]
fn signal_target_is_the_guard_for_real_signals_not_just_the_probe() {
    // The `sig 0` probe merely misreports if this leaks; `treewalk::kill_by_identity` and
    // `wait::macos::{kill, terminate}` would SIGKILL the caller's own process group, so pin
    // the two values that make `kill(2)` group-directed rather than process-directed.
    assert_eq!(signal_target(0), None, "kill(0, sig) signals our own process group");
    assert_eq!(
        signal_target(u32::MAX),
        None,
        "kill(-1, sig) signals every process we may signal"
    );
}
