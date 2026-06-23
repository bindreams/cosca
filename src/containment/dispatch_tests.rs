// Unit tests for dispatch root-detection and mechanism-selection logic.
// These test pure functions directly — no process-env mutation required.

use super::is_nested;

/// Without the marker the process is the root (not nested).
#[test]
fn is_nested_without_marker_is_false() {
    assert!(!is_nested(false));
}

/// With the marker the process is already inside a contained tree (nested).
#[test]
fn is_nested_with_marker_is_true() {
    assert!(is_nested(true));
}

// unix_setup_for mutual-exclusivity tests (S3) =====

/// `ContainMode::Session` must select `UnixSetup::Session` (setsid) — never
/// `ProcessGroup`. This is the critical S3 invariant: calling both setsid AND
/// setpgid/process_group(0) on the same Command would cause EPERM.
#[cfg(unix)]
#[test]
fn unix_setup_for_session_selects_setsid() {
    use super::{unix_setup_for, UnixSetup};
    use crate::containment::ContainMode;
    assert_eq!(unix_setup_for(Some(ContainMode::Session)), UnixSetup::Session);
}

/// `ContainMode::Strongest` must select `UnixSetup::ProcessGroup` — never Session.
#[cfg(unix)]
#[test]
fn unix_setup_for_strongest_selects_process_group() {
    use super::{unix_setup_for, UnixSetup};
    use crate::containment::ContainMode;
    assert_eq!(unix_setup_for(Some(ContainMode::Strongest)), UnixSetup::ProcessGroup);
}

/// `ContainMode::TreeWalk` must select `UnixSetup::None` — NO pre-spawn process
/// group. TreeWalk exists to catch children that escape a process group via
/// `setsid`/`setpgid`, so the root must not be put in a group; teardown is by
/// identity at kill time.
#[cfg(unix)]
#[test]
fn unix_setup_for_treewalk_selects_none() {
    use super::{unix_setup_for, UnixSetup};
    use crate::containment::ContainMode;
    assert_eq!(unix_setup_for(Some(ContainMode::TreeWalk)), UnixSetup::None);
}

/// Uncontained (`None` mode) must select `UnixSetup::ProcessGroup` (the
/// prepare path gates on `mode.is_some()` before calling this, but the
/// default fallback is well-defined).
#[cfg(unix)]
#[test]
fn unix_setup_for_none_mode_selects_process_group() {
    use super::{unix_setup_for, UnixSetup};
    assert_eq!(unix_setup_for(None), UnixSetup::ProcessGroup);
}
