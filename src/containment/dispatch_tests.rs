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

// Attached actionability + nested delegation =====

#[test]
fn attached_is_actionable() {
    use super::Attached;
    // No teardown mechanism -> not actionable (the _tree guard rejects these).
    assert!(!Attached::None.is_actionable()); // uncontained / lone
    assert!(!Attached::Delegated.is_actionable());
    // Every real mechanism is actionable. Cheap variants are built inline; Cgroup/JobObject
    // need an OS handle, so a test-only constructor builds one (asserted on its own platform).
    assert!(Attached::TreeWalk(crate::identity::ProcessId::current()).is_actionable());
    #[cfg(unix)]
    assert!(Attached::ProcessGroup(0).is_actionable());
    #[cfg(target_os = "linux")]
    assert!(Attached::Cgroup(crate::containment::cgroup::CgroupLeaf::placeholder_for_test()).is_actionable());
    #[cfg(windows)]
    assert!(Attached::JobObject(crate::containment::windows::JobHandle::create_empty_for_test()).is_actionable());
}

/// Drives the real `attach()` nested arms (not a hand-built variant): a nested
/// (`!is_root`) contained spawn must yield BOTH halves of the delegated pair —
/// `Containment::Delegated` and `Attached::Delegated` — for a kernel mechanism
/// (Strongest) and TreeWalk, so `containment()` predicts the `_tree` error.
#[test]
fn nested_attach_is_delegated() {
    use super::{attach, Attached, Prepared};
    use crate::containment::{ContainMode, Containment};

    fn spawn_trivial() -> std::process::Child {
        // attach()'s nested arms don't touch the child, so an exited child is fine.
        #[cfg(unix)]
        return std::process::Command::new("true").spawn().expect("spawn true");
        #[cfg(windows)]
        return std::process::Command::new("cmd")
            .args(["/C", "exit"])
            .spawn()
            .expect("spawn cmd");
    }

    for mode in [ContainMode::Strongest, ContainMode::TreeWalk] {
        let mut child = spawn_trivial();
        let prepared = Prepared {
            mode: Some(mode),
            is_root: false, // nested member
            #[cfg(target_os = "linux")]
            cgroup_leaf: None,
        };
        let (containment, attached) = attach(&child, prepared).expect("attach nested");
        // Reap before asserting: `attached` is owned and independent of `child`, so a
        // failing assertion must not leak the helper (the nested arms don't touch it).
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            containment,
            Containment::Delegated,
            "nested member ({mode:?}) must report Containment::Delegated, got {containment:?}"
        );
        assert!(
            matches!(attached, Attached::Delegated),
            "nested member ({mode:?}) must be Attached::Delegated, got {attached:?}"
        );
    }
}
