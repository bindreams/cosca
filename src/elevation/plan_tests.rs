use super::{BackendSet, Host, Os, Transition};
use crate::elevation::{Auth, Backend, Privilege};
use std::path::PathBuf;

fn all_backends() -> BackendSet {
    BackendSet {
        run0: Some(PathBuf::from("/usr/bin/run0")),
        sudo: Some(PathBuf::from("/usr/bin/sudo")),
        doas: Some(PathBuf::from("/usr/bin/doas")),
        pkexec: Some(PathBuf::from("/usr/bin/pkexec")),
    }
}

fn unix_host(available: BackendSet, elevated: bool, has_tty: bool) -> Host {
    Host {
        elevated,
        has_tty,
        available,
        os: Os::Unix,
    }
}

#[test]
fn unprivileged_target_runs_as_is() {
    let h = unix_host(all_backends(), false, true);
    assert!(matches!(
        h.plan(Privilege::Unprivileged, Backend::Auto, Auth::Interactive),
        Transition::RunAsIs
    ));
}

#[test]
fn already_elevated_runs_as_is() {
    let h = unix_host(all_backends(), true, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::RunAsIs
    ));
}

#[test]
fn auto_prefers_sudo_then_doas() {
    // run0 present but Auto ignores it -> sudo.
    let h = unix_host(all_backends(), false, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevatePosix {
            backend: Backend::Sudo,
            ..
        }
    ));
    // only doas -> doas
    let h = unix_host(
        BackendSet {
            run0: None,
            sudo: None,
            doas: Some(PathBuf::from("/usr/bin/doas")),
            pkexec: None,
        },
        false,
        true,
    );
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevatePosix {
            backend: Backend::Doas,
            ..
        }
    ));
}

#[test]
fn auto_never_selects_run0_or_pkexec() {
    // Only run0 + pkexec available: Auto must reject (BackendUnavailable), not pick either.
    let h = unix_host(
        BackendSet {
            run0: Some(PathBuf::from("/usr/bin/run0")),
            sudo: None,
            doas: None,
            pkexec: Some(PathBuf::from("/usr/bin/pkexec")),
        },
        false,
        true,
    );
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::Reject { .. }
    ));
}

#[test]
fn resolved_transition_carries_the_absolute_backend_path() {
    let h = unix_host(all_backends(), false, true);
    match h.plan(Privilege::Elevated, Backend::Doas, Auth::Interactive) {
        Transition::ElevatePosix {
            backend: Backend::Doas,
            path,
            ..
        } => {
            assert_eq!(path, PathBuf::from("/usr/bin/doas"));
        }
        other => panic!("expected doas ElevatePosix, got {other:?}"),
    }
}

#[test]
#[ignore = "windows arm lands in Task 5"]
fn windows_unprivileged_elevates_via_uac() {
    let h = Host {
        elevated: false,
        has_tty: false,
        available: BackendSet::default(),
        os: Os::Windows,
    };
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevateWindows { .. }
    ));
}
