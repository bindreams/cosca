use super::{BackendSet, Host, Os, Transition};
use crate::elevation::{Auth, Backend, Privilege};
use crate::error::{ElevationErrorKind, Error};
use std::path::PathBuf;

fn reject_error(t: Transition) -> Error {
    match t {
        Transition::Reject { error } => error,
        other => panic!("expected Reject, got {other:?}"),
    }
}

fn is_unsupported(t: Transition) -> bool {
    matches!(
        t,
        Transition::Reject {
            error: Error::Unsupported { .. }
        }
    )
}

fn win_host(elevated: bool) -> Host {
    Host {
        elevated,
        has_tty: false,
        available: BackendSet::default(),
        os: Os::Windows,
    }
}

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

#[test]
fn structural_posix_matrix_is_privilege_independent() {
    let cases: &[(Backend, Auth)] = &[
        (Backend::Doas, Auth::Askpass(PathBuf::from("/x"))),
        (Backend::Run0, Auth::Askpass(PathBuf::from("/x"))),
        (Backend::Doas, Auth::Stdin(crate::elevation::Secret::new("p"))),
        (Backend::Run0, Auth::Stdin(crate::elevation::Secret::new("p"))),
        (Backend::Pkexec, Auth::Interactive),
        (Backend::Pkexec, Auth::NonInteractive),
        (Backend::Pkexec, Auth::Askpass(PathBuf::from("/x"))),
        (Backend::Sudo, Auth::Gui),
        (Backend::Doas, Auth::Gui),
        (Backend::Run0, Auth::Gui),
        (Backend::Auto, Auth::Gui),
    ];
    for (backend, auth) in cases {
        for elevated in [false, true] {
            let h = unix_host(all_backends(), elevated, true);
            assert!(
                is_unsupported(h.plan(Privilege::Elevated, *backend, auth.clone())),
                "expected Unsupported for {backend:?} + {auth:?} (elevated={elevated})",
            );
        }
    }
}

#[test]
fn structural_windows_matrix_is_privilege_independent() {
    for elevated in [false, true] {
        assert!(is_unsupported(win_host(elevated).plan(
            Privilege::Elevated,
            Backend::Sudo,
            Auth::Interactive
        )));
        assert!(is_unsupported(win_host(elevated).plan(
            Privilege::Elevated,
            Backend::Auto,
            Auth::NonInteractive
        )));
        assert!(is_unsupported(win_host(elevated).plan(
            Privilege::Elevated,
            Backend::Auto,
            Auth::Askpass(PathBuf::from("/x"))
        )));
        assert!(is_unsupported(win_host(elevated).plan(
            Privilege::Elevated,
            Backend::Auto,
            Auth::Stdin(crate::elevation::Secret::new("p"))
        )));
    }
}

#[test]
fn windows_accepts_only_interactive_and_gui() {
    assert!(matches!(
        win_host(false).plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevateWindows { .. }
    ));
    assert!(matches!(
        win_host(false).plan(Privilege::Elevated, Backend::Auto, Auth::Gui),
        Transition::ElevateWindows { .. }
    ));
}

#[test]
fn interactive_without_tty_is_no_tty() {
    let h = unix_host(all_backends(), false, /* has_tty */ false);
    let e = reject_error(h.plan(Privilege::Elevated, Backend::Sudo, Auth::Interactive));
    assert!(
        matches!(
            e,
            Error::Elevation {
                kind: ElevationErrorKind::NoTty,
                ..
            }
        ),
        "{e}"
    );
}

#[test]
fn noninteractive_without_tty_is_allowed() {
    let h = unix_host(all_backends(), false, false);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Sudo, Auth::NonInteractive),
        Transition::ElevatePosix {
            backend: Backend::Sudo,
            ..
        }
    ));
}

#[test]
fn auto_resolving_to_doas_rejects_stdin() {
    // Privilege-independent: Auto resolving to a non-sudo backend must reject
    // Auth::Stdin identically whether or not we're already elevated (the
    // config verdict must not flip on ambient privilege).
    for elevated in [false, true] {
        let h = unix_host(
            BackendSet {
                run0: None,
                sudo: None,
                doas: Some(PathBuf::from("/usr/bin/doas")),
                pkexec: None,
            },
            elevated,
            true,
        );
        assert!(
            is_unsupported(h.plan(
                Privilege::Elevated,
                Backend::Auto,
                Auth::Stdin(crate::elevation::Secret::new("p"))
            )),
            "expected Unsupported for Auto+Stdin on a doas-only host (elevated={elevated})",
        );
    }
}

#[test]
fn pkexec_with_gui_is_accepted() {
    let h = unix_host(all_backends(), false, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Pkexec, Auth::Gui),
        Transition::ElevatePosix {
            backend: Backend::Pkexec,
            ..
        }
    ));
}
