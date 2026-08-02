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
        arg_max: None,
    }
}

fn all_backends() -> BackendSet {
    BackendSet {
        run0: Some(PathBuf::from("/usr/bin/run0")),
        sudo: Some(PathBuf::from("/usr/bin/sudo")),
        doas: Some(PathBuf::from("/usr/bin/doas")),
        pkexec: Some(PathBuf::from("/usr/bin/pkexec")),
        osascript: None,
    }
}

fn unix_host(available: BackendSet, elevated: bool, has_tty: bool) -> Host {
    Host {
        elevated,
        has_tty,
        available,
        os: Os::Unix,
        arg_max: None,
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
            osascript: None,
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
            osascript: None,
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
        arg_max: None,
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
                osascript: None,
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

/// A macOS host: sudo exists, pkexec/run0/doas do not, osascript does.
fn macos_host(elevated: bool, has_tty: bool) -> Host {
    Host {
        elevated,
        has_tty,
        available: BackendSet {
            run0: None,
            sudo: Some(PathBuf::from("/usr/bin/sudo")),
            doas: None,
            pkexec: None,
            osascript: Some(PathBuf::from("/usr/bin/osascript")),
        },
        os: Os::MacOs,
        arg_max: Some(1_048_576),
    }
}

fn unsupported_platform(t: Transition) -> &'static str {
    match reject_error(t) {
        Error::Unsupported { platform, .. } => platform,
        other => panic!("expected Unsupported, got {other}"),
    }
}

#[test]
fn macos_pkexec_is_unsupported_not_backend_unavailable() {
    // pkexec can never exist on macOS, so a "backend not on PATH" verdict would
    // wrongly invite installing it. Even with a fabricated pkexec path present,
    // the verdict must be a platform Unsupported.
    let mut h = macos_host(false, true);
    h.available.pkexec = Some(PathBuf::from("/usr/bin/pkexec"));
    assert_eq!(
        unsupported_platform(h.plan(Privilege::Elevated, Backend::Pkexec, Auth::Gui)),
        "macos"
    );
}

#[test]
fn macos_run0_is_unsupported_not_backend_unavailable() {
    // Same reasoning as pkexec: run0 ships with systemd, so "not on PATH" would
    // invite installing something that does not exist for this platform.
    let mut h = macos_host(false, true);
    h.available.run0 = Some(PathBuf::from("/usr/bin/run0"));
    for auth in [Auth::Interactive, Auth::NonInteractive] {
        match reject_error(h.plan(Privilege::Elevated, Backend::Run0, auth)) {
            Error::Unsupported { platform, detail, .. } => {
                assert_eq!(platform, "macos");
                assert!(detail.contains("systemd"), "{detail}");
            }
            other => panic!("expected Unsupported, got {other}"),
        }
    }
}

#[test]
fn macos_keeps_the_backends_that_really_do_run_there() {
    // sudo and doas are portable and DO exist on macOS, so they must not be swept
    // into the impossible-backend guard alongside pkexec/run0.
    let mut h = macos_host(false, true);
    h.available.doas = Some(PathBuf::from("/usr/local/bin/doas"));
    for backend in [Backend::Sudo, Backend::Doas] {
        assert!(
            matches!(
                h.plan(Privilege::Elevated, backend, Auth::Interactive),
                Transition::ElevatePosix { .. }
            ),
            "{backend:?} must still be usable on macOS"
        );
    }
}

#[test]
fn macos_sudo_still_works_like_other_unix() {
    let h = macos_host(false, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevatePosix {
            backend: Backend::Sudo,
            ..
        }
    ));
}

#[test]
fn non_macos_unix_gui_still_requires_pkexec() {
    let h = unix_host(all_backends(), false, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Pkexec, Auth::Gui),
        Transition::ElevatePosix {
            backend: Backend::Pkexec,
            ..
        }
    ));
    assert!(is_unsupported(h.plan(Privilege::Elevated, Backend::Sudo, Auth::Gui)));
}

#[test]
fn macos_gui_resolves_to_the_osascript_transition() {
    let h = macos_host(false, /* has_tty */ false);
    match h.plan(Privilege::Elevated, Backend::Auto, Auth::Gui) {
        Transition::ElevateMacosGui { osascript, arg_max } => {
            assert_eq!(osascript, PathBuf::from("/usr/bin/osascript"));
            assert_eq!(arg_max, Some(1_048_576));
        }
        other => panic!("expected ElevateMacosGui, got {other:?}"),
    }
}

#[test]
fn macos_gui_needs_no_controlling_terminal() {
    // A windowed app has no controlling terminal, so Auth::Gui must not trip the
    // NoTty gate the way Auth::Interactive does.
    let h = macos_host(false, false);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Gui),
        Transition::ElevateMacosGui { .. }
    ));
    assert!(matches!(
        reject_error(h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive)),
        Error::Elevation {
            kind: ElevationErrorKind::NoTty,
            ..
        }
    ));
}

#[test]
fn macos_gui_with_a_non_auto_backend_is_still_unsupported() {
    // Auth::Gui names Authorization Services on macOS; no CLI wrapper is involved,
    // so a forced sudo/doas/run0 is a config error, not something osascript runs.
    for backend in [Backend::Sudo, Backend::Doas, Backend::Run0] {
        let h = macos_host(false, true);
        // `plan_tests.rs` is NOT platform-gated, so asserting the message HERE is
        // what keeps this arm's wording checked on the Windows CI leg too.
        match reject_error(h.plan(Privilege::Elevated, backend, Auth::Gui)) {
            Error::Unsupported { platform, detail, .. } => {
                assert_eq!(platform, "macos", "{backend:?}");
                assert!(detail.contains("Backend::Auto"), "{backend:?}: {detail}");
            }
            other => panic!("expected Unsupported for {backend:?}, got {other}"),
        }
    }
}

#[test]
fn macos_gui_without_osascript_is_a_backend_problem_not_a_platform_one() {
    // Here BackendUnavailable is honest: /usr/bin/osascript really can be absent
    // or non-executable on a stripped system.
    let mut h = macos_host(false, true);
    h.available.osascript = None;
    assert!(matches!(
        reject_error(h.plan(Privilege::Elevated, Backend::Auto, Auth::Gui)),
        Error::Elevation {
            kind: ElevationErrorKind::BackendUnavailable,
            ..
        }
    ));
}

#[test]
fn macos_gui_already_elevated_runs_as_is() {
    let h = macos_host(true, false);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Gui),
        Transition::RunAsIs
    ));
}
