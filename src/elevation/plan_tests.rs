use super::{BackendSet, FrontState, Host, Os, Transition};
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
        pkexec_version: crate::elevation::pkexec::PkexecVersion::NotProbed,
        pkexec_pin: None,
    }
}

fn all_backends() -> BackendSet {
    BackendSet {
        sudo: FrontState::Found(PathBuf::from("/usr/bin/sudo")),
        doas: FrontState::Found(PathBuf::from("/usr/bin/doas")),
        pkexec: FrontState::Found(PathBuf::from("/usr/bin/pkexec")),
        osascript: FrontState::Absent,
    }
}

/// A front whose search stopped on an entry that could not be examined, `ELOOP`.
fn unexamined() -> FrontState {
    FrontState::Unexamined(std::sync::Arc::new(Error::Io(std::io::Error::from_raw_os_error(40))))
}

fn unix_host(available: BackendSet, elevated: bool, has_tty: bool) -> Host {
    Host {
        elevated,
        has_tty,
        available,
        os: Os::Linux,
        arg_max: None,
        pkexec_version: crate::elevation::pkexec::PkexecVersion::NotProbed,
        pkexec_pin: None,
    }
}

#[skuld::test]
fn unprivileged_target_runs_as_is() {
    let h = unix_host(all_backends(), false, true);
    assert!(matches!(
        h.plan(Privilege::Unprivileged, Backend::Auto, Auth::Interactive),
        Transition::RunAsIs
    ));
}

#[skuld::test]
fn already_elevated_runs_as_is() {
    let h = unix_host(all_backends(), true, true);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::RunAsIs
    ));
}

#[skuld::test]
fn auto_prefers_sudo_then_doas() {
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
            sudo: FrontState::Absent,
            doas: FrontState::Found(PathBuf::from("/usr/bin/doas")),
            pkexec: FrontState::Absent,
            osascript: FrontState::Absent,
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

#[skuld::test]
fn auto_never_selects_pkexec() {
    // Only pkexec available: Auto must reject (BackendUnavailable), not pick it.
    let h = unix_host(
        BackendSet {
            sudo: FrontState::Absent,
            doas: FrontState::Absent,
            pkexec: FrontState::Found(PathBuf::from("/usr/bin/pkexec")),
            osascript: FrontState::Absent,
        },
        false,
        true,
    );
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::Reject { .. }
    ));
}

#[skuld::test]
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

#[skuld::test]
fn windows_unprivileged_elevates_via_uac() {
    let h = Host {
        elevated: false,
        has_tty: false,
        available: BackendSet::default(),
        os: Os::Windows,
        arg_max: None,
        pkexec_version: crate::elevation::pkexec::PkexecVersion::NotProbed,
        pkexec_pin: None,
    };
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Interactive),
        Transition::ElevateWindows { .. }
    ));
}

#[skuld::test]
fn structural_posix_matrix_is_privilege_independent() {
    let cases: &[(Backend, Auth)] = &[
        (Backend::Doas, Auth::Askpass(PathBuf::from("/x"))),
        (Backend::Doas, Auth::Stdin(crate::elevation::Secret::new("p"))),
        (Backend::Pkexec, Auth::Interactive),
        (Backend::Pkexec, Auth::NonInteractive),
        (Backend::Pkexec, Auth::Askpass(PathBuf::from("/x"))),
        (Backend::Sudo, Auth::Gui),
        (Backend::Doas, Auth::Gui),
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

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
fn auto_resolving_to_doas_rejects_stdin() {
    // Privilege-independent: Auto resolving to a non-sudo backend must reject
    // Auth::Stdin identically whether or not we're already elevated (the
    // config verdict must not flip on ambient privilege).
    for elevated in [false, true] {
        let h = unix_host(
            BackendSet {
                sudo: FrontState::Absent,
                doas: FrontState::Found(PathBuf::from("/usr/bin/doas")),
                pkexec: FrontState::Absent,
                osascript: FrontState::Absent,
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

#[skuld::test]
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

/// cosca launches pkexec through Linux's `/proc`, so a non-Linux Unix refuses it up front, naming
/// that, whatever pkexec's version.
#[skuld::test]
fn pkexec_off_linux_is_refused_naming_linux() {
    for elevated in [false, true] {
        let h = Host {
            os: Os::Unix,
            ..unix_host(all_backends(), elevated, true)
        };
        match reject_error(h.plan(Privilege::Elevated, Backend::Pkexec, Auth::Gui)) {
            Error::Unsupported { detail, .. } => {
                assert!(detail.contains("Linux"), "{detail}");
                assert!(!detail.contains("121"), "{detail}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}

/// `Backend::Auto` goes to `sudo` first, then `doas`, and takes the first whose search did not end
/// in a miss. If that front could not be looked up, whether it is there is unknown: the plan reports
/// it, with the cause, and takes no later one, found or not. Under `Auth::Stdin` and `Askpass`,
/// which only `sudo` serves, that verdict is the same for a root caller as for one who is not, as
/// the structural matrix is run first. (Under `Interactive` a root caller runs as is, before the
/// front is looked at, as it does for a clean miss.) A `Backend::Doas` named is `Unsupported` under
/// those two auths whatever its search found, and under `Interactive` fails as `Auto` does.
///
/// Mutants: `Auto` falls through to the later front when the first's search failed, or skips an
/// unexamined `doas` for "no sudo/doas"; the structural matrix lets an unexamined `sudo` or `doas`
/// through, so root is `RunAsIs`, or checks only the `sudo`.
#[skuld::test]
fn auto_reports_a_front_that_could_not_be_looked_up_instead_of_taking_the_next() {
    let found = || all_backends().doas;
    for (sudo, doas, backend) in [
        (unexamined(), found(), Backend::Auto),
        (unexamined(), FrontState::Absent, Backend::Auto),
        (FrontState::Absent, unexamined(), Backend::Auto),
        (FrontState::Absent, unexamined(), Backend::Doas),
    ] {
        for elevated in [true, false] {
            let h = unix_host(
                BackendSet {
                    sudo: sudo.clone(),
                    doas: doas.clone(),
                    ..all_backends()
                },
                elevated,
                true,
            );
            let mut auths = vec![
                Auth::Stdin(crate::elevation::Secret::new("p")),
                Auth::Askpass("/usr/bin/ssh-askpass".into()),
            ];
            if !elevated {
                auths.push(Auth::Interactive);
            }
            for auth in auths {
                let case = format!("{backend:?}, elevated {elevated}, {auth:?}");
                let doas_needs_sudo = backend == Backend::Doas && !matches!(auth, Auth::Interactive);
                let error = reject_error(h.plan(Privilege::Elevated, backend, auth));
                if doas_needs_sudo {
                    assert!(matches!(error, Error::Unsupported { .. }), "{case}: {error:?}");
                } else {
                    assert_eq!(crate::error::first_os_code(&error), Some(40), "{case}: {error:?}");
                    assert!(
                        matches!(
                            error,
                            Error::Elevation {
                                kind: ElevationErrorKind::BackendUnavailable,
                                ..
                            }
                        ),
                        "{case}: {error:?}"
                    );
                }
            }
        }
    }
}

/// A front's lookup error is read only when the plan needs that front: a `sudo` found makes the
/// `doas` error nothing, and so does a request that names another backend.
#[skuld::test]
fn a_lookup_error_for_a_front_the_plan_does_not_use_changes_nothing() {
    let h = unix_host(
        BackendSet {
            doas: unexamined(),
            pkexec: unexamined(),
            ..all_backends()
        },
        false,
        true,
    );
    for backend in [Backend::Auto, Backend::Sudo] {
        assert!(
            matches!(
                h.plan(Privilege::Elevated, backend, Auth::Interactive),
                Transition::ElevatePosix {
                    backend: Backend::Sudo,
                    ..
                }
            ),
            "{backend:?}"
        );
    }
}

/// A macOS host: sudo exists, pkexec/doas do not, osascript does.
fn macos_host(elevated: bool, has_tty: bool) -> Host {
    Host {
        elevated,
        has_tty,
        available: BackendSet {
            sudo: FrontState::Found(PathBuf::from("/usr/bin/sudo")),
            doas: FrontState::Absent,
            pkexec: FrontState::Absent,
            osascript: FrontState::Found(PathBuf::from("/usr/bin/osascript")),
        },
        os: Os::MacOs,
        arg_max: Some(1_048_576),
        pkexec_version: crate::elevation::pkexec::PkexecVersion::NotProbed,
        pkexec_pin: None,
    }
}

fn unsupported_platform(t: Transition) -> &'static str {
    match reject_error(t) {
        Error::Unsupported { platform, .. } => platform,
        other => panic!("expected Unsupported, got {other}"),
    }
}

#[skuld::test]
fn macos_pkexec_is_unsupported_not_backend_unavailable() {
    // pkexec can never exist on macOS, so a "backend not on PATH" verdict would
    // wrongly invite installing it. Even with a fabricated pkexec path present,
    // the verdict must be a platform Unsupported.
    let mut h = macos_host(false, true);
    h.available.pkexec = FrontState::Found(PathBuf::from("/usr/bin/pkexec"));
    assert_eq!(
        unsupported_platform(h.plan(Privilege::Elevated, Backend::Pkexec, Auth::Gui)),
        "macos"
    );
}

#[skuld::test]
fn macos_keeps_the_backends_that_really_do_run_there() {
    // sudo and doas are portable and DO exist on macOS, so they must not be swept
    // into the impossible-backend guard alongside pkexec.
    let mut h = macos_host(false, true);
    h.available.doas = FrontState::Found(PathBuf::from("/usr/local/bin/doas"));
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

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
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

#[skuld::test]
fn macos_gui_with_a_non_auto_backend_is_still_unsupported() {
    // Auth::Gui names Authorization Services on macOS; no CLI wrapper is involved,
    // so a forced sudo/doas is a config error, not something osascript runs.
    for backend in [Backend::Sudo, Backend::Doas] {
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

/// A missing `/usr/bin/osascript` and one that cannot be examined are both `BackendUnavailable`, not
/// a platform verdict: the first says it is missing, the second has the examination's error as its
/// cause.
///
/// Mutant: an osascript that cannot be examined is reported as missing.
#[skuld::test]
fn macos_gui_without_osascript_is_a_backend_problem_not_a_platform_one() {
    let mut h = macos_host(false, true);
    h.available.osascript = FrontState::Absent;
    match reject_error(h.plan(Privilege::Elevated, Backend::Auto, Auth::Gui)) {
        Error::Elevation {
            kind: ElevationErrorKind::BackendUnavailable,
            detail,
            source: None,
        } => assert!(detail.contains("missing") && !detail.contains("executable"), "{detail}"),
        other => panic!("expected BackendUnavailable, got {other:?}"),
    }
    h.available.osascript = unexamined();
    let error = reject_error(h.plan(Privilege::Elevated, Backend::Auto, Auth::Gui));
    assert_eq!(crate::error::first_os_code(&error), Some(40), "{error:?}");
    assert!(
        matches!(
            error,
            Error::Elevation {
                kind: ElevationErrorKind::BackendUnavailable,
                ..
            }
        ),
        "{error:?}"
    );
}

#[skuld::test]
fn macos_gui_already_elevated_runs_as_is() {
    let h = macos_host(true, false);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Gui),
        Transition::RunAsIs
    ));
}
