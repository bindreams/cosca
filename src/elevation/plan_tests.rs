use super::{BackendSet, FrontState, Host, Os, Transition};
use crate::elevation::elevation_tests::unavailable;
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

/// A front whose search stopped on an entry that could not be examined, `ELOOP` (40).
fn unexamined() -> FrontState {
    unexamined_by(40)
}

/// An unexamined front whose cause carries OS error `code`, to tell two such fronts' errors apart.
fn unexamined_by(code: i32) -> FrontState {
    FrontState::Unexamined(std::sync::Arc::new(Error::Io(std::io::Error::from_raw_os_error(code))))
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

/// A caller that is already elevated runs a request its OS, backend and auth allow as is, whether
/// `sudo` is absent or not examinable, whatever the auth and the terminal. One that is not elevated is
/// `BackendUnavailable`, caused by the lookup's error if the search could not be completed. A named
/// `Sudo` ignores the `doas` state.
///
/// Mutants: a root caller is refused for an unexamined `sudo`; `Auth` or the terminal is read before a
/// root caller runs as is; the lookup's error is not the cause; the `Auto` table is applied to a named
/// `Sudo`.
#[skuld::test]
fn an_elevated_caller_runs_as_is_where_the_front_is_unusable_and_one_that_is_not_is_refused() {
    for os in [Os::Linux, Os::Unix, Os::MacOs] {
        for (sudo, doas, backend) in [
            (FrontState::Absent, FrontState::Absent, Backend::Auto),
            (FrontState::Absent, FrontState::Absent, Backend::Sudo),
            (unexamined(), FrontState::Absent, Backend::Auto),
            (unexamined(), FrontState::Absent, Backend::Sudo),
            (FrontState::Absent, all_backends().doas, Backend::Sudo),
            (FrontState::Absent, unexamined_by(41), Backend::Sudo),
            (unexamined(), all_backends().doas, Backend::Sudo),
            (unexamined(), unexamined_by(41), Backend::Sudo),
        ] {
            let cause = matches!(sudo, FrontState::Unexamined(_)).then_some(40);
            for auth in [
                Auth::Stdin(crate::elevation::Secret::new("p")),
                Auth::Askpass("/usr/bin/ssh-askpass".into()),
                Auth::Interactive,
                Auth::NonInteractive,
            ] {
                for has_tty in [true, false] {
                    let case = format!("{os:?}, {backend:?}, sudo {sudo:?}, doas {doas:?}, {auth:?}, tty {has_tty}");
                    let available = BackendSet {
                        sudo: sudo.clone(),
                        doas: doas.clone(),
                        ..all_backends()
                    };
                    let root = Host {
                        os,
                        ..unix_host(available.clone(), true, has_tty)
                    };
                    assert!(
                        matches!(
                            root.plan(Privilege::Elevated, backend, auth.clone()),
                            Transition::RunAsIs
                        ),
                        "root, {case}"
                    );
                    let non_root = Host {
                        os,
                        ..unix_host(available, false, has_tty)
                    };
                    let (_, got, report) = unavailable(non_root.plan(Privilege::Elevated, backend, auth.clone()));
                    assert_eq!(got, cause, "non-root, {case}: {report}");
                }
            }
        }
    }
}

/// The root rule beyond `sudo`: a request its platform allows runs as is for a root caller whose
/// front (`pkexec`, `osascript` or a named `doas`) is absent or not examinable; a caller that is not
/// elevated is `BackendUnavailable`, caused by the lookup's error if there was one.
///
/// Mutants: a root caller is refused for such a front; a non-root caller's unexamined front is
/// reported as absent.
#[skuld::test]
fn an_elevated_caller_runs_as_is_where_a_non_sudo_front_or_a_graphical_one_is_unusable() {
    /// Picks the front a row's request needs.
    type Front = fn(&mut BackendSet) -> &mut FrontState;
    let mut rows: Vec<(Os, Backend, Front, Auth)> = vec![
        (Os::Linux, Backend::Pkexec, |set| &mut set.pkexec, Auth::Gui),
        (Os::MacOs, Backend::Auto, |set| &mut set.osascript, Auth::Gui),
    ];
    for os in [Os::Linux, Os::Unix, Os::MacOs] {
        rows.push((os, Backend::Doas, |set| &mut set.doas, Auth::Interactive));
        rows.push((os, Backend::Doas, |set| &mut set.doas, Auth::NonInteractive));
    }
    for (os, backend, front, auth) in rows {
        for state in [FrontState::Absent, unexamined()] {
            let cause = matches!(state, FrontState::Unexamined(_)).then_some(40);
            let mut available = all_backends();
            *front(&mut available) = state.clone();
            let case = format!("{os:?}, {backend:?}, front {state:?}, {auth:?}");
            let root = Host {
                os,
                ..unix_host(available.clone(), true, true)
            };
            assert!(
                matches!(
                    root.plan(Privilege::Elevated, backend, auth.clone()),
                    Transition::RunAsIs
                ),
                "root, {case}"
            );
            let non_root = Host {
                os,
                ..unix_host(available, false, true)
            };
            let (_, got, report) = unavailable(non_root.plan(Privilege::Elevated, backend, auth.clone()));
            assert_eq!(got, cause, "non-root, {case}: {report}");
        }
    }
}

/// What a plan answers: run as is, elevate through `sudo`, `Unsupported`, or `BackendUnavailable` with
/// the lookup error's OS code as its cause (`None` for no cause) and its detail.
#[derive(Debug, Clone, Copy)]
enum Verdict {
    RunAsIs,
    Sudo,
    Unsupported,
    Unavailable(Option<i32>, Option<&'static str>),
}

/// The detail of a `BackendUnavailable` for a `sudo` or `doas` that could not be examined.
const SUDO_OPEN: &str = "Auth::Stdin and Auth::Askpass need sudo; whether sudo is on PATH could not be told";
const DOAS_OPEN: &str =
    "Auth::Stdin and Auth::Askpass need sudo, which is not on PATH; whether doas is there could not be told";

/// The table in [`Backend::Auto`]'s doc, row by row. Each row is `sudo`, `doas`, then the answer for a
/// root caller and for one that is not.
///
/// Mutants: an unexamined `sudo` is taken as `sudo` whatever the `doas` is; the cause is the `doas`'s
/// where the `sudo`'s is expected.
#[skuld::test]
fn stdin_and_askpass_with_auto_are_decided_by_both_fronts() {
    use Verdict::{RunAsIs, Sudo, Unavailable, Unsupported};
    let found = FrontState::Found;
    let doas_found = || found(PathBuf::from("/usr/bin/doas"));
    let sudo_found = || found(PathBuf::from("/usr/bin/sudo"));
    let rows = [
        (sudo_found(), FrontState::Absent, RunAsIs, Sudo),
        (sudo_found(), doas_found(), RunAsIs, Sudo),
        (sudo_found(), unexamined_by(41), RunAsIs, Sudo),
        (FrontState::Absent, FrontState::Absent, RunAsIs, Unavailable(None, None)),
        (FrontState::Absent, doas_found(), Unsupported, Unsupported),
        (
            FrontState::Absent,
            unexamined_by(41),
            Unavailable(Some(41), Some(DOAS_OPEN)),
            Unavailable(Some(41), Some(DOAS_OPEN)),
        ),
        (
            unexamined_by(40),
            FrontState::Absent,
            RunAsIs,
            Unavailable(Some(40), None),
        ),
        (
            unexamined_by(40),
            doas_found(),
            Unavailable(Some(40), Some(SUDO_OPEN)),
            Unavailable(Some(40), Some(SUDO_OPEN)),
        ),
        (
            unexamined_by(40),
            unexamined_by(41),
            Unavailable(Some(40), Some(SUDO_OPEN)),
            Unavailable(Some(40), Some(SUDO_OPEN)),
        ),
    ];
    for os in [Os::Linux, Os::Unix, Os::MacOs] {
        for (sudo, doas, root, non_root) in &rows {
            for auth in [
                Auth::Stdin(crate::elevation::Secret::new("p")),
                Auth::Askpass("/usr/bin/ssh-askpass".into()),
            ] {
                for (elevated, want) in [(true, root), (false, non_root)] {
                    let case = format!("{os:?}, sudo {sudo:?}, doas {doas:?}, {auth:?}, elevated {elevated}");
                    let available = BackendSet {
                        sudo: sudo.clone(),
                        doas: doas.clone(),
                        ..all_backends()
                    };
                    let host = Host {
                        os,
                        ..unix_host(available, elevated, true)
                    };
                    let plan = host.plan(Privilege::Elevated, Backend::Auto, auth.clone());
                    match want {
                        RunAsIs => assert!(matches!(plan, Transition::RunAsIs), "{case}: {plan:?}"),
                        Sudo => assert!(
                            matches!(
                                plan,
                                Transition::ElevatePosix {
                                    backend: Backend::Sudo,
                                    ..
                                }
                            ),
                            "{case}: {plan:?}"
                        ),
                        Unsupported => assert!(is_unsupported(plan), "{case}"),
                        Unavailable(code, detail) => {
                            let (got_detail, got_code, report) = unavailable(plan);
                            assert_eq!(got_code, *code, "{case}: {report}");
                            if let Some(detail) = detail {
                                assert_eq!(got_detail, *detail, "{case}");
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A named `Doas` under `Stdin` or `Askpass` is `Unsupported` for every caller, whatever its search
/// found.
///
/// Mutant: a named `Doas` that could not be examined is `BackendUnavailable`.
#[skuld::test]
fn stdin_and_askpass_with_a_named_doas_are_unsupported_whatever_the_lookup_found() {
    for os in [Os::Linux, Os::Unix, Os::MacOs] {
        for state in [FrontState::Absent, unexamined(), all_backends().doas] {
            for elevated in [true, false] {
                for auth in [
                    Auth::Stdin(crate::elevation::Secret::new("p")),
                    Auth::Askpass("/usr/bin/ssh-askpass".into()),
                ] {
                    let h = Host {
                        os,
                        ..unix_host(
                            BackendSet {
                                doas: state.clone(),
                                ..all_backends()
                            },
                            elevated,
                            true,
                        )
                    };
                    let error = reject_error(h.plan(Privilege::Elevated, Backend::Doas, auth.clone()));
                    assert!(
                        matches!(error, Error::Unsupported { .. }),
                        "{os:?}, doas {state:?}, elevated {elevated}, {auth:?}: {error:?}"
                    );
                }
            }
        }
    }
}

/// Where `Auto` could not examine the front it names, under the auths `doas` serves, a root caller
/// runs as is and one that is not is `BackendUnavailable`, caused by that front's error: the `doas`'s
/// when `sudo` is absent, else the `sudo`'s. Resolution finds the front before it reads the terminal,
/// so without one the answer is the same `BackendUnavailable`, not `NoTty`.
///
/// Mutant: `Auto` skips an unexamined front, so the cause is lost or the next front's.
#[skuld::test]
fn auto_names_an_unexamined_front_for_the_auths_doas_serves() {
    for os in [Os::Linux, Os::Unix, Os::MacOs] {
        for (sudo, doas) in [
            (FrontState::Absent, unexamined_by(40)),
            (unexamined_by(40), all_backends().doas),
            (unexamined_by(40), unexamined_by(41)),
        ] {
            for auth in [Auth::Interactive, Auth::NonInteractive] {
                for has_tty in [true, false] {
                    let available = BackendSet {
                        sudo: sudo.clone(),
                        doas: doas.clone(),
                        ..all_backends()
                    };
                    let case = format!("{os:?}, sudo {sudo:?}, doas {doas:?}, {auth:?}, tty {has_tty}");
                    let root = Host {
                        os,
                        ..unix_host(available.clone(), true, has_tty)
                    };
                    assert!(
                        matches!(
                            root.plan(Privilege::Elevated, Backend::Auto, auth.clone()),
                            Transition::RunAsIs
                        ),
                        "root, {case}"
                    );
                    let non_root = Host {
                        os,
                        ..unix_host(available, false, has_tty)
                    };
                    let (_, cause, report) =
                        unavailable(non_root.plan(Privilege::Elevated, Backend::Auto, auth.clone()));
                    assert_eq!(cause, Some(40), "{case}: {report}");
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
    let (detail, cause, report) = unavailable(h.plan(Privilege::Elevated, Backend::Auto, Auth::Gui));
    assert!(detail.contains("missing") && !detail.contains("executable"), "{detail}");
    assert_eq!(cause, None, "{report}");
    h.available.osascript = unexamined();
    let (_, cause, report) = unavailable(h.plan(Privilege::Elevated, Backend::Auto, Auth::Gui));
    assert_eq!(cause, Some(40), "{report}");
}

#[skuld::test]
fn macos_gui_already_elevated_runs_as_is() {
    let h = macos_host(true, false);
    assert!(matches!(
        h.plan(Privilege::Elevated, Backend::Auto, Auth::Gui),
        Transition::RunAsIs
    ));
}
