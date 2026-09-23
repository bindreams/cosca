use super::Secret;

#[test]
fn secret_debug_is_redacted() {
    let s = Secret::new("hunter2");
    let dbg = format!("{s:?}");
    assert!(!dbg.contains("hunter2"), "Secret Debug must not leak the value: {dbg}");
    assert!(dbg.contains("Secret"), "{dbg}");
}

#[test]
fn secret_exposes_bytes_for_the_effect_layer() {
    let s = Secret::new("pw");
    assert_eq!(s.expose(), b"pw");
}

use super::{Auth, Backend, ElevatedStdio, ElevatedVia, ElevationReport, Privilege};

#[test]
fn backend_defaults_to_auto() {
    assert_eq!(Backend::default(), Backend::Auto);
}

#[test]
fn auth_defaults_to_interactive() {
    assert!(matches!(Auth::default(), Auth::Interactive));
}

#[test]
fn privilege_variants_are_distinct() {
    assert_ne!(Privilege::Unprivileged, Privilege::Elevated);
}

#[test]
fn elevated_via_distinguishes_windows_uac_from_wrapped() {
    assert_ne!(ElevatedVia::WindowsUac, ElevatedVia::Wrapped(Backend::Sudo));
    assert_ne!(ElevatedVia::WindowsUac, ElevatedVia::AlreadyElevated);
}

#[test]
fn elevation_report_holds_achieved_state() {
    let r = ElevationReport {
        via: ElevatedVia::Wrapped(Backend::Sudo),
        stripped_env: vec!["LD_PRELOAD".into()],
        stdio: ElevatedStdio::Passthrough,
    };
    assert_eq!(r.via, ElevatedVia::Wrapped(Backend::Sudo));
    assert_eq!(r.stripped_env, vec![std::ffi::OsString::from("LD_PRELOAD")]);
    assert_eq!(r.stdio, ElevatedStdio::Passthrough);
}

#[test]
fn already_elevated_report_is_single_sourced() {
    let r = super::already_elevated_report(ElevatedStdio::Passthrough);
    assert_eq!(r.via, ElevatedVia::AlreadyElevated);
    assert!(r.stripped_env.is_empty());
    assert_eq!(r.stdio, ElevatedStdio::Passthrough);
}

#[test]
fn remap_backend_missing_is_backend_unavailable_with_cause() {
    use crate::error::{ElevationErrorKind, Error};
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
    let e = super::remap_derived_spawn_error(Error::Io(io), std::path::Path::new("/nonexistent/sudo"));
    match e {
        Error::Elevation {
            kind: ElevationErrorKind::BackendUnavailable,
            detail,
        } => {
            assert!(
                detail.contains("/nonexistent/sudo"),
                "detail must name the backend path: {detail}"
            );
            assert!(
                detail.contains("no such file"),
                "detail must embed the underlying cause: {detail}"
            );
        }
        other => panic!("expected BackendUnavailable, got {other:?}"),
    }
}

#[test]
fn remap_preserves_a_non_backend_io_error() {
    use crate::error::Error;
    // The backend path exists (this test binary), so a NotFound is NOT the backend —
    // it is attributable elsewhere (e.g. a bad current_dir()). The original Io survives.
    let exe = std::env::current_exe().unwrap();
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "cwd gone");
    let e = super::remap_derived_spawn_error(Error::Io(io), &exe);
    assert!(
        matches!(e, Error::Io(_)),
        "a non-backend NotFound must not be remapped: {e:?}"
    );
}

#[test]
fn remap_passes_through_unrelated_errors() {
    use crate::error::Error;
    let e = super::remap_derived_spawn_error(
        Error::Unsupported {
            op: "x".into(),
            platform: "unix",
            detail: "y".into(),
        },
        std::path::Path::new("/nonexistent/sudo"),
    );
    assert!(matches!(e, Error::Unsupported { .. }));
}

#[cfg(unix)]
#[test]
fn remap_backend_exists_but_not_executable_is_backend_unavailable() {
    use crate::error::{ElevationErrorKind, Error};
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let backend_path = dir.path().join("fake-sudo");
    std::fs::write(&backend_path, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&backend_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    // A real exec attempt on a non-executable file yields PermissionDenied.
    let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
    let e = super::remap_derived_spawn_error(Error::Io(io), &backend_path);
    match e {
        Error::Elevation {
            kind: ElevationErrorKind::BackendUnavailable,
            detail,
        } => {
            assert!(
                detail.contains(backend_path.to_str().unwrap()),
                "detail must name the backend path: {detail}"
            );
        }
        other => panic!("expected BackendUnavailable for an existing-but-non-executable backend, got {other:?}"),
    }
}

#[test]
fn elevated_stdio_stdin_consumed_variant_exists() {
    // POSIX Auth::Stdin binds fd0 to the elevation password channel; reporting
    // Passthrough would be a lie. This variant must exist and be distinct.
    assert_ne!(ElevatedStdio::StdinConsumed, ElevatedStdio::Passthrough);
    assert_ne!(ElevatedStdio::StdinConsumed, ElevatedStdio::OwnConsole);
}

#[cfg(unix)]
#[test]
fn is_elevated_matches_effective_uid_ground_truth() {
    // Never assume ambient privilege; compare against an independent syscall.
    // SAFETY: geteuid has no preconditions and never fails.
    let euid0 = unsafe { libc::geteuid() } == 0;
    assert_eq!(super::is_elevated(), euid0, "is_elevated disagreed with geteuid()==0");
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn detect_reports_unix_os() {
    let h = super::plan::Host::detect();
    assert_eq!(h.os, super::plan::Os::Unix);
}

/// macOS must NOT report `Os::Unix`: the whole point of the split is that the
/// planner can tell it apart, and detection is the only place that decision is made.
#[cfg(target_os = "macos")]
#[test]
fn detect_reports_macos() {
    let h = super::plan::Host::detect();
    assert_eq!(h.os, super::plan::Os::MacOs);
    assert!(
        h.available.osascript.is_some(),
        "a macOS host must resolve /usr/bin/osascript"
    );
    assert!(h.arg_max.is_some(), "kern.argmax must be readable on macOS");
}

#[test]
fn kill_error_on_an_elevated_wrapper_is_unkillable() {
    use crate::error::{ElevationErrorKind, Error};
    let eperm = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let e = super::map_elevated_kill_error(eperm, /* elevated_wrapper */ true);
    assert!(
        matches!(
            e,
            Error::Elevation {
                kind: ElevationErrorKind::Unkillable,
                ..
            }
        ),
        "{e:?}"
    );
}

#[test]
fn kill_error_on_a_plain_child_stays_io() {
    use crate::error::Error;
    let eperm = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert!(matches!(super::map_elevated_kill_error(eperm, false), Error::Io(_)));
}

#[test]
fn non_permission_kill_error_stays_io_even_when_elevated() {
    use crate::error::Error;
    let other = std::io::Error::from(std::io::ErrorKind::NotFound);
    assert!(matches!(super::map_elevated_kill_error(other, true), Error::Io(_)));
}

/// Every backend's argv gate is this one function; only the words differ.
#[test]
fn the_shared_argv_gate_refuses_each_rule_with_the_backends_words() {
    use crate::command::Command;
    use crate::error::Error;
    const WORDS: super::ArgvRefusals = super::ArgvRefusals {
        platform: "test",
        op_prefix: "test elevation",
        commandline: "no command lines here",
        argv0: "no separate argv[0] here",
    };
    let refusal = |c: &Command| match super::elevation_argv(c, &WORDS) {
        Err(Error::Unsupported { op, platform, detail }) => {
            assert_eq!(platform, "test");
            format!("{op} / {detail}")
        }
        other => panic!("expected Unsupported, got {other:?}"),
    };
    let mut empty_argv = Command::new();
    empty_argv.args::<[&str; 0], &str>([]);
    for no_program in [Command::new(), empty_argv] {
        assert_eq!(
            refusal(&no_program),
            "test elevation of an empty command / set a program via .args([...]) before .elevate()"
        );
    }
    let mut line = Command::new();
    line.commandline("id -u");
    assert_eq!(
        refusal(&line),
        "test elevation of a commandline() command / no command lines here"
    );
    let mut argv0 = Command::new();
    argv0.executable("/usr/bin/id").args(["not-id"]);
    assert_eq!(
        refusal(&argv0),
        "test elevation with an argv[0] distinct from executable() / no separate argv[0] here"
    );
    let mut ok = Command::new();
    ok.executable("/usr/bin/id").args(["/usr/bin/id", "-u"]);
    assert_eq!(super::elevation_argv(&ok, &WORDS).expect("accepted").len(), 2);
}
