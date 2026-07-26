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
