use crate::error::{Error, QuoteError, QuoteErrorKind};

#[skuld::test]
fn containment_error_displays_detail() {
    let e = Error::Containment {
        detail: "cgroup leaf not writable".into(),
    };
    assert!(e.to_string().contains("cgroup leaf not writable"), "{e}");
}

#[skuld::test]
fn no_console_error_names_the_cause() {
    let e = Error::NoConsole {
        detail: "CTRL_BREAK to group 1234".into(),
    };
    let s = e.to_string();
    assert!(s.contains("no attached console"), "{s}");
    assert!(s.contains("CTRL_BREAK to group 1234"), "{s}");
    assert!(matches!(e, Error::NoConsole { .. }));
}

#[skuld::test]
fn quote_error_displays_kind_and_offset() {
    let e = QuoteError::new(7, QuoteErrorKind::UnterminatedSingleQuote);
    assert_eq!(e.to_string(), "unterminated single quote at offset 7");
}

#[skuld::test]
fn quote_error_kinds_have_distinct_messages() {
    assert_eq!(
        QuoteErrorKind::UnterminatedDoubleQuote.to_string(),
        "unterminated double quote"
    );
    assert_eq!(QuoteErrorKind::TrailingBackslash.to_string(), "trailing backslash");
    assert_eq!(QuoteErrorKind::NonUtf8.to_string(), "not valid UTF-8");
    assert_eq!(
        QuoteErrorKind::UnrepresentableChar.to_string(),
        "character cannot be represented in this grammar"
    );
    // The whole set, so a new variant colliding with an existing message fails here.
    let all = [
        QuoteErrorKind::UnterminatedSingleQuote,
        QuoteErrorKind::UnterminatedDoubleQuote,
        QuoteErrorKind::TrailingBackslash,
        QuoteErrorKind::NonUtf8,
        QuoteErrorKind::UnrepresentableChar,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a.to_string(), b.to_string(), "{a:?} vs {b:?}");
        }
    }
}

#[skuld::test]
fn error_wraps_quote_error_via_from() {
    let e: Error = QuoteError::new(0, QuoteErrorKind::TrailingBackslash).into();
    assert!(matches!(e, Error::Quote(_)));
    assert!(e.to_string().contains("trailing backslash"));
}

#[skuld::test]
fn unsupported_displays_op_platform_and_detail() {
    let e = Error::Unsupported {
        op: "fd 3".into(),
        platform: "windows",
        detail: "arbitrary fds require the raw backend".into(),
    };
    let s = e.to_string();
    assert!(s.contains("fd 3"), "{s}");
    assert!(s.contains("windows"), "{s}");
    assert!(s.contains("raw backend"), "{s}");
}

#[skuld::test]
fn elevation_error_displays_kind_and_detail() {
    use crate::error::ElevationErrorKind;
    let e = Error::Elevation {
        kind: ElevationErrorKind::NoTty,
        detail: "interactive auth requested with no controlling terminal".into(),
    };
    let s = e.to_string();
    assert!(s.contains("no controlling terminal"), "{s}");
    assert!(matches!(
        e,
        Error::Elevation {
            kind: ElevationErrorKind::NoTty,
            ..
        }
    ));
}

#[skuld::test]
fn command_too_long_names_the_host_not_the_platform() {
    // The wording matters: this verdict is per-host and per-command, so it must not
    // read like a permanent platform limitation.
    let m = crate::error::ElevationErrorKind::CommandTooLong.to_string();
    assert_eq!(m, "the elevation command is too long for this host");
}

#[skuld::test]
fn elevation_error_kinds_have_distinct_messages() {
    use crate::error::ElevationErrorKind::*;
    let all = [
        BackendUnavailable,
        AuthFailed,
        AuthDeclined,
        NoTty,
        Unkillable,
        Untracked,
        CommandTooLong,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a.to_string(), b.to_string(), "{a:?} vs {b:?}");
        }
    }
}

#[skuld::test]
fn untracked_message_does_not_assert_termination() {
    // The kind's Display is neutral; termination status lives in `detail`.
    use crate::error::ElevationErrorKind::Untracked;
    let s = Untracked.to_string();
    assert!(
        !s.contains("terminated"),
        "Untracked Display must not claim termination: {s}"
    );
}

#[skuld::test]
fn unkillable_message_is_about_the_failed_signal_not_the_childs_fate() {
    // Display describes the signal denial; whether the child lives is in `detail`.
    use crate::error::ElevationErrorKind::Unkillable;
    let s = Unkillable.to_string();
    assert!(
        !s.contains("terminated"),
        "Unkillable Display must not claim termination: {s}"
    );
    assert!(
        s.contains("terminate") || s.contains("signal") || s.contains("kill"),
        "{s}"
    );
}

#[skuld::test]
fn unassessable_reads_as_a_refusal_not_a_failure() {
    let e = crate::error::Error::Unassessable {
        detail: "pid 4 could not be opened".into(),
        source: Some(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
    };
    let s = e.to_string();
    assert!(
        s.contains("could not determine"),
        "must not read as a failure of the target: {s}"
    );
    assert!(s.contains("pid 4 could not be opened"), "detail must survive: {s}");
    // The OS cause stays reachable rather than flattened into prose.
    assert!(std::error::Error::source(&e).is_some(), "source is preserved");
}

#[skuld::test]
fn unassessable_carries_no_source_when_there_is_no_os_error() {
    let e = crate::error::Error::Unassessable {
        detail: "identity could not be confirmed".into(),
        source: None,
    };
    assert!(std::error::Error::source(&e).is_none());
}

/// Context added to an OS error keeps the OS error as its `source`, so the code a caller branches
/// on survives: several OS codes share one `ErrorKind`.
#[skuld::test]
fn io_context_keeps_the_os_error_as_its_source() {
    // Access denied: `ERROR_ACCESS_DENIED` on Windows, `EACCES` elsewhere.
    let code = if cfg!(windows) { 5 } else { 13 };
    let e = crate::error::io_context("could not check C:\\t.exe", std::io::Error::from_raw_os_error(code));
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(e.to_string().starts_with("could not check C:\\t.exe: "), "{e}");
    let source = std::error::Error::source(e.get_ref().expect("a custom error"))
        .and_then(|s| s.downcast_ref::<std::io::Error>())
        .expect("the OS error is the source");
    assert_eq!(source.raw_os_error(), Some(code));
}

/// A note keeps the variant, and an I/O error keeps its kind and its OS code as the source.
/// Mutants: a noted error is rewrapped into another variant; the I/O kind or source is lost.
#[cfg(unix)]
#[skuld::test]
fn with_note_keeps_the_variant_and_appends() {
    let unassessable = Error::Unassessable {
        detail: "refused".into(),
        source: None,
    }
    .with_note("left running");
    assert!(matches!(&unassessable, Error::Unassessable { detail, .. } if detail == "refused; left running"));
    let containment = Error::Containment {
        detail: "attach".into(),
    }
    .with_note("left running");
    assert!(matches!(&containment, Error::Containment { detail } if detail == "attach; left running"));
    let Error::Io(io) = Error::Io(std::io::Error::from_raw_os_error(libc::EACCES)).with_note("left running") else {
        panic!("an Io error stays Io");
    };
    assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(io.to_string().ends_with("; left running"), "{io}");
    let source = std::error::Error::source(io.get_ref().expect("a custom payload")).expect("the original");
    let original = source.downcast_ref::<std::io::Error>().expect("an io::Error");
    assert_eq!(original.raw_os_error(), Some(libc::EACCES));
}
