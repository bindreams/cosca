use crate::error::{ChildFate, Error, QuoteError, QuoteErrorKind};
use crate::test_child::over_fake::exited_unreaped;

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

/// `Error::raw_os_error` finds the OS code of an `Error::Io` wherever the walk from it first meets
/// one: on the `io::Error` itself, or below the context and the note cosca added. Any other variant
/// has none.
#[skuld::test]
fn raw_os_error_walks_an_error_io_to_the_first_os_code() {
    let code = if cfg!(windows) { 5 } else { 13 };
    let os = || std::io::Error::from_raw_os_error(code);
    let context = || crate::error::io_context("pidfd_open", os());

    assert_eq!(Error::Io(os()).raw_os_error(), Some(code), "bare");
    assert_eq!(Error::Io(context()).raw_os_error(), Some(code), "io_context");
    assert_eq!(
        Error::Io(os()).with_note("while tearing down").raw_os_error(),
        Some(code),
        "a note"
    );
    assert_eq!(
        Error::Io(context()).with_note("while tearing down").raw_os_error(),
        Some(code),
        "io_context and a note"
    );
    assert_eq!(
        Error::Io(std::io::Error::other("no code")).raw_os_error(),
        None,
        "no code anywhere"
    );
    assert_eq!(
        Error::Containment { detail: "d".into() }.raw_os_error(),
        None,
        "not an Error::Io"
    );
}

/// Where the OS code sits below an `Error::Io`: its own `source()` is the wrapper cosca added, which
/// has no code, and the code is on the error the wrapper holds.
#[skuld::test]
fn an_error_io_over_io_context_has_the_code_one_io_error_down() {
    let code = if cfg!(windows) { 5 } else { 13 };
    let e = Error::Io(crate::error::io_context(
        "could not check C:\\t.exe",
        std::io::Error::from_raw_os_error(code),
    ));
    assert_eq!(codes_down(&e), [None, Some(code)]);
}

/// A note on an `Error::Io` puts its own code-less `io::Error` above the original one.
#[skuld::test]
fn a_noted_error_io_has_the_code_one_io_error_down() {
    let code = if cfg!(windows) { 5 } else { 13 };
    let e = Error::Io(std::io::Error::from_raw_os_error(code)).with_note("while tearing down");
    assert_eq!(codes_down(&e), [None, Some(code)]);
}

/// A note on an `io_context` error, the shape the unix spawn teardowns produce, leaves the OS code
/// under both wrappers.
#[skuld::test]
fn a_note_on_a_context_error_io_has_the_code_under_both_wrappers() {
    let code = if cfg!(windows) { 5 } else { 13 };
    let e = Error::Io(crate::error::io_context(
        "pidfd_open",
        std::io::Error::from_raw_os_error(code),
    ))
    .with_note("while tearing down");
    assert_eq!(codes_down(&e), [None, None, Some(code)]);
}

/// A note keeps every variant and its other fields, appends to the detail, and keeps each `source`.
/// An I/O error keeps its kind, and its OS code as the note's `source`.
#[cfg(unix)]
#[skuld::test]
fn with_note_keeps_each_variant_and_appends() {
    use crate::error::{ElevationErrorKind, RecordErrorKind};
    use std::error::Error as _;
    let os = || std::io::Error::from_raw_os_error(libc::EACCES);
    let source_code = |e: &Error| {
        e.source()
            .and_then(|s| s.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error)
    };
    let note = "left running";

    let noted = Error::Io(os()).with_note(note);
    assert_eq!(
        noted.raw_os_error(),
        Some(libc::EACCES),
        "the original is below the note"
    );
    let Error::Io(io) = noted else {
        panic!("an Io error stays Io");
    };
    assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(io.to_string().ends_with("; left running"), "{io}");

    let e = Error::Unsupported {
        op: "op".into(),
        platform: "linux",
        detail: "d".into(),
    }
    .with_note(note);
    assert!(
        matches!(&e, Error::Unsupported { op, platform: "linux", detail } if op == "op" && detail == "d; left running")
    );
    let e = Error::Containment { detail: "d".into() }.with_note(note);
    assert!(matches!(&e, Error::Containment { detail } if detail == "d; left running"));
    let e = Error::NoConsole { detail: "d".into() }.with_note(note);
    assert!(matches!(&e, Error::NoConsole { detail } if detail == "d; left running"));
    let e = Error::Elevation {
        kind: ElevationErrorKind::AuthFailed,
        detail: "d".into(),
    }
    .with_note(note);
    assert!(matches!(
        &e,
        Error::Elevation { kind: ElevationErrorKind::AuthFailed, detail } if detail == "d; left running"
    ));
    let e = Error::Unassessable {
        detail: "d".into(),
        source: Some(os()),
    }
    .with_note(note);
    assert!(matches!(&e, Error::Unassessable { detail, .. } if detail == "d; left running"));
    assert_eq!(source_code(&e), Some(libc::EACCES));
    let e = Error::NotThreadGroupLeader {
        pid: 7,
        detail: "d".into(),
        source: os(),
    }
    .with_note(note);
    assert!(matches!(&e, Error::NotThreadGroupLeader { pid: 7, detail, .. } if detail == "d; left running"));
    assert_eq!(source_code(&e), Some(libc::EACCES));
    let e = Error::IdentityRecord {
        kind: RecordErrorKind::ForeignPlatform,
        detail: "d".into(),
        source: Some(os()),
    }
    .with_note(note);
    assert!(matches!(
        &e,
        Error::IdentityRecord { kind: RecordErrorKind::ForeignPlatform, detail, .. } if detail == "d; left running"
    ));
    assert_eq!(source_code(&e), Some(libc::EACCES));
}

/// A member left behind by a refused kill takes a note and keeps its OS error as the error's source:
/// the code is the variant's contract, and the note goes in the variant's own `note`. One that could
/// not be read takes it the same way, and a second note follows the first.
///
/// Mutants: `with_note` wraps the refusal's `io::Error`, which then has no OS code; it drops the note
/// of a refusal.
#[cfg(unix)]
#[skuld::test]
fn with_note_keeps_the_os_error_of_a_refused_kill_a_member_not_killed() {
    let refused = Error::MemberNotKilled {
        pid: 7,
        source: Box::new(Error::Io(std::io::Error::from_raw_os_error(libc::EPERM))),
        note: None,
    }
    .with_note("front left");
    let Error::MemberNotKilled { pid: 7, source, .. } = &refused else {
        panic!("expected MemberNotKilled, got {refused:?}");
    };
    assert!(
        matches!(&**source, Error::Io(e) if e.raw_os_error() == Some(libc::EPERM)),
        "{refused:?}"
    );
    assert!(refused.to_string().ends_with("(os error 1); front left"), "{refused}");

    let unread = Error::MemberNotKilled {
        pid: 7,
        source: Box::new(Error::Unassessable {
            detail: "d".into(),
            source: None,
        }),
        note: None,
    }
    .with_note("front left")
    .with_note("and more");
    assert!(unread.to_string().ends_with("d; front left; and more"), "{unread}");
}

/// The elevated-program note belongs to a wrapper-elevated spawn only, and only to a fate that says
/// the backend is not running.
///
/// Mutants: the note on every spawn; the note missing from a wrapper-elevated one; the note on a
/// `Running` fate.
#[skuld::test]
fn the_elevated_program_note_is_for_a_wrapper_elevated_spawn_only() {
    let note = "an elevated program behind it may still run";
    let message = |fate: ChildFate, wrapper_elevated: bool| {
        Error::MayHaveStarted {
            fate,
            wrapper_elevated,
            source: Box::new(Error::Io(std::io::Error::other("cause"))),
            unreaped: None,
        }
        .to_string()
    };
    for fate in [ChildFate::Reaped, ChildFate::Killed, ChildFate::Gone] {
        assert!(!message(fate, false).contains(note), "{fate:?}, not wrapper-elevated");
        assert!(message(fate, true).contains(note), "{fate:?}, wrapper-elevated");
    }
    for fate in [ChildFate::Running { id: None }, ChildFate::Unknown] {
        assert!(!message(fate, true).contains(note), "{fate:?}");
    }
}

/// An error that carries the child reads, prints and matches as the same error without it.
///
/// Mutant: `fate` or `Display` looks at `unreaped`.
#[skuld::test]
fn an_error_with_an_unreaped_child_still_reports_its_fate_and_message() {
    let id = crate::identity::ProcessId::current();
    let fate = ChildFate::Running { id: Some(id) };
    let error = |unreaped| Error::MayHaveStarted {
        fate,
        wrapper_elevated: false,
        source: Box::new(Error::Io(std::io::Error::other("cause"))),
        unreaped,
    };
    let with_child = error(Some(exited_unreaped(id)));
    assert_eq!(with_child.fate(), Some(fate));
    assert_eq!(with_child.to_string(), error(None).to_string());
}

/// A note added to the error keeps the child it carries.
///
/// Mutant: `with_note` rebuilds the variant without `unreaped`.
#[skuld::test]
fn with_note_keeps_the_unreaped_child() {
    let id = crate::identity::ProcessId::current();
    let error = Error::MayHaveStarted {
        fate: ChildFate::Running { id: Some(id) },
        wrapper_elevated: false,
        source: Box::new(Error::Containment { detail: "x".into() }),
        unreaped: Some(exited_unreaped(id)),
    }
    .with_note("front left");
    let Error::MayHaveStarted { source, unreaped, .. } = &error else {
        panic!("expected MayHaveStarted, got {error:?}");
    };
    assert_eq!(unreaped.as_ref().map(|child| child.pid()), Some(Some(id.pid())));
    assert!(
        matches!(**source, Error::Containment { ref detail } if detail == "x; front left"),
        "{source:?}"
    );
}

/// A Win32 failure wrapped as `HRESULT_FROM_WIN32` comes back as its Win32 code, as std's own
/// spawn reports it, so `kind()` classifies it. Any other HRESULT is kept whole.
#[cfg(windows)]
#[skuld::test]
fn win32_io_error_unwraps_a_win32_hresult() {
    use crate::error::win32_io_error;
    use windows::core::{Error, HRESULT};
    let dir = win32_io_error(Error::from_hresult(HRESULT(0x8007_010Bu32 as i32)));
    assert_eq!(dir.raw_os_error(), Some(267));
    assert_eq!(dir.kind(), std::io::ErrorKind::NotADirectory);
    let e_fail = win32_io_error(Error::from_hresult(HRESULT(0x8000_4005u32 as i32)));
    assert_eq!(e_fail.raw_os_error(), Some(0x8000_4005u32 as i32));
}

#[skuld::test]
fn io_error_source_is_the_wrapped_io_error() {
    let e = Error::Io(std::io::Error::from_raw_os_error(13));
    let source = std::error::Error::source(&e).expect("Error::Io has a source");
    let io = source
        .downcast_ref::<std::io::Error>()
        .expect("the source is the io::Error");
    assert_eq!(io.raw_os_error(), Some(13));
}

#[skuld::test]
fn io_error_displays_the_wrapped_message_unchanged() {
    let inner = std::io::Error::other("disk on fire");
    let expected = inner.to_string();
    assert_eq!(Error::Io(inner).to_string(), expected);
}

/// The `raw_os_error()` of each of `e`'s [`Error::io_errors`].
fn codes_down(e: &Error) -> Vec<Option<i32>> {
    e.io_errors().map(std::io::Error::raw_os_error).collect()
}
