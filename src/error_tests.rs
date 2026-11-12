use crate::error::{chain, first_os_code, ChildFate, Error, Failures, QuoteError, QuoteErrorKind, Report};
use crate::test_child::over_fake::exited_unreaped;
use std::sync::Arc;

#[skuld::test]
fn containment_error_displays_detail() {
    let e = Error::Containment {
        detail: "cgroup leaf not writable".into(),
        source: None,
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
        source: None,
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
        source: None,
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
        source: Some(Arc::new(Error::Io(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )))),
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

/// Mutant: the hand-out is rebuilt from the code or from the text, so the words or the code are lost.
#[skuld::test]
fn a_shared_io_context_cause_reports_as_the_original_and_keeps_its_code() {
    let code = if cfg!(windows) { 5 } else { 13 };
    let shared = Arc::new(crate::error::io_context("w", std::io::Error::from_raw_os_error(code)));

    let handed = crate::error::shared_io(&shared);

    assert_eq!(Report(&handed).to_string(), Report(&*shared).to_string());
    assert_eq!(first_os_code(&handed), Some(code));
    assert_eq!(handed.kind(), shared.kind());
}

/// Mutant: the hand-out wraps the bare error, so its own `raw_os_error()` is `None`.
#[skuld::test]
fn a_shared_bare_os_error_is_handed_out_with_its_raw_code() {
    let code = if cfg!(windows) { 5 } else { 13 };
    let shared = Arc::new(std::io::Error::from_raw_os_error(code));

    let handed = crate::error::shared_io(&shared);

    assert_eq!(handed.raw_os_error(), Some(code));
    assert_eq!(handed.kind(), shared.kind());
}

/// Mutant: the hand-out takes the words off the end of the original's text.
#[skuld::test]
fn a_shared_wrapped_io_error_reports_as_the_original() {
    let code = if cfg!(windows) { 5 } else { 13 };
    let os = || std::io::Error::from_raw_os_error(code);
    let timed_out = || std::io::Error::new(std::io::ErrorKind::TimedOut, "ran out");
    let ctx = crate::error::io_context;
    let note = |e: std::io::Error| Error::Io(e).with_note("n").into_io();
    let originals = [
        ("a note", note(os()), Some(code)),
        ("a context and a note", note(ctx("w", os())), Some(code)),
        ("two contexts", ctx("outer", ctx("w", os())), Some(code)),
        ("a note and a context", ctx("w", note(os())), Some(code)),
        ("two notes", note(note(os())), Some(code)),
        ("no code, plain", timed_out(), None),
        ("no code, a context", ctx("w", timed_out()), None),
        ("no code, a note", note(timed_out()), None),
    ];
    for (what, original, expected) in originals {
        let shared = Arc::new(original);

        let handed = crate::error::shared_io(&shared);

        assert_eq!(Report(&handed).to_string(), Report(&*shared).to_string(), "{what}");
        assert_eq!(first_os_code(&handed), expected, "{what}");
        assert_eq!(handed.kind(), shared.kind(), "{what}");
    }
}

/// `first_os_code` finds the OS code of an `Error::Io` wherever the walk from it first meets one: on
/// the `io::Error` itself, or below the context and the note cosca added. Any other variant has
/// none.
#[skuld::test]
fn first_os_code_walks_an_error_io_to_the_first_os_code() {
    let code = if cfg!(windows) { 5 } else { 13 };
    let os = || std::io::Error::from_raw_os_error(code);
    let context = || crate::error::io_context("pidfd_open", os());

    assert_eq!(first_os_code(&Error::Io(os())), Some(code), "bare");
    assert_eq!(first_os_code(&Error::Io(context())), Some(code), "io_context");
    assert_eq!(
        first_os_code(&Error::Io(os()).with_note("while tearing down")),
        Some(code),
        "a note"
    );
    assert_eq!(
        first_os_code(&Error::Io(context()).with_note("while tearing down")),
        Some(code),
        "io_context and a note"
    );
    assert_eq!(
        first_os_code(&Error::Io(std::io::Error::other("no code"))),
        None,
        "no code anywhere"
    );
    assert_eq!(
        first_os_code(&Error::Containment {
            detail: "d".into(),
            source: None
        }),
        None,
        "a variant with no cause"
    );
}

#[skuld::test]
fn first_os_code_walks_the_chain_of_any_variant() {
    let code = if cfg!(windows) { 5 } else { 13 };
    let os = || Arc::new(Error::Io(std::io::Error::from_raw_os_error(code)));
    let context = || {
        Arc::new(Error::Io(crate::error::io_context(
            "pidfd_open",
            std::io::Error::from_raw_os_error(code),
        )))
    };

    let unassessable = Error::Unassessable {
        detail: "d".into(),
        source: Some(os()),
    };
    assert_eq!(first_os_code(&unassessable), Some(code), "Unassessable");
    let leader = Error::NotThreadGroupLeader {
        pid: 1,
        detail: "d".into(),
        source: context(),
    };
    assert_eq!(
        first_os_code(&leader),
        Some(code),
        "NotThreadGroupLeader, under io_context"
    );
    let record = Error::IdentityRecord {
        kind: crate::error::RecordErrorKind::ScopeUnreadable,
        detail: "d".into(),
        source: Some(os()),
    };
    assert_eq!(first_os_code(&record), Some(code), "IdentityRecord");
    let containment = Error::Containment {
        detail: "d".into(),
        source: Some(os()),
    };
    assert_eq!(first_os_code(&containment), Some(code), "Containment");
    let unsupported = Error::Unsupported {
        op: "op".into(),
        platform: "p",
        detail: "d".into(),
        source: Some(os()),
    };
    assert_eq!(first_os_code(&unsupported), Some(code), "Unsupported");
    let elevation = Error::Elevation {
        kind: crate::error::ElevationErrorKind::AuthFailed,
        detail: "d".into(),
        source: Some(os()),
    };
    assert_eq!(first_os_code(&elevation), Some(code), "Elevation");
    let member = Error::MemberNotKilled {
        pid: 1,
        source: Arc::new(Error::Unassessable {
            detail: "d".into(),
            source: Some(os()),
        }),
    };
    assert_eq!(first_os_code(&member), Some(code), "through two causes");
    let no_code = Error::Unassessable {
        detail: "d".into(),
        source: Some(Arc::new(Error::Io(std::io::Error::other("no code")))),
    };
    assert_eq!(first_os_code(&no_code), None, "no code anywhere");
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

#[skuld::test]
fn io_errors_of_any_variant_lists_the_io_errors_of_its_chain() {
    let code = if cfg!(windows) { 5 } else { 13 };
    let os = || std::io::Error::from_raw_os_error(code);
    let leader = Error::NotThreadGroupLeader {
        pid: 1,
        detail: "d".into(),
        source: Arc::new(Error::Io(os())),
    };
    assert!(
        chain(&leader).any(|layer| layer.is::<std::io::Error>()),
        "the chain holds an io::Error"
    );
    assert_eq!(codes_down(&leader), [Some(code)]);
    let member = Error::MemberNotKilled {
        pid: 1,
        source: Arc::new(Error::Io(os())),
    };
    assert_eq!(codes_down(&member), [Some(code)]);
    let bare = Error::Containment {
        detail: "d".into(),
        source: None,
    };
    assert_eq!(codes_down(&bare), []);
}

/// A note keeps every variant and its other fields, appends to the detail, and keeps each `source`.
/// An I/O error keeps its kind, and its OS code as the note's `source`.
#[cfg(unix)]
#[skuld::test]
fn with_note_keeps_each_variant_and_appends() {
    use crate::error::{ElevationErrorKind, RecordErrorKind};
    let os = || std::io::Error::from_raw_os_error(libc::EACCES);
    let cause = || Arc::new(Error::Io(os()));
    let note = "left running";

    let noted = Error::Io(os()).with_note(note);
    assert_eq!(
        first_os_code(&noted),
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
        source: Some(cause()),
    }
    .with_note(note);
    assert!(
        matches!(&e, Error::Unsupported { op, platform: "linux", detail, .. } if op == "op" && detail == "d; left running")
    );
    assert_eq!(first_os_code(&e), Some(libc::EACCES));
    let e = Error::Containment {
        detail: "d".into(),
        source: Some(cause()),
    }
    .with_note(note);
    assert!(matches!(&e, Error::Containment { detail, .. } if detail == "d; left running"));
    assert_eq!(first_os_code(&e), Some(libc::EACCES));
    let e = Error::NoConsole { detail: "d".into() }.with_note(note);
    assert!(matches!(&e, Error::NoConsole { detail } if detail == "d; left running"));
    let e = Error::Elevation {
        kind: ElevationErrorKind::AuthFailed,
        detail: "d".into(),
        source: Some(cause()),
    }
    .with_note(note);
    assert!(matches!(
        &e,
        Error::Elevation { kind: ElevationErrorKind::AuthFailed, detail, .. } if detail == "d; left running"
    ));
    assert_eq!(first_os_code(&e), Some(libc::EACCES));
    let e = Error::Unassessable {
        detail: "d".into(),
        source: Some(cause()),
    }
    .with_note(note);
    assert!(matches!(&e, Error::Unassessable { detail, .. } if detail == "d; left running"));
    assert_eq!(first_os_code(&e), Some(libc::EACCES));
    let e = Error::NotThreadGroupLeader {
        pid: 7,
        detail: "d".into(),
        source: cause(),
    }
    .with_note(note);
    assert!(matches!(&e, Error::NotThreadGroupLeader { pid: 7, detail, .. } if detail == "d; left running"));
    assert_eq!(first_os_code(&e), Some(libc::EACCES));
    let e = Error::IdentityRecord {
        kind: RecordErrorKind::ForeignPlatform,
        detail: "d".into(),
        source: Some(cause()),
    }
    .with_note(note);
    assert!(matches!(
        &e,
        Error::IdentityRecord { kind: RecordErrorKind::ForeignPlatform, detail, .. } if detail == "d; left running"
    ));
    assert_eq!(first_os_code(&e), Some(libc::EACCES));
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
            source: Arc::new(Error::Io(std::io::Error::other("cause"))),
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
        source: Arc::new(Error::Io(std::io::Error::other("cause"))),
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
        source: Arc::new(Error::Containment {
            detail: "x".into(),
            source: None,
        }),
        unreaped: Some(exited_unreaped(id)),
    }
    .with_note("front left");
    let Error::MayHaveStarted { source, unreaped, .. } = &error else {
        panic!("expected MayHaveStarted, got {error:?}");
    };
    assert_eq!(unreaped.as_ref().map(|child| child.pid()), Some(Some(id.pid())));
    assert!(
        matches!(**source, Error::Containment { ref detail, .. } if detail == "x; front left"),
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

/// A mapped `NTSTATUS` becomes its Win32 code, so `kind()` classifies it.
#[cfg(windows)]
#[skuld::test]
fn nt_io_error_maps_a_status_to_its_win32_code() {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, STATUS_ACCESS_DENIED};
    let e = crate::error::nt_io_error(STATUS_ACCESS_DENIED);
    assert_eq!(e.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32));
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
}

/// `0xC0FFEE01` is a made-up error status (a facility and code Microsoft never assigned), which
/// `RtlNtStatusToDosError` has no Win32 code for: it maps to `ERROR_MR_MID_NOT_FOUND`, and the
/// status is logged at `debug`, as it is kept nowhere else.
#[cfg(windows)]
#[skuld::test]
fn nt_io_error_logs_a_status_with_no_win32_code() {
    use windows::Win32::Foundation::{ERROR_MR_MID_NOT_FOUND, NTSTATUS};
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let e = crate::error::nt_io_error(NTSTATUS(0xC0FF_EE01u32 as i32));
    assert_eq!(e.raw_os_error(), Some(ERROR_MR_MID_NOT_FOUND.0 as i32));
    let levels = crate::log_capture::levels_since(mark, "0xc0ffee01");
    assert_eq!(levels, [log::Level::Debug], "one debug record names the status");
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

/// A test error that says one layer and has a cause.
#[derive(Debug)]
struct Layer(&'static str, Option<Box<Layer>>);

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Layer {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.1.as_deref().map(|l| l as _)
    }
}

#[skuld::test]
fn report_joins_every_layer_with_a_colon() {
    let e = Layer(
        "outer",
        Some(Box::new(Layer("middle", Some(Box::new(Layer("inner", None)))))),
    );
    assert_eq!(Report(&e).to_string(), "outer: middle: inner");
}

/// A layer that says nothing still takes its place: the joins around it stay.
#[skuld::test]
fn report_keeps_a_layer_whose_display_is_empty() {
    let e = Layer("outer", Some(Box::new(Layer("", Some(Box::new(Layer("inner", None)))))));
    assert_eq!(Report(&e).to_string(), "outer: : inner");
}

#[skuld::test]
fn report_of_a_leaf_is_its_display() {
    let leaf = Error::Containment {
        detail: "d".into(),
        source: None,
    };
    assert_eq!(Report(&leaf).to_string(), leaf.to_string());
}

#[skuld::test]
fn report_of_an_io_error_with_context_prints_the_context_and_the_os_error() {
    let code = if cfg!(windows) { 5 } else { 13 };
    let os = std::io::Error::from_raw_os_error(code);
    let os_text = os.to_string();
    let e = Error::Io(crate::error::io_context("pidfd_open", os));
    let report = Report(&e).to_string();
    assert!(report.starts_with("pidfd_open: "), "{report}");
    assert!(report.ends_with(&os_text), "{report}");
    assert_eq!(
        chain(&e).last().map(ToString::to_string),
        Some(os_text),
        "the last layer is the OS error"
    );
}

// Compound errors: `Failures`, `Several`, `MembersLeft` -----

/// Three OS codes that name three different failures on this platform.
const CODES: [i32; 3] = if cfg!(windows) { [5, 2, 3] } else { [13, 2, 1] };

fn os_text(code: i32) -> String {
    std::io::Error::from_raw_os_error(code).to_string()
}

fn coded(code: i32) -> Arc<Error> {
    Error::io_cause(std::io::Error::from_raw_os_error(code))
}

fn several(codes: &[i32]) -> Error {
    Error::Several(failures_of(codes.iter().map(|&code| coded(code))))
}

fn failures_of(members: impl IntoIterator<Item = Arc<Error>>) -> Failures {
    Failures::collect(members).expect("a member")
}

fn not_killed(pid: u32, source: Arc<Error>) -> Arc<Error> {
    Arc::new(Error::MemberNotKilled { pid, source })
}

/// Mutant: `iter` skips the first member, or `first` is another than the first.
#[skuld::test]
fn failures_hold_their_members_in_order_with_the_count_from_iter() {
    let members = failures_of(CODES.map(coded));
    assert_eq!(members.iter().len(), 3);
    assert!(Arc::ptr_eq(members.first(), members.iter().next().expect("a member")));
    let codes: Vec<_> = members.iter().map(|m| first_os_code(&**m)).collect();
    assert_eq!(codes, CODES.map(Some));
    assert!(
        Failures::collect(std::iter::empty()).is_none(),
        "an empty list is not built"
    );
}

/// Mutant: one failure is wrapped in a `Several`, which is for two or more.
#[skuld::test]
fn one_failure_is_its_own_cause_and_two_or_more_are_a_several() {
    let one = coded(CODES[0]);
    let cause = failures_of([Arc::clone(&one)]).into_cause();
    assert!(Arc::ptr_eq(&cause, &one), "{cause:?}");

    let cause = failures_of([coded(CODES[0]), coded(CODES[1])]).into_cause();
    let Error::Several(members) = &*cause else {
        panic!("expected Several, got {cause:?}");
    };
    assert_eq!(members.iter().len(), 2);
}

#[skuld::test]
fn a_several_says_its_count_and_its_source_is_the_first_member() {
    let e = several(&CODES);
    assert_eq!(e.to_string(), "3 failures");
    let source = std::error::Error::source(&e)
        .and_then(|source| source.downcast_ref::<Error>())
        .expect("the first member");
    let Error::Several(members) = &e else { unreachable!() };
    assert!(std::ptr::eq(source, &**members.first()));
}

#[skuld::test]
fn members_left_says_its_count_and_its_source_is_the_first_member() {
    let e = Error::MembersLeft {
        members: failures_of([not_killed(7, coded(CODES[0])), not_killed(9, coded(CODES[1]))]),
        unwalked: None,
    };
    assert_eq!(e.to_string(), "2 members of the tree were left running");
    let source = std::error::Error::source(&e).expect("the first member");
    assert!(
        matches!(
            source.downcast_ref::<Error>(),
            Some(Error::MemberNotKilled { pid: 7, .. })
        ),
        "{source:?}"
    );
}

/// The walk that could not be made is no member: the count is of `members`, and one is not "1 members".
/// Mutants: the count includes the unwalked error; the singular is not worded.
#[skuld::test]
fn members_left_counts_its_members_not_the_walk_that_was_not_made() {
    let one = Error::MembersLeft {
        members: failures_of([not_killed(7, coded(CODES[0]))]),
        unwalked: Some(walk_not_made()),
    };
    assert_eq!(one.to_string(), "1 member of the tree was left running");
    let two = Error::MembersLeft {
        members: failures_of([not_killed(7, coded(CODES[0])), not_killed(9, coded(CODES[1]))]),
        unwalked: Some(walk_not_made()),
    };
    assert_eq!(two.to_string(), "2 members of the tree were left running");
}

fn walk_not_made() -> Arc<Error> {
    Arc::new(Error::Unassessable {
        detail: "the table could not be read".into(),
        source: None,
    })
}

#[skuld::test]
fn the_os_code_of_a_compound_error_is_the_first_members() {
    assert_eq!(first_os_code(&several(&[CODES[1], CODES[0]])), Some(CODES[1]));
    let left = Error::MembersLeft {
        members: failures_of([not_killed(7, coded(CODES[2])), not_killed(9, coded(CODES[0]))]),
        unwalked: None,
    };
    assert_eq!(first_os_code(&left), Some(CODES[2]));
    let left = Error::MembersLeft {
        members: failures_of([not_killed(7, coded(CODES[2]))]),
        unwalked: Some(walk_not_made()),
    };
    assert_eq!(first_os_code(&left), Some(CODES[2]));
}

/// The members of a `MembersLeft` are only `MemberNotKilled`s: what the walk could not do is `unwalked`.
///
/// Mutant: the constructor takes any error as a member, or drops the contract.
#[skuld::test]
#[cfg_attr(debug_assertions, should_panic(expected = "is a MemberNotKilled"))]
fn a_members_left_of_an_error_that_is_no_member_is_a_contract_breach() {
    let _ = Error::members_left(failures_of([walk_not_made()]), None);
}

/// Mutant: `Report` follows `source()` only, so it prints the first member's chain and none of the others.
#[skuld::test]
fn report_of_a_several_prints_every_members_chain() {
    let [a, b] = [os_text(CODES[0]), os_text(CODES[1])];
    assert_eq!(
        Report(&several(&[CODES[0], CODES[1]])).to_string(),
        format!("2 failures: (1) {a}: {a}; (2) {b}: {b}")
    );
}

#[skuld::test]
fn report_of_members_left_prints_every_members_chain() {
    let [a, b] = [os_text(CODES[0]), os_text(CODES[1])];
    let left = Error::MembersLeft {
        members: failures_of([not_killed(7, coded(CODES[0])), not_killed(9, coded(CODES[1]))]),
        unwalked: None,
    };
    assert_eq!(
        Report(&left).to_string(),
        format!(
            "2 members of the tree were left running: (1) pid 7 was not killed: {a}: {a}; \
             (2) pid 9 was not killed: {b}: {b}"
        )
    );
}

/// The walk that could not be made follows the members, not numbered among them.
///
/// Mutant: `Report` leaves `unwalked` out, or numbers it as a member.
#[skuld::test]
fn report_of_members_left_with_an_unwalked_error_prints_it_after_the_members() {
    let [a, b] = [os_text(CODES[0]), os_text(CODES[1])];
    let left = Error::MembersLeft {
        members: failures_of([not_killed(7, coded(CODES[0])), not_killed(9, coded(CODES[1]))]),
        unwalked: Some(walk_not_made()),
    };
    assert_eq!(
        Report(&left).to_string(),
        format!(
            "2 members of the tree were left running: (1) pid 7 was not killed: {a}: {a}; \
             (2) pid 9 was not killed: {b}: {b}; \
             walk not made: could not determine the target process's state: the table could not be read"
        )
    );
}

/// A list inside a member's chain reads in brackets, so the `;` between its members is not taken
/// for the outer list's.
#[skuld::test]
fn report_of_a_list_in_a_member_brackets_the_inner_list() {
    let [a, b, c] = CODES.map(os_text);
    let inner = Arc::new(several(&[CODES[0], CODES[1]]));
    let left = Error::MembersLeft {
        members: failures_of([not_killed(7, inner), not_killed(9, coded(CODES[2]))]),
        unwalked: None,
    };
    assert_eq!(
        Report(&left).to_string(),
        format!(
            "2 members of the tree were left running: \
             (1) pid 7 was not killed: 2 failures: [(1) {a}: {a}; (2) {b}: {b}]; \
             (2) pid 9 was not killed: {c}: {c}"
        )
    );
}

/// The list is below the site's own variant: its layer's text comes first, and every member after it.
#[skuld::test]
fn report_of_a_several_under_a_variant_prints_the_variant_then_every_member() {
    let [a, b] = [os_text(CODES[0]), os_text(CODES[1])];
    let e = Error::Unassessable {
        detail: "d".into(),
        source: Some(Arc::new(several(&[CODES[0], CODES[1]]))),
    };
    assert_eq!(
        Report(&e).to_string(),
        format!("could not determine the target process's state: d: 2 failures: (1) {a}: {a}; (2) {b}: {b}")
    );
}

fn codes_of(list: &Failures) -> Vec<Option<i32>> {
    list.iter().map(|member| first_os_code(&**member)).collect()
}

/// The other failures of an operation join the error it returns, below its variant, after its own
/// cause. Mutants: the variant changes; the own cause is dropped or comes after the peers; the
/// detail takes the peers' text.
#[skuld::test]
fn peers_join_the_own_cause_in_a_several_under_the_same_variant() {
    let e = Error::Unassessable {
        detail: "d".into(),
        source: Some(coded(CODES[0])),
    }
    .with_peers([coded(CODES[1]), coded(CODES[2])]);
    let Error::Unassessable {
        detail,
        source: Some(source),
    } = &e
    else {
        panic!("the variant is kept: {e:?}");
    };
    assert_eq!(detail, "d");
    let Error::Several(list) = &**source else {
        panic!("expected Several, got {source:?}");
    };
    assert_eq!(codes_of(list), CODES.map(Some));
    assert_eq!(first_os_code(&e), Some(CODES[0]));
}

/// With no cause of its own and one peer, the peer is the cause: a list is for two or more.
#[skuld::test]
fn one_peer_and_no_own_cause_makes_the_peer_the_cause() {
    let e = Error::Containment {
        detail: "d".into(),
        source: None,
    }
    .with_peers([coded(CODES[1])]);
    let Error::Containment {
        source: Some(source), ..
    } = &e
    else {
        panic!("{e:?}");
    };
    assert!(
        matches!(&**source, Error::Io(io) if io.raw_os_error() == Some(CODES[1])),
        "{source:?}"
    );
}

#[skuld::test]
fn peers_join_a_member_not_killed_and_a_several() {
    let e = Error::MemberNotKilled {
        pid: 7,
        source: coded(CODES[0]),
    }
    .with_peers([coded(CODES[1])]);
    let Error::MemberNotKilled { pid: 7, source } = &e else {
        panic!("{e:?}");
    };
    assert!(matches!(&**source, Error::Several(list) if codes_of(list) == [Some(CODES[0]), Some(CODES[1])]));

    let e = several(&[CODES[0], CODES[1]]).with_peers([coded(CODES[2])]);
    assert!(
        matches!(&e, Error::Several(list) if codes_of(list) == CODES.map(Some)),
        "{e:?}"
    );
}

/// An `Error::Io`, `Quote` and `NoConsole` have no cause to hold peers: a site that can have peers
/// returns a variant that has one, so giving them some is a contract breach, not a silent drop.
///
/// Mutant: `with_peers` returns a leaf as it is, or drops the contract.
#[skuld::test]
#[cfg_attr(debug_assertions, should_panic(expected = "has no cause to hold peers"))]
fn with_peers_on_an_io_error_is_a_contract_breach() {
    let _ = Error::Io(std::io::Error::from_raw_os_error(CODES[0])).with_peers([coded(CODES[1])]);
}

#[skuld::test]
#[cfg_attr(debug_assertions, should_panic(expected = "has no cause to hold peers"))]
fn with_peers_on_a_no_console_error_is_a_contract_breach() {
    let _ = Error::NoConsole { detail: "d".into() }.with_peers([coded(CODES[1])]);
}

#[skuld::test]
#[cfg_attr(debug_assertions, should_panic(expected = "has no cause to hold peers"))]
fn with_peers_on_a_quote_error_is_a_contract_breach() {
    let _ = Error::Quote(QuoteError::new(7, QuoteErrorKind::TrailingBackslash)).with_peers([coded(CODES[1])]);
}

/// The members of a `MembersLeft` are a walk's: peers appended to it would read as members left running.
///
/// Mutant: `with_peers` adds them as members, or drops the contract.
#[skuld::test]
#[cfg_attr(debug_assertions, should_panic(expected = "are a walk's members"))]
fn with_peers_on_members_left_is_a_contract_breach() {
    let _ = Error::MembersLeft {
        members: failures_of([not_killed(7, coded(CODES[0]))]),
        unwalked: None,
    }
    .with_peers([coded(CODES[1])]);
}

/// A note goes in a site's own variant. A list has no detail of its own to carry one.
///
/// Mutant: `with_note` appends to a compound error as it does to the others, or drops the contract.
#[skuld::test]
#[cfg_attr(debug_assertions, should_panic(expected = "never to a compound error"))]
fn with_note_on_a_several_is_a_contract_breach() {
    let _ = several(&CODES).with_note("n");
}

#[skuld::test]
#[cfg_attr(debug_assertions, should_panic(expected = "never to a compound error"))]
fn with_note_on_members_left_is_a_contract_breach() {
    let left = Error::MembersLeft {
        members: failures_of([not_killed(7, coded(CODES[0]))]),
        unwalked: None,
    };
    let _ = left.with_note("n");
}

#[skuld::test]
#[cfg_attr(debug_assertions, should_panic(expected = "never to a compound error"))]
fn with_note_on_a_member_not_killed_is_a_contract_breach() {
    let _ = Error::MemberNotKilled {
        pid: 7,
        source: coded(CODES[0]),
    }
    .with_note("n");
}
