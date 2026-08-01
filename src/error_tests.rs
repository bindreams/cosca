use crate::error::{Error, QuoteError, QuoteErrorKind};

#[test]
fn containment_error_displays_detail() {
    let e = Error::Containment {
        detail: "cgroup leaf not writable".into(),
    };
    assert!(e.to_string().contains("cgroup leaf not writable"), "{e}");
}

#[test]
fn quote_error_displays_kind_and_offset() {
    let e = QuoteError::new(7, QuoteErrorKind::UnterminatedSingleQuote);
    assert_eq!(e.to_string(), "unterminated single quote at offset 7");
}

#[test]
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

#[test]
fn error_wraps_quote_error_via_from() {
    let e: Error = QuoteError::new(0, QuoteErrorKind::TrailingBackslash).into();
    assert!(matches!(e, Error::Quote(_)));
    assert!(e.to_string().contains("trailing backslash"));
}

#[test]
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

#[test]
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

#[test]
fn command_too_long_names_the_host_not_the_platform() {
    // The wording matters: this verdict is per-host and per-command, so it must not
    // read like a permanent platform limitation.
    let m = crate::error::ElevationErrorKind::CommandTooLong.to_string();
    assert_eq!(m, "the elevation command is too long for this host");
}

#[test]
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

#[test]
fn untracked_message_does_not_assert_termination() {
    // The kind's Display is neutral; termination status lives in `detail`.
    use crate::error::ElevationErrorKind::Untracked;
    let s = Untracked.to_string();
    assert!(
        !s.contains("terminated"),
        "Untracked Display must not claim termination: {s}"
    );
}

#[test]
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
