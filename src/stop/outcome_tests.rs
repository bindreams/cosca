//! `StopError`: it converts into the `Error` it holds, and shows and chains as that error does.

use std::sync::Arc;

use super::{SendOutcome, StopError};
use crate::error::{Error, Failures, Report};

fn io(text: &str) -> Error {
    Error::Io(std::io::Error::other(text.to_owned()))
}

fn stopped(error: Error) -> StopError {
    StopError::new(error, SendOutcome::NotSent)
}

/// A function that returns an `Error` can `?` a `StopError`, and keeps the error.
fn through_question_mark(stopped: StopError) -> Result<(), Error> {
    Err(stopped)?;
    Ok(())
}

/// `?` and `From` give back the error the action answered, and `error()` lends it.
///
/// Mutant: the conversion builds another error (its text or variant changes).
#[skuld::test]
fn a_stop_error_converts_into_the_error_it_holds() {
    let held = Error::Unsupported {
        op: "the test".into(),
        platform: "test",
        detail: "kept".into(),
        source: None,
    };
    let stop = stopped(held);
    assert!(matches!(stop.error(), Error::Unsupported { detail, .. } if detail == "kept"));
    assert_eq!(stop.outcome(), SendOutcome::NotSent);

    let err = through_question_mark(stop).expect_err("the error passes through");
    assert!(
        matches!(&err, Error::Unsupported { detail, .. } if detail == "kept"),
        "{err:?}"
    );
    let converted: Error = stopped(io("again")).into();
    assert!(matches!(converted, Error::Io(_)));
}

/// `Display`, the `source()` chain and a `Report` of a `StopError` read as those of the error inside it,
/// for an error with a source and for a list, which a `Report` prints in full.
///
/// Mutants: `Display` says something of its own; `source()` is the inner error (the layer shows twice);
/// a `Report` of the layer prints the list's first member only.
#[skuld::test]
fn a_stop_error_shows_and_chains_as_the_error_inside_it() {
    let list = Error::Several(Failures::new(Arc::new(io("first")), [Arc::new(io("second"))]));
    // The inner error's own `Display`, `Report` and `source()` text, as literals.
    let rows = [
        (
            io("one cause"),
            "an I/O operation failed",
            "an I/O operation failed: one cause",
            Some("one cause"),
        ),
        (
            list,
            "2 failures",
            "2 failures: (1) an I/O operation failed: first; (2) an I/O operation failed: second",
            Some("an I/O operation failed"),
        ),
    ];
    for (inner, display, report, source) in rows {
        let stop = stopped(inner);
        assert_eq!(stop.to_string(), display);
        assert_eq!(Report::new(&stop).to_string(), report);
        assert_eq!(
            std::error::Error::source(&stop).map(ToString::to_string).as_deref(),
            source,
            "the source is the inner error's own source"
        );
    }
}
