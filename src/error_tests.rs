use crate::error::{Error, QuoteError, QuoteErrorKind};

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
    assert_eq!(
        QuoteErrorKind::TrailingBackslash.to_string(),
        "trailing backslash"
    );
}

#[test]
fn error_wraps_quote_error_via_from() {
    let e: Error = QuoteError::new(0, QuoteErrorKind::TrailingBackslash).into();
    assert!(matches!(e, Error::Quote(_)));
    assert!(e.to_string().contains("trailing backslash"));
}
