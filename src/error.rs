//! Crate error taxonomy. Extended by later plans (spawn, containment, identity).

/// Why splitting a command line failed. `pos` is a 0-based byte offset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind} at offset {pos}")]
pub struct QuoteError {
    pub pos: usize,
    pub kind: QuoteErrorKind,
}

impl QuoteError {
    pub(crate) fn new(pos: usize, kind: QuoteErrorKind) -> Self {
        QuoteError { pos, kind }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QuoteErrorKind {
    #[error("unterminated single quote")]
    UnterminatedSingleQuote,
    #[error("unterminated double quote")]
    UnterminatedDoubleQuote,
    #[error("trailing backslash")]
    TrailingBackslash,
}

/// The crate's top-level error type. Grows as later plans add fallible operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("argument parsing failed: {0}")]
    Quote(#[from] QuoteError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An operation isn't available on this platform / in this build.
    #[error("{op} is not supported on {platform}: {detail}")]
    Unsupported {
        op: String,
        platform: &'static str,
        detail: String,
    },
    /// A containment mechanism could not be established or torn down.
    #[error("process containment failed: {detail}")]
    Containment { detail: String },
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod error_tests;
