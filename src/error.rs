//! Crate error taxonomy.

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
#[non_exhaustive]
pub enum QuoteErrorKind {
    #[error("unterminated single quote")]
    UnterminatedSingleQuote,
    #[error("unterminated double quote")]
    UnterminatedDoubleQuote,
    #[error("trailing backslash")]
    TrailingBackslash,
    /// The text is not valid UTF-8, and the target grammar (AppleScript) is
    /// defined over UTF-8 text rather than bytes.
    #[error("not valid UTF-8")]
    NonUtf8,
    /// A character the target grammar cannot express at all.
    #[error("character cannot be represented in this grammar")]
    UnrepresentableChar,
}

/// Runtime elevation failures — "could work here but failed now" (contrast
/// [`Error::Unsupported`], which is "can never work on this platform").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ElevationErrorKind {
    /// The requested (or auto-detected) backend is not on PATH, or the resolved
    /// backend could not be executed.
    #[error("no usable elevation backend is available")]
    BackendUnavailable,
    /// Wrong password, or `sudo -n` found no cached credential, or the launch failed.
    #[error("elevation authentication failed")]
    AuthFailed,
    /// The UAC / GUI prompt was cancelled by the user (Windows `ERROR_CANCELLED`).
    #[error("elevation prompt was declined")]
    AuthDeclined,
    /// Interactive auth requested but there is no controlling terminal to prompt on.
    #[error("no controlling terminal for interactive elevation")]
    NoTty,
    /// An unprivileged parent could not signal its elevated child (EPERM on POSIX,
    /// ACCESS_DENIED on Windows). Whether the child is still running is in `detail`.
    #[error("could not terminate an elevated child: permission denied")]
    Unkillable,
    /// The elevated child launched, but the parent could not resolve its identity to
    /// manage it. Whether it was terminated is reported in the error `detail`.
    #[error("elevated child launched but could not be tracked")]
    Untracked,
    /// The composed elevation command exceeded this host's exec argument budget
    /// (`kern.argmax` on macOS). A property of THIS command on THIS host, not of
    /// the platform: a shorter command, or a host with a larger budget, succeeds.
    #[error("the elevation command is too long for this host")]
    CommandTooLong,
}

/// The crate's top-level error type.
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
    /// Privilege elevation could not be completed at runtime.
    #[error("elevation failed ({kind}): {detail}")]
    Elevation { kind: ElevationErrorKind, detail: String },
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod error_tests;
