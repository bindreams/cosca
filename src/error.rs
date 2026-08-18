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

/// Why a [`ProcessIdRecord`](crate::identity::ProcessIdRecord) could not be produced from,
/// or turned back into, a [`ProcessId`](crate::identity::ProcessId).
///
/// No variant says anything about whether the process is running — that is
/// [`ProcessId::is_alive`](crate::identity::ProcessId::is_alive). These are all statements
/// about whether a start token can be *compared* on this host at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecordErrorKind {
    /// The record's format version is not one this build knows how to read.
    #[error("unknown record format version")]
    UnknownVersion,
    /// The record was written on a different OS. Start tokens are not comparable across
    /// platforms — Linux's are boot-relative jiffies, Windows's and macOS's are absolute
    /// timestamps — so a cross-platform comparison is meaningless, not merely wrong.
    #[error("the record was written on a different platform")]
    ForeignPlatform,
    /// The record's pid cannot name a single process on this platform: zero anywhere, or
    /// above `i32::MAX` on Unix, where it would wrap negative and address a whole process
    /// *group*. A restored identity is used for `kill(2)` and `pidfd_open`, so this is
    /// rejected up front rather than left to fail — or, worse, succeed — later.
    #[error("the record's pid cannot name a single process")]
    InvalidPid,
    /// Linux: the record was written in a different boot session, where the jiffy counter
    /// started over. The saved token would alias onto an unrelated process.
    #[error("the record was written in a different boot session")]
    ForeignBootSession,
    /// Linux: the record carries no boot identifier, so its boot session cannot be checked.
    #[error("the record carries no boot session identifier")]
    MissingBootSession,
    /// Linux: the record was written in a different pid namespace, where the same pid
    /// number names a different process.
    #[error("the record was written in a different pid namespace")]
    ForeignPidNamespace,
    /// Linux: the record carries no pid namespace identifier.
    #[error("the record carries no pid namespace identifier")]
    MissingPidNamespace,
    /// This host's own boot session could not be read, so a record could neither be
    /// written nor checked. The only variant that is not about the record's contents; the
    /// failing path and the OS error are in the error's `detail` and `source`.
    #[error("this host's boot session could not be read")]
    ScopeUnreadable,
}

/// The crate's top-level error type.
///
/// `#[non_exhaustive]`: the crate is still growing failure modes, so callers carry a
/// wildcard arm rather than have each new variant break them.
#[non_exhaustive]
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
    /// The calling process has no attached console, so Windows' console-group graceful
    /// signal (`CTRL_BREAK`) cannot be delivered — the caller is a GUI-subsystem binary,
    /// a service, or was spawned detached. Every graceful op that reaches a console group is
    /// affected, lone and tree alike; `kill` and `kill_tree` need no console, and a lone or
    /// nested child that has no `kill_tree` still has `kill`.
    #[error("no attached console for the graceful console-group signal: {detail}")]
    NoConsole { detail: String },
    /// Privilege elevation could not be completed at runtime.
    #[error("elevation failed ({kind}): {detail}")]
    Elevation { kind: ElevationErrorKind, detail: String },
    /// The OS refused to establish whether the target process exists or is running, so the
    /// operation was not performed. Distinct from a failure of the operation: nothing is
    /// known to have gone wrong with the target — the caller was not allowed to look.
    /// Typically an unprivileged caller querying a service, or a parent that cannot open
    /// its own elevated child. Also covers the crate's own refusal to act on a target it
    /// cannot address safely — a pid that names a process *group* rather than a single
    /// process, or one the handle no longer pins against reuse — where nothing was asked of
    /// the OS at all; those carry no `source`.
    #[error("could not determine the target process's state: {detail}")]
    Unassessable {
        detail: String,
        #[source]
        source: Option<std::io::Error>,
    },
    /// A persisted process identity could not be produced or restored — see
    /// [`RecordErrorKind`] for why. `source` carries the OS error when the failure was a
    /// failed read of this host's boot session rather than a rejected record.
    #[error("persisted process identity is not usable here ({kind}): {detail}")]
    IdentityRecord {
        kind: RecordErrorKind,
        detail: String,
        #[source]
        source: Option<std::io::Error>,
    },
}

/// Test-only: assert a user-facing `detail` carries no run of two or more spaces.
///
/// A hard-wrapped string literal that loses its `\` line-continuation bakes the source
/// indentation into the value, and both a variant match and a substring check read right past
/// it. This is the one assertion that sees it.
// Windows-gated with its callers: every refusal detail it guards is behind `cfg(windows)`, so
// off Windows it would be a `pub(crate)` item with no caller, which `-D warnings` rejects.
#[cfg(all(test, windows))]
pub(crate) fn assert_detail_is_not_hard_wrapped(detail: &str) {
    assert!(
        !detail.contains("  "),
        "a run of two or more spaces means a hard-wrapped literal lost its `\\` continuation: {detail:?}"
    );
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod error_tests;
