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
    /// An unprivileged parent could not signal or stop its elevated child: the OS refused the
    /// signal (EPERM on POSIX, ACCESS_DENIED on Windows), or the tracked process is a front (see
    /// [`Child::kill`](crate::Child::kill)), so nothing was sent. `detail` says which, and whether
    /// the child is still running.
    #[error("could not signal or stop an elevated child")]
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
    ///
    /// # A refused `pidfd_open` on Linux
    ///
    /// Every Linux operation that observes or signals a process by identity needs a pidfd
    /// (kernel 5.3 or later): [`Process::wait`](crate::Process::wait),
    /// [`wait_timeout`](crate::Process::wait_timeout), [`kill`](crate::Process::kill),
    /// [`terminate`](crate::Process::terminate), the `graceful_shutdown*` family, and their
    /// `tokio` twins. When `pidfd_open` is refused they fail with this variant,
    /// with `op` naming the operation that needed it (`process wait`, `process kill`,
    /// `process terminate`) and `detail` naming the errno.
    ///
    /// - `ENOSYS`: the kernel predates 5.3, or a seccomp filter hides the syscall.
    /// - `EPERM` and `EACCES`: the kernel's own `pidfd_open` never returns them, so a seccomp
    ///   filter or an LSM is answering.
    /// - `ENODEV`: documented by `pidfd_open(2)` for a kernel without the anonymous-inode
    ///   filesystem. Such a kernel fails at boot, so in practice a filter or LSM is answering;
    ///   either way no pidfd is possible.
    ///
    /// Any other failure is transient and surfaces as [`Error::Io`], prefixed `pidfd_open:`
    /// (`EMFILE`, `ENFILE`, `ENOMEM`).
    ///
    /// `spawn` (sync and `tokio`) needs a pidfd for its child too, and gets it before the
    /// program can run. It first calls `pidfd_open` on its own process: a refusal is this
    /// variant with `op` `spawn`, and no child was forked. The child then opens a pidfd on itself
    /// before `exec` and sends it to the parent; if its `pidfd_open` fails the child never runs
    /// the program and the failure is this variant (a refusal) or [`Error::Io`] (a transient
    /// failure).
    ///
    /// A process that is gone (`ESRCH`, or `EINVAL`/`ENOENT`
    /// for a non-leader thread) is not an error: the operation reports it as exited.
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
    ///
    /// **A spawn that fails this way may have started the program.** On macOS an identity that
    /// becomes unreadable after the program started leaves the child running (a warning names its
    /// pid), so retrying may start a second instance. Elsewhere the child is torn down, unless its
    /// kill is refused. The exception is a macOS child that could not read its own unique id: it is
    /// stopped before `exec`, and the program did not start.
    ///
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
    /// The pid names a live thread that is not its process's thread-group leader, so it is not
    /// a process that can be waited on or signalled as one (on Linux, `pidfd_open` refuses it).
    /// Not "gone": the thread is running. `source` is the OS error that refused it; compare
    /// [`raw_os_error`](std::io::Error::raw_os_error), not the message.
    #[error("pid {pid} names a live thread, not a thread-group leader; {detail}")]
    NotThreadGroupLeader {
        pid: u32,
        detail: String,
        #[source]
        source: std::io::Error,
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

/// `source` with `context` prepended to its message and kept as the new error's
/// [`source`](std::error::Error::source), so its OS code survives: several codes share one
/// [`std::io::ErrorKind`], and the code is what tells a caller which failure it was.
pub(crate) fn io_context(context: impl Into<String>, source: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        source.kind(),
        IoContext {
            context: context.into(),
            source,
        },
    )
}

#[derive(Debug)]
struct IoContext {
    context: String,
    source: std::io::Error,
}

impl std::fmt::Display for IoContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.context, self.source)
    }
}

impl std::error::Error for IoContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl Error {
    /// This error with `note` appended to what it says, its variant and kind kept: a caller that
    /// matches on the variant still sees the cause. An [`Error::Io`] keeps its kind, and its
    /// original error as the [`source`](std::error::Error::source), which keeps the OS code.
    #[cfg_attr(not(unix), allow(dead_code, reason = "only the unix spawn teardowns add a note"))]
    pub(crate) fn with_note(self, note: &str) -> Error {
        let append = |detail: String| format!("{detail}; {note}");
        match self {
            Error::Io(source) => Error::Io(std::io::Error::new(
                source.kind(),
                IoNote {
                    note: note.to_owned(),
                    source,
                },
            )),
            Error::Unsupported { op, platform, detail } => Error::Unsupported {
                op,
                platform,
                detail: append(detail),
            },
            Error::Containment { detail } => Error::Containment { detail: append(detail) },
            Error::NoConsole { detail } => Error::NoConsole { detail: append(detail) },
            Error::Elevation { kind, detail } => Error::Elevation {
                kind,
                detail: append(detail),
            },
            Error::Unassessable { detail, source } => Error::Unassessable {
                detail: append(detail),
                source,
            },
            Error::NotThreadGroupLeader { pid, detail, source } => Error::NotThreadGroupLeader {
                pid,
                detail: append(detail),
                source,
            },
            Error::IdentityRecord { kind, detail, source } => Error::IdentityRecord {
                kind,
                detail: append(detail),
                source,
            },
            Error::Quote(e) => {
                debug_assert!(
                    false,
                    "a note is added only to a spawn's error, never a quoting one: {e}"
                );
                Error::Quote(e)
            }
        }
    }
}

/// An I/O error with a note after its message; the error itself is the source.
#[derive(Debug)]
struct IoNote {
    note: String,
    source: std::io::Error,
}

impl std::fmt::Display for IoNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; {}", self.source, self.note)
    }
}

impl std::error::Error for IoNote {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
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
