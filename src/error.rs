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
    /// manage it. Whether it was terminated is reported in the error `detail`. A spawn returns it
    /// inside [`Error::MayHaveStarted`].
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
    /// **From a spawn, this variant comes inside [`Error::MayHaveStarted`] when the program may have
    /// started.** On macOS an identity that becomes unreadable after the program started leaves the
    /// child running (a warning names its pid), so retrying may start a second instance. Elsewhere
    /// the child is torn down, unless its kill is refused. A spawn returns it bare only for a macOS
    /// child that could not read its own unique id: it is stopped before `exec`, and the program did
    /// not start.
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
    /// A spawn failed, and the program may have started: retrying it may run it twice. `source` is
    /// what failed, and `fate` is what the failed spawn did with its child.
    ///
    /// Every error a spawn returns answers whether the program could have started, meaning the
    /// child reached `exec` (on Windows: `CreateProcess` or `ShellExecuteEx` succeeded). This
    /// variant says it may have. Any other variant from a spawn says it did not, and cosca has
    /// proved it. Where cosca cannot prove it, the answer is this variant:
    ///
    /// - every failure after `exec`, such as an identity read, a containment attach, or a password
    ///   write to the elevation backend;
    /// - on Unix, a [`tokio::Command`](crate::tokio::Command) whose child failed between its first
    ///   `pre_exec` hook and `exec` (a failed `exec`, `ENOENT` included, or a failed descriptor
    ///   mapping), and on Windows, any failed spawn of one through `std`: tokio can fail a spawn after
    ///   `std`'s succeeded, and the error does not say which of the two failed;
    /// - on macOS, a child whose unique-id report was not yet written, or could not be read, when
    ///   the spawn looked.
    ///
    /// `Command::output`, `status` and `read`, sync and tokio, return this variant for every
    /// failure after their spawn succeeded. They tear the child down then, as its drop would (see
    /// `kill_on_drop`), and the fate says what that did; `read`'s invalid UTF-8 comes after the exit
    /// was collected (`Reaped`).
    ///
    /// On Windows, a failed `ShellExecuteEx` launch is classified by its error (see `runas_failure`).
    #[error("the program may have started, and {fate}{}: {source}", elevated_note(.fate, *.wrapper_elevated))]
    MayHaveStarted {
        fate: ChildFate,
        /// Whether the child is an elevation backend (`sudo`, `doas`, `pkexec`, `osascript`), whose
        /// elevated program is its own child and may outlive it: `fate` is then about the backend
        /// only (see [`ChildFate`]), and the message says so.
        wrapper_elevated: bool,
        #[source]
        source: Box<Error>,
    },
}

/// What a spawn that failed after its program may have started did with its child: the `fate` of
/// [`Error::MayHaveStarted`] (see [`Error::fate`]).
///
/// It is about the child cosca spawned. On a wrapper-elevated spawn that child is the backend
/// (`sudo`, `doas`, `pkexec`, `osascript`), and the elevated program is its own child, which cosca
/// never signals: `Reaped`, `Killed` and `Gone` say the backend is not running, not that the program
/// is not. A front that had exited by itself is `Reaped` while the program it launched may still
/// run. Descendants of a contained child are not covered either; the containment's own teardown is.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildFate {
    /// cosca collected the child's exit: it killed the child, or found it had exited, and reaped it.
    /// The child is not running; on a wrapper-elevated spawn, the elevated program may be (see the
    /// type's doc).
    Reaped,
    /// The child is dead or dying, but cosca did not collect its exit, and cosca's kill was delivered
    /// (or the child had exited by itself): the wait for it failed, someone else collected its exit
    /// or holds its zombie after the kill, a Windows child was terminated and not
    /// waited for, a dropped async child was signalled and left to tokio to collect, or a
    /// containment teardown ended it. On a wrapper-elevated spawn, the elevated program may still
    /// run.
    Killed,
    /// The child may still be running: cosca left it alone (an elevation front, which it never
    /// signals, a child it could not show to be its own, or one `kill_on_drop(false)` keeps) or
    /// could not kill it.
    ///
    /// `id` is its identity when the spawn had read one, and `None` when the failure came before
    /// that read (an identity that could not be read, or a macOS report that never came). It is an
    /// identity, not a pin: the child may exit and be reaped, and its pid reused. Check it before acting on it ([`ProcessId::is_alive`], or the
    /// identity-checked kills of [`Process`](crate::Process)); never signal its number by itself.
    ///
    /// [`ProcessId::is_alive`]: crate::identity::ProcessId::is_alive
    Running { id: Option<crate::identity::ProcessId> },
    /// Someone else reaped the child, or its zombie is held by another process (on macOS, launchd
    /// holds a tracer-orphaned child's zombie), so cosca could not collect it, and cosca delivered
    /// no kill: a child that was gone already, or not ours, when cosca came to it. (One cosca killed
    /// and found collected is [`Killed`](ChildFate::Killed).) The child is not running; on a wrapper-elevated spawn, the elevated program may be (see the type's doc).
    Gone,
    /// cosca cannot say what became of the child.
    Unknown,
}

impl std::fmt::Display for ChildFate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChildFate::Reaped => f.write_str("its child was reaped"),
            ChildFate::Killed => f.write_str("its child was killed, its exit not collected"),
            ChildFate::Running { id: Some(id) } => write!(f, "its child, pid {}, may still be running", id.pid()),
            ChildFate::Running { id: None } => f.write_str("its child may still be running"),
            ChildFate::Gone => f.write_str("its child had been reaped by someone else"),
            ChildFate::Unknown => f.write_str("what became of its child is unknown"),
        }
    }
}

/// What [`Error::MayHaveStarted`] appends to the fate of an elevation backend: the elevated program
/// behind it may still run, whenever the fate says the backend is not running.
fn elevated_note(fate: &ChildFate, wrapper_elevated: bool) -> &'static str {
    match fate {
        ChildFate::Reaped | ChildFate::Killed | ChildFate::Gone if wrapper_elevated => {
            " (an elevated program behind it may still run)"
        }
        _ => "",
    }
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
    /// What a failed spawn did with its child, for an error that says the program may have started
    /// ([`Error::MayHaveStarted`]); `None` for any other error, including one that says the program
    /// did not start.
    ///
    /// ```
    /// use cosca::error::{ChildFate, Error};
    ///
    /// fn retry_is_safe(error: &Error) -> bool {
    ///     match error.fate() {
    ///         // The program did not start: running it again runs it once.
    ///         None => true,
    ///         // It may have run, or still be running.
    ///         Some(ChildFate::Running { id: Some(id) }) => {
    ///             eprintln!("pid {} may still be running", id.pid());
    ///             false
    ///         }
    ///         Some(_) => false,
    ///     }
    /// }
    ///
    /// let mut cmd = cosca::Command::new();
    /// cmd.args(["cosca-no-such-program"]);
    /// let error = cmd.spawn().expect_err("no such program");
    /// assert!(retry_is_safe(&error));
    /// ```
    pub fn fate(&self) -> Option<ChildFate> {
        match self {
            Error::MayHaveStarted { fate, .. } => Some(*fate),
            _ => None,
        }
    }

    /// The OS error code of an [`Error::Io`], for a look whose failure is told apart by it.
    #[cfg(any(unix, feature = "tokio"))]
    pub(crate) fn raw_os_error(&self) -> Option<i32> {
        match self {
            Error::Io(e) => e.raw_os_error(),
            _ => None,
        }
    }

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
            Error::MayHaveStarted {
                fate,
                wrapper_elevated,
                source,
            } => Error::MayHaveStarted {
                fate,
                wrapper_elevated,
                source: Box::new(source.with_note(note)),
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
