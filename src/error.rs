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
/// about whether a saved token can be *compared* on this host at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecordErrorKind {
    /// The record's format version is not one this build knows how to read.
    #[error("unknown record format version")]
    UnknownVersion,
    /// The record was written on a different OS. Start tokens are not comparable across
    /// platforms — Linux's are per-boot values (a pidfd inode or boot-relative jiffies), Windows's
    /// and macOS's are absolute timestamps — so a cross-platform comparison is meaningless, not
    /// merely wrong.
    #[error("the record was written on a different platform")]
    ForeignPlatform,
    /// The record's pid cannot name a single process on this platform: zero anywhere, or
    /// above `i32::MAX` on Unix, where it would wrap negative and address a whole process
    /// *group*. A restored identity is used for `kill(2)` and `pidfd_open`, so this is
    /// rejected up front rather than left to fail — or, worse, succeed — later.
    #[error("the record's pid cannot name a single process")]
    InvalidPid,
    /// Linux: the record was written in a different boot session, where the token's counter (the
    /// pidfd inodes, the jiffies) started over. The saved token would alias onto an unrelated
    /// process.
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
    /// Linux: the record's token is of another kind than this host's: a `pidfs` inode where this
    /// host's pidfds have none, or a `starttime` where they do. The two are never comparable, so
    /// the saved token would alias onto an unrelated process. A kind this build does not know is
    /// this too.
    #[error("the record's token is of another kind than this host's")]
    ForeignTokenKind,
    /// Linux: the record carries no kind of token, so it cannot be told which this is.
    #[error("the record carries no kind of token")]
    MissingTokenKind,
    /// This host's own boot session, or on Linux its kind of token (read from its own pidfd), could
    /// not be read, so a record could neither be
    /// written nor checked. The only variant that is not about the record's contents; the
    /// failing path and the OS error are in the error's `detail` and `source`.
    #[error("this host's boot session could not be read")]
    ScopeUnreadable,
}

/// The crate's top-level error type.
///
/// `#[non_exhaustive]`: the crate is still growing failure modes, so callers carry a
/// wildcard arm rather than have each new variant break them.
///
/// # The OS code
///
/// The OS code of a failure may sit on an `io::Error` down the `source()` chain of any variant,
/// below context cosca added: walk `source()` and take the first `io::Error` whose
/// `raw_os_error()` is `Some`.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("argument parsing failed: {0}")]
    Quote(#[from] QuoteError),
    /// An I/O error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// An operation isn't available on this platform / in this build.
    ///
    /// # A refused `pidfd_open` on Linux
    ///
    /// Every Linux operation that opens a process by identity needs a pidfd (kernel 5.3 or
    /// later): [`Process::open`](crate::Process::open), [`open_pid`](crate::Process::open_pid)
    /// and [`current`](crate::Process::current), their `tokio` twins, and the by-identity acts of
    /// a [`tokio::Child`](crate::tokio::Child) (`terminate`, `graceful_shutdown`). A
    /// [`Child`](crate::Child) acts through its own handle and needs none. When
    /// `pidfd_open` is refused they fail with this variant, with `op` `process open` and
    /// `detail` naming the errno. An open [`Process`](crate::Process) holds its pidfd, so none of
    /// its acts can be refused later.
    ///
    /// - `ENOSYS`: the kernel predates 5.3, or a seccomp filter hides the syscall.
    /// - `EPERM` and `EACCES`: the kernel's own `pidfd_open` never returns them, so a seccomp
    ///   filter or an LSM is answering.
    /// - `ENODEV`: documented by `pidfd_open(2)` for a kernel without the anonymous-inode
    ///   filesystem. Such a kernel fails at boot, so in practice a filter or LSM is answering;
    ///   either way no pidfd is possible.
    ///
    /// Only a failed `pidfd_open` is refused. Any other failure is [`Error::Io`] prefixed with the
    /// call's name (`pidfd_open:`, `pidfs_ino:`, `poll:`).
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
        #[source]
        source: Option<Box<Error>>,
    },
    /// A containment mechanism could not be established or torn down.
    #[error("process containment failed: {detail}")]
    Containment {
        detail: String,
        #[source]
        source: Option<Box<Error>>,
    },
    /// The calling process has no attached console, so Windows' console-group graceful
    /// signal (`CTRL_BREAK`) cannot be delivered — the caller is a GUI-subsystem binary,
    /// a service, or was spawned detached. Every graceful op that reaches a console group is
    /// affected, lone and tree alike; `kill` and `kill_tree` need no console, and a lone or
    /// nested child that has no `kill_tree` still has `kill`.
    #[error("no attached console for the graceful console-group signal: {detail}")]
    NoConsole { detail: String },
    /// Privilege elevation could not be completed at runtime.
    #[error("elevation failed ({kind}): {detail}")]
    Elevation {
        kind: ElevationErrorKind,
        detail: String,
        #[source]
        source: Option<Box<Error>>,
    },
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
        source: Option<Box<Error>>,
    },
    /// A tree-walk kill left a member running: it killed what it could, and `pid`, the first member
    /// it left behind, was not. `source` says why: the member's identity could not be read, at the
    /// walk or when the kill came ([`Error::Unassessable`], or [`Error::Unsupported`] when the OS
    /// refuses the pidfd the identity is read through), or the OS refused the kill
    /// ([`Error::Io`], whose [`raw_os_error`](std::io::Error::raw_os_error) is the refusal's code, as
    /// for [`Process::kill`](crate::Process::kill)). It names the first member left; the call warns of
    /// the others. The root is named only when it is the sole member left. On Linux, any other
    /// error that opening the member's pidfd finishes with (a live thread that leads no group, a
    /// `poll` that reports `POLLERR`) is wrapped as [`Error::Unassessable`], the error its source.
    ///
    /// Comes from the `TreeWalk` mechanism's `kill_tree` and `graceful_shutdown_tree`, and from
    /// [`Process::kill_tree`](crate::Process::kill_tree) and its `graceful_shutdown_tree`, which walk
    /// the tree. A `TreeWalk` handle's retry kills the members it left again by identity, and a member
    /// whose identity was never read is reported again. `Process::kill_tree` walks again.
    ///
    /// **macOS.** There [`ContainMode::TreeWalk`](crate::ContainMode::TreeWalk) is the fd marker's
    /// sweep, which reports a member it could not reach as [`Error::Containment`] or
    /// [`Error::Unassessable`] without a `source`. This variant comes from the ppid walk alone:
    /// `Process::kill_tree`, and a `TreeWalk` handle on Linux and Windows.
    #[error("pid {pid} was not killed: {source}{}", .note.as_deref().map(|note| format!("; {note}")).unwrap_or_default())]
    MemberNotKilled {
        pid: u32,
        #[source]
        source: Box<Error>,
        /// What the spawn's cleanup adds of the child's fate, when it is the one that returns the
        /// error. It leaves `source` as it is, which keeps the refusal's OS error.
        note: Option<String>,
    },
    /// The pid names a live thread that is not its process's thread-group leader, so it is not
    /// a process that can be waited on or signalled as one (on Linux, `pidfd_open` refuses it).
    /// Not "gone": the thread is running. `source` is the refusal, an [`Error::Io`]; compare its OS
    /// code (`raw_os_error` down the chain), not the message.
    #[error("pid {pid} names a live thread, not a thread-group leader; {detail}")]
    NotThreadGroupLeader {
        pid: u32,
        detail: String,
        #[source]
        source: Box<Error>,
    },
    /// A persisted process identity could not be produced or restored — see
    /// [`RecordErrorKind`] for why. `source` carries the OS error when the failure was a
    /// failed read of this host's boot session rather than a rejected record.
    #[error("persisted process identity is not usable here ({kind}): {detail}")]
    IdentityRecord {
        kind: RecordErrorKind,
        detail: String,
        #[source]
        source: Option<Box<Error>>,
    },
    /// A spawn failed, and the program may have started: retrying it may run it twice. `source` is
    /// what failed, and `fate` is what the failed spawn did with its child.
    ///
    /// Every error a spawn returns answers whether the program could have started, meaning the
    /// child reached `exec` (on Windows: `CreateProcess` or `ShellExecuteEx` succeeded). This
    /// variant says it may have. Any other variant from a spawn says it did not, and cosca has
    /// proved it. Where cosca cannot prove it, the answer is this variant:
    ///
    /// - every failure after `exec`, such as an identity read that finds the child gone, a
    ///   containment attach (one that needs the child's identity fails with the error of the read
    ///   the OS refused), or a password write to the elevation backend;
    /// - on macOS, a child whose unique-id report was not yet written, or could not be read, when
    ///   the spawn looked.
    ///
    /// `Command::output`, `status` and `read`, sync and tokio, return this variant for every
    /// failure after their spawn succeeded. They tear the child down then, as its drop would (see
    /// `kill_on_drop`), and the fate says what that did; `read`'s invalid UTF-8 comes after the exit
    /// was collected (`Reaped`). When their teardown cannot end the child (a refused kill, or an
    /// elevation front, which is sent none) and it is not known to have been collected, they
    /// return it in `unreaped`; a tokio method's is dropped without blocking (see
    /// [`Unreaped`](crate::Unreaped)). [`SuspendedChild::resume`](crate::SuspendedChild::resume)
    /// and its tokio twin do not, for the frozen child they could not kill after a failed
    /// release: they leave it running and warn, with `unreaped` `None` and `fate` `Running`, since
    /// that thread may stay frozen, so waiting for the child could block for ever. The split by
    /// arm is in `resume`'s `# Errors`.
    ///
    /// A failed spawn, sync or tokio, hands back the child when the spawn or run could not end it:
    /// on Linux, when the identity read or the attach fails after the handshake, on every Unix,
    /// when the elevation backend's password write fails, and on Windows, when a
    /// `kill_on_drop(false)` child's job refuses the disarm and the kill that follows is refused
    /// too. The other failed spawns leave a child they could not end running and warn.
    ///
    /// On Windows, a failed `ShellExecuteEx` launch is classified by its error (see `runas_failure`).
    #[error("the program may have started, and {fate}{}: {source}", elevated_note(.fate, *.wrapper_elevated))]
    MayHaveStarted {
        fate: ChildFate,
        /// Whether the child is an elevation front (`sudo`, `doas`, `osascript`), whose elevated
        /// program may outlive it: `fate` is then about the front only (see [`ChildFate`]), and the
        /// message says so. A pkexec child is the program itself, so this is `false` for it.
        wrapper_elevated: bool,
        #[source]
        source: Box<Error>,
        /// The child itself, when the spawn could not end it and hands it to the caller; see
        /// [`Unreaped`](crate::Unreaped) for how to settle it. Then `fate` is the one of a child that
        /// is not known to have been collected: [`ChildFate::Running`], [`ChildFate::Unknown`] when
        /// the look at it failed, or [`ChildFate::Killed`] when the wait for it failed after the kill.
        /// A `Running` fate carries the child's own identity, except where the identity read failed
        /// (`id: None`). Dropped while its thread is panicking, it is given up, not waited for.
        unreaped: Option<Box<crate::Unreaped>>,
    },
}

/// What a spawn that failed after its program may have started did with its child: the `fate` of
/// [`Error::MayHaveStarted`] (see [`Error::fate`]).
///
/// It is about the child cosca spawned. Behind an elevation front (`sudo`, `doas`, `osascript`)
/// that child is usually the front, and the elevated program its own child, which cosca never
/// signals: `Reaped`, `Killed` and `Gone` say the front is not running, not that the program is
/// not. A front that had exited by itself is `Reaped` while the program it launched may still run.
/// (A pkexec child is the program itself.) Descendants of a contained child are not covered
/// either; the containment's own teardown is.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildFate {
    /// cosca collected the child's exit: it killed the child, or found it had exited, and reaped it.
    /// The child is not running; behind an elevation front, the elevated program may be (see the
    /// type's doc).
    Reaped,
    /// The child is dead or dying, but cosca did not collect its exit, and cosca's kill was delivered
    /// (or the child had exited by itself): the wait for it failed, someone else collected its exit
    /// or holds its zombie after the kill, a Windows child was terminated and not waited for, or a
    /// containment teardown ended it. Behind an elevation front, the elevated program may still
    /// run.
    Killed,
    /// The child may still be running: cosca left it alone (an elevation front, which it never
    /// signals, a child it could not show to be its own, or one `kill_on_drop(false)` keeps) or
    /// could not kill it. Either may come back to the caller: see the `unreaped` field of
    /// [`Error::MayHaveStarted`].
    ///
    /// `id` is its identity when the spawn had read one, and `None` when the failure came before
    /// that read (an identity that could not be read, or a macOS report that never came). It is an
    /// identity, not a pin: the child may exit and be reaped, and its pid reused. Check it before acting on it ([`ProcessId::is_alive`]), or open it ([`Process::open`](crate::Process::open)),
    /// whose acts reach only that process; never signal its number by itself.
    ///
    /// [`ProcessId::is_alive`]: crate::identity::ProcessId::is_alive
    Running { id: Option<crate::identity::ProcessId> },
    /// Someone else reaped the child, or its zombie is held by another process (on macOS, launchd
    /// holds a tracer-orphaned child's zombie), so cosca could not collect it, and cosca delivered
    /// no kill: a child that was gone already, or not ours, when cosca came to it. (One cosca killed
    /// and found collected is [`Killed`](ChildFate::Killed).) The child is not running; behind an elevation front, the elevated program may be (see the type's doc).
    Gone,
    /// cosca cannot say what became of the child.
    Unknown,
}

impl ChildFate {
    /// Whether the child is not running: killed, reaped, or already gone. The one meaning of "the
    /// root is dead" that settles a tree kill's report, as [`SweepFailure::killed_root`] has it for a
    /// kill through the handle.
    ///
    /// [`SweepFailure::killed_root`]: crate::containment::dispatch::SweepFailure::killed_root
    pub(crate) fn not_running(&self) -> bool {
        matches!(self, ChildFate::Reaped | ChildFate::Killed | ChildFate::Gone)
    }
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

/// What [`Error::MayHaveStarted`] appends to the fate of an elevation front: the elevated program
/// behind it may still run, whenever the fate says the front is not running.
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

/// `e` as the `io::Error` std reports for the same failure: a `HRESULT_FROM_WIN32` code unwrapped to
/// its Win32 code, which `raw_os_error()` and `kind()` classify. Every `windows::core::Error` that
/// becomes an `io::Error` goes through here: the `windows` crate's own conversion keeps the HRESULT
/// (`0x8007xxxx`), which `kind()` cannot classify and which differs from what std returns. Clippy
/// cannot ban the `windows` crate's conversion (see `clippy.toml`); review catches a bare `.into()`,
/// `io::Error::from` or `?`.
#[cfg(windows)]
pub(crate) fn win32_io_error(e: windows::core::Error) -> std::io::Error {
    let code = e.code().0 as u32;
    if code & 0xFFFF_0000 == 0x8007_0000 {
        std::io::Error::from_raw_os_error((code & 0xFFFF) as i32)
    } else {
        std::io::Error::from_raw_os_error(code as i32)
    }
}

/// `error`, then each of its [`source`](std::error::Error::source)s, outermost first.
pub(crate) fn chain<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> impl Iterator<Item = &'a (dyn std::error::Error + 'static)> {
    std::iter::successors(Some(error), |e| e.source())
}

/// An error as one line: every layer of its [`chain`], each layer's `Display` joined with `": "`.
/// The one-line form of std's unstable `std::error::Report`; every cosca log line that prints an
/// error uses it.
pub(crate) struct Report<'a>(pub(crate) &'a (dyn std::error::Error + 'static));

impl std::fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, layer) in chain(self.0).enumerate() {
            if i > 0 {
                f.write_str(": ")?;
            }
            write!(f, "{layer}")?;
        }
        Ok(())
    }
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
    /// Windows has no per-process graceful-termination signal: what a graceful terminate of a lone
    /// process answers there.
    #[cfg(windows)]
    pub(crate) fn terminate_unsupported() -> Error {
        Error::Unsupported {
            op: "graceful terminate (SIGTERM-equivalent)".into(),
            platform: "windows",
            detail: "Windows has no per-process graceful-termination signal; for a contained \
                     child use graceful_shutdown_tree (CTRL_BREAK to the group)"
                .into(),
            source: None,
        }
    }

    /// `e` as the `source` of an error it caused.
    pub(crate) fn io_cause(e: std::io::Error) -> Box<Error> {
        Box::new(Error::Io(e))
    }

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

    /// This error as an [`std::io::Error`]: an [`Error::Io`] as it is, any other variant wrapped.
    pub(crate) fn into_io(self) -> std::io::Error {
        match self {
            Error::Io(e) => e,
            other => std::io::Error::other(other),
        }
    }

    /// The OS error code of a failure, for a look whose failure is told apart by it: the first of
    /// [`io_errors`](Error::io_errors) that has one. `None` when the chain holds none.
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn raw_os_error(&self) -> Option<i32> {
        self.io_errors().find_map(std::io::Error::raw_os_error)
    }

    /// The `io::Error`s down this error's `source()` chain, outermost first. Under [`io_context`]
    /// and [`with_note`](Error::with_note) the first of them is a code-less wrapper and the OS error
    /// comes below it.
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn io_errors(&self) -> impl Iterator<Item = &std::io::Error> {
        chain(self).filter_map(|s| s.downcast_ref::<std::io::Error>())
    }

    /// This error with `note` appended to what it says, its variant and kind kept: a caller that
    /// matches on the variant still sees the cause. An [`Error::Io`] keeps its kind, and its
    /// original error as the [`source`](std::error::Error::source), so the OS code stays where
    /// `Error::raw_os_error`, the walk described on [`Error`], finds it. An
    /// [`Error::MemberNotKilled`] takes the note in its own `note`, so its `source` (and the OS error
    /// that is part of its contract) is untouched.
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
            Error::Unsupported {
                op,
                platform,
                detail,
                source,
            } => Error::Unsupported {
                op,
                platform,
                detail: append(detail),
                source,
            },
            Error::Containment { detail, source } => Error::Containment {
                detail: append(detail),
                source,
            },
            Error::NoConsole { detail } => Error::NoConsole { detail: append(detail) },
            Error::Elevation { kind, detail, source } => Error::Elevation {
                kind,
                detail: append(detail),
                source,
            },
            Error::Unassessable { detail, source } => Error::Unassessable {
                detail: append(detail),
                source,
            },
            // The note goes beside `source`, not into it: a refused kill's OS error is the contract of
            // this variant, and wrapping it would hide it (an `io::Error` with a payload has no OS code).
            Error::MemberNotKilled {
                pid,
                source,
                note: earlier,
            } => Error::MemberNotKilled {
                pid,
                source,
                note: Some(earlier.map_or_else(|| note.to_owned(), append)),
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
                unreaped,
            } => Error::MayHaveStarted {
                fate,
                wrapper_elevated,
                source: Box::new(source.with_note(note)),
                unreaped,
            },
            Error::Quote(e) => {
                debug_assert!(
                    false,
                    "a note is added only to a spawn's error, never a quoting one: {}",
                    Report(&e)
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
