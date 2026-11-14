//! One pid's file (`<pid>/stat`, `<pid>/cgroup`) or link (`<pid>/ns/pid`) through the checked `/proc`:
//! [`read`] and [`read_link`] are the one read of such a file in the crate, and the one place that
//! decides what its failure means.
//!
//! A scan that skips a pid it could not read reports a table with a live process missing, and a
//! tree walk over it misses that process and its subtree. So only the failures that mean "this pid
//! is not there for us" skip; every other one fails the scan, as `Unsupported` when it is a
//! [`Refusal`].

use std::io;
use std::sync::Arc;

use super::kernel::Kernel;
use super::proc_read::{read_own, OwnUnreadable, ProcDir, ReadFailure};
use super::refusal::Refusal;
use crate::error::io_context;

/// What reading one pid's file yielded.
#[derive(Debug)]
pub(crate) enum ReadOutcome {
    Read(Vec<u8>),
    /// The pid exited: `ESRCH`, of the open, of a file's `read(2)` or of a link's `readlinkat`; or, of
    /// a link's `readlinkat`, `ENOENT` (the task has no namespace left). The error is why.
    Exited(io::Error),
    /// The pid is not shown to us: it is gone (`ENOENT`), or `hidepid` hides it (`EACCES`, or `EPERM`
    /// while the checked directory still answers); of a link's `readlinkat`, `EACCES`, with its reason
    /// (ptrace of the task is denied, or the task has exited) as the error's words. The error is why. A
    /// caller that holds the pid unreaped, so that it cannot be gone, reads this as `/proc` hiding it.
    Hidden(io::Error),
    /// The `openat2` was refused.
    Refused(Refusal),
}

/// Why one pid's file could not be read and is not simply absent. Its words say what failed; the OS
/// error behind them is the [`source`](std::error::Error::source).
///
/// A layer of the error chain: a caller wraps it as the cause of its own error and never folds its
/// words into a message of its own.
#[derive(Debug)]
pub(crate) struct Unreadable {
    pid: u32,
    /// The file of the pid that was read: `stat`, `cgroup`, or the link `ns/pid`.
    file: &'static str,
    kind: Kind,
    cause: io::Error,
    /// The other read that failed with it, when there is one ([`Kind::RecheckFailed`]): the pid's
    /// `EPERM` beside the re-check's error. It is no layer of the chain; the caller takes it
    /// ([`into_cause`](Self::into_cause)).
    peer: Option<io::Error>,
}

impl Unreadable {
    /// The other failure that came with this one, once: for a caller that holds both.
    pub(crate) fn take_peer(&mut self) -> Option<io::Error> {
        self.peer.take()
    }

    /// This failure as the cause of its caller's error, with the peer beside it when there is one
    /// (a [`Error::Several`](crate::error::Error::Several), this failure first).
    pub(crate) fn into_cause(mut self) -> crate::error::Error {
        use crate::error::Error;
        let peer = self.take_peer();
        let own = Error::Io(io::Error::other(self));
        match peer {
            None => own,
            Some(peer) => Error::Several(crate::error::Failures::new(
                std::sync::Arc::new(own),
                [Error::io_cause(peer)],
            )),
        }
    }

    /// [`into_cause`](Self::into_cause) as an `io::Error`, for a caller that returns one: this
    /// failure alone, or both failures as the members of a list that a context ("two reads failed")
    /// holds, which names neither the pid nor the file again.
    pub(crate) fn into_io(self) -> io::Error {
        self.into_cause().into_io_over("two reads failed")
    }
}

#[derive(Debug)]
enum Kind {
    /// `EXDEV`/`ELOOP` of the `openat2`: the checked directory refused to cross a mount, so the
    /// record is not the kernel's.
    BeyondMount,
    /// The pid's failure beside a refusal ([`Refusal::beside`]); the source of this layer.
    BesideRefusal,
    /// `EPERM`, and the `self/stat` re-check failed without refusing: whether the pid is hidden is
    /// unknown. The re-check's error is the source, and the pid's own `EPERM` is the peer.
    RecheckFailed,
    /// `EMFILE`, `ENOMEM`, `EIO`, ... of the `openat2`, or a failure of the read step (`read(2)`, or a
    /// link's `readlinkat`) that is no exit or hiding of the pid: nothing is known about it.
    Other,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Unreadable { pid, file, kind, .. } = self;
        match kind {
            Kind::BeyondMount => write!(f, "{pid}/{file} lies beyond a mount in /proc and was not read"),
            Kind::BesideRefusal => write!(
                f,
                "{pid}/{file} was refused, and the checked /proc refused self/stat too"
            ),
            Kind::RecheckFailed => write!(f, "{pid}/{file} was refused, and the re-check of self/stat failed"),
            Kind::Other => write!(f, "{pid}/{file} could not be read"),
        }
    }
}

impl std::error::Error for Unreadable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// `pid`'s `file` (`stat`, `cgroup`) through `dir`: a pid that is not there for us is
/// [`ReadOutcome::Exited`] or [`ReadOutcome::Hidden`], a [`Refusal`] is [`ReadOutcome::Refused`], any
/// other failure is [`Unreadable`].
///
/// Never asks `kill(pid, 0)`: under `hidepid` it answers a foreign uid `EPERM` too, so the first
/// foreign process would abort every scan.
pub(crate) fn read(
    kernel: &dyn Kernel,
    dir: &ProcDir,
    pid: u32,
    file: &'static str,
) -> Result<ReadOutcome, Unreadable> {
    classify(
        kernel,
        dir,
        pid,
        file,
        Entry::File,
        kernel.read(dir, &format!("{pid}/{file}")),
    )
}

/// [`read`] of the symlink `<pid>/<file>` (`ns/pid`): its target is the [`ReadOutcome::Read`] bytes.
/// The `readlinkat` is the read step, as `read(2)` is of a file, with its own errnos.
pub(crate) fn read_link(
    kernel: &dyn Kernel,
    dir: &ProcDir,
    pid: u32,
    file: &'static str,
) -> Result<ReadOutcome, Unreadable> {
    classify(
        kernel,
        dir,
        pid,
        file,
        Entry::Link,
        kernel.read_link(dir, &format!("{pid}/{file}")),
    )
}

/// What kind of entry of a pid's directory is read, which decides what its read step's errno means.
#[derive(Clone, Copy)]
enum Entry {
    File,
    Link,
}

/// The one rule of a pid's `file`, a file or a link as `entry` says, applied to `read`, the result of
/// reading it through `kernel` and `dir`: what the read yielded.
fn classify(
    kernel: &dyn Kernel,
    dir: &ProcDir,
    pid: u32,
    file: &'static str,
    entry: Entry,
    read: Result<Vec<u8>, ReadFailure>,
) -> Result<ReadOutcome, Unreadable> {
    let source = match read {
        Ok(bytes) => return Ok(ReadOutcome::Read(bytes)),
        Err(ReadFailure::Open(source)) => source,
        // The entry opened, so no `openat2` errno is in play; only the read step's own say anything
        // about the pid.
        Err(ReadFailure::Read(source)) => match (entry, source.raw_os_error()) {
            // A task that exited after the open: a file's `read(2)` reports it, and so does gVisor's
            // `checkTaskState` for a link whose task is dead.
            (_, Some(libc::ESRCH)) => return Ok(ReadOutcome::Exited(source)),
            // The `readlinkat` of a namespace link. Linux v6.12: `proc_ns_readlink`
            // (fs/proc/namespaces.c) answers `EACCES` when ptrace of the task is denied or the task is
            // gone before it is looked up, and `ns_get_name` (fs/nsfs.c) `ENOENT` when the task, once
            // found, has no namespace left, which is exiting. gVisor ab5f509c
            // (pkg/sentry/fsimpl/proc/task_files.go, `namespaceSymlink.Readlink`): `checkTaskState`
            // answers `EACCES` for a zombie and `ESRCH` for a dead task, and `ENOENT` for a task with
            // no namespace of the kind; it checks no ptrace right.
            (Entry::Link, Some(libc::EACCES)) => {
                return Ok(ReadOutcome::Hidden(io_context(
                    "the link was not read: ptrace of the task is denied, or the task has exited",
                    source,
                )));
            }
            (Entry::Link, Some(libc::ENOENT)) => return Ok(ReadOutcome::Exited(source)),
            _ => {
                return Err(Unreadable {
                    pid,
                    file,
                    kind: Kind::Other,
                    cause: source,
                    peer: None,
                });
            }
        },
    };
    let (kind, cause, peer) = match source.raw_os_error() {
        Some(libc::ESRCH) => return Ok(ReadOutcome::Exited(source)),
        Some(libc::ENOENT | libc::EACCES) => return Ok(ReadOutcome::Hidden(source)),
        // `hidepid`'s answer only if the checked directory still reads.
        Some(libc::EPERM) => match read_own(kernel, dir, "self/stat") {
            Ok(_) => return Ok(ReadOutcome::Hidden(source)),
            Err(OwnUnreadable::Refused(refusal)) => {
                let pid_failure = Unreadable {
                    pid,
                    file,
                    kind: Kind::BesideRefusal,
                    cause: source,
                    peer: None,
                };
                return Ok(ReadOutcome::Refused(refusal.beside(Arc::new(pid_failure.into_cause()))));
            }
            Err(OwnUnreadable::Failed(recheck)) => (Kind::RecheckFailed, recheck, Some(source)),
        },
        Some(libc::EXDEV | libc::ELOOP) => (Kind::BeyondMount, source, None),
        _ => {
            let failure = ReadFailure::Open(source);
            match failure.refusal() {
                Some(refusal) => return Ok(ReadOutcome::Refused(refusal)),
                None => (Kind::Other, failure.into_io(), None),
            }
        }
    };
    Err(Unreadable {
        pid,
        file,
        kind,
        cause,
        peer,
    })
}

#[cfg(test)]
#[path = "pid_file_tests.rs"]
mod pid_file_tests;
