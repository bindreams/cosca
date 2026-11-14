//! A call the kernel answered in a way that says cosca cannot run here: [`FailedCall`] is a call and
//! its errno, and [`Refusal`] is one whose errno is in the table of refusals. Below every module that
//! reads `/proc` or opens a pid, and knows none of them.

use std::sync::Arc;

use rustix::io::Errno;

use crate::error::{Error, Failures};

#[derive(Debug, Clone, Copy)]
enum Call {
    PidfdOpen,
    PidfsIno,
    Poll,
    Openat2,
}

/// A call that failed, and the errno it answered.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FailedCall {
    call: Call,
    errno: Errno,
}

impl FailedCall {
    /// A `pidfd_open` that answered `errno`.
    pub(crate) const fn pidfd_open(errno: Errno) -> FailedCall {
        FailedCall {
            call: Call::PidfdOpen,
            errno,
        }
    }

    /// A read of a pidfd's inode that answered `errno`.
    pub(crate) const fn pidfs_ino(errno: Errno) -> FailedCall {
        FailedCall {
            call: Call::PidfsIno,
            errno,
        }
    }

    /// A `poll` of a pidfd that answered `errno`.
    pub(crate) const fn poll(errno: Errno) -> FailedCall {
        FailedCall {
            call: Call::Poll,
            errno,
        }
    }

    /// An `openat2` that answered `errno`.
    pub(crate) const fn openat2(errno: Errno) -> FailedCall {
        FailedCall {
            call: Call::Openat2,
            errno,
        }
    }

    /// The call's name, as an error says what failed.
    pub(crate) const fn name(&self) -> &'static str {
        match self.call {
            Call::PidfdOpen => "pidfd_open",
            Call::PidfsIno => "pidfs_ino",
            Call::Poll => "poll",
            Call::Openat2 => "openat2",
        }
    }

    pub(crate) const fn errno(&self) -> Errno {
        self.errno
    }

    /// What cosca requires of the kernel, when this call is a [`Refusal`]: the one sentence an
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) for a refused call carries as its
    /// `detail`. The table is the one place that says which errno of which call is a refusal.
    pub(crate) fn requirement(&self) -> Option<String> {
        let (floor, errno) = match (self.call, self.errno) {
            (Call::PidfdOpen, Errno::NOSYS) => ("5.3", "ENOSYS"),
            (Call::PidfdOpen, Errno::PERM) => ("5.3", "EPERM"),
            (Call::PidfdOpen, Errno::ACCESS) => ("5.3", "EACCES"),
            (Call::PidfdOpen, Errno::NODEV) => ("5.3", "ENODEV"),
            (Call::Openat2, Errno::NOSYS) => ("5.6", "ENOSYS"),
            (Call::Openat2, Errno::PERM) => ("5.6", "EPERM"),
            (Call::Openat2, Errno::NODEV) => ("5.6", "ENODEV"),
            _ => return None,
        };
        let name = self.name();
        Some(format!(
            "cosca requires {name} (Linux \u{2265} {floor}), refused here: {name} answered {errno}"
        ))
    }

    /// This call as a [`Refusal`], when it is one.
    pub(crate) fn refusal(self) -> Option<Refusal> {
        self.requirement().map(|requirement| Refusal {
            call: self,
            requirement,
            beside: None,
        })
    }

    /// [`Error::Unsupported`] naming `op` and the [`requirement`](Self::requirement), when this
    /// call is a refusal. The errno is its `source`.
    pub(crate) fn unsupported(&self, op: impl Into<String>) -> Option<Error> {
        self.refusal().map(|refusal| refusal.unsupported(op))
    }
}

/// A [`FailedCall`] that is a refusal, with the [`requirement`](FailedCall::requirement) it names,
/// built once: a holder never asks again whether the call was refused.
///
/// The rule, stated here once for every place an `openat2` or `pidfd_open` is met: a call is refused
/// when its errno is in [`requirement`](FailedCall::requirement)'s table. A read in `/proc` is an
/// `openat2` here, so the same holds for the view-open, the reads that establish the view, the
/// `/proc` listing and each pid's `stat`. That `stat` answering `EPERM` is `hidepid`'s answer, and a
/// refusal only if the checked directory refuses `self/stat` too: the re-check's errno is then the
/// refusal, and the pid's failure is kept beside it. Every other errno is the call's own failure.
#[derive(Debug, Clone)]
pub(crate) struct Refusal {
    call: FailedCall,
    requirement: String,
    /// The failure of the pid the refusal was met beside, when there is one: the pid's own `EPERM`
    /// beside a checked directory that refuses `self/stat`.
    beside: Option<Arc<Error>>,
}

impl Refusal {
    /// This refusal, with `failure`, the other failure it was met beside, kept as a second cause.
    pub(crate) fn beside(mut self, failure: Arc<Error>) -> Refusal {
        self.beside = Some(failure);
        self
    }

    pub(crate) fn requirement(&self) -> &str {
        &self.requirement
    }

    pub(crate) fn os_error(&self) -> std::io::Error {
        std::io::Error::from(self.call.errno())
    }

    /// The failures behind the refusal: the refusing errno, then the other failure, as an
    /// [`Error::Several`] when there is one.
    pub(crate) fn cause(&self) -> Error {
        let own = self.os_error();
        match &self.beside {
            None => Error::Io(own),
            Some(beside) => Error::Several(Failures::new(Error::io_cause(own), [Arc::clone(beside)])),
        }
    }

    /// [`cause`](Self::cause) as an `io::Error`, for a caller whose cause is one: the refusing errno
    /// alone, or, with a failure beside it, a layer that holds both, so every member is reported.
    pub(crate) fn cause_io(&self) -> std::io::Error {
        self.cause()
            .into_io_over("the refusal and the failure it was met beside")
    }

    /// [`Error::Unsupported`] naming `op` and the requirement, with [`cause`](Self::cause) as its
    /// `source`.
    pub(crate) fn unsupported(&self, op: impl Into<String>) -> Error {
        Error::Unsupported {
            op: op.into(),
            platform: "linux",
            detail: self.requirement.clone(),
            source: Some(Arc::new(self.cause())),
        }
    }

    /// [`unsupported`](Self::unsupported) as an `io::Error` of kind `Unsupported`, for a caller whose
    /// error type is `io::Error`: the refusing errno is still found down its source chain.
    pub(crate) fn unsupported_io(&self, op: impl Into<String>) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Unsupported, self.unsupported(op))
    }
}

/// `error`, what a [`Refusal`] ended the scan `caller` with, logged at `warn` and handed back. The
/// one place such a refusal is warned about, where it is met: its caller does not log it again.
pub(crate) fn warn_refused<E: std::error::Error + 'static>(caller: &str, error: E) -> E {
    log::warn!("{caller}: {report}", report = crate::error::Report(&error));
    error
}
