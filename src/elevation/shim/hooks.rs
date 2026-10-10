//! Test seams of the shim, injected by the host's `main` through
//! [`init_with_test_hooks`](super::init_with_test_hooks). [`init`](super::init) installs none, and
//! the library reads no environment for seams, so a shipped shim cannot reach one.
//!
//! No hook runs in the child between the clone and `execve`: the child-side seams are data the
//! shim asks for before the clone (a gate path, a flag), and the child acts on them with raw
//! system calls.

use std::os::fd::RawFd;
use std::path::PathBuf;

/// A point where the shim waits for the test to release it.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Gate {
    /// Before the shim connects to cosca's socket.
    BeforeConnect,
    /// After it connected and before it reads who cosca is.
    BeforeIdentity,
    /// After the answer `A`, before the owner re-check and the clone.
    AfterAnswer,
    /// After the owner re-check and everything the clone needs, right before the clone.
    BeforeClone,
    /// After the clone, when the start must not go on and the held child is about to be killed.
    BeforeAbandon,
    /// After the clone, before the shim's stdio is replaced.
    AfterFork,
    /// After the shim's stdio is replaced, before the loop.
    BeforeLoop,
}

impl Gate {
    /// The name the shim's log gives the gate.
    #[doc(hidden)]
    pub fn name(self) -> &'static str {
        match self {
            Gate::BeforeConnect => "before-connect",
            Gate::BeforeIdentity => "before-identity",
            Gate::AfterAnswer => "after-answer",
            Gate::BeforeClone => "before-clone",
            Gate::BeforeAbandon => "before-abandon",
            Gate::AfterFork => "after-fork",
            Gate::BeforeLoop => "before-loop",
        }
    }
}

/// A fault or interference the shim can be told to produce.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Inject {
    /// The clone fails with `EAGAIN`.
    ForkFails,
    /// Creating the status pipe fails with `EMFILE`.
    PipeFails,
    /// `clone3` answers `ENOSYS`, as Docker's default seccomp profile does.
    Clone3Enosys,
    /// The shim exits right after the clone.
    DieAfterFork,
    /// The shim reaps the child by pid itself, as a foreign reaper would.
    StealReap,
    /// A host thread of the shim reaps with `waitpid(-1)` once released.
    ReapingHostThread,
    /// The `poll` of an owner re-check fails: `RLIMIT_NOFILE`'s soft limit is 0 around it, and the
    /// kernel answers `EINVAL` to a `poll` of more descriptors than that.
    OwnerPollFails,
    /// The child asks `PR_SET_PDEATHSIG` for a signal that does not exist, which the kernel refuses
    /// with `EINVAL`.
    ChildSetupFails,
}

impl Inject {
    /// Every injection, for a host that must tell a known name from a misspelt one.
    pub const ALL: [Inject; 8] = [
        Inject::ForkFails,
        Inject::PipeFails,
        Inject::Clone3Enosys,
        Inject::DieAfterFork,
        Inject::StealReap,
        Inject::ReapingHostThread,
        Inject::OwnerPollFails,
        Inject::ChildSetupFails,
    ];

    #[doc(hidden)]
    pub fn name(self) -> &'static str {
        match self {
            Inject::ForkFails => "fork-fails",
            Inject::PipeFails => "pipe-fails",
            Inject::Clone3Enosys => "clone3-enosys",
            Inject::DieAfterFork => "die-after-fork",
            Inject::StealReap => "steal-reap",
            Inject::ReapingHostThread => "reaping-host-thread",
            Inject::OwnerPollFails => "owner-poll-fails",
            Inject::ChildSetupFails => "child-setup-fails",
        }
    }
}

/// What a test can do to the shim. Every method has a default that does nothing.
#[doc(hidden)]
pub trait ShimTestHooks: Sync {
    /// Blocks until the test releases `gate`.
    fn gate(&self, _gate: Gate) {}

    fn inject(&self, _what: Inject) -> bool {
        false
    }

    /// A close-on-exec descriptor the shim writes its log lines to, and the child writes its own
    /// preformatted lines to. The hooks own it for the life of the process.
    fn log_fd(&self) -> Option<RawFd> {
        None
    }

    /// A path the child opens and reads one byte from, before it execs: it waits there.
    fn child_gate(&self) -> Option<PathBuf> {
        None
    }

    /// The child faults (a null write) before it execs.
    fn child_fault(&self) -> bool {
        false
    }

    /// A path opened non-blocking and polled by the loop: when it is readable, supervision fails.
    fn loop_failure(&self) -> Option<PathBuf> {
        None
    }

    /// Lowers `RLIMIT_NOFILE`'s soft limit to the shim's lowest free descriptor before the owner's
    /// `pidfd_open`, and restores it after: no descriptor can be made meanwhile.
    fn exhaust_fds(&self) -> bool {
        false
    }
}
