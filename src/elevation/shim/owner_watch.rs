//! Why the shim could not watch cosca's process (Linux: `pidfd_open` on cosca's pid, before hello).

use super::codes;

/// What a failed owner `pidfd_open` means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerPidfdFailure {
    /// No process holds cosca's pid, or a non-leader thread does: cosca is gone.
    CoscaGone,
    /// The watch cannot be set up (descriptors, memory, a seccomp profile): cosca may be alive.
    Unwatchable,
}

impl OwnerPidfdFailure {
    /// `errno` of a failed `pidfd_open(<cosca's pid>, 0)`.
    pub(crate) fn from_errno(errno: i32) -> OwnerPidfdFailure {
        match errno {
            libc::ESRCH | libc::EINVAL => OwnerPidfdFailure::CoscaGone,
            _ => OwnerPidfdFailure::Unwatchable,
        }
    }

    /// The shim's exit code.
    pub(crate) fn exit_code(self) -> i32 {
        match self {
            OwnerPidfdFailure::CoscaGone => codes::OWNER_GONE,
            OwnerPidfdFailure::Unwatchable => codes::OWNER_WATCH,
        }
    }
}

#[cfg(test)]
#[path = "owner_watch_tests.rs"]
mod owner_watch_tests;
