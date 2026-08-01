//! Tri-state answers for the identity layer.
//!
//! Every identity question has three outcomes, not two: yes, no, and *we were not allowed
//! to ask*. Collapsing the third into the second makes an unprivileged caller read a live,
//! healthy service as gone, so none of these types offer a `bool` conversion, a `Default`,
//! or an `unwrap_or`: narrowing to two states must name the variant being folded away.

/// Whether a `ProcessId` still resolves (zombie-inclusive — see
/// [`ProcessId::exists`](super::ProcessId::exists)).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Existence {
    /// The pid resolves to this exact identity.
    Present,
    /// The pid resolves to nothing, or to a different identity (recycled).
    Gone,
    /// The OS refused the query; the process may well be present.
    Unknown,
}

impl Existence {
    pub fn is_unknown(self) -> bool {
        matches!(self, Existence::Unknown)
    }
}

/// Whether a process is currently running (zombie-*exclusive* — see
/// [`ProcessId::is_alive`](super::ProcessId::is_alive)).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Liveness {
    /// Running: this exact identity, not exited.
    Alive,
    /// Exited, reaped, or the pid now names a different process.
    Dead,
    /// The OS refused the query, or answered ambiguously; the process may well be alive.
    Unknown,
}

impl Liveness {
    pub fn is_unknown(self) -> bool {
        matches!(self, Liveness::Unknown)
    }
}

/// The outcome of resolving something by pid.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolved<T> {
    Found(T),
    /// No such process.
    Gone,
    /// The OS refused the query; a process may well be there.
    Unknown,
}

impl<T> Resolved<T> {
    /// The value if resolved. Discards *why* it did not resolve — use only where `Gone` and
    /// `Unknown` genuinely warrant the same handling.
    pub fn found(self) -> Option<T> {
        match self {
            Resolved::Found(v) => Some(v),
            Resolved::Gone | Resolved::Unknown => None,
        }
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Resolved::Unknown)
    }

    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Resolved<U> {
        match self {
            Resolved::Found(v) => Resolved::Found(f(v)),
            Resolved::Gone => Resolved::Gone,
            Resolved::Unknown => Resolved::Unknown,
        }
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod state_tests;
