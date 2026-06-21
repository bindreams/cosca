//! The `Fd` (descriptor address) and `Stdio` (redirection target) model.

use std::fmt;
use std::fs::File;

use crate::error::Error;

/// A target descriptor. `i32` matches POSIX fd numbering; on Windows 0/1/2 are
/// the std handles and n>=3 is the MSVCRT fd-table slot (Plan 4). Use a bare
/// `i32` at call sites via `From`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fd(i32);

impl Fd {
    pub const STDIN: Fd = Fd(0);
    pub const STDOUT: Fd = Fd(1);
    pub const STDERR: Fd = Fd(2);

    pub fn raw(self) -> i32 {
        self.0
    }
}

impl From<i32> for Fd {
    fn from(n: i32) -> Fd {
        debug_assert!(n >= 0, "a file descriptor must be non-negative, got {n}");
        Fd(n)
    }
}

impl fmt::Display for Fd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("stdin"),
            1 => f.write_str("stdout"),
            2 => f.write_str("stderr"),
            n => write!(f, "fd {n}"),
        }
    }
}

/// Which way a pipe flows relative to the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Child reads (parent holds the write end).
    In,
    /// Child writes (parent holds the read end).
    Out,
}

/// A redirection target for a descriptor. Opaque; built via the constructors.
#[derive(Debug)]
pub struct Stdio(StdioKind);

#[derive(Debug)]
enum StdioKind {
    Inherit,
    Null,
    /// `None` = infer direction from the slot at resolve time; `Some` = explicit.
    Pipe(Option<Direction>),
    File(File),
    Merge(Fd),
    #[cfg(feature = "pty")]
    Pty,
}

impl Stdio {
    /// Pass the parent's matching descriptor through to the child.
    pub fn inherit() -> Stdio {
        Stdio(StdioKind::Inherit)
    }
    /// Connect to the null device (`/dev/null` / `NUL`).
    pub fn null() -> Stdio {
        Stdio(StdioKind::Null)
    }
    /// A pipe whose direction is inferred from the slot (stdin=child-reads,
    /// stdout/stderr=child-writes). Use [`pipe_in`]/[`pipe_out`] for fds >= 3.
    pub fn pipe() -> Stdio {
        Stdio(StdioKind::Pipe(None))
    }
    /// A pipe the child reads (parent holds the write end).
    pub fn pipe_in() -> Stdio {
        Stdio(StdioKind::Pipe(Some(Direction::In)))
    }
    /// A pipe the child writes (parent holds the read end).
    pub fn pipe_out() -> Stdio {
        Stdio(StdioKind::Pipe(Some(Direction::Out)))
    }
    /// Redirect to/from an already-open file.
    pub fn from_file(f: File) -> Stdio {
        Stdio(StdioKind::File(f))
    }
    /// Duplicate another descriptor's target onto this one (e.g. `2>&1`).
    pub fn merge(other: Fd) -> Stdio {
        Stdio(StdioKind::Merge(other))
    }
    /// A pseudo-terminal. The variant exists now; wiring lands behind the `pty`
    /// feature later, so this currently resolves to `Unsupported`.
    #[cfg(feature = "pty")]
    pub fn pty() -> Stdio {
        Stdio(StdioKind::Pty)
    }

    /// Resolve to a concrete, direction-unambiguous target for `slot`.
    pub(crate) fn resolve(self, slot: Fd) -> Result<ResolvedStdio, Error> {
        Ok(match self.0 {
            StdioKind::Inherit => ResolvedStdio::Inherit,
            StdioKind::Null => ResolvedStdio::Null,
            StdioKind::File(f) => ResolvedStdio::File(f),
            StdioKind::Merge(t) => ResolvedStdio::Merge(t),
            StdioKind::Pipe(Some(dir)) => ResolvedStdio::Pipe(dir),
            StdioKind::Pipe(None) => match slot {
                Fd::STDIN => ResolvedStdio::Pipe(Direction::In),
                Fd::STDOUT | Fd::STDERR => ResolvedStdio::Pipe(Direction::Out),
                other => {
                    return Err(Error::Unsupported {
                        op: format!("ambiguous pipe direction on {other}"),
                        platform: std::env::consts::OS,
                        detail: "use Stdio::pipe_in()/pipe_out() for descriptors >= 3".into(),
                    })
                }
            },
            #[cfg(feature = "pty")]
            StdioKind::Pty => {
                return Err(Error::Unsupported {
                    op: format!("pty on {slot}"),
                    platform: std::env::consts::OS,
                    detail: "PTY support is not wired yet".into(),
                })
            }
        })
    }
}

/// A fully direction-resolved redirection target (crate-internal).
#[derive(Debug)]
pub(crate) enum ResolvedStdio {
    Inherit,
    Null,
    Pipe(Direction),
    File(File),
    Merge(Fd),
}

#[cfg(test)]
#[path = "stdio_tests.rs"]
mod stdio_tests;
