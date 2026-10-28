//! A teardown that blocks a runtime thread on what it killed (principle 2): a failed async spawn's,
//! or the armed drop's. Each of those waits runs through [`wait_warning`], which warns once if the
//! wait passes a threshold.

use std::time::{Duration, Instant};

/// When a teardown's warn is due, and how long into the wait that is.
#[derive(Clone, Copy)]
pub(crate) struct Due {
    pub(crate) until: Instant,
    pub(crate) after: Duration,
}

impl Due {
    /// Due `after` from now, if there is a threshold.
    pub(crate) fn in_(after: Option<Duration>) -> Option<Due> {
        after.map(|after| Due {
            until: crate::wait::now() + after,
            after,
        })
    }
}

/// Runs `wait` on `state`: a teardown's blocking wait for something it killed. Every such wait,
/// whatever it waits for, is this one.
///
/// With `due`, `ended_by(state, due.until)` first watches for what `wait` waits for, blocking no
/// later than `due.until`, and `warn(due.after)` runs once if it answers `false`. `ended_by` answers
/// `true` for anything it cannot read, leaving it to `wait`. Then `wait` runs, unbounded, and its
/// answer is the result: the threshold picks the message and nothing else. Without `due`, only
/// `wait` runs.
pub(crate) fn wait_warning<S, R>(
    mut state: S,
    due: Option<Due>,
    ended_by: impl FnOnce(&mut S, Instant) -> bool,
    warn: impl FnOnce(Duration),
    wait: impl FnOnce(S) -> R,
) -> R {
    if let Some(due) = due {
        #[cfg(feature = "tokio")]
        crate::bounded::assert_may_block("a teardown's warned wait");
        if !ended_by(&mut state, due.until) {
            warn(due.after);
        }
    }
    wait(state)
}

/// What a wait for a child's exit watches, on Linux.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(crate) enum ExitWatch<'a> {
    /// The child's pidfd.
    PidFd(std::os::fd::BorrowedFd<'a>),
    /// A child that sent only its `/proc` directory, `dir`, and its number, `pid`.
    ProcDir {
        pid: rustix::process::Pid,
        dir: std::os::fd::BorrowedFd<'a>,
    },
}

/// For [`wait_warning`]: whether the exit of the child `watch` names is visible to this process by
/// `until` ([`pidfd_exit_visible_by`](crate::wait::pidfd_exit_visible_by)).
///
/// A child known by its `/proc` directory is watched through a pidfd opened on its number, kept only
/// if the directory shows the child still unreaped after the open: the number named it then. A child
/// reaped elsewhere, or a refused open, answers `true`.
#[cfg(target_os = "linux")]
pub(crate) fn exit_visible_by(watch: ExitWatch<'_>, until: Instant) -> bool {
    use std::os::fd::AsFd as _;

    match watch {
        ExitWatch::PidFd(pidfd) => crate::wait::pidfd_exit_visible_by(pidfd, until),
        ExitWatch::ProcDir { pid, dir } => {
            match rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) {
                Ok(pidfd) if proc_dir_unreaped(dir) => crate::wait::pidfd_exit_visible_by(pidfd.as_fd(), until),
                Ok(_) => true,
                Err(e) => {
                    log::debug!("a look at a killed child's exit failed ({e}); the wait that follows decides");
                    true
                }
            }
        }
    }
}

/// Whether the process the open `/proc/<pid>` directory `dir` names is unreaped: once it is reaped,
/// nothing opens through the directory, whatever process the number names by then.
#[cfg(target_os = "linux")]
pub(crate) fn proc_dir_unreaped(dir: std::os::fd::BorrowedFd<'_>) -> bool {
    use std::os::fd::AsRawFd as _;

    // SAFETY: a NUL-terminated name relative to an open directory; the result is closed.
    let stat = unsafe { libc::openat(dir.as_raw_fd(), c"stat".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if stat >= 0 {
        // SAFETY: the descriptor just opened, closed once.
        unsafe { libc::close(stat) };
    }
    stat >= 0
}
