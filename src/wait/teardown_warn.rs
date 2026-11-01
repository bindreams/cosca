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
    #[cfg_attr(
        not(any(test, feature = "tokio")),
        allow(dead_code, reason = "only an async spawn's teardown has a threshold to start from")
    )]
    pub(crate) fn in_(after: Option<Duration>) -> Option<Due> {
        after.map(|after| Due {
            until: crate::wait::now() + after,
            after,
        })
    }
}

/// Runs `wait` on `state`: a teardown's blocking wait for something it killed.
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

/// For [`wait_warning`]: whether the process `handle` names has exited (the handle is signalled) by
/// `until`. Any answer but a timeout, an error included, is `true`, for the wait to find.
#[cfg(windows)]
pub(crate) fn handle_signaled_by(handle: windows::Win32::Foundation::HANDLE, until: Instant) -> bool {
    use windows::Win32::Foundation::{WAIT_FAILED, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::WaitForSingleObject;

    let mut failed = None;
    // SAFETY: the caller's live process handle, kept open across the call.
    let waited = crate::wait::wait_until(Some(until), |ms| {
        let waited = unsafe { WaitForSingleObject(handle, ms) };
        if waited == WAIT_FAILED {
            failed = Some(std::io::Error::last_os_error());
        }
        waited
    });
    #[cfg(test)]
    let waited = if crate::child::spawn::fault::take_late_exit() {
        WAIT_TIMEOUT
    } else {
        waited
    };
    if let Some(e) = failed {
        log::debug!("a look at a killed child's exit failed ({e}); the wait that follows decides");
    }
    waited != WAIT_TIMEOUT
}

#[cfg(test)]
#[path = "teardown_warn_tests.rs"]
mod teardown_warn_tests;
