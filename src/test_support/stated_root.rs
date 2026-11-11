//! A [`Root`] answering from stated facts (pid, [`RootState`], Linux pidfd).

use crate::containment::Root;
use crate::signal::RootState;

pub(crate) struct StatedRoot<'a> {
    pid: u32,
    /// Built fresh per call: a `RootState` holds an `io::Error`.
    state: Box<dyn Fn() -> RootState + 'a>,
    #[cfg(target_os = "linux")]
    pidfd: Option<std::os::fd::BorrowedFd<'a>>,
}

impl<'a> StatedRoot<'a> {
    /// An unreaped root, with no pidfd.
    pub(crate) fn unreaped() -> StatedRoot<'a> {
        StatedRoot::with_state(std::process::id(), || RootState::Unreaped)
    }

    pub(crate) fn with_state(pid: u32, state: impl Fn() -> RootState + 'a) -> StatedRoot<'a> {
        StatedRoot {
            pid,
            state: Box::new(state),
            #[cfg(target_os = "linux")]
            pidfd: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_pidfd(mut self, pidfd: std::os::fd::BorrowedFd<'a>) -> StatedRoot<'a> {
        self.pidfd = Some(pidfd);
        self
    }
}

impl Root for StatedRoot<'_> {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn state(&self) -> RootState {
        (self.state)()
    }

    #[cfg(target_os = "linux")]
    fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.pidfd
    }
}
