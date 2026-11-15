//! A [`Root`] answering from stated facts (pid, [`RootState`], Linux pidfd).

use crate::containment::Root;
#[cfg(unix)]
use crate::identity::NumberRead;
use crate::signal::RootState;

pub(crate) struct StatedRoot<'a> {
    pid: u32,
    /// Built fresh per call: a `RootState` holds an `io::Error`.
    state: Box<dyn Fn() -> RootState + 'a>,
    #[cfg(target_os = "linux")]
    pidfd: Option<std::os::fd::BorrowedFd<'a>>,
    /// What [`Root::number_holder`] answers, built fresh per call: an `UnknownCause` is not
    /// `Clone`. `None`: such a read panics.
    #[cfg(unix)]
    number: Option<Box<dyn Fn() -> NumberRead + 'a>>,
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
            #[cfg(unix)]
            number: None,
        }
    }

    /// The root's number reads as `read`, every time, with the cause `read` states for an `Unknown`.
    #[cfg(unix)]
    pub(crate) fn holding(mut self, read: impl Fn() -> NumberRead + 'a) -> StatedRoot<'a> {
        self.number = Some(Box::new(read));
        self
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

    /// A stated root holds no process: its handle says the root is gone.
    fn signal(&self, _sig: crate::signal::Sig) -> Result<crate::signal::Sent, crate::error::Error> {
        Ok(crate::signal::Sent::Gone)
    }

    fn state(&self) -> RootState {
        (self.state)()
    }

    #[cfg(unix)]
    fn number_holder(&self) -> NumberRead {
        let number = self
            .number
            .as_deref()
            .expect("a StatedRoot's number was read past the stated facts");
        number()
    }

    #[cfg(target_os = "linux")]
    fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.pidfd
    }
}
