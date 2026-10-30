//! macOS: the kqueue behind [`WaitFor::Kqueue`](super::WaitFor::Kqueue).

use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use nix::sys::event::{EvFlags, Kqueue};

use crate::error::Error;
use crate::wait::backend::{arm_note_exit_on, block_on_kqueue, drain_proc_exit};

/// A kqueue armed for one event, and whether that event was ever read. A kqueue reports an exit
/// once, so a wait that consumed it must not hide it from the next look: `seen` stays set.
///
/// An `AtomicBool`, not a `Cell`, so a future that holds `&ExitWatch` stays `Send`.
#[derive(Debug)]
pub(crate) struct ExitWatch {
    kq: Kqueue,
    seen: AtomicBool,
}

impl ExitWatch {
    fn new(kq: Kqueue) -> Self {
        Self {
            kq,
            seen: AtomicBool::new(false),
        }
    }

    /// Arm `NOTE_EXIT` for `pid`. `Ok(None)`: the pid is already gone.
    pub(crate) fn proc_exit(pid: u32) -> Result<Option<Self>, Error> {
        let kq = Kqueue::new().map_err(|e| Error::Io(e.into()))?;
        Ok(arm_note_exit_on(&kq, pid)?.map(|()| Self::new(kq)))
    }

    /// Arm `EVFILT_READ` on `fd`, a pipe the test fires.
    #[cfg(test)]
    pub(crate) fn readable(fd: BorrowedFd<'_>) -> Result<Self, Error> {
        use std::os::fd::AsRawFd;

        use nix::sys::event::{EventFilter, FilterFlag, KEvent};

        let kq = Kqueue::new().map_err(|e| Error::Io(e.into()))?;
        let change = KEvent::new(
            fd.as_raw_fd() as usize,
            EventFilter::EVFILT_READ,
            EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
            FilterFlag::empty(),
            0,
            0,
        );
        match crate::wait::backend::add_with_receipt(&kq, change)? {
            0 => Ok(Self::new(kq)),
            errno => Err(Error::Io(std::io::Error::from_raw_os_error(errno as i32))),
        }
    }

    /// Block until the event has been read, by this call or an earlier one, or until `deadline`.
    /// `Ok(true)` = the event was read. An `EV_ERROR` event is `Err`.
    pub(crate) fn block(&self, deadline: Option<Option<Instant>>) -> Result<bool, Error> {
        if self.seen.load(Ordering::Relaxed) {
            return Ok(true);
        }
        block_on_kqueue(&self.kq, deadline, false, |event, _already_elapsed| {
            if event.flags().contains(EvFlags::EV_ERROR) {
                return Err(Error::Io(std::io::Error::from_raw_os_error(event.data() as i32)));
            }
            self.seen.store(true, Ordering::Relaxed);
            Ok(Some(true))
        })
    }

    /// Read a pending event without blocking. `Ok(true)` = the event has been read, now or
    /// earlier. An `EV_ERROR` event is `Err`.
    pub(crate) fn drain(&self) -> Result<bool, Error> {
        if drain_proc_exit(&self.kq)?.is_some() {
            self.seen.store(true, Ordering::Relaxed);
        }
        Ok(self.seen.load(Ordering::Relaxed))
    }

    /// The kqueue's descriptor, for a reactor that registers it.
    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        self.kq.as_fd()
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
