//! Waiting for a cgroup leaf to drain: its `populated` reading 0, or the leaf being removed.
//!
//! A `cgroup.events` notification alone is not enough. The kernel rate-limits them: one that comes
//! within 10 ms of the previous is postponed on a timer (`cgroup_file_notify`), and removing the
//! cgroup cancels that timer (`cgroup_rm_file`'s `del_timer_sync`) without notifying. Removing the
//! file wakes no `poll` waiter either (`kernfs_drain_open_files`). So a leaf that drains and is
//! removed at once, by any party, can leave a waiter on `cgroup.events` blocked for good. What a
//! removal does deliver is `IN_DELETE` to its parent directory's watchers, since every cgroup
//! `rmdir` goes through `vfs_rmdir`, which ends in `d_delete_notify` → `fsnotify_delete`. (Kernel
//! v6.12: `kernel/cgroup/cgroup.c`, `fs/kernfs/file.c`, `fs/namei.c`, `include/linux/fsnotify.h`.)
//!
//! So the watch is one inotify instance holding two watches, both armed before the first read:
//! `IN_MODIFY` on `cgroup.events`, which the kernel's notification work delivers once it runs
//! (`kernfs_notify_workfn`; the watch keeps the file's inode cached, which that work needs), and
//! `IN_DELETE` on the parent, for the leaf's own name.
//!
//! Creating an inotify instance can fail (`EMFILE` at `fs.inotify.max_user_instances`, 128 per
//! user by default), as can adding a watch (`ENOSPC`). The watch then falls back to `POLLPRI` on
//! `cgroup.events`, which is what the kernel offers without inotify. It never strands a leaf: it
//! wakes on every notification that is delivered. It keeps the gap above: a third party removing
//! the leaf within 10 ms of its previous notification leaves the wait blocked.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::Path;

use rustix::event::PollFlags;
use rustix::fs::inotify;

use super::{read_populated, removed_after_drain};
use crate::containment::TreeDrain;
use crate::error::Error;

/// A watch on one leaf's drain. See the module docs.
pub(crate) struct DrainWatch {
    /// The leaf's `cgroup.events`, read for `populated`.
    events: File,
    wake: Wake,
    /// Whether the leaf was seen removed.
    gone: bool,
    buf: String,
}

/// What wakes the wait.
enum Wake {
    /// `IN_MODIFY` on `cgroup.events`, and `IN_DELETE` of `name` on the parent.
    Inotify { fd: OwnedFd, parent: i32, name: OsString },
    /// No inotify: `POLLPRI` on `cgroup.events`.
    Priority,
}

impl DrainWatch {
    /// Arm a watch on the leaf at `leaf`, before anything is read. `None`: the leaf is already gone.
    pub(crate) fn arm(leaf: &Path) -> Result<Option<DrainWatch>, Error> {
        let events_path = leaf.join("cgroup.events");
        let wake = match Wake::inotify(leaf, &events_path) {
            Ok(Some(wake)) => wake,
            Ok(None) => return Ok(None),
            Err(e) => {
                log::debug!(
                    "cgroup leaf {}: no inotify watch ({e}); waiting on cgroup.events alone",
                    leaf.display()
                );
                Wake::Priority
            }
        };
        let events = match File::open(&events_path) {
            Ok(f) => f,
            Err(e) if removed_after_drain(&e) => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        };
        Ok(Some(DrainWatch {
            events,
            wake,
            gone: false,
            buf: String::new(),
        }))
    }

    /// Whether the leaf still has a member. A removed leaf has none.
    pub(crate) fn populated(&mut self) -> Result<bool, Error> {
        if self.gone {
            return Ok(false);
        }
        read_populated(&mut self.events, &mut self.buf)
    }

    /// The readiness that means "look again" on [`as_raw_fd`](AsRawFd::as_raw_fd).
    pub(crate) fn readiness(&self) -> PollFlags {
        match self.wake {
            Wake::Inotify { .. } => PollFlags::IN,
            Wake::Priority => PollFlags::PRI,
        }
    }

    /// Take in what made the fd ready, without blocking.
    pub(crate) fn consume(&mut self) -> Result<(), Error> {
        let Wake::Inotify { fd, parent, name } = &self.wake else {
            // `populated`'s next read rearms kernfs's event count.
            return Ok(());
        };
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
        let mut reader = inotify::Reader::new(fd, &mut buf);
        loop {
            match reader.next() {
                Ok(event) => {
                    let named_us = event
                        .file_name()
                        .is_some_and(|n| n.to_bytes() == name.as_encoded_bytes());
                    if event.wd() == *parent && event.events().contains(inotify::ReadFlags::DELETE) && named_us {
                        self.gone = true;
                    }
                }
                Err(rustix::io::Errno::AGAIN) => return Ok(()),
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(Error::Io(e.into())),
            }
        }
    }

    /// Block until the leaf drains or `deadline` passes (see [`crate::wait::remaining`]). No
    /// interval: each round is one `poll` for the caller's own remaining time.
    pub(crate) fn wait(&mut self, deadline: Option<Option<std::time::Instant>>) -> Result<TreeDrain, Error> {
        use rustix::event::{poll, PollFd};

        loop {
            if !self.populated()? {
                return Ok(TreeDrain::AllMembersExited);
            }
            let remaining = crate::wait::remaining(deadline);
            if remaining == Some(std::time::Duration::ZERO) {
                return Ok(TreeDrain::MembersRemain);
            }
            let ts = remaining.map(|d| rustix::event::Timespec {
                tv_sec: d.as_secs().min(i64::MAX as u64) as i64,
                tv_nsec: d.subsec_nanos() as _,
            });
            #[cfg(test)]
            super::fault::notify_drain_blocking();
            let mut fds = [PollFd::from_borrowed_fd(self.wait_fd(), self.readiness())];
            match poll(&mut fds, ts.as_ref()) {
                Ok(0) => return Ok(TreeDrain::MembersRemain),
                Ok(_) => self.consume()?,
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(Error::Io(e.into())),
            }
        }
    }

    fn wait_fd(&self) -> BorrowedFd<'_> {
        match &self.wake {
            Wake::Inotify { fd, .. } => fd.as_fd(),
            Wake::Priority => self.events.as_fd(),
        }
    }
}

impl AsRawFd for DrainWatch {
    fn as_raw_fd(&self) -> RawFd {
        self.wait_fd().as_raw_fd()
    }
}

impl Wake {
    /// The inotify watch. `Ok(None)`: the leaf is already gone.
    fn inotify(leaf: &Path, events_path: &Path) -> io::Result<Option<Wake>> {
        #[cfg(test)]
        if super::fault::take_force_inotify_failure() {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        let (Some(parent_path), Some(name)) = (leaf.parent(), leaf.file_name()) else {
            return Err(io::Error::other("a cgroup leaf path has a parent and a name"));
        };
        let fd = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK)?;
        let parent = match inotify::add_watch(
            &fd,
            parent_path,
            inotify::WatchFlags::DELETE | inotify::WatchFlags::ONLYDIR,
        ) {
            Ok(wd) => wd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match inotify::add_watch(&fd, events_path, inotify::WatchFlags::MODIFY) {
            Ok(_) => {}
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        Ok(Some(Wake::Inotify {
            fd,
            parent,
            name: name.to_os_string(),
        }))
    }
}
