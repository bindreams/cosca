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
//! `IN_DELETE` on the parent, for the leaf's own name. Both bind to the held inodes, through
//! `/proc/self/fd`, never to a path a mount could redirect.
//!
//! Each leaf arms one watch, at creation, read by the leaf's pump for every wait on the leaf
//! (see `watcher.rs`), and by the leaf's own teardown once the pump is stopped.
//!
//! An inotify instance counts against `fs.inotify.max_user_instances` (128 per user by default),
//! and each watch against `fs.inotify.max_user_watches`. Arming one can therefore fail, and a
//! failure is returned, never replaced by a weaker wait.
//!
//! A leaf's watch is held for the leaf's life, and its parent watch queues an event for every
//! sibling removed meanwhile, up to `fs.inotify.max_queued_events` (16384 by default) per
//! instance, kernel memory the user is charged for. A full queue loses events after an
//! `IN_Q_OVERFLOW`, which is harmless here: any event is only a reason to read `cgroup.events`
//! again, a removed leaf reads as drained (`ENODEV`), and each wait empties the queue.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use rustix::fs::inotify;

use super::{above_stdio, fd_path, read_populated, removed_after_drain, LeafDir};
use crate::containment::TreeDrain;
use crate::error::Error;

/// A watch on one leaf's drain. See the module docs.
pub(crate) struct DrainWatch {
    /// The leaf's `cgroup.events`, read for `populated`.
    events: File,
    /// The inotify instance: `IN_MODIFY` on `cgroup.events`, `IN_DELETE` on the parent.
    fd: OwnedFd,
    /// The parent's watch.
    parent: i32,
    /// The leaf's name in its parent.
    name: OsString,
    /// Whether the leaf was seen removed.
    gone: bool,
    buf: String,
}

impl DrainWatch {
    /// Arm a watch on the leaf `dir`, before anything is read. `None`: the leaf is already gone.
    pub(crate) fn arm(dir: &LeafDir) -> io::Result<Option<DrainWatch>> {
        let events = match dir.open("cgroup.events", rustix::fs::OFlags::RDONLY) {
            Ok(fd) => File::from(above_stdio(fd)?),
            Err(e) if removed_after_drain(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        #[cfg(test)]
        super::fault::record_arm(dir.name());
        #[cfg(test)]
        if super::fault::take_force_inotify_failure() {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        let fd = above_stdio(inotify::init(
            inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK,
        )?)?;
        let parent = inotify::add_watch(
            &fd,
            fd_path(dir.parent()),
            inotify::WatchFlags::DELETE | inotify::WatchFlags::ONLYDIR,
        )?;
        inotify::add_watch(&fd, fd_path(events.as_fd()), inotify::WatchFlags::MODIFY)?;
        // A removal between the open and the parent's watch is still seen: reads through `events`
        // then fail with `ENODEV`.
        Ok(Some(DrainWatch {
            events,
            fd,
            parent,
            name: dir.name().to_os_string(),
            gone: false,
            buf: String::new(),
        }))
    }

    /// Whether an event taken in so far said the leaf was removed.
    pub(crate) fn saw_removal(&self) -> bool {
        self.gone
    }

    /// Whether the leaf still has a member. A removed leaf has none.
    pub(crate) fn populated(&mut self) -> Result<bool, Error> {
        if self.gone {
            return Ok(false);
        }
        read_populated(&mut self.events, &mut self.buf)
    }

    /// Take in what made the watch readable, without blocking.
    pub(crate) fn consume(&mut self) -> Result<(), Error> {
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
        let mut reader = inotify::Reader::new(&self.fd, &mut buf);
        loop {
            match reader.next() {
                Ok(event) => {
                    let named_us = event
                        .file_name()
                        .is_some_and(|n| n.to_bytes() == self.name.as_encoded_bytes());
                    if event.wd() == self.parent && event.events().contains(inotify::ReadFlags::DELETE) && named_us {
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
        use rustix::event::{poll, PollFd, PollFlags};

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
            let mut fds = [PollFd::from_borrowed_fd(self.fd.as_fd(), PollFlags::IN)];
            match poll(&mut fds, ts.as_ref()) {
                Ok(0) => return Ok(TreeDrain::MembersRemain),
                Ok(_) => self.consume()?,
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(Error::Io(e.into())),
            }
        }
    }
}

impl AsRawFd for DrainWatch {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for DrainWatch {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
