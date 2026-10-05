//! Detection of a fork copy, with no descriptor, path or `/proc` read after creation, so that
//! checking it needs no resource a full fd table or a sandbox could refuse.
//!
//! A bare pid cannot tell a fork copy from its original: in another pid namespace the copy can have
//! the original's pid.
//!
//! - **Linux:** one page marked `MADV_WIPEONFORK` (kernel 4.14, below the 5.6 floor), with a marker
//!   byte set at creation. A fork copy reads zero. The check is a memory read and cannot fail.
//! - **macOS:** the process's audit token (`task_info(mach_task_self(), TASK_AUDIT_TOKEN)`: pid and
//!   pidversion), read at creation and again at each check. Unlike `proc_pidinfo`, it works under a
//!   Seatbelt sandbox entered after creation. The read is a call that could in principle fail, so
//!   [`Origin::Unknown`] exists: a contract violation, reported on stderr, and never taken for either
//!   answer.
//! - **Other platforms:** no exact mechanism, so [`ForkGuard::new`] is `Unsupported`.

use std::io;

/// What [`ForkGuard::origin`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// The process that created the guard.
    Original,
    /// A fork copy of it.
    Copy,
    /// The platform could not say (macOS only, and a contract violation). Whoever asks must do only
    /// what is safe in both cases: nothing shared with the original, and nothing that waits on it.
    Unknown,
}

/// Writes `message` to stderr with a bare `write(2)`: for a process that may be a fork copy, where the
/// `log` facade and the allocator are not safe to use. A failed write is ignored.
pub(crate) fn warn_unlogged(message: &[u8]) {
    // SAFETY: `write` to fd 2 from a valid buffer.
    unsafe { libc::write(2, message.as_ptr().cast(), message.len()) };
}

/// Created by the original; [`origin`](Self::origin) is [`Origin::Copy`] in a fork copy of it.
pub(crate) struct ForkGuard {
    guard: imp::Guard,
    /// A test makes the guard unable to say.
    #[cfg(test)]
    unreadable: std::sync::atomic::AtomicBool,
}

impl ForkGuard {
    /// An error if the platform cannot give the guard its identity, or has no exact mechanism.
    pub(crate) fn new() -> io::Result<ForkGuard> {
        Ok(ForkGuard {
            guard: imp::Guard::new()?,
            #[cfg(test)]
            unreadable: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Which process this is. Never panics in a release build; see [`Origin::Unknown`].
    pub(crate) fn origin(&self) -> Origin {
        #[cfg(test)]
        if self.unreadable.load(std::sync::atomic::Ordering::SeqCst) {
            return Origin::Unknown;
        }
        match self.guard.origin() {
            Ok(origin) => origin,
            Err(why) => {
                // Possibly a fork copy, which must not take the `log` facade's locks.
                warn_unlogged(b"cosca: cannot tell whether this process made a fork guard\n");
                debug_assert!(false, "the fork guard's identity read failed: {why}");
                Origin::Unknown
            }
        }
    }

    /// Makes [`origin`](Self::origin) answer [`Origin::Unknown`], as a failed read would.
    #[cfg(test)]
    pub(crate) fn make_unreadable(&self) {
        self.unreadable.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::ptr::NonNull;

    use rustix::mm::{madvise, mmap_anonymous, munmap, Advice, MapFlags, ProtFlags};

    use super::Origin;

    const MARKER: u8 = 0x5a;
    /// `mmap` rounds up to a page, which is what `madvise` covers.
    const LEN: usize = 1;

    pub(super) struct Guard(NonNull<u8>);

    // SAFETY: the page is only ever read, through a volatile read of one byte, after creation.
    unsafe impl Send for Guard {}
    // SAFETY: as above.
    unsafe impl Sync for Guard {}

    impl Guard {
        pub(super) fn new() -> io::Result<Guard> {
            // SAFETY: an anonymous private mapping at a kernel-chosen address.
            let page = unsafe {
                mmap_anonymous(
                    std::ptr::null_mut(),
                    LEN,
                    ProtFlags::READ | ProtFlags::WRITE,
                    MapFlags::PRIVATE,
                )
            }?;
            // SAFETY: `page` is a fresh mapping of at least `LEN` bytes.
            let wiped = unsafe { madvise(page, LEN, Advice::LinuxWipeOnFork) };
            if let Err(e) = wiped {
                // SAFETY: the mapping made above, not used again.
                unsafe { munmap(page, LEN) }.ok();
                return Err(e.into());
            }
            let page = NonNull::new(page.cast::<u8>()).expect("mmap does not return null");
            // SAFETY: writable, and in bounds.
            unsafe { page.as_ptr().write_volatile(MARKER) };
            Ok(Guard(page))
        }

        pub(super) fn origin(&self) -> Result<Origin, String> {
            // SAFETY: the mapping lives as long as `self`.
            let marker = unsafe { self.0.as_ptr().read_volatile() };
            Ok(if marker == MARKER {
                Origin::Original
            } else {
                Origin::Copy
            })
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: the mapping made in `new`, not used after this.
            unsafe { munmap(self.0.as_ptr().cast(), LEN) }.ok();
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::io;

    use mach2::kern_return::KERN_SUCCESS;
    use mach2::message::audit_token_t;
    use mach2::task::task_info;
    use mach2::task_info::{TASK_AUDIT_TOKEN, TASK_AUDIT_TOKEN_COUNT};
    use mach2::traps::mach_task_self;

    use super::Origin;

    /// `(pid, pidversion)`: `audit_token_to_pid` and `audit_token_to_pidversion`.
    type Ids = (u32, u32);

    pub(super) struct Guard(Ids);

    /// This process's pid and pidversion, from its own task: no descriptor, no `proc_pidinfo`, and no
    /// permission a sandbox could take away.
    fn own_ids() -> Result<Ids, String> {
        let mut token = audit_token_t::default();
        let mut count = TASK_AUDIT_TOKEN_COUNT;
        // SAFETY: `token` is `count` words of writable memory; `mach_task_self` has no preconditions.
        let kr = unsafe {
            task_info(
                mach_task_self(),
                TASK_AUDIT_TOKEN,
                (&mut token as *mut audit_token_t).cast(),
                &mut count,
            )
        };
        if kr == KERN_SUCCESS && count == TASK_AUDIT_TOKEN_COUNT {
            Ok((token.val[5], token.val[7]))
        } else {
            Err(format!("task_info(TASK_AUDIT_TOKEN) returned {kr} with {count} words"))
        }
    }

    impl Guard {
        pub(super) fn new() -> io::Result<Guard> {
            own_ids().map(Guard).map_err(io::Error::other)
        }

        pub(super) fn origin(&self) -> Result<Origin, String> {
            own_ids().map(|ids| if ids == self.0 { Origin::Original } else { Origin::Copy })
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use std::io;

    use super::Origin;

    pub(super) struct Guard;

    impl Guard {
        pub(super) fn new() -> io::Result<Guard> {
            Err(io::ErrorKind::Unsupported.into())
        }

        pub(super) fn origin(&self) -> Result<Origin, String> {
            Ok(Origin::Unknown)
        }
    }
}

#[cfg(test)]
#[path = "fork_guard_tests.rs"]
mod fork_guard_tests;
