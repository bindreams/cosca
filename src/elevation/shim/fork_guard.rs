//! Exact detection of a fork copy, with no I/O after creation, so that checking it can neither fail
//! nor panic, and a `Drop` that checks it cannot abort an unwind.
//!
//! A bare pid cannot tell a fork copy from its original: in another pid namespace the copy can have
//! the original's pid.
//!
//! - **Linux:** one page marked `MADV_WIPEONFORK` (kernel 4.14, below the 5.6 floor), with a marker
//!   byte set at creation. A fork copy reads zero.
//! - **macOS:** the process's unique id (`proc_pidinfo` flavour 17, which takes no descriptor), read
//!   at creation; a copy is another process, with another id.

use std::io;

/// Created by the original; [`is_original`](Self::is_original) is `false` in a fork copy of it.
pub(crate) struct ForkGuard(imp::Guard);

impl ForkGuard {
    /// An error if the platform cannot give the guard its identity.
    pub(crate) fn new() -> io::Result<ForkGuard> {
        imp::Guard::new().map(ForkGuard)
    }

    /// Whether this is the process that created the guard. A question the platform cannot answer
    /// (macOS only) is `false`: whatever is guarded is then left alone, never torn down on a guess.
    pub(crate) fn is_original(&self) -> bool {
        self.0.is_original()
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::ptr::NonNull;

    use rustix::mm::{madvise, mmap_anonymous, munmap, Advice, MapFlags, ProtFlags};

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

        pub(super) fn is_original(&self) -> bool {
            // SAFETY: the mapping lives as long as `self`.
            unsafe { self.0.as_ptr().read_volatile() == MARKER }
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: the mapping made in `new`, not used after this.
            unsafe { munmap(self.0.as_ptr().cast(), LEN) }.ok();
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::io;

    pub(super) struct Guard(u64);

    #[cfg(target_os = "macos")]
    fn unique_id() -> Result<u64, i32> {
        crate::identity::own_unique_id()
    }

    /// Other Unixes: the pid, which a fork copy outside a pid namespace does not share.
    #[cfg(not(target_os = "macos"))]
    fn unique_id() -> Result<u64, i32> {
        Ok(u64::from(std::process::id()))
    }

    impl Guard {
        pub(super) fn new() -> io::Result<Guard> {
            unique_id().map(Guard).map_err(io::Error::from_raw_os_error)
        }

        pub(super) fn is_original(&self) -> bool {
            match unique_id() {
                Ok(id) => id == self.0,
                Err(errno) => {
                    log::warn!("cannot read this process's unique id (errno {errno}); treating it as a fork copy");
                    false
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "fork_guard_tests.rs"]
mod fork_guard_tests;
