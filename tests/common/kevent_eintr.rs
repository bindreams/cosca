//! Forces `EINTR` out of a `kevent` wait, which macOS returns even to a handler installed with
//! `SA_RESTART` (tokio's SIGCHLD handler is one).
//!
//! The thread that is about to block calls [`interrupt_once_blocked`]. A helper thread waits for
//! that thread's Mach run state to be WAITING, signals it, waits for the handler to have run, and
//! keeps signalling until the wait has COUNTED an `EINTR` retry ([`count_retry`], called by each
//! `kevent` wait on `EINTR`). A WAITING run state is any blocking wait, not necessarily the
//! `kevent`, so a signal can land elsewhere; the counter proves the wait itself was interrupted.
//! The helper then calls `release`, which must make the wait end. It also calls `release` if the
//! wait returned without a retry or if the helper itself panics, so a failure here never leaves
//! the waiter blocked.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Handler runs since process start. The interrupter reads it before each signal and waits for it
/// to change, so only its own deliveries are waited on.
static HANDLED: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// The retry counter of the wait this thread is about to run, if an [`Interrupter`] is armed
    /// for it. Per thread so a concurrent test's own `EINTR` (say, from `SIGCHLD`) is not counted.
    static RETRIES: RefCell<Option<Arc<AtomicUsize>>> = const { RefCell::new(None) };
}

/// Called by a `kevent` wait each time it retries after `EINTR`.
pub fn count_retry() {
    RETRIES.with(|r| {
        if let Some(counter) = r.borrow().as_ref() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
}

extern "C" fn handler(_: libc::c_int) {
    HANDLED.fetch_add(1, Ordering::SeqCst);
}

fn is_waiting(port: u32) -> bool {
    // SAFETY: a zeroed `thread_basic_info` is a valid out-parameter.
    let mut info: libc::thread_basic_info = unsafe { std::mem::zeroed() };
    let mut count = libc::THREAD_BASIC_INFO_COUNT;
    // SAFETY: `info` holds `count` integers, as `THREAD_BASIC_INFO` requires; `port` is a live
    // send right for a thread of this process.
    let kr = unsafe {
        libc::thread_info(
            port,
            libc::THREAD_BASIC_INFO as libc::thread_flavor_t,
            (&mut info as *mut libc::thread_basic_info).cast(),
            &mut count,
        )
    };
    assert_eq!(kr, 0, "thread_info(THREAD_BASIC_INFO): kern_return {kr}");
    info.run_state == libc::TH_STATE_WAITING
}

/// Runs `release` when dropped, so every way out of the helper (a return, a panic) releases the
/// waiter.
struct ReleaseOnDrop<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for ReleaseOnDrop<F> {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            release();
        }
    }
}

/// The running interrupter. Dropping it, whether through [`finish`](Self::finish) or by unwinding,
/// stops and joins the helper, restores the signal handler and clears this thread's retry counter.
pub struct Interrupter {
    thread: Option<JoinHandle<()>>,
    previous: libc::sigaction,
    waiter_returned: Arc<AtomicBool>,
    retries: Arc<AtomicUsize>,
}

impl Interrupter {
    /// Call once the wait has returned or panicked. Fails unless the wait retried an `EINTR` on
    /// this thread since [`interrupt_once_blocked`]: a wait that never saw one proved nothing, and
    /// a wait that panicked on one did not retry.
    pub fn finish(self) {
        let retries = self.retries.clone();
        drop(self);
        assert!(
            retries.load(Ordering::SeqCst) >= 1,
            "the interrupted kevent wait never retried after EINTR"
        );
    }
}

impl Drop for Interrupter {
    fn drop(&mut self) {
        self.waiter_returned.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            if let Err(panic) = thread.join() {
                if !std::thread::panicking() {
                    std::panic::resume_unwind(panic);
                }
            }
        }
        RETRIES.with(|r| *r.borrow_mut() = None);
        // SAFETY: restores the action `interrupt_once_blocked` replaced.
        let rc = unsafe { libc::sigaction(libc::SIGUSR2, &self.previous, std::ptr::null_mut()) };
        debug_assert_eq!(rc, 0, "restore SIGUSR2: {}", std::io::Error::last_os_error());
    }
}

/// Call on the thread that is about to block in `kevent`. `release` runs on the helper thread once
/// the wait has counted an `EINTR` retry, and also when the wait returned first or the helper
/// panicked.
pub fn interrupt_once_blocked(release: impl FnOnce() + Send + 'static) -> Interrupter {
    // SAFETY: a zeroed `sigaction` is a valid starting value; the handler only touches an atomic.
    let (previous, rc) = unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as extern "C" fn(libc::c_int) as usize;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        let mut previous: libc::sigaction = std::mem::zeroed();
        let rc = libc::sigaction(libc::SIGUSR2, &action, &mut previous);
        (previous, rc)
    };
    assert_eq!(rc, 0, "install SIGUSR2: {}", std::io::Error::last_os_error());
    let retries = Arc::new(AtomicUsize::new(0));
    RETRIES.with(|r| *r.borrow_mut() = Some(retries.clone()));
    let counted = retries.clone();
    let waiter_returned = Arc::new(AtomicBool::new(false));
    let returned = waiter_returned.clone();
    // SAFETY: plain queries of the calling thread.
    let (waiter, port) = unsafe {
        let me = libc::pthread_self();
        (me as usize, libc::pthread_mach_thread_np(me))
    };
    let thread = std::thread::spawn(move || {
        let _release = ReleaseOnDrop(Some(release));
        loop {
            if counted.load(Ordering::SeqCst) != 0 || returned.load(Ordering::SeqCst) {
                return;
            }
            if !is_waiting(port) {
                std::thread::yield_now();
                continue;
            }
            let handled = HANDLED.load(Ordering::SeqCst);
            // SAFETY: the waiter is alive: it is in a wait this thread has not yet released.
            let rc = unsafe { libc::pthread_kill(waiter as libc::pthread_t, libc::SIGUSR2) };
            assert_eq!(rc, 0, "pthread_kill: {rc}");
            while HANDLED.load(Ordering::SeqCst) == handled {
                std::thread::yield_now();
            }
            // The handler ran. A signal that hit the `kevent` is counted as a retry right after; one
            // that hit another wait is not, and the next iteration signals again.
        }
    });
    Interrupter {
        thread: Some(thread),
        previous,
        waiter_returned,
        retries,
    }
}
