//! Forces `EINTR` out of a `kevent` wait, which macOS returns even to a handler installed with
//! `SA_RESTART` (tokio's SIGCHLD handler is one).
//!
//! The thread that is about to block calls [`interrupt_once_blocked`]. A helper thread waits for
//! that thread's Mach run state to be WAITING (parked in `kevent`), signals it, waits for the
//! handler to have run, and keeps signalling until the wait has COUNTED an `EINTR` retry
//! ([`count_retry`], called by each `kevent` wait on `EINTR`). Only then does it call `release`,
//! which must make the wait end. A WAITING run state is any blocking wait, not necessarily the
//! `kevent`, so a signal can land elsewhere; the counter is what proves the wait itself was
//! interrupted, and the loop ends on it, not on a clock or a count.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Handler runs since process start. One test per binary uses this, so a baseline read at install
/// time identifies this test's deliveries.
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

const TH_STATE_WAITING: i32 = 3;
const THREAD_BASIC_INFO: i32 = 3;
/// `sizeof(thread_basic_info_data_t) / sizeof(integer_t)`.
const THREAD_BASIC_INFO_COUNT: u32 = 10;
/// Index of `run_state` in `thread_basic_info`: two `time_value_t` (2 ints each), `cpu_usage`, `policy`.
const RUN_STATE: usize = 6;

unsafe extern "C" {
    /// `<mach/thread_act.h>`; not in `mach2`.
    fn thread_info(thread: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
}

extern "C" fn handler(_: libc::c_int) {
    HANDLED.fetch_add(1, Ordering::SeqCst);
}

fn is_waiting(port: u32) -> bool {
    let mut info = [0i32; THREAD_BASIC_INFO_COUNT as usize];
    let mut count = THREAD_BASIC_INFO_COUNT;
    // SAFETY: `info` holds `count` integers, as `THREAD_BASIC_INFO` requires; `port` is a live
    // send right for a thread of this process.
    let kr = unsafe { thread_info(port, THREAD_BASIC_INFO, info.as_mut_ptr(), &mut count) };
    assert_eq!(kr, 0, "thread_info(THREAD_BASIC_INFO): kern_return {kr}");
    info[RUN_STATE] == TH_STATE_WAITING
}

/// The running interrupter; [`finish`](Self::finish) joins it and restores the signal handler.
pub struct Interrupter {
    thread: JoinHandle<()>,
    previous: libc::sigaction,
    waiter_returned: Arc<AtomicBool>,
    retries: Arc<AtomicUsize>,
}

impl Interrupter {
    /// Call once the wait has returned or panicked. Fails unless the wait retried an `EINTR`
    /// on this thread since [`interrupt_once_blocked`]: a wait that never saw one proved nothing, and a wait that
    /// panicked on one did not retry.
    pub fn finish(self) {
        self.waiter_returned.store(true, Ordering::SeqCst);
        self.thread.join().expect("the interrupter thread");
        RETRIES.with(|r| *r.borrow_mut() = None);
        let retried = self.retries.load(Ordering::SeqCst);
        assert!(retried >= 1, "the interrupted kevent wait never retried after EINTR");
        // SAFETY: restores the action `interrupt_once_blocked` replaced.
        let rc = unsafe { libc::sigaction(libc::SIGUSR2, &self.previous, std::ptr::null_mut()) };
        assert_eq!(rc, 0, "restore SIGUSR2: {}", std::io::Error::last_os_error());
    }
}

/// Call on the thread that is about to block in `kevent`. `release` runs on the helper thread
/// once the waiter has been interrupted at least once.
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
        // Ends on the waiter's own progress, never on a clock or a count: a retry was counted, or
        // the wait returned without one (the no-retry regression panics on its first `EINTR`).
        loop {
            if counted.load(Ordering::SeqCst) != 0 {
                break;
            }
            if returned.load(Ordering::SeqCst) {
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
        release();
    });
    Interrupter {
        thread,
        previous,
        waiter_returned,
        retries,
    }
}
