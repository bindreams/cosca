//! The runtime a `start_paused` test runs on, for `#[skuld::test(runtime = ...)]`.

#[cfg(windows)]
use crate::test_child::Parked;

/// A current-thread runtime with I/O and time drivers and the clock paused, as
/// `#[tokio::test(start_paused = true)]` builds it.
pub(crate) fn paused() -> ::tokio::runtime::Runtime {
    ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("build the paused test runtime")
}

/// A current-thread runtime with I/O and time drivers whose blocking pool is one thread, for a test
/// that decides what that thread is doing, or that must see a wait queue behind it for ever.
pub(crate) fn single_thread_pool_runtime() -> ::tokio::runtime::Runtime {
    ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .expect("build a runtime with a one-thread blocking pool")
}

/// The unbounded exit waits the blocking-pool thread of [`watched_pool_runtime`] made.
#[cfg(windows)]
#[derive(Clone, Default)]
pub(crate) struct PoolBlocks(std::sync::Arc<std::sync::atomic::AtomicU32>);

#[cfg(windows)]
impl PoolBlocks {
    /// Fails unless no exit wait blocked on the pool. Counted here because a panic on the pool
    /// thread would be a `JoinError` that a mutant's own code could swallow.
    #[track_caller]
    pub(crate) fn assert_none(&self) {
        let blocks = self.0.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(blocks, 0, "an unbounded exit wait blocked on the blocking pool");
    }
}

#[cfg(windows)]
thread_local! {
    /// The hook armed on this blocking-pool thread, kept until the thread stops.
    static POOL_HOOK: std::cell::RefCell<Option<crate::wait::block_probe::Armed>> =
        const { std::cell::RefCell::new(None) };
}

/// [`single_thread_pool_runtime`] whose pool thread releases `held` at any block it makes, of
/// whatever kind, so no wait there can hold the test, and counts as the failure only an unbounded
/// exit wait (a `WaitObject::Handles` block armed `None`, the one a wait run on the pool by mistake
/// makes): the test fails by asserting [`PoolBlocks::assert_none`] after its join.
#[cfg(windows)]
pub(crate) fn watched_pool_runtime(held: Vec<Parked>) -> (::tokio::runtime::Runtime, PoolBlocks) {
    use crate::wait::block_probe::{on_each_block, WaitObject};

    let blocks = PoolBlocks::default();
    let seen = blocks.clone();
    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .on_thread_start(move || {
            let seen = seen.clone();
            let held = held.clone();
            let hook = on_each_block(move |block| {
                if matches!(block.on, WaitObject::Handles) && block.armed.is_none() {
                    seen.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                held.iter().for_each(Parked::release);
            });
            POOL_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
        })
        .on_thread_stop(|| POOL_HOOK.with(|slot| drop(slot.borrow_mut().take())))
        .build()
        .expect("build a runtime whose one-thread blocking pool is watched");
    (rt, blocks)
}

/// Panics unless the caller runs on a current-thread runtime, skuld's default. A test whose seam is
/// a thread-local calls it first: a multi-thread runtime could move its futures to another thread.
pub(crate) fn assert_current_thread() {
    assert_eq!(
        ::tokio::runtime::Handle::current().runtime_flavor(),
        ::tokio::runtime::RuntimeFlavor::CurrentThread,
        "this test's seam is thread-local: its futures must be polled on this thread"
    );
}

/// Awaits `f` and fails if it blocked its thread on an OS wait: a driver wait that called its blocking
/// twin would stall every task on this runtime thread.
pub(crate) async fn never_blocking<F: std::future::Future>(f: F) -> F::Output {
    use std::cell::Cell;
    use std::rc::Rc;

    let blocked = Rc::new(Cell::new(false));
    let _hook = crate::wait::block_probe::on_blocking({
        let blocked = blocked.clone();
        move || blocked.set(true)
    });
    let output = f.await;
    assert!(!blocked.get(), "the call blocked a runtime thread");
    output
}

/// A waker that sends once for each wake, for a test that polls a future by hand and needs to know
/// when it is woken.
struct Woken(std::sync::Mutex<std::sync::mpsc::Sender<()>>);

impl std::task::Wake for Woken {
    fn wake(self: std::sync::Arc<Self>) {
        _ = self.0.lock().expect("the sender").send(());
    }
}

/// A waker, and the receiver that gets one `()` for each time it is woken.
pub(crate) fn counting_waker() -> (std::task::Waker, std::sync::mpsc::Receiver<()>) {
    let (woken, wakes) = std::sync::mpsc::channel();
    let waker = std::task::Waker::from(std::sync::Arc::new(Woken(std::sync::Mutex::new(woken))));
    (waker, wakes)
}

#[cfg(test)]
#[path = "test_runtime_tests.rs"]
mod test_runtime_tests;
