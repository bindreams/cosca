//! The runtime a `start_paused` test runs on, for `#[skuld::test(runtime = ...)]`.

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

/// Panics unless the caller runs on a current-thread runtime, skuld's default. A test whose seam is
/// a thread-local calls it first: a multi-thread runtime could move its futures to another thread.
pub(crate) fn assert_current_thread() {
    assert_eq!(
        ::tokio::runtime::Handle::current().runtime_flavor(),
        ::tokio::runtime::RuntimeFlavor::CurrentThread,
        "this test's seam is thread-local: its futures must be polled on this thread"
    );
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
