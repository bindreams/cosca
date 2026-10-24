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

/// Panics unless the caller runs on a current-thread runtime, skuld's default. A test whose seam is
/// a thread-local calls it first: a multi-thread runtime could move its futures to another thread.
pub(crate) fn assert_current_thread() {
    assert_eq!(
        ::tokio::runtime::Handle::current().runtime_flavor(),
        ::tokio::runtime::RuntimeFlavor::CurrentThread,
        "this test's seam is thread-local: its futures must be polled on this thread"
    );
}

/// Whether the caller runs inside `block_in_place`: tokio allows `Handle::block_on` only on a thread
/// that has left the runtime, which `block_in_place` does and nothing else on a worker does.
pub(crate) fn inside_block_in_place() -> bool {
    std::panic::catch_unwind(|| ::tokio::runtime::Handle::current().block_on(async {})).is_ok()
}

#[cfg(test)]
#[path = "test_runtime_tests.rs"]
mod test_runtime_tests;
