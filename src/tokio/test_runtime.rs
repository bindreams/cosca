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

#[cfg(test)]
#[path = "test_runtime_tests.rs"]
mod test_runtime_tests;
