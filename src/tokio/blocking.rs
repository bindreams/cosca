//! Where a spawn's unavoidable wait for a killed child's exit runs.

/// Runs `wait`, a wait for a process to exit that cannot be made async, on the calling thread. On a
/// multi-thread runtime it runs inside [`block_in_place`](::tokio::task::block_in_place), which hands
/// the worker's tasks to another thread first. On a `current_thread` runtime, or outside one, it runs
/// in place: `block_in_place` would panic there, and the runtime stops until the wait ends.
pub(crate) fn wait_in_place<R>(wait: impl FnOnce() -> R) -> R {
    use ::tokio::runtime::{Handle, RuntimeFlavor};

    match Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => ::tokio::task::block_in_place(wait),
        _ => wait(),
    }
}

#[cfg(test)]
#[path = "blocking_tests.rs"]
mod blocking_tests;
