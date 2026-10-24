use ::tokio::runtime::{Builder, Handle};

use super::wait_in_place;
use crate::tokio::test_runtime::inside_block_in_place;

/// On a `current_thread` runtime the wait runs in place and does not panic.
///
/// Mutant: an unconditional `block_in_place`, which panics on this flavour.
#[skuld::test]
async fn a_wait_on_a_current_thread_runtime_runs_in_place() {
    crate::tokio::test_runtime::assert_current_thread();
    assert_eq!(wait_in_place(|| 7), 7);
}

/// On a multi-thread worker the wait runs inside `block_in_place`, which has left the runtime: the
/// worker's tasks keep running elsewhere.
///
/// Mutant: no `block_in_place`, so the wait holds the worker and the runtime is still entered.
#[skuld::test]
fn a_wait_on_a_multi_thread_worker_runs_in_block_in_place() {
    let runtime = Builder::new_multi_thread().worker_threads(1).build().unwrap();
    let (before, during) = runtime
        .block_on(runtime.spawn(async { (inside_block_in_place(), wait_in_place(inside_block_in_place)) }))
        .unwrap();
    assert!(!before, "a worker is inside the runtime, which this probe relies on");
    assert!(during, "the wait must run inside `block_in_place`");
}

/// Outside any runtime the wait runs in place.
#[skuld::test]
fn a_wait_outside_a_runtime_runs_in_place() {
    assert!(Handle::try_current().is_err());
    assert_eq!(wait_in_place(|| 7), 7);
}
