//! `run_ready`: the sync driver's one poll.

use super::run_ready;

/// Mutant: a future that is ready is polled again or its value dropped.
#[skuld::test]
fn a_ready_future_gives_its_output_through_every_await() {
    async fn ready(n: u32) -> u32 {
        n
    }
    assert_eq!(run_ready(async { ready(1).await + ready(2).await }), 3);
}

/// Mutant: a pending future is waited for instead of refused.
#[skuld::test]
#[should_panic(expected = "run_ready: the future is pending, but a blocking driver's waits are all ready")]
fn a_pending_future_is_a_broken_contract() {
    run_ready(std::future::pending::<()>());
}
