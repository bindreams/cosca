//! Which fates of a forgotten tokio `Child` keep the root's pidfd in the backend that replaces it.

use super::proc_source::Forgotten;
use crate::test_child::reaped_elsewhere::reap_behind;

/// Forgets the live root of a fresh handle as `fate`, and answers whether the handle still holds
/// the root's pidfd.
async fn holds_the_pidfd_after_forgetting_a_live_root_as(fate: Forgotten) -> bool {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = super::root_state_tests::session_blocker(false);
    let pid = child.id().pid();
    assert!(child.root_pidfd().is_some(), "a spawned handle holds its root's pidfd");
    child.proc_mut().forget_as("was forgotten by a test", fate);
    let held = child.root_pidfd().is_some();
    drop(writer);
    reap_behind(pid);
    held
}

/// Mutant: "the pidfd is handed off for every fate".
#[skuld::test]
async fn an_unproven_forget_keeps_no_pidfd() {
    assert!(
        !holds_the_pidfd_after_forgetting_a_live_root_as(Forgotten::Unproven).await,
        "a child not shown to be ours is not reached through the handle any more"
    );
}

/// Mutant: "the pidfd is dropped for every fate".
#[skuld::test]
async fn a_forget_as_reaped_elsewhere_keeps_the_pidfd() {
    assert!(
        holds_the_pidfd_after_forgetting_a_live_root_as(Forgotten::ReapedElsewhere).await,
        "the root's group is still decided through its pidfd"
    );
}
