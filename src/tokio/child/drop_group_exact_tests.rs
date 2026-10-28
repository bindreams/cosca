//! Async twin of `child/drop_group_exact_tests.rs`: the drop and a failed elevated spawn's cleanup,
//! for a process group whose root is reaped. On Linux 6.9+ the root's pidfd decides; below 6.9
//! nothing goes out by the group's number.

use super::group_exact_tests::{kill_and_reap_behind, releasable_group_root, releasable_root_with_a_member};
use crate::send_log::{assert_group_signalled_first_through_the_pidfd, Capture};
use crate::test_child::reaped_elsewhere::kill_own_child;
use crate::test_groups::{pidfd_group_signal, Group};

/// Who reaps the root.
#[derive(Debug, Clone, Copy)]
enum Reap {
    /// This handle's own `wait`.
    Own,
    /// Another reaper in the process, behind the handle's back.
    Foreign,
    /// A foreign reap that this handle's `try_wait` then observed: it forgets tokio's `Child`.
    ForeignSeenByTryWait,
    /// A foreign reap that this handle's `wait` then observed: it forgets tokio's `Child`.
    ForeignSeenByWait,
    /// A foreign reap that this handle's second `kill` then observed: it forgets tokio's `Child`.
    ForeignSeenByKill,
    /// As `ForeignSeenByKill`, but the kill's look at the root fails: it forgets tokio's `Child` as
    /// not shown to be ours.
    ForeignSeenByKillWithAFailedPeek,
}

/// The teardown under test.
#[derive(Debug, Clone, Copy)]
enum Teardown {
    Drop,
    FinishElevated,
}

/// Ends `child`'s root alone by [`kill_own_child`] (the kill is setup here) and has `reap` reap it
/// (see [`kill_and_reap_behind`] for `release`).
async fn reap_root(child: &mut crate::tokio::Child, release: std::io::PipeWriter, reap: Reap) {
    match reap {
        Reap::Own => {
            kill_own_child(child.id().pid());
            drop(release);
            let status = child.wait().await.expect("this handle reaps the root");
            crate::test_child::assert_killed("the root", status);
        }
        Reap::Foreign => kill_and_reap_behind(child, release),
        Reap::ForeignSeenByTryWait => {
            kill_and_reap_behind(child, release);
            child.try_wait().expect_err("a foreign reap answers ECHILD");
        }
        Reap::ForeignSeenByWait => {
            kill_and_reap_behind(child, release);
            child.wait().await.expect_err("a foreign reap answers ECHILD");
        }
        Reap::ForeignSeenByKill => {
            kill_and_reap_behind(child, release);
            child.kill().expect("a root reaped elsewhere has nothing left to kill");
        }
        Reap::ForeignSeenByKillWithAFailedPeek => {
            use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
            kill_and_reap_behind(child, release);
            let failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));
            child.kill().expect("a root reaped elsewhere has nothing left to kill");
            assert_peeks_exhausted();
            drop(failed);
        }
    }
}

/// Runs `teardown` on `child`: the error's detail for a cleanup, `None` for a drop.
fn tear_down(child: crate::tokio::Child, teardown: Teardown) -> Option<String> {
    match teardown {
        Teardown::Drop => {
            drop(child);
            None
        }
        Teardown::FinishElevated => {
            let (err, _fate) = crate::tokio::finish_elevated(
                child,
                Err(crate::error::Error::Io(std::io::Error::other("no password"))),
            )
            .expect_err("the password write failed")
            .expect_may_have_started_with();
            Some(err.to_string())
        }
    }
}

/// 6.9+: a reaped root whose group still has a member: the teardown kills the group through the
/// root's pidfd.
async fn kills_the_group_left_behind(reap: Reap, teardown: Teardown) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, member, release) = releasable_root_with_a_member();
    reap_root(&mut child, release, reap).await;
    let capture = Capture::start();
    tear_down(child, teardown);
    let steps = capture.group_steps();
    assert_group_signalled_first_through_the_pidfd(&steps, libc::SIGKILL);
    member.assert_killed();
}

/// Below 6.9 the old behaviour holds: a reaped root's group is sent nothing, and its member lives
/// on.
async fn below_6_9_sends_nothing_to_the_group(reap: Reap, teardown: Teardown) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, member, release) = releasable_root_with_a_member();
    reap_root(&mut child, release, reap).await;
    let old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let capture = Capture::start();
    tear_down(child, teardown);
    let steps = capture.group_steps();
    drop(old_kernel);
    assert_eq!(steps, [], "nothing was sent to the group");
    member.assert_survived();
}

/// 6.9+: a reaped root whose group has no member left has no tree left behind: the teardown sends
/// nothing and reports no skipped kill.
async fn sends_nothing_to_an_empty_group_and_reports_no_skip(reap: Reap, teardown: Teardown) {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, release) = releasable_group_root();
    reap_root(&mut child, release, reap).await;
    let mark = crate::log_capture::mark();
    let capture = Capture::start();
    let detail = tear_down(child, teardown);
    let steps = capture.group_steps();
    assert_eq!(steps, [], "nothing was sent");
    if let Some(detail) = detail {
        assert!(!detail.contains("tree was not killed"), "{detail}");
    }
    // Nothing was left behind. A foreign reap still warns of forgetting tokio's `Child`, and of
    // nothing else.
    let warns: Vec<String> = crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level == log::Level::Warn)
        .map(|(_, text)| text)
        .collect();
    match reap {
        // A reap the handle saw forgot tokio's `Child`, and warned of it, before the teardown.
        Reap::Foreign => assert!(
            !warns.is_empty() && warns.iter().all(|warn| warn.contains(FORGOT_TOKIO_CHILD)),
            "only the forget of tokio's `Child` is warned of: {warns:?}"
        ),
        _ => assert_eq!(warns, Vec::<String>::new(), "nothing was left behind"),
    }
}

/// What the one warn of a teardown that forgot tokio's `Child` says.
const FORGOT_TOKIO_CHILD: &str = "forgetting tokio's handle for it leaks";

#[skuld::test]
async fn a_drop_after_its_own_wait_kills_the_group_left_behind(#[fixture(pidfd_group_signal)] _group: &Group) {
    kills_the_group_left_behind(Reap::Own, Teardown::Drop).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_kills_the_group_left_behind(#[fixture(pidfd_group_signal)] _group: &Group) {
    kills_the_group_left_behind(Reap::Foreign, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_its_own_wait_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::Own, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::Foreign, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_drop_after_its_own_wait_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::Own, Teardown::Drop).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::Foreign, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_its_own_wait_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::Own, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::Foreign, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_drop_after_its_own_wait_sends_nothing_to_an_empty_group_and_reports_no_skip(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::Own, Teardown::Drop).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_sends_nothing_to_an_empty_group_and_reports_no_skip(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::Foreign, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_its_own_wait_reports_no_skip_for_an_empty_group(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::Own, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_reports_no_skip_for_an_empty_group(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::Foreign, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_seen_by_try_wait_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::ForeignSeenByTryWait, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_seen_by_try_wait_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::ForeignSeenByTryWait, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_seen_by_wait_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::ForeignSeenByWait, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_seen_by_wait_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::ForeignSeenByWait, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_seen_by_try_wait_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::ForeignSeenByTryWait, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_seen_by_try_wait_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::ForeignSeenByTryWait, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_seen_by_wait_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::ForeignSeenByWait, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_seen_by_wait_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::ForeignSeenByWait, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_seen_by_try_wait_sends_nothing_to_an_empty_group_and_reports_no_skip(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::ForeignSeenByTryWait, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_seen_by_try_wait_sends_nothing_to_an_empty_group_and_reports_no_skip(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::ForeignSeenByTryWait, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_seen_by_wait_sends_nothing_to_an_empty_group_and_reports_no_skip(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::ForeignSeenByWait, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_seen_by_wait_sends_nothing_to_an_empty_group_and_reports_no_skip(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::ForeignSeenByWait, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_seen_by_kill_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::ForeignSeenByKill, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_seen_by_kill_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::ForeignSeenByKill, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_seen_by_kill_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::ForeignSeenByKill, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_seen_by_kill_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::ForeignSeenByKill, Teardown::FinishElevated).await;
}

#[skuld::test]
async fn a_drop_after_a_foreign_reap_seen_by_kill_sends_nothing_to_an_empty_group_and_reports_no_skip(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::ForeignSeenByKill, Teardown::Drop).await;
}

#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_seen_by_kill_sends_nothing_to_an_empty_group_and_reports_no_skip(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::ForeignSeenByKill, Teardown::FinishElevated).await;
}

/// Mutant: "only a child shown reaped elsewhere keeps its pidfd".
#[skuld::test]
async fn a_drop_after_a_foreign_reap_seen_by_a_kill_whose_look_failed_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::ForeignSeenByKillWithAFailedPeek, Teardown::Drop).await;
}

/// Mutant: "only a child shown reaped elsewhere keeps its pidfd".
#[skuld::test]
async fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_seen_by_a_kill_whose_look_failed_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::ForeignSeenByKillWithAFailedPeek, Teardown::FinishElevated).await;
}
