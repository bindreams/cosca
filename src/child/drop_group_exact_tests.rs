//! Linux: the drop and a failed elevated spawn's cleanup, for a process group whose root is reaped.
//! On 6.9+ the root's pidfd names the group exactly, whoever reaped the root, so they decide as
//! `kill_tree` does (`group_exact_tests`); below 6.9 nothing goes out by the group's number.

use crate::child::group_exact_tests::root_with_a_member;
use crate::send_log::{assert_group_signalled_first_through_the_pidfd, Capture, GroupStep};
use crate::test_child::reaped_elsewhere::{reap_behind, session_sleep};
use crate::test_groups::{pidfd_group_signal, Group};

/// Who reaps the root.
#[derive(Debug, Clone, Copy)]
enum Reap {
    /// This handle's own `wait`.
    Own,
    /// Another reaper in the process, behind the handle's back.
    Foreign,
}

/// The teardown under test.
#[derive(Debug, Clone, Copy)]
enum Teardown {
    Drop,
    FinishElevated,
}

/// Kills `child`'s root alone and has `reap` reap it.
fn reap_root(child: &crate::Child, reap: Reap) {
    child.kill().expect("kill the root alone");
    match reap {
        Reap::Own => {
            child.wait().expect("this handle reaps the root");
        }
        Reap::Foreign => reap_behind(child.id().pid()),
    }
}

/// Runs `teardown` on `child`: the error's detail for a cleanup, `None` for a drop.
fn tear_down(child: crate::Child, teardown: Teardown) -> Option<String> {
    match teardown {
        Teardown::Drop => {
            drop(child);
            None
        }
        Teardown::FinishElevated => {
            let (err, _fate) = crate::child::spawn::finish_elevated(
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
/// root's pidfd. Mutant: "a teardown never signals the group of a reaped root".
fn kills_the_group_left_behind(reap: Reap, teardown: Teardown) {
    let (child, member) = root_with_a_member();
    reap_root(&child, reap);
    let capture = Capture::start();
    tear_down(child, teardown);
    let steps = capture.group_steps();
    assert_group_signalled_first_through_the_pidfd(&steps, libc::SIGKILL);
    member.assert_killed();
}

/// Below 6.9 the old behaviour holds: a reaped root's group is sent nothing, and its member lives
/// on. Mutant: "a refused flag still lets the teardown signal the group".
fn below_6_9_sends_nothing_to_the_group(reap: Reap, teardown: Teardown) {
    let (child, member) = root_with_a_member();
    reap_root(&child, reap);
    let old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let capture = Capture::start();
    tear_down(child, teardown);
    let steps = capture.group_steps();
    drop(old_kernel);
    assert_eq!(steps, [], "nothing was sent to the group");
    member.assert_survived();
}

/// 6.9+: a reaped root whose group has no member left has no tree left behind: the teardown sends
/// nothing and reports no skipped kill. Mutant: "an empty group is still a skip".
fn sends_nothing_to_an_empty_group_and_reports_no_skip(reap: Reap, teardown: Teardown) {
    crate::log_capture::install();
    let child = session_sleep().spawn().expect("spawn");
    reap_root(&child, reap);
    let mark = crate::log_capture::mark();
    let capture = Capture::start();
    let detail = tear_down(child, teardown);
    let steps = capture.group_steps();
    assert_eq!(steps, [], "nothing was sent");
    if let Some(detail) = detail {
        assert!(!detail.contains("tree was not killed"), "{detail}");
    }
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level == log::Level::Warn)
        .collect();
    assert_eq!(warns, [], "nothing was left behind");
}

#[skuld::test]
fn a_drop_after_its_own_wait_kills_the_group_left_behind(#[fixture(pidfd_group_signal)] _group: &Group) {
    kills_the_group_left_behind(Reap::Own, Teardown::Drop);
}

#[skuld::test]
fn a_drop_after_a_foreign_reap_kills_the_group_left_behind(#[fixture(pidfd_group_signal)] _group: &Group) {
    kills_the_group_left_behind(Reap::Foreign, Teardown::Drop);
}

#[skuld::test]
fn a_failed_elevated_spawns_cleanup_after_its_own_wait_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::Own, Teardown::FinishElevated);
}

#[skuld::test]
fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group_left_behind(Reap::Foreign, Teardown::FinishElevated);
}

#[skuld::test]
fn a_drop_after_its_own_wait_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::Own, Teardown::Drop);
}

#[skuld::test]
fn a_drop_after_a_foreign_reap_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::Foreign, Teardown::Drop);
}

#[skuld::test]
fn a_failed_elevated_spawns_cleanup_after_its_own_wait_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::Own, Teardown::FinishElevated);
}

#[skuld::test]
fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Reap::Foreign, Teardown::FinishElevated);
}

#[skuld::test]
fn a_drop_after_its_own_wait_sends_nothing_to_an_empty_group_and_does_not_warn(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::Own, Teardown::Drop);
}

#[skuld::test]
fn a_drop_after_a_foreign_reap_sends_nothing_to_an_empty_group_and_does_not_warn(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::Foreign, Teardown::Drop);
}

#[skuld::test]
fn a_failed_elevated_spawns_cleanup_after_its_own_wait_reports_no_skip_for_an_empty_group(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::Own, Teardown::FinishElevated);
}

#[skuld::test]
fn a_failed_elevated_spawns_cleanup_after_a_foreign_reap_reports_no_skip_for_an_empty_group(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    sends_nothing_to_an_empty_group_and_reports_no_skip(Reap::Foreign, Teardown::FinishElevated);
}

/// 6.9+: a root whose handle cannot say whether it was reaped still names its group exactly through
/// its pidfd, so the drop kills the group as usual. Mutant: "only a reaped root's group is decided
/// by the pidfd".
#[skuld::test]
fn a_drop_of_a_root_its_handle_cannot_read_kills_its_group_through_the_pidfd(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    let (child, member) = root_with_a_member();
    let capture = Capture::start();
    let forced = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    drop(child);
    assert_peeks_exhausted();
    drop(forced);
    let steps = capture.group_steps();
    assert_group_signalled_first_through_the_pidfd(&steps, libc::SIGKILL);
    member.assert_killed();
}

/// 6.9+: a root whose handle cannot say whether it was reaped, whose group has no member, may have
/// left the group alive, so the drop still skips the group and says so. Mutant: "the drop takes an
/// unanswered root for a reaped one".
#[skuld::test]
fn a_drop_of_a_root_its_handle_cannot_read_with_no_member_left_still_skips_the_group(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    use crate::identity::Resolved;
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    crate::log_capture::install();
    let child = session_sleep().spawn().expect("spawn");
    let id = child.id();
    reap_root(&child, Reap::Foreign);
    let mark = crate::log_capture::mark();
    let capture = Capture::start();
    let _as_root = crate::child::fault::force_next_root_read(Resolved::Found(id));
    let forced = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    drop(child);
    assert_peeks_exhausted();
    drop(forced);
    let steps = capture.group_steps();
    assert_eq!(steps, [], "nothing was sent to the group");
    let skips = crate::log_capture::records_since_on_current_thread(mark, "so it does not kill its process group");
    assert_eq!(skips.len(), 1, "{skips:?}");
}

/// 6.9+: a drop that finds, listed by its group's number, a process the root's pidfd shows is not a
/// member sends it nothing and does not warn. Mutant: "a group with no member left leaves the
/// listed process unassessable".
#[skuld::test]
fn a_drop_leaves_alone_a_group_that_took_the_number_of_its_emptied_group(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    use crate::child::group_exact_tests::EmptiedGroup;
    crate::log_capture::install();
    let (child, armed) = EmptiedGroup::new().arm();
    let mark = crate::log_capture::mark();
    let capture = Capture::start();
    drop(child);
    let steps = capture.group_steps();
    armed.finish();
    assert!(
        !steps.iter().any(|step| matches!(step, GroupStep::Member(..))),
        "nothing was resent: {steps:?}"
    );
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level == log::Level::Warn)
        .collect();
    assert_eq!(warns, [], "the tree is gone");
}
