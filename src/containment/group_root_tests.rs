// `GroupRoot::check` on Linux: on 6.9+ the root's pidfd answers whether its group still has a
// member, which no caller's check can see; on an older kernel the caller's check answers.

use std::os::fd::AsFd as _;
use std::os::unix::process::ExitStatusExt as _;

use super::{GroupRoot, NotItsGroup};
use crate::test_child::{await_member_ready, member_command};
use crate::test_groups::{pidfd_group_signal, Group};

/// A leader in a group of its own, blocked on its stdin, and its pidfd.
fn leader() -> (std::process::Child, std::os::fd::OwnedFd) {
    let mut leader = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn the leader");
    await_member_ready(&mut leader);
    let pidfd = crate::containment::cgroup::test_support::pidfd_of(leader.id());
    (leader, pidfd)
}

/// Kills and reaps `leader`, which leaves its group's number free once no member is left.
fn kill_and_reap(mut leader: std::process::Child) {
    leader.kill().expect("kill the leader");
    let status = leader.wait().expect("reap the leader");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
}

/// A reaped root whose group has no member left fails the check, though the caller's check passes:
/// its number may name another group. Mutant: "the check asks only the caller's check".
#[skuld::test]
fn check_fails_once_the_group_has_no_member(#[fixture(pidfd_group_signal)] _group: &Group) {
    let (leader, pidfd) = leader();
    kill_and_reap(leader);
    let passes = || Ok(());
    let checked = GroupRoot::new(Some(pidfd.as_fd()), &passes).check();
    assert_eq!(checked, Err(NotItsGroup::Empty));
}

/// A root reaped elsewhere whose group still has a member passes the check, though the caller's
/// check fails: the group's number is still its own. Mutant: "the check asks only the caller's
/// check".
#[skuld::test]
fn check_passes_while_the_group_has_a_member(#[fixture(pidfd_group_signal)] _group: &Group) {
    let (leader, pidfd) = leader();
    let mut member = crate::test_spawn::spawn(&mut member_command(leader.id() as i32)).expect("spawn the member");
    await_member_ready(&mut member);
    kill_and_reap(leader);
    let reaped = || Err("the root was reaped elsewhere".to_owned());
    let checked = GroupRoot::new(Some(pidfd.as_fd()), &reaped).check();
    member.kill().expect("kill the member");
    member.wait().expect("reap the member");
    checked.expect("a group with a member left");
}

/// A kernel that refuses `PIDFD_SIGNAL_PROCESS_GROUP` leaves the answer to the caller's check, even
/// for a group with a member. Mutant: "a refused flag passes the check".
#[skuld::test]
fn check_asks_the_callers_check_when_the_kernel_refuses_the_flag() {
    let (mut leader, pidfd) = leader();
    let reaped = || Err("the root was reaped elsewhere".to_owned());
    let refused = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let failed = GroupRoot::new(Some(pidfd.as_fd()), &reaped).check();
    let passes = || Ok(());
    let passed = GroupRoot::new(Some(pidfd.as_fd()), &passes).check();
    drop(refused);
    leader.kill().expect("kill the leader");
    leader.wait().expect("reap the leader");
    assert_eq!(
        failed,
        Err(NotItsGroup::Unproven("the root was reaped elsewhere".to_owned()))
    );
    assert_eq!(passed, Ok(()));
}
