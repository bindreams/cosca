use super::{number_holds, Refusal};
use crate::identity::{ProcessId, Resolved};
use crate::signal::RootState;

/// A pgid no test process holds: the checks only name it in their text.
const PGID: i32 = 999_999;

// number_holds -----

/// A send by the group's number is allowed only while the root is unreaped.
#[skuld::test]
fn number_holds_only_for_an_unreaped_root() {
    let own = std::process::id();
    assert!(number_holds(own, RootState::Unreaped).is_ok());
    let refused = [
        (RootState::Reaped { own: false }, "reaped elsewhere"),
        (
            RootState::Unknown(std::io::Error::other("a failed peek")),
            "a failed peek",
        ),
        (RootState::Unpinned, "not pinned"),
        // This process holds its own pid, so the number names another process than the root.
        (RootState::Reaped { own: true }, "another process holds"),
    ];
    for (state, why) in refused {
        let label = format!("{state:?}");
        let err = number_holds(own, state).expect_err(&label).to_string();
        assert!(err.contains(why), "{label}: {err}");
    }
}

/// `number_holds` reads `own` from the state: a reap by someone else refuses whatever the pid's
/// identity read says, and an own reap is refused whatever that read says, each as its own variant.
#[skuld::test]
fn number_holds_reads_own_from_the_state() {
    let other = || ProcessId::from_parts_for_test(PGID as u32, crate::identity::Key::for_test(1));
    let reads = || [Resolved::Gone, Resolved::Found(other()), Resolved::Unknown];
    for read in reads() {
        let _read = crate::child::fault::force_root_reads(read);
        let err = number_holds(PGID as u32, RootState::Reaped { own: false }).expect_err("reaped elsewhere");
        assert!(matches!(err, Refusal::ReapedElsewhere(_)), "{err}");
    }
    let _gone = crate::child::fault::force_root_reads(Resolved::Gone);
    let err = number_holds(PGID as u32, RootState::Reaped { own: true }).expect_err("names no process");
    assert!(matches!(err, Refusal::ReapedPidGone(_)), "{err}");
    assert!(err.to_string().contains("names no process"), "{err}");
    drop(_gone);
    let _found = crate::child::fault::force_root_reads(Resolved::Found(other()));
    let err = number_holds(PGID as u32, RootState::Reaped { own: true }).expect_err("another process holds");
    assert!(matches!(err, Refusal::ReapedPidTaken(_)), "{err}");
    drop(_found);
    let _unknown = crate::child::fault::force_root_reads(Resolved::Unknown);
    let err = number_holds(PGID as u32, RootState::Reaped { own: true }).expect_err("unreadable");
    assert!(matches!(err, Refusal::ReapedPidUnread(_)), "{err}");
    assert!(err.to_string().contains("could not be read"), "{err}");
}

// check_number through the root's pidfd -----

#[cfg(target_os = "linux")]
mod pidfd {
    use std::os::fd::AsFd as _;
    use std::os::unix::process::ExitStatusExt as _;

    use crate::containment::{check_number, NotItsGroup};
    use crate::signal::RootState;
    use crate::test_child::{await_member_ready, member_command};
    use crate::test_groups::{pidfd_group_signal, Group};
    use crate::test_support::stated_root::StatedRoot;

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

    /// A root of `pid` whose own handle says it was reaped elsewhere, with `pidfd`.
    fn reaped_elsewhere(pid: u32, pidfd: std::os::fd::BorrowedFd<'_>) -> StatedRoot<'_> {
        StatedRoot::with_state(pid, || RootState::Reaped { own: false }).with_pidfd(pidfd)
    }

    fn reaped_elsewhere_text(pid: u32) -> String {
        format!("the root (pid {pid}) was reaped elsewhere")
    }

    /// A reaped root whose group has no member left fails the check, though its state would pass
    /// it: its number may name another group.
    #[skuld::test]
    fn check_fails_once_the_group_has_no_member(#[fixture(pidfd_group_signal)] _group: &Group) {
        let (leader, pidfd) = leader();
        kill_and_reap(leader);
        let root = StatedRoot::unreaped().with_pidfd(pidfd.as_fd());
        assert!(matches!(check_number(Some(&root)), Err(NotItsGroup::Empty)));
    }

    /// A root reaped elsewhere whose group still has a member passes the check, though its state
    /// fails it: the group's number is still its own.
    #[skuld::test]
    fn check_passes_while_the_group_has_a_member(#[fixture(pidfd_group_signal)] _group: &Group) {
        let (leader, pidfd) = leader();
        let mut member = crate::test_spawn::spawn(&mut member_command(leader.id() as i32)).expect("spawn the member");
        await_member_ready(&mut member);
        let root = reaped_elsewhere(leader.id(), pidfd.as_fd());
        kill_and_reap(leader);
        let checked = check_number(Some(&root));
        member.kill().expect("kill the member");
        member.wait().expect("reap the member");
        checked.expect("a group with a member left");
    }

    /// A kernel that refuses `PIDFD_SIGNAL_PROCESS_GROUP` leaves the answer to the root's state,
    /// even for a group with a member.
    #[skuld::test]
    fn check_asks_the_roots_state_when_the_kernel_refuses_the_flag() {
        let (mut leader, pidfd) = leader();
        let pid = leader.id();
        let reaped = reaped_elsewhere(pid, pidfd.as_fd());
        let refused = crate::containment::unix::fault::refuse_pidfd_group_flag();
        let failed = check_number(Some(&reaped));
        let unreaped = StatedRoot::unreaped().with_pidfd(pidfd.as_fd());
        let passed = check_number(Some(&unreaped));
        drop(refused);
        leader.kill().expect("kill the leader");
        leader.wait().expect("reap the leader");
        assert_eq!(
            failed.expect_err("reaped elsewhere").to_string(),
            reaped_elsewhere_text(pid)
        );
        passed.expect("an unreaped root");
    }

    /// A signal-0 group send answered `EPERM` (as a seccomp filter may answer for a group whose
    /// number another group took) says nothing about the group: the root's state answers.
    #[skuld::test]
    fn check_asks_the_roots_state_when_the_group_probe_answers_eperm() {
        let (mut leader, pidfd) = leader();
        let pid = leader.id();
        let reaped = reaped_elsewhere(pid, pidfd.as_fd());
        let answered = crate::containment::unix::fault::answer_group_probes_with(libc::EPERM);
        let checked = check_number(Some(&reaped));
        drop(answered);
        leader.kill().expect("kill the leader");
        leader.wait().expect("reap the leader");
        assert_eq!(
            checked.expect_err("reaped elsewhere").to_string(),
            reaped_elsewhere_text(pid)
        );
    }

    /// The check's signal-0 group send is a send like any other: recorded, through the root's
    /// pidfd, on any kernel.
    #[skuld::test]
    fn the_group_probe_is_a_recorded_send() {
        use crate::send_log::{GroupStep, Route};
        let (leader, pidfd) = leader();
        let root = StatedRoot::unreaped().with_pidfd(pidfd.as_fd());
        let capture = crate::send_log::Capture::start();
        let checked = check_number(Some(&root));
        let steps = capture.group_steps_with_probes();
        kill_and_reap(leader);
        assert_eq!(steps, [GroupStep::Check, GroupStep::Group(Route::Pidfd, 0)]);
        checked.expect("the leader's group has a member");
    }
}
