// How `kill_group` names its targets: through the root's pidfd where the kernel allows, and by the
// group's number only right after a check of the root.

use std::os::unix::process::ExitStatusExt as _;

use super::kill_group;
use crate::containment::GroupRoot;
use crate::send_log::{GroupStep, Route};
#[cfg(target_os = "linux")]
use crate::test_groups::{pidfd_group_signal, Group};

/// A leader in a group of its own with two members, all blocked on reads of the test's pipe, the
/// write end that ends them once dropped, and the members' pids. Returns once both members exist.
fn group_of_three() -> (std::process::Child, std::process::ChildStdin, [u32; 2]) {
    use std::io::BufRead as _;
    use std::os::unix::process::CommandExt;
    // Through fd 3: an asynchronous list's stdin is `/dev/null`, and dash points it there before a
    // `<&0` would apply.
    let mut child = crate::test_spawn::spawn(
        std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"exec 3<&0; cat <&3 & a=$!; cat <&3 & echo "$a $!"; wait"#)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .process_group(0),
    )
    .expect("spawn the leader");
    let stdin = child.stdin.take().expect("piped stdin");
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().expect("piped stdout"))
        .read_line(&mut line)
        .expect("read the members' pids");
    let members: Vec<u32> = line
        .split_whitespace()
        .map(|pid| pid.parse().expect("a member's pid"))
        .collect();
    let members = <[u32; 2]>::try_from(members).unwrap_or_else(|got| panic!("two members' pids, got {got:?}"));
    (child, stdin, members)
}

/// Every send whose target is named by the group's number is right after its own check of the
/// root: the `killpg`, the leader's signal by number after a refused group send, and each member's
/// resend (a member is the group's by its number, whatever names the member itself).
#[track_caller]
fn assert_each_send_by_number_follows_its_check(steps: &[GroupStep]) {
    for (i, step) in steps.iter().enumerate() {
        let by_number = matches!(
            step,
            GroupStep::Group(Route::Number, _) | GroupStep::Leader(Route::Number, _) | GroupStep::Member(..)
        );
        if by_number {
            assert!(
                i > 0 && steps[i - 1] == GroupStep::Check,
                "step {i} ({step:?}) is not right after a check of the root: {steps:?}"
            );
        }
    }
}

/// With the group's own send refused, the leader's signal and two members' resends follow it, and
/// each send by the group's number has a check of its own right before it. Mutants: "check once
/// before the `killpg` and send the rest on its strength", "no check before the leader's signal",
/// "check once before the members' resends".
#[skuld::test]
fn each_send_by_the_group_number_has_its_own_check_right_before_it() {
    let (mut child, stdin, members) = group_of_three();
    let pgid = child.id() as i32;
    let check = || Ok(());
    let root = GroupRoot::new(None, &check);
    let capture = crate::send_log::Capture::start();
    let refused = super::fault::refuse_group_sends();
    kill_group(pgid, &root).expect("kill_group on an owned group");
    drop(refused);
    let steps = capture.group_steps();
    drop(stdin);

    assert_each_send_by_number_follows_its_check(&steps);
    assert!(
        steps.iter().any(|s| matches!(s, GroupStep::Group(Route::Number, _)))
            && steps.iter().any(|s| matches!(s, GroupStep::Leader(..))),
        "the group's send and the leader's signal were made: {steps:?}"
    );
    // The leader is resent too when it had not yet exited from its own kill at the listing.
    let resent: Vec<u32> = steps
        .iter()
        .filter_map(|s| match s {
            GroupStep::Member(_, pid, _) => Some(*pid),
            _ => None,
        })
        .collect();
    for member in members {
        assert_eq!(
            resent.iter().filter(|&&pid| pid == member).count(),
            1,
            "member {member} was resent the kill once: {steps:?}"
        );
    }
    assert!(
        resent.iter().all(|&pid| members.contains(&pid) || pid == child.id()),
        "only the group was resent the kill: {steps:?}"
    );
    let status = child.wait().expect("reap the leader");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
}

/// A check that fails sends nothing by the group's number, and says why. Mutant: "send on a failed
/// check".
#[skuld::test]
fn a_failed_check_sends_nothing_by_the_group_number() {
    let (mut child, stdin, _) = group_of_three();
    let pgid = child.id() as i32;
    let check = || Err("the root was reaped elsewhere".to_owned());
    let root = GroupRoot::new(None, &check);
    let capture = crate::send_log::Capture::start();
    let err = kill_group(pgid, &root).expect_err("a failed check is an error");
    let steps = capture.group_steps();

    assert_eq!(steps, [GroupStep::Check], "nothing was sent");
    match &err {
        crate::error::Error::Unassessable { detail, source: None } => {
            assert!(detail.contains("the root was reaped elsewhere"), "{detail}");
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
    drop(stdin);
    let status = child.wait().expect("the leader exits once its stdin closes");
    assert!(status.success(), "nothing killed the leader: {status:?}");
}

/// Linux 6.9+: the group's send goes through the root's pidfd, which names the group exactly, and
/// nothing goes by its number. Mutant: "always `killpg`".
#[cfg(target_os = "linux")]
#[skuld::test]
fn kill_group_signals_through_the_root_pidfd(#[fixture(pidfd_group_signal)] _group: &Group) {
    use std::os::fd::AsFd as _;
    let (mut child, stdin, _) = group_of_three();
    let pidfd = crate::containment::cgroup::test_support::pidfd_of(child.id());
    let check = || Ok(());
    let root = GroupRoot::new(Some(pidfd.as_fd()), &check);
    let capture = crate::send_log::Capture::start();
    kill_group(child.id() as i32, &root).expect("kill_group on an owned group");
    let steps = capture.group_steps();
    drop(stdin);

    assert_eq!(
        steps.first(),
        Some(&GroupStep::Group(Route::Pidfd, libc::SIGKILL)),
        "the group's send went through the pidfd on this kernel ({}): {steps:?}",
        kernel_release()
    );
    assert!(
        !steps.iter().any(|s| matches!(s, GroupStep::Group(Route::Number, _))),
        "nothing went by the group's number on this kernel ({}): {steps:?}",
        kernel_release()
    );
    let status = child.wait().expect("reap the leader");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
}

/// The running kernel's release, for a failure message.
#[cfg(target_os = "linux")]
fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_or_else(|e| format!("unreadable: {e}"), |r| r.trim().to_owned())
}

/// A kernel that refuses `PIDFD_SIGNAL_PROCESS_GROUP` (`EINVAL`, before 6.9) gets the group's send
/// by its number, after a check. Mutant: "`EINVAL` is an error".
#[cfg(target_os = "linux")]
#[skuld::test]
fn kill_group_falls_back_to_the_number_when_the_kernel_refuses_the_flag() {
    use std::os::fd::AsFd as _;
    let (mut child, stdin, _) = group_of_three();
    let pidfd = crate::containment::cgroup::test_support::pidfd_of(child.id());
    let check = || Ok(());
    let root = GroupRoot::new(Some(pidfd.as_fd()), &check);
    let capture = crate::send_log::Capture::start();
    let refused = super::fault::refuse_pidfd_group_flag();
    kill_group(child.id() as i32, &root).expect("kill_group on an owned group");
    drop(refused);
    let steps = capture.group_steps();
    drop(stdin);

    assert_eq!(
        steps.get(..3),
        Some(
            &[
                GroupStep::Group(Route::Pidfd, libc::SIGKILL),
                GroupStep::Check,
                GroupStep::Group(Route::Number, libc::SIGKILL)
            ][..]
        ),
        "{steps:?}"
    );
    assert_each_send_by_number_follows_its_check(&steps);
    let status = child.wait().expect("reap the leader");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
}

/// After a refused group send, the leader's signal goes through the root's pidfd when it has one,
/// never by its number. Mutant: "the leader by number".
#[cfg(target_os = "linux")]
#[skuld::test]
fn the_leader_signal_goes_through_the_root_pidfd() {
    use std::os::fd::AsFd as _;
    let (mut child, stdin, _) = group_of_three();
    let pidfd = crate::containment::cgroup::test_support::pidfd_of(child.id());
    let check = || Ok(());
    let root = GroupRoot::new(Some(pidfd.as_fd()), &check);
    let capture = crate::send_log::Capture::start();
    let refused = super::fault::refuse_group_sends();
    kill_group(child.id() as i32, &root).expect("kill_group on an owned group");
    drop(refused);
    let steps = capture.group_steps();
    drop(stdin);

    assert!(
        steps
            .iter()
            .any(|s| matches!(s, GroupStep::Leader(Route::Pidfd, libc::SIGKILL))),
        "{steps:?}"
    );
    assert!(
        !steps.iter().any(|s| matches!(s, GroupStep::Leader(Route::Number, _))),
        "{steps:?}"
    );
    assert_each_send_by_number_follows_its_check(&steps);
    let status = child.wait().expect("reap the leader");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
}

/// After a refused group send, a root with no pidfd gets the leader's `SIGTERM` by its number,
/// right after a check, and it ends the leader. Mutant: "the leader's signal by number is not made"
/// (the leader then exits once its members end at their stdin's EOF).
#[skuld::test]
fn term_group_ends_the_leader_by_its_number_when_the_group_send_is_refused() {
    let (mut child, stdin, _) = group_of_three();
    let root = GroupRoot::trusted_for_test();
    let capture = crate::send_log::Capture::start();
    let refused = super::fault::refuse_group_sends();
    let result = super::term_group(child.id() as i32, &root);
    drop(refused);
    let steps = capture.group_steps();
    drop(stdin);
    let status = child.wait().expect("reap the leader");

    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, GroupStep::Leader(Route::Number, libc::SIGTERM))),
        "{steps:?}"
    );
    assert_each_send_by_number_follows_its_check(&steps);
    result.expect("term_group on an owned group");
}
