use std::os::fd::AsFd as _;

use super::{
    classify_kill, classify_pidfd, evaluate, has_exited, maps_every_uid, match_stands, parse_status_uids,
    shares_user_ns, Rule, Sender, SignalCall, Target,
};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::refusal::Verdict;

// The kernel's permission rule (`check_kill_permission` -> `kill_ok_by_cred`) =====

fn sender(ruid: u32, euid: u32, cap_kill: bool) -> Sender {
    Sender { ruid, euid, cap_kill }
}

fn target(ruid: u32, suid: u32) -> Target {
    Target { ruid, suid }
}

// One row per clause of the rule, each with every other clause false, so a mutant that drops or
// swaps one clause fails on exactly its row.
#[test]
fn the_rule_is_cap_kill_or_a_sender_uid_matching_a_target_ruid_or_suid() {
    // Nothing matches: a setuid-root helper (all 0) signalled by uid 1000.
    assert_eq!(evaluate(sender(1000, 1000, false), target(0, 0)), Rule::Refused);
    // CAP_KILL alone.
    assert_eq!(evaluate(sender(1000, 1000, true), target(0, 0)), Rule::Permitted);
    // sender euid == target ruid.
    assert_eq!(evaluate(sender(7, 1000, false), target(1000, 1)), Rule::MatchedAt(1000));
    // sender euid == target suid.
    assert_eq!(evaluate(sender(7, 1000, false), target(1, 1000)), Rule::MatchedAt(1000));
    // sender ruid == target ruid.
    assert_eq!(evaluate(sender(1000, 7, false), target(1000, 1)), Rule::MatchedAt(1000));
    // sender ruid == target suid.
    assert_eq!(evaluate(sender(1000, 7, false), target(1, 1000)), Rule::MatchedAt(1000));
}

// The target's EFFECTIVE uid is not in the rule: it is not even an input, so a sender matching
// nothing else is refused whatever the target's euid is.
#[test]
fn a_target_euid_alone_does_not_permit_the_signal() {
    assert_eq!(evaluate(sender(5, 5, false), target(6, 6)), Rule::Refused);
}

// CAP_KILL decides before any uid is compared, so the overflow uid never enters.
#[test]
fn cap_kill_decides_regardless_of_the_uids() {
    assert_eq!(evaluate(sender(0, 0, true), target(0, 0)), Rule::Permitted);
}

// A match at the overflow uid =====

fn undecidable() -> Error {
    Error::Unassessable {
        detail: "undecidable".into(),
        source: None,
    }
}

fn stands(uid: u32, overflow: u32, all_mapped: bool, shared: bool) -> Result<bool, Error> {
    match_stands(uid, || Ok(overflow), || Ok(all_mapped), || Ok(shared), undecidable)
}

// A uid other than the overflow uid is a match without asking about the namespace.
#[test]
fn a_match_at_an_ordinary_uid_stands() {
    let stands = match_stands(
        1000,
        || Ok(65534),
        || panic!("not asked"),
        || panic!("not asked"),
        undecidable,
    );
    assert!(stands.expect("decided"));
}

// At the overflow uid the match stands if every uid is mapped, or if the target shares our user
// namespace; only when neither holds is it undecidable. Each row differs from the last in one
// answer.
#[test]
fn a_match_at_the_overflow_uid_stands_when_nothing_can_be_unmapped_or_the_ns_is_shared() {
    assert!(stands(65534, 65534, true, false).expect("every uid mapped"));
    assert!(stands(65534, 65534, false, true).expect("shared namespace"));
    let err = stands(65534, 65534, false, false).expect_err("neither");
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
}

// The overflow uid is a per-namespace sysctl, not the constant 65534.
#[test]
fn the_overflow_uid_is_the_one_the_caller_reads() {
    assert!(stands(65534, 7, false, false).expect("65534 is an ordinary uid here"));
    assert!(stands(7, 7, false, false).is_err(), "7 is the overflow uid here");
}

// Errors from any question propagate.
#[test]
fn a_failed_overflow_or_namespace_read_is_an_error_not_a_match() {
    assert!(match_stands(1, || Err(undecidable()), || Ok(true), || Ok(true), undecidable).is_err());
    assert!(match_stands(65534, || Ok(65534), || Err(undecidable()), || Ok(true), undecidable).is_err());
    assert!(match_stands(65534, || Ok(65534), || Ok(false), || Err(undecidable()), undecidable).is_err());
}

// The namespace comparison =====

fn links<'a>(theirs: &'a [u8], ours: &'a [u8]) -> impl Fn(&str) -> std::io::Result<Vec<u8>> + 'a {
    move |path| match path {
        "self/ns/user" => Ok(ours.to_vec()),
        p if p.ends_with("/ns/user") => Ok(theirs.to_vec()),
        other => panic!("unexpected link {other}"),
    }
}

#[test]
fn the_same_user_ns_link_is_shared_and_a_different_one_is_not() {
    let id = ProcessId::current();
    assert!(shares_user_ns(id, links(b"user:[4026531837]", b"user:[4026531837]")).expect("read"));
    assert!(!shares_user_ns(id, links(b"user:[4026532000]", b"user:[4026531837]")).expect("read"));
}

#[test]
fn an_unreadable_user_ns_link_is_unassessable_not_shared() {
    let id = ProcessId::current();
    let denied = |_: &str| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert!(matches!(shares_user_ns(id, denied), Err(Error::Unassessable { .. })));
}

// The real links: this process shares its own user namespace.
#[test]
fn this_process_shares_its_own_user_ns() {
    let dir = crate::identity::ProcDir::open().expect("open /proc");
    assert!(shares_user_ns(ProcessId::current(), |path| dir.read_link(path)).expect("read"));
}

// `uid_map` text =====

#[test]
fn only_a_map_from_zero_over_every_uid_maps_every_uid() {
    assert!(maps_every_uid("         0          0 4294967295\n"));
    assert!(!maps_every_uid("         0     100000      65536\n"));
    assert!(!maps_every_uid("         1          0 4294967295\n"), "starts above 0");
    assert!(!maps_every_uid("         0          0 4294967294\n"), "one short");
    assert!(maps_every_uid(
        "         0       1000          1\n         0          0 4294967295\n"
    ));
    assert!(!maps_every_uid(""));
}

// The `Uid:` line of `/proc/<pid>/status` =====

#[test]
fn the_uid_line_is_real_effective_saved_filesystem() {
    let status = "Name:\thelper\nState:\tZ (zombie)\nUid:\t1\t2\t3\t4\nGid:\t9\t9\t9\t9\n";
    assert_eq!(parse_status_uids(status), Some([1, 2, 3, 4]));
}

#[test]
fn a_status_without_a_well_formed_uid_line_has_no_uids() {
    assert_eq!(parse_status_uids("Name:\tx\nGid:\t1\t1\t1\t1\n"), None);
    assert_eq!(parse_status_uids("Uid:\t1\t2\t3\n"), None);
    assert_eq!(parse_status_uids("Uid:\t1\t2\tx\t4\n"), None);
    assert_eq!(parse_status_uids(""), None);
}

// Has the target exited? =====

fn cat() -> (std::process::Child, ProcessId) {
    let mut cmd = std::process::Command::new("cat");
    cmd.stdin(std::process::Stdio::piped());
    let child = crate::test_spawn::spawn(&mut cmd).expect("spawn cat");
    let id = ProcessId::of(child.id()).found().expect("identity of a live child");
    (child, id)
}

fn pidfd_of(id: ProcessId) -> rustix::fd::OwnedFd {
    let pid = rustix::process::Pid::from_raw(id.pid() as i32).expect("nonzero pid");
    rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open")
}

// Kills a `cat` (closing its stdin) and returns once it is a zombie, unreaped.
fn make_zombie(child: &mut std::process::Child, id: ProcessId) {
    drop(child.stdin.take());
    assert!(
        crate::wait::block_until_exit(id, None).expect("watch the exit"),
        "the watch returns on the exit"
    );
}

#[test]
fn a_running_own_child_has_not_exited() {
    let (mut child, id) = cat();
    let pidfd = pidfd_of(id);
    assert!(!has_exited(id, pidfd.as_fd()).expect("waitid"));
    drop(child.stdin.take());
    child.wait().expect("reap");
}

#[test]
fn an_unreaped_zombie_own_child_has_exited() {
    let (mut child, id) = cat();
    let pidfd = pidfd_of(id);
    make_zombie(&mut child, id);
    assert!(has_exited(id, pidfd.as_fd()).expect("waitid"));
    child.wait().expect("reap");
}

// `waitid(WNOWAIT)` must leave the zombie for its parent: the check never reaps.
#[test]
fn the_exit_check_does_not_reap() {
    let (mut child, id) = cat();
    let pidfd = pidfd_of(id);
    make_zombie(&mut child, id);
    assert!(has_exited(id, pidfd.as_fd()).expect("waitid"));
    assert!(has_exited(id, pidfd.as_fd()).expect("a second check still sees the zombie"));
    let status = child
        .try_wait()
        .expect("try_wait")
        .expect("the zombie is still there to reap");
    assert!(status.success());
}

// Not our child: `waitid(P_PIDFD)` answers `ECHILD`, and the check falls back on the target's
// `/proc` state. Pid 1 is live and never our child.
#[test]
fn a_live_process_that_is_not_our_child_has_not_exited() {
    let init = ProcessId::of(1).found().expect("pid 1 resolves");
    let pidfd = pidfd_of(init);
    assert!(!has_exited(init, pidfd.as_fd()).expect("the fallback"));
}

// What would a refused signal at this target mean? =====

// The kernel permits a signal to a live child of our own uid, so an `EPERM` there can only be a
// filter's: the two syscalls are named in the verdict.
#[test]
fn eperm_at_a_live_own_uid_child_is_a_filter() {
    let (mut child, id) = cat();
    assert_eq!(classify_kill(id).expect("classify"), Verdict::Filter(SignalCall::Kill));
    let pidfd = pidfd_of(id);
    assert_eq!(
        classify_pidfd(id, pidfd.as_fd(), SignalCall::PidfdTerminate).expect("classify"),
        Verdict::Filter(SignalCall::PidfdTerminate)
    );
    drop(child.stdin.take());
    child.wait().expect("reap");
}

#[test]
fn eperm_at_an_exited_child_is_exited_not_a_filter() {
    let (mut child, id) = cat();
    let pidfd = pidfd_of(id);
    make_zombie(&mut child, id);
    assert_eq!(classify_kill(id).expect("classify"), Verdict::Exited);
    assert_eq!(
        classify_pidfd(id, pidfd.as_fd(), SignalCall::PidfdTerminate).expect("classify"),
        Verdict::Exited
    );
    child.wait().expect("reap");
}

// Reaped before the classification: nothing to refuse.
#[test]
fn eperm_at_a_reaped_child_is_exited() {
    let (mut child, id) = cat();
    drop(child.stdin.take());
    child.wait().expect("reap");
    assert_eq!(classify_kill(id).expect("classify"), Verdict::Exited);
}
