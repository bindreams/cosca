//! The kill of the process group an abandoned spawn's child leads, which only a child that exec'd
//! outside its leaf has (`kill_group_outside_leaf`), over forked processes with no cgroup. What it
//! sends is read from the send log. The child's own teardown is the table's (see
//! [`teardown`](crate::child::owned::owned_tests)).

use super::super::test_support::{fork_running, pidfd_of, KillOnDrop};
use super::super::TAG_INTENT;
use super::{kill_group_outside_leaf, Abandoned, CgroupLeaf, NoWarn};
use crate::child::owned::teardown::Past;
use crate::child::owned::OwnedChild;
use crate::os_process::linux::LinuxProcess;
use crate::test_groups::{pidfd_group_signal, Group};

/// An [`OwnedChild`] over a pidfd on the forked child `pid`, as the abandonment builds one.
fn owned_over(pid: u32) -> OwnedChild {
    OwnedChild::new(Box::new(LinuxProcess::new(Some(pid), pidfd_of(pid))))
}

/// A forked child that leads its own process group, as a spawned child does, and exits by itself
/// once the returned writer closes.
fn group_leader_ending_at_eof() -> (KillOnDrop, std::io::PipeWriter) {
    use std::os::fd::AsRawFd;
    let (from_test, to_child) = std::io::pipe().expect("pipe");
    let input = from_test.as_raw_fd();
    let child = fork_running(&[input], move || {
        // SAFETY: async-signal-safe syscalls on fds this process holds.
        unsafe {
            libc::setpgid(0, 0);
            let mut byte = 0u8;
            while libc::read(input, (&raw mut byte).cast(), 1) == 1 {}
        }
    });
    drop(from_test);
    // SAFETY: plain syscall on this process's own child.
    let set = unsafe { libc::setpgid(child.pid() as i32, child.pid() as i32) };
    assert_eq!(set, 0, "setpgid: {}", std::io::Error::last_os_error());
    (child, to_child)
}

/// A forked group leader that forked a member into its group, as a child that exec'd outside its
/// leaf may. The leader exits at once. The member blocks reading the returned writer's pipe; once
/// that closes it writes `survived` to the returned reader's pipe and exits, so a member a kill
/// missed is seen as that marker, never as a hang. Returns once the member exists.
fn leader_with_member_exiting() -> (KillOnDrop, std::io::PipeWriter, std::io::PipeReader) {
    let (leader, _, to_member, from_member) = fork_leader_with_member(false);
    (leader, to_member, from_member)
}

/// [`leader_with_member_exiting`], but the leader runs until the returned writer, its input,
/// closes, and then exits by itself.
fn leader_held_with_member() -> (
    KillOnDrop,
    std::io::PipeWriter,
    std::io::PipeWriter,
    std::io::PipeReader,
) {
    fork_leader_with_member(true)
}

/// A leader's input writer (held leaders only), then the member's writer and reader.
fn fork_leader_with_member(
    held: bool,
) -> (
    KillOnDrop,
    std::io::PipeWriter,
    std::io::PipeWriter,
    std::io::PipeReader,
) {
    use std::os::fd::AsRawFd;
    let (from_test, to_member) = std::io::pipe().expect("pipe");
    let (from_member, to_test) = std::io::pipe().expect("pipe");
    let (leader_input, to_leader) = std::io::pipe().expect("pipe");
    let fds = [
        from_test.as_raw_fd(),
        to_member.as_raw_fd(),
        from_member.as_raw_fd(),
        to_test.as_raw_fd(),
        leader_input.as_raw_fd(),
        to_leader.as_raw_fd(),
    ];
    let leader = fork_running(&fds, move || {
        let [input, test_end, member_reader, output, leader_in, leader_test_end] = fds;
        // SAFETY: async-signal-safe syscalls on fds this process holds.
        unsafe {
            libc::setpgid(0, 0);
            // Closed before the fork, so the member holds no end of the leader's input.
            libc::close(leader_test_end);
            if libc::fork() == 0 {
                libc::close(test_end);
                libc::close(member_reader);
                libc::close(leader_in);
                let mut byte = 0u8;
                while libc::read(input, (&raw mut byte).cast(), 1) == 1 {}
                libc::write(output, b"survived".as_ptr().cast(), 8);
                libc::_exit(0);
            }
            libc::write(output, b"r".as_ptr().cast(), 1);
            if held {
                let mut byte = 0u8;
                while libc::read(leader_in, (&raw mut byte).cast(), 1) == 1 {}
            }
        }
    });
    drop((from_test, to_test, leader_input));
    let mut from_member = from_member;
    let mut ready = [0u8; 1];
    std::io::Read::read_exact(&mut from_member, &mut ready).expect("the member exists");
    assert_eq!(&ready, b"r");
    (leader, to_leader, to_member, from_member)
}

/// What the member of [`leader_with_member_exiting`] wrote once its pipe closed: `survived`, or
/// nothing if it was killed.
fn member_output(to_member: std::io::PipeWriter, mut from_member: std::io::PipeReader) -> String {
    drop(to_member);
    let mut out = String::new();
    std::io::Read::read_to_string(&mut from_member, &mut out).expect("read the member's output");
    out
}

/// The one `warn` of an event whose group kill was not sent because the kernel refused the flag and
/// the child was reaped: it names the group.
fn assert_one_warn_for_the_unsent_group_kill(mark: usize, pid: u32) {
    let warns = crate::log_capture::warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains(&format!("process group {pid}")),
        "it names the group: {warns:?}"
    );
}

/// Linux 6.9+: the group kill of a child outside its leaf goes through its handle, which names the
/// group exactly, and kills its member.
#[skuld::test]
fn a_group_kill_goes_through_the_childs_handle(#[fixture(pidfd_group_signal)] _group: &Group) {
    use crate::send_log::{GroupStep, Route};
    let (leader, _input, to_member, from_member) = leader_held_with_member();
    let owned = owned_over(leader.pid());
    let capture = crate::send_log::Capture::start();

    assert_eq!(kill_group_outside_leaf(&owned, leader.pid()), None);

    assert_eq!(
        member_output(to_member, from_member),
        "",
        "the group kill ended the member"
    );
    assert_eq!(capture.group_steps(), [GroupStep::Group(Route::Pidfd, libc::SIGKILL)]);
}

/// Where the kernel refuses `PIDFD_SIGNAL_PROCESS_GROUP` (before 6.9), the group kill goes by the
/// group's number only right after a check that the child is still unreaped, and kills its member.
/// Mutants: "no check before the group kill by number", "`EINVAL` ends the group kill", "the group
/// kill by number is not made".
#[skuld::test]
fn a_group_kill_by_number_follows_its_own_check() {
    use crate::send_log::{GroupStep, Route};
    let (leader, _input, to_member, from_member) = leader_held_with_member();
    let owned = owned_over(leader.pid());
    let capture = crate::send_log::Capture::start();
    let refused = crate::containment::unix::fault::refuse_pidfd_group_flag();

    assert_eq!(kill_group_outside_leaf(&owned, leader.pid()), None);

    drop(refused);
    assert_eq!(member_output(to_member, from_member), "", "the member was killed");
    assert_eq!(
        capture.group_steps(),
        [
            GroupStep::Group(Route::Pidfd, libc::SIGKILL),
            GroupStep::Check,
            GroupStep::Group(Route::Number, libc::SIGKILL)
        ]
    );
}

/// A group with no member left (Linux 6.9+, `ESRCH` through the handle) is logged at `debug`, not
/// warned of.
///
/// Mutant: the group kill's result discarded (no record), or logged at `warn`.
#[skuld::test]
fn a_group_kill_finding_no_group_is_logged_at_debug(#[fixture(pidfd_group_signal)] _group: &Group) {
    crate::log_capture::install();
    let (leader, input) = group_leader_ending_at_eof();
    let pid = leader.defuse();
    let owned = owned_over(pid);
    drop(input);
    crate::test_child::reaped_elsewhere::reap_behind(pid);

    let mark = crate::log_capture::mark();
    assert_eq!(kill_group_outside_leaf(&owned, pid), None);

    let records = crate::log_capture::records_since_on_current_thread(mark, "process group");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Debug, "{records:?}");
    assert!(records[0].1.contains(&pid.to_string()), "{records:?}");
}

/// Linux 6.9+: a child outside its leaf that another reaper reaped before the kill still names its
/// process group through its handle, so the member it left there is killed.
///
/// Mutant: a child reaped before the kill gets no group kill.
#[skuld::test]
fn a_reaped_childs_group_is_killed_through_its_handle(#[fixture(pidfd_group_signal)] _group: &Group) {
    use crate::send_log::{GroupStep, Route};
    let (leader, to_member, from_member) = leader_with_member_exiting();
    // Reaped below, so the guard has nothing to reap.
    let pid = leader.defuse();
    let owned = owned_over(pid);
    crate::test_child::reaped_elsewhere::reap_behind(pid);
    let capture = crate::send_log::Capture::start();

    assert_eq!(kill_group_outside_leaf(&owned, pid), None);

    assert_eq!(capture.group_steps(), [GroupStep::Group(Route::Pidfd, libc::SIGKILL)]);
    assert_eq!(member_output(to_member, from_member), "", "the member was killed");
}

/// Where the kernel refuses `PIDFD_SIGNAL_PROCESS_GROUP` (before 6.9), a child reaped before the
/// kill gets nothing sent to its group's number: the check before it finds the child reaped. Its
/// member lives on, which is the refusal returned naming the group, for the event's one warn: the
/// kill logs none of its own.
///
/// Mutants: "a group kill by number for a reaped child"; "the unsent group kill is not returned";
/// "the group kill warns on its own".
#[skuld::test]
fn a_reaped_childs_group_gets_no_kill_by_number() {
    use crate::send_log::{GroupStep, Route};
    crate::log_capture::install();
    let (leader, to_member, from_member) = leader_with_member_exiting();
    // Reaped below, so the guard has nothing to reap.
    let pid = leader.defuse();
    let owned = owned_over(pid);
    crate::test_child::reaped_elsewhere::reap_behind(pid);
    let capture = crate::send_log::Capture::start();
    let refused = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let mark = crate::log_capture::mark();

    let not_sent = kill_group_outside_leaf(&owned, pid);

    drop(refused);
    assert!(
        not_sent.is_some_and(|text| text.contains(&format!("process group {pid}"))),
        "it names the group"
    );
    let warns = crate::log_capture::warns_since(mark, "");
    assert!(warns.is_empty(), "the group kill logs no warn of its own: {warns:?}");
    let steps = capture.group_steps();
    assert!(
        !steps.iter().any(|s| matches!(s, GroupStep::Group(Route::Number, _))),
        "nothing went by the number: {steps:?}"
    );
    assert_eq!(member_output(to_member, from_member), "survived");
}

/// What the abandonment does to a forked child that sent its intent, and then a failed placement
/// (`WriteFailed`, so it exec'd outside its leaf), a placement (`Placed`) or no report: the leaf
/// is a plain directory, and the child is named by its pidfd.
fn abandon_group_leader_reporting(report: Option<i32>) -> (Abandoned, String) {
    let (leader, _input, to_member, from_member) = leader_held_with_member();
    let pid = leader.defuse();
    let (_dir, mut leaf) = leaf_told(pid, report);
    let pidfd = pidfd_of(pid);
    // By the number: the kernel's own refusal of the flag is not needed, and the check is the
    // child being unreaped, which only a group kill before the child's teardown finds.
    let refused = crate::containment::unix::fault::refuse_pidfd_group_flag();

    let abandoned = leaf.abandon_before_verdict(false, (pidfd, Past::Clean), &mut NoWarn);

    drop(refused);
    (abandoned, member_output(to_member, from_member))
}

/// A plain-directory leaf, and its directory, that was sent the intent of the forked child `pid`
/// and then `report`, if any.
fn leaf_told(pid: u32, report: Option<i32>) -> (tempfile::TempDir, CgroupLeaf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-group-leader");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let leaf = CgroupLeaf::for_test_at(leaf_path);
    let slot = leaf.placement_slot();
    // SAFETY: the leaf's channel is open.
    unsafe {
        slot.send(TAG_INTENT, pid as i32).expect("send the intent");
        if let Some(report) = report {
            slot.send_report(report).expect("send the report");
        }
    }
    (dir, leaf)
}

/// A child that exec'd outside its leaf, whose group kill is refused and whose teardown ends it
/// cleanly, is one event with one `warn`, the group kill's: the abandonment answers `Ended`, and the
/// member the kill missed lives on.
///
/// Mutants: the group kill logs a warn of its own beside the child's; the refusal is dropped.
#[skuld::test]
fn a_refused_group_kill_of_an_ended_child_is_the_events_one_warn() {
    crate::log_capture::install();
    let (leader, to_member, from_member) = leader_with_member_exiting();
    let pid = leader.defuse();
    let (_dir, mut leaf) = leaf_told(pid, Some(libc::EBADF));
    let pidfd = pidfd_of(pid);
    crate::test_child::reaped_elsewhere::reap_behind(pid);
    let refused = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let mark = crate::log_capture::mark();

    let abandoned = leaf.abandon_before_verdict(false, (pidfd, Past::Clean), &mut NoWarn);

    drop(refused);
    assert!(matches!(abandoned, Abandoned::Ended(_)), "{abandoned:?}");
    assert_one_warn_for_the_unsent_group_kill(mark, pid);
    assert_eq!(member_output(to_member, from_member), "survived");
}

/// A child that exec'd outside its leaf has its group killed before it is torn down: the group goes
/// by its number (here, as on kernels refusing the pidfd group flag) and needs the child unreaped,
/// which its teardown ends. A child that entered its leaf, or reported nothing, never exec'd outside
/// it, and its group is left.
///
/// Mutants: the group kill after the child's teardown (the member survives); the group kill sent for
/// every child (the member of a child that entered or reported nothing dies).
#[skuld::test]
fn an_abandoned_child_outside_its_leaf_has_its_group_killed_before_it_is_torn_down() {
    for (report, member) in [
        (Some(libc::EBADF), ""),
        (Some(super::super::REPORT_PLACED), "survived"),
        (None, "survived"),
    ] {
        let (abandoned, output) = abandon_group_leader_reporting(report);
        assert!(matches!(abandoned, Abandoned::Ended(_)), "{report:?}: {abandoned:?}");
        assert_eq!(output, member, "{report:?}");
    }
}
