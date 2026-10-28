//! `end_child`, called directly on an abandoned spawn's child: a forked process that pauses or
//! ends when its input closes, with no cgroup. What it sends is read from `fault::take_child_sends`.

use super::super::fault::{self, ChildSend};
use super::super::test_support::{fork_running, KillOnDrop};
use super::{end_child, ChildFate, NoWarn, PlacementReport, Received, WarnAfter};
use crate::test_groups::{cgroup, pidfd_group_signal, Group};

/// A forked child that pauses until killed, leading its own process group, as a spawned child
/// does. Its group is set from this side too, so it is in place before this returns.
fn paused_group_leader() -> KillOnDrop {
    let child = fork_running(|| {
        // SAFETY: async-signal-safe.
        unsafe { libc::setpgid(0, 0) };
        loop {
            // SAFETY: async-signal-safe.
            unsafe { libc::pause() };
        }
    });
    // SAFETY: plain syscall on this process's own unexec'd child.
    let set = unsafe { libc::setpgid(child.pid() as i32, child.pid() as i32) };
    assert_eq!(set, 0, "setpgid: {}", std::io::Error::last_os_error());
    child
}

/// A forked child that echoes each byte written to the returned writer back on the returned
/// reader, until killed: an echo round trip proves it alive, where a `SIGKILL` lands
/// asynchronously. Once it is dead the reader answers EOF, so a test fails without hanging.
fn echoing_child() -> (KillOnDrop, std::io::PipeWriter, std::io::PipeReader) {
    use std::os::fd::AsRawFd;
    let (from_test, to_child) = std::io::pipe().expect("pipe");
    let (from_child, to_test) = std::io::pipe().expect("pipe");
    let (input, output) = (from_test.as_raw_fd(), to_test.as_raw_fd());
    let child = fork_running(move || {
        let mut byte = 0u8;
        // SAFETY: async-signal-safe; a one-byte buffer on an fd the child holds.
        while unsafe { libc::read(input, (&raw mut byte).cast(), 1) } == 1 {
            // SAFETY: as above.
            unsafe { libc::write(output, (&raw const byte).cast(), 1) };
        }
    });
    // Only the child holds these ends now, so its death closes the test's reader.
    drop((from_test, to_test));
    (child, to_child, from_child)
}

/// The background reaper took the notifier a test armed, so the test's wait for its reap ends.
#[track_caller]
fn assert_handed_to_the_background_reaper() {
    assert!(
        fault::take_background_reap_notifier().is_none(),
        "the child must be handed to the background reaper"
    );
}

/// How a child ended: the signal, or `None` for an exit by itself.
type EndedBy = std::rc::Rc<std::cell::Cell<Option<Option<i32>>>>;

/// Arms the exit-wait seam of `end_child` to end `input` (see [`group_leader_ending_at_eof`]) and
/// then run `then`, and to read how the child `pid` ended, without reaping it. A child the handle's
/// kill reached ends by `SIGKILL`, which was pending before the release; one no kill reached
/// exits by itself, and the test fails by assertion instead of `end_child` waiting for it forever.
fn release_at_the_exit_wait(
    pid: u32,
    input: std::io::PipeWriter,
    then: impl FnOnce() + 'static,
) -> (fault::BeforeExitWaitGuard, EndedBy) {
    let ended: EndedBy = std::rc::Rc::default();
    let pidfd = super::super::test_support::pidfd_of(pid);
    let guard = fault::set_before_exit_wait({
        let ended = std::rc::Rc::clone(&ended);
        move || {
            drop(input);
            let status = loop {
                match rustix::process::waitid(
                    rustix::process::WaitId::PidFd(std::os::fd::AsFd::as_fd(&pidfd)),
                    rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
                ) {
                    Err(rustix::io::Errno::INTR) => {}
                    other => break other,
                }
            };
            let status = status
                .expect("waitid on the child's pidfd")
                .expect("a blocking waitid returns a status");
            ended.set(Some(status.terminating_signal()));
            then();
        }
    });
    (guard, ended)
}

#[track_caller]
fn assert_killed(ended: &EndedBy) {
    assert_eq!(
        ended.get(),
        Some(Some(libc::SIGKILL)),
        "the child died of the handle's kill, not by itself once released"
    );
}

/// What `end_child` receives for `child`, named by its pidfd, after `report`. `end_child` reaps
/// it from here on.
fn received(child: KillOnDrop, report: Option<PlacementReport>) -> Received {
    let pidfd = super::super::test_support::pidfd_of(child.pid());
    Received {
        report,
        pid: Some(child.defuse()),
        pidfd: Some(pidfd),
        proc_dir: None,
    }
}

/// The child is killed through its pidfd, then reaped by the test before `end_child`'s final wait,
/// which answers `ECHILD`: a foreign reap, logged at `debug`, and the fate stays `Killed`.
///
/// Mutant: the `debug_assert!` on the failed reap kept (a debug panic), or its `warn`.
#[skuld::test]
fn an_abandoned_childs_foreign_reap_is_debug_not_a_panic() {
    crate::log_capture::install();
    let (child, input) = group_leader_ending_at_eof();
    let received = received(child, None);
    let pid = received.pid.expect("a pid");
    // `end_child` has already sent its `SIGKILL`.
    let (_reaped_elsewhere, ended) =
        release_at_the_exit_wait(pid, input, move || super::super::test_support::reap(pid));

    let mark = crate::log_capture::mark();
    let fate = end_child(&received, &mut NoWarn);

    assert_killed(&ended);
    assert_eq!(fate, ChildFate::Killed);
    let records = crate::log_capture::records_since_on_current_thread(mark, "reaped elsewhere");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Debug, "{records:?}");
    assert!(
        records[0].1.contains(&pid.to_string()),
        "it names the child: {records:?}"
    );
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect();
    assert_eq!(warns, [], "a foreign reap is not a warning");
}

/// A child that reported a failed placement exec'd outside its leaf, so what it forks is reachable
/// only as its process group. That group is killed while the child is still unreaped, before the
/// kill through its handle, which ends it and so frees its number for a foreign reaper. Its member
/// is killed: the handle's kill ends only the child.
///
/// The group kill reaches the leader too, so only when it and the handle's kill both send nothing
/// does the leader end by itself, released at `end_child`'s exit wait: `assert_killed` then fails
/// instead of the wait hanging.
///
/// Mutants: the group killed after the handle's kill (`[Handle, Group]`); the group kill sends nothing.
#[skuld::test]
fn an_abandoned_child_outside_its_leaf_is_killed_as_its_group_before_its_handle(#[fixture(cgroup)] _group: &Group) {
    let (child, input, to_member, from_member) = leader_held_with_member();
    let received = received(child, Some(PlacementReport::WriteFailed(libc::EBADF)));
    let (_released, ended) = release_at_the_exit_wait(received.pid.expect("a pid"), input, || {});

    assert_eq!(end_child(&received, &mut NoWarn), ChildFate::Killed);
    assert_killed(&ended);
    assert_eq!(fault::take_child_sends(), [ChildSend::Group, ChildSend::Handle]);
    assert_eq!(
        member_output(to_member, from_member),
        "",
        "the group kill ended the member"
    );
}

/// A child that entered its leaf is killed with the leaf, and one that never reported never
/// exec'd: neither has anything only its group reaches, so neither is sent a kill by number.
///
/// Mutant: the group kill sent for every child (`[Handle, Group]`).
#[skuld::test]
fn an_abandoned_child_in_its_leaf_or_unreported_is_sent_no_group_kill() {
    for report in [Some(PlacementReport::Placed), None] {
        let (child, input) = group_leader_ending_at_eof();
        let received = received(child, report);
        let (_released, ended) = release_at_the_exit_wait(received.pid.expect("a pid"), input, || {});

        assert_eq!(end_child(&received, &mut NoWarn), ChildFate::Killed, "{report:?}");
        assert_killed(&ended);
        assert_eq!(fault::take_child_sends(), [ChildSend::Handle], "{report:?}");
    }
}

/// A group kill that finds no group (`ESRCH`, forced here) is logged at `debug`, and the child is
/// still killed through its handle.
///
/// Mutant: the group kill's result discarded (no record).
#[skuld::test]
fn an_abandoned_childs_group_kill_finding_no_group_is_logged_at_debug(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let (child, input) = group_leader_ending_at_eof();
    let received = received(child, Some(PlacementReport::WriteFailed(libc::EBADF)));
    let pid = received.pid.expect("a pid");
    let (_released, ended) = release_at_the_exit_wait(pid, input, || {});
    let _gone = fault::force_group_kill_gone();

    let mark = crate::log_capture::mark();
    assert_eq!(end_child(&received, &mut NoWarn), ChildFate::Killed);
    assert_killed(&ended);

    let records = crate::log_capture::records_since_on_current_thread(mark, "process group");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Debug, "{records:?}");
    assert!(records[0].1.contains(&pid.to_string()), "{records:?}");
}

/// A child outside its leaf that refuses both its group kill and its handle's kill (as a setuid
/// child does) is one abandoned child: one refusal naming both, left to the caller's one warn.
///
/// Mutant: either refusal warned about here (a warn), or the group's left out of the refusal.
#[skuld::test]
fn an_abandoned_child_refusing_both_kills_is_one_refusal_naming_both(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let child = paused_group_leader();
    let received = received(child, Some(PlacementReport::WriteFailed(libc::EBADF)));
    let pid = received.pid.expect("a pid");
    let pidfd = super::super::test_support::pidfd_of(pid);
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    fault::set_force_group_kill_denied(true);
    fault::set_force_child_kill_denied(true);
    fault::set_background_reap_notifier(reaped_tx);

    let mark = crate::log_capture::mark();
    let fate = end_child(&received, &mut NoWarn);

    let ChildFate::Unkillable(refused) = &fate else {
        panic!("expected Unkillable, got {fate:?}");
    };
    assert!(
        refused.contains(&format!("process group {pid}")),
        "it names the refused group kill: {refused}"
    );
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect();
    assert_eq!(warns, [], "the caller warns");
    rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL).expect("kill the child");
    assert_handed_to_the_background_reaper();
    reaped_rx.recv().expect("the background reaper must reap it");
}

/// A kill its handle refuses (`EPERM`, forced here in place of the syscall, as from a setuid
/// child) is not retried by the child's bare pid: the child is out of reach, still running, and
/// reaped once it exits. `end_child` cannot see the forced refusal, so a retry would be real.
///
/// Mutant: a by-pid kill on `EPERM` (fate `Killed`, or no echo).
#[skuld::test]
fn an_abandoned_child_refusing_its_handles_kill_is_not_killed_by_pid() {
    let (child, mut to_child, mut from_child) = echoing_child();
    let received = received(child, None);
    let pidfd = super::super::test_support::pidfd_of(received.pid.expect("a pid"));
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    fault::set_force_child_kill_denied(true);
    fault::set_background_reap_notifier(reaped_tx);

    let fate = end_child(&received, &mut NoWarn);
    assert!(matches!(fate, ChildFate::Unkillable(_)), "{fate:?}");
    assert_eq!(fault::take_child_sends(), [ChildSend::Handle]);
    crate::test_child::assert_echoes(&mut to_child, &mut from_child);

    // Unreaped, so its pidfd still names it.
    rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL).expect("kill the child");
    assert_handed_to_the_background_reaper();
    reaped_rx.recv().expect("the background reaper must reap it");
}

/// A child outside its leaf whose group kill is refused, but whose own kill lands, is warned about
/// once, naming the group: what is left in it may keep running.
///
/// Mutant: the group-refused arm removed, or logged at `debug`.
#[skuld::test]
fn an_abandoned_child_whose_group_kill_is_refused_is_warned_about_once(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let (child, input) = group_leader_ending_at_eof();
    let received = received(child, Some(PlacementReport::WriteFailed(libc::EBADF)));
    let pid = received.pid.expect("a pid");
    let (_released, ended) = release_at_the_exit_wait(pid, input, || {});
    fault::set_force_group_kill_denied(true);

    let mark = crate::log_capture::mark();
    assert_eq!(end_child(&received, &mut NoWarn), ChildFate::Killed);
    assert_killed(&ended);

    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].1.contains(&format!("process group {pid}")),
        "it names the refused group kill: {warns:?}"
    );
}

/// A forked child that leads its own process group, as a spawned child does, and exits by itself
/// once the returned writer closes. So a kill that was never made shows as an exit that is not a
/// `SIGKILL`, where waiting on the child would hang.
fn group_leader_ending_at_eof() -> (KillOnDrop, std::io::PipeWriter) {
    use std::os::fd::AsRawFd;
    let (from_test, to_child) = std::io::pipe().expect("pipe");
    let (input, test_end) = (from_test.as_raw_fd(), to_child.as_raw_fd());
    let child = fork_running(move || {
        // SAFETY: async-signal-safe syscalls on fds this process holds.
        unsafe {
            libc::setpgid(0, 0);
            libc::close(test_end);
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

/// A child reaped elsewhere after its group kill and before its handle's kill (`ESRCH`) is
/// `Killed`: cosca's kill reached its group. One no kill of cosca's reached, killed and reaped by
/// someone else, is `Gone`. The reaper ends the child's input first and checks that it died of
/// `SIGKILL`: a kill sent before the hook lands before the child can read the end of its input.
///
/// Mutants: `ESRCH` from the handle's kill read as `Gone` whatever the group kill did; the group
/// kill not made.
#[skuld::test]
fn an_abandoned_child_reaped_elsewhere_after_its_group_kill_is_killed(#[fixture(cgroup)] _group: &Group) {
    for (report, fate) in [
        (Some(PlacementReport::WriteFailed(libc::EBADF)), ChildFate::Killed),
        (None, ChildFate::Gone),
    ] {
        let (child, input) = group_leader_ending_at_eof();
        let received = received(child, report);
        let pid = received.pid.expect("a pid");
        let pidfd = super::super::test_support::pidfd_of(pid);
        let signal = std::rc::Rc::new(std::cell::Cell::new(None));
        let _reaped_elsewhere = fault::set_before_handle_kill({
            let signal = std::rc::Rc::clone(&signal);
            move || {
                if report.is_none() {
                    rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL).expect("kill the child");
                }
                drop(input);
                let mut status = 0;
                // SAFETY: `pid` is this test's own child; this plays another reaper in the process.
                let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
                assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
                signal.set(libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status)));
            }
        });

        let ended = end_child(&received, &mut NoWarn);
        assert_eq!(signal.get(), Some(libc::SIGKILL), "the child was killed: {report:?}");
        assert_eq!(ended, fate, "{report:?}");
    }
}

/// Where the kernel refuses `PIDFD_SIGNAL_PROCESS_GROUP` (before 6.9), the group kill of a child
/// outside its leaf goes by its number only right after a check that the child is still unreaped,
/// and kills its member. Mutants: "no check before the group kill by number", "`EINVAL` ends the
/// group kill", "the group kill by number is not made".
#[skuld::test]
fn an_abandoned_childs_group_kill_by_number_follows_its_own_check() {
    use crate::send_log::{GroupStep, Route};
    let (child, input, to_member, from_member) = leader_held_with_member();
    let received = received(child, Some(PlacementReport::WriteFailed(libc::EBADF)));
    let (_released, ended) = release_at_the_exit_wait(received.pid.expect("a pid"), input, || {});
    let capture = crate::send_log::Capture::start();
    let refused = crate::containment::unix::fault::refuse_pidfd_group_flag();

    assert_eq!(end_child(&received, &mut NoWarn), ChildFate::Killed);
    assert_killed(&ended);
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
    assert_eq!(fault::take_child_sends(), [ChildSend::Group, ChildSend::Handle]);
}

/// Linux 6.9+: the group kill of a child outside its leaf goes through its handle, which names the
/// group exactly, and kills its member: the handle's kill ends only the child.
#[skuld::test]
fn an_abandoned_childs_group_kill_goes_through_its_handle(#[fixture(pidfd_group_signal)] _group: &Group) {
    use crate::send_log::{GroupStep, Route};
    let (child, input, to_member, from_member) = leader_held_with_member();
    let received = received(child, Some(PlacementReport::WriteFailed(libc::EBADF)));
    let (_released, ended) = release_at_the_exit_wait(received.pid.expect("a pid"), input, || {});
    let capture = crate::send_log::Capture::start();

    assert_eq!(end_child(&received, &mut NoWarn), ChildFate::Killed);
    assert_killed(&ended);
    assert_eq!(
        member_output(to_member, from_member),
        "",
        "the group kill ended the member"
    );
    assert_eq!(capture.group_steps(), [GroupStep::Group(Route::Pidfd, libc::SIGKILL)]);
}

/// A child reaped elsewhere after the look gets no group kill by its number: the check right before
/// it finds the child gone. What may be left in its group is one `warn` naming the group. Mutants:
/// "the check's answer is not heeded"; "the unsent group kill is a `debug`".
#[skuld::test]
fn an_abandoned_child_reaped_before_its_group_kill_by_number_is_not_sent_it() {
    use crate::send_log::{GroupStep, Route};
    crate::log_capture::install();
    let child = paused_group_leader();
    let pid = child.pid();
    let received = received(child, Some(PlacementReport::WriteFailed(libc::EBADF)));
    // The kill through the handle and the reap are this test's: nothing else reaches the child.
    fault::set_between_check_and_kill(move || {
        // SAFETY: a plain syscall on this process's own child.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        super::super::test_support::reap(pid);
    });
    let capture = crate::send_log::Capture::start();
    let refused = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let mark = crate::log_capture::mark();

    let fate = end_child(&received, &mut NoWarn);
    drop(refused);
    assert_one_warn_for_the_unsent_group_kill(mark, pid);
    assert_eq!(
        capture.group_steps(),
        [GroupStep::Group(Route::Pidfd, libc::SIGKILL), GroupStep::Check]
    );
    assert!(
        !capture
            .group_steps()
            .iter()
            .any(|s| matches!(s, GroupStep::Group(Route::Number, _))),
        "nothing went by the number"
    );
    assert_eq!(fate, ChildFate::Gone);
}

/// The one `warn` for a group kill that was not sent because the kernel refused the flag and the
/// child was reaped: it names the group, as a kill that was refused does.
fn assert_one_warn_for_the_unsent_group_kill(mark: usize, pid: u32) {
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].1.contains(&format!("process group {pid}")),
        "it names the group: {warns:?}"
    );
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
/// closes, and then exits by itself. So a leader no kill reached ends by itself, not by `SIGKILL`,
/// where waiting on it would hang (see [`release_at_the_exit_wait`]).
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
    let leader = fork_running(move || {
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

/// Linux 6.9+: a child outside its leaf that another reaper reaped before `end_child`'s look still
/// names its process group through its handle, so the member it left there is killed. The child is
/// `Gone`: no kill of cosca's reached it. Mutants: "a child reaped before the look gets no group
/// kill", "the group kill makes it `Killed`".
#[skuld::test]
fn an_abandoned_child_reaped_before_the_look_has_its_group_killed(#[fixture(pidfd_group_signal)] _group: &Group) {
    use crate::send_log::{GroupStep, Route};
    let (leader, to_member, from_member) = leader_with_member_exiting();
    let received = received(leader, Some(PlacementReport::WriteFailed(libc::EBADF)));
    crate::test_child::reaped_elsewhere::reap_behind(received.pid.expect("a pid"));
    let capture = crate::send_log::Capture::start();

    let fate = end_child(&received, &mut NoWarn);
    let steps = capture.group_steps();
    let out = member_output(to_member, from_member);
    assert_eq!(steps, [GroupStep::Group(Route::Pidfd, libc::SIGKILL)]);
    assert_eq!(out, "", "the member was killed");
    assert_eq!(fate, ChildFate::Gone);
}

/// Where the kernel refuses `PIDFD_SIGNAL_PROCESS_GROUP` (before 6.9), a child reaped before the
/// look is `Gone`, and nothing goes to its group's number: the check before it finds the child
/// reaped. Its member lives on, which is one `warn` naming the group. Mutants: "a group kill by
/// number for a reaped child"; "the unsent group kill is a `debug`".
#[skuld::test]
fn an_abandoned_child_reaped_before_the_look_gets_no_group_kill_by_number() {
    use crate::send_log::{GroupStep, Route};
    crate::log_capture::install();
    let (leader, to_member, from_member) = leader_with_member_exiting();
    let received = received(leader, Some(PlacementReport::WriteFailed(libc::EBADF)));
    let pid = received.pid.expect("a pid");
    crate::test_child::reaped_elsewhere::reap_behind(pid);
    let capture = crate::send_log::Capture::start();
    let refused = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let mark = crate::log_capture::mark();

    let fate = end_child(&received, &mut NoWarn);
    drop(refused);
    assert_one_warn_for_the_unsent_group_kill(mark, pid);
    let steps = capture.group_steps();
    let out = member_output(to_member, from_member);
    assert!(
        !steps.iter().any(|s| matches!(s, GroupStep::Group(Route::Number, _))),
        "nothing went by the number: {steps:?}"
    );
    assert_eq!(out, "survived");
    assert_eq!(fate, ChildFate::Gone);
}

/// A child known by its `/proc` directory, killed and then reaped by another reaper before the wait:
/// its number may name another child of this process by then, one that is running. The wait's warn
/// does not name that process. (The wait by the number collects it: the residual the cgroup
/// module's Ownership paragraph states.)
///
/// Mutant: the warn watches through a pidfd opened on the number, unchecked against the directory.
#[skuld::test]
fn a_child_reaped_elsewhere_is_not_warned_about_through_its_number() {
    use std::os::fd::AsRawFd as _;

    use crate::test_support::foreign_tracer::{await_blocked_or_finished, Holder};

    crate::log_capture::install();
    let gone = fork_running(|| loop {
        // SAFETY: async-signal-safe.
        unsafe { libc::pause() };
    });
    // Stands for the process the number names next: running until its pipe closes.
    let (from_test, to_holder) = std::io::pipe().expect("pipe");
    let (input, output) = (from_test.as_raw_fd(), to_holder.as_raw_fd());
    let holder = fork_running(move || {
        // SAFETY: async-signal-safe; the child's own copy of the test's end, so EOF can come.
        unsafe { libc::close(output) };
        let mut byte = 0u8;
        // SAFETY: async-signal-safe; a one-byte buffer on an fd the child holds.
        while unsafe { libc::read(input, (&raw mut byte).cast(), 1) } == 1 {}
    });
    // Only the holder reads now; `end_child`'s wait reaps it, below.
    drop(from_test);
    let gone = gone.defuse();
    let holder = holder.defuse();
    let proc_dir = std::fs::File::open(format!("/proc/{gone}")).expect("open the /proc directory");
    let received = Received {
        report: None,
        pid: Some(holder),
        pidfd: None,
        proc_dir: Some(proc_dir.into()),
    };

    let mark = crate::log_capture::mark();
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let (seen, fate) = std::thread::scope(|s| {
        let ended = s.spawn(|| {
            tid_tx
                .send(rustix::thread::gettid().as_raw_nonzero().get())
                .expect("report the tid");
            let _reaped_elsewhere = fault::set_before_exit_wait(move || super::super::test_support::reap(gone));
            end_child(&received, &mut WarnAfter(Some(std::time::Duration::ZERO)))
        });
        let seen = await_blocked_or_finished(tid_rx.recv().expect("the tid"));
        drop(to_holder);
        (seen, ended.join().expect("end_child"))
    });

    assert_eq!(seen, Holder::Blocked, "the wait by the number waits for the holder");
    assert_eq!(fate, ChildFate::Killed);
    let warns = crate::log_capture::records_since(mark, "still waiting");
    assert_eq!(warns, Vec::<String>::new(), "no warn names the number's holder");
}
