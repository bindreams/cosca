//! Forced kills of a front in a cgroup: the cgroup lane (the `cgroup` group, as root). The front is
//! an ordinary child reported as launched by `sudo`.
//!
//! A cgroup kill reaches a member whatever its credentials, and nothing is signalled after it: with
//! direct exec the tracked process is the root program, which refuses the caller's signal. That case
//! is real here. The front runs as `nobody`, and the test thread drops `CAP_KILL` from its
//! effective set, so a signal to the front fails with `EPERM` while the `cgroup.kill` write, a file
//! write, still succeeds.

use std::io::{PipeWriter, Read as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;

use crate::child::fault::record_root_teardowns;
use crate::child::front_kill_tests::{
    assert_ends_unsignalled, assert_reaped_unsignalled, assert_refused_by, assert_unkillable_front, cat, spawn_as,
};
use crate::command::Command;
use crate::elevation::{Backend, ElevatedVia};
use crate::test_groups::{cgroup, Group};
use crate::{ContainMode, Containment, Stdio};

const SUDO: ElevatedVia = ElevatedVia::Wrapped(Backend::Sudo);

/// A forced kill of a child: `kill` or `kill_tree`.
type Kill = fn(&crate::Child) -> Result<(), crate::error::Error>;

/// `cmd`, contained in a cgroup.
fn in_cgroup(mut cmd: Command) -> Command {
    cmd.contain_with(ContainMode::Strongest);
    cmd
}

/// A `cat` that runs as `nobody` in a cgroup, reported as launched by `sudo`: a front whose signal a
/// thread without `CAP_KILL` is refused. Returns once it runs as `nobody`.
pub(crate) fn nobody_cat() -> Command {
    let mut cmd = Command::new();
    cmd.args([
        "setpriv",
        "--reuid=65534",
        "--regid=65534",
        "--clear-groups",
        "sh",
        "-c",
        "echo ready; exec cat",
    ]);
    cmd.stdout(Stdio::pipe_out()).expect("stdout pipe");
    in_cgroup(cmd)
}

/// Spawns [`nobody_cat`] as a `sudo` front, and waits for its `ready`.
fn spawn_nobody_front() -> (crate::Child, PipeWriter) {
    let (mut child, stdin) = spawn_as(nobody_cat(), SUDO);
    assert_eq!(child.containment(), Containment::CgroupV2);
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut ready)
        .expect("read `ready`");
    assert_eq!(&ready, b"ready\n");
    (child, stdin)
}

/// While it lives, this thread has no `CAP_KILL` in its effective set: its signal to another user's
/// process is refused. Capabilities are per thread, so the test's own thread is the only one
/// affected; the guard puts the capability back.
#[must_use = "the capability returns as soon as the guard is dropped"]
pub(crate) struct WithoutKillCap(rustix::thread::CapabilitySets);

impl WithoutKillCap {
    /// Drops `CAP_KILL`, and asserts a signal to `pid`, another user's process, is now refused.
    pub(crate) fn refusing(pid: u32) -> WithoutKillCap {
        use rustix::thread::{capabilities, set_capabilities, CapabilitySet};
        let saved = capabilities(None).expect("capget");
        assert!(
            saved.effective.contains(CapabilitySet::KILL),
            "the cgroup lane runs as root, with CAP_KILL: {saved:?}"
        );
        let mut without = saved;
        without.effective.remove(CapabilitySet::KILL);
        set_capabilities(None, without).expect("capset without CAP_KILL");
        let guard = WithoutKillCap(saved);
        let target = rustix::process::Pid::from_raw(pid as i32).expect("a positive pid");
        assert_eq!(
            rustix::process::test_kill_process(target),
            Err(rustix::io::Errno::PERM),
            "the front {pid} must refuse this thread's signal"
        );
        guard
    }
}

impl Drop for WithoutKillCap {
    fn drop(&mut self) {
        rustix::thread::set_capabilities(None, self.0).expect("capset to restore CAP_KILL");
    }
}

/// A pidfd for `pid`, an unreaped child of this process, to read its end without reaping it.
pub(crate) fn pidfd_of(pid: u32) -> OwnedFd {
    let pid = rustix::process::Pid::from_raw(pid as i32).expect("a positive pid");
    rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open")
}

/// Whether the child `pidfd` names has been reaped, by anyone. Consumes nothing.
pub(crate) fn reaped(pidfd: &OwnedFd) -> bool {
    loop {
        match rustix::process::waitid(
            rustix::process::WaitId::PidFd(pidfd.as_fd()),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        ) {
            Ok(_) => return false,
            Err(rustix::io::Errno::CHILD) => return true,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => panic!("waitid on a pidfd: {e}"),
        }
    }
}

/// Moves `pid` out of its leaf into this process's own cgroup, as pam_systemd moves sudo into a
/// session scope. The lane's cgroup enables no controllers, so it may hold processes.
pub(crate) fn move_out_of_its_leaf(pid: u32) {
    let own = std::fs::read_to_string("/proc/self/cgroup").expect("read /proc/self/cgroup");
    let path = own
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("a cgroup v2 `0::` line");
    let procs = format!("/sys/fs/cgroup{path}/cgroup.procs");
    std::fs::write(&procs, pid.to_string()).unwrap_or_else(|e| panic!("move {pid} into {procs}: {e}"));
}

/// The cgroup directory `pid` is in.
pub(crate) fn cgroup_dir_of(pid: u32) -> String {
    let own = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("read the cgroup");
    let path = own
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("a cgroup v2 `0::` line");
    format!("/sys/fs/cgroup{path}")
}

/// Moves `pid` from its leaf into a new cgroup beside it, named as the leaf with ` (deleted)` after
/// it, as `/proc` prints the leaf once it is removed.
pub(crate) fn move_into_a_namesake_of_its_leaf(pid: u32) {
    let own = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("read the front's cgroup");
    let leaf = own
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("a cgroup v2 `0::` line");
    let namesake = format!("/sys/fs/cgroup{leaf} (deleted)");
    std::fs::create_dir(&namesake).unwrap_or_else(|e| panic!("make {namesake}: {e}"));
    std::fs::write(format!("{namesake}/cgroup.procs"), pid.to_string())
        .unwrap_or_else(|e| panic!("move {pid} into {namesake}: {e}"));
}

/// Moves `pid` from its leaf into a cgroup two levels under it, `a/b`, as a program may make one,
/// and returns that cgroup's directory.
pub(crate) fn move_under_its_leaf(pid: u32) -> String {
    let own = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("read the front's cgroup");
    let leaf = own
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("a cgroup v2 `0::` line");
    let nested = format!("/sys/fs/cgroup{leaf}/a/b");
    std::fs::create_dir_all(&nested).unwrap_or_else(|e| panic!("make {nested}: {e}"));
    std::fs::write(format!("{nested}/cgroup.procs"), pid.to_string())
        .unwrap_or_else(|e| panic!("move {pid} into {nested}: {e}"));
    nested
}

/// The kill goes through `cgroup.kill`, and sends the front nothing after it.
#[skuld::test]
fn cgroup_kill_of_a_front_goes_through_the_cgroup_alone(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    assert_eq!(child.containment(), Containment::CgroupV2);
    crate::wait::exit_only::seams::signals_sent();
    child.kill().expect("the cgroup kill reaches the program");
    assert_eq!(
        crate::wait::exit_only::seams::signals_sent(),
        0,
        "nothing is signalled after it"
    );
    assert!(child.tree_killed.is_set(), "the kill must go through the cgroup");
    // Closed first: a front nothing killed then exits 0, and the assertion fails.
    drop(stdin);
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
}

/// `kill_tree` likewise.
#[skuld::test]
fn cgroup_kill_tree_of_a_front_goes_through_the_cgroup_alone(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    crate::wait::exit_only::seams::signals_sent();
    child.kill_tree().expect("the cgroup kill reaches the program");
    assert_eq!(
        crate::wait::exit_only::seams::signals_sent(),
        0,
        "nothing is signalled after it"
    );
    assert!(child.tree_killed.is_set());
    // Closed first: a front nothing killed then exits 0, and the assertion fails.
    drop(stdin);
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
}

/// The drop kills the front through the cgroup and reaps it, sending it nothing.
#[skuld::test]
fn cgroup_drop_of_a_front_kills_it_through_the_cgroup_and_reaps_it(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let teardowns = record_root_teardowns();
    let (child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pidfd = pidfd_of(child.id().pid());
    let mark = crate::log_capture::mark();
    drop(child);
    assert_eq!(teardowns.count(), 0, "the drop sends the front no kill of its own");
    assert!(reaped(&pidfd), "the drop reaps the front its cgroup kill ended");
    let warns = crate::log_capture::records_since_on_current_thread(mark, "Child::drop");
    assert_eq!(warns, [], "a front the cgroup killed is not left behind");
}

/// A failed cgroup kill may leave the program running, so the front is not signalled either.
#[skuld::test]
fn cgroup_a_failed_kill_of_a_front_leaves_the_front_alone(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        crate::child::front_kill_tests::assert_refused_by(child.kill(), "its cgroup kill failed");
        crate::child::front_kill_tests::assert_refused_by(child.kill_tree(), "its cgroup kill failed");
    }
    assert_ends_unsignalled(&child, stdin);
}

/// The drop, too, leaves a front alone when its cgroup kill fails.
#[skuld::test]
fn cgroup_a_failed_drop_kill_of_a_front_leaves_the_front_alone(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let teardowns = record_root_teardowns();
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let crate::containment::Attached::Cgroup(leaf) = &child.attached else {
        panic!("expected a cgroup leaf, got {:?}", child.attached);
    };
    let leaf = leaf.path().to_path_buf();
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        drop(child);
    }
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "Child::drop")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect();
    assert_eq!(warns.len(), 1, "one warn for the one event: {warns:?}");
    assert!(
        warns[0].1.contains("contained-tree teardown did not fully succeed")
            && warns[0].1.contains("elevation front pid"),
        "the failed kill and the front are in it: {warns:?}"
    );
    assert_eq!(teardowns.count(), 0, "the drop must not kill or reap the front");
    drop(stdin);
    assert_reaped_unsignalled(pid);
    // The failed kill left the leaf behind; it is empty now.
    std::fs::remove_dir(&leaf).unwrap_or_else(|e| panic!("remove the leaf {}: {e}", leaf.display()));
}

/// A `cat` front, contained and reported as launched by `sudo`, that has also started a `sleep` in
/// its leaf: another member of the tree. Returns the front, its stdin and a pidfd of the `sleep`.
pub(crate) fn spawn_front_with_member() -> (crate::Child, PipeWriter, OwnedFd) {
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "sleep 1000 & echo $!; exec cat"]);
    cmd.stdout(Stdio::pipe_out()).expect("stdout pipe");
    let (mut child, stdin) = spawn_as(in_cgroup(cmd), SUDO);
    let mut line = Vec::new();
    let mut stdout = child.stdout().expect("stdout pipe");
    let mut byte = [0u8; 1];
    while stdout.read_exact(&mut byte).is_ok() && byte[0] != b'\n' {
        line.push(byte[0]);
    }
    let member: u32 = String::from_utf8(line)
        .expect("utf8")
        .trim()
        .parse()
        .expect("the sleep's pid");
    (child, stdin, pidfd_of(member))
}

/// Blocks until the process `pidfd` names (it need not be a child) has exited. Only for a process
/// whose kill has been shown to have been written, so the wait is for the kill's effect.
pub(crate) fn wait_until_exited(pidfd: &OwnedFd) {
    let mut fds = [rustix::event::PollFd::from_borrowed_fd(
        pidfd.as_fd(),
        rustix::event::PollFlags::IN,
    )];
    while rustix::event::poll(&mut fds, None) == Err(rustix::io::Errno::INTR) {}
}

/// What a drop that keeps its leaf armed does with a front in the leaf: the leaf's kill ends the
/// front and every other member, the drop reaps the front (a later `waitid` on its pidfd finds
/// nothing to wait for), says so at `debug` with how it died, and never says the front is left
/// running. `fault` arms whatever made the drop's own look at the front fail.
#[track_caller]
fn assert_drop_kills_the_leaf_and_reaps_the_front(fault: impl FnOnce() -> Box<dyn std::any::Any>) {
    crate::log_capture::install();
    let (child, stdin, member) = spawn_front_with_member();
    let front = pidfd_of(child.id().pid());
    let pid = child.id().pid();
    // At the look: the front's end is awaited, after releasing its stdin so a front nothing killed
    // ends too (and the status below says how).
    let stdin = std::rc::Rc::new(std::cell::Cell::new(Some(stdin)));
    let _look = crate::child::fault::set_before_front_look({
        let stdin = std::rc::Rc::clone(&stdin);
        move || {
            drop(stdin.take());
            crate::test_child::wait_until_zombie(pid);
        }
    });
    crate::containment::cgroup::fault::record_leaf_steps();
    let mark = crate::log_capture::mark();
    {
        let _fault = fault();
        drop(child);
    }
    let steps = crate::containment::cgroup::fault::take_leaf_steps();
    let said =
        crate::log_capture::records_since_on_current_thread(mark, &format!("Child::drop: elevation front pid {pid}"));
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(said[0].0, log::Level::Debug, "{said:?}");
    assert!(
        said[0].1.contains("killed through its cgroup and reaped (signal: 9"),
        "{said:?}"
    );
    assert!(reaped(&front), "the drop reaps the front its leaf's kill ended");
    assert!(steps.iter().any(|s| s == "kill"), "{steps:?}");
    wait_until_exited(&member);
}

/// A drop whose placement read fails (so it cannot tell the front is in its leaf) still lets the
/// armed leaf kill the leaf, front included, and reaps the front after the leaf's drain. Mutants:
/// "the drop disarms the leaf" (the front survives), "the drop does not reap".
#[skuld::test]
fn cgroup_a_drop_whose_placement_read_fails_kills_the_leaf_and_reaps_the_front(#[fixture(cgroup)] _group: &Group) {
    assert_drop_kills_the_leaf_and_reaps_the_front(|| Box::new(crate::containment::cgroup::fault::fail_pidfd_info()));
}

/// A drop whose own first `cgroup.kill` write fails: the leaf's retry kills the leaf, and the front
/// is reaped, with no word of it running. Mutants as above.
#[skuld::test]
fn cgroup_a_drop_whose_first_cgroup_kill_fails_kills_the_leaf_and_reaps_the_front(#[fixture(cgroup)] _group: &Group) {
    assert_drop_kills_the_leaf_and_reaps_the_front(|| {
        Box::new(crate::containment::cgroup::fault::fail_next_kill_write())
    });
}

/// A drop whose kill landed but whose reach cannot be read: the front is looked at once the leaf
/// has drained, found exited, and reaped. Mutant: "the drop warns the front is not reached without
/// looking".
#[skuld::test]
fn cgroup_a_drop_whose_post_kill_read_fails_reaps_the_front_the_kill_ended(#[fixture(cgroup)] _group: &Group) {
    assert_drop_kills_the_leaf_and_reaps_the_front(|| {
        let unreadable = std::rc::Rc::new(std::cell::RefCell::new(None));
        let arming = crate::containment::cgroup::fault::set_before_kill_write({
            let unreadable = std::rc::Rc::clone(&unreadable);
            move || *unreadable.borrow_mut() = Some(crate::containment::cgroup::fault::fail_pidfd_info())
        });
        let running = crate::elevation::front::seams::read_front_running_at_every_reach_read();
        Box::new((arming, running, unreadable))
    });
}

/// What a drop does with a front its leaf's kill ended, when the look at its exit still reads it as
/// running, as on a kernel before 6.19, where a killed task leaves its cgroup (ending the leaf's
/// drain) before it can be collected: its place says it is dying, so it is waited for and reaped,
/// and never called running. Neither the drain nor the look's hook waits for it. Mutant: "the look
/// trusts the exit alone" (the warning then says it is left running, and nothing reaps it).
#[skuld::test]
fn cgroup_a_drop_places_a_front_that_reads_as_running_and_reaps_it(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let (child, _stdin, member) = spawn_front_with_member();
    let pid = child.id().pid();
    let front = pidfd_of(pid);
    let _old_kernel = crate::child::fault::read_front_as_running_at_the_look();
    let mark = crate::log_capture::mark();
    {
        let _first_write_fails = crate::containment::cgroup::fault::fail_next_kill_write();
        drop(child);
    }
    let said =
        crate::log_capture::records_since_on_current_thread(mark, &format!("Child::drop: elevation front pid {pid}"));
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(said[0].0, log::Level::Debug, "{said:?}");
    assert!(
        said[0].1.contains("killed through its cgroup and reaped (signal: 9"),
        "{said:?}"
    );
    assert!(reaped(&front), "the drop reaps the front");
    wait_until_exited(&member);
}

/// The same front whose place cannot be read (its pidfd's cgroup id fails) is not called running,
/// nor waited for: one warning says where it is cannot be read. Mutant: "an unreadable place is
/// taken for running".
#[skuld::test]
fn cgroup_a_drop_that_cannot_place_a_front_does_not_call_it_running(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let (child, _stdin, _member) = spawn_front_with_member();
    let pid = child.id().pid();
    let _old_kernel = crate::child::fault::read_front_as_running_at_the_look();
    let mark = crate::log_capture::mark();
    {
        let _unreadable = crate::containment::cgroup::fault::fail_pidfd_info();
        drop(child);
    }
    let said =
        crate::log_capture::records_since_on_current_thread(mark, &format!("Child::drop: elevation front pid {pid}"));
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(said[0].0, log::Level::Warn, "{said:?}");
    assert!(said[0].1.contains("cannot be read"), "{said:?}");
    assert!(!said[0].1.contains("left running"), "{said:?}");
    // The leaf's kill ended it, and the drop left it unreaped.
    crate::child::front_kill_tests::reap(pid);
}

/// A front outside its leaf (moved out) is left running, with the warning true: the look finds it
/// running. The rest of the leaf is killed all the same, since the leaf stays armed. Mutants: "the
/// drop disarms the leaf" (the member survives), "the drop never looks" (no warning).
#[skuld::test]
fn cgroup_drop_of_a_front_outside_its_leaf_leaves_it_running_and_kills_the_rest(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let (child, stdin, member) = spawn_front_with_member();
    let pid = child.id().pid();
    move_out_of_its_leaf(pid);
    // Released at the wait a drop makes for a front it places in its leaf, which this one is not in:
    // a drop that waited for it would end it and fail the warning below, not hang.
    let stdin = std::rc::Rc::new(std::cell::Cell::new(Some(stdin)));
    let _released = crate::child::spawn::fault::set_between_kill_and_wait({
        let stdin = std::rc::Rc::clone(&stdin);
        move || drop(stdin.take())
    });
    crate::containment::cgroup::fault::record_leaf_steps();
    let mark = crate::log_capture::mark();
    drop(child);
    let steps = crate::containment::cgroup::fault::take_leaf_steps();
    let said =
        crate::log_capture::records_since_on_current_thread(mark, &format!("Child::drop: elevation front pid {pid}"));
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(said[0].0, log::Level::Warn);
    assert!(said[0].1.contains("is left running and unreaped"), "{said:?}");
    assert!(steps.iter().any(|s| s == "kill"), "the leaf was killed: {steps:?}");
    wait_until_exited(&member);
    drop(stdin.take().expect("the drop must not wait for the front"));
    assert_reaped_unsignalled(pid);
}

/// A front whose signal is refused (direct exec: the root program) is still killed, through the
/// cgroup, and `kill`/`kill_tree` answer `Ok`.
#[skuld::test]
fn cgroup_kill_of_a_front_that_refuses_signals_is_ok(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_nobody_front();
    {
        let _refusing = WithoutKillCap::refusing(child.id().pid());
        child.kill().expect("the cgroup kill ends the front");
        child.kill_tree().expect("the cgroup kill ends the front");
    }
    // Closed first: a front nothing killed then exits 0, and the assertion fails.
    drop(stdin);
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
}

/// The drop of such a front kills it through the cgroup and reaps it, warning of nothing.
#[skuld::test]
fn cgroup_drop_of_a_front_that_refuses_signals_reaps_it(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let (child, _stdin) = spawn_nobody_front();
    let pidfd = pidfd_of(child.id().pid());
    let mark = crate::log_capture::mark();
    {
        let _refusing = WithoutKillCap::refusing(child.id().pid());
        drop(child);
    }
    assert!(reaped(&pidfd), "the drop reaps the front its cgroup kill ended");
    let warns = crate::log_capture::records_since_on_current_thread(mark, "could not be terminated");
    assert_eq!(warns, [], "nothing was refused");
}

/// A failed password write's teardown of such a front says it was terminated.
#[skuld::test]
fn cgroup_a_failed_password_write_terminates_a_front_that_refuses_signals(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_nobody_front();
    let pid = child.id().pid();
    let _refusing = WithoutKillCap::refusing(pid);
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    // Closed at the teardown's wait: a front nothing killed then exits 0, and the status below fails.
    let stdin = std::rc::Rc::new(std::cell::Cell::new(Some(stdin)));
    let _released = crate::child::spawn::fault::set_between_kill_and_wait({
        let stdin = std::rc::Rc::clone(&stdin);
        move || drop(stdin.take())
    });
    let err = crate::child::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("a failed write fails the spawn");
    let rendered = err.to_string();
    assert!(rendered.contains("the elevated child was terminated"), "{rendered}");
    let (_, status) = reaps
        .recorded()
        .into_iter()
        .find(|(reaped, _)| *reaped == pid)
        .expect("the teardown reaped the front");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the front ended by the cgroup kill"
    );
}

/// A failed password write whose cgroup kill fails refuses the front's kill as `kill` does,
/// naming the failure, and sends the front nothing. The front then ends on its stdin, unsignalled,
/// and the leaf the failed kill left behind is removed.
#[skuld::test]
fn cgroup_a_failed_password_write_whose_cgroup_kill_fails_refuses_as_kill_does(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pid = child.id().pid();
    let leaf = leaf_of(&child).path().to_path_buf();
    let err = {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        crate::child::spawn::finish_elevated(
            child,
            Err(crate::error::Error::Elevation {
                kind: crate::error::ElevationErrorKind::AuthFailed,
                detail: "forced password-write failure".into(),
            }),
        )
        .expect_err("a failed write fails the spawn")
    };
    assert_front_refused_by_its_cgroup_kill(&err, pid);
    drop(stdin);
    assert_reaped_unsignalled(pid);
    std::fs::remove_dir(&leaf).unwrap_or_else(|e| panic!("remove the leaf {}: {e}", leaf.display()));
}

/// `err`, a failed password write's, says its front `pid` was refused as `kill` refuses a front
/// whose cgroup kill failed.
#[track_caller]
pub(crate) fn assert_front_refused_by_its_cgroup_kill(err: &crate::error::Error, pid: u32) {
    let text = err.to_string();
    assert!(text.contains("the elevated child could not be terminated"), "{text}");
    assert!(text.contains(&format!("pid {pid} is what sudo left")), "{text}");
    assert!(text.contains("no kill was sent"), "{text}");
    assert!(text.contains("(its cgroup kill failed: "), "{text}");
}

/// A front that has left its leaf is out of the cgroup kill's reach: sent nothing, and refused.
#[skuld::test]
fn cgroup_a_front_that_left_its_leaf_is_unkillable_and_sent_nothing(#[fixture(cgroup)] _group: &Group) {
    let teardowns = record_root_teardowns();
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pid = child.id().pid();
    move_out_of_its_leaf(pid);
    assert_unkillable_front(child.kill(), pid);
    assert_unkillable_front(child.kill_tree(), pid);
    assert!(!child.tree_killed.is_set(), "no cgroup kill ran");
    drop(child);
    assert_eq!(teardowns.count(), 0, "the drop must not kill or reap the front");
    drop(stdin);
    assert_reaped_unsignalled(pid);
}

/// An exited front has nothing left to orphan, so its kill is `Ok` even though the signal to it, a
/// zombie that keeps its credentials, is refused.
#[skuld::test]
fn cgroup_kill_of_an_exited_front_that_refuses_signals_is_ok(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_nobody_front();
    let pid = child.id().pid();
    drop(stdin);
    crate::test_child::wait_until_zombie(pid);
    {
        let _refusing = WithoutKillCap::refusing(pid);
        child.kill().expect("an exited front is killed like any exited child");
        child
            .kill_tree()
            .expect("an exited front is killed like any exited child");
    }
    assert!(child.wait().expect("wait").success());
}

/// A front that a session manager moves out of its leaf between the gate and the `cgroup.kill`
/// write was not killed: the kill answers `Unkillable`, read after the write, and the front is sent
/// nothing.
#[skuld::test]
fn cgroup_a_front_moved_out_during_its_kill_is_unkillable(#[fixture(cgroup)] _group: &Group) {
    let kills: [Kill; 2] = [crate::Child::kill, crate::Child::kill_tree];
    for kill in kills {
        let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
        let pid = child.id().pid();
        let _moving = crate::containment::cgroup::fault::set_before_kill_write(move || move_out_of_its_leaf(pid));
        assert_refused_by(kill(&child), "left the cgroup before its kill");
        assert_ends_unsignalled(&child, stdin);
    }
}

/// The drop of such a front leaves it running and unreaped, and never waits for it. The front's
/// stdin is closed only by a wait's hook, so a drop that waits ends it and reaps it, which the test
/// sees, rather than hanging.
#[skuld::test]
fn cgroup_drop_of_a_front_moved_out_during_its_kill_leaves_it_unreaped(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pid = child.id().pid();
    let stdin = std::rc::Rc::new(std::cell::Cell::new(Some(stdin)));
    let _moving = crate::containment::cgroup::fault::set_before_kill_write(move || move_out_of_its_leaf(pid));
    let _released = crate::child::spawn::fault::set_between_kill_and_wait({
        let stdin = std::rc::Rc::clone(&stdin);
        move || drop(stdin.take())
    });
    let mark = crate::log_capture::mark();
    drop(child);
    let warns = crate::log_capture::records_since_on_current_thread(mark, "is left running and unreaped");
    assert_eq!(warns.len(), 1, "{warns:?}");
    drop(stdin.take().expect("the drop must not wait for the front"));
    assert_reaped_unsignalled(pid);
}

/// `kill_tree` asks the gate once: after the cgroup kill a killed front can read as neither exited
/// nor in its cgroup.
#[skuld::test]
fn cgroup_kill_tree_of_a_front_asks_the_gate_once(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let gates = crate::elevation::front::seams::count_kill_gates();
    child.kill_tree().expect("the cgroup kill reaches the front");
    assert_eq!(gates.count(), 1);
}

/// A failed password write's teardown asks the gate once, for the same reason. The handle opts out
/// of the drop, whose own teardown would ask again.
#[skuld::test]
fn cgroup_a_failed_password_write_asks_the_gate_once(#[fixture(cgroup)] _group: &Group) {
    let mut cmd = in_cgroup(cat());
    cmd.kill_on_drop(false);
    let (child, _stdin) = spawn_as(cmd, SUDO);
    let gates = crate::elevation::front::seams::count_kill_gates();
    let err = crate::child::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("a failed write fails the spawn");
    assert!(err.to_string().contains("the elevated child was terminated"), "{err}");
    assert_eq!(gates.count(), 1);
}

/// How a failed spawn's leaf meets its front (see [`failed_held_front_spawns`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafKill {
    /// The leaf's kill lands on the front.
    Lands,
    /// The leaf's `cgroup.kill` write fails.
    Fails,
    /// The front is moved out of its leaf before the leaf's kill, as pam_systemd moves sudo.
    MissesMovedFront,
    /// The front is moved into a cgroup nested under its leaf, which the leaf's kill reaches, and
    /// `/proc` hides it (`hidepid`).
    LandsNestedHidden,
    /// The leaf's kill lands on the front, whose place is read through `/proc` alone (no
    /// `PIDFD_GET_INFO`): once the leaf is removed, `/proc` names it with ` (deleted)`.
    LandsReadThroughProc,
    /// The front is moved into a live cgroup beside its leaf named as `/proc` prints the removed
    /// leaf, and its place is read through `/proc` alone.
    MissesIntoNamesake,
}

/// A failed front spawn: its error, the front's pid, and the front's stdin, which the test holds
/// so that only a kill ends the front. A teardown's wait on the front releases it first (see
/// `set_between_kill_and_wait`), so a wait on a front no kill reached ends it with status 0 instead
/// of hanging.
pub(crate) struct HeldFailure {
    pub(crate) err: crate::error::Error,
    pub(crate) pid: u32,
    pub(crate) stdin: std::rc::Rc<std::cell::RefCell<Option<PipeWriter>>>,
}

/// Spawns of a contained `cat` marked as a `sudo` front, through `spawn`, that fail after their
/// fork: once in the attach, once in the identity check, with the leaf's kill meeting the front
/// as `kill` says.
pub(crate) fn failed_held_front_spawns(
    kill: LeafKill,
    spawn: impl Fn(&mut Command) -> Result<(), crate::error::Error>,
) -> [HeldFailure; 2] {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::spawn::fault;
    let arms: [fn(bool); 2] = [fault::set_force_attach_failure, fault::set_force_identity_vanished];
    arms.map(|force_arm| {
        let (reader, writer) = std::io::pipe().expect("pipe");
        let stdin = Rc::new(RefCell::new(Some(writer)));
        let mut cmd = in_cgroup(cat());
        cmd.stdin(Stdio::from_file(std::fs::File::from(OwnedFd::from(reader))))
            .expect("stdin");
        cmd.set_elevation_front(crate::elevation::front::front(Some(&SUDO)));
        let _released = fault::set_between_kill_and_wait({
            let stdin = Rc::clone(&stdin);
            move || drop(stdin.borrow_mut().take())
        });
        // The spawn has returned from std, so the front has run its placement: it is in its leaf.
        // Both failures come after this point.
        // A namesake front leaves the leaf empty, and an empty leaf is removed without a kill: a
        // filler kept in it makes its kill land, so only the record answers for the front.
        let (filler, filler_stdin) = if kill == LeafKill::MissesIntoNamesake {
            let (filler, stdin) = spawn_as(cat(), SUDO);
            (Some(Rc::new(filler)), Some(stdin))
        } else {
            (None, None)
        };
        let _moved = match kill {
            LeafKill::MissesMovedFront => Some(fault::set_at(fault::SpawnPoint::BeforeIdentity, || {
                move_out_of_its_leaf(fault::spawn_pid())
            })),
            LeafKill::LandsNestedHidden => Some(fault::set_at(fault::SpawnPoint::BeforeIdentity, || {
                move_under_its_leaf(fault::spawn_pid());
            })),
            LeafKill::MissesIntoNamesake => {
                let filler = filler.clone();
                Some(fault::set_at(fault::SpawnPoint::BeforeIdentity, move || {
                    let pid = fault::spawn_pid();
                    let leaf = cgroup_dir_of(pid);
                    let filler = filler.as_ref().expect("a filler for the namesake case").id().pid();
                    std::fs::write(format!("{leaf}/cgroup.procs"), filler.to_string())
                        .unwrap_or_else(|e| panic!("move the filler into {leaf}: {e}"));
                    move_into_a_namesake_of_its_leaf(pid);
                }))
            }
            LeafKill::Lands | LeafKill::Fails | LeafKill::LandsReadThroughProc => None,
        };
        let _missing = matches!(kill, LeafKill::LandsReadThroughProc | LeafKill::MissesIntoNamesake)
            .then(crate::containment::cgroup::fault::miss_pidfd_info);
        let _hidden = (kill == LeafKill::LandsNestedHidden).then(crate::containment::cgroup::fault::hide_proc);
        let _failing = (kill == LeafKill::Fails).then(crate::containment::cgroup::fault::fail_kill_writes);
        force_arm(true);
        let result = spawn(&mut cmd);
        force_arm(false);
        // The filler kept the leaf busy, so the leaf's removal killed through it: the kill landed.
        // Its stdin is closed first, so a filler nothing killed exits 0 and the assertion fails.
        if let Some((filler, stdin)) = filler.as_ref().zip(filler_stdin) {
            drop(stdin);
            assert_eq!(
                filler.wait().expect("wait").signal(),
                Some(libc::SIGKILL),
                "the leaf's kill"
            );
        }
        let err = result.expect_err("the forced arm fails the spawn");
        let crate::identity::Resolved::Found(id) = fault::take_captured().expect("the seam captured the child") else {
            panic!("the seam must capture a resolved identity");
        };
        HeldFailure {
            err,
            pid: id.pid(),
            stdin,
        }
    })
}

/// Each failure notes its front was killed by its leaf and reaped, and the teardown's own wait
/// reaped it dead of `SIGKILL`, as `reaps` recorded.
#[track_caller]
pub(crate) fn assert_killed_by_the_leaf(
    failures: &[HeldFailure; 2],
    reaps: &crate::child::spawn::fault::TeardownReaps,
) {
    let recorded = reaps.recorded();
    for HeldFailure { err, pid, .. } in failures {
        let text = err.to_string();
        assert!(text.contains(&format!("pid {pid} is what sudo left")), "{text}");
        assert!(text.contains("its cgroup's kill ended it, and it was reaped"), "{text}");
        let status = recorded
            .iter()
            .find_map(|(reaped, status)| (reaped == pid).then_some(*status))
            .unwrap_or_else(|| panic!("the teardown waited for front {pid}: {recorded:?}"));
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "front {pid} ended by its leaf's kill"
        );
    }
}

/// Each failure notes its front was left unreaped, and the teardown never waited on it: its stdin
/// is still held. Then ends each front by closing its stdin, reaps it, unsignalled, and removes
/// the leaf a failed kill left behind with it.
#[track_caller]
pub(crate) fn assert_left_running(kill: LeafKill, failures: [HeldFailure; 2]) {
    for HeldFailure { err, pid, stdin } in failures {
        let text = err.to_string();
        assert!(text.contains(&format!("pid {pid} is what sudo left")), "{text}");
        assert!(
            text.contains("the elevated program may be running; it is left unreaped"),
            "{text}"
        );
        assert!(
            stdin.borrow().is_some(),
            "the teardown waited on front {pid}, which no kill reached"
        );
        let own = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("read the front's cgroup");
        let path = own
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .expect("a cgroup v2 `0::` line")
            .to_owned();
        drop(stdin.borrow_mut().take());
        let status = crate::child::front_kill_tests::reap(pid).expect("the front was left unreaped");
        assert!(status.success(), "front {pid} was signalled: {status:?}");
        // The cgroup the front was left in, if the test made it or a failed kill left it behind.
        if matches!(kill, LeafKill::Fails | LeafKill::MissesIntoNamesake) {
            let left = format!("/sys/fs/cgroup{path}");
            std::fs::remove_dir(&left).unwrap_or_else(|e| panic!("remove {left}: {e}"));
        }
    }
}

/// A failed spawn's teardown drops a contained front's leaf first, whose kill ends it, then waits
/// for it through its pidfd, reaps it and says so, on the error it would have returned anyway. The
/// front's stdin stays open, so only the kill ends it. The teardown is made to see the front still
/// running, as it can: a task leaves its cgroup, which ends the leaf's drain, before its parent can
/// collect it.
#[skuld::test]
fn cgroup_a_failed_spawn_kills_a_contained_front_and_reaps_it(#[fixture(cgroup)] _group: &Group) {
    let _running = crate::child::spawn::fault::see_fronts_running();
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let failures = failed_held_front_spawns(LeafKill::Lands, |cmd| cmd.spawn().map(drop));
    assert_killed_by_the_leaf(&failures, &reaps);
}

/// A failed spawn's teardown reads a front its leaf's kill has made a zombie, with its own wait,
/// not the seam that has it see the front running: the real read finds the zombie and reaps it,
/// waiting for nothing. The teardown first waits (without reaping) until the front is a zombie, so
/// the read is not a race with the kill. Mutant: "a zombie front is left unreaped".
#[skuld::test]
fn cgroup_a_failed_spawn_reaps_a_front_its_leaf_made_a_zombie_without_waiting(#[fixture(cgroup)] _group: &Group) {
    let _zombie = crate::child::spawn::fault::exit_fronts_before_teardown();
    crate::containment::cgroup::fault::record_leaf_steps();
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let failures = failed_held_front_spawns(LeafKill::Lands, |cmd| cmd.spawn().map(drop));
    for HeldFailure { err, pid, .. } in &failures {
        let text = err.to_string();
        assert!(text.contains(&format!("pid {pid} is what sudo left")), "{text}");
        assert!(text.contains("and it was reaped"), "{text}");
        assert_eq!(
            crate::child::front_kill_tests::reap(*pid),
            None,
            "the teardown's read reaped front {pid}"
        );
    }
    assert_eq!(reaps.recorded(), [], "the zombie was reaped by the read, not by a wait");
}

/// A failed spawn's front, its place read through `/proc` alone, is killed by its leaf and reaped:
/// once the leaf is removed `/proc` names it with ` (deleted)`, which the place recorded before the
/// removal answers.
#[skuld::test]
fn cgroup_a_failed_spawn_kills_a_front_read_through_proc_and_reaps_it(#[fixture(cgroup)] _group: &Group) {
    let _running = crate::child::spawn::fault::see_fronts_running();
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let failures = failed_held_front_spawns(LeafKill::LandsReadThroughProc, |cmd| cmd.spawn().map(drop));
    assert_killed_by_the_leaf(&failures, &reaps);
}

/// A failed spawn whose front was moved into a live cgroup named as `/proc` prints the removed leaf
/// leaves it running. A filler kept in the leaf makes the leaf's kill land, so nothing but the
/// record tells the front from one the kill reached: before the leaf's removal, with the leaf live,
/// the front read the leaf's path with ` (deleted)` after it, so it was recorded outside, and the
/// record answers once the leaf is gone.
#[skuld::test]
fn cgroup_a_failed_spawn_leaves_a_front_in_a_namesake_of_its_leaf_running(#[fixture(cgroup)] _group: &Group) {
    let kill = LeafKill::MissesIntoNamesake;
    assert_left_running(kill, failed_held_front_spawns(kill, |cmd| cmd.spawn().map(drop)));
}

/// A failed spawn whose leaf's kill fails leaves its front running: in its leaf, but reached by
/// nothing, so it is not waited for.
#[skuld::test]
fn cgroup_a_failed_spawn_whose_leaf_kill_fails_leaves_the_front_running(#[fixture(cgroup)] _group: &Group) {
    let kill = LeafKill::Fails;
    assert_left_running(kill, failed_held_front_spawns(kill, |cmd| cmd.spawn().map(drop)));
}

/// A failed spawn whose front was moved out of its leaf leaves it running: the leaf's kill did not
/// reach it, so it is not waited for.
#[skuld::test]
fn cgroup_a_failed_spawn_leaves_a_front_moved_out_of_its_leaf_running(#[fixture(cgroup)] _group: &Group) {
    let kill = LeafKill::MissesMovedFront;
    assert_left_running(kill, failed_held_front_spawns(kill, |cmd| cmd.spawn().map(drop)));
}

/// A contained front that outlives the grace is killed through its cgroup alone. Its `cat` ignores
/// `SIGTERM`, so the escalation runs.
#[skuld::test]
fn cgroup_graceful_shutdown_of_a_front_escalates_through_the_cgroup(#[fixture(cgroup)] _group: &Group) {
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "trap '' TERM; echo ready; exec cat"]);
    cmd.stdout(Stdio::pipe_out()).expect("stdout pipe");
    let (mut child, _stdin) = spawn_as(in_cgroup(cmd), SUDO);
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut ready)
        .expect("read `ready`");
    let status = child
        .graceful_shutdown(std::time::Duration::ZERO)
        .expect("the cgroup kill ends the front");
    assert!(child.tree_killed.is_set(), "the escalation must go through the cgroup");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}

/// A contained front's escalation whose cgroup kill fails is refused as `Unkillable`, naming the
/// failure, and sends the front nothing. Its `cat` ignores `SIGTERM`, so the escalation runs.
#[skuld::test]
fn cgroup_a_failed_escalation_of_a_front_is_unkillable(#[fixture(cgroup)] _group: &Group) {
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "trap '' TERM; echo ready; exec cat"]);
    cmd.stdout(Stdio::pipe_out()).expect("stdout pipe");
    let (mut child, stdin) = spawn_as(in_cgroup(cmd), SUDO);
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut ready)
        .expect("read `ready`");
    // Released at the wait that follows the escalation, which a swallowed failure would reach: the
    // front then ends by itself, and the refusal below fails, instead of the wait hanging.
    let release = crate::graceful_hooks::release_at(crate::graceful_hooks::HookPoint::BeforeReap, stdin);
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        assert_refused_by(
            child.graceful_shutdown(std::time::Duration::ZERO),
            "its cgroup kill failed",
        );
    }
    // Closes the front's stdin: it ends unsignalled.
    drop(release);
    let status = child.wait().expect("wait");
    assert!(status.success(), "the front was signalled: {status:?}");
}

/// A front that exits, and that another thread's `wait` reaps, between the kill gate's read of
/// whether it runs and its read of its cgroup, has exited: `kill` is `Ok`, and sends nothing. The
/// hook between the reads closes the front's stdin, then lets the waiter reap it.
#[skuld::test]
fn cgroup_a_front_reaped_by_a_concurrent_wait_inside_the_gate_has_exited(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    std::thread::scope(|scope| {
        let child = &child;
        scope.spawn(move || {
            if go_rx.recv().is_ok() {
                reaped_tx
                    .send(child.wait().map_err(|e| e.to_string()))
                    .expect("report the reap");
            }
        });
        let _between = crate::elevation::front::seams::set_between_gate_reads({
            let fired = std::rc::Rc::clone(&fired);
            move || {
                fired.set(true);
                drop(stdin);
                go_tx.send(()).expect("start the waiter");
                let status = reaped_rx.recv().expect("the waiter reaps").expect("wait");
                assert!(status.success(), "the front ended on its stdin: {status:?}");
            }
        });
        crate::wait::exit_only::seams::signals_sent();
        child.kill().expect("a front that exited is not refused");
        assert_eq!(
            crate::wait::exit_only::seams::signals_sent(),
            0,
            "nothing is signalled to a reaped front"
        );
    });
    assert!(fired.get(), "the hook between the gate's reads ran");
}

/// A front its cgroup kill ended, and that another thread's `wait` reaped before its cgroup is
/// read, was reached: `kill` is `Ok`. The hook after the kill's write lets the waiter reap it.
#[skuld::test]
fn cgroup_a_front_reaped_by_a_concurrent_wait_after_its_kill_was_reached(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    std::thread::scope(|scope| {
        let child = &child;
        scope.spawn(move || {
            if go_rx.recv().is_ok() {
                reaped_tx
                    .send(child.wait().map_err(|e| e.to_string()))
                    .expect("report the reap");
            }
        });
        // The check's first read finds the front running, whether or not the kill has ended it by
        // then, so the hook below always runs between the check's reads.
        let _running = crate::elevation::front::seams::read_front_running_at_the_first_reach_read();
        let _between = crate::elevation::front::seams::set_between_reach_reads({
            let fired = std::rc::Rc::clone(&fired);
            move || {
                fired.set(true);
                // The kill was written, so the front dies of it; one the kill missed exits 0 here.
                drop(stdin);
                go_tx.send(()).expect("start the waiter");
                let status = reaped_rx.recv().expect("the waiter reaps").expect("wait");
                assert_eq!(status.signal(), Some(libc::SIGKILL), "the cgroup kill ended the front");
            }
        });
        child
            .kill()
            .expect("a front its kill ended is reached, whoever reaped it");
    });
    assert!(fired.get(), "the hook between the check's reads ran");
}

/// The leaf `child` is contained in.
fn leaf_of(child: &crate::Child) -> &crate::containment::cgroup::CgroupLeaf {
    match &child.attached {
        crate::containment::Attached::Cgroup(leaf) => leaf,
        other => panic!("expected a cgroup leaf, got {other:?}"),
    }
}

/// A front killed through its leaf stays in it, by its pidfd's cgroup id, until it is freed: as a
/// zombie too, and with `/proc` unreadable (`hidepid`).
#[skuld::test]
fn cgroup_a_killed_front_is_placed_in_its_leaf_by_its_pidfd(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pid = child.id().pid();
    child.attached.hard_kill().expect("cgroup.kill");
    crate::test_child::wait_until_zombie(pid);
    let hidden = crate::containment::cgroup::fault::hide_proc();
    let names = leaf_of(&child).names(pid, child.proc.pidfd());
    drop(hidden);
    assert!(
        names.expect("the pidfd read needs no /proc"),
        "a killed front stays in its leaf"
    );
}

/// Without `PIDFD_GET_INFO` (before 6.13) the place is read through `/proc`, with the same answers.
#[skuld::test]
fn cgroup_without_pidfd_info_a_front_is_placed_through_proc(#[fixture(cgroup)] _group: &Group) {
    let _missing = crate::containment::cgroup::fault::miss_pidfd_info();
    let (killed, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pid = killed.id().pid();
    killed.attached.hard_kill().expect("cgroup.kill");
    crate::test_child::wait_until_zombie(pid);
    assert!(leaf_of(&killed)
        .names(pid, killed.proc.pidfd())
        .expect("/proc is readable here"));
    let (moved, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    move_out_of_its_leaf(moved.id().pid());
    assert!(!leaf_of(&moved)
        .names(moved.id().pid(), moved.proc.pidfd())
        .expect("/proc is readable here"));
}

/// A front moved out of its leaf is outside it, by its pidfd's cgroup id.
#[skuld::test]
fn cgroup_a_moved_front_is_placed_outside_its_leaf_by_its_pidfd(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pid = child.id().pid();
    move_out_of_its_leaf(pid);
    let hidden = crate::containment::cgroup::fault::hide_proc();
    let names = leaf_of(&child).names(pid, child.proc.pidfd());
    drop(hidden);
    assert!(
        !names.expect("the pidfd read needs no /proc"),
        "a moved front is outside its leaf"
    );
}

/// A front moved into a cgroup nested under its leaf is in the leaf's subtree: by the walk of the
/// leaf's descendants with `PIDFD_GET_INFO`, whatever `/proc` hides; without it by its path, which a
/// hidden `/proc` does not give (such a host refuses the spawn, see `front_placement`).
#[skuld::test]
fn cgroup_a_front_under_its_leaf_is_placed_by_the_walk(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pid = child.id().pid();
    move_under_its_leaf(pid);
    let names = || leaf_of(&child).names(pid, child.proc.pidfd());
    assert!(names().expect("/proc is readable here"));
    {
        let _hidden = crate::containment::cgroup::fault::hide_proc();
        assert!(names().expect("the walk needs no /proc"), "found by the walk");
        let _missing = crate::containment::cgroup::fault::miss_pidfd_info();
        names().expect_err("a hidden path places nothing");
    }
    // The child's drop kills the leaf, then removes `a/b`, `a` and the leaf.
}

/// A front in a cgroup nested under its leaf, on a host whose `/proc` hides it: its kill goes
/// through the leaf, which reaches it, and is `Ok`, and the front dies of it.
#[skuld::test]
fn cgroup_a_front_nested_under_its_leaf_is_killed_under_hidepid(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    move_under_its_leaf(child.id().pid());
    {
        let _hidden = crate::containment::cgroup::fault::hide_proc();
        child.kill().expect("the leaf's kill reaches a front nested under it");
    }
    // Closed first: a front nothing killed then exits 0, and the assertion fails.
    drop(stdin);
    let status = child.wait().expect("wait");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the front dies of its leaf's kill"
    );
}

/// A failed spawn whose front is nested under its leaf, on a host whose `/proc` hides it: the
/// leaf's kill reaches it, and its sweep removes the nested cgroups before the teardown asks, so the
/// sweep's record places it; the teardown waits for it and reaps it.
#[skuld::test]
fn cgroup_a_failed_spawn_kills_a_front_nested_under_its_leaf_under_hidepid(#[fixture(cgroup)] _group: &Group) {
    let _running = crate::child::spawn::fault::see_fronts_running();
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let failures = failed_held_front_spawns(LeafKill::LandsNestedHidden, |cmd| cmd.spawn().map(drop));
    assert_killed_by_the_leaf(&failures, &reaps);
}

/// A front in a cgroup under its leaf behind a mount, which the walk cannot list: its place is
/// read through `/proc` instead, and its kill, which reaches it, is `Ok`. The spawning thread has
/// its own mount namespace, the mount's, in which the spawn holds the leaf; the mount is gone with
/// the thread.
#[skuld::test]
fn cgroup_a_front_behind_a_mount_under_its_leaf_is_placed_through_proc(#[fixture(cgroup)] _group: &Group) {
    use crate::containment::cgroup::dir_walk_tests::{enter_private_mount_ns, TmpfsOver};
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                enter_private_mount_ns();
                let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
                let nested = std::path::PathBuf::from(move_under_its_leaf(child.id().pid()));
                let mounted_on = nested.parent().expect("`a`, under the leaf");
                let killed = {
                    let _mounted = TmpfsOver::new(mounted_on);
                    child.kill()
                };
                killed.expect("a front /proc places under its leaf was reached");
                // Closed first: a front nothing killed then exits 0, and the assertion fails.
                drop(stdin);
                let status = child.wait().expect("wait");
                assert_eq!(
                    status.signal(),
                    Some(libc::SIGKILL),
                    "the front dies of its leaf's kill"
                );
            })
            .join()
            .expect("the spawning thread");
    });
}

/// Where a front is when its leaf records its place, before the leaf's removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordCase {
    /// In a live cgroup beside the leaf named as `/proc` prints the removed leaf.
    Namesake,
    /// In the leaf itself, which the leaf's drop kills.
    Leaf,
    /// In the namesake, with the read of whether the leaf is live failing (`EMFILE`).
    NamesakeLivenessUnread,
    /// In the leaf, killed through it, and the leaf removed by someone else before its drop, so the
    /// front's zombie reads the leaf's path with ` (deleted)` after it.
    LeafRemovedFirst,
}

/// A leaf records its watched front's place just before its removal: outside for a front in a
/// live namesake of the removed leaf, read while the leaf is live; inside for a front in the leaf.
/// Nothing is recorded where the path is undecidable: the leaf's liveness cannot be read, or the
/// leaf is already gone.
#[skuld::test]
fn cgroup_a_leaf_records_its_fronts_place_before_its_removal(#[fixture(cgroup)] _group: &Group) {
    use crate::containment::cgroup::dir_walk_tests::Scratch;
    crate::log_capture::install();
    let scratch = Scratch::new("record");
    let cgroup_of = |path: &std::path::Path| {
        format!(
            "/{}",
            path.strip_prefix("/sys/fs/cgroup")
                .expect("under the cgroup root")
                .display()
        )
    };
    for (n, case) in [
        RecordCase::Namesake,
        RecordCase::Leaf,
        RecordCase::NamesakeLivenessUnread,
        RecordCase::LeafRemovedFirst,
    ]
    .into_iter()
    .enumerate()
    {
        let leaf_path = scratch.make(&format!("leaf-{n}"));
        let mut leaf = crate::containment::cgroup::test_support::entered_leaf_at(leaf_path.clone());
        leaf.set_cgroup_path_for_test(cgroup_of(&leaf_path));
        let placed = leaf.placed_for_test();
        let (front, stdin) = spawn_as(cat(), SUDO);
        let pid = front.id().pid();
        leaf.watch_front(pid);
        let namesake = leaf_path.with_file_name(format!("leaf-{n} (deleted)"));
        let in_leaf = matches!(case, RecordCase::Leaf | RecordCase::LeafRemovedFirst);
        if in_leaf {
            std::fs::write(leaf_path.join("cgroup.procs"), pid.to_string()).expect("move the front into the leaf");
        } else {
            std::fs::create_dir(&namesake).expect("make the namesake");
            std::fs::write(namesake.join("cgroup.procs"), pid.to_string()).expect("move the front into the namesake");
        }
        if case == RecordCase::LeafRemovedFirst {
            std::fs::write(leaf_path.join("cgroup.kill"), "1").expect("kill through the leaf");
            // `rmdir` needs `populated 0`, which a waitable zombie does not imply: wait on the
            // leaf's own drain watch (inotify on `cgroup.events`, no timeout) for it.
            assert_eq!(
                leaf.wait_drained(None).expect("wait for the leaf to drain"),
                crate::containment::TreeDrain::AllMembersExited
            );
            std::fs::remove_dir(&leaf_path).expect("remove the drained leaf, as a cgroup manager may");
        }
        let unread = (case == RecordCase::NamesakeLivenessUnread)
            .then(|| crate::containment::cgroup::fault::fail_liveness_read(libc::EMFILE));
        let mark = crate::log_capture::mark();
        // The leaf's drop kills what is in it, and removes it.
        drop(leaf);
        drop(unread);
        // An undecided path is the leaf's own path with ` (deleted)` after it, left unrecorded:
        // that, and no other failure of the read, is what leaves no record.
        let unrecorded =
            crate::log_capture::records_since_on_current_thread(mark, "before its leaf's removal cannot be read");
        if matches!(case, RecordCase::NamesakeLivenessUnread | RecordCase::LeafRemovedFirst) {
            assert!(
                unrecorded
                    .iter()
                    .any(|(_, text)| text.contains("is either the removed leaf or a live cgroup of that name")),
                "{case:?}: {unrecorded:?}"
            );
        }
        let expected = match case {
            RecordCase::Namesake => Some(false),
            RecordCase::Leaf => Some(true),
            RecordCase::NamesakeLivenessUnread | RecordCase::LeafRemovedFirst => None,
        };
        assert_eq!(placed.of(pid), expected, "{case:?}");
        drop(stdin);
        let status = front.wait().expect("wait");
        assert_eq!(
            status.signal(),
            in_leaf.then_some(libc::SIGKILL),
            "{case:?}: {status:?}"
        );
        if !in_leaf {
            std::fs::remove_dir(&namesake).expect("remove the namesake");
        }
    }
}

/// Spawns `cmd`, marked as an elevation-derived `sudo` front, through `spawn`, and returns its
/// result with the pid it forked, if it reached its attach.
pub(crate) fn spawn_front_noting_fork<T>(
    mut cmd: Command,
    spawn: impl FnOnce(&mut Command) -> Result<T, crate::error::Error>,
) -> (Result<T, crate::error::Error>, Option<u32>) {
    use crate::child::spawn::fault::{set_at, spawn_pid, SpawnPoint};
    cmd.set_elevation_front(crate::elevation::front::front(Some(&SUDO)));
    let pid = std::rc::Rc::new(std::cell::Cell::new(None));
    let _seen = set_at(SpawnPoint::BeforeAttach, {
        let pid = std::rc::Rc::clone(&pid);
        move || pid.set(Some(spawn_pid()))
    });
    let result = spawn(&mut cmd);
    (result, pid.get())
}

/// `result` is the refusal of a host that cannot place a front, naming `hidepid`, and nothing was
/// forked for it: no front exists to kill, wait for or leave.
#[track_caller]
pub(crate) fn assert_refused_unforked<T: std::fmt::Debug>(result: Result<T, crate::error::Error>, forked: Option<u32>) {
    assert_refused_unforked_naming(result, forked, "hidepid");
}

/// [`assert_refused_unforked`], for a refusal whose detail names `cause`.
#[track_caller]
pub(crate) fn assert_refused_unforked_naming<T: std::fmt::Debug>(
    result: Result<T, crate::error::Error>,
    forked: Option<u32>,
    cause: &str,
) {
    match result {
        Err(crate::error::Error::Unsupported { detail, .. }) => {
            assert!(detail.contains(cause), "{detail}");
            assert!(detail.contains("before anything is spawned"), "{detail}");
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
    assert_eq!(forked, None, "a refused spawn forks nothing");
}

/// Before 6.13 a host whose `/proc` hides a process this one may not trace cannot place a front
/// after a cgroup kill, so an elevated, cgroup-contained spawn is refused there before anything is
/// forked: whatever a kill on drop, a failing `cgroup.kill` or a front moved out would do to a
/// front, there is none.
#[skuld::test]
fn cgroup_an_unplaceable_front_is_refused_before_its_fork(#[fixture(cgroup)] _group: &Group) {
    let _missing = crate::containment::cgroup::fault::miss_pidfd_info();
    let _hidden = crate::containment::cgroup::fault::hide_proc();
    let _failing = crate::containment::cgroup::fault::fail_kill_writes();
    let mut cmd = in_cgroup(cat());
    cmd.kill_on_drop(true);
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let (result, forked) = spawn_front_noting_fork(cmd, |cmd| cmd.spawn().map(drop));
    assert_refused_unforked(result, forked);
}

/// A host whose leaves give no cgroup id (`name_to_handle_at` answers `ENOSYS` on a kernel without
/// `CONFIG_FHANDLE`) cannot place a front after a cgroup kill: an elevated, cgroup-contained spawn
/// is refused before anything is forked.
#[skuld::test]
fn cgroup_a_front_whose_leaf_gives_no_id_is_refused_before_its_fork(#[fixture(cgroup)] _group: &Group) {
    let _no_id = crate::containment::cgroup::fault::fail_cgroup_id(libc::ENOSYS);
    let mut cmd = in_cgroup(cat());
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let (result, forked) = spawn_front_noting_fork(cmd, |cmd| cmd.spawn().map(drop));
    assert_refused_unforked_naming(result, forked, "name_to_handle_at");
}

/// The refusal is decided before the fork with fds 0 and 1 closed too, where std's spawn returns
/// before the child's `exec`. Runs in a process of its own: closing 0 and 1 is process-wide.
#[skuld::test]
fn cgroup_an_unplaceable_front_is_refused_before_its_fork_with_fds_0_and_1_closed(#[fixture(cgroup)] _group: &Group) {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;
    use crate::test_stdio::RestoreStdio;

    let Some(done) = own_process(
        test_path!(cgroup_an_unplaceable_front_is_refused_before_its_fork_with_fds_0_and_1_closed),
        spawn,
    ) else {
        return;
    };
    let _missing = crate::containment::cgroup::fault::miss_pidfd_info();
    let _hidden = crate::containment::cgroup::fault::hide_proc();
    let mut cmd = in_cgroup(cat());
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let restore = RestoreStdio::close(&done, &[0, 1]);
    let (result, forked) = spawn_front_noting_fork(cmd, |cmd| cmd.spawn().map(drop));
    drop(restore);
    assert_refused_unforked(result, forked);
}

/// A host whose `/proc` shows a process this one may not trace can place a front without
/// `PIDFD_GET_INFO`: the spawn goes on. The cgroup group declares the precondition: the lane runs
/// as root, whose `CAP_SYS_PTRACE` reads a non-dumpable child's cgroup through any `/proc`, even a
/// `hidepid` one.
#[skuld::test]
fn cgroup_a_front_placeable_through_proc_is_not_refused(#[fixture(cgroup)] _group: &Group) {
    let _missing = crate::containment::cgroup::fault::miss_pidfd_info();
    let mut cmd = in_cgroup(cat());
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let (result, forked) = spawn_front_noting_fork(cmd, |cmd| cmd.spawn());
    result.expect("a front /proc shows is placeable");
    assert!(forked.is_some());
}

/// A `cat` front spawned for a cgroup leaf that does not take it (its placement write is made to
/// fail, so the attach falls back to its process group), with its stdin a pipe the caller owns.
pub(crate) fn front_its_leaf_did_not_take() -> (Command, PipeWriter) {
    let (reader, writer) = std::io::pipe().expect("pipe");
    let mut cmd = in_cgroup(cat());
    cmd.stdin(Stdio::from_file(std::fs::File::from(OwnedFd::from(reader))))
        .expect("stdin");
    cmd.set_elevation_front(crate::elevation::front::front(Some(&SUDO)));
    crate::containment::cgroup::fault::set_force_placement_write_result(0);
    (cmd, writer)
}

/// Spawns `cmd` through `spawn` with its identity check failing (`Gone`), and returns the error with
/// the child's pid.
pub(crate) fn fail_the_identity_check(
    cmd: &mut Command,
    spawn: impl FnOnce(&mut Command) -> Result<(), crate::error::Error>,
) -> (crate::error::Error, u32) {
    use crate::child::spawn::fault;
    fault::set_force_identity_vanished(true);
    let result = spawn(cmd);
    fault::set_force_identity_vanished(false);
    let err = result.expect_err("the forced identity failure fails the spawn");
    let crate::identity::Resolved::Found(id) = fault::take_captured().expect("the seam captured the child") else {
        panic!("the seam must capture a resolved identity");
    };
    (err, id.pid())
}

/// `err` notes that the front `pid` is left unreaped, and closing `stdin` then ends it unsignalled.
#[track_caller]
pub(crate) fn assert_left_unsignalled(err: &crate::error::Error, pid: u32, stdin: PipeWriter) {
    let text = err.to_string();
    assert!(text.contains(&format!("pid {pid} is what sudo left")), "{text}");
    assert!(
        text.contains("the elevated program may be running; it is left unreaped"),
        "{text}"
    );
    drop(stdin);
    assert_reaped_unsignalled(pid);
}

/// A front whose leaf did not take it is uncontained: a failed identity check sends it nothing, and
/// says so.
#[skuld::test]
fn cgroup_a_front_its_leaf_did_not_take_is_left_by_a_failed_identity_check(#[fixture(cgroup)] _group: &Group) {
    let (mut cmd, stdin) = front_its_leaf_did_not_take();
    let (err, pid) = fail_the_identity_check(&mut cmd, |cmd| cmd.spawn().map(drop));
    assert_left_unsignalled(&err, pid, stdin);
}

/// A front spawn that cannot capture its leaf's subtree (the cgroup id read fails) says so at
/// `debug`, with the cause: a failed spawn's teardown could not place the front. Mutant: "the
/// error is dropped".
#[skuld::test]
fn cgroup_a_front_spawn_that_cannot_read_its_leaf_subtree_says_why(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, stdin) = {
        let _failing = crate::containment::cgroup::fault::fail_subtree(libc::EIO);
        spawn_as(in_cgroup(cat()), SUDO)
    };
    let logs = crate::log_capture::records_since_on_current_thread(mark, "leaf subtree cannot be read");
    assert_eq!(logs.len(), 1, "{logs:?}");
    assert_eq!(logs[0].0, log::Level::Debug);
    assert!(logs[0].1.contains("Input/output error"), "{logs:?}");
    drop(stdin);
    drop(child);
}

/// A failed spawn's settled verdict for a child its leaf did not take says why at `debug`, with
/// the leaf's diagnosis. Mutant: "the diagnosis is dropped".
#[skuld::test]
fn cgroup_a_failed_spawn_says_why_its_leaf_did_not_take_the_child(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let (mut cmd, stdin) = front_its_leaf_did_not_take();
    let mark = crate::log_capture::mark();
    let (err, pid) = fail_the_identity_check(&mut cmd, |cmd| cmd.spawn().map(drop));
    let logs = crate::log_capture::records_since_on_current_thread(mark, "not placed in its leaf");
    assert_eq!(logs.len(), 1, "{logs:?}");
    assert_eq!(logs[0].0, log::Level::Debug);
    assert!(
        logs[0].1.contains(&format!("child {pid} is not in the leaf cgroup")),
        "{logs:?}"
    );
    assert_left_unsignalled(&err, pid, stdin);
}
