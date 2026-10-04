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

/// The kill goes through `cgroup.kill`, and sends the front nothing after it. Mutants: a front in a
/// cgroup is refused; its kill skips the cgroup; it signals the front after the cgroup kill.
#[skuld::test]
fn cgroup_kill_of_a_front_goes_through_the_cgroup_alone(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    assert_eq!(child.containment(), Containment::CgroupV2);
    crate::wait::exit_only::seams::signals_sent();
    child.kill().expect("the cgroup kill reaches the program");
    assert_eq!(
        crate::wait::exit_only::seams::signals_sent(),
        0,
        "nothing is signalled after it"
    );
    assert!(child.tree_killed.is_set(), "the kill must go through the cgroup");
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
}

/// `kill_tree` likewise. Mutant: its backstop signals the front after the cgroup kill.
#[skuld::test]
fn cgroup_kill_tree_of_a_front_goes_through_the_cgroup_alone(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    crate::wait::exit_only::seams::signals_sent();
    child.kill_tree().expect("the cgroup kill reaches the program");
    assert_eq!(
        crate::wait::exit_only::seams::signals_sent(),
        0,
        "nothing is signalled after it"
    );
    assert!(child.tree_killed.is_set());
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
}

/// The drop kills the front through the cgroup and reaps it, sending it nothing. Mutants: the drop
/// leaves a front in a cgroup running; it tears the root down (a kill of its own); it leaves it
/// unreaped.
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
/// Mutant: the front is signalled after a failed cgroup kill.
#[skuld::test]
fn cgroup_a_failed_kill_of_a_front_leaves_the_front_alone(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        assert!(child.kill().is_err(), "the forced cgroup.kill failure surfaces");
        assert!(child.kill_tree().is_err(), "the forced cgroup.kill failure surfaces");
    }
    assert_ends_unsignalled(&child, stdin);
}

/// The drop, too, leaves a front alone when its cgroup kill fails. Mutant: the drop tears the front
/// down after a failed cgroup kill.
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
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        drop(child);
    }
    assert_eq!(teardowns.count(), 0, "the drop must not kill or reap the front");
    drop(stdin);
    assert_reaped_unsignalled(pid);
    // The failed kill left the leaf behind; it is empty now.
    std::fs::remove_dir(&leaf).unwrap_or_else(|e| panic!("remove the leaf {}: {e}", leaf.display()));
}

/// A front whose signal is refused (direct exec: the root program) is still killed, through the
/// cgroup, and `kill`/`kill_tree` answer `Ok`. Mutant: the front is signalled after the cgroup kill,
/// which the refusal turns into a false `Unkillable`.
#[skuld::test]
fn cgroup_kill_of_a_front_that_refuses_signals_is_ok(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_nobody_front();
    {
        let _refusing = WithoutKillCap::refusing(child.id().pid());
        child.kill().expect("the cgroup kill ends the front");
        child.kill_tree().expect("the cgroup kill ends the front");
    }
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
}

/// The drop of such a front kills it through the cgroup and reaps it, warning of nothing. Mutant:
/// the drop's own kill is refused and it leaves the dead front unreaped, with a warning.
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

/// A failed password write's teardown of such a front says it was terminated. Mutant: the front is
/// signalled after the cgroup kill, and the note says it could not be.
#[skuld::test]
fn cgroup_a_failed_password_write_terminates_a_front_that_refuses_signals(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_nobody_front();
    let _refusing = WithoutKillCap::refusing(child.id().pid());
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
}

/// A front that has left its leaf is out of the cgroup kill's reach: sent nothing, and refused.
/// Mutants: membership is not checked, so the cgroup kill runs and the front is reported killed
/// (or signalled); the drop tears it down.
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
/// zombie that keeps its credentials, is refused. Mutant: an exited front is signalled like any
/// child, and the refusal reads as `Unkillable`.
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
/// nothing. Mutant: whether the kill reached the front is not read after the write (`Ok`).
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
/// sees, rather than hanging. Mutant: the drop waits for a front its kill did not reach.
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
/// nor in its cgroup. Mutant: the backstop asks again.
#[skuld::test]
fn cgroup_kill_tree_of_a_front_asks_the_gate_once(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let gates = crate::elevation::front::seams::count_kill_gates();
    child.kill_tree().expect("the cgroup kill reaches the front");
    assert_eq!(gates.count(), 1);
}

/// A failed password write's teardown asks the gate once, for the same reason. The handle opts out
/// of the drop, whose own teardown would ask again. Mutant: the root's kill asks again.
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

/// A failed spawn's teardown drops a contained front's leaf first, whose kill and drain end it, then
/// reaps it and says so, on the error it would have returned anyway. Mutants: the leaf drops after
/// the teardown, which then says the front may be running and leaves its zombie unreaped; the
/// error's variant is replaced.
#[skuld::test]
fn cgroup_a_failed_spawn_kills_a_contained_front_and_reaps_it(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_kill_tests::{assert_noted, failed_front_spawns, reap};
    let failures = failed_front_spawns(Some(ContainMode::Strongest), |cmd| cmd.spawn().map(drop));
    assert_noted(&failures, "had exited by the teardown");
    for (_, pid) in &failures {
        assert_eq!(reap(*pid), None, "the teardown reaps a front its cgroup's kill ended");
    }
}
