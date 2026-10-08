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
        let _moved = match kill {
            LeafKill::MissesMovedFront => Some(fault::set_at(fault::SpawnPoint::BeforeIdentity, || {
                move_out_of_its_leaf(fault::spawn_pid())
            })),
            LeafKill::LandsNestedHidden => Some(fault::set_at(fault::SpawnPoint::BeforeIdentity, || {
                move_under_its_leaf(fault::spawn_pid());
            })),
            LeafKill::MissesIntoNamesake => Some(fault::set_at(fault::SpawnPoint::BeforeIdentity, || {
                move_into_a_namesake_of_its_leaf(fault::spawn_pid());
            })),
            LeafKill::Lands | LeafKill::Fails | LeafKill::LandsReadThroughProc => None,
        };
        let _missing = matches!(kill, LeafKill::LandsReadThroughProc | LeafKill::MissesIntoNamesake)
            .then(crate::containment::cgroup::fault::miss_pidfd_info);
        let _hidden = (kill == LeafKill::LandsNestedHidden).then(crate::containment::cgroup::fault::hide_proc);
        let _failing = (kill == LeafKill::Fails).then(crate::containment::cgroup::fault::fail_kill_writes);
        force_arm(true);
        let result = spawn(&mut cmd);
        force_arm(false);
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
/// leaves it running: the place recorded before the leaf's removal says it was outside.
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
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        assert_refused_by(
            child.graceful_shutdown(std::time::Duration::ZERO),
            "its cgroup kill failed",
        );
    }
    assert_ends_unsignalled(&child, stdin);
}

/// A front that exits, and that another thread's `wait` reaps, between the kill gate's read of
/// whether it runs and its read of its cgroup, has exited: `kill` is `Ok`, and sends nothing. The
/// hook between the reads closes the front's stdin, then lets the waiter reap it.
#[skuld::test]
fn cgroup_a_front_reaped_by_a_concurrent_wait_inside_the_gate_has_exited(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let child = &child;
        scope.spawn(move || {
            if go_rx.recv().is_ok() {
                reaped_tx
                    .send(child.wait().map_err(|e| e.to_string()))
                    .expect("report the reap");
            }
        });
        let _between = crate::elevation::front::seams::set_between_gate_reads(move || {
            drop(stdin);
            go_tx.send(()).expect("start the waiter");
            let status = reaped_rx.recv().expect("the waiter reaps").expect("wait");
            assert!(status.success(), "the front ended on its stdin: {status:?}");
        });
        crate::wait::exit_only::seams::signals_sent();
        child.kill().expect("a front that exited is not refused");
        assert_eq!(
            crate::wait::exit_only::seams::signals_sent(),
            0,
            "nothing is signalled to a reaped front"
        );
    });
}

/// A front its cgroup kill ended, and that another thread's `wait` reaped before its cgroup is
/// read, was reached: `kill` is `Ok`. The hook after the kill's write lets the waiter reap it.
#[skuld::test]
fn cgroup_a_front_reaped_by_a_concurrent_wait_after_its_kill_was_reached(#[fixture(cgroup)] _group: &Group) {
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let child = &child;
        scope.spawn(move || {
            if go_rx.recv().is_ok() {
                reaped_tx
                    .send(child.wait().map_err(|e| e.to_string()))
                    .expect("report the reap");
            }
        });
        let _between = crate::elevation::front::seams::set_between_reach_reads(move || {
            // The kill was written, so the front dies of it; one the kill missed exits 0 here.
            drop(stdin);
            go_tx.send(()).expect("start the waiter");
            let status = reaped_rx.recv().expect("the waiter reaps").expect("wait");
            assert_eq!(status.signal(), Some(libc::SIGKILL), "the cgroup kill ended the front");
        });
        child
            .kill()
            .expect("a front its kill ended is reached, whoever reaped it");
    });
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

/// A host whose leaves give no cgroup id (`name_to_handle_at` refused, as on a kernel without
/// `CONFIG_FHANDLE`) cannot place a front after a cgroup kill: an elevated, cgroup-contained spawn
/// is refused before anything is forked.
#[skuld::test]
fn cgroup_a_front_whose_leaf_gives_no_id_is_refused_before_its_fork(#[fixture(cgroup)] _group: &Group) {
    let _no_id = crate::containment::cgroup::fault::fail_cgroup_id(libc::EOPNOTSUPP);
    let mut cmd = in_cgroup(cat());
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let (result, forked) = spawn_front_noting_fork(cmd, |cmd| cmd.spawn().map(drop));
    assert_refused_unforked_naming(result, forked, "CONFIG_FHANDLE");
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
/// `PIDFD_GET_INFO`: the spawn goes on.
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
