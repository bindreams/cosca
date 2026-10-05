//! A front in a Linux cgroup: the cgroup lane (the `cgroup` group, as root). The front is an
//! ordinary `cat` reported as launched by `sudo`.
//!
//! A front its cgroup leaf holds is not gated: its kills, drop and graceful escalation signal it as
//! on `main`, and a spawn that fails after its fork tears it down as any child. Held means what the
//! attach made of it: a front whose leaf did not take it is in a process group, and gated as any
//! uncontained front.

use std::io::{PipeWriter, Read as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;

use crate::child::front_kill_tests::{assert_reaped_unsignalled, cat, failed_front_spawns, reap, spawn_as};
use crate::command::Command;
use crate::elevation::{Backend, ElevatedVia};
use crate::test_groups::{cgroup, Group};
use crate::{ContainMode, Containment, Stdio};

const SUDO: ElevatedVia = ElevatedVia::Wrapped(Backend::Sudo);

/// `cmd`, contained in a cgroup.
pub(crate) fn in_cgroup(mut cmd: Command) -> Command {
    cmd.contain_with(ContainMode::Strongest);
    cmd
}

/// A `sudo` front its cgroup leaf holds, with its stdin.
fn spawn_contained_front(cmd: Command) -> (crate::Child, PipeWriter) {
    let (child, stdin) = spawn_as(in_cgroup(cmd), SUDO);
    assert_eq!(child.containment(), Containment::CgroupV2);
    (child, stdin)
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

/// Mutant: a front its leaf holds is gated, so its kill is `Unkillable`.
#[skuld::test]
fn cgroup_kill_of_a_contained_front_signals_it_as_on_main(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_contained_front(cat());
    child.kill().expect("a contained front is killed as any child");
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
}

/// Mutant: a front its leaf holds is gated, so its `kill_tree` is `Unkillable`.
#[skuld::test]
fn cgroup_kill_tree_of_a_contained_front_signals_it_as_on_main(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_contained_front(cat());
    child
        .kill_tree()
        .expect("a contained front's tree is killed as any child's");
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
}

/// The drop kills and reaps a contained front, as on `main`. Mutant: a front its leaf holds is
/// gated, so the drop leaves it unreaped.
#[skuld::test]
fn cgroup_drop_of_a_contained_front_kills_and_reaps_it_as_on_main(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_contained_front(cat());
    let pidfd = pidfd_of(child.id().pid());
    drop(child);
    assert!(reaped(&pidfd), "the drop kills and reaps a contained front");
}

/// A contained front that outlives the grace is killed by the escalation, as on `main`. Its `cat`
/// ignores `SIGTERM`. Mutant: a front its leaf holds is gated, so the escalation is `Unkillable`.
#[skuld::test]
fn cgroup_graceful_shutdown_of_a_contained_front_escalates_as_on_main(#[fixture(cgroup)] _group: &Group) {
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "trap '' TERM; echo ready; exec cat"]);
    cmd.stdout(Stdio::pipe_out()).expect("stdout pipe");
    let (mut child, _stdin) = spawn_contained_front(cmd);
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut ready)
        .expect("read `ready`");
    let status = child
        .graceful_shutdown(std::time::Duration::ZERO)
        .expect("the escalation kills a contained front");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}

/// A front contained in a cgroup is not gated: a spawn that fails after its fork tears it down as
/// any child, killed and reaped, and its error carries no note. Mutant: the spawn's teardown leaves
/// a contained front alone.
#[skuld::test]
fn cgroup_a_failed_spawn_tears_a_contained_front_down_as_any_child(#[fixture(cgroup)] _group: &Group) {
    for (err, pid) in failed_front_spawns(Some(ContainMode::Strongest), |cmd| cmd.spawn().map(drop)) {
        assert!(!err.to_string().contains("what sudo left"), "no note: {err}");
        assert_eq!(reap(pid), None, "the teardown reaps it");
    }
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
/// says so. Mutant: "contained" is read from the leaf the spawn prepared, not from what the attach
/// made, so the teardown kills the front.
#[skuld::test]
fn cgroup_a_front_its_leaf_did_not_take_is_left_by_a_failed_identity_check(#[fixture(cgroup)] _group: &Group) {
    let (mut cmd, stdin) = front_its_leaf_did_not_take();
    let (err, pid) = fail_the_identity_check(&mut cmd, |cmd| cmd.spawn().map(drop));
    assert_left_unsignalled(&err, pid, stdin);
}
