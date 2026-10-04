//! Signals to a child behind an elevation front, on an ordinary `cat` this test owns and reports as
//! launched by `sudo` or `osascript` (`set_elevation`). No forced kill may signal a live front, and
//! no `SIGTERM` a live osascript. The cgroup lane's cases are in `front_cgroup_tests.rs`.
//!
//! Whether anything signalled the `cat` is read from how it ended: it exits 0 once the test closes
//! its stdin, and dies of `SIGKILL` if it was killed first.

use std::io::{PipeWriter, Read as _};
use std::os::unix::process::ExitStatusExt as _;
use std::time::Duration;

use crate::child::fault::record_root_teardowns;
use crate::command::Command;
use crate::elevation::{Backend, ElevatedStdio, ElevatedVia, ElevationReport};
use crate::error::{ElevationErrorKind, Error};
#[cfg(target_os = "linux")]
use crate::test_groups::{cgroup, Group};
use crate::{ContainMode, Containment, Stdio};

pub(crate) fn report(via: ElevatedVia) -> Option<ElevationReport> {
    Some(ElevationReport {
        via,
        stripped_env: Vec::new(),
        stdio: ElevatedStdio::Passthrough,
    })
}

/// Spawns `cmd` with a piped stdin, reported as launched by `via`.
pub(crate) fn spawn_as(mut cmd: Command, via: ElevatedVia) -> (crate::Child, PipeWriter) {
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    child.set_elevation(report(via));
    let stdin = child.stdin().expect("stdin pipe");
    (child, stdin)
}

pub(crate) fn cat() -> Command {
    let mut cmd = Command::new();
    cmd.args(["cat"]);
    cmd
}

/// `r` is the `Unkillable` refusal of the live sudo front `pid`.
#[track_caller]
pub(crate) fn assert_unkillable_front<T: std::fmt::Debug>(r: Result<T, Error>, pid: u32) {
    assert_refused_by(r, &format!("pid {pid} is what sudo left"));
}

/// `r` is an `Unkillable` refusal whose detail contains `names`.
#[track_caller]
pub(crate) fn assert_refused_by<T: std::fmt::Debug>(r: Result<T, Error>, names: &str) {
    match r {
        Err(Error::Elevation {
            kind: ElevationErrorKind::Unkillable,
            detail,
        }) => assert!(detail.contains(names), "{detail}"),
        other => panic!("expected Unkillable naming {names:?}, got {other:?}"),
    }
}

/// Closes the `cat`'s stdin and reaps it: it must exit 0, so nothing signalled it.
#[track_caller]
pub(crate) fn assert_ends_unsignalled(child: &crate::Child, stdin: PipeWriter) {
    drop(stdin);
    let status = child.wait().expect("wait");
    assert!(status.success(), "the front was signalled: {status:?}");
}

/// Mutant: `kill()` signals the front (it answers `Ok`, and the `cat` dies of `SIGKILL`).
#[skuld::test]
fn kill_of_a_live_front_is_unkillable_and_sends_nothing() {
    let (child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    assert_unkillable_front(child.kill(), child.id().pid());
    assert_ends_unsignalled(&child, stdin);
}

/// A front that has exited orphans nothing, so its kill answers as any child's. Mutant: the
/// front's exit is not read, so the kill is `Unkillable`.
#[skuld::test]
fn kill_of_an_exited_front_is_ok() {
    let (child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    drop(stdin);
    crate::test_child::wait_until_zombie(child.id().pid());
    child.kill().expect("an exited front is killed like any child");
    assert!(child.wait().expect("wait").success());
}

/// pkexec execs the program, so the tracked process is the program: it is signalled. Mutant:
/// pkexec counted as a front.
#[skuld::test]
fn kill_of_a_pkexec_child_signals_it() {
    let (child, _stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Pkexec));
    child.kill().expect("kill");
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
}

/// A process group or a walked tree is signalled subject to the target's credentials, so it does
/// not reach the program either. Mutants: `kill_tree` runs the group kill; it signals the front.
#[skuld::test]
fn kill_tree_of_a_live_front_outside_a_cgroup_is_unkillable_and_sends_nothing() {
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Session);
    let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    assert_ne!(child.containment(), Containment::CgroupV2);
    assert_unkillable_front(child.kill_tree(), child.id().pid());
    assert_ends_unsignalled(&child, stdin);
}

/// The escalation is the gated kill. A `cat` that ignores `SIGTERM` outlives the grace. Mutant:
/// the escalation signals the front directly.
#[skuld::test]
fn graceful_shutdown_of_a_front_that_outlives_the_grace_is_unkillable() {
    let mut cmd = Command::new();
    // An ignored disposition survives `exec`; `ready` says it is set.
    cmd.args(["sh", "-c", "trap '' TERM; echo ready; exec cat"]);
    cmd.stdout(Stdio::pipe_out()).expect("stdout pipe");
    let (mut child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut ready)
        .expect("read `ready`");
    assert_eq!(&ready, b"ready\n");
    assert_unkillable_front(child.graceful_shutdown(Duration::ZERO), child.id().pid());
    assert_ends_unsignalled(&child, stdin);
}

/// The drop neither kills nor waits for a live front, and says so. Mutants: the drop runs the
/// root's teardown (kill and reap); it warns of nothing.
#[skuld::test]
fn drop_of_a_live_front_leaves_it_running_unreaped_and_warns() {
    crate::log_capture::install();
    let teardowns = record_root_teardowns();
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Session);
    let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(teardowns.count(), 0, "the drop must not kill or reap a live front");
    let warns = crate::log_capture::records_since_on_current_thread(mark, "Child::drop");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert_eq!(warns[0].0, log::Level::Warn);
    assert!(
        warns[0].1.contains(&format!("pid {pid} is what sudo left")),
        "{warns:?}"
    );

    // Still this process's unreaped child: end it and reap it here.
    drop(stdin);
    assert_reaped_unsignalled(pid);
}

/// Reaps `pid`, an unreaped child of this process that nothing else reaps, and asserts it exited 0.
#[track_caller]
pub(crate) fn assert_reaped_unsignalled(pid: u32) {
    let mut status = 0;
    // SAFETY: `status` is a valid out-parameter.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(
        reaped,
        pid as libc::pid_t,
        "waitpid: {}",
        std::io::Error::last_os_error()
    );
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the front was signalled: raw status {status:#x}"
    );
}

/// A failed password write's teardown signals neither a live front nor its group, and says why.
/// The `killpg` recorder stands in for the group kill. Mutants: the teardown runs the group kill;
/// it signals the front.
#[skuld::test]
fn a_failed_password_write_signals_neither_a_live_front_nor_its_group() {
    let groups = crate::containment::unix::fault::record_kill_group();
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Session);
    let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let pid = child.id().pid();
    let err = crate::child::spawn::finish_elevated(
        child,
        Err(Error::Elevation {
            kind: ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("a failed write fails the spawn");
    assert_eq!(
        groups.killed(),
        Vec::<i32>::new(),
        "no group kill of a live front: {err}"
    );
    let Error::Elevation { detail, .. } = &err else {
        panic!("expected an Elevation error, got {err:?}");
    };
    assert!(detail.contains("could not be terminated"), "{detail}");
    assert!(detail.contains(&format!("pid {pid} is what sudo left")), "{detail}");
    // The handle was dropped with the front alive and unreaped.
    drop(stdin);
    assert_reaped_unsignalled(pid);
}

/// A `SIGTERM` would end osascript and orphan the program, so `terminate()` on a live osascript
/// front sends nothing. Mutant: osascript's `SIGTERM` is sent (the `cat` dies of it).
#[skuld::test]
fn terminate_of_a_live_osascript_is_unkillable_and_sends_nothing() {
    let (child, stdin) = spawn_as(cat(), ElevatedVia::MacosOsascript);
    let pid = child.id().pid();
    assert_refused_by(child.terminate(), &format!("pid {pid} is osascript"));
    assert_ends_unsignalled(&child, stdin);
}

/// The graceful path starts with `terminate()`, so it is refused before any grace or kill. Then a
/// kill is refused too, as it was before the attempt. Mutants: the graceful path signals
/// osascript; a kill after it does.
#[skuld::test]
fn graceful_shutdown_of_a_live_osascript_is_unkillable_and_sends_nothing() {
    let (child, stdin) = spawn_as(cat(), ElevatedVia::MacosOsascript);
    let pid = child.id().pid();
    assert_refused_by(
        child.graceful_shutdown(Duration::ZERO),
        &format!("pid {pid} is osascript"),
    );
    assert_refused_by(child.kill(), &format!("pid {pid} is osascript"));
    assert_ends_unsignalled(&child, stdin);
}

/// sudo relays `SIGTERM` to the program, so it is sent. Mutant: every front's `SIGTERM` is refused.
#[skuld::test]
fn terminate_of_a_live_sudo_front_is_sent() {
    let (child, _stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    child.terminate().expect("sudo relays SIGTERM");
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGTERM));
}

/// Spawns of a `cat` marked as an elevation-derived `sudo` front, in `contain` mode if any, that fail
/// after their fork: once in the attach, once in the identity check. Returns each failure with the
/// child's pid. The failed spawn closes the `cat`'s stdin, so a front left alone exits 0.
#[cfg(target_os = "linux")]
pub(crate) fn failed_front_spawns(
    contain: Option<ContainMode>,
    spawn: impl Fn(&mut Command) -> Result<(), Error>,
) -> [(Error, u32); 2] {
    use crate::child::spawn::fault;
    let arms: [fn(bool); 2] = [fault::set_force_attach_failure, fault::set_force_identity_vanished];
    arms.map(|force_arm| {
        let mut cmd = cat();
        cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
        if let Some(mode) = contain {
            cmd.contain_with(mode);
        }
        cmd.set_elevation_front(crate::elevation::front::front(Some(&ElevatedVia::Wrapped(
            Backend::Sudo,
        ))));
        force_arm(true);
        let err = spawn(&mut cmd);
        force_arm(false);
        let err = err.expect_err("the forced arm fails the spawn");
        let crate::identity::Resolved::Found(id) = fault::take_captured().expect("the seam captured the child") else {
            panic!("the seam must capture a resolved identity");
        };
        (err, id.pid())
    })
}

/// Reaps `pid`, this process's own child, and answers how it ended: `None` if something reaped it
/// already.
#[cfg(target_os = "linux")]
pub(crate) fn reap(pid: u32) -> Option<std::process::ExitStatus> {
    let mut raw = 0;
    // SAFETY: `raw` is a valid out-parameter; `pid` is this process's own child.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut raw, 0) };
    if reaped == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
        return None;
    }
    assert_eq!(
        reaped,
        pid as libc::pid_t,
        "waitpid: {}",
        std::io::Error::last_os_error()
    );
    Some(std::os::unix::process::ExitStatusExt::from_raw(raw))
}

/// The two failures keep their variants (an attach's `Containment`, an identity check's `Io`) and
/// carry the front's fate in their text, `fate`.
#[cfg(target_os = "linux")]
#[track_caller]
pub(crate) fn assert_noted(failures: &[(Error, u32); 2], fate: &str) {
    let [(attach, attach_pid), (identity, identity_pid)] = failures;
    assert!(
        matches!(attach, Error::Containment { .. }),
        "the attach failure keeps its variant: {attach:?}"
    );
    assert!(
        matches!(identity, Error::Io(_)),
        "the identity failure keeps its variant: {identity:?}"
    );
    for (err, pid) in [(attach, attach_pid), (identity, identity_pid)] {
        let text = err.to_string();
        assert!(text.contains(&format!("pid {pid} is what sudo left")), "{text}");
        assert!(text.contains(fate), "{text}");
    }
}

/// A spawn that fails after its fork sends an elevation front nothing (a kill would orphan the
/// program), leaves it unreaped, and says so on the error it would have returned anyway. Mutants:
/// the teardown kills the front; it hands the front to a reaper; the error's variant is replaced;
/// the error does not say so.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_spawn_leaves_an_elevation_front_running_and_says_so() {
    let failures = failed_front_spawns(None, |cmd| cmd.spawn().map(drop));
    assert_noted(&failures, "the elevated program may be running; it is left unreaped");
    for (_, pid) in &failures {
        let status = reap(*pid).expect("the front must be left unreaped");
        assert!(status.success(), "the teardown signalled the front: {status:?}");
    }
}

/// A front contained in a cgroup is not gated: a spawn that fails after its fork tears it down as
/// any child, killed and reaped, and its error carries no note. Needs a delegated cgroup: the cgroup
/// lane. Mutant: the spawn's teardown leaves a contained front alone.
#[cfg(target_os = "linux")]
#[skuld::test]
fn cgroup_a_failed_spawn_tears_a_contained_front_down_as_any_child(#[fixture(cgroup)] _group: &Group) {
    for (err, pid) in failed_front_spawns(Some(ContainMode::Strongest), |cmd| cmd.spawn().map(drop)) {
        assert!(!err.to_string().contains("what sudo left"), "no note: {err}");
        assert_eq!(reap(pid), None, "the teardown reaps it");
    }
}
