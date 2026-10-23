//! The shim where it needs more than its own uid: a real root, a pid namespace of its own, a tracer,
//! a setuid copy of itself. Each test is in the group that names the environment it needs, and runs
//! in that group's CI lane.

use std::io::{Read, Write};
use std::process::{Child, Stdio};

use super::owner_tests::{assert_never_started, owned_by};
use super::rig::Owner;
use super::*;
use crate::elevation::shim::hooks::{Gate, Inject};
use crate::elevation::shim::link::KillOutcome;
use crate::test_groups::{namespaces, setuid, tracer_group, uid_switch, Group};

// A pid namespace of its own -----

const PIDNS: &str = "COSCA_TEST_PIDNS";

/// Runs the calling test in a pid namespace of its own, where it is pid 1.
///
/// In the parent this re-executes the test under `unshare --pid --fork --mount-proc` and panics with
/// its output unless it passed; it returns `false`. In the namespace it returns `true`, and the test
/// goes on. Processes of the namespace die with it: pid 1 ending kills the rest.
fn in_pid_namespace(path: &str) -> bool {
    let test = crate::test_own_process::test_filter(path);
    if std::process::id() == 1 && std::env::var(PIDNS).is_ok_and(|v| v == test) {
        return true;
    }
    let mut command = crate::test_reexec::command("unshare");
    command
        .args(["--pid", "--fork", "--mount-proc", "--kill-child"])
        .arg(std::env::current_exe().expect("the test binary"))
        .args(crate::test_reexec::fixture_args(test))
        .env(PIDNS, test);
    crate::test_reexec::with_json_events(&mut command);
    let out = crate::test_spawn::output_captured(&mut command).expect("run unshare");
    if let Err(why) = crate::test_reexec::suite_passed_exactly_one(&out) {
        panic!(
            "{test} did not pass in its pid namespace: {why}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    false
}

/// A process that is alive until it is dropped, and proves it with an echo.
struct Stranger(Child);

impl Stranger {
    /// Makes the next process of this namespace have pid `want`, and starts the stranger as it. A pid
    /// taken by someone else in between fails the test.
    fn take_pid(want: u32) -> Stranger {
        assert_eq!(
            std::process::id(),
            1,
            "ns_last_pid is the namespace's: write it only in the test's own"
        );
        std::fs::write("/proc/sys/kernel/ns_last_pid", (want - 1).to_string()).expect("set ns_last_pid");
        let mut command = std::process::Command::new("cat");
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
        let child = crate::test_spawn::spawn(&mut command).expect("the stranger starts");
        assert_eq!(
            child.id(),
            want,
            "the pid was taken by another process: the test missed"
        );
        Stranger(child)
    }

    /// Whether the stranger still echoes.
    fn echoes(&mut self) -> bool {
        let stdin = self.0.stdin.as_mut().expect("piped");
        if stdin.write_all(b"x\n").and_then(|()| stdin.flush()).is_err() {
            return false;
        }
        let mut echoed = [0u8; 2];
        self.0.stdout.as_mut().expect("piped").read_exact(&mut echoed).is_ok() && &echoed == b"x\n"
    }
}

impl Drop for Stranger {
    fn drop(&mut self) {
        _ = self.0.kill();
        _ = self.0.wait();
    }
}

#[skuld::test]
fn owner_reaped_and_reused_after_a_is_123(#[fixture(namespaces)] _group: &Group) {
    if !in_pid_namespace(crate::test_own_process::test_path!(
        owner_reaped_and_reused_after_a_is_123
    )) {
        return;
    }
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut owner = Owner::start("plain");
    let mut run = owned_by(&rig, &owner, marker_program(&marker).gate(Gate::AfterAnswer));
    // cosca answered `A`, and then died and was reaped; a stranger has its pid when the shim acts.
    run.wait_for("gate: waiting at after-answer");
    owner.kill();
    let mut stranger = Stranger::take_pid(owner.pid);
    run.release(Gate::AfterAnswer);
    let done = run.finish();
    assert_never_started(&done, &marker, 123);
    assert!(stranger.echoes(), "the stranger was touched");
}

#[skuld::test]
fn owner_pid_reused_before_connect_never_starts(#[fixture(namespaces)] _group: &Group) {
    if !in_pid_namespace(crate::test_own_process::test_path!(
        owner_pid_reused_before_connect_never_starts
    )) {
        return;
    }
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    // cosca dies while a fork copy keeps its listener; a stranger takes its pid; then the shim connects.
    let mut owner = Owner::start("hold-copy");
    let mut run = owned_by(&rig, &owner, marker_program(&marker).gate(Gate::BeforeConnect));
    run.wait_for("gate: waiting at before-connect");
    owner.kill();
    let mut stranger = Stranger::take_pid(owner.pid);
    run.release(Gate::BeforeConnect);
    // The owner watch names the stranger, so it cannot say cosca is gone; the shim says hello and waits.
    run.wait_for("hello sent");
    // The copy's end closes the listener, and the wait ends.
    owner.close_stdin();
    let done = run.finish();
    assert_never_started(&done, &marker, 124);
    assert!(stranger.echoes(), "the stranger was touched");
}

#[skuld::test]
fn reaped_childs_pid_reused_leaves_the_stranger_alive(#[fixture(namespaces)] _group: &Group) {
    if !in_pid_namespace(crate::test_own_process::test_path!(
        reaped_childs_pid_reused_leaves_the_stranger_alive
    )) {
        return;
    }
    // On `clone3`, and on `clone` where `clone3` is refused (Docker's default seccomp profile).
    for (refuse_clone3, path) in [(false, "via Clone3"), (true, "via Clone")] {
        let rig = ShimRig::new();
        let mut spec = Spec::sh("exit 0")
            .gate(Gate::BeforeLoop)
            .inject(Inject::ReapingHostThread);
        if refuse_clone3 {
            spec = spec.inject(Inject::Clone3Enosys);
        }
        let mut run = rig.spawn(spec);
        let forked = run.wait_for("forked child pid=");
        assert!(forked.ends_with(path), "{forked}");
        let pid = run.program_pid();
        // A host thread of the shim reaps the program, and a stranger takes its pid, before `K`.
        run.wait_for("host thread: reaped pid");
        let mut stranger = Stranger::take_pid(pid as u32);
        run.wait_for("gate: waiting at before-loop");
        assert_eq!(rig.link.link.kill().unwrap(), KillOutcome::Delivered);
        run.release(Gate::BeforeLoop);
        assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::StatusLost);
        run.finish();
        assert!(stranger.echoes(), "{path}: the stranger was signalled");
    }
}

// A real root -----

#[skuld::test]
fn cosca_with_ruid_ne_euid_starts(#[fixture(uid_switch)] _group: &Group) {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    // cosca's real uid is 1000 and its effective uid is root's: the answer names the effective one.
    let owner = Owner::start_with(
        "plain",
        &["/usr/bin/setpriv", "--ruid", "1000", "--euid", "0", "--keep-groups"],
    );
    let run = owned_by(&rig, &owner, marker_program(&marker).cosca_euid(0));
    let done = run.finish();
    assert_eq!(done.code, Some(0), "{}\n{:#?}", done.stderr, done.lines);
    assert!(done.logged("first byte: A"), "{:#?}", done.lines);
    assert!(marker.exists(), "the program did not run");
}

// A tracer -----

#[skuld::test]
fn traced_zombie_waits_for_the_tracer_and_reports_the_exact_status(#[fixture(tracer_group)] _group: &Group) {
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::new("cat", &[]).stdin_held());
    run.wait_for("status pipe: EOF");
    let pid = run.program_pid();
    // This thread traces the program, as a debugger would: a descendant, so Yama allows it.
    let null = std::ptr::null_mut::<libc::c_void>;
    // SAFETY: a ptrace request on a pid; the variadic address and data are typed nulls.
    let seized = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, null(), null()) };
    assert_eq!(seized, 0, "PTRACE_SEIZE: {}", std::io::Error::last_os_error());
    // The program exits: a zombie that only its tracer can see. The shim waits for it.
    run.close_stdin();
    run.wait_for("exited, but only its tracer can see it yet");
    let mut status = 0;
    // SAFETY: `status` is valid; `pid` is traced by this thread.
    let reaped = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
    assert_eq!(reaped, pid, "{}", std::io::Error::last_os_error());
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "{status:#x}");
    // Handed back to its parent, the shim, with the exact status.
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(0));
    assert_eq!(run.finish().code, Some(0));
}

// A set-id shim -----

#[skuld::test]
fn setuid_shim_is_refused_before_anything(#[fixture(setuid)] _group: &Group) {
    let helper = crate::test_privilege::setuid::setuid_helper();
    let rig = ShimRig::new();
    let run = rig.spawn(Spec::sh("true").exe(&helper));
    let done = run.finish();
    assert_eq!(done.code, Some(121), "{}\n{:#?}", done.stderr, done.lines);
    assert!(done.stderr.contains("(exit 121)"), "{}", done.stderr);
    assert!(!done.logged("shim pid="), "it did something first: {:#?}", done.lines);
    assert_eq!(rig.link.link.wait().unwrap(), not_started_unconnected());
}
