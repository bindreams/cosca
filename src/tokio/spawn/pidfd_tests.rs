//! The async spawn's pre-fork probe and `pre_exec` pidfd handshake; the sync twins are in
//! `child/spawn/pidfd_handshake_tests.rs`. A program that "ran" is told apart by its stdout, read
//! to EOF after the command is dropped.

use std::cell::Cell;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::rc::Rc;

use rustix::io::Errno;

use crate::child::spawn::failure::{expect_may_have_started_with, expect_not_started};
use crate::child::spawn::pidfd_handshake::fault::{self, ChildFault};
use crate::error::{ChildFate, Error};
use crate::stdio::Stdio;
use crate::test_groups::{tracer_group, Group};
use crate::tokio::Command;

fn marker_command() -> (Command, std::io::PipeReader) {
    let (reader, writer) = std::io::pipe().expect("pipe");
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "echo ran"]);
    cmd.stdout(Stdio::from_file(std::fs::File::from(OwnedFd::from(writer))))
        .expect("set stdout");
    (cmd, reader)
}

fn program_ran(cmd: Command, mut reader: std::io::PipeReader) -> bool {
    drop(cmd);
    let mut out = String::new();
    reader.read_to_string(&mut out).expect("read the marker to EOF");
    out == "ran\n"
}

/// Mutant: the probe is skipped (the refusal lands after the fork, so `spawns()` is 1).
#[skuld::test]
async fn a_refused_probe_fails_unsupported_and_forks_nothing() {
    for (errno, name) in [(Errno::PERM, "EPERM"), (Errno::NOSYS, "ENOSYS")] {
        let (mut cmd, reader) = marker_command();
        fault::reset_spawns();
        let forced = crate::os_process::linux::open::fault::force_pidfd_open_errno_once(errno);
        let err = cmd.spawn().err();
        drop(forced);

        let err = expect_not_started(err.expect("a refused probe fails the spawn"));
        assert!(
            matches!(err, Error::Unsupported { platform: "linux", .. }),
            "{name}: {err:?}"
        );
        assert_eq!(fault::spawns(), 0, "{name}: the fork must not be reached");
        assert!(!program_ran(cmd, reader), "{name}: the program must not run");
    }
}

/// Mutants: the child execs despite its failed `pidfd_open`; the parent ignores its errno report.
#[skuld::test]
async fn emfile_in_the_child_fails_io_and_the_program_never_runs() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    fault::reset_leaked_pid();
    let forced = crate::os_process::linux::open::fault::force_pidfd_open_script([None, Some(Errno::MFILE)]);
    let err = cmd.spawn().err();
    drop(forced);

    match expect_not_started(err.expect("a failed pidfd_open must fail the spawn")) {
        Error::Io(e) => assert_eq!(e.to_string(), "pidfd_open: Too many open files (os error 24)"),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_eq!(fault::spawns(), 1, "the child was forked and held");
    assert_eq!(fault::take_leaked_pid(), None);
    assert!(!program_ran(cmd, reader), "the aborted child must never exec");
}

#[skuld::test]
async fn a_normal_spawn_runs_the_program() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    let probes = fault::arm_end_probes();
    let mut child = cmd.spawn().expect("a normal spawn succeeds");
    drop(probes);
    let ends = fault::take_ends().expect("the end probes saw the run");
    assert!(!ends.child_end_copy_held && ends.eof_reached, "{ends:?}");
    assert_eq!(fault::spawns(), 1);
    assert!(child.wait().await.expect("wait").success());
    assert!(program_ran(cmd, reader));
}

/// A child that sent its pidfd and died before it could be told to go never ran the program: the
/// spawn fails, and tokio reaps the child once the pidfd shows it exited.
///
/// Mutant: `Gone` is a successful spawn.
#[skuld::test]
async fn a_child_gone_before_its_go_ahead_fails_the_spawn_and_is_reaped() {
    let (mut cmd, reader) = marker_command();
    let armed = fault::arm_child_fault(ChildFault::SigkillAfterReport);
    let held = fault::hold_verdict_until_spawn_returns(|_| {});
    let err = cmd.spawn().err();
    drop(held);
    drop(armed);

    let err = expect_not_started(err.expect("a child that never ran the program must fail the spawn"));
    assert!(
        err.to_string().ends_with("died before exec: the program never ran"),
        "{err}"
    );
    crate::child::spawn::pidfd_handshake::pidfd_handshake_tests::assert_no_child_of_this_thread(
        "tokio reaped the child",
    );
    assert!(!program_ran(cmd, reader));
}

/// With no cgroup leaf, a child the handshake reaped before its go is logged at `debug` as reaped,
/// not warned as left running.
///
/// Mutant: the abandonment hedges at `warn` despite the child's fate.
#[skuld::test]
async fn a_leafless_child_the_handshake_reaped_is_not_said_to_be_left_running() {
    crate::log_capture::install();
    let (mut cmd, _reader) = marker_command();
    let armed = fault::arm_child_fault(ChildFault::SigkillAfterReport);
    let held = fault::hold_verdict_until_spawn_returns(|_| {});
    let mark = crate::log_capture::mark();
    let err = cmd.spawn().err();
    drop(held);
    drop(armed);

    err.expect("a child that never ran the program must fail the spawn");
    let said = crate::log_capture::records_since_on_current_thread(mark, "died before exec");
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(said[0].0, log::Level::Debug, "{said:?}");
    assert!(said[0].1.contains("its child was reaped"), "{said:?}");
    assert!(
        !said[0].1.contains("left running") && !said[0].1.contains("unreaped"),
        "{said:?}"
    );
}

/// With no cgroup leaf, a child that died before it sent its pidfd never ran the program, and tokio
/// collects it: the spawn logs at `debug` what became of it.
///
/// Mutant: the arm answers a plain `not started`, with no fate, so the abandonment hedges at `warn`
/// that the child may be left running.
#[skuld::test]
async fn a_leafless_child_dead_before_its_report_is_not_said_to_be_left_running() {
    crate::log_capture::install();
    let (mut cmd, _reader) = marker_command();
    cmd.contain_with(crate::ContainMode::Session);
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let mark = crate::log_capture::mark();
    let err = cmd.spawn().err();
    drop(armed);

    err.expect("a child that never sent its pidfd must fail the spawn");
    let said = crate::log_capture::records_since_on_current_thread(mark, "died before it could send its pidfd");
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(said[0].0, log::Level::Debug, "{said:?}");
    assert!(said[0].1.contains("its child was killed"), "{said:?}");
}

/// The one `warn` a leafless tokio spawn's failure logs when its child, never told to go, was
/// dropped with no pidfd held on it: the child never ran the program, and only its reaping is open.
#[track_caller]
fn assert_says_the_child_never_ran_and_may_be_unreaped(said: &[(log::Level, String)]) {
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(said[0].0, log::Level::Warn, "{said:?}");
    let text = &said[0].1;
    assert!(text.contains("the child never ran the program"), "{said:?}");
    assert!(text.contains("may be left unreaped"), "{said:?}");
    assert!(
        !text.contains("left running") && !text.contains("nothing can reach it"),
        "{said:?}"
    );
    assert!(!text.contains("  "), "{said:?}");
}

/// A tokio spawn that fails after its fork, with no cgroup leaf, for a child that died before it
/// sent its pidfd, drops a child that never ran the program and that nothing holds. The warn says
/// that, and that it may be left unreaped: never that it may be left running.
///
/// Mutant: the `(Err, NoReport)` arm answers a plain `not started`, so the abandonment hedges that
/// the child "may be left running and nothing can reach it".
#[skuld::test]
async fn a_leafless_tokio_failure_for_a_child_dead_before_its_report_says_it_never_ran() {
    use std::os::fd::AsFd as _;

    use rustix::process::{waitid, WaitId, WaitIdOptions};

    crate::log_capture::install();
    let (mut cmd, _reader) = marker_command();
    cmd.contain_with(crate::ContainMode::Session);
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let mark = crate::log_capture::mark();
    let err = {
        let _failing = crate::child::spawn::fault::fail_tokio_spawns_after_fork();
        cmd.spawn().err()
    };
    drop(armed);

    expect_not_started(err.expect("the forced failure must fail the spawn"));
    let said = crate::log_capture::records_since_on_current_thread(mark, "tokio spawn failed");
    // The seam dropped the child, as tokio does: this test reaps it.
    crate::child::spawn::fault::take_forgotten_pid().expect("the seam dropped a child");
    let pidfd = crate::child::spawn::fault::take_forgotten_pidfd().expect("the seam took a pidfd for the child");
    waitid(WaitId::PidFd(pidfd.as_fd()), WaitIdOptions::EXITED).expect("reap the dropped child");
    assert_says_the_child_never_ran_and_may_be_unreaped(&said);
}

/// As above, for a child whose own `pidfd_open` failed: it reported an errno, so the helper has no
/// pidfd to hold it by.
///
/// Mutant: the `(Err, Failed(_, None))` arm answers a plain `not started`.
#[skuld::test]
async fn a_leafless_tokio_failure_for_a_child_with_no_usable_pidfd_says_it_never_ran() {
    crate::log_capture::install();
    let (mut cmd, _reader) = marker_command();
    cmd.contain_with(crate::ContainMode::Session);
    let forced = crate::os_process::linux::open::fault::force_pidfd_open_script([None, Some(Errno::MFILE)]);
    let mark = crate::log_capture::mark();
    let err = {
        let _failing = crate::child::spawn::fault::fail_tokio_spawns_after_fork();
        cmd.spawn().err()
    };
    drop(forced);

    expect_not_started(err.expect("the failed pidfd_open must fail the spawn"));
    let said = crate::log_capture::records_since_on_current_thread(mark, "tokio spawn failed");
    assert_says_the_child_never_ran_and_may_be_unreaped(&said);
}

/// The fate a tokio spawn, contained by its session, that failed without running the program
/// carries for the child its handshake held.
fn fate_of_unexecuted() -> ChildFate {
    let mut cmd = crate::Command::new();
    cmd.args(["sh", "-c", "echo ran"]);
    cmd.contain_with(crate::ContainMode::Session);
    match super::spawn(&mut cmd) {
        Ok(_) => panic!("a child that never ran the program must fail the spawn"),
        Err(failure) => failure.expect_not_started_with_child().1,
    }
}

/// A child reaped by another reaper after the handshake's kill was killed: the kill reached it,
/// though its exit is lost.
///
/// Mutant: tokio's failed look after the kill is `Gone`, as if no kill had reached the child.
#[skuld::test]
async fn a_child_reaped_elsewhere_after_the_handshakes_kill_was_killed() {
    let pid = Rc::new(Cell::new(None));
    let armed = fault::arm_child_fault(ChildFault::SigkillAfterReport);
    let held = fault::hold_verdict_until_spawn_returns({
        let pid = Rc::clone(&pid);
        move |p| pid.set(p)
    });
    let reaped = crate::child::spawn::fault::set_between_kill_and_wait({
        let pid = Rc::clone(&pid);
        move || crate::test_child::reaped_elsewhere::reap_behind(pid.get().expect("the child's pid"))
    });
    let fate = fate_of_unexecuted();
    drop((reaped, held, armed));
    assert_eq!(fate, ChildFate::Killed);
}

/// A child reaped by another reaper before the handshake's kill is `Gone`: no kill of cosca's
/// reached it.
///
/// Mutant: tokio's failed look is `Killed` whether or not the kill was delivered.
#[skuld::test]
async fn a_child_reaped_elsewhere_before_the_handshakes_kill_is_gone() {
    let armed = fault::arm_child_fault(ChildFault::SigkillAfterReport);
    let held = fault::hold_verdict_until_spawn_returns(|pid| {
        crate::test_child::reaped_elsewhere::reap_behind(pid.expect("the child's pid"));
    });
    let fate = fate_of_unexecuted();
    drop((held, armed));
    assert_eq!(fate, ChildFate::Gone);
}

/// A foreign tracer holds the zombie of a child that died before its go, and the handshake's wait
/// for its exit fails (forced), so tokio finds it unexited: the handshake's kill reached it, and
/// tokio collects it once the tracer lets go. With no cgroup leaf, the spawn logs that at `debug`.
///
/// Mutant: the tracer-held arm's fate is `Unknown`, so the abandonment hedges at `warn` that the
/// child may be left running.
#[skuld::test]
async fn a_leafless_child_a_tracer_holds_after_the_handshakes_kill_is_not_said_to_be_left_running(
    #[fixture(tracer_group)] _group: &Group,
) {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;

    use crate::test_support::foreign_tracer::{self, EXIT};

    crate::log_capture::install();
    // Started first: the spawning thread holds `spawn_lock` until the child dies.
    let mut tracer = foreign_tracer::spawn_unseized_helper();
    let (mut ready_read, ready_write) = std::io::pipe().expect("ready pipe");
    let (gate_read, mut gate_write) = std::io::pipe().expect("gate pipe");
    let child_fault = ChildFault::TracedThenSigkillAfterReport {
        ready: ready_write.as_raw_fd(),
        gate: gate_read.as_raw_fd(),
        parent_ends: [ready_read.as_raw_fd(), gate_write.as_raw_fd()],
    };
    // Opens the child's gate once the tracer holds the child; a panic here closes it, which the
    // child reads as EOF.
    let seizer = std::thread::spawn(move || {
        let mut pid = [0u8; 4];
        ready_read.read_exact(&mut pid).expect("the child's pid");
        tracer.seize(u32::try_from(i32::from_ne_bytes(pid)).expect("a positive pid"));
        gate_write.write_all(b"g").expect("open the child's gate");
        tracer
    });
    let (mut cmd, _reader) = marker_command();
    cmd.contain_with(crate::ContainMode::Session);
    let armed = fault::arm_child_fault(child_fault);
    let held = fault::hold_verdict_until_spawn_returns(|_| {});
    let unwaited = fault::fail_unexecuted_wait(Errno::NOMEM);
    let mark = crate::log_capture::mark();
    let err = cmd.spawn().err();
    drop((unwaited, held, armed, ready_write, gate_read));
    let mut tracer = seizer.join().expect("the tracer seized the child");

    err.expect("a child that never ran the program must fail the spawn");
    let said = crate::log_capture::records_since_on_current_thread(mark, "died before exec");
    tracer.send(EXIT);
    tracer.finish();
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(said[0].0, log::Level::Debug, "{said:?}");
    assert!(said[0].1.contains("its child was killed"), "{said:?}");
}

/// tokio can fail a spawn after std's succeeded, so after the child's `exec`, and its error does not
/// say which failed: the spawn says the program may have started. The child, which tokio dropped, is
/// killed and reaped through its pidfd.
///
/// Mutant: a failed tokio spawn after the child was told to go answers that it did not start.
#[skuld::test]
async fn a_tokio_failure_after_the_fork_may_have_started() {
    let (mut cmd, _reader) = marker_command();
    let err = {
        let _failing = crate::child::spawn::fault::fail_tokio_spawns_after_fork();
        cmd.spawn().expect_err("the forced failure fails the spawn")
    };
    crate::child::spawn::fault::take_forgotten_pid().expect("the seam forked a child");
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
    assert_eq!(
        fate,
        crate::error::ChildFate::Reaped,
        "killed and reaped through its pidfd"
    );
    assert!(
        matches!(err, Error::Io(ref e) if e.raw_os_error() == Some(libc::ENOSPC)),
        "{err:?}"
    );
    crate::child::spawn::pidfd_handshake::pidfd_handshake_tests::assert_no_child_of_this_thread(
        "the teardown reaped the child",
    );
}

/// A tokio exec failure is one the spawn cannot tell from tokio's own failure after `exec`: it may
/// have started.
///
/// Mutant: a failed tokio exec answers that the program did not start.
#[skuld::test]
async fn a_tokio_exec_failure_may_have_started() {
    let mut cmd = Command::new();
    cmd.args(["cosca-no-such-program-142"]);
    let (err, fate) = expect_may_have_started_with(cmd.spawn().expect_err("a missing program fails the spawn"));
    assert_eq!(
        fate,
        crate::error::ChildFate::Gone,
        "std had collected the child whose exec failed"
    );
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound),
        "{err:?}"
    );
}

/// A tokio runtime built without IO makes tokio panic inside the spawn, after std's fork. With a
/// forked copy of the child's end held, the unwind still does not wait on the holder: EOF is
/// forced before the helper is joined.
///
/// Mutant: no forced EOF on unwind (the unwind checks shut the channel and record it).
#[skuld::test]
fn a_runtime_without_io_panics_without_waiting_on_a_held_copy() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime without IO");
    let (mut cmd, _reader) = marker_command();
    fault::reset_spawns();
    let holder = fault::arm_fork_holder();
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let result = rt.block_on(async { catch_unwind(AssertUnwindSafe(|| cmd.spawn().err())) });
    drop(armed);
    let unwound = fault::take_unwound();
    drop(holder);

    assert!(result.is_err(), "tokio panics in a runtime without IO");
    assert_eq!(fault::spawns(), 1, "the panic came after the fork");
    assert_eq!(
        unwound.map(|u| u.eof_reached),
        Some(true),
        "the helper must read EOF by the time the unwind guards are done"
    );
}
