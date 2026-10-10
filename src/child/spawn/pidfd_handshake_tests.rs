//! Tests for the Linux pre-fork probe and the `pre_exec` pidfd handshake.
//!
//! A program that "ran" is told apart from one that did not by its stdout: the test owns the only
//! write end besides the child's, so reading to EOF returns once the child is gone, with data
//! exactly if the program ran. No timing is involved.

use std::cell::{Cell, RefCell};
use std::io::Read;
use std::os::fd::OwnedFd;
use std::rc::Rc;

use rustix::io::Errno;
use rustix::net::ReturnFlags;

use super::fault::{self, ChildFault};
use super::{classify_send, parse_report, Delivery, Outcome, Report, REPORT_ERRNO, REPORT_LEN, REPORT_PIDFD};
use crate::child::spawn::failure::expect_not_started;
use crate::child::spawn::SpawnFailure;
use crate::command::Command;
use crate::error::ChildFate;
use crate::error::Error;
use crate::stdio::Stdio;
use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;
use crate::test_groups::{namespaces, Group};

/// A command that writes `ran` to a pipe and exits, and the read end of that pipe.
fn marker_command() -> (Command, std::io::PipeReader) {
    let (reader, writer) = std::io::pipe().expect("pipe");
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "echo ran"]);
    cmd.stdout(Stdio::from_file(std::fs::File::from(OwnedFd::from(writer))))
        .expect("set stdout");
    (cmd, reader)
}

/// Whether the program ran: `cmd` is dropped first, so the child holds the only write end.
fn program_ran(cmd: Command, mut reader: std::io::PipeReader) -> bool {
    drop(cmd);
    let mut out = String::new();
    reader.read_to_string(&mut out).expect("read the marker to EOF");
    out == "ran\n"
}

/// The calling thread has no child, running or zombie. `__WNOTHREAD` keeps the answer to this
/// thread's own children, so a concurrent test's child cannot change it.
pub(crate) fn assert_no_child_of_this_thread(what: &str) {
    // SAFETY: a `waitid` with no output buffer, `WNOWAIT`: it consumes nothing.
    let rc = unsafe {
        libc::waitid(
            libc::P_ALL,
            0,
            std::ptr::null_mut(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WNOTHREAD,
        )
    };
    let err = std::io::Error::last_os_error();
    assert!(
        rc == -1 && err.raw_os_error() == Some(libc::ECHILD),
        "{what}: this thread must have no child, got rc {rc} ({err})"
    );
}

/// A raw `std` command for a handshake driven directly, with the hook registered first.
fn raw_command(program: &str) -> (std::process::Command, super::Pending) {
    let mut std_cmd = std::process::Command::new(program);
    let pending = super::register(&mut std_cmd);
    (std_cmd, pending)
}

/// What an armed `run` saw of the channel's ends: no copy of the child's end held by the spawning
/// thread once `spawn()` returned, and the helper at EOF once the wait was over.
fn assert_ends_closed(ends: Option<fault::Ends>, what: &str) -> fault::Ends {
    let ends = ends.unwrap_or_else(|| panic!("{what}: the end probes saw no run"));
    assert!(
        !ends.child_end_copy_held,
        "{what}: the spawning thread must close its copy of the child's end as soon as spawn() returns"
    );
    assert!(
        ends.eof_reached,
        "{what}: the helper must read EOF once the wait for the child is over"
    );
    ends
}

// Normal spawns =====

/// Mutant: a handshake that leaves the child held forever (the spawn hangs: bounded by the nextest
/// override) or aborts it.
#[skuld::test]
fn a_normal_spawn_runs_the_program_and_forks_once() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    let probes = fault::arm_end_probes();
    let child = cmd.spawn().expect("a normal spawn succeeds");
    drop(probes);
    assert_ends_closed(fault::take_ends(), "a normal spawn");
    assert_eq!(fault::spawns(), 1);
    assert!(child.wait().expect("wait").success());
    assert_no_child_of_this_thread("after the wait");
    assert!(program_ran(cmd, reader));
}

// The pre-fork probe =====

/// A refusal before the fork is `Unsupported` naming `spawn`, and no child is ever forked.
///
/// Mutant: the probe is skipped (the refusal then lands after the fork, so `spawns()` is 1).
#[skuld::test]
fn a_refused_probe_fails_unsupported_and_forks_nothing() {
    for (errno, name) in [
        (Errno::PERM, "EPERM"),
        (Errno::ACCESS, "EACCES"),
        (Errno::NODEV, "ENODEV"),
        (Errno::NOSYS, "ENOSYS"),
    ] {
        let (mut cmd, reader) = marker_command();
        fault::reset_spawns();
        let forced = crate::wait::backend::fault::force_pidfd_open_errno_once(errno);
        let err = cmd.spawn().err();
        drop(forced);

        let err = err.unwrap_or_else(|| panic!("{name}: a refused pidfd_open must fail the spawn"));
        assert_eq!(
            err.to_string(),
            format!(
                "spawn is not supported on linux: cosca requires pidfd_open (Linux \u{2265} 5.3), \
                 refused here: pidfd_open answered {name}"
            ),
            "{err:?}"
        );
        assert_eq!(fault::spawns(), 0, "{name}: the fork must not be reached");
        assert_no_child_of_this_thread(name);
        assert!(!program_ran(cmd, reader), "{name}: the program must not run");
    }
}

/// A transient failure of the probe itself fails the spawn as `Io` naming `pidfd_open`, before any
/// fork.
#[skuld::test]
fn a_probe_that_hits_emfile_fails_io_and_forks_nothing() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    let forced = crate::wait::backend::fault::force_pidfd_open_errno_once(Errno::MFILE);
    let err = cmd.spawn().err();
    drop(forced);

    match err.expect("a failed probe must fail the spawn") {
        Error::Io(e) => assert_eq!(e.to_string(), "pidfd_open: Too many open files (os error 24)"),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_eq!(fault::spawns(), 0);
    assert!(!program_ran(cmd, reader));
}

// The child's own pidfd_open =====

/// The probe passes and the child's `pidfd_open` on itself hits `EMFILE`: the spawn fails `Io`
/// naming `pidfd_open`, and the program never ran. std collected the child.
///
/// Mutants: the child execs despite its failed `pidfd_open`; the parent ignores its errno report.
#[skuld::test]
fn emfile_in_the_child_fails_io_and_the_program_never_runs() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    fault::reset_leaked_pid();
    let forced = crate::wait::backend::fault::force_pidfd_open_script([None, Some(Errno::MFILE)]);
    let err = cmd.spawn().err();
    drop(forced);

    match err.expect("a failed pidfd_open must fail the spawn") {
        Error::Io(e) => assert_eq!(e.to_string(), "pidfd_open: Too many open files (os error 24)"),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_eq!(fault::spawns(), 1, "the child was forked and held");
    assert_eq!(fault::take_leaked_pid(), None, "std collected the aborted child");
    assert_no_child_of_this_thread("after the abort");
    assert!(!program_ran(cmd, reader), "the aborted child must never exec");
}

/// A refusal that only shows in the child is still `Unsupported` naming `spawn`, and the program
/// never ran.
#[skuld::test]
fn a_refusal_in_the_child_is_unsupported_and_the_program_never_runs() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    let forced = crate::wait::backend::fault::force_pidfd_open_script([None, Some(Errno::PERM)]);
    let err = cmd.spawn().err();
    drop(forced);

    let err = err.expect("a refused pidfd_open must fail the spawn");
    assert_eq!(
        err.to_string(),
        "spawn is not supported on linux: cosca requires pidfd_open (Linux \u{2265} 5.3), \
         refused here: pidfd_open answered EPERM",
        "{err:?}"
    );
    assert_eq!(fault::spawns(), 1);
    assert_no_child_of_this_thread("after the abort");
    assert!(!program_ran(cmd, reader));
}

// The report =====

/// A report whose descriptor the kernel could not install is an error; a well-formed report is
/// its pidfd, its errno, or EOF.
#[skuld::test]
fn a_truncated_report_is_an_error_and_a_whole_one_is_read() {
    let fd = || OwnedFd::from(std::fs::File::open("/dev/null").expect("open /dev/null"));
    let message = |tag: i32, value: i32| {
        let mut message = [0u8; REPORT_LEN];
        message[..4].copy_from_slice(&tag.to_ne_bytes());
        message[4..].copy_from_slice(&value.to_ne_bytes());
        message
    };

    let truncated = parse_report(REPORT_LEN, ReturnFlags::CTRUNC, &message(REPORT_PIDFD, 0), vec![], 0);
    match truncated {
        Err(Error::Io(e)) => assert!(e.to_string().contains("could not be received"), "{e}"),
        other => panic!("a truncated report must be an error, got {other:?}"),
    }
    assert!(matches!(
        parse_report(
            REPORT_LEN,
            ReturnFlags::empty(),
            &message(REPORT_PIDFD, 0),
            vec![fd()],
            0
        ),
        Ok(Report::Pidfd(_))
    ));
    assert!(matches!(
        parse_report(
            REPORT_LEN,
            ReturnFlags::empty(),
            &message(REPORT_ERRNO, libc::EPERM),
            vec![],
            0
        ),
        Ok(Report::Errno(Errno::PERM))
    ));
    assert!(matches!(
        parse_report(0, ReturnFlags::empty(), &[0; REPORT_LEN], vec![], 0),
        Ok(Report::Eof)
    ));
}

// The verdict =====

/// Only a closed or shut end means the child is gone; `EINTR` sends again, and any other error
/// fails the spawn.
///
/// Mutant: every send error is taken as the child being gone.
#[skuld::test]
fn only_a_closed_end_makes_an_undelivered_go_mean_gone() {
    assert!(matches!(classify_send(Ok(1)), Some(Delivery::Delivered)));
    assert!(classify_send(Err(Errno::INTR)).is_none(), "EINTR must send again");
    for errno in [Errno::PIPE, Errno::CONNRESET] {
        assert!(matches!(classify_send(Err(errno)), Some(Delivery::Gone)), "{errno:?}");
    }
    for errno in [Errno::NOBUFS, Errno::NOMEM, Errno::AGAIN] {
        match classify_send(Err(errno)) {
            Some(Delivery::Failed(e)) => assert_eq!(e.raw_os_error(), Some(errno.raw_os_error())),
            other => panic!("{errno:?} must fail the spawn, got {other:?}"),
        }
    }
}

/// A go-ahead the parent could not send fails the spawn naming why, and the waiting child still
/// reads EOF although a process forked without `exec` holds a copy of the parent's end.
///
/// Mutants: the helper does not shut the parent's end (the child would wait forever on the copy);
/// every send error is taken as the child being gone (the error would be the child's abort).
#[skuld::test]
fn an_undelivered_go_ahead_fails_the_spawn_and_ends_the_childs_wait() {
    let (mut cmd, reader) = marker_command();
    let holder = fault::arm_fork_holder();
    let forced = fault::force_go_send_errnos([Errno::NOBUFS]);
    let err = cmd.spawn().err();
    drop(forced);
    let shut = fault::parent_end_shut();
    drop(holder);

    assert_eq!(
        shut,
        Some(true),
        "the helper must shut the parent's end, whatever copies of it exist"
    );
    match err.expect("an undelivered go-ahead must fail the spawn") {
        Error::Io(e) => assert_eq!(
            e.to_string(),
            "pidfd handshake: sending the child its go-ahead: No buffer space available (os error 105)"
        ),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_no_child_of_this_thread("std collected the aborted child");
    assert!(!program_ran(cmd, reader));
}

/// A child that sent its pidfd and died before it could be told to go never ran the program: the
/// spawn fails, and the child is reaped through its pidfd.
///
/// Mutant: `Gone` is a successful spawn.
#[skuld::test]
fn a_child_gone_before_its_go_ahead_fails_the_spawn_and_is_reaped() {
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
    assert_no_child_of_this_thread("the child is reaped through its pidfd");
    assert!(!program_ran(cmd, reader));
}

// Failures after the fork =====

/// tokio can fail a spawn after std's succeeded, dropping the child neither killed nor reaped:
/// the handshake kills and reaps it through the pidfd it sent. The failure is faked with std's
/// `Child`, whose own spawn never fails after `exec`, so the answer is `not started`; tokio's is
/// pinned by `conclude_answers_whether_the_program_could_have_started`.
///
/// Mutant: the pidfd is dropped when the spawn fails.
#[skuld::test]
fn a_spawn_that_fails_after_the_child_execed_kills_and_reaps_it() {
    use std::os::unix::process::ExitStatusExt;

    let (reader, writer) = std::io::pipe().expect("pipe");
    let (mut std_cmd, pending) = raw_command(crate::test_child::BLOCKER_ARGV[0]);
    std_cmd
        .args(&crate::test_child::BLOCKER_ARGV[1..])
        .stdin(std::process::Stdio::from(OwnedFd::from(reader)))
        .stdout(std::process::Stdio::null());
    // Only the kill ends it: its stdin's writer is released between the kill and the reap.
    let fired = Rc::new(Cell::new(false));
    let release = crate::child::spawn::fault::set_between_kill_and_wait({
        let fired = Rc::clone(&fired);
        move || {
            drop(writer);
            fired.set(true);
        }
    });
    let reaps = crate::child::spawn::fault::record_teardown_reaps();

    let guard = super::super::spawn_lock();
    let handshake = pending.open(&guard).expect("open");
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `guard`")]
    let result = handshake.run(|| {
        let child = std_cmd.spawn()?;
        drop(child);
        Err::<std::process::Child, _>(std::io::Error::other("post-fork failure (test)"))
    });
    drop(guard);

    match result {
        Err(SpawnFailure::NotStarted(Error::Io(e))) => assert_eq!(e.to_string(), "post-fork failure (test)"),
        other => panic!("expected the spawn's own error, got {:?}", other.err()),
    }
    assert!(fired.get(), "the running child must be killed through its pidfd");
    let recorded = reaps.recorded();
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert_eq!(recorded[0].1.signal(), Some(libc::SIGKILL));
    assert_no_child_of_this_thread("the child is reaped through its pidfd");
    drop(release);
}

/// A hook after the handshake's fails: std reports it and collects the child, so there is nothing
/// left to kill.
#[skuld::test]
fn a_later_hook_failure_leaves_nothing_to_kill() {
    let (mut std_cmd, pending) = raw_command("true");
    // SAFETY: returns an error; nothing else.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut std_cmd, || {
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        });
    }
    let fired = Rc::new(Cell::new(false));
    let hook = crate::child::spawn::fault::set_between_kill_and_wait({
        let fired = Rc::clone(&fired);
        move || fired.set(true)
    });

    let guard = super::super::spawn_lock();
    let handshake = pending.open(&guard).expect("open");
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `guard`")]
    let result = handshake.run(|| std_cmd.spawn());
    drop(guard);
    drop(hook);

    match result {
        Err(SpawnFailure::NotStarted(Error::Io(e))) => assert_eq!(e.raw_os_error(), Some(libc::EIO), "{e:?}"),
        other => panic!(
            "expected the hook's error, got {:?}",
            other.err().map(|e| Error::from(e).to_string())
        ),
    }
    assert!(!fired.get(), "a child std collected must not be signalled");
    assert_no_child_of_this_thread("std collected the child");
}

// Deadlock paths =====

/// A child whose hook fails before it reports ends the helper at EOF, and the spawn reports the
/// child's error.
///
/// Mutant: the spawning thread keeps its copy of the child's end open past `spawn()` (the helper
/// then never reads EOF).
#[skuld::test]
fn a_child_that_fails_before_reporting_ends_the_spawn() {
    let (mut cmd, reader) = marker_command();
    let armed = fault::arm_child_fault(ChildFault::Fail);
    let probes = fault::arm_end_probes();
    let err = cmd.spawn().err();
    drop(probes);
    assert_ends_closed(fault::take_ends(), "a child that fails before reporting");
    drop(armed);

    match err.expect("a child that fails before exec fails the spawn") {
        Error::Io(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO), "{e:?}"),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_no_child_of_this_thread("std collected the failed child");
    assert!(!program_ran(cmd, reader));
}

/// As above, with a process forked without `exec` holding a copy of the child's end: the helper
/// still reads EOF, because the parent shuts its own end for reading, not just closes the child's.
///
/// Mutant: the parent does not force EOF after a failed spawn (the helper would wait forever on
/// the copy).
#[skuld::test]
fn eof_reaches_the_helper_through_a_forked_copy_of_the_childs_end() {
    let (mut cmd, reader) = marker_command();
    let holder = fault::arm_fork_holder();
    let armed = fault::arm_child_fault(ChildFault::Fail);
    let probes = fault::arm_end_probes();
    let err = cmd.spawn().err();
    drop(probes);
    drop(armed);
    let ends = assert_ends_closed(fault::take_ends(), "a failed spawn with a forked copy");
    drop(holder);

    assert!(ends.eof_forced, "only a forced EOF reaches the helper through the copy");
    match err.expect("a child that fails before exec fails the spawn") {
        Error::Io(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO), "{e:?}"),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_no_child_of_this_thread("std collected the failed child");
    assert!(!program_ran(cmd, reader));
}

/// A child killed before it reports, with a process forked without `exec` holding a copy of its
/// end: `spawn()` returns, the child has exited, and the parent forces EOF so the helper reads it.
///
/// Mutant: the parent never watches the child, so it never forces EOF (the helper would wait
/// forever on the copy).
#[skuld::test]
fn eof_reaches_the_helper_when_a_killed_child_leaves_a_forked_copy() {
    let (mut cmd, reader) = marker_command();
    fault::reset_leaked_pid();
    let holder = fault::arm_fork_holder();
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let probes = fault::arm_end_probes();
    let err = cmd.spawn().err();
    drop(probes);
    drop(armed);
    let ends = assert_ends_closed(fault::take_ends(), "a killed child with a forked copy");
    drop(holder);

    assert!(ends.eof_forced, "only a forced EOF reaches the helper through the copy");
    assert!(matches!(err, Some(Error::Io(_))), "{err:?}");
    let pid = fault::take_leaked_pid()
        .expect("the unreaped child is named")
        .expect("it has a pid");
    // SAFETY: `pid` is this thread's own zombie child, so waiting on it is sound.
    let reaped = unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), 0) };
    assert_eq!(reaped, pid as i32);
    assert!(!program_ran(cmd, reader));
}

/// With two of fds 0 to 2 closed, std's status pipe sits on a stdio slot the child replaces, and
/// `spawn()` returns before the child's hooks run. The child still reports, and runs the program.
///
/// Mutant: the parent forces EOF as soon as `spawn()` returns, while the child still has to report
/// (the child's report then fails, and so does the spawn).
///
/// Runs in a process of its own: closing 1 and 2 is process-wide.
///
/// Precondition: std returns from `spawn()` before the child's hooks run, so the child is gated
/// inside `spawn()` until the release; a std that blocks until `exec` hangs the test, not fails it.
#[skuld::test]
fn a_spawn_that_returns_before_the_hooks_run_still_runs_the_program() {
    use std::io::{Seek, Write};
    use std::os::fd::AsRawFd;

    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;
    use crate::test_stdio::RestoreStdio;

    let Some(done) = own_process(
        test_path!(a_spawn_that_returns_before_the_hooks_run_still_runs_the_program),
        spawn,
    ) else {
        return;
    };
    let mut file = tempfile::tempfile().expect("tempfile");
    let (gate_read, gate_write) = std::io::pipe().expect("open the gate");
    let gate_write = Rc::new(RefCell::new(Some(gate_write)));
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "echo ran"]);
    for slot in [1, 2] {
        cmd.fd(slot, Stdio::from_file(file.try_clone().expect("clone the file")))
            .expect("wire the slot to the file");
    }
    // The child waits at its hook until the parent, its spawn returned, is about to wait for it in
    // turn. The release also runs when the wait is over, so a parent that never reaches it (a
    // regression) cannot hold the child, and the test, forever.
    let armed = fault::arm_child_fault(ChildFault::Gate(gate_read.as_raw_fd()));
    let probes = fault::arm_end_probes();
    let release_gate = {
        let gate_write = Rc::clone(&gate_write);
        move || {
            if let Some(mut gate) = gate_write.borrow_mut().take() {
                gate.write_all(b"x").expect("release the child");
            }
        }
    };
    let release = fault::before_awaiting_the_child_do(release_gate.clone());
    let released_at_the_end = fault::wait_over_do(release_gate);
    let restore = RestoreStdio::close(&done, &[1, 2]);
    let spawned = cmd.spawn();
    drop(restore);
    drop(release);
    drop(released_at_the_end);
    drop(probes);
    drop(armed);
    // Released whatever happened, before any assert: a child held forever holds the file.
    if let Some(mut gate) = gate_write.borrow_mut().take() {
        gate.write_all(b"x").expect("release the child");
    }

    assert_ends_closed(fault::take_ends(), "a spawn that returns before the hooks run");
    let child = spawned.expect("the spawn must succeed");
    assert!(child.wait().expect("wait").success());
    let mut written = String::new();
    file.rewind().expect("rewind the file");
    file.read_to_string(&mut written).expect("read the file");
    assert_eq!(written, "ran\n");
}

/// A child killed before it reports: std reads the closed status pipe as success, the helper
/// reads EOF. The child is dead, unreaped and pidless-to-us, so it is left unreaped and named,
/// and the spawn fails.
#[skuld::test]
fn a_child_killed_before_reporting_is_left_unreaped_and_named() {
    use std::os::unix::process::ExitStatusExt;

    let (mut cmd, reader) = marker_command();
    fault::reset_leaked_pid();
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let probes = fault::arm_end_probes();
    let err = cmd.spawn().err();
    drop(probes);
    drop(armed);

    assert_ends_closed(fault::take_ends(), "a child killed before it reports");
    let err = err.expect("a child killed before it reports fails the spawn");
    let pid = fault::take_leaked_pid()
        .expect("the unreaped child is named")
        .expect("it has a pid");
    assert_eq!(
        err.to_string(),
        format!("the spawned child (pid {pid}) died before it could send its pidfd")
    );
    // The test owns this cleanup: the pid is this thread's unreaped zombie.
    let mut status = 0;
    // SAFETY: `pid` is this thread's own zombie child, so waiting on it is sound.
    let reaped = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    assert_eq!(reaped, pid as i32);
    assert_eq!(std::process::ExitStatus::from_raw(status).signal(), Some(libc::SIGKILL));
    assert!(!program_ran(cmd, reader));
}

/// A child killed before it reports, with a copy of its end held, and a watch that fails as
/// `fault` says: the parent still forces EOF, so the spawn does not wait on the holder. Returns the
/// spawn's error text. The child is reaped here when the watch left it unreaped.
fn killed_child_with_a_failing_watch(fault_kind: fault::WatchFault) -> String {
    let (mut cmd, reader) = marker_command();
    fault::reset_leaked_pid();
    let holder = fault::arm_fork_holder();
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let watch = fault::fail_watch(fault_kind);
    let probes = fault::arm_end_probes();
    let err = cmd.spawn().err();
    drop(probes);
    drop(watch);
    drop(armed);
    let ends = fault::take_ends();
    drop(holder);

    let ends = assert_ends_closed(ends, &format!("a killed child, a held copy and {fault_kind:?}"));
    assert!(
        ends.eof_forced,
        "{fault_kind:?}: only a forced EOF reaches the helper through the copy"
    );
    let err = err
        .expect("a child killed before it reports fails the spawn")
        .to_string();
    if let Some(Some(pid)) = fault::take_leaked_pid() {
        // SAFETY: `pid` is this thread's own zombie child, so waiting on it is sound.
        let reaped = unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), 0) };
        assert_eq!(reaped, pid as i32);
    }
    assert!(!program_ran(cmd, reader));
    err
}

/// A watch that cannot be opened or moved forces EOF and names its cause, whatever the cause.
///
/// Mutants: any such failure (open, move, peek or poll) only warns and returns "keep waiting" (the spawn then waits on the
/// holder, and the end probes shut the channel and report no forced EOF).
#[skuld::test]
fn a_watch_that_cannot_be_set_up_forces_eof_and_names_the_cause() {
    for fault_kind in [
        fault::WatchFault::Open(Errno::MFILE),
        fault::WatchFault::Open(Errno::NFILE),
        fault::WatchFault::Open(Errno::NOMEM),
        fault::WatchFault::Move(Errno::MFILE),
        fault::WatchFault::Peek(Errno::INVAL),
        // A same-user process lowering `RLIMIT_NOFILE` below 2 makes `poll` fail so.
        fault::WatchFault::Poll(Errno::INVAL),
    ] {
        let (fault::WatchFault::Open(errno)
        | fault::WatchFault::Move(errno)
        | fault::WatchFault::Peek(errno)
        | fault::WatchFault::Poll(errno)) = fault_kind;
        let said = killed_child_with_a_failing_watch(fault_kind);
        assert!(
            said.contains("its exit could not be watched") && said.contains(&errno.to_string()),
            "{fault_kind:?}: {said}"
        );
    }
}

/// A watch that finds the number names no child of this process (`ESRCH`; `ENOENT` or `EINVAL`
/// where a thread took it) means the child is gone: EOF is forced, and the death is the cause.
#[skuld::test]
fn a_number_that_names_no_child_forces_eof() {
    for errno in [Errno::SRCH, Errno::NOENT, Errno::INVAL] {
        let said = killed_child_with_a_failing_watch(fault::WatchFault::Open(errno));
        assert!(said.ends_with("died before it could send its pidfd"), "{errno}: {said}");
    }
}

/// A spawn that fails before any fork still ends the helper thread: `run` returns.
///
/// Mutant: the spawning thread keeps its copy of the child's end open (`run` hangs).
#[skuld::test]
fn a_spawn_that_fails_before_the_fork_ends_the_helper() {
    let (_std_cmd, pending) = raw_command("true");
    let guard = super::super::spawn_lock();
    let handshake = pending.open(&guard).expect("open");
    let probes = fault::arm_end_probes();
    let result = handshake.run(|| Err::<std::process::Child, _>(std::io::Error::other("failed before the fork")));
    drop(probes);
    assert_ends_closed(fault::take_ends(), "a spawn that fails before the fork");
    drop(guard);

    match result {
        Err(SpawnFailure::NotStarted(Error::Io(e))) => assert_eq!(e.to_string(), "failed before the fork"),
        other => panic!("expected the spawn's own error, got {:?}", other.err()),
    }
}

/// The helper has run to its end when `run` returns: it is joined, not detached.
///
/// Mutant: the helper is detached (a `thread::spawn` that is never joined). The probe holds the
/// helper at its very end until the join point opens its gate, so an unjoined helper is never
/// released and never finishes.
#[skuld::test]
fn the_helper_is_joined_before_the_spawn_returns() {
    let (mut cmd, reader) = marker_command();
    let probe = fault::arm_helper_probe();
    let child = cmd.spawn().expect("spawn");
    assert!(
        probe.finished(),
        "the helper thread must be joined before spawn returns"
    );
    assert!(child.wait().expect("wait").success());
    assert!(program_ran(cmd, reader));
}

/// A panic on the spawning thread after `spawn()` returned still fires the wait-over hook, which
/// releases what a test holds for the wait (the closed-stdio child's gate).
///
/// Mutant: the hook fires only on the normal path (a panic leaves the held child gated, and the
/// scope joins a helper that waits for it).
#[skuld::test]
fn a_panic_after_the_spawn_still_fires_the_wait_over_hook() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let (mut cmd, _reader) = marker_command();
    let fired = Rc::new(std::cell::Cell::new(false));
    let after = fault::after_spawn_returns_do(|_| panic!("the after-spawn hook panicked on purpose"));
    let over = fault::wait_over_do({
        let fired = Rc::clone(&fired);
        move || fired.set(true)
    });
    let result = catch_unwind(AssertUnwindSafe(|| cmd.spawn().err()));
    drop(over);
    drop(after);

    assert!(result.is_err(), "the hook's panic goes on");
    assert!(fired.get(), "the wait-over hook must fire on the way out");
}

/// A panic on the spawning thread still opens the helper probe's gate, so the join does not hang.
///
/// Mutant: the gate opens only at the join (a panic before it leaves the helper held at its end,
/// and the scope waits for it).
#[skuld::test]
fn a_panic_after_the_spawn_still_opens_the_helper_probe() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let (mut cmd, _reader) = marker_command();
    let probe = fault::arm_helper_probe();
    let after = fault::after_spawn_returns_do(|_| panic!("the after-spawn hook panicked on purpose"));
    let result = catch_unwind(AssertUnwindSafe(|| cmd.spawn().err()));
    drop(after);

    assert!(result.is_err(), "the hook's panic goes on");
    assert!(probe.finished(), "the helper must have run to its end");
    let unwound = fault::take_unwound().expect("the run unwound");
    assert_eq!(
        unwound.probe_open,
        Some(true),
        "the probe's gate must be open by the time the unwind guards are done, not at the join"
    );
}

/// A panic on the spawning thread after the fork, with a forked copy of the child's end held,
/// forces EOF before the scope joins the helper: the unwind does not wait on the holder.
///
/// Mutant: no forced EOF on unwind (the helper waits on the copy; the unwind checks shut the
/// channel and record that EOF was not reached).
#[skuld::test]
fn a_panic_after_the_spawn_forces_eof_through_a_held_copy() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let (mut cmd, _reader) = marker_command();
    let holder = fault::arm_fork_holder();
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let after = fault::after_spawn_returns_do(|_| panic!("the after-spawn hook panicked on purpose"));
    let result = catch_unwind(AssertUnwindSafe(|| cmd.spawn().err()));
    drop(after);
    drop(armed);
    let unwound = fault::take_unwound();
    drop(holder);

    assert!(result.is_err(), "the hook's panic goes on");
    assert_eq!(
        unwound.map(|u| u.eof_reached),
        Some(true),
        "the helper must read EOF by the time the unwind guards are done"
    );
}

/// A panic while the helper may still wait on a holder (here from the wait's own hook, with the
/// poll faulted so the wait is reached) still forces EOF: the unwind guard covers the whole wait,
/// not only the after-spawn hook.
///
/// Mutant: the guard is disarmed once the after-spawn hook has run.
#[skuld::test]
fn a_panic_inside_the_wait_forces_eof_through_a_held_copy() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let (mut cmd, _reader) = marker_command();
    let holder = fault::arm_fork_holder();
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let watch = fault::fail_watch(fault::WatchFault::Poll(Errno::INVAL));
    let before = fault::before_awaiting_the_child_do(|| panic!("the wait's hook panicked on purpose"));
    let result = catch_unwind(AssertUnwindSafe(|| cmd.spawn().err()));
    drop(before);
    drop(watch);
    drop(armed);
    let unwound = fault::take_unwound();
    drop(holder);

    assert!(result.is_err(), "the hook's panic goes on");
    assert_eq!(
        unwound.map(|u| u.eof_reached),
        Some(true),
        "the helper must read EOF by the time the unwind guards are done"
    );
}

// Pid namespaces =====

/// A private procfs of this pid namespace on `/proc`: where `/proc/sys` is read-only (a container
/// without `systempaths=unconfined`), `ns_last_pid` cannot be written through the inherited one.
fn own_procfs() {
    ns::enter_private_mount_ns();
    ns::mount_proc(std::path::Path::new("/proc"));
}

/// The child dies after it sent its pidfd; a foreign reaper reaps it, and the number goes to
/// another child of this process before the parent acts on the report. The pidfd names the dead
/// child, never the reuser: the reuser is left untouched.
///
/// Mutant: the child sends its pid number, and the parent opens a pidfd on that number (it opens
/// the reuser, then kills and reaps it as the child that never ran).
#[skuld::test]
fn namespaces_a_reused_number_never_reaches_the_handshake(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_reused_number_driver));
}

#[skuld::test]
fn fixture_reused_number_driver() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_reused_number_init));
}

/// Pid 1 of a fresh pid namespace, where only this fixture allocates numbers.
#[skuld::test]
fn fixture_reused_number_init() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    own_procfs();
    let (mut cmd, reader) = marker_command();
    let reuser: Rc<RefCell<Option<std::process::Child>>> = Rc::default();
    let armed = fault::arm_child_fault(ChildFault::SigkillAfterReport);
    let held = fault::hold_verdict_until_spawn_returns({
        let reuser = Rc::clone(&reuser);
        move |pid| {
            let pid = pid.expect("the spawned child's pid");
            // A foreign reaper: the child is dead of its own SIGKILL.
            let mut status = 0;
            // SAFETY: `pid` is this thread's own child, dead and unreaped.
            let reaped = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
            assert_eq!(
                reaped,
                pid as i32,
                "reap the child: {}",
                std::io::Error::last_os_error()
            );
            ns::set_last_pid(pid - 1);
            #[allow(clippy::disallowed_methods, reason = "the enclosing cosca spawn holds spawn_lock")]
            let next = std::process::Command::new("cat")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("spawn the reuser");
            assert_eq!(
                next.id(),
                pid,
                "precondition: the reuser takes the reaped child's number"
            );
            *reuser.borrow_mut() = Some(next);
        }
    });
    let err = cmd.spawn().err();
    drop(held);
    drop(armed);

    let mut reuser = reuser.borrow_mut().take().expect("the verdict hook ran");
    let untouched = reuser.try_wait();
    assert!(
        matches!(untouched, Ok(None)),
        "the reuser of the number must be neither signalled nor reaped, got {untouched:?}"
    );
    let err = err.expect("a child that never ran the program must fail the spawn");
    assert!(
        err.to_string().ends_with("died before exec: the program never ran"),
        "{err}"
    );
    reuser.kill().expect("kill the reuser");
    reuser.wait().expect("reap the reuser");
    assert!(!program_ran(cmd, reader));
}

/// A child dies before it reports; a foreign reaper reaps it, and its number goes to another
/// running child of this process, all before the parent looks at the child. Nothing holds a copy of
/// the child's end, so the helper reads EOF when the child dies, and the spawn returns at once
/// instead of waiting for the reuser to exit.
///
/// Mutant: the spawning thread keeps its copy of the child's end past `spawn()` (the probe finds it
/// held; without the probe the spawn blocks until the reuser exits).
#[skuld::test]
fn namespaces_a_reused_number_never_holds_the_spawn_when_the_child_dies_unreported(
    #[fixture(namespaces)] _group: &Group,
) {
    ns::run(fixture_path!(fixture_unreported_death_driver));
}

#[skuld::test]
fn fixture_unreported_death_driver() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_unreported_death_init));
}

/// Pid 1 of a fresh pid namespace, where only this fixture allocates numbers.
#[skuld::test]
fn fixture_unreported_death_init() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    own_procfs();
    let (mut cmd, reader) = marker_command();
    fault::reset_leaked_pid();
    let reuser: Rc<RefCell<Option<std::process::Child>>> = Rc::default();
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let probes = fault::arm_end_probes();
    let after = fault::after_spawn_returns_do({
        let reuser = Rc::clone(&reuser);
        move |pid| {
            let pid = pid.expect("the spawned child's pid");
            // A foreign reaper: the child is dead of its own SIGKILL.
            // SAFETY: `pid` is this thread's own child, which kills itself.
            let reaped = unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), 0) };
            assert_eq!(
                reaped,
                pid as i32,
                "reap the child: {}",
                std::io::Error::last_os_error()
            );
            ns::set_last_pid(pid - 1);
            #[allow(clippy::disallowed_methods, reason = "the enclosing cosca spawn holds spawn_lock")]
            let next = std::process::Command::new("cat")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("spawn the reuser");
            assert_eq!(
                next.id(),
                pid,
                "precondition: the reuser takes the reaped child's number"
            );
            *reuser.borrow_mut() = Some(next);
        }
    });
    let err = cmd.spawn().err();
    drop(after);
    drop(probes);
    drop(armed);

    let mut reuser = reuser.borrow_mut().take().expect("the after-spawn hook ran");
    let running = reuser.try_wait();
    // Before anything else: the reuser must still be running, so the spawn did not wait for it.
    let ends = fault::take_ends();
    reuser.kill().expect("kill the reuser");
    reuser.wait().expect("reap the reuser");
    assert!(
        matches!(running, Ok(None)),
        "the spawn returned only once the reuser exited: {running:?}"
    );
    assert_ends_closed(ends, "a child that died before reporting");
    let err = err.expect("a child that died before reporting fails the spawn");
    assert_eq!(
        err.to_string(),
        format!(
            "the spawned child (pid {}) died before it could send its pidfd",
            reuser.id()
        )
    );
    assert!(!program_ran(cmd, reader));
}

/// A panic in the verdict hook fails the test; it does not leave the helper parked at the hold
/// where the scope waits for it.
///
/// Mutant: the gate is opened only after the hook returns. This test then hangs, bounded by the
/// nextest override; `the_verdict_hook_runs_under_a_guard_that_opens_the_hold` fails at once.
#[skuld::test]
#[should_panic(expected = "the verdict hook panicked on purpose")]
fn a_panicking_verdict_hook_fails_the_spawn_instead_of_hanging_it() {
    let (mut cmd, _reader) = marker_command();
    let armed = fault::arm_child_fault(ChildFault::SigkillAfterReport);
    let held = fault::hold_verdict_until_spawn_returns(|_| panic!("the verdict hook panicked on purpose"));
    drop(cmd.spawn());
    drop(held);
    drop(armed);
}

/// The verdict hook runs while a guard that opens the held verdict on unwind is live. This is the
/// fast twin of the test above: without the guard, that one can only hang.
///
/// Mutant: the gate is opened only after the hook returns.
#[skuld::test]
fn the_verdict_hook_runs_under_a_guard_that_opens_the_hold() {
    let (mut cmd, _reader) = marker_command();
    let guarded = Rc::new(Cell::new(None));
    let armed = fault::arm_child_fault(ChildFault::SigkillAfterReport);
    let held = fault::hold_verdict_until_spawn_returns({
        let guarded = Rc::clone(&guarded);
        move |_| guarded.set(Some(fault::verdict_guarded()))
    });
    drop(cmd.spawn());
    drop(held);
    drop(armed);

    assert_eq!(guarded.get(), Some(true), "the hook ran, under the guard");
    assert!(!fault::verdict_guarded(), "the guard is gone once the spawn returns");
}

/// A thread that unshared its pid namespace for children cannot start threads, so it cannot run
/// the handshake: the spawn fails before any fork, naming that cause.
#[skuld::test]
fn namespaces_a_spawn_from_a_thread_that_unshared_its_pid_namespace_names_the_cause(
    #[fixture(namespaces)] _group: &Group,
) {
    ns::run(fixture_path!(fixture_unshared_thread));
}

#[skuld::test]
fn fixture_unshared_thread() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    let Err(err) = cmd.spawn() else {
        panic!("the spawn must fail");
    };
    assert!(
        err.to_string().starts_with(
            "starting the pidfd handshake thread (Linux refuses new threads to a thread that has \
             unshared or entered a pid or time namespace for its children"
        ),
        "{err}"
    );
    assert_eq!(fault::spawns(), 0, "nothing may be forked");
    assert!(!program_ran(cmd, reader));
}

// The helper's own steps =====

/// A report read from a socketpair, through `help`, with `seams`.
fn help_with_report(seams: &fault::HelperSeams) -> Outcome {
    let (parent_end, child_end) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("socketpair");
    let pidfd = rustix::process::pidfd_open(rustix::process::getpid(), rustix::process::PidfdFlags::empty())
        .expect("a pidfd on this process");
    super::send_report(
        std::os::fd::AsRawFd::as_raw_fd(&child_end),
        REPORT_PIDFD,
        0,
        std::os::fd::AsRawFd::as_raw_fd(&pidfd),
    )
    .expect("send the report");
    drop(pidfd);
    super::help(&parent_end, seams)
}

/// A pidfd whose move above the stdio slots fails is still the child's pidfd: it is handed on, so
/// the child can be reaped through it.
///
/// Mutant: the pidfd is dropped when its move fails.
#[skuld::test]
fn a_pidfd_that_cannot_move_above_stdio_is_still_handed_on() {
    let seams = fault::HelperSeams::failing_move(Errno::MFILE);
    match help_with_report(&seams) {
        Outcome::Failed(Error::Io(e), Some(_)) => assert_eq!(e.raw_os_error(), Some(libc::EMFILE), "{e:?}"),
        Outcome::Failed(e, pidfd) => panic!("expected EMFILE with the pidfd, got {e:?}, pidfd {}", pidfd.is_some()),
        _ => panic!("a failed move must fail the spawn"),
    }
}

/// A child left unreaped is worded by why, not always as a death before its report.
#[skuld::test]
fn an_abandoned_child_is_worded_by_its_cause() {
    struct Recorder(std::rc::Rc<RefCell<Option<String>>>);
    impl super::Spawned for Recorder {
        const ERR_PROVES_NO_EXEC: bool = true;

        fn pid(&self) -> Option<u32> {
            Some(4)
        }
        fn reap_unexecuted(self, _: OwnedFd) {
            panic!("there is no pidfd to reap through");
        }
        fn abandon_unreported(self, why: &str) {
            *self.0.borrow_mut() = Some(why.to_string());
        }
    }

    let said = std::rc::Rc::new(RefCell::new(None));
    let failed = Outcome::Failed(Error::Io(std::io::Error::other("the report was cut short")), None);
    let err = super::conclude(Ok(Recorder(Rc::clone(&said))), failed, super::LeftFront::NotAFront).err();
    assert_eq!(
        err.map(|e| e.expect_not_started().to_string()).as_deref(),
        Some("the report was cut short")
    );
    let why = said.borrow_mut().take().expect("the child was abandoned");
    assert!(
        why.contains("the report was cut short") && !why.contains("died"),
        "{why}"
    );

    super::conclude(
        Ok(Recorder(Rc::clone(&said))),
        Outcome::NoReport,
        super::LeftFront::NotAFront,
    )
    .err();
    let why = said.borrow_mut().take().expect("the child was abandoned");
    assert!(why.contains("died before it sent its pidfd"), "{why}");
}

/// A child dies before it reports and a foreign reaper reaps it, a copy of its end is held, and the
/// number goes to a THREAD of this process: the watch finds no thread-group leader (`ENOENT` or
/// `EINVAL`, by kernel), so the child is gone and EOF is forced. The spawn does not wait on the
/// holder.
///
/// Mutant: only `ESRCH` means gone (the spawn waits on the holder; the end probes shut the channel
/// and report no forced EOF).
#[skuld::test]
fn namespaces_a_thread_taking_the_number_never_holds_the_spawn(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_thread_reuse_driver));
}

#[skuld::test]
fn fixture_thread_reuse_driver() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_thread_reuse_init));
}

/// Pid 1 of a fresh pid namespace, where only this fixture allocates numbers.
#[skuld::test]
fn fixture_thread_reuse_init() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    own_procfs();
    let (mut cmd, reader) = marker_command();
    fault::reset_leaked_pid();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let (tid_tx, tid_rx) = std::sync::mpsc::channel::<u32>();
    let reuser: Rc<RefCell<Option<std::thread::JoinHandle<()>>>> = Rc::default();
    let holder = fault::arm_fork_holder();
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let probes = fault::arm_end_probes();
    let after = fault::after_spawn_returns_do({
        let reuser = Rc::clone(&reuser);
        move |pid| {
            let pid = pid.expect("the spawned child's pid");
            // A foreign reaper: the child is dead of its own SIGKILL.
            // SAFETY: `pid` is this thread's own child, which kills itself.
            let reaped = unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), 0) };
            assert_eq!(
                reaped,
                pid as i32,
                "reap the child: {}",
                std::io::Error::last_os_error()
            );
            ns::set_last_pid(pid - 1);
            let thread = std::thread::spawn(move || {
                // SAFETY: `gettid` takes no arguments.
                let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
                tid_tx.send(tid).expect("report the thread's id");
                // Alive until the test is done: the number stays taken.
                _ = stop_rx.recv();
            });
            assert_eq!(
                tid_rx.recv().expect("the thread's id"),
                pid,
                "precondition: the thread takes the reaped child's number"
            );
            *reuser.borrow_mut() = Some(thread);
        }
    });
    let err = cmd.spawn().err();
    drop(after);
    drop(probes);
    drop(armed);
    let ends = fault::take_ends();
    drop(holder);
    drop(stop_tx);
    reuser
        .borrow_mut()
        .take()
        .expect("the after-spawn hook ran")
        .join()
        .expect("join the thread");

    let ends = assert_ends_closed(ends, "a thread that took a reaped child's number");
    assert!(ends.eof_forced, "a number that names no leader means the child is gone");
    let pid = fault::take_leaked_pid()
        .expect("the unreaped child is named")
        .expect("it has a pid");
    assert_eq!(
        err.expect("a child that died before reporting fails the spawn")
            .to_string(),
        format!("the spawned child (pid {pid}) died before it could send its pidfd")
    );
    assert!(!program_ran(cmd, reader));
}

/// An `open` that fails before the channel is published leaves it dead: spawning the command anyway
/// fails in the gate, not in a hook that reads numbers that now belong to something else.
///
/// Mutant: `open` publishes the ends before it makes its done fd.
#[skuld::test]
fn a_failed_open_leaves_no_numbers_live() {
    let mut cmd = std::process::Command::new("true");
    let pending = super::register(&mut cmd);
    let guard = crate::child::spawn::spawn_lock();
    let armed = fault::fail_done_fd(Errno::MFILE);
    let opened = pending.open(&guard);
    drop(armed);
    assert!(opened.is_err(), "the forced failure fails the open");
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `guard`")]
    let spawned = cmd.spawn();
    assert_eq!(spawned.expect_err("never published").raw_os_error(), Some(libc::EBADF));
}

/// A child of a failed spawn, for `conclude`'s arms that never reach it. `TOKIO` stands for
/// tokio's spawn, whose failure does not prove the program never ran, rather than std's.
struct NoChild<const TOKIO: bool = true>;

impl<const TOKIO: bool> super::Spawned for NoChild<TOKIO> {
    const ERR_PROVES_NO_EXEC: bool = !TOKIO;

    fn pid(&self) -> Option<u32> {
        None
    }
    fn reap_unexecuted(self, _: OwnedFd) {
        panic!("no child was handed back");
    }
    fn abandon_unreported(self, _: &str) {
        panic!("no child was handed back");
    }
}

/// The front `sudo` leaves, left to the handshake.
fn sudo_front() -> super::LeftFront {
    super::LeftFront::Here(
        crate::elevation::front::front(Some(&crate::elevation::ElevatedVia::Wrapped(
            crate::elevation::Backend::Sudo,
        )))
        .expect("sudo leaves a front"),
    )
}

/// A `cat` whose stdin this test holds, and a pidfd naming it.
fn cat_with_pidfd() -> (std::process::Child, OwnedFd) {
    let cat = crate::test_spawn::spawn(std::process::Command::new("cat").stdin(std::process::Stdio::piped()))
        .expect("spawn cat");
    let pid = rustix::process::Pid::from_raw(cat.id() as i32).expect("a positive pid");
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open");
    (cat, pidfd)
}

/// A front tokio dropped after it ran the program is sent nothing and left, and the error says so.
#[skuld::test]
fn a_dropped_front_is_left_and_noted() {
    let (mut cat, pidfd) = cat_with_pidfd();
    let (err, fate) = super::conclude(
        Err::<NoChild, _>(std::io::Error::other("tokio failed")),
        Outcome::Opened(pidfd),
        sudo_front(),
    )
    .err()
    .expect("the spawn fails")
    .expect_may_have_started_with();
    assert_eq!(
        fate,
        ChildFate::Running { id: None },
        "a front is left running, its identity unread"
    );
    let text = err.to_string();
    assert!(text.contains("the spawned child is what sudo left"), "{text}");
    assert!(text.contains("it is left unreaped"), "{text}");
    drop(cat.stdin.take());
    assert!(cat.wait().expect("wait").success(), "the front was signalled");
}

/// A front std already collected never ran the program: it is torn down, with no note.
#[skuld::test]
fn a_collected_front_is_no_front() {
    let (mut cat, pidfd) = cat_with_pidfd();
    drop(cat.stdin.take());
    cat.wait().expect("collect the child");
    let (err, fate) = super::conclude(
        Err::<NoChild, _>(std::io::Error::other("exec failed")),
        Outcome::Opened(pidfd),
        sudo_front(),
    )
    .err()
    .expect("the spawn fails")
    .expect_may_have_started_with();
    assert_eq!(fate, ChildFate::Gone, "std had collected it");
    assert!(!err.to_string().contains("what sudo left"), "{err}");
}

/// A child that died before it was told to go never ran the program: it is reaped, with no note.
#[skuld::test]
fn a_front_gone_before_its_go_is_no_front() {
    let (mut cat, pidfd) = cat_with_pidfd();
    let pid = cat.id();
    cat.kill().expect("kill the child");
    crate::test_child::wait_until_zombie(pid);
    let err = super::conclude(
        Err::<NoChild, _>(std::io::Error::other("killed on its way")),
        Outcome::Gone(pidfd),
        sudo_front(),
    )
    .err()
    .expect("the spawn fails")
    .expect_not_started();
    assert!(!err.to_string().contains("what sudo left"), "{err}");
    assert_eq!(crate::child::front_kill_tests::reap(pid), None, "the teardown reaps it");
}

/// A dropped front whose pidfd cannot be peeked is taken to be there still: sent nothing, and left.
#[skuld::test]
fn an_unpeekable_dropped_front_is_left_and_noted() {
    let (mut cat, pidfd) = cat_with_pidfd();
    let _unpeekable = crate::wait::exit_only::seams::force_peek_once(Err(std::io::Error::from_raw_os_error(libc::EIO)));
    let (err, fate) = super::conclude(
        Err::<NoChild, _>(std::io::Error::other("tokio failed")),
        Outcome::Opened(pidfd),
        sudo_front(),
    )
    .err()
    .expect("the spawn fails")
    .expect_may_have_started_with();
    assert_eq!(
        fate,
        ChildFate::Running { id: None },
        "a front that cannot be peeked is taken to be there"
    );
    assert!(err.to_string().contains("the spawned child is what sudo left"), "{err}");
    drop(cat.stdin.take());
    assert!(cat.wait().expect("wait").success(), "the front was signalled");
}

/// A front spawned for a cgroup leaf and dropped by tokio after its fork is the leaf's to answer
/// for: the handshake stashes its pidfd for the leaf, signals and waits on nothing, and returns the
/// error as it came, with no note of the front's fate. Mutants: "the arm tears the child down",
/// "the arm notes the front", "the arm drops the pidfd".
#[skuld::test]
fn a_front_left_to_its_leaf_keeps_its_pidfd_and_is_sent_nothing() {
    use std::os::fd::AsRawFd as _;

    let (mut cat, pidfd) = cat_with_pidfd();
    let raw = pidfd.as_raw_fd();
    let left: super::LeftPidfd = Rc::new(Cell::new(None));
    let (err, fate) = super::conclude(
        Err::<NoChild, _>(std::io::Error::other("tokio failed")),
        Outcome::Opened(pidfd),
        super::LeftFront::ToLeaf(Rc::clone(&left)),
    )
    .err()
    .expect("the spawn fails")
    .expect_may_have_started_with();
    assert_eq!(
        err.to_string(),
        Error::Io(std::io::Error::other("tokio failed")).to_string()
    );
    assert_eq!(
        fate,
        ChildFate::Unknown,
        "the leaf's abandonment answers, not the handshake"
    );
    let stashed = left.take().expect("the pidfd is left for the leaf");
    assert_eq!(stashed.as_raw_fd(), raw, "the pidfd it was given");
    // Not signalled and not waited on: closing its stdin ends it with status 0, and it was not
    // reaped before this wait.
    drop(cat.stdin.take());
    assert!(cat.wait().expect("wait").success(), "the front was signalled");
}

/// Only a child told to go can run the program, so every arm of `conclude` but one answers that it
/// did not start: a failed `spawn` after the child was told to go, from a spawn whose error does not
/// prove that it failed before `exec` (tokio's). std's does, so its answer there is `not started`.
/// `conclude_answers_every_remaining_pair` drives the pairs this leaves.
///
/// Mutant: any one arm's answer flipped, or the `Opened` arm's answer not taken from the spawn.
#[skuld::test]
fn conclude_answers_whether_the_program_could_have_started() {
    let io = |what: &str| std::io::Error::other(what.to_string());
    let failed = |what: &str| Error::Io(io(what));
    let answered = |result: Result<super::Held<NoChild>, SpawnFailure>| result.err().expect("the spawn fails");

    // Told to go, then the spawn failed: tokio's may have failed after `exec`, std's did not.
    let (_cat, pidfd) = cat_with_pidfd();
    let (_, fate) = answered(super::conclude(
        Err::<NoChild, _>(io("tokio")),
        Outcome::Opened(pidfd),
        super::LeftFront::NotAFront,
    ))
    .expect_may_have_started_with();
    // A live child tokio dropped is killed and reaped through the pidfd.
    assert_eq!(fate, crate::error::ChildFate::Reaped);
    let (_cat, pidfd) = cat_with_pidfd();
    super::conclude(
        Err::<NoChild<false>, _>(io("std")),
        Outcome::Opened(pidfd),
        super::LeftFront::NotAFront,
    )
    .err()
    .expect("the spawn fails")
    .expect_not_started();

    // Never told to go.
    let (mut cat, pidfd) = cat_with_pidfd();
    cat.kill().expect("kill the child");
    crate::test_child::wait_until_zombie(cat.id());
    answered(super::conclude(
        Err::<NoChild, _>(io("gone")),
        Outcome::Gone(pidfd),
        super::LeftFront::NotAFront,
    ))
    .expect_not_started();
    answered(super::conclude(
        Err::<NoChild, _>(io("x")),
        Outcome::Failed(failed("helper"), None),
        super::LeftFront::NotAFront,
    ))
    .expect_not_started();
    answered(super::conclude(
        Err::<NoChild, _>(io("x")),
        Outcome::NoReport,
        super::LeftFront::NotAFront,
    ))
    .expect_not_started();
    answered(super::conclude(
        Err::<NoChild, _>(io("x")),
        Outcome::Unwatched("cause".into()),
        super::LeftFront::NotAFront,
    ))
    .expect_not_started();
    let (cat, pidfd) = cat_with_pidfd();
    super::conclude(Ok(cat), Outcome::Gone(pidfd), super::LeftFront::NotAFront)
        .err()
        .expect("the spawn fails")
        .expect_not_started();
    let (cat, pidfd) = cat_with_pidfd();
    super::conclude(
        Ok(cat),
        Outcome::Failed(failed("helper"), Some(pidfd)),
        super::LeftFront::NotAFront,
    )
    .err()
    .expect("the spawn fails")
    .expect_not_started();
    assert_no_child_of_this_thread("every cat is reaped through its pidfd");
}

/// The pairs of `conclude_answers_whether_the_program_could_have_started` leaves: a spawn that
/// returned a child with no go (`Failed`, `NoReport`, `Unwatched`) fails it as not started, the helper's
/// own error standing; a spawn that returned a child told to go carries on; and a spawn that failed
/// while the helper had failed too, with a pidfd, reaps the child it names. Together they drive all
/// twelve `(spawned, outcome)` pairs.
///
/// Mutant: any of these arms answers that the program may have started, or the carry-on arm fails.
#[skuld::test]
fn conclude_answers_every_remaining_pair() {
    let io = |what: &str| std::io::Error::other(what.to_string());
    let failed = |what: &str| Error::Io(io(what));
    // A `cat` that has already ended, so a child an arm abandons leaves nothing running.
    let ended_cat = || {
        let (mut cat, pidfd) = cat_with_pidfd();
        drop(cat.stdin.take());
        crate::test_child::wait_until_zombie(cat.id());
        (cat, pidfd)
    };

    // Told to go, and the spawn succeeded: it carries on.
    let (cat, pidfd) = ended_cat();
    let held = super::conclude(Ok(cat), Outcome::Opened(pidfd), super::LeftFront::NotAFront)
        .expect("a child told to go is held");
    let mut cat = held.child;
    cat.wait().expect("collect the child");

    // Never told to go, and the spawn succeeded anyway: the helper's error stands, not started.
    let (cat, _pidfd) = ended_cat();
    let error = super::conclude(
        Ok(cat),
        Outcome::Failed(failed("helper"), None),
        super::LeftFront::NotAFront,
    )
    .err()
    .expect("the spawn fails")
    .expect_not_started();
    assert!(matches!(&error, Error::Io(e) if e.to_string() == "helper"), "{error:?}");
    let (cat, _pidfd) = ended_cat();
    let error = super::conclude(Ok(cat), Outcome::NoReport, super::LeftFront::NotAFront)
        .err()
        .expect("the spawn fails")
        .expect_not_started();
    assert!(
        matches!(&error, Error::Io(e) if e.to_string().contains("died before it could send its pidfd")),
        "{error:?}"
    );
    let (cat, _pidfd) = ended_cat();
    let error = super::conclude(Ok(cat), Outcome::Unwatched("cause".into()), super::LeftFront::NotAFront)
        .err()
        .expect("the spawn fails")
        .expect_not_started();
    assert!(
        matches!(&error, Error::Io(e) if e.to_string().contains("its exit could not be watched (cause)")),
        "{error:?}"
    );

    // The spawn failed while the helper had failed too, with the child's pidfd: it is reaped.
    let (cat, pidfd) = cat_with_pidfd();
    let mut cat = cat;
    drop(cat.stdin.take());
    cat.wait().expect("collect the child");
    let error = super::conclude(
        Err::<NoChild, _>(io("spawn")),
        Outcome::Failed(failed("helper"), Some(pidfd)),
        super::LeftFront::NotAFront,
    )
    .err()
    .expect("the spawn fails")
    .expect_not_started();
    assert!(matches!(&error, Error::Io(e) if e.to_string() == "helper"), "{error:?}");
}
