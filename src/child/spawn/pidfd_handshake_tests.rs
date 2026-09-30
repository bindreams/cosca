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
use super::{classify_send, parse_report, Delivery, Report, REPORT_ERRNO, REPORT_LEN, REPORT_PIDFD};
use crate::command::Command;
use crate::error::Error;
use crate::stdio::Stdio;
use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;

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

// Normal spawns =====

/// Mutant: a handshake that leaves the child held forever (the spawn hangs) or aborts it.
#[test]
fn a_normal_spawn_runs_the_program_and_forks_once() {
    let (mut cmd, reader) = marker_command();
    fault::reset_spawns();
    let child = cmd.spawn().expect("a normal spawn succeeds");
    assert_eq!(fault::spawns(), 1);
    assert!(child.wait().expect("wait").success());
    assert_no_child_of_this_thread("after the wait");
    assert!(program_ran(cmd, reader));
}

// The pre-fork probe =====

/// A refusal before the fork is `Unsupported` naming `spawn`, and no child is ever forked.
///
/// Mutant: the probe is skipped (the refusal then lands after the fork, so `spawns()` is 1).
#[test]
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
#[test]
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
#[test]
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
#[test]
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
#[test]
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
#[test]
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
#[test]
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
#[test]
fn a_child_gone_before_its_go_ahead_fails_the_spawn_and_is_reaped() {
    let (mut cmd, reader) = marker_command();
    let armed = fault::arm_child_fault(ChildFault::SigkillAfterReport);
    let held = fault::hold_verdict_until_spawn_returns(|_| {});
    let err = cmd.spawn().err();
    drop(held);
    drop(armed);

    let err = err.expect("a child that never ran the program must fail the spawn");
    assert!(
        err.to_string().ends_with("died before exec: the program never ran"),
        "{err}"
    );
    assert_no_child_of_this_thread("the child is reaped through its pidfd");
    assert!(!program_ran(cmd, reader));
}

// Failures after the fork =====

/// tokio can fail a spawn after std's succeeded, dropping the child neither killed nor reaped:
/// the handshake kills and reaps it through the pidfd it sent.
///
/// Mutant: the pidfd is dropped when the spawn fails.
#[test]
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
        Err(Error::Io(e)) => assert_eq!(e.to_string(), "post-fork failure (test)"),
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
#[test]
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
        Err(Error::Io(e)) => assert_eq!(e.raw_os_error(), Some(libc::EIO), "{e:?}"),
        other => panic!(
            "expected the hook's error, got {:?}",
            other.err().map(|e| e.to_string())
        ),
    }
    assert!(!fired.get(), "a child std collected must not be signalled");
    assert_no_child_of_this_thread("std collected the child");
}

// Deadlock paths =====

/// A child whose hook fails before it reports ends the helper at EOF, and the spawn reports the
/// child's error.
///
/// Mutant: the parent does not shut its end of the child's socket.
#[test]
fn a_child_that_fails_before_reporting_ends_the_spawn() {
    let (mut cmd, reader) = marker_command();
    let armed = fault::arm_child_fault(ChildFault::Fail);
    let err = cmd.spawn().err();
    assert_eq!(
        fault::child_end_shut(),
        Some(true),
        "the parent must shut the child's end once the spawn returns"
    );
    drop(armed);

    match err.expect("a child that fails before exec fails the spawn") {
        Error::Io(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO), "{e:?}"),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_no_child_of_this_thread("std collected the failed child");
    assert!(!program_ran(cmd, reader));
}

/// As above, with a process forked without `exec` holding a copy of the child's end: the helper
/// still reads EOF, because the end is shut, not just closed.
///
/// Mutant: the parent does not shut its end of the child's socket (the helper would wait forever
/// on the copy).
#[test]
fn eof_reaches_the_helper_through_a_forked_copy_of_the_childs_end() {
    let (mut cmd, reader) = marker_command();
    let holder = fault::arm_fork_holder();
    let armed = fault::arm_child_fault(ChildFault::Fail);
    let err = cmd.spawn().err();
    drop(armed);
    let shut = fault::child_end_shut();
    drop(holder);

    assert_eq!(
        shut,
        Some(true),
        "the parent must shut the child's end, whatever copies of it exist"
    );
    match err.expect("a child that fails before exec fails the spawn") {
        Error::Io(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO), "{e:?}"),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_no_child_of_this_thread("std collected the failed child");
    assert!(!program_ran(cmd, reader));
}

/// A child killed before it reports: std reads the closed status pipe as success, the helper
/// reads EOF. The child is dead, unreaped and pidless-to-us, so it is left unreaped and named,
/// and the spawn fails.
#[test]
fn a_child_killed_before_reporting_is_left_unreaped_and_named() {
    use std::os::unix::process::ExitStatusExt;

    let (mut cmd, reader) = marker_command();
    fault::reset_leaked_pid();
    let armed = fault::arm_child_fault(ChildFault::Sigkill);
    let err = cmd.spawn().err();
    drop(armed);

    let err = err.expect("a child killed before it reports fails the spawn");
    let pid = fault::take_leaked_pid()
        .expect("the unreaped child is named")
        .expect("it has a pid");
    assert!(matches!(err, Error::Io(_)), "{err:?}");
    // The test owns this cleanup: the pid is this thread's unreaped zombie.
    let mut status = 0;
    // SAFETY: `pid` is this thread's own zombie child, so waiting on it is sound.
    let reaped = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    assert_eq!(reaped, pid as i32);
    assert_eq!(std::process::ExitStatus::from_raw(status).signal(), Some(libc::SIGKILL));
    assert!(!program_ran(cmd, reader));
}

/// A spawn that fails before any fork still ends the helper thread: `run` returns.
///
/// Mutant: the parent does not shut its end of the child's socket (`run` hangs).
#[test]
fn a_spawn_that_fails_before_the_fork_ends_the_helper() {
    let (_std_cmd, pending) = raw_command("true");
    let guard = super::super::spawn_lock();
    let handshake = pending.open(&guard).expect("open");
    let result = handshake.run(|| Err::<std::process::Child, _>(std::io::Error::other("failed before the fork")));
    assert_eq!(
        fault::child_end_shut(),
        Some(true),
        "the parent must shut the child's end once the spawn returns"
    );
    drop(guard);

    match result {
        Err(Error::Io(e)) => assert_eq!(e.to_string(), "failed before the fork"),
        other => panic!("expected the spawn's own error, got {:?}", other.err()),
    }
}

/// The helper has run to its end when `run` returns: it is joined, not detached.
///
/// Mutant: the helper is detached (a `thread::spawn` that is never joined). The probe holds the
/// helper at its very end until the join point opens its gate, so an unjoined helper is never
/// released and never finishes.
#[test]
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

// Pid namespaces =====

/// The child dies after it sent its pidfd; a foreign reaper reaps it, and the number goes to
/// another child of this process before the parent acts on the report. The pidfd names the dead
/// child, never the reuser: the reuser is left untouched.
///
/// Mutant: the child sends its pid number, and the parent opens a pidfd on that number (it opens
/// the reuser, then kills and reaps it as the child that never ran).
#[test]
fn namespaces_a_reused_number_never_reaches_the_handshake() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_reused_number_driver));
}

#[test]
fn fixture_reused_number_driver() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_reused_number_init));
}

/// Pid 1 of a fresh pid namespace, where only this fixture allocates numbers.
#[test]
fn fixture_reused_number_init() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
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

/// A thread that unshared its pid namespace for children cannot start threads, so it cannot run
/// the handshake: the spawn fails before any fork, naming that cause.
#[test]
fn namespaces_a_spawn_from_a_thread_that_unshared_its_pid_namespace_names_the_cause() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_unshared_thread));
}

#[test]
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
