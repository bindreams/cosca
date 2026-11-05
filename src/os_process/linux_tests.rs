use std::time::Duration;

use crate::identity::ProcessId;
use crate::os_process::drive::exited_held;
use crate::os_process::{kill, open, terminate, terminate_by_id, Exit};
use crate::signal::{Sent, Sig};
use crate::test_child::{held_contained_blocker_without_cgroup, wait_until_zombie};
use crate::test_groups::{tracer_group, Group};

/// A live blocker, its stdin (held open so it stays alive) and its identity.
fn blocker() -> (crate::Child, std::io::PipeWriter, ProcessId) {
    let (child, stdin) = held_contained_blocker_without_cgroup(crate::Stdio::null());
    let id = child.id();
    (child, stdin, id)
}

#[skuld::test]
fn one_open_serves_look_signal_and_wait() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    assert!(matches!(p.exited().unwrap(), Exit::Running(_)));
    assert!(!exited_held(&*p, Some(Duration::ZERO)).unwrap());
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(exited_held(&*p, None).unwrap());
    child.wait().unwrap();
}

#[skuld::test]
fn open_after_reap_is_none() {
    let (child, _stdin, id) = blocker();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(open(id).unwrap().is_none());
}

#[skuld::test]
fn open_with_wrong_start_token_is_none_and_sends_nothing() {
    let (child, _stdin, id) = blocker();
    let other = ProcessId::from_parts_for_test(id.pid(), id.start_token_raw() + 1);
    assert!(open(other).unwrap().is_none());
    // Still running: the right identity opens and sees no exit.
    let p = open(id).unwrap().expect("the blocker is alive");
    assert!(!exited_held(&*p, Some(Duration::ZERO)).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[skuld::test]
fn exited_before_first_look_returns_true() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    wait_until_zombie(id.pid());
    assert!(exited_held(&*p, Some(Duration::ZERO)).unwrap());
    child.wait().unwrap();
}

/// Mutant: `ESRCH` is an error, or a reaped process is reported `Delivered`.
#[skuld::test]
fn signal_after_exit_is_gone() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Gone);
    // A reaped process reads as exited, too (POLLHUP).
    assert!(exited_held(&*p, Some(Duration::ZERO)).unwrap());
}

/// Mutant: a look hands out some other fd to wait on. The kernel names a pidfd's process in its
/// `fdinfo`.
#[skuld::test]
fn the_wait_is_on_the_pidfd_of_the_process() {
    use std::os::fd::AsRawFd;
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    match p.exited().unwrap() {
        Exit::Running(crate::os_process::WaitFor::Readable(fd)) => {
            let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
            assert!(
                info.lines().any(|line| line == format!("Pid:	{}", id.pid())),
                "not a pidfd of {}: {info}",
                id.pid()
            );
        }
        other => panic!("a live process reads Running(Readable): {other:?}"),
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Mutant: `terminate_by_id` sends `SIGKILL`.
#[skuld::test]
fn terminate_by_id_sends_sigterm_and_the_blocker_exits() {
    use std::os::unix::process::ExitStatusExt;
    let (child, _stdin, id) = blocker();
    terminate_by_id(id).unwrap();
    assert_eq!(
        child.wait().unwrap().signal(),
        Some(rustix::process::Signal::TERM.as_raw())
    );
}

#[skuld::test]
fn kill_sends_sigkill_and_the_blocker_exits() {
    use std::os::unix::process::ExitStatusExt;
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    kill(&*p).unwrap();
    assert_eq!(
        child.wait().unwrap().signal(),
        Some(rustix::process::Signal::KILL.as_raw())
    );
}

/// A held process that its owner has reaped is gone: both acts are `Ok`. Mutant: `ESRCH` is an
/// error.
#[skuld::test]
fn kill_and_terminate_of_a_held_process_that_is_gone_are_ok() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    child.wait().unwrap();
    kill(&*p).unwrap();
    terminate(&*p).unwrap();
}

#[skuld::test]
fn terminate_by_id_on_a_gone_process_is_ok() {
    let (child, _stdin, id) = blocker();
    let other = ProcessId::from_parts_for_test(id.pid(), id.start_token_raw() + 1);
    terminate_by_id(other).unwrap();
    let p = open(id).unwrap().expect("the blocker is alive");
    assert!(!exited_held(&*p, Some(Duration::ZERO)).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
    terminate_by_id(id).unwrap();
}

/// `Process::kill` promises the raw errno of a refused kill. Mutant: `signal` wraps the errno in
/// an `io_context`, so `raw_os_error()` is `None`.
#[skuld::test]
fn refused_signal_keeps_its_raw_errno() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    let refused = crate::signal::seams::refuse_kills();
    let err = p.signal(Sig::Kill).unwrap_err();
    drop(refused);
    let crate::error::Error::Io(e) = err else {
        panic!("expected Error::Io, got {err:?}");
    };
    assert_eq!(e.raw_os_error(), Some(libc::EPERM), "{e:?}");
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    child.kill().unwrap();
    child.wait().unwrap();
}

// OsChild =====

/// A reap of a running child hands out the child's own pidfd to wait on.
#[skuld::test]
fn try_reap_of_a_running_child_waits_on_its_pidfd() {
    use std::os::fd::AsRawFd;

    use crate::os_process::child::{adopted_blocker, TryReapOutcome};
    use crate::os_process::WaitFor;
    let (os, _id, stdin) = adopted_blocker();
    let TryReapOutcome::Running(WaitFor::Readable(fd)) = os.try_reap().unwrap() else {
        panic!("a running child is waited on its pidfd");
    };
    assert_eq!(fd.as_raw_fd(), os.os_handle().as_raw_fd());
    drop(stdin);
    assert!(exited_held(&*os, None).unwrap());
    assert!(matches!(os.try_reap().unwrap(), TryReapOutcome::Reaped(_)));
}

/// A reap of an exited child consumes its record once; the child is then foreign.
///
/// Mutant: a second reap hands the record out again, or answers `Running`.
#[skuld::test]
fn try_reap_of_an_exited_child_reaps_once_then_is_foreign() {
    use crate::os_process::child::{adopted_blocker, Foreign, TryReapOutcome};
    let (os, _id, stdin) = adopted_blocker();
    drop(stdin);
    assert!(exited_held(&*os, None).unwrap());
    assert!(matches!(os.try_reap().unwrap(), TryReapOutcome::Reaped(_)));
    assert!(matches!(os.try_reap().unwrap(), TryReapOutcome::Foreign(Foreign::Gone)));
}

/// A peek of an exited child sees its record and consumes nothing: the reap that follows has it.
///
/// Mutant: the peek is a consuming `waitid`.
#[skuld::test]
fn peek_of_an_exited_child_consumes_nothing() {
    use crate::os_process::child::{adopted_blocker, PeekOutcome, TryReapOutcome};
    let (os, _id, stdin) = adopted_blocker();
    drop(stdin);
    assert!(exited_held(&*os, None).unwrap());
    assert!(matches!(os.peek().unwrap(), PeekOutcome::Exit(_)));
    assert!(matches!(os.peek().unwrap(), PeekOutcome::Exit(_)));
    assert!(matches!(os.try_reap().unwrap(), TryReapOutcome::Reaped(_)));
}

/// A zombie only its tracer sees has a readable pidfd and no record: a reap asks for a recheck, not
/// for a wait on a pidfd that would return at once for ever. The tracer then hands the zombie back
/// and the reap has the record.
///
/// Mutant: the reap answers `Running(Readable)`, which spins its holder.
#[skuld::test]
fn try_reap_of_a_zombie_only_its_tracer_sees_is_recheck(#[fixture(tracer_group)] _group: &Group) {
    use std::os::fd::AsRawFd as _;

    use crate::os_process::child::{adopt_std, TryReapOutcome};
    use crate::test_child::reaped_elsewhere::kill_own_child;
    use crate::test_support::foreign_tracer::{self, REAP};

    let mut cmd = crate::test_child::held_std_killable_blocker();
    foreign_tracer::allow_any_tracer(&mut cmd);
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    let _stdin = child.stdin.take().expect("piped stdin");
    let id = ProcessId::of(child.id()).found().expect("identity");
    let os = adopt_std(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let mut tracer = foreign_tracer::spawn_helper(id.pid());
    // Setup: the test ends the tracee itself.
    kill_own_child(id.pid());
    // The exit, which the tracer alone can see: the pidfd turns readable.
    let mut fds = [libc::pollfd {
        fd: os.os_handle().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];
    loop {
        // SAFETY: `fds` is one valid `pollfd`.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 1, -1) };
        if r == 1 {
            break;
        }
        let e = std::io::Error::last_os_error();
        assert!(r == -1 && e.raw_os_error() == Some(libc::EINTR), "poll: {e}");
    }
    assert!(matches!(os.try_reap().unwrap(), TryReapOutcome::Recheck));
    tracer.send(REAP);
    tracer.expect("reaped");
    assert!(matches!(os.try_reap().unwrap(), TryReapOutcome::Reaped(_)));
    tracer.finish();
}

/// A child whose pid is unknown (its spawn failed after the handshake opened its pidfd) is signalled
/// and reaped through the pidfd alone.
///
/// Mutant: a pid is required to signal or to settle the child.
#[skuld::test]
fn a_pidless_linux_child_is_signalled_and_reaped_through_its_pidfd() {
    use crate::child::owned::teardown::TeardownKind;
    use crate::error::ChildFate;
    use crate::os_process::linux::LinuxProcess;

    let mut cmd = crate::test_child::held_std_killable_blocker();
    let child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    let id = ProcessId::of(child.id())
        .found()
        .expect("the live child has an identity");
    let pidfd = crate::wait::exit_only::open_own_child(id.pid(), Some(id))
        .expect("pidfd_open")
        .expect("the child is not reaped");
    // std's `Child` neither kills nor reaps on drop; the pidfd is all that is left of it.
    drop(child);
    let owned = crate::child::owned::OwnedChild::new(Box::new(LinuxProcess::new(None, pidfd)));
    assert_eq!(owned.pid(), None);
    let torn = owned.tear_down(None, TeardownKind::Kill, None);
    assert_eq!(torn.fate, ChildFate::Reaped, "{torn:?}");
    assert_eq!(torn.left, None);
}

/// A send through the pidfd of a pid-less child that finds it reaped says "already gone" without a
/// number.
///
/// Mutant: the unknown pid is worded as `child 0`.
#[skuld::test]
fn a_signal_to_a_reaped_pidless_linux_child_is_named_without_a_number() {
    use crate::os_process::linux::LinuxProcess;
    use crate::os_process::OsProcess as _;

    crate::log_capture::install();
    let mut cmd = crate::test_child::held_std_killable_blocker();
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    let id = ProcessId::of(child.id())
        .found()
        .expect("the live child has an identity");
    let pidfd = crate::wait::exit_only::open_own_child(id.pid(), Some(id))
        .expect("pidfd_open")
        .expect("the child is not reaped");
    let os = LinuxProcess::new(None, pidfd);
    assert_eq!(os.signal(Sig::Kill).expect("kill"), Sent::Delivered);
    child.wait().expect("reap the killed child");
    let mark = crate::log_capture::mark();
    assert_eq!(os.signal(Sig::Kill).expect("a reaped child is gone"), Sent::Gone);
    let said = crate::log_capture::records_since_on_current_thread(mark, "already gone");
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0]
            .1
            .contains(&format!("to {}: ", crate::os_process::PIDLESS_CHILD)),
        "{said:?}"
    );
}
