use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

use super::{ExitWatch, MacProcess};
use crate::error::Error;
use crate::identity::{uniq_info, ProcessId, ReadPurpose, UniqRead};
use crate::os_process::drive::exited_by;
use crate::os_process::{kill_by_id, open, terminate_by_id, Exit, Op, OsProcess};
use crate::signal::{Sent, Sig};
use crate::test_child::wait_until_zombie;

/// A watch on a pipe's read end, and the two ends.
fn pipe_watch() -> (std::io::PipeReader, std::io::PipeWriter, ExitWatch) {
    let (rx, tx) = std::io::pipe().unwrap();
    let watch = crate::os_process::fake::readable_watch(rx.as_fd()).unwrap();
    (rx, tx, watch)
}

/// An already-passed deadline: one non-blocking pass.
fn expired() -> Option<Option<std::time::Instant>> {
    crate::wait::deadline_from(Duration::ZERO)
}

#[skuld::test]
fn an_unfired_watch_reads_nothing() {
    let (_rx, _tx, watch) = pipe_watch();
    assert!(!watch.drain().unwrap());
    assert!(!watch.block(expired()).unwrap());
}

#[skuld::test]
fn block_remembers_the_event_it_read() {
    let (mut rx, mut tx, watch) = pipe_watch();
    tx.write_all(&[1]).unwrap();
    assert!(watch.block(None).unwrap());
    // The pipe is empty again, so only `seen` can answer.
    rx.read_exact(&mut [0]).unwrap();
    assert!(watch.drain().unwrap());
}

#[skuld::test]
fn drain_remembers_the_event_it_read() {
    let (mut rx, mut tx, watch) = pipe_watch();
    tx.write_all(&[1]).unwrap();
    assert!(watch.drain().unwrap());
    rx.read_exact(&mut [0]).unwrap();
    crate::wait::block_probe::take();
    assert!(watch.block(expired()).unwrap());
    assert!(
        crate::wait::block_probe::take().is_empty(),
        "a block that returns at once on `seen` arms no wait"
    );
}

#[skuld::test]
fn block_records_a_wait_it_arms() {
    let (_rx, _tx, watch) = pipe_watch();
    crate::wait::block_probe::take();
    assert!(!watch.block(expired()).unwrap());
    assert_eq!(crate::wait::block_probe::take().len(), 1);
}

// MacProcess =====

/// A live `cat` blocker, held open by the child's own piped stdin, and its identity.
fn blocker() -> (std::process::Child, ProcessId) {
    let child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn blocker");
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    (child, id)
}

#[skuld::test]
fn open_live_then_kill_then_exited() {
    let (mut child, id) = blocker();
    let mut p = open(id, Op::Wait).unwrap().expect("a live process opens");
    assert!(
        matches!(p.exited().unwrap(), Exit::Running(_)),
        "a live process reads Running"
    );
    assert!(!exited_by(&mut *p, Some(Duration::ZERO)).unwrap());
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(exited_by(&mut *p, None).unwrap());
    assert_eq!(
        child.wait().unwrap().signal(),
        Some(libc::SIGKILL),
        "it died of the SIGKILL"
    );
}

/// Mutant: `open` arms the kqueue watch for a kill, so a kill needs a descriptor and a kevent
/// registration it never used. A look at a signal-only object is a caller bug: a debug assertion,
/// and in release an `Err`; never an answer.
#[skuld::test]
fn a_kill_opens_no_watch_and_still_kills() {
    let (mut child, id) = blocker();
    let mut p = open(id, Op::Kill).unwrap().expect("a live process opens");
    let looked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.exited().map(|_| ())));
    // Debug builds assert the contract; release builds return the error.
    let err = match looked {
        Ok(Err(Error::Io(e))) => Some(e),
        Err(_) => None,
        Ok(other) => panic!("a signal-only process has no exit watch to answer a look: {other:?}"),
    };
    match err {
        Some(e) => assert!(e.to_string().contains("opened for a signal"), "{e}"),
        None if cfg!(debug_assertions) => {}
        None => panic!("release builds return an error, not a panic"),
    }
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
}

#[skuld::test]
fn open_with_wrong_start_token_is_none_and_sends_nothing() {
    let (mut child, id) = blocker();
    let sends = crate::send_log::Capture::start();
    let other = ProcessId::from_parts_for_test(id.pid(), id.start_token_raw() + 1);
    assert!(
        open(other, Op::Kill).unwrap().is_none(),
        "a wrong start token opens nothing"
    );
    kill_by_id(other).unwrap();
    terminate_by_id(other).unwrap();
    assert_eq!(sends.by_identity(), vec![], "nothing may be sent to a stranger");
    // Still running: the right identity opens and sees no exit.
    let mut p = open(id, Op::Wait).unwrap().expect("the blocker is alive");
    assert!(!exited_by(&mut *p, Some(Duration::ZERO)).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[skuld::test]
fn open_after_reap_is_none() {
    let (mut child, id) = blocker();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(open(id, Op::Wait).unwrap().is_none());
}

/// Mutant: the first look blocks, or misses an exit the watch already holds.
#[skuld::test]
fn exited_before_first_look_returns_true() {
    let (mut child, id) = blocker();
    let mut p = open(id, Op::Wait).unwrap().expect("a live process opens");
    child.kill().unwrap();
    wait_until_zombie(id.pid());
    crate::wait::block_probe::take();
    assert!(exited_by(&mut *p, Some(Duration::ZERO)).unwrap());
    assert!(
        crate::wait::block_probe::take().is_empty(),
        "an exit the watch holds is found by the look, with no wait armed"
    );
    child.wait().unwrap();
}

/// Mutant: `exited` forgets an exit a wait already consumed, so the driver looks again forever.
#[skuld::test]
fn exited_stays_true_after_a_wait_consumed_the_event() {
    let (mut child, id) = blocker();
    let mut p = open(id, Op::Wait).unwrap().expect("a live process opens");
    child.kill().unwrap();
    assert!(exited_by(&mut *p, None).unwrap());
    assert!(
        matches!(p.exited().unwrap(), Exit::Exited),
        "a later look still says Exited"
    );
    child.wait().unwrap();
}

/// The blocker `exec`s itself into `cat` after `open`, which changes its
/// `p_idversion`. Mutant: `ESRCH` is read as "gone", so the process survives `signal`.
#[skuld::test]
fn signal_reaches_a_process_that_execed_after_open() {
    use std::io::Write;

    let mut cmd = std::process::Command::new("sh");
    cmd.args(["-c", "read line; exec cat"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn sh");
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let mut p = open(id, Op::Wait).unwrap().expect("a live process opens");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = child.stdout.take().expect("piped stdout");
    // Releases `read`, so `sh` execs `cat`. Only `cat` echoes, so the echo reports the exec.
    stdin.write_all(b"go\n").unwrap();
    crate::test_child::assert_echoes(&mut stdin, &mut stdout);
    let sends = crate::send_log::Capture::start();
    assert_eq!(
        p.signal(Sig::Kill).unwrap(),
        Sent::Delivered,
        "an exec'd process still runs: it is not Gone"
    );
    assert_eq!(
        sends.by_identity(),
        vec![(id.pid(), libc::SIGKILL), (id.pid(), libc::SIGKILL)],
        "the first token was stale (exec changed p_idversion), the second carried the new one"
    );
    assert!(exited_by(&mut *p, None).unwrap());
    assert_eq!(
        child.wait().unwrap().signal(),
        Some(libc::SIGKILL),
        "it died of the SIGKILL"
    );
}

/// Mutant: a zombie is retried (`ESRCH` with an unchanged version loops), or called an error.
#[skuld::test]
fn signal_to_a_zombie_is_gone_after_one_attempt() {
    let (mut child, id) = blocker();
    let mut p = open(id, Op::Kill).unwrap().expect("a live process opens");
    child.kill().unwrap();
    wait_until_zombie(id.pid());
    let sends = crate::send_log::Capture::start();
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Gone);
    assert_eq!(sends.by_identity().len(), 1, "a zombie is not signalled again");
    child.wait().unwrap();
}

/// Mutant: `ESRCH` after the reap is an error, or the re-read of a missing process loops.
#[skuld::test]
fn signal_after_reap_is_gone() {
    let (mut child, id) = blocker();
    let mut p = open(id, Op::Kill).unwrap().expect("a live process opens");
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Gone);
}

/// Mutant: the re-read after `ESRCH` is unchecked, or its refusal loses the errno (`EPERM` must
/// stay `PermissionDenied`).
#[skuld::test]
fn a_refused_reread_after_esrch_keeps_the_errno() {
    use crate::identity::uniq_fault::force_uniq_read_once;

    let (mut child, id) = blocker();
    let mut p = open(id, Op::Kill).unwrap().expect("a live process opens");
    child.kill().unwrap();
    wait_until_zombie(id.pid());
    let _refused = force_uniq_read_once(ReadPurpose::Kill, UniqRead::Refused(libc::EPERM));
    let err = p.signal(Sig::Kill).expect_err("a refused re-read is an error");
    let Error::Io(io) = &err else {
        panic!("a refused re-read is Error::Io: {err:?}");
    };
    assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied, "{err:?}");
    child.wait().unwrap();
}

/// Mutant: `open` ignores the second unique-id read, so a pid taken between the first read and
/// the arming of the watch is watched as the original.
#[skuld::test]
fn open_is_none_when_another_process_holds_the_pid_after_arming() {
    use crate::identity::uniq_fault::force_uniq_read_once;
    use crate::identity::UniqInfo;

    let (mut child, id) = blocker();
    let UniqRead::Found(real) = uniq_info(id.pid(), ReadPurpose::Kill) else {
        panic!("the blocker's unique id must be readable");
    };
    let _first = force_uniq_read_once(ReadPurpose::Open, UniqRead::Found(real));
    let _second = force_uniq_read_once(
        ReadPurpose::Open,
        UniqRead::Found(UniqInfo {
            unique_id: real.unique_id ^ 1,
            ..real
        }),
    );
    assert!(open(id, Op::Wait).unwrap().is_none());
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Mutant: a refused read in `open` is "gone" (an exit that never happened), or loses the errno.
#[skuld::test]
fn open_with_a_refused_read_is_unassessable_with_the_errno() {
    use crate::identity::uniq_fault::force_uniq_read_once;

    let (mut child, id) = blocker();
    let _refused = force_uniq_read_once(ReadPurpose::Open, UniqRead::Refused(libc::EPERM));
    let err = open(id, Op::Wait).expect_err("a refused read is an error");
    let Error::Unassessable {
        source: Some(source), ..
    } = &err
    else {
        panic!("a refused read is Unassessable with its errno as source: {err:?}");
    };
    assert_eq!(source.raw_os_error(), Some(libc::EPERM));
    child.kill().unwrap();
    child.wait().unwrap();
}

/// `kernel_task` is pid 0, which macOS resolves: it is no signal target. Mutant: the guard is
/// removed, so a token naming pid 0 reaches the kernel (it answers `EINVAL`, an `Io` error, and the
/// attempt is recorded).
#[skuld::test]
fn pid_zero_is_refused_unassessable() {
    let mut p = MacProcess {
        id: ProcessId::from_parts_for_test(0, 1),
        unique: 1,
        idversion: 1,
        watch: None,
    };
    let sends = crate::send_log::Capture::start();
    let err = p.signal(Sig::Kill).expect_err("pid 0 is no target");
    assert!(
        matches!(err, Error::Unassessable { source: None, .. }),
        "pid 0 is refused as Unassessable: {err:?}"
    );
    assert_eq!(sends.by_identity(), vec![], "nothing reached the kernel");
}
