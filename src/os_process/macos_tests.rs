use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

use super::{ExitWatch, MacProcess};
use crate::error::Error;
use crate::identity::{uniq_info, ProcessId, ReadPurpose, UniqRead};
use crate::os_process::drive::{absolute, drive};
use crate::os_process::{kill, open, terminate, terminate_by_id, Exit, OsProcess};
use crate::signal::{Sent, Sig};
use crate::test_child::wait_until_zombie;

// ExitWatch =====

#[skuld::test]
fn a_watch_on_a_live_process_reads_not_exited() {
    let (mut child, id) = blocker();
    let watch = ExitWatch::proc_exit(id.pid()).unwrap();
    assert!(!watch.exited().unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Mutant: a look reads the queue, so the second look finds it empty.
#[skuld::test]
fn a_look_at_an_exited_process_does_not_consume_the_exit() {
    let (mut child, id) = blocker();
    let watch = ExitWatch::proc_exit(id.pid()).unwrap();
    child.kill().unwrap();
    wait_until_zombie(id.pid());
    assert!(watch.exited().unwrap());
    assert!(watch.exited().unwrap(), "the exit is still there for the next look");
    child.wait().unwrap();
}

/// A pid above the kernel's pid limit is past registration, as an exited process is: `ESRCH`.
#[skuld::test]
fn a_watch_armed_past_registration_reads_exited() {
    let watch = ExitWatch::proc_exit(i32::MAX as u32).unwrap();
    assert!(watch.exited().unwrap());
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
fn one_open_serves_look_signal_and_wait() {
    let (mut child, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    assert!(
        matches!(p.exited().unwrap(), Exit::Running(_)),
        "a live process reads Running"
    );
    assert!(!drive(&*p, absolute(Some(Duration::ZERO))).unwrap());
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(drive(&*p, absolute(None)).unwrap());
    assert_eq!(
        child.wait().unwrap().signal(),
        Some(libc::SIGKILL),
        "it died of the SIGKILL"
    );
}

#[skuld::test]
fn open_with_wrong_start_token_is_none_and_sends_nothing() {
    let (mut child, id) = blocker();
    let sends = crate::send_log::Capture::start();
    let other = ProcessId::from_parts_for_test(id.pid(), id.start_token_raw() + 1);
    assert!(open(other).unwrap().is_none(), "a wrong start token opens nothing");
    terminate_by_id(other).unwrap();
    assert_eq!(sends.by_identity(), vec![], "nothing may be sent to a stranger");
    // Still running: the right identity opens and sees no exit.
    let p = open(id).unwrap().expect("the blocker is alive");
    assert!(!drive(&*p, absolute(Some(Duration::ZERO))).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

/// A held process that its owner has reaped is gone: both acts are `Ok`. Mutant: a stale signal
/// is an error.
#[skuld::test]
fn kill_and_terminate_of_a_held_process_that_is_gone_are_ok() {
    let (mut child, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    child.wait().unwrap();
    kill(&*p).unwrap();
    terminate(&*p).unwrap();
}

#[skuld::test]
fn open_after_reap_is_none() {
    let (mut child, id) = blocker();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(open(id).unwrap().is_none());
}

/// Mutant: the first look blocks, or misses an exit the watch already holds.
#[skuld::test]
fn exited_before_first_look_returns_true() {
    let (mut child, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    wait_until_zombie(id.pid());
    crate::wait::block_probe::take();
    assert!(drive(&*p, absolute(Some(Duration::ZERO))).unwrap());
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
    let p = open(id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    assert!(drive(&*p, absolute(None)).unwrap());
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
    let p = open(id).unwrap().expect("a live process opens");
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
    assert!(drive(&*p, absolute(None)).unwrap());
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
    let p = open(id).unwrap().expect("a live process opens");
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
    let p = open(id).unwrap().expect("a live process opens");
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
    let p = open(id).unwrap().expect("a live process opens");
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
    assert!(open(id).unwrap().is_none());
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Mutant: a refused read in `open` is "gone" (an exit that never happened), or loses the errno.
#[skuld::test]
fn open_with_a_refused_read_is_unassessable_with_the_errno() {
    use crate::identity::uniq_fault::force_uniq_read_once;

    let (mut child, id) = blocker();
    let _refused = force_uniq_read_once(ReadPurpose::Open, UniqRead::Refused(libc::EPERM));
    let err = open(id).expect_err("a refused read is an error");
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
    let p = MacProcess {
        id: ProcessId::from_parts_for_test(0, 1),
        unique: 1,
        idversion: std::sync::atomic::AtomicI32::new(1),
        watch: ExitWatch::new(super::kqueue::Kqueue::new().unwrap()),
    };
    let sends = crate::send_log::Capture::start();
    let err = p.signal(Sig::Kill).expect_err("pid 0 is no target");
    assert!(
        matches!(err, Error::Unassessable { source: None, .. }),
        "pid 0 is refused as Unassessable: {err:?}"
    );
    assert_eq!(sends.by_identity(), vec![], "nothing reached the kernel");
}

/// `kill(0, sig)` would signal the caller's ENTIRE process group, so pid 0 must never be signalled.
/// Two independent layers stop it, and this pins the outer one: `open`'s flavor-17 read of the pid
/// followed by `exists()`. `ProcessId::of(0)` resolves on macOS (`kernel_task`), but to a token that
/// no caller-held identity matches, so a pid-0 identity is rejected as recycled, `open` is
/// `Ok(None)`, and the signal is never formed — the test process, which is what `kill(0, ..)` would
/// have killed, survives to make the assertion.
///
/// The inner layer, `probe::signal_target`, is defence in depth for a caller holding
/// `kernel_task`'s *genuine* identity. It is not exercised here on purpose: a regression in
/// it would SIGKILL the CI runner's process group rather than fail a test. Its own contract
/// is pinned by `identity::probe::probe_tests::signal_target_is_the_guard_for_real_signals`.
#[skuld::test]
fn a_pid_zero_identity_never_reaches_kill() {
    let bogus = crate::identity::ProcessId::from_parts_for_test(0, 1);
    // The pid holds `kernel_task`, not the process this identity names: nothing opens.
    assert!(
        open(bogus).expect("a pid-0 identity resolves to a stranger").is_none(),
        "a pid-0 identity opens nothing"
    );
    crate::os_process::terminate_by_id(bogus).expect("same for the graceful signal");
    // If either call had reached `kill(2)`, this process would have died with it.
    assert_eq!(
        crate::identity::ProcessId::current().is_alive(),
        crate::identity::Liveness::Alive,
        "the caller must have survived - nothing may signal process group 0"
    );
}

/// Two waiters on one open: the exit reaches both. Mutant: a wait reads the exit event from the
/// kqueue, so the other wait blocks forever on an exited process.
#[skuld::test]
fn two_threads_waiting_on_one_process_both_return_after_it_exits() {
    let (mut child, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    let p: &dyn OsProcess = &*p;
    std::thread::scope(|scope| {
        let waiters = [
            scope.spawn(|| drive(p, absolute(None))),
            scope.spawn(|| drive(p, absolute(None))),
        ];
        assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
        for waiter in waiters {
            assert!(
                waiter.join().unwrap().unwrap(),
                "every wait ends when the process exits"
            );
        }
    });
    assert!(
        matches!(p.exited().unwrap(), Exit::Exited),
        "and a later look says Exited"
    );
    child.wait().unwrap();
}
