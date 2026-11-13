use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

use super::{ExitWatch, MacProcess};
use crate::error::Error;
use crate::identity::{uniq_info, ProcessId, ReadPurpose, UniqRead};
use crate::os_process::drive::exited_held;
use crate::os_process::{kill, open, terminate, Exit, OsProcess};
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
    assert!(!exited_held(&*p, Some(Duration::ZERO)).unwrap());
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(exited_held(&*p, None).unwrap());
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
    let other = id.with_other_value();
    assert!(open(other).unwrap().is_none(), "a wrong start token opens nothing");
    assert_eq!(sends.by_identity(), vec![], "nothing may be sent to a stranger");
    // Still running: the right identity opens and sees no exit.
    let p = open(id).unwrap().expect("the blocker is alive");
    assert!(!exited_held(&*p, Some(Duration::ZERO)).unwrap());
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
    assert!(exited_held(&*p, Some(Duration::ZERO)).unwrap());
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
    assert!(exited_held(&*p, None).unwrap());
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
    assert!(exited_held(&*p, None).unwrap());
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

/// Mutant: the open arms the watch, so it costs a descriptor and a send can fail for want of one.
#[skuld::test]
fn an_open_and_a_send_arm_no_watch_and_the_first_look_arms_it() {
    let (mut child, id) = blocker();
    let p = MacProcess::open(id).unwrap().expect("a live process opens");
    assert!(p.watch.get().is_none(), "an open arms nothing");
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(p.watch.get().is_none(), "a send arms nothing");
    assert!(exited_held(&p, None).unwrap());
    assert!(p.watch.get().is_some(), "the first look arms the watch");
    child.wait().unwrap();
}

/// A watch that has fired is an exit only once the process is a zombie or gone. The registration
/// refusal stands in for the exit edge XNU posts before `p_stat = SZOMB` (a pid past `P_REF_DEAD`
/// is refused as an exited one is): the watch reads fired while the process still runs.
///
/// Mutant: `exited` answers `Exited` on the watch alone, so the first look is `Exited`.
#[skuld::test]
fn a_fired_watch_on_a_process_is_exited_only_once_it_is_a_zombie() {
    use crate::os_process::macos::kqueue::test_hooks::{force_proc_registration_once, Registration};

    let (mut child, id) = blocker();
    let p = MacProcess::open(id).unwrap().expect("a live process opens");
    let _fired = force_proc_registration_once(Registration::ExitWatch);
    assert!(
        matches!(p.exited(), Ok(Exit::Recheck)),
        "the watch fired, the process is not a zombie"
    );
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    wait_until_zombie(id.pid());
    assert!(matches!(p.exited(), Ok(Exit::Exited)));
    child.wait().unwrap();
}

/// A spawned blocker child, its stdin, its identity, and a [`MacChild`] over it whose exit watch has
/// fired while it runs (the registration refusal stands in for the edge, as for `MacProcess` above).
fn a_child_with_a_fired_watch() -> (
    std::process::Child,
    std::process::ChildStdin,
    ProcessId,
    crate::os_process::macos::child::MacChild,
) {
    use crate::os_process::macos::child::MacChild;
    use crate::os_process::macos::kqueue::test_hooks::{force_proc_registration_once, Registration};

    let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let UniqRead::Found(read) = uniq_info(id.pid(), ReadPurpose::Kill) else {
        panic!("the blocker's unique id must be readable");
    };
    let fired = force_proc_registration_once(Registration::ExitWatch);
    let mac = MacChild::new(id.pid(), read.unique_id).expect("watch the child");
    drop(fired);
    (child, stdin, id, mac)
}

/// [`a_fired_watch_on_a_process_is_exited_only_once_it_is_a_zombie`] for the owned child.
///
/// Mutant: `MacChild::exited` answers `Exited` on the watch alone, so the first look is `Exited`.
#[skuld::test]
fn a_fired_watch_on_a_child_is_exited_only_once_it_is_a_zombie() {
    let (mut child, stdin, id, mac) = a_child_with_a_fired_watch();
    assert!(
        matches!(mac.exited(), Ok(Exit::Recheck)),
        "the watch fired, the child is not a zombie"
    );
    drop(stdin);
    wait_until_zombie(id.pid());
    assert!(matches!(mac.exited(), Ok(Exit::Exited)));
    child.wait().unwrap();
}

/// A look at a watch that has not fired reads no state of the process: a process's reads nothing, and a
/// child's, whose parent is this process, reads only that parent, never whether it is a zombie. The
/// confirming read is forced refused: a look that makes it before it asks the watch is an error for
/// a process that runs.
///
/// Mutant: `ExitWatch::look` reads the process's state before it asks the watch; `MacChild::exited`
/// reads whether the child is a zombie while this process is its parent.
#[skuld::test]
fn a_look_at_an_unfired_watch_reads_nothing() {
    use crate::identity::uniq_fault::force_uniq_read_once;
    use crate::os_process::macos::child::MacChild;

    let (mut child, id) = blocker();
    let UniqRead::Found(read) = uniq_info(id.pid(), ReadPurpose::Kill) else {
        panic!("the blocker's unique id must be readable");
    };
    let p = MacProcess::open(id).unwrap().expect("a live process opens");
    let mac = MacChild::new(id.pid(), read.unique_id).expect("watch the child");
    let _refused = force_uniq_read_once(ReadPurpose::Exit, UniqRead::Refused(libc::EPERM));
    let reads = crate::identity::uniq_fault::record();
    assert!(
        matches!(p.exited(), Ok(Exit::Running(_))),
        "an unfired watch on a running process is Running"
    );
    assert_eq!(reads.purposes(), vec![], "a process's unfired watch reads nothing");
    assert!(
        matches!(mac.exited(), Ok(Exit::Running(_))),
        "an unfired watch on a running child is Running"
    );
    assert_eq!(
        reads.purposes(),
        vec![ReadPurpose::Running, ReadPurpose::Running],
        "a child's unfired watch reads its parent (two unique-id reads) and nothing else"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

/// The driver waits through a fired watch until the process is a zombie, and what it returns is the
/// state [`ProcessId::is_alive`] reads: `Dead`.
///
/// Mutant: the production `exited` skips the confirmation, so the deadline-less zero wait on the
/// still-running process says `true`.
#[skuld::test]
fn a_wait_through_a_fired_watch_returns_a_process_that_reads_dead() {
    use crate::identity::Liveness;
    use crate::os_process::macos::kqueue::test_hooks::{force_proc_registration_once, Registration};

    let (mut child, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    let _fired = force_proc_registration_once(Registration::ExitWatch);
    assert!(
        !exited_held(&*p, Some(Duration::ZERO)).unwrap(),
        "a fired watch on a process that runs is not an exit"
    );
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(exited_held(&*p, None).unwrap());
    assert_eq!(id.is_alive(), Liveness::Dead);
    child.wait().unwrap();
}

/// [`a_wait_through_a_fired_watch_returns_a_process_that_reads_dead`] through the tokio driver. A
/// skuld async test runs on a current-thread runtime, so the thread-local forcing reaches the watch
/// the driver arms.
///
/// Mutant: as there; or the forcing is not consumed, so the watch never fired and the rest proves
/// nothing.
#[cfg(feature = "tokio")]
#[skuld::test]
async fn a_tokio_wait_through_a_fired_watch_returns_a_process_that_reads_dead() {
    use crate::identity::Liveness;
    use crate::os_process::macos::kqueue::test_hooks::{
        force_proc_registration_once, take_forced_registration, Registration,
    };
    use crate::tokio::drive::exited_held;

    let (mut child, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    let _fired = force_proc_registration_once(Registration::ExitWatch);
    assert!(
        !exited_held(&*p, Some(Duration::ZERO)).await.unwrap(),
        "a fired watch on a process that runs is not an exit"
    );
    assert!(
        !take_forced_registration(Registration::ExitWatch),
        "the watch's registration consumed the forcing"
    );
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(exited_held(&*p, None).await.unwrap());
    assert_eq!(id.is_alive(), Liveness::Dead);
    child.wait().unwrap();
}

/// A refused read of the process's state is not an exit: `Unassessable`, with the errno as its source.
fn assert_a_refused_confirmation_is_unassessable_with_the_errno(p: &dyn OsProcess) {
    use crate::identity::uniq_fault::force_uniq_read_once;

    let _refused = force_uniq_read_once(ReadPurpose::Exit, UniqRead::Refused(libc::EPERM));
    let err = p.exited().expect_err("a refused read is an error");
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err:?}");
}

/// [`assert_a_refused_confirmation_is_unassessable_with_the_errno`] for a [`MacProcess`].
///
/// Mutant: a refused read answers `Exited`, or loses the errno.
#[skuld::test]
fn a_refused_confirmation_of_a_process_is_unassessable_with_the_errno() {
    use crate::os_process::macos::kqueue::test_hooks::{force_proc_registration_once, Registration};

    let (mut child, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    let _fired = force_proc_registration_once(Registration::ExitWatch);
    assert_a_refused_confirmation_is_unassessable_with_the_errno(&*p);
    child.kill().unwrap();
    child.wait().unwrap();
}

/// [`assert_a_refused_confirmation_is_unassessable_with_the_errno`] for a [`MacChild`].
///
/// Mutant: as there.
#[skuld::test]
fn a_refused_confirmation_of_a_child_is_unassessable_with_the_errno() {
    let (mut child, stdin, _id, mac) = a_child_with_a_fired_watch();
    assert_a_refused_confirmation_is_unassessable_with_the_errno(&mac);
    drop(stdin);
    child.wait().unwrap();
}

/// A watch armed while another process holds the pid reads `Exited`: the arming's and the
/// confirming unique-id reads both name another process. The live blocker stands for it.
///
/// Mutant: the arming ignores its unique-id read, so a pid taken between the open and the first look
/// is watched as the original; or the confirmation keys on the pid, so the process that holds it
/// now is read as the watched one and the wait is `Recheck` for ever.
#[skuld::test]
fn a_watch_armed_while_another_process_holds_the_pid_reads_exited() {
    use crate::identity::uniq_fault::force_uniq_read_once;
    use crate::identity::UniqInfo;

    let (mut child, id) = blocker();
    let UniqRead::Found(real) = uniq_info(id.pid(), ReadPurpose::Kill) else {
        panic!("the blocker's unique id must be readable");
    };
    let p = open(id).unwrap().expect("a live process opens");
    let other = || {
        UniqRead::Found(UniqInfo {
            unique_id: real.unique_id ^ 1,
            ..real
        })
    };
    let _arm = force_uniq_read_once(ReadPurpose::Open, other());
    let _confirm = force_uniq_read_once(ReadPurpose::Exit, other());
    assert!(
        matches!(p.exited(), Ok(Exit::Exited)),
        "the process that was opened is not the one holding the pid"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Mutant: a refused read at the arming is read as an exit, or loses the errno.
#[skuld::test]
fn a_refused_read_at_the_arming_is_unassessable_with_the_errno() {
    use crate::identity::uniq_fault::force_uniq_read_once;

    let (mut child, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    let _refused = force_uniq_read_once(ReadPurpose::Open, UniqRead::Refused(libc::EPERM));
    let err = p.exited().expect_err("a refused read is an error");
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err:?}");
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
    assert_eq!(crate::error::first_os_code(&**source), Some(libc::EPERM));
    child.kill().unwrap();
    child.wait().unwrap();
}

#[skuld::test]
fn a_refused_identity_read_for_an_open_keeps_its_errno_as_the_source() {
    use crate::identity::uniq_fault::force_uniq_read_once;

    let _forced = force_uniq_read_once(ReadPurpose::Open, UniqRead::Refused(libc::EPERM));
    let err = super::read_for_open(77, "it was not opened").expect_err("refused");
    match &err {
        Error::Unassessable { detail, .. } => {
            assert_eq!(detail, "pid 77 identity could not be read; it was not opened");
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err:?}");
}

/// A refused `has_exited` read is `Unassessable` with the errno as its source, and the message
/// does not word it as an "errno". Both readers of it (`ExitWatch::look` and `MacChild::exited` past
/// an unfired watch) build it with this function, each with its own situation text.
#[skuld::test]
fn a_refused_has_exited_read_is_unassessable_with_its_errno_as_the_source_and_words_none() {
    for (situation, said) in [
        (
            "its exit watch fired, but whether it has exited could not be read",
            "pid 77: its exit watch fired, but whether it has exited could not be read",
        ),
        (
            "its exit watch has not fired, and whether it has exited could not be read",
            "pid 77: its exit watch has not fired, and whether it has exited could not be read",
        ),
    ] {
        let err = super::exit_read_refused(77, libc::EPERM, situation);
        let Error::Unassessable { detail, .. } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err:?}");
        assert_eq!(detail.as_str(), said);
        assert!(!crate::error::said(&err).contains("errno"), "{err:?}");
    }
}

/// A refused read of a child's look whose watch has not fired, of its parent or of whether it is a
/// zombie, is `Unassessable` with the errno as its source, and says its watch has not fired. The
/// child's parent reads launchd, so the second read is reached.
///
/// Mutant: `MacChild::exited` wraps the errno as `Error::Io`, words another situation, or answers
/// `Running` for a read it could not make.
#[skuld::test]
fn a_refused_read_past_an_unfired_watch_is_unassessable_with_the_errno() {
    use crate::identity::uniq_fault::force_uniq_read_once;
    use crate::identity::{ppid_fault, LAUNCHD};
    use crate::os_process::macos::child::MacChild;

    for zombie_read in [false, true] {
        let (mut child, id) = blocker();
        let UniqRead::Found(read) = uniq_info(id.pid(), ReadPurpose::Kill) else {
            panic!("the blocker's unique id must be readable");
        };
        let mac = MacChild::new(id.pid(), read.unique_id).expect("watch the child");
        let _parent = ppid_fault::force_ppid_with(|| Ok(LAUNCHD));
        // The parent read is two unique-id reads and the zombie read two more: the third is the
        // zombie read's first.
        let mut forced = Vec::new();
        if zombie_read {
            forced.push(force_uniq_read_once(ReadPurpose::Running, UniqRead::Found(read)));
            forced.push(force_uniq_read_once(ReadPurpose::Running, UniqRead::Found(read)));
        }
        forced.push(force_uniq_read_once(
            ReadPurpose::Running,
            UniqRead::Refused(libc::EPERM),
        ));
        let err = mac.exited().expect_err("a refused read is an error");
        let Error::Unassessable { detail, .. } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err:?}");
        assert_eq!(
            detail,
            &format!(
                "pid {}: its exit watch has not fired, and whether it has exited could not be read",
                id.pid()
            ),
            "zombie read: {zombie_read}"
        );
        drop(forced);
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// A child whose parent is another process (its tracer, or launchd) gets no `NOTE_EXIT` from XNU, so
/// its unfired watch cannot say it is running: while the process is no zombie, the look is
/// `Recheck`, which the driver paces. This process's own pid stands in for the child, and its parent
/// read is forced.
///
/// Mutant: an unfired watch on a child another process holds is `Running`, so a wait on it blocks
/// for an event that never comes.
#[skuld::test]
fn an_unfired_watch_on_a_running_child_another_process_holds_is_a_recheck() {
    use crate::identity::{ppid_fault, LAUNCHD};
    use crate::os_process::macos::child::MacChild;
    use crate::wait::exit_only::macos_tests::{echild_yet_resolvable, held_by_a_tracer_pid};

    let (pid, unique) = echild_yet_resolvable();
    let mac = MacChild::new(pid, unique).expect("watch the stand-in");
    for parent in [LAUNCHD, held_by_a_tracer_pid()] {
        let _parent = ppid_fault::force_ppid_with(move || Ok(parent));
        assert!(
            matches!(mac.exited(), Ok(Exit::Recheck)),
            "held by pid {parent}, the child is no zombie and its watch cannot fire"
        );
    }
}

/// A child whose pid names another process now, or none, has been reaped: exited, with its watch
/// unfired. The look remembers it, so later looks read nothing. The read of the pid is forced, once
/// each way.
///
/// Mutant: a reaped child is `Recheck` or `Running`; or the confirmation is not remembered.
#[skuld::test]
fn a_child_that_was_reaped_is_exited_with_its_watch_unfired_and_remembered() {
    use crate::identity::uniq_fault::{force_uniq_read_once, record};
    use crate::identity::UniqInfo;
    use crate::os_process::macos::child::MacChild;

    for reaped in ["gone", "another process"] {
        let (mut child, id) = blocker();
        let UniqRead::Found(read) = uniq_info(id.pid(), ReadPurpose::Kill) else {
            panic!("the blocker's unique id must be readable");
        };
        let mac = MacChild::new(id.pid(), read.unique_id).expect("watch the child");
        let answer = match reaped {
            "gone" => UniqRead::Gone,
            _ => UniqRead::Found(UniqInfo {
                unique_id: read.unique_id ^ 1,
                ..read
            }),
        };
        let forced = force_uniq_read_once(ReadPurpose::Running, answer);
        assert!(matches!(mac.exited(), Ok(Exit::Exited)), "{reaped}");
        drop(forced);
        let reads = record();
        assert!(matches!(mac.exited(), Ok(Exit::Exited)), "{reaped}");
        assert_eq!(reads.purposes(), vec![], "a confirmed exit is not read again: {reaped}");
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Once a look has confirmed the exit, later looks make no `Exit` read. The watch is armed on a live
/// process that then exits, so it fires from `NOTE_EXIT`; the reads are counted by their recorded
/// purposes.
///
/// Mutant: `ExitWatch::look` does not remember the confirmation, so the second look reads again.
#[skuld::test]
fn a_confirmed_exit_is_remembered_and_later_looks_read_nothing() {
    use crate::identity::uniq_fault::record;

    let (mut child, id) = blocker();
    let p = MacProcess::open(id).unwrap().expect("a live process opens");
    assert!(
        matches!(p.exited(), Ok(Exit::Running(_))),
        "the watch is armed on a live process"
    );
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    wait_until_zombie(id.pid());
    let reads = record();
    assert!(matches!(p.exited(), Ok(Exit::Exited)), "the zombie confirms");
    let confirming = reads.purposes().iter().filter(|p| **p == ReadPurpose::Exit).count();
    assert!(
        confirming > 0,
        "the fired watch was confirmed by a read: {:?}",
        reads.purposes()
    );
    assert!(matches!(p.exited(), Ok(Exit::Exited)));
    assert!(matches!(p.exited(), Ok(Exit::Exited)));
    let after = reads.purposes().iter().filter(|p| **p == ReadPurpose::Exit).count();
    assert_eq!(after, confirming, "a confirmed exit is not read again");
    child.wait().unwrap();
}

/// `kernel_task` is pid 0, which macOS resolves: it is no signal target. Mutant: the guard is
/// removed, so a token naming pid 0 reaches the kernel (it answers `EINVAL`, an `Io` error, and the
/// attempt is recorded).
#[skuld::test]
fn pid_zero_is_refused_unassessable() {
    let p = MacProcess {
        id: ProcessId::from_parts_for_test(0, crate::identity::Key::for_test(1)),
        unique: 1,
        idversion: std::sync::atomic::AtomicI32::new(1),
        watch: std::sync::OnceLock::new(),
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
    let bogus = crate::identity::ProcessId::from_parts_for_test(0, crate::identity::Key::for_test(1));
    // The pid holds `kernel_task`, not the process this identity names: nothing opens.
    assert!(
        open(bogus).expect("a pid-0 identity resolves to a stranger").is_none(),
        "a pid-0 identity opens nothing"
    );
    // If the call had reached `kill(2)`, this process would have died with it.
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
            scope.spawn(|| exited_held(p, None)),
            scope.spawn(|| exited_held(p, None)),
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

// MacChild =====

/// A pid past registration at the exit watch's arming (`ESRCH`, forced) is not a failure: the child
/// has exited, `exited` says so, and the reap asks for a recheck while the zombie is not yet
/// visible, then has the record.
///
/// Mutant: `ESRCH` at the exit watch's registration fails the adoption, or reads as a running child.
#[skuld::test]
fn esrch_at_registration_reads_as_exited_and_rechecks() {
    use crate::os_process::child::{adopt_std, PeekOutcome, TryReapOutcome};
    use crate::os_process::macos::kqueue::test_hooks::{force_proc_registration_once, Registration};
    use crate::wait::exit_only::seams::force_peek_once;

    let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    drop(child.stdin.take());
    let id = ProcessId::of(child.id()).found().expect("identity");
    wait_until_zombie(id.pid());
    let forced = force_proc_registration_once(Registration::ExitWatch);
    let os = adopt_std(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    drop(forced);
    assert!(matches!(os.exited().unwrap(), Exit::Exited));
    // The zombie is not yet visible to the look's peek.
    let _running = force_peek_once(Ok(PeekOutcome::Running));
    assert!(matches!(os.try_reap().unwrap(), TryReapOutcome::Recheck));
    assert!(matches!(os.try_reap().unwrap(), TryReapOutcome::Reaped(_)));
}

/// A running child, a [`MacChild`] over it, and the identity, with `silent_watch` making the shared
/// exit watch one that never fires (the force is spent on the adoption, so the exit wait's own
/// registrations are not forced).
fn a_running_child_with_a_watch(
    silent_watch: bool,
) -> (
    std::process::Child,
    std::process::ChildStdin,
    ProcessId,
    crate::os_process::macos::child::MacChild,
) {
    use crate::os_process::macos::child::MacChild;
    use crate::os_process::macos::kqueue::test_hooks::{force_proc_registration_once, Registration};

    let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let UniqRead::Found(read) = uniq_info(id.pid(), ReadPurpose::Kill) else {
        panic!("the blocker's unique id must be readable");
    };
    let silent = silent_watch.then(|| force_proc_registration_once(Registration::SilentExitWatch));
    let mac = MacChild::new(id.pid(), read.unique_id).expect("watch the child");
    drop(silent);
    (child, stdin, id, mac)
}

/// An exit wait whose registration found the pid past registration (`ESRCH`, forced) has no event to
/// come, so a look at a running child is a recheck, never a wait on its kqueue.
///
/// Mutant: `ChildExit::look` drops the `unarmed` branch, so the look is `Step::Wait` on a kqueue
/// nothing will ever signal.
#[skuld::test]
fn an_exit_wait_that_found_no_registration_rechecks_instead_of_waiting() {
    use crate::os_process::drive::Step;
    use crate::os_process::macos::kqueue::test_hooks::{force_proc_registration_once, Registration};

    let (mut child, stdin, _id, mac) = a_running_child_with_a_watch(false);
    let forced = force_proc_registration_once(Registration::Reap);
    let mut wait = mac.exit_wait().expect("arm the wait");
    drop(forced);
    assert!(
        matches!(wait.look(), Ok(Step::Recheck)),
        "no event will come: the look must not wait"
    );
    drop(wait);
    drop(stdin);
    child.wait().unwrap();
}

/// A drain that read the child's `NOTE_EXIT` while the shared watch still says `Running` (its knote
/// is not queued yet) is a recheck, never a wait on the drained kqueue, whose `NOTE_EXIT` is gone.
/// The shared watch is made silent (it never fires), the child exits, and the wait's own kqueue is
/// the only one that has the event.
///
/// Mutant: `ChildExit::look` drops the `exit_seen` branch, so the look is `Step::Wait` on the drained
/// kqueue and the wake is lost.
#[skuld::test]
fn an_exit_wait_whose_drain_read_the_exit_rechecks_while_the_shared_watch_says_running() {
    use crate::os_process::drive::Step;

    let (mut child, stdin, id, mac) = a_running_child_with_a_watch(true);
    let mut wait = mac.exit_wait().expect("arm the wait");
    drop(stdin);
    // `NOTE_EXIT` precedes the zombie state, so the event is queued on the wait's kqueue by now.
    wait_until_zombie(id.pid());
    assert!(
        matches!(wait.look(), Ok(Step::Recheck)),
        "the drain read NOTE_EXIT and the shared watch says Running"
    );
    drop(wait);
    child.wait().unwrap();
}

/// A drain that read the child's `NOTE_EXIT` and `NOTE_REAP` (the child was reaped after the wait
/// was armed) is read as the pid gone: the look is `Done`, not the recheck a drained `NOTE_EXIT`
/// alone gets. The shared watch is silent, so the answer is the exit read's and not the watch's.
///
/// Mutant: `ChildExit::look` answers `Recheck` for any drained `NOTE_EXIT` before it asks `exited`,
/// so a reaped child is rechecked for ever.
#[skuld::test]
fn an_exit_wait_whose_drain_read_the_reap_is_done_because_the_pid_is_gone() {
    use crate::os_process::drive::Step;

    let (mut child, stdin, id, mac) = a_running_child_with_a_watch(true);
    let mut wait = mac.exit_wait().expect("arm the wait");
    drop(stdin);
    wait_until_zombie(id.pid());
    child.wait().unwrap();
    assert!(
        matches!(wait.look(), Ok(Step::Done(()))),
        "NOTE_EXIT and NOTE_REAP were drained, and the pid is gone"
    );
}

/// A pid past registration at the reap registration (`ESRCH`, forced) is not a failure either, and it
/// is no news about the exit: the exit watch registered on its own and the running child reads
/// `Running`. The forcing was the reap's (the exit watch's registration left it armed).
///
/// Mutant: `ESRCH` at the reap registration fails the adoption, or reads the child as exited (marks
/// the exit watch fired).
#[skuld::test]
fn esrch_at_the_reap_registration_adopts_a_running_child() {
    use crate::os_process::macos::child::MacChild;
    use crate::os_process::macos::kqueue::test_hooks::{
        force_proc_registration_once, take_forced_registration, Registration,
    };

    let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let id = ProcessId::of(child.id()).found().expect("identity");
    let UniqRead::Found(read) = uniq_info(id.pid(), ReadPurpose::Kill) else {
        panic!("the blocker's unique id must be readable");
    };
    let forced = force_proc_registration_once(Registration::Reap);
    let os = MacChild::new(id.pid(), read.unique_id).expect("the reap's ESRCH is no failure");
    assert!(
        !take_forced_registration(Registration::Reap),
        "the reap registration consumed the forcing"
    );
    drop(forced);
    assert!(
        matches!(os.exited().unwrap(), Exit::Running(_)),
        "the exit watch registered on its own: the child runs"
    );
    drop(stdin);
    child.wait().unwrap();
}

/// A child whose tracer began its exit, then lost its own tracer, is held by launchd with its
/// `p_oppid` kept: its `NOTE_EXIT` reaches only launchd, so nothing wakes a wait on the reap kqueue.
/// The look is `Recheck`, which the driver paces, not `Running` on that kqueue. This process's own
/// pid stands in for the child, held by a blocker whose forced parents say launchd holds it.
///
/// Mutant: a tracer launchd holds answers `Running` on the reap kqueue: the wait blocks for an event
/// that never comes.
#[skuld::test]
fn a_child_whose_tracer_is_exiting_at_launchd_is_a_recheck() {
    use crate::identity::{ppid_fault, LAUNCHD};
    use crate::os_process::child::{OsChild, TryReapOutcome};
    use crate::os_process::macos::child::MacChild;
    use crate::wait::exit_only::macos_tests::echild_yet_resolvable;

    let (pid, unique) = echild_yet_resolvable();
    let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
    let mut tracer = crate::test_spawn::spawn(&mut cmd).expect("spawn the stand-in tracer");
    let tracer_stdin = tracer.stdin.take();
    let tracer_pid = tracer.id();
    let _parent = ppid_fault::force_ppid_with(move || Ok(tracer_pid));
    let _dying = crate::identity::kinfo::fault::force_parents(tracer_pid, || {
        (std::process::id() as libc::pid_t, LAUNCHD as libc::pid_t)
    });
    let mac = MacChild::new(pid, unique).expect("watch the stand-in");

    let look = mac.try_reap().expect("look");

    assert!(matches!(look, TryReapOutcome::Recheck), "{look:?}");
    drop(tracer_stdin);
    tracer.wait().expect("reap the stand-in tracer");
}

const KQUEUE_MARKER: &str = "COSCA_TESTCFG_MACCHILD_KQUEUE";
const KQUEUE_CASE_ENV: &str = "COSCA_TESTCFG_MACCHILD_KQUEUE_CASE";

/// A refused kqueue fails the adoption with the refusal, instead of an adopted child that can
/// never be waited on. The descriptor table is full from the fixture's own lowered limit, so the
/// adoption's `kqueue()` is refused; each case runs in a fresh re-exec, since the limit is
/// process-wide.
///
/// Mutant: the adoption ignores a failed `kqueue()`.
#[skuld::test]
fn adoption_fails_when_a_kqueue_cannot_be_made() {
    if !crate::test_child::is_marked_fixture_reexec(KQUEUE_MARKER) {
        crate::test_child::run_fixture_case(
            crate::test_child::fixture_path!(adoption_fails_when_a_kqueue_cannot_be_made),
            KQUEUE_MARKER,
            KQUEUE_CASE_ENV,
            "",
        );
        return;
    }
    use crate::os_process::child::adopt_std;

    let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let id = ProcessId::of(child.id()).found().expect("identity");
    // SAFETY: plain descriptor and resource-limit calls on this throwaway re-exec; the limit is
    // lowered to the lowest free descriptor, so the next one is refused, and restored after.
    let (saved, probe) = unsafe {
        let probe = libc::dup(0);
        assert!(probe > 0, "dup: {}", std::io::Error::last_os_error());
        let mut saved = std::mem::zeroed::<libc::rlimit>();
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut saved), 0);
        let lowered = libc::rlimit {
            rlim_cur: probe as libc::rlim_t,
            rlim_max: saved.rlim_max,
        };
        assert_eq!(libc::close(probe), 0);
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lowered), 0);
        (saved, probe)
    };
    let adopted = adopt_std(child, id);
    // SAFETY: restores the limit saved above.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &saved) }, 0);
    let (error, mut child) = match adopted {
        Ok(_) => panic!("adopted with the descriptor table full (limit {probe})"),
        Err(refused) => refused,
    };
    let Error::Io(e) = &error else {
        panic!("a refused kqueue is an io error: {error:?}")
    };
    assert_eq!(e.raw_os_error(), Some(libc::EMFILE), "{e:?}");
    drop(stdin);
    child.wait().expect("the child is handed back unreaped");
}

/// A reap of a running child waits on the reap kqueue, a descriptor of its own beside the exit
/// kqueue a look hands out: the one is drained by the reap's holder, the other is never read.
///
/// Mutant: the reap waits on the exit kqueue, which its holder's drain would then empty for every
/// other waiter.
#[skuld::test]
fn try_reap_of_a_running_child_waits_on_the_reap_kqueue() {
    use std::os::fd::AsRawFd;

    use crate::os_process::child::{adopted_blocker, TryReapOutcome};
    use crate::os_process::WaitFor;
    let (os, id, stdin) = adopted_blocker();
    let Exit::Running(WaitFor::Readable(exit_fd)) = os.exited().unwrap() else {
        panic!("a live child reads Running");
    };
    let TryReapOutcome::Running(WaitFor::Readable(reap_fd)) = os.try_reap().unwrap() else {
        panic!("a running child is waited on its reap kqueue");
    };
    assert_ne!(reap_fd.as_raw_fd(), exit_fd.as_raw_fd());
    drop(stdin);
    assert!(exited_held(&*os, None).unwrap());
    // `NOTE_EXIT` can come before XNU shows the zombie to `waitid`.
    wait_until_zombie(id.pid());
    assert!(matches!(
        os.try_reap().unwrap(),
        crate::os_process::child::TryReapOutcome::Reaped(_)
    ));
}

/// A peek of an exited child sees its record and consumes nothing: the reap that follows has it.
///
/// Mutant: the peek is a consuming `waitid`.
#[skuld::test]
fn peek_of_an_exited_child_consumes_nothing() {
    use crate::os_process::child::{adopted_blocker, PeekOutcome, TryReapOutcome};
    let (os, id, stdin) = adopted_blocker();
    drop(stdin);
    assert!(exited_held(&*os, None).unwrap());
    // `NOTE_EXIT` can come before XNU shows the zombie to `waitid`.
    wait_until_zombie(id.pid());
    assert!(matches!(os.peek().unwrap(), PeekOutcome::Exit(_)));
    assert!(matches!(os.peek().unwrap(), PeekOutcome::Exit(_)));
    assert!(matches!(os.try_reap().unwrap(), TryReapOutcome::Reaped(_)));
}
