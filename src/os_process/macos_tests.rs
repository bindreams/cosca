use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

use super::{signal_by_token, ExitWatch, MacosProcess, SignalByTokenOutcome};
use crate::child::spawn::identity_macos_tests::other_unique_id;
use crate::error::Error;
use crate::identity::kinfo::kinfo_proc;
use crate::identity::{FakeKernel, HostKernel, Kernel as _, ProcessId, UniqInfo, UniqRead};
use crate::os_process::drive::exited_held;
use crate::os_process::{kill, open, terminate, Exit, OsProcess};
use crate::signal::{Sent, Sig};
use crate::test_child::{wait_until_zombie, StdChild};
use crate::wait::exit_only::macos_tests::unique_of;
use crate::wait::macos::reap_registration;

// ExitWatch =====

#[skuld::test]
fn a_watch_on_a_live_process_reads_not_exited() {
    let (_child, id) = blocker();
    let watch = ExitWatch::proc_exit(&HostKernel, id.pid()).unwrap();
    assert!(!watch.exited().unwrap());
}

/// Mutant: a look reads the queue, so the second look finds it empty.
#[skuld::test]
fn a_look_at_an_exited_process_does_not_consume_the_exit() {
    let (mut child, id) = blocker();
    let watch = ExitWatch::proc_exit(&HostKernel, id.pid()).unwrap();
    child.kill().unwrap();
    wait_until_zombie(id.pid());
    assert!(watch.exited().unwrap());
    assert!(watch.exited().unwrap(), "the exit is still there for the next look");
}

/// A pid above the kernel's pid limit is past registration, as an exited process is: `ESRCH`.
#[skuld::test]
fn a_watch_armed_past_registration_reads_exited() {
    let watch = ExitWatch::proc_exit(&HostKernel, i32::MAX as u32).unwrap();
    assert!(watch.exited().unwrap());
}

// MacosProcess =====

/// A live `cat` blocker, held open by the child's own piped stdin, and its identity.
fn blocker() -> (StdChild, ProcessId) {
    let child = crate::test_child::blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    (child, id)
}

/// The host's kernel, except that the registration of `pid`'s exit watch is refused with `ESRCH`:
/// the watch reads fired while the process runs, as XNU posts the exit edge before `p_stat = SZOMB`.
fn a_kernel_that_fires_the_exit_watch(pid: u32) -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel).on_subscribe_refused(ExitWatch::registration(pid), libc::ESRCH)
}

/// What the host says of `id`'s process: the answer a row repeats where a test lets that read pass.
fn own_unique_info(id: ProcessId) -> UniqInfo {
    let UniqRead::Found(info) = HostKernel.unique_info(id.pid()) else {
        panic!("the live blocker has a unique id");
    };
    info
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

/// A held process keeps the kernel it was opened with: a later look is answered by it. The fake's
/// rows are the open's unique-id read (the process's own), then the exit watch's arming read and
/// the look's, which both say the pid is gone, so the live blocker reads exited. Mutant: "the held
/// process looks through `HostKernel`": the blocker reads `Running`.
#[skuld::test]
fn a_held_process_looks_through_the_kernel_it_was_opened_with() {
    use crate::os_process::open_with;

    let (_child, id) = blocker();
    let UniqRead::Found(own) = HostKernel.unique_info(id.pid()) else {
        panic!("the live blocker has a unique id");
    };
    let kernel = FakeKernel::over(&HostKernel)
        .on_unique_info(id.pid(), UniqRead::Found(own))
        .on_unique_info(id.pid(), UniqRead::Gone)
        .on_unique_info(id.pid(), UniqRead::Gone);
    let p = open_with(kernel, id)
        .unwrap()
        .expect("the open reads the process's own id");
    assert!(
        matches!(p.exited().unwrap(), Exit::Exited),
        "the look is the kernel's, not the live blocker's"
    );
}

#[skuld::test]
fn open_with_wrong_start_token_is_none_and_sends_nothing() {
    let (_child, id) = blocker();
    let sends = crate::send_log::Capture::start();
    let other = id.with_other_value();
    assert!(open(other).unwrap().is_none(), "a wrong start token opens nothing");
    assert_eq!(sends.by_identity(), vec![], "nothing may be sent to a stranger");
    // Still running: the right identity opens and sees no exit.
    let p = open(id).unwrap().expect("the blocker is alive");
    assert!(!exited_held(&*p, Some(Duration::ZERO)).unwrap());
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
    let mut child = StdChild::spawn(&mut cmd);
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
    use crate::os_process::open_with;

    let (mut child, id) = blocker();
    // The open's own read, then the re-read after the signal found a zombie (`ESRCH`).
    let kernel = FakeKernel::over(&HostKernel)
        .on_unique_info(id.pid(), UniqRead::Found(own_unique_info(id)))
        .on_unique_info(id.pid(), UniqRead::Refused(libc::EPERM));
    let p = open_with(kernel, id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    wait_until_zombie(id.pid());
    let err = p.signal(Sig::Kill).expect_err("a refused re-read is an error");
    let Error::Io(io) = &err else {
        panic!("a refused re-read is Error::Io: {err:?}");
    };
    assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied, "{err:?}");
}

/// The token send answers `EPERM` to a process whose exit has begun and that is not yet a zombie
/// (`P_WEXIT` set, `p_stat` `SRUN`). The send is not an error then, and not a refusal: the process is
/// on its way out.
///
/// The `EPERM` and the record are stated here, not read from a really exiting child: the window is
/// too narrow for a host test of it to be deterministic.
///
/// Mutants: the `EPERM` is surfaced raw whether or not the exit has begun; the exit is read from
/// `p_stat` alone (`SZOMB`), which is not set in this window.
#[skuld::test]
fn a_token_send_refused_while_the_exit_has_begun_is_exiting() {
    let (_child, id) = blocker();
    let known = own_unique_info(id);
    let kernel = FakeKernel::over(&HostKernel).on_kinfo(id.pid(), kinfo_proc::of_host_with_exit(id.pid(), true));
    let mut idversion = known.id_version;
    let refused = crate::signal::seams::refuse_kills();
    let outcome = signal_by_token(&kernel, id.pid(), known.unique_id, &mut idversion, Sig::Kill);
    drop(refused);
    assert_eq!(
        outcome.expect("an exiting process is no refuser"),
        SignalByTokenOutcome::Exiting
    );
    assert!(
        kernel.all_rows_taken(),
        "the exit was read once, from the kernel the send was given"
    );
}

/// An `EPERM` from a process whose exit has not begun is a refusal, and stays the raw errno
/// (`Process::kill` and `Child::kill` promise it).
///
/// Mutant: any `EPERM` is read as an exit.
#[skuld::test]
fn a_token_send_refused_with_no_exit_begun_keeps_the_raw_eperm() {
    let (_child, id) = blocker();
    let known = own_unique_info(id);
    let kernel = FakeKernel::over(&HostKernel).on_kinfo(id.pid(), kinfo_proc::of_host_with_exit(id.pid(), false));
    let mut idversion = known.id_version;
    let refused = crate::signal::seams::refuse_kills();
    let outcome = signal_by_token(&kernel, id.pid(), known.unique_id, &mut idversion, Sig::Kill);
    drop(refused);
    let err = outcome.expect_err("a live refuser is an error");
    assert_eq!(err.raw_os_error(), Some(libc::EPERM), "{err}");
    assert!(kernel.all_rows_taken(), "the exit was read, and found running");
}

/// An exit that cannot be read leaves the `EPERM` as it was answered.
///
/// Mutant: an unreadable exit is read as begun.
#[skuld::test]
fn a_token_send_refused_with_an_unreadable_exit_keeps_the_raw_eperm() {
    let (_child, id) = blocker();
    let known = own_unique_info(id);
    let kernel = FakeKernel::over(&HostKernel).on_kinfo_refused(id.pid(), libc::EACCES);
    let mut idversion = known.id_version;
    let refused = crate::signal::seams::refuse_kills();
    let outcome = signal_by_token(&kernel, id.pid(), known.unique_id, &mut idversion, Sig::Kill);
    drop(refused);
    let err = outcome.expect_err("an unreadable exit settles nothing");
    assert_eq!(err.raw_os_error(), Some(libc::EPERM), "{err}");
    assert!(kernel.all_rows_taken(), "the exit was read, and refused");
}

/// Only a `SIGKILL` is read for an exit: any other signal refused with `EPERM` keeps the raw errno,
/// and the process's record is never read.
///
/// Mutant: the `EPERM` of a `SIGTERM` is read as an exit, so the refusal reads as delivered.
#[skuld::test]
fn a_sigterm_refused_with_eperm_keeps_the_raw_eperm_whatever_the_exit() {
    let (_child, id) = blocker();
    let known = own_unique_info(id);
    let kernel = FakeKernel::over(&HostKernel).on_kinfo(id.pid(), kinfo_proc::of_host_with_exit(id.pid(), true));
    let mut idversion = known.id_version;
    let refused = crate::signal::seams::refuse_kills();
    let outcome = signal_by_token(&kernel, id.pid(), known.unique_id, &mut idversion, Sig::Term);
    drop(refused);
    let err = outcome.expect_err("only a SIGKILL's refusal is read for an exit");
    assert_eq!(err.raw_os_error(), Some(libc::EPERM), "{err}");
    assert_eq!(kernel.kinfo_reads(id.pid()), 0, "the record is never read");
}

/// The exit is read between two unique-id reads. The first matches and the `kinfo_proc` read between
/// them shows the exit begun; the second answers another process, none, or a refusal. The record is
/// then of no process the send was for, or unproven: another process or none is `Gone`, a refused
/// read keeps the raw `EPERM`.
///
/// Mutant: the second unique-id read is not made, or its refusal is read as an answer.
#[skuld::test]
fn a_pid_taken_or_a_read_refused_after_the_exit_was_read_settles_nothing() {
    type Second = fn(u32) -> UniqRead;
    let cases: [(Second, Option<SignalByTokenOutcome>); 3] = [
        (other_unique_id, Some(SignalByTokenOutcome::Gone)),
        (|_| UniqRead::Gone, Some(SignalByTokenOutcome::Gone)),
        (|_| UniqRead::Refused(libc::EACCES), None),
    ];
    for (second, expected) in cases {
        let (_child, id) = blocker();
        let known = own_unique_info(id);
        let kernel = FakeKernel::over(&HostKernel)
            .on_unique_info(id.pid(), UniqRead::Found(known))
            .on_kinfo(id.pid(), kinfo_proc::of_host_with_exit(id.pid(), true))
            .on_unique_info(id.pid(), second(id.pid()));
        let mut idversion = known.id_version;
        let refused = crate::signal::seams::refuse_kills();
        let outcome = signal_by_token(&kernel, id.pid(), known.unique_id, &mut idversion, Sig::Kill);
        drop(refused);
        match expected {
            Some(expected) => assert_eq!(outcome.expect("answered"), expected),
            None => {
                let err = outcome.expect_err("a refused read settles nothing");
                assert_eq!(err.raw_os_error(), Some(libc::EPERM), "{err}");
            }
        }
        assert!(kernel.all_rows_taken(), "both id reads and the exit read were made");
    }
}

/// An `EPERM` from a pid that is gone by the time the exit is read is a process that is gone. The
/// kernel states the pid gone, so the test does not rely on a freed pid staying unused.
///
/// Mutant: the `EPERM` is surfaced for a pid no process holds.
#[skuld::test]
fn a_token_send_refused_for_a_pid_that_is_gone_is_gone() {
    let (_child, id) = blocker();
    let known = own_unique_info(id);
    let kernel = FakeKernel::over(&HostKernel).on_unique_info(id.pid(), UniqRead::Gone);
    let mut idversion = known.id_version;
    let refused = crate::signal::seams::refuse_kills();
    let outcome = signal_by_token(&kernel, id.pid(), known.unique_id, &mut idversion, Sig::Kill);
    drop(refused);
    assert_eq!(
        outcome.expect("a gone process is no refuser"),
        SignalByTokenOutcome::Gone
    );
    assert!(kernel.all_rows_taken());
}

/// An `EPERM` whose pid names another process by the time the exit is read is a process that is gone:
/// the other process's exit state says nothing of ours, even when it shows the exit begun.
///
/// Mutant: the exit is read by bare pid, so the other process's `P_WEXIT` reads as ours (`Exiting`).
#[skuld::test]
fn a_token_send_refused_for_a_pid_that_names_another_process_is_gone() {
    let (_child, id) = blocker();
    let known = own_unique_info(id);
    let kernel = FakeKernel::over(&HostKernel)
        .on_unique_info(id.pid(), other_unique_id(id.pid()))
        .on_kinfo(id.pid(), kinfo_proc::of_host_with_exit(id.pid(), true));
    let mut idversion = known.id_version;
    let refused = crate::signal::seams::refuse_kills();
    let outcome = signal_by_token(&kernel, id.pid(), known.unique_id, &mut idversion, Sig::Kill);
    drop(refused);
    assert_eq!(
        outcome.expect("another process's pid is no refuser"),
        SignalByTokenOutcome::Gone
    );
    assert_eq!(
        kernel.kinfo_reads(id.pid()),
        0,
        "another process's record is never read"
    );
}

/// An `EPERM` from a zombie is a process that has exited and is not reaped, as `ESRCH` from one is:
/// `p_stat` is `SZOMB`, which is not the `Exiting` window.
///
/// Mutant: a zombie's `EPERM` reads as `Exiting`, which every caller reads as delivered, so a holder
/// of no child waits for an exit that has happened.
#[skuld::test]
fn a_token_send_refused_by_a_zombie_is_exited_unreaped() {
    let (_child, id) = blocker();
    let known = own_unique_info(id);
    let mut zombie = kinfo_proc::of_host_with_exit(id.pid(), true);
    zombie.kp_proc.p_stat = libc::SZOMB as libc::c_char;
    let kernel = FakeKernel::over(&HostKernel).on_kinfo(id.pid(), zombie);
    let mut idversion = known.id_version;
    let refused = crate::signal::seams::refuse_kills();
    let outcome = signal_by_token(&kernel, id.pid(), known.unique_id, &mut idversion, Sig::Kill);
    drop(refused);
    assert_eq!(
        outcome.expect("a zombie is no refuser"),
        SignalByTokenOutcome::ExitedUnreaped
    );
}

/// A held process whose exit has begun reads as signalled: its exit is what the kill is for, and the
/// kill's wait goes on to wait for it. A zombie, which is gone to a holder of no child, stays `Gone`
/// (`signal_to_a_zombie_is_gone_after_one_attempt`).
///
/// Mutant: an exiting process is read as `Gone`, so the wait skips it.
#[skuld::test]
fn signal_to_a_process_whose_exit_began_is_delivered() {
    use crate::os_process::open_with;

    let (_child, id) = blocker();
    let kernel = FakeKernel::over(&HostKernel)
        .on_unique_info(id.pid(), UniqRead::Found(own_unique_info(id)))
        .on_kinfo(id.pid(), kinfo_proc::of_host_with_exit(id.pid(), true));
    let p = open_with(kernel, id).unwrap().expect("a live process opens");
    let refused = crate::signal::seams::refuse_kills();
    let sent = p.signal(Sig::Kill);
    drop(refused);
    assert_eq!(sent.unwrap(), Sent::Delivered);
}

/// Mutant: the open arms the watch, so it costs a descriptor and a send can fail for want of one.
#[skuld::test]
fn an_open_and_a_send_arm_no_watch_and_the_first_look_arms_it() {
    let (_child, id) = blocker();
    let p = MacosProcess::open(HostKernel, id)
        .unwrap()
        .expect("a live process opens");
    assert!(p.watch.get().is_none(), "an open arms nothing");
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(p.watch.get().is_none(), "a send arms nothing");
    assert!(exited_held(&p, None).unwrap());
    assert!(p.watch.get().is_some(), "the first look arms the watch");
}

/// A watch that has fired is an exit only once the process is a zombie or gone. The registration
/// refusal stands in for the exit edge XNU posts before `p_stat = SZOMB` (a pid past `P_REF_DEAD`
/// is refused as an exited one is): the watch reads fired while the process still runs.
///
/// Mutant: `exited` answers `Exited` on the watch alone, so the first look is `Exited`.
#[skuld::test]
fn a_fired_watch_on_a_process_is_exited_only_once_it_is_a_zombie() {
    let (_child, id) = blocker();
    let kernel = std::sync::Arc::new(a_kernel_that_fires_the_exit_watch(id.pid()));
    let p = MacosProcess::open(std::sync::Arc::clone(&kernel), id)
        .unwrap()
        .expect("a live process opens");
    assert!(
        matches!(p.exited(), Ok(Exit::Recheck)),
        "the watch fired, the process is not a zombie"
    );
    assert!(
        kernel.all_rows_taken(),
        "the first look's registration consumed the refusal"
    );
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    wait_until_zombie(id.pid());
    assert!(matches!(p.exited(), Ok(Exit::Exited)));
}

/// A spawned blocker child, its stdin, its identity, a [`MacosChild`] over the kernel `kernel` builds
/// from the child's identity, whose exit watch has fired while it runs (see
/// [`a_kernel_that_fires_the_exit_watch`]), and a handle to that kernel.
fn a_child_with_a_fired_watch(
    kernel: impl FnOnce(FakeKernel<'static>, ProcessId) -> FakeKernel<'static>,
) -> (
    StdChild,
    std::process::ChildStdin,
    ProcessId,
    crate::os_process::macos::child::MacosChild<std::sync::Arc<FakeKernel<'static>>>,
    std::sync::Arc<FakeKernel<'static>>,
) {
    use crate::os_process::macos::child::MacosChild;

    let mut child = crate::test_child::blocker();
    let stdin = child.stdin.take().expect("piped stdin");
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let unique = unique_of(id.pid());
    let kernel = std::sync::Arc::new(kernel(a_kernel_that_fires_the_exit_watch(id.pid()), id));
    let mac = MacosChild::new(std::sync::Arc::clone(&kernel), id.pid(), unique).expect("watch the child");
    (child, stdin, id, mac, kernel)
}

/// [`a_fired_watch_on_a_process_is_exited_only_once_it_is_a_zombie`] for the owned child.
///
/// Mutant: `MacosChild::exited` answers `Exited` on the watch alone, so the first look is `Exited`.
#[skuld::test]
fn a_fired_watch_on_a_child_is_exited_only_once_it_is_a_zombie() {
    let (_child, stdin, id, mac, kernel) = a_child_with_a_fired_watch(|kernel, _| kernel);
    assert!(
        matches!(mac.exited(), Ok(Exit::Recheck)),
        "the watch fired, the child is not a zombie"
    );
    assert!(
        kernel.all_rows_taken(),
        "the adoption's registration consumed the refusal"
    );
    drop(stdin);
    wait_until_zombie(id.pid());
    assert!(matches!(mac.exited(), Ok(Exit::Exited)));
}

/// A look at a watch that has not fired reads no state of the process: a process's first look arms
/// the watch, which proves the process by one unique-id read, and later looks read nothing; a child's,
/// whose parent is this process, reads only that parent (two unique-id reads), never whether it is a
/// zombie.
///
/// Mutant: `ExitWatch::look` reads the process's state before it asks the watch; `MacosChild::exited`
/// reads whether the child is a zombie while this process is its parent.
#[skuld::test]
fn the_first_look_at_an_unfired_watch_arms_it_by_one_read_and_reads_no_state() {
    use crate::os_process::macos::child::MacosChild;

    let (_child, id) = blocker();
    let info = own_unique_info(id);
    let found = || UniqRead::Found(info);
    let refused = || UniqRead::Refused(libc::EPERM);
    // The open's read and the arming's.
    let process_kernel = FakeKernel::over(&HostKernel)
        .on_unique_info(id.pid(), found())
        .on_unique_info(id.pid(), found())
        .on_unique_info(id.pid(), refused());
    let p = MacosProcess::open(process_kernel, id)
        .unwrap()
        .expect("a live process opens");
    // The child's parent read: the unique id before and after it.
    let child_kernel = FakeKernel::over(&HostKernel)
        .on_unique_info(id.pid(), found())
        .on_unique_info(id.pid(), found())
        .on_unique_info(id.pid(), refused());
    let mac = MacosChild::new(child_kernel, id.pid(), info.unique_id).expect("watch the child");
    assert!(
        matches!(p.exited(), Ok(Exit::Running(_))),
        "the first look arms the watch with one read of the unique id and reads no state: Running"
    );
    assert!(
        matches!(p.exited(), Ok(Exit::Running(_))),
        "a look at an armed, unfired watch reads nothing"
    );
    assert!(
        matches!(mac.exited(), Ok(Exit::Running(_))),
        "an unfired watch on a running child reads its parent and nothing else"
    );
}

/// The driver waits through a fired watch until the process is a zombie, and what it returns is the
/// state [`ProcessId::is_alive`] reads: `Dead`.
///
/// Mutant: the production `exited` skips the confirmation, so the deadline-less zero wait on the
/// still-running process says `true`.
#[skuld::test]
fn a_wait_through_a_fired_watch_returns_a_process_that_reads_dead() {
    use crate::identity::Liveness;
    use crate::os_process::open_with;

    let (_child, id) = blocker();
    let kernel = std::sync::Arc::new(a_kernel_that_fires_the_exit_watch(id.pid()));
    let p = open_with(std::sync::Arc::clone(&kernel), id)
        .unwrap()
        .expect("a live process opens");
    assert!(
        !exited_held(&*p, Some(Duration::ZERO)).unwrap(),
        "a fired watch on a process that runs is not an exit"
    );
    assert!(kernel.all_rows_taken(), "the watch's registration consumed the refusal");
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(exited_held(&*p, None).unwrap());
    assert_eq!(id.is_alive(), Liveness::Dead);
}

/// [`a_wait_through_a_fired_watch_returns_a_process_that_reads_dead`] through the tokio driver.
///
/// Mutant: as there; or the driver arms no watch through the process's kernel, so the watch never
/// fired and the rest proves nothing.
#[cfg(feature = "tokio")]
#[skuld::test]
async fn a_tokio_wait_through_a_fired_watch_returns_a_process_that_reads_dead() {
    use crate::identity::Liveness;
    use crate::os_process::open_with;
    use crate::tokio::drive::exited_held;

    let (_child, id) = blocker();
    let kernel = std::sync::Arc::new(a_kernel_that_fires_the_exit_watch(id.pid()));
    let p = open_with(std::sync::Arc::clone(&kernel), id)
        .unwrap()
        .expect("a live process opens");
    assert!(
        !exited_held(&*p, Some(Duration::ZERO)).await.unwrap(),
        "a fired watch on a process that runs is not an exit"
    );
    assert!(kernel.all_rows_taken(), "the watch's registration consumed the refusal");
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(exited_held(&*p, None).await.unwrap());
    assert_eq!(id.is_alive(), Liveness::Dead);
}

/// A refused read of the process's state is not an exit: `Unassessable`, with the errno as its source.
fn assert_a_refused_confirmation_is_unassessable_with_the_errno(p: &dyn OsProcess) {
    let err = p.exited().expect_err("a refused read is an error");
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err:?}");
}

/// [`assert_a_refused_confirmation_is_unassessable_with_the_errno`] for a [`MacosProcess`].
///
/// Mutant: a refused read answers `Exited`, or loses the errno.
#[skuld::test]
fn a_refused_confirmation_of_a_process_is_unassessable_with_the_errno() {
    use crate::os_process::open_with;

    let (_child, id) = blocker();
    // The open's read, the arming's, then the confirming one, which is refused.
    let own = UniqRead::Found(own_unique_info(id));
    let kernel = std::sync::Arc::new(
        a_kernel_that_fires_the_exit_watch(id.pid())
            .on_unique_info(id.pid(), own)
            .on_unique_info(id.pid(), own)
            .on_unique_info(id.pid(), UniqRead::Refused(libc::EPERM)),
    );
    let p = open_with(std::sync::Arc::clone(&kernel), id)
        .unwrap()
        .expect("a live process opens");
    assert_a_refused_confirmation_is_unassessable_with_the_errno(&*p);
    assert!(
        kernel.all_rows_taken(),
        "the open, the arming and the confirming read each read"
    );
}

/// [`assert_a_refused_confirmation_is_unassessable_with_the_errno`] for a [`MacosChild`].
///
/// Mutant: as there.
#[skuld::test]
fn a_refused_confirmation_of_a_child_is_unassessable_with_the_errno() {
    // The child's first read is the confirming one.
    let (_child, stdin, _id, mac, kernel) =
        a_child_with_a_fired_watch(|kernel, id| kernel.on_unique_info(id.pid(), UniqRead::Refused(libc::EPERM)));
    assert_a_refused_confirmation_is_unassessable_with_the_errno(&mac);
    assert!(
        kernel.all_rows_taken(),
        "the adoption's registration was refused, and the confirming read was refused"
    );
    drop(stdin);
}

/// A watch armed while another process holds the pid reads `Exited`: the arming's and the
/// confirming unique-id reads both name another process. The live blocker stands for it.
///
/// Mutant: the arming ignores its unique-id read, so a pid taken between the open and the first look
/// is watched as the original; or the confirmation keys on the pid, so the process that holds it
/// now is read as the watched one and the wait is `Recheck` for ever.
#[skuld::test]
fn a_watch_armed_while_another_process_holds_the_pid_reads_exited() {
    use crate::os_process::open_with;

    let (_child, id) = blocker();
    // The open's read, then the arming's and the confirming one, which name another process.
    let kernel = FakeKernel::over(&HostKernel)
        .on_unique_info(id.pid(), UniqRead::Found(own_unique_info(id)))
        .on_unique_info(id.pid(), other_unique_id(id.pid()))
        .on_unique_info(id.pid(), other_unique_id(id.pid()));
    let p = open_with(kernel, id).unwrap().expect("a live process opens");
    assert!(
        matches!(p.exited(), Ok(Exit::Exited)),
        "the process that was opened is not the one holding the pid"
    );
}

/// Mutant: a refused read at the arming is read as an exit, or loses the errno.
#[skuld::test]
fn a_refused_read_at_the_arming_is_unassessable_with_the_errno() {
    use crate::os_process::open_with;

    let (_child, id) = blocker();
    // The open's read, then the arming's, which is refused.
    let kernel = FakeKernel::over(&HostKernel)
        .on_unique_info(id.pid(), UniqRead::Found(own_unique_info(id)))
        .on_unique_info(id.pid(), UniqRead::Refused(libc::EPERM));
    let p = open_with(kernel, id).unwrap().expect("a live process opens");
    let err = p.exited().expect_err("a refused read is an error");
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err:?}");
}

/// Mutant: a refused read in `open` is "gone" (an exit that never happened), or loses the errno.
#[skuld::test]
fn open_with_a_refused_read_is_unassessable_with_the_errno() {
    let (_child, id) = blocker();
    let kernel = FakeKernel::over(&HostKernel).on_unique_info(id.pid(), UniqRead::Refused(libc::EPERM));
    let err = MacosProcess::open(kernel, id).expect_err("a refused read is an error");
    let Error::Unassessable {
        source: Some(source), ..
    } = &err
    else {
        panic!("a refused read is Unassessable with its errno as source: {err:?}");
    };
    assert_eq!(crate::error::first_os_code(&**source), Some(libc::EPERM));
}

#[skuld::test]
fn a_refused_identity_read_for_an_open_keeps_its_errno_as_the_source() {
    let kernel = FakeKernel::new().on_unique_info(77, UniqRead::Refused(libc::EPERM));
    let err = super::read_for_open(&kernel, 77, "it was not opened").expect_err("refused");
    match &err {
        Error::Unassessable { detail, .. } => {
            assert_eq!(detail, "pid 77 identity could not be read; it was not opened");
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err:?}");
}

/// A refused `has_exited` read is `Unassessable` with the errno as its source, and the message
/// does not word it as an "errno". Both readers of it (`ExitWatch::look` and `MacosChild::exited` past
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
/// child's parent reads launchd, so the second read is reached. The row states only that parent; the
/// child's state stays the host's.
///
/// Mutant: `MacosChild::exited` wraps the errno as `Error::Io`, words another situation, or answers
/// `Running` for a read it could not make.
#[skuld::test]
fn a_refused_read_past_an_unfired_watch_is_unassessable_with_the_errno() {
    use crate::identity::LAUNCHD;
    use crate::os_process::macos::child::MacosChild;
    use crate::wait::exit_only::macos_tests::parent_reads;

    for zombie_read in [false, true] {
        let (_child, id) = blocker();
        let read = own_unique_info(id);
        // The parent read is two unique-id reads around the parent, which is launchd, and the zombie
        // read two more: the third unique-id read is the zombie read's first.
        let mut kernel = parent_reads(id.pid(), LAUNCHD, 1);
        if zombie_read {
            kernel = kernel
                .on_unique_info(id.pid(), UniqRead::Found(read))
                .on_unique_info(id.pid(), UniqRead::Found(read));
        }
        kernel = kernel.on_unique_info(id.pid(), UniqRead::Refused(libc::EPERM));
        let mac = MacosChild::new(kernel, id.pid(), read.unique_id).expect("watch the child");
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
    }
}

/// A child whose parent is another process (its tracer, or launchd) gets no `NOTE_EXIT` from XNU, so
/// its unfired watch cannot say it is running: while the process is no zombie, the look is
/// `Recheck`, which the driver paces. This process's own pid stands in for the child, and its parent
/// reads are stated.
///
/// Mutant: an unfired watch on a child another process holds is `Running`, so a wait on it blocks
/// for an event that never comes.
#[skuld::test]
fn an_unfired_watch_on_a_running_child_another_process_holds_is_a_recheck() {
    use crate::identity::{short_info_held_by, LAUNCHD};
    use crate::os_process::macos::child::MacosChild;
    use crate::wait::exit_only::macos_tests::{echild_yet_resolvable, held_by_a_tracer_pid};

    let (pid, unique) = echild_yet_resolvable();
    // Each look reads the parent, then whether the child is a zombie: two reads of the record.
    let kernel = [LAUNCHD, held_by_a_tracer_pid()]
        .into_iter()
        .fold(FakeKernel::over(&HostKernel), |kernel, parent| {
            kernel
                .on_short_bsd(pid, Ok(short_info_held_by(pid, parent)))
                .on_short_bsd(pid, Ok(short_info_held_by(pid, parent)))
        });
    let mac = MacosChild::new(kernel, pid, unique).expect("watch the stand-in");
    for parent in [LAUNCHD, held_by_a_tracer_pid()] {
        assert!(
            matches!(mac.exited(), Ok(Exit::Recheck)),
            "held by pid {parent}, the child is no zombie and its watch cannot fire"
        );
    }
}

/// A child whose pid names another process now, or none, has been reaped: exited, with its watch
/// unfired. The look remembers it, so later looks read nothing: the kernel states the read of the pid
/// once each way, then a refusal, which a later look that read again would meet.
///
/// Mutant: a reaped child is `Recheck` or `Running`; or the confirmation is not remembered.
#[skuld::test]
fn a_child_that_was_reaped_is_exited_with_its_watch_unfired_and_remembered() {
    use crate::os_process::macos::child::MacosChild;

    for reaped in ["gone", "another process"] {
        let (_child, id) = blocker();
        let read = own_unique_info(id);
        let answer = match reaped {
            "gone" => UniqRead::Gone,
            _ => other_unique_id(id.pid()),
        };
        let kernel = FakeKernel::over(&HostKernel)
            .on_unique_info(id.pid(), answer)
            .on_unique_info(id.pid(), UniqRead::Refused(libc::EPERM));
        let mac = MacosChild::new(kernel, id.pid(), read.unique_id).expect("watch the child");
        assert!(matches!(mac.exited(), Ok(Exit::Exited)), "{reaped}");
        assert!(
            matches!(mac.exited(), Ok(Exit::Exited)),
            "a confirmed exit is not read again: {reaped}"
        );
    }
}

/// Once a look has confirmed the exit, later looks make no read. The process runs throughout and its
/// watch has fired (the registration refusal stands in for the edge), so the host never says it is a
/// zombie: only the kernel's rows can, and the kernel states the reads of the open and the arming,
/// a first confirming look (id, state, id) that finds it running, and a second that finds a zombie.
/// A third and fourth look that read again would meet the host's running process.
///
/// Mutant: `ExitWatch::look` answers `Exited` without its confirming reads, so the first look is not
/// `Recheck`; or it does not remember the confirmation, so the third look is `Recheck`.
#[skuld::test]
fn a_confirmed_exit_is_remembered_and_later_looks_read_nothing() {
    use crate::identity::{short_info, LAUNCHD};
    use crate::os_process::open_with;

    let (_child, id) = blocker();
    let own = UniqRead::Found(own_unique_info(id));
    let kernel = std::sync::Arc::new(
        a_kernel_that_fires_the_exit_watch(id.pid())
            // The open's read, and the arming's.
            .on_unique_info(id.pid(), own)
            .on_unique_info(id.pid(), own)
            // The first confirming look: the process runs.
            .on_unique_info(id.pid(), own)
            .on_short_bsd(id.pid(), Ok(short_info(LAUNCHD, libc::SRUN)))
            .on_unique_info(id.pid(), own)
            // The second: a zombie.
            .on_unique_info(id.pid(), own)
            .on_short_bsd(id.pid(), Ok(short_info(LAUNCHD, libc::SZOMB)))
            .on_unique_info(id.pid(), own),
    );
    let p = open_with(std::sync::Arc::clone(&kernel), id)
        .unwrap()
        .expect("a live process opens");
    assert!(
        matches!(p.exited(), Ok(Exit::Recheck)),
        "the watch fired and the first confirming read finds it running"
    );
    assert!(
        matches!(p.exited(), Ok(Exit::Exited)),
        "the second confirming read finds a zombie"
    );
    assert!(kernel.all_rows_taken(), "the two confirming looks took every row");
    assert!(matches!(p.exited(), Ok(Exit::Exited)));
    assert!(matches!(p.exited(), Ok(Exit::Exited)));
}

/// `kernel_task` is pid 0, which macOS resolves: it is no signal target. Mutant: the guard is
/// removed, so a token naming pid 0 reaches the kernel (it answers `EINVAL`, an `Io` error, and the
/// attempt is recorded).
#[skuld::test]
fn pid_zero_is_refused_unassessable() {
    let p = MacosProcess {
        kernel: HostKernel,
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
    let (_child, id) = blocker();
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
}

// MacosChild =====

/// A pid past registration at the exit watch's arming (`ESRCH`, a refusal row) is not a failure: the
/// child has exited, `exited` says so, and the reap asks for a recheck while the zombie is not yet
/// visible, then has the record.
///
/// Mutant: `ESRCH` at the exit watch's registration fails the adoption, or reads as a running child.
#[skuld::test]
fn esrch_at_registration_reads_as_exited_and_rechecks() {
    use crate::os_process::child::{adopt_std_over, TryObserveOutcome};

    let mut child = crate::test_child::blocker().into_inner();
    drop(child.stdin.take());
    let id = ProcessId::of(child.id()).found().expect("identity");
    wait_until_zombie(id.pid());
    // The zombie is not yet visible to the look's peek.
    let kernel = std::sync::Arc::new(a_kernel_that_fires_the_exit_watch(id.pid()).on_peek(id.pid(), Ok(None)));
    let os = adopt_std_over(
        {
            let kernel = std::sync::Arc::clone(&kernel);
            move |_, _| kernel
        },
        child,
        id,
    )
    .unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    assert!(matches!(os.exited().unwrap(), Exit::Exited));
    assert!(matches!(os.try_observe().unwrap(), TryObserveOutcome::Recheck));
    assert!(
        kernel.all_rows_taken(),
        "the adoption's registration was refused, and the first try_observe's peek took its row"
    );
    assert!(matches!(os.try_observe().unwrap(), TryObserveOutcome::Exited(_)));
}

/// A running child, a [`MacosChild`] over the kernel `kernel` makes from the child's pid, and the
/// identity. The rows' registrations are taken in order, the adoption's first, so a later row is
/// the exit wait's.
fn a_running_child_with_a_watch(
    kernel: impl FnOnce(u32) -> FakeKernel<'static>,
) -> (
    StdChild,
    std::process::ChildStdin,
    ProcessId,
    crate::os_process::macos::child::MacosChild<std::sync::Arc<FakeKernel<'static>>>,
    std::sync::Arc<FakeKernel<'static>>,
) {
    use crate::os_process::macos::child::MacosChild;

    let mut child = crate::test_child::blocker();
    let stdin = child.stdin.take().expect("piped stdin");
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let UniqRead::Found(read) = HostKernel.unique_info(id.pid()) else {
        panic!("the blocker's unique id must be readable");
    };
    let kernel = std::sync::Arc::new(kernel(id.pid()));
    let mac = MacosChild::new(std::sync::Arc::clone(&kernel), id.pid(), read.unique_id).expect("watch the child");
    (child, stdin, id, mac, kernel)
}

/// The host's kernel, except that the exit watch of `pid` is made and never fires: the shared watch
/// of a child whose `NOTE_EXIT` has not reached it yet, while another kqueue has the event.
fn a_kernel_with_a_silent_exit_watch(pid: u32) -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel).on_subscribe(ExitWatch::registration(pid))
}

/// An exit wait whose registration found the pid past registration (`ESRCH`, a refusal row) has no
/// event to come, so a look at a running child is a recheck, never a wait on its kqueue.
///
/// Mutant: `ChildExit::look` drops the `unarmed` branch, so the look is `Step::Wait` on a kqueue
/// nothing will ever signal.
#[skuld::test]
fn an_exit_wait_that_found_no_registration_rechecks_instead_of_waiting() {
    use crate::os_process::drive::Step;

    // The adoption's reap registration is made (and never fires: nothing here reads that queue); the
    // exit wait's, the second, is refused.
    let (_child, stdin, _id, mac, kernel) = a_running_child_with_a_watch(|pid| {
        FakeKernel::over(&HostKernel)
            .on_subscribe(reap_registration(pid))
            .on_subscribe_refused(reap_registration(pid), libc::ESRCH)
    });
    let mut wait = mac.exit_wait().expect("arm the wait");
    assert!(
        matches!(wait.look(), Ok(Step::Recheck)),
        "no event will come: the look must not wait"
    );
    assert!(
        kernel.all_rows_taken(),
        "the adoption made its registration and the exit wait's was refused"
    );
    drop(wait);
    drop(stdin);
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

    let (_child, stdin, id, mac, kernel) = a_running_child_with_a_watch(a_kernel_with_a_silent_exit_watch);
    let mut wait = mac.exit_wait().expect("arm the wait");
    drop(stdin);
    // `NOTE_EXIT` precedes the zombie state, so the event is queued on the wait's kqueue by now.
    wait_until_zombie(id.pid());
    assert!(
        matches!(wait.look(), Ok(Step::Recheck)),
        "the drain read NOTE_EXIT and the shared watch says Running"
    );
    assert!(kernel.all_rows_taken(), "the adoption armed the silent exit watch");
    drop(wait);
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

    let (mut child, stdin, id, mac, kernel) = a_running_child_with_a_watch(a_kernel_with_a_silent_exit_watch);
    let mut wait = mac.exit_wait().expect("arm the wait");
    drop(stdin);
    wait_until_zombie(id.pid());
    child.wait().unwrap();
    assert!(
        matches!(wait.look(), Ok(Step::Done(()))),
        "NOTE_EXIT and NOTE_REAP were drained, and the pid is gone"
    );
    assert!(kernel.all_rows_taken(), "the adoption armed the silent exit watch");
}

/// A pid past registration at the reap registration (`ESRCH`, a refusal row) is not a failure either,
/// and it is no news about the exit: the exit watch registered on its own and the running child reads
/// `Running`.
///
/// Mutant: `ESRCH` at the reap registration fails the adoption, or reads the child as exited (marks
/// the exit watch fired).
#[skuld::test]
fn esrch_at_the_reap_registration_adopts_a_running_child() {
    use crate::os_process::macos::child::MacosChild;

    let mut child = crate::test_child::blocker();
    let stdin = child.stdin.take().expect("piped stdin");
    let id = ProcessId::of(child.id()).found().expect("identity");
    let UniqRead::Found(read) = HostKernel.unique_info(id.pid()) else {
        panic!("the blocker's unique id must be readable");
    };
    let kernel = std::sync::Arc::new(
        FakeKernel::over(&HostKernel).on_subscribe_refused(reap_registration(id.pid()), libc::ESRCH),
    );
    let os = MacosChild::new(std::sync::Arc::clone(&kernel), id.pid(), read.unique_id)
        .expect("the reap's ESRCH is no failure");
    assert!(kernel.all_rows_taken(), "the reap registration consumed the refusal");
    assert!(
        matches!(os.exited().unwrap(), Exit::Running(_)),
        "the exit watch registered on its own: the child runs"
    );
    drop(stdin);
}

/// A child whose tracer began its exit, then lost its own tracer, is held by launchd with its
/// `p_oppid` kept: its `NOTE_EXIT` reaches only launchd, so nothing wakes a wait on the reap kqueue.
/// The look is `Recheck`, which the driver paces, not `Running` on that kqueue. This process's own
/// pid stands in for the child, held by a blocker whose stated parents say launchd holds it. The
/// child's row states only its parent, the tracer; its state stays the host's.
///
/// Mutant: a tracer launchd holds answers `Running` on the reap kqueue: the wait blocks for an event
/// that never comes.
#[skuld::test]
fn a_child_whose_tracer_is_exiting_at_launchd_is_a_recheck() {
    use crate::identity::LAUNCHD;
    use crate::os_process::child::{OsChild, TryObserveOutcome};
    use crate::os_process::macos::child::MacosChild;
    use crate::wait::exit_only::macos_tests::{echild_yet_resolvable, parent_reads};

    let (pid, unique) = echild_yet_resolvable();
    let tracer = crate::test_child::blocker();
    let tracer_pid = tracer.id();
    // The child's parent is the tracer, which this process started and launchd holds.
    let kernel = parent_reads(pid, tracer_pid, 1).on_kinfo(
        tracer_pid,
        kinfo_proc::of_host_held_by(tracer_pid, std::process::id() as libc::pid_t, LAUNCHD as libc::pid_t),
    );
    let mac = MacosChild::new(kernel, pid, unique).expect("watch the stand-in");

    let look = mac.try_observe().expect("look");

    assert!(matches!(look, TryObserveOutcome::Recheck), "{look:?}");
}

const KQUEUE_MARKER: &str = "COSCA_TESTCFG_MACCHILD_KQUEUE";
// `run_fixture_case` requires a case variable; this fixture does not read it.
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

    let (child, stdin) = crate::test_child::blocker().into_parts();
    let id = ProcessId::of(child.id()).found().expect("identity");
    let refused = crate::test_child::refuse_new_descriptors();
    let adopted = adopt_std(child, id);
    let limit = refused.limit;
    drop(refused);
    let (error, mut child) = match adopted {
        Ok(_) => panic!("adopted with the descriptor table full (limit {limit})"),
        Err(refused) => refused,
    };
    let Error::Io(e) = &error else {
        panic!("a refused kqueue is an io error: {error:?}")
    };
    assert_eq!(e.raw_os_error(), Some(libc::EMFILE), "{e:?}");
    drop(stdin);
    child.wait().expect("the child is handed back unreaped");
}

/// A look at a running child waits on the reap kqueue, a descriptor of its own beside the exit
/// kqueue `exited` hands out: the one is drained by the look's holder, the other is never read.
///
/// Mutant: the look waits on the exit kqueue, which its holder's drain would then empty for every
/// other waiter.
#[skuld::test]
fn try_observe_of_a_running_child_waits_on_the_reap_kqueue() {
    use std::os::fd::AsRawFd;

    use crate::os_process::child::{adopted_blocker, TryObserveOutcome};
    use crate::os_process::WaitFor;
    use crate::wait::exit_only::Reap;
    let (os, id, stdin) = adopted_blocker();
    let Exit::Running(WaitFor::Readable(exit_fd)) = os.exited().unwrap() else {
        panic!("a live child reads Running");
    };
    let TryObserveOutcome::Running(WaitFor::Readable(reap_fd)) = os.try_observe().unwrap() else {
        panic!("a running child is waited on its reap kqueue");
    };
    assert_ne!(reap_fd.as_raw_fd(), exit_fd.as_raw_fd());
    drop(stdin);
    assert!(exited_held(&*os, None).unwrap());
    // `NOTE_EXIT` can come before XNU shows the zombie to `waitid`.
    wait_until_zombie(id.pid());
    assert!(matches!(os.try_observe().unwrap(), TryObserveOutcome::Exited(_)));
    assert!(matches!(os.try_reap().unwrap(), Reap::Reaped(_)));
}

/// A peek of an exited child sees its record and consumes nothing: the reap that follows has it.
///
/// Mutant: the peek is a consuming `waitid`.
#[skuld::test]
fn peek_of_an_exited_child_consumes_nothing() {
    use crate::os_process::child::{adopted_blocker, PeekOutcome};
    use crate::wait::exit_only::Reap;
    let (os, id, stdin) = adopted_blocker();
    drop(stdin);
    assert!(exited_held(&*os, None).unwrap());
    // `NOTE_EXIT` can come before XNU shows the zombie to `waitid`.
    wait_until_zombie(id.pid());
    assert!(matches!(os.peek().unwrap(), PeekOutcome::Exit(_)));
    assert!(matches!(os.peek().unwrap(), PeekOutcome::Exit(_)));
    assert!(matches!(os.try_reap().unwrap(), Reap::Reaped(_)));
}
