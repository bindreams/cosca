//! macOS-only `SharedChild` tests: the kqueue wait under `SIG_IGN`, and the by-pid reaps.
//! The cases that change the process-wide `SIGCHLD` disposition each run in a fresh re-exec of the
//! test binary.

use std::time::{Duration, Instant};

use super::fixtures::{spawn_std_blocker, Blocker};
use crate::child::shared::SharedChild;
use crate::identity::{ppid_fault, uniq_fault, uniq_info, ReadPurpose, UniqInfo, UniqRead, LAUNCHD};
use crate::wait::backend::test_hooks::{self, ForcedOnce};
use crate::wait::exit_only::seams::{self as exit_seams, ForcedReap, HolderStep};
use crate::wait::exit_only::{self, Foreign, Peek, Target};

fn far() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

fn is_echild(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ECHILD)
}

fn found(unique_id: u64) -> UniqRead {
    UniqRead::Found(UniqInfo { unique_id })
}

/// `pid`'s real unique id.
fn unique_of(pid: u32) -> u64 {
    match uniq_info(pid, ReadPurpose::Adopt) {
        UniqRead::Found(info) => info.unique_id,
        other => panic!("the unique id of {pid}: {other:?}"),
    }
}

// S11m: a reap that finds nothing after `Reapable` =====

/// S11m: a consuming reap that finds nothing right after the wait saw a zombie means the pid
/// names something else now. It takes the `ECHILD` path, with no assert in any build, and the
/// state goes back to `N`.
///
/// Mutant: a `debug_assert!` on the by-pid target.
#[test]
fn a_reap_that_finds_none_after_reapable_takes_the_echild_path() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let none = exit_seams::force_reap_once(ForcedReap::None);
    let err = b.shared.wait().expect_err("the forced empty reap");
    drop(none);
    assert!(is_echild(&err), "{err}");
    assert!(format!("{:?}", b.shared).contains("N"), "{:?}", b.shared);
    // The zombie was never consumed (the reap was forced empty): a real wait reaps it.
    b.shared.wait().expect("the zombie is still there");
}

// S2g: an identity read that says the pid is gone =====

/// S2g: an id-checked peek whose identity read says the pid is `Gone` answers `Foreign(Gone)`.
///
/// Mutant: `Gone` treated as a match: the peek returns `Exit`.
#[test]
fn an_identity_read_gone_takes_the_echild_path() {
    let (child, stdin) = spawn_std_blocker();
    let unique = unique_of(child.id());
    drop(stdin);
    let mut child = child;
    // The child's exit, seen without consuming it.
    let target = Target::pid(child.id(), Some(unique));
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Peek, UniqRead::Gone);
    let peeked = loop {
        match exit_only::peek(&target).expect("peek") {
            Peek::Running => confirm_exit_of(&child),
            other => break other,
        }
    };
    drop(forced);
    assert_eq!(peeked, Peek::Foreign(Foreign::Gone));
    child.wait().expect("reap");
}

/// Block until `child`'s exit is visible, without consuming it.
fn confirm_exit_of(child: &std::process::Child) {
    // SAFETY: an all-zero `siginfo_t` is a valid value, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT,
        )
    };
    assert_eq!(r, 0, "waitid(WNOWAIT): {}", std::io::Error::last_os_error());
}

// S10r: the second reap =====

/// The second reap of an exited, unreaped child, whose unique id reads as `read`.
fn second_reap_with_unique(read: UniqRead) -> std::process::Child {
    let (mut child, stdin) = spawn_std_blocker();
    drop(stdin);
    confirm_exit_of(&child);
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::SecondPeek, read);
    crate::wait::exit_only::second_reap(child.id(), Some(7));
    drop(forced);
    let _ = &mut child;
    child
}

/// S10r: a second reap whose start no longer matches is skipped: nothing is consumed.
///
/// Mutant: a second consume without the start check.
#[test]
fn a_second_reap_with_an_id_mismatch_is_skipped() {
    let mut child = second_reap_with_unique(found(99));
    let status = child
        .wait()
        .expect("the zombie must still be there: the mismatch skipped the consume");
    assert!(status.success());
}

/// S10r: a second reap whose start matches consumes the leftover zombie.
///
/// Mutant: the start check inverted.
#[test]
fn a_second_reap_with_a_matching_id_consumes_the_leftover() {
    let child = second_reap_with_unique(found(7));
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer.
    let r = unsafe { libc::waitpid(child.id() as i32, &mut status, libc::WNOHANG) };
    assert_eq!(r, -1, "the matching second reap must have consumed the zombie");
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
    std::mem::forget(child);
}

/// S10r: a second peek that meets `ECHILD` is skipped quietly, not logged as a foreign reap or a
/// warning.
///
/// Mutant: the `ECHILD` logged at `warn`.
#[test]
fn a_second_reap_that_meets_echild_is_skipped() {
    crate::log_capture::install();
    let (mut child, stdin) = spawn_std_blocker();
    drop(stdin);
    confirm_exit_of(&child);
    let marker = format!("second reap of pid {}", child.id());
    let mark = crate::log_capture::mark();
    let forced = exit_seams::force_peek_once(Err(std::io::Error::from_raw_os_error(libc::ECHILD)));
    crate::wait::exit_only::second_reap(child.id(), None);
    drop(forced);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(
        !levels.contains(&log::Level::Warn),
        "an ECHILD must not warn: {levels:?}"
    );
    child.wait().expect("the zombie was never consumed");
}

/// S10r: a second reap with no start to check is skipped with a `warn`, and consumes nothing: a
/// consume by a bare pid could take a reusing process's record.
///
/// Mutant: the consume runs when there is no start.
#[test]
fn a_second_reap_without_an_id_is_skipped_with_a_warning() {
    crate::log_capture::install();
    let (mut child, stdin) = spawn_std_blocker();
    drop(stdin);
    confirm_exit_of(&child);
    let marker = format!("second reap of pid {}", child.id());
    let mark = crate::log_capture::mark();
    crate::wait::exit_only::second_reap(child.id(), None);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert_eq!(levels, [log::Level::Warn], "{levels:?}");
    child.wait().expect("the zombie was never consumed");
}

/// S10r: a second consume that finds nothing is skipped quietly.
///
/// Mutant: a `debug_assert!` on the by-pid consume.
#[test]
fn a_second_reap_that_finds_nothing_is_skipped() {
    crate::log_capture::install();
    let (mut child, stdin) = spawn_std_blocker();
    drop(stdin);
    confirm_exit_of(&child);
    let marker = format!("second reap of pid {}", child.id());
    let mark = crate::log_capture::mark();
    let same = uniq_fault::force_uniq_read_once(ReadPurpose::SecondPeek, found(7));
    let none = exit_seams::force_reap_once(ForcedReap::None);
    crate::wait::exit_only::second_reap(child.id(), Some(7));
    drop(none);
    drop(same);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(
        !levels.contains(&log::Level::Warn),
        "finding nothing must not warn: {levels:?}"
    );
    child.wait().expect("the zombie was never consumed");
}

/// S10r: the second peek runs after every first reap, traced or not. For an untraced child it
/// answers `ECHILD` and is skipped quietly.
///
/// Mutant: a second peek gated on `p_oppid`: no `SecondPeek` step for an untraced child.
#[test]
fn a_second_peek_runs_after_every_first_reap() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    exit_seams::holder_steps();
    b.shared.wait().expect("wait");
    assert_eq!(exit_seams::holder_steps(), [HolderStep::Reap, HolderStep::SecondPeek]);
}

/// `uniq_info`'s test seam hits only its purpose: arming one of `Peek`, `PreReap` and `SecondPeek`
/// leaves the other two reads untouched.
///
/// Mutant: a purpose-blind seam.
#[test]
fn force_uniq_read_once_hits_only_its_purpose() {
    let pid = std::process::id();
    let real = uniq_info(pid, ReadPurpose::Peek);
    assert!(matches!(real, UniqRead::Found(_)), "{real:?}");
    let all = [ReadPurpose::Peek, ReadPurpose::PreReap, ReadPurpose::SecondPeek];
    for armed in all {
        let forced = uniq_fault::force_uniq_read_once(armed, UniqRead::Refused(libc::EPERM));
        for other in all.into_iter().filter(|p| *p != armed) {
            assert_eq!(uniq_info(pid, other), real, "{other:?} read while {armed:?} was armed");
        }
        assert_eq!(uniq_info(pid, armed), UniqRead::Refused(libc::EPERM));
        assert_eq!(uniq_info(pid, armed), real, "the force is taken once");
        drop(forced);
    }
}

// Task 2b: the `SIG_IGN` hang =====

const MARKER: &str = "COSCA_TEST_SHARED_SIGIGN";
const CASE_ENV: &str = "COSCA_TEST_SHARED_SIGIGN_CASE";

fn run_case(path: &str, case: &str) {
    crate::test_child::run_fixture_case(path, MARKER, CASE_ENV, case);
}

/// A root child adopted into a `SharedChild`, under `SIGCHLD` set to `SIG_IGN` with a live
/// sibling blocked on its stdin, so the kernel reaps the root itself and a blocking `waitid`
/// would sleep until the sibling is gone. The root's stdin closes from inside the holder's first
/// blocking `kevent` round, so the waiter is known to be asleep first.
fn ignoring_sigchld_with_a_sibling() -> (SharedChild, std::process::Child, std::process::ChildStdin, ForcedOnce) {
    crate::test_child::set_sigchld_ignored(true);
    let (sibling, sibling_stdin) = spawn_std_blocker();
    let (root, root_stdin) = spawn_std_blocker();
    let id = super::fixtures::identity_of(&root);
    let shared = SharedChild::adopt(root, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let mut root_stdin = Some(root_stdin);
    let end = test_hooks::on_kevent_round(0, move || drop(root_stdin.take()));
    (shared, sibling, sibling_stdin, end)
}

/// The holder's wait on macOS is the kqueue wait, never a blocking `waitid`. Structural, and
/// under the default disposition: the exit is confirmed first (a zombie is there), so a
/// `waitid` would return at once and only the kevent request tells the two apart. This is what
/// the `SIG_IGN` cases below prove by hanging.
///
/// Mutant: the holder's platform wait is a blocking `waitid(WNOWAIT)`.
#[test]
fn the_holder_waits_on_the_kqueue_not_in_waitid() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let _hooks = test_hooks::HookGuard::install(|_, _| {});
    b.shared.wait().expect("wait");
    assert!(
        !test_hooks::await_requested_timeouts().is_empty(),
        "the holder never asked the kqueue"
    );
}

/// A `wait` on a child the kernel reaped returns `ECHILD` while a sibling lives.
///
/// Mutant: a blocking `waitid` instead of the kqueue form, which sleeps until the child list
/// empties.
#[test]
fn a_wait_on_a_child_the_kernel_reaped_returns_while_a_sibling_lives() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_wait_on_a_child_the_kernel_reaped_returns_while_a_sibling_lives),
            "",
        );
    }
    let (shared, _sibling, _stdin, _end) = ignoring_sigchld_with_a_sibling();
    let err = shared.wait().expect_err("the kernel reaped the root");
    assert!(is_echild(&err), "{err}");
}

/// A `wait_deadline` far past the bound returns `ECHILD`, not `Ok(None)`.
///
/// Mutant: the same.
#[test]
fn a_wait_timeout_far_past_the_bound_returns_echild() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_wait_timeout_far_past_the_bound_returns_echild),
            "",
        );
    }
    let (shared, _sibling, _stdin, _end) = ignoring_sigchld_with_a_sibling();
    let err = shared.wait_deadline(far()).expect_err("the kernel reaped the root");
    assert!(is_echild(&err), "{err}");
}

/// A sync drop of a child the kernel reaped returns: its wait after a successful kill answers
/// `ECHILD` instead of sleeping.
///
/// Mutant: the same.
#[test]
fn a_sync_drop_of_a_child_the_kernel_reaped_returns() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_sync_drop_of_a_child_the_kernel_reaped_returns),
            "",
        );
    }
    crate::test_child::set_sigchld_ignored(true);
    let (_sibling, _sibling_stdin) = spawn_std_blocker();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::test_child::leaked_writer_stdin()).expect("stdin");
    cmd.stdout(crate::Stdio::null()).expect("stdout");
    let child = cmd.spawn().expect("spawn");
    drop(child);
}

// Identity: the unique id is checked on every by-pid surface =====

/// The handle's target carries the child's unique id, so every peek and consume checks it.
///
/// Mutant: `Target::pid(pid, None)`.
#[test]
fn the_shared_childs_target_carries_its_unique_id() {
    let b = Blocker::spawn();
    let target = b.shared.target().expect("a target");
    let Target::Pid { pid, unique, .. } = target;
    assert_eq!(pid, b.shared.id());
    assert_eq!(unique, Some(unique_of(pid)));
}

/// `try_wait` on an exited child whose pid now reads as another process answers `ECHILD` and
/// consumes nothing.
///
/// Mutant: `target()` without the id: the exit is reported.
#[test]
fn try_wait_on_a_pid_with_another_unique_id_is_echild_and_consumes_nothing() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let other = unique_of(b.shared.id()) ^ 1;
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Peek, found(other));
    let err = b.shared.try_wait().expect_err("another process holds the pid");
    drop(forced);
    assert!(is_echild(&err), "{err}");
    b.shared.wait().expect("our zombie was never consumed");
}

/// The wait itself checks the id: a pid that reads as another process ends the wait as `Gone`,
/// before any reap step.
///
/// Mutant: the wait's peek without the id: it reports `Reapable` and reaches the reap.
#[test]
fn a_wait_on_a_pid_with_another_unique_id_never_reaches_the_reap() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    exit_seams::holder_steps();
    let other = unique_of(b.shared.id()) ^ 1;
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Peek, found(other));
    let err = b.shared.wait().expect_err("another process holds the pid");
    drop(forced);
    assert!(is_echild(&err), "{err}");
    assert!(
        !exit_seams::holder_steps().contains(&HolderStep::Reap),
        "the wait reached the reap for a pid that is not ours"
    );
    b.shared.wait().expect("our zombie was never consumed");
}

/// `kill` sends nothing to a pid whose unique id is no longer the child's: the child then ends on its own,
/// by EOF on its stdin, and exits cleanly.
///
/// Mutant: `kill` by the bare pid, as std's `Child::kill` does: the child dies of `SIGKILL`.
#[test]
fn kill_sends_nothing_to_a_pid_with_another_unique_id() {
    let mut b = Blocker::spawn();
    let log = crate::send_log::Capture::start();
    let other = match b.shared.identity {
        crate::signal::Identity::Known(id) => id ^ 1,
        other => panic!("a live child's identity: {other:?}"),
    };
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Kill, found(other));
    b.shared.kill().expect("a pid that is not ours is gone, not an error");
    drop(forced);
    assert_eq!(log.entries(), []);
    b.end_child();
    let status = b.shared.wait().expect("wait");
    assert!(status.success(), "the child was signalled: {status:?}");
}

/// `kill` on a live child sends `SIGKILL` by pid and records it.
///
/// Mutant: nothing sent.
#[test]
fn kill_signals_a_live_child_by_its_verified_pid() {
    let b = Blocker::spawn();
    let log = crate::send_log::Capture::start();
    b.shared.kill().expect("kill");
    assert_eq!(
        log.entries(),
        [(b.shared.id(), crate::signal::Sig::Kill, crate::send_log::Via::Pid)]
    );
    let status = b.shared.wait().expect("wait");
    assert_eq!(super::fixtures::signal_of(status), Some(libc::SIGKILL));
}

// A pid that is not our child, yet still names it (a tracer holds it) =====

/// Our own pid: `waitid` answers `ECHILD` for it, as it does for a child a tracer holds, and it
/// still resolves to its unique id.
fn echild_yet_resolvable() -> (u32, u64) {
    let pid = std::process::id();
    (pid, unique_of(pid))
}

/// The parent read of a live process another process holds, as a tracer holds a child: not
/// launchd.
fn held_by_a_tracer() -> ppid_fault::Forced {
    ppid_fault::force_ppid_once(Ok(4242))
}

/// The parent read of a zombie whose tracer died: XNU reparented it to launchd.
fn orphaned_to_launchd() -> ppid_fault::Forced {
    ppid_fault::force_ppid_once(Ok(LAUNCHD))
}

/// A by-pid `ECHILD` for a pid that still names the child, and that a live process holds, is not a
/// reap.
///
/// Mutant: `ECHILD` mapped to `Foreign(Gone)` without the id and parent check.
#[test]
fn an_echild_for_a_pid_held_by_a_tracer_is_running() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let forced = held_by_a_tracer();
    assert_eq!(exit_only::peek(&target).expect("peek"), Peek::Running);
    drop(forced);
    let _forced = held_by_a_tracer();
    assert_eq!(
        exit_only::try_reap(&target).expect("try_reap"),
        exit_only::Reap::Running
    );
}

/// launchd answers `ECHILD` to our `waitid` and refuses `PROC_PIDTBSDINFO` to a caller that is not
/// root, yet its unique id and parent read unprivileged: it is held, not reaped. Its parent is the
/// kernel, pid 0, not launchd.
///
/// Mutant: the parent read through a same-user flavor: `Foreign(Gone)`.
#[test]
fn an_echild_for_another_users_process_that_launchd_does_not_own_is_running() {
    let target = Target::pid(1, Some(unique_of(1)));
    assert_eq!(exit_only::peek(&target).expect("peek"), Peek::Running);
    assert_eq!(
        exit_only::try_reap(&target).expect("try_reap"),
        exit_only::Reap::Running
    );
}

/// A by-pid `ECHILD` for a pid that still names the child but that launchd owns: a zombie whose
/// tracer died and which XNU reparented to launchd. Only a wait by launchd would hand it back.
///
/// Mutant: the parent ignored: `Running`.
#[test]
fn an_echild_for_a_pid_orphaned_to_launchd_is_foreign() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let forced = orphaned_to_launchd();
    assert_eq!(exit_only::peek(&target).expect("peek"), Peek::Foreign(Foreign::Gone));
    drop(forced);
    let _forced = orphaned_to_launchd();
    assert_eq!(
        exit_only::try_reap(&target).expect("try_reap"),
        exit_only::Reap::Foreign(Foreign::Gone)
    );
}

/// An `ECHILD` for a pid with another unique id is a reuse, whether the first read or the one that
/// closes the parent read says so; a pid that is gone or unreadable is gone.
///
/// Mutant: any `ECHILD` taken for `Running`; the closing read dropped.
#[test]
fn an_echild_for_a_pid_that_no_longer_names_the_child_is_foreign() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let other = found(unique ^ 1);
    for (reads, want) in [
        (vec![other], Foreign::Other),
        // The process changed while its parent was being read.
        (vec![found(unique), other], Foreign::Other),
        (vec![UniqRead::Refused(libc::EPERM)], Foreign::Gone),
        (vec![UniqRead::Gone], Foreign::Gone),
        (vec![found(unique), UniqRead::Gone], Foreign::Gone),
    ] {
        let forced: Vec<_> = reads
            .iter()
            .map(|read| uniq_fault::force_uniq_read_once(ReadPurpose::Echild, *read))
            .collect();
        assert_eq!(
            exit_only::peek(&target).expect("peek"),
            Peek::Foreign(want),
            "{reads:?}"
        );
        drop(forced);
    }
}

/// A `Running` peek names a child of ours; if the pid now reads as another process, it is a reuse.
///
/// Mutant: `Running` never checks the id.
#[test]
fn a_running_peek_of_a_pid_with_another_unique_id_is_foreign() {
    let mut b = Blocker::spawn();
    let unique = unique_of(b.shared.id());
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Running, found(unique ^ 1));
    let err = b.shared.try_wait().expect_err("another process holds the pid");
    drop(forced);
    assert!(is_echild(&err), "{err}");
    // An id that cannot be read, or that matches, leaves it running.
    for read in [UniqRead::Refused(libc::EPERM), found(unique)] {
        let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Running, read);
        assert_eq!(b.shared.try_wait().expect("try_wait"), None, "{read:?}");
        drop(forced);
    }
    b.end_child();
    b.shared.wait().expect("wait");
}

/// With no id there is nothing to check an `ECHILD` against: it stays a reap.
///
/// Mutant: `ECHILD` taken for `Running` whatever the id.
#[test]
fn an_echild_with_no_id_stays_foreign() {
    let (pid, _) = echild_yet_resolvable();
    assert_eq!(
        exit_only::peek(&Target::pid(pid, None)).expect("peek"),
        Peek::Foreign(Foreign::Gone)
    );
}

/// The kqueue wait does not read a held child as reaped: it is still running at its deadline.
///
/// Mutant: the wait's peek without the id: `Gone`.
#[test]
fn the_kqueue_wait_keeps_waiting_for_a_child_that_answers_echild_yet_resolves() {
    use crate::wait::backend::{await_reapable, Waited};
    let (pid, unique) = echild_yet_resolvable();
    // The first look, and the final one at expiry.
    let _forced = (held_by_a_tracer(), held_by_a_tracer());
    // An expired deadline: no blocking.
    let waited = await_reapable(pid, Some(unique), Some(Instant::now())).expect("wait");
    assert_eq!(waited, Waited::DeadlinePassed);
}

/// The wait's verdict for a pid that reads as another process is `Gone`.
///
/// Mutant: the wait ignores the id.
#[test]
fn the_kqueue_wait_reports_gone_for_a_pid_with_another_unique_id() {
    use crate::wait::backend::{await_reapable, Waited};
    let (pid, unique) = echild_yet_resolvable();
    let waited = await_reapable(pid, Some(unique ^ 1), Some(Instant::now())).expect("wait");
    assert_eq!(waited, Waited::Gone);
}

// S11m: the reap finds no exit record after `Reapable` =====

/// A reap whose own peek finds no exit record right after the wait saw one is still our child (a
/// foreign reap is `Foreign`): the holder waits again, and gets the exit.
///
/// Mutant: `Gone` at once: the wait answers `ECHILD`.
#[test]
fn a_reap_that_finds_no_exit_record_after_reapable_waits_again() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let slot = std::rc::Rc::new(std::cell::RefCell::new(None));
    let _hook = exit_seams::on_holder_step(HolderStep::Reap, {
        let slot = std::rc::Rc::clone(&slot);
        move || *slot.borrow_mut() = Some(exit_seams::force_peek_once(Ok(Peek::Running)))
    });
    let status = b.shared.wait().expect("the holder waited again and got the exit");
    assert!(status.success(), "{status:?}");
    assert!(
        exit_seams::take_forced_peek().is_none(),
        "the reap must have consumed the forced peek"
    );
}

// A child whose identity a same-user read refuses (the `setuid` group) =====

/// A setuid-root `setuid-stdin-block root` child that has become root, with its stdin.
fn spawn_root_child() -> Option<(std::process::Child, std::process::ChildStdin)> {
    use std::io::Read as _;
    let helper = crate::test_privilege::setuid::setuid_helper()?;
    let mut cmd = std::process::Command::new(helper);
    cmd.args(["setuid-stdin-block", "root"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the setuid helper");
    let stdin = child.stdin.take().expect("piped stdin");
    let mut ready = [0u8; 1];
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_exact(&mut ready)
        .expect("the helper reports ready");
    assert_eq!(ready, *b"+");
    Some((child, stdin))
}

/// `kill` of a child this caller may not signal reads its identity all the same, and surfaces the
/// `EPERM` as `PermissionDenied`, not an untyped error.
///
/// Mutant: the identity read through the same-user `PROC_PIDTBSDINFO`: `ErrorKind::Other`.
#[test]
fn setuid_kill_of_a_root_child_is_permission_denied() {
    let Some((child, stdin)) = spawn_root_child() else {
        return;
    };
    let id = super::fixtures::identity_of(&child);
    let shared = SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    assert!(
        matches!(shared.identity, crate::signal::Identity::Known(_)),
        "the identity of another user's process is readable: {:?}",
        shared.identity
    );
    let err = shared.kill().expect_err("this caller may not signal a root process");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    drop(stdin);
    let status = shared.wait().expect("the helper exits on EOF");
    assert!(status.success(), "{status:?}");
}

/// The same through the public handle: `Child::kill` is `Io(PermissionDenied)`, which the elevated
/// wrapper's mapping turns into `Unkillable`.
///
/// Mutant: as above.
#[test]
fn setuid_child_kill_is_permission_denied() {
    let Some(helper) = crate::test_privilege::setuid::setuid_helper() else {
        return;
    };
    let mut cmd = crate::Command::new();
    // `args` is the whole argv, program name included.
    cmd.executable(&helper)
        .args(["cosca_testbin", "setuid-stdin-block", "root"]);
    cmd.stdin(crate::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(crate::Stdio::null()).expect("stderr null");
    let mut child = cmd.spawn().expect("spawn the setuid helper");
    let stdin = child.stdin().expect("piped stdin");
    let mut ready = [0u8; 1];
    std::io::Read::read_exact(&mut child.stdout().expect("piped stdout"), &mut ready).expect("ready");
    assert_eq!(ready, *b"+");
    let err = child.kill().expect_err("this caller may not signal a root process");
    assert!(
        matches!(&err, crate::error::Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{err:?}"
    );
    drop(stdin);
    let status = child.wait().expect("the helper exits on EOF");
    assert!(status.success(), "{status:?}");
}
