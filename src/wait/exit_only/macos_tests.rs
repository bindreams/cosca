//! Tests of `exit_only`'s macOS backend over real children and this process's own pid: the second
//! reap, the `ECHILD` pid that is held rather than reaped (a tracer holds it, or launchd), and the
//! unique-id checks of a peek. The helpers at the top are shared with the `OwnedChild` macOS tests.

use crate::child::spawn::identity_macos_tests::reap_by_pid;
use crate::identity::{ppid_fault, uniq_fault, uniq_info, ReadErr, ReadPurpose, UniqInfo, UniqRead, LAUNCHD};
use crate::os_process::child::{adopted_blocker, Foreign, OsChild, PeekOutcome};
use crate::test_child::wait_until_zombie;
use crate::wait::exit_only::seams as exit_seams;
use crate::wait::exit_only::{self, Target};

pub(crate) fn found(unique_id: u64) -> UniqRead {
    UniqRead::Found(UniqInfo {
        unique_id,
        id_version: 0,
    })
}

/// `pid`'s real unique id.
pub(crate) fn unique_of(pid: u32) -> u64 {
    match uniq_info(pid, ReadPurpose::Adopt) {
        UniqRead::Found(info) => info.unique_id,
        other => panic!("the unique id of {pid}: {other:?}"),
    }
}

/// Our own pid: `waitid` answers `ECHILD` for it, as it does for a child a tracer holds, and it
/// still resolves to its unique id.
pub(crate) fn echild_yet_resolvable() -> (u32, u64) {
    let pid = std::process::id();
    (pid, unique_of(pid))
}

/// The parent read of a live process another process holds, as a tracer holds a child: not
/// launchd.
pub(crate) fn held_by_a_tracer() -> ppid_fault::Forced {
    ppid_fault::force_ppid_once(Ok(4242))
}

/// The parent read of a zombie whose tracer died: XNU reparented it to launchd.
fn orphaned_to_launchd() -> ppid_fault::Forced {
    ppid_fault::force_ppid_once(Ok(LAUNCHD))
}

/// A blocker that has exited and is not yet reaped, adopted (so a `MacChild` holds it), and its pid.
fn exited_unreaped_blocker() -> (Box<dyn OsChild>, u32) {
    let (os, id, stdin) = adopted_blocker();
    drop(stdin);
    wait_until_zombie(id.pid());
    (os, id.pid())
}

// An identity read that says the pid is gone =====

/// An id-checked peek whose identity read says the pid is `Gone` answers `Foreign(Gone)`.
///
/// Mutant: `Gone` treated as a match: the peek returns `Exit`.
#[skuld::test]
fn an_identity_read_gone_takes_the_echild_path() {
    let (_os, pid) = exited_unreaped_blocker();
    let target = Target::pid(pid, Some(unique_of(pid)));
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Peek, UniqRead::Gone);
    let peeked = exit_only::peek(&target).expect("peek");
    drop(forced);
    assert_eq!(peeked, PeekOutcome::Foreign(Foreign::Gone));
    reap_by_pid(pid);
}

// The second reap =====

/// The second reap of an exited, unreaped child, whose unique id reads as `read`. The zombie is
/// left for the caller.
fn second_reap_with_unique(read: UniqRead) -> (Box<dyn OsChild>, u32) {
    let (os, pid) = exited_unreaped_blocker();
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::SecondPeek, read);
    exit_only::second_reap(pid, Some(7));
    drop(forced);
    (os, pid)
}

/// A second reap whose start no longer matches is skipped: nothing is consumed.
///
/// Mutant: a second consume without the start check.
#[skuld::test]
fn a_second_reap_with_an_id_mismatch_is_skipped() {
    let (_os, pid) = second_reap_with_unique(found(99));
    // Fails if the zombie is gone: the mismatch skipped the consume.
    reap_by_pid(pid);
}

/// A second reap whose start matches consumes the leftover zombie.
///
/// Mutant: the start check inverted.
#[skuld::test]
fn a_second_reap_with_a_matching_id_consumes_the_leftover() {
    let (_os, pid) = second_reap_with_unique(found(7));
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer.
    let r = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
    assert_eq!(r, -1, "the matching second reap must have consumed the zombie");
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
}

/// A second peek that meets `ECHILD` is skipped quietly, not logged as a foreign reap or a
/// warning.
///
/// Mutant: the `ECHILD` logged at `warn`.
#[skuld::test]
fn a_second_reap_that_meets_echild_is_skipped() {
    crate::log_capture::install();
    let (_os, pid) = exited_unreaped_blocker();
    let marker = format!("second reap of pid {pid}");
    let mark = crate::log_capture::mark();
    let forced = exit_seams::force_peek_once(Err(std::io::Error::from_raw_os_error(libc::ECHILD)));
    exit_only::second_reap(pid, None);
    drop(forced);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(
        !levels.contains(&log::Level::Warn),
        "an ECHILD must not warn: {levels:?}"
    );
    reap_by_pid(pid);
}

/// A second reap with no start to check is skipped with a `warn`, and consumes nothing: a
/// consume by a bare pid could take a reusing process's record.
///
/// Mutant: the consume runs when there is no start.
#[skuld::test]
fn a_second_reap_without_an_id_is_skipped_with_a_warning() {
    crate::log_capture::install();
    let (_os, pid) = exited_unreaped_blocker();
    let marker = format!("second reap of pid {pid}");
    let mark = crate::log_capture::mark();
    exit_only::second_reap(pid, None);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert_eq!(levels, [log::Level::Warn], "{levels:?}");
    reap_by_pid(pid);
}

/// A second consume that finds nothing is skipped quietly.
///
/// Mutant: a `debug_assert!` on the by-pid consume.
#[skuld::test]
fn a_second_reap_that_finds_nothing_is_skipped() {
    crate::log_capture::install();
    let (_os, pid) = exited_unreaped_blocker();
    let marker = format!("second reap of pid {pid}");
    let mark = crate::log_capture::mark();
    let same = uniq_fault::force_uniq_read_once(ReadPurpose::SecondPeek, found(7));
    let none = exit_seams::force_empty_reap_once();
    exit_only::second_reap(pid, Some(7));
    drop(none);
    drop(same);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(
        !levels.contains(&log::Level::Warn),
        "finding nothing must not warn: {levels:?}"
    );
    reap_by_pid(pid);
}

/// `uniq_info`'s test seam hits only its purpose: arming one of `Peek`, `PreReap` and `SecondPeek`
/// leaves the other two reads untouched.
///
/// Mutant: a purpose-blind seam.
#[skuld::test]
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

// A pid that is not our child, yet still names it =====

/// A by-pid `ECHILD` for a pid that still names the child, and that a live process holds, is not a
/// reap.
///
/// Mutant: `ECHILD` mapped to `Foreign(Gone)` without the id and parent check.
#[skuld::test]
fn an_echild_for_a_pid_held_by_a_tracer_is_running() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let forced = held_by_a_tracer();
    assert_eq!(exit_only::peek(&target).expect("peek"), PeekOutcome::Running);
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
#[skuld::test]
fn an_echild_for_another_users_process_that_launchd_does_not_own_is_running() {
    let target = Target::pid(1, Some(unique_of(1)));
    assert_eq!(exit_only::peek(&target).expect("peek"), PeekOutcome::Running);
    assert_eq!(
        exit_only::try_reap(&target).expect("try_reap"),
        exit_only::Reap::Running
    );
}

/// A by-pid `ECHILD` for a pid that still names the child but that launchd owns: a zombie whose
/// tracer died and which XNU reparented to launchd. Only a wait by launchd would hand it back.
///
/// Mutant: the parent ignored: `Running`; the launchd hold mapped to `Gone` (a reap).
#[skuld::test]
fn an_echild_for_a_pid_orphaned_to_launchd_is_orphaned() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let forced = orphaned_to_launchd();
    assert_eq!(
        exit_only::peek(&target).expect("peek"),
        PeekOutcome::Foreign(Foreign::Orphaned)
    );
    drop(forced);
    let _forced = orphaned_to_launchd();
    assert_eq!(
        exit_only::try_reap(&target).expect("try_reap"),
        exit_only::Reap::Foreign(Foreign::Orphaned)
    );
}

/// A parent read that fails between two matching id reads is not a hold: a refusal is `Gone`. `ESRCH`
/// there contradicts the matching reads that bracket it (xnu cannot produce it), so it asserts in a
/// debug build and is `Gone` in a release build.
///
/// Mutant: a failed parent read taken for a parent pid, and so for `Running`.
#[skuld::test]
fn an_echild_whose_parent_read_fails_is_foreign() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let forced = ppid_fault::force_ppid_once(Err(ReadErr::Refused(libc::EPERM)));
    assert_eq!(
        exit_only::peek(&target).expect("peek"),
        PeekOutcome::Foreign(Foreign::Gone)
    );
    drop(forced);
    let forced = ppid_fault::force_ppid_once(Err(ReadErr::Gone));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| exit_only::peek(&target)));
    drop(forced);
    if cfg!(debug_assertions) {
        assert!(outcome.is_err(), "a debug build asserts the contract");
    } else {
        assert_eq!(
            outcome.expect("release returns").expect("peek"),
            PeekOutcome::Foreign(Foreign::Gone)
        );
    }
}

/// An `ECHILD` for a pid with another unique id is a reuse, whether the first read or the one that
/// closes the parent read says so; a pid that is gone or unreadable is gone.
///
/// Mutant: any `ECHILD` taken for `Running`; the closing read dropped.
#[skuld::test]
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
            PeekOutcome::Foreign(want),
            "{reads:?}"
        );
        drop(forced);
    }
}

/// With no id there is nothing to check an `ECHILD` against: it stays a reap.
///
/// Mutant: `ECHILD` taken for `Running` whatever the id.
#[skuld::test]
fn an_echild_with_no_id_stays_foreign() {
    let (pid, _) = echild_yet_resolvable();
    assert_eq!(
        exit_only::peek(&Target::pid(pid, None)).expect("peek"),
        PeekOutcome::Foreign(Foreign::Gone)
    );
}

/// A verified peek (a caller that treats `Running` as "ours") cannot read an `ECHILD` pid's id: a
/// denial is not a reap, so it is an error with the errno, where the plain peek calls it `Gone`.
///
/// Mutant: the verified peek maps `Held::Refused` to `Foreign(Gone)`.
#[skuld::test]
fn a_refused_echild_read_is_an_error_to_a_verified_peek() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let _forced = uniq_fault::force_uniq_read_once(ReadPurpose::Echild, UniqRead::Refused(libc::EPERM));
    let err = exit_only::peek_verified(&target).expect_err("a denied read cannot show a reap");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
}
