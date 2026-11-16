//! Tests of `exit_only`'s macOS backend over real children and this process's own pid: the second
//! reap, the `ECHILD` pid that is held rather than reaped (a tracer holds it, or launchd), and the
//! unique-id checks of a peek. The helpers at the top are shared with the `OwnedChild` macOS tests.

use crate::child::spawn::identity_macos_tests::reap_by_pid;
use crate::identity::{short_info_held_by, FakeKernel, HostKernel, Kernel as _, ReadErr, UniqInfo, UniqRead, LAUNCHD};
use crate::os_process::child::{adopted_blocker, Foreign, OsChild, PeekOutcome};
use crate::test_child::wait_until_zombie;
use crate::wait::exit_only::{self, Target};

pub(crate) fn found(unique_id: u64) -> UniqRead {
    UniqRead::Found(UniqInfo {
        unique_id,
        id_version: 0,
    })
}

/// `pid`'s real unique id.
pub(crate) fn unique_of(pid: u32) -> u64 {
    match HostKernel.unique_info(pid) {
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

/// A kernel that reads `pid`'s parent as `ppid` for its next `reads` parent reads, its state as the
/// host's, and is the host's otherwise: `pid` is held by `ppid`, as a tracer holds a child (not
/// launchd), or launchd holds a zombie whose tracer died (XNU reparented it).
pub(crate) fn parent_reads(pid: u32, ppid: u32, reads: usize) -> FakeKernel<'static> {
    (0..reads).fold(FakeKernel::over(&HostKernel), |kernel, _| {
        kernel.on_short_bsd(pid, Ok(short_info_held_by(pid, ppid)))
    })
}

/// The tracer's pid in the parent reads of a process [`parent_reads`] states as held by a tracer.
pub(crate) fn held_by_a_tracer_pid() -> u32 {
    4242
}

/// A blocker that has exited and is not yet reaped, adopted (so a `MacosChild` holds it), and its pid.
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
    let kernel = FakeKernel::over(&HostKernel).on_unique_info(pid, UniqRead::Gone);
    let target = Target::pid(&kernel, pid, Some(unique_of(pid)));
    let peeked = exit_only::peek(&target).expect("peek");
    assert_eq!(peeked, PeekOutcome::Foreign(Foreign::Gone));
    reap_by_pid(pid);
}

/// `err` is a refused read's: `PermissionDenied`, `EPERM` as its OS code, `words` in its message
/// and no "errno" in it.
fn assert_refused_read(err: &std::io::Error, words: &str) {
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert_eq!(crate::error::first_os_code(err), Some(libc::EPERM), "{err}");
    let said = crate::error::said(err);
    assert!(said.contains(words), "{said}");
    assert!(!said.contains("errno"), "{said}");
}

/// A peek whose id read of an exited child is refused does not consume the exit: it is an error
/// with the refusal's code.
///
/// Mutant: the branch answers `Foreign(Gone)`, or words the errno in its text.
#[skuld::test]
fn a_refused_identity_read_of_an_exited_child_is_an_error_with_the_refusals_code() {
    let (_os, pid) = exited_unreaped_blocker();
    let kernel = FakeKernel::over(&HostKernel).on_unique_info(pid, UniqRead::Refused(libc::EPERM));
    let target = Target::pid(&kernel, pid, Some(unique_of(pid)));
    let err = exit_only::peek(&target).expect_err("an exit that cannot be tied to the child is not consumed");
    assert_refused_read(&err, "its exit was not consumed");
    reap_by_pid(pid);
}

/// A verified peek of a running child whose id read is refused cannot show it to be ours: an error
/// with the refusal's code.
///
/// Mutant: the branch answers `Running`, or words the errno in its text.
#[skuld::test]
fn a_refused_identity_read_of_a_running_child_is_an_error_to_a_verified_peek() {
    let (_os, id, _stdin) = adopted_blocker();
    let kernel = FakeKernel::over(&HostKernel).on_unique_info(id.pid(), UniqRead::Refused(libc::EPERM));
    let target = Target::pid(&kernel, id.pid(), Some(unique_of(id.pid())));
    let err = exit_only::peek_verified(&target).expect_err("a running child cannot be shown to be ours");
    assert_refused_read(&err, "it cannot be shown to be ours");
}

// The second reap =====

/// The second reap of an exited, unreaped child, whose unique id reads as `read`. The zombie is
/// left for the caller.
fn second_reap_with_unique(read: UniqRead) -> (Box<dyn OsChild>, u32) {
    let (os, pid) = exited_unreaped_blocker();
    let kernel = FakeKernel::over(&HostKernel).on_unique_info(pid, read);
    exit_only::second_reap(&kernel, pid, Some(7));
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
    assert_zombie_consumed(pid, "the matching second reap");
}

/// Panics unless `pid` has no zombie left to reap: `who` must have consumed it. A peek, so a zombie
/// that is left stays for whatever the test does next.
#[track_caller]
pub(crate) fn assert_zombie_consumed(pid: u32, who: &str) {
    use crate::identity::Kernel as _;

    let peeked = HostKernel.peek(pid);
    assert!(
        matches!(&peeked, Err(e) if e.raw_os_error() == Some(libc::ECHILD)),
        "{who} must have consumed the zombie: {peeked:?}"
    );
}

/// A second peek that meets `ECHILD` reads as `Foreign` (`peek_raw` maps it) and is skipped
/// quietly: nothing is consumed, and no warning is logged. The unique id is `None`, so a second
/// peek that went on would warn.
///
/// Mutant: the `Foreign` arm of `second_reap` logs at `warn`, or falls through to the consume.
#[skuld::test]
fn a_second_reap_that_meets_echild_is_skipped() {
    crate::log_capture::install();
    let (_os, pid) = exited_unreaped_blocker();
    let marker = format!("second reap of pid {pid}");
    let mark = crate::log_capture::mark();
    let kernel = FakeKernel::over(&HostKernel).on_peek(pid, Err(std::io::Error::from_raw_os_error(libc::ECHILD)));
    exit_only::second_reap(&kernel, pid, None);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(
        !levels.contains(&log::Level::Warn),
        "an ECHILD must not warn: {levels:?}"
    );
    assert!(kernel.all_rows_taken(), "the second reap must peek");
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
    exit_only::second_reap(&HostKernel, pid, None);
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
    let kernel = FakeKernel::over(&HostKernel)
        .on_unique_info(pid, found(7))
        .on_consume(pid, Ok(None));
    exit_only::second_reap(&kernel, pid, Some(7));
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(
        !levels.contains(&log::Level::Warn),
        "finding nothing must not warn: {levels:?}"
    );
    assert!(kernel.all_rows_taken(), "the second reap must read the id and consume");
    reap_by_pid(pid);
}

// A pid that is not our child, yet still names it =====

/// A by-pid `ECHILD` for a pid that still names the child, and that a live process holds, is not a
/// reap.
///
/// Mutant: `ECHILD` mapped to `Foreign(Gone)` without the id and parent check.
#[skuld::test]
fn an_echild_for_a_pid_held_by_a_tracer_is_running() {
    let (pid, unique) = echild_yet_resolvable();
    // The peek reads the parent, and so does the `try_reap`'s.
    let kernel = parent_reads(pid, held_by_a_tracer_pid(), 2);
    let target = Target::pid(&kernel, pid, Some(unique));
    assert_eq!(exit_only::peek(&target).expect("peek"), PeekOutcome::Running);
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
    let target = Target::pid(&HostKernel, 1, Some(unique_of(1)));
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
    let kernel = parent_reads(pid, LAUNCHD, 2);
    let target = Target::pid(&kernel, pid, Some(unique));
    assert_eq!(
        exit_only::peek(&target).expect("peek"),
        PeekOutcome::Foreign(Foreign::Orphaned)
    );
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
    let kernel = FakeKernel::over(&HostKernel)
        .on_short_bsd(pid, Err(ReadErr::Refused(libc::EPERM)))
        .on_short_bsd(pid, Err(ReadErr::Gone));
    let target = Target::pid(&kernel, pid, Some(unique));
    assert_eq!(
        exit_only::peek(&target).expect("peek"),
        PeekOutcome::Foreign(Foreign::Gone)
    );
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| exit_only::peek(&target)));
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
    let other = found(unique ^ 1);
    for (reads, want) in [
        (vec![other], Foreign::Other),
        // The process changed while its parent was being read.
        (vec![found(unique), other], Foreign::Other),
        (vec![UniqRead::Refused(libc::EPERM)], Foreign::Gone),
        (vec![UniqRead::Gone], Foreign::Gone),
        (vec![found(unique), UniqRead::Gone], Foreign::Gone),
    ] {
        let kernel = reads.iter().fold(FakeKernel::over(&HostKernel), |kernel, read| {
            kernel.on_unique_info(pid, *read)
        });
        let target = Target::pid(&kernel, pid, Some(unique));
        assert_eq!(
            exit_only::peek(&target).expect("peek"),
            PeekOutcome::Foreign(want),
            "{reads:?}"
        );
    }
}

/// With no id there is nothing to check an `ECHILD` against: it stays a reap.
///
/// Mutant: `ECHILD` taken for `Running` whatever the id.
#[skuld::test]
fn an_echild_with_no_id_stays_foreign() {
    let (pid, _) = echild_yet_resolvable();
    assert_eq!(
        exit_only::peek(&Target::pid(&HostKernel, pid, None)).expect("peek"),
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
    let kernel = FakeKernel::over(&HostKernel).on_unique_info(pid, UniqRead::Refused(libc::EPERM));
    let target = Target::pid(&kernel, pid, Some(unique));
    let err = exit_only::peek_verified(&target).expect_err("a denied read cannot show a reap");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err}");
}
