//! Tests of `exit_only`'s Linux backend over real children: the contract breaches of its blocking
//! waits, and `open_own_child`'s answers (a pidfd opened by number, and when it is gone).

use crate::identity::ProcessId;
use crate::os_process::child::{adopted_blocker, TryReapOutcome};
use crate::os_process::linux::open::fault;
use crate::test_child::wait_until_zombie;
use crate::wait::exit_only::seams as exit_seams;
use crate::wait::exit_only::Target;

// A blocking `waitid` that finds no record =====

/// A blocking `waitid` that finds no record is a contract breach, not a ptrace stop: it asserts in
/// a debug build and is an error in a release build, never a `Running` a caller loops on.
///
/// Mutant: `Ok(None)` folded into the non-exit arm, which answers `Running`.
#[skuld::test]
fn a_blocking_waitid_that_finds_no_record_is_a_contract_breach() {
    let (os, id, stdin) = adopted_blocker();
    drop(stdin);
    wait_until_zombie(id.pid());
    let target = Target::PidFd(os.os_handle());
    let forced = exit_seams::force_visible_none_once();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::wait::exit_only::wait_visible_exit(&target)
    }));
    drop(forced);
    if cfg!(debug_assertions) {
        assert!(outcome.is_err(), "a debug build asserts the contract");
    } else {
        let err = outcome.expect("release returns").expect_err("a breach is an error");
        assert!(err.to_string().contains("no record"), "{err}");
    }
}

/// The same breach in `reap_blocking` is not a ptrace stop to wait past either.
///
/// Mutant: `Ok(None)` folded into the ptrace-stop arm, which waits again (a busy loop without
/// the seam; here the next wait reaps the child and answers).
#[skuld::test]
fn a_blocking_reap_that_finds_no_record_is_a_contract_breach() {
    let (os, id, stdin) = adopted_blocker();
    drop(stdin);
    wait_until_zombie(id.pid());
    let target = Target::PidFd(os.os_handle());
    let forced = exit_seams::force_visible_none_once();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::wait::exit_only::reap_blocking(&target)
    }));
    drop(forced);
    if cfg!(debug_assertions) {
        assert!(outcome.is_err(), "a debug build asserts the contract");
    } else {
        let err = outcome.expect("release returns").expect_err("a breach is an error");
        assert!(err.to_string().contains("no record"), "{err}");
    }
}

// `open_own_child` =====

/// Open the pidfd of an exited, unreaped child of ours under the force `arm` installs, expecting
/// the gone answer: `Ok(None)`. The child has already exited when it is opened, so a force that
/// is not applied leaves a pidfd that opens, and the assertion fails instead of blocking.
fn assert_open_is_gone<G>(arm: impl FnOnce() -> G) {
    let (os, id, stdin) = adopted_blocker();
    drop(stdin);
    wait_until_zombie(id.pid());
    let forced = arm();
    let opened = crate::wait::exit_only::open_own_child(id.pid(), Some(id)).expect("a gone answer is not a failure");
    drop(forced);
    assert!(opened.is_none(), "the child was gone, yet it opened");
    // The force was synthetic: the child is still this test's own, unreaped.
    assert!(
        matches!(os.try_reap(), Ok(TryReapOutcome::Reaped(_))),
        "reap the fixture"
    );
}

/// `pidfd_open` answering `ESRCH` is the gone answer.
///
/// Mutant: `open_own_child` fails on `ESRCH`.
#[skuld::test]
fn open_on_esrch_is_gone() {
    assert_open_is_gone(|| fault::force_pidfd_open_errno_once(rustix::io::Errno::SRCH));
}

/// `EINVAL` (before 6.16: a reaped leader whose number is held as a PGID, or reused by a
/// non-leader) is the gone answer for our own child.
///
/// Mutant: `EINVAL` returned as `Io`, so a spawn tears down a child that was never ours.
#[skuld::test]
fn open_on_einval_is_gone() {
    assert_open_is_gone(|| fault::force_pidfd_open_errno_once(rustix::io::Errno::INVAL));
}

/// `ENOENT` (from 6.16: a number reused by a live non-leader thread) is the gone answer too.
///
/// Mutant: `ENOENT` returned as `Io`, so the open fails on a 6.16 kernel.
#[skuld::test]
fn open_on_enoent_is_gone() {
    assert_open_is_gone(|| fault::force_pidfd_open_errno_once(rustix::io::Errno::NOENT));
}

/// A pidfd whose identity no longer matches is gone, whatever the pid now names.
///
/// Mutant: a by-number pidfd trusted unchecked.
#[skuld::test]
fn open_treats_a_pidfd_whose_identity_is_gone_as_gone() {
    assert_open_is_gone(|| fault::force_exists_once(crate::identity::Existence::Gone));
}

/// A pid that is not our child answers `ECHILD` to the confirming `waitid`, even when a pidfd for
/// it opens and its identity matches: it is gone for us.
///
/// Mutant: a by-number pidfd trusted unchecked.
#[skuld::test]
fn open_treats_a_pidfd_that_is_not_our_child_as_gone() {
    // SAFETY: `getppid` takes no arguments and cannot fail.
    let parent = unsafe { libc::getppid() } as u32;
    let id = ProcessId::of(parent).found();
    let opened = crate::wait::exit_only::open_own_child(parent, id).expect("open");
    assert!(opened.is_none(), "our parent is never our child");
}

/// Open a live blocker under a forced `/proc` view whose identity check would say `Gone`: the
/// check must be skipped and the confirming `waitid` decide, so the pidfd opens.
fn open_under_view_with_exists_gone(view: crate::identity::proc_view_fault::ForcedView) {
    let (os, id, stdin) = adopted_blocker();
    let gone = fault::force_exists_once(crate::identity::Existence::Gone);
    let forced_view = crate::identity::proc_view_fault::force_proc_view_once(view);
    let opened = crate::wait::exit_only::open_own_child(id.pid(), Some(id)).expect("open");
    drop(forced_view);
    drop(gone);
    assert!(opened.is_some(), "the child is kept, with a pidfd");
    // The child ends on EOF, and the adopted handle reaps it.
    drop(stdin);
    wait_until_zombie(id.pid());
    assert!(
        matches!(os.try_reap(), Ok(TryReapOutcome::Reaped(_))),
        "reap the fixture"
    );
}

/// On a diverged `/proc` the identity check is skipped: a live child is kept, with its pidfd,
/// relying on the `waitid` confirmation.
///
/// Mutant: trust `exists()` on a diverged `/proc`: the pidfd is dropped as gone.
#[skuld::test]
fn open_skips_the_identity_check_on_a_diverged_proc() {
    open_under_view_with_exists_gone(crate::identity::proc_view_fault::ForcedView::Diverged);
}

/// Likewise when the view cannot be assessed.
///
/// Mutant: the same.
#[skuld::test]
fn open_on_an_unassessable_proc_view_skips_the_identity_check() {
    open_under_view_with_exists_gone(crate::identity::proc_view_fault::ForcedView::Unassessable);
}
