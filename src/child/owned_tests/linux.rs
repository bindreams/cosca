//! Linux-only `OwnedChild` tests: the blocking `waitid` of the visible-exit wait that the async
//! backend and the spawn handshake still use, and adoption of a child by its pidfd (`pidfd_open`
//! by number).

use super::fixtures::{identity_of, spawn_std_blocker, Blocker};
use crate::child::owned::OwnedChild;
use crate::identity::ProcessId;
use crate::os_process::linux::open::fault;
use crate::wait::exit_only::seams as exit_seams;
use crate::wait::exit_only::Target;

// A blocking `waitid` that finds no record =====

/// A blocking `waitid` that finds no record is a contract breach, not a ptrace stop: it asserts in
/// a debug build and is an error in a release build, never a `Running` a caller loops on.
///
/// Mutant: `Ok(None)` folded into the non-exit arm, which answers `Running`.
#[skuld::test]
fn a_blocking_waitid_that_finds_no_record_is_a_contract_breach() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let target = Target::PidFd(b.owned.os_handle());
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
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let target = Target::PidFd(b.owned.os_handle());
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

// Adoption =====

/// Block until `pid`'s exit is visible, without consuming it.
fn confirm_exit_of(pid: u32) {
    // SAFETY: an all-zero `siginfo_t` is a valid value, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(r, 0, "waitid(WNOWAIT): {}", std::io::Error::last_os_error());
}

/// Open the pidfd of an exited, unreaped child of ours under the force `arm` installs, expecting
/// the gone answer: `Ok(None)`. The child has already exited when it is opened, so a force that
/// is not applied leaves a pidfd that opens, and the assertion fails instead of blocking.
fn assert_open_is_gone<G>(arm: impl FnOnce() -> G) {
    let (child, stdin) = spawn_std_blocker();
    let pid = child.id();
    let id = identity_of(&child);
    drop(stdin);
    confirm_exit_of(pid);
    let forced = arm();
    let opened = crate::wait::exit_only::open_own_child(pid, Some(id)).expect("a gone answer is not a failure");
    drop(forced);
    assert!(opened.is_none(), "the child was gone, yet it opened");
    // The force was synthetic: the child is still this test's own, unreaped.
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer.
    let r = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    assert_eq!(r, pid as i32, "reap the fixture: {}", std::io::Error::last_os_error());
    drop(child);
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
    let (child, stdin) = spawn_std_blocker();
    let id = identity_of(&child);
    let gone = fault::force_exists_once(crate::identity::Existence::Gone);
    let forced_view = crate::identity::proc_view_fault::force_proc_view_once(view);
    let opened = crate::wait::exit_only::open_own_child(id.pid(), Some(id)).expect("open");
    drop(forced_view);
    drop(gone);
    assert!(opened.is_some(), "the child is kept, with a pidfd");
    // Adopted, so that its end is a kill and a reap by the handle.
    let owned = OwnedChild::adopt(child, id).expect("adopt");
    owned.signal(crate::signal::Sig::Kill).expect("the child is killable");
    drop(stdin);
    super::fixtures::wait_status(&owned);
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

// The pidfd's number =====

const SLOT_MARKER: &str = "COSCA_TEST_OWNED_STDIO_SLOT";
const SLOT_CASE_ENV: &str = "COSCA_TEST_OWNED_STDIO_SLOT_CASE";

/// The adopted pidfd never sits in a stdio slot, even when 0, 1 or 2 is closed at adoption: an
/// application that restores its stdio with `dup2` afterwards would otherwise destroy it.
/// Each case runs in a fresh re-exec, since a closed slot is process-wide.
///
/// Mutant: the pidfd kept at the lowest free number.
#[skuld::test]
fn an_adopted_pidfd_never_sits_in_a_stdio_slot() {
    if !crate::test_child::is_marked_fixture_reexec(SLOT_MARKER) {
        for case in ["0", "1", "2"] {
            crate::test_child::run_fixture_case(
                crate::test_child::fixture_path!(an_adopted_pidfd_never_sits_in_a_stdio_slot),
                SLOT_MARKER,
                SLOT_CASE_ENV,
                case,
            );
        }
        return;
    }
    let slot: i32 = std::env::var(SLOT_CASE_ENV).expect("case").parse().expect("slot");
    let (child, stdin) = spawn_std_blocker();
    let id = identity_of(&child);
    // SAFETY: fd juggling on the standard descriptors of this throwaway re-exec; `saved` is above
    // 2, and the slot is restored below, as an application restoring its stdio would.
    let saved = std::os::fd::IntoRawFd::into_raw_fd(
        rustix::io::fcntl_dupfd_cloexec(unsafe { rustix::fd::BorrowedFd::borrow_raw(slot) }, 10)
            .expect("dup the slot aside"),
    );
    assert!(saved >= 10);
    assert_eq!(unsafe { libc::close(slot) }, 0);
    let owned = OwnedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let fd = std::os::fd::AsRawFd::as_raw_fd(&owned.os_handle());
    // Restore the slot first: the pidfd is still usable afterwards only if it never sat there.
    assert_eq!(unsafe { libc::dup2(saved, slot) }, slot);
    assert!(fd >= 3, "the pidfd took the closed stdio slot: {fd}");
    drop(stdin);
    super::fixtures::wait_status(&owned);
}
