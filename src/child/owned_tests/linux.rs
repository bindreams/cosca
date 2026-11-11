//! Linux-only `OwnedChild` test: the adopted pidfd never sits in a stdio slot.

use super::fixtures::{identity_of, spawn_std_blocker};
use crate::child::owned::OwnedChild;

// The pidfd's number =====

const SLOT_MARKER: &str = "COSCA_TESTCFG_OWNED_STDIO_SLOT";
const SLOT_CASE_ENV: &str = "COSCA_TESTCFG_OWNED_STDIO_SLOT_CASE";

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
