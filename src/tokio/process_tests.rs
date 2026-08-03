//! The async mirror's introspection delegates. `exists` and `is_alive` are one-line
//! forwards, which is exactly the shape where a mis-wired delegate (forwarding to the other
//! method, or answering from the wrong side) survives every happy-path test. Each of the
//! three `Existence` variants is asserted through the async wrapper; `Present` is covered by
//! `tests/tokio_foreign.rs`, and the two negative cases are here because they need
//! crate-internal fixtures.
//!
//! Plain `#[test]`, not `#[tokio::test]`: these two methods are synchronous by design.

use super::Process;
use crate::identity::{Existence, Liveness, ProcessId};

#[test]
fn a_recycled_pid_reads_as_gone_through_the_async_wrapper() {
    let real = ProcessId::current();
    let stale = ProcessId::from_parts_for_test(real.pid(), real.start_token_raw().wrapping_add(1));
    let p = Process::from_id(stale);
    assert_eq!(p.id(), stale, "the identity is kept verbatim");
    assert_eq!(p.exists(), Existence::Gone);
    assert_eq!(p.is_alive(), Liveness::Dead);
}

#[cfg(windows)]
#[test]
fn a_denied_identity_reads_as_unknown_not_gone_through_the_async_wrapper() {
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let child = crate::identity::windows_fixture::spawn_restricted(PROCESS_SYNCHRONIZE.0);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let p = Process::from_id(id);
    assert_eq!(p.exists(), Existence::Unknown, "denied must not read as Gone");
    assert_eq!(p.is_alive(), Liveness::Unknown, "denied must not read as Dead");
    assert!(child.is_running(), "and it must still have been live throughout");
}
