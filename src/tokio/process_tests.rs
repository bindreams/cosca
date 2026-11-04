//! The async `Process::open` negative cases (error forwarded, `None` stays `None`); they need
//! crate-internal fixtures. The positive case is `tests/tokio_foreign.rs`. Synchronous: `open` is
//! not async.

use super::Process;
use crate::identity::ProcessId;

#[skuld::test]
fn open_of_a_recycled_identity_is_none_through_the_async_wrapper() {
    let real = ProcessId::current();
    let stale = ProcessId::from_parts_for_test(real.pid(), real.start_token_raw().wrapping_add(1));
    assert!(Process::open(stale)
        .expect("a stale identity is not an error")
        .is_none());
}

#[cfg(windows)]
#[skuld::test]
fn open_of_a_denied_identity_is_unassessable_through_the_async_wrapper() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(open_of_a_denied_identity_is_unassessable_through_the_async_wrapper),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let child = crate::identity::windows_fixture::spawn_restricted(&done, PROCESS_SYNCHRONIZE.0);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let result = Process::open(id);
    assert!(
        matches!(result, Err(crate::error::Error::Unassessable { .. })),
        "denied must not read as gone: {result:?}"
    );
    assert!(child.is_running(), "and it must still have been live throughout");
}
