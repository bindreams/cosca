//! The fixture must spawn a process that is genuinely LIVE and genuinely denied. If these
//! fail, every access-denied test downstream is vacuous — so they assert the raw Win32
//! verdicts, not our wrappers.

use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

use super::{spawn_query_only, spawn_restricted, spawn_unkillable};

/// The raw Win32 error code for `OpenProcess(mask, pid)`, or `None` if it succeeded.
fn open_err(pid: u32, mask: PROCESS_ACCESS_RIGHTS) -> Option<u32> {
    // SAFETY: OpenProcess tolerates any pid; the handle is closed before return.
    match unsafe { OpenProcess(mask, false, pid) } {
        Ok(h) => {
            unsafe { CloseHandle(h) }.expect("CloseHandle of an owned process handle");
            None
        }
        // HRESULT_FROM_WIN32 packs the Win32 code in the low 16 bits.
        Err(e) => Some(e.code().0 as u32 & 0xFFFF),
    }
}

#[test]
fn the_fixture_child_is_actually_running() {
    let child = spawn_restricted(PROCESS_SYNCHRONIZE.0);
    assert!(
        child.is_running(),
        "the fixture must hand back a LIVE process, or every denial test below is vacuous"
    );
}

#[test]
fn query_limited_is_denied_when_not_granted() {
    let child = spawn_restricted(PROCESS_SYNCHRONIZE.0);
    assert_eq!(
        open_err(child.pid(), PROCESS_QUERY_LIMITED_INFORMATION),
        Some(ERROR_ACCESS_DENIED.0),
        "the fixture must make QUERY_LIMITED genuinely unopenable"
    );
    assert!(
        child.is_running(),
        "and it must still be live at the point of the claim"
    );
}

#[test]
fn synchronize_is_denied_while_query_limited_is_granted() {
    let child = spawn_restricted(PROCESS_QUERY_LIMITED_INFORMATION.0);
    assert_eq!(open_err(child.pid(), PROCESS_QUERY_LIMITED_INFORMATION), None);
    assert_eq!(
        open_err(child.pid(), PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE),
        Some(ERROR_ACCESS_DENIED.0),
        "the fixture must make the SYNCHRONIZE upgrade genuinely fail"
    );
    assert!(child.is_running());
}

#[test]
fn spawn_unkillable_denies_everything() {
    // The empty DACL is load-bearing for four downstream tests; if it ever granted anything
    // they would all take the Opened::Found path and pass vacuously.
    let child = spawn_unkillable();
    assert_eq!(
        open_err(child.pid(), PROCESS_QUERY_LIMITED_INFORMATION),
        Some(ERROR_ACCESS_DENIED.0)
    );
    assert_eq!(open_err(child.pid(), PROCESS_TERMINATE), Some(ERROR_ACCESS_DENIED.0));
    assert!(child.is_running(), "precondition: the subject must be live");
}

#[test]
fn spawn_query_only_denies_terminate_and_grants_query_limited() {
    // Its denial property is what makes `wait::kill`'s Denied arm reachable at all; without
    // this the test that depends on it would pass by terminating a corpse instead.
    let child = spawn_query_only();
    assert_eq!(open_err(child.pid(), PROCESS_QUERY_LIMITED_INFORMATION), None);
    assert_eq!(
        open_err(child.pid(), PROCESS_TERMINATE),
        Some(ERROR_ACCESS_DENIED.0),
        "spawn_query_only must deny PROCESS_TERMINATE"
    );
    assert!(child.is_running(), "precondition: the subject must be live");
}

#[test]
fn terminate_is_granted_by_spawn_restricted_and_denied_by_spawn_unkillable() {
    // Bound, not temporaries: the fixture's own handle keeps a dead child's kernel object
    // (and pid) alive, so both verdicts below hold on a corpse. Liveness must be asserted.
    let granted = spawn_restricted(0);
    assert_eq!(open_err(granted.pid(), PROCESS_TERMINATE), None);
    assert!(granted.is_running(), "precondition: the subject must be live");

    let denied = spawn_unkillable();
    assert_eq!(open_err(denied.pid(), PROCESS_TERMINATE), Some(ERROR_ACCESS_DENIED.0));
    assert!(denied.is_running(), "precondition: the subject must be live");
}

#[test]
fn terminate_records_the_exit_and_is_idempotent() {
    let child = spawn_restricted(PROCESS_QUERY_LIMITED_INFORMATION.0);
    child.terminate();
    assert!(!child.is_running(), "terminate must record an exit");
    child.terminate(); // second call must not panic — Drop calls it again
}
