//! Windows: a tokio child is killed through its own process handle.

use crate::signal::{Sent, Sig};

/// A raw tokio child that exits at once.
fn exiting_child() -> ::tokio::process::Child {
    crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn")
}

/// After tokio reaped the child its handle is closed, so a kill sends nothing.
///
/// Mutant: `signal` terminates a handle that is gone, or answers an error.
#[skuld::test]
async fn a_kill_after_the_child_was_reaped_is_gone() {
    let mut proc = super::proc_source::ProcSource::new(exiting_child());
    proc.wait().await.expect("wait");

    assert_eq!(proc.signal(Sig::Kill).expect("a kill of a reaped child"), Sent::Gone);
}

/// A child that has exited but is not reaped still has its process object, so `TerminateProcess`
/// answers `ACCESS_DENIED`; the wait on the handle then shows it exited, and the kill is a success.
///
/// Mutant: `ACCESS_DENIED` is returned as an error without the wait.
#[skuld::test]
async fn a_kill_of_an_exited_unreaped_child_is_a_success() {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};

    let child = exiting_child();
    let handle = child.raw_handle().expect("tokio holds the handle");
    // SAFETY: tokio owns the live process handle; this only waits on it, without reaping.
    unsafe { WaitForSingleObject(HANDLE(handle), INFINITE) };
    let proc = super::proc_source::ProcSource::new(child);

    assert_eq!(
        proc.signal(Sig::Kill).expect("a kill of an exited child"),
        Sent::Delivered
    );
}

/// An exited child's handle that holds `PROCESS_TERMINATE` but cannot be waited on: the refusal is
/// the exit, so the kill is a success.
///
/// Mutant: `terminate_unreaped` reads a refusal by whether the handle can be waited on, so the
/// missing `SYNCHRONIZE` makes it an `ACCESS_DENIED` error for a dead child.
#[skuld::test]
async fn a_kill_of_an_exited_child_through_an_unwaitable_handle_is_a_success() {
    use super::proc_source::terminate_unreaped;
    use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_HANDLE_OPTIONS, HANDLE};
    use windows::Win32::System::Threading::{
        GetCurrentProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    let child = exiting_child();
    let handle = HANDLE(child.raw_handle().expect("tokio holds the handle"));
    // SAFETY: tokio owns the live process handle; this only waits on it, without reaping.
    unsafe { WaitForSingleObject(handle, INFINITE) };
    let mut limited = HANDLE::default();
    // SAFETY: duplicating the child's handle into this process; `limited` is a valid out-parameter.
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut limited,
            (PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION).0,
            false,
            DUPLICATE_HANDLE_OPTIONS(0),
        )
    }
    .expect("duplicate the child's handle without SYNCHRONIZE");
    let result = terminate_unreaped(limited);
    // SAFETY: `limited` is the owned duplicate made above.
    unsafe { CloseHandle(limited) }.expect("close the duplicate");

    assert_eq!(result.expect("a refusal on an exited child"), Sent::Delivered);
}

// Win32 codes of failures =====
//
// A bare `.into()` on a `windows::core::Error` keeps the HRESULT (`0x8007xxxx`) where std reports
// the Win32 code. Each test makes the real call fail and asserts the code.

/// `TerminateProcess` on a handle that is not a process fails with `ERROR_INVALID_HANDLE`, which
/// reaches the caller as that plain code.
///
/// Mutant: the final arm of `terminate_unreaped` converts with `.into()`, so the code is
/// `0x80070006`.
#[skuld::test]
fn a_terminate_failure_carries_its_win32_code() {
    use super::proc_source::terminate_unreaped;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{ERROR_INVALID_HANDLE, HANDLE};

    let event = crate::os_process::windows::new_cancel_event().expect("create an event");
    let err = terminate_unreaped(HANDLE(event.as_raw_handle())).expect_err("an event cannot be terminated");
    let crate::error::Error::Io(err) = err else {
        panic!("expected Io, got {err:?}");
    };
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE.0 as i32), "{err:?}");
}

/// A handle without `PROCESS_TERMINATE` that cannot be waited on either is a real denial: an error
/// with `ERROR_ACCESS_DENIED` as its code and `PermissionDenied` as its kind, which
/// `map_elevated_kill_error` turns into `Unkillable` for an elevated wrapper.
///
/// Mutant: the `ACCESS_DENIED` arm of `terminate_unreaped` converts with `.into()`, so the code is
/// `0x80070005` and the kind is not `PermissionDenied`.
#[skuld::test]
fn a_denied_terminate_of_an_unwaitable_handle_carries_its_win32_code() {
    use super::proc_source::terminate_unreaped;
    use windows::Win32::Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_HANDLE_OPTIONS, ERROR_ACCESS_DENIED, HANDLE,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // A handle to this very process with only QUERY_LIMITED: no TERMINATE, no SYNCHRONIZE.
    let mut limited = HANDLE::default();
    // SAFETY: duplicating this process's pseudo-handle into this process; `limited` is a valid
    // out-parameter.
    unsafe {
        let me = GetCurrentProcess();
        DuplicateHandle(
            me,
            me,
            me,
            &mut limited,
            PROCESS_QUERY_LIMITED_INFORMATION.0,
            false,
            DUPLICATE_HANDLE_OPTIONS(0),
        )
    }
    .expect("duplicate this process's handle with reduced access");
    let result = terminate_unreaped(limited);
    // SAFETY: `limited` is the owned duplicate made above.
    unsafe { CloseHandle(limited) }.expect("close the duplicate");

    let err = result.expect_err("a handle with no terminate and no synchronize right is a denial");
    let crate::error::Error::Io(err) = err else {
        panic!("expected Io, got {err:?}");
    };
    assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{err:?}");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err:?}");
}
