use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows::Win32::Foundation::ERROR_INVALID_HANDLE;

use super::OwnedJobDup;

/// A null handle fails with plain `ERROR_INVALID_HANDLE`, not an HRESULT.
///
/// Mutant: `OwnedJobDup::new` converts with the `windows` crate's own `io::Error` conversion, which
/// keeps the HRESULT (`0x80070006`).
#[skuld::test]
fn duplicate_failure_carries_the_win32_code() {
    // SAFETY: the value is only handed to `DuplicateHandle`, which refuses it; this test needs a
    // handle the OS refuses.
    let null = unsafe { BorrowedHandle::borrow_raw(std::ptr::null_mut()) };
    let Err(err) = OwnedJobDup::new(null) else {
        panic!("duplicating a null handle must fail");
    };
    let crate::error::Error::Io(err) = err else {
        panic!("expected Error::Io, got {err:?}");
    };
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE.0 as i32), "{err:?}");
}

/// `OwnedJobDup::new` returns a handle of its own, and dropping it leaves the original job open
/// with its member still alive and in it.
///
/// Mutant: `new` hands back the original handle -> the handle values are equal, and the drop closes
/// the job's own.
#[skuld::test]
fn a_dropped_duplicate_leaves_the_job_open_and_its_member_alive() {
    let mut child = crate::test_spawn::spawn(
        std::process::Command::new("cmd")
            .args(["/C", "more"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn cmd /C more");
    let job = crate::containment::windows::assign_to_kill_on_close_job(child.as_raw_handle()).expect("assign to job");

    let dup = OwnedJobDup::new(job.handle()).expect("duplicate the job handle");
    assert_ne!(
        dup.handle().as_raw_handle(),
        job.handle().as_raw_handle(),
        "the duplicate must be a handle of its own"
    );
    drop(dup);

    assert!(
        child.try_wait().expect("poll the member").is_none(),
        "the member must still be alive"
    );
    assert!(
        crate::containment::windows::job_contains_pid(&job, child.id()),
        "the member must still be in the job, and the job handle still open"
    );

    drop(job); // KILL_ON_JOB_CLOSE: reaps the held member
    child.wait().expect("reap the member");
}
