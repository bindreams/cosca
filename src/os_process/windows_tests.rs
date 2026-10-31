use std::time::Duration;

use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, HANDLE};
use windows::Win32::System::Threading::CreateEventW;

use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::drive::{absolute, drive};
use crate::os_process::{kill_by_id, open, terminate_by_id, Exit, Op, OsProcess as _, WaitFor};
use crate::signal::{Sent, Sig};
use crate::test_child::live_blocker as blocker;

/// The kill handle lacks `SYNCHRONIZE`, so the wait goes through a second, `Op::Wait` object.
#[skuld::test]
fn open_live_then_kill_then_exited() {
    let (child, _stdin, id) = blocker();
    let mut waiter = open(id, Op::Wait).unwrap().expect("a live process opens");
    assert!(matches!(waiter.exited().unwrap(), Exit::Running(WaitFor::Signalled(_))));
    assert!(!drive(&mut *waiter, absolute(Some(Duration::ZERO))).unwrap());
    let mut killer = open(id, Op::Kill).unwrap().expect("a live process opens");
    assert_eq!(killer.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(drive(&mut *waiter, absolute(None)).unwrap());
    child.wait().unwrap();
}

#[skuld::test]
fn open_with_wrong_start_token_is_none_and_sends_nothing() {
    let (child, _stdin, id) = blocker();
    let other = ProcessId::from_parts_for_test(id.pid(), id.start_token_raw() + 1);
    assert!(open(other, Op::Kill).unwrap().is_none());
    assert!(open(other, Op::Wait).unwrap().is_none());
    kill_by_id(other).expect("a stale identity is already gone");
    // Still running: the right identity opens and sees no exit.
    let mut p = open(id, Op::Wait).unwrap().expect("the blocker is alive");
    assert!(!drive(&mut *p, absolute(Some(Duration::ZERO))).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[skuld::test]
fn exited_before_first_look_returns_true() {
    let (child, _stdin, id) = blocker();
    let mut p = open(id, Op::Wait).unwrap().expect("a live process opens");
    child.kill().unwrap();
    // `TerminateProcess` returns before the process object is signalled; the child's own wait is
    // the barrier.
    child.wait().unwrap();
    assert!(drive(&mut *p, absolute(Some(Duration::ZERO))).unwrap());
}

/// Mutant: a refused `TerminateProcess` on an exited process is an error, or `kill_by_id` of an
/// exited process whose handle is still held by its owner fails.
#[skuld::test]
fn kill_after_exit_is_ok() {
    let (child, _stdin, id) = blocker();
    child.kill().unwrap();
    child.wait().unwrap();
    kill_by_id(id).expect("killing an exited process is success");
}

#[skuld::test]
fn signal_after_exit_is_gone() {
    let (child, _stdin, id) = blocker();
    let mut p = open(id, Op::Kill).unwrap().expect("a live process opens");
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Gone);
}

#[skuld::test]
fn kill_by_id_ends_the_process() {
    let (child, _stdin, id) = blocker();
    kill_by_id(id).unwrap();
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "a killed blocker does not exit by itself: {status:?}"
    );
}

/// Windows has no per-process graceful signal: `Unsupported`, and the process is untouched.
#[skuld::test]
fn terminate_by_id_is_unsupported_and_sends_nothing() {
    let (child, _stdin, id) = blocker();
    let err = terminate_by_id(id).expect_err("Windows has no graceful per-process signal");
    let Error::Unsupported { op, platform, detail } = err else {
        panic!("expected Unsupported: {err:?}");
    };
    assert_eq!(op, "graceful terminate (SIGTERM-equivalent)");
    assert_eq!(platform, "windows");
    assert!(detail.contains("graceful_shutdown_tree"), "{detail}");
    let mut p = open(id, Op::Wait).unwrap().expect("the blocker is alive");
    assert!(!drive(&mut *p, absolute(Some(Duration::ZERO))).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

/// A look at a signal-only object is a caller bug: a debug assertion, and in release a typed `Err`
/// rather than the OS's denial of the handle's missing `SYNCHRONIZE`; never an answer.
///
/// Mutant: `exited` waits on a handle opened for a kill, so the error is a raw `ACCESS_DENIED`.
#[skuld::test]
fn a_kill_opens_no_wait_and_still_kills() {
    let (child, _stdin, id) = blocker();
    let mut p = open(id, Op::Kill).unwrap().expect("a live process opens");
    let looked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.exited().map(|_| ())));
    // Debug builds assert the contract; release builds return the error.
    let err = match looked {
        Ok(Err(Error::Io(e))) => Some(e),
        Err(_) => None,
        Ok(other) => panic!("a signal-only process has no wait to answer a look: {other:?}"),
    };
    match err {
        Some(e) => assert!(e.to_string().contains("opened for a signal"), "{e}"),
        None if cfg!(debug_assertions) => {}
        None => panic!("release builds return an error, not a panic"),
    }
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    child.wait().unwrap();
}

/// Mutant: a look hands out some other handle to wait on.
#[skuld::test]
fn the_wait_is_on_the_opened_process_handle() {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::GetProcessId;

    let (child, _stdin, id) = blocker();
    let mut p = open(id, Op::Wait).unwrap().expect("a live process opens");
    match p.exited().unwrap() {
        // SAFETY: `h` is the live process handle `p` owns.
        Exit::Running(WaitFor::Signalled(h)) => {
            assert_eq!(unsafe { GetProcessId(HANDLE(h.as_raw_handle())) }, id.pid())
        }
        other => panic!("a live process reads Running(Signalled): {other:?}"),
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

/// A `TerminateProcess` failure that is not a refusal by an exiting process is `Io` with the plain
/// Win32 code. An event is a real handle that is not a process, so `TerminateProcess` on it fails
/// with `ERROR_INVALID_HANDLE`.
///
/// Mutant: `signal` converts with `.into()`, so the code is `0x80070006`.
#[skuld::test]
fn signal_failure_carries_the_win32_code() {
    use windows::Win32::Foundation::ERROR_INVALID_HANDLE;

    let mut p = super::WindowsProcess {
        id: ProcessId::current(),
        op: Op::Kill,
        handle: super::cancel::new_cancel_event().expect("create an event handle"),
    };
    let err = p.signal(Sig::Kill).expect_err("an event cannot be terminated");
    let Error::Io(io) = err else {
        panic!("expected Io, got {err:?}");
    };
    assert_eq!(io.raw_os_error(), Some(ERROR_INVALID_HANDLE.0 as i32), "{io:?}");
}

/// `kill_by_id` of a process that is exiting but not yet signalled is `Ok`; the seam refuses and
/// the process stays alive.
///
/// Mutant: a refusal is success only once the process reads signalled, so this one is `Err(Io)`.
#[skuld::test]
fn kill_by_id_of_a_process_that_is_exiting_but_not_signalled_is_ok() {
    let (child, _stdin, id) = blocker();
    crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    let result = kill_by_id(id);
    // The seam sent no terminate: end the fixture before asserting.
    child.kill().expect("end the fixture");
    child.wait().expect("reap the fixture");

    result.expect("a refusal on an exiting process is not a failed kill");
}

// Win32 codes of failures =====
//
// Each site converts a `windows::core::Error` to an `io::Error`. A bare `.into()` keeps the
// HRESULT (`0x8007xxxx`) where std reports the Win32 code, so each test drives the failing call
// and asserts the code.

/// An event handle: a real handle that is not a process, so `GetProcessTimes` and
/// `TerminateProcess` on it fail with `ERROR_INVALID_HANDLE`. The callee under test closes it.
fn event_handle() -> HANDLE {
    // SAFETY: creating an unnamed event has no preconditions.
    unsafe { CreateEventW(None, true, false, None) }.expect("create an event handle")
}

/// An identity that cannot be read from the held handle is `Unassessable` with the plain Win32
/// code, for `open_verified` and `open_verified_for_kill`, which share `holds_process`.
///
/// Mutant: `holds_process` converts with `.into()`, so the source's code is `0x80070006`.
#[skuld::test]
fn holds_process_of_an_unreadable_handle_carries_the_win32_code() {
    let err = super::holds_process(event_handle(), ProcessId::current()).expect_err("an event has no creation time");
    let crate::error::Error::Unassessable { source, .. } = err else {
        panic!("expected Unassessable, got {err:?}");
    };
    let io = source.expect("the OS error is preserved");
    assert_eq!(io.raw_os_error(), Some(ERROR_INVALID_HANDLE.0 as i32), "{io:?}");
}

/// `open_verified` on a live process we may not open is `Unassessable` with the plain Win32 code.
/// Needs the DACL fixture, which creates a Job Object: CI only.
///
/// Mutant: the `Opened::Denied` arm of `open_verified` converts with `.into()`, so the code is
/// `0x80070005`.
#[skuld::test]
fn open_verified_of_an_access_denied_live_process_carries_the_win32_code() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(open_verified_of_an_access_denied_live_process_carries_the_win32_code),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let io = denied_open_source(&done, |id| super::open_verified(id).map(|_| ()));
    assert_eq!(io.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{io:?}");
}

/// The `Unassessable` source of a refused open of the unkillable fixture, which `call` runs `id`
/// through. Needs the DACL fixture, which creates a Job Object: CI only.
fn denied_open_source(
    done: &crate::test_own_process::Completion,
    call: impl FnOnce(ProcessId) -> Result<(), crate::error::Error>,
) -> std::io::Error {
    let child = crate::identity::windows_fixture::spawn_unkillable(done);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let err = call(id).expect_err("an unopenable live process is not 'gone'");
    let crate::error::Error::Unassessable { source, .. } = err else {
        panic!("expected Unassessable, got {err:?}");
    };
    source.expect("the OS error is preserved")
}
