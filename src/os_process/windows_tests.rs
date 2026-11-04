use std::time::Duration;

use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, HANDLE};
use windows::Win32::System::Threading::CreateEventW;

use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::drive::exited_held;
use crate::os_process::{kill, open, terminate, terminate_by_id, Exit, OsProcess as _, WaitFor};
use crate::signal::{Sent, Sig};
use crate::test_child::live_blocker as blocker;

/// One open: a look, a kill and a wait.
#[skuld::test]
fn one_open_serves_look_signal_and_wait() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    assert!(matches!(p.exited().unwrap(), Exit::Running(WaitFor::Signalled(_))));
    assert!(!exited_held(&*p, Some(Duration::ZERO)).unwrap());
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(exited_held(&*p, None).unwrap());
    child.wait().unwrap();
}

#[skuld::test]
fn open_with_wrong_start_token_is_none_and_sends_nothing() {
    let (child, _stdin, id) = blocker();
    let other = ProcessId::from_parts_for_test(id.pid(), id.start_token_raw() + 1);
    assert!(open(other).unwrap().is_none());
    // Still running: the right identity opens and sees no exit.
    let p = open(id).unwrap().expect("the blocker is alive");
    assert!(!exited_held(&*p, Some(Duration::ZERO)).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[skuld::test]
fn exited_before_first_look_returns_true() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    // `TerminateProcess` returns before the process object is signalled; the child's own wait is
    // the barrier.
    child.wait().unwrap();
    assert!(exited_held(&*p, Some(Duration::ZERO)).unwrap());
}

/// Mutant: a refused `TerminateProcess` on an exited process is an error, or a kill of an exited
/// process whose handle is still held by its owner fails.
#[skuld::test]
fn kill_after_exit_is_ok() {
    let (child, _stdin, id) = blocker();
    child.kill().unwrap();
    child.wait().unwrap();
    let p = open(id)
        .unwrap()
        .expect("an exited process whose owner holds its handle opens");
    kill(&*p).expect("killing an exited process is success");
}

#[skuld::test]
fn signal_after_exit_is_gone() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Gone);
}

#[skuld::test]
fn kill_ends_the_process() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    kill(&*p).unwrap();
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
    let p = open(id).unwrap().expect("the blocker is alive");
    assert!(!exited_held(&*p, Some(Duration::ZERO)).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Windows has no graceful per-process signal, so a held process refuses it too: `Unsupported`, and
/// the process is untouched.
#[skuld::test]
fn terminate_of_a_windows_held_process_is_unsupported() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    let err = terminate(&*p).expect_err("Windows has no graceful per-process signal");
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
    assert!(!exited_held(&*p, Some(Duration::ZERO)).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Mutant: a look hands out some other handle to wait on.
#[skuld::test]
fn the_wait_is_on_the_opened_process_handle() {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::GetProcessId;

    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
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

    let p = super::WindowsProcess {
        pid: std::process::id(),
        handle: super::cancel::new_cancel_event().expect("create an event handle"),
        has_synchronize: true,
    };
    let err = p.signal(Sig::Kill).expect_err("an event cannot be terminated");
    let Error::Io(io) = err else {
        panic!("expected Io, got {err:?}");
    };
    assert_eq!(io.raw_os_error(), Some(ERROR_INVALID_HANDLE.0 as i32), "{io:?}");
}

/// A kill of a process that is exiting but not yet signalled is `Ok`; the seam refuses and the
/// process stays alive.
///
/// Mutant: a refusal is success only once the process reads signalled, so this one is `Err(Io)`.
#[skuld::test]
fn kill_of_a_process_that_is_exiting_but_not_signalled_is_ok() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    let result = kill(&*p);
    // The seam sent no terminate: end the fixture before asserting.
    child.kill().expect("end the fixture");
    child.wait().expect("reap the fixture");

    result.expect("a refusal on an exiting process is not a failed kill");
}

// The access rule =====

/// The `Io` error of `ERROR_ACCESS_DENIED` that a refused look or kill carries.
fn assert_access_denied<T: std::fmt::Debug>(result: Result<T, Error>, what: &str) {
    let Err(Error::Io(io)) = result else {
        panic!("{what} must be Io(ERROR_ACCESS_DENIED), got {result:?}");
    };
    assert_eq!(io.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{what}: {io:?}");
}

/// QUERY alone: no `SYNCHRONIZE`, so a look reads the exit code. A running process cannot be told
/// from exit code 259, so the look is refused; an exit proves itself.
///
/// Mutant: a look without `SYNCHRONIZE` reads `STILL_ACTIVE` as running, or as an exit.
#[skuld::test]
fn a_look_without_synchronize_reads_the_exit_code() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_look_without_synchronize_reads_the_exit_code),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = crate::identity::windows_fixture::spawn_query_only(&done);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    let p = open(id).unwrap().expect("a live process opens with QUERY alone");
    assert_access_denied(p.exited(), "a look at a running process");
    assert_access_denied(
        exited_held(&*p, Some(Duration::ZERO)),
        "a driven look at a running process",
    );
    child.terminate();
    assert!(
        matches!(p.exited().unwrap(), Exit::Exited),
        "an exit code proves the exit"
    );
}

/// A kill refused for lack of `PROCESS_TERMINATE` on a live process is the OS's denial, as `Io`,
/// and kills nothing.
///
/// Mutant: the refusal reads as an exit (`Gone`), or as `Unassessable`.
#[skuld::test]
fn kill_of_a_live_process_without_terminate_is_io_access_denied() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(kill_of_a_live_process_without_terminate_is_io_access_denied),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = crate::identity::windows_fixture::spawn_query_only(&done);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    let p = open(id).unwrap().expect("a live process opens with QUERY alone");
    assert_access_denied(p.signal(Sig::Kill), "a kill without PROCESS_TERMINATE");
    assert!(child.is_running(), "nothing killed it");
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

// OsChild =====

/// A running child has no exit record: a peek says so, and consumes nothing.
#[skuld::test]
fn peek_of_a_running_child_is_running() {
    use crate::os_process::child::{adopted_blocker, PeekOutcome, TryReapOutcome};
    let (os, _id, _stdin) = adopted_blocker();
    assert_eq!(os.peek().unwrap(), PeekOutcome::Running);
    os.signal(Sig::Kill).unwrap();
    assert!(exited_held(&*os, None).unwrap());
    assert!(matches!(os.try_reap().unwrap(), TryReapOutcome::Reaped(_)));
}

/// A reap of a running child hands out the process handle to wait on.
#[skuld::test]
fn try_reap_of_a_running_child_waits_on_the_handle() {
    use crate::os_process::child::{adopted_blocker, TryReapOutcome};
    let (os, _id, _stdin) = adopted_blocker();
    assert!(matches!(
        os.try_reap().unwrap(),
        TryReapOutcome::Running(WaitFor::Signalled(_))
    ));
    os.signal(Sig::Kill).unwrap();
    assert!(exited_held(&*os, None).unwrap());
}

/// A reap of an exited child reads its exit code.
///
/// Mutant: the reap answers `Running` for a signalled handle, or reads the code of another process.
#[skuld::test]
fn try_reap_of_an_exited_child_reads_the_exit_code() {
    use crate::os_process::child::{adopted_blocker, ExitRecord, TryReapOutcome};
    let (os, _id, _stdin) = adopted_blocker();
    os.signal(Sig::Kill).unwrap();
    assert!(exited_held(&*os, None).unwrap());
    let TryReapOutcome::Reaped(ExitRecord::Status(status)) = os.try_reap().unwrap() else {
        panic!("an exited child is reaped");
    };
    // The code the kill's `TerminateProcess` ended the child with.
    assert_eq!(status.code(), Some(crate::identity::WINDOWS_TERMINATE_EXIT_CODE as i32));
}
