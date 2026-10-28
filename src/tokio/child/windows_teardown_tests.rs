//! Windows: the async spawn's teardown (`ProcSource::reap_now`) around its kill and its wait on
//! tokio's process handle.

use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE,
};

use crate::error::ChildFate;

use super::proc_source::{ProcSource, Waited};

/// A `cmd /C exit 0` child that has exited and is not reaped: its process handle is signalled, and
/// `TerminateProcess` on it is refused.
fn exited_unreaped_child() -> (::tokio::process::Child, u32) {
    let child = crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn");
    let pid = child.id().expect("tokio owns an un-reaped child");
    let handle = child.raw_handle().expect("tokio holds the handle");
    // SAFETY: tokio owns the live process handle; this only waits on it, without reaping.
    unsafe { WaitForSingleObject(HANDLE(handle), INFINITE) };
    (child, pid)
}

/// A `more.com` child blocked on its stdin, and the guard that closes that stdin once the
/// teardown's kill has returned and its wait begins: a kill that sent nothing leaves a process that
/// exits `0`, and the test fails on what it asserts of the exit instead of hanging.
fn blocker_child() -> (
    ::tokio::process::Child,
    u32,
    crate::child::spawn::fault::TeardownBlocker,
) {
    let mut cmd = ::tokio::process::Command::new(crate::test_child::windows_more());
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = crate::test_spawn::spawn_tokio(&mut cmd).expect("spawn the blocker");
    let pid = child.id().expect("tokio owns an un-reaped child");
    let stdin = child.stdin.take().expect("piped stdin");
    (
        child,
        pid,
        crate::child::spawn::fault::release_between_kill_and_wait(stdin),
    )
}

/// A handle of our own to the process `pid`, which outlives tokio's.
fn observer_handle(pid: u32) -> OwnedHandle {
    // SAFETY: plain OpenProcess on the live pid that tokio's handle pins.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .expect("open the child to observe it");
    // SAFETY: a fresh owned handle from OpenProcess.
    unsafe { OwnedHandle::from_raw_handle(handle.0) }
}

/// The "still waiting" warns logged by this thread since `mark`.
fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "still waiting")
        .into_iter()
        .map(|(_, text)| text)
        .collect()
}

/// A teardown whose kill was refused because the child's exit is underway (here: it has exited and
/// is not reaped) and whose wait then fails says `Killed`: the child is dead or dying.
///
/// Mutant: the teardown answers `Unknown` for a failed wait after a refusal.
#[skuld::test]
async fn reap_now_with_an_exit_under_way_and_a_failed_wait_is_killed() {
    crate::tokio::test_runtime::assert_current_thread();
    let (child, pid) = exited_unreaped_child();
    let proc = ProcSource::new(child);
    let failed = super::fault::fail_handle_wait();

    let fate = proc.reap_now(pid, None);

    assert!(failed.taken(), "the teardown made the wait that failed");
    assert_eq!(fate, ChildFate::Killed);
}

/// A teardown whose kill was delivered to a live child and whose wait then fails says the child was
/// killed: the kill ended it (exit code 1), and nothing collected its exit.
///
/// Mutants: the teardown answers `Unknown` for any failed wait; its kill sends nothing, so the
/// blocker's closed stdin ends the child with code 0; the failed wait is recorded as a reap.
#[skuld::test]
async fn reap_now_with_a_delivered_kill_and_a_failed_wait_is_killed() {
    crate::tokio::test_runtime::assert_current_thread();
    let (child, pid, blocker) = blocker_child();
    let observer = observer_handle(pid);
    let proc = ProcSource::new(child);
    let failed = super::fault::fail_handle_wait();

    let fate = proc.reap_now(pid, None);

    assert!(failed.taken(), "the teardown made the wait that failed");
    assert_eq!(fate, ChildFate::Killed);
    // SAFETY: our own live handle. The blocker's stdin was closed when the teardown's wait began, so
    // this returns even if the kill sent nothing.
    assert_eq!(
        unsafe { WaitForSingleObject(HANDLE(observer.as_raw_handle()), INFINITE) },
        WAIT_OBJECT_0
    );
    let mut code = 0u32;
    // SAFETY: our own live handle, and a valid out-parameter.
    unsafe { GetExitCodeProcess(HANDLE(observer.as_raw_handle()), &mut code) }
        .expect("read the exit code of a process that has exited");
    assert_eq!(code, 1, "the teardown's kill must have ended the child");
    assert!(
        blocker.recorded().is_empty(),
        "the wait failed, so no reap was made: {:?}",
        blocker.recorded()
    );
}

/// A teardown with warnings on, whose child has already exited by the time it looks, does not warn.
///
/// Mutant: the look at the child's exit finds it late whatever its handle says.
#[skuld::test]
async fn reap_now_of_an_exited_child_with_warnings_on_does_not_warn() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, pid) = exited_unreaped_child();
    let proc = ProcSource::new(child);
    let _warn = super::fault::warn_slow_teardowns();

    let fate = proc.reap_now(pid, None);

    assert_eq!(fate, ChildFate::Reaped);
    assert_eq!(warns_since(mark), Vec::<String>::new());
}

/// A teardown with warnings on whose child is still running when it looks (the kill is refused as an
/// exit under way, so nothing ends it until the wait begins) warns once, naming the child, and goes
/// on to the wait. The child is really unsignalled: nothing overrides the look.
///
/// Mutants: the look finds the child exited whatever its handle says; the warn drops the pid.
#[skuld::test]
async fn reap_now_of_a_running_child_with_warnings_on_warns_once_naming_it() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, pid, _blocker) = blocker_child();
    let proc = ProcSource::new(child);
    let _warn = super::fault::warn_slow_teardowns_after(std::time::Duration::ZERO);
    crate::identity::windows_fault::refuse_next_terminate_as_exiting();

    let fate = proc.reap_now(pid, None);

    assert_eq!(fate, ChildFate::Reaped, "the wait goes on past the warn");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "one warn: {warns:?}");
    assert!(
        warns[0].contains(&format!("child {pid} ")),
        "the warn names the child: {warns:?}"
    );
}

/// A wait that fails on a real handle (one without `SYNCHRONIZE`) is not an exit.
///
/// Mutant: a failed wait reads as the exit.
#[skuld::test]
fn a_wait_that_fails_on_a_real_handle_is_unverified() {
    let pid = std::process::id();
    // SAFETY: plain OpenProcess on our own pid.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.expect("open ourselves");
    // SAFETY: a fresh owned handle from OpenProcess.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };

    let waited = super::proc_source::wait_for_exit(HANDLE(handle.as_raw_handle()), pid);

    assert_eq!(waited, Waited::Unverified);
}
