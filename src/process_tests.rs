use super::Process;
use crate::error::Error;
use crate::identity::{Liveness, ProcessId};

#[skuld::test]
fn current_opens_and_is_alive() {
    let me = Process::current().expect("this process opens");
    assert_eq!(me.id(), ProcessId::current());
    assert_eq!(me.is_alive(), Liveness::Alive);
    let by_id = Process::open(me.id()).expect("open").expect("this process is running");
    assert_eq!(by_id.id(), me.id());
    let by_pid = Process::open_pid(me.id().pid())
        .expect("open")
        .expect("this process is running");
    assert_eq!(by_pid.id(), me.id());
}

/// A live pid bearing a DIFFERENT start token is the recycle case: the pid resolves, but its
/// identity does not match the saved one. Built against our own (definitely-live) pid with a token
/// that cannot be the real one. Mutant: `open` verifies the pid and not the start token.
#[skuld::test]
fn open_of_a_recycled_identity_is_none() {
    let real = ProcessId::current();
    let stale = ProcessId::from_parts_for_test(real.pid(), real.start_token_raw().wrapping_add(1));
    assert!(Process::open(stale)
        .expect("a stale identity is not an error")
        .is_none());
    assert_eq!(stale.exists(), crate::identity::Existence::Gone);
    assert_eq!(stale.is_alive(), Liveness::Dead);
}

#[skuld::test]
fn process_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Process>();
}

/// A live pid whose identity read is refused (`hidepid`, a sandbox) cannot be opened by pid: the
/// error names the pid, it is not `Ok(None)`. Mutant: "an unqueryable pid is gone".
#[cfg(unix)]
#[skuld::test]
fn open_pid_of_a_pid_that_cannot_be_queried_is_unassessable() {
    let (child, id) = crate::test_child::live_exiting_member();
    let (kernel, _guard) = crate::identity::unreadable(id.pid());
    match Process::open_pid_with(&kernel, id.pid()) {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(
                detail.contains(&format!("pid {} exists but could not be queried", id.pid())),
                "{detail}"
            )
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
    crate::test_child::release_unsignalled(child);
}

#[cfg(windows)]
#[skuld::test]
fn open_pid_of_an_access_denied_process_is_unassessable() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(open_pid_of_an_access_denied_process_is_unassessable),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let child = crate::identity::windows_fixture::spawn_restricted(&done, PROCESS_SYNCHRONIZE.0);
    assert!(child.is_running(), "precondition: the subject must be live");
    let result = Process::open_pid(child.pid());
    assert!(
        matches!(result, Err(Error::Unassessable { .. })),
        "a live process we may not query must not open as gone: {result:?}"
    );
}

/// A saved identity of a process we may not open reaches `Unassessable` through `open`, a
/// different path than `open_pid`: the identity is already in hand, and the denial comes from the
/// open. Mutant: "a denied open is `Ok(None)`".
#[cfg(windows)]
#[skuld::test]
fn open_of_a_denied_identity_is_unassessable_not_none() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(open_of_a_denied_identity_is_unassessable_not_none),
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
        matches!(result, Err(Error::Unassessable { .. })),
        "denied must not read as gone: {result:?}"
    );
    assert_eq!(id.exists(), crate::identity::Existence::Unknown);
    assert_eq!(id.is_alive(), Liveness::Unknown);
    assert!(child.is_running(), "and it must still have been live throughout");
}

/// A handle with QUERY alone (no `SYNCHRONIZE`) cannot tell a running process from exit code 259:
/// `is_alive` is `Unknown`, `wait_timeout` is the OS's `ERROR_ACCESS_DENIED`, and an exit proves
/// itself, so `is_alive` reads `Dead` once the process is terminated.
///
/// Mutant: the refused look reads as `Alive`, as `Dead`, or as `Ok(false)` from `wait_timeout`.
#[cfg(windows)]
#[skuld::test]
fn a_query_only_handle_is_unknown_while_running_and_dead_after_termination() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_query_only_handle_is_unknown_while_running_and_dead_after_termination),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = crate::identity::windows_fixture::spawn_query_only(&done);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    let p = Process::open(id)
        .expect("QUERY alone opens")
        .expect("a live process opens");

    assert_eq!(p.is_alive(), Liveness::Unknown);
    let Err(Error::Io(io)) = p.wait_timeout(std::time::Duration::ZERO) else {
        panic!("a look at a running process without SYNCHRONIZE must be Io");
    };
    assert_eq!(
        io.raw_os_error(),
        Some(windows::Win32::Foundation::ERROR_ACCESS_DENIED.0 as i32),
        "{io:?}"
    );

    child.terminate();
    assert_eq!(p.is_alive(), Liveness::Dead);
}
