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
    let stale = real.with_other_value();
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

/// The open that follows the identity read goes through the same kernel: a kernel whose pidfd for
/// the pid has an inode of its own (not the real process's) opens a handle, which the real kernel
/// would find to be another process. Mutant: "`open_pid_with` opens through `HostKernel`": the
/// proof fails and the pid is `Ok(None)`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn open_pid_with_opens_through_its_kernel() {
    use crate::identity::{FakeKernel, HostKernel};

    let (child, id) = crate::test_child::live_exiting_member();
    let (stand_in, _writer) = std::io::pipe().expect("a pipe");
    let kernel = FakeKernel::over(&HostKernel)
        .on_pidfd_open(id.pid(), Ok(stand_in.into()))
        .on_pidfs_ino(id.pid(), Ok(Some(77)));
    let opened = Process::open_pid_with(&kernel, id.pid()).expect("the open is not an error");
    assert!(opened.is_some(), "the kernel's pidfd is the process");
    crate::test_child::release_unsignalled(child);
}

/// A pidfd call that failed while reading the pid's identity is the open's own failure, as for
/// `open`: a refused `pidfd_open` is `Unsupported`, a failed inode read `Io` naming `pidfs_ino` with
/// the raw errno. Mutant: "the identity read's failed call is `Unassessable`".
#[cfg(target_os = "linux")]
#[skuld::test]
fn open_pid_of_a_pid_whose_pidfd_call_failed_is_the_opens_error() {
    use rustix::io::Errno;

    use crate::identity::FakeKernel;

    const PID: u32 = 4242;
    let refused = FakeKernel::new().on_pidfd_open(PID, Err(Errno::PERM));
    assert!(
        matches!(Process::open_pid_with(&refused, PID), Err(Error::Unsupported { .. })),
        "a refused pidfd_open"
    );

    let (stand_in, _writer) = std::io::pipe().expect("a pipe");
    let unreadable = FakeKernel::new()
        .on_pidfd_open(PID, Ok(stand_in.into()))
        .on_pidfs_ino(PID, Err(Errno::BADF));
    let result = Process::open_pid_with(&unreadable, PID);
    let Err(e @ Error::Io(_)) = &result else {
        panic!("a failed inode read: expected Io, got {result:?}");
    };
    assert!(e.to_string().starts_with("pidfs_ino: "), "{e}");
    assert_eq!(e.raw_os_error(), Some(Errno::BADF.raw_os_error()));
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

/// `kill_tree` kills the root through the handle the `Process` holds, not through a second open of
/// its identity: the held fake is sent the one `SIGKILL`, and the live process it stands in front
/// of, which a send by identity would kill, runs on.
///
/// Mutant: the walk kills the root by its identity.
#[skuld::test]
fn kill_tree_sends_the_roots_kill_through_the_held_handle() {
    use crate::os_process::fake::FakeProcess;
    use crate::signal::{Sent, Sig};

    let (child, _stdin) = crate::test_child::held_uncontained_blocker(true);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let fake = FakeProcess::new([]).signals([Ok(Sent::Delivered)]);
    let held = Process {
        id,
        os: Box::new(fake.clone()),
    };

    held.kill_tree_with(&crate::identity::HostKernel)
        .expect("the held handle took the kill and the root has no descendant");

    assert_eq!(fake.signal_calls(), vec![Sig::Kill]);
    assert!(
        child.try_wait().expect("look at the live process").is_none(),
        "the real process was killed by its identity, not through the held handle"
    );
}
