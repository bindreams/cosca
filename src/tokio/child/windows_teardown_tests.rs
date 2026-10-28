//! Windows: the async spawn's teardown (`ProcSource::reap_now`) when its wait on tokio's process
//! handle fails.

use crate::error::ChildFate;

use super::proc_source::ProcSource;

/// A teardown whose kill was denied (the child's exit is underway, here: it has exited and is not
/// reaped) and whose wait then fails cannot say the kill ended the child: the fate is `Unknown`.
///
/// Mutant: the teardown answers `Killed` for a denied kill whose wait failed.
#[skuld::test]
async fn reap_now_with_a_denied_kill_and_a_failed_wait_is_unknown() {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};

    crate::tokio::test_runtime::assert_current_thread();
    let child = crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn");
    let pid = child.id().expect("tokio owns an un-reaped child");
    let handle = child.raw_handle().expect("tokio holds the handle");
    // SAFETY: tokio owns the live process handle; this only waits on it, without reaping. An exited
    // process that is not reaped answers `TerminateProcess` with `ERROR_ACCESS_DENIED`.
    unsafe { WaitForSingleObject(HANDLE(handle), INFINITE) };
    let proc = ProcSource::new(child);
    let failed = super::fault::fail_handle_wait();

    let fate = proc.reap_now(pid, None);

    assert!(failed.taken(), "the teardown made the wait that failed");
    assert_eq!(fate, ChildFate::Unknown);
}

/// A teardown whose kill was delivered to a live child and whose wait then fails says the child was
/// killed.
///
/// Mutant: the teardown answers `Unknown` for any failed wait.
#[skuld::test]
async fn reap_now_with_a_delivered_kill_and_a_failed_wait_is_killed() {
    use std::io::Read as _;

    crate::tokio::test_runtime::assert_current_thread();
    let (listener, addr) = crate::test_child::registration_rendezvous();
    // Raw tokio bypasses cosca's spawn path, so `spawn_tokio` takes `spawn_lock()` for it.
    let child = crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::from(crate::test_reexec::command(
            std::env::current_exe().expect("current_exe"),
        ))
        .args(crate::test_reexec::fixture_args(
            crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_TEST,
        ))
        .env(crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV, &addr)
        .env(crate::test_child::ack::ACK_ENV, "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null()),
    )
    .expect("spawn the rendezvous fixture");
    let pid = child.id().expect("tokio owns an un-reaped child");
    let proc = ProcSource::new(child);
    let target = crate::Process::from_pid(pid)
        .found()
        .expect("resolve the freshly spawned fixture's pid")
        .id();
    // The fixture is running and blocked: only the teardown's kill can end it.
    let mut sock = crate::test_child::accept_or_die(&listener, target);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the fixture's readiness tag");
    let failed = super::fault::fail_handle_wait();

    let fate = proc.reap_now(pid, None);

    assert!(failed.taken(), "the teardown made the wait that failed");
    assert_eq!(fate, ChildFate::Killed);
}
