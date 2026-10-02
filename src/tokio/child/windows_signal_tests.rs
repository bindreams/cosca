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
