//! A forgotten tokio `Child` leaves the root's pidfd in the backend that replaces it, whatever its
//! fate, and the handle closes it.

use std::os::fd::{AsRawFd, RawFd};

use super::proc_source::{Forgotten, Waited};
use crate::test_child::reaped_elsewhere::reap_behind;

/// Forgets the live root of a fresh handle as `fate`, and answers whether the handle still holds
/// the root's pidfd.
async fn holds_the_pidfd_after_forgetting_a_live_root_as(fate: Forgotten) -> bool {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = super::root_state_tests::session_blocker(false);
    let pid = child.id().pid();
    assert!(child.root_pidfd().is_some(), "a spawned handle holds its root's pidfd");
    child.proc_mut().forget_as("was forgotten by a test", fate);
    let held = child.root_pidfd().is_some();
    drop(writer);
    reap_behind(pid);
    held
}

/// Mutant: "only a child reaped elsewhere keeps its pidfd".
#[skuld::test]
async fn an_unproven_forget_keeps_the_pidfd() {
    assert!(
        holds_the_pidfd_after_forgetting_a_live_root_as(Forgotten::Unproven).await,
        "the pidfd names the root exactly whatever a peek said"
    );
}

/// Mutant: "the pidfd is dropped for every fate".
#[skuld::test]
async fn a_forget_as_reaped_elsewhere_keeps_the_pidfd() {
    assert!(
        holds_the_pidfd_after_forgetting_a_live_root_as(Forgotten::ReapedElsewhere).await,
        "the root's group is still decided through its pidfd"
    );
}

/// A root killed and reaped behind its handle's back, and the handle's pidfd number.
fn reaped_elsewhere_root() -> (crate::tokio::Child, std::io::PipeWriter, RawFd) {
    let (mut child, writer) = super::root_state_tests::session_blocker(false);
    let fd = child
        .root_pidfd()
        .expect("a spawned handle holds its root's pidfd")
        .as_raw_fd();
    child.kill().expect("kill the root");
    reap_behind(child.id().pid());
    (child, writer, fd)
}

/// The pidfd number `child` holds after `forget` forgets its tokio `Child`, which it must.
fn pidfd_after(child: &mut crate::tokio::Child, forget: impl FnOnce(&mut super::ProcSource) -> bool) -> RawFd {
    assert!(forget(child.proc_mut()), "the forget forgot tokio's `Child`");
    child.root_pidfd().expect("the forget kept the pidfd").as_raw_fd()
}

/// The drop's and a cleanup's forget keep the pidfd. Mutant: "`forget_for` drops it".
#[skuld::test]
async fn a_forget_for_a_drop_keeps_the_pidfd() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _writer, fd) = reaped_elsewhere_root();
    let view = child.read_root_view("a test");
    assert_eq!(pidfd_after(&mut child, |proc| proc.forget_for(&view).is_some()), fd);
}

/// A failed spawn's wait that found the child foreign, or unproven, keeps the pidfd. Mutant:
/// "`forget_for_wait` drops it".
#[skuld::test]
async fn a_forget_for_a_wait_keeps_the_pidfd() {
    crate::tokio::test_runtime::assert_current_thread();
    for waited in [Waited::Foreign, Waited::Unverified] {
        let (mut child, _writer, fd) = reaped_elsewhere_root();
        assert_eq!(
            pidfd_after(&mut child, |proc| proc.forget_for_wait(waited, None).is_some()),
            fd,
            "{waited:?}"
        );
    }
}

/// The forget moves the pidfd itself, and the handle's drop closes it: the number is the same
/// before and after the forget, and refers to nothing once the handle is gone (nothing else opens
/// an fd in between). Mutants: "the hand-off duplicates the pidfd"; "the forgotten backend leaks it".
#[skuld::test]
async fn the_forget_moves_the_pidfd_and_the_handle_closes_it() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _writer, fd) = reaped_elsewhere_root();
    child.try_wait().expect_err("a foreign reap answers ECHILD");
    assert_eq!(
        child.root_pidfd().expect("the forget kept the pidfd").as_raw_fd(),
        fd,
        "the same fd, not a duplicate"
    );
    drop(child);
    // SAFETY: `F_GETFD` only reads the descriptor's flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    let err = std::io::Error::last_os_error();
    assert_eq!(
        (flags, err.raw_os_error()),
        (-1, Some(libc::EBADF)),
        "the handle's drop closed the pidfd"
    );
}
