//! `kill` on the channel side (D5, D20).

use super::super::fake_shim::Rig;
use super::super::{KillError, KillOutcome, LinkOutcome};
use crate::elevation::shim::protocol::Frame;

/// Runs `f` with `SIGPIPE` blocked on this thread, and says whether `f` raised it. On Linux a blocked
/// signal is never discarded, even where its disposition is `SIG_IGN` (as Rust's runtime sets it), so
/// this sees a `send` that did not suppress the signal without changing any process-wide state.
fn raises_sigpipe(f: impl FnOnce()) -> bool {
    // SAFETY: plain signal-mask calls on zeroed sets, restoring the mask before returning.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGPIPE);
        let mut old: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old), 0);
        f();
        let mut pending: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigpending(&mut pending), 0);
        let raised = libc::sigismember(&pending, libc::SIGPIPE) == 1;
        if raised {
            // Consume it, so unblocking cannot kill the process.
            let mut signo = 0;
            assert_eq!(libc::sigwait(&set, &mut signo), 0);
        }
        assert_eq!(libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()), 0);
        raised
    }
}

#[skuld::test]
fn failed_k_without_a_frame_is_shim_lost() {
    let rig = Rig::new();
    rig.live().close();
    assert!(matches!(rig.link.kill(), Err(KillError::ShimLost)));
    assert_eq!(rig.link.observe().unwrap().outcome, Some(LinkOutcome::ShimLost));
}

#[skuld::test]
fn failed_k_after_a_frame_is_ok_and_never_raises_sigpipe() {
    let rig = Rig::new();
    let mut shim = rig.live();
    shim.send_frame(Frame::Status(0x2a00));
    shim.close();
    let mut killed = None;
    let raised = raises_sigpipe(|| killed = Some(rig.link.kill()));
    // macOS discards an ignored signal even while it is blocked, so `raises_sigpipe` cannot see it
    // there; the socket option that suppresses it is checked instead.
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsFd;
        let conn = rig.link.shared.conn.get().expect("Live has a connection");
        assert!(rustix::net::sockopt::socket_nosigpipe(conn.as_fd()).unwrap());
    }
    assert!(!raised, "a K to a closed shim must not raise SIGPIPE");
    assert_eq!(killed.unwrap().unwrap(), KillOutcome::AlreadyEnded);
    assert_eq!(rig.link.wait().unwrap(), LinkOutcome::Exited(0x2a00));
}

#[skuld::test]
fn kill_delivers_k_while_live_and_refuses_the_start_otherwise() {
    let rig = Rig::new();
    assert_eq!(rig.link.kill().unwrap(), KillOutcome::RefusedStart);
    assert_eq!(
        rig.link.kill().unwrap(),
        KillOutcome::RefusedStart,
        "refused stays refused"
    );

    let live = Rig::new();
    let mut shim = live.live();
    assert_eq!(live.link.kill().unwrap(), KillOutcome::Delivered);
    assert_eq!(shim.read_byte(), Some(b'K'));
}

#[skuld::test]
fn kill_on_a_full_socket_is_unkillable_not_gone() {
    let rig = Rig::new();
    let _shim = rig.live();
    // Nobody reads the K bytes, so the socket's buffer fills; that is the event that ends the loop.
    let err = loop {
        match rig.link.kill() {
            Ok(KillOutcome::Delivered) => {}
            other => break other,
        }
    };
    assert!(matches!(err, Err(KillError::Unkillable)), "{err:?}");
}

#[skuld::test]
fn owner_check_refuses_a_fork_copy() {
    use super::super::outcome::{owner_check, NotOwner};
    use crate::elevation::shim::fork_guard::Origin;
    assert_eq!(owner_check(Origin::Original), Ok(()));
    assert_eq!(owner_check(Origin::Copy), Err(NotOwner));
    assert_eq!(owner_check(Origin::Unknown), Err(NotOwner));
}
