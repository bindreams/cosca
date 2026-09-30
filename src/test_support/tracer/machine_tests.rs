//! `real_round` on a real kqueue.

use std::time::Duration;

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

/// A timeout beyond XNU's `kevent` limit still delivers a pending exit instead of panicking. The
/// child is `cat` on a pipe, so it cannot exit before `NOTE_EXIT` is armed: XNU refuses to arm it
/// on an exited process (`ESRCH`).
///
/// Mutant: build the timespec inline, unclamped -> `kevent failed: EINVAL`.
#[test]
fn real_round_with_a_far_timeout_returns_the_pending_exit() {
    let mut cat = std::process::Command::new("/bin/cat");
    cat.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null());
    let mut child = crate::test_spawn::spawn(&mut cat).expect("spawn cat");
    let stdin = child.stdin.take().expect("cat's stdin is piped");
    let kq = Kqueue::new().expect("kqueue");
    let change = KEvent::new(
        child.id() as usize,
        EventFilter::EVFILT_PROC,
        EvFlags::EV_ADD,
        FilterFlag::NOTE_EXIT,
        0,
        0,
    );
    kq.kevent(&[change], &mut [], Some(libc::timespec { tv_sec: 0, tv_nsec: 0 }))
        .expect("arm NOTE_EXIT");
    drop(stdin);
    let batch = super::real_round(&kq, Some(Duration::from_secs(u64::from(u32::MAX))));
    assert!(batch.note_exit, "the exit is delivered, not an EINVAL panic");
    child.wait().expect("reap");
}
