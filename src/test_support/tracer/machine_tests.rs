//! `real_round` on a real kqueue.

use std::time::Duration;

use crate::os_process::macos::kqueue::{Kqueue, SubscribeOutcome, Subscription};

/// A timeout beyond XNU's `kevent` limit still delivers a pending exit instead of panicking. The
/// child blocks on a pipe until `NOTE_EXIT` is armed, since XNU refuses to arm it on an exited
/// process (`ESRCH`).
///
/// Mutant: build the timespec inline, unclamped -> `kevent failed: EINVAL`.
#[skuld::test]
fn real_round_with_a_far_timeout_returns_the_pending_exit() {
    let mut cat = std::process::Command::new("/bin/cat");
    cat.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null());
    let mut child = crate::test_spawn::spawn(&mut cat).expect("spawn cat");
    let stdin = child.stdin.take().expect("cat's stdin is piped");
    let kq = Kqueue::new().expect("kqueue");
    let exit = Subscription::Process {
        pid: child.id(),
        signals: false,
        reap: false,
    };
    assert_eq!(kq.subscribe(exit).expect("arm NOTE_EXIT"), SubscribeOutcome::Subscribed);
    drop(stdin);
    let batch = super::real_round(
        &kq,
        &mut super::SignalPipe::default(),
        Some(Duration::from_secs(u64::from(u32::MAX))),
    );
    assert!(batch.note_exit, "the exit is delivered, not an EINVAL panic");
    child.wait().expect("reap");
}
