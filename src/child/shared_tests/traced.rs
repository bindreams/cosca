//! A child held by a tracer, as a debugger holds it: the parent's `waitid` answers `ECHILD` for
//! it, yet it is not reaped. `TRACER`-group tests, run in CI only.

use std::time::Instant;

use crate::identity::{uniq_info, ReadPurpose, UniqRead};
use crate::test_support::tracer::{self, Mode, Report};
use crate::wait::backend::{await_reapable, test_hooks, Waited};
use crate::wait::exit_only::{self, Reap, Target};

/// A held child is running until the tracer hands it back: the by-pid `ECHILD` is not a reap,
/// the kqueue wait keeps waiting, and the hand-back's `NOTE_EXIT` ends it as `Reapable`.
///
/// Mutant: a by-pid `ECHILD` taken for a foreign reap without checking the pid still names the
/// child.
#[test]
fn a_child_held_by_a_tracer_is_running_until_the_hand_back() {
    if !crate::test_support::require_group("TRACER") {
        return;
    }
    let mut tracee = tracer::spawn_tracee(false);
    let stdin = tracee.stdin().expect("the tracee's stdin is piped");
    let pid = tracee.id().pid();
    let unique = match uniq_info(pid, ReadPurpose::Adopt) {
        UniqRead::Found(info) => info.unique_id,
        other => panic!("the tracee's unique id: {other:?}"),
    };
    let mut helper = tracer::start(Mode::Auto).attach(&mut tracee);
    assert_eq!(helper.recv(), Report::Attached);

    let target = Target::pid(pid, Some(unique));
    assert_eq!(exit_only::try_reap(&target).expect("try_reap"), Reap::Running);
    // An expired deadline: one look, no blocking.
    let held = await_reapable(pid, Some(unique), Some(Instant::now())).expect("wait");
    assert_eq!(held, Waited::DeadlinePassed);

    drop(stdin);
    assert_eq!(helper.recv(), Report::Reaped);
    // The zombie is ours again: an unbounded wait sees the exit.
    assert_eq!(await_reapable(pid, Some(unique), None).expect("wait"), Waited::Reapable);
    drop(helper);
    let status = tracee.wait().expect("the handed-back zombie is ours to reap");
    assert!(status.success(), "{status:?}");
}

/// A tracee held by a tracer, its handle, and the stdin that ends it.
fn held() -> Option<(crate::Child, std::io::PipeWriter)> {
    if !crate::test_support::require_group("TRACER") {
        return None;
    }
    let mut tracee = tracer::spawn_tracee(false);
    let stdin = tracee.stdin().expect("the tracee's stdin is piped");
    Some((tracee, stdin))
}

/// Runs `tracee.wait()` on a thread and returns once that thread is about to block in its first
/// `kevent`, with the knote registered: no event can be lost after that.
fn wait_blocked<'s, G>(
    scope: &'s std::thread::Scope<'s, '_>,
    tracee: &'s crate::Child,
    arm: impl FnOnce() -> G + Send + 's,
) -> std::thread::ScopedJoinHandle<'s, Result<std::process::ExitStatus, crate::error::Error>> {
    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let waiter = scope.spawn(move || {
        let _armed = arm();
        let _blocked = test_hooks::on_kevent_round(0, move || _ = blocked_tx.send(()));
        tracee.wait()
    });
    blocked_rx.recv().expect("the waiter must reach its blocking kevent");
    waiter
}

/// A `SharedChild::wait` blocked while a tracer holds the child stays blocked through the child's
/// exit, and returns the status once the tracer hands the zombie back. `try_wait` meanwhile says
/// running.
///
/// Mutant: a by-pid `ECHILD` taken for a foreign reap: the wait returns `ECHILD`.
#[test]
fn a_wait_blocked_across_the_exit_and_the_hand_back_returns_the_status() {
    let Some((tracee, stdin)) = held() else { return };
    let mut helper = tracer::start(Mode::Auto).attach_shared(&tracee);
    assert_eq!(helper.recv(), Report::Attached);
    std::thread::scope(|s| {
        let waiter = wait_blocked(s, &tracee, || ());
        assert_eq!(tracee.try_wait().expect("try_wait"), None, "a held child is running");
        drop(stdin);
        assert_eq!(helper.recv(), Report::Reaped);
        let status = waiter.join().expect("waiter").expect("the wait ends with the status");
        assert!(status.success(), "{status:?}");
    });
}

/// `kill` reaches a held child, the tracer hands the zombie back, and the wait returns the kill.
///
/// Mutant: `kill` refused for a pid the start read cannot see, or a wait that gives up on `ECHILD`.
#[test]
fn kill_ends_a_held_child_and_the_wait_returns_the_kill() {
    let Some((tracee, _stdin)) = held() else { return };
    let mut helper = tracer::start(Mode::Auto).attach_shared(&tracee);
    assert_eq!(helper.recv(), Report::Attached);
    assert_eq!(tracee.try_wait().expect("try_wait"), None, "a held child is running");
    tracee.kill().expect("kill");
    assert_eq!(helper.recv(), Report::Reaped);
    drop(helper);
    let status = tracee.wait().expect("the handed-back zombie is ours to reap");
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGKILL)
    );
}

/// A tracee that has exited, as a zombie on the tracer's own list, is still running for its
/// parent: `ECHILD`, and its tracer is alive, so the wait continues until the tracer hands it back.
///
/// Mutant: an `ECHILD` for a resolvable pid taken for a reap once nothing traces it (a held
/// zombie is no longer flagged as traced): the wait and `try_wait` answer `ECHILD`.
#[test]
fn a_zombie_a_tracer_holds_is_running_until_the_hand_back() {
    let Some((tracee, stdin)) = held() else { return };
    let mut helper = tracer::start(Mode::Hold).attach_shared(&tracee);
    assert_eq!(helper.recv(), Report::Attached);
    std::thread::scope(|s| {
        let waiter = wait_blocked(s, &tracee, || ());
        drop(stdin);
        assert_eq!(helper.recv(), Report::Exited);
        assert_eq!(
            tracee.try_wait().expect("try_wait"),
            None,
            "a held zombie is not ours yet"
        );
        helper.signal();
        assert_eq!(helper.recv(), Report::Reaped);
        let status = waiter.join().expect("waiter").expect("the wait ends with the status");
        assert!(status.success(), "{status:?}");
    });
}
