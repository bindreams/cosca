//! A tree call's look at the root and its sends by the root's number are one step to this handle's
//! own reaps: a `wait` on another thread cannot reap the root between them, so what goes out by the
//! number still names the root's group. The recorders replace `killpg` with a record.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::containment::unix::fault::{record_kill_group, record_term_group};
use crate::graceful_hooks::{at, HookPoint};

/// What the waiter thread did first.
#[derive(Debug, PartialEq, Eq)]
enum Waiter {
    /// Found the handle's lock held, and blocked on it: it has not reaped.
    Blocked,
    /// Reaped the root.
    Reaped,
}

type Wait = JoinHandle<Result<std::process::ExitStatus, crate::error::Error>>;

/// A zombie root leading its own group (its fd marker suppressed on macOS).
fn zombie_group_root() -> Arc<crate::Child> {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    #[cfg(target_os = "macos")]
    cmd.suppress_fd_marker();
    let child = cmd.spawn().expect("spawn");
    drop(writer);
    crate::test_child::wait_until_zombie(child.id().pid());
    Arc::new(child)
}

/// Runs `op` on `child` with a `wait` started on another thread right after the call's look, and
/// returns what that wait did first, and the wait. The look's hook does not return until the wait
/// has either reaped or blocked on the handle's lock: both are events, so nothing waits on time.
fn run_with_a_wait_after_the_look(child: &Arc<crate::Child>, op: impl FnOnce(&crate::Child)) -> (Waiter, Wait) {
    let (tx, rx) = channel();
    let _blocked = {
        let tx = tx.clone();
        crate::child::shared::seams::on_lock_contended(move || {
            _ = tx.send(Waiter::Blocked);
        })
    };
    let seen: Rc<RefCell<Option<(Waiter, Wait)>>> = Rc::default();
    let _hook = at(HookPoint::AfterRootLook, {
        let child = Arc::clone(child);
        let seen = Rc::clone(&seen);
        move || {
            let wait = std::thread::spawn(move || {
                let status = child.wait();
                _ = tx.send(Waiter::Reaped);
                status
            });
            let first = rx.recv().expect("the waiter reaps or blocks");
            *seen.borrow_mut() = Some((first, wait));
        }
    });
    op(child);
    let seen = seen.borrow_mut().take().expect("the call took its look");
    seen
}

/// Mutants: the look and the sends not held against this handle's reaps; the hold dropped after
/// the look, before the sends.
fn own_wait_lands_after_the_sends(op: impl FnOnce(&crate::Child), on_send: impl FnOnce(Box<dyn FnMut(i32)>)) {
    let child = zombie_group_root();
    let pgid = child.id().pid() as i32;
    // Each send to the group, and whether this thread held the handle's lock at it.
    let sends: Rc<RefCell<Vec<(i32, bool)>>> = Rc::default();
    on_send(Box::new({
        let child = Arc::clone(&child);
        let sends = Rc::clone(&sends);
        move |group| sends.borrow_mut().push((group, child.proc.is_held_by_current_thread()))
    }));

    let (first, wait) = run_with_a_wait_after_the_look(&child, op);

    assert_eq!(
        first,
        Waiter::Blocked,
        "an own wait reaped the root between the look and the sends"
    );
    let sends = sends.take();
    assert!(
        sends.iter().any(|(group, _)| *group == pgid),
        "the group was signalled by its number: {sends:?}"
    );
    assert!(
        sends.iter().all(|(group, held)| *group != pgid || *held),
        "the group was signalled with this handle's reaps no longer held off: {sends:?}"
    );
    // The root exited by itself (its stdin closed) before the call: the waiter collects that.
    let status = wait.join().expect("the waiter").expect("the waiter reaps the root");
    assert!(status.success(), "{status:?}");
}

#[skuld::test]
fn kill_tree_holds_off_an_own_wait_until_its_sends_are_done() {
    let killed = record_kill_group();
    own_wait_lands_after_the_sends(
        |child| child.kill_tree().expect("kill the tree"),
        |hook| killed.on_send(hook),
    );
}

#[skuld::test]
fn terminate_tree_holds_off_an_own_wait_until_its_sends_are_done() {
    let termed = record_term_group();
    own_wait_lands_after_the_sends(
        |child| child.terminate_tree().expect("signal the tree"),
        |hook| termed.on_send(hook),
    );
}

/// The `SIGTERM` is the send the look decides; the sweep after the grace takes its own look.
#[skuld::test]
fn graceful_shutdown_tree_holds_off_an_own_wait_until_its_sigterm_is_sent() {
    let termed = record_term_group();
    let _killed = record_kill_group();
    own_wait_lands_after_the_sends(
        |child| {
            child
                .graceful_shutdown_tree(std::time::Duration::ZERO)
                .map(drop)
                .unwrap_or_else(|e| panic!("shut the tree down: {e}"))
        },
        |hook| termed.on_send(hook),
    );
}
