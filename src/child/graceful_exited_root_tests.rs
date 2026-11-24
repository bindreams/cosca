//! Windows: a timed tree shutdown over a Job Object whose root exited before the kill, while a
//! grandchild stays. The call's `TimedOut` names what the sweep's wait did not see exit; a root
//! that has exited is not among it. Not covered: a root that exits during the call, or a holder
//! that records the exit during it. No console event is sent and no proxy is started: the stop
//! action is the test's own, and it makes the root leave by closing the root's control socket.

use std::net::TcpStream;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::Error;
use crate::identity::windows_fixture::image_of;
use crate::identity::{ProcessId, Recursive};
use crate::test_child::ctrl_break::{spawn_member, Grandchild, Handler};
use crate::wait::block_probe::{on_each_block, spawn_signalling_at_block};
use crate::wait::test_clock::{advance, FrozenClockGuard};
use crate::ContainMode;

/// The call's timeout and grace.
const TIMEOUT: Duration = Duration::from_secs(1);

/// What the second thread's `Child::wait` is doing when the call is made.
#[derive(Clone, Copy, Debug)]
enum Waiter {
    /// It has returned with the root's status: the child's box already holds the exit.
    Returned,
    /// It holds the wait and is parked just before blocking on the root, until the call has answered.
    Blocked,
}

/// The root's descendants as they were before the call: pid and image.
struct Listing(Vec<(ProcessId, String)>);

impl Listing {
    fn of(root: &ProcessId) -> Listing {
        let below = root.children(Recursive::Yes).expect("the root's descendants");
        Listing(
            below
                .into_iter()
                .map(|id| {
                    let image = format!("{:?}", image_of(id.pid()));
                    (id, image)
                })
                .collect(),
        )
    }

    /// `ids` by pid, with the image the listing read for it; a pid the listing did not hold prints alone.
    fn describe(&self, ids: &[ProcessId]) -> String {
        ids.iter()
            .map(|id| match self.0.iter().find(|(held, _)| held.pid() == id.pid()) {
                Some((held, image)) => format!("pid {} ({image})", held.pid()),
                None => format!("pid {}", id.pid()),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn all(&self) -> String {
        let ids: Vec<ProcessId> = self.0.iter().map(|(id, _)| *id).collect();
        self.describe(&ids)
    }
}

/// A contained root over a Job Object that leaves when its socket closes, and the grandchild it started, which
/// stays while the grandchild's socket is held.
struct Tree {
    child: Arc<crate::Child>,
    grand: Grandchild,
    root: ProcessId,
    before: Listing,
}

/// A [`Tree`] whose stop action ends the root, runs `after_exit`, then moves the frozen clock past the call's
/// deadline.
fn spawn_tree(after_exit: impl Fn() + Send + Sync + 'static) -> Tree {
    let root_sock = Arc::new(Mutex::new(None::<TcpStream>));
    let (child, sock, grand) = spawn_member(
        Handler::Default,
        Some(Handler::Default),
        ContainMode::Strongest,
        |cmd| {
            let root_sock = Arc::clone(&root_sock);
            cmd.graceful_stop(move |target| {
                drop(root_sock.lock().expect("the root's socket").take());
                let root = target.id().expect("the root's identity");
                assert!(
                    crate::test_child::exited_through_open(root, None).expect("a wait for the root"),
                    "the root leaves when its socket closes"
                );
                after_exit();
                advance(TIMEOUT * 2);
                Ok(())
            });
        },
    );
    *root_sock.lock().expect("the root's socket") = Some(sock);
    assert_eq!(child.containment(), crate::Containment::JobObject);
    let root = child.id().expect("the root's identity");
    let grand = grand.expect("the grandchild");
    let before = Listing::of(&root);
    assert!(
        before.0.iter().any(|(id, _)| *id == grand.id),
        "the grandchild is below the root: {}",
        before.all()
    );
    Tree {
        child: Arc::new(child),
        grand,
        root,
        before,
    }
}

/// A timed tree shutdown, with `timeout == grace`, of a Job tree whose root leaves on the stop while a grandchild
/// stays, and a second thread is in `Child::wait` on the same child as `waiter` says, never names the root: it has
/// exited, and the call knew it. The answer is `TimedOut` or, when the kill's effect on the grandchild is already
/// visible at the sweep's look, `Ok`; which of the Job's other members (a console host) it names is not pinned.
///
/// Because the clock passes the deadline in the action, each sweep wait makes one look.
///
/// Mutant: `Unseen::after_root` names the root whatever its look saw.
fn a_root_that_exited_before_the_kill_is_not_named(waiter: Waiter) {
    let (returned_tx, returned_rx) = mpsc::channel::<()>();
    let returned_rx = Mutex::new(returned_rx);
    let tree = spawn_tree(move || {
        if matches!(waiter, Waiter::Returned) {
            returned_rx
                .lock()
                .expect("the receiver")
                .recv()
                .expect("the waiting thread returned");
        }
    });
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (thread, reached) = spawn_signalling_at_block({
        let child = Arc::clone(&tree.child);
        move || {
            // `Blocked`: the thread holds the child's wait and has not yet made it.
            let _park = matches!(waiter, Waiter::Blocked).then(|| {
                let mut release_rx = Some(release_rx);
                on_each_block(move |block| {
                    if let Some(release_rx) = release_rx.take_if(|_| block.is_round()) {
                        _ = release_rx.recv();
                    }
                })
            });
            let status = child.wait().expect("the root's status");
            _ = returned_tx.send(());
            status
        }
    });
    // Both rows: the thread was about to wait on a live root, so it is in the wait when the root leaves.
    reached.recv().expect("the waiting thread reached its wait");

    let (clock, _) = FrozenClockGuard::install();
    let answered = tree.child.graceful_shutdown_tree_timeout(TIMEOUT, TIMEOUT);
    drop(clock);
    drop(release_tx);
    // A call that failed before its stop action ran left the root running: end it, or the join never returns.
    if !matches!(answered, Ok(_) | Err(Error::TimedOut { .. })) {
        _ = tree.child.kill_tree();
    }
    let waited = thread.join().expect("the waiting thread");

    let Tree {
        child,
        grand,
        root,
        before,
    } = tree;
    match &answered {
        Err(Error::TimedOut { members, .. }) => assert!(
            members.iter().all(|member| member.pid() != root.pid()),
            "{waiter:?}: the exited root, pid {}, is named: members {}; the tree was {}",
            root.pid(),
            before.describe(members),
            before.all(),
        ),
        Ok(status) => assert_eq!(status.code(), Some(0), "{waiter:?}: the root's own status"),
        Err(other) => panic!("{waiter:?}: {other:?}; the tree was {}", before.all()),
    }
    assert_eq!(waited.code(), Some(0), "{waiter:?}: the root left by itself");

    // Released, a member the sweep missed leaves by itself with 0; the sweep's kill reads 1.
    let Grandchild { sock, exit, .. } = grand;
    drop(sock);
    assert_eq!(
        exit.wait_for_exit_code(),
        1,
        "{waiter:?}: the sweep killed the grandchild"
    );
    child.kill_tree().expect("the tree is ended");
    drop(child);
}

#[skuld::test]
fn a_timed_tree_shutdown_does_not_name_a_root_a_returned_wait_collected() {
    a_root_that_exited_before_the_kill_is_not_named(Waiter::Returned);
}

#[skuld::test]
fn a_timed_tree_shutdown_does_not_name_a_root_while_a_wait_on_it_is_held() {
    a_root_that_exited_before_the_kill_is_not_named(Waiter::Blocked);
}
