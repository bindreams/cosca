//! A child held by a tracer, as a debugger holds it: the parent's `waitid` answers `ECHILD` for
//! it, yet it is not reaped. `TRACER`-group tests, run in CI only.

use std::time::Instant;

use crate::identity::{uniq_info, ReadPurpose, UniqRead};
use crate::os_process::macos::kqueue::test_hooks;
use crate::test_groups::{tracer_group, Group};
use crate::test_support::tracer::{self, Mode, Report};
use crate::wait::exit_only::{self, Reap, Target};
use crate::wait::macos::{await_reapable, Waited};

/// A held child is running until the tracer hands it back: the by-pid `ECHILD` is not a reap,
/// the kqueue wait keeps waiting, and the hand-back's `NOTE_EXIT` ends it as `Reapable`.
///
/// Mutant: a by-pid `ECHILD` taken for a foreign reap without checking the pid still names the
/// child.
#[skuld::test]
fn a_child_held_by_a_tracer_is_running_until_the_hand_back(#[fixture(tracer_group)] _group: &Group) {
    let (mut tracee, _) = tracer::spawn_tracee(tracer::Tracee::Plain);
    let stdin = tracee.stdin().expect("the tracee's stdin is piped");
    let pid = tracee.pid();
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
fn held() -> (crate::Child, crate::PipeWriter) {
    let (mut tracee, _) = tracer::spawn_tracee(tracer::Tracee::Plain);
    let stdin = tracee.stdin().expect("the tracee's stdin is piped");
    (tracee, stdin)
}

/// Runs `wait(tracee)` on a thread and returns once that thread is about to block on its first
/// `poll` of a kqueue, whose knote is registered: no event can be lost after that.
fn blocked_in<'s, G, R: Send + 's>(
    scope: &'s std::thread::Scope<'s, '_>,
    tracee: &'s crate::Child,
    arm: impl FnOnce() -> G + Send + 's,
    wait: impl FnOnce(&'s crate::Child) -> R + Send + 's,
) -> std::thread::ScopedJoinHandle<'s, R> {
    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let waiter = scope.spawn(move || {
        let _armed = arm();
        let _blocked = crate::wait::block_probe::on_blocking(move || _ = blocked_tx.send(()));
        wait(tracee)
    });
    blocked_rx.recv().expect("the waiter must reach its blocking poll");
    waiter
}

/// [`blocked_in`] for `tracee.wait()`, which blocks on the reap kqueue.
fn wait_blocked<'s, G>(
    scope: &'s std::thread::Scope<'s, '_>,
    tracee: &'s crate::Child,
    arm: impl FnOnce() -> G + Send + 's,
) -> std::thread::ScopedJoinHandle<'s, Result<std::process::ExitStatus, crate::error::Error>> {
    blocked_in(scope, tracee, arm, |tracee| tracee.wait())
}

/// An `OwnedChild` wait blocked while a tracer holds the child stays blocked through the child's
/// exit, and returns the status once the tracer hands the zombie back. `try_wait` meanwhile says
/// running.
///
/// Mutant: a by-pid `ECHILD` taken for a foreign reap: the wait returns `ECHILD`.
#[skuld::test]
fn a_wait_blocked_across_the_exit_and_the_hand_back_returns_the_status(#[fixture(tracer_group)] _group: &Group) {
    let (tracee, stdin) = held();
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
#[skuld::test]
fn kill_ends_a_held_child_and_the_wait_returns_the_kill(#[fixture(tracer_group)] _group: &Group) {
    let (tracee, _stdin) = held();
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
#[skuld::test]
fn a_zombie_a_tracer_holds_is_running_until_the_hand_back(#[fixture(tracer_group)] _group: &Group) {
    let (tracee, stdin) = held();
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

/// A tracee whose tracer holds its zombie has exited for the grace watch, though XNU sends its
/// `NOTE_EXIT` to the tracer alone: the look reads the zombie itself, so the watch ends with the
/// tracer still holding it. While the tracee runs, the held look is a `Recheck`, so it reads as
/// running at an expired deadline.
///
/// Mutant: `exited_by` waits on the exit watch alone, which fires only at the hand-back: the
/// unbounded watch below never returns.
#[skuld::test]
fn a_zombie_a_tracer_holds_has_exited_for_the_grace_watch_before_the_hand_back(
    #[fixture(tracer_group)] _group: &Group,
) {
    let (tracee, stdin) = held();
    let mut helper = tracer::start(Mode::Hold).attach_shared(&tracee);
    assert_eq!(helper.recv(), Report::Attached);
    assert!(
        !tracee.proc.exited_by(Some(Instant::now())).expect("a held live root"),
        "a held root that runs has not exited"
    );
    drop(stdin);
    assert_eq!(helper.recv(), Report::Exited);
    assert!(
        tracee.proc.exited_by(None).expect("a held zombie"),
        "the held zombie has exited"
    );
    assert_eq!(
        tracee.try_wait().expect("try_wait"),
        None,
        "a held zombie is not ours yet"
    );
    helper.signal();
    assert_eq!(helper.recv(), Report::Reaped);
    let status = tracee.wait().expect("the handed-back zombie is ours to reap");
    assert!(status.success(), "{status:?}");
}

/// A zombie that launchd holds has exited for the grace watch, with a long grace unspent. The tracer's
/// hold is the real state, and its parent read is forced to launchd, as when the tracer died while the
/// tracee was exiting.
///
/// Mutant: the look reads past the exit watch only for a parent that is a tracer, not for launchd.
#[skuld::test]
fn a_zombie_launchd_holds_has_exited_for_the_grace_watch_at_once(#[fixture(tracer_group)] _group: &Group) {
    use crate::identity::{ppid_fault, LAUNCHD};

    let (tracee, stdin) = held();
    let mut helper = tracer::start(Mode::Hold).attach_shared(&tracee);
    assert_eq!(helper.recv(), Report::Attached);
    drop(stdin);
    assert_eq!(helper.recv(), Report::Exited);
    {
        let _launchd = ppid_fault::force_ppid_with(|| Ok(LAUNCHD));
        let long = Instant::now() + std::time::Duration::from_secs(3600);
        assert!(
            tracee.proc.exited_by(Some(long)).expect("a zombie launchd holds"),
            "the zombie has exited: no grace is spent on it"
        );
    }
    helper.signal();
    assert_eq!(helper.recv(), Report::Reaped);
    let status = tracee.wait().expect("the handed-back zombie is ours to reap");
    assert!(status.success(), "{status:?}");
}

/// A real tracer that attaches while the grace watch is blocked (`graceful_shutdown`'s wait, here
/// [`OwnedChild::exited_by`](crate::child::owned::OwnedChild::exited_by) with no deadline): the
/// attach's `SIGSTOP` wakes the watch on its own kqueue, its look finds another process holding the
/// child, and the watch ends once the tracer holds the child's zombie. XNU sends that `NOTE_EXIT` to
/// the tracer alone.
///
/// Mutant: the exit wait registers no `NOTE_SIGNAL`, or blocks on the shared exit kqueue, whose
/// `NOTE_EXIT` is withheld: the watch never returns.
#[skuld::test]
fn a_tracer_that_attaches_during_the_grace_watch_wakes_it(#[fixture(tracer_group)] _group: &Group) {
    let (tracee, stdin) = held();
    std::thread::scope(|s| {
        let watcher = blocked_in(s, &tracee, || (), |tracee| tracee.proc.exited_by(None));
        let mut helper = tracer::start(Mode::Hold).attach_shared(&tracee);
        assert_eq!(helper.recv(), Report::Attached);
        drop(stdin);
        assert_eq!(helper.recv(), Report::Exited);
        assert!(
            watcher.join().expect("watcher").expect("the watch"),
            "the held zombie has exited"
        );
        helper.signal();
        assert_eq!(helper.recv(), Report::Reaped);
    });
    let status = tracee.wait().expect("the handed-back zombie is ours to reap");
    assert!(status.success(), "{status:?}");
}

/// A thread that asks `is_alive` while the grace watch is blocked takes nothing from it: the attach
/// that follows still wakes the watch, which ends once the tracer holds the zombie. The watch's
/// kqueue is its own, and `is_alive` reads only the shared exit watch.
///
/// Mutant: the watch blocks on a kqueue that `is_alive` reads, which takes the attach's event.
#[skuld::test]
fn is_alive_during_the_grace_watch_does_not_swallow_its_wake(#[fixture(tracer_group)] _group: &Group) {
    let (tracee, stdin) = held();
    std::thread::scope(|s| {
        let watcher = blocked_in(s, &tracee, || (), |tracee| tracee.proc.exited_by(None));
        assert_eq!(tracee.is_alive(), crate::identity::Liveness::Alive);
        let mut helper = tracer::start(Mode::Hold).attach_shared(&tracee);
        assert_eq!(helper.recv(), Report::Attached);
        // Whatever it answers for a held child, it must not take the watch's wake.
        let _liveness = tracee.is_alive();
        drop(stdin);
        assert_eq!(helper.recv(), Report::Exited);
        assert!(
            watcher.join().expect("watcher").expect("the watch"),
            "the held zombie has exited"
        );
        helper.signal();
        assert_eq!(helper.recv(), Report::Reaped);
    });
    let status = tracee.wait().expect("the handed-back zombie is ours to reap");
    assert!(status.success(), "{status:?}");
}

/// The live blocker [`tracer::spawn_tracee`] makes, its stdin (closing it ends the tracee), and its
/// unique id.
fn tracee_with_unique() -> (crate::Child, crate::PipeWriter, u64) {
    let (mut tracee, _) = tracer::spawn_tracee(tracer::Tracee::Plain);
    let stdin = tracee.stdin().expect("the tracee's stdin is piped");
    let unique = match uniq_info(tracee.pid(), ReadPurpose::Adopt) {
        UniqRead::Found(info) => info.unique_id,
        other => panic!("the tracee's unique id: {other:?}"),
    };
    (tracee, stdin, unique)
}

/// A real tracer that attaches while the wait is blocked: the attach's `SIGSTOP` wakes the wait
/// through the child's `NOTE_SIGNAL`, before anything else happens to the child. The wait then
/// watches the tracer; the child's exit and the tracer's hand-back end it with the child's status.
///
/// Mutant: the wait registers no `NOTE_SIGNAL` on the child.
#[skuld::test]
fn a_tracer_that_attaches_during_a_wait_wakes_it(#[fixture(tracer_group)] _group: &Group) {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    let (tracee, stdin, unique) = tracee_with_unique();
    let pid = tracee.pid();
    let (owned, mac) = super::macos::watch(pid, unique);
    let pending = RefCell::new(Some(tracer::start(Mode::Auto)));
    let helper = Rc::new(RefCell::new(None));
    let stdin = RefCell::new(Some(stdin));
    let attach_woke = Rc::new(Cell::new(None));
    let _rounds = super::macos::on_rounds(&mac, {
        let (helper, attach_woke) = (Rc::clone(&helper), Rc::clone(&attach_woke));
        move |round, mac| match round {
            0 => {
                let mut attached = pending.borrow_mut().take().expect("the helper").attach_unheld(pid);
                assert_eq!(attached.recv(), Report::Attached);
                *helper.borrow_mut() = Some(attached);
                attach_woke.set(Some(mac.event_pending()));
                attach_woke.get() == Some(true)
            }
            1 => {
                drop(stdin.borrow_mut().take());
                true
            }
            _ => true,
        }
    });
    let outcome = owned.wait(None);
    assert_eq!(attach_woke.get(), Some(true), "the attach's SIGSTOP must wake the wait");
    let mut helper = helper.borrow_mut().take().expect("the helper attached");
    assert_eq!(helper.recv(), Report::Reaped);
    drop(helper);
    let status = super::fixtures::status(outcome);
    assert!(status.success(), "{status:?}");
}

/// A child whose real tracer is itself traced by a second one: the wait walks the chain and
/// registers the second tracer too, whose signals then wake it. A `SIGCONT` to the second tracer,
/// which leaves a running process running, shows the registration. The child's exit and its
/// tracer's hand-back end the wait with the child's status.
///
/// Mutant: the walk stops at the child's tracer.
#[skuld::test]
fn a_wait_on_a_child_whose_tracer_is_traced_watches_that_tracers_tracer(#[fixture(tracer_group)] _group: &Group) {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    let (tracee, stdin, unique) = tracee_with_unique();
    let pid = tracee.pid();
    let mut inner = tracer::start(Mode::Auto).attach_unheld(pid);
    assert_eq!(inner.recv(), Report::Attached);
    let mut outer = tracer::start(Mode::Auto).attach_unheld(inner.helper_pid());
    assert_eq!(outer.recv(), Report::Attached);
    let outer_pid = outer.helper_pid();
    let stdin = RefCell::new(Some(stdin));
    let watched = Rc::new(Cell::new(None));
    let (owned, mac) = super::macos::watch(pid, unique);
    let _rounds = super::macos::on_rounds(&mac, {
        let watched = Rc::clone(&watched);
        move |round, mac| match round {
            0 => {
                test_hooks::send_signal(outer_pid, libc::SIGCONT);
                watched.set(Some(mac.event_pending()));
                watched.get() == Some(true)
            }
            1 => {
                drop(stdin.borrow_mut().take());
                true
            }
            _ => true,
        }
    });
    let outcome = owned.wait(None);
    assert_eq!(
        watched.get(),
        Some(true),
        "the wait must watch the signals of the tracer's own tracer"
    );
    assert_eq!(inner.recv(), Report::Reaped);
    // The inner helper's exit goes to the outer one, its tracer and parent, which hands it back
    // when it reaps it; until then this process's reap of it fails with `ECHILD`.
    inner.close_signal_pipe();
    assert_eq!(outer.recv(), Report::Reaped);
    drop(inner);
    drop(outer);
    let status = super::fixtures::status(outcome);
    assert!(status.success(), "{status:?}");
}
