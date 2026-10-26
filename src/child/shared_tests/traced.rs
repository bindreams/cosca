//! A child held by a tracer, as a debugger holds it: the parent's `waitid` answers `ECHILD` for
//! it, yet it is not reaped. `TRACER`-group tests, run in CI only.

use std::time::Instant;

use crate::identity::{uniq_info, ReadPurpose, UniqRead};
use crate::test_groups::{tracer_group, Group};
use crate::test_support::tracer::{self, Mode, Report};
use crate::wait::backend::{await_reapable, test_hooks, Waited};
use crate::wait::exit_only::{self, Reap, Target};

/// A held child is running until the tracer hands it back: the by-pid `ECHILD` is not a reap,
/// the kqueue wait keeps waiting, and the hand-back's `NOTE_EXIT` ends it as `Reapable`.
///
/// Mutant: a by-pid `ECHILD` taken for a foreign reap without checking the pid still names the
/// child.
#[skuld::test]
fn a_child_held_by_a_tracer_is_running_until_the_hand_back(#[fixture(tracer_group)] _group: &Group) {
    let (mut tracee, _) = tracer::spawn_tracee(tracer::Tracee::Plain);
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
fn held() -> (crate::Child, std::io::PipeWriter) {
    let (mut tracee, _) = tracer::spawn_tracee(tracer::Tracee::Plain);
    let stdin = tracee.stdin().expect("the tracee's stdin is piped");
    (tracee, stdin)
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

/// The live blocker [`tracer::spawn_tracee`] makes, its stdin (closing it ends the tracee), and its
/// unique id.
fn tracee_with_unique() -> (crate::Child, std::io::PipeWriter, u64) {
    let (mut tracee, _) = tracer::spawn_tracee(tracer::Tracee::Plain);
    let stdin = tracee.stdin().expect("the tracee's stdin is piped");
    let unique = match uniq_info(tracee.id().pid(), ReadPurpose::Adopt) {
        UniqRead::Found(info) => info.unique_id,
        other => panic!("the tracee's unique id: {other:?}"),
    };
    (tracee, stdin, unique)
}

/// A real tracer that attaches while the wait is blocked: the attach's `SIGSTOP` wakes the wait
/// through the child's `NOTE_SIGNAL`, before anything else happens to the child. The wait then
/// watches the tracer; the child's exit and the tracer's hand-back end it as `Reapable`.
///
/// Mutant: the wait registers no `NOTE_SIGNAL` on the child.
#[skuld::test]
fn a_tracer_that_attaches_during_a_wait_wakes_it(#[fixture(tracer_group)] _group: &Group) {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use crate::wait::backend::await_reapable_on;
    let (tracee, stdin, unique) = tracee_with_unique();
    let pid = tracee.id().pid();
    let pending = RefCell::new(Some(tracer::start(Mode::Auto)));
    let helper = Rc::new(RefCell::new(None));
    let stdin = RefCell::new(Some(stdin));
    let attach_woke = Rc::new(Cell::new(None));
    let kq = Rc::new(nix::sys::event::Kqueue::new().expect("kqueue"));
    let _rounds = super::macos::on_rounds(&kq, {
        let (helper, attach_woke) = (Rc::clone(&helper), Rc::clone(&attach_woke));
        move |round, kq| match round {
            0 => {
                let mut attached = pending.borrow_mut().take().expect("the helper").attach_unheld(pid);
                assert_eq!(attached.recv(), Report::Attached);
                *helper.borrow_mut() = Some(attached);
                attach_woke.set(Some(test_hooks::event_pending(kq)));
                attach_woke.get() == Some(true)
            }
            1 => {
                drop(stdin.borrow_mut().take());
                true
            }
            _ => true,
        }
    });
    let waited = await_reapable_on(&kq, pid, Some(unique), None).expect("wait");
    assert_eq!(attach_woke.get(), Some(true), "the attach's SIGSTOP must wake the wait");
    assert_eq!(waited, Waited::Reapable);
    let mut helper = helper.borrow_mut().take().expect("the helper attached");
    assert_eq!(helper.recv(), Report::Reaped);
    drop(helper);
    let status = tracee.wait().expect("the handed-back zombie is ours to reap");
    assert!(status.success(), "{status:?}");
}

/// A child whose real tracer is itself traced by a second one: the wait walks the chain and
/// registers the second tracer too, whose signals then wake it. A `SIGCONT` to the second tracer,
/// which leaves a running process running, shows the registration. The child's exit and its
/// tracer's hand-back end the wait as `Reapable`.
///
/// Mutant: the walk stops at the child's tracer.
#[skuld::test]
fn a_wait_on_a_child_whose_tracer_is_traced_watches_that_tracers_tracer(#[fixture(tracer_group)] _group: &Group) {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use crate::wait::backend::await_reapable_on;
    let d = tracer::diag805;
    d("test: start");
    let (tracee, stdin, unique) = tracee_with_unique();
    d("test: tracee ready");
    let pid = tracee.id().pid();
    let mut inner = tracer::start(Mode::Auto).attach_unheld(pid);
    assert_eq!(inner.recv(), Report::Attached);
    d("test: inner attached");
    let mut outer = tracer::start(Mode::Auto).attach_unheld(inner.helper_pid());
    assert_eq!(outer.recv(), Report::Attached);
    d("test: outer attached");
    let outer_pid = outer.helper_pid();
    let stdin = RefCell::new(Some(stdin));
    let watched = Rc::new(Cell::new(None));
    let kq = Rc::new(nix::sys::event::Kqueue::new().expect("kqueue"));
    let _rounds = super::macos::on_rounds(&kq, {
        let watched = Rc::clone(&watched);
        move |round, kq| match round {
            0 => {
                test_hooks::send_signal(outer_pid, libc::SIGCONT);
                watched.set(Some(test_hooks::event_pending(kq)));
                watched.get() == Some(true)
            }
            1 => {
                drop(stdin.borrow_mut().take());
                true
            }
            _ => true,
        }
    });
    let waited = await_reapable_on(&kq, pid, Some(unique), None).expect("wait");
    d("test: wait returned");
    assert_eq!(
        watched.get(),
        Some(true),
        "the wait must watch the signals of the tracer's own tracer"
    );
    assert_eq!(waited, Waited::Reapable);
    assert_eq!(inner.recv(), Report::Reaped);
    d("test: inner reaped");
    // The inner helper's exit goes to the outer one, its tracer and parent, which hands it back
    // when it reaps it; until then this process's reap of it fails with `ECHILD`.
    inner.close_signal_pipe();
    assert_eq!(outer.recv(), Report::Reaped);
    d("test: outer reaped");
    drop(inner);
    drop(outer);
    let status = tracee.wait().expect("the handed-back zombie is ours to reap");
    assert!(status.success(), "{status:?}");
    d("test: end");
}
