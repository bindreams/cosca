//! A failed async spawn's teardown blocks the spawning thread until the child it killed is reaped,
//! and warns once, naming the child, when that wait passes 1 s (principle 2). The async spawn is the
//! sync spawn told the async policy (`SpawnPolicy::teardown_warn_after`), so each row fails the spawn
//! at one arm and pins that the arm passes the policy through to its wait. A foreign tracer holds the
//! killed child's zombie, so the wait cannot end before the tracer lets go; it lets go only once the
//! spawning thread sleeps in a blocking `waitid`, which the teardown reaches only after the warn.
//!
//! The tracee ends only by a kill, or by its stdin closing. The teardown's thread holds the stdin
//! writer and drops it between the teardown's kill and its wait (`release_between_kill_and_wait`),
//! so a kill that sent nothing leaves a tracee that exits `0` into the tracer's hold, and the
//! teardown's reap records that status.

use std::io::BufRead as _;

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::containment::cgroup::fault as leaf_fault;
use crate::test_groups::{cgroup, tracer_group, Group};
use crate::test_support::foreign_tracer::{
    self, assert_reaped_by_sigkill, assert_warns_once_before_blocking, Names, Tracer, LET_EXIT, REAP,
};

/// Fails the spawn at `point`, with `arm` making it fail from there, and `disarm` undoing `arm`.
#[derive(Clone, Copy)]
struct FailAt {
    point: SpawnPoint,
    arm: fn(),
    disarm: fn(),
}

/// The attach fails.
const ATTACH: FailAt = FailAt {
    point: SpawnPoint::BeforeAttach,
    arm: || fault::set_force_attach_failure(true),
    disarm: || fault::set_force_attach_failure(false),
};

/// The identity read says the child vanished.
const IDENTITY_VANISHED: FailAt = FailAt {
    point: SpawnPoint::BeforeIdentity,
    arm: || fault::set_force_identity_vanished(true),
    disarm: || fault::set_force_identity_vanished(false),
};

/// As [`assert_warns_once_before_blocking`], with the tracee spawned and handed to the tracer where
/// `fail` says.
///
/// Mutant (for each test below, besides its own): the teardown's root kill sends nothing.
fn assert_teardown_warns_once_before_blocking(fail: FailAt) {
    assert_front_or_child_teardown_warns_once_before_blocking(fail, false, Names::Pid);
}

/// [`assert_teardown_warns_once_before_blocking`] for a tracee that is, when `front`, an elevation
/// front in a cgroup leaf. `names`: who the warn names.
fn assert_front_or_child_teardown_warns_once_before_blocking(fail: FailAt, front: bool, names: Names) {
    let (stdin, stdin_writer) = crate::test_child::held_writer_stdin();
    let (out_reader, out_writer) = std::io::pipe().expect("pipe");
    let (tracer_tx, tracer_rx) = std::sync::mpsc::channel::<(u32, Tracer)>();
    // Started first: the spawn lock is held where the tracee is seized, and the helper's spawn needs it.
    let mut idle = foreign_tracer::spawn_unseized_helper();
    let (spawned, reaps) = assert_warns_once_before_blocking(
        names,
        move || {
            // A front is ended by its leaf's kill, not by a send to it: the release comes after the
            // `cgroup.kill` write, and before the wait for the front's exit.
            let held = std::rc::Rc::new(std::cell::Cell::new(Some(stdin_writer)));
            let release = || {
                let held = std::rc::Rc::clone(&held);
                move || drop(held.take())
            };
            let (_after_leaf_kill, _between_kill_and_wait);
            let blocker = if front {
                _after_leaf_kill = Some(leaf_fault::set_after_kill_write(release()));
                _between_kill_and_wait = Some(fault::set_between_kill_and_wait(release()));
                None
            } else {
                _after_leaf_kill = None;
                _between_kill_and_wait = None;
                Some(fault::release_between_kill_and_wait(held.take()))
            };
            let rt = ::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let _rt = rt.enter();
            // Kept open until the teardown is done: the tracee's later writes must not stop it on a
            // `SIGPIPE` that only the tracer, which is released after the teardown blocks, could lift.
            let out_open = std::rc::Rc::new(std::cell::RefCell::new(None));
            let seizing = {
                let out_open = std::rc::Rc::clone(&out_open);
                move |pid: u32| {
                    let mut out = std::io::BufReader::new(out_reader);
                    let allowed = (&mut out)
                        .lines()
                        .map(|line| line.expect("read the tracee's stdout"))
                        .any(|line| line.ends_with("@@allowed@@"));
                    *out_open.borrow_mut() = Some(out);
                    assert!(allowed, "the tracee ended without reporting \"allowed\"");
                    idle.seize(pid);
                    tracer_tx.send((pid, idle)).expect("hand the tracer over");
                }
            };
            let _at = fault::set_at(fail.point, move || seizing(fault::spawn_pid()));
            (fail.arm)();
            let mut cmd = foreign_tracer::tokio_tracee_command();
            if front {
                cmd.contain_with(crate::ContainMode::Strongest);
                cmd.set_elevation_report(crate::child::front_kill_tests::sudo_report());
            }
            cmd.stdin(stdin).expect("set stdin");
            let out = std::fs::File::from(std::os::fd::OwnedFd::from(out_writer));
            cmd.stdout(crate::stdio::Stdio::from_file(out)).expect("set stdout");
            let spawned = cmd.spawn().map(drop);
            (fail.disarm)();
            (spawned, blocker.map(|blocker| blocker.recorded()).unwrap_or_default())
        },
        || tracer_rx.recv().expect("the tracer seized the child"),
    );
    assert!(spawned.is_err(), "the forced failure fails the spawn");
    // A front is ended by its leaf's kill, not by a send to it, so what it was reaped as says
    // nothing of the sends under test.
    if !front {
        assert_reaped_by_sigkill(&reaps);
    }
}

/// The teardown after a failed attach (`tear_down_held`, the attach-failure arm).
///
/// Mutant: the arm's `HeldTeardown` carries no threshold.
#[skuld::test]
fn a_teardown_after_a_failed_attach_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    assert_teardown_warns_once_before_blocking(ATTACH);
}

/// The teardown after the identity read says the child vanished (`tear_down_held`, the identity arm).
///
/// Mutant: the arm's `HeldTeardown` carries no threshold.
#[skuld::test]
fn a_teardown_after_a_vanished_identity_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    assert_teardown_warns_once_before_blocking(IDENTITY_VANISHED);
}

/// The teardown after a failed attach of an elevation front in a cgroup leaf. The leaf's kill ends
/// the front, which is sent nothing itself, and the teardown waits for its exit through its pidfd
/// (`OwnedChild::look_at_front`).
///
/// Mutant: the front's wait has no warn.
#[skuld::test]
fn a_front_teardown_after_a_failed_attach_warns_once_past_1s(
    #[fixture(tracer_group)] _tracer: &Group,
    #[fixture(cgroup)] _cgroup: &Group,
) {
    assert_front_or_child_teardown_warns_once_before_blocking(ATTACH, true, Names::Pid);
}

/// The leaf of a failed attach is dropped, which kills it and waits for it to drain
/// (`CgroupLeaf::drop`). A tracee a foreign tracer holds at its exit stop is a live member of the
/// leaf whatever the kill, so the drain outlasts the threshold; the tracer lets it on only from the
/// hook that runs right after the warn (or, for a teardown that never warns, when the wait is about
/// to block, so a missing warn fails the count below instead of hanging).
///
/// Mutants: the leaf's drop waits with no warn; the async spawn hands `prepare` no threshold.
#[skuld::test]
fn a_leaf_drained_past_1s_after_a_failed_attach_warns_once(
    #[fixture(tracer_group)] _tracer: &Group,
    #[fixture(cgroup)] _cgroup: &Group,
) {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (stdin, _stdin_writer) = crate::test_child::held_writer_stdin();
    let (out_reader, out_writer) = std::io::pipe().expect("pipe");
    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let _rt = rt.enter();
    let _warn = crate::tokio::child::fault::warn_slow_teardowns();

    let tracer: Rc<RefCell<Option<Tracer>>> = Rc::default();
    let warns_at_release = Rc::new(Cell::new(None));
    // Lets the tracee on and reaps it, once: the zombie is the tracer's, and the teardown's reap
    // after the leaf's would otherwise wait for it too.
    let release: Rc<dyn Fn()> = {
        let (tracer, warns_at_release) = (Rc::clone(&tracer), Rc::clone(&warns_at_release));
        Rc::new(move || {
            let Some(mut tracer) = tracer.borrow_mut().take() else {
                return;
            };
            warns_at_release.set(Some(
                crate::log_capture::records_since(mark, "still waiting for it to drain").len(),
            ));
            tracer.send(LET_EXIT);
            tracer.expect("continued");
            tracer.send(REAP);
            tracer.expect("reaped");
        })
    };
    let _after_warn = leaf_fault::set_after_drain_warn({
        let release = Rc::clone(&release);
        move || release()
    });
    let _backstop = leaf_fault::set_before_drain_block({
        let release = Rc::clone(&release);
        move || release()
    });
    let _hook = fault::set_at(SpawnPoint::BeforeAttach, {
        let tracer = Rc::clone(&tracer);
        move || {
            let pid = fault::spawn_pid();
            let allowed = std::io::BufReader::new(out_reader)
                .lines()
                .map(|line| line.expect("read the tracee's stdout"))
                .any(|line| line.ends_with("@@allowed@@"));
            assert!(allowed, "the tracee ended without reporting \"allowed\"");
            *tracer.borrow_mut() = Some(foreign_tracer::spawn_helper_holding_exit(pid));
        }
    });
    (ATTACH.arm)();
    let mut cmd = foreign_tracer::tokio_tracee_command();
    cmd.contain_with(crate::ContainMode::Strongest);
    cmd.stdin(stdin).expect("set stdin");
    let out = std::fs::File::from(std::os::fd::OwnedFd::from(out_writer));
    cmd.stdout(crate::stdio::Stdio::from_file(out)).expect("set stdout");
    let spawned = cmd.spawn().map(drop);
    (ATTACH.disarm)();

    assert!(spawned.is_err(), "the forced failure fails the spawn");
    assert_eq!(
        warns_at_release.get(),
        Some(1),
        "one warn for the leaf, out before the tracee was let on"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, "still waiting for it to drain"),
        [log::Level::Warn],
        "exactly one warn, at warn"
    );
}

/// The cleanup of a spawn whose elevation write failed (`finish_elevated`) kills the root, then
/// waits for it, under the policy the async spawn gave the child.
///
/// Mutants: `wait_killed_elevated` waits with no warn; the cleanup's root kill sends nothing.
#[skuld::test]
async fn a_failed_elevation_writes_cleanup_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    // The spawn reads the warn threshold into the child's policy, so it is set before the spawn.
    let _warn = crate::tokio::warn_slow_teardowns();
    let (child, stdin) = foreign_tracer::spawn_tokio_tracee().await;
    let pid = child.pid();
    let tracer = foreign_tracer::spawn_helper(pid);
    let (cleaned, reaps) = assert_warns_once_before_blocking(
        Names::Pid,
        move || {
            let blocker = fault::release_between_kill_and_wait(stdin);
            let cleaned = crate::child::spawn::finish_elevated(
                child.inner,
                Err(crate::error::Error::Io(std::io::Error::other("w"))),
            )
            .map(drop);
            (cleaned, blocker.recorded())
        },
        move || (pid, tracer),
    );
    assert!(cleaned.is_err(), "the failed write fails the spawn");
    assert_reaped_by_sigkill(&reaps);
}
