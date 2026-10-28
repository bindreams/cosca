//! A failed async spawn's teardown blocks the spawning thread until the child it killed is reaped,
//! and warns once, naming the child, when that wait passes 1 s (principle 2). A foreign tracer
//! holds the killed child's zombie, so the wait cannot end before the tracer lets go; it lets go
//! only once the spawning thread sleeps in a blocking `waitid`, which the teardown reaches only
//! after the warn.
//!
//! The tracee ends only by a kill, or by its stdin closing. The teardown's thread holds the stdin
//! writer and drops it between the teardown's kill and its wait (`release_between_kill_and_wait`),
//! so a kill that sent nothing leaves a tracee that exits `0` into the tracer's hold, and the
//! teardown's reap records that status.

use std::io::BufRead as _;

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::test_groups::{cgroup, tracer_group, Group};
use crate::test_support::foreign_tracer::{self, assert_warns_once_before_blocking, Names, Tracer, LET_EXIT, REAP};

/// Where a tracee is handed to the foreign tracer.
#[derive(Clone, Copy)]
enum Seize {
    /// At the spawn point, with `arm` making the spawn fail from there.
    At(SpawnPoint, fn()),
    /// Right after tokio's `spawn()` forked it, with the spawn made to fail there.
    AfterTokioFailsAfterFork,
}

/// Spawns a tracee whose spawn fails as `seize` says, with a foreign tracer seizing it there, and
/// asserts as [`assert_warns_once_before_blocking`] does of its teardown, and that the teardown's
/// kill ended the tracee.
///
/// Mutant (for each test below, besides its own): the teardown's root kill sends nothing.
fn assert_teardown_warns_once_before_blocking(seize: Seize) {
    assert_front_or_child_teardown_warns_once_before_blocking(seize, false, Names::Pid);
}

/// [`assert_teardown_warns_once_before_blocking`] for a tracee that is, when `front`, an elevation
/// front in a cgroup leaf. `names`: who the warn names.
fn assert_front_or_child_teardown_warns_once_before_blocking(seize: Seize, front: bool, names: Names) {
    let (stdin, stdin_writer) = crate::test_child::held_writer_stdin();
    let (out_reader, out_writer) = std::io::pipe().expect("pipe");
    let (tracer_tx, tracer_rx) = std::sync::mpsc::channel::<(u32, Tracer)>();
    // Started first: the spawn lock is held where the tracee is seized, and the helper's spawn needs it.
    let mut idle = foreign_tracer::spawn_unseized_helper();
    let (spawned, reaps) = assert_warns_once_before_blocking(
        names,
        move || {
            let blocker = fault::release_between_kill_and_wait(stdin_writer);
            let rt = ::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let _rt = rt.enter();
            let seizing = move |pid: u32| {
                let allowed = std::io::BufReader::new(out_reader)
                    .lines()
                    .map(|line| line.expect("read the tracee's stdout"))
                    .any(|line| line.ends_with("@@allowed@@"));
                assert!(allowed, "the tracee ended without reporting \"allowed\"");
                idle.seize(pid);
                tracer_tx.send((pid, idle)).expect("hand the tracer over");
            };
            let (_at, _after_fork);
            match seize {
                Seize::At(point, arm) => {
                    _at = Some(fault::set_at(point, move || seizing(fault::spawn_pid())));
                    _after_fork = None;
                    arm();
                }
                Seize::AfterTokioFailsAfterFork => {
                    _at = None;
                    _after_fork = Some(fault::fail_tokio_spawns_after_fork_then(seizing));
                }
            }
            let mut cmd = foreign_tracer::tokio_tracee_command();
            if front {
                cmd.contain_with(crate::ContainMode::Strongest);
                cmd.set_elevation_front(crate::elevation::front::front(Some(
                    &crate::elevation::ElevatedVia::Wrapped(crate::elevation::Backend::Sudo),
                )));
            }
            cmd.stdin(stdin).expect("set stdin");
            let out = std::fs::File::from(std::os::fd::OwnedFd::from(out_writer));
            cmd.stdout(crate::stdio::Stdio::from_file(out)).expect("set stdout");
            let spawned = cmd.spawn().map(drop);
            fault::set_force_attach_failure(false);
            fault::set_force_identity_unknown(false);
            (spawned, blocker.recorded())
        },
        || tracer_rx.recv().expect("the tracer seized the child"),
    );
    assert!(spawned.is_err(), "the forced failure fails the spawn");
    // A front is ended by its leaf's kill, not by a send to it, so what it was reaped as says
    // nothing of the sends under test.
    if !front {
        assert_sigkilled(&reaps);
    }
}

/// At least one child was reaped by a teardown, and each died of `SIGKILL`: the teardown's kill was
/// delivered, and the child did not exit `0` on its stdin's release.
fn assert_sigkilled(reaps: &[(u32, std::process::ExitStatus)]) {
    use std::os::unix::process::ExitStatusExt as _;

    assert!(!reaps.is_empty(), "the teardown must have reaped the child");
    for (pid, status) in reaps {
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "pid {pid} must be SIGKILLed by its teardown kill, not exit once its stdin was released: {status:?}"
        );
    }
}

/// The teardown after a failed attach (`ProcSource::reap_now`).
///
/// Mutant: `reap_now` waits with no warn.
#[skuld::test]
fn a_teardown_after_a_failed_attach_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    assert_teardown_warns_once_before_blocking(Seize::At(SpawnPoint::BeforeAttach, || {
        fault::set_force_attach_failure(true);
    }));
}

/// The teardown after a refused identity read, through the pidfd
/// (`ProcSource::teardown_through_pidfd`).
///
/// Mutant: `teardown_through_pidfd` reaps with no warn.
#[skuld::test]
fn a_teardown_after_a_refused_identity_read_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    assert_teardown_warns_once_before_blocking(Seize::At(SpawnPoint::BeforeIdentity, || {
        fault::set_force_identity_unknown(true);
    }));
}

/// The teardown whose first kill was refused hands the child to the pidfd teardown, whose own kill
/// lands; its reap warns as well.
///
/// Mutant: the pidfd teardown reaps with no warn.
#[skuld::test]
fn a_teardown_whose_first_kill_was_refused_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    assert_teardown_warns_once_before_blocking(Seize::At(SpawnPoint::BeforeAttach, || {
        fault::set_force_attach_failure(true);
        fault::set_force_kill_failure_leaving_child_alive_as("refused", std::io::ErrorKind::PermissionDenied);
    }));
}

/// The teardown after a failed attach of an elevation front in a cgroup leaf. The leaf's kill ends
/// the front, which is sent nothing itself, and the teardown waits for its exit through its pidfd
/// (`teardown_unadopted_or_front_noting`).
///
/// Mutant: the front's wait has no warn.
#[skuld::test]
fn a_front_teardown_after_a_failed_attach_warns_once_past_1s(
    #[fixture(tracer_group)] _tracer: &Group,
    #[fixture(cgroup)] _cgroup: &Group,
) {
    assert_front_or_child_teardown_warns_once_before_blocking(
        Seize::At(SpawnPoint::BeforeAttach, || fault::set_force_attach_failure(true)),
        true,
        Names::Pid,
    );
}

/// tokio's `spawn()` fails after its fork, with no pid to give. The handshake tears down the child it
/// holds through its pidfd (`pidfd_handshake::conclude`), and its wait warns, saying the pid is
/// unknown.
///
/// Mutants: the async spawn does not hand `Handshake::warning_past` the threshold; `conclude`'s
/// teardown waits with no warn.
#[skuld::test]
fn a_spawn_failing_after_its_fork_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    assert_front_or_child_teardown_warns_once_before_blocking(Seize::AfterTokioFailsAfterFork, false, Names::Unknown);
}

/// As above, for an elevation front in a cgroup leaf: the handshake leaves the front to its leaf,
/// whose abandonment kills through the leaf and waits for the front's exit (`end_front`).
///
/// Mutants: `end_front` waits with no warn; the abandonment hands it no threshold.
#[skuld::test]
fn a_front_whose_spawn_failed_after_its_fork_warns_once_past_1s(
    #[fixture(tracer_group)] _tracer: &Group,
    #[fixture(cgroup)] _cgroup: &Group,
) {
    assert_front_or_child_teardown_warns_once_before_blocking(Seize::AfterTokioFailsAfterFork, true, Names::Pid);
}

/// The leaf of a failed attach is dropped, which kills it and waits for it to drain
/// (`CgroupLeaf::drop`). A tracee a foreign tracer holds at its exit stop is a live member of the
/// leaf whatever the kill, so the drain outlasts the threshold; the tracer lets it on only from the
/// hook that runs right after the warn (or, for a teardown that never warns, when the wait is about
/// to block, so a missing warn fails the count below instead of hanging).
///
/// Mutants: the leaf's drop waits with no warn; the failed spawn sets no `teardown_warn_after`.
#[skuld::test]
fn a_leaf_drained_past_1s_after_a_failed_attach_warns_once(
    #[fixture(tracer_group)] _tracer: &Group,
    #[fixture(cgroup)] _cgroup: &Group,
) {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use crate::containment::cgroup::fault as leaf_fault;

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
    fault::set_force_attach_failure(true);
    let mut cmd = foreign_tracer::tokio_tracee_command();
    cmd.contain_with(crate::ContainMode::Strongest);
    cmd.stdin(stdin).expect("set stdin");
    let out = std::fs::File::from(std::os::fd::OwnedFd::from(out_writer));
    cmd.stdout(crate::stdio::Stdio::from_file(out)).expect("set stdout");
    let spawned = cmd.spawn().map(drop);
    fault::set_force_attach_failure(false);

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
/// waits for it.
///
/// Mutants: `wait_and_reap_blocking` waits with no warn; the cleanup's root kill sends nothing.
#[skuld::test]
async fn a_failed_elevation_writes_cleanup_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    let (child, stdin) = foreign_tracer::spawn_tokio_tracee().await;
    let pid = child.id().pid();
    let tracer = foreign_tracer::spawn_helper(pid);
    let (cleaned, reaps) = assert_warns_once_before_blocking(
        Names::Pid,
        move || {
            let blocker = fault::release_between_kill_and_wait(stdin);
            let cleaned =
                crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
                    .map(drop);
            (cleaned, blocker.recorded())
        },
        move || (pid, tracer),
    );
    assert!(cleaned.is_err(), "the failed write fails the spawn");
    assert_sigkilled(&reaps);
}
