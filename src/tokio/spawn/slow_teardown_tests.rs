//! A failed async spawn's teardown blocks the spawning thread until the child it killed is reaped,
//! and warns once, naming the child, when that wait passes 1 s (principle 2). A foreign tracer
//! holds the killed child's zombie, so the wait cannot end before the tracer lets go; it lets go
//! only once the spawning thread sleeps in a blocking `waitid`, which the teardown reaches only
//! after the warn.

use std::io::BufRead as _;

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::test_groups::{tracer_group, Group};
use crate::test_support::foreign_tracer::{self, await_blocked_or_finished, Holder, Tracer, REAP};

/// Runs `teardown` on a thread of its own, on which slow teardowns warn, until it sleeps in a
/// blocking `waitid`; then has the tracer `seized` answers hand the zombie of its child back.
/// `seized` runs once the thread has started. Asserts that the teardown blocked, and that by then
/// exactly one warn naming the child said it was still waiting. Answers what `teardown` returned.
fn assert_warns_once_before_blocking<R: Send>(
    teardown: impl FnOnce() -> R + Send,
    seized: impl FnOnce() -> (u32, Tracer),
) -> R {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();

    // Asserted only after the tracer lets go: a failure inside the scope would join a thread the
    // tracer still blocks.
    let (pid, holder, warns, done) = std::thread::scope(|s| {
        let thread = s.spawn(move || {
            tid_tx
                .send(rustix::thread::gettid().as_raw_nonzero().get())
                .expect("report the tid");
            let _warn = crate::tokio::child::fault::warn_slow_teardowns();
            teardown()
        });
        let tid = tid_rx.recv().expect("the teardown's tid");
        let (pid, mut tracer) = seized();
        let holder = await_blocked_or_finished(tid);
        let warns: Vec<_> = crate::log_capture::records_since(mark, &format!("child {pid}"))
            .into_iter()
            .filter(|text| text.contains("still waiting"))
            .collect();
        tracer.send(REAP);
        tracer.expect("reaped");
        (pid, holder, warns, thread.join().expect("the teardown"))
    });

    assert_eq!(
        holder,
        Holder::Blocked,
        "the teardown returned while the tracer still held child {pid}'s zombie"
    );
    assert_eq!(warns.len(), 1, "one warn before the blocking wait: {warns:?}");
    assert_eq!(
        crate::log_capture::levels_since(mark, "still waiting"),
        [log::Level::Warn],
        "exactly one warn, at warn"
    );
    done
}

/// Spawns a tracee whose spawn `arm` makes fail, with a foreign tracer seizing it at `point`, and
/// asserts as [`assert_warns_once_before_blocking`] does of its teardown.
fn assert_teardown_warns_once_before_blocking(point: SpawnPoint, arm: fn()) {
    let (stdin, _stdin_writer) = crate::test_child::held_writer_stdin();
    let (out_reader, out_writer) = std::io::pipe().expect("pipe");
    let (tracer_tx, tracer_rx) = std::sync::mpsc::channel::<(u32, Tracer)>();
    let spawned = assert_warns_once_before_blocking(
        move || {
            let rt = ::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let _rt = rt.enter();
            let _hook = fault::set_at(point, move || {
                let pid = fault::spawn_pid();
                let allowed = std::io::BufReader::new(out_reader)
                    .lines()
                    .map(|line| line.expect("read the tracee's stdout"))
                    .any(|line| line.ends_with("@@allowed@@"));
                assert!(allowed, "the tracee ended without reporting \"allowed\"");
                tracer_tx
                    .send((pid, foreign_tracer::spawn_helper(pid)))
                    .expect("hand the tracer over");
            });
            arm();
            let mut cmd = foreign_tracer::tokio_tracee_command();
            cmd.stdin(stdin).expect("set stdin");
            let out = std::fs::File::from(std::os::fd::OwnedFd::from(out_writer));
            cmd.stdout(crate::stdio::Stdio::from_file(out)).expect("set stdout");
            let spawned = cmd.spawn().map(drop);
            fault::set_force_attach_failure(false);
            fault::set_force_identity_unknown(false);
            spawned
        },
        || tracer_rx.recv().expect("the tracer seized the child"),
    );
    assert!(spawned.is_err(), "the forced failure fails the spawn");
}

/// The teardown after a failed attach (`ProcSource::reap_now`).
///
/// Mutant: `reap_now` waits with no warn.
#[skuld::test]
fn a_teardown_after_a_failed_attach_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    assert_teardown_warns_once_before_blocking(SpawnPoint::BeforeAttach, || {
        fault::set_force_attach_failure(true);
    });
}

/// The teardown after a refused identity read, through the pidfd
/// (`ProcSource::teardown_through_pidfd`).
///
/// Mutant: `teardown_through_pidfd` reaps with no warn.
#[skuld::test]
fn a_teardown_after_a_refused_identity_read_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    assert_teardown_warns_once_before_blocking(SpawnPoint::BeforeIdentity, || {
        fault::set_force_identity_unknown(true);
    });
}

/// The teardown whose first kill was refused hands the child to the pidfd teardown, whose own kill
/// lands; its reap warns as well.
///
/// Mutant: the pidfd teardown reaps with no warn.
#[skuld::test]
fn a_teardown_whose_first_kill_was_refused_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    assert_teardown_warns_once_before_blocking(SpawnPoint::BeforeAttach, || {
        fault::set_force_attach_failure(true);
        fault::set_force_kill_failure_leaving_child_alive_as("refused", std::io::ErrorKind::PermissionDenied);
    });
}

/// The cleanup of a spawn whose elevation write failed (`finish_elevated`) kills the root, then
/// waits for it.
///
/// Mutant: `wait_and_reap_blocking` waits with no warn.
#[skuld::test]
async fn a_failed_elevation_writes_cleanup_warns_once_past_1s(#[fixture(tracer_group)] _group: &Group) {
    let (child, _stdin) = foreign_tracer::spawn_tokio_tracee().await;
    let pid = child.id().pid();
    let tracer = foreign_tracer::spawn_helper(pid);
    let cleaned = assert_warns_once_before_blocking(
        move || {
            crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
                .map(drop)
        },
        move || (pid, tracer),
    );
    assert!(cleaned.is_err(), "the failed write fails the spawn");
}
