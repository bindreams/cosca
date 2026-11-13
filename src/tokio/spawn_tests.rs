//! The async spawn runs the sync spawn whole on the blocking pool, and leaves the command as the
//! sync spawn does.

use std::cell::Cell;
use std::future::Future as _;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::command::CommandInput;
use crate::graceful_hooks::{self, HookPoint};
use crate::identity::{Liveness, Resolved};
use crate::test_child::{held_writer_stdin, tokio_command, Console, BLOCKER_ARGV};

/// Set on a command to check that its environment survives the async spawn.
const SPAWN_TEST_ENV: &str = "COSCA_SPAWN_TEST";

/// The sync spawn's own code runs on a blocking-pool thread, not on the runtime's.
///
/// Mutant: the async spawn runs the sync spawn in place.
#[skuld::test]
async fn the_spawn_runs_on_a_blocking_pool_thread() {
    crate::tokio::test_runtime::assert_current_thread();
    let (tx, rx) = std::sync::mpsc::channel();
    let _probe = fault::install_ran(tx);
    let (stdin, writer) = held_writer_stdin();
    let mut cmd = tokio_command(Console::Hidden);
    cmd.args(BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("stdin");
    let mut child = cmd.spawn().await.expect("spawn");
    drop(writer);
    child.wait().await.expect("wait");

    let ran: Vec<_> = rx.try_iter().collect();
    assert!(
        ran.iter().any(|at| at.point == SpawnPoint::BeforeIdentity),
        "the sync spawn reported no step: the probe did not follow it"
    );
    let here = std::thread::current().id();
    for at in &ran {
        assert_ne!(
            at.thread, here,
            "the sync spawn ran on the runtime's thread at {:?}",
            at.point
        );
    }
}

/// A spawn that completed leaves the command as the sync spawn does: its fds taken, the rest kept.
///
/// Mutant: the command is moved into the blocking task and not moved back.
#[skuld::test]
async fn a_completed_spawn_leaves_the_command_as_the_sync_spawn_does() {
    let (stdin, writer) = held_writer_stdin();
    let mut cmd = tokio_command(Console::Hidden);
    cmd.args(BLOCKER_ARGV.iter().copied()).env(SPAWN_TEST_ENV, "kept");
    cmd.stdin(stdin).expect("stdin");
    let mut child = cmd.spawn().await.expect("spawn");
    drop(writer);
    child.wait().await.expect("wait");

    let sync = cmd.sync();
    match sync.input() {
        CommandInput::Argv(argv) => assert_eq!(argv.len(), BLOCKER_ARGV.len(), "the args are kept"),
        other => panic!("the args are kept, got {other:?}"),
    }
    assert_eq!(sync.env_ops().len(), 1, "the env is kept");
    assert!(sync.fds().is_empty(), "the spawn takes the fds");
}

/// A failed spawn leaves the command as a completed one does.
///
/// Mutant: the command is moved back on success only.
#[skuld::test]
async fn a_failed_spawn_leaves_the_command_as_the_sync_spawn_does() {
    let mut cmd = tokio_command(Console::Hidden);
    cmd.executable("cosca-no-such-program-176").arg("kept");
    cmd.spawn().await.expect_err("there is no such program");
    assert!(matches!(cmd.sync().input(), CommandInput::Argv(argv) if argv.len() == 1));
}

/// A spawn future dropped after its first poll leaves the command as `Command::new()` makes it, and
/// the spawn still runs to its end on the pool, where the child it made is dropped: a `kill_on_drop`
/// child is killed and reaped.
///
/// Mutants: the command is not moved into the task; a dropped future's child is not dropped.
#[skuld::test]
fn a_spawn_dropped_after_its_first_poll_runs_to_its_end_on_the_pool() {
    let (tx, rx) = std::sync::mpsc::channel();
    let _probe = fault::install_ran(tx);
    let (stdin, _writer) = held_writer_stdin();
    let rt = crate::tokio::test_runtime::single_thread_pool_runtime();
    let (release, held) = std::sync::mpsc::channel::<()>();
    let hold = rt.spawn_blocking(move || held.recv());
    let mut cmd = tokio_command(Console::Hidden);
    cmd.args(BLOCKER_ARGV.iter().copied()).env(SPAWN_TEST_ENV, "gone");
    cmd.stdin(stdin).expect("stdin");
    cmd.stdout(crate::Stdio::null()).expect("stdout");
    rt.block_on(async {
        let mut spawn = Box::pin(cmd.spawn());
        std::future::poll_fn(|cx| {
            assert!(
                spawn.as_mut().poll(cx).is_pending(),
                "the spawn is queued behind the held thread"
            );
            Poll::Ready(())
        })
        .await;
        drop(spawn);
    });
    release.send(()).expect("release the held thread");
    drop(hold);
    drop(rt);

    let sync = cmd.sync();
    assert!(
        matches!(sync.input(), CommandInput::Empty),
        "the args went with the spawn"
    );
    assert!(sync.env_ops().is_empty(), "the env went with the spawn");
    let child = rx
        .try_iter()
        .find(|at| at.point == SpawnPoint::BeforeIdentity)
        .expect("the spawn ran to its end after its future was dropped");
    let Resolved::Found(id) = child.id else {
        panic!("the child was not identified: {:?}", child.id)
    };
    assert_eq!(
        id.is_alive(),
        Liveness::Dead,
        "the dropped spawn's child is killed and reaped"
    );
}

/// A spawn future dropped after its task finished, before its next poll, drops the finished spawn's
/// child on the pool, not on the runtime thread that drops the future: a `kill_on_drop` child's
/// teardown waits.
///
/// The one blocking thread is held, so the first poll is `Pending`; the waker says the task has
/// finished, and the future is dropped without another poll. The kill-on-drop teardown reports to a
/// hook armed on the dropping thread, so a drop there is seen.
///
/// Mutant: the finished task's output is the join handle's own, dropped with it on the dropping thread.
#[skuld::test]
fn a_spawn_dropped_after_its_task_finished_drops_the_child_off_the_runtime_thread() {
    let (tx, rx) = std::sync::mpsc::channel();
    let _probe = fault::install_ran(tx);
    let (stdin, _writer) = held_writer_stdin();
    let rt = crate::tokio::test_runtime::single_thread_pool_runtime();
    let (release, held) = std::sync::mpsc::channel::<()>();
    let hold = rt.spawn_blocking(move || held.recv());
    let mut cmd = tokio_command(Console::Hidden);
    cmd.args(BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("stdin");
    let dropped_here = Rc::new(Cell::new(false));
    rt.block_on(async {
        let _teardown_here = graceful_hooks::at(HookPoint::AfterDropKill, {
            let dropped_here = Rc::clone(&dropped_here);
            move || dropped_here.set(true)
        });
        let (waker, finished) = crate::tokio::test_runtime::counting_waker();
        let mut spawn = Box::pin(cmd.spawn());
        assert!(
            spawn.as_mut().poll(&mut Context::from_waker(&waker)).is_pending(),
            "the spawn is queued behind the held thread"
        );
        release.send(()).expect("release the held thread");
        finished.recv().expect("the spawn's task finished");
        drop(spawn);
    });
    drop(hold);
    // Control: a child dropped on the armed thread is seen by the same hook, so the negative
    // assertion below can fail.
    let control_here = Rc::new(Cell::new(false));
    rt.block_on(async {
        let _teardown_here = graceful_hooks::at(HookPoint::AfterDropKill, {
            let control_here = Rc::clone(&control_here);
            move || control_here.set(true)
        });
        let (stdin, _writer) = held_writer_stdin();
        let mut control = tokio_command(Console::Hidden);
        control.args(BLOCKER_ARGV.iter().copied());
        control.stdin(stdin).expect("stdin");
        drop(control.spawn().await.expect("spawn the control child"));
    });
    drop(rt);

    assert!(
        control_here.get(),
        "a child dropped on the armed thread is not seen by the hook"
    );
    assert!(
        !dropped_here.get(),
        "the finished spawn's child was dropped on the runtime thread"
    );
    let child = rx
        .try_iter()
        .find(|at| at.point == SpawnPoint::BeforeIdentity)
        .expect("the spawn ran");
    let Resolved::Found(id) = child.id else {
        panic!("the child was not identified: {:?}", child.id)
    };
    assert_eq!(id.is_alive(), Liveness::Dead, "the dropped child is killed and reaped");
}
