//! `OwnedChild::wait_async`: the async reap through `tokio::drive::run`, over a `FakeProcess` for the
//! policy and over real children for the waits.

use std::pin::pin;
use std::process::{ChildStdin, ExitStatus};

use super::fixtures::{identity_of, spawn_std_blocker_with, status};
use crate::child::owned::{ChildWaitOutcome, OwnedChild};
use crate::os_process::child::ExitRecord;
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::tokio::drive::drive_tests::poll_once;

fn exit() -> ExitRecord {
    ExitRecord::Status(ExitStatus::default())
}

/// A child that exits 3 once its stdin closes, and the write end of that stdin.
pub(super) fn exits_three_on_eof() -> (OwnedChild, ChildStdin) {
    let (child, stdin) = spawn_std_blocker_with(|cmd| {
        #[cfg(unix)]
        let mut command = std::process::Command::new("sh");
        #[cfg(unix)]
        command.args(["-c", "read x; exit 3"]);
        #[cfg(windows)]
        let mut command = std::process::Command::new("cmd");
        #[cfg(windows)]
        command.args(["/D", "/C", "more >nul & exit 3"]);
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null());
        *cmd = command;
    });
    let id = identity_of(&child);
    let owned = OwnedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    (owned, stdin)
}

/// A `Recheck` is paused on tokio's timer, and the record is cached: a later sync `wait` answers it
/// without a look (the fake panics past its script).
///
/// Mutant: no `E` write; or the pause is not taken.
#[cfg(unix)]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn wait_async_reaps_and_caches_the_record() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Recheck, ReapAnswer::Reaped(exit())]);
    let mut child = OwnedChild::new(Box::new(fake.clone()));
    assert_eq!(child.wait_async().await.unwrap(), ChildWaitOutcome::Exited(exit()));
    assert_eq!(child.wait(None).unwrap(), ChildWaitOutcome::Exited(exit()));
    assert_eq!(fake.looks(), 2);
}

/// Mutant: `wait_async` looks at the OS though the record is cached.
#[skuld::test]
async fn wait_async_after_a_sync_wait_answers_from_the_cache() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Reaped(exit())]);
    let mut child = OwnedChild::new(Box::new(fake.clone()));
    child.wait(None).unwrap();
    assert_eq!(child.wait_async().await.unwrap(), ChildWaitOutcome::Exited(exit()));
    assert_eq!(fake.looks(), 1);
}

/// Mutant: a pause on a duration instead of the backoff; or a pause that does not restart.
#[cfg(unix)]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn wait_async_pauses_on_tokio_s_timer_for_a_recheck() {
    crate::wait::block_probe::take();
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Recheck, ReapAnswer::Recheck, ReapAnswer::Reaped(exit())]);
    let mut child = OwnedChild::new(Box::new(fake));
    child.wait_async().await.unwrap();
    let pauses: Vec<_> = crate::wait::block_probe::take()
        .into_iter()
        .map(|pause| pause.expect("a pause is bounded"))
        .collect();
    assert_eq!(crate::os_process::drive::drive_tests::whole_ms(&pauses), [1, 2]);
}

/// The wait on a real child's exit, through the `Wait` path: the first poll finds it running.
///
/// Mutant: the status is not read from the reap.
#[skuld::test]
async fn wait_async_waits_for_a_real_exit() {
    let (mut child, stdin) = exits_three_on_eof();
    let outcome = {
        let mut wait = pin!(child.wait_async());
        assert!(poll_once(wait.as_mut()).is_pending(), "a running child is waited for");
        drop(stdin);
        wait.await
    };
    assert_eq!(status(outcome).code(), Some(3));
    assert!(child.is_reaped());
}

/// A wait dropped while it waits leaves the state `N` and holds nothing: a sync `wait` reaps the
/// child, and on Windows the watcher thread is released while the child still runs.
///
/// Mutant: the record is written before the reap.
#[skuld::test]
async fn a_dropped_wait_async_leaves_nobody_waiting() {
    #[cfg(windows)]
    let (tx, released) = std::sync::mpsc::channel();
    #[cfg(windows)]
    let observer = crate::tokio::wait::fault_observer::install(tx);
    let (mut child, stdin) = exits_three_on_eof();
    {
        let mut wait = pin!(child.wait_async());
        assert!(poll_once(wait.as_mut()).is_pending(), "a running child is waited for");
    }
    #[cfg(windows)]
    {
        drop(observer);
        released
            .recv()
            .expect("the watcher must return once the drop released it");
    }
    assert!(!child.is_reaped());
    drop(stdin);
    assert_eq!(status(child.wait(None)).code(), Some(3));
}

/// The future is `Send`, so `tokio::spawn` accepts it.
#[skuld::test]
fn wait_async_is_send() {
    fn assert_send<T: Send>(_: &T) {}

    let mut child = OwnedChild::new(Box::new(FakeProcess::new([])));
    assert_send(&child.wait_async());
}
