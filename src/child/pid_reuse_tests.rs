//! The sync twins of `tokio::child::pid_reuse_tests`: a sync child reaped behind its back, its pid
//! reused, then killed or dropped. The sync `SharedChild` signals through its held pidfd. They pin
//! that against a rewrite of its signal path.

use crate::test_child::pid_reuse::{in_fresh_pid_ns, reap_behind_and_reuse, sigusr1_and_wait};
use crate::test_groups::namespaces;
use crate::Command;

fn spawn_blocker() -> (crate::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    (cmd.spawn().expect("spawn"), writer)
}

/// Mutant: sync `kill` by `kill(pid)`.
fn kill_after_foreign_reap_and_reuse_body() {
    let (child, writer) = spawn_blocker();
    drop(writer);
    let reuser = reap_behind_and_reuse(child.id().pid());
    child.kill().expect("a kill of a foreign-reaped child answers Ok");
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
in_fresh_pid_ns!(
    namespaces_sync_kill_after_foreign_reap_and_reuse_signals_nothing,
    fixture_sync_kill_reuse_driver,
    fixture_sync_kill_reuse_init,
    kill_after_foreign_reap_and_reuse_body
);

/// Mutant: sync `Drop` kill by `kill(pid)`.
fn drop_kill_after_foreign_reap_and_reuse_body() {
    let (child, writer) = spawn_blocker();
    drop(writer);
    let reuser = reap_behind_and_reuse(child.id().pid());
    drop(child);
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
in_fresh_pid_ns!(
    namespaces_sync_drop_kill_after_foreign_reap_and_reuse_signals_nothing,
    fixture_sync_drop_reuse_driver,
    fixture_sync_drop_reuse_init,
    drop_kill_after_foreign_reap_and_reuse_body
);
