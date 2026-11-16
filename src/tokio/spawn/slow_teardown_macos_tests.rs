//! macOS: a failed async spawn's teardown warns once, naming the child, when its wait for the child
//! it killed passes its threshold, and keeps waiting until the child is reaped (principle 2). A test
//! here can have no foreign tracer, so the threshold is zero and the first two looks at the child
//! are forced to find it running.

use std::cell::Cell;
use std::sync::Arc;

use crate::test_child::Console;
use std::rc::Rc;

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::error::ChildFate;
use crate::identity::{FakeKernel, HostKernel};

/// Spawns a blocker whose spawn `force` makes fail, with its next two looks stated, from `point` on,
/// as rows of the spawn's kernel that find it running, and answers the child's fate and the "still
/// waiting" warns naming it.
fn teardown_with_forced_looks(point: SpawnPoint, force: fn(bool)) -> (ChildFate, Vec<String>) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let kernel = Arc::new(FakeKernel::over(&HostKernel));
    let pid = Rc::new(Cell::new(None));
    let _hook = fault::set_at(point, {
        let (kernel, pid) = (Arc::clone(&kernel), Rc::clone(&pid));
        move || {
            pid.set(Some(fault::spawn_pid()));
            kernel.state_peek(fault::spawn_pid(), Ok(None));
            kernel.state_peek(fault::spawn_pid(), Ok(None));
        }
    });
    let _warn = crate::tokio::child::fault::warn_slow_teardowns_after(std::time::Duration::ZERO);
    force(true);
    let spawned = crate::child::spawn::spawn_uncommitted(
        cmd.as_sync_mut(),
        crate::tokio::child::async_policy(),
        Arc::clone(&kernel),
    );
    force(false);
    let failed = spawned.expect_err("the forced failure fails the spawn");
    assert!(kernel.all_rows_taken(), "both stated looks were made");
    let (_, fate) = failed.expect_may_have_started_with();
    let pid = pid.get().expect("the hook ran");
    let warns = crate::log_capture::records_since(mark, &format!("child {pid}"))
        .into_iter()
        .filter(|text| text.contains("still waiting"))
        .collect();
    (fate, warns)
}

/// The teardown after a failed attach (`held_teardown::tear_down_held`).
///
/// Mutant: the attach arm gives `tear_down_held` no threshold.
#[skuld::test]
async fn macos_a_teardown_after_a_failed_attach_warns_once_past_its_threshold() {
    let (fate, warns) = teardown_with_forced_looks(SpawnPoint::BeforeAttach, fault::set_force_attach_failure);
    assert_eq!(warns.len(), 1, "one warn, and the wait goes on: {warns:?}");
    assert_eq!(fate, ChildFate::Reaped, "the wait goes on past the threshold");
}
