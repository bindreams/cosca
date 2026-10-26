//! macOS: a failed async spawn's teardown warns once, naming the child, when its wait for the child
//! it killed passes its threshold, and keeps waiting until the child is reaped (principle 2). A test
//! here can have no foreign tracer, so the threshold is zero and the first two looks at the child
//! are forced to find it running.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::error::ChildFate;
use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peeks};
use crate::wait::exit_only::Peek;

/// Spawns a blocker whose spawn `force` makes fail, with its next two looks forced from `point` on,
/// and answers the child's fate and the "still waiting" warns naming it.
fn teardown_with_forced_looks(point: SpawnPoint, force: fn(bool)) -> (ChildFate, Vec<String>) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let forced = Rc::new(RefCell::new(None));
    let pid = Rc::new(Cell::new(None));
    let _hook = fault::set_at(point, {
        let (forced, pid) = (Rc::clone(&forced), Rc::clone(&pid));
        move || {
            pid.set(Some(fault::spawn_pid()));
            *forced.borrow_mut() = Some(force_peeks([Ok(Peek::Running), Ok(Peek::Running)]));
        }
    });
    let _warn = crate::tokio::child::fault::warn_slow_teardowns_after(std::time::Duration::ZERO);
    force(true);
    let spawned = cmd.spawn();
    force(false);
    let failed = spawned.expect_err("the forced failure fails the spawn");
    assert_peeks_exhausted();
    let (_, fate) = crate::child::spawn::failure::expect_may_have_started_with(failed);
    let pid = pid.get().expect("the hook ran");
    let warns = crate::log_capture::records_since(mark, &format!("child {pid}"))
        .into_iter()
        .filter(|text| text.contains("still waiting"))
        .collect();
    (fate, warns)
}

/// The teardown after a failed attach (`kill_and_reap_verified`).
///
/// Mutant: the attach arm gives `kill_and_reap_verified` no threshold.
#[skuld::test]
async fn macos_a_teardown_after_a_failed_attach_warns_once_past_its_threshold() {
    let (fate, warns) = teardown_with_forced_looks(SpawnPoint::BeforeAttach, fault::set_force_attach_failure);
    assert_eq!(warns.len(), 1, "one warn, and the wait goes on: {warns:?}");
    assert_eq!(fate, ChildFate::Reaped, "the wait goes on past the threshold");
}

/// The teardown after an identity read that found the child gone (`ProcSource::reap_now`).
///
/// Mutant: `reap_now` waits with no warn.
#[skuld::test]
async fn macos_a_teardown_after_a_vanished_identity_warns_once_past_its_threshold() {
    let (fate, warns) = teardown_with_forced_looks(SpawnPoint::BeforeIdentity, fault::set_force_identity_vanished);
    assert_eq!(warns.len(), 1, "one warn, and the wait goes on: {warns:?}");
    assert_eq!(fate, ChildFate::Reaped, "the wait goes on past the threshold");
}
