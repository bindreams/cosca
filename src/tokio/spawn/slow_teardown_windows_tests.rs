//! Windows: a failed async spawn's teardown warns once when its wait for the process it terminated
//! passes its threshold, and keeps waiting until the process is gone (principle 2). No test can make
//! `TerminateProcess` slow, so each row makes the wait real another way: the kill is refused as an
//! exit under way and the threshold is zero, so the child is running at the first look; stdin closes
//! once the wait blocks. They check that the kill reached `TerminateProcess` to be refused.
//!
//! Both Windows spawns (std and raw) tear down through `OwnedChild::tear_down`, told the async policy
//! at the spawn's entry; a row for each failure arm pins that the arm passes the policy through.

use crate::child::spawn::fault;
use crate::error::ChildFate;
use crate::log_capture::warns_since;
use crate::test_child::Console;

/// Which backend a spawn takes: `CreateProcessW` through std, or the raw one (an explicit
/// `executable`).
#[derive(Clone, Copy)]
enum Backend {
    Std,
    Raw,
}

/// Fails a spawn of a blocker through `backend` with `force` (a fault seam that fails the attach or
/// the identity read), with a zero threshold and the kill refused as an exit under way, so the child
/// is still running when the teardown first looks and nothing but its stdin closing ends it: closed
/// once the wait blocks, which is after the warn. Answers the teardown's fate and warns.
fn teardown_with_an_exit_under_way(backend: Backend, force: fn(bool)) -> (ChildFate, Vec<String>) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    if matches!(backend, Backend::Raw) {
        cmd.executable(crate::test_child::BLOCKER_ARGV[0]);
    }
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin pipe");
    cmd.stdout(crate::stdio::Stdio::null()).expect("set stdout");
    let _warn = crate::tokio::child::fault::warn_slow_teardowns_after(std::time::Duration::ZERO);
    let _end = crate::wait::block_probe::on_blocking(move || drop(writer));
    let refusal = crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    force(true);
    let spawned = cmd.spawn();
    force(false);
    let (_, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        spawned.expect_err("the forced failure fails the spawn"),
    );
    // The refusal stands in for the kill's `TerminateProcess`, so the teardown did send its kill.
    refusal.assert_fired();
    (fate, warns_since(mark, "still waiting"))
}

fn assert_warns_once_and_waits_on((fate, warns): (ChildFate, Vec<String>)) {
    assert_eq!(warns.len(), 1, "one warn, and the wait goes on: {warns:?}");
    assert_eq!(fate, ChildFate::Reaped, "the wait goes on past the threshold");
}

/// Mutants: the std spawn's attach-failure teardown waits with no warn; the async spawn hands it no
/// threshold.
#[skuld::test]
async fn a_std_teardown_after_a_failed_attach_warns_once_past_its_threshold() {
    assert_warns_once_and_waits_on(teardown_with_an_exit_under_way(
        Backend::Std,
        fault::set_force_attach_failure,
    ));
}

/// The identity read fails, so no identity is known.
///
/// Mutant: the async std spawn hands the identity-failure teardown no threshold.
#[skuld::test]
async fn a_std_teardown_after_a_failed_identity_read_warns_once_past_its_threshold() {
    assert_warns_once_and_waits_on(teardown_with_an_exit_under_way(
        Backend::Std,
        fault::set_force_identity_vanished,
    ));
}

/// Mutants: the raw teardown waits with no warn; the async raw spawn hands it no threshold.
#[skuld::test]
async fn a_raw_teardown_after_a_failed_attach_warns_once_past_its_threshold() {
    assert_warns_once_and_waits_on(teardown_with_an_exit_under_way(
        Backend::Raw,
        fault::set_force_attach_failure,
    ));
}

/// Mutant: the async raw spawn hands the identity-failure teardown no threshold.
#[skuld::test]
async fn a_raw_teardown_after_a_failed_identity_read_warns_once_past_its_threshold() {
    assert_warns_once_and_waits_on(teardown_with_an_exit_under_way(
        Backend::Raw,
        fault::set_force_identity_vanished,
    ));
}
