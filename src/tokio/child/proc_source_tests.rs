use super::after_refused_kill;
use crate::error::ChildFate;
use crate::identity::ProcessId;

/// What a refused teardown kill answers: the pidfd reaper's answer wins over the forgetting's, and
/// either wins over the fallback.
///
/// Mutant: the forgetting wins over the reaper, or an answer is dropped for the fallback.
#[skuld::test]
fn a_refused_kill_answers_with_the_reaper_then_the_forgetting() {
    let id = Some(ProcessId::current());
    assert_eq!(
        after_refused_kill(Some(ChildFate::Reaped), Some(ChildFate::Gone), id),
        ChildFate::Reaped
    );
    assert_eq!(after_refused_kill(None, Some(ChildFate::Gone), id), ChildFate::Gone);
    assert_eq!(after_refused_kill(Some(ChildFate::Killed), None, id), ChildFate::Killed);
}

/// Off Linux a child whose kill was refused and that is not forgotten is released to tokio's orphan
/// queue, still running, with the identity the spawn had read.
///
/// Mutant: the fallback is `Unknown`, or drops the identity.
#[cfg(not(target_os = "linux"))]
#[skuld::test]
fn a_refused_kill_with_no_other_answer_leaves_the_child_running() {
    let id = Some(ProcessId::current());
    assert_eq!(after_refused_kill(None, None, id), ChildFate::Running { id });
    assert_eq!(after_refused_kill(None, None, None), ChildFate::Running { id: None });
}

/// On Linux every child that is not forgotten is handed to the pidfd reaper, so no answer from either
/// is a contract breach, asserted in debug.
///
/// Mutant: the fallback is silent on Linux.
#[cfg(target_os = "linux")]
#[skuld::test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "neither handed to the pidfd reaper nor forgotten")
)]
fn a_refused_kill_with_no_other_answer_asserts_on_linux() {
    let id = Some(ProcessId::current());
    assert_eq!(after_refused_kill(None, None, id), ChildFate::Running { id });
}
