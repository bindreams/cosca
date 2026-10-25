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

/// `exit_visible_by` waits, so it refuses to run inside an async drop's bounded section, before it
/// looks at the backend.
///
/// Mutant: drop the assert from `exit_visible_by`.
#[cfg(unix)]
#[skuld::test]
#[should_panic(expected = "would block inside an async Drop")]
fn exit_visible_by_refuses_inside_a_section() {
    let proc = super::ProcSource::Foreign {
        stdin: None,
        stdout: None,
        stderr: None,
        fate: super::Forgotten::Unproven,
    };
    let _section = crate::bounded::Section::enter();
    proc.exit_visible_by(1, std::time::Instant::now());
}

/// `ECHILD` from the reap right after a look that showed the child's exit means something else
/// reaped it in between: the awaited reap says so, not that it cannot show the child is ours. The
/// child is killed and reaped behind tokio's back, and the look is made to show the exit.
///
/// Mutant: a failed `try_wait` is `Waited::Unverified` whatever its errno.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn an_echild_after_a_look_that_showed_the_exit_is_a_foreign_reap() {
    use std::os::unix::process::ExitStatusExt as _;

    use crate::wait::exit_only::{seams::force_peeks, Peek, Reaped};

    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    let proc = child.proc_mut();
    assert_eq!(
        proc.signal(crate::signal::Sig::Kill).expect("kill"),
        crate::signal::Sent::Delivered
    );
    let raw = rustix::process::Pid::from_raw(pid as i32).expect("a positive pid");
    rustix::process::waitid(
        rustix::process::WaitId::Pid(raw),
        rustix::process::WaitIdOptions::EXITED,
    )
    .expect("reap behind tokio's back")
    .expect("an exit record");
    let _shows_exit = force_peeks([Ok(Peek::Exit(Reaped::Status(std::process::ExitStatus::from_raw(9))))]);

    let (waited, cause) = proc.wait_and_reap_awaiting().await.expect("the exit can be watched");

    assert_eq!(waited, super::Waited::Foreign, "{cause:?}");
    drop(child);
}
