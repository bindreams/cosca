//! Unit tests for the graceful-mechanism vocabulary and its dispatch.

use std::cell::Cell;

use super::{after_grace, after_tree_grace, GracefulMechanism};
use crate::error::Error;

fn io_error(msg: &str) -> Error {
    Error::Io(std::io::Error::other(msg.to_owned()))
}

/// Runs `policy` with a closure that counts its calls and returns `result`; returns the policy's
/// result and the call count.
fn counted(
    result: Result<(), Error>,
    policy: impl FnOnce(&mut dyn FnMut() -> Result<(), Error>) -> Result<(), Error>,
) -> (Result<(), Error>, u32) {
    let calls = Cell::new(0);
    let mut result = Some(result);
    let out = policy(&mut || {
        calls.set(calls.get() + 1);
        result.take().expect("called at most once")
    });
    (out, calls.get())
}

fn message(r: Result<(), Error>) -> String {
    r.expect_err("an error").to_string()
}

// The four strings are a stable, distinct vocabulary. Exact, not `contains`: a refactor that
// collapsed two variants onto one string would still satisfy a substring check.
#[skuld::test]
fn graceful_mechanism_display_is_stable_and_distinct() {
    let all = [
        (GracefulMechanism::Process, "process"),
        (GracefulMechanism::ConsoleGroup, "own console group"),
        (
            GracefulMechanism::OtherConsoleGroup,
            "own console group in another console",
        ),
        (GracefulMechanism::Unknown, "unknown"),
        (GracefulMechanism::None, "none"),
    ];
    for (mechanism, expected) in all {
        assert_eq!(mechanism.to_string(), expected, "Display for {mechanism:?}");
    }
    for (i, (_, a)) in all.iter().enumerate() {
        for (_, b) in all.iter().skip(i + 1) {
            assert_ne!(a, b, "two variants share a Display string");
        }
    }
}

// `None` is the one mechanism the crate refuses up front, and it refuses with the remedy: a
// wildcard arm that fell through to the console call would return something else entirely.
#[skuld::test]
fn signal_refuses_a_child_with_no_mechanism() {
    let id = crate::identity::ProcessId::current();
    let err = super::signal(GracefulMechanism::None, id).expect_err("no group to address");
    let crate::error::Error::Unsupported { detail, .. } = &err else {
        panic!("expected Unsupported, got {err:?}");
    };
    assert!(detail.contains("contain"), "the refusal must name the remedy: {detail}");
}

// `OtherConsoleGroup` shares `ConsoleGroup`'s arm — the flag word says the child's group lives
// in another console, but a child may re-attach to ours after it starts, so the signal is
// attempted rather than refused. No spawn through the public containment API can carry this
// mechanism (the flag words emitted never produce it), so the dispatcher is the only place the
// routing can be pinned at all. `Ok` is what separates the two worlds: the `Unsupported` arms
// refuse, and `os_process::terminate_by_id` — the only other path out of `signal` — is itself `Unsupported`
// on Windows.
#[cfg(windows)]
#[skuld::test]
fn signal_attempts_a_child_whose_group_may_be_in_another_console() {
    let (child, stdin) = crate::test_child::windows_blocker();
    let other = super::signal(GracefulMechanism::OtherConsoleGroup, child.id());
    let group = super::signal(GracefulMechanism::ConsoleGroup, child.id());
    assert!(
        other.is_ok(),
        "OtherConsoleGroup must be attempted, not refused: {other:?}"
    );
    assert_eq!(
        other.is_ok(),
        group.is_ok(),
        "the two console mechanisms must take one path: {other:?} vs {group:?}"
    );
    // Cleanup, not the subject: the two breaks may already have ended the blocker (a delivered break
    // ends a handler-less child), so the kill's outcome and the exit status prove nothing here.
    // Releasing stdin keeps the wait from blocking if the blocker is still alive.
    _ = child.kill_tree();
    drop(stdin);
    _ = child.wait();
}

// The dispatcher's half of `uac_elevated_attachment_has_no_in_process_route`, which pins only
// the recorded constant. The subject is a live contained child of OUR own, whose group a
// wrongly-routed event really would reach: a dispatcher that fired at it returns `Ok` (or the
// OS's `Io` if the event finds no group), never this typed refusal, so the variant-and-detail
// assertion below is what separates the two worlds — and the misfire lands on a child this test
// already owns rather than a stranger.
#[cfg(windows)]
#[skuld::test]
fn signal_refuses_a_child_cosca_did_not_create() {
    let (child, stdin) = crate::test_child::windows_blocker();
    let mechanism = crate::containment::Attachment::uac_elevated().graceful;
    let err = super::signal(mechanism, child.id()).expect_err("a child cosca did not create must not be signalled");
    let crate::error::Error::Unsupported { detail, .. } = &err else {
        panic!("expected Unsupported, got {err:?}");
    };
    assert!(
        detail.contains("did not create this child"),
        "the refusal must say whose child this is not: {detail}"
    );
    assert!(detail.contains("kill()"), "the refusal must name the remedy: {detail}");
    child.kill_tree().expect("kill_tree");
    // Released after the kill so a no-op kill fails the assertion, not the wait.
    drop(stdin);
    crate::test_child::assert_killed("the blocker", child.wait().expect("reap the blocker"));
}

// after_grace / after_tree_grace =====
// Pure: the policy takes the watch result and one closure, so no process is involved.

#[skuld::test]
fn after_grace_is_done_without_a_kill_when_the_process_exited_in_grace() {
    let (out, kills) = counted(Ok(()), |k| after_grace(Ok(true), k));
    out.expect("exited in grace is done");
    assert_eq!(kills, 0);
}

#[skuld::test]
fn after_grace_kills_when_the_grace_ran_out() {
    let (out, kills) = counted(Ok(()), |k| after_grace(Ok(false), k));
    out.expect("a successful kill is done");
    assert_eq!(kills, 1);
}

#[skuld::test]
fn after_grace_kills_then_reports_the_watch_error() {
    let (out, kills) = counted(Ok(()), |k| after_grace(Err(io_error("watch")), k));
    assert!(message(out).contains("watch"));
    assert_eq!(kills, 1, "an unobservable grace escalates");
}

#[skuld::test]
fn after_grace_kill_error_wins_over_the_watch_error() {
    let (out, kills) = counted(Err(io_error("kill")), |k| after_grace(Err(io_error("watch")), k));
    let msg = message(out);
    assert!(msg.contains("kill") && !msg.contains("watch"), "{msg}");
    assert_eq!(kills, 1);
}

#[skuld::test]
fn after_tree_grace_sweeps_even_when_the_root_exited() {
    let (out, sweeps) = counted(Ok(()), |s| after_tree_grace(Ok(true), s));
    out.expect("a successful sweep is done");
    assert_eq!(sweeps, 1);
}

#[skuld::test]
fn after_tree_grace_sweep_error_wins_over_the_watch_error() {
    let (out, sweeps) = counted(Err(io_error("sweep")), |s| after_tree_grace(Err(io_error("watch")), s));
    let msg = message(out);
    assert!(msg.contains("sweep") && !msg.contains("watch"), "{msg}");
    assert_eq!(sweeps, 1);
}

#[skuld::test]
fn after_tree_grace_reports_the_watch_error_after_the_sweep() {
    let (out, sweeps) = counted(Ok(()), |s| after_tree_grace(Err(io_error("watch")), s));
    assert!(message(out).contains("watch"));
    assert_eq!(sweeps, 1);
}
