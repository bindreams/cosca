//! Unit tests for the graceful-mechanism vocabulary and its dispatch.

use std::cell::Cell;

use super::{after_grace, after_tree_grace, GracefulMechanism};
use crate::error::Error;

/// The call a pure policy row names, as a caller's `graceful_shutdown_tree(pid)` does.
const CALL: &str = "graceful_shutdown_tree(7)";

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

/// The root's closure for a mechanism that must not signal the root.
fn root_is_not_signalled(sig: crate::signal::Sig) -> Result<(), crate::error::Error> {
    panic!("the mechanism signalled the root with {sig:?}")
}

// The Unix `Process` mechanism signals through the caller's own handle, with `SIGTERM`, and by
// nothing else: a dispatcher that opened the child by its number would never call the closure.
// The id names no process, so such a regression finds nothing to signal.
#[cfg(unix)]
#[skuld::test]
fn signal_hands_the_process_mechanism_to_the_roots_closure_as_a_term() {
    let mut sent = Vec::new();
    super::signal(GracefulMechanism::Process, 0x7fff_fffe, |sig| {
        sent.push(sig);
        Ok(())
    })
    .expect("the closure's answer is the call's");
    assert_eq!(sent, [crate::signal::Sig::Term]);
}

// Windows has no per-process graceful signal: the `Process` mechanism is refused, and the root's
// closure is never called.
#[cfg(windows)]
#[skuld::test]
fn signal_refuses_the_process_mechanism_without_signalling_the_root() {
    let err = super::signal(GracefulMechanism::Process, std::process::id(), root_is_not_signalled)
        .expect_err("Windows has no per-process graceful signal");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "{err:?}");
}

// `None` is the one mechanism the crate refuses up front, and it refuses with the remedy: a
// wildcard arm that fell through to the console call would return something else entirely.
#[skuld::test]
fn signal_refuses_a_child_with_no_mechanism() {
    let err = super::signal(GracefulMechanism::None, std::process::id(), root_is_not_signalled)
        .expect_err("no group to address");
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
// refuse, and the `Process` arm — the only other path out of `signal` — is itself `Unsupported` on
// Windows.
#[cfg(windows)]
#[skuld::test]
fn signal_attempts_a_child_whose_group_may_be_in_another_console() {
    let (child, stdin) = crate::test_child::held_contained_blocker_on_console(crate::Stdio::null());
    let other = super::signal(GracefulMechanism::OtherConsoleGroup, child.pid(), root_is_not_signalled);
    let group = super::signal(GracefulMechanism::ConsoleGroup, child.pid(), root_is_not_signalled);
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
    let (child, stdin) = crate::test_child::held_contained_blocker_on_console(crate::Stdio::null());
    let mechanism = crate::containment::Attachment::uac_elevated().graceful;
    let err = super::signal(mechanism, child.pid(), root_is_not_signalled)
        .expect_err("a child cosca did not create must not be signalled");
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
    let (out, kills) = counted(Ok(()), |k| after_grace(CALL, Ok(true), k));
    out.expect("exited in grace is done");
    assert_eq!(kills, 0);
}

#[skuld::test]
fn after_grace_kills_when_the_grace_ran_out() {
    let (out, kills) = counted(Ok(()), |k| after_grace(CALL, Ok(false), k));
    out.expect("a successful kill is done");
    assert_eq!(kills, 1);
}

#[skuld::test]
fn after_grace_kills_then_reports_the_watch_error() {
    let (out, kills) = counted(Ok(()), |k| after_grace(CALL, Err(io_error("watch")), k));
    assert!(message(out).contains("watch"));
    assert_eq!(kills, 1, "an unobservable grace escalates");
}

/// The texts of the failures below a slot variant's cause.
fn failures_below(error: &Error) -> Vec<String> {
    error.failures_below().into_iter().map(ToString::to_string).collect()
}

/// A failure that has a slot, with nothing below it.
fn containment(detail: &str) -> Error {
    Error::Containment {
        detail: detail.to_owned(),
        source: None,
    }
}

// A kill's `Io` is the answer at every count, with its OS code: nothing's meaning covers a refused
// kill but the refusal itself. The grace wait's failure is logged at warn, not carried.
#[skuld::test]
fn after_grace_an_io_kill_error_stays_the_answer_and_the_watch_error_is_a_warn() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (out, kills) = counted(Err(io_error("kill")), |k| after_grace(CALL, Err(io_error("watch")), k));
    assert!(matches!(&out, Err(Error::Io(e)) if e.to_string() == "kill"), "{out:?}");
    assert_eq!(kills, 1);
    let logged = crate::log_capture::records_since_on_current_thread(mark, "watch");
    assert!(
        matches!(&logged[..], [(log::Level::Warn, line)] if line.starts_with(CALL)),
        "the warn names the caller's call: {logged:?}"
    );
}

// With no watch failure the kill's error is returned as it is: a raw `Io` keeps its code.
#[skuld::test]
fn after_grace_a_lone_kill_error_stays_as_it_is() {
    let (out, _) = counted(Err(io_error("kill")), |k| after_grace(CALL, Ok(false), k));
    assert!(matches!(out, Err(Error::Io(_))), "{out:?}");
}

// A kill error that has a slot keeps its variant, with the watch failure as its cause.
#[skuld::test]
fn after_grace_a_kill_error_with_a_slot_keeps_its_variant() {
    let (out, _) = counted(Err(containment("kill")), |k| {
        after_grace(CALL, Err(io_error("watch")), k)
    });
    assert!(
        matches!(&out, Err(Error::Containment { detail, source: Some(cause) })
            if detail == "kill" && cause.to_string() == "watch"),
        "{out:?}"
    );
}

#[skuld::test]
fn after_tree_grace_sweeps_even_when_the_root_exited() {
    let (out, sweeps) = counted(Ok(()), |s| after_tree_grace(CALL, Ok(true), s));
    out.expect("a successful sweep is done");
    assert_eq!(sweeps, 1);
}

#[skuld::test]
fn after_tree_grace_an_io_sweep_error_stays_the_answer_and_the_watch_error_is_a_warn() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (out, sweeps) = counted(Err(io_error("sweep")), |s| {
        after_tree_grace(CALL, Err(io_error("watch")), s)
    });
    assert!(matches!(&out, Err(Error::Io(e)) if e.to_string() == "sweep"), "{out:?}");
    assert_eq!(sweeps, 1);
    let logged = crate::log_capture::records_since_on_current_thread(mark, "watch");
    assert!(matches!(&logged[..], [(log::Level::Warn, _)]), "{logged:?}");
}

// A sweep that left members has a slot for the call's other failures: they are its `others`, in the
// order given, and not members.
#[skuld::test]
fn a_sweep_that_left_members_carries_the_refusal_and_the_watch_error_in_others() {
    let left = || {
        Error::members_left(
            crate::error::Failures::new(
                std::sync::Arc::new(Error::MemberNotKilled {
                    pid: 7,
                    source: std::sync::Arc::new(io_error("member")),
                }),
                [],
            ),
            None,
        )
    };
    let out = super::joined(CALL, left(), [containment("refused"), io_error("watch")]);
    let Error::MembersLeft { members, others } = &out else {
        panic!("the variant is kept: {out:?}");
    };
    assert_eq!(members.iter().len(), 1);
    let Some(Error::Several(others)) = others.as_deref() else {
        panic!("expected a Several in others: {out:?}");
    };
    let texts: Vec<_> = others.iter().map(|e| e.to_string()).collect();
    assert!(
        texts[0].contains("refused") && texts[1] == "watch" && texts.len() == 2,
        "{texts:?}"
    );

    let out = after_tree_grace(CALL, Err(io_error("watch")), || Err(left()));
    assert!(
        matches!(&out, Err(Error::MembersLeft { others: Some(o), .. }) if o.to_string() == "watch"),
        "{out:?}"
    );
}

#[skuld::test]
fn after_tree_grace_a_sweep_error_with_a_slot_keeps_its_variant() {
    let (out, _) = counted(Err(containment("sweep")), |s| {
        after_tree_grace(CALL, Err(io_error("watch")), s)
    });
    assert!(
        matches!(&out, Err(Error::Containment { detail, source: Some(cause) })
            if detail == "sweep" && cause.to_string() == "watch"),
        "{out:?}"
    );
}

// The root's reap is the answer when it fails, with the refusal of the cooperative signal and then
// the watch failure below it; a reap that succeeds leaves the watch failure as the answer (the sweep
// proved the tree clear, which supersedes the refusal), and with neither failing the status comes
// back.
#[skuld::test]
fn after_reap_takes_the_refusal_and_the_watch_error_as_peers_of_a_failed_reap() {
    let status = std::process::ExitStatus::default();
    let out = super::after_reap(
        CALL,
        Err(containment("reap")),
        Some(containment("refused")),
        Some(io_error("watch")),
    );
    let out = out.expect_err("all failed");
    assert!(
        matches!(&out, Error::Containment { detail, .. } if detail == "reap"),
        "{out:?}"
    );
    let below = failures_below(&out);
    assert!(
        below.len() == 2 && below[0].contains("refused") && below[1] == "watch",
        "{below:?}"
    );
    assert_eq!(
        message_of(super::after_reap(
            CALL,
            Ok(status),
            Some(containment("refused")),
            Some(io_error("watch"))
        )),
        "watch"
    );
    assert_eq!(
        message_of(super::after_reap(CALL, Err(io_error("reap")), None, None)),
        "reap"
    );
    assert_eq!(
        super::after_reap(CALL, Ok(status), None, None).expect("neither failed"),
        status
    );
    assert_eq!(
        super::after_reap(CALL, Ok(status), Some(containment("refused")), None).expect("a superseded refusal"),
        status
    );
}

fn message_of(r: Result<std::process::ExitStatus, Error>) -> String {
    r.expect_err("an error").to_string()
}

#[skuld::test]
fn after_tree_grace_reports_the_watch_error_after_the_sweep() {
    let (out, sweeps) = counted(Ok(()), |s| after_tree_grace(CALL, Err(io_error("watch")), s));
    assert!(message(out).contains("watch"));
    assert_eq!(sweeps, 1);
}
