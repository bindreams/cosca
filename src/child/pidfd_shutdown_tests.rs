//! [`PidfdShutdown`]'s outcomes: the `SIGTERM` through the root's pidfd, the grace, and the kill, for
//! a root whose number may name another process but whose pidfd names it exactly (Linux).

use std::cell::RefCell;

use super::PidfdShutdown;
use crate::containment::dispatch::TreeSignal;
use crate::containment::{Refusal, Skip, SkipCall, Why};
use crate::elevation::front::Gate;
use crate::error::Error;
use crate::log_capture::warns_since;
use crate::signal::Sent;
use crate::test_child::reaped_elsewhere::{ROOT_KILLED_BY_PIDFD, ROOT_TERMED_BY_PIDFD};

/// A pgid no test process holds: the decisions only name it in their text.
const PGID: i32 = 999_999;

fn graceful_call() -> SkipCall<'static> {
    SkipCall {
        op: "graceful_shutdown_tree",
        pid: PGID as u32,
        signal: TreeSignal::Term,
        earlier: None,
    }
}

/// What the call skipped: a root its handle could not answer for, which the pidfd still names.
fn skip() -> Skip {
    Skip {
        action: format!("signal its process group (pgid {PGID})"),
        why: Why::MayNameAnother(Refusal::Unsure(PGID as u32, std::io::Error::other("forced"))),
        root_alone: true,
        holders: None,
    }
}

fn unkillable(what: &str) -> Error {
    Error::Elevation {
        kind: crate::error::ElevationErrorKind::Unkillable,
        detail: what.into(),
        source: None,
    }
}

/// One run: `term` answers the `SIGTERM`, `exited` the grace (`None`: the grace is not asked),
/// `kill_gate` and `kill` the escalation. Returns the error, what was sent, and the warns.
fn run(
    gate: Gate,
    term: Result<Sent, Error>,
    exited: Option<Result<bool, std::io::Error>>,
    kill_gate: Gate,
    kill: Result<Sent, Error>,
) -> (Error, Vec<&'static str>, Vec<String>) {
    crate::log_capture::install();
    let call = graceful_call();
    let sent = RefCell::new(Vec::new());
    let mark = crate::log_capture::mark();
    let shutdown = match PidfdShutdown::start(gate, || {
        sent.borrow_mut().push("term");
        term
    }) {
        Ok(shutdown) => shutdown,
        Err(e) => return (e, sent.into_inner(), warns_since(mark, "")),
    };
    // A grace the row does not answer reads as an exit, so a wrongly waited one shows in `sent`.
    let waited = shutdown.needs_grace().then(|| {
        sent.borrow_mut().push("grace");
        exited.unwrap_or(Ok(true))
    });
    let err = shutdown.finish(
        &call,
        &skip(),
        waited,
        || kill_gate,
        || {
            sent.borrow_mut().push("kill");
            kill
        },
    );
    (err, sent.into_inner(), warns_since(mark, ""))
}

#[skuld::test]
fn a_front_the_sigterm_may_not_reach_is_refused_with_nothing_sent() {
    let (err, sent, warns) = run(
        Gate::Closed(unkillable("osascript")),
        Ok(Sent::Delivered),
        Some(Ok(true)),
        Gate::Open,
        Ok(Sent::Delivered),
    );
    assert!(
        matches!(&err, Error::Elevation { detail, .. } if detail == "osascript"),
        "{err:?}"
    );
    assert_eq!(sent, Vec::<&str>::new());
    assert_eq!(warns, Vec::<String>::new());
}

#[skuld::test]
fn a_failed_grace_wait_kills_the_root_at_once() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (err, sent, warns) = run(
        Gate::Open,
        Ok(Sent::Delivered),
        Some(Err(std::io::Error::other("forced wait failure"))),
        Gate::Open,
        Ok(Sent::Delivered),
    );
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(sent, ["term", "grace", "kill"]);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
    let debug = crate::log_capture::records_since_on_current_thread(mark, "grace wait failed");
    assert_eq!(debug.len(), 1, "{debug:?}");
    assert_eq!(debug[0].0, log::Level::Debug, "{debug:?}");
    assert!(debug[0].1.contains("forced wait failure"), "{debug:?}");
}

#[skuld::test]
fn a_front_the_kill_may_not_reach_is_refused_after_the_grace() {
    let (err, sent, warns) = run(
        Gate::Open,
        Ok(Sent::Delivered),
        Some(Ok(false)),
        Gate::Closed(unkillable("sudo")),
        Ok(Sent::Delivered),
    );
    assert!(
        matches!(&err, Error::Elevation { detail, .. } if detail == "sudo"),
        "{err:?}"
    );
    assert_eq!(sent, ["term", "grace"]);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("then the kill of the root through its pidfd failed"),
        "{warns:?}"
    );
}

#[skuld::test]
fn a_failed_sigterm_waits_no_grace_and_is_the_error() {
    let forced = || Error::Io(std::io::Error::other("forced term failure"));
    let (err, sent, warns) = run(Gate::Open, Err(forced()), None, Gate::Open, Ok(Sent::Delivered));
    assert!(
        matches!(&err, Error::Io(e) if e.to_string() == "forced term failure"),
        "{err:?}"
    );
    assert_eq!(sent, ["term"]);
    assert_eq!(warns.len(), 1, "{warns:?}");
    let said = format!(
        "sent nothing: the SIGTERM to the root through its pidfd failed ({})",
        crate::error::Report(&forced())
    );
    assert!(warns[0].contains(&said), "{warns:?}");
}

/// A `SIGTERM` that finds the root gone, or a handle that no longer reaches it (a tokio backend
/// forgotten unproven holds no pidfd), waits no grace and sends no kill.
#[skuld::test]
fn a_sigterm_that_reached_nothing_waits_no_grace() {
    for (term, says) in [
        (Sent::Gone, "sent nothing: the root's pidfd shows it is gone"),
        (Sent::Unverified, "sent nothing: the root's handle no longer reaches it"),
    ] {
        let (err, sent, warns) = run(Gate::Open, Ok(term), None, Gate::Open, Ok(Sent::Delivered));
        assert!(matches!(err, Error::Unassessable { .. }), "{says}: {err:?}");
        assert_eq!(sent, ["term"], "{says}");
        assert_eq!(warns.len(), 1, "{says}: {warns:?}");
        assert!(warns[0].contains(says), "{warns:?}");
        assert!(!warns[0].contains(ROOT_TERMED_BY_PIDFD), "{warns:?}");
    }
}

#[skuld::test]
fn a_kill_that_finds_the_root_gone_says_so() {
    let (err, sent, warns) = run(
        Gate::Open,
        Ok(Sent::Delivered),
        Some(Ok(false)),
        Gate::Open,
        Ok(Sent::Gone),
    );
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(sent, ["term", "grace", "kill"]);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("its pidfd showed it gone after the grace"),
        "{warns:?}"
    );
    assert!(!warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
}
