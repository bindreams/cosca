//! [`PidfdShutdown`]'s outcomes: the `SIGTERM` through the root's pidfd, the grace, and the kill, for
//! a root whose number may name another process but whose pidfd names it exactly (Linux).

use std::cell::RefCell;

use super::PidfdShutdown;
use crate::child::owned::OwnedChild;
use crate::containment::dispatch::TreeSignal;
use crate::containment::{Refusal, Skip, SkipCall, Why};
use crate::elevation::front::{Front, TrackedKind};
use crate::error::{ElevationErrorKind, Error};
use crate::log_capture::warns_since;
use crate::os_process::child::PeekOutcome;
use crate::os_process::fake::FakeProcess;
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
        why: Why::MayNameAnother(
            Refusal::Unsure(PGID as u32, std::sync::Arc::new(std::io::Error::other("forced"))),
            None,
        ),
        root_alone: true,
        holders: None,
    }
}

/// The `Unassessable` the call ends in names the skip: what it left undone and why.
fn assert_names_the_skip(err: &Error) {
    let Error::Unassessable { detail, .. } = err else {
        panic!("{err:?}")
    };
    let said = format!(
        "graceful_shutdown_tree(): the root's own handle could not say whether it (pid {PGID}) was reaped, \
         so its number may name another process; it did not signal its process group (pgid {PGID}), and "
    );
    assert!(detail.starts_with(&said), "{detail}");
    assert!(!detail.contains("forced"), "{detail}");
    assert!(crate::error::said(err).contains("forced"), "{err:?}");
}

/// A box over a fake that reads running at every read, tracked as `kind`. Its end consumes nothing.
fn running_as(kind: TrackedKind) -> OwnedChild {
    OwnedChild::new(
        Box::new(
            FakeProcess::new([])
                .peeks_always(|| Ok(PeekOutcome::Running))
                .with_exact_consume(false),
        ),
        kind,
    )
}

/// What the box of a [`run`] is: the rule's answer to a `SIGTERM` or a kill follows from it.
#[derive(Clone, Copy)]
enum LiveBox {
    /// Not a front: its `SIGTERM` and its kill go as `run`'s rows say.
    Own,
    /// A live osascript front: the rule refuses its `SIGTERM`, and nothing is sent.
    Osascript,
    /// A live sudo front in no cgroup: the rule lets its `SIGTERM` through and refuses the escalation's
    /// kill, which goes through the box's [`kill_root_only`](OwnedChild::kill_root_only).
    SudoOutsideACgroup,
}

/// One run over the box `kind`: `term` answers the `SIGTERM` (unless the rule refuses it), `exited` the
/// grace (`None`: the grace is not asked), `kill` the escalation (unless the rule refuses it). Returns
/// the error, what was sent, and the warns.
fn run(
    kind: LiveBox,
    term: Result<Sent, Error>,
    exited: Option<Result<bool, std::io::Error>>,
    kill: Result<Sent, Error>,
) -> (Error, Vec<&'static str>, Vec<String>) {
    crate::log_capture::install();
    let call = graceful_call();
    let sent = RefCell::new(Vec::new());
    let mark = crate::log_capture::mark();
    let child = running_as(match kind {
        LiveBox::Own => TrackedKind::Own,
        LiveBox::Osascript => TrackedKind::Front(Front::Osascript),
        LiveBox::SudoOutsideACgroup => TrackedKind::Front(Front::Sudo),
    });
    let shutdown = match PidfdShutdown::start(&child, || {
        sent.borrow_mut().push("term");
        term
    }) {
        Ok(shutdown) => shutdown,
        Err(e) => return (e, sent.into_inner(), warns_since(mark, "")),
    };
    // A grace the row does not answer reads as an exit, so a wrongly waited one shows in `sent`.
    let waited = shutdown.needs_grace().then(|| {
        sent.borrow_mut().push("grace");
        exited.unwrap_or(Ok(true)).map_err(Error::Io)
    });
    let err = shutdown.finish(&call, &skip(), waited, || match kind {
        LiveBox::SudoOutsideACgroup => child.kill_root_only(None),
        LiveBox::Own | LiveBox::Osascript => {
            sent.borrow_mut().push("kill");
            kill
        }
    });
    (err, sent.into_inner(), warns_since(mark, ""))
}

#[skuld::test]
fn a_front_the_sigterm_may_not_reach_is_refused_with_nothing_sent() {
    let (err, sent, warns) = run(
        LiveBox::Osascript,
        Ok(Sent::Delivered),
        Some(Ok(true)),
        Ok(Sent::Delivered),
    );
    assert!(
        matches!(&err, Error::Elevation { kind: ElevationErrorKind::Unkillable, detail, .. }
            if detail.contains("is osascript") && detail.contains("no SIGTERM was sent")),
        "{err:?}"
    );
    assert_eq!(sent, Vec::<&str>::new());
    assert_eq!(warns, Vec::<String>::new());
}

/// A failed grace wait kills the root at once, and its failure is in the answer: below the call's
/// `Unassessable`, after the refusal's cause.
///
/// Mutant: the failure is logged and dropped.
#[skuld::test]
fn a_failed_grace_wait_kills_the_root_at_once_and_is_in_the_answer() {
    let (err, sent, warns) = run(
        LiveBox::Own,
        Ok(Sent::Delivered),
        Some(Err(std::io::Error::other("forced wait failure"))),
        Ok(Sent::Delivered),
    );
    assert_names_the_skip(&err);
    assert_eq!(sent, ["term", "grace", "kill"]);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
    let below = err.failures_below();
    assert!(
        matches!(&below[..], [cause, watch]
            if crate::error::said(*cause).contains("forced")
                && crate::error::said(*watch) == crate::error::io_said("forced wait failure")),
        "{below:?}"
    );
}

/// With the grace wait failed and the kill failed too, both are in the answer after the refusal's
/// cause: the kill's, which is the call's failure, then the wait's, as at every graceful site.
///
/// Mutant: the watch failure is dropped when the kill fails.
#[skuld::test]
fn a_failed_grace_wait_and_a_failed_kill_are_both_in_the_answer_in_order() {
    let (err, sent, _) = run(
        LiveBox::Own,
        Ok(Sent::Delivered),
        Some(Err(std::io::Error::other("forced wait failure"))),
        Err(Error::Io(std::io::Error::other("forced kill failure"))),
    );
    assert_eq!(sent, ["term", "grace", "kill"]);
    assert!(
        matches!(&err, Error::Unassessable { detail, .. }
            if detail.contains("then the kill of the root through its pidfd failed")
                && !detail.contains("forced kill failure")),
        "the failure is below the answer, not in its words: {err:?}"
    );
    let below: Vec<_> = err
        .failures_below()
        .into_iter()
        .map(|failure| crate::error::said(failure))
        .collect();
    assert_eq!(below.len(), 3, "{below:?}");
    assert!(below[0].contains("forced"), "{below:?}");
    assert_eq!(below[1], crate::error::io_said("forced kill failure"), "{below:?}");
    assert_eq!(below[2], crate::error::io_said("forced wait failure"), "{below:?}");
}

/// The escalation's kill of a live front outside a cgroup goes through the box's rule, which refuses
/// it and sends nothing.
///
/// Mutant: the escalation's kill bypasses the rule and sends the front its kill.
#[skuld::test]
fn a_front_the_kill_may_not_reach_is_refused_after_the_grace() {
    let (err, sent, warns) = run(
        LiveBox::SudoOutsideACgroup,
        Ok(Sent::Delivered),
        Some(Ok(false)),
        Ok(Sent::Delivered),
    );
    assert!(
        matches!(&err, Error::Elevation { kind: ElevationErrorKind::Unkillable, detail, .. }
            if detail.contains("sudo")
                && detail.contains("no kill was sent.")
                && detail.contains("Only a cgroup (Linux containment) that holds it reaches the program.")),
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
    let (err, sent, warns) = run(LiveBox::Own, Err(forced()), None, Ok(Sent::Delivered));
    // An `Io` is a leaf with no slot for peers: the call's `Unassessable` holds it, after the refusal's cause.
    assert!(
        matches!(&err, Error::Unassessable { detail, .. }
            if detail.contains("the SIGTERM to the root through its pidfd failed")
                && !detail.contains("forced term failure")),
        "the failure is below the answer, not in its words: {err:?}"
    );
    assert!(
        matches!(err.failures_below().get(1), Some(Error::Io(e)) if e.to_string() == "forced term failure"),
        "{err:?}"
    );
    assert_eq!(sent, ["term"]);
    assert_eq!(warns.len(), 1, "{warns:?}");
    let said = format!(
        "sent nothing: the SIGTERM to the root through its pidfd failed ({})",
        crate::error::said(&forced())
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
        let (err, sent, warns) = run(LiveBox::Own, Ok(term), None, Ok(Sent::Delivered));
        assert_names_the_skip(&err);
        assert_eq!(sent, ["term"], "{says}");
        assert_eq!(warns.len(), 1, "{says}: {warns:?}");
        assert!(warns[0].contains(says), "{warns:?}");
        assert!(!warns[0].contains(ROOT_TERMED_BY_PIDFD), "{warns:?}");
    }
}

#[skuld::test]
fn a_kill_that_finds_the_root_gone_says_so() {
    let (err, sent, warns) = run(LiveBox::Own, Ok(Sent::Delivered), Some(Ok(false)), Ok(Sent::Gone));
    assert_names_the_skip(&err);
    assert_eq!(sent, ["term", "grace", "kill"]);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("its pidfd showed it gone after the grace"),
        "{warns:?}"
    );
    assert!(!warns[0].contains(ROOT_KILLED_BY_PIDFD), "{warns:?}");
}
