//! `StopTarget` (see `crate::stop::target`).

use std::time::Duration;

use super::{StopTarget, TreeCall};
use crate::os_process::fake::FakeProcess;
use crate::test_child::over_fake::child_over;

/// A target names its child, and says whether it stands for the tree.
#[skuld::test]
fn a_root_target_stands_for_the_root_and_a_tree_target_for_the_tree() {
    let child = child_over(&FakeProcess::new([]));
    let root = StopTarget::from(&child);
    let tree = StopTarget::tree(&child, TreeCall::SignalOnly);
    for target in [&root, &tree] {
        assert_eq!(target.pid(), child.pid());
        assert_eq!(target.id(), child.id());
    }
    assert!(!root.covers_tree());
    assert!(tree.covers_tree());
}

/// A refused send is the last send's record, over an earlier one that went out, for either kind of
/// target: the call goes on from what the last send did, as the action's own answer is not what decides.
///
/// Mutants: a refusal is left unrecorded; it is recorded for one kind of target only.
#[skuld::test]
fn a_refused_send_replaces_the_record_of_an_earlier_one() {
    use super::{RootRecord, TreeRecord};

    let refusal = || crate::error::Error::Unsupported {
        op: "the test".into(),
        platform: "test",
        detail: "refused by the test".into(),
        source: None,
    };
    let child = child_over(&FakeProcess::new([]));

    let root = StopTarget::from(&child);
    root.note_root_sent("SIGTEST");
    assert!(matches!(
        &*root.root_record.lock().unwrap(),
        Some(RootRecord::Sent("SIGTEST"))
    ));
    root.note_not_sent(&refusal());
    assert!(
        matches!(root.into_root_record(), Some(RootRecord::NotSent(Some(report))) if report.contains("refused by the test"))
    );

    // A call that ends at its send reads only how it went and keeps no report; a call that goes on from
    // the send keeps the one it logs.
    let tree = StopTarget::tree(&child, TreeCall::SignalOnly);
    tree.note_tree(TreeRecord::bare(crate::stop::SendOutcome::Sent));
    tree.note_not_sent(&refusal());
    assert!(matches!(
        tree.into_tree_record(),
        Some(TreeRecord::Sent {
            outcome: crate::stop::SendOutcome::NotSent,
            ..
        })
    ));
    let token = crate::containment::treewalk::WalkToken::new();
    let shutdown = StopTarget::tree(&child, TreeCall::Shutdown(&token));
    shutdown.note_not_sent(&refusal());
    assert!(
        matches!(shutdown.into_tree_record(), Some(TreeRecord::NotSent(report)) if report.contains("refused by the test"))
    );
}

/// A root record names a stop only for a send that may have gone out: `Sent` and `Unknown` name it; a send
/// that found the root gone and one that was refused name none, and no record says "sent" for a send that
/// went out to nobody.
///
/// Mutants: a root that was gone is recorded as a send of the stop; an unknown send reads as `Sent`.
#[skuld::test]
fn a_root_record_names_a_stop_only_for_a_send_that_may_have_gone_out() {
    use super::RootRecord;
    use crate::stop::SendOutcome::{NotSent, Sent, Unknown};

    let child = child_over(&FakeProcess::new([]));
    let refusal = crate::error::Error::Unsupported {
        op: "the test".into(),
        platform: "test",
        detail: "refused by the test".into(),
        source: None,
    };
    type Note = fn(&StopTarget<'_>, &crate::error::Error);
    let rows: [(&str, Note, crate::stop::SendOutcome, Option<&str>); 4] = [
        ("sent", |t, _| t.note_root_sent("SIGTEST"), Sent, Some("SIGTEST")),
        (
            "unknown",
            |t, _| t.note_root_unknown("SIGTEST"),
            Unknown,
            Some("SIGTEST"),
        ),
        ("refused", |t, e| t.note_not_sent(e), NotSent, None),
        ("gone", |t, _| t.note_root_gone(), NotSent, None),
    ];
    for (what, note, outcome, names) in rows {
        let target = StopTarget::from(&child);
        note(&target, &refusal);
        let record = target.into_root_record().expect("the send left a record");
        assert_eq!(record.outcome(), outcome, "{what}");
        let named = match &record {
            RootRecord::Sent(name) | RootRecord::Unknown(name) => Some(*name),
            RootRecord::NotSent(_) => None,
        };
        assert_eq!(named, names, "{what}");
    }
}

/// What the route of a tree send answered, as the outcome the target records for the call to read back: a send
/// that went out is `Sent` whatever a check after it found (`Err` included), one that sent nothing is
/// `NotSent` (an exited root too, though `graceful_shutdown_tree` goes on past it), and one that may have gone
/// out is `Unknown`; for `terminate_tree`'s answer and for `graceful_shutdown_tree`'s alike. A send that went
/// to no process is `NotSent` whatever its check found, and the shutdown that goes on after it names no
/// earlier send. The table states the route's answers; the routes' own tests say when each is given.
///
/// Mutants: a check's error reads the send as not made; an unknown answer reads as `Sent`; an exited root reads
/// as `Sent` in the shutdown's record (it goes on, which is not a send); a send that went to no process reads
/// as `Sent` or names an earlier send; either call records nothing.
#[skuld::test]
fn a_tree_routes_answer_is_recorded_as_how_the_send_went() {
    use super::TreeRecord;
    use crate::containment::TerminateOutcome;
    use crate::error::Error;
    use crate::stop::SendOutcome::{self, NotSent, Sent, Unknown};

    let error = |detail: &str| Error::Unassessable {
        detail: detail.to_owned(),
        source: None,
    };
    type Route = fn(Error) -> TerminateOutcome;
    // The route's answer, the outcome, and whether the shutdown's call goes on past it (`Ok`).
    let rows: [(&str, Route, SendOutcome, bool); 7] = [
        (
            "sent, the check found nothing",
            |_| TerminateOutcome::Sent {
                result: Ok(()),
                earlier: None,
            },
            Sent,
            true,
        ),
        (
            "sent, the check failed",
            |e| TerminateOutcome::Sent {
                result: Err(e),
                earlier: None,
            },
            Sent,
            false,
        ),
        (
            "sent to nobody, the check found nothing",
            |_| TerminateOutcome::NoneReached { result: Ok(()) },
            NotSent,
            true,
        ),
        (
            "sent to nobody, the check failed",
            |e| TerminateOutcome::NoneReached { result: Err(e) },
            NotSent,
            false,
        ),
        ("not sent", TerminateOutcome::NotSent, NotSent, false),
        ("root exited", TerminateOutcome::RootExited, NotSent, true),
        (
            "unknown",
            |e| TerminateOutcome::Unknown {
                error: e,
                earlier: None,
            },
            Unknown,
            false,
        ),
    ];
    let child = child_over(&FakeProcess::new([]));
    for (what, route, outcome, shutdown_goes_on) in rows {
        let target = StopTarget::tree(&child, TreeCall::SignalOnly);
        let answer = target.signal_only_answer(
            route(error(what)),
            #[cfg(unix)]
            crate::signal::Sig::Graceful(crate::signal::Signal::Term),
        );
        assert_eq!(
            answer.is_ok(),
            what.ends_with("the check found nothing"),
            "terminate_tree, {what}"
        );
        assert_eq!(
            target.into_tree_record().map(|r| r.outcome()),
            Some(outcome),
            "terminate_tree, {what}"
        );

        let token = crate::containment::treewalk::WalkToken::new();
        let target = StopTarget::tree(&child, TreeCall::Shutdown(&token));
        let answer = target.shutdown_answer(
            route(error(what)),
            None,
            "SIGTEST",
            #[cfg(unix)]
            crate::signal::Sig::Graceful(crate::signal::Signal::Term),
        );
        assert_eq!(answer.is_ok(), shutdown_goes_on, "graceful_shutdown_tree, {what}");
        let record = target.into_tree_record();
        assert_eq!(
            record.as_ref().map(|r| r.outcome()),
            Some(outcome),
            "graceful_shutdown_tree, {what}"
        );
        if what.starts_with("sent to nobody") {
            assert!(
                matches!(record, Some(TreeRecord::Sent { earlier: None, .. })),
                "graceful_shutdown_tree, {what}: no earlier send is named"
            );
        }
    }
}

/// A signal through a root's handle is `Sent` only when it was delivered: a root that was gone, one the handle
/// could not vouch for, and a refusal are not.
///
/// Mutant: any `Ok` answer of the handle reads as `Sent`.
#[skuld::test]
fn a_signal_through_a_handle_is_sent_only_when_delivered() {
    use super::signal_outcome;
    use crate::signal::Sent;
    use crate::stop::SendOutcome;

    assert_eq!(signal_outcome(&Ok(Sent::Delivered)), SendOutcome::Sent);
    assert_eq!(signal_outcome(&Ok(Sent::Gone)), SendOutcome::NotSent);
    assert_eq!(signal_outcome(&Ok(Sent::Unverified)), SendOutcome::NotSent);
    assert_eq!(
        signal_outcome(&Err(crate::error::Error::Io(std::io::Error::other("refused")))),
        SendOutcome::NotSent
    );
}

/// A signal the root's handle answers `Gone` or `Unverified` to is not sent, and the lone shutdown that goes
/// on after it names no earlier send, where one the handle delivered names the stop: `terminate` answers its
/// outcome from the record, and the kill after the grace words what was sent before it from it.
///
/// Mutants: a signal that was not delivered is recorded as a send of the `SIGTERM` (the kill's words name
/// it); a delivered one names none.
#[cfg(unix)]
#[skuld::test]
fn a_signal_the_root_was_gone_for_is_recorded_as_not_sent_and_names_no_stop() {
    use crate::child::graceful::shutdown::{run_ready, stop_root, BlockingDriver};
    use crate::signal::Sent;
    use crate::stop::SendOutcome;

    let child_answering = |answer: Sent| {
        let fake = FakeProcess::new([]).signals([Ok(answer)]);
        #[cfg(target_os = "macos")]
        let fake = fake.peeks_always(|| Ok(crate::os_process::child::PeekOutcome::Running));
        child_over(&fake)
    };
    let rows = [
        (Sent::Delivered, SendOutcome::Sent, Some("the SIGTERM")),
        (Sent::Gone, SendOutcome::NotSent, None),
        (Sent::Unverified, SendOutcome::NotSent, None),
    ];
    for (answer, outcome, said) in rows {
        let child = child_answering(answer);
        let target = StopTarget::from(&child);
        crate::stop::send_signal(&target, crate::Signal::Term).expect("the handle answered");
        assert_eq!(
            target.into_root_record().map(|r| r.outcome()),
            Some(outcome),
            "{answer:?}"
        );

        let child = child_answering(answer);
        let (acted, earlier) = run_ready(stop_root(&BlockingDriver(&child)));
        acted.expect("the handle answered");
        assert_eq!(earlier.as_deref(), said, "{answer:?}");
    }
}

/// `wait_exit` waits for the root through the child's handle, for a root target and a tree target alike,
/// and reaps nothing: the child's own wait still gets its status.
///
/// Mutants: it answers `true` whatever the root did; it reaps the root.
#[skuld::test]
fn wait_exit_waits_for_the_root_and_reaps_nothing_for_both_kinds_of_target() {
    let (child, stdin) = crate::test_child::held_uncontained_blocker(true);
    let root = StopTarget::from(&child);
    let tree = StopTarget::tree(&child, TreeCall::SignalOnly);
    // One look: the root runs.
    assert!(!root.wait_exit(Duration::ZERO).expect("a look"));
    assert!(!tree.wait_exit(Duration::ZERO).expect("a look"));

    child.kill().expect("kill");
    // The wait ends on the root's exit, which the kill brings.
    assert!(root.wait_exit(Duration::from_secs(3600)).expect("the root exits"));
    assert!(tree.wait_exit(Duration::from_secs(3600)).expect("the root exited"));
    drop(stdin);
    crate::test_child::assert_killed(
        "the blocker",
        child.wait().expect("the status is still there to collect"),
    );
}

/// Windows: the recorded route is the group flag, with none of the flags that put the child on a console
/// of its own, and a console this process had at the spawn.
///
/// Mutant: one of the three conditions is left out.
#[cfg(windows)]
#[skuld::test]
fn leads_group_on_our_console_is_the_recorded_facts() {
    use crate::containment::windows::ConsoleFacts;

    let mut child = child_over(&FakeProcess::new([]));
    for (group, own_console_flags, caller_had_console, leads) in [
        (true, false, true, true),
        (false, false, true, false),
        (true, true, true, false),
        (true, false, false, false),
    ] {
        child.console = ConsoleFacts {
            group,
            own_console_flags,
            caller_had_console,
            elevated: false,
        };
        assert_eq!(
            StopTarget::from(&child).leads_group_on_our_console(),
            leads,
            "{:?}",
            child.console
        );
    }
}
