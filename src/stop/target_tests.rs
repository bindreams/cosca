//! `StopTarget` (see `crate::stop::target`).

use std::time::Duration;

use super::{Deadline, StopTarget, TreeCall};
use crate::containment::UnsentKind;
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
    root.note_not_sent(&refusal(), UnsentKind::NotSent);
    assert!(
        matches!(root.into_root_record(), Some(RootRecord::NotSent(Some(report), _)) if report.contains("refused by the test"))
    );

    // A call that ends at its send reads only how it went and keeps no report; a call that goes on from
    // the send keeps the one it logs.
    let tree = StopTarget::tree(&child, TreeCall::SignalOnly);
    tree.note_tree(TreeRecord::bare(crate::stop::SendOutcome::Sent));
    tree.note_not_sent(&refusal(), UnsentKind::NotSent);
    assert!(matches!(
        tree.into_tree_record(),
        Some(TreeRecord::Sent {
            outcome: crate::stop::SendOutcome::NotSent,
            ..
        })
    ));
    let token = crate::containment::treewalk::WalkToken::new();
    let shutdown = StopTarget::tree(&child, TreeCall::Shutdown(&token));
    shutdown.note_not_sent(&refusal(), UnsentKind::NotSent);
    assert!(
        matches!(shutdown.into_tree_record(), Some(TreeRecord::NotSent(report, _)) if report.contains("refused by the test"))
    );
}

/// A root record names a stop only for a send that may have gone out: `Sent` and `Unknown` name it; a send
/// that found the root gone, one that was refused and one that found the child not yet started name none,
/// and no record says "sent" for a send that went out to nobody.
///
/// Mutants: a root that was gone is recorded as a send of the stop; an unknown send reads as `Sent`; a send
/// that found the child not yet started reads as `NotSent`.
#[skuld::test]
fn a_root_record_names_a_stop_only_for_a_send_that_may_have_gone_out() {
    use super::RootRecord;
    use crate::stop::SendOutcome::{NotSent, NotYet, Sent, Unknown};

    let child = child_over(&FakeProcess::new([]));
    let refusal = crate::error::Error::Unsupported {
        op: "the test".into(),
        platform: "test",
        detail: "refused by the test".into(),
        source: None,
    };
    type Note = fn(&StopTarget<'_>, &crate::error::Error);
    let rows: [(&str, Note, crate::stop::SendOutcome, Option<&str>); 5] = [
        ("sent", |t, _| t.note_root_sent("SIGTEST"), Sent, Some("SIGTEST")),
        (
            "unknown",
            |t, _| t.note_root_unknown("SIGTEST"),
            Unknown,
            Some("SIGTEST"),
        ),
        ("refused", |t, e| t.note_not_sent(e, UnsentKind::NotSent), NotSent, None),
        ("not yet", |t, e| t.note_not_sent(e, UnsentKind::NotYet), NotYet, None),
        ("gone", |t, _| t.note_root_gone(), NotSent, None),
    ];
    for (what, note, outcome, names) in rows {
        let target = StopTarget::from(&child);
        note(&target, &refusal);
        let record = target.into_root_record().expect("the send left a record");
        assert_eq!(record.outcome(), outcome, "{what}");
        let named = match &record {
            RootRecord::Sent(name) | RootRecord::Unknown(name) => Some(*name),
            RootRecord::NotSent(..) => None,
        };
        assert_eq!(named, names, "{what}");
    }
}

/// What the route of a tree send answered, as the outcome the target records for the call to read back: a send
/// that went out is `Sent` whatever a check after it found (`Err` included), one that sent nothing is
/// `NotSent` (an exited root too, though `graceful_shutdown_tree` goes on past it), and one that may have gone
/// out is `Unknown`, and one that found the child not yet started `NotYet`; for `terminate_tree`'s answer and
/// for `graceful_shutdown_tree`'s alike. A send that went to no process is `NotSent` whatever its check
/// found, and the shutdown that goes on after it names no earlier send. The table states the answers every platform's routes give; the Unix answers that carry a
/// `Skip` (`End`, `HoldersOnly`, `RootThroughPidfd`) are asserted through the public calls
/// (`foreign_reap_tree_tests`, `fdmarker_tests`, `unpinned_public_tests`).
///
/// Mutants: a check's error reads the send as not made; an unknown answer reads as `Sent`; an exited root
/// reads as `Sent` in the shutdown's record (it goes on, which is not a send); a send that went to no process
/// reads as `Sent` or names an earlier send; a send that went out drops the earlier send it names; either call
/// records nothing; a send that found the child not yet started is recorded as `NotSent`.
#[skuld::test]
fn a_tree_routes_answer_is_recorded_as_how_the_send_went() {
    use super::TreeRecord;
    use crate::containment::TerminateOutcome;
    use crate::error::Error;
    use crate::stop::SendOutcome::{self, NotSent, NotYet, Sent, Unknown};

    let error = |detail: &str| Error::Unassessable {
        detail: detail.to_owned(),
        source: None,
    };
    type Route = fn(Error) -> TerminateOutcome;
    struct Row {
        what: &'static str,
        route: Route,
        outcome: SendOutcome,
        /// `terminate_tree` answers `Ok`.
        terminate_tree_ok: bool,
        /// `graceful_shutdown_tree` goes on past the route's answer (`Ok`).
        shutdown_goes_on: bool,
        /// The shutdown's record names no earlier send.
        names_no_earlier_send: bool,
    }
    let row = |what, route, outcome, terminate_tree_ok, shutdown_goes_on, names_no_earlier_send| Row {
        what,
        route,
        outcome,
        terminate_tree_ok,
        shutdown_goes_on,
        names_no_earlier_send,
    };
    let rows = [
        row(
            "sent, the check found nothing",
            |_| TerminateOutcome::Sent {
                result: Ok(()),
                earlier: Some("an earlier stop".to_owned()),
            },
            Sent,
            true,
            true,
            false,
        ),
        row(
            "sent, the check failed",
            |e| TerminateOutcome::Sent {
                result: Err(e),
                earlier: Some("an earlier stop".to_owned()),
            },
            Sent,
            false,
            false,
            false,
        ),
        row(
            "sent to nobody, the check found nothing",
            |_| TerminateOutcome::NoneReached { result: Ok(()) },
            NotSent,
            true,
            true,
            true,
        ),
        row(
            "sent to nobody, the check failed",
            |e| TerminateOutcome::NoneReached { result: Err(e) },
            NotSent,
            false,
            false,
            true,
        ),
        row(
            "not sent",
            |e| TerminateOutcome::NotSent(e, UnsentKind::NotSent),
            NotSent,
            false,
            false,
            true,
        ),
        row("root exited", TerminateOutcome::RootExited, NotSent, false, true, true),
        row(
            "not yet",
            |e| TerminateOutcome::NotSent(e, UnsentKind::NotYet),
            NotYet,
            false,
            false,
            true,
        ),
        row(
            "unknown",
            |e| TerminateOutcome::Unknown {
                error: e,
                earlier: Some("an earlier stop".to_owned()),
            },
            Unknown,
            false,
            false,
            false,
        ),
    ];
    let child = child_over(&FakeProcess::new([]));
    for Row {
        what,
        route,
        outcome,
        terminate_tree_ok,
        shutdown_goes_on,
        names_no_earlier_send,
    } in rows
    {
        let target = StopTarget::tree(&child, TreeCall::SignalOnly);
        let answer = target.signal_only_answer(
            route(error(what)),
            #[cfg(unix)]
            crate::signal::Sig::Graceful(crate::signal::Signal::Term),
        );
        assert_eq!(answer.is_ok(), terminate_tree_ok, "terminate_tree, {what}");
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
        assert_eq!(
            matches!(record, Some(TreeRecord::Sent { earlier: Some(_), .. })),
            !names_no_earlier_send,
            "graceful_shutdown_tree, {what}: whether an earlier send is named"
        );
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

/// A signal the handle answers `Gone` or `Exited` to is not sent: `terminate` reports `NotSent` and the kill
/// after the grace names no earlier send. A delivered signal names the stop.
///
/// Mutants: a signal that was not delivered is recorded as a send of the `SIGTERM` (the kill's words name
/// it), an `Exited` one above all; a delivered one names none.
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
        (Sent::Exited, SendOutcome::NotSent, None),
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
        let (_, earlier) = run_ready(stop_root(&BlockingDriver(&child), None)).expect("the handle answered");
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

/// The wait of `wait_exit` ends by the shorter of the grace and what is left before the target's deadline,
/// and its answer says which: for a root still running, `Err(TimedOut)` naming the root when the deadline was
/// the bound (a deadline already past is one look), `Ok(false)` when the grace
/// was; an exited root is `Ok(true)` whichever. The root runs until the hook, at a block armed past the
/// bound the row expects, ends it, so a wait that ignored the bound answers `Ok(true)` and fails the
/// assertion on the error (or on the armed values), with no hang.
///
/// Mutants: the deadline is not read (the first rows block unbounded and are released, answering `true`);
/// the deadline replaces the grace instead of cutting it (the grace row arms the deadline); the grace is
/// cut to the deadline when there is none (the last row arms zero); the deadline's end answers `Ok(false)`;
/// the grace's end answers `TimedOut`; a past deadline answers `TimedOut` for a root that has exited. (The
/// tie is pinned on a frozen clock, by `cut_is_the_nearer_of_the_graces_instant_and_the_deadline_and_says_which`.)
#[skuld::test]
fn wait_exit_waits_the_shorter_of_the_grace_and_what_is_left_before_the_deadline() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::error::Error;
    use crate::wait::block_probe::{on_each_block, take};

    let bound = Duration::from_millis(20);
    let far = Duration::from_secs(3600);
    let (child, stdin) = crate::test_child::held_uncontained_blocker(true);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let stdin = Rc::new(RefCell::new(Some(stdin)));
    // A block armed for more than `allowed` (or for ever) is where a wait that ignored the bound is released.
    let allowed = Rc::new(RefCell::new(Duration::ZERO));
    let _release = on_each_block({
        let (stdin, allowed) = (Rc::clone(&stdin), Rc::clone(&allowed));
        move |block| {
            if block.armed.is_none_or(|armed| armed > *allowed.borrow()) {
                drop(stdin.borrow_mut().take());
            }
        }
    });
    let row = |deadline: Option<Duration>, grace: Duration, allowed_to_arm: Duration| {
        *allowed.borrow_mut() = allowed_to_arm;
        take();
        let target = StopTarget::from(&child).with_deadline(deadline.and_then(Deadline::real));
        let answered = target.wait_exit(grace);
        (answered, take())
    };
    let timed_out = |answered: Result<bool, Error>, case: &str| match answered {
        Err(Error::TimedOut {
            detail,
            members,
            source: None,
        }) => {
            assert_eq!(members, [id], "{case}: the root is the member");
            assert!(detail.contains(&format!("pid {}", child.pid())), "{case}: {detail}");
        }
        other => panic!("{case}: the deadline ended the wait with the root running: {other:?}"),
    };

    // Shorter than the grace: armed for the deadline, never past it, and the root did not exit.
    let (answered, armed) = row(Some(bound), Duration::MAX, bound);
    timed_out(answered, "deadline before the grace");
    assert!(
        armed.iter().all(|armed| armed.is_some_and(|armed| armed <= bound)),
        "every block was armed within the deadline: {armed:?}"
    );
    // Already past: one look, which never blocks for longer than none.
    let (answered, armed) = row(Some(Duration::ZERO), Duration::MAX, Duration::ZERO);
    timed_out(answered, "a deadline already past");
    assert!(
        armed.iter().all(|armed| armed.is_some_and(|armed| armed.is_zero())),
        "a past deadline arms no wait: {armed:?}"
    );
    // A tie: no grace, and nothing left. The deadline is the bound.
    let (answered, armed) = row(Some(Duration::ZERO), Duration::ZERO, Duration::ZERO);
    timed_out(answered, "a tie goes to the deadline");
    assert!(
        armed.iter().all(|armed| armed.is_some_and(|armed| armed.is_zero())),
        "{armed:?}"
    );
    // The grace is the shorter: it is what the wait is armed for, and its end is `false`.
    let (answered, armed) = row(Some(far), bound, bound);
    assert!(
        matches!(answered, Ok(false)),
        "the grace ran out with the root running: {answered:?}"
    );
    assert!(
        armed.iter().all(|armed| armed.is_some_and(|armed| armed <= bound)),
        "every block was armed within the grace: {armed:?}"
    );
    assert!(stdin.borrow().is_some(), "no block above was past its bound");
    // No deadline: the whole grace. The wait is unbounded, which is where the hook ends the root.
    let (answered, armed) = row(None, Duration::MAX, bound);
    assert!(
        matches!(answered, Ok(true)),
        "with no deadline the wait is for the whole grace, and the root exited: {answered:?}"
    );
    assert!(armed.contains(&None), "the wait was unbounded: {armed:?}");
    assert!(
        stdin.borrow().is_none(),
        "the hook ended the root at the unbounded block"
    );
    // The root has exited: a deadline already past is one look, which sees it.
    let (answered, _) = row(Some(Duration::ZERO), Duration::MAX, Duration::ZERO);
    assert!(
        matches!(answered, Ok(true)),
        "an exited root is `true` at a past deadline: {answered:?}"
    );
    let status = child.wait().expect("the status is still there to collect");
    assert!(status.success(), "the blocker ended at its input's end: {status:?}");
}

/// What a wait that `cut` ended answers for a root that did not exit: `TimedOut` when the deadline ended it,
/// `Ok(false)` when the grace did, and `Ok(true)` for a root that exited, whichever ended the wait.
///
/// Mutants: the two bounds swapped; an exited root is an error at the deadline; the members are dropped.
#[skuld::test]
fn the_answer_to_a_cut_wait_is_by_which_bound_ended_it() {
    use super::Bound;
    use crate::error::Error;

    let child = child_over(&FakeProcess::new([]));
    let target = StopTarget::from(&child);
    for bound in [Bound::Grace, Bound::Deadline] {
        assert!(matches!(target.exit_answer(true, bound), Ok(true)), "{bound:?}");
    }
    assert!(matches!(target.exit_answer(false, Bound::Grace), Ok(false)));
    match target.exit_answer(false, Bound::Deadline) {
        Err(Error::TimedOut { detail, members, .. }) => {
            assert_eq!(members, child.id().into_iter().collect::<Vec<_>>());
            assert!(detail.contains(&format!("pid {}", child.pid())), "{detail}");
        }
        other => panic!("the deadline ended the wait with the root running: {other:?}"),
    }
}

/// `cut` hands the wait the instant it ends by and says which bound that is: no deadline is no cut, a deadline far
/// off leaves the grace, a nearer one is the deadline itself, one already past is itself (and wins a tie with a
/// grace of nothing), and a grace too large for the clock is no bound. Exact, on a frozen clock.
///
/// Mutants: the deadline is not read; the grace's instant is handed over when the deadline is the nearer; a tie
/// is the grace's.
#[skuld::test]
fn cut_is_the_nearer_of_the_graces_instant_and_the_deadline_and_says_which() {
    use super::Bound;
    use crate::wait::test_clock::FrozenClockGuard;

    let (_clock, now) = FrozenClockGuard::install();
    let grace = Duration::from_secs(5);
    let cut = |deadline: Option<Duration>, grace| {
        Deadline::cut(deadline.and_then(Deadline::real), grace).map(|(by, bound)| (by.at, bound))
    };
    assert_eq!(cut(None, grace), None);
    let far = Duration::from_secs(3600);
    assert_eq!(cut(Some(far), grace), Some((now + grace, Bound::Grace)));
    assert_eq!(
        cut(Some(Duration::from_secs(1)), grace),
        Some((now + Duration::from_secs(1), Bound::Deadline))
    );
    assert_eq!(cut(Some(Duration::ZERO), grace), Some((now, Bound::Deadline)));
    assert_eq!(
        cut(Some(Duration::ZERO), Duration::ZERO),
        Some((now, Bound::Deadline)),
        "a tie is the deadline's"
    );
    assert_eq!(
        cut(Some(far), Duration::MAX),
        Some((now + far, Bound::Deadline)),
        "a grace too large for the clock is no bound"
    );
}

/// `wait_exit` arms its wait at the call's deadline, not at a duration read off it earlier: the driver below
/// moves the frozen clock on between the cut and the arm, so a wait armed from a duration computed at the cut is
/// armed for the whole 20 ms, and one armed at the deadline for what is left of it, 15 ms. The root runs until
/// the hook, at a block armed for more than that, ends it, so the wrong arm answers `Ok(true)` and fails the
/// assertion on the armed values.
///
/// Mutant: the wait is handed to the driver as a duration (`root_exited`) computed at the cut.
#[skuld::test]
fn wait_exit_arms_the_wait_at_the_calls_deadline_not_at_a_duration_read_earlier() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::wait_exit_with;
    use crate::child::graceful::shutdown::{run_ready, BlockingDriver};
    use crate::error::Error;
    use crate::stop::StopWaits;
    use crate::wait::block_probe::{on_each_block, take};
    use crate::wait::test_clock::{advance, FrozenClockGuard};

    /// The sync driver, with the clock moved on by `by` as a wait is handed to it.
    struct Late<'a> {
        inner: BlockingDriver<'a>,
        by: Duration,
    }
    impl StopWaits for Late<'_> {
        async fn root_exited(&self, within: Duration) -> Result<bool, Error> {
            advance(self.by);
            self.inner.root_exited(within).await
        }
        async fn root_exited_by(&self, by: Deadline) -> Result<bool, Error> {
            advance(self.by);
            self.inner.root_exited_by(by).await
        }
        #[cfg(windows)]
        type Proxy = ();
        #[cfg(windows)]
        async fn start_proxy(
            &self,
            _: &std::path::Path,
            _: &crate::stop::proxy::protocol::ProxyArgs,
        ) -> Result<(u32, ()), Error> {
            unreachable!("`wait_exit` starts no proxy")
        }
        #[cfg(windows)]
        async fn wait_proxy(
            &self,
            _: &mut (),
            _: Duration,
            _: impl FnOnce(Duration) + Send,
            _: Option<std::time::Instant>,
        ) -> Result<Option<std::process::ExitStatus>, Error> {
            unreachable!("`wait_exit` waits for no proxy")
        }
    }

    let (child, stdin) = crate::test_child::held_uncontained_blocker(true);
    let stdin = Rc::new(RefCell::new(Some(stdin)));
    let _release = on_each_block({
        let stdin = Rc::clone(&stdin);
        move |block| {
            if block.armed.is_none_or(|armed| armed > Duration::from_millis(15)) {
                drop(stdin.borrow_mut().take());
            }
        }
    });
    let (_clock, _) = FrozenClockGuard::install();
    let target = StopTarget::from(&child).with_deadline(Deadline::real(Duration::from_millis(20)));
    let driver = Late {
        inner: BlockingDriver(&child),
        by: Duration::from_millis(5),
    };
    take();
    let answered = run_ready(wait_exit_with(&driver, &target, Duration::MAX));
    let armed = take();
    assert_eq!(
        armed.first(),
        Some(&Some(Duration::from_millis(15))),
        "the first block was armed for what was left of the deadline: {armed:?}"
    );
    assert!(
        matches!(answered, Err(Error::TimedOut { .. })),
        "the deadline ended the wait: {answered:?}"
    );
    drop(stdin.borrow_mut().take());
    let status = child.wait().expect("the status is still there to collect");
    assert!(status.success(), "the blocker ended at its input's end: {status:?}");
}

/// A deadline is read on the clock it was made on, by the target alone, and re-expressed by it for a wait on the
/// other: a tokio-clock deadline on a paused runtime, whose clock is advanced a long way while the real one barely
/// moves, is cut by what is left of the tokio timeline, and is the real clock's instant that same time from now.
///
/// Mutants: the target reads the real clock for a deadline made on tokio's; a deadline is handed to a wait on the
/// real clock as it is.
#[cfg(feature = "tokio")]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn a_tokio_deadline_is_read_on_tokios_clock_and_re_expressed_for_the_real_one() {
    use super::{Bound, ClockKind};

    let child = child_over(&FakeProcess::new([]));
    let target = StopTarget::from(&child).with_deadline(Deadline::tokio(Duration::from_secs(3600)));
    let deadline = target.deadline.expect("the target has a deadline");
    let grace = Duration::from_secs(1000);
    let cut = |target: &StopTarget<'_>| Deadline::cut(target.deadline, grace).map(|(by, bound)| (by.at, bound));
    assert_eq!(cut(&target).map(|(_, bound)| bound), Some(Bound::Grace));
    ::tokio::time::advance(Duration::from_secs(3000)).await;
    assert_eq!(
        cut(&target),
        Some((deadline.at, Bound::Deadline)),
        "the grace is past the deadline on tokio's clock"
    );
    let before = crate::wait::now();
    let real = deadline
        .at_on(ClockKind::Real)
        .expect("a deadline the real clock holds");
    let after = crate::wait::now();
    let left = Duration::from_secs(600);
    assert!(
        before + left <= real && real <= after + left,
        "the 600 s left on tokio's clock, from now on the real one: {real:?} against {before:?}..{after:?}"
    );
    assert_eq!(deadline.at_on(ClockKind::Tokio), Some(deadline.at));
}

// Windows: the recorded route is the group flag, with none of the flags that put the child on a console
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
