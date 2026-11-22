//! `run_ready`, the sync driver's one poll, and `graceful_status_of_reap`, the one answer of both cores for the reap.

use std::time::Duration;

use super::run_ready;
use crate::child::owned::ChildWaitOutcome;
use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::child::ExitRecord;
use crate::os_process::fake::{Answer, ReapAnswer};
use crate::signal::{Sent, Sig};
use crate::test_child::over_fake::{child_over, killed_root, root_looking};
use crate::wait::block_probe;

/// Mutant: a future that is ready is polled again or its value dropped.
#[skuld::test]
fn a_ready_future_gives_its_output_through_every_await() {
    async fn ready(n: u32) -> u32 {
        n
    }
    assert_eq!(run_ready(async { ready(1).await + ready(2).await }), 3);
}

/// Mutant: a pending future is waited for instead of refused.
#[skuld::test]
#[should_panic(expected = "run_ready: the future is pending, but a blocking driver's waits are all ready")]
fn a_pending_future_is_a_broken_contract() {
    run_ready(std::future::pending::<()>());
}

/// A root reaped elsewhere, or whose pid names another process now, leaves no exit status: the answer is
/// `Unassessable` naming the call, with the `ECHILD` every wait answers as its `source()`, so a caller can
/// tell it from any other refusal. The same for both calls.
///
/// Mutant: the foreign verdict is folded into an `Io`, or its `ECHILD` is dropped.
#[cfg(unix)]
#[skuld::test]
fn a_root_reaped_elsewhere_answers_unassessable_with_its_echild_as_the_source() {
    use crate::error::Error;
    use crate::os_process::child::Foreign;

    for foreign in [Foreign::Gone, Foreign::Other] {
        for op in ["graceful_shutdown", "graceful_shutdown_tree"] {
            let answer = super::graceful_status_of_reap(4242, None, op, Ok(ChildWaitOutcome::Foreign(foreign)))
                .expect_err("no exit status was collected");

            let Error::Unassessable { detail, .. } = &answer else {
                panic!("{answer:?}");
            };
            // Only what is true on every path: the status cannot be collected, and why. Nothing about what was
            // sent, which the record of the stop's send says and this answer does not know.
            assert_eq!(
                detail,
                &format!("pid 4242: {op}: the root's exit status cannot be collected: the root was reaped elsewhere")
            );
            assert_eq!(crate::error::first_os_code(&answer), Some(libc::ECHILD), "{answer:?}");
        }
    }
}

/// A reap that failed is the answer as it is, even with an `ECHILD` in it: only the reap's own foreign
/// verdict says the root was reaped elsewhere.
///
/// Mutant: any `ECHILD` below the failure counts.
#[cfg(unix)]
#[skuld::test]
fn a_failed_reap_stays_the_answer_whatever_it_holds() {
    use crate::error::Error;

    let failed = Error::Io(std::io::Error::from_raw_os_error(libc::ECHILD));
    let words = failed.to_string();

    let answer =
        super::graceful_status_of_reap(4242, None, "graceful_shutdown", Err(failed)).expect_err("the reap failed");

    assert!(matches!(answer, Error::Io(_)), "{answer:?}");
    assert_eq!(answer.to_string(), words);
}

/// An exit record is the status.
///
/// Mutant: a record is answered as a foreign reap.
#[skuld::test]
fn an_exit_record_is_the_status() {
    use crate::os_process::child::ExitRecord;

    let status = std::process::ExitStatus::default();
    let answered = super::graceful_status_of_reap(
        4242,
        None,
        "graceful_shutdown",
        Ok(ChildWaitOutcome::Exited(ExitRecord::Status(status))),
    );
    assert_eq!(answered.expect("an exit"), status);
}

/// A zombie launchd holds has no status to collect: the macOS refusal, for both calls, with no source
/// and no warn.
///
/// Mutant: it is answered as a root reaped elsewhere.
#[cfg(target_os = "macos")]
#[skuld::test]
fn a_zombie_launchd_holds_answers_the_unpinned_refusal_quietly() {
    use crate::error::Error;
    use crate::os_process::child::Foreign;

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    for op in ["graceful_shutdown", "graceful_shutdown_tree"] {
        let answer = super::graceful_status_of_reap(4242, None, op, Ok(ChildWaitOutcome::Foreign(Foreign::Orphaned)))
            .expect_err("no exit status");

        let Error::Unassessable { detail, source: None } = &answer else {
            panic!("{answer:?}");
        };
        assert!(
            detail.starts_with(&format!("pid 4242: {op}: the root's exit status cannot be collected")),
            "{detail}"
        );
        assert!(!detail.contains("sent"), "{detail}");
        assert!(detail.contains("launchd"), "{detail}");
    }
    assert_eq!(crate::log_capture::warns_since(mark, ""), Vec::<String>::new());
}

/// A reap that ran into the call's deadline with the root running is `TimedOut` naming the root, with no
/// source, for both calls; with no identity to name, no member.
///
/// Mutants: the outcome is folded into an `Io` ("an unbounded wait ended with no exit"); the root is not named.
#[skuld::test]
fn a_reap_that_ran_into_the_deadline_is_a_timeout_naming_the_root() {
    use crate::identity::{Key, ProcessId};

    let id = ProcessId::from_parts_for_test(4242, Key::for_test(1));
    for op in ["graceful_shutdown", "graceful_shutdown_tree"] {
        for (named, members) in [(Some(id), vec![id]), (None, vec![])] {
            let answer = super::graceful_status_of_reap(4242, named, op, Ok(ChildWaitOutcome::DeadlinePassed))
                .expect_err("the root had not exited");

            let Error::TimedOut {
                detail,
                members: left,
                source: None,
            } = &answer
            else {
                panic!("{answer:?}");
            };
            assert_eq!(left, &members, "{op}");
            assert!(detail.starts_with(&format!("pid 4242: {op}:")), "{detail}");
        }
    }
}

fn exited() -> ReapAnswer {
    ReapAnswer::Exited(ExitRecord::Status(std::process::ExitStatus::default()))
}

fn the_root(child: &crate::Child) -> Vec<ProcessId> {
    child.id().into_iter().collect()
}

/// A lone shutdown whose timeout has passed when its grace would start still sends the kill: the grace is cut
/// to nothing (one look), the root is killed, and the reap, a wait that ends by the same deadline, looks once and
/// answers `TimedOut` naming the root, which the handle keeps.
///
/// Mutants: the call returns with no kill once the deadline has passed; the reap waits with no bound, so its
/// second look finds the root exited and the call answers `Ok`; the call answers `Ok` for a root it did not see
/// exit.
#[skuld::test]
fn a_timed_lone_shutdown_past_its_timeout_still_kills_and_names_the_root_it_did_not_see_exit() {
    let root = killed_root([Answer::Running]);
    let child = child_over(&root);

    let error = child
        .graceful_shutdown_timeout(Duration::from_secs(3600), Duration::ZERO)
        .expect_err("the root was not seen to exit");

    let Error::TimedOut { members, .. } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(members, &the_root(&child));
    assert_eq!(
        root.signal_calls().last(),
        Some(&Sig::Kill),
        "the root was killed whatever the deadline"
    );
}

/// With a timeout far off the same shutdown answers the root's status: the reap waits for the exit, which a
/// deadline treated as passed would cut. The wait it arms is no longer than the time left before the timeout.
///
/// Mutants: a set deadline is treated as already passed (the reap answers `TimedOut`); the reap is armed past the
/// deadline.
#[skuld::test]
fn a_timed_lone_shutdown_with_time_left_answers_the_roots_status() {
    let timeout = Duration::from_secs(3600);
    let root = killed_root([Answer::Running]);
    let child = child_over(&root);
    block_probe::take();

    let status = child
        .graceful_shutdown_timeout(Duration::ZERO, timeout)
        .expect("the root exited");

    assert_eq!(status, std::process::ExitStatus::default());
    let armed = block_probe::take();
    assert!(!armed.is_empty(), "the reap waited");
    assert!(
        armed.iter().all(|armed| armed.is_some_and(|armed| armed <= timeout)),
        "every wait was armed within the timeout: {armed:?}"
    );
}

/// The grace is cut to the call's timeout, pinned through the wait the grace arms, on a frozen clock: a grace of an
/// hour under a timeout of 10 s arms its block for 10 s. The root exits at the second look, so no kill follows.
///
/// Mutants: the grace is not cut (the block is armed for the hour); the timeout replaces the grace instead of
/// cutting it (a grace shorter than the timeout arms the timeout).
#[skuld::test]
fn a_timed_lone_shutdown_arms_its_grace_wait_at_the_timeout_when_that_is_nearer() {
    use crate::wait::test_clock::FrozenClockGuard;

    let (_clock, _) = FrozenClockGuard::install();
    let root = root_looking([Answer::Running, Answer::Exited])
        .signals([Ok(Sent::Delivered)])
        .reaps([exited()]);
    let child = child_over(&root);
    block_probe::take();

    child
        .graceful_shutdown_timeout(Duration::from_secs(3600), Duration::from_secs(10))
        .expect("the root exited within the grace");
    assert_eq!(block_probe::take().first(), Some(&Some(Duration::from_secs(10))));

    let root = root_looking([Answer::Running, Answer::Exited])
        .signals([Ok(Sent::Delivered)])
        .reaps([exited()]);
    let child = child_over(&root);
    child
        .graceful_shutdown_timeout(Duration::from_secs(5), Duration::from_secs(3600))
        .expect("the root exited within the grace");
    assert_eq!(
        block_probe::take().first(),
        Some(&Some(Duration::from_secs(5))),
        "a grace shorter than the timeout is the grace"
    );
}

/// The error of a stop action whose own wait ran out: its own `TimedOut`, made long before any deadline of the call.
fn action_timed_out() -> Error {
    Error::TimedOut {
        detail: "the action's wait ran into the timeout".into(),
        members: Vec::new(),
        source: None,
    }
}

fn action_refused() -> Error {
    Error::Unsupported {
        op: "the action".into(),
        platform: "test",
        detail: "refused by the test".into(),
        source: None,
    }
}

/// A stop action whose `wait_exit` the call's deadline cut goes on to the kill, as a grace that is over does: the
/// call reaps the root and answers its status. The deadline is 10 s ahead when the action runs, on a frozen clock,
/// and the wait reaches it only through its own block (the hook moves the clock on by what the block is armed for),
/// so only the wait's own record says the deadline cut it. Any other error of the action ends the call as it does
/// without a timeout: that error, nothing killed.
///
/// Mutants: the deadline is read before the action runs; `exit_answer` does not record the cut; the recorded
/// `TimedOut` ends the call; any error of the action goes on to the kill.
#[skuld::test]
fn a_lone_shutdown_goes_on_to_the_kill_after_an_action_whose_wait_the_deadline_cut_and_ends_after_any_other_error() {
    use crate::wait::block_probe::on_each_block;
    use crate::wait::test_clock::{advance, FrozenClockGuard};

    let (_clock, _) = FrozenClockGuard::install();
    let _blocks = on_each_block(|block| {
        if let Some(armed) = block.armed {
            advance(armed);
        }
    });
    let root = root_looking([Answer::Running, Answer::Running, Answer::Running, Answer::Running])
        .signals([Ok(Sent::Delivered)])
        .reaps([exited()]);
    let mut child = child_over(&root);
    child.stop = crate::stop::StopAction::sync(|target| target.wait_exit(Duration::from_secs(3600)).map(|_| ()));
    block_probe::take();

    let status = child
        .graceful_shutdown_timeout(Duration::ZERO, Duration::from_secs(10))
        .expect("the deadline cut the action's wait, and the kill followed");

    assert_eq!(status, std::process::ExitStatus::default());
    assert_eq!(
        block_probe::take().first(),
        Some(&Some(Duration::from_secs(10))),
        "the action's wait was armed for the 10 s that were left"
    );
    assert_eq!(
        root.signal_calls(),
        [Sig::Kill],
        "the action sent nothing, and the kill went out"
    );

    let root = killed_root([]);
    let mut child = child_over(&root);
    child.stop = crate::stop::StopAction::sync(move |_| Err(action_refused()));
    let error = child
        .graceful_shutdown_timeout(Duration::ZERO, Duration::ZERO)
        .expect_err("the action was refused");
    assert!(
        matches!(&error, Error::Unsupported { detail, .. } if detail == "refused by the test"),
        "{error:?}"
    );
    assert_eq!(root.signal_calls(), [], "nothing was killed");
}

/// An action's `TimedOut` that no wait of the call's deadline cut is the action's own and ends the call, as any
/// error of the action does, even when the deadline has passed by the time the action returns (the action moved
/// the clock past it). That error is the answer and nothing is killed. The untimed call and a timed one whose
/// deadline is far off are the same row: the action's own timeout records nothing.
///
/// Mutants: the deadline's passing is read off the clock after the action instead of the record of a cut wait
/// (the `TimedOut` goes on to the kill); every `TimedOut` of the action goes on to the kill.
#[skuld::test]
fn a_lone_shutdown_ends_with_an_action_timeout_the_deadline_did_not_cut() {
    use crate::wait::test_clock::{advance, FrozenClockGuard};

    let (_clock, _) = FrozenClockGuard::install();
    let root = killed_root([Answer::Running]);
    let mut child = child_over(&root);
    child.stop = crate::stop::StopAction::sync(|_| {
        advance(Duration::from_secs(20));
        Err(action_timed_out())
    });

    let error = child
        .graceful_shutdown_timeout(Duration::ZERO, Duration::from_secs(10))
        .expect_err("the action timed out of its own accord");

    assert!(
        matches!(&error, Error::TimedOut { detail, .. } if detail == "the action's wait ran into the timeout"),
        "{error:?}"
    );
    assert_eq!(root.signal_calls(), [], "nothing was killed");
}

/// The record is the rule: once the deadline has cut one of the action's waits, any `TimedOut` the action answers
/// goes on to the kill, one of the action's own making included. The action swallows a `wait_exit` the deadline cut
/// and then answers a `TimedOut` of its own: the call goes on to the kill and answers the root's status.
///
/// Mutant: `ran_into_deadline` ignores the record for an error the target did not make (the call ends with the
/// action's error, nothing killed).
#[skuld::test]
fn a_lone_shutdown_goes_on_to_the_kill_after_an_own_timeout_that_follows_a_wait_the_deadline_cut() {
    use crate::wait::block_probe::on_each_block;
    use crate::wait::test_clock::{advance, FrozenClockGuard};

    let (_clock, _) = FrozenClockGuard::install();
    let _blocks = on_each_block(|block| {
        if let Some(armed) = block.armed {
            advance(armed);
        }
    });
    let root = root_looking([Answer::Running, Answer::Running, Answer::Running, Answer::Running])
        .signals([Ok(Sent::Delivered)])
        .reaps([exited()]);
    let mut child = child_over(&root);
    child.stop = crate::stop::StopAction::sync(|target| {
        let cut = target.wait_exit(Duration::from_secs(3600));
        assert!(
            matches!(cut, Err(Error::TimedOut { .. })),
            "the deadline cut the wait: {cut:?}"
        );
        Err(action_timed_out())
    });

    let status = child
        .graceful_shutdown_timeout(Duration::ZERO, Duration::from_secs(10))
        .expect("the deadline cut a wait of the action, so its next TimedOut went on to the kill");

    assert_eq!(status, std::process::ExitStatus::default());
    assert_eq!(root.signal_calls(), [Sig::Kill], "the kill went out");
}

/// A tree shutdown whose timeout has passed when its grace would start still sends the sweep: the member the kill
/// reached runs and so does the root, and the answer names both, the member first, the root last (each looked at
/// once, the wait blocking on neither). The kill is the mechanism's, sent. The member's wait would block if it
/// were not bounded, and the hook that ends the member there makes such a wait answer `Ok`.
///
/// Mutants: the call returns with no sweep once the deadline has passed; the wait for the members has no bound;
/// the root is left out of the answer; the call answers `Ok`.
#[skuld::test]
fn a_timed_tree_shutdown_past_its_timeout_still_sweeps_and_names_what_it_did_not_see_exit() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::containment::fake::FakeContains;
    use crate::containment::Containment;
    use crate::identity::Liveness;
    use crate::test_child::over_fake::{child_with, live_member};

    let (member, writer, id) = live_member();
    let root = root_looking([Answer::Running, Answer::Running]).reaps([ReapAnswer::Running]);
    let (fake, sends) = FakeContains::new(Containment::Session, false);
    let child = child_with(&root, fake.reaching([id]));
    let writer = Rc::new(Cell::new(Some(writer)));
    let blocked = Rc::new(Cell::new(false));
    let _blocking = block_probe::on_blocking({
        let (writer, blocked) = (writer.clone(), blocked.clone());
        move || {
            blocked.set(true);
            drop(writer.take());
        }
    });

    let error = child
        .graceful_shutdown_tree_timeout(Duration::from_secs(3600), Duration::ZERO)
        .expect_err("a member and the root were not seen to exit");

    assert!(!blocked.get(), "a wait blocked past the call's deadline");
    let Error::TimedOut { members, .. } = &error else {
        panic!("{error:?}");
    };
    let mut named = vec![id];
    named.extend(the_root(&child));
    assert_eq!(members, &named);
    assert!(sends.lock().unwrap().contains(&"kill"), "the sweep was sent");
    assert_eq!(id.is_alive(), Liveness::Alive, "the fake killed nothing");
    drop(writer.take());
    _ = member.wait();
}

/// A tree shutdown whose sweep ran out of time while the root's own kill was refused (so the sweep's wait does not
/// wait for the root) answers for the root by one look after the sweep. The sweep's `TimedOut` is the answer, with the
/// refusal below it. A root the look finds running joins `members`, once, after the member the kill reached, and
/// `detail` says the look found it. A root it sees exit is collected and not named. A look that fails names nothing,
/// and its failure is below the answer.
///
/// Mutants: the call answers before the look (the root is missing); the root is named when the look saw it exit;
/// the detail is not extended; the look's failure is logged and dropped.
#[skuld::test]
fn a_timed_tree_shutdown_whose_root_kill_was_refused_answers_for_the_root_by_one_look() {
    use crate::containment::fake::FakeContains;
    use crate::containment::Containment;
    use crate::test_child::over_fake::{child_with, live_member};

    #[cfg(unix)]
    const REFUSED: i32 = libc::EPERM;
    #[cfg(windows)]
    const REFUSED: i32 = 5;

    for look in [
        ReapAnswer::Running,
        exited(),
        ReapAnswer::Err(std::io::ErrorKind::PermissionDenied),
    ] {
        let (member, writer, id) = live_member();
        let root = root_looking([Answer::Running, Answer::Running])
            .signals([Err(std::io::Error::from_raw_os_error(REFUSED))])
            .reaps([look]);
        let (fake, _) = FakeContains::new(Containment::Session, false);
        let child = child_with(&root, fake.reaching([id]));

        let error = child
            .graceful_shutdown_tree_timeout(Duration::from_secs(3600), Duration::ZERO)
            .expect_err("the member was not seen to exit");

        let Error::TimedOut { detail, members, .. } = &error else {
            panic!("{error:?}");
        };
        match look {
            ReapAnswer::Running => {
                let mut expected = vec![id];
                expected.extend(the_root(&child));
                assert_eq!(members, &expected);
                assert!(
                    detail.ends_with(&format!(
                        "; the root, pid {}, was running when the call looked at it after the sweep",
                        child.pid()
                    )),
                    "{detail}"
                );
                assert_eq!(
                    crate::error::first_os_code(&error),
                    Some(REFUSED),
                    "the refusal is below the answer: {error:?}"
                );
            }
            ReapAnswer::Err(_) => {
                assert_eq!(members, &[id]);
                assert!(
                    error
                        .failures_below()
                        .iter()
                        .any(|e| matches!(e, Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied)),
                    "the look's failure is below the answer: {error:?}"
                );
            }
            _ => assert_eq!(members, &[id]),
        }
        drop(writer);
        _ = member.wait();
    }
}

/// With a timeout far off the same call waits for the member (which ends at the block) and answers the root's
/// status.
///
/// Mutants: a set deadline is treated as already passed, so the wait does not block and the call answers
/// `TimedOut`; the wait is armed past the deadline.
#[skuld::test]
fn a_timed_tree_shutdown_with_time_left_waits_for_the_members_and_answers_the_roots_status() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::containment::fake::FakeContains;
    use crate::containment::Containment;
    use crate::test_child::over_fake::{child_with, live_member};

    let timeout = Duration::from_secs(3600);
    let (member, writer, id) = live_member();
    let root = root_looking([Answer::Running, Answer::Exited]).reaps([exited()]);
    let (fake, _) = FakeContains::new(Containment::Session, false);
    let child = child_with(&root, fake.reaching([id]));
    let writer = Rc::new(Cell::new(Some(writer)));
    let armed = Rc::new(Cell::new(None));
    let _blocking = block_probe::on_blocking({
        let (writer, armed) = (writer.clone(), armed.clone());
        move || {
            armed.set(Some(()));
            drop(writer.take());
        }
    });
    block_probe::take();

    let status = child
        .graceful_shutdown_tree_timeout(Duration::ZERO, timeout)
        .expect("the member exited, and so did the root");

    assert_eq!(status, std::process::ExitStatus::default());
    assert!(armed.get().is_some(), "the wait for the member blocked");
    let armed = block_probe::take();
    assert!(
        armed.iter().all(|armed| armed.is_some_and(|armed| armed <= timeout)),
        "every wait was armed within the timeout: {armed:?}"
    );
    _ = member.wait();
}

/// The tree twin of the lone row: an action of a tree shutdown whose `wait_exit` the call's deadline cut, and that
/// sent nothing, goes on to the sweep, as a grace that is over does. Any other error of such an action ends the
/// call with that error and no sweep.
///
/// Mutants: the deadline is read before the action runs; `exit_answer` does not record the cut; the recorded
/// `TimedOut` ends the call; any error of the action goes on to the sweep.
#[skuld::test]
fn a_tree_shutdown_goes_on_to_the_sweep_after_an_action_whose_wait_the_deadline_cut_and_ends_after_any_other_error() {
    use crate::containment::fake::FakeContains;
    use crate::containment::Containment;
    use crate::test_child::over_fake::child_with;
    use crate::wait::block_probe::on_each_block;
    use crate::wait::test_clock::{advance, FrozenClockGuard};

    let (_clock, _) = FrozenClockGuard::install();
    let _blocks = on_each_block(|block| {
        if let Some(armed) = block.armed {
            advance(armed);
        }
    });
    let (fake, sends) = FakeContains::new(Containment::Session, false);
    let root = root_looking([Answer::Running, Answer::Running, Answer::Running, Answer::Exited]).reaps([exited()]);
    let mut child = child_with(&root, fake);
    child.stop = crate::stop::StopAction::sync(|target| target.wait_exit(Duration::from_secs(3600)).map(|_| ()));

    let status = child
        .graceful_shutdown_tree_timeout(Duration::ZERO, Duration::from_secs(10))
        .expect("the deadline cut the action's wait, and the sweep followed");

    assert_eq!(status, std::process::ExitStatus::default());
    assert!(sends.lock().unwrap().contains(&"kill"), "the sweep was sent");

    let (fake, sends) = FakeContains::new(Containment::Session, false);
    let root = root_looking([]);
    let mut child = child_with(&root, fake);
    child.stop = crate::stop::StopAction::sync(|_| Err(action_refused()));
    let error = child
        .graceful_shutdown_tree_timeout(Duration::ZERO, Duration::ZERO)
        .expect_err("the action was refused");
    assert!(
        matches!(&error, Error::Unsupported { detail, .. } if detail == "refused by the test"),
        "{error:?}"
    );
    assert!(!sends.lock().unwrap().contains(&"kill"), "nothing was swept");
}

/// As for the lone call: an action's `TimedOut` that no wait of the call's deadline cut ends the tree call with
/// that error and sweeps nothing, though the deadline has passed by the time the action returns.
///
/// Mutants: the deadline's passing is read off the clock after the action instead of the record of a cut wait;
/// every `TimedOut` of the action goes on to the sweep.
#[skuld::test]
fn a_tree_shutdown_ends_with_an_action_timeout_the_deadline_did_not_cut() {
    use crate::containment::fake::FakeContains;
    use crate::containment::Containment;
    use crate::test_child::over_fake::child_with;
    use crate::wait::test_clock::{advance, FrozenClockGuard};

    let (_clock, _) = FrozenClockGuard::install();
    let (fake, sends) = FakeContains::new(Containment::Session, false);
    let root = root_looking([Answer::Running, Answer::Exited]).reaps([exited()]);
    let mut child = child_with(&root, fake);
    child.stop = crate::stop::StopAction::sync(|_| {
        advance(Duration::from_secs(20));
        Err(action_timed_out())
    });

    let error = child
        .graceful_shutdown_tree_timeout(Duration::ZERO, Duration::from_secs(10))
        .expect_err("the action timed out of its own accord");

    assert!(
        matches!(&error, Error::TimedOut { detail, .. } if detail == "the action's wait ran into the timeout"),
        "{error:?}"
    );
    assert!(!sends.lock().unwrap().contains(&"kill"), "nothing was swept");
}
