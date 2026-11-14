use super::{Skip, Why};
use crate::containment::dispatch::TreeKillOutcome;
use crate::containment::{Refusal, Tree};

const PID: u32 = 999_999;

fn skip(why: Why) -> Skip {
    Skip {
        action: "kill its process group".to_owned(),
        why,
        root_alone: false,
        holders: None,
    }
}

/// A tree a completed kill settled, and a fresh one.
fn killed(settled: bool) -> Tree {
    let tree = Tree::none();
    if settled {
        tree.settle(TreeKillOutcome::Ran(Ok(())), true)
            .answer
            .expect("a kill that left nothing");
    }
    assert_eq!(tree.is_killed(), settled);
    tree
}

/// A skipped call whose root's handle could not say whether it was reaped answers `Unassessable`
/// with the handle's error as its `source()`, so its OS code is reachable, and not in the `detail`.
/// The `warn` still says the error.
///
/// Mutant: the answer folds the error into its text and keeps no source.
#[skuld::test]
fn a_skip_over_an_unsure_handle_answers_with_its_error_as_the_source() {
    use super::SkipCall;
    use crate::containment::dispatch::TreeSignal;
    use crate::error::Error;

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let os_error = std::io::Error::from_raw_os_error(libc::EPERM).to_string();
    let call = SkipCall {
        op: "skip_cause_probe_7e1",
        pid: PID,
        signal: TreeSignal::Term,
        earlier: None,
    };
    let why = Why::MayNameAnother(
        Refusal::Unsure(PID, std::sync::Arc::new(std::io::Error::from_raw_os_error(libc::EPERM))),
        None,
    );

    let answer = call
        .answer(&killed(false), skip(why), None)
        .answer
        .expect_err("a skipped call is no success");

    let Error::Unassessable { detail, .. } = &answer else {
        panic!("got {answer:?}");
    };
    assert_eq!(crate::error::first_os_code(&answer), Some(libc::EPERM), "{answer:?}");
    assert!(!detail.contains(&os_error), "{detail}");
    let warns = crate::log_capture::warns_since(mark, "skip_cause_probe_7e1");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains(&os_error), "{warns:?}");
}

/// A sweep that skipped what the root's number names, and whose holders' sweep (macOS) failed
/// nowhere, is `Unassessable` with the handle's error behind the skip as its `source()`; a holders'
/// sweep that failed is the answer itself.
///
/// Mutant: the answer folds the error into its text, or keeps no source.
#[skuld::test]
fn a_sweep_that_skipped_has_the_handles_error_as_its_source_unless_the_holders_failed() {
    use crate::error::Error;

    let os_error = std::io::Error::from_raw_os_error(libc::EPERM).to_string();
    let why = || {
        Why::MayNameAnother(
            Refusal::Unsure(PID, std::sync::Arc::new(std::io::Error::from_raw_os_error(libc::EPERM))),
            None,
        )
    };

    let answer = skip(why()).sweep_error();

    let Error::Unassessable { detail, .. } = &answer else {
        panic!("got {answer:?}");
    };
    assert_eq!(crate::error::first_os_code(&answer), Some(libc::EPERM), "{answer:?}");
    assert!(!detail.contains(&os_error), "{detail}");

    let own = Error::Containment {
        detail: "the holders' sweep failed".into(),
        source: None,
    };
    let answer = Skip {
        holders: Some(Err(own)),
        ..skip(why())
    }
    .sweep_error();
    assert!(matches!(answer, Error::Containment { .. }), "{answer:?}");
    assert_eq!(
        crate::error::first_os_code(&answer),
        Some(libc::EPERM),
        "the skip's reason is below the holders' error: {answer:?}"
    );
}

/// A skip is moot only over a tree this handle killed, and only because its own reap left the pid
/// naming no process or unreadable, or the root's number cannot be trusted (macOS): a root reaped
/// elsewhere and a handle that could not say leave the tree's number in doubt for another reason.
///
/// Mutants: any one of the refusals reads as moot; a skip is moot over a tree never killed.
#[skuld::test]
fn a_skip_is_moot_only_over_a_killed_tree_after_the_own_reap() {
    /// A reason, and whether it makes a skip moot over a killed tree.
    type Case = (&'static str, fn() -> Why, bool);
    let whys: [Case; 6] = [
        (
            "own reap, pid gone",
            || Why::MayNameAnother(Refusal::ReapedPidGone(PID), None),
            true,
        ),
        (
            "own reap, pid unread",
            || Why::MayNameAnother(Refusal::ReapedPidUnread(PID, None), None),
            true,
        ),
        (
            "own reap, pid taken",
            || Why::MayNameAnother(Refusal::ReapedPidTaken(PID), None),
            false,
        ),
        (
            "reaped elsewhere",
            || Why::MayNameAnother(Refusal::ReapedElsewhere(PID), None),
            false,
        ),
        (
            "handle could not say",
            || {
                Why::MayNameAnother(
                    Refusal::Unsure(PID, std::sync::Arc::new(std::io::Error::other("forced"))),
                    None,
                )
            },
            false,
        ),
        (
            "untrusted",
            || Why::Untrusted {
                why: "forced".to_owned(),
                cause: None,
            },
            true,
        ),
    ];
    for (name, why, moot) in whys {
        assert_eq!(skip(why()).is_moot(&killed(true)), moot, "{name}, tree killed");
        assert!(!skip(why()).is_moot(&killed(false)), "{name}, tree never killed");
    }
}

// A skip over an untrusted root settles the same for a tree call and a drop =====

/// A kill that skipped what the root's number names, because the root is untrusted, saw no member
/// running: a tree call (`kill_tree`) answers it with an error but leaves the tree as it was, so a
/// later drop over it settles as a drop alone does, with nothing to warn of beyond the skip it already
/// words. `holders`: the macOS fd marker's sweep of its holders, or none for a mechanism without one.
///
/// Mutant: the tree call settles the skip as a kill that ran and left something, which leaves the
/// tree unvouched, so a drop after it warns that the tree could not be vouched for.
#[skuld::test]
fn a_tree_call_that_skipped_an_untrusted_root_leaves_the_drop_what_a_drop_alone_finds() {
    use super::SkipCall;
    use crate::containment::dispatch::TreeSignal;

    let untrusted = |swept: bool| Skip {
        holders: swept.then_some(Ok(())),
        ..skip(Why::untrusted(&crate::signal::RootState::Unpinned))
    };
    let call = SkipCall {
        op: "skip_untrusted_probe_c3",
        pid: PID,
        signal: TreeSignal::Kill,
        earlier: None,
    };
    for swept in [false, true] {
        let alone = killed(false);
        assert!(
            alone
                .settle_for_drop(TreeKillOutcome::Skipped(untrusted(swept)), false)
                .is_none(),
            "swept {swept}: a drop alone has nothing to warn of"
        );

        let called = killed(false);
        call.answer(&called, untrusted(swept), None)
            .answer
            .expect_err("a skipped kill is no success");
        assert!(!called.is_killed(), "swept {swept}: a skip kills nothing");
        let left = called.settle_for_drop(TreeKillOutcome::Skipped(untrusted(swept)), false);
        assert!(
            left.is_none(),
            "swept {swept}: the drop after a skipped tree call warns as a drop alone does: {:?}",
            left.map(|left| left.text)
        );
    }
}

/// A kind of skip: its name, and a reason of that kind.
type Kind = (&'static str, fn() -> Why);

/// The two kinds of skip a tree call settles: the root's number cannot be trusted (macOS), and it may
/// name another process.
fn kinds() -> [Kind; 2] {
    [
        ("untrusted", || Why::untrusted(&crate::signal::RootState::Unpinned)),
        ("may name another", || {
            Why::MayNameAnother(Refusal::ReapedElsewhere(PID), None)
        }),
    ]
}

fn kill_call(op: &'static str) -> super::SkipCall<'static> {
    super::SkipCall {
        op,
        pid: PID,
        signal: crate::containment::dispatch::TreeSignal::Kill,
        earlier: None,
    }
}

/// A tree that names its members by a walk, which settles held members by identity.
fn walking_tree() -> Tree {
    use crate::containment::mechanism::Mechanism;
    Tree::contained(Mechanism::Walk(crate::containment::treewalk::Walker::new(
        crate::identity::ProcessId::current(),
    )))
}

/// A member an earlier kill refused, as a settlement holds it: `id` is its identity, if it was read.
fn refused(tree: &Tree, pid: u32, id: Option<crate::identity::ProcessId>) {
    use crate::containment::dispatch::Unkilled;
    tree.settle(
        TreeKillOutcome::Ran(Err(Unkilled {
            members: vec![crate::error::Error::MemberNotKilled {
                pid,
                source: std::sync::Arc::new(crate::error::Error::Unassessable {
                    detail: "its identity could not be read".into(),
                    source: None,
                }),
            }],
            root: None,
            resolved: id.into_iter().collect(),
        })),
        true,
    )
    .answer
    .expect_err("the member was left");
}

/// A skipped kill over a tree that holds a member an earlier kill refused answers that member, for
/// either kind of skip: the answer holds every member the tree is left with, whether or not the
/// skip's sweep of the marker holders ran.
///
/// Mutant: the settlement's answer is dropped when no holders were swept.
#[skuld::test]
fn a_skipped_kill_answers_a_member_the_tree_holds_for_either_kind() {
    for (kind, why) in kinds() {
        let tree = walking_tree();
        refused(&tree, 7, None);

        let answer = kill_call("skip_held_probe_e1")
            .answer(&tree, skip(why()), None)
            .answer
            .expect_err("a skipped kill is no success");

        let members = answer.left_members();
        assert!(
            members
                .iter()
                .any(|member| matches!(member, crate::error::Error::MemberNotKilled { pid: 7, .. })),
            "{kind}: the member the tree holds is named: {answer:?}"
        );
    }
}

/// A skipped kill that killed the members the handle held by identity says so, for either kind of
/// skip, and does not claim it sent nothing.
///
/// Mutant: the answer says "sent nothing" over a settlement that killed a held member.
#[skuld::test]
fn a_skipped_kill_that_killed_a_held_member_says_so_for_either_kind() {
    use crate::error::Error;
    for (kind, why) in kinds() {
        let (blocker, stdin) = crate::test_child::held_uncontained_blocker(false);
        let id = blocker.id().expect(crate::test_child::IDENTITY_READ);
        let tree = walking_tree();
        refused(&tree, id.pid(), Some(id));

        let settled = kill_call("skip_held_probe_e2").answer(&tree, skip(why()), None);

        // Released after the kill: a settlement that sent nothing lets the member exit on EOF, which
        // fails the assertion instead of leaving a wait unbounded.
        drop(stdin);
        crate::test_child::assert_killed("the held member", blocker.wait().expect("reap the member"));
        assert_eq!(settled.killed_again, vec![id], "{kind}");
        let answer = settled.answer.expect_err("a skipped kill is no success");
        let Error::Unassessable { detail, .. } = &answer else {
            panic!("{kind}: got {answer:?}");
        };
        let said = format!("killed the members it held by identity (pid {})", id.pid());
        assert!(detail.contains(&said), "{kind}: {detail}");
        assert!(!detail.contains("sent nothing"), "{kind}: {detail}");
    }
}

/// A skipped kill whose sweep of the marker holders failed answers that failure and leaves the drop a
/// warn, whichever of the tree call and the drop ran first, for either kind of skip: the drop after the
/// call warns as the drop before it did.
///
/// Mutant: a kind of skip settles differently in a tree call than in a drop.
#[skuld::test]
fn a_skipped_kill_whose_holders_failed_leaves_the_drop_a_warn_in_either_order() {
    use crate::error::Error;
    for (kind, why) in kinds() {
        let failing = || Skip {
            holders: Some(Err(Error::Containment {
                detail: "the holders' sweep failed".into(),
                source: None,
            })),
            ..skip(why())
        };
        let call = kill_call("skip_failed_probe_f1");
        let says = |answer: Error| {
            assert!(
                matches!(&answer, Error::Containment { detail, .. } if detail == "the holders' sweep failed"),
                "{kind}: {answer:?}"
            );
        };

        let called_first = killed(false);
        says(
            call.answer(&called_first, failing(), None)
                .answer
                .expect_err("a failed sweep is no success"),
        );
        let after = called_first
            .settle_for_drop(TreeKillOutcome::Skipped(failing()), false)
            .unwrap_or_else(|| panic!("{kind}: the drop after the call warns"));

        let dropped_first = killed(false);
        let before = dropped_first
            .settle_for_drop(TreeKillOutcome::Skipped(failing()), false)
            .unwrap_or_else(|| panic!("{kind}: the drop alone warns"));
        says(
            call.answer(&dropped_first, failing(), None)
                .answer
                .expect_err("a failed sweep is no success"),
        );

        assert_eq!(
            after.text, before.text,
            "{kind}: the drop warns the same in both orders"
        );
    }
}

/// A skipped call over a tree this handle already killed is moot, for either kind of skip: a kill
/// answers `Ok` and warns of nothing, as a drop over it is silent.
///
/// Mutant: an untrusted skip over a killed tree answers `Unassessable`.
#[skuld::test]
fn a_skipped_call_over_a_killed_tree_is_moot_for_either_kind() {
    use crate::containment::dispatch::TreeSignal;
    for (kind, why) in kinds() {
        let moot = |signal: TreeSignal| {
            super::SkipCall {
                op: "skip_moot_probe_g1",
                pid: PID,
                signal,
                earlier: None,
            }
            .answer(&killed(true), skip(why()), None)
            .answer
        };
        // The refusals that outlive a kill, a root reaped elsewhere, are not moot: only the untrusted
        // root (and the own reap's) is. The other kind is the control.
        if kind == "untrusted" {
            moot(TreeSignal::Kill).expect("a kill over a killed tree");
            moot(TreeSignal::Term).expect("a terminate over a killed tree");
        } else {
            moot(TreeSignal::Kill).expect_err("a root reaped elsewhere leaves the tree in doubt");
        }
        assert!(
            killed(true)
                .settle_for_drop(TreeKillOutcome::Skipped(skip(why())), false)
                .is_none(),
            "{kind}: the drop over a killed tree is silent"
        );
    }
}

// The other failures of a skipped call join the error it returns =====

/// A skip whose reason holds an error with the code `code`.
fn unsure(code: i32) -> Why {
    Why::MayNameAnother(
        Refusal::Unsure(PID, std::sync::Arc::new(std::io::Error::from_raw_os_error(code))),
        None,
    )
}

fn term_call(op: &'static str) -> super::SkipCall<'static> {
    super::SkipCall {
        op,
        pid: PID,
        signal: crate::containment::dispatch::TreeSignal::Term,
        earlier: None,
    }
}

/// The codes of the members of the `Several` an error holds as its source, in order.
fn codes_below(error: &crate::error::Error) -> Vec<Option<i32>> {
    use std::error::Error as _;
    let source = error.source().and_then(|s| s.downcast_ref::<crate::error::Error>());
    let Some(crate::error::Error::Several(list)) = source else {
        panic!("expected a Several below the variant: {error:?}");
    };
    list.iter()
        .map(|member| crate::error::first_os_code(&**member))
        .collect()
}

/// A call whose holders' sweep failed and whose root signal failed too returns the holders' error with
/// the root's failure and the refusal's cause below its variant, in that order. No member's words
/// are in the detail.
///
/// Mutants: the root's failure is dropped when the holders failed; the refusal's cause is dropped.
#[skuld::test]
fn a_skipped_call_whose_holders_and_root_both_failed_keeps_both_and_the_reason() {
    use crate::error::Error;
    let holders = Error::Containment {
        detail: "the holders' sweep failed".into(),
        source: None,
    };
    let root = Error::Unassessable {
        detail: "the root's signal failed".into(),
        source: Some(Error::io_cause(std::io::Error::from_raw_os_error(libc::EPERM))),
    };

    let answer = term_call("skip_peers_probe_a1")
        .answer(
            &killed(false),
            Skip {
                holders: Some(Err(holders)),
                ..skip(unsure(libc::EACCES))
            },
            Some(Err(root)),
        )
        .answer
        .expect_err("a skipped call is no success");

    let Error::Containment { detail, .. } = &answer else {
        panic!("the holders' variant is kept: {answer:?}");
    };
    assert_eq!(detail, "the holders' sweep failed");
    assert_eq!(codes_below(&answer), [Some(libc::EPERM), Some(libc::EACCES)]);
}

/// A root signal that failed with a variant that holds a cause (not an `Error::Io`, which keeps its
/// code as it is) takes the refusal's cause as a peer of its own.
#[skuld::test]
fn a_skipped_calls_root_failure_takes_the_reason_as_a_peer() {
    use crate::error::Error;
    let root = Error::Unassessable {
        detail: "the root's signal failed".into(),
        source: Some(Error::io_cause(std::io::Error::from_raw_os_error(libc::EPERM))),
    };

    let answer = term_call("skip_peers_probe_a2")
        .answer(&killed(false), skip(unsure(libc::EACCES)), Some(Err(root)))
        .answer
        .expect_err("a skipped call is no success");

    assert!(matches!(&answer, Error::Unassessable { detail, .. } if detail == "the root's signal failed"));
    assert_eq!(codes_below(&answer), [Some(libc::EPERM), Some(libc::EACCES)]);
}

/// A root signal that failed with an `Error::Io`, a leaf with no slot for peers, goes below the call's
/// `Unassessable`, after the refusal's cause: also when nothing else failed. Its code is found down
/// the chain, as `Error`'s "The OS code" section promises.
///
/// Mutants: the `Io` is returned bare; the `Io` is dropped; it comes before the refusal's cause.
#[skuld::test]
fn a_skipped_calls_io_failure_goes_below_the_unassessable_after_the_reason() {
    use crate::error::Error;
    let eperm = || Error::Io(std::io::Error::from_raw_os_error(libc::EPERM));

    let answer = term_call("skip_peers_probe_a3")
        .answer(&killed(false), skip(unsure(libc::EACCES)), Some(Err(eperm())))
        .answer
        .expect_err("a skipped call is no success");
    assert!(matches!(&answer, Error::Unassessable { .. }), "{answer:?}");
    assert_eq!(codes_below(&answer), [Some(libc::EACCES), Some(libc::EPERM)]);

    let alone = term_call("skip_peers_probe_a4")
        .answer(
            &killed(false),
            skip(Why::MayNameAnother(Refusal::ReapedElsewhere(PID), None)),
            Some(Err(eperm())),
        )
        .answer
        .expect_err("a skipped call is no success");
    assert!(matches!(&alone, Error::Unassessable { .. }), "{alone:?}");
    assert_eq!(crate::error::first_os_code(&alone), Some(libc::EPERM), "{alone:?}");
}

/// A call over an untrusted root (macOS) whose holders' sweep failed returns that failure with the
/// error of the root's state below it, which was only a debug line.
#[skuld::test]
fn an_untrusted_roots_cause_joins_the_failed_holders_sweep() {
    use crate::error::Error;
    let untrusted = Why::Untrusted {
        why: "its state could not be read".to_owned(),
        cause: Some(std::sync::Arc::new(std::io::Error::from_raw_os_error(libc::EACCES))),
    };
    let holders = Error::Containment {
        detail: "the holders' sweep failed".into(),
        source: Some(Error::io_cause(std::io::Error::from_raw_os_error(libc::EPERM))),
    };

    let answer = term_call("skip_peers_probe_b1")
        .answer(
            &killed(false),
            Skip {
                holders: Some(Err(holders)),
                ..skip(untrusted)
            },
            None,
        )
        .answer
        .expect_err("a skipped call is no success");

    assert!(matches!(&answer, Error::Containment { detail, .. } if detail == "the holders' sweep failed"));
    assert_eq!(codes_below(&answer), [Some(libc::EPERM), Some(libc::EACCES)]);
}

/// A reason that holds two causes (a handle that could not say, and the group probe that failed
/// before it) joins a failed holders' sweep as two more members of one flat list, in the answer of a
/// call and of a sweep alike.
///
/// Mutant: the reason's `Several` is nested in the list as one member.
#[skuld::test]
fn a_reason_with_two_causes_joins_the_failed_holders_sweep_flat() {
    use crate::error::Error;
    let reason = || {
        Why::MayNameAnother(
            Refusal::Unsure(
                PID,
                std::sync::Arc::new(std::io::Error::from_raw_os_error(libc::EACCES)),
            ),
            Some(libc::EMFILE),
        )
    };
    let holders = || Error::Containment {
        detail: "the holders' sweep failed".into(),
        source: Some(Error::io_cause(std::io::Error::from_raw_os_error(libc::EPERM))),
    };
    let expected = [Some(libc::EPERM), Some(libc::EACCES), Some(libc::EMFILE)];

    let answer = term_call("skip_peers_probe_d1")
        .answer(
            &killed(false),
            Skip {
                holders: Some(Err(holders())),
                ..skip(reason())
            },
            None,
        )
        .answer
        .expect_err("a skipped call is no success");
    assert_eq!(codes_below(&answer), expected, "{answer:?}");

    let swept = Skip {
        holders: Some(Err(holders())),
        ..skip(reason())
    }
    .sweep_error();
    assert_eq!(codes_below(&swept), expected, "{swept:?}");
}

/// The kill after a holders-only `SIGTERM` that failed too (macOS) returns the kill's error with the
/// `SIGTERM`'s failure and the skip's reason below its variant, in that order; a kill that left nothing
/// is the call's `Unassessable` with the reason first, then the `SIGTERM`'s failure.
///
/// Mutants: the `SIGTERM`'s failure stays in the warn; it comes after the reason.
#[skuld::test]
fn a_holders_only_kill_that_failed_takes_the_term_and_the_reason_as_peers() {
    use crate::containment::dispatch::Unkilled;
    use crate::error::Error;
    let kill = Error::Containment {
        detail: "a holder refused the kill".into(),
        source: Some(Error::io_cause(std::io::Error::from_raw_os_error(libc::EPERM))),
    };
    let term_failed = || Error::Containment {
        detail: "a holder refused the SIGTERM".into(),
        source: Some(Error::io_cause(std::io::Error::from_raw_os_error(libc::EIO))),
    };

    let settled = term_call("skip_peers_probe_c1").holders_settled(
        &killed(false),
        Skip {
            holders: Some(Err(term_failed())),
            ..skip(unsure(libc::EACCES))
        },
        TreeKillOutcome::Ran(Err(Unkilled::from(kill))),
    );
    assert!(matches!(&settled.answer, Error::Containment { detail, .. } if detail == "a holder refused the kill"));
    assert_eq!(
        codes_below(&settled.answer),
        [Some(libc::EPERM), Some(libc::EIO), Some(libc::EACCES)]
    );

    let settled = term_call("skip_peers_probe_c2").holders_settled(
        &killed(false),
        Skip {
            holders: Some(Err(term_failed())),
            ..skip(unsure(libc::EACCES))
        },
        TreeKillOutcome::Ran(Ok(())),
    );
    assert!(
        matches!(&settled.answer, Error::Unassessable { .. }),
        "{:?}",
        settled.answer
    );
    assert_eq!(codes_below(&settled.answer), [Some(libc::EACCES), Some(libc::EIO)]);
}

/// A Linux call that signalled the root through its pidfd and failed, over a skip with a reason,
/// returns the signal's error with the reason below its variant, and an `Error::Io` (a leaf) goes below
/// the call's `Unassessable` after the reason.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_pidfd_shutdown_that_failed_takes_the_reason_as_a_peer() {
    use crate::child::graceful::PidfdShutdown;
    use crate::elevation::front::Gate;
    use crate::error::Error;
    let failed = |term: Error| {
        PidfdShutdown::start(Gate::Open, || Err(term))
            .expect("the gate is open")
            .finish(
                &term_call("skip_peers_probe_d1"),
                &skip(unsure(libc::EACCES)),
                None,
                || Gate::Open,
                || Ok(crate::signal::Sent::Delivered),
            )
    };

    let answer = failed(Error::Unassessable {
        detail: "the SIGTERM failed".into(),
        source: Some(Error::io_cause(std::io::Error::from_raw_os_error(libc::EPERM))),
    });
    assert!(matches!(&answer, Error::Unassessable { detail, .. } if detail == "the SIGTERM failed"));
    assert_eq!(codes_below(&answer), [Some(libc::EPERM), Some(libc::EACCES)]);

    let answer = failed(Error::Io(std::io::Error::from_raw_os_error(libc::EPERM)));
    assert!(matches!(&answer, Error::Unassessable { .. }), "{answer:?}");
    assert_eq!(codes_below(&answer), [Some(libc::EACCES), Some(libc::EPERM)]);
}
