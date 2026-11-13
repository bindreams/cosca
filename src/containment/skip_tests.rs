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
    let why = Why::MayNameAnother(Refusal::Unsure(
        PID,
        std::sync::Arc::new(std::io::Error::from_raw_os_error(libc::EPERM)),
    ));

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
        Why::MayNameAnother(Refusal::Unsure(
            PID,
            std::sync::Arc::new(std::io::Error::from_raw_os_error(libc::EPERM)),
        ))
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
/// naming no process or unreadable: a root reaped elsewhere, a handle that could not say, and an
/// untrusted root (macOS) leave the tree's number in doubt for another reason.
///
/// Mutants: any one of the refusals reads as moot; a skip is moot over a tree never killed.
#[skuld::test]
fn a_skip_is_moot_only_over_a_killed_tree_after_the_own_reap() {
    /// A reason, and whether it makes a skip moot over a killed tree.
    type Case = (&'static str, fn() -> Why, bool);
    let whys: [Case; 6] = [
        (
            "own reap, pid gone",
            || Why::MayNameAnother(Refusal::ReapedPidGone(PID)),
            true,
        ),
        (
            "own reap, pid unread",
            || Why::MayNameAnother(Refusal::ReapedPidUnread(PID)),
            true,
        ),
        (
            "own reap, pid taken",
            || Why::MayNameAnother(Refusal::ReapedPidTaken(PID)),
            false,
        ),
        (
            "reaped elsewhere",
            || Why::MayNameAnother(Refusal::ReapedElsewhere(PID)),
            false,
        ),
        (
            "handle could not say",
            || {
                Why::MayNameAnother(Refusal::Unsure(
                    PID,
                    std::sync::Arc::new(std::io::Error::other("forced")),
                ))
            },
            false,
        ),
        (
            "untrusted",
            || Why::Untrusted {
                why: "forced".to_owned(),
                cause: None,
            },
            false,
        ),
    ];
    for (name, why, moot) in whys {
        assert_eq!(skip(why()).is_moot(&killed(true)), moot, "{name}, tree killed");
        assert!(!skip(why()).is_moot(&killed(false)), "{name}, tree never killed");
    }
}

// The other failures of a skipped call join the error it returns =====

/// A skip whose reason holds an error with the code `code`.
fn unsure(code: i32) -> Why {
    Why::MayNameAnother(Refusal::Unsure(
        PID,
        std::sync::Arc::new(std::io::Error::from_raw_os_error(code)),
    ))
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
            skip(Why::MayNameAnother(Refusal::ReapedElsewhere(PID))),
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
