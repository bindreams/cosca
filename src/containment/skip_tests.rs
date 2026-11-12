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
