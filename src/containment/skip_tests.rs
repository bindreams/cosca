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
            .expect("a kill that left nothing");
    }
    assert_eq!(tree.is_killed(), settled);
    tree
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
            || Why::MayNameAnother(Refusal::Unsure(PID, std::io::Error::other("forced"))),
            false,
        ),
        ("untrusted", || Why::Untrusted("forced".to_owned()), false),
    ];
    for (name, why, moot) in whys {
        assert_eq!(skip(why()).is_moot(&killed(true)), moot, "{name}, tree killed");
        assert!(!skip(why()).is_moot(&killed(false)), "{name}, tree never killed");
    }
}
