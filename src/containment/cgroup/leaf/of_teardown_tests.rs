//! The answer for an abandoned child, from what its teardown through the handshake's pidfd did.
//! The teardowns are the table's own (see
//! [`teardown_lines`](crate::child::owned::owned_tests::teardown_lines)).

use super::Abandoned;
use crate::child::owned::owned_tests::teardown_lines::{outcome, rows};
use crate::child::owned::teardown::{Disposition, Expect, HandleTeardown, Left, Past};
use crate::child::spawn::Diagnosis;
use crate::error::ChildFate;
use crate::os_process::child::KillRefusal;

/// `Ended` promises the child is reaped or will be, so a teardown that left it uncollected (a kill
/// refused and the child running, a look or a wait that failed) is not `Ended`: it is `Uncollected`,
/// and says what the teardown found, as the one warn the caller logs. A collected child is `Ended`,
/// with the teardown's fate.
///
/// Each row carries the expectation its path would have: an uncollected child that is not running
/// was left by a failed look or wait, which only a caller that knows a look failed can come to, and
/// that caller's past is `WaitMayFail`; any other teardown's is what a caller that knows no look
/// failed has, `Clean`.
///
/// Mutants: every teardown answers `Ended`; an uncollected one answers a collected child's fate;
/// the `Left` carries another expectation than the teardown's; `Ended` carries another fate than
/// the teardown's.
#[skuld::test]
fn an_abandoned_child_is_ended_only_if_its_teardown_collected_it() {
    for row in rows() {
        let outcome = outcome(&row, Disposition::Leave);
        let past = if row.uncollected && !matches!(outcome.fate(), ChildFate::Running { .. }) {
            Past::WaitMayFail
        } else {
            Past::Clean
        };
        // The pidfd's allowance is its constructor's: a refusal of permission alone.
        let expect = Expect {
            refusal: KillRefusal::Permission,
            past,
        };
        let torn = HandleTeardown::new(outcome, expect);
        let remains = torn.outcome.remains();
        let answer = Abandoned::of_teardown(torn, &mut Diagnosis::default());
        if row.uncollected {
            assert_eq!(
                answer,
                Abandoned::Uncollected(Left {
                    clause: row.leave.clone(),
                    remains,
                    expect,
                }),
                "{:?} {:?}",
                row.kill,
                row.found
            );
        } else {
            assert_eq!(answer, Abandoned::Ended(remains.fate), "{:?} {:?}", row.kill, row.found);
        }
    }
}

/// What the abandonment found wrong on the way (a refused group kill) leads the one warn of a child
/// its teardown left uncollected, and is not owed again.
///
/// Mutant: the finding is dropped, or left owed beside the clause (a second warn).
#[skuld::test]
fn a_finding_on_the_way_leads_the_one_warn_of_an_uncollected_child() {
    let row = rows()
        .into_iter()
        .find(|row| row.uncollected && matches!(outcome(row, Disposition::Leave).fate(), ChildFate::Running { .. }))
        .expect("a row that leaves a running child");
    let expect = Expect {
        refusal: KillRefusal::Permission,
        past: Past::Clean,
    };
    let mut why = Diagnosis::default();
    why.add("the group kill was refused");

    let answer = Abandoned::of_teardown(HandleTeardown::new(outcome(&row, Disposition::Leave), expect), &mut why);

    let Abandoned::Uncollected(left) = answer else {
        panic!("{answer:?}");
    };
    assert_eq!(left.clause, format!("the group kill was refused; {}", row.leave));
    assert!(!why.is_owed(), "the finding was folded in, not left to be logged again");
}
