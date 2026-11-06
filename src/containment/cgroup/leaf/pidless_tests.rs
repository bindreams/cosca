//! The answer for a child that never named itself, from what its teardown through the handshake's
//! pidfd did. The teardowns are the table's own (see
//! [`teardown_lines`](crate::child::owned::owned_tests::teardown_lines)).

use super::Abandoned;
use crate::child::owned::owned_tests::teardown_lines::{outcome, rows};
use crate::child::owned::teardown::{Disposition, Expect, HandleTeardown, Left};
use crate::error::ChildFate;

/// `Ended` promises the child is reaped or will be, so a teardown that left it uncollected (a kill
/// refused and the child running, a look or a wait that failed) is not `Ended`: it is `Uncollected`,
/// and says what the teardown found, as the one warn the caller logs. A collected child is `Ended`.
///
/// Each row carries the expectation its path would have: an uncollected child that is not running
/// was left by a failed look or wait, which only a caller that knows a look failed can come to, and
/// that caller expects `Anything`; any other teardown expects what a caller that knows no look
/// failed does, `Waited`.
///
/// Mutants: every teardown of a child that never named itself answers `Ended`; an uncollected one
/// answers `OutOfReach`, which says it is out of its leaf's reach; the `Left` carries another
/// expectation than the teardown's.
#[skuld::test]
fn a_child_that_never_named_itself_is_ended_only_if_its_teardown_collected_it() {
    for row in rows() {
        let outcome = outcome(&row, Disposition::Leave);
        let expect = if row.uncollected && !matches!(outcome.fate(), ChildFate::Running { .. }) {
            Expect::Anything
        } else {
            Expect::Waited
        };
        let torn = HandleTeardown::new(outcome, expect);
        let remains = torn.outcome.remains();
        let answer = Abandoned::after_pidless_teardown(torn);
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
            assert_eq!(answer, Abandoned::Ended, "{:?} {:?}", row.kill, row.found);
        }
    }
}
