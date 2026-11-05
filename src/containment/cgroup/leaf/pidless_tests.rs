//! The answer for a child that never named itself, from what its teardown through the handshake's
//! pidfd did. The teardowns are the table's own (see
//! [`teardown_lines`](crate::child::owned::owned_tests::teardown_lines)).

use super::Abandoned;
use crate::child::owned::owned_tests::teardown_lines::{outcome, rows};
use crate::child::owned::teardown::Disposition;
use crate::child::spawn::held_teardown::{Expect, Left, PidfdTeardown};

/// `Ended` promises the child is reaped or will be, so a teardown that left it uncollected (a kill
/// refused and the child running, a look or a wait that failed) is not `Ended`: it is `Uncollected`,
/// and says what the teardown found, as the one warn the caller logs. A collected child is `Ended`.
///
/// Mutants: every teardown of a child that never named itself answers `Ended`; an uncollected one
/// answers `OutOfReach`, which says it is out of its leaf's reach.
#[skuld::test]
fn a_child_that_never_named_itself_is_ended_only_if_its_teardown_collected_it() {
    for row in rows() {
        let torn = PidfdTeardown::new(outcome(&row, Disposition::Leave), Expect::Anything);
        let verdict = torn.verdict();
        let answer = Abandoned::after_pidless_teardown(torn);
        if row.uncollected {
            assert_eq!(
                answer,
                Abandoned::Uncollected(Left {
                    clause: row.leave.clone(),
                    verdict
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
