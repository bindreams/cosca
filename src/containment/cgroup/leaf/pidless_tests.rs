//! The answer for a child that never named itself, from what its teardown through the handshake's
//! pidfd did. The teardowns are the table's own (see
//! [`teardown_lines`](crate::child::owned::owned_tests::teardown_lines)).

use super::{pidless_expect, Abandoned};
use crate::child::owned::owned_tests::teardown_lines::{outcome, rows};
use crate::child::owned::teardown::{Disposition, Expect, Left, PidfdTeardown};
use crate::error::ChildFate;

/// `Ended` promises the child is reaped or will be, so a teardown that left it uncollected (a kill
/// refused and the child running, a look or a wait that failed) is not `Ended`: it is `Uncollected`,
/// and says what the teardown found, as the one warn the caller logs. A collected child is `Ended`.
///
/// Mutants: every teardown of a child that never named itself answers `Ended`; an uncollected one
/// answers `OutOfReach`, which says it is out of its leaf's reach.
#[skuld::test]
fn a_child_that_never_named_itself_is_ended_only_if_its_teardown_collected_it() {
    for row in rows() {
        let outcome = outcome(&row, Disposition::Leave);
        // A child left uncollected that is not running was left by a failed look or wait: only a
        // caller that knows a look failed can come to that, and it expects `Anything`.
        let expect = if row.uncollected && !matches!(outcome.fate, ChildFate::Running { .. }) {
            Expect::Anything
        } else {
            Expect::Waited
        };
        let torn = PidfdTeardown::new(outcome, expect);
        let fate = torn.outcome.fate;
        let answer = Abandoned::after_pidless_teardown(torn);
        if row.uncollected {
            assert_eq!(
                answer,
                Abandoned::Uncollected(Left {
                    clause: row.leave.clone(),
                    fate,
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

/// A teardown through the handshake's pidfd expects what the handshake handed over; one through the
/// child's own intent pidfd expects anything: nothing there shows that the child never ran the
/// program or that no look failed.
///
/// Mutant: the child's own pidfd expects `Unexecuted` or `Waited`, which assert that its kill is not
/// refused or that its wait does not fail.
#[skuld::test]
fn a_child_that_never_named_itself_expects_what_its_pidfds_holder_knows() {
    assert_eq!(pidless_expect(None), Expect::Anything);
    for handed in [Expect::Anything, Expect::Waited, Expect::Unexecuted] {
        assert_eq!(pidless_expect(Some(handed)), handed);
    }
}
