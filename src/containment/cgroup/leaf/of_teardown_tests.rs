//! The answer for an abandoned child, from what its teardown through the handshake's pidfd did.
//! The teardowns are the table's own (see
//! [`teardown_lines`](crate::child::owned::owned_tests::teardown_lines)).

use super::Abandoned;
use crate::child::owned::owned_tests::teardown_lines::{outcome, rows};
use crate::child::owned::teardown::{Disposition, Expect, HandleTeardown, Left, Past};
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
        let answer = Abandoned::of_teardown(torn);
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
