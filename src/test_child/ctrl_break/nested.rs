//! The graceful ops on a nested member, whose caller is itself contained. The checks run in a
//! re-exec of this binary spawned contained, so that its own crate spawn is nested and its thread
//! holds the record of the break it sends (see [`super`]); the driver in
//! `child::ctrl_break_tests` reads only whether the checks finished.

use super::{
    assert_acked, assert_break_sent_to, assert_in_our_console, connect_reporter, report_done, spawn_member, Handler,
};
use crate::{Containment, GracefulMechanism};

/// The fully-qualified libtest path of [`fixture_nested_terminate_reporter`].
pub(crate) const REPORTER_TEST: &str = "test_child::ctrl_break::nested::fixture_nested_terminate_reporter";

/// The environment variable carrying the address the reporter reports to.
pub(crate) const ADDR_ENV: &str = "COSCA_FIXTURE_NESTED_TERMINATE_ADDR";

/// Spawns a nested member that acks `CTRL_BREAK`: [`Containment::Delegated`], so it owns no tree
/// teardown, yet it leads a console process group of its own. A `terminate` must reach that group
/// although no tree operation on any handle could, and the nested member's own handler must
/// acknowledge it.
///
/// Connects to the driver first, so a panic below reaches it as EOF. Writes [`DONE`](super::DONE)
/// last.
#[skuld::test]
fn fixture_nested_terminate_reporter() {
    let Some(mut report) = connect_reporter(ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };

    let (child, mut sock, _) = spawn_member(Handler::Ack, None, crate::ContainMode::Strongest, |_| {});
    let pid = child.id().pid();
    assert_eq!(
        child.containment(),
        Containment::Delegated,
        "this process is contained, so its own spawn is nested"
    );
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    assert_in_our_console(pid, "the nested member");

    // A nested member owns no tree teardown. The refusal comes before any signal, so the one break
    // asserted below is `terminate`'s.
    assert!(
        matches!(child.terminate_tree(), Err(crate::error::Error::Unsupported { .. })),
        "a nested member still owns no tree teardown"
    );
    child.terminate().expect("terminate a nested console-group child");
    assert_break_sent_to(pid);
    assert_acked(&mut sock, "the nested member");

    // Its handler returned "handled", so it still runs; only the kill ends it. Released after the
    // kill, so code 1 is the kill's, not a release (which exits 0).
    child.kill().expect("kill the nested member");
    drop(sock);
    let status = child.wait().expect("reap the nested member");
    assert_eq!(status.code(), Some(1), "the kill must end it, got {status:?}");

    report_done(&mut report);
}
