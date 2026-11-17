//! The graceful ops on a nested member, whose caller is itself contained. The checks run in a
//! re-exec of this binary spawned contained, so that its own crate spawn is nested and its thread
//! holds the record of the break it sends (see [`super`]); the driver in
//! `child::ctrl_break_tests` reads only whether the checks finished.

use super::{
    assert_acked, assert_break_sent_to, assert_in_our_console, assert_no_break_sent, connect_reporter,
    kill_release_reap, report_done, spawn_member, Handler,
};
use crate::{Containment, StopTarget};

/// The fully-qualified libtest path of [`fixture_nested_terminate_reporter`].
pub(crate) const REPORTER_TEST: &str = "test_child::ctrl_break::nested::fixture_nested_terminate_reporter";

/// The environment variable carrying the address the reporter reports to.
pub(crate) const ADDR_ENV: &str = "COSCA_FIXTURE_NESTED_TERMINATE_ADDR";

/// Spawns a nested member that acks `CTRL_BREAK`: [`Containment::Delegated`], so it owns no tree
/// teardown, yet it leads a console process group of its own. A `terminate` must reach that group
/// although no tree operation on any handle could, and the nested member's own handler must
/// acknowledge it.
#[skuld::test]
fn fixture_nested_terminate_reporter() {
    let Some(mut report) = connect_reporter(ADDR_ENV) else {
        return;
    };
    let _warns = crate::log_capture::warn_watch();

    let (child, mut sock, _) = spawn_member(Handler::Ack, None, crate::ContainMode::Strongest, |_| {});
    let pid = child.pid();
    assert_eq!(
        child.containment(),
        Containment::Delegated,
        "this process is contained, so its own spawn is nested"
    );
    assert!(StopTarget::from(&child).leads_group_on_our_console());
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

    // Its handler returned "handled", so it still runs; only the kill ends it.
    kill_release_reap(&child, sock, false);

    report_done(&mut report);
}

/// The fully-qualified libtest path of [`fixture_nested_without_group_reporter`].
pub(crate) const NO_GROUP_REPORTER_TEST: &str = "test_child::ctrl_break::nested::fixture_nested_without_group_reporter";

/// The environment variable carrying the address that reporter reports to.
pub(crate) const NO_GROUP_ADDR_ENV: &str = "COSCA_FIXTURE_NESTED_NO_GROUP_ADDR";

/// Spawns a nested member given `new_process_group(false)`: [`Containment::Delegated`] still, but it
/// leads no group, so `terminate` is refused by naming the setter and sends no break. The member stays
/// in its spawner's group, which is this reporter's: a break the driver sends to the reporter's group
/// reaches it too, so the root's own `terminate` is what stops it.
#[skuld::test]
fn fixture_nested_without_group_reporter() {
    let Some(mut report) = connect_reporter(NO_GROUP_ADDR_ENV) else {
        return;
    };
    let _warns = crate::log_capture::warn_watch();

    let (child, sock, _) = spawn_member(Handler::Ack, None, crate::ContainMode::Strongest, |cmd| {
        _ = cmd.new_process_group(false)
    });
    assert_eq!(
        child.containment(),
        Containment::Delegated,
        "this process is contained, so its own spawn is nested"
    );
    assert!(!StopTarget::from(&child).leads_group_on_our_console());
    let err = child
        .terminate()
        .expect_err("a nested member that leads no group cannot be addressed");
    assert!(
        matches!(&err, crate::error::Error::Unsupported { detail, .. } if detail.contains("Command::new_process_group")),
        "the refusal names the setter: {err:?}"
    );
    assert_no_break_sent();

    kill_release_reap(&child, sock, false);

    report_done(&mut report);
}
