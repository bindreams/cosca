//! A tree walk whose `/proc` view cannot be trusted errors instead of walking an empty snapshot.
//! Linux only: the view seam is `identity::proc_view_fault`.
//!
//! Each test forces the view for the walk's snapshot, then checks that the walk returned
//! `Unassessable` and that a live root was NOT signalled. Mutant: "`process_parents` yields an
//! empty snapshot when the view is not `Same`" — the walk then reports success having signalled
//! nothing.

use std::process::Child;

use crate::error::Error;
use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};
use crate::identity::ProcessId;
use crate::test_child::{await_member_ready, member_command};

/// A live child that blocks until its stdin closes (dropping the returned `Child` handle's pipe
/// releases it), and its identity.
fn live_member() -> (Child, ProcessId) {
    let mut child = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn the member");
    await_member_ready(&mut child);
    let id = ProcessId::of(child.id()).found().expect("the live member resolves");
    (child, id)
}

fn assert_unassessable_naming(result: Result<(), Error>, cause: &str) {
    match result {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(detail.contains(cause), "the error must name {cause:?}: {detail}");
        }
        other => panic!("a walk over an untrusted /proc view must be Unassessable, got {other:?}"),
    }
}

fn release(mut child: Child) {
    drop(child.stdin.take()); // EOF ends the member's `read`
    child.wait().expect("reap the member");
}

fn views() -> [(ForcedView, &'static str); 2] {
    [
        (ForcedView::Diverged, "outer pid namespace"),
        (ForcedView::Unassessable, "forced by a test"),
    ]
}

#[test]
fn hard_kill_errors_instead_of_killing_nothing_when_the_view_is_untrusted() {
    for (view, cause) in views() {
        let (mut child, id) = live_member();
        let forced = force_proc_view_once(view);
        let result = super::hard_kill(id);
        drop(forced);
        assert_unassessable_naming(result, cause);
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "no signal may be sent on a walk that could not enumerate"
        );
        release(child);
    }
}

#[test]
fn terminate_errors_instead_of_signalling_nothing_when_the_view_is_untrusted() {
    for (view, cause) in views() {
        let (mut child, id) = live_member();
        let forced = force_proc_view_once(view);
        let result = super::terminate(id);
        drop(forced);
        assert_unassessable_naming(result, cause);
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "SIGTERM must not be sent"
        );
        release(child);
    }
}

#[test]
fn a_foreign_kill_tree_errors_when_the_view_is_untrusted() {
    for (view, cause) in views() {
        let (mut child, id) = live_member();
        let process = crate::Process::from_id(id);
        let forced = force_proc_view_once(view);
        let result = process.kill_tree();
        drop(forced);
        assert_unassessable_naming(result, cause);
        assert!(child.try_wait().expect("try_wait").is_none(), "nothing may be killed");
        release(child);
    }
}

#[test]
fn a_foreign_terminate_tree_errors_when_the_view_is_untrusted() {
    for (view, cause) in views() {
        let (mut child, id) = live_member();
        let process = crate::Process::from_id(id);
        let forced = force_proc_view_once(view);
        let result = process.terminate_tree();
        drop(forced);
        assert_unassessable_naming(result, cause);
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "nothing may be signalled"
        );
        release(child);
    }
}
