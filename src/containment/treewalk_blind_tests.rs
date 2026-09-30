//! A tree walk over a failed macOS process listing errors and signals nothing. macOS only: the
//! seam is `enumerate::backend_fault`.

use crate::containment::enumerate::backend_fault::{force_blind_snapshot, force_denied, force_join_alloc_failure};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::test_child::{live_exiting_member as live_member, release_unsignalled as release};
use crate::Recursive;

fn assert_unassessable_naming(result: Result<(), Error>, cause: &str) {
    match result {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(detail.contains(cause), "the error must name {cause:?}: {detail}")
        }
        other => panic!("expected Unassessable naming {cause:?}, got {other:?}"),
    }
}

type Walk = fn(ProcessId) -> Result<(), Error>;

fn walks() -> [(&'static str, Walk); 4] {
    [
        ("hard_kill", |id| super::hard_kill(id)),
        ("terminate", |id| super::terminate(id)),
        ("kill_tree", |id| crate::Process::from_id(id).kill_tree()),
        ("terminate_tree", |id| crate::Process::from_id(id).terminate_tree()),
    ]
}

type Query = fn(&crate::Process) -> Result<(), Error>;

fn queries() -> [(&'static str, Query); 3] {
    [
        ("parent", |p| p.parent().map(|_| ())),
        ("children(No)", |p| p.children(Recursive::No).map(|_| ())),
        ("children(Yes)", |p| p.children(Recursive::Yes).map(|_| ())),
    ]
}

/// Mutants: "the walk reads an empty snapshot for a failed listing" (`Ok`, nothing found); "signal
/// the root, then return the error".
#[test]
fn every_walk_over_a_failed_listing_errors_and_signals_nothing() {
    for (name, walk) in walks() {
        let (child, id) = live_member();
        let forced = force_blind_snapshot();
        let result = walk(id);
        drop(forced);
        assert!(
            matches!(&result, Err(Error::Unassessable { detail, .. }) if detail.contains("proc_listallpids")),
            "{name}: {result:?}"
        );
        release(child);
    }
}

/// Mutant: "`parent` / `children` map the snapshot's error to `Ok(None)` / `Ok(vec![])`".
#[test]
fn parent_and_children_over_a_failed_listing_are_unassessable() {
    let me = crate::Process::from_id(ProcessId::current());
    for (name, query) in queries() {
        let forced = force_blind_snapshot();
        let result = query(&me);
        drop(forced);
        assert!(
            matches!(&result, Err(Error::Unassessable { detail, .. }) if detail.contains("proc_listallpids")),
            "{name}: {result:?}"
        );
    }
}

/// A pid denied its ppid read leaves its subtree out of any walk, so the snapshot is
/// `Unassessable` naming the count and the pid, and no walk signals. Mutant: "`denied > 0` still
/// returns `Ok`".
#[test]
fn every_walk_over_a_snapshot_with_a_denied_ppid_errors_and_signals_nothing() {
    for (name, walk) in walks() {
        let (child, id) = live_member();
        let forced = force_denied(&[id.pid() as libc::c_int]);
        let result = walk(id);
        drop(forced);
        assert!(
            matches!(&result, Err(Error::Unassessable { detail, .. }) if detail.contains(&format!("sample: [{}]", id.pid()))),
            "{name}: {result:?}"
        );
        release(child);
    }
}

/// Mutant: "`parent` / `children` ignore a denied ppid elsewhere in the table".
#[test]
fn parent_and_children_over_a_snapshot_with_a_denied_ppid_are_unassessable() {
    let (child, id) = live_member();
    let me = crate::Process::from_id(ProcessId::current());
    for (_, query) in queries() {
        let forced = force_denied(&[id.pid() as libc::c_int]);
        let result = query(&me);
        drop(forced);
        assert_unassessable_naming(result, &format!("sample: [{}]", id.pid()));
    }
    release(child);
}

/// An allocation failure joining the edges is `Unassessable` too, not an empty tree. Mutant:
/// "`join_edges`' failure is an empty snapshot".
#[test]
fn every_walk_over_a_failed_edge_allocation_errors_and_signals_nothing() {
    for (name, walk) in walks() {
        let (child, id) = live_member();
        let forced = force_join_alloc_failure();
        let result = walk(id);
        drop(forced);
        assert!(
            matches!(&result, Err(Error::Unassessable { detail, .. }) if detail.contains("edge buffer")),
            "{name}: {result:?}"
        );
        release(child);
    }
}

/// A root that no longer holds its pid has no descendants: its pid's new owner's children are not
/// its own. Mutant: "walk without an anchor".
#[test]
fn every_walk_from_a_root_that_lost_its_pid_is_ok_and_signals_nothing() {
    let me = ProcessId::current();
    let stale = ProcessId::from_parts_for_test(me.pid(), me.start_token_raw().wrapping_sub(1));
    for (name, walk) in walks() {
        let (child, _) = live_member();
        let result = walk(stale);
        assert!(result.is_ok(), "{name}: {result:?}");
        release(child);
    }
}
