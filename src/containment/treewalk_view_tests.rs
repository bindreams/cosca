//! A tree walk whose `/proc` view cannot be trusted errors instead of walking an empty snapshot,
//! and never walks from a root that no longer holds its pid. Linux only: the view seam is
//! `identity::proc_view_fault`.
//!
//! A live root must come out of every failing walk unsignalled: [`release`] proves it by its exit
//! status.

use crate::error::Error;
use crate::identity::proc_view_fault::{
    force_openat2_errno, force_proc_view_after, force_proc_view_once, proc_view_fired_at, ForcedView,
};
use crate::identity::ProcessId;
use crate::test_child::{live_exiting_member as live_member, release_unsignalled as release};
use crate::Recursive;

/// An identity for this process's pid that this process no longer holds: its children are the
/// children of the pid's new owner.
fn stale_root() -> ProcessId {
    let me = ProcessId::current();
    ProcessId::from_parts_for_test(me.pid(), me.start_token_raw().wrapping_sub(1))
}

fn assert_unassessable_naming(result: Result<(), Error>, cause: &str) {
    match result {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(detail.contains(cause), "the error must name {cause:?}: {detail}");
        }
        other => panic!("expected Unassessable naming {cause:?}, got {other:?}"),
    }
}

fn views() -> [(ForcedView, &'static str); 2] {
    [
        (ForcedView::Diverged, "outer pid namespace"),
        (ForcedView::Unassessable, "forced by a test"),
    ]
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

// An untrusted view =====

/// Mutant: "`process_parents` yields an empty snapshot when the view is not `Same`", or "signal
/// the root, then return the error": the walk reports success, or kills the root.
#[test]
fn every_walk_over_an_untrusted_view_errors_and_signals_nothing() {
    for (name, walk) in walks() {
        for (view, cause) in views() {
            let (child, id) = live_member();
            let forced = force_proc_view_once(view);
            let result = walk(id);
            drop(forced);
            assert!(
                matches!(&result, Err(Error::Unassessable { detail, .. }) if detail.contains(cause)),
                "{name}: {result:?}"
            );
            release(child);
        }
    }
}

/// Without `openat2` every walk errors `Unsupported` naming the requirement, and signals nothing.
/// Mutants: "map the snapshot's error to `Unassessable`" in `hard_kill`, `terminate`, or the
/// snapshot itself.
#[test]
fn every_walk_without_openat2_is_unsupported_naming_it() {
    for (name, walk) in walks() {
        for (errno, code) in [(rustix::io::Errno::NOSYS, "ENOSYS"), (rustix::io::Errno::PERM, "EPERM")] {
            let (child, id) = live_member();
            let forced = force_openat2_errno(errno);
            let result = walk(id);
            drop(forced);
            match result {
                Err(Error::Unsupported { detail, .. }) => {
                    assert_eq!(detail, crate::identity::openat2_refused_message(code), "{name} {errno}")
                }
                other => panic!("{name} {errno}: expected Unsupported, got {other:?}"),
            }
            release(child);
        }
    }
}

/// `parent` and `children` are `Unsupported` naming `openat2`, never "none". Mutant: "map the
/// error to `Ok(None)` / `Ok(vec![])`".
#[test]
fn parent_and_children_without_openat2_are_unsupported_naming_it() {
    let me = crate::Process::from_id(ProcessId::current());
    for (errno, code) in [(rustix::io::Errno::NOSYS, "ENOSYS"), (rustix::io::Errno::PERM, "EPERM")] {
        let forced = force_openat2_errno(errno);
        let results = [
            ("parent", me.parent().map(|_| ())),
            ("children(No)", me.children(Recursive::No).map(|_| ())),
            ("children(Yes)", me.children(Recursive::Yes).map(|_| ())),
        ];
        drop(forced);
        for (name, result) in results {
            match result {
                Err(Error::Unsupported { detail, .. }) => {
                    assert_eq!(detail, crate::identity::openat2_refused_message(code), "{name} {errno}")
                }
                other => panic!("{name} {errno}: expected Unsupported, got {other:?}"),
            }
        }
    }
}

// The snapshot precedes the anchor =====

fn queries() -> [(&'static str, fn(&crate::Process) -> Result<(), Error>); 3] {
    [
        ("parent", |p| p.parent().map(|_| ())),
        ("children(No)", |p| p.children(Recursive::No).map(|_| ())),
        ("children(Yes)", |p| p.children(Recursive::Yes).map(|_| ())),
    ]
}

/// The snapshot is the first view read, so the anchor that follows it vouches for the pid across
/// the whole snapshot. Mutant: "the anchor is checked before the snapshot" - the forced view lands
/// on the anchor and the error blames the wrong read.
#[test]
fn parent_and_children_take_the_snapshot_before_the_anchor() {
    let me = crate::Process::from_id(ProcessId::current());
    for (name, query) in queries() {
        for (view, cause) in views() {
            let forced = force_proc_view_once(view);
            let result = query(&me);
            assert_eq!(
                proc_view_fired_at(),
                Some(0),
                "{name}: the snapshot is the first view read"
            );
            drop(forced);
            assert_unassessable_naming(result, &format!("the process snapshot could not be taken: {cause}"));
        }
    }
}

/// The anchor failing after a good snapshot names the view that failed it (the one the failing read
/// used, not a second look), and the pid. Mutants: "`unqueryable` re-derives the cause" (the view
/// has recovered by then, so the error blames access); "the table read's error is dropped".
#[test]
fn an_anchor_read_that_fails_names_the_view_that_failed_it() {
    let me = crate::Process::from_id(ProcessId::current());
    let pid = me.id().pid();
    for (name, query) in queries() {
        for (view, cause) in views() {
            let forced = force_proc_view_after(1, view);
            let result = query(&me);
            assert_eq!(
                proc_view_fired_at(),
                Some(1),
                "{name}: the anchor is the second view read"
            );
            drop(forced);
            assert_unassessable_naming(result, &format!("pid {pid} identity could not be read: {cause}"));
        }
    }
}

// The anchor guards the walk =====

/// A root that no longer holds its pid has no descendants: its pid's new owner's children are not
/// its own, and are never signalled. Mutant: "walk without an anchor".
#[test]
fn every_walk_from_a_root_that_lost_its_pid_is_ok_and_signals_nothing() {
    for (name, walk) in walks() {
        let (child, _) = live_member();
        let result = walk(stale_root());
        assert!(result.is_ok(), "{name}: {result:?}");
        release(child);
    }
}

/// A root whose pid cannot be queried is an error naming the pid and the view, with nothing
/// signalled. Mutants: "an unqueryable root is treated as gone"; "the anchor is skipped".
#[test]
fn every_walk_from_a_root_that_cannot_be_queried_errors_and_signals_nothing() {
    for (name, walk) in walks() {
        let (child, id) = live_member();
        let forced = force_proc_view_after(1, ForcedView::Unassessable);
        let result = walk(id);
        assert_eq!(
            proc_view_fired_at(),
            Some(1),
            "{name}: the anchor is the second view read"
        );
        drop(forced);
        assert_unassessable_naming(
            result,
            &format!("pid {} identity could not be read: forced by a test", id.pid()),
        );
        release(child);
    }
}

// A live process missing from the table =====

/// This process is live, so a table without it is not "no parent" / "no children": the entry was
/// omitted, not the process gone. `EACCES` makes the scan skip every pid, `self` included.
/// Mutant: "a `self` missing from the table is `Ok(None)` / `Ok(vec![])`".
#[test]
fn a_live_self_missing_from_the_table_is_unassessable() {
    let me = crate::Process::from_id(ProcessId::current());
    let _forced = crate::identity::pid_stat::fault::force_stat_read(libc::EACCES, None);
    for (_, query) in queries() {
        assert_unassessable_naming(query(&me), &format!("pid {} is live but absent", me.id().pid()));
    }
}
