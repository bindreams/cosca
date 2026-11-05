//! A tree walk whose `/proc` view cannot be trusted errors instead of walking an empty snapshot,
//! and never walks from a root that no longer holds its pid. Linux only: the view is a
//! [`FakeKernel`]'s `self/status` row.
//!
//! A live root must come out of every failing walk unsignalled: [`release`] proves it by its exit
//! status.

use crate::error::Error;
use crate::identity::{FakeKernel, HostKernel, Kernel, ProcessId, UNREADABLE_STATUS_REASON};
use crate::test_child::{live_exiting_member as live_member, release_unsignalled as release};
use crate::Recursive;

/// An identity for this process's pid that this process no longer holds: its children are the
/// children of the pid's new owner.
fn stale_root() -> ProcessId {
    let me = ProcessId::current();
    ProcessId::from_parts_for_test(me.pid(), me.start_token_raw().wrapping_sub(1))
}

fn assert_unassessable_naming(result: Result<(), Error>, causes: &[&str]) {
    match result {
        Err(Error::Unassessable { detail, .. }) => {
            for cause in causes {
                assert!(detail.contains(cause), "the error must name {cause:?}: {detail}");
            }
        }
        other => panic!("expected Unassessable naming {causes:?}, got {other:?}"),
    }
}

/// How a view fails, and what its error names.
#[derive(Clone, Copy)]
enum View {
    Diverged,
    Unreadable,
}

impl View {
    /// `kernel` whose `self/status` reads fail this way from the read that follows `earlier` reads.
    fn fail<'a>(self, kernel: FakeKernel<'a>, earlier: usize) -> FakeKernel<'a> {
        match self {
            View::Diverged => kernel.on_read_after("self/status", earlier, Ok(b"NSpid:\t4242\t1\n")),
            View::Unreadable => kernel.on_read_after("self/status", earlier, Err(libc::EIO)),
        }
    }

    fn cause(self) -> &'static str {
        match self {
            View::Diverged => "outer pid namespace",
            View::Unreadable => UNREADABLE_STATUS_REASON,
        }
    }
}

const VIEWS: [View; 2] = [View::Diverged, View::Unreadable];

type Walk = fn(&dyn Kernel, ProcessId) -> Result<(), Error>;

fn walks() -> [(&'static str, Walk); 2] {
    [
        ("hard_kill", |k, id| super::hard_kill(k, id).map(|_| ())),
        ("terminate", |k, id| super::terminate(k, id)),
    ]
}

// An untrusted view =====

/// Mutant: "`process_parents` yields an empty snapshot when the view is not `Same`", or "signal
/// the root, then return the error": the walk reports success, or kills the root.
#[skuld::test]
fn every_walk_over_an_untrusted_view_errors_and_signals_nothing() {
    for (name, walk) in walks() {
        for view in VIEWS {
            let (child, id) = live_member();
            let kernel = view.fail(FakeKernel::over(&HostKernel), 0);
            let result = walk(&kernel, id);
            assert!(
                matches!(&result, Err(Error::Unassessable { detail, .. }) if detail.contains(view.cause())),
                "{name}: {result:?}"
            );
            release(child);
        }
    }
}

// The snapshot precedes the anchor =====

type Query = fn(&ProcessId, &dyn Kernel) -> Result<(), Error>;

fn queries() -> [(&'static str, Query); 3] {
    [
        ("parent", |p, k| p.parent_with(k).map(|_| ())),
        ("children(No)", |p, k| p.children_with(k, Recursive::No).map(|_| ())),
        ("children(Yes)", |p, k| p.children_with(k, Recursive::Yes).map(|_| ())),
    ]
}

/// The snapshot is the first view read, so the anchor that follows it vouches for the pid across
/// the whole snapshot. Mutant: "the anchor is checked before the snapshot" - the failing view lands
/// on the anchor and the error blames the wrong read.
#[skuld::test]
fn parent_and_children_take_the_snapshot_before_the_anchor() {
    let me = ProcessId::current();
    for (_, query) in queries() {
        for view in VIEWS {
            let kernel = view.fail(FakeKernel::over(&HostKernel), 0);
            let result = query(&me, &kernel);
            assert_unassessable_naming(result, &["the process snapshot could not be taken", view.cause()]);
        }
    }
}

/// The anchor failing after a good snapshot names the view that failed it (the one the failing read
/// used, not a second look), and the pid. Mutants: "`unqueryable` re-derives the cause" (the view
/// has recovered by then, so the error blames access); "the table read's error is dropped".
#[skuld::test]
fn an_anchor_read_that_fails_names_the_view_that_failed_it() {
    let me = ProcessId::current();
    let pid = me.pid();
    for (_, query) in queries() {
        for view in VIEWS {
            let kernel = view.fail(FakeKernel::over(&HostKernel).same_view(), 1);
            let result = query(&me, &kernel);
            assert_unassessable_naming(
                result,
                &[&format!("pid {pid} identity could not be read"), view.cause()],
            );
        }
    }
}

// The anchor guards the walk =====

/// A root that no longer holds its pid has no descendants: its pid's new owner's children are not
/// its own, and are never signalled. Mutant: "walk without an anchor".
#[skuld::test]
fn every_walk_from_a_root_that_lost_its_pid_is_ok_and_signals_nothing() {
    for (name, walk) in walks() {
        let (child, _) = live_member();
        let result = walk(&HostKernel, stale_root());
        assert!(result.is_ok(), "{name}: {result:?}");
        release(child);
    }
}

/// A root whose pid cannot be queried is an error naming the pid and the view, with nothing
/// signalled. Mutants: "an unqueryable root is treated as gone"; "the anchor is skipped".
#[skuld::test]
fn every_walk_from_a_root_that_cannot_be_queried_errors_and_signals_nothing() {
    for (_, walk) in walks() {
        let (child, id) = live_member();
        let kernel = View::Unreadable.fail(FakeKernel::over(&HostKernel).same_view(), 1);
        let result = walk(&kernel, id);
        assert_unassessable_naming(
            result,
            &[
                &format!("pid {} identity could not be read", id.pid()),
                UNREADABLE_STATUS_REASON,
            ],
        );
        release(child);
    }
}

// A live process missing from the table =====

/// This process is live, so a table without it is not "no parent" / "no children": the entry was
/// omitted, not the process gone. `EACCES` on the scan's read of `self` makes it skip this pid; the
/// anchor's read after it succeeds. Mutant: "a `self` missing from the table is `Ok(None)` /
/// `Ok(vec![])`".
#[skuld::test]
fn a_live_self_missing_from_the_table_is_unassessable() {
    let me = ProcessId::current();
    let stat = std::fs::read("/proc/self/stat").expect("this process's stat");
    let path = format!("{}/stat", me.pid());
    for (_, query) in queries() {
        let kernel =
            FakeKernel::listing_unreadable_pid(&HostKernel, me.pid(), libc::EACCES).on_read_after(&path, 1, Ok(&stat));
        assert_unassessable_naming(query(&me, &kernel), &[&format!("pid {} is live but absent", me.pid())]);
    }
}
