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

/// Without `openat2` every walk that enumerates errors `Unsupported` naming the requirement, and
/// signals nothing. Mutants: "map the snapshot's error to `Unassessable`" in `hard_kill`, in
/// `terminate`, or in the snapshot itself.
#[test]
fn every_walk_without_openat2_is_unsupported_naming_it() {
    use crate::identity::proc_view_fault::force_openat2_errno;
    type Walk = fn(ProcessId) -> Result<(), Error>;
    let walks: [(&str, Walk); 4] = [
        ("hard_kill", |id| super::hard_kill(id)),
        ("terminate", |id| super::terminate(id)),
        ("kill_tree", |id| crate::Process::from_id(id).kill_tree()),
        ("terminate_tree", |id| crate::Process::from_id(id).terminate_tree()),
    ];
    for (name, walk) in walks {
        for (errno, code) in [(rustix::io::Errno::NOSYS, "ENOSYS"), (rustix::io::Errno::PERM, "EPERM")] {
            let (mut child, id) = live_member();
            let forced = force_openat2_errno(errno);
            let result = walk(id);
            drop(forced);
            match result {
                Err(Error::Unsupported { detail, .. }) => assert_eq!(
                    detail,
                    format!("cosca requires openat2 (Linux \u{2265} 5.6), refused here: openat2 answered {code}"),
                    "{name} {errno}"
                ),
                other => panic!("{name} {errno}: expected Unsupported, got {other:?}"),
            }
            assert!(
                child.try_wait().expect("try_wait").is_none(),
                "{name} {errno}: nothing may be signalled"
            );
            release(child);
        }
    }
}

/// `parent` and `children` error, never answer "none", where the answer cannot be established:
/// `Unsupported` naming `openat2`, whether the anchor read (this pid's `exists()` answers
/// `Unknown`) or the table read is what fails. Mutants: "map the error to `Ok(None)` /
/// `Ok(vec![])`" at the anchor, or at the table read.
#[test]
fn parent_and_children_without_openat2_are_unsupported_naming_it() {
    use crate::identity::proc_view_fault::force_openat2_errno;
    use crate::Recursive;
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
                Err(Error::Unsupported { detail, .. }) => assert!(
                    detail.contains(&format!("refused here: openat2 answered {code}")),
                    "{name} {errno}: {detail}"
                ),
                other => panic!("{name} {errno}: expected Unsupported, got {other:?}"),
            }
        }
    }
}

/// An untrusted `/proc` view is `Unassessable`, not "no parent" / "no children". The view is
/// forced once, so the anchor read may take it; either read failing must surface. Mutant: "map
/// the error to `Ok(None)` / `Ok(vec![])`".
#[test]
fn parent_and_children_over_an_untrusted_view_are_unassessable() {
    use crate::Recursive;
    let me = crate::Process::from_id(ProcessId::current());
    for (view, _) in views() {
        let forced = force_proc_view_once(view);
        let result = me.parent().map(|_| ());
        drop(forced);
        assert!(matches!(result, Err(Error::Unassessable { .. })), "parent: {result:?}");
        for recursive in [Recursive::No, Recursive::Yes] {
            let forced = force_proc_view_once(view);
            let result = me.children(recursive).map(|_| ());
            drop(forced);
            assert!(
                matches!(result, Err(Error::Unassessable { .. })),
                "children({recursive:?}): {result:?}"
            );
        }
    }
}

/// The table read alone failing, the anchor having passed, still errors and names the view.
/// Mutant: "`process_parents()?` becomes `unwrap_or_default()`" in `parent` / `children`, which
/// the tests above cannot see because their anchor read fails first.
#[test]
fn parent_and_children_error_when_only_the_table_read_fails() {
    use crate::identity::proc_view_fault::force_proc_view_after;
    use crate::Recursive;
    let me = crate::Process::from_id(ProcessId::current());
    for (view, cause) in views() {
        // The anchor's `exists()` reads the view once; the table read is the next.
        let forced = force_proc_view_after(1, view);
        let result = me.parent().map(|_| ());
        drop(forced);
        assert_unassessable_naming(result, cause);
        for recursive in [Recursive::No, Recursive::Yes] {
            let forced = force_proc_view_after(1, view);
            let result = me.children(recursive).map(|_| ());
            drop(forced);
            assert_unassessable_naming(result, cause);
        }
    }
}
