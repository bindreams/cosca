//! A tree walk over a failed ToolHelp snapshot errors and terminates nothing, and never walks from
//! a root that no longer holds its pid. Windows only: the seam is `enumerate::backend_fault`.

use crate::containment::enumerate::backend_fault::force_snapshot_failure;
use crate::error::Error;
use crate::identity::ProcessId;
use crate::test_child::{live_findstr_blocker as live_member, release_findstr_unterminated as release};
use crate::Recursive;

fn assert_names_toolhelp(result: Result<(), Error>, what: &str) {
    match result {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(detail.contains("CreateToolhelp32Snapshot"), "{what}: {detail}")
        }
        other => panic!("{what}: expected Unassessable, got {other:?}"),
    }
}

/// Mutants: "the walk reads an empty snapshot for a failed one" (`Ok`); "terminate the root, then
/// return the error".
#[skuld::test]
fn every_walk_over_a_failed_snapshot_errors_and_terminates_nothing() {
    type Walk = fn(ProcessId) -> Result<(), Error>;
    let walks: [(&str, Walk); 2] = [
        ("hard_kill", |id| super::hard_kill(id).map(|_| ())),
        ("kill_tree", |id| crate::Process::from_id(id).kill_tree()),
    ];
    for (name, walk) in walks {
        let (child, id) = live_member();
        let forced = force_snapshot_failure();
        let result = walk(id);
        drop(forced);
        assert_names_toolhelp(result, name);
        release(child);
    }
}

/// Mutant: "`parent` / `children` map the snapshot's error to `Ok(None)` / `Ok(vec![])`".
#[skuld::test]
fn parent_and_children_over_a_failed_snapshot_are_unassessable() {
    let me = crate::Process::from_id(ProcessId::current());
    let forced = force_snapshot_failure();
    let results = [
        ("parent", me.parent().map(|_| ())),
        ("children(No)", me.children(Recursive::No).map(|_| ())),
        ("children(Yes)", me.children(Recursive::Yes).map(|_| ())),
    ];
    drop(forced);
    for (name, result) in results {
        assert_names_toolhelp(result, name);
    }
}

/// A root that no longer holds its pid has no descendants: its pid's new owner's children are not
/// its own. Mutant: "walk without an anchor".
#[skuld::test]
fn a_walk_from_a_root_that_lost_its_pid_terminates_nothing() {
    let me = ProcessId::current();
    let stale = ProcessId::from_parts_for_test(me.pid(), me.start_token_raw().wrapping_sub(1));
    let (child, _) = live_member();
    super::hard_kill(stale).expect("a root that lost its pid is nothing to do");
    crate::Process::from_id(stale).kill_tree().expect("likewise");
    release(child);
}

/// The `Unassessable` source of a failed snapshot is the plain Win32 code (here the seam's
/// `ERROR_ACCESS_DENIED`), so `kind()` classifies it. Mutant: `snapshot_failed` converts with the
/// `windows` crate's own `io::Error` conversion, which keeps the HRESULT (`0x80070005`).
#[skuld::test]
fn a_failed_snapshot_is_unassessable_with_its_win32_code() {
    let me = crate::Process::from_id(ProcessId::current());
    let forced = force_snapshot_failure();
    let result = me.parent();
    drop(forced);
    let Err(Error::Unassessable {
        source: Some(source), ..
    }) = result
    else {
        panic!("expected Unassessable with a source, got {result:?}");
    };
    assert_eq!(
        source.raw_os_error(),
        Some(windows::Win32::Foundation::ERROR_ACCESS_DENIED.0 as i32),
        "{source:?}"
    );
    assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied, "{source:?}");
}
