//! A tree walk over a failed ToolHelp snapshot errors and terminates nothing, and never walks from
//! a root that no longer holds its pid. Windows only: the seam is `enumerate::backend_fault`.

use crate::containment::enumerate::backend_fault::force_snapshot_failure;
use crate::error::Error;
use crate::identity::ProcessId;
use crate::test_child::{live_findstr_blocker as live_member, open_live, release_findstr_unterminated as release};
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
    type Walk = fn(&crate::Process) -> Result<(), Error>;
    let walks: [(&str, Walk); 2] = [
        ("hard_kill", |p| super::hard_kill(&crate::identity::HostKernel, p.id())),
        ("kill_tree", |p| p.kill_tree()),
    ];
    for (name, walk) in walks {
        let (child, id) = live_member();
        let process = open_live(id);
        let forced = force_snapshot_failure();
        let result = walk(&process);
        drop(forced);
        assert_names_toolhelp(result, name);
        release(child);
    }
}

/// Mutant: "`children` maps the snapshot's error to `Ok(vec![])`".
#[skuld::test]
fn children_over_a_failed_snapshot_are_unassessable() {
    let me = ProcessId::current();
    let forced = force_snapshot_failure();
    let results = [
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
    let stale = me.with_other_value();
    let (child, _) = live_member();
    super::hard_kill(&crate::identity::HostKernel, stale).expect("a root that lost its pid is nothing to do");
    release(child);
}

/// The `Unassessable` source of a failed snapshot is the plain Win32 code (here the seam's
/// `ERROR_ACCESS_DENIED`), so `kind()` classifies it. Mutant: `snapshot_failed` converts with the
/// `windows` crate's own `io::Error` conversion, which keeps the HRESULT (`0x80070005`).
#[skuld::test]
fn a_failed_snapshot_is_unassessable_with_its_win32_code() {
    let me = ProcessId::current();
    let forced = force_snapshot_failure();
    let result = me.children(Recursive::No);
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
