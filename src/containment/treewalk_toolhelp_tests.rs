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
        ("hard_kill", |p| {
            let hk = &crate::identity::HostKernel;
            super::hard_kill(hk, p.id(), &super::ByIdentity::new(hk, p.id()))
                .outcome()
                .into_result()
                .map_err(crate::containment::dispatch::Unkilled::into_error)
        }),
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
    assert!(
        matches!(
            super::hard_kill(
                &crate::identity::HostKernel,
                stale,
                &super::ByIdentity::new(&crate::identity::HostKernel, stale)
            )
            .outcome(),
            crate::containment::dispatch::TreeKillOutcome::NoRoot(..)
        ),
        "a root that lost its pid is nothing to do"
    );
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
        detail,
        source: Some(source),
    }) = result
    else {
        panic!("expected Unassessable with a source, got {result:?}");
    };
    let Error::Io(source) = &*source else {
        panic!("expected an Io source, got {source:?}");
    };
    assert_eq!(
        detail,
        "the process snapshot could not be taken: CreateToolhelp32Snapshot failed"
    );
    assert_eq!(
        source.raw_os_error(),
        Some(windows::Win32::Foundation::ERROR_ACCESS_DENIED.0 as i32),
        "{source:?}"
    );
    assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied, "{source:?}");
}

/// A walk names the members of its tree for a send that reaches each by itself: the root, then the
/// descendants a walk from its identity finds.
///
/// Mutants: the root is left out; the descendants are.
#[skuld::test]
fn a_walks_member_ids_are_the_root_and_its_descendants() {
    use crate::containment::treewalk::Walker;
    use crate::containment::Contains as _;
    use crate::test_child::ctrl_break::{kill_release_reap, spawn_member, Handler};

    let (child, sock, grand) = spawn_member(
        Handler::Ignore,
        Some(Handler::Ignore),
        crate::ContainMode::TreeWalk,
        |_| {},
    );
    let grand = grand.expect("a grandchild was asked for");
    let root = child.id().expect("the root's identity");
    let descendants = root.children(Recursive::Yes).expect("the descendants of the root");
    assert!(!descendants.is_empty(), "the grandchild is a descendant");

    let members = Walker::over(root, crate::identity::HostKernel)
        .member_ids()
        .expect("the walk lists its members");

    assert_eq!(members.named[0], root, "{members:?}");
    assert_eq!(members.named[1..], descendants[..], "{members:?}");
    drop(grand);
    kill_release_reap(&child, sock, false);
}

/// A walk anchors on the root's held handle, so it still finds the descendants of a root that has
/// exited and is held, and names them; the root is not one of them (it has no windows to ask).
///
/// Mutant: the exited root is listed first, as a running one is.
#[skuld::test]
fn a_walks_member_ids_leave_out_a_root_that_has_exited_and_keep_its_descendants() {
    use crate::containment::treewalk::Walker;
    use crate::containment::Contains as _;
    use crate::identity::Liveness;
    use crate::test_child::ctrl_break::{spawn_member, Handler};

    let (child, sock, grand) = spawn_member(
        Handler::Ignore,
        Some(Handler::Ignore),
        crate::ContainMode::TreeWalk,
        |_| {},
    );
    let grand = grand.expect("a grandchild was asked for");
    let root = child.id().expect("the root's identity");
    let descendants = root.children(Recursive::Yes).expect("the descendants of the root");
    assert!(!descendants.is_empty(), "the grandchild is a descendant");
    child.kill().expect("kill the root alone");
    child.wait().expect("the root has exited, and the child still holds it");
    assert_eq!(root.is_alive(), Liveness::Dead, "premise: the root has exited");

    let members = Walker::over(root, crate::identity::HostKernel)
        .member_ids()
        .expect("the walk lists its members");

    assert_eq!(members.named, descendants);
    drop(sock);
    drop(grand);
}

/// A root that is gone, or whose pid names another process now, names no member: a walk from it finds
/// nothing. The pid here is this process's, with an identity it does not have.
///
/// Mutant: a gone root names itself.
#[skuld::test]
fn a_walks_member_ids_are_none_for_a_root_whose_pid_names_another_process() {
    use crate::containment::treewalk::Walker;
    use crate::containment::Contains as _;
    use crate::identity::Key;

    let another = ProcessId::from_parts_for_test(std::process::id(), Key::for_test(1));
    let walker = Walker::over(another, crate::identity::HostKernel);

    assert_eq!(
        walker.member_ids().expect("a root that is gone lists nothing").named,
        Vec::<ProcessId>::new()
    );
}
