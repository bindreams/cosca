use crate::error::Error;
use crate::identity::{HostKernel, ProcessId, Resolved};
#[cfg(unix)]
use crate::test_child::{live_exiting_member as live_member, release_unsignalled as release};
#[cfg(windows)]
use crate::test_child::{live_findstr_blocker as live_member, release_findstr_unterminated as release};
use crate::Recursive;

/// An unassessable anchor is an error, not the empty answer a gone one gives.
#[cfg(windows)]
#[skuld::test]
fn parent_and_children_of_an_unassessable_anchor_are_unassessable() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(parent_and_children_of_an_unassessable_anchor_are_unassessable),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let child = crate::identity::windows_fixture::spawn_restricted(&done, PROCESS_SYNCHRONIZE.0);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Unknown,
        "precondition: unassessable"
    );
    assert!(matches!(id.parent(), Err(Error::Unassessable { .. })));
    for recursive in [Recursive::No, Recursive::Yes] {
        assert!(matches!(id.children(recursive), Err(Error::Unassessable { .. })));
    }
}

/// The ppid branch, distinct from the anchor branch: the subject resolves fine, but its
/// PARENT is access-denied. Built by having the restricted fixture itself be the parent - a
/// DACL is not inherited, so `cmd.exe` is unopenable while the `ping` it spawns is not.
#[cfg(windows)]
#[skuld::test]
fn parent_of_a_process_whose_parent_is_access_denied_is_unassessable_naming_the_ppid() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(
            parent_of_a_process_whose_parent_is_access_denied_is_unassessable_naming_the_ppid
        ),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let parent = crate::identity::windows_fixture::spawn_restricted_shell(&done, PROCESS_SYNCHRONIZE.0);
    let kid_pid = parent.wait_for_child();
    assert!(parent.is_running(), "precondition: the denied parent must be live");
    let crate::identity::Resolved::Found(kid) = ProcessId::of(kid_pid) else {
        panic!("the grandchild is not DACL-restricted, so it must resolve");
    };
    assert_eq!(
        ProcessId::of(parent.pid()),
        crate::identity::Resolved::Unknown,
        "precondition: the parent must be unassessable"
    );
    match kid.parent() {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(detail.contains(&format!("ppid {}", parent.pid())), "{detail}");
        }
        other => panic!("an unassessable ppid must be Unassessable, got {other:?}"),
    }
}

/// A gone or recycled anchor is a real "nothing": `Ok`, not an error. Mutant: "an error for a
/// gone anchor".
#[skuld::test]
fn parent_and_children_of_a_gone_anchor_are_ok_and_empty() {
    let real = ProcessId::current();
    let stale = real.with_other_value();
    assert!(matches!(stale.parent(), Ok(None)));
    for recursive in [Recursive::No, Recursive::Yes] {
        assert_eq!(stale.children(recursive).expect("gone is not an error"), Vec::new());
    }
}

// Unknown reads without a view to blame (Unix) =====

/// A live pid whose identity read is refused (`hidepid`, a sandbox) is not absent: `Unassessable`
/// blaming access. Mutant: "an unqueryable anchor is `Ok(None)` / `Ok(vec![])`".
#[cfg(unix)]
#[skuld::test]
fn an_anchor_that_is_access_denied_is_unassessable_blaming_access() {
    let (child, id) = live_member();
    // The `/proc` path: the anchor's `starttime` is its identity, so a refused `stat` is a refused
    // identity. (A pidfs anchor's identity needs no `/proc`; see `tree_pidfs_tests`.)
    #[cfg(target_os = "linux")]
    let id = crate::identity::ticks_id(id.pid());
    let (kernel, _guard) = crate::identity::unreadable(id.pid());
    let expected = format!("pid {} exists but could not be queried", id.pid());
    for result in [
        id.parent_with(&kernel).map(|_| ()),
        id.children_with(&kernel, Recursive::No).map(|_| ()),
        id.children_with(&kernel, Recursive::Yes).map(|_| ()),
    ] {
        match result {
            Err(Error::Unassessable { detail, .. }) => assert!(detail.contains(&expected), "{detail}"),
            other => panic!("expected Unassessable, got {other:?}"),
        }
    }
    release(child);
}

/// The parent being access-denied is `Unassessable` naming the ppid, not "no parent". Mutant: "an
/// unknown ppid reads as no parent".
#[cfg(unix)]
#[skuld::test]
fn a_parent_that_is_access_denied_is_unassessable_naming_the_ppid() {
    let (child, id) = live_member();
    let me = std::process::id();
    let (kernel, _guard) = crate::identity::unreadable(me);
    match id.parent_with(&kernel) {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(
                detail.contains(&format!("ppid {me} exists but could not be queried")),
                "{detail}"
            )
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
    release(child);
}

/// A spawned child's parent is this process: `parent` reads the child again under the parent it
/// found, which must name that parent on every platform. Mutant: the check of the child's own
/// parent rejects the real one.
#[skuld::test]
fn the_parent_of_a_spawned_child_is_the_current_process() {
    let (child, kid) = live_member();
    let parent = kid.parent().expect("the parent is readable");
    release(child);
    assert_eq!(parent, Some(ProcessId::current()));
}

/// A live process that did not create the candidate is not its parent, though it is a real process
/// holding a real pid: the candidate's own parent number is read, not the listing's claim.
///
/// Mutant: `of_ordered_with` ignores `parent`.
#[skuld::test]
fn a_candidate_is_gone_under_a_parent_that_did_not_create_it() {
    let (x_child, x) = live_member();
    let (y_child, y) = live_member();
    let (read, _) = ProcessId::of_ordered_with(&HostKernel, y.pid(), Some(x));
    release(y_child);
    release(x_child);
    assert_eq!(read, Resolved::Gone);
}

/// The candidate's parent number is right but another process holds it: the proof of the parent
/// after the read fails.
///
/// Mutant: the parent is not proved again after the candidate's read.
#[skuld::test]
fn a_candidate_is_gone_under_the_right_parent_pid_with_another_key() {
    let (child, kid) = live_member();
    let (read, _) = ProcessId::of_ordered_with(&HostKernel, kid.pid(), Some(ProcessId::current().with_other_value()));
    release(child);
    assert_eq!(read, Resolved::Gone);
}

/// The candidate's parent number is right but its parent cannot be proved: `Unknown`, blaming the
/// parent and not the candidate. Windows has its own row, in `windows_tests`, whose parent is a
/// process that grants no query right.
///
/// Mutant: an unprovable parent reads as held (`Found`) or as gone, or blames the candidate.
#[cfg(unix)]
#[skuld::test]
fn a_candidate_is_unknown_when_its_parent_cannot_be_proved() {
    let (child, kid) = live_member();
    let me = std::process::id();
    // On Linux the parent is a `ticks` id: a `pidfs` id is proved by its pidfd, without `/proc`, so
    // a refused `stat` would not make its proof fail.
    #[cfg(target_os = "linux")]
    let parent = crate::identity::ticks_id(me);
    #[cfg(not(target_os = "linux"))]
    let parent = ProcessId::current();
    let (kernel, _guard) = crate::identity::unreadable(me);
    let (read, cause) = ProcessId::of_ordered_with(&kernel, kid.pid(), Some(parent));
    release(child);
    assert_eq!(read, Resolved::Unknown);
    assert_eq!(cause.blamed_parent(), Some(me));
}

/// A process that has exited while its handle is held still has its creator: Toolhelp does not list
/// it (measured on Windows 11 26100.9711), so `parent` reads the number from the process's own
/// handle, not from the snapshot, and is not an error for a row that is not there.
///
/// Mutant: `parent` takes the parent number from the snapshot row.
#[cfg(windows)]
#[skuld::test]
fn the_parent_of_an_exited_process_whose_handle_is_held_is_its_creator() {
    let (mut child, id) = live_member();
    // The std `Child` holds the process handle until it is dropped, at the end of the row.
    child.kill().expect("terminate the child");
    child.wait().expect("the child's exit is recorded");
    let parents = crate::containment::enumerate::process_parents(&HostKernel).expect("the process snapshot");
    assert!(
        !parents.iter().any(|&(pid, _)| pid == id.pid()),
        "precondition: Toolhelp must not list the exited process whose handle is held"
    );
    assert_eq!(
        id.parent().expect("the creator is readable"),
        Some(ProcessId::current())
    );
}

/// A spawned child is among the current process's direct children, by identity.
#[skuld::test]
fn children_of_the_current_process_contain_a_spawned_child() {
    let (child, kid) = live_member();
    let direct = ProcessId::current()
        .children(Recursive::No)
        .expect("children are enumerable");
    assert!(direct.contains(&kid), "{kid:?} not among {direct:?}");
    release(child);
}
