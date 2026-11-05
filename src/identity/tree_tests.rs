use crate::error::Error;
use crate::identity::ProcessId;
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
