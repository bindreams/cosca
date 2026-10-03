use super::Process;
use crate::identity::ProcessId;

#[skuld::test]
fn current_resolves_and_is_alive() {
    let me = Process::current();
    assert_eq!(me.is_alive(), crate::identity::Liveness::Alive);
    assert_eq!(Process::from_id(me.id()), me);
    assert_eq!(
        Process::from_id(me.id()).exists(),
        crate::identity::Existence::Present,
        "the Present case of the method that replaced the constructor's check"
    );
    assert_eq!(Process::from_pid(me.id().pid()), crate::identity::Resolved::Found(me));
}

#[skuld::test]
fn a_recycled_pid_is_reported_by_exists_not_by_the_constructor() {
    // A live pid bearing a DIFFERENT start token is the recycle case: the pid resolves, but
    // its identity does not match the saved one. Built against our own (definitely-live) pid
    // with a token that cannot be the real one.
    let real = ProcessId::current();
    let stale = ProcessId::from_parts_for_test(real.pid(), real.start_token_raw().wrapping_add(1));
    let p = Process::from_id(stale);
    assert_eq!(p.id(), stale, "the identity is kept verbatim");
    assert_eq!(
        p.exists(),
        crate::identity::Existence::Gone,
        "a mismatched start token is not this process"
    );
    assert_eq!(p.is_alive(), crate::identity::Liveness::Dead);
}

#[skuld::test]
fn process_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Process>();
}

#[cfg(windows)]
#[skuld::test]
fn from_pid_is_unknown_for_an_access_denied_process() {
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let child = crate::identity::windows_fixture::spawn_restricted(PROCESS_SYNCHRONIZE.0);
    assert!(child.is_running(), "precondition: the subject must be live");
    assert_eq!(
        Process::from_pid(child.pid()),
        crate::identity::Resolved::Unknown,
        "a live process we may not query must not resolve as Gone"
    );
}

/// A `Process` built from a saved identity reaches Unknown through a different path than
/// `from_pid` - it additionally compares the resolved identity against the caller-s, and that
/// comparison is where an Unknown-into-Gone collapse would hide.
#[cfg(windows)]
#[skuld::test]
fn a_process_built_from_a_denied_identity_is_unknown_not_gone() {
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let child = crate::identity::windows_fixture::spawn_restricted(PROCESS_SYNCHRONIZE.0);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    // The identity survives construction - this is the whole point of an infallible
    // `from_id`: an unelevated supervisor keeps the handle to a service it may not query.
    let p = Process::from_id(id);
    assert_eq!(
        p.exists(),
        crate::identity::Existence::Unknown,
        "denied must not read as Gone"
    );
    assert_eq!(
        p.is_alive(),
        crate::identity::Liveness::Unknown,
        "denied must not read as Dead"
    );
    assert!(child.is_running(), "and it must still have been live throughout");
}

/// An unassessable anchor is an error, not the empty answer a gone one gives.
#[cfg(windows)]
#[skuld::test]
fn parent_and_children_of_an_unassessable_anchor_are_unassessable() {
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let child = crate::identity::windows_fixture::spawn_restricted(PROCESS_SYNCHRONIZE.0);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Unknown,
        "precondition: unassessable"
    );
    let p = Process::from_id(id);
    assert!(matches!(p.parent(), Err(crate::error::Error::Unassessable { .. })));
    for recursive in [crate::Recursive::No, crate::Recursive::Yes] {
        assert!(matches!(
            p.children(recursive),
            Err(crate::error::Error::Unassessable { .. })
        ));
    }
}

/// The ppid branch, distinct from the anchor branch: the subject resolves fine, but its
/// PARENT is access-denied. Built by having the restricted fixture itself be the parent - a
/// DACL is not inherited, so `cmd.exe` is unopenable while the `ping` it spawns is not.
#[cfg(windows)]
#[skuld::test]
fn parent_of_a_process_whose_parent_is_access_denied_is_unassessable_naming_the_ppid() {
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let parent = crate::identity::windows_fixture::spawn_restricted_shell(PROCESS_SYNCHRONIZE.0);
    let kid_pid = parent.wait_for_child();
    assert!(parent.is_running(), "precondition: the denied parent must be live");
    let crate::identity::Resolved::Found(kid) = Process::from_pid(kid_pid) else {
        panic!("the grandchild is not DACL-restricted, so it must resolve");
    };
    assert_eq!(
        ProcessId::of(parent.pid()),
        crate::identity::Resolved::Unknown,
        "precondition: the parent must be unassessable"
    );
    match kid.parent() {
        Err(crate::error::Error::Unassessable { detail, .. }) => {
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
    let stale = ProcessId::from_parts_for_test(real.pid(), real.start_token_raw().wrapping_add(1));
    let p = Process::from_id(stale);
    assert!(matches!(p.parent(), Ok(None)));
    for recursive in [crate::Recursive::No, crate::Recursive::Yes] {
        assert_eq!(p.children(recursive).expect("gone is not an error"), Vec::new());
    }
}

// Unknown reads without a view to blame (Unix) =====

/// A live pid whose identity read is refused (`hidepid`, a sandbox) is not absent: `Unassessable`
/// blaming access. Mutant: "an unqueryable anchor is `Ok(None)` / `Ok(vec![])`".
#[cfg(unix)]
#[skuld::test]
fn an_anchor_that_is_access_denied_is_unassessable_blaming_access() {
    let (child, id) = crate::test_child::live_exiting_member();
    let forced = crate::identity::force_unknown_identity(id.pid());
    let p = Process::from_id(id);
    let expected = format!("pid {} exists but could not be queried", id.pid());
    for result in [
        p.parent().map(|_| ()),
        p.children(crate::Recursive::No).map(|_| ()),
        p.children(crate::Recursive::Yes).map(|_| ()),
    ] {
        match result {
            Err(crate::error::Error::Unassessable { detail, .. }) => assert!(detail.contains(&expected), "{detail}"),
            other => panic!("expected Unassessable, got {other:?}"),
        }
    }
    drop(forced);
    crate::test_child::release_unsignalled(child);
}

/// The parent being access-denied is `Unassessable` naming the ppid, not "no parent". Mutant: "an
/// unknown ppid reads as no parent".
#[cfg(unix)]
#[skuld::test]
fn a_parent_that_is_access_denied_is_unassessable_naming_the_ppid() {
    let (child, id) = crate::test_child::live_exiting_member();
    let me = std::process::id();
    let forced = crate::identity::force_unknown_identity(me);
    let result = Process::from_id(id).parent();
    drop(forced);
    match result {
        Err(crate::error::Error::Unassessable { detail, .. }) => {
            assert!(
                detail.contains(&format!("ppid {me} exists but could not be queried")),
                "{detail}"
            )
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
    crate::test_child::release_unsignalled(child);
}
