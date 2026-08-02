use super::Process;
use crate::identity::ProcessId;

#[test]
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

#[test]
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

#[test]
fn process_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Process>();
}

#[cfg(windows)]
#[test]
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
#[test]
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

/// Pinned default: an unassessable anchor yields the same empty answers as a gone one.
#[cfg(windows)]
#[test]
fn parent_and_children_of_an_unassessable_anchor_are_empty() {
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
    assert!(p.parent().is_none());
    assert!(p.children(crate::Recursive::No).is_empty());
    assert!(p.children(crate::Recursive::Yes).is_empty());
}

/// The ppid branch, distinct from the anchor branch: the subject resolves fine, but its
/// PARENT is access-denied. Built by having the restricted fixture itself be the parent - a
/// DACL is not inherited, so `cmd.exe` is unopenable while the `ping` it spawns is not.
#[cfg(windows)]
#[test]
fn parent_of_a_process_whose_parent_is_access_denied_is_none_and_warns() {
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    crate::log_capture::install();
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
    let mark = crate::log_capture::mark();
    assert!(kid.parent().is_none(), "an unassessable ppid yields no parent");
    // Pinned to THIS fixture-s ppid and to this site-s prefix: `contains_since` bounds time
    // only, and `treewalk::resolve_or_drop` emits a message sharing the "could not be
    // queried" tail from any concurrent teardown in the same test process.
    assert!(crate::log_capture::contains_since(
        mark,
        &format!("Process::parent: ppid {} could not be queried", parent.pid())
    ));
}
