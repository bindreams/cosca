use super::Process;
use crate::identity::ProcessId;

#[test]
fn current_resolves_and_is_alive() {
    let me = Process::current();
    assert!(me.is_alive());
    assert_eq!(Process::from_id(me.id()), Some(me));
    assert_eq!(Process::from_pid(me.id().pid()), Some(me));
}

#[test]
fn from_id_rejects_a_recycled_pid() {
    // A live pid bearing a DIFFERENT start token is the recycle case: the pid resolves,
    // but its identity no longer matches the saved one, so resolution must fail. Built
    // against our own (definitely-live) pid with a token that cannot be the real one.
    let real = ProcessId::current();
    let stale = ProcessId::from_parts_for_test(real.pid(), real.start_token_raw().wrapping_add(1));
    assert_eq!(
        Process::from_id(stale),
        None,
        "a mismatched start token must not resolve"
    );
}

#[test]
fn process_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Process>();
}
