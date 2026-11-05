use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows::Win32::System::Threading::{
    PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

use super::{creation_token, current_token, exit_look, is_running, open_dropping_refused, start_token, Look, Opened};
use crate::identity::windows_fixture::{spawn_restricted, spawn_restricted_shell};
use crate::identity::{Key, Liveness, Resolved};

/// One look at whether `id`'s process has exited, through the open: gone or recycled
/// is exited.
fn exited_now(id: crate::identity::ProcessId) -> Result<bool, crate::error::Error> {
    crate::test_child::exited_through_open(id, Some(std::time::Duration::ZERO))
}

#[skuld::test]
fn start_token_of_current_process_is_stable() {
    let pid = std::process::id();
    let a = start_token(pid);
    assert!(matches!(a, Resolved::Found(_)), "our own token must resolve: {a:?}");
    assert_eq!(a, start_token(pid), "the same pid must yield the same token");
}

/// `current_token` reads the pseudo-handle, so it must agree with the by-pid read on a
/// process that permits both — and, unlike it, can never be denied.
#[skuld::test]
fn current_token_agrees_with_the_by_pid_read() {
    assert_eq!(current_token(), start_token(std::process::id()));
}

#[skuld::test]
fn is_running_alive_for_self_dead_for_wrong_token() {
    let pid = std::process::id();
    let Resolved::Found(tok) = start_token(pid) else {
        panic!("our own token must resolve");
    };
    assert_eq!(is_running(pid, tok), Liveness::Alive, "we are obviously running");
    let wrong = Key::from_raw(tok.raw().wrapping_add(1));
    assert_eq!(
        is_running(pid, wrong),
        Liveness::Dead,
        "a wrong token is a different process"
    );
}

/// A LIVE process we may not open at all: ERROR_ACCESS_DENIED must NOT read as absence.
#[skuld::test]
fn denied_query_limited_reads_unknown_not_gone() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(denied_query_limited_reads_unknown_not_gone),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = spawn_restricted(&done, PROCESS_SYNCHRONIZE.0);
    let token = creation_token(child.handle()).expect("the owned handle can always read the token");
    assert!(child.is_running(), "precondition: the subject must be live");
    assert_eq!(
        start_token(child.pid()),
        Resolved::Unknown,
        "an access-denied live process must not resolve as Gone"
    );
    assert_eq!(
        is_running(child.pid(), token),
        Liveness::Unknown,
        "an access-denied live process must not read as Dead"
    );
    assert!(child.is_running(), "and it must still have been live throughout");
}

/// QUERY_LIMITED granted, SYNCHRONIZE denied: the identity resolves, but the signaled state
/// cannot be read and GetExitCodeProcess reports STILL_ACTIVE, which does not distinguish
/// "running" from "exited with code 259". Unknown, not Alive, not Dead.
#[skuld::test]
fn denied_synchronize_resolves_identity_but_liveness_is_unknown_while_running() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(denied_synchronize_resolves_identity_but_liveness_is_unknown_while_running),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = spawn_restricted(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
    let token = creation_token(child.handle()).expect("owned handle reads the token");
    assert!(child.is_running(), "precondition: the subject must be live");
    assert_eq!(start_token(child.pid()), Resolved::Found(token));
    assert_eq!(
        is_running(child.pid(), token),
        Liveness::Unknown,
        "SYNCHRONIZE is denied and STILL_ACTIVE is ambiguous — never Alive, never Dead"
    );
    assert!(child.is_running());
}

/// The same process after it exits with a concrete code: GetExitCodeProcess PROVES the exit
/// through QUERY_LIMITED alone, so this must be Dead — not Unknown, or every already-dead
/// `kill` on such a process would report failure.
#[skuld::test]
fn exited_process_denying_synchronize_reads_dead() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(exited_process_denying_synchronize_reads_dead),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = spawn_restricted(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
    let token = creation_token(child.handle()).expect("owned handle reads the token");
    child.terminate(); // exit code 1
    assert!(!child.is_running(), "precondition: the subject must have exited");
    assert_eq!(is_running(child.pid(), token), Liveness::Dead);
}

/// A pid that cannot exist classifies as definitely-gone, not Unknown — otherwise the
/// tri-state would degenerate to always-Unknown.
#[skuld::test]
fn nonexistent_pid_is_gone_not_unknown() {
    // OpenProcess for an unused pid returns ERROR_INVALID_PARAMETER, the "no such process"
    // signal. The value is chosen, not arbitrary: Windows allocates pids from a low, densely
    // packed table (multiples of 4), so a value near u32::MAX is unallocatable rather than
    // merely unlikely — the "gone" precondition holds by construction, the way the denied
    // tests assert theirs by fixture.
    let ghost = 0xFFFF_FFF0u32;
    assert_eq!(start_token(ghost), Resolved::Gone);
    assert_eq!(is_running(ghost, Key::from_raw(1)), Liveness::Dead);
}

/// `Process::kill` documents "a real failure (no rights / access-denied on a live process)
/// => Err". An access-denied live process must therefore not produce Ok.
#[skuld::test]
fn kill_of_an_access_denied_live_process_is_an_error() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(kill_of_an_access_denied_live_process_is_an_error),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = crate::identity::windows_fixture::spawn_unkillable(&done);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let err = crate::os_process::open(id).expect_err("a process we may not open must not read as gone");
    let crate::error::Error::Unassessable { source, .. } = err else {
        panic!("a denial must not read as an I/O failure: {err:?}");
    };
    let io = source.expect("the OS error is preserved");
    assert_eq!(io.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{io}");
    assert!(child.is_running(), "and it must still be running — nothing killed it");
}

/// `Process::wait` must not report an exit it never observed.
#[skuld::test]
fn waiting_on_an_access_denied_live_process_is_an_error() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(waiting_on_an_access_denied_live_process_is_an_error),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = crate::identity::windows_fixture::spawn_unkillable(&done);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let err = exited_now(id).expect_err("an unopenable live process must not be reported as exited");
    let crate::error::Error::Unassessable { source, .. } = err else {
        panic!("a denial must not read as an I/O failure: {err:?}");
    };
    let io = source.expect("the OS error is preserved");
    assert_eq!(io.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{io}");
}

/// The other side of the same branch: `Denied` plus a provably-Dead target must still report
/// success, or every already-exited kill or wait on such a process would start failing. The
/// two entry points need DIFFERENT fixtures, because their masks differ.
#[skuld::test]
fn wait_of_a_synchronize_denied_but_exited_process_reports_exited() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(wait_of_a_synchronize_denied_but_exited_process_reports_exited),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = spawn_restricted(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    child.terminate();
    assert!(!child.is_running(), "precondition: the subject must have exited");
    assert_eq!(id.is_alive(), Liveness::Dead, "precondition: provably dead");
    assert!(exited_now(id).expect("waiting on an already-exited process is success"));
}

#[skuld::test]
fn kill_of_a_terminate_denied_but_exited_process_reports_success() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(kill_of_a_terminate_denied_but_exited_process_reports_success),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_TERMINATE;
    let child = crate::identity::windows_fixture::spawn_query_only(&done);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    // Precondition: the terminate right must actually be refused, or this exercises the
    // Opened::Found path and never reaches the arm under test.
    assert!(
        matches!(
            super::open_classified(child.pid(), PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION),
            super::Opened::Denied(_)
        ),
        "precondition: the open with the terminate right must be denied"
    );
    child.terminate();
    assert!(!child.is_running(), "precondition: the subject must have exited");
    assert_eq!(id.is_alive(), Liveness::Dead, "precondition: provably dead");
    let process = crate::os_process::open(id)
        .expect("the open of an exited process")
        .expect("the exited process is still held by its fixture");
    crate::os_process::kill(&*process).expect("killing an already-exited process is success");
}

const OPTIONAL: [PROCESS_ACCESS_RIGHTS; 2] = [PROCESS_SYNCHRONIZE, PROCESS_TERMINATE];

/// The rights `open_dropping_refused` grants on `pid`, the handle closed. `None`: the open is
/// denied.
fn granted_on(pid: u32) -> Option<PROCESS_ACCESS_RIGHTS> {
    match open_dropping_refused(pid, &OPTIONAL) {
        (Opened::Found(handle), granted) => {
            super::close(handle);
            Some(granted)
        }
        (Opened::Denied(_), _) => None,
        (Opened::Gone, _) => panic!("pid {pid} is live"),
    }
}

/// Each refused right is dropped on its own, down to the query right; a process that refuses even
/// that is denied.
///
/// Mutant: one refusal drops every optional right, or the search stops at the first denial.
#[skuld::test]
fn open_dropping_refused_drops_each_refused_right() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(open_dropping_refused_drops_each_refused_right),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let query = PROCESS_QUERY_LIMITED_INFORMATION;
    let query_only = crate::identity::windows_fixture::spawn_query_only(&done);
    assert_eq!(granted_on(query_only.pid()), Some(query));
    let restricted = spawn_restricted(&done, query.0);
    assert_eq!(granted_on(restricted.pid()), Some(query | PROCESS_TERMINATE));
    assert_eq!(
        granted_on(std::process::id()),
        Some(query | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE)
    );
    let unkillable = crate::identity::windows_fixture::spawn_unkillable(&done);
    assert_eq!(granted_on(unkillable.pid()), None, "QUERY itself is refused");
}

/// What `is_running` must say for a look: the mapping of `exit_look`'s answer.
fn liveness_of(look: windows::core::Result<Look>) -> Liveness {
    match look {
        Ok(Look::Running) => Liveness::Alive,
        Ok(Look::Exited) => Liveness::Dead,
        Err(_) => Liveness::Unknown,
    }
}

/// `is_running` is `exit_look` over the handle `open_dropping_refused` opened, with the token check
/// and the denial in front.
///
/// Mutant: `is_running` keeps its own look, which drifts from `exit_look`.
#[skuld::test]
fn exit_look_agrees_with_is_running() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(exit_look_agrees_with_is_running),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let look_at = |pid: u32| {
        let (Opened::Found(handle), granted) = open_dropping_refused(pid, &[PROCESS_SYNCHRONIZE]) else {
            panic!("pid {pid} opens with QUERY");
        };
        let look = exit_look(handle, granted.0 & PROCESS_SYNCHRONIZE.0 != 0);
        super::close(handle);
        look
    };
    let token_of = |pid: u32| match start_token(pid) {
        Resolved::Found(t) => t,
        other => panic!("pid {pid} resolves: {other:?}"),
    };

    let me = std::process::id();
    assert_eq!(is_running(me, token_of(me)), liveness_of(look_at(me)));
    assert_eq!(is_running(me, token_of(me)), Liveness::Alive);

    let query_only = crate::identity::windows_fixture::spawn_query_only(&done);
    let token = token_of(query_only.pid());
    assert_eq!(
        is_running(query_only.pid(), token),
        liveness_of(look_at(query_only.pid()))
    );
    assert_eq!(
        is_running(query_only.pid(), token),
        Liveness::Unknown,
        "running, unprovable"
    );
    query_only.terminate();
    assert_eq!(
        is_running(query_only.pid(), token),
        liveness_of(look_at(query_only.pid()))
    );
    assert_eq!(
        is_running(query_only.pid(), token),
        Liveness::Dead,
        "an exit code proves it"
    );

    let unkillable = crate::identity::windows_fixture::spawn_unkillable(&done);
    let token = creation_token(unkillable.handle()).expect("the owned handle reads the token");
    assert_eq!(
        is_running(unkillable.pid(), token),
        Liveness::Unknown,
        "QUERY refused: no look"
    );
}

/// A stale identity over a pid whose occupant we CAN read: the token comparison runs, finds
/// a different process, and reports the original exited.
#[skuld::test]
fn wait_on_a_stale_identity_over_a_readable_pid_reports_exited() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(wait_on_a_stale_identity_over_a_readable_pid_reports_exited),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = spawn_restricted(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
    let real = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    let stale = real.with_other_value();
    assert!(child.is_running(), "precondition: the pid's occupant is live");
    assert!(exited_now(stale).expect("a readable stranger on the pid proves the stale identity is gone"));
}

/// The other half of the documented asymmetry: when the pid's occupant cannot be read
/// either, the original's exit cannot be established. `Err`, not a guessed `Ok`.
#[skuld::test]
fn wait_on_a_stale_identity_over_an_unreadable_pid_is_an_error() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(wait_on_a_stale_identity_over_an_unreadable_pid_is_an_error),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = crate::identity::windows_fixture::spawn_unkillable(&done);
    let real = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    let stale = real.with_other_value();
    assert!(
        child.is_running(),
        "precondition: the pid's occupant is live and unreadable"
    );
    exited_now(stale).expect_err("an unreadable occupant cannot prove the original identity exited");
}

// terminate_held =====

/// A child that blocks on its piped stdin until the test ends it.
fn spawn_blocked_child() -> std::process::Child {
    crate::test_spawn::spawn(
        std::process::Command::new("cmd")
            .args(["/C", "more"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn cmd /C more")
}

fn handle_of(child: &std::process::Child) -> windows::Win32::Foundation::HANDLE {
    use std::os::windows::io::AsRawHandle;
    windows::Win32::Foundation::HANDLE(child.as_raw_handle())
}

fn end(mut child: std::process::Child) {
    child.kill().expect("end the fixture");
    child.wait().expect("reap the fixture");
}

/// A second handle to `child`'s process opened with `rights` (never `PROCESS_TERMINATE`), closed
/// on drop.
struct Limited(windows::Win32::Foundation::HANDLE);

impl Limited {
    fn of(child: &std::process::Child, rights: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS) -> Limited {
        // SAFETY: `child` is live and its handle pins the pid, so the open names this process.
        let h = unsafe { windows::Win32::System::Threading::OpenProcess(rights, false, child.id()) }
            .expect("open a limited handle on the fixture");
        Limited(h)
    }
}

impl Drop for Limited {
    fn drop(&mut self) {
        super::close(self.0);
    }
}

/// The seam refuses a process that stays alive and unsignalled.
///
/// Mutant: a refusal is `Exited` only for a signalled process, so this one is `Failed`.
#[skuld::test]
fn a_refusal_on_a_handle_holding_terminate_is_the_exit() {
    let child = spawn_blocked_child();
    super::fault::refuse_next_terminate_as_exiting();
    let outcome = super::terminate_held(handle_of(&child));
    end(child);
    assert!(
        matches!(outcome, super::Termination::Exited),
        "got a failure or a terminate"
    );
}

/// The same for a process that has exited and was signalled: the real refusal, no seam.
///
/// Mutant: a refusal is `Exited` only while the process is unsignalled.
#[skuld::test]
fn a_real_refusal_on_a_handle_holding_terminate_of_an_exited_process_is_the_exit() {
    let mut child = spawn_blocked_child();
    child.kill().expect("end the fixture");
    child.wait().expect("reap the fixture");
    let outcome = super::terminate_held(handle_of(&child));
    assert!(
        matches!(outcome, super::Termination::Exited),
        "got a failure or a terminate"
    );
}

/// A handle without `PROCESS_TERMINATE` is refused for good, for a live process: the refusal is
/// not the exit, whatever the caller thinks the handle holds.
///
/// Mutant: every `ERROR_ACCESS_DENIED` reads as the exit.
#[skuld::test]
fn a_refusal_on_a_handle_without_terminate_is_failed_while_the_process_runs() {
    let child = spawn_blocked_child();
    let limited = Limited::of(&child, PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
    let outcome = super::terminate_held(limited.0);
    drop(limited);
    end(child);
    let super::Termination::Failed(e) = outcome else {
        panic!("a live process is not an exit");
    };
    assert!(super::is_access_denied(&e), "{e:?}");
}

/// As above with the seam's refusal, the process being exiting but unsignalled: a handle without
/// the right cannot show the exit.
///
/// Mutant: the granted access is not read, so the seam's refusal reads as the exit.
#[skuld::test]
fn an_exiting_refusal_on_a_handle_without_terminate_is_failed_while_unsignalled() {
    let child = spawn_blocked_child();
    let limited = Limited::of(&child, PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
    super::fault::refuse_next_terminate_as_exiting();
    let outcome = super::terminate_held(limited.0);
    drop(limited);
    end(child);
    let super::Termination::Failed(e) = outcome else {
        panic!("an unsignalled process is not shown to have exited");
    };
    assert!(super::is_access_denied(&e), "{e:?}");
}

/// A handle with neither `PROCESS_TERMINATE` nor `SYNCHRONIZE` to a running process: `Failed` with
/// the refusal, not `Exited`. Its exit code, `STILL_ACTIVE`, cannot be told from exit code 259.
///
/// Mutant: `STILL_ACTIVE` reads as the exit.
#[skuld::test]
fn a_refusal_on_a_handle_without_terminate_or_synchronize_is_failed() {
    let child = spawn_blocked_child();
    let limited = Limited::of(&child, PROCESS_QUERY_LIMITED_INFORMATION);
    let outcome = super::terminate_held(limited.0);
    drop(limited);
    end(child);
    let super::Termination::Failed(e) = outcome else {
        panic!("a handle that cannot be waited on shows no exit");
    };
    assert!(super::is_access_denied(&e), "{e:?}");
}

/// A handle without `PROCESS_TERMINATE` to a process that has exited: its signalled state is the
/// proof of the exit.
///
/// Mutant: the signalled read is dropped, so the refusal stays `Failed`.
#[skuld::test]
fn a_refusal_on_a_handle_without_terminate_is_the_exit_once_the_process_is_signalled() {
    let mut child = spawn_blocked_child();
    let limited = Limited::of(&child, PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION);
    child.kill().expect("end the fixture");
    // Reap through a real wait: the process object is signalled when this returns.
    child.wait().expect("reap the fixture");
    let outcome = super::terminate_held(limited.0);
    drop(limited);
    assert!(
        matches!(outcome, super::Termination::Exited),
        "a signalled process is the exit"
    );
}

/// A handle with neither `PROCESS_TERMINATE` nor `SYNCHRONIZE` to a process that has exited: its
/// exit code is the proof of the exit.
///
/// Mutant: the exit code is not read, so the refusal stays `Failed`.
#[skuld::test]
fn a_refusal_on_a_handle_without_terminate_or_synchronize_is_the_exit_once_the_code_is_recorded() {
    let mut child = spawn_blocked_child();
    let limited = Limited::of(&child, PROCESS_QUERY_LIMITED_INFORMATION);
    child.kill().expect("end the fixture");
    // Reap through a real wait: the exit code is recorded when this returns.
    child.wait().expect("reap the fixture");
    let outcome = super::terminate_held(limited.0);
    drop(limited);
    assert!(
        matches!(outcome, super::Termination::Exited),
        "an exit code other than STILL_ACTIVE is the exit"
    );
}

/// A handle whose granted access cannot be read is `Failed` with that error: the refusal is not
/// guessed to be the exit. A null handle is a real `STATUS_INVALID_HANDLE`.
///
/// Mutant: a failed read of the granted access is treated as holding the right.
#[skuld::test]
fn a_refusal_on_a_handle_whose_rights_cannot_be_read_is_failed() {
    super::fault::refuse_next_terminate_as_exiting();
    let outcome = super::terminate_held(windows::Win32::Foundation::HANDLE::default());
    let super::Termination::Failed(e) = outcome else {
        panic!("a handle that cannot be read is not shown to be of an exiting process");
    };
    assert!(
        !super::is_access_denied(&e),
        "the failure is the rights read's own: {e:?}"
    );
}

// order key =====

fn order_key_of(id: crate::identity::ProcessId) -> crate::identity::OrderKey {
    match id.order_key_with(&crate::identity::HostKernel).0 {
        Resolved::Found(key) => key,
        other => panic!("the order key of {id:?} should read, got {other:?}"),
    }
}

/// The order key is the process sequence number, not the creation time that is the id's key.
///
/// Mutant: the order key is the id's key.
#[skuld::test]
fn the_order_key_is_not_the_creation_time() {
    let me = crate::identity::ProcessId::current();
    let (read, _) = crate::identity::ProcessId::of_ordered_with(&crate::identity::HostKernel, me.pid(), None);
    let Resolved::Found((id, key)) = read else {
        panic!("our own order key must read, got {read:?}");
    };
    assert_eq!(id, me, "the id of the ordered read is the id of the by-pid read");
    assert_ne!(key, crate::identity::OrderKey::for_test(me.key().raw()));
    assert_eq!(key, order_key_of(me), "both reads of one process agree");
}

/// The fact the tree walk relies on: a process's sequence number is greater than its creator's.
///
/// Mutant: the order key is a value that does not grow from creator to child.
#[skuld::test]
fn a_child_orders_after_its_creator_and_a_grandchild_after_the_child() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_child_orders_after_its_creator_and_a_grandchild_after_the_child),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = spawn_restricted_shell(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
    let grandchild = child.wait_for_child();
    let me = crate::identity::ProcessId::current();
    let child_id = crate::identity::ProcessId::of(child.pid())
        .found()
        .expect("the child is ours");
    let grandchild_id = crate::identity::ProcessId::of(grandchild)
        .found()
        .expect("the grandchild is ours");
    let keys = (order_key_of(me), order_key_of(child_id), order_key_of(grandchild_id));
    assert!(keys.0 < keys.1, "child {:?} after creator {:?}", keys.1, keys.0);
    assert!(keys.1 < keys.2, "grandchild {:?} after child {:?}", keys.2, keys.1);
}

/// A pid that another process holds has no order key for the id that was read before.
///
/// Mutant: the order key of a recycled pid is read as the new holder's.
#[skuld::test]
fn the_order_key_of_a_stale_id_is_gone() {
    let stale = crate::identity::ProcessId::current().with_other_value();
    assert_eq!(stale.order_key_with(&crate::identity::HostKernel).0, Resolved::Gone);
}

/// Mutant: the walk drops a genuine descendant under the sequence-number order.
#[skuld::test]
fn the_walk_keeps_a_real_child_and_grandchild_of_a_real_spawned_root() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(the_walk_keeps_a_real_child_and_grandchild_of_a_real_spawned_root),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = spawn_restricted_shell(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
    let grandchild = child.wait_for_child();
    let root = crate::identity::ProcessId::of(child.pid())
        .found()
        .expect("the root is ours");
    let direct = root.children(crate::Recursive::No);
    let below_us = crate::identity::ProcessId::current().children(crate::Recursive::Yes);
    let direct = direct.expect("the root's children are enumerable");
    assert!(
        direct.iter().any(|id| id.pid() == grandchild),
        "{grandchild} not among {direct:?}"
    );
    let below_us = below_us.expect("our descendants are enumerable");
    for pid in [root.pid(), grandchild] {
        assert!(
            below_us.iter().any(|id| id.pid() == pid),
            "{pid} not among {below_us:?}"
        );
    }
}

// the two reads of one handle =====

const REFUSED: windows::Win32::Foundation::NTSTATUS = windows::Win32::Foundation::NTSTATUS(0xC000_0004_u32 as i32);

fn refused_key() -> windows::core::Result<Key> {
    Err(windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(
        windows::Win32::Foundation::ERROR_ACCESS_DENIED.0,
    )))
}

/// The error text of a read's cause, for the subject `pid 7`.
fn cause_text(cause: crate::identity::UnknownCause) -> Option<String> {
    cause.into_error("pid 7").map(|e| e.to_string())
}

/// Both reads answered: the id's key and the order key, from one handle.
///
/// Mutant: the order key is the key.
#[skuld::test]
fn two_good_reads_are_the_key_and_the_sequence_number() {
    let key = Key::for_test(5);
    for expected in [None, Some(key)] {
        let (read, cause) = super::combine(7, expected, Ok(key), Ok(9));
        assert_eq!(read, Resolved::Found((key, crate::identity::OrderKey::for_test(9))));
        assert_eq!(cause_text(cause), None);
    }
}

/// A refused sequence-number query on the process asked about is `Unknown`, with its status.
///
/// Mutant: the refusal reads as the generic "access denied?" one.
#[skuld::test]
fn a_refused_sequence_number_on_the_expected_process_is_unknown_with_its_status() {
    let key = Key::for_test(5);
    for expected in [None, Some(key)] {
        let (read, cause) = super::combine(7, expected, Ok(key), Err(REFUSED));
        assert_eq!(read, Resolved::Unknown);
        let text = cause_text(cause).expect("the refusal is the cause");
        assert!(
            text.contains("pid 7") && text.contains("process sequence number query failed: NTSTATUS 0xc0000004"),
            "{text}"
        );
    }
}

/// Another process's key is `Gone` whatever the sequence-number query said: a recycled pid whose
/// new holder refuses the query is not an unreadable root.
///
/// Mutant: the sequence-number result is looked at before the key.
#[skuld::test]
fn another_processs_key_is_gone_whether_or_not_its_sequence_number_reads() {
    let (read, cause) = super::combine(7, Some(Key::for_test(5)), Ok(Key::for_test(6)), Err(REFUSED));
    assert_eq!(read, Resolved::Gone);
    assert_eq!(cause_text(cause), None);
    let (read, _) = super::combine(7, Some(Key::for_test(5)), Ok(Key::for_test(6)), Ok(9));
    assert_eq!(read, Resolved::Gone);
}

/// A key that cannot be read leaves nothing to compare: `Unknown`. When the sequence-number query
/// was refused too, the cause keeps its status and the log keeps the key's failure.
///
/// Mutant: the second failure is dropped.
#[skuld::test]
fn two_failed_reads_keep_both_failures() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (read, cause) = super::combine(70_007, Some(Key::for_test(5)), refused_key(), Err(REFUSED));
    assert_eq!(read, Resolved::Unknown);
    assert!(
        cause_text(cause).is_some_and(|t| t.contains("NTSTATUS 0xc0000004")),
        "the sequence-number refusal is the cause"
    );
    assert!(
        crate::log_capture::contains_since(mark, "GetProcessTimes failed on an opened handle for pid 70007"),
        "the key's failure is logged"
    );

    let (read, cause) = super::combine(70_008, None, refused_key(), Ok(9));
    assert_eq!(read, Resolved::Unknown);
    assert_eq!(cause_text(cause), None, "a key refusal alone has no status to name");
}

/// Class 92 answers for every process this caller can open: the CI pin of the private read on the
/// runner's real process population. Read-only.
/// An elevated caller opens more, so an elevated runner covers processes an unelevated one cannot.
///
/// Mutant: the class is refused for a kind of process (a protected or system one).
#[skuld::test]
fn the_sequence_number_reads_on_every_process_that_opens() {
    let parents =
        crate::containment::enumerate::process_parents(&crate::identity::HostKernel).expect("the process snapshot");
    let (mut opened, mut refused, mut gone) = (0usize, 0usize, 0usize);
    let mut failures = Vec::new();
    for (pid, _) in parents {
        match super::open_classified(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
            Opened::Found(handle) => {
                opened += 1;
                if let Err(status) = super::sequence_number(handle) {
                    failures.push(format!("pid {pid}: NTSTATUS {:#010x}", status.0 as u32));
                }
                super::close(handle);
            }
            Opened::Denied(_) => refused += 1,
            Opened::Gone => gone += 1,
        }
    }
    eprintln!("sequence number read on {opened} processes; {refused} refused to open, {gone} gone");
    assert!(opened > 0, "no process could be opened: {refused} refused, {gone} gone");
    assert!(
        failures.is_empty(),
        "class 92 failed on {} of {opened} opened processes ({refused} refused to open): {failures:?}",
        failures.len()
    );
}
