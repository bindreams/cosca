use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows::Win32::System::Threading::{PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE};

use super::{creation_token, current_token, is_running, start_token};
use crate::identity::windows_fixture::spawn_restricted;
use crate::identity::{Liveness, Resolved, StartToken};

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
    let wrong = StartToken::from_raw(tok.raw().wrapping_add(1));
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
    assert_eq!(is_running(ghost, StartToken::from_raw(1)), Liveness::Dead);
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
    let err = crate::wait::kill(id).expect_err("killing a process we may not open must not report success");
    let crate::error::Error::Unassessable { source, .. } = err else {
        panic!("a denial must not read as an I/O failure: {err:?}");
    };
    let io = source.expect("the OS error is preserved");
    assert_eq!(io.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{io}");
    assert!(child.is_running(), "and it must still be running — nothing killed it");
}

/// `Process::wait` must not report an exit it never observed.
#[skuld::test]
fn block_until_exit_of_an_access_denied_live_process_is_an_error() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(block_until_exit_of_an_access_denied_live_process_is_an_error),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = crate::identity::windows_fixture::spawn_unkillable(&done);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let err = crate::wait::block_until_exit(id, Some(std::time::Duration::ZERO))
        .expect_err("an unopenable live process must not be reported as exited");
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
    assert!(crate::wait::block_until_exit(id, Some(std::time::Duration::ZERO))
        .expect("waiting on an already-exited process is success"));
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
    // Precondition: kill's own mask must actually be refused, or this exercises the
    // Opened::Found path and never reaches the arm under test.
    assert!(
        matches!(
            super::open_classified(child.pid(), PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION),
            super::Opened::Denied(_)
        ),
        "precondition: wait::kill's open must be denied"
    );
    child.terminate();
    assert!(!child.is_running(), "precondition: the subject must have exited");
    assert_eq!(id.is_alive(), Liveness::Dead, "precondition: provably dead");
    crate::wait::kill(id).expect("killing an already-exited process is success");
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
    let stale = crate::identity::ProcessId::from_parts_for_test(real.pid(), real.start_token_raw() ^ 1);
    assert!(child.is_running(), "precondition: the pid's occupant is live");
    assert!(crate::wait::block_until_exit(stale, Some(std::time::Duration::ZERO))
        .expect("a readable stranger on the pid proves the stale identity is gone"));
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
    let stale = crate::identity::ProcessId::from_parts_for_test(real.pid(), real.start_token_raw() ^ 1);
    assert!(
        child.is_running(),
        "precondition: the pid's occupant is live and unreadable"
    );
    crate::wait::block_until_exit(stale, Some(std::time::Duration::ZERO))
        .expect_err("an unreadable occupant cannot prove the original identity exited");
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

/// A refusal on a handle that holds `PROCESS_TERMINATE` is the exit, whether or not the process
/// object is signalled yet: the seam refuses a process that stays alive and unsignalled.
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

/// A handle with neither `PROCESS_TERMINATE` nor `SYNCHRONIZE` cannot be waited on: `Failed` with
/// the refusal, not `Exited`.
///
/// Mutant: the wait's `WAIT_FAILED` reads as the exit.
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
