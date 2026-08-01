use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows::Win32::System::Threading::{PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE};

use super::{creation_token, current_token, is_running, start_token};
use crate::identity::windows_fixture::spawn_restricted;
use crate::identity::{Liveness, Resolved, StartToken};

#[test]
fn start_token_of_current_process_is_stable() {
    let pid = std::process::id();
    let a = start_token(pid);
    assert!(matches!(a, Resolved::Found(_)), "our own token must resolve: {a:?}");
    assert_eq!(a, start_token(pid), "the same pid must yield the same token");
}

/// `current_token` reads the pseudo-handle, so it must agree with the by-pid read on a
/// process that permits both — and, unlike it, can never be denied.
#[test]
fn current_token_agrees_with_the_by_pid_read() {
    assert_eq!(current_token(), start_token(std::process::id()));
}

#[test]
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
#[test]
fn denied_query_limited_reads_unknown_not_gone() {
    let child = spawn_restricted(PROCESS_SYNCHRONIZE.0);
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
#[test]
fn denied_synchronize_resolves_identity_but_liveness_is_unknown_while_running() {
    let child = spawn_restricted(PROCESS_QUERY_LIMITED_INFORMATION.0);
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
#[test]
fn exited_process_denying_synchronize_reads_dead() {
    let child = spawn_restricted(PROCESS_QUERY_LIMITED_INFORMATION.0);
    let token = creation_token(child.handle()).expect("owned handle reads the token");
    child.terminate(); // exit code 1
    assert!(!child.is_running(), "precondition: the subject must have exited");
    assert_eq!(is_running(child.pid(), token), Liveness::Dead);
}

/// A pid that cannot exist classifies as definitely-gone, not Unknown — otherwise the
/// tri-state would degenerate to always-Unknown.
#[test]
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
#[test]
fn kill_of_an_access_denied_live_process_is_an_error() {
    let child = crate::identity::windows_fixture::spawn_unkillable();
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let err = crate::wait::kill(id).expect_err("killing a process we may not open must not report success");
    let crate::error::Error::Unassessable { source, .. } = err else {
        panic!("a denial must not read as an I/O failure: {err:?}");
    };
    let io = source.expect("the OS error is preserved");
    // `From<windows::core::Error> for io::Error` stores the HRESULT, not the bare Win32
    // code, so compare against the wrapped form — `Some(5)` would never match.
    assert_eq!(
        io.raw_os_error(),
        Some(windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0).0),
        "{io}"
    );
    assert!(child.is_running(), "and it must still be running — nothing killed it");
}

/// `Process::wait` must not report an exit it never observed.
#[test]
fn block_until_exit_of_an_access_denied_live_process_is_an_error() {
    let child = crate::identity::windows_fixture::spawn_unkillable();
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let err = crate::wait::block_until_exit(id, Some(std::time::Duration::ZERO))
        .expect_err("an unopenable live process must not be reported as exited");
    let crate::error::Error::Unassessable { source, .. } = err else {
        panic!("a denial must not read as an I/O failure: {err:?}");
    };
    let io = source.expect("the OS error is preserved");
    assert_eq!(
        io.raw_os_error(),
        Some(windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0).0),
        "{io}"
    );
}

/// The other side of the same branch: `Denied` plus a provably-Dead target must still report
/// success, or every already-exited kill or wait on such a process would start failing. The
/// two entry points need DIFFERENT fixtures, because their masks differ.
#[test]
fn wait_of_a_synchronize_denied_but_exited_process_reports_exited() {
    let child = spawn_restricted(PROCESS_QUERY_LIMITED_INFORMATION.0);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    child.terminate();
    assert!(!child.is_running(), "precondition: the subject must have exited");
    assert_eq!(id.is_alive(), Liveness::Dead, "precondition: provably dead");
    assert!(crate::wait::block_until_exit(id, Some(std::time::Duration::ZERO))
        .expect("waiting on an already-exited process is success"));
}

#[test]
fn kill_of_a_terminate_denied_but_exited_process_reports_success() {
    use windows::Win32::System::Threading::PROCESS_TERMINATE;
    let child = crate::identity::windows_fixture::spawn_query_only();
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
#[test]
fn wait_on_a_stale_identity_over_a_readable_pid_reports_exited() {
    let child = spawn_restricted(PROCESS_QUERY_LIMITED_INFORMATION.0);
    let real = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    let stale = crate::identity::ProcessId::from_parts_for_test(real.pid(), real.start_token_raw() ^ 1);
    assert!(child.is_running(), "precondition: the pid's occupant is live");
    assert!(crate::wait::block_until_exit(stale, Some(std::time::Duration::ZERO))
        .expect("a readable stranger on the pid proves the stale identity is gone"));
}

/// The other half of the documented asymmetry: when the pid's occupant cannot be read
/// either, the original's exit cannot be established. `Err`, not a guessed `Ok`.
#[test]
fn wait_on_a_stale_identity_over_an_unreadable_pid_is_an_error() {
    let child = crate::identity::windows_fixture::spawn_unkillable();
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
