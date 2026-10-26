//! The graceful ops from a caller with no console. The checks run in a re-exec of this binary
//! spawned `DETACHED_PROCESS`, whose thread holds the record of the breaks it sends (see
//! [`super`]); the driver in `child::ctrl_break_tests` reads only whether the checks finished.
//!
//! A target's reply cannot show that no break was sent: its handler thread may not have run yet.
//! The sender's own record can, because a send is recorded as the syscall returns.

use std::net::TcpStream;
use std::time::Duration;

use super::{assert_no_break_sent, connect_reporter, report_done, spawn_member, Handler};
use crate::error::Error;
use crate::identity::Liveness;
use crate::{Containment, GracefulMechanism};

/// The fully-qualified libtest path of [`fixture_console_less_reporter`].
pub(crate) const REPORTER_TEST: &str = "test_child::ctrl_break::console_less::fixture_console_less_reporter";

/// The environment variable carrying the address the reporter reports to.
pub(crate) const ADDR_ENV: &str = "COSCA_FIXTURE_CONSOLE_LESS_ADDR";

/// A contained member that ignores every console event, so only a kill ends it. It is released
/// after the kill, so exit code 1 is the kill's, not a release (which exits 0).
fn spawn_ignoring_root() -> (crate::Child, TcpStream) {
    let (child, sock, _) = spawn_member(Handler::Ignore, None, crate::ContainMode::Strongest, |_| {});
    (child, sock)
}

fn kill_release_reap(child: &crate::Child, sock: TcpStream, tree: bool) {
    if tree {
        child.kill_tree().expect("hard teardown needs no console");
    } else {
        child.kill().expect("hard teardown needs no console");
    }
    drop(sock);
    let status = child.wait().expect("reap");
    assert_eq!(status.code(), Some(1), "the kill must end the member, got {status:?}");
}

/// Require that this process has no console, measured: a zero from `GetConsoleProcessList` is also
/// how it reports failure, so the error code must say "no console" for the checks not to be
/// vacuous.
fn assert_no_console() {
    use windows::Win32::Foundation::{SetLastError, ERROR_INVALID_HANDLE, WIN32_ERROR};
    use windows::Win32::System::Console::GetConsoleProcessList;

    let mut list = [0u32; 1];
    // SAFETY: `SetLastError` only writes this thread's last-error slot, which is cleared so the
    // code read below is this call's; `list` is a valid writable slice.
    let n = unsafe {
        SetLastError(WIN32_ERROR(0));
        GetConsoleProcessList(&mut list)
    };
    assert_eq!(n, 0, "the reporter must have no console, else the checks are vacuous");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(ERROR_INVALID_HANDLE.0 as i32),
        "GetConsoleProcessList must fail for want of a console, not for another reason"
    );
}

/// Runs the tree ops and then the lone ops against a contained member that cannot be signalled, from
/// a caller with no console: each cooperative op fails with `NoConsole` and leaves the member
/// running, the forced ops still end it, and the sender recorded no break at all.
///
/// Connects to the driver first, so a panic below reaches it as EOF. Writes [`DONE`](super::DONE)
/// last.
#[skuld::test]
fn fixture_console_less_reporter() {
    let Some(mut report) = connect_reporter(ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    assert_no_console();

    // The tree ops. The member ignores every event, so a break sent anyway would not end it and
    // only the record would tell.
    let (child, sock) = spawn_ignoring_root();
    assert_eq!(child.containment(), Containment::JobObject);
    assert!(
        matches!(child.terminate_tree(), Err(Error::NoConsole { .. })),
        "terminate_tree must report NoConsole"
    );
    assert_eq!(
        child.is_alive(),
        Liveness::Alive,
        "a fail-fast terminate leaves the tree alone"
    );
    assert!(
        matches!(
            child.graceful_shutdown_tree(Duration::ZERO),
            Err(Error::NoConsole { .. })
        ),
        "graceful_shutdown_tree must report NoConsole"
    );
    assert_eq!(
        child.is_alive(),
        Liveness::Alive,
        "graceful_shutdown_tree must fail before signalling, not after hard-killing"
    );
    assert_no_break_sent();
    kill_release_reap(&child, sock, true);

    // The lone ops. The child's own flags do not exclude delivery; it is the caller that cannot send.
    let (child, sock) = spawn_ignoring_root();
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    assert!(
        matches!(child.terminate(), Err(Error::NoConsole { .. })),
        "terminate must report NoConsole"
    );
    assert_eq!(
        child.is_alive(),
        Liveness::Alive,
        "a fail-fast terminate leaves the child alone"
    );
    assert!(
        matches!(child.graceful_shutdown(Duration::ZERO), Err(Error::NoConsole { .. })),
        "graceful_shutdown must report NoConsole"
    );
    assert_eq!(
        child.is_alive(),
        Liveness::Alive,
        "graceful_shutdown must fail before signalling, not after hard-killing"
    );
    assert_no_break_sent();
    kill_release_reap(&child, sock, false);

    report_done(&mut report);
}
