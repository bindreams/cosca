//! Proving that a `kill_tree` killed the members of a tree, by assertion.
//!
//! A test that ends a tree and then reads a member's socket for EOF hangs if the kill sent
//! nothing. [`assert_members_killed`] fails by assertion instead, and never waits on a member that
//! a missing kill left alive. Call them right after the kill, before any wait on the tree.

use std::io::{Read, Write};
use std::net::TcpStream;

#[path = "../../testbin/echo_held.rs"]
mod echo_held;
pub use echo_held::ECHO_HELD_ENV;
pub use echo_held::RELEASED_EXIT_ENV;

/// Prove a member that echoes (see [`ECHO_HELD_ENV`]) is dead without waiting for its death: send
/// a byte and read. A killed member refuses the write or gives EOF or a reset on the read; one a
/// missing kill left alive echoes the byte, so a `kill_tree` that sends nothing fails by assertion
/// instead of hanging a read for an EOF.
///
/// Unix only: it relies on a delivered `SIGKILL` (or a `SIGTERM` the member does not handle) being
/// pending before the call returns, so the member dies before it can echo. Windows uses
/// [`assert_members_killed`].
pub fn assert_dead(sock: &mut TcpStream, who: &str) {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset};
    // A dead peer surfaces on the write, or on the read: BSD checks `so_error` before EOF, so the
    // read may be a reset rather than `Ok(0)`. Only an echoed byte means alive.
    if sock.write_all(b"p").is_err() {
        return;
    }
    let mut b = [0u8; 1];
    match sock.read(&mut b) {
        Ok(0) => {}
        Err(e) if matches!(e.kind(), ConnectionReset | ConnectionAborted | BrokenPipe) => {}
        other => panic!("{who} must be dead after the kill, but answered: {other:?}"),
    }
}

/// A tree member's pid and control socket, plus on Windows a handle on its process. Build it while
/// the member is alive and blocked on `sock`, before the kill: a live member cannot exit, so its pid
/// cannot be reissued before the handle is open. The open handle then pins the pid, so on Windows
/// dropping a `Member` terminates the process it was built on and no other, which a bare pid could
/// not promise once the member exits.
pub struct Member {
    pub pid: u32,
    pub sock: TcpStream,
    #[cfg(windows)]
    exit: windows_exit::ExitHandle,
}

impl Member {
    pub fn new(sock: TcpStream, pid: u32) -> Member {
        Member {
            pid,
            sock,
            #[cfg(windows)]
            exit: windows_exit::ExitHandle::open(pid),
        }
    }

    /// Alive, proven positively: a byte in, the same byte back. The member must be one that echoes
    /// (`control-echo-pid`, or a `control-block` family member with [`ECHO_HELD_ENV`] set).
    pub fn assert_alive(&mut self, who: &str) {
        self.sock.write_all(b"x").expect("write to the control socket");
        let mut b = [0u8; 1];
        let n = self.sock.read(&mut b).expect("read the control socket");
        assert_eq!(n, 1, "{who} (pid {}) must still be alive and echoing", self.pid);
        assert_eq!(&b, b"x", "{who} echoed {b:?} instead of the byte sent");
    }

    /// [`assert_dead`] on this member's socket, naming its pid.
    #[cfg(unix)]
    pub fn assert_dead(&mut self, who: &str) {
        assert_dead(&mut self.sock, &format!("{who} (pid {})", self.pid));
    }
}

/// The exit code a `control-echo-pid` member leaves with when released, for a tree started with
/// [`RELEASED_EXIT_ENV`] set to it. Chosen to differ from every code a kill produces.
pub const RELEASED_EXIT_CODE: u32 = 77;

/// Assert that `kill_tree` killed every member, each named for the failure message.
///
/// Unix: [`assert_dead`] on each. Windows: release every member (close its socket), then wait for
/// each process to exit and assert it died to the kill's exit code `1`. `TerminateProcess` only
/// starts termination, so a probe right after the kill could still be answered by a member that
/// is about to die; the exit event cannot. A member a missing kill left alive leaves on the
/// release with `0`, so the wait ends either way and a missing kill fails by assertion.
pub fn assert_members_killed(members: Vec<(Member, &str)>) {
    #[cfg(unix)]
    for (mut member, who) in members {
        assert_dead(&mut member.sock, who);
    }
    #[cfg(windows)]
    for (code, who) in release_and_wait(members) {
        assert_eq!(
            code, 1,
            "{who} must die to the kill (exit code 1), not leave on its own when released"
        );
    }
}

/// Assert that a teardown that does not wait (a drop) ended every member. Windows: as
/// [`assert_members_not_released`], so the tree must have been started with [`RELEASED_EXIT_ENV`].
/// Unix: [`assert_dead`] on each, so the members must echo.
pub fn assert_members_torn_down(members: Vec<(Member, &str)>) {
    #[cfg(windows)]
    assert_members_not_released(members);
    #[cfg(unix)]
    for (mut member, who) in members {
        assert_dead(&mut member.sock, who);
    }
}

/// The exit codes a testbin member can leave with for a reason other than the kill, besides
/// [`RELEASED_EXIT_CODE`]: `101` (a Rust panic) and the NTSTATUS codes of an access violation, an
/// illegal instruction and a fast-fail abort.
#[cfg(windows)]
const CRASH_EXIT_CODES: [u32; 4] = [101, 0xC000_0005, 0xC000_001D, 0xC000_0409];

/// Windows: assert that every member died to the kill and none left for another reason. For a kill
/// whose own exit code is not known (`KILL_ON_JOB_CLOSE`): the tree was started with
/// [`RELEASED_EXIT_ENV`] set to [`RELEASED_EXIT_CODE`], so a member the kill missed leaves on the
/// release with that code. A member that crashed on the release (a panic on a reset socket, say)
/// leaves with one of [`CRASH_EXIT_CODES`] and must not pass as killed either.
#[cfg(windows)]
pub fn assert_members_not_released(members: Vec<(Member, &str)>) {
    for (code, who) in release_and_wait(members) {
        println!("{who}: exit code {code:#x}");
        assert_ne!(
            code, RELEASED_EXIT_CODE,
            "{who} must be killed, not leave on its own when released (exit code {code:#x})"
        );
        assert!(
            !CRASH_EXIT_CODES.contains(&code),
            "{who} must be killed, not crash when released (exit code {code:#x})"
        );
    }
}

/// Block until `pid` has exited, then its exit status, consuming nothing: on Unix it stays an
/// unreaped zombie ([`zombie_exit_status`](super::zombie_exit_status)), on Windows the wait is on a
/// handle of its own. The caller's handle on the child must pin `pid`.
pub fn exit_status_once_exited(pid: u32) -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        super::zombie_exit_status(pid)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt as _;
        std::process::ExitStatus::from_raw(windows_exit::ExitHandle::open(pid).wait_for_exit_code())
    }
}

/// Release every member (close its socket), then wait for each process to exit and return its
/// exit code.
#[cfg(windows)]
fn release_and_wait(members: Vec<(Member, &str)>) -> Vec<(u32, &str)> {
    let mut exits = Vec::new();
    for (member, who) in members {
        drop(member.sock);
        exits.push((member.exit, who));
    }
    exits
        .into_iter()
        .map(|(exit, who)| (exit.wait_for_exit_code(), who))
        .collect()
}

#[cfg(windows)]
mod windows_exit {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, TerminateProcess, WaitForSingleObject, INFINITE,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };

    /// A process handle that can wait for the exit, read the exit code and terminate the process.
    pub struct ExitHandle(HANDLE);

    impl ExitHandle {
        pub fn open(pid: u32) -> ExitHandle {
            // SAFETY: plain Win32 call; the handle is owned and closed by `Drop`.
            let handle = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                    false,
                    pid,
                )
            }
            .unwrap_or_else(|e| panic!("OpenProcess({pid}) for the exit watch: {e}"));
            ExitHandle(handle)
        }

        /// Block until the process has exited (the kernel's exit event), then its exit code.
        pub fn wait_for_exit_code(&self) -> u32 {
            // SAFETY: `self.0` is a live handle this struct owns.
            let waited = unsafe { WaitForSingleObject(self.0, INFINITE) };
            assert_eq!(waited, WAIT_OBJECT_0, "waiting for the process to exit: {waited:?}");
            let mut code = 0u32;
            // SAFETY: as above; `code` is a valid out-pointer.
            unsafe { GetExitCodeProcess(self.0, &mut code) }.expect("GetExitCodeProcess");
            code
        }
    }

    impl Drop for ExitHandle {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live handle this struct owns. The open handle pins the pid, so
            // this can only reach the member it was opened on; a process that already exited makes
            // it fail harmlessly.
            let _ = unsafe { TerminateProcess(self.0, 1) };
            // SAFETY: closes the handle `open` returned.
            let closed = unsafe { CloseHandle(self.0) };
            debug_assert!(closed.is_ok(), "CloseHandle on the exit watch failed: {closed:?}");
        }
    }
}
