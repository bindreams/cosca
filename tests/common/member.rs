//! Proving that a `kill_tree` killed the members of a tree, by assertion.
//!
//! A test that ends a tree and then reads a member's socket for EOF hangs if the kill sent
//! nothing. [`assert_members_killed`] fails by assertion instead, and never waits on a member that
//! a missing kill left alive.

use std::io::{Read, Write};
use std::net::TcpStream;

/// The env var that makes the testbin's `control-block` family echo each byte the test writes
/// instead of leaving on it, so [`assert_dead`] can tell a killed member from one that is alive.
/// The `control-echo-pid` members echo regardless. Keep in sync with `ECHO_HELD_ENV` in
/// `testbin/main.rs`: a rename on one side makes `assert_dead` pass for a member that exited.
pub const ECHO_HELD_ENV: &str = "COSCA_TEST_ECHO_HELD";

/// Prove a member that echoes (see [`ECHO_HELD_ENV`]) is DEAD without waiting for its death: send
/// a byte and read. A killed member refuses the write or gives EOF or a reset on the read; one a
/// missing kill left alive echoes the byte. That makes a `kill_tree` that sends nothing fail here
/// by assertion instead of hanging a blocking read for an EOF, so call it right after the kill,
/// before any wait on the tree.
///
/// Unix only in effect (see [`assert_members_killed`] for the portable form): it rests on a
/// delivered `SIGKILL` being pending before the kill call returns, so the member cannot run user
/// code again. `TerminateProcess` and `TerminateJobObject` only START termination, so on Windows a
/// member may still echo for a moment after the kill returned.
pub fn assert_dead(sock: &mut TcpStream, who: &str) {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset};
    // A dead peer can surface on the write (the FIN or RST already arrived) or, if the write went
    // through, on the read: macOS (BSD `soreceive`) checks `so_error` before end-of-file, so the
    // read can return `ECONNRESET` or `EPIPE` instead of `Ok(0)`. Every write error means the
    // peer is gone; only an echoed byte means it is alive.
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

/// A tree member's control socket, plus on Windows a handle on its process. Build it while the
/// member is alive and blocked on `sock`, before the kill: a live member cannot exit, so its pid
/// cannot be reissued before the handle is open.
pub struct Member {
    pub sock: TcpStream,
    #[cfg(windows)]
    exit: windows_exit::ExitHandle,
}

impl Member {
    pub fn new(sock: TcpStream, pid: u32) -> Member {
        #[cfg(not(windows))]
        let _ = pid;
        Member {
            sock,
            #[cfg(windows)]
            exit: windows_exit::ExitHandle::open(pid),
        }
    }
}

/// Assert that `kill_tree` killed every member, each named for the failure message. Call it right
/// after the kill, before any wait on the tree.
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
    {
        let mut exits = Vec::new();
        for (member, who) in members {
            drop(member.sock);
            exits.push((member.exit, who));
        }
        for (exit, who) in exits {
            assert_eq!(
                exit.wait_for_exit_code(),
                1,
                "{who} must die to the kill (exit code 1), not leave on its own when released"
            );
        }
    }
}

#[cfg(windows)]
mod windows_exit {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    };

    /// A process handle that can wait for the exit and read the exit code.
    pub struct ExitHandle(HANDLE);

    impl ExitHandle {
        pub fn open(pid: u32) -> ExitHandle {
            // SAFETY: plain Win32 call; the handle is owned and closed by `Drop`.
            let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
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
            // SAFETY: closes the handle `open` returned.
            let closed = unsafe { CloseHandle(self.0) };
            debug_assert!(closed.is_ok(), "CloseHandle on the exit watch failed: {closed:?}");
        }
    }
}
