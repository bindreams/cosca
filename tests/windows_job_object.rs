//! The public `cosca::Job` primitive, end to end: a caller that spawns its own process via a raw
//! `CreateProcessW` (never going through `cosca::Command`) follows the mandatory
//! suspend/assign/resume sequence from `cosca::Job`'s own docs, and the kernel guarantee that
//! buys must actually hold — every descendant, including a grandchild the root spawns AFTER
//! being resumed, is genuinely reachable through the job.
//!
//! Both required behaviors need a real, provably-alive descendant tree, not merely "hasn't been
//! reaped yet": `control-block`'s EOF-on-death is proof of death, never proof of life. Both
//! members here run the testbin's `control-echo-pid` round-trip (via `spawn-grandchild-echo`),
//! mirroring `tests/macos_fdmarker.rs`'s `Member` (alive = a real write/read round trip; dead =
//! EOF/reset on a socket the test itself still holds).
#![cfg(windows)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::windows::io::{BorrowedHandle, RawHandle};

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, TerminateProcess, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
};

/// One tree member's control channel: its pid, the socket that proves it alive or dead, and
/// an owned handle opened while it was provably alive.
///
/// The handle is what makes cleanup safe. Terminating by pid alone races the member's own
/// exit: Windows recycles a dead process's pid, so a pid read at handshake time can name an
/// unrelated process by the time a test tears down — and on a shared CI runner that is
/// someone else's process. An open handle pins the pid for as long as it is held, so the
/// terminate can only ever land on the intended member.
///
/// Mirrors `tests/macos_fdmarker.rs`'s `Member`.
struct Member {
    pid: u32,
    sock: TcpStream,
    process: HANDLE,
}

impl Drop for Member {
    fn drop(&mut self) {
        // SAFETY: `process` is this struct's own handle, opened once and closed only here.
        unsafe {
            let _ = TerminateProcess(self.process, 1);
            let _ = CloseHandle(self.process);
        }
    }
}

impl Member {
    /// Alive, proven positively: a byte in, the same byte back. A dead member EOFs instead.
    fn assert_alive(&mut self, who: &str) {
        self.sock.write_all(b"x").expect("write to the control socket");
        let mut b = [0u8; 1];
        let n = self.sock.read(&mut b).expect("read the control socket");
        assert_eq!(n, 1, "{who} (pid {}) must still be alive and echoing", self.pid);
        assert_eq!(&b, b"x", "{who} echoed {b:?} instead of the byte sent");
    }

    /// Dead, proven by a write failure OR a read failure/EOF on a socket the test still holds.
    fn assert_dead(&mut self, who: &str) {
        if self.sock.write_all(b"x").is_err() {
            return; // the peer already closed its end: dead, as expected
        }
        let mut b = [0u8; 1];
        match self.sock.read(&mut b) {
            Ok(0) => {} // EOF: dead, as expected
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                // the kernel resolved the race the other way (RST before FIN): also dead
            }
            Ok(n) => panic!("{who} (pid {}) must be dead; it echoed {n} byte(s) instead", self.pid),
            Err(e) => panic!("{who} (pid {}): unexpected control-socket error: {e}", self.pid),
        }
    }
}

/// A process created `CREATE_SUSPENDED` via a raw `CreateProcessW` call — never through
/// `cosca::Command` — so the test genuinely exercises the caller sequence `cosca::Job`'s docs
/// describe: create suspended, assign, only then resume.
struct Suspended {
    process: HANDLE,
    thread: HANDLE,
    pid: u32,
}

impl Suspended {
    /// Spawn `exe` with `args` (argv[1..]), suspended. The command line is built with
    /// `cosca::quote::windows::join_wide` rather than hand-rolled quoting.
    fn spawn(exe: &str, args: &[&str]) -> Suspended {
        let wide_args: Vec<Vec<u16>> = std::iter::once(exe)
            .chain(args.iter().copied())
            .map(|a| a.encode_utf16().collect())
            .collect();
        let refs: Vec<&[u16]> = wide_args.iter().map(Vec::as_slice).collect();
        let mut cmdline = cosca::quote::windows::join_wide(&refs);
        cmdline.push(0); // CreateProcessW requires a NUL-terminated, writable buffer.

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        // Serialized against the crate's own inheritable-handle window, exactly like
        // `tests/windows_console_identity.rs`'s `probe_raw` — a raw spawn that bypasses
        // `cosca::Command` entirely still needs to be ordered against it.
        let created = {
            let _guard = cosca::test_spawn_lock();
            // SAFETY: `cmdline` is a NUL-terminated, writable UTF-16 buffer; `si`/`pi` are
            // valid, correctly-sized in/out params; no handles are inherited.
            unsafe {
                CreateProcessW(
                    None,
                    Some(PWSTR(cmdline.as_mut_ptr())),
                    None,
                    None,
                    false,
                    CREATE_SUSPENDED,
                    None,
                    None,
                    &si,
                    &mut pi,
                )
            }
        };
        created.expect("CreateProcessW(CREATE_SUSPENDED)");
        Suspended {
            process: pi.hProcess,
            thread: pi.hThread,
            pid: pi.dwProcessId,
        }
    }

    /// Borrow the process handle for [`cosca::Job::assign`]. The borrow does not outlive this
    /// call; `Suspended` keeps owning (and eventually closing) the real handle.
    fn borrow_process(&self) -> BorrowedHandle<'_> {
        let raw: RawHandle = self.process.0;
        // SAFETY: `self.process` is a live handle owned by `self`, which outlives this borrow.
        unsafe { BorrowedHandle::borrow_raw(raw) }
    }

    /// Resume the (single) initial thread. Must only be called after the process has been
    /// assigned to a job — see `cosca::Job`'s mandatory sequence.
    fn resume(&mut self) {
        // SAFETY: `self.thread` is the live, still-suspended main thread from `CreateProcessW`.
        let prev = unsafe { ResumeThread(self.thread) };
        assert_eq!(
            prev, 1,
            "pid {}: a CREATE_SUSPENDED process's main thread must resume from exactly one suspend",
            self.pid
        );
    }
}

impl Drop for Suspended {
    fn drop(&mut self) {
        // Best-effort cleanup: whether the tree is contained, disarmed, or already dead by the
        // time a test ends, nothing should be left running past it. `TerminateProcess` on an
        // already-exited process is a harmless failure.
        // SAFETY: `self.process`/`self.thread` are live, owned handles.
        unsafe {
            let _ = TerminateProcess(self.process, 1);
            let _ = CloseHandle(self.thread);
            let _ = CloseHandle(self.process);
        }
    }
}

/// Spawn the testbin's `spawn-grandchild-echo` tree, contained: create the root suspended,
/// assign it to a fresh `cosca::Job`, resume it, then demux both members' `<tag><pid>\n`
/// handshakes by tag. The grandchild is spawned by the ROOT after resume — proving the job
/// reaches a descendant this test process never itself created or assigned.
fn spawn_contained_tree() -> (Suspended, cosca::Job, Member, Member) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();

    let mut root = Suspended::spawn(env!("CARGO_BIN_EXE_cosca_testbin"), &["spawn-grandchild-echo", &addr]);
    // Step 1 (spawn suspended) already happened above. Step 2: assign, while still frozen.
    let job = cosca::Job::assign(root.borrow_process()).expect("Job::assign");
    // Step 3: only now resume.
    root.resume();

    let mut root_member = None;
    let mut grand_member = None;
    for _ in 0..2 {
        let (s, _) = listener.accept().expect("accept");
        let mut line = String::new();
        BufReader::new(s.try_clone().expect("clone"))
            .read_line(&mut line)
            .expect("read tag+pid");
        let (tag, pid) = line.trim().split_at(1);
        let pid: u32 = pid.parse().expect("member pid");
        // Opened here, while the handshake proves the member alive — see `Member`'s doc for
        // why a pid captured now cannot be trusted at teardown.
        // SAFETY: standard Win32 call; the handle is closed by `Member::drop`.
        let process = unsafe {
            windows::Win32::System::Threading::OpenProcess(
                windows::Win32::System::Threading::PROCESS_TERMINATE,
                false,
                pid,
            )
            .expect("open the member that just completed its handshake")
        };
        let m = Member { pid, sock: s, process };
        match tag {
            "R" => root_member = Some(m),
            "G" => grand_member = Some(m),
            other => panic!("unexpected tree tag {other:?}"),
        }
    }
    (
        root,
        job,
        root_member.expect("root tag"),
        grand_member.expect("grandchild tag"),
    )
}

/// The contract this whole primitive exists for: a caller that spawns its own process
/// (suspend/assign/resume, never `cosca::Command`) still gets the full kernel guarantee —
/// `kill_tree()` reaps every descendant, including one the root spawned after being resumed.
#[test]
fn kill_tree_reaps_every_descendant() {
    let (_root, job, mut root_member, mut grand_member) = spawn_contained_tree();
    root_member.assert_alive("the root, before teardown");
    grand_member.assert_alive("the grandchild, before teardown");

    job.kill_tree().expect("kill_tree");

    root_member.assert_dead("the root, after kill_tree");
    grand_member.assert_dead("the grandchild, after kill_tree");
}

/// The other half of the contract: `disarm()` is "session ended normally, leave background
/// processes alone" — dropping (or having already dropped) the `Job` afterward must not kill
/// anything, for the whole tree, not just the root.
#[test]
fn disarm_leaves_every_descendant_running() {
    let (root, job, mut root_member, mut grand_member) = spawn_contained_tree();
    root_member.assert_alive("the root, before disarm");
    grand_member.assert_alive("the grandchild, before disarm");

    job.disarm();
    drop(job);

    root_member.assert_alive("the root, after disarm + drop(Job)");
    grand_member.assert_alive("the grandchild, after disarm + drop(Job)");

    // Cleanup: `Suspended::drop` only reaches the root; the grandchild survives it, because a
    // disarmed job is by design no longer this test's tool for reaching it. `Member::drop`
    // terminates each through its own pinned handle.
    root_member.sock.shutdown(std::net::Shutdown::Both).ok();
    grand_member.sock.shutdown(std::net::Shutdown::Both).ok();
    drop(root);
}

/// Dropping a live `Job` reaps the tree, exactly as `kill_tree` does.
///
/// This is the path a caller reaches by doing nothing, and it is the one the `#[must_use]` on
/// `assign` warns about — so it needs coverage of its own rather than being inferred from
/// `kill_tree`'s. The distinction matters: `kill_tree` terminates explicitly, whereas this
/// relies on `KILL_ON_JOB_CLOSE` firing when the last handle closes.
#[test]
fn dropping_a_live_job_reaps_every_descendant() {
    let (root, job, mut root_member, mut grand_member) = spawn_contained_tree();
    root_member.assert_alive("the root, before drop");
    grand_member.assert_alive("the grandchild, before drop");

    drop(job);

    root_member.assert_dead("the root, after dropping the Job");
    grand_member.assert_dead("the grandchild, after dropping the Job");
    drop(root);
}
