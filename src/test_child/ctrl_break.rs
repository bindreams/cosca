//! Windows fixtures for the tests that prove a `CTRL_BREAK` arrived: a re-exec'd member with a
//! chosen console-ctrl disposition, optionally the root of a grandchild in its own console process
//! group, and the caller's side of its handshake.
//!
//! A break lands asynchronously, and the OS runs a console handler on a thread it creates in the
//! target, so "did it see a break yet?" has no answer a caller can trust. The tests built on these
//! assert first that the break was sent to the expected group ([`assert_break_sent_to`], which reads
//! the sender's own record) and only then wait, with no deadline, for the member's own evidence:
//! its handler's ack, or its exit code. A call that sent nothing fails that assertion instead of
//! leaving the wait unbounded, and nothing is released that could race the break. The sender must
//! therefore run in a process of this binary: a probe in another binary has no record to read.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use super::{accept_or_die, ack, fixture_argv};

pub(crate) mod console_less;
pub(crate) mod nested;

/// The fully-qualified libtest path of [`fixture_ctrl_break_member`].
pub(crate) const MEMBER_TEST: &str = "test_child::ctrl_break::fixture_ctrl_break_member";

/// The `127.0.0.1:<port>` address the member connects to. Its presence also tells the fixture it
/// was re-exec'd deliberately rather than picked up by an ordinary suite run.
const ADDR_ENV: &str = "COSCA_FIXTURE_CTRL_BREAK_ADDR";
/// The member's tag byte: `R` for a root, `G` for the grandchild it starts.
const TAG_ENV: &str = "COSCA_FIXTURE_CTRL_BREAK_TAG";
/// The member's [`Handler`].
const HANDLER_ENV: &str = "COSCA_FIXTURE_CTRL_BREAK_HANDLER";
/// Set on a root: the [`Handler`] of the grandchild it starts.
const GRANDCHILD_ENV: &str = "COSCA_FIXTURE_CTRL_BREAK_GRANDCHILD";

/// How a member answers a console control event.
#[derive(Clone, Copy)]
pub(crate) enum Handler {
    /// No handler: a delivered break ends it with [`STATUS_CONTROL_C_EXIT`].
    Default,
    /// Writes `B` to its control socket on `CTRL_BREAK` and keeps running.
    Ack,
    /// Handles every event and keeps running, so only a kill ends it.
    Ignore,
    /// Frees its console before its tag, so it is outside ours: a break reaches nobody and only a
    /// kill ends it.
    Detached,
}

impl Handler {
    fn name(self) -> &'static str {
        match self {
            Handler::Default => "default",
            Handler::Ack => "ack",
            Handler::Ignore => "ignore",
            Handler::Detached => "detached",
        }
    }
}

/// The exit code of a process a delivered `CTRL_BREAK` ended through the default disposition. A
/// kill gives `1`, and a break that lands before the process could handle it `0xC0000142`.
pub(crate) const STATUS_CONTROL_C_EXIT: i32 = 0xC000_013A_u32 as i32;

/// The argv of a re-exec'd [`fixture_ctrl_break_member`]; see [`fixture_argv`].
pub(crate) fn member_argv() -> [&'static str; 5] {
    fixture_argv(MEMBER_TEST)
}

/// The environment of a root member that connects to `addr`, answers with `handler`, and starts a
/// grandchild answering with `grandchild` when given. Apply it after
/// [`scrub_env`](crate::test_reexec::scrub_env).
pub(crate) fn member_env(addr: &str, handler: Handler, grandchild: Option<Handler>) -> Vec<(&'static str, String)> {
    let mut env = vec![
        (ADDR_ENV, addr.to_owned()),
        (TAG_ENV, "R".to_owned()),
        (HANDLER_ENV, handler.name().to_owned()),
        (ack::ACK_ENV, "1".to_owned()),
    ];
    if let Some(grandchild) = grandchild {
        env.push((GRANDCHILD_ENV, grandchild.name().to_owned()));
    }
    env
}

/// Connects, installs its [`Handler`], writes its tag, and blocks on a read of its socket until the
/// caller closes it (then exits 0) or something ends it. A root with [`GRANDCHILD_ENV`] set starts
/// that grandchild after its tag, with no creation flags, so it stays in the root's console process
/// group, and then writes the grandchild's pid (4 bytes, little-endian). The grandchild connects to
/// the same address with tag `G`. The root holds the grandchild's process handle while it lives, so
/// the pid stays the grandchild's.
///
/// The tag is the readiness edge: the member cannot write it before it runs its own code, which on
/// Windows is also after the console has registered it and after its handler is installed.
#[skuld::test]
fn fixture_ctrl_break_member() {
    let Some(addr) = std::env::var_os(ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    let addr = addr.into_string().expect("utf8 addr");
    let tag = std::env::var(TAG_ENV).expect("the member's tag");
    let mut sock = ack::connect_control(&addr).expect("connect the control socket");
    match std::env::var(HANDLER_ENV).expect("the member's handler").as_str() {
        "default" => {}
        "ack" => install_ack(&sock),
        "ignore" => install_ignore(),
        "detached" => free_console(),
        other => panic!("unknown handler {other:?}"),
    }
    sock.write_all(tag.as_bytes()).expect("write the tag");
    let _grandchild = std::env::var(GRANDCHILD_ENV).ok().map(|handler| {
        let grandchild = crate::test_spawn::spawn(
            crate::test_reexec::command(std::env::current_exe().expect("current_exe"))
                // `[1..]`: skip `fixture_argv`'s slot-0 placeholder; `std::process::Command` supplies argv[0].
                .args(&member_argv()[1..])
                .env(TAG_ENV, "G")
                .env(HANDLER_ENV, handler)
                .env_remove(GRANDCHILD_ENV)
                .stdout(std::process::Stdio::null()),
        )
        .expect("spawn the grandchild");
        sock.write_all(&grandchild.id().to_le_bytes())
            .expect("report the grandchild's pid");
        grandchild
    });
    sock.flush().expect("flush");
    let mut sink = [0u8; 1];
    _ = sock.read(&mut sink);
}

/// Acks a `CTRL_BREAK` by writing `B` through a clone of `sock`, and keeps the process running.
/// Only `CTRL_BREAK` is acked, so a stray `CTRL_C` or `CTRL_CLOSE` cannot pass for it.
fn install_ack(sock: &TcpStream) {
    use std::sync::{Mutex, OnceLock};

    use windows::core::BOOL;
    use windows::Win32::System::Console::{SetConsoleCtrlHandler, CTRL_BREAK_EVENT};

    // The handler runs on a thread the OS creates, not in signal context, so allocating I/O is
    // fine. Nothing in it may panic: unwinding out of an `extern "system"` fn aborts.
    static ACK: OnceLock<Mutex<TcpStream>> = OnceLock::new();
    unsafe extern "system" fn ack(event: u32) -> BOOL {
        if event != CTRL_BREAK_EVENT {
            return BOOL(0); // not handled: the default disposition applies
        }
        let Some(Ok(mut sock)) = ACK.get().map(Mutex::lock) else {
            return BOOL(0);
        };
        match sock.write_all(b"B").and_then(|()| sock.flush()) {
            Ok(()) => BOOL(1), // handled: keep running
            Err(_) => BOOL(0),
        }
    }
    ACK.set(Mutex::new(sock.try_clone().expect("clone the control socket")))
        .expect("one handler per process");
    // SAFETY: installing a console ctrl handler has no preconditions.
    unsafe { SetConsoleCtrlHandler(Some(ack), true) }.expect("install the ctrl handler");
}

/// Leaves the console the process was started in, so a break to its group reaches nobody.
fn free_console() {
    // SAFETY: no preconditions.
    unsafe { windows::Win32::System::Console::FreeConsole() }.expect("free the console");
}

/// Handles every console control event, so the process keeps running.
fn install_ignore() {
    use windows::core::BOOL;
    use windows::Win32::System::Console::SetConsoleCtrlHandler;

    unsafe extern "system" fn ignore(_event: u32) -> BOOL {
        BOOL(1)
    }
    // SAFETY: installing a console ctrl handler has no preconditions.
    unsafe { SetConsoleCtrlHandler(Some(ignore), true) }.expect("install the ctrl handler");
}

// The caller's side =====

/// A [`fixture_ctrl_break_member`] root answering with `handler`, after its handshake, and the
/// grandchild it starts in its console process group when `grandchild` is given. It is spawned
/// contained (`mode`), or as a nested member when the caller is itself contained; `configure` is
/// applied to the command last. The root's socket keeps it running while held.
pub(crate) fn spawn_member(
    handler: Handler,
    grandchild: Option<Handler>,
    mode: crate::ContainMode,
    configure: impl FnOnce(&mut crate::Command),
) -> (crate::Child, TcpStream, Option<Grandchild>) {
    let (listener, addr) = crate::test_child::registration_rendezvous();
    let mut cmd = crate::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(member_argv());
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    for (key, value) in member_env(&addr, handler, grandchild) {
        cmd.env(key, value);
    }
    cmd.contain_with(mode);
    configure(&mut cmd);
    let child = cmd.spawn().expect("spawn the root");
    let mut sock = accept_root(&listener, child.id());
    let grand = grandchild.map(|_| accept_grandchild(&listener, &mut sock));
    (child, sock, grand)
}

/// Require that `pid` shares our console, after its handshake: a break to a group outside it is
/// accepted and lost.
pub(crate) fn assert_in_our_console(pid: u32, who: &str) {
    assert_eq!(
        in_our_console(pid),
        Some(true),
        "{who} must share our console for the break to be deliverable"
    );
}

/// Read the `B` an acking member writes when its handler receives the break. Call it only after
/// [`assert_break_sent_to`]: the handler runs on a thread the OS creates, so the read waits for it,
/// and only a send that really happened ends that wait.
pub(crate) fn assert_acked(sock: &mut TcpStream, who: &str) {
    let mut ack = [0u8; 1];
    sock.read_exact(&mut ack)
        .unwrap_or_else(|e| panic!("{who} must acknowledge the break: {e}"));
    assert_eq!(&ack, b"B", "{who} acked something other than CTRL_BREAK");
}

/// Accepts the root member `root` (death-watched) and reads its tag.
pub(crate) fn accept_root(listener: &TcpListener, root: crate::identity::ProcessId) -> TcpStream {
    let mut sock = accept_or_die(listener, root);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("the root's tag");
    assert_eq!(&tag, b"R", "wrong root tag");
    sock
}

/// The grandchild a root member started: its control socket, which keeps it running while held,
/// and a handle on its process.
pub(crate) struct Grandchild {
    pub(crate) sock: TcpStream,
    pub(crate) exit: ExitWatch,
}

/// Reads the grandchild's pid from the root's socket (after [`accept_root`]), opens its process,
/// then accepts its connection (death-watched) and reads its tag. The root holds the grandchild's
/// handle while it lives, and the caller holds the root's socket, so the pid cannot be reissued
/// before the open.
pub(crate) fn accept_grandchild(listener: &TcpListener, root_sock: &mut TcpStream) -> Grandchild {
    let mut pid = [0u8; 4];
    root_sock.read_exact(&mut pid).expect("the grandchild's pid");
    let pid = u32::from_le_bytes(pid);
    let exit = ExitWatch::open(pid);
    let id = crate::identity::ProcessId::of(pid)
        .found()
        .expect("the grandchild resolves while the root holds its handle");
    let mut sock = accept_or_die(listener, id);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("the grandchild's tag");
    assert_eq!(&tag, b"G", "wrong grandchild tag");
    Grandchild { sock, exit }
}

/// A contained [`Handler::Ignore`] root after its handshake, and its control socket, which keeps it
/// running while held (it leaves with 0 once the socket closes). For a test whose root only a kill
/// ends and which sends a break first: the handshake is the readiness edge, so the break cannot land
/// before the root could handle it.
pub(crate) fn spawn_ignoring_root() -> (crate::Child, TcpStream) {
    let (child, sock, _) = spawn_member(Handler::Ignore, None, crate::ContainMode::Strongest, |_| {});
    (child, sock)
}

/// [`spawn_ignoring_root`] for the tokio `Child`.
#[cfg(feature = "tokio")]
pub(crate) fn spawn_ignoring_root_async() -> (crate::tokio::Child, TcpStream) {
    let (listener, addr) = crate::test_child::registration_rendezvous();
    let mut cmd = crate::tokio::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(member_argv());
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    for (key, value) in member_env(&addr, Handler::Ignore, None) {
        cmd.env(key, value);
    }
    cmd.contain();
    let child = cmd.spawn().expect("spawn the root");
    let sock = accept_root(&listener, child.id());
    (child, sock)
}

/// Assert that the call under test sent exactly one `CTRL_BREAK`, to the group led by `group`.
pub(crate) fn assert_break_sent_to(group: u32) {
    assert_eq!(
        crate::containment::windows::observe::take_ctrl_breaks(),
        [group],
        "the call must send one CTRL_BREAK, to the group led by {group}"
    );
}

/// Kill the member (its whole tree when `tree`), then release it: a released member leaves with 0,
/// so code 1 is the kill's.
pub(crate) fn kill_release_reap(child: &crate::Child, sock: TcpStream, tree: bool) {
    if tree {
        child.kill_tree().expect("kill_tree");
    } else {
        child.kill().expect("kill");
    }
    drop(sock);
    let status = child.wait().expect("reap");
    assert_eq!(status.code(), Some(1), "the kill must end the member, got {status:?}");
}

/// What a reporter writes once every check passed. Anything else read before EOF, or none, means
/// it did not get that far: it panicked, or its filter matched no test.
pub(crate) const DONE: &[u8] = b"K";

/// A reporter's side of [`drive_reporter`]: connects to the driver at the address in `addr_env`
/// first, so a panic later reaches the driver as EOF. `None` when `addr_env` is unset: the fixture
/// was picked up by an ordinary suite run and stays inert.
pub(crate) fn connect_reporter(addr_env: &str) -> Option<TcpStream> {
    let addr = std::env::var_os(addr_env)?.into_string().expect("utf8 addr");
    Some(ack::connect_control(&addr).expect("connect to the driver"))
}

/// A reporter's last act: [`DONE`], after every check passed.
pub(crate) fn report_done(report: &mut TcpStream) {
    report.write_all(DONE).expect("report");
    report.flush().expect("flush the report");
}

/// The driver of a reporter: a re-exec of this binary running the fixture `test`, which finds the
/// driver's address in `addr_env` (see [`connect_reporter`]). `configure` is applied to the
/// command last. Passes only if the reporter wrote [`DONE`] and exited 0.
pub(crate) fn drive_reporter(test: &str, addr_env: &str, configure: impl FnOnce(&mut crate::Command)) {
    let (listener, addr) = crate::test_child::registration_rendezvous();
    let mut cmd = crate::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(fixture_argv(test))
        .env(addr_env, addr)
        .env(ack::ACK_ENV, "1");
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    configure(&mut cmd);
    let child = cmd.spawn().expect("spawn the reporter");
    let mut sock = accept_or_die(&listener, child.id());
    let mut report = Vec::new();
    sock.read_to_end(&mut report).expect("read the report");
    assert_eq!(
        report, DONE,
        "the reporter did not finish its checks; its panic is in its stderr"
    );
    let status = child.wait().expect("reap the reporter");
    assert!(status.success(), "the reporter failed: {status:?}");
}

/// Is `pid` attached to our console? `None` when the probe found no console at all. A break to a
/// group outside our console is accepted and delivered to no one, so a test that waits for a
/// delivered break first requires `Some(true)`, after the member's handshake.
pub(crate) fn in_our_console(pid: u32) -> Option<bool> {
    use windows::Win32::System::Console::GetConsoleProcessList;

    // Grown to the count the API reports: a buffer too small gets the required count back unfilled.
    let mut list = vec![0u32; 16];
    loop {
        // SAFETY: `list` is a valid writable slice.
        let n = unsafe { GetConsoleProcessList(&mut list) } as usize;
        if n == 0 {
            return None;
        }
        if n <= list.len() {
            return Some(list[..n].contains(&pid));
        }
        list.resize(n, 0);
    }
}

/// A handle on a process that can wait for its exit and read its exit code. Dropping it terminates
/// the process if it still runs: the open handle pins the pid, so that reaches no other process.
pub(crate) struct ExitWatch(windows::Win32::Foundation::HANDLE);

impl ExitWatch {
    fn open(pid: u32) -> ExitWatch {
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        };
        // SAFETY: plain Win32 call; `Drop` closes the handle.
        let handle = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                false,
                pid,
            )
        }
        .unwrap_or_else(|e| panic!("OpenProcess({pid}): {e}"));
        ExitWatch(handle)
    }

    /// Block until the process has exited, then its exit code.
    pub(crate) fn wait_for_exit_code(&self) -> i32 {
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
        // SAFETY: `self.0` is a live handle this struct owns.
        let waited = unsafe { WaitForSingleObject(self.0, INFINITE) };
        assert_eq!(waited, WAIT_OBJECT_0, "waiting for the exit: {waited:?}");
        let mut code = 0u32;
        // SAFETY: as above; `code` is a valid out-pointer.
        unsafe { GetExitCodeProcess(self.0, &mut code) }.expect("GetExitCodeProcess");
        code as i32
    }
}

impl Drop for ExitWatch {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::TerminateProcess;
        // SAFETY: `self.0` is a live handle this struct owns; an exited process makes this fail
        // harmlessly.
        _ = unsafe { TerminateProcess(self.0, 1) };
        // SAFETY: closes the handle `open` returned.
        let closed = unsafe { CloseHandle(self.0) };
        debug_assert!(closed.is_ok(), "CloseHandle: {closed:?}");
    }
}
