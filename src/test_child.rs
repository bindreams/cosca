//! Test-only child processes shared across the crate's unit tests.

#[cfg(target_os = "linux")]
pub(crate) mod namespaces;

#[cfg(target_os = "macos")]
#[path = "../tests/common/kevent_eintr.rs"]
mod kevent_eintr;

// Blocker fixtures =====

/// The argv of a child that does nothing until its stdin reaches EOF or it is killed: `cat`, or
/// `findstr x` on Windows. Every fixture that needs a child "still alive at some later check"
/// uses this instead of a fixed-duration `sleep`/`ping`, whose own timer would end the child on
/// its own and let a mutant that skips the kill under test pass for the wrong reason. Stdin is
/// what decides the child's fate, so the writer's lifetime is the fixture's lifetime:
///
/// - [`leaked_writer_stdin`]: the write end is never closed, so only a kill by the code under
///   test ends the child (teardown tests that own no handle on it).
/// - [`held_std_blocker`], [`held_contained_blocker`] and [`held_contained_blocker_async`]: the
///   caller holds the write end and must keep it for exactly as long as the child must stay
///   alive. Dropping it (or `std::process::Child::wait()`, which closes the piped stdin before
///   it waits) is a deliberate EOF release.
///
/// A `cat` backgrounded inside an `sh -c` script gets `/dev/null` as stdin (POSIX, for a
/// non-interactive shell) unless it is redirected explicitly, and would exit at once. Write it
/// `exec 3<&0; cat <&3 3<&- &`: `<&3` gives it the real pipe and `3<&-` closes the spare copy.
///
/// Neither `cat` nor `findstr` is proof of life by itself: `Existence::Present` is
/// zombie-inclusive, and `SIGKILL`/`TerminateProcess` land asynchronously. A liveness claim needs
/// an echo round trip through a piped stdout, or (Windows, where `findstr` does not echo) a
/// clean exit after a closed stdin.
pub(crate) const BLOCKER_ARGV: &[&str] = if cfg!(windows) { &["findstr", "x"] } else { &["cat"] };

/// A [`Stdio`](crate::stdio::Stdio) reading from a pipe whose write end is leaked (see
/// [`BLOCKER_ARGV`]).
pub(crate) fn leaked_writer_stdin() -> crate::stdio::Stdio {
    let (reader, writer) = std::io::pipe().expect("pipe");
    #[cfg(unix)]
    let file = std::fs::File::from(std::os::fd::OwnedFd::from(reader));
    #[cfg(windows)]
    let file = std::fs::File::from(std::os::windows::io::OwnedHandle::from(reader));
    std::mem::forget(writer);
    crate::stdio::Stdio::from_file(file)
}

/// Like [`leaked_writer_stdin`], but the caller keeps the write end: dropping it is the only way
/// to make the [`BLOCKER_ARGV`] child exit by itself (status 0), so a test that must see a kill
/// end it drops the writer only after the kill.
// Consumed by the Linux-only kill tests in `spawn_tests`.
#[cfg(target_os = "linux")]
pub(crate) fn held_writer_stdin() -> (crate::stdio::Stdio, std::io::PipeWriter) {
    let (reader, writer) = std::io::pipe().expect("pipe");
    #[cfg(unix)]
    let file = std::fs::File::from(std::os::fd::OwnedFd::from(reader));
    #[cfg(windows)]
    let file = std::fs::File::from(std::os::windows::io::OwnedHandle::from(reader));
    (crate::stdio::Stdio::from_file(file), writer)
}

/// A [`BLOCKER_ARGV`] `std::process::Command` with piped stdin (held by the spawned `Child`'s
/// own `stdin` field) and the given stdout. The caller spawns it under `spawn_lock()`.
pub(crate) fn held_std_blocker(stdout: std::process::Stdio) -> std::process::Command {
    let mut cmd = std::process::Command::new(BLOCKER_ARGV[0]);
    cmd.args(&BLOCKER_ARGV[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(stdout);
    cmd
}

/// A spawned, contained [`BLOCKER_ARGV`] child and the write end of its stdin.
pub(crate) fn held_contained_blocker(stdout: crate::Stdio) -> (crate::Child, std::io::PipeWriter) {
    let mut cmd = crate::Command::new();
    cmd.args(BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(stdout).expect("set stdout");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// Async twin of [`held_contained_blocker`].
#[cfg(feature = "tokio")]
pub(crate) fn held_contained_blocker_async(stdout: crate::Stdio) -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(stdout).expect("set stdout");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// A process-group member that announces its own pid on a piped stdout and then blocks on a
/// piped stdin. `pgid` is the group to join (`0` mints a new one of the member's own). The
/// caller must take [`await_member_ready`] before using the member's identity: `spawn()`
/// returning establishes neither that the image is running nor that its `setpgid` is visible.
///
/// `std::process::Child::wait()` closes the piped stdin before it waits, so `wait()` itself ends
/// the member by EOF on its `read` (non-zero exit, no signal). An assertion that a real signal
/// was the cause must check the status's `.signal()` and deliver the signal BEFORE `wait()`.
#[cfg(unix)]
pub(crate) fn member_command(pgid: i32) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("echo $$; read _ignored")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .process_group(pgid);
    cmd
}

/// Blocks until a [`member_command`] child has announced itself, and checks that the
/// announcement came from that child.
#[cfg(unix)]
pub(crate) fn await_member_ready(child: &mut std::process::Child) {
    use std::io::BufRead;
    let mut out = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("read the member's announcement");
    let announced: crate::identity::RawPid = line.trim().parse().expect("the announcement carries a pid");
    assert_eq!(
        announced,
        child.id(),
        "the announcement must come from the member itself"
    );
    // Hand the pipe back rather than dropping it: the member outlives this call, and closing
    // the read end under a live child would make any later write to it a `SIGPIPE`.
    child.stdout = Some(out.into_inner());
}

/// A [`member_command`] in its own group that exits `0` at EOF (the plain member's `read` fails
/// there, so the script would exit `1`): an unsignalled member ends by a clean exit, which a
/// signal cannot fake.
#[cfg(unix)]
pub(crate) fn exiting_member_command() -> std::process::Command {
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("echo $$; read _ignored; exit 0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    cmd
}

/// A live [`exiting_member_command`] child that has announced itself, and its identity.
#[cfg(unix)]
pub(crate) fn live_exiting_member() -> (std::process::Child, crate::identity::ProcessId) {
    let mut child = crate::test_spawn::spawn(&mut exiting_member_command()).expect("spawn the member");
    await_member_ready(&mut child);
    let id = crate::identity::ProcessId::of(child.id())
        .found()
        .expect("the live member resolves");
    (child, id)
}

/// End a [`live_exiting_member`] by EOF and assert it was never signalled: only a clean exit
/// proves no `SIGKILL`/`SIGTERM` arrived, which a `try_wait` straight after a signal cannot.
#[cfg(unix)]
pub(crate) fn release_unsignalled(mut child: std::process::Child) {
    use std::os::unix::process::ExitStatusExt;
    drop(child.stdin.take());
    let status = child.wait().expect("reap the member");
    assert_eq!(status.signal(), None, "the member must not have been signalled");
    assert_eq!(status.code(), Some(0), "the member must exit by itself");
}

/// A live [`BLOCKER_ARGV`] (`findstr`) child with piped stdin and stdout, and its identity.
#[cfg(windows)]
pub(crate) fn live_findstr_blocker() -> (std::process::Child, crate::identity::ProcessId) {
    let child =
        crate::test_spawn::spawn(&mut held_std_blocker(std::process::Stdio::piped())).expect("spawn the blocker");
    let id = crate::identity::ProcessId::of(child.id())
        .found()
        .expect("the live blocker resolves");
    (child, id)
}

/// Finish a [`live_findstr_blocker`] and assert it was never terminated: fed a matching line and
/// EOF it exits `0` and echoes the match, and `TerminateProcess` gives neither.
#[cfg(windows)]
pub(crate) fn release_findstr_unterminated(mut child: std::process::Child) {
    use std::io::{Read as _, Write as _};
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin.write_all(b"x\r\n").expect("write to the blocker");
    drop(stdin);
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_end(&mut output)
        .expect("read stdout to EOF");
    let status = child.wait().expect("reap the blocker");
    assert!(status.success(), "the blocker must exit by itself, got {status:?}");
    assert!(
        output.contains(&b'x'),
        "the blocker must echo its match, got {output:?}"
    );
}

/// Proves a `cat` blocker is alive and responsive: writes a byte to its stdin and reads it back
/// from its stdout. A killed-but-unreaped `cat` cannot echo.
#[cfg(unix)]
pub(crate) fn assert_echoes(stdin: &mut impl std::io::Write, stdout: &mut impl std::io::Read) {
    stdin.write_all(b"x").expect("write to the blocker");
    let mut echo = [0u8; 1];
    stdout
        .read_exact(&mut echo)
        .expect("the blocker must still be alive to echo");
    assert_eq!(&echo, b"x");
}

/// Block until `pid` has exited without reaping it: a zombie, which still pins its group number.
#[cfg(unix)]
pub(crate) fn wait_until_zombie(pid: u32) {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid out-parameter. WNOWAIT leaves the child reapable.
    let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
}

/// Writes `bytes` to a held blocker stdin whose reader may already be dead: `Ok` and
/// `BrokenPipe` (the kill under test already landed, so the write goes nowhere) are both
/// expected; any other error is a fixture fault and panics.
pub(crate) fn write_to_possibly_dead_stdin(stdin: &mut impl std::io::Write, bytes: &[u8]) {
    match stdin.write_all(bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(e) => panic!("writing to the held stdin failed for a reason other than a dead reader: {e}"),
    }
}

#[cfg(test)]
mod write_to_possibly_dead_stdin_tests {
    use super::write_to_possibly_dead_stdin;

    struct FailsWith(std::io::ErrorKind);
    impl std::io::Write for FailsWith {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(self.0.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_dead_reader_is_expected() {
        write_to_possibly_dead_stdin(&mut FailsWith(std::io::ErrorKind::BrokenPipe), b"x");
    }

    #[test]
    fn a_live_reader_is_expected() {
        write_to_possibly_dead_stdin(&mut Vec::new(), b"x");
    }

    #[test]
    #[should_panic(expected = "other than a dead reader")]
    fn any_other_error_panics() {
        write_to_possibly_dead_stdin(&mut FailsWith(std::io::ErrorKind::PermissionDenied), b"x");
    }
}

// Re-exec fixtures =====

#[cfg(unix)]
#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, unused_imports, reason = "only the macOS tracer fixtures use it so far")
)]
mod bounded;
#[cfg(unix)]
#[cfg_attr(
    not(target_os = "macos"),
    allow(unused_imports, reason = "only the macOS tracer fixtures use it so far")
)]
pub(crate) use bounded::{run_fixture_output_within, step, watchdog};
#[cfg(unix)]
mod scratch;
#[cfg(unix)]
pub(crate) use scratch::fixture_scratch_tempdir;

/// The accept handshake shared with `tests/common/accept.rs` and the testbin.
#[path = "../testbin/ack.rs"]
pub(crate) mod ack;

/// The ack, event precedence and drain outcome shared with `tests/common/accept.rs`.
#[path = "../tests/common/accept/shared.rs"]
pub(crate) mod shared;

/// Blocks until either `listener` gets a connection, or `target` exits first, never a bare,
/// hang-forever `accept()`. The `src/` twin of `tests/common/accept.rs`'s `accept_or_die` (a
/// separate compilation unit), built on the crate's own identity-verified exit-watch primitives
/// (`crate::wait::backend::open_verified`, `arm_proc_exit`, `block_until_exit_or_cancel`). The
/// `target` identity is verified when the watch is armed, so a reissued pid is reported as the
/// target being gone, never watched.
///
/// One thread, one wait: each platform's own multiplexer (`poll`, `kqueue`,
/// `WaitForMultipleObjects`) blocks on "the listener is readable" OR "the target exited", and this
/// thread is the only one that ever calls `listener.accept()`.
///
/// A connection is accepted and acked ([`ack`]); the fixture waits for the ack after connecting
/// when [`ack::ACK_ENV`] is set in its environment, so it cannot exit between `connect()` and the
/// accept. An exit before the accept is therefore a failure, decided without consulting the
/// accept queue.
pub(crate) fn accept_or_die(
    listener: &std::net::TcpListener,
    target: crate::identity::ProcessId,
) -> std::net::TcpStream {
    #[cfg(target_os = "linux")]
    let event = watch_linux(listener, target);
    #[cfg(target_os = "macos")]
    let event = watch_macos(listener, target);
    #[cfg(windows)]
    let event = watch_windows(listener, target);
    match event {
        WatchEvent::Connection => shared::accept_and_ack(listener),
        WatchEvent::Died => panic!("the control target (pid {}) died before it connected", target.pid()),
    }
}

/// What ended the wait.
enum WatchEvent {
    Connection,
    Died,
}

/// How a tree's drain wait ended, handed from the watcher thread to [`accept_or_signalled`]: a
/// wait that FAILED must not be reported as the tree having drained.
#[cfg(windows)]
pub(crate) struct DrainSignal {
    event: std::os::windows::io::OwnedHandle,
    outcome: shared::DrainOutcome,
}

#[cfg(windows)]
impl DrainSignal {
    pub(crate) fn new() -> Self {
        Self {
            event: crate::wait::backend::new_cancel_event().expect("create the drain event"),
            outcome: shared::DrainOutcome::default(),
        }
    }

    /// Records the result of `wait_tree` and wakes the acceptor.
    pub(crate) fn record<T: std::fmt::Debug, E: std::fmt::Display>(&self, result: Result<T, E>) {
        self.outcome.store(result);
        crate::wait::backend::signal_cancel(&self.event);
    }

    /// Runs `wait` (a `wait_tree`) and records its result; a `wait` that panics records an error.
    pub(crate) fn watch<T: std::fmt::Debug, E: std::fmt::Display>(&self, wait: impl FnOnce() -> Result<T, E>) {
        shared::run_watcher(&self.outcome, || crate::wait::backend::signal_cancel(&self.event), wait);
    }
}

/// Windows: accepts and acks a connection, or fails once `drained` is signalled. For a target
/// expected to exit at once while a descendant in the job connects, so its pid cannot be watched:
/// the job draining is the death of every possible connector. A watcher thread records
/// `wait_tree`'s result into `drained`; only this thread accepts. The connector waits for the
/// ack, so a drain with nothing accepted is a failure.
#[cfg(windows)]
pub(crate) fn accept_or_signalled(listener: &std::net::TcpListener, drained: &DrainSignal) -> std::net::TcpStream {
    use std::os::windows::io::{AsRawHandle, AsRawSocket};

    use windows::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
    use windows::Win32::Networking::WinSock::{WSAEventSelect, FD_ACCEPT, SOCKET, WSAEVENT};
    use windows::Win32::System::Threading::{WaitForMultipleObjects, INFINITE};

    let accept_event =
        crate::wait::backend::new_cancel_event().expect("create an event for the listener's accept-readiness watch");
    let sock = SOCKET(listener.as_raw_socket() as usize);
    // SAFETY: `sock` is the listener's own live socket; the event is a live, owned handle.
    let rc = unsafe {
        WSAEventSelect(
            sock,
            Some(WSAEVENT(accept_event.as_raw_handle() as _)),
            FD_ACCEPT as i32,
        )
    };
    assert_eq!(
        rc,
        0,
        "WSAEventSelect(FD_ACCEPT) on the control listener: {}",
        std::io::Error::last_os_error()
    );
    // The drain is listed first: the lowest signalled index wins.
    let handles = [
        HANDLE(drained.event.as_raw_handle()),
        HANDLE(accept_event.as_raw_handle()),
    ];
    // SAFETY: both handles are live and owned for the call's duration.
    let woken = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
    let wait_error = std::io::Error::last_os_error();
    // SAFETY: `sock` is still the listener's own live socket.
    let cancel_rc = unsafe { WSAEventSelect(sock, None, 0) };
    assert_eq!(
        cancel_rc,
        0,
        "WSAEventSelect(0) to cancel the accept-readiness association: {}",
        std::io::Error::last_os_error()
    );
    // Cancelling alone does not reliably leave the socket blocking.
    listener
        .set_nonblocking(false)
        .expect("restore the control listener to blocking mode");
    assert_ne!(
        woken, WAIT_FAILED,
        "WaitForMultipleObjects while waiting for a control connection: {wait_error}"
    );
    let drain = woken == WAIT_OBJECT_0;
    let connection = woken.0 == WAIT_OBJECT_0.0 + 1;
    assert!(
        drain || connection,
        "WaitForMultipleObjects returned {woken:?} for two handles"
    );
    match shared::first_ready(drain, connection) {
        Some(shared::Ready::Exit) => drained.outcome.fail("tree"),
        Some(shared::Ready::Source) => shared::accept_and_ack(listener),
        None => unreachable!("one of the two handles signalled"),
    }
}

/// Linux: a pidfd (via the crate's own [`crate::wait::backend::open_verified`]) polled alongside
/// the listener's fd in ONE `poll()` call.
#[cfg(target_os = "linux")]
fn watch_linux(listener: &std::net::TcpListener, target: crate::identity::ProcessId) -> WatchEvent {
    use std::os::fd::AsFd;

    use rustix::event::{poll, PollFd, PollFlags};

    let Some(pidfd) = crate::wait::backend::open_verified(target, crate::wait::backend::PidfdOp::Wait)
        .expect("open a pidfd to watch the target")
    else {
        return WatchEvent::Died;
    };
    let listener_fd = listener.as_fd();
    let mut fds = [
        PollFd::new(&pidfd, PollFlags::IN),
        PollFd::new(&listener_fd, PollFlags::IN),
    ];
    loop {
        match poll(&mut fds, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => panic!(
                "poll while waiting for a control connection: {}",
                std::io::Error::from(e)
            ),
        }
        let (pidfd_revents, listener_revents) = (fds[0].revents(), fds[1].revents());
        // POLLNVAL would mean this function handed poll() a bad fd. It returns at once and never
        // clears, so ignoring it spins forever: a violation fails in every build.
        assert!(
            !pidfd_revents.contains(PollFlags::NVAL),
            "the pidfd went invalid mid-wait"
        );
        assert!(
            !listener_revents.contains(PollFlags::NVAL),
            "the control listener's fd went invalid mid-wait"
        );
        if listener_revents.contains(PollFlags::ERR) || listener_revents.contains(PollFlags::HUP) {
            panic!("the control listener reported an error while waiting for a connection: {listener_revents:?}");
        }
        if pidfd_revents.contains(PollFlags::ERR) {
            panic!("pidfd poll returned POLLERR while watching pid {}", target.pid());
        }
        match shared::first_ready(
            pidfd_revents.contains(PollFlags::IN),
            listener_revents.contains(PollFlags::IN),
        ) {
            Some(shared::Ready::Exit) => return WatchEvent::Died,
            Some(shared::Ready::Source) => return WatchEvent::Connection,
            None => {}
        }
    }
}

/// macOS: the crate's own [`crate::wait::backend::arm_proc_exit`] kqueue, with an `EVFILT_READ`
/// watch on the listener added to the SAME kqueue (via the crate's own
/// [`crate::wait::backend::add_with_receipt`]).
#[cfg(target_os = "macos")]
fn watch_macos(listener: &std::net::TcpListener, target: crate::identity::ProcessId) -> WatchEvent {
    use std::os::fd::AsRawFd;

    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

    let Some(kq) = crate::wait::backend::arm_proc_exit(target).expect("arm a kqueue exit-watch for the target") else {
        return WatchEvent::Died;
    };
    let listener_change = KEvent::new(
        listener.as_raw_fd() as usize,
        EventFilter::EVFILT_READ,
        EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
        FilterFlag::empty(),
        0,
        0,
    );
    let listener_errno =
        crate::wait::backend::add_with_receipt(&kq, listener_change).expect("kevent(EV_ADD) to arm the listener watch");
    assert_eq!(
        listener_errno, 0,
        "kevent(EV_ADD) for EVFILT_READ on the control listener reported errno {listener_errno}"
    );

    let placeholder = KEvent::new(0, EventFilter::EVFILT_PROC, EvFlags::empty(), FilterFlag::empty(), 0, 0);
    let mut events = [placeholder; 2];
    loop {
        // Retries the wait on `EINTR` (see `kevent_eintr`).
        let n = match kq.kevent(&[], &mut events, None) {
            Ok(n) => n,
            Err(nix::errno::Errno::EINTR) => {
                kevent_eintr::count_retry();
                continue;
            }
            Err(e) => panic!("kevent while waiting for a control connection: {e}"),
        };
        for ev in &events[..n] {
            debug_assert!(
                !ev.flags().contains(EvFlags::EV_ERROR),
                "an armed kevent reported EV_ERROR: {ev:?}"
            );
        }
        let exited = events[..n].iter().any(|ev| ev.filter() == Ok(EventFilter::EVFILT_PROC));
        let connection = events[..n].iter().any(|ev| ev.filter() == Ok(EventFilter::EVFILT_READ));
        match shared::first_ready(exited, connection) {
            Some(shared::Ready::Exit) => return WatchEvent::Died,
            Some(shared::Ready::Source) => return WatchEvent::Connection,
            None => {}
        }
    }
}

/// Windows: the crate's own identity-verified [`crate::wait::backend::open_verified`] process
/// handle and the listener's `FD_ACCEPT` event (via `WSAEventSelect`) in one explicit
/// `WaitForMultipleObjects`.
#[cfg(windows)]
fn watch_windows(listener: &std::net::TcpListener, target: crate::identity::ProcessId) -> WatchEvent {
    use std::os::windows::io::{AsRawHandle, AsRawSocket, FromRawHandle, OwnedHandle};

    use windows::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
    use windows::Win32::Networking::WinSock::{WSAEventSelect, FD_ACCEPT, SOCKET, WSAEVENT};
    use windows::Win32::System::Threading::{WaitForMultipleObjects, INFINITE};

    let Some(process) = crate::wait::backend::open_verified(target).expect("open a handle to watch the target") else {
        return WatchEvent::Died;
    };
    // SAFETY: `open_verified` returns a handle the caller owns; this wraps it so it is closed.
    let process = unsafe { OwnedHandle::from_raw_handle(process.0 as _) };
    let accept_event =
        crate::wait::backend::new_cancel_event().expect("create an event for the listener's accept-readiness watch");
    let sock = SOCKET(listener.as_raw_socket() as usize);
    let wsa_event = WSAEVENT(accept_event.as_raw_handle() as _);
    // SAFETY: `sock` is the listener's own live socket; `wsa_event` wraps `accept_event`, a live,
    // owned event handle for the call's duration.
    let rc = unsafe { WSAEventSelect(sock, Some(wsa_event), FD_ACCEPT as i32) };
    assert_eq!(
        rc,
        0,
        "WSAEventSelect(FD_ACCEPT) on the control listener: {}",
        std::io::Error::last_os_error()
    );

    // The process is listed first: the lowest signalled index wins, so an exit beats a connection.
    let handles = [HANDLE(process.as_raw_handle()), HANDLE(accept_event.as_raw_handle())];
    // SAFETY: both handles are live and owned for the call's duration.
    let woken = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
    let wait_error = std::io::Error::last_os_error();

    // Cancel the association, then restore blocking mode explicitly: cancelling alone does not
    // reliably leave the socket blocking.
    // SAFETY: `sock` is still the listener's own live socket.
    let cancel_rc = unsafe { WSAEventSelect(sock, None, 0) };
    assert_eq!(
        cancel_rc,
        0,
        "WSAEventSelect(0) to cancel the accept-readiness association: {}",
        std::io::Error::last_os_error()
    );
    listener
        .set_nonblocking(false)
        .expect("restore the control listener to blocking mode");

    assert_ne!(
        woken, WAIT_FAILED,
        "WaitForMultipleObjects while waiting for a control connection: {wait_error}"
    );
    let exited = woken == WAIT_OBJECT_0;
    let connection = woken.0 == WAIT_OBJECT_0.0 + 1;
    assert!(
        exited || connection,
        "WaitForMultipleObjects returned {woken:?} for two handles"
    );
    match shared::first_ready(exited, connection) {
        Some(shared::Ready::Exit) => WatchEvent::Died,
        _ => WatchEvent::Connection,
    }
}

/// Runs the libtest fixture at fully-qualified path `fixture` (e.g.
/// `"resolve::resolve_tests::fixture_foo"`) in a FRESH re-exec of this test binary whose OS-level
/// cwd is `cwd`. This proves what the fixture's body proves about a process's real cwd without
/// mutating this shared, multithreaded binary's own cwd. `Command::current_dir` sets the child's
/// cwd before its `exec`/`CreateProcessW`.
///
/// `marker_env` is set to `cwd` in the child only. The fixture uses it to tell a deliberate
/// re-exec from an ordinary suite run, where it must no-op, and to assert its own
/// `current_dir()` against the value, so a dropped `.current_dir(cwd)` is caught (see
/// [`expected_cwd`]).
///
/// Spawns under `spawn_lock()`, like every raw `std::process::Command` re-exec of this binary (see
/// [`spawn_a_process_that_exits`]).
///
/// Panics with the child's captured output on a non-zero exit, or when its libtest banner does not
/// show exactly one test ran and passed: `--exact <fixture>` naming no test matches ZERO tests and
/// still exits 0. Build `fixture` with [`fixture_path!`] so a stale name is a compile error; the
/// banner check backstops the rest.
pub(crate) fn run_fixture_with_cwd(fixture: &str, cwd: &std::path::Path, marker_env: &str) {
    let mut cmd = fixture_command(fixture);
    cmd.env(marker_env, cwd).current_dir(cwd);
    run_fixture_command(fixture, cmd);
}

/// Runs the libtest fixture at `fixture` in a FRESH re-exec of this binary that starts without
/// DAC bypass (see [`fixture_command_without_dac_bypass`]), for a fixture whose `EACCES`
/// precondition must hold for a root driver too. Credentials are per-process state, so the drop
/// cannot happen in this shared suite process.
///
/// The fixture gets a scratch directory built here, under this driver's ambient `TMPDIR`, that
/// its post-drop identity can use; it reaches it with [`fixture_scratch_tempdir`]. Loosening the
/// ambient `TMPDIR` instead would widen a directory this crate does not own.
///
/// See [`run_fixture_with_cwd`] for the re-exec, the panic conditions and [`fixture_path!`].
#[cfg(unix)]
pub(crate) fn run_fixture(fixture: &str) {
    let scratch = tempfile::tempdir().expect("tempdir for fixture scratch root");
    let (mut cmd, _exe_copy) = fixture_command_without_dac_bypass(fixture);

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt as _;
        // `spawn_lock` spans open-to-spawn: `O_CLOEXEC` only acts at `exec`, and a bare `fork`
        // copies the whole fd table, so no other fork that takes the lock may land in between.
        let guard = crate::child::spawn::spawn_lock();
        let fd = scratch::open_scratch_fd(scratch.path());
        let raw = fd.0;
        cmd.env(scratch::FIXTURE_SCRATCH_FD_ENV, raw.to_string());
        // SAFETY: async-signal-safe `fcntl` in the forked child, clearing close-on-exec on the
        // child's own copy only.
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(raw, libc::F_SETFD, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        #[allow(
            clippy::disallowed_methods,
            reason = "spawn_lock is held by `guard`, taken earlier in this fn"
        )]
        let child = cmd.spawn().expect("spawn fixture child");
        drop(fd);
        drop(guard);
        finish_fixture_command(fixture, child);
    }

    #[cfg(not(target_os = "linux"))]
    {
        // The fixture runs as a different uid when this driver is root: hand it the scratch root.
        if unsafe { libc::geteuid() } == 0 {
            use std::os::unix::ffi::OsStrExt as _;
            let path = std::ffi::CString::new(scratch.path().as_os_str().as_bytes())
                .expect("scratch root path has no interior NUL");
            // SAFETY: `path` is a valid C string naming a directory this function just created.
            let rc = unsafe {
                libc::chown(
                    path.as_ptr(),
                    crate::test_privilege::UNPRIVILEGED,
                    crate::test_privilege::UNPRIVILEGED,
                )
            };
            assert!(
                rc == 0,
                "chown scratch root to the fixture's post-drop identity: {}",
                std::io::Error::last_os_error()
            );
        }
        cmd.env(scratch::FIXTURE_SCRATCH_ROOT_ENV, scratch.path());
        let child = crate::test_spawn::spawn(&mut cmd).expect("spawn fixture child");
        finish_fixture_command(fixture, child);
    }
}

/// [`fixture_command`] whose child drops DAC bypass in `pre_exec` (see
/// [`crate::test_privilege::drop_dac_bypass_before_exec`]), so the fixture is unprivileged from its
/// first instruction and so is everything it spawns.
///
/// Where a root driver changes uid (non-Linux), the fixture re-execs a copy of this binary in a
/// directory the new uid can enter, and the ambient `TMPDIR` must be one it can enter too. The
/// returned directory holds that copy: keep it until the fixture has exited.
#[cfg(unix)]
pub(crate) fn fixture_command_without_dac_bypass(fixture: &str) -> (std::process::Command, Option<tempfile::TempDir>) {
    #[cfg(target_os = "linux")]
    let (mut cmd, exe_copy) = (fixture_command(fixture), None);
    #[cfg(not(target_os = "linux"))]
    let (mut cmd, exe_copy) = if unsafe { libc::geteuid() } == 0 {
        scratch::assert_dropped_identity_can_traverse_tmpdir();
        let (dir, exe) = scratch::copy_exe_to_traversable_scratch();
        let mut cmd = std::process::Command::new(exe);
        configure_fixture_command(&mut cmd, fixture);
        (cmd, Some(dir))
    } else {
        (fixture_command(fixture), None)
    };
    crate::test_privilege::drop_dac_bypass_before_exec(&mut cmd);
    (cmd, exe_copy)
}

/// Restores a directory's mode on drop, so a test that locked a tempdir down can still remove it,
/// even after a panic. Declare it after the `TempDir` it guards: locals drop in reverse order, so
/// the restore runs first. (`TempDir::drop` swallows its own removal error and would leak the
/// directory.)
#[cfg(unix)]
pub(crate) struct RestoreMode {
    path: std::path::PathBuf,
    mode: u32,
}

#[cfg(unix)]
impl RestoreMode {
    pub(crate) fn new(path: impl Into<std::path::PathBuf>, mode: u32) -> Self {
        Self {
            path: path.into(),
            mode,
        }
    }
}

#[cfg(unix)]
impl Drop for RestoreMode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(e) = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode)) {
            log::warn!("could not restore mode {:o} on {:?}: {e}", self.mode, self.path);
        }
    }
}

/// The `std::process::Command` common to every fixture re-exec: this binary, filtered to exactly
/// one test, single-threaded, stdio captured, [`FIXTURE_PARENT_PID_ENV`] set (see
/// [`is_fixture_reexec`]).
///
/// The ambient `TMPDIR` is inherited untouched; see [`run_fixture`] for writable scratch after a
/// drop.
///
/// No argv-slot-0 placeholder, unlike [`fixture_argv`]: `std::process::Command` supplies argv[0].
///
/// `pub(crate)` so a launcher with its own stdio needs (`exact_posix_tests.rs` pipes stdin) can
/// start here and override only that.
pub(crate) fn fixture_command(fixture: &str) -> std::process::Command {
    // `/proc/self/exe`: the binary's own directory (e.g. nextest's extraction dir under a `0700`
    // TMPDIR) may be unreachable post-drop; the kernel grants a process its own image regardless.
    #[cfg(target_os = "linux")]
    let program = std::path::PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let program = std::env::current_exe().expect("current_exe");
    let mut cmd = std::process::Command::new(program);
    configure_fixture_command(&mut cmd, fixture);
    cmd
}

/// The argv, env and stdio common to every fixture re-exec, split out for a caller that supplies
/// its own program path.
pub(crate) fn configure_fixture_command(cmd: &mut std::process::Command, fixture: &str) {
    cmd.args(["--test-threads=1", "--exact", fixture])
        .env(FIXTURE_PARENT_PID_ENV, std::process::id().to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
}

/// Set by every fixture re-exec to its parent's pid; see [`is_fixture_reexec`].
const FIXTURE_PARENT_PID_ENV: &str = "COSCA_FIXTURE_PARENT_PID";

/// Whether this process's real parent is the one that re-exec'd it via `run_fixture*`; an
/// inherited marker env var alone does not prove that. On `true`, writes
/// [`FIXTURE_GATE_PASSED_LINE`]; a caller with further checks before its gate is really passed
/// uses [`parent_pid_matches`] and writes the line itself.
#[cfg(unix)]
pub(crate) fn is_fixture_reexec() -> bool {
    let reexec = parent_pid_matches();
    if reexec {
        write_gate_passed();
    }
    reexec
}

/// [`is_fixture_reexec`]'s check, without the write.
#[cfg(unix)]
fn parent_pid_matches() -> bool {
    std::env::var(FIXTURE_PARENT_PID_ENV)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .is_some_and(|pid| pid == std::os::unix::process::parent_id())
}

/// Written to a fixture's real stderr, bypassing libtest's capture, once its gate passes. A gate
/// that returns early exits 0 like a fixture that ran and passed, so [`finish_fixture_command`]
/// requires the line to tell them apart.
pub(crate) const FIXTURE_GATE_PASSED_LINE: &str = "COSCA_FIXTURE_GATE_PASSED";

fn write_gate_passed() {
    use std::io::Write;
    // A failed write is a broken fixture, not a missing line for the driver to guess at.
    writeln!(std::io::stderr(), "{FIXTURE_GATE_PASSED_LINE}").expect("write the gate line to stderr");
}

/// Spawns `cmd` (from [`fixture_command`]) under `spawn_lock()` and waits for it; panics as
/// [`run_fixture_with_cwd`] documents.
fn run_fixture_command(fixture: &str, mut cmd: std::process::Command) {
    let child = crate::test_spawn::spawn(&mut cmd).expect("spawn fixture child");
    finish_fixture_command(fixture, child);
}

/// The post-spawn half of [`run_fixture_command`], for a launcher that spawned under its own lock.
fn finish_fixture_command(fixture: &str, child: std::process::Child) {
    let output = child.wait_with_output().expect("wait for fixture child");
    assert_fixture_passed(fixture, &output);
}

/// Panics unless `output` is that of a fixture that ran and passed exactly one test, and wrote its
/// gate line. For a launcher that waits for the fixture by its own means.
pub(crate) fn assert_fixture_passed(fixture: &str, output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "fixture {fixture} failed (status {:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status,
    );
    assert!(
        stdout.contains("running 1 test") && stdout.contains("test result: ok. 1 passed;"),
        "fixture {fixture} exited 0 but did not run and pass exactly one test; `--exact {fixture}` \
         probably matched none:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
    assert!(
        stderr.contains(FIXTURE_GATE_PASSED_LINE),
        "fixture {fixture} passed but never wrote {FIXTURE_GATE_PASSED_LINE:?}: its re-exec gate \
         returned early without running its body:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

/// Whether this process is the fixture re-exec that [`run_fixture_output`] started for `marker_env`:
/// the marker holds the driver's pid, and so does the pid variable every [`fixture_command`] sets.
/// Portable, unlike [`is_fixture_reexec`]; an inherited marker alone proves nothing. On `true`,
/// writes [`FIXTURE_GATE_PASSED_LINE`].
pub(crate) fn is_marked_fixture_reexec(marker_env: &str) -> bool {
    let marker = std::env::var(marker_env).ok();
    let driver = std::env::var(FIXTURE_PARENT_PID_ENV).ok();
    let marked = marker.is_some() && marker == driver;
    if marked {
        write_gate_passed();
    }
    marked
}

/// Runs the libtest fixture at `fixture` in a FRESH re-exec of this binary with `marker_env` set
/// to this process's pid (see [`is_marked_fixture_reexec`]), and returns its output whatever its
/// exit status: for a fixture that is meant to die, unlike [`run_fixture_with_cwd`] which requires
/// it to pass. Spawns under `spawn_lock()`. Build `fixture` with [`fixture_path!`].
pub(crate) fn run_fixture_output(fixture: &str, marker_env: &str) -> std::process::Output {
    let mut cmd = fixture_command(fixture);
    cmd.env(marker_env, std::process::id().to_string());
    // libtest reads its settings from the environment when the command line does not say: an
    // inherited `RUST_TEST_NOCAPTURE` turns the child's output capture off and changes what a
    // fixture that dies can prove. `RUST_TEST_THREADS` is overridden by `--test-threads=1`; the
    // time and shuffle variables cannot matter to one exact test.
    cmd.env_remove("RUST_TEST_NOCAPTURE");
    let child = crate::test_spawn::spawn(&mut cmd).expect("spawn fixture child");
    child.wait_with_output().expect("wait for fixture child")
}

/// [`run_fixture_output`] for a fixture that must pass, with the case it should run in
/// `case_env`: for a fixture that changes process-wide state (a signal disposition, say) and so
/// runs one case per re-exec. Panics with the fixture's output unless it passes and wrote its gate
/// line. Build `fixture` with [`fixture_path!`].
#[cfg(unix)]
pub(crate) fn run_fixture_case(fixture: &str, marker_env: &str, case_env: &str, case: &str) {
    let mut cmd = fixture_command(fixture);
    cmd.env(marker_env, std::process::id().to_string()).env(case_env, case);
    cmd.env_remove("RUST_TEST_NOCAPTURE");
    let child = crate::test_spawn::spawn(&mut cmd).expect("spawn fixture child");
    let output = child.wait_with_output().expect("wait for fixture child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("running 1 test") && stdout.contains("test result: ok. 1 passed;"),
        "fixture {fixture} case {case:?} failed (status {:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status,
    );
    assert!(
        stderr.contains(FIXTURE_GATE_PASSED_LINE),
        "fixture {fixture} case {case:?} never wrote {FIXTURE_GATE_PASSED_LINE:?}:\n{stderr}",
    );
}

/// Set `SIGCHLD`'s disposition, process-wide: `SIG_IGN` if `ignore`, else `SIG_DFL`. Only a
/// fixture re-exec (see [`run_fixture_case`]) may call it: it changes every thread of the process.
#[cfg(target_os = "macos")]
pub(crate) fn set_sigchld_ignored(ignore: bool) {
    let handler = if ignore { libc::SIG_IGN } else { libc::SIG_DFL };
    // SAFETY: `signal` with `SIG_IGN` or `SIG_DFL` installs no handler code.
    let previous = unsafe { libc::signal(libc::SIGCHLD, handler) };
    assert_ne!(
        previous,
        libc::SIG_ERR,
        "signal(SIGCHLD): {}",
        std::io::Error::last_os_error()
    );
}

/// The directory [`run_fixture_with_cwd`]'s caller prepared, read from `marker_env`; `None` when it
/// is unset or (on unix) [`parent_pid_matches`] says this is not a deliberate re-exec. Either way
/// the fixture is also picked up by ordinary suite runs, where it must no-op.
///
/// Also asserts this process's own `current_dir()` IS that directory, so a fixture that reads its
/// cwd through here cannot keep passing after `.current_dir(cwd)` is silently dropped. The gate
/// line is written last, after both checks.
pub(crate) fn expected_cwd(marker_env: &str) -> Option<std::path::PathBuf> {
    #[cfg(unix)]
    if !parent_pid_matches() {
        return None;
    }
    let expected = std::path::PathBuf::from(std::env::var_os(marker_env)?);
    let actual = std::env::current_dir().expect("current_dir");
    assert_eq!(
        actual.canonicalize().expect("canonicalize actual cwd"),
        expected.canonicalize().expect("canonicalize expected cwd"),
        "this fixture's OS-level cwd must be the directory run_fixture_with_cwd's caller prepared",
    );
    write_gate_passed();
    Some(expected)
}

/// Builds the fully-qualified libtest `--exact` path of the `#[test] fn` named `$name`, for
/// [`run_fixture_with_cwd`]'s `fixture` argument. Two things tie the call site to the fixture
/// instead of letting them drift apart as two independently hand-typed strings:
///
/// - `let _: fn() = $name;` forces the compiler to resolve `$name` as an item in scope — a typo
///   or a stale name after a rename is a compile error here, not a filter that silently matches
///   zero tests at runtime (see [`run_fixture_with_cwd`]'s doc for why that is exactly the bug
///   this macro exists to rule out).
/// - `module_path!()` derives the module portion at compile time, so it can never fall out of
///   sync with a file move or a module rename; libtest's `--exact` filter never includes the
///   crate-name component `module_path!()` always carries as its own first segment, hence the
///   [`strip_crate_prefix`] call.
macro_rules! fixture_path {
    ($name:ident) => {{
        let _: fn() = $name;
        crate::test_child::strip_crate_prefix(concat!(module_path!(), "::", stringify!($name)))
    }};
}
pub(crate) use fixture_path;

/// Strips the crate-name segment `module_path!()` always carries as its own first component
/// (e.g. `"cosca::resolve::resolve_tests"`), since libtest's `--exact` filter never includes it
/// (e.g. `"resolve::resolve_tests"`). Panics if `path` does not start with that segment, which
/// would mean `module_path!()`'s documented contract no longer holds.
pub(crate) fn strip_crate_prefix(path: &'static str) -> &'static str {
    let prefix = concat!(env!("CARGO_PKG_NAME"), "::");
    path.strip_prefix(prefix)
        .unwrap_or_else(|| panic!("{path:?} does not start with {prefix:?} — module_path!()'s contract changed"))
}

/// A child that exits promptly and needs no external binary: this same test binary, run
/// with a filter that matches nothing, so libtest runs zero tests and exits 0.
///
/// The libtest filter is mandatory, and is why this lives in exactly one place: re-execing
/// the test binary with NO arguments runs the whole suite — including whichever test called
/// this — which then re-execs again, unboundedly.
///
/// Spawns under `spawn_lock()`: on macOS, a fork here that lands while another test's fd
/// marker write end happens to be open would transiently inherit it, and a concurrently
/// running sweep could then find and signal this bystander child. `spawn_lock()` is the same
/// lock every cosca-originated spawn in this test binary already takes.
pub(crate) fn spawn_a_process_that_exits() -> std::process::Child {
    crate::test_spawn::spawn(
        std::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args(["--exact", "__cosca_no_such_test__"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn")
}

/// `more.com` by its `System32` path (no `PATH` lookup): blocks reading stdin and exits 0 on EOF,
/// unlike `findstr x`, whose exit 1 is indistinguishable from a kill.
#[cfg(windows)]
pub(crate) fn windows_more() -> std::path::PathBuf {
    std::path::Path::new(&std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows"))
        .join("System32")
        .join("more.com")
}

/// A contained [`windows_more`] child blocked on a piped stdin the caller holds. It ends only by a
/// real kill or the caller closing the pipe (exit 0). Stdout is nulled because `more` echoes.
#[cfg(windows)]
pub(crate) fn windows_blocker() -> (crate::Child, std::io::PipeWriter) {
    let mut cmd = crate::Command::new();
    cmd.args([windows_more()]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// Async twin of [`windows_blocker`]; `configure` selects the containment under test.
#[cfg(all(windows, feature = "tokio"))]
pub(crate) fn windows_blocker_async(
    configure: impl FnOnce(&mut crate::tokio::Command),
) -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    let mut cmd = crate::tokio::Command::new();
    cmd.args([windows_more()]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    configure(&mut cmd);
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// The argv of a child that ignores `SIGTERM` (an ignored disposition survives the `exec`), tells
/// its stdout it is ready, then blocks on stdin as `cat`. Only `SIGKILL` or stdin EOF ends it.
#[cfg(unix)]
const TERM_IGNORING_BLOCKER_ARGV: &[&str] = &["sh", "-c", "trap '' TERM; echo r; exec cat"];

/// A spawned, contained `SIGTERM`-ignoring [`TERM_IGNORING_BLOCKER_ARGV`] child and the write end of
/// its stdin, returned once its readiness byte proves the trap is installed. A test whose only end
/// for it is a sweep or escalation holds the stdin and releases it after the kill.
#[cfg(unix)]
pub(crate) fn term_ignoring_blocker() -> (crate::Child, std::io::PipeWriter) {
    use std::io::Read as _;

    let mut cmd = crate::Command::new();
    cmd.args(TERM_IGNORING_BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let mut readiness = [0u8; 1];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut readiness)
        .expect("readiness byte");
    (child, stdin)
}

/// Async twin of [`term_ignoring_blocker`].
#[cfg(all(unix, feature = "tokio"))]
pub(crate) async fn term_ignoring_blocker_async() -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    use ::tokio::io::AsyncReadExt as _;

    let mut cmd = crate::tokio::Command::new();
    cmd.args(TERM_IGNORING_BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let mut readiness = [0u8; 1];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut readiness)
        .await
        .expect("readiness byte");
    (child, stdin)
}

/// A blocker died to a kill, not by exiting on its own once its stdin closed: `SIGKILL` on Unix, a
/// non-zero exit on Windows (`more.com` exits 0 on EOF). Separate compilation units cannot share
/// it: `tests/common` keeps its own copy.
pub(crate) fn assert_killed(who: &str, status: std::process::ExitStatus) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "{who} must be SIGKILLed, not exit on its own: {status:?}"
        );
    }
    #[cfg(windows)]
    assert!(
        !status.success(),
        "{who} must be killed, not exit on its own: {status:?}"
    );
}

/// The argv for re-executing this test binary against one fixture through `cosca::Command`,
/// whose `args` is the **full** argv — libtest drops slot 0 as the binary name, so a filter or
/// option placed there is silently eaten and `--exact` degrades to substring matching.
/// `--test-threads=1` keeps a future filter that matches more than one test from running them
/// concurrently inside a process the caller is about to signal.
#[cfg(windows)]
pub(crate) fn fixture_argv(test: &str) -> [&str; 4] {
    ["cosca_unit_tests", "--test-threads=1", "--exact", test]
}

/// The fully-qualified libtest path of [`fixture_survives_group_signal`], for callers that
/// re-exec this binary against it directly (`current_exe() --exact <this>`) rather than through
/// [`spawn_a_process_that_exits`]'s own filter.
#[cfg(windows)]
pub(crate) const FIXTURE_SURVIVES_GROUP_SIGNAL_TEST: &str = "test_child::fixture_survives_group_signal";

/// The env var carrying the `127.0.0.1:<port>` address the grandchild (a re-exec'd
/// [`fixture_registers_then_blocks`]) connects back to; [`fixture_survives_group_signal`] only
/// forwards it. Its presence also tells that fixture it was re-exec'd deliberately rather than
/// picked up by an ordinary, unfiltered suite run.
#[cfg(windows)]
pub(crate) const FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV: &str = "COSCA_FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR";

/// Windows-only fixture for the `root_exited`-on-`MembersRemain` regression (sync and async
/// twins): a no-op when picked up by an ordinary, unfiltered suite run —
/// [`FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV`] is unset there. Re-executed via `current_exe()
/// --exact` [`FIXTURE_SURVIVES_GROUP_SIGNAL_TEST`] with that var set, it spawns a grandchild a
/// group `CTRL_BREAK` can never reach — `CREATE_NEW_PROCESS_GROUP` puts it in its own process
/// group, the same isolation `graceful_shutdown_tree`'s own doc describes for a nested
/// contained descendant — then returns immediately, letting this intermediate process exit.
///
/// The grandchild is itself a re-exec'd [`fixture_registers_then_blocks`], given THIS fixture's
/// OWN `addr` (forwarded via [`FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV`]) so it connects and
/// blocks DIRECTLY against the caller's listener — never against a socket this short-lived
/// intermediate process would itself own and then close on its own exit, which a
/// caller-chosen `grace` can easily outlive. The grandchild's own connect-and-tag is thus the
/// happens-before edge the caller blocks on: it cannot tag until its own code is running, in
/// its own group. The tag goes out over a real TCP socket, not `print!`/`io::stdout()`: libtest
/// captures the latter per-test and discards it for a passing test, so a stdout-based readiness
/// byte never reaches the caller's piped reader at all — this is the same control-channel shape
/// `tests/common`'s `spawn_tree`/`spawn_tree_async` tag handshake already uses for exactly this
/// reason, not a Windows-specific mechanism. The job object still tracks the grandchild as a
/// tree member despite its own process group (job membership and process group are independent
/// Win32 concepts), so it shows up as a `MembersRemain` survivor even though the signal itself
/// never reaches it, and it stays that way for as long as the caller holds its control socket
/// open. Mirrors [`spawn_a_process_that_exits`]'s
/// filtered-re-exec idiom (see its own doc for why the filter is mandatory) put to a second use.
#[cfg(windows)]
#[test]
fn fixture_survives_group_signal() {
    let Some(addr) = std::env::var_os(FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::os::windows::process::CommandExt;

    // CREATE_NEW_PROCESS_GROUP (winbase.h). A scalar flag, so a raw constant needs no
    // `windows`-crate import: `std::os::windows::process::CommandExt::creation_flags` takes it
    // as a plain `u32`.
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    #[allow(
        clippy::zombie_processes,
        reason = "the grandchild must outlive us; containment kills it"
    )]
    let _survivor = crate::test_spawn::spawn(
        std::process::Command::new(std::env::current_exe().expect("current_exe"))
            // `[1..]`: skip `fixture_argv`'s slot-0 placeholder; `std::process::Command` supplies argv[0].
            .args(&fixture_argv(FIXTURE_REGISTERS_THEN_BLOCKS_TEST)[1..])
            .env(FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV, &addr)
            .creation_flags(CREATE_NEW_PROCESS_GROUP)
            .stdout(std::process::Stdio::null()),
    )
    .expect("spawn a grandchild the group signal cannot reach");
}

/// The fully-qualified libtest path of [`fixture_registers_then_blocks`], for callers that
/// re-exec this binary against it directly (`current_exe() --exact <this>`).
// Gated with its consumers: the sync caller uses it only under `cfg(windows)`, the other two are
// behind the `tokio` feature, so a default-feature Unix build has none and `-D warnings` rejects it.
#[cfg(any(windows, feature = "tokio"))]
pub(crate) const FIXTURE_REGISTERS_THEN_BLOCKS_TEST: &str = "test_child::fixture_registers_then_blocks";

/// The env var carrying the `127.0.0.1:<port>` address [`fixture_registers_then_blocks`] tags.
/// Its mere presence also tells the fixture it was re-exec'd deliberately rather than picked up
/// by an ordinary, unfiltered suite run.
pub(crate) const FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV: &str = "COSCA_FIXTURE_REGISTERS_THEN_BLOCKS_ADDR";

/// Bind a rendezvous listener for [`fixture_registers_then_blocks`]; returns it and its
/// `127.0.0.1:<port>` address.
#[cfg(any(windows, feature = "tokio"))]
pub(crate) fn registration_rendezvous() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind rendezvous listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    (listener, addr)
}

/// Fixture supplying a happens-before edge on a live child: a no-op when picked up by an
/// ordinary, unfiltered suite run ([`FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV`] is unset there).
/// Re-executed via `current_exe() --exact` [`FIXTURE_REGISTERS_THEN_BLOCKS_TEST`] with that var
/// set, it connects to the caller's listener, writes one tag byte, then blocks on a 1-byte read
/// of that same socket. The caller unblocks it by writing a byte back, and it then exits 0 of
/// its own accord — an exit code no forced kill can produce.
///
/// The tag is the edge: the fixture cannot write it until it is executing its own code. On
/// Windows that is also after the console has registered it — a child signalled before that
/// point dies during loader init instead of to the console event, which is a different exit code
/// and a different thing under test.
///
/// It installs no console-control handler, so `CTRL_BREAK`'s default disposition terminates it.
/// Blocking on the socket rather than parking means a panicking or aborted caller closes the
/// socket and the fixture exits on EOF instead of orphaning.
#[test]
fn fixture_registers_then_blocks() {
    let Some(addr) = std::env::var_os(FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::io::{Read, Write};

    let mut sock = ack::connect_control(addr.to_str().expect("utf8 addr")).expect("connect rendezvous socket");
    sock.write_all(b"R").expect("write registration tag");
    sock.flush().expect("flush registration tag");
    let mut sink = [0u8; 1];
    _ = sock.read(&mut sink);
}

/// The fully-qualified libtest path of [`fixture_connects_and_exits`].
const FIXTURE_CONNECTS_AND_EXITS_TEST: &str = "test_child::fixture_connects_and_exits";

/// The env var carrying the `127.0.0.1:<port>` address [`fixture_connects_and_exits`] tags.
const FIXTURE_CONNECTS_AND_EXITS_ADDR_ENV: &str = "COSCA_FIXTURE_CONNECTS_AND_EXITS_ADDR";

/// A child that connects, tags, and exits 0 immediately, with no blocking read. Whether it waits
/// for the accept ack after connecting is up to its environment ([`ack::ACK_ENV`]).
#[test]
fn fixture_connects_and_exits() {
    let Some(addr) = std::env::var_os(FIXTURE_CONNECTS_AND_EXITS_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::io::Write;

    let mut sock = ack::connect_control(addr.to_str().expect("utf8 addr")).expect("connect rendezvous socket");
    sock.write_all(b"R").expect("write registration tag");
    sock.flush().expect("flush registration tag");
}

/// Spawns [`fixture_connects_and_exits`], with the ack handshake when `acked`. Returns the child
/// and the target identity to watch.
fn spawn_connects_and_exits(
    listener: &std::net::TcpListener,
    acked: bool,
) -> (std::process::Child, crate::identity::ProcessId) {
    let addr = listener.local_addr().expect("local_addr").to_string();
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("current_exe"));
    cmd.args(["--test-threads=1", "--exact", FIXTURE_CONNECTS_AND_EXITS_TEST])
        .env(FIXTURE_CONNECTS_AND_EXITS_ADDR_ENV, &addr)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if acked {
        cmd.env(ack::ACK_ENV, "1");
    }
    let child = crate::test_spawn::spawn(&mut cmd).expect("spawn the connects-and-exits fixture");
    let target = crate::Process::from_pid(child.id())
        .found()
        .expect("resolve the freshly spawned fixture's pid")
        .id();
    (child, target)
}

/// Waits for the zombie edge WITHOUT reaping, so the pid keeps naming the target.
#[cfg(unix)]
fn wait_unreaped(pid: u32) {
    loop {
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `si` is a valid out-param; `pid` is our own unreaped child.
        let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED | libc::WNOWAIT) };
        if rc == 0 {
            return;
        }
        let e = std::io::Error::last_os_error();
        assert_eq!(e.raw_os_error(), Some(libc::EINTR), "waitid: {e}");
    }
}

/// A fixture that connects and exits without waiting for the ack (not opted in) is dead whether
/// or not its connection reached the accept queue: the exit alone decides. The target has exited,
/// unreaped, before `accept_or_die` starts.
#[test]
fn death_watch_accept_or_die_reports_a_target_that_connected_and_exited_without_the_ack_as_dead() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind rendezvous listener");
    let (mut child, target) = spawn_connects_and_exits(&listener, false);
    #[cfg(unix)]
    wait_unreaped(child.id());
    #[cfg(windows)]
    child.wait().expect("wait for the fixture to exit"); // the Child keeps its handle, so the pid stays valid

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| accept_or_die(&listener, target)));
    let payload = result.expect_err("accept_or_die must panic for an exited target");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .expect("string panic payload");
    assert_eq!(
        message,
        format!("the control target (pid {}) died before it connected", target.pid())
    );
    child.wait().expect("reap the fixture");
}

/// The ack protects an opted-in fixture that connects, tags and exits at once: it cannot exit
/// before `accept_or_die` accepted and acked, so the connection is always returned.
#[test]
fn death_watch_accept_or_die_returns_the_connection_of_an_acked_target_that_exits_at_once() {
    use std::io::Read;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind rendezvous listener");
    let (mut child, target) = spawn_connects_and_exits(&listener, true);
    let mut sock = accept_or_die(&listener, target);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the fixture's tag");
    assert_eq!(&tag, b"R");
    child.wait().expect("reap the fixture");
}

/// Exit code of the `tool` in [`cwd_and_path_tools`]'s first directory.
#[cfg(unix)]
pub(crate) const CWD_TOOL_EXIT: i32 = 11;
/// Exit code of the `tool` in [`cwd_and_path_tools`]'s second directory.
#[cfg(unix)]
pub(crate) const PATH_TOOL_EXIT: i32 = 22;

/// Two directories, each holding an executable script named `tool` that exits with its own code
/// ([`CWD_TOOL_EXIT`], [`PATH_TOOL_EXIT`]), so a child's exit status says which one was loaded.
/// Meant as the child's working directory and its `PATH`, respectively.
///
/// Each write is serialized against every other spawn's `fork` and the guard dropped before the
/// caller's spawn: a `fork` while a script's writable descriptor is open leaves the forked child
/// holding it until it execs, and `execve` of that script then fails with `ETXTBSY`. The lock is
/// not reentrant, so holding it across a `spawn()` would deadlock.
#[cfg(unix)]
pub(crate) fn cwd_and_path_tools() -> (tempfile::TempDir, tempfile::TempDir) {
    use std::os::unix::fs::PermissionsExt;
    let dirs = (
        tempfile::tempdir().expect("tempdir"),
        tempfile::tempdir().expect("tempdir"),
    );
    for (dir, code) in [(&dirs.0, CWD_TOOL_EXIT), (&dirs.1, PATH_TOOL_EXIT)] {
        let tool = dir.path().join("tool");
        let _guard = crate::child::spawn::spawn_lock();
        std::fs::write(&tool, format!("#!/bin/sh\nexit {code}\n")).expect("write tool");
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod tool");
    }
    dirs
}

#[cfg(test)]
#[path = "test_child_tests.rs"]
mod test_child_tests;
