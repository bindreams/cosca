//! Shared control-spawn test harness — the CANONICAL single source (`tests/lifecycle.rs`
//! consumes this too; integration test crates are separate compilation units, so helpers
//! are shared via `#[path = "common/mod.rs"] mod common;`).

// Each test crate compiles the whole module but uses only the subset it needs (e.g.
// `lifecycle` never calls `spawn_blocker`), so per-crate dead code and unused imports (e.g. the
// log-capture re-exports, which only `macos_fdmarker.rs` uses) are expected here.
#![allow(dead_code, unused_imports)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[cfg(target_os = "linux")]
pub mod cgroup;

pub fn testbin() -> &'static str {
    env!("CARGO_BIN_EXE_cosca_testbin")
}

/// Run `cmd` under `cosca::test_spawn_lock()` and return its captured output — the ONLY way
/// this test surface should fork a RAW `std::process::Command` (one not going through
/// `cosca::Command`, which already takes this same lock internally). Cargo runs `#[test]` fns
/// in one binary concurrently, and every test in `tests/macos_fdmarker.rs` runs a real
/// `FdMarker` sweep; an unguarded raw fork can transiently inherit a live marker pre-`exec`,
/// and a concurrent sweep can then confirm and SIGKILL it before it gets there. A single
/// wrapper, not a `let _guard = ...;` line the caller must remember, closes that gap for
/// every call site at once — including any added later.
pub fn output_locked(cmd: &mut std::process::Command) -> std::io::Result<std::process::Output> {
    let _guard = cosca::test_spawn_lock();
    cmd.output()
}

/// The `.status()` sibling of [`output_locked`] — see there for why raw spawns in this test
/// surface must go through one of these two, not a bare `std::process::Command` call.
pub fn status_locked(cmd: &mut std::process::Command) -> std::io::Result<std::process::ExitStatus> {
    let _guard = cosca::test_spawn_lock();
    cmd.status()
}

/// Block until `pid` — which MUST be an unreaped child of this process — has exited AND become
/// a zombie, leaving it unreaped for the caller to assert on and then reap. The canonical
/// zombie edge for this suite: the ONLY sync point that a liveness assertion about a zombie may
/// be taken at.
///
/// A death-watch is NOT a substitute. `Process::wait` returns on the OS exit edge, and on macOS
/// that edge is `proc_exit`'s `proc_knote(p, NOTE_EXIT)`, which XNU posts well before the same
/// function assigns `p->p_stat = SZOMB` — so a liveness check taken there can still read the
/// process as running. Neither is a pipe or socket EOF on the dying process's own descriptors:
/// `proc_exit` invalidates the fd table earlier still. `waitid` reports `WEXITED` only out of
/// the kernel's `SZOMB` case, so its return IS the zombie transition, and `WNOWAIT` leaves the
/// zombie collectable.
#[cfg(unix)]
pub fn block_until_zombie(pid: cosca::identity::RawPid) {
    loop {
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `si` is a valid, correctly-sized out-param; `pid` is our own unreaped child.
        let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED | libc::WNOWAIT) };
        if rc == 0 {
            return;
        }
        // EINTR is a restart, not a failure — the codebase's convention for every blocking
        // syscall (see `wait/macos.rs`, `identity/macos/kinfo.rs`).
        let e = std::io::Error::last_os_error();
        assert_eq!(
            e.raw_os_error(),
            Some(libc::EINTR),
            "waitid(P_PID, {pid}, WEXITED | WNOWAIT): {e}"
        );
    }
}

/// The ONE `log::Log` this test crate installs. A capturing logger, for asserting on log output
/// from an integration-test process — a fresh copy of `src/log_capture.rs`'s `pub(crate)`-private
/// original, which a separate compilation unit like this one cannot name, extended to also echo
/// every record to stderr (in the same `[LEVEL] text` format `spawn_io.rs`'s `stderr_log` used to
/// print through a logger of its own) so a failing `assert_eq!(…, CgroupV2)`'s degrade reason
/// still reaches CI output — libtest captures a failing test's stderr and prints it with the
/// failure.
///
/// `log::set_logger` is once-per-process, so a second, competing logger in the same test binary
/// would race this one and panic whichever call lost — a real failure under `cargo test`'s
/// default one-binary, many-tests-per-process model (nextest's one-process-per-test does not hit
/// it, but local `cargo test` runs do). [`install_log_capture`] is therefore the only installer
/// left in this crate: `spawn_io.rs`'s `stderr_log::install` is now a thin alias for it.
mod log_capture {
    use std::sync::{Mutex, OnceLock};

    struct CaptureLog;
    static RECORDS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static INSTALLED: OnceLock<()> = OnceLock::new();

    impl log::Log for CaptureLog {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            let text = record.args().to_string();
            eprintln!("[{}] {text}", record.level());
            RECORDS.lock().unwrap().push(text);
        }
        fn flush(&self) {}
    }

    /// `Trace`, the full set: no narrower filter can drop a record before it reaches this
    /// logger (`log!` checks `max_level()` first).
    pub fn install() {
        INSTALLED.get_or_init(|| {
            log::set_logger(&CaptureLog).expect("first logger in this test process");
            log::set_max_level(log::LevelFilter::Trace);
        });
    }

    pub fn mark() -> usize {
        RECORDS.lock().unwrap().len()
    }

    pub fn contains_since(mark: usize, needle: &str) -> bool {
        RECORDS.lock().unwrap()[mark..].iter().any(|m| m.contains(needle))
    }
}
pub use log_capture::{contains_since, install as install_log_capture, mark as log_mark};

/// Is `pid` attached to OUR console? `None` when the probe found no console at all, so a
/// broken or console-less probe can never satisfy an "absent" assertion — the two are
/// different facts and folding them together would make an absence assertion unfailable.
///
/// The answer is only meaningful once the target has executed its own code: console
/// registration is not synchronous with the spawn returning, so a probe taken at the instant
/// `spawn()` returns reads "absent" for a perfectly ordinary console child. Every caller must
/// complete a handshake with the target first.
#[cfg(windows)]
pub fn in_our_console(pid: u32) -> Option<bool> {
    // Grow to whatever count the API reports rather than capping: a too-small buffer makes it
    // return the REQUIRED count without filling, which a fixed cap would silently read as
    // "absent".
    let mut buf = vec![0u32; 16];
    loop {
        // SAFETY: standard Win32; `buf` is a valid writable slice.
        let n = unsafe { windows::Win32::System::Console::GetConsoleProcessList(&mut buf) } as usize;
        if n == 0 {
            return None; // no console at all, or the probe itself failed
        }
        if n <= buf.len() {
            return Some(buf[..n].contains(&pid));
        }
        buf.resize(n, 0);
    }
}

/// Exact-key extraction from a `key=value` report line. Substring matching would be unsafe:
/// `console=0` shares its value alphabet with every other field.
#[cfg(windows)]
pub fn report_field<'a>(report: &'a str, key: &str) -> &'a str {
    report
        .split_ascii_whitespace()
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("no field {key} in report: {report}"))
}

/// Build a `CreateProcessW`-style command line from plain args, the way the raw backend's own
/// quoter would join them (`cosca::quote::windows::join_wide`). ONE definition for every test
/// crate that needs a `.commandline(...)`-shaped string from argv-like input: two copies could
/// drift apart and agree on the wrong quoting.
#[cfg(windows)]
pub fn commandline_from(args: &[&str]) -> String {
    let wide_args: Vec<Vec<u16>> = args.iter().map(|a| a.encode_utf16().collect()).collect();
    let refs: Vec<&[u16]> = wide_args.iter().map(Vec::as_slice).collect();
    String::from_utf16(&cosca::quote::windows::join_wide(&refs)).unwrap()
}

/// The escaping `report-console-identity` applies to its `argv0` field, so a test can state its
/// expectation in plain text. ONE definition for every test crate that asserts on that field: two
/// copies could drift apart and agree on the wrong answer.
#[cfg(windows)]
pub fn escape_report_field(value: &str) -> String {
    let mut out = String::new();
    for b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Read exactly the one report line a `report-console-identity` child writes before it blocks. A
/// child that panicked after connecting reaches us as EOF (an empty line), which fails the
/// caller's field lookup loudly instead of hanging.
#[cfg(windows)]
pub fn read_report_line(sock: &TcpStream) -> String {
    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(sock.try_clone().expect("clone report socket"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("read report line");
    line
}

/// Blocks until either `listener` gets an incoming connection, or the target process
/// (`target_pid`) exits first — via the OS's own process-exit notification (a `pidfd` on Linux, a
/// `kqueue`'s `EVFILT_PROC`/`NOTE_EXIT` on macOS, a process HANDLE via `WaitForMultipleObjects` on
/// Windows — see each platform's own `accept_or_die` below), never a pipe. A pipe's EOF is hidden
/// by any descendant still holding its write end open: measured, `sh -c 'sleep 8 & exit 3'`
/// reports its OWN exit only 8s later through a pipe-EOF proxy, and `spawn_tree`'s grandchildren
/// inherit the root's stdout the same way; on macOS the write end can also leak into a concurrent,
/// unrelated fork. A plain blocking `accept()` would hang forever if the target dies first, for
/// the same reason; this doesn't.
///
/// No thread, no reconnect: an earlier revision used a background thread that death-watched the
/// target and, on death, RECONNECTED to `listener`'s own address to signal it — measured to be
/// unsound: after the real target's own process (and this function) have moved on, nothing keeps
/// that port reserved, and the OS can and does reissue it (observed on macOS) to a completely
/// unrelated later listener, which then sees a spurious, wrongly-attributed connection.
///
/// The exit notification is a PROMPT to check again, not proof by itself: a target that connects
/// and then exits immediately (an ordinary success for most callers) races its own exit signal
/// against the connection already sitting in the listener's backlog. Every platform's
/// implementation below resolves that race the same way, in [`final_peek_or_die`]: once the exit
/// notification fires, a final NON-BLOCKING `accept()` is the actual authority, and wins if a
/// connection is there — only an empty backlog at that instant is treated as "died before
/// connecting".
#[cfg(target_os = "linux")]
pub fn accept_or_die(listener: &TcpListener, target_pid: u32) -> TcpStream {
    use std::os::fd::AsRawFd;

    let raw = rustix::process::Pid::from_raw(target_pid as i32).expect("a spawned child's pid is never 0");
    let pidfd = match rustix::process::pidfd_open(raw, rustix::process::PidfdFlags::empty()) {
        Ok(fd) => fd,
        // The target was already gone by the time we tried to open it — not a setup failure,
        // just the exit-first race arriving before this function could even arm its watch.
        Err(rustix::io::Errno::SRCH) => return final_peek_or_die(listener, target_pid),
        Err(e) => panic!(
            "pidfd_open({target_pid}) for the death-watch: {}",
            std::io::Error::from(e)
        ),
    };

    let mut fds = [
        libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `fds` is a valid, correctly-sized array for the call's duration.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            panic!("poll while waiting for a control connection: {e}");
        }
        // POLLNVAL on either fd would mean this function handed poll() a bad fd — a contract
        // this function itself owns end to end, so a violation is a bug here, not a runtime
        // condition to recover from.
        debug_assert_eq!(
            fds[0].revents & libc::POLLNVAL,
            0,
            "the control listener's fd went invalid mid-wait"
        );
        debug_assert_eq!(fds[1].revents & libc::POLLNVAL, 0, "the pidfd went invalid mid-wait");
        // Unlike POLLNVAL, an error on the LISTENER is a real, externally-caused condition (the
        // socket itself failing) — surfaced in every build, not compiled out with debug_assert.
        if fds[0].revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            panic!(
                "the control listener reported an error while waiting for a connection (revents={:#x})",
                fds[0].revents
            );
        }
        if fds[0].revents & libc::POLLIN != 0 {
            return listener.accept().expect("accept a control connection").0;
        }
        if fds[1].revents & libc::POLLIN != 0 {
            return final_peek_or_die(listener, target_pid);
        }
    }
}

/// macOS sibling of the Linux `accept_or_die` above — same contract, via one `kqueue` carrying
/// both an `EVFILT_PROC`/`NOTE_EXIT` watch on the target and an `EVFILT_READ` watch on the
/// listener, instead of `poll()` over two fds: a `kqueue` fd is itself only readable, not
/// filter-specific, so this is what actually distinguishes "the target exited" from "the listener
/// is ready" on this platform.
#[cfg(target_os = "macos")]
pub fn accept_or_die(listener: &TcpListener, target_pid: u32) -> TcpStream {
    use std::os::fd::AsRawFd;

    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

    let kq = Kqueue::new().expect("kqueue() for the death-watch");
    let changes = [
        KEvent::new(
            target_pid as usize,
            EventFilter::EVFILT_PROC,
            EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
            FilterFlag::NOTE_EXIT,
            0,
            0,
        ),
        KEvent::new(
            listener.as_raw_fd() as usize,
            EventFilter::EVFILT_READ,
            EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
            FilterFlag::empty(),
            0,
            0,
        ),
    ];
    let mut receipts = [changes[0]; 2];
    kq.kevent(&changes, &mut receipts, None)
        .expect("kevent(EV_ADD) to arm the death-watch and the listener watch");
    for r in &receipts {
        // EV_RECEIPT makes EV_ADD synchronous and always reports EV_ERROR, with the outcome (0 =
        // armed OK) in `data` — this is the ONLY way to observe an EV_ADD failure at all; without
        // it, a bad filter fails silently and this function would then wait forever.
        assert!(
            r.flags().contains(EvFlags::EV_ERROR),
            "EV_RECEIPT should always report EV_ERROR: {r:?}"
        );
        let errno = r.data() as i32;
        if r.filter() == Ok(EventFilter::EVFILT_PROC) && errno == libc::ESRCH {
            // Already gone by the time we tried to arm the watch — the exit-first race arriving
            // before this function could even arm it, same as the Linux SRCH case above.
            return final_peek_or_die(listener, target_pid);
        }
        assert_eq!(
            errno,
            0,
            "kevent(EV_ADD) receipt for {:?} reported errno {errno}",
            r.filter()
        );
    }

    let mut events = [changes[0]; 2];
    loop {
        let n = kq
            .kevent(&[], &mut events, None)
            .expect("kevent while waiting for a control connection");
        for ev in &events[..n] {
            // An armed kevent (not an EV_ADD receipt) reporting EV_ERROR would mean the kernel
            // itself hit a problem delivering a notification this function already successfully
            // armed — not a condition either filter's own documentation describes as possible.
            debug_assert!(
                !ev.flags().contains(EvFlags::EV_ERROR),
                "an armed kevent reported EV_ERROR: {ev:?}"
            );
            match ev.filter() {
                Ok(EventFilter::EVFILT_READ) => return listener.accept().expect("accept a control connection").0,
                Ok(EventFilter::EVFILT_PROC) => return final_peek_or_die(listener, target_pid),
                _ => {}
            }
        }
    }
}

/// Shared by every platform's `accept_or_die`: once the exit notification fires, a non-blocking
/// `accept()` is the actual authority — see `accept_or_die`'s own doc for why the notification
/// alone is only a prompt to check again, never proof.
fn final_peek_or_die(listener: &TcpListener, target_pid: u32) -> TcpStream {
    listener
        .set_nonblocking(true)
        .expect("set the listener nonblocking for the final accept peek");
    let peek = listener.accept();
    listener
        .set_nonblocking(false)
        .expect("restore the listener to blocking mode after the peek");
    match peek {
        Ok((stream, _)) => stream,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            panic!("the control target (pid {target_pid}) died before it connected")
        }
        Err(e) => panic!("accept during the final peek before declaring pid {target_pid} died: {e}"),
    }
}

/// Windows sibling of the Linux/macOS `accept_or_die` above — same contract, via
/// `WaitForMultipleObjects` over a process HANDLE (opened fresh by pid, needing no raw-handle
/// accessor from `cosca::Child`/`cosca::tokio::Child` — any caller that knows the target's pid can
/// use this) and a `WSAEVENT` armed for `FD_ACCEPT` on the listener.
#[cfg(windows)]
pub fn accept_or_die(listener: &TcpListener, target_pid: u32) -> TcpStream {
    use std::os::windows::io::AsRawSocket;

    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
    use windows::Win32::Networking::WinSock::{WSACloseEvent, WSACreateEvent, WSAEventSelect, FD_ACCEPT, SOCKET};
    use windows::Win32::System::Threading::{OpenProcess, WaitForMultipleObjects, INFINITE, PROCESS_SYNCHRONIZE};

    // SAFETY: opens the target by pid with only SYNCHRONIZE — enough to wait for its exit.
    // Unlike `src/wait/windows.rs`'s own by-pid wait, this does not re-verify the pid was not
    // recycled between spawn and here: that production path guards a long-lived wait against an
    // attacker-controlled window; this one's spawn-to-here window is microseconds of a test's
    // own setup, so the same rigor buys nothing here.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, target_pid) }
        .unwrap_or_else(|e| panic!("OpenProcess({target_pid}, SYNCHRONIZE) for the death-watch: {e}"));

    // SAFETY: creates an unnamed, unowned manual-reset event; closed explicitly below on every
    // path out of this function.
    let accept_event = unsafe { WSACreateEvent() }.expect("WSACreateEvent for the listener's accept-readiness watch");
    let sock = SOCKET(listener.as_raw_socket() as usize);
    // SAFETY: `sock` is the listener's own live socket; `accept_event` was just created above.
    let rc = unsafe { WSAEventSelect(sock, Some(accept_event), FD_ACCEPT as i32) };
    assert_eq!(
        rc,
        0,
        "WSAEventSelect(FD_ACCEPT) on the control listener: {}",
        std::io::Error::last_os_error()
    );

    let handles = [HANDLE(accept_event.0 as *mut _), process];
    // SAFETY: both handles are live and owned by this function for the call's duration.
    let woken = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };

    // WSAEventSelect(s, None, 0) cancels the association, documented as also returning the
    // socket to blocking mode — measured in CI to NOT actually be reliable: a real run hit
    // WSAEWOULDBLOCK on the very next `accept()` below without the explicit `set_nonblocking`
    // that follows it. Both calls stay: the first cancels the FD_ACCEPT association (skipping it
    // and going straight to `set_nonblocking` left the association armed, which — same CI
    // evidence — is its own source of spurious wakeups), the second is what the socket's
    // blocking mode has actually been observed to need.
    // SAFETY: `sock` is still the listener's own live socket.
    let rc = unsafe { WSAEventSelect(sock, None, 0) };
    assert_eq!(
        rc,
        0,
        "WSAEventSelect(0) to cancel the accept-readiness association: {}",
        std::io::Error::last_os_error()
    );
    listener
        .set_nonblocking(false)
        .expect("restore the control listener to blocking mode");
    // SAFETY: closes only the two handles this function opened above.
    unsafe {
        let _ = WSACloseEvent(accept_event);
        let _ = CloseHandle(process);
    }

    if woken == WAIT_FAILED {
        panic!(
            "WaitForMultipleObjects while waiting for a control connection failed: {}",
            std::io::Error::last_os_error()
        );
    }
    match woken.0.wrapping_sub(WAIT_OBJECT_0.0) {
        0 => listener.accept().expect("accept a control connection").0,
        1 => final_peek_or_die(listener, target_pid),
        _ => panic!("WaitForMultipleObjects while waiting for a control connection returned {woken:?}"),
    }
}

/// Async sibling of [`accept_or_die`], for the `tokio`-feature helpers below: same contract, via
/// a biased `tokio::select!` between accepting and the SAME exit watch cosca's own async `Child`
/// already implements (`cosca::tokio::Child::wait`) — not a pipe, and no platform-specific fd/
/// HANDLE plumbing needed here either, since `wait` already IS that on every platform.
///
/// `biased;` with the accept arm first gives the "listener wins" contract: `TcpListener::accept()`
/// is cancel-safe (a dropped, not-yet-ready future consumes nothing), so a connection already
/// queued when this function is polled is taken on the very first poll, before `wait()` is polled
/// at all — the same "exit is a prompt, not proof" question the sync implementations resolve with
/// `final_peek_or_die` does not even arise here, because polling itself is already atomic per
/// call: there is no window where both arms are "ready" and one must be chosen over the other.
#[cfg(feature = "tokio")]
pub async fn accept_or_die_async(listener: &::tokio::net::TcpListener, child: &mut cosca::tokio::Child) -> TcpStream {
    ::tokio::select! {
        biased;
        accepted = listener.accept() => {
            let (stream, _) = accepted.expect("accept a control connection");
            let stream = stream.into_std().expect("convert the accepted tokio stream to std");
            // `into_std` does NOT reset blocking mode (verified: it just rewraps the same raw
            // fd/socket, which tokio itself always keeps non-blocking) — every caller of this
            // function does ordinary BLOCKING std reads/writes on the result, so this must
            // explicitly restore blocking mode, not merely convert the type.
            stream.set_nonblocking(false).expect("restore the accepted stream to blocking mode");
            stream
        }
        status = child.wait() => {
            match status {
                Ok(status) => panic!("the control target exited ({status}) before it connected"),
                // An error watching the exit is reported as exactly that error — never folded
                // into "died", which would misattribute a wait-mechanism failure to the target.
                Err(e) => panic!("watching the control target's exit while waiting for a connection: {e}"),
            }
        }
    }
}

/// Spawn `mode <addr> [extra...]` as a control child that connects, writes a 1-byte tag,
/// then blocks; returns the owned `Child` and the accepted socket (the tag read proves it
/// is alive). `contain` applies `.contain()`. This is the canonical form; `tests/lifecycle.rs`
/// now calls this instead of keeping its own copy.
pub fn spawn_control(mode: &str, extra: &[&str], contain: bool) -> (cosca::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut argv: Vec<String> = vec!["cosca_testbin".into(), mode.into(), addr];
    argv.extend(extra.iter().map(|s| s.to_string()));
    let mut cmd = cosca::Command::new();
    cmd.executable(testbin()).args(&argv);
    if contain {
        cmd.contain();
    }
    let child = cmd.spawn().expect("spawn control child");
    let mut sock = accept_or_die(&listener, child.id().pid());
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    (child, sock)
}

/// `spawn_control`'s shape against the GUI-subsystem helper: it takes no mode argument (the
/// binary has exactly one behaviour) and tags `b"G"`. A GUI-subsystem image never attaches to
/// its spawner's console, so this is the only way to construct a child whose creation flags say
/// nothing excludes delivery while the OS puts it out of reach.
#[cfg(windows)]
pub fn spawn_gui_control(contain: bool) -> (cosca::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let exe = env!("CARGO_BIN_EXE_cosca_testbin_gui");
    let mut cmd = cosca::Command::new();
    cmd.executable(exe).args([exe, addr.as_str()]);
    if contain {
        cmd.contain();
    }
    let child = cmd.spawn().expect("spawn gui control child");
    let mut sock = accept_or_die(&listener, child.id().pid());
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    assert_eq!(&tag, b"G", "wrong gui tag");
    (child, sock)
}

/// Async sibling of [`spawn_gui_control`] — see there for why the GUI-subsystem image is the
/// only way to construct a child whose flags say nothing excludes delivery while the OS puts it
/// out of reach.
#[cfg(all(windows, feature = "tokio"))]
pub async fn spawn_gui_control_async(contain: bool) -> (cosca::tokio::Child, TcpStream) {
    let std_listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = std_listener.local_addr().unwrap().to_string();
    std_listener
        .set_nonblocking(true)
        .expect("set the listener nonblocking for tokio");
    let listener = ::tokio::net::TcpListener::from_std(std_listener).expect("wrap the listener for tokio");
    let exe = env!("CARGO_BIN_EXE_cosca_testbin_gui");
    let mut cmd = cosca::tokio::Command::new();
    cmd.args([exe, addr.as_str()]);
    if contain {
        cmd.contain();
    }
    let mut child = cmd.spawn().expect("spawn async gui control child");
    let mut sock = accept_or_die_async(&listener, &mut child).await;
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    assert_eq!(&tag, b"G", "wrong gui tag");
    (child, sock)
}

/// Convenience alias for the common `control-block` blocker (no `.contain()`). A one-line
/// shortcut over `spawn_control`, NOT a second copy of the body.
pub fn spawn_blocker() -> (cosca::Child, TcpStream) {
    spawn_control("control-block", &["R"], false)
}

/// Spawn a 2-level tree via a grandchild-spawning testbin `mode` (root tag "R" + one grandchild
/// tag "G"), optionally contained, and return the owned `Child` plus BOTH accepted sockets (the
/// two tag reads prove the 2-level tree is alive). The tree dies — and both sockets EOF — only
/// when the whole tree is torn down, so callers prove teardown by reading EOF on both, never by
/// a timer.
pub fn spawn_tree(mode: &str, contain: bool) -> (cosca::Child, Vec<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = cosca::Command::new();
    cmd.executable(testbin()).args(["cosca_testbin", mode, addr.as_str()]);
    if contain {
        cmd.contain();
    }
    let child = cmd.spawn().expect("spawn tree");
    let target_pid = child.id().pid();
    // Demux by tag exactly like spawn_tree_async (accept order is not guaranteed, and a
    // duplicate or foreign tag is a harness bug worth failing loudly on). Only the ROOT's own
    // death is watched (both accepts share the same target_pid) — if the root dies the whole
    // tree typically dies with it; the grandchild dying independently is not this helper's
    // contract to catch.
    let (mut root, mut grand) = (None, None);
    for _ in 0..2 {
        let mut s = accept_or_die(&listener, target_pid);
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        match &tag {
            b"R" => root = Some(s),
            b"G" => grand = Some(s),
            other => panic!("unexpected tree tag {other:?}"),
        }
    }
    (
        child,
        vec![root.expect("root R connected"), grand.expect("grandchild G connected")],
    )
}

/// Spawn the `spawn-grandchild` helper tree.
pub fn spawn_grandchild(contain: bool) -> (cosca::Child, Vec<TcpStream>) {
    spawn_tree("spawn-grandchild", contain)
}

/// Binds a fresh `127.0.0.1:0` listener in tokio's async form, for the `*_async` helpers below —
/// one definition so every caller sets non-blocking mode (required for `TcpListener::from_std`)
/// the same way.
#[cfg(feature = "tokio")]
fn bind_async_listener() -> (::tokio::net::TcpListener, String) {
    let std_listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = std_listener.local_addr().unwrap().to_string();
    std_listener
        .set_nonblocking(true)
        .expect("set the listener nonblocking for tokio");
    let listener = ::tokio::net::TcpListener::from_std(std_listener).expect("wrap the listener for tokio");
    (listener, addr)
}

/// Async analogue of `spawn_control`: spawn a testbin control child (it connects back and
/// sends its tag before the helper returns), optionally contained.
#[cfg(feature = "tokio")]
pub async fn spawn_control_async(mode: &str, extra: &[&str], contain: bool) -> (cosca::tokio::Child, TcpStream) {
    let (listener, addr) = bind_async_listener();
    let mut argv: Vec<String> = vec!["cosca_testbin".into(), mode.into(), addr];
    argv.extend(extra.iter().map(|s| s.to_string()));
    let mut cmd = cosca::tokio::Command::new();
    if contain {
        // Load the testbin as argv[0] via the std path (mode/addr stay at args[1..], so it behaves
        // identically) — keeps this shared helper on one code path across OSes. The async raw
        // backend also serves contained `executable()` (see raw_windows_async.rs).
        let mut path_argv = vec![testbin().to_string()];
        path_argv.extend(argv.into_iter().skip(1));
        cmd.args(path_argv);
        cmd.contain();
    } else {
        cmd.executable(testbin()).args(&argv); // uncontained → the async raw backend
    }
    let mut child = cmd.spawn().expect("spawn async control child");
    let mut sock = accept_or_die_async(&listener, &mut child).await;
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    (child, sock)
}

/// Spawn a 2-level tree via a grandchild-spawning testbin `mode` (root tag "R", grandchild
/// tag "G"), with builder configuration supplied by `configure` (containment mode, nesting).
/// Returns the root and grandchild control sockets identified by tag (accept order is not
/// guaranteed).
///
/// Only the ROOT's own death is watched (both accepts race the same `child.wait()`), exactly
/// like the sync `spawn_tree` — see its doc for why that is the established contract this
/// mirrors, not a gap introduced here.
#[cfg(feature = "tokio")]
pub async fn spawn_tree_async(
    mode: &str,
    configure: impl FnOnce(&mut cosca::tokio::Command),
) -> (cosca::tokio::Child, TcpStream, TcpStream) {
    let (listener, addr) = bind_async_listener();
    let mut cmd = cosca::tokio::Command::new();
    // Load the testbin as argv[0] via the std path (mode/addr at args[1..], so it behaves
    // identically): these trees are usually contained and the sole uncontained caller is
    // backend-agnostic, so argv[0] keeps this helper on one code path across OSes. `configure`
    // applies the containment/nesting/kill_on_drop.
    cmd.args([testbin(), mode, addr.as_str()]);
    configure(&mut cmd);
    let mut child = cmd.spawn().expect("spawn async tree");
    let (mut root, mut grandchild) = (None, None);
    for _ in 0..2 {
        let mut s = accept_or_die_async(&listener, &mut child).await;
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        match &tag {
            b"R" => root = Some(s),
            b"G" => grandchild = Some(s),
            other => panic!("unexpected tree tag {other:?}"),
        }
    }
    (
        child,
        root.expect("root R connected"),
        grandchild.expect("grandchild G connected"),
    )
}

/// A contained async `spawn-grandchild-echo` tree: both members round-trip a byte, so a test can
/// prove each POSITIVELY alive (see [`assert_echoes`]).
#[cfg(feature = "tokio")]
pub struct AsyncEchoTree {
    pub child: cosca::tokio::Child,
    pub root: TcpStream,
    pub grand: TcpStream,
    /// The grandchild's own pid, for reading the tree's cgroup back out of `/proc`.
    pub grand_pid: u32,
}

/// Spawn a contained [`AsyncEchoTree`] with the given `kill_on_drop`. Only the root's death is
/// watched, as in `spawn_tree_async` above.
#[cfg(feature = "tokio")]
pub async fn spawn_echo_tree_async(kill_on_drop: bool) -> AsyncEchoTree {
    let (listener, addr) = bind_async_listener();
    let mut cmd = cosca::tokio::Command::new();
    cmd.args([testbin(), "spawn-grandchild-echo", addr.as_str()]);
    cmd.contain();
    cmd.kill_on_drop(kill_on_drop);
    let mut child = cmd.spawn().expect("spawn async echo tree");
    let (mut root, mut grand) = (None, None);
    for _ in 0..2 {
        let mut s = accept_or_die_async(&listener, &mut child).await;
        match read_tag_and_pid(&mut s) {
            (b'R', _) => root = Some(s),
            (b'G', pid) => grand = Some((s, pid)),
            (tag, _) => panic!("unexpected tree tag {:?}", tag as char),
        }
    }
    let (grand, grand_pid) = grand.expect("grandchild G connected");
    AsyncEchoTree {
        child,
        root: root.expect("root R connected"),
        grand,
        grand_pid,
    }
}

/// Async `control-block` blocker (uncontained): a child that connects, tags "R", and blocks on
/// its socket. The accept/tag-read is sync std (the test side); the CHILD is async.
#[cfg(feature = "tokio")]
pub async fn spawn_blocker_async() -> (cosca::tokio::Child, TcpStream) {
    spawn_control_async("control-block", &["R"], false).await
}

/// Async analogue of `spawn_grandchild`, returning the root ("R") and grandchild ("G") control
/// sockets identified by tag (accept order is not guaranteed).
#[cfg(feature = "tokio")]
pub async fn spawn_grandchild_async(contain: bool) -> (cosca::tokio::Child, TcpStream, TcpStream) {
    spawn_grandchild_async_with(contain, true).await
}

/// `spawn_grandchild_async` with explicit `contain` and `kill_on_drop` flags, so a test can
/// exercise the `kill_on_drop(false)` Drop early-return (attached still armed) without `detach()`.
#[cfg(feature = "tokio")]
pub async fn spawn_grandchild_async_with(
    contain: bool,
    kill_on_drop: bool,
) -> (cosca::tokio::Child, TcpStream, TcpStream) {
    spawn_tree_async("spawn-grandchild", |cmd| {
        if contain {
            cmd.contain();
        }
        cmd.kill_on_drop(kill_on_drop);
    })
    .await
}

/// Read one `<tag><pid>\n` line from a freshly accepted `control-echo-pid` connection.
pub fn read_tag_and_pid(sock: &mut std::net::TcpStream) -> (u8, u32) {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = sock.read(&mut b).expect("read the control line");
        assert_ne!(n, 0, "the control connection closed before sending its tag line");
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
    }
    assert!(line.len() > 1, "a control line is a tag plus a pid, got {line:?}");
    let pid = std::str::from_utf8(&line[1..])
        .expect("the pid is ASCII")
        .parse()
        .expect("the pid is a number");
    (line[0], pid)
}

/// Prove a `control-echo-pid` member is POSITIVELY alive: send a byte and read the echo back.
/// A killed member gives EOF or `ConnectionReset` on the read instead, never the byte.
pub fn assert_echoes(sock: &mut std::net::TcpStream, who: &str) {
    sock.write_all(b"p")
        .unwrap_or_else(|e| panic!("{who} must accept a write while alive: {e}"));
    let mut b = [0u8; 1];
    sock.read_exact(&mut b)
        .unwrap_or_else(|e| panic!("{who} must echo the byte back while alive: {e}"));
    assert_eq!(&b, b"p", "{who} echoed {b:?} instead of the byte it was sent");
}

/// Duplicate each of `fds` aside and close it, restoring all of them (on drop, even if the test
/// panics) so the CURRENT process's own low-numbered descriptors are free for a test to reuse —
/// then land back where they started. Some fd_map regression tests need this THIS process's own
/// fd 1 and/or fd 2 closed to reproduce a bug that only manifests when a mapping's parent-side
/// source, or a `Stdio::from_file` target, gets allocated one of those exact numbers.
///
/// Safe only because this workspace's test runner (`cargo nextest`) puts every test function in
/// its own OS process — a plain `cargo test` run shares one process across parallel test
/// threads, so this would race with (and could disable output from) unrelated tests.
#[cfg(unix)]
pub struct RestoreStdio {
    saved: Vec<(libc::c_int, std::os::fd::OwnedFd)>,
}

#[cfg(unix)]
impl RestoreStdio {
    pub fn close(fds: &[libc::c_int]) -> RestoreStdio {
        use std::os::fd::{FromRawFd, OwnedFd};
        let mut saved = Vec::with_capacity(fds.len());
        for &fd in fds {
            // SAFETY: F_DUPFD_CLOEXEC(fd, 3) duplicates fd to a fresh number >= 3, checked below.
            let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            assert!(dup >= 0, "dup fd {fd} aside before closing it");
            // SAFETY: `dup` was just returned by a successful F_DUPFD_CLOEXEC.
            let dup = unsafe { OwnedFd::from_raw_fd(dup) };
            assert_eq!(unsafe { libc::close(fd) }, 0, "close the test process' fd {fd}");
            saved.push((fd, dup));
        }
        RestoreStdio { saved }
    }
}

#[cfg(unix)]
impl Drop for RestoreStdio {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        for (fd, dup) in &self.saved {
            // SAFETY: dup2 back onto `fd`; `dup` stays valid (closed normally by its own Drop,
            // right after) regardless of this call's outcome.
            //
            // Retries EINTR the same way `fd_map::dup2_onto` does, so a signal landing mid-restore
            // cannot leave `fd` unrestored, and asserts the final result: a restore failure here
            // would silently leave this test process' own fd in the wrong state for every test
            // that runs after it, defeating this guard's whole purpose.
            let ret = loop {
                let ret = unsafe { libc::dup2(dup.as_raw_fd(), *fd) };
                if ret != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break ret;
                }
            };
            debug_assert_eq!(
                ret,
                *fd,
                "dup2({}, {fd}) while restoring a guarded fd failed: {}",
                dup.as_raw_fd(),
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Lower this process' own `RLIMIT_NOFILE` soft limit to `to`, for the life of the guard,
/// restoring the original soft limit on drop (even if the test panics).
///
/// A forked child inherits its parent's rlimits at fork time, before any `pre_exec` hook runs —
/// so lowering the limit HERE, in the process that calls `spawn()`, is what makes an ordinary,
/// valid-looking child fd number deterministically exceed the CHILD's own limit and fail its
/// `dup2` with `EBADF`, regardless of whatever the host's real `ulimit -n` happens to be (on
/// Linux, a soft limit raised past `1_000_000` is entirely ordinary, so a test that assumes a
/// large but fixed child fd is always out of range is otherwise runner-dependent).
///
/// Safe only because this workspace's test runner (`cargo nextest`) puts every test function in
/// its own OS process — see `RestoreStdio`'s doc for why a plain `cargo test` run would not be.
#[cfg(unix)]
pub struct RestoreRlimitNofile {
    original: libc::rlimit,
}

#[cfg(unix)]
impl RestoreRlimitNofile {
    pub fn lower_to(to: libc::rlim_t) -> RestoreRlimitNofile {
        let mut original: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `original` is a valid, correctly-sized out-param.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) },
            0,
            "getrlimit(RLIMIT_NOFILE): {}",
            std::io::Error::last_os_error()
        );
        let lowered = libc::rlimit {
            rlim_cur: to,
            rlim_max: original.rlim_max,
        };
        // SAFETY: `lowered` only ever lowers `rlim_cur`; `rlim_max` is passed through unchanged,
        // so this cannot raise the process' hard ceiling.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) },
            0,
            "setrlimit(RLIMIT_NOFILE, {{cur: {to}, max: {}}}): {}",
            original.rlim_max,
            std::io::Error::last_os_error()
        );
        RestoreRlimitNofile { original }
    }
}

#[cfg(unix)]
impl Drop for RestoreRlimitNofile {
    fn drop(&mut self) {
        // SAFETY: restores exactly the limit `getrlimit` reported before this guard lowered it.
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.original) };
        // Raising a soft limit back up to (at most) its own untouched hard limit always succeeds
        // for an unprivileged process — asserted, not just documented in prose, matching
        // `lower_to`'s own checked `getrlimit`/`setrlimit` calls: if that guarantee is ever wrong
        // (a hardened sandbox, a future refactor that also lowers `rlim_max`), this fails loudly
        // here instead of silently leaving a lowered limit in place for every fd-hungry test that
        // runs in this process afterward.
        debug_assert_eq!(
            ret,
            0,
            "setrlimit(RLIMIT_NOFILE, restore to {{cur: {}, max: {}}}) failed: {}",
            self.original.rlim_cur,
            self.original.rlim_max,
            std::io::Error::last_os_error()
        );
    }
}
