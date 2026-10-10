//! A process that owns a [`ShimLink`](super::link::ShimLink) and can be ended on demand: cosca, for
//! the tests that end it while a real shim runs.
//!
//! The lib's test binary is also this helper: its `main` calls [`run_if_requested`] first. It binds
//! a link in the directory it is given, prints `dir=<link dir>` and `pid=<its pid>`, and then lives
//! until its stdin ends or it is killed. Its stdout carries what it observes, one event per line. The
//! line `fork` on its stdin makes a fork copy of it, as `hold-copy` does at the start; the line
//! `send-exit <bytes>` sends each byte as a control byte to the shim and exits at once; the line
//! `read-frames` makes a copy that reads the shim's connection until the shim ends it and then prints
//! `frames <hex>`, so that a test can see what the shim said to a cosca that has been killed.
//!
//! Modes:
//! - `plain`: the acceptor answers as usual.
//! - `hold`: the acceptor is held before it serves anything, so a shim's hello is never answered.
//! - `hold-copy`: `hold`, and a fork copy of this process, holding the listener and every other
//!   descriptor, lives until stdin ends: the connection stays open when this process is killed, so
//!   only the owner watch can tell the shim that cosca is gone.
//! - `leak-before`, `leak-after`: `hold`, and a fork copy that accepts the shim's connection on the
//!   copied listener and writes `A` to it, right after accepting (`before`: ahead of the shim's
//!   checks) or after reading the shim's hello (`after`).

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

use super::link::probe::Probe;
use super::link::ShimLink;

const FLAG: &str = "--cosca-shim-test-owner";
/// The stdin command that sends control bytes and exits, followed by the bytes.
pub(crate) const SEND_EXIT: &str = "send-exit ";
/// The stdin command that forks a copy holding the shim's connection and reading what the shim sends.
pub(crate) const READ_FRAMES: &str = "read-frames";

/// Runs the helper and exits, if this process was started as one.
pub(crate) fn run_if_requested() {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.get(1).is_none_or(|a| a != FLAG) {
        return;
    }
    let mode = args[2].to_string_lossy().into_owned();
    std::process::exit(run(&mode, Path::new(&args[3])));
}

/// The argv (after the program name) that starts the helper.
pub(crate) fn argv(mode: &str, work: &Path) -> Vec<OsString> {
    vec![FLAG.into(), mode.into(), work.into()]
}

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").expect("the test is reading");
    out.flush().expect("the test is reading");
}

fn run(mode: &str, work: &Path) -> i32 {
    // SAFETY: `geteuid` has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let (probe, events) = Probe::new();
    let link = ShimLink::bind_probed(work, euid, probe.clone()).expect("the link binds");
    if mode != "plain" {
        probe.hold_acceptor();
    }
    say(&format!("dir={}", link.dir().display()));
    say(&format!("pid={}", std::process::id()));
    std::thread::spawn(move || {
        for event in events {
            say(&format!("event {event:?}"));
        }
    });
    match mode {
        "plain" | "hold" => {}
        "hold-copy" => fork_copy(|| {}),
        "leak-before" => fork_copy(|| leak(false)),
        "leak-after" => fork_copy(|| leak(true)),
        other => panic!("unknown mode {other}"),
    }
    say("ready");
    // Lives until the test closes this process's stdin. `fork` makes a copy of everything open now.
    for line in std::io::stdin().lines() {
        match line.expect("stdin").as_str() {
            "fork" => {
                fork_copy(|| {});
                say("forked");
            }
            READ_FRAMES => {
                let conn = link.connection_fd().expect("the shim is connected");
                fork_copy(|| read_frames(conn));
                say("forked");
            }
            command if command.starts_with(SEND_EXIT) => {
                for byte in command[SEND_EXIT.len()..].bytes() {
                    link.send_control(byte).expect("the byte reaches the shim");
                }
                // No destructors: the process ends as cosca would when killed.
                std::process::exit(0);
            }
            other => panic!("unknown command {other}"),
        }
    }
    drop(link);
    0
}

/// Forks a copy that runs `body` and then waits for stdin to end. Only system calls run in the copy:
/// another thread of this process may hold the allocator's lock.
fn fork_copy(body: impl FnOnce()) {
    // SAFETY: the copy calls only `libc` functions and `body`, which does the same, until `_exit`.
    match unsafe { libc::fork() } {
        -1 => panic!("fork: {}", std::io::Error::last_os_error()),
        0 => {
            body();
            let mut byte = 0u8;
            // SAFETY: `byte` is valid for 1 byte; the loop reads until stdin ends.
            unsafe {
                while libc::read(0, (&mut byte as *mut u8).cast(), 1) > 0 {}
                libc::_exit(0)
            }
        }
        _ => {}
    }
}

/// The exit code of a copy whose `poll` failed.
pub(crate) const POLL_FAILED: i32 = 92;

/// In a copy: blocks until `fd` is readable or hung up. A failed `poll` ends the copy with
/// [`POLL_FAILED`], so that a test that waits for it does not mistake the silence for an answer. Raw
/// system calls only.
unsafe fn wait_readable(fd: libc::c_int) {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` is valid for the call.
    unsafe {
        while libc::poll(&mut poll, 1, -1) < 0 {
            if *libc::__errno_location() != libc::EINTR {
                libc::_exit(POLL_FAILED);
            }
        }
    }
}

/// In the copy: reads `conn` until the other end closes it, prints the bytes as `frames <hex>` and
/// ends. Raw system calls only. The connection is non-blocking, and shared with the owner.
fn read_frames(conn: std::os::fd::RawFd) {
    // SAFETY: raw system calls on a descriptor and stack buffers only.
    unsafe {
        let mut bytes = [0u8; 64];
        let mut len = 0;
        while len < bytes.len() {
            wait_readable(conn);
            let n = libc::read(conn, bytes.as_mut_ptr().add(len).cast(), bytes.len() - len);
            if n == 0 {
                break;
            }
            if n > 0 {
                len += n as usize;
            } else if *libc::__errno_location() != libc::EAGAIN && *libc::__errno_location() != libc::EINTR {
                break;
            }
        }
        let mut line = [0u8; 8 + 2 * 64 + 1];
        line[..7].copy_from_slice(b"frames ");
        let digits = b"0123456789abcdef";
        for i in 0..len {
            line[7 + 2 * i] = digits[(bytes[i] >> 4) as usize];
            line[7 + 2 * i + 1] = digits[(bytes[i] & 15) as usize];
        }
        line[7 + 2 * len] = b'\n';
        libc::write(1, line.as_ptr().cast(), 7 + 2 * len + 1);
        libc::_exit(0)
    }
}

/// In the copy: accepts on the copied listener and writes `A`, after reading the hello if `after_hello`.
fn leak(after_hello: bool) {
    // SAFETY: raw system calls on descriptors and stack buffers only.
    unsafe {
        let listener = (3..1024)
            .find(|&fd| {
                let mut accepting: libc::c_int = 0;
                let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ACCEPTCONN,
                    (&mut accepting as *mut libc::c_int).cast(),
                    &mut len,
                ) == 0
                    && accepting == 1
            })
            .unwrap_or_else(|| libc::_exit(90));
        // The listener is non-blocking: the connection may not be queued yet.
        wait_readable(listener);
        let conn = libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut());
        if conn < 0 {
            libc::_exit(91);
        }
        if after_hello {
            let mut hello = 0u8;
            libc::read(conn, (&mut hello as *mut u8).cast(), 1);
        }
        libc::write(conn, b"A".as_ptr().cast(), 1);
    }
}

#[cfg(test)]
#[path = "owner_helper_tests.rs"]
mod owner_helper_tests;
