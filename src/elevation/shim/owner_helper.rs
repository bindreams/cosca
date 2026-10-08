//! A process that owns a [`ShimLink`](super::link::ShimLink) and can be ended on demand: cosca, for
//! the tests that end it while a real shim runs (`owner_exit_*`, `foreign_writer_of_a_is_refused`).
//!
//! The lib's test binary is also this helper: its `main` calls [`run_if_requested`] first. It binds
//! a link in the directory it is given, prints `dir=<link dir>` and `pid=<its pid>`, and then lives
//! until its stdin ends or it is killed. Its stdout carries what it observes, one event per line. The
//! line `fork` on its stdin makes a fork copy of it, as `hold-copy` does at the start.
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
        let mut poll = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        libc::poll(&mut poll, 1, -1);
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
