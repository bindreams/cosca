//! A root and one leaf that report the signals they get, each a process of its own: the lib's test
//! binary re-run as [`ROOT`], dispatched from `main` before the runner starts, so it is single-threaded
//! when it starts the leaf (its reaper thread starts after). The root starts the leaf, which shares its
//! stdin and stdout, so a test sees both members' lines on one stream and can tell which signal each of
//! them received.
//!
//! A [`Mode`] names the signals a member reports. A member prints `<root|leaf> SIG<NAME>` for one, and
//! then exits, except for [`Mode::ThenTerm`]'s `SIGUSR1`, after which it goes on. The leaf prints `r`
//! once it holds every signal of the mode, so a signal sent after the test reads it is always reported.
//! When a member's stdin ends with nothing reported it prints `<root|leaf> eof`.
//!
//! A handler for each signal of the mode (from `signal-hook`) sets the signal's flag and then writes one
//! byte, without blocking, to a pipe of the member's own. The main thread waits for its stdin and that
//! pipe together; on a wake-up it empties the pipe and reports the flags that are set, in the order
//! [`Mode::signals`] lists them, whatever the order they arrived in. When the stdin ends it does that
//! once more before it prints `eof`, so a signal sent before the end is reported before `eof`.
//!
//! Only the main thread has the mode's signals unblocked, so the thread that records a signal is the one
//! that reports it. Handlers are installed before `r` is printed (the root's before the leaf exists).
//!
//! The reports rest on one fact: a signal sent before the stdin ended has run its handler before the
//! main thread sees `poll` return. That holds by construction where the kernel runs a handler before
//! the thread returns to user space, and under Rosetta it is a claim about the translator, not a
//! guarantee.
//!
//! A member that cannot set itself up (a libc call fails, a thread cannot start, a read fails) says why
//! on its stderr and exits with 101. A leaf that fails so ends the root too, so the tree's stdout
//! closes and the test fails on it. If the root fails after it started the leaf, the leaf still holds
//! the stdout, and a test that waits for the root's line waits on. A closed stdout is a normal end: the
//! member exits with 0.

use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use nix::sys::signal::{SigSet, Signal};
use rustix::event::{PollFd, PollFlags};

use super::fixture_role::FixtureRole;

pub(crate) const ROOT: FixtureRole = FixtureRole::new("--cosca-signal-tree-root", run_root);
pub(crate) const LEAF: FixtureRole = FixtureRole::new("--cosca-signal-tree-leaf", run_leaf);

/// The signals a tree reports.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// `SIGHUP`, `SIGTERM`, `SIGUSR1` and `SIGUSR2`, each reported and ending the member.
    Reporting,
    /// `SIGUSR1`, reported and the member goes on, and `SIGTERM`, reported and ending it.
    ThenTerm,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Reporting => "reporting",
            Mode::ThenTerm => "then-term",
        }
    }

    fn parse(name: &str) -> Mode {
        [Mode::Reporting, Mode::ThenTerm]
            .into_iter()
            .find(|mode| mode.name() == name)
            .unwrap_or_else(|| die(&format!("no mode {name:?}")))
    }

    /// The signals of the mode, in the order a member reports those it has seen together.
    fn signals(self) -> &'static [Signal] {
        match self {
            Mode::Reporting => &[Signal::SIGHUP, Signal::SIGTERM, Signal::SIGUSR1, Signal::SIGUSR2],
            Mode::ThenTerm => &[Signal::SIGUSR1, Signal::SIGTERM],
        }
    }

    fn ends_on(self, signal: Signal) -> bool {
        match self {
            Mode::Reporting => true,
            Mode::ThenTerm => signal == Signal::SIGTERM,
        }
    }
}

#[derive(Clone, Copy)]
enum TreeMember {
    Root,
    Leaf,
}

impl TreeMember {
    fn name(self) -> &'static str {
        match self {
            TreeMember::Root => "root",
            TreeMember::Leaf => "leaf",
        }
    }
}

fn run_root(rest: &[OsString]) -> ! {
    run(TreeMember::Root, mode_of(TreeMember::Root, rest))
}

fn run_leaf(rest: &[OsString]) -> ! {
    run(TreeMember::Leaf, mode_of(TreeMember::Leaf, rest))
}

/// The mode `member` is started with: the first argument after its flag.
fn mode_of(member: TreeMember, rest: &[OsString]) -> Mode {
    let name = rest
        .first()
        .and_then(|mode| mode.to_str())
        .unwrap_or_else(|| die(&format!("the {} has no mode in {rest:?}", member.name())));
    Mode::parse(name)
}

/// The arguments, after the test binary's path, that start the root of a tree of `mode`.
pub(crate) fn argv(mode: Mode) -> Vec<OsString> {
    ROOT.argv(&[OsStr::new(mode.name())])
}

/// The exit code of a member that could not set itself up: a panic's.
const SETUP_FAILED: i32 = 101;

/// Ends the process, not only the calling thread, with [`SETUP_FAILED`].
fn die(message: &str) -> ! {
    // A closed stderr is no reason to do anything else.
    _ = writeln!(std::io::stderr(), "signal tree: {message}");
    std::process::exit(SETUP_FAILED)
}

/// What a member has seen: a flag per signal of the mode, and the read end of the pipe that wakes it.
struct Seen {
    flags: Vec<(Signal, Arc<AtomicBool>)>,
    wake: UnixStream,
}

/// Installs a handler for each signal of `mode`: it sets the signal's flag, then writes a byte to the
/// returned pipe. The registry runs a signal's actions in the order they were registered, which is what
/// puts the flag first.
fn register_handlers(mode: Mode) -> Seen {
    let (wake, write) = UnixStream::pair().unwrap_or_else(|e| die(&format!("socketpair: {e}")));
    wake.set_nonblocking(true)
        .unwrap_or_else(|e| die(&format!("make the wake pipe non-blocking: {e}")));
    let flags = mode
        .signals()
        .iter()
        .map(|&signal| {
            let flag = Arc::new(AtomicBool::new(false));
            let number = signal as libc::c_int;
            signal_hook::flag::register(number, Arc::clone(&flag))
                .unwrap_or_else(|e| die(&format!("register the flag of {signal}: {e}")));
            let write = write
                .try_clone()
                .unwrap_or_else(|e| die(&format!("duplicate the wake pipe: {e}")));
            signal_hook::low_level::pipe::register(number, write)
                .unwrap_or_else(|e| die(&format!("register the wake pipe of {signal}: {e}")));
            (signal, flag)
        })
        .collect();
    Seen { flags, wake }
}

/// Blocks or unblocks (`how`) the signals of `mode` for the calling thread.
fn change_mask(how: libc::c_int, mode: Mode) {
    let mut set = SigSet::empty();
    for &signal in mode.signals() {
        set.add(signal);
    }
    // SAFETY: `set` is an initialised set.
    let rc = unsafe { libc::pthread_sigmask(how, set.as_ref(), std::ptr::null_mut()) };
    if rc != 0 {
        die(&format!("pthread_sigmask: {}", std::io::Error::from_raw_os_error(rc)));
    }
}

/// Whether the calling thread blocks `signal`.
fn blocks(signal: Signal) -> bool {
    let mut current = std::mem::MaybeUninit::uninit();
    // SAFETY: a null `set` only reads the mask, into `current`.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), current.as_mut_ptr()) };
    if rc != 0 {
        die(&format!("pthread_sigmask: {}", std::io::Error::from_raw_os_error(rc)));
    }
    // SAFETY: `pthread_sigmask` initialised `current`.
    unsafe { libc::sigismember(current.as_ptr(), signal as libc::c_int) == 1 }
}

fn run(member: TreeMember, mode: Mode) -> ! {
    let seen = match member {
        TreeMember::Root => {
            // Blocked here, so the reaper inherits it and only the main thread has the signals.
            change_mask(libc::SIG_BLOCK, mode);
            let seen = register_handlers(mode);
            let mut leaf = start_leaf(mode);
            // The reaper waits, so a leaf that ends first is no zombie while the root lives. A leaf that
            // could not set itself up ends the root too: the stdout closes and the test fails on it.
            std::thread::Builder::new()
                .name("reaper".to_owned())
                .spawn(move || {
                    let status = leaf.wait().unwrap_or_else(|e| die(&format!("wait for the leaf: {e}")));
                    if status.code() == Some(SETUP_FAILED) {
                        die("the leaf could not set itself up");
                    }
                })
                .unwrap_or_else(|e| die(&format!("start the reaper thread: {e}")));
            change_mask(libc::SIG_UNBLOCK, mode);
            seen
        }
        TreeMember::Leaf => {
            let seen = register_handlers(mode);
            // The root's mask may have come with the exec: the handlers are in place, so unblock.
            change_mask(libc::SIG_UNBLOCK, mode);
            report("r\n");
            seen
        }
    };
    debug_assert!(
        mode.signals().iter().all(|&signal| !blocks(signal)),
        "the main thread of a signal tree member must not block the mode's signals"
    );
    serve(member, mode, &seen)
}

/// Waits for the stdin and the wake pipe, and reports what it has seen, until the stdin ends.
fn serve(member: TreeMember, mode: Mode, seen: &Seen) -> ! {
    let stdin = rustix::stdio::stdin();
    // The stdin is shared with the other member, so a read must not block on bytes the other took.
    let flags = rustix::fs::fcntl_getfl(stdin).unwrap_or_else(|e| die(&format!("fcntl(F_GETFL) on the stdin: {e}")));
    rustix::fs::fcntl_setfl(stdin, flags | rustix::fs::OFlags::NONBLOCK)
        .unwrap_or_else(|e| die(&format!("fcntl(F_SETFL) on the stdin: {e}")));
    loop {
        let mut fds = [
            PollFd::new(&stdin, PollFlags::IN),
            PollFd::new(&seen.wake, PollFlags::IN),
        ];
        crate::wait::poll_ready(&mut fds).unwrap_or_else(|e| die(&format!("poll: {e}")));
        let stdin_ready = !fds[0].revents().is_empty();
        empty_wake_pipe(seen);
        report_seen(member, mode, seen);
        if stdin_ready && stdin_ended(stdin) {
            // A signal sent before the end has run its handler by now.
            empty_wake_pipe(seen);
            report_seen(member, mode, seen);
            report(&format!("{} eof\n", member.name()));
            std::process::exit(0);
        }
    }
}

/// Reads and discards what the stdin holds now; whether it has ended.
fn stdin_ended(stdin: rustix::fd::BorrowedFd<'_>) -> bool {
    let mut buf = [0u8; 256];
    match rustix::io::retry_on_intr(|| rustix::io::read(stdin, &mut buf)) {
        Ok(0) => true,
        Ok(_) => false,
        Err(rustix::io::Errno::AGAIN) => false,
        Err(e) => die(&format!("read the stdin: {e}")),
    }
}

/// Drains the wake pipe.
fn empty_wake_pipe(seen: &Seen) {
    let mut buf = [0u8; 256];
    loop {
        match (&seen.wake).read(&mut buf) {
            Ok(0) => die("the wake pipe closed"),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => die(&format!("read the wake pipe: {e}")),
        }
    }
}

/// Reports the signals seen, in the mode's order.
fn report_seen(member: TreeMember, mode: Mode, seen: &Seen) {
    for (signal, flag) in &seen.flags {
        if flag.swap(false, Ordering::SeqCst) {
            report_signal(member, mode, *signal);
        }
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "this process is single-threaded here: nothing else forks, so there is no lock to hold"
)]
fn start_leaf(mode: Mode) -> std::process::Child {
    LEAF.command(&[OsStr::new(mode.name())])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| die(&format!("spawn the leaf: {e}")))
}

fn report_signal(member: TreeMember, mode: Mode, signal: Signal) {
    report(&format!("{} {}\n", member.name(), signal.as_str()));
    if mode.ends_on(signal) {
        std::process::exit(0);
    }
}

/// Writes `line` (one line, far below `PIPE_BUF`) to the stdout in one `write`, so the two members'
/// lines never interleave. A reader that has gone is a normal end: the member exits with 0.
fn report(line: &str) {
    let mut out = std::io::stdout().lock();
    match out.write_all(line.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
        Err(e) => die(&format!("write {line:?} to the stdout: {e}")),
    }
}
