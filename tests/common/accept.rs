//! The death-watched accept: wait for a connection on a listener, but fail loudly instead of
//! hanging if the process that should make it dies first.
//!
//! # Contract
//!
//! - The target is an unreaped child the caller owns: a [`Target`] (`cosca::Child`,
//!   `std::process::Child`). A pid only names a process while it is an unreaped child (a zombie
//!   at worst) or a handle to it is open. Every entry point
//!   first calls [`Target::has_exited`], a `try_wait`: `true` means the target is dead (and now
//!   reaped, its status cached for the caller's own later `wait`), so the pid is never opened;
//!   `false` means it is unreaped now and stays so, because nothing but the caller's own `wait`
//!   or `try_wait` reaps a `cosca::Child` (`SharedChild` starts no reaper thread; it reaps only
//!   inside `SharedChild::new`, `wait` and `try_wait`). The pid is then a stable name for
//!   `pidfd_open`, `kqueue` or `OpenProcess`. The caller must not `wait` on the target
//!   concurrently.
//! - The target performs the accept handshake ([`ack`]): after `connect()` it blocks until
//!   the harness has accepted the connection and written the ack byte, before doing anything
//!   else, including exiting. This is what makes the verdict deterministic: `connect()` returning
//!   does not mean the server side has queued the connection (the final ACK of the loopback
//!   handshake can sit in a backlog, or be deferred to ksoftirqd), so "the target exited and the
//!   queue is empty" cannot prove "it died before connecting". An opted-in target cannot exit
//!   between `connect()` and the accept, so any exit seen before the accept is a failure and is
//!   reported as one, without consulting the queue. Opt in by setting [`ACK_ENV`] on the
//!   target's command; a target that is not opted in but connects and exits is reported dead,
//!   and one that is opted in but connects to a plain `accept()` blocks forever.
//! - `also`, when given, is the [`ProcessId`] of a live descendant of the target, captured while
//!   the target's own liveness kept the descendant's pid stable (see `tests/common/report.rs`).
//!   The watch on it is opened first and then confirmed against that identity, so a pid that was
//!   reissued is reported as the descendant being gone, never watched.
//! - A caller must not close a member's control socket before the remaining accepts: a member that
//!   exits because its socket was closed is an ordinary exit that these functions report as
//!   "died before it connected".

use std::cell::RefCell;
use std::net::{TcpListener, TcpStream};

use cosca::identity::ProcessId;

#[path = "../../testbin/ack.rs"]
pub mod ack;
pub use ack::ACK_ENV;

#[cfg(target_os = "linux")]
#[path = "accept/linux.rs"]
mod linux;
#[cfg(target_os = "macos")]
#[path = "accept/macos.rs"]
mod macos;
#[cfg(windows)]
#[path = "accept/windows.rs"]
mod win;
#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(windows)]
use win as platform;

#[cfg(feature = "tokio")]
#[path = "accept/tokio.rs"]
mod async_impl;
#[cfg(feature = "tokio")]
pub use async_impl::{accept_or_die_async, accept_or_die_async_also};

#[cfg(windows)]
pub use win::wait_handles;

/// A child process the caller owns and has not reaped.
pub trait Target {
    fn pid(&self) -> u32;
    /// `try_wait`: `true` when the target has exited, in which case it is now reaped.
    fn has_exited(&mut self) -> bool;
}

impl Target for cosca::Child {
    fn pid(&self) -> u32 {
        self.id().pid()
    }

    fn has_exited(&mut self) -> bool {
        self.try_wait()
            .expect("try_wait the control target before watching it")
            .is_some()
    }
}

impl Target for std::process::Child {
    fn pid(&self) -> u32 {
        self.id()
    }

    fn has_exited(&mut self) -> bool {
        self.try_wait()
            .expect("try_wait the control target before watching it")
            .is_some()
    }
}

/// What a death-watched wait is waiting to become ready.
pub(crate) enum Source<'a> {
    Listener(&'a TcpListener),
    Stream(&'a TcpStream),
}

/// What ended a death-watched wait.
pub(crate) enum WatchEvent {
    /// The source is ready: a connection to accept, or bytes (or EOF) to read.
    Ready,
    /// This pid exited first.
    Died(u32),
}

/// The one message for a control target that exited before its connection was accepted, shared
/// by the sync and async paths.
pub fn died_before_connecting(pid: u32) -> ! {
    panic!("the control target (pid {pid}) died before it connected")
}

/// The message for a target that connected but exited before reporting.
pub fn died_before_reporting(pid: u32, what: &str) -> ! {
    panic!("the control target (pid {pid}) died before it reported {what}")
}

/// [`accept_or_die_also`] watching only `target`.
pub fn accept_or_die(listener: &TcpListener, target: &mut impl Target) -> TcpStream {
    accept_or_die_also(listener, target, None)
}

/// Blocks until either `listener` gets a connection, or `target` (or `also`) exits first, via the
/// OS's own exit notification (a `pidfd` on Linux, a `kqueue` `NOTE_EXIT` on macOS, a process
/// HANDLE on Windows), never a pipe: a descendant holding the pipe's write end open hides the
/// target's own exit from its EOF. A connection is accepted and acked (see the module doc).
///
/// An exit is checked before the listener on Linux and Windows, and among simultaneously returned
/// events on macOS. Both being ready means the target broke the ack handshake; either verdict then
/// reports that misuse.
///
/// `also` covers a tree whose root is alive but whose grandchild died before connecting: watching
/// the root alone would wait forever.
pub fn accept_or_die_also(listener: &TcpListener, target: &mut impl Target, also: Option<ProcessId>) -> TcpStream {
    let pid = target.pid();
    debug_assert_ne!(Some(pid), also.map(|id| id.pid()), "the two watched pids must differ");
    if target.has_exited() {
        died_before_connecting(pid);
    }
    match platform::wait(Source::Listener(listener), pid, also) {
        WatchEvent::Ready => accept_and_ack(listener),
        WatchEvent::Died(dead) => died_before_connecting(dead),
    }
}

/// Blocks until `pid` exits, with the same contract on `pid` as [`accept_or_die_also`]'s target:
/// an unreaped child the caller does not `wait` on concurrently.
///
/// The backends wait on a source and a pid, so the source here is one end of a loopback pair
/// whose other end lives in this frame: nothing can ever make it readable, and unlike a
/// listener no stranger can connect to it.
pub(crate) fn wait_for_exit(pid: u32) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the exit watch's private pair");
    let held = TcpStream::connect(listener.local_addr().expect("local_addr of the private pair"))
        .expect("connect the exit watch's private pair");
    let (silent, _) = listener.accept().expect("accept the exit watch's private pair");
    match platform::wait(Source::Stream(&silent), pid, None) {
        WatchEvent::Died(dead) => debug_assert_eq!(dead, pid, "the exit watch watches one pid"),
        WatchEvent::Ready => unreachable!("nothing writes to or closes the exit watch's private pair"),
    }
    drop(held);
}

/// Waits until `stream` has bytes (or EOF) to read, or `target_pid` exits first.
pub(crate) fn wait_readable(stream: &TcpStream, target_pid: u32) -> WatchEvent {
    platform::wait(Source::Stream(stream), target_pid, None)
}

/// Accepts the connection the wait reported ready and writes the ack byte to it.
fn accept_and_ack(listener: &TcpListener) -> TcpStream {
    let (stream, _) = listener.accept().expect("accept a control connection");
    ack_now(stream)
}

/// Writes the ack to `stream`, which the caller has accepted and left in blocking mode.
pub(crate) fn ack_now(mut stream: TcpStream) -> TcpStream {
    ack::send_ack(&mut stream)
        .unwrap_or_else(|e| panic!("writing the accept acknowledgement to the control connection failed: {e}"));
    stream
}

// Test seam =====

type ArmedHook = Box<dyn FnMut()>;

thread_local! {
    static ARMED_HOOK: RefCell<Option<ArmedHook>> = const { RefCell::new(None) };
}

/// Runs `body` with `hook` called on this thread every time a death-watched wait has armed its
/// watches and is about to block. That is the one moment a test can act on the target knowing the
/// watch is already in place, so an exit the hook triggers is an exit AFTER arming, on every
/// platform. The hook is removed when `body` returns or unwinds.
pub fn with_armed_hook<R>(hook: impl FnMut() + 'static, body: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ARMED_HOOK.with(|h| *h.borrow_mut() = None);
        }
    }
    ARMED_HOOK.with(|h| {
        let mut slot = h.borrow_mut();
        debug_assert!(slot.is_none(), "an armed hook is already installed on this thread");
        *slot = Some(Box::new(hook));
    });
    let _reset = Reset;
    body()
}

/// Called by each platform wait after arming, before it blocks.
pub(crate) fn notify_armed() {
    // The hook is taken out for the call so that it can itself install nothing and re-enter
    // nothing; it goes back afterwards, in case the wait loops and arms again.
    let taken = ARMED_HOOK.with(|h| h.borrow_mut().take());
    if let Some(mut hook) = taken {
        hook();
        ARMED_HOOK.with(|h| *h.borrow_mut() = Some(hook));
    }
}
