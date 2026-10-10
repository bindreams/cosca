//! Everything before the program starts: the connection, who cosca is, the owner watch, hello, and
//! the answer.
//!
//! Nothing is written until the listener is verified and the owner watch is open. A refusal before
//! hello writes nothing, so cosca, which answers a connection only after hello, never sees it, and
//! the outcome there is always "not started, shim not connected".

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{open, stat, Mode, OFlags};
use rustix::io::Errno;
use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use rustix::process::{pidfd_open, Pid, PidfdFlags};

use super::child::Spawned;
use super::fds::{readable_now, wait_readable};
use super::{Exit, Shim};
use crate::elevation::shim::codes;
use crate::elevation::shim::creds::{peer_credentials, recv_with_credentials, set_passcred, Received};
use crate::elevation::shim::hooks::{Gate, Inject};
use crate::elevation::shim::link::SOCKET_NAME;
use crate::elevation::shim::owner_watch::OwnerPidfdFailure;
use crate::elevation::shim::protocol::{Frame, Refusal, ShimArgs};

/// Sends all of `bytes` without raising `SIGPIPE`.
pub(super) fn send_all(fd: BorrowedFd<'_>, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        match rustix::net::send(fd, bytes, rustix::net::SendFlags::NOSIGNAL) {
            Ok(n) => bytes = &bytes[n..],
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Why the start must not go on.
enum Stop {
    OwnerExited,
    Signaled,
}

/// What a failed `stat` of `fd_path`, a path under `/proc`, says: only `ENOENT` means `/proc` is not there.
fn proc_probe_failure(fd_path: &str, errno: Errno) -> String {
    match errno {
        Errno::NOENT => format!("/proc must be mounted: {fd_path}: {errno}"),
        _ => format!("cannot reach {fd_path}: {errno}"),
    }
}

impl Shim {
    /// Connects to `<dir>/s` relative to the directory's descriptor, so that a long `TMPDIR` cannot
    /// overflow `sun_path`: through `/proc/thread-self/fd`.
    pub(super) fn connect(&mut self, args: &ShimArgs) -> Result<(), Exit> {
        let unreachable = |shim: &Shim, why: String| shim.refuse(codes::NO_ANSWER, &why);
        let dir = open(
            &args.dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| unreachable(self, format!("could not open {}: {e}", args.dir.display())))?;
        let socket = socket_with(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::CLOEXEC, None)
            .map_err(|e| unreachable(self, format!("could not make a socket: {e}")))?;
        set_passcred(socket.as_fd()).map_err(|e| unreachable(self, format!("SO_PASSCRED: {e}")))?;
        // The probe comes first: without `/proc`, the connect below fails with a bare `ENOENT`.
        let fd_path = format!("/proc/thread-self/fd/{}", dir.as_raw_fd());
        stat(&fd_path).map_err(|e| unreachable(self, proc_probe_failure(&fd_path, e)))?;
        let path = format!("{fd_path}/{SOCKET_NAME}");
        let address = SocketAddrUnix::new(&path).map_err(|e| unreachable(self, format!("{path}: {e}")))?;
        connect(&socket, &address).map_err(|e| unreachable(self, format!("could not reach cosca: {e}")))?;
        self.conn = Some(socket);
        Ok(())
    }

    /// The listener's pid and euid must be cosca's, as argv says.
    pub(super) fn verify_listener(&mut self, args: &ShimArgs) -> Result<(), Exit> {
        let creds = peer_credentials(self.conn().as_fd()).map_err(|e| {
            self.refuse(
                codes::NOT_COSCA,
                &format!("cannot read the listener's credentials: {e}"),
            )
        })?;
        if creds.pid != args.cosca_pid as i32 || creds.uid != args.cosca_euid {
            return Err(self.refuse(codes::NOT_COSCA, "the listener's pid or euid is not cosca's"));
        }
        Ok(())
    }

    /// Opens the owner watch: a pidfd on cosca's pid, before hello. cosca answers only after it has
    /// read the hello, and the answer's credentials name cosca's pid, so cosca was alive after
    /// this open and the pidfd names it.
    pub(super) fn watch_owner(&mut self, args: &ShimArgs) -> Result<OwnedFd, Exit> {
        let lowered = self
            .hooks
            .is_some_and(|h| h.exhaust_fds())
            .then(|| lower_nofile(lowest_free_fd()));
        // A pid no process can have is the kernel's `EINVAL`, which reads as "gone".
        let opened = match i32::try_from(args.cosca_pid).ok().and_then(Pid::from_raw) {
            Some(pid) => pidfd_open(pid, PidfdFlags::empty()),
            None => Err(Errno::INVAL),
        };
        if let Some(previous) = lowered {
            previous.restore();
        }
        let owner = opened.map_err(|e| {
            let errno = e.raw_os_error();
            let failure = OwnerPidfdFailure::from_errno(errno);
            self.log
                .line(format_args!("pidfd_open(owner): errno {errno} ({failure:?})"));
            let why = match failure {
                OwnerPidfdFailure::CoscaGone => "cosca's process is gone",
                OwnerPidfdFailure::Unwatchable => "could not watch cosca's process",
            };
            self.refuse(failure.exit_code(), why)
        })?;
        self.log.line(format_args!("owner verified pid={}", args.cosca_pid));
        Ok(owner)
    }

    pub(super) fn say_hello(&mut self) -> Result<(), Exit> {
        send_all(self.conn().as_fd(), &Frame::Hello.encode())
            .map_err(|e| self.refuse(codes::NO_ANSWER, &format!("could not say hello: {e}")))?;
        self.hello_sent = true;
        self.log.line(format_args!("hello sent; awaiting the answer"));
        Ok(())
    }

    /// Waits for the first byte: `A` or `N`, written by cosca. cosca's exit ends the wait (123), and so
    /// does a signal to the shim (124); a writer that is not cosca is refused (122).
    pub(super) fn await_answer(&mut self, args: &ShimArgs, owner: &OwnedFd) -> Result<(), Exit> {
        let wake = self.wake().rx.as_fd();
        let ready = wait_readable([Some(owner.as_fd()), Some(wake), Some(self.conn().as_fd())])
            .map_err(|e| self.refuse_with(Refusal::NoAnswer, &format!("poll failed: {e}")))?;
        if ready[0] {
            return Err(self.refuse_with(Refusal::CoscaGone, "cosca exited before the start"));
        }
        if ready[1] {
            self.log
                .line(format_args!("a signal reached the shim before the answer"));
            return Err(self.refuse_with(Refusal::NoAnswer, "a signal reached the shim before cosca's answer"));
        }
        let received = recv_with_credentials(self.conn().as_fd())
            .map_err(|e| self.refuse_with(Refusal::NoAnswer, &format!("no answer from cosca: {e}")))?;
        let Received::Byte(byte, creds) = received else {
            self.log.line(format_args!("first byte: EOF"));
            return Err(self.refuse_with(Refusal::NoAnswer, "no answer from cosca"));
        };
        let cosca = creds.is_some_and(|c| c.pid == args.cosca_pid as i32 && c.uid == args.cosca_euid);
        if !cosca {
            return Err(self.refuse_with(Refusal::NotCosca, "the answer was not written by cosca"));
        }
        self.log
            .line(format_args!("owner pidfd confirmed by the answer's credentials"));
        self.log.line(format_args!("first byte: {}", byte as char));
        match byte {
            b'A' => Ok(()),
            b'N' => Err(self.refuse_with(Refusal::Denied, "cosca refused the start")),
            _ => Err(self.refuse_with(Refusal::NoAnswer, "no answer from cosca")),
        }
    }

    /// Whether the start must not go on: cosca has exited, or a signal has reached the shim. A failed
    /// poll is an error, so it is never taken for "nothing".
    fn why_stop(&self, owner: &OwnedFd) -> Result<Option<Stop>, Errno> {
        let polled = if self.injected(Inject::OwnerPollFails) {
            // `poll` fails with `EINVAL` when it is given more descriptors than `RLIMIT_NOFILE` allows.
            let previous = lower_nofile(0);
            let polled = readable_now([owner.as_fd(), self.wake().rx.as_fd()]);
            previous.restore();
            polled
        } else {
            readable_now([owner.as_fd(), self.wake().rx.as_fd()])
        };
        Ok(match polled? {
            [true, _] => Some(Stop::OwnerExited),
            [false, true] => Some(Stop::Signaled),
            [false, false] => None,
        })
    }

    /// Cosca's exit, or a signal to the shim, between the answer and the program's start means never
    /// start. `held` is the program's process when the clone has happened and the process is held
    /// before `exec`: it is killed and reaped first, so the program never runs.
    pub(super) fn check_owner(&self, owner: &OwnedFd, held: Option<&Spawned>) -> Result<(), Exit> {
        let stop = self.why_stop(owner);
        if !matches!(stop, Ok(None)) {
            if let Some(child) = held {
                self.gate(Gate::BeforeAbandon);
                self.abandon(child);
            }
        }
        match stop {
            Ok(None) => Ok(()),
            Ok(Some(Stop::OwnerExited)) => Err(self.refuse_with(Refusal::CoscaGone, "cosca exited before the start")),
            Ok(Some(Stop::Signaled)) => {
                self.log
                    .line(format_args!("a signal reached the shim before the start"));
                Err(self.refuse_with(Refusal::NoAnswer, "a signal reached the shim before the start"))
            }
            Err(e) => Err(self.setup_failed("cannot tell whether cosca is alive", e)),
        }
    }

    /// Kills the held process and collects it. It cannot have reached `exec`, so the program never ran.
    fn abandon(&self, child: &Spawned) {
        child.kill(&self.log);
        let status = child.reap(false, &self.log);
        self.log.line(format_args!("held child reaped status {status:?}"));
    }

    /// The re-check before the clone.
    pub(super) fn recheck_owner(&mut self, owner: &OwnedFd) -> Result<(), Exit> {
        self.check_owner(owner, None)
    }
}

/// `RLIMIT_NOFILE` before a test hook lowered its soft limit.
struct PreviousLimit(rustix::process::Rlimit);

impl PreviousLimit {
    fn restore(self) {
        let restored = rustix::process::setrlimit(rustix::process::Resource::Nofile, self.0);
        debug_assert!(restored.is_ok(), "setrlimit(NOFILE) back: {restored:?}");
    }
}

/// Lowers the soft limit to `soft`.
fn lower_nofile(soft: u64) -> PreviousLimit {
    let previous = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    let lowered = rustix::process::Rlimit {
        current: Some(soft),
        maximum: previous.maximum,
    };
    let set = rustix::process::setrlimit(rustix::process::Resource::Nofile, lowered);
    debug_assert!(set.is_ok(), "setrlimit(NOFILE) to {soft}: {set:?}");
    PreviousLimit(previous)
}

/// The lowest descriptor number that is free: a soft limit of that number lets none be made.
fn lowest_free_fd() -> u64 {
    let fd = rustix::io::dup(rustix::stdio::stdin()).expect("a descriptor to measure with");
    std::os::fd::AsRawFd::as_raw_fd(&fd) as u64
}

#[cfg(test)]
#[path = "handshake_tests.rs"]
mod handshake_tests;
