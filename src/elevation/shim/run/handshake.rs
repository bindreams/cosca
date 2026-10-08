//! Everything before the program starts (plan F, D2, D22): the connection, who cosca is, the owner
//! watch, hello, and the answer.
//!
//! Nothing is written until the listener is verified and the owner watch is open. A refusal before
//! hello writes nothing, so cosca, which answers a connection only after hello, never sees it, and
//! the outcome there is always "not started, shim not connected".

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use rustix::fs::{open, Mode, OFlags};
use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use super::{Exit, Shim};
use crate::elevation::shim::codes;
use crate::elevation::shim::creds::{peer_credentials, recv_with_credentials, set_passcred, Received};
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

/// Blocks until `fd` is readable or hung up, retrying `EINTR`. One of the shim's deliberate
/// blocking calls: the wait for cosca's answer.
fn wait_any(fds: &[RawFd]) -> io::Result<Vec<bool>> {
    let mut polled: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    loop {
        // SAFETY: `polled` is valid for its length.
        if unsafe { libc::poll(polled.as_mut_ptr(), polled.len() as _, -1) } >= 0 {
            return Ok(polled.iter().map(|p| p.revents != 0).collect());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Whether `fd` is readable right now.
fn readable_now(fd: RawFd) -> bool {
    let mut p = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    // SAFETY: `p` is valid for its length.
    unsafe { libc::poll(p.as_mut_ptr(), 1, 0) > 0 }
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
        let path = format!("/proc/thread-self/fd/{}/{SOCKET_NAME}", dir.as_raw_fd());
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
    /// this open and the pidfd names it (D2).
    pub(super) fn watch_owner(&mut self, args: &ShimArgs) -> Result<OwnedFd, Exit> {
        let lowered = self.hooks.is_some_and(|h| h.exhaust_fds()).then(lower_nofile);
        // SAFETY: `pidfd_open(pid, 0)` has no pointer arguments.
        let opened = unsafe { libc::syscall(libc::SYS_pidfd_open, args.cosca_pid as libc::pid_t, 0) };
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        if let Some(previous) = lowered {
            previous.restore();
        }
        if opened < 0 {
            let failure = OwnerPidfdFailure::from_errno(errno);
            self.log
                .line(format_args!("pidfd_open(owner): errno {errno} ({failure:?})"));
            let why = match failure {
                OwnerPidfdFailure::CoscaGone => "cosca's process is gone",
                OwnerPidfdFailure::Unwatchable => "could not watch cosca's process",
            };
            return Err(self.refuse(failure.exit_code(), why));
        }
        self.log.line(format_args!("owner verified pid={}", args.cosca_pid));
        // SAFETY: `pidfd_open` made this descriptor, and nothing else owns it.
        Ok(unsafe { OwnedFd::from_raw_fd(opened as RawFd) })
    }

    pub(super) fn say_hello(&mut self) -> Result<(), Exit> {
        send_all(self.conn().as_fd(), &Frame::Hello.encode())
            .map_err(|e| self.refuse(codes::NO_ANSWER, &format!("could not say hello: {e}")))?;
        self.hello_sent = true;
        self.log.line(format_args!("hello sent; awaiting the answer"));
        Ok(())
    }

    /// Waits for the first byte: `A` or `N`, written by cosca. cosca's exit ends the wait (123); a
    /// writer that is not cosca is refused (122).
    pub(super) fn await_answer(&mut self, args: &ShimArgs, owner: &OwnedFd) -> Result<(), Exit> {
        let ready = wait_any(&[owner.as_raw_fd(), self.conn().as_raw_fd()])
            .map_err(|e| self.refuse(codes::NO_ANSWER, &format!("poll failed: {e}")))?;
        if ready[0] {
            return Err(self.refuse(Refusal::CoscaGone as i32, "cosca exited before the start"));
        }
        let received = recv_with_credentials(self.conn().as_fd())
            .map_err(|e| self.refuse(Refusal::NoAnswer as i32, &format!("no answer from cosca: {e}")))?;
        let Received::Byte(byte, creds) = received else {
            self.log.line(format_args!("first byte: EOF"));
            return Err(self.refuse(Refusal::NoAnswer as i32, "no answer from cosca"));
        };
        let cosca = creds.is_some_and(|c| c.pid == args.cosca_pid as i32 && c.uid == args.cosca_euid);
        if !cosca {
            return Err(self.refuse(Refusal::NotCosca as i32, "the answer was not written by cosca"));
        }
        self.log
            .line(format_args!("owner pidfd confirmed by the answer's credentials"));
        self.log.line(format_args!("first byte: {}", byte as char));
        match byte {
            b'A' => Ok(()),
            b'N' => Err(self.refuse(Refusal::Denied as i32, "cosca refused the start")),
            _ => Err(self.refuse(Refusal::NoAnswer as i32, "no answer from cosca")),
        }
    }

    /// Cosca's exit between the answer and the clone means never start (D22).
    pub(super) fn recheck_owner(&mut self, owner: &OwnedFd) -> Result<(), Exit> {
        if readable_now(owner.as_raw_fd()) {
            return Err(self.refuse(Refusal::CoscaGone as i32, "cosca exited before the start"));
        }
        Ok(())
    }
}

/// `RLIMIT_NOFILE`'s soft limit before a test hook lowered it.
struct PreviousLimit(libc::rlimit);

impl PreviousLimit {
    fn restore(self) {
        // SAFETY: `self.0` is a valid `rlimit`.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) };
    }
}

/// Lowers the soft limit to the lowest free descriptor number, so that none can be made.
fn lower_nofile() -> PreviousLimit {
    // SAFETY: an all-zero `rlimit` is a valid out-parameter.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: `limit` is valid for the call.
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    let previous = PreviousLimit(limit);
    // SAFETY: `dup` and `close` of a standard descriptor.
    let lowest_free = unsafe {
        let fd = libc::dup(0);
        libc::close(fd);
        fd
    };
    limit.rlim_cur = lowest_free as libc::rlim_t;
    // SAFETY: `limit` is valid for the call.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    previous
}
