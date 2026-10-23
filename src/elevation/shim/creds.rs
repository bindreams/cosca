//! Linux `SCM_CREDENTIALS` on the shim channel.
//!
//! The shim sets `SO_PASSCRED` on its socket and compares the credentials that arrive with the first
//! byte against argv's. cosca names them explicitly: the kernel attaches the sender's real uid
//! otherwise, and a cosca whose real uid differs from its effective uid would not be recognised. The
//! kernel lets a sender name its own real, effective or saved ids, and the pid only if it is the
//! sender's own tgid (or the sender is privileged over its pid namespace).
//!
//! Sending goes through rustix. Receiving stays on libc: rustix reads the credentials into a `UCred`,
//! whose `Pid` is non-zero, and the kernel reports pid 0 for a sender outside the receiver's pid
//! namespace, so rustix's read of it would be undefined behaviour.

use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, BorrowedFd};

/// A process's credentials as the kernel reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Creds {
    pub(crate) pid: i32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

impl Creds {
    /// cosca's own, as it names them: pid, effective uid, effective gid.
    pub(crate) fn own_effective() -> Creds {
        // SAFETY: these calls have no preconditions and cannot fail.
        unsafe {
            Creds {
                pid: libc::getpid(),
                uid: libc::geteuid(),
                gid: libc::getegid(),
            }
        }
    }
}

impl From<libc::ucred> for Creds {
    fn from(c: libc::ucred) -> Creds {
        Creds {
            pid: c.pid,
            uid: c.uid,
            gid: c.gid,
        }
    }
}

/// The room for one `SCM_CREDENTIALS` message, aligned for `cmsghdr`.
#[repr(C)]
union CmsgSpace {
    _align: libc::cmsghdr,
    bytes: [u8; 64],
}

const _: () = assert!(size_of::<CmsgSpace>() >= unsafe { libc::CMSG_SPACE(size_of::<libc::ucred>() as u32) } as usize);

/// Sends `byte`, naming `creds` as the sender's. Never raises `SIGPIPE`.
pub(crate) fn send_with_credentials(fd: BorrowedFd<'_>, byte: u8, creds: Creds) -> io::Result<()> {
    use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, UCred};
    use rustix::process::{Gid, Pid, Uid};
    let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
    // A pid of zero is not one rustix can name; no sender has one to name.
    let ucred = UCred {
        pid: Pid::from_raw(creds.pid).ok_or_else(invalid)?,
        uid: Uid::from_raw(creds.uid),
        gid: Gid::from_raw(creds.gid),
    };
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let pushed = control.push(SendAncillaryMessage::ScmCredentials(ucred));
    debug_assert!(pushed, "the buffer has room for one credentials message");
    loop {
        match sendmsg(fd, &[io::IoSlice::new(&[byte])], &mut control, SendFlags::NOSIGNAL) {
            Ok(1) => return Ok(()),
            // A one-byte send that sends nothing cannot be told from a full buffer.
            Ok(_) => return Err(io::ErrorKind::WouldBlock.into()),
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// What one `recvmsg` of a byte found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Received {
    Eof,
    /// The byte, and the credentials that came with it, if any.
    Byte(u8, Option<Creds>),
}

/// Reads one byte and its `SCM_CREDENTIALS`; the socket needs `SO_PASSCRED`. Retries `EINTR`.
pub(crate) fn recv_with_credentials(fd: BorrowedFd<'_>) -> io::Result<Received> {
    let mut data = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut data as *mut u8).cast(),
        iov_len: 1,
    };
    // SAFETY: an all-zero `msghdr` and `CmsgSpace` are valid.
    let (mut msg, mut space): (libc::msghdr, CmsgSpace) = unsafe { (zeroed(), zeroed()) };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (&mut space as *mut CmsgSpace).cast();
    msg.msg_controllen = std::mem::size_of_val(&space) as _;
    let received = loop {
        // SAFETY: `msg` and what it points to are valid for the call.
        let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 {
            break n;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    };
    if received == 0 {
        return Ok(Received::Eof);
    }
    let mut creds = None;
    // SAFETY: the kernel filled `msg_control` with well-formed headers, which the CMSG macros walk.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_CREDENTIALS
                && (*header).cmsg_len as usize >= libc::CMSG_LEN(size_of::<libc::ucred>() as u32) as usize
            {
                creds = Some(Creds::from(std::ptr::read_unaligned(
                    libc::CMSG_DATA(header).cast::<libc::ucred>(),
                )));
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }
    Ok(Received::Byte(data, creds))
}

/// `SO_PEERCRED`: the pid, euid and egid of the process that made the listener.
pub(crate) fn peer_credentials(fd: BorrowedFd<'_>) -> io::Result<Creds> {
    // SAFETY: an all-zero `ucred` is valid.
    let mut ucred: libc::ucred = unsafe { zeroed() };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `ucred` and `len` are valid for the call.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut ucred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ucred.into())
}

/// Asks the kernel to attach the sender's credentials to what this socket receives.
pub(crate) fn set_passcred(fd: BorrowedFd<'_>) -> io::Result<()> {
    rustix::net::sockopt::set_socket_passcred(fd, true).map_err(io::Error::from)
}

#[cfg(test)]
#[path = "creds_tests.rs"]
mod creds_tests;
