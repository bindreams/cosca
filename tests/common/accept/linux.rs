//! Linux backend of the death-watched accept: `poll` over the source and one `pidfd` per pid.

use std::os::fd::{AsRawFd, OwnedFd};

use cosca::identity::{Existence, ProcessId};

use super::{notify_armed, Source, WatchEvent};

fn open(pid: u32) -> Result<OwnedFd, rustix::io::Errno> {
    let raw = rustix::process::Pid::from_raw(pid as i32).expect("a watched pid is never 0");
    rustix::process::pidfd_open(raw, rustix::process::PidfdFlags::empty())
}

pub(super) fn wait(source: Source<'_>, target_pid: u32, also: Option<ProcessId>) -> WatchEvent {
    // An unreaped zombie still opens, and the caller just saw the target unreaped (see the
    // module doc), so ESRCH here would mean somebody else reaped it: a contract violation.
    let target_fd = open(target_pid).unwrap_or_else(|e| {
        panic!(
            "pidfd_open({target_pid}) for the death-watch: {} (the target must be an unreaped child)",
            std::io::Error::from(e)
        )
    });
    let mut watched = vec![(target_pid, target_fd)];
    if let Some(id) = also {
        let pid = id.pid();
        match open(pid) {
            // The pidfd is only ever the descendant's if its identity still resolves after the
            // open; a reissued pid does not, and is reported as the descendant being gone.
            Ok(fd) => match id.exists() {
                Existence::Present => watched.push((pid, fd)),
                Existence::Gone => return WatchEvent::Died(pid),
                Existence::Unknown => panic!("the OS refused to confirm the identity of pid {pid} for the death-watch"),
            },
            // Reaped (a descendant whose parent is gone is reaped by init): dead.
            Err(rustix::io::Errno::SRCH) => return WatchEvent::Died(pid),
            Err(e) => panic!("pidfd_open({pid}) for the death-watch: {}", std::io::Error::from(e)),
        }
    }

    let source_fd = match source {
        Source::Listener(l) => l.as_raw_fd(),
        Source::Stream(s) => s.as_raw_fd(),
    };
    let mut fds = vec![libc::pollfd {
        fd: source_fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    fds.extend(watched.iter().map(|(_, fd)| libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }));
    notify_armed();
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
        // POLLNVAL would mean this function handed poll() a bad fd, a contract it owns end to
        // end, so a violation is a bug here, not a runtime condition.
        for f in &fds {
            debug_assert_eq!(f.revents & libc::POLLNVAL, 0, "a polled fd went invalid mid-wait");
        }
        // An error on a LISTENER is a real, externally-caused condition, surfaced in every build.
        // (A stream reports HUP at EOF, which is a readable event, not an error.)
        if matches!(source, Source::Listener(_)) && fds[0].revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            panic!(
                "the control listener reported an error while waiting for a connection (revents={:#x})",
                fds[0].revents
            );
        }
        // Exits are checked BEFORE the source on purpose: routing every exit through one verdict
        // gives one path to reason about, and a ready source alongside an exit belongs to a
        // target that broke the accept handshake (see the module doc of `accept`).
        for (i, (pid, _)) in watched.iter().enumerate() {
            if fds[i + 1].revents & libc::POLLIN != 0 {
                return WatchEvent::Died(*pid);
            }
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            return WatchEvent::Ready;
        }
    }
}
