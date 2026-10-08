//! Collecting the child's status through its pidfd (plan F, D3).

use rustix::process::{waitid, WaitId, WaitIdOptions, WaitIdStatus};

use super::child::Spawned;

/// A wait status in the layout `waitpid` gives: `code << 8` for an exit, the signal for a kill, with
/// `0x80` added for a core dump.
fn wait_status(status: &WaitIdStatus) -> Option<i32> {
    if let Some(code) = status.exit_status() {
        Some((code & 0xff) << 8)
    } else {
        status
            .terminating_signal()
            .map(|signal| signal | if status.dumped() { 0x80 } else { 0 })
    }
}

impl Spawned {
    /// The wait status, or `None` when someone else collected it.
    ///
    /// `ready` is true when the pidfd has fired, so the child has exited and the first call does not
    /// block. If the zombie is still invisible, because another process traces the child and only
    /// that tracer can see it until it collects it, the call then blocks until the kernel hands the
    /// status on: the program is already dead, so nothing is left to control. Only `ECHILD`, someone
    /// else having reaped it, is a lost status. If the tracer never collects, this waits, as a plain
    /// parent's `waitpid` would.
    pub(in crate::elevation::shim) fn reap(&self, ready: bool, log: &super::log::Log) -> Option<i32> {
        let mut options = WaitIdOptions::EXITED;
        if ready {
            options |= WaitIdOptions::NOHANG;
        }
        match wait_on(self, options) {
            Wait::Status(status) => return Some(status),
            Wait::Gone => return None,
            Wait::NotYet => {}
        }
        log.line(format_args!(
            "exited, but only its tracer can see it yet: waiting for its status"
        ));
        // The one deliberate blocking call after the loop's poll: see above.
        match wait_on(self, WaitIdOptions::EXITED) {
            Wait::Status(status) => Some(status),
            Wait::Gone | Wait::NotYet => None,
        }
    }
}

enum Wait {
    Status(i32),
    Gone,
    /// `WNOHANG` and nothing to collect yet.
    NotYet,
}

fn wait_on(child: &Spawned, options: WaitIdOptions) -> Wait {
    loop {
        return match waitid(WaitId::PidFd(child.pidfd.as_fd()), options) {
            Ok(Some(status)) => wait_status(&status).map_or(Wait::Gone, Wait::Status),
            Ok(None) => Wait::NotYet,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => Wait::Gone,
        };
    }
}

use std::os::fd::AsFd;
