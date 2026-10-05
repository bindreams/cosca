//! cosca's end of the shim channel (D4, D5, D7, D14, D20, D21, D23): the private directory and the
//! listener in it, the acceptor thread that answers the shim, and the one outcome the shim's frame
//! settles.
//!
//! The link owns the acceptor thread and joins it in `Drop`; it holds no state outside itself.

use std::io;
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use rustix::io::Errno;

use super::private_dir::{PrivateDir, PrivateDirError};
use crate::identity::ProcessId;

mod acceptor;
mod outcome;
pub(crate) mod probe;
mod state;
mod sys;

use acceptor::Wake;
use probe::Probe;
use state::Shared;
#[allow(unused_imports, reason = "no caller outside the link yet")]
pub(crate) use {
    outcome::{AcceptorFailure, KillError, KillOutcome, LinkOutcome, NotOwner, NotStarted, NotStartedCause},
    state::{Observed, StartState},
};

/// The listener's name inside the private directory.
pub(crate) const SOCKET_NAME: &str = "s";

#[derive(Debug, thiserror::Error)]
pub(crate) enum BindError {
    #[error(transparent)]
    Dir(#[from] PrivateDirError),
    #[error("cannot set up the shim channel in {}: {source}", dir.display())]
    Io { dir: std::path::PathBuf, source: io::Error },
}

pub(crate) struct ShimLink {
    shared: Arc<Shared>,
    wake: Arc<Wake>,
    acceptor: Option<JoinHandle<()>>,
    dir: Option<PrivateDir>,
    /// The pid that bound the link (D21).
    owner: ProcessId,
}

impl ShimLink {
    /// In [`std::env::temp_dir`], for a shim running as `peer_euid` (root, in production).
    pub(crate) fn bind(peer_euid: u32) -> Result<Self, BindError> {
        Self::bind_in(&std::env::temp_dir(), peer_euid)
    }

    pub(crate) fn bind_in(tmp: &Path, peer_euid: u32) -> Result<Self, BindError> {
        Self::bind_probed(tmp, peer_euid, Probe::none())
    }

    pub(crate) fn bind_probed(tmp: &Path, peer_euid: u32, probe: Probe) -> Result<Self, BindError> {
        let dir = PrivateDir::create_in(tmp)?;
        let io_err = |source| BindError::Io {
            dir: dir.path().to_owned(),
            source,
        };
        let sock_path = dir.path().join(SOCKET_NAME);
        // The socket file may exist even if setting the listener up failed, and must go before the
        // directory does.
        let remove_socket = || match std::fs::remove_file(&sock_path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                log::warn!("cannot remove the socket {}: {e}", sock_path.display());
            }
            _ => {}
        };
        let listener = match sys::bind_listener(&probe, &sock_path) {
            Ok(listener) => listener,
            Err(e) => {
                remove_socket();
                return Err(io_err(e));
            }
        };
        let started = (|| {
            let (reader, writer) = sys::pipe(&probe)?;
            let wake = Arc::new(Wake { reader, writer });
            let settled = sys::pipe(&probe)?;
            let shared = Arc::new(Shared::new(sock_path.clone(), peer_euid, probe.clone(), settled));
            let thread = {
                let (shared, wake) = (shared.clone(), wake.clone());
                std::thread::Builder::new()
                    .name("cosca-shim-acceptor".into())
                    .spawn(move || acceptor::run(shared, listener, wake))?
            };
            Ok::<_, io::Error>((shared, wake, thread))
        })();
        let (shared, wake, thread) = match started {
            Ok(parts) => parts,
            Err(e) => {
                remove_socket();
                return Err(io_err(e));
            }
        };
        Ok(ShimLink {
            shared,
            wake,
            acceptor: Some(thread),
            dir: Some(dir),
            owner: ProcessId::current(),
        })
    }

    /// The private directory: `ShimArgs::dir`.
    pub(crate) fn dir(&self) -> &Path {
        self.dir.as_ref().expect("the directory lives until teardown").path()
    }

    fn check_owner(&self) -> Result<(), NotOwner> {
        let checked = outcome::owner_check(self.owner, ProcessId::current());
        debug_assert!(checked.is_ok(), "a fork copy of a ShimLink was used to control it");
        checked
    }

    /// D5, the channel side. The caller signals the front on [`KillOutcome::RefusedStart`].
    ///
    /// `Ok(Delivered)` means `K` reached the shim's socket, and no more: a root actor or the OOM
    /// killer can end or stop the shim between `K` and the signal. Every later observation then
    /// reports `ShimLost`, never "gone".
    pub(crate) fn kill(&self) -> Result<KillOutcome, KillError> {
        self.check_owner().map_err(|NotOwner| KillError::NotOwner)?;
        self.shared.kill()
    }

    /// The outcome, once the caller has reaped the front (D7). Blocks until it is settled. A start
    /// still pending is refused first, so the front must be gone: a late shim would be answered `N`.
    pub(crate) fn wait(&self) -> Result<LinkOutcome, NotOwner> {
        self.check_owner()?;
        Ok(self.shared.wait())
    }

    /// [`wait`](Self::wait) without blocking: `None` while the frame is incomplete. The same caveat
    /// applies.
    pub(crate) fn try_wait(&self) -> Result<Option<LinkOutcome>, NotOwner> {
        self.check_owner()?;
        Ok(self.shared.settle())
    }

    /// The state and cached outcome, after one nonblocking read when `Live`. Moves nothing (D7a).
    pub(crate) fn observe(&self) -> Result<Observed, NotOwner> {
        self.check_owner()?;
        Ok(self.shared.observe())
    }

    /// `Drop`'s body, for `who` as the current process. Only the process that bound the link tears
    /// it down. The stop byte, the path and the directory are the owner's (D21), and a fork copy has
    /// no acceptor thread to join.
    ///
    /// A copy drops what it owns, but not what the acceptor thread holds: the listener, the
    /// connection and the wake pipe are kept alive by `Arc`s that the thread, which does not exist
    /// in the copy, never drops. They stay open in the copy until it execs or exits. A shim that
    /// reached the copy's connection copy would see the same as an idle one (the owner's accepted
    /// idle-root-shim residual); closing them by hand would need raw closes of descriptors the
    /// owner still uses.
    fn release(&mut self, who: ProcessId) {
        if outcome::owner_check(self.owner, who).is_err() {
            std::mem::forget(self.acceptor.take());
            return;
        }
        self.teardown();
    }

    /// D14's order: refuse a start still pending (which removes the path), stop the acceptor so its
    /// final drain answers the backlog, join it, close the connection, remove the directory.
    fn teardown(&mut self) {
        // On macOS the acceptor takes `spawn_lock` to accept (D23), so joining it from a thread that
        // holds the lock would deadlock.
        #[cfg(all(target_os = "macos", any(test, debug_assertions)))]
        debug_assert!(
            !crate::child::spawn::spawn_lock_held_by_this_thread(),
            "a ShimLink must not be dropped while holding spawn_lock"
        );
        {
            let mut inner = self.shared.lock();
            self.shared.refuse_pending(&mut inner);
        }
        self.shared.probe.release();
        let stopped = loop {
            match rustix::io::write(self.wake.writer.as_fd(), &[1]) {
                Err(Errno::INTR) => continue,
                other => break other,
            }
        };
        match (stopped, self.acceptor.take()) {
            (Ok(_), Some(thread)) => {
                if thread.join().is_err() {
                    log::warn!("the acceptor thread for {} panicked", self.shared.sock_path.display());
                }
            }
            (Err(e), thread) => {
                log::error!(
                    "cannot stop the acceptor for {}: {e}; its thread is left running",
                    self.shared.sock_path.display()
                );
                drop(thread);
            }
            (Ok(_), None) => {}
        }
        // The thread's `Arc` is gone with it, so the connection can be closed here.
        if let Some(shared) = Arc::get_mut(&mut self.shared) {
            drop(shared.conn.take());
        }
        if let Some(dir) = self.dir.take() {
            // `remove` logs what it finds.
            dir.remove();
        }
    }
}

impl Drop for ShimLink {
    fn drop(&mut self) {
        self.release(ProcessId::current());
    }
}

#[cfg(test)]
pub(crate) mod fake_shim;
#[cfg(test)]
#[path = "link_tests.rs"]
mod link_tests;
