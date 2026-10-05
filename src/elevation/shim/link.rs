//! cosca's end of the shim channel: the private directory and the listener in it, the acceptor thread
//! that answers the shim, and the one outcome the shim's frame settles.
//!
//! The link owns the acceptor thread and joins it in `Drop`; it holds no state outside itself.

use std::io;
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use rustix::io::Errno;

use super::fork_guard::{ForkGuard, Origin};
use super::private_dir::{PrivateDir, PrivateDirError};

mod acceptor;
mod outcome;
pub(crate) mod probe;
mod state;
mod sys;

use acceptor::Wake;
use probe::{LinkEvent, Probe};
use state::Shared;
#[allow(unused_imports, reason = "no caller outside the link yet")]
pub(crate) use {
    outcome::{AcceptorFailure, KillError, KillOutcome, LinkOutcome, NotOwner, NotStarted, NotStartedCause, WaitError},
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
    #[error("cannot set up the fork guard of the shim channel: {0}")]
    ForkGuard(io::Error),
    #[error(
        "the shim's socket is bound relative to its directory through /proc/self/fd, which is not usable here ({source}); TMPDIR ({}) cannot hold it on this system",
        tmpdir.display()
    )]
    ProcUnusable {
        tmpdir: std::path::PathBuf,
        source: io::Error,
    },
    #[error(
        "TMPDIR ({}) is too long: the shim's socket path would be {length} bytes, and this system allows {limit}",
        tmpdir.display()
    )]
    TmpdirTooLong {
        tmpdir: std::path::PathBuf,
        length: usize,
        limit: usize,
    },
}

pub(crate) struct ShimLink {
    shared: Arc<Shared>,
    wake: Arc<Wake>,
    acceptor: Option<JoinHandle<()>>,
    dir: Option<PrivateDir>,
    /// Tells the process that bound the link from a fork copy of it. It does no I/O, so `Drop` and
    /// every control call can use it, and it also decides whether the directory may be removed.
    owner: ForkGuard,
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
        let owner = ForkGuard::new().map_err(BindError::ForkGuard)?;
        // Before anything is created: a socket path that cannot fit `sun_path` is refused. A temp
        // directory that cannot be resolved is reported by the private directory instead.
        if let Ok(real) = std::fs::canonicalize(tmp) {
            if let Err((length, limit)) = sys::full_path_fits(&real, SOCKET_NAME) {
                return Err(BindError::TmpdirTooLong {
                    tmpdir: tmp.to_owned(),
                    length,
                    limit,
                });
            }
        }
        let dir = PrivateDir::create_unguarded(tmp)?;
        let sock_path = dir.path().join(SOCKET_NAME);
        // Any failure from here on removes what was made: the socket file, if it was bound, goes
        // before the directory.
        let fail = |dir: PrivateDir, error: BindError| {
            match std::fs::remove_file(&sock_path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => {
                    log::warn!("cannot remove the socket {}: {e}", sock_path.display());
                }
                _ => {}
            }
            // `remove` logs what it finds.
            let removed = dir.remove(Origin::Original);
            debug_assert!(removed.is_ok(), "the original may remove its directory");
            error
        };
        let io_err = |dir: &PrivateDir, source| BindError::Io {
            dir: dir.path().to_owned(),
            source,
        };
        // The socket is bound relative to the directory's descriptor where the platform allows it,
        // so that a long `TMPDIR` cannot overflow `sun_path`.
        let bind_path = match sys::socket_path(&probe, &dir, SOCKET_NAME) {
            Ok(path) => path,
            Err(source) => {
                let error = BindError::ProcUnusable {
                    tmpdir: tmp.to_owned(),
                    source,
                };
                return Err(fail(dir, error));
            }
        };
        let listener = match sys::bind_listener(&probe, &bind_path) {
            Ok(listener) => listener,
            Err(e) => {
                let error = io_err(&dir, e);
                return Err(fail(dir, error));
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
                let error = io_err(&dir, e);
                return Err(fail(dir, error));
            }
        };
        Ok(ShimLink {
            shared,
            wake,
            acceptor: Some(thread),
            dir: Some(dir),
            owner,
        })
    }

    /// The private directory, which `ShimArgs::dir` names.
    pub(crate) fn dir(&self) -> &Path {
        self.dir.as_ref().expect("the directory lives until teardown").path()
    }

    /// Only the process that bound the link controls it. A fork copy calling this is reachable, so
    /// it is an error and never an assertion.
    fn check_owner(&self) -> Result<(), NotOwner> {
        outcome::owner_check(self.owner.origin())
    }

    /// Sends `K`. The caller signals the front on [`KillOutcome::RefusedStart`].
    ///
    /// `Ok(Delivered)` means `K` reached the shim's socket, and no more: a root actor or the OOM
    /// killer can end or stop the shim between `K` and the signal. Every later observation then
    /// reports `ShimLost`, never "gone".
    pub(crate) fn kill(&self) -> Result<KillOutcome, KillError> {
        self.check_owner()?;
        self.shared.kill()
    }

    /// Blocks for the outcome. Call only after reaping the front: a still-pending start is refused
    /// here, so a late shim is answered `N`. A failure to wait leaves the outcome unset.
    pub(crate) fn wait(&self) -> Result<LinkOutcome, WaitError> {
        self.check_owner()?;
        self.shared.wait().map_err(|e| WaitError::Poll(e.into()))
    }

    /// Non-blocking `wait`: `None` until the frame is complete.
    pub(crate) fn try_wait(&self) -> Result<Option<LinkOutcome>, NotOwner> {
        self.check_owner()?;
        Ok(self.shared.settle())
    }

    /// The state and cached outcome, after one nonblocking read when `Live`. Moves nothing.
    pub(crate) fn observe(&self) -> Result<Observed, NotOwner> {
        self.check_owner()?;
        Ok(self.shared.observe())
    }

    /// `Drop`'s body. Only the process that bound the link tears it down; a fork copy has no
    /// acceptor thread to join. A copy keeps the descriptors the acceptor thread holds (listener,
    /// connection, both pipes) open until it execs or exits, since the thread that would drop them
    /// does not exist there: the accepted idle-root-shim residual.
    ///
    /// An origin that cannot be told is a contract violation, and the process may be either, so it
    /// does only what is safe in both and never uses `log`, which a copy must not touch: refuse a
    /// pending start in its own memory (`try_lock`, so it cannot hang), set its own stop flag, write
    /// the stop byte (a copy's byte is ignored by the owner's acceptor), and remove and join nothing.
    /// If it was the original, its acceptor stops and the thread handle and directory leak.
    fn release(&mut self, origin: Origin) {
        match origin {
            Origin::Original => self.teardown(),
            Origin::Copy => std::mem::forget(self.acceptor.take()),
            Origin::Unknown => {
                super::fork_guard::warn_unlogged(
                    b"cosca: cannot tell whether this process bound a shim link; stopping its acceptor only\n",
                );
                let refused = self.shared.refuse_pending_in_memory();
                self.shared.request_stop();
                let stop_written = self.write_stop().is_ok();
                self.shared
                    .probe
                    .event(|| LinkEvent::UnknownOriginHandled { refused, stop_written });
                std::mem::forget(self.acceptor.take());
            }
        }
    }

    /// Writes the stop byte. The write end is nonblocking and `stopping` is already set, so a full
    /// pipe (`EAGAIN`) means the acceptor will see the stop anyway.
    fn write_stop(&self) -> Result<(), Errno> {
        let written = match self.shared.probe.stop_write_error() {
            Some(injected) => Err(injected),
            None => sys::write_byte(self.wake.writer.as_fd()),
        };
        match written {
            Err(e) if e != Errno::AGAIN => Err(e),
            _ => Ok(()),
        }
    }

    /// Refuse a start still pending (which removes the path), stop the acceptor so its final drain
    /// answers the backlog, join it, close the connection, remove the directory.
    fn teardown(&mut self) {
        // On macOS the acceptor takes `spawn_lock` to accept, so joining it from a thread that holds
        // the lock would deadlock.
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
        self.shared.request_stop();
        if let Err(e) = self.write_stop() {
            // The stop cannot be delivered, so joining would hang: leak as an unknown origin does.
            log::error!(
                "cannot stop the acceptor for {}: {e}; leaking its thread handle and the directory",
                self.shared.sock_path.display()
            );
            std::mem::forget(self.acceptor.take());
            debug_assert!(false, "writing the stop byte failed: {e}");
            return;
        }
        if let Some(thread) = self.acceptor.take() {
            if thread.join().is_err() {
                log::warn!("the acceptor thread for {} panicked", self.shared.sock_path.display());
            }
        }
        // The thread's `Arc` is gone with it, so the connection can be closed here.
        if let Some(shared) = Arc::get_mut(&mut self.shared) {
            drop(shared.conn.take());
        }
        if let Some(dir) = self.dir.take() {
            // `remove` logs what it finds.
            let removed = dir.remove(Origin::Original);
            debug_assert!(removed.is_ok(), "the original may remove its directory");
        }
    }
}

impl Drop for ShimLink {
    fn drop(&mut self) {
        self.release(self.owner.origin());
    }
}

#[cfg(test)]
pub(crate) mod fake_shim;
#[cfg(test)]
#[path = "link_tests.rs"]
mod link_tests;
