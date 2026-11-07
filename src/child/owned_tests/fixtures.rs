//! Fixtures shared by the `OwnedChild` tests.

use std::process::{ChildStdin, ExitStatus};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::child::owned::seams;
use crate::child::owned::{ChildWaitOutcome, OwnedChild};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::child::ExitRecord;
use crate::os_process::fake::FakeProcess;

// Real children =====

/// A running blocker child (see [`crate::test_child::held_std_killable_blocker`]) adopted into an
/// [`OwnedChild`], and the write end of its stdin. Closing the stdin ends the child.
pub(super) struct Blocker {
    pub(super) owned: Arc<OwnedChild>,
    pub(super) pid: u32,
    stdin: Option<ChildStdin>,
}

/// A blocker spawned under `spawn_lock`, not yet adopted.
pub(super) fn spawn_std_blocker() -> (std::process::Child, ChildStdin) {
    spawn_std_blocker_with(|_| {})
}

/// [`spawn_std_blocker`] after `configure` has adjusted its command.
pub(super) fn spawn_std_blocker_with(
    configure: impl FnOnce(&mut std::process::Command),
) -> (std::process::Child, ChildStdin) {
    let mut cmd = crate::test_child::held_std_killable_blocker();
    configure(&mut cmd);
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    (child, stdin)
}

pub(super) fn identity_of(child: &std::process::Child) -> ProcessId {
    ProcessId::of(child.id())
        .found()
        .expect("the live child has an identity")
}

impl Blocker {
    pub(super) fn spawn() -> Blocker {
        Blocker::spawn_with(|_| {})
    }

    /// [`Blocker::spawn`] with `configure` run on the command first.
    pub(super) fn spawn_with(configure: impl FnOnce(&mut std::process::Command)) -> Blocker {
        let (child, stdin) = spawn_std_blocker_with(configure);
        let id = identity_of(&child);
        let owned = OwnedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
        Blocker {
            owned: Arc::new(owned),
            pid: id.pid(),
            stdin: Some(stdin),
        }
    }

    /// End the child: close its stdin, so it reads EOF and exits.
    pub(super) fn end_child(&mut self) {
        drop(self.stdin.take());
    }

    /// End the child and wait until its exit is visible, without reaping it.
    #[cfg(not(target_os = "linux"))]
    pub(super) fn end_child_and_confirm_exit(&mut self) {
        self.end_child();
        confirm_exit(&self.owned, self.pid);
    }
}

impl Drop for Blocker {
    fn drop(&mut self) {
        // Best effort; never block a panicking test.
        drop(self.stdin.take());
        _ = self.owned.signal(crate::signal::Sig::Kill);
        if !std::thread::panicking() {
            _ = self.owned.wait(None);
        }
    }
}

/// Block until the child's exit is visible, without consuming it.
#[cfg(not(target_os = "linux"))]
pub(super) fn confirm_exit(owned: &OwnedChild, pid: u32) {
    // Windows waits on the handle, macOS reads the exit by pid.
    let _ = (owned, pid);
    #[cfg(target_os = "macos")]
    {
        // SAFETY: an all-zero `siginfo_t` is a valid value, and `waitid` writes only into it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
        assert_eq!(r, 0, "waitid(WNOWAIT): {}", std::io::Error::last_os_error());
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;

        use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};

        // SAFETY: the handle is the owned child's own, alive for the call.
        let r = unsafe { WaitForSingleObject(HANDLE(owned.os_handle().as_raw_handle()), INFINITE) };
        assert_eq!(r, WAIT_OBJECT_0);
    }
}

// Outcomes =====

/// The exit status of a wait that reaped.
#[track_caller]
pub(super) fn status(outcome: Result<ChildWaitOutcome, Error>) -> ExitStatus {
    match outcome {
        Ok(ChildWaitOutcome::Exited(ExitRecord::Status(status))) => status,
        other => panic!("expected an exit status, got {other:?}"),
    }
}

/// Block until `owned` exits, and its status.
#[track_caller]
pub(super) fn wait_status(owned: &OwnedChild) -> ExitStatus {
    status(owned.wait(None))
}

/// One look at the present moment, as `Child::try_wait` makes it.
pub(super) fn try_wait(owned: &OwnedChild) -> Result<ChildWaitOutcome, Error> {
    owned.wait(Some(crate::wait::now()))
}

/// The signal number of `status`, on macOS (the Linux tests ask `ExitStatusExt` themselves).
#[cfg(target_os = "macos")]
pub(super) fn signal_of(status: ExitStatus) -> Option<i32> {
    std::os::unix::process::ExitStatusExt::signal(&status)
}

// Hand-off checks =====

/// After the holder with `token` has returned, and before any waiter is joined: the handle must
/// not still be in that holder's `W`, every state write must have been followed at once by a
/// `notify_all`, the state must be the last write logged, and the writes must be a legal
/// sequence. On a breach the state is repaired first (`N`, and a wake), so the blocked waiters
/// return, and then the test fails: a stranded holder fails by assertion, not by a hang.
pub(super) fn assert_handed_off(owned: &OwnedChild, token: u64) {
    use crate::child::owned::{Logged, State};
    let mut lock = owned.lock();
    let stranded = matches!(lock.state, State::W { token: t } if t == token);
    // Each write and its wake are pushed together, in one critical section.
    let unnotified = lock
        .log
        .iter()
        .enumerate()
        .any(|(i, entry)| matches!(entry, Logged::Write(_)) && lock.log.get(i + 1) != Some(&Logged::Notify));
    // A write that bypassed `Inner::set` leaves the state ahead of the log.
    let unlogged = lock
        .log
        .iter()
        .rev()
        .find_map(|entry| match entry {
            Logged::Write(state) => Some(*state),
            Logged::Notify => None,
        })
        .is_some_and(|last| last != lock.state);
    // The writes must form a legal sequence from the initial `N`: a `W` never follows a `W` (a
    // direct write that took a holder's state over, whoever woke first), and nothing follows `E`.
    let mut prev = State::N;
    let mut illegal = false;
    for entry in &lock.log {
        if let Logged::Write(next) = entry {
            illegal |= !matches!(
                (prev, *next),
                (State::N, State::W { .. }) | (State::N | State::W { .. }, State::E(_)) | (State::W { .. }, State::N)
            );
            prev = *next;
        }
    }
    if stranded || unnotified || unlogged || illegal {
        let log = lock.log.clone();
        lock.set(State::N);
        owned.notify(&mut lock);
        drop(lock);
        panic!(
            "the holder {token} left the handle stranded ({stranded}), unnotified ({unnotified}), \
             with a state the log does not show ({unlogged}) or with an illegal write sequence \
             ({illegal}): {log:?}"
        );
    }
}

// Threads over a `FakeProcess` =====

/// An `OwnedChild` over `fake`, shared across threads. The test keeps `fake` (or a clone) to fire
/// its wait and to read what it was asked.
pub(super) fn owned_over(fake: &FakeProcess) -> Arc<OwnedChild> {
    Arc::new(OwnedChild::new(Box::new(fake.clone())))
}

/// A thread that is blocked on its `fake`'s wait, as a holder.
pub(super) struct ParkedHolder<T> {
    thread: JoinHandle<T>,
    fake: FakeProcess,
}

impl<T> ParkedHolder<T> {
    /// Fire the wait the holder is blocked on, and join it.
    pub(super) fn release_and_join(self) -> T {
        self.fake.wake();
        self.thread.join().expect("the holder thread must not panic")
    }

    /// Fire the wait, and join the thread, whatever became of it.
    pub(super) fn release_and_join_thread(self) -> std::thread::Result<T> {
        self.fake.wake();
        self.thread.join()
    }
}

/// Start a holder on its own thread: it runs `body` on `owned` (a `wait`, say) and blocks on the
/// wait its first look returned, which `fake` hands out and the test fires. Returns once it is
/// blocked, with the lock released, so the state is `W`.
pub(super) fn park_holder<T: Send + 'static>(
    owned: &Arc<OwnedChild>,
    fake: &FakeProcess,
    body: impl FnOnce(&OwnedChild) -> T + Send + 'static,
) -> ParkedHolder<T> {
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    let owned = Arc::clone(owned);
    let thread = std::thread::spawn(move || {
        let _blocking = crate::wait::block_probe::on_blocking(move || {
            _ = reached_tx.send(());
        });
        body(&owned)
    });
    reached_rx.recv().expect("the holder must reach its wait");
    ParkedHolder {
        thread,
        fake: fake.clone(),
    }
}

/// A blocked non-holder: a thread that arms `blocked` on its `Condvar` wait and calls `body`.
/// `recv()` on the returned receiver returns once it is inside the `Condvar`, or fails at once if
/// the thread ended without blocking (its `Sender` drops with the hook).
///
/// A waiter that wrongly becomes a holder looks at its `FakeProcess`, whose tables the test keeps
/// to the holder's looks: the call past them panics, which ends the thread.
pub(super) fn spawn_waiter<T: Send + 'static>(
    owned: &Arc<OwnedChild>,
    body: impl FnOnce(&OwnedChild) -> T + Send + 'static,
) -> (JoinHandle<T>, Receiver<()>) {
    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let owned = Arc::clone(owned);
    let thread = std::thread::spawn(move || {
        let _hook = seams::on_condvar_block(move || {
            _ = blocked_tx.send(());
        });
        body(&owned)
    });
    (thread, blocked_rx)
}
