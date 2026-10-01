//! Fixtures shared by the `SharedChild` tests.

use std::io;
use std::process::{ChildStdin, ExitStatus};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::child::shared::seams::{self, ForcedWait};
use crate::child::shared::SharedChild;
use crate::identity::ProcessId;

/// A running blocker child (see [`crate::test_child::BLOCKER_ARGV`]) adopted into a
/// [`SharedChild`], and the write end of its stdin. Closing the stdin ends the child.
pub(super) struct Blocker {
    pub(super) shared: Arc<SharedChild>,
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
    let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
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
        let shared = SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
        Blocker {
            shared: Arc::new(shared),
            stdin: Some(stdin),
        }
    }

    /// End the child: close its stdin, so it reads EOF and exits.
    pub(super) fn end_child(&mut self) {
        drop(self.stdin.take());
    }

    /// End the child and wait until its exit is visible, without reaping it.
    pub(super) fn end_child_and_confirm_exit(&mut self) {
        self.end_child();
        confirm_exit(&self.shared);
    }
}

impl Drop for Blocker {
    fn drop(&mut self) {
        // Best effort; never block a panicking test.
        drop(self.stdin.take());
        if std::thread::panicking() {
            _ = self.shared.kill();
        } else {
            _ = self.shared.kill();
            _ = self.shared.wait();
        }
    }
}

/// Block until the child's exit is visible, without consuming it.
pub(super) fn confirm_exit(shared: &SharedChild) {
    #[cfg(target_os = "linux")]
    {
        let target = shared.target().expect("a pidfd");
        let peeked = crate::wait::exit_only::wait_visible_exit(&target, shared.id()).expect("wait for the exit");
        assert!(
            matches!(peeked, crate::wait::exit_only::Peek::Exit(_)),
            "the exit must be visible, got {peeked:?}"
        );
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: an all-zero `siginfo_t` is a valid value, and `waitid` writes only into it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::waitid(
                libc::P_PID,
                shared.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(r, 0, "waitid(WNOWAIT): {}", io::Error::last_os_error());
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;

        use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};

        // SAFETY: the handle is the shared child's own, alive for the call.
        let r = unsafe { WaitForSingleObject(HANDLE(shared.handle.as_raw_handle()), INFINITE) };
        assert_eq!(r, WAIT_OBJECT_0);
    }
}

// Adoption of a child that is gone =====

/// Whether `e` is `ECHILD`.
#[cfg(target_os = "linux")]
fn is_echild(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ECHILD)
}

/// Block until `child`'s exit is visible, without consuming it.
#[cfg(target_os = "linux")]
fn confirm_exit_of(child: &std::process::Child) {
    // SAFETY: an all-zero `siginfo_t` is a valid value, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT,
        )
    };
    assert_eq!(r, 0, "waitid(WNOWAIT): {}", io::Error::last_os_error());
}

/// Adopt a child under the force `arm` installs, and expect the gone path: every wait answers
/// `ECHILD`, and `kill` succeeds without sending. The child has already exited (and is not yet reaped) when it is adopted, so a force
/// that is not applied leaves a handle whose methods answer at once with a status, and the
/// assertions fail instead of blocking on a live child.
#[cfg(target_os = "linux")]
pub(super) fn assert_adoption_is_gone<G>(arm: impl FnOnce() -> G) {
    let (child, stdin) = spawn_std_blocker();
    let pid = child.id();
    let id = identity_of(&child);
    drop(stdin);
    confirm_exit_of(&child);
    let forced = arm();
    let shared = SharedChild::adopt(child, id).expect("a gone answer is not a failure");
    drop(forced);
    let far = std::time::Instant::now() + std::time::Duration::from_secs(3600);
    assert!(is_echild(&shared.wait().expect_err("wait")));
    assert!(is_echild(&shared.try_wait().expect_err("try_wait")));
    assert!(is_echild(&shared.wait_deadline(far).expect_err("wait_deadline")));
    let log = crate::send_log::Capture::start();
    shared
        .kill()
        .expect("a child that was gone at adoption is already dead: success");
    assert_eq!(log.entries(), [], "nothing is sent without a pidfd");
    drop(log);
    // The force was synthetic: the child is still this test's own, unreaped.
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer.
    let r = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    assert_eq!(r, pid as i32, "reap the fixture: {}", io::Error::last_os_error());
}

// Hand-off checks =====

/// After the holder with `token` has returned, and before any waiter is joined: the handle must
/// not still be in that holder's `W`, every state write must have been followed at once by a
/// `notify_all`, the state must be the last write logged, and the writes must be a legal
/// sequence. On a breach the state is repaired first (`N`, and a wake), so the blocked waiters
/// return, and then the test fails: a stranded holder fails by assertion, not by a hang.
pub(super) fn assert_handed_off(shared: &SharedChild, token: u64) {
    use crate::child::shared::{Logged, State};
    let mut lock = shared.lock();
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
        shared.notify(&mut lock);
        drop(lock);
        panic!(
            "the holder {token} left the handle stranded ({stranded}), unnotified ({unnotified}), \
             with a state the log does not show ({unlogged}) or with an illegal write sequence \
             ({illegal}): {log:?}"
        );
    }
}

// Threads =====

/// A thread that parked in its holder's unlocked wait, and the ends that drive it.
pub(super) struct ParkedHolder {
    pub(super) thread: JoinHandle<io::Result<Option<ExitStatus>>>,
    release: Sender<()>,
}

impl ParkedHolder {
    /// Release the holder into its platform wait, and join it.
    pub(super) fn release_and_join(self) -> io::Result<Option<ExitStatus>> {
        drop(self.release);
        self.thread.join().expect("the holder thread must not panic")
    }

    /// Release the holder into its platform wait, and join it, whatever became of the thread.
    pub(super) fn release_and_join_thread(self) -> std::thread::Result<io::Result<Option<ExitStatus>>> {
        drop(self.release);
        self.thread.join()
    }
}

/// Start a holder on its own thread: it calls `wait` (or `wait_deadline` for `Some`) and parks
/// inside the unlocked wait, with `arm` run first on that thread (it returns the guards to keep). Returns once it is parked, so
/// the state is `W`.
pub(super) fn park_holder<G>(
    shared: &Arc<SharedChild>,
    deadline: Option<std::time::Instant>,
    arm: impl FnOnce() -> G + Send + 'static,
) -> ParkedHolder {
    let (gate, reached, release) = seams::park_gate();
    let shared = Arc::clone(shared);
    let thread = std::thread::spawn(move || {
        let _armed = arm();
        let _park = seams::park_in_unlocked_wait(gate);
        match deadline {
            None => shared.wait().map(Some),
            Some(d) => shared.wait_deadline(d),
        }
    });
    reached.recv().expect("the holder must reach its unlocked wait");
    ParkedHolder { thread, release }
}

/// A blocked non-holder: a thread that arms `blocked` on its `Condvar` wait and calls `body`.
/// `recv()` on the returned receiver returns once it is inside the `Condvar`, or fails at once if
/// the thread ended without blocking (its `Sender` drops with the hook).
///
/// With `must_not_hold`, a waiter that wrongly becomes a holder fails fast instead of blocking in
/// the platform wait: its unlocked wait panics, which ends the thread and drops the hook's
/// `Sender`. A waiter that is meant to take over as holder passes `false`.
pub(super) fn spawn_waiter<T: Send + 'static>(
    shared: &Arc<SharedChild>,
    must_not_hold: bool,
    body: impl FnOnce(&SharedChild) -> T + Send + 'static,
) -> (JoinHandle<T>, Receiver<()>) {
    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let shared = Arc::clone(shared);
    let thread = std::thread::spawn(move || {
        let _hook = seams::on_condvar_block(move || {
            _ = blocked_tx.send(());
        });
        let _forced = must_not_hold.then(|| seams::force_unlocked_wait(ForcedWait::Panic));
        body(&shared)
    });
    (thread, blocked_rx)
}

/// The signal number of `status`, on Unix.
#[cfg(unix)]
pub(super) fn signal_of(status: ExitStatus) -> Option<i32> {
    std::os::unix::process::ExitStatusExt::signal(&status)
}
