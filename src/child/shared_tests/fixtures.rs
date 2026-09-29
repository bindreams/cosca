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
    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn the blocker");
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
        let (child, stdin) = spawn_std_blocker();
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
        let peeked = crate::wait::exit_only::wait_visible_exit(&target).expect("wait for the exit");
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
