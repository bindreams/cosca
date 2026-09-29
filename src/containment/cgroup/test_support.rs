//! Helpers the cgroup module's tests share.

/// Fork a child that runs `body` and `_exit(0)`s; `body` must be async-signal-safe (this process
/// has other threads). The child never `exec`s, so an unreaped orphan keeps this binary's
/// inherited fds (stdout) open. The returned [`KillOnDrop`] SIGKILLs and reaps it on drop unless
/// [`defused`](KillOnDrop::defuse).
///
/// Forks under [`spawn_lock`], so the never-exec child cannot inherit an fd another spawn holds
/// transiently non-`CLOEXEC` inside its own `spawn_lock` section. Held across `fork()` until the
/// parent's `pidfd_open` resolves.
#[cfg(target_os = "linux")]
pub(crate) fn fork_running(body: impl FnOnce()) -> KillOnDrop {
    let guard =
        crate::child::spawn::spawn_lock_tracked(crate::containment::cgroup::fault::run_fork_running_lock_contended);
    // Taken before the fork: the child uses this captured value, not the thread-local.
    let report_fd = crate::containment::cgroup::fault::take_fork_running_lock_held_report_fd();
    // SAFETY: the child runs only `body`, async-signal-safe by the caller's contract, then
    // `_exit`s without unwinding or running destructors.
    let raw_pid = unsafe { libc::fork() };
    match raw_pid {
        -1 => panic!("fork: {}", std::io::Error::last_os_error()),
        0 => {
            // Report whether the forked copy saw the lock held: a plain `Cell` read and a raw
            // `write(2)`, both async-signal-safe. Reading it in the child (not the parent) can't
            // be fooled by drop-before/reacquire-after the fork.
            if let Some(fd) = report_fd {
                let held: u8 = crate::child::spawn::spawn_lock_held_by_this_thread().into();
                // SAFETY: `fd` is a pipe write end a test provided for exactly this; `held` is a
                // valid one-byte buffer.
                let written = unsafe { libc::write(fd, (&raw const held).cast(), 1) };
                if written != 1 {
                    // No formatted panic (allocates) between fork and `_exit`: a distinct exit
                    // code the test reads from the reaped status.
                    // SAFETY: async-signal-safe.
                    unsafe { libc::_exit(REPORT_WRITE_FAILED_EXIT) };
                }
            }
            // Never dropped here: `MutexGuard::drop`'s unlock (an atomic swap, a `FUTEX_WAKE`
            // when contended) is not async-signal-safe, and this process's own copy of the lock
            // state dies with it regardless — only the parent's release is real.
            std::mem::forget(guard);
            body();
            // SAFETY: async-signal-safe.
            unsafe { libc::_exit(0) }
        }
        raw_pid => {
            let pid = raw_pid as u32;
            // Opened right after the fork: only our still-unreaped child can hold this pid now,
            // so the pidfd names it exactly.
            let child = rustix::process::Pid::from_raw(raw_pid).expect("fork returned a positive pid");
            let pidfd = if crate::containment::cgroup::fault::take_force_fork_running_pidfd_failure() {
                Err(rustix::io::Errno::MFILE)
            } else {
                rustix::process::pidfd_open(child, rustix::process::PidfdFlags::empty())
            };
            match pidfd {
                Ok(pidfd) => {
                    let kod = KillOnDrop {
                        pid,
                        pidfd: Some(pidfd),
                    };
                    // Run only once `kod` exists, and only then release the lock: a seam that
                    // panics still unwinds through `kod`'s `Drop`, which kills and reaps the child.
                    crate::containment::cgroup::fault::run_after_fork_still_locked();
                    drop(guard);
                    kod
                }
                Err(e) => {
                    drop(guard);
                    crate::containment::cgroup::fault::run_fork_running_cleanup();
                    // The probe pidfd lets the test verify the reap without racing pid reuse. Its
                    // failure is reported but must not skip the kill/reap.
                    let probe = if crate::containment::cgroup::fault::take_force_fork_running_probe_pidfd_failure() {
                        Err(rustix::io::Errno::MFILE)
                    } else {
                        rustix::process::pidfd_open(child, rustix::process::PidfdFlags::empty())
                    };
                    match probe {
                        Ok(probe) => crate::containment::cgroup::fault::record_fork_running_pidfd_failure_probe(probe),
                        Err(probe_err) => {
                            use std::io::Write;
                            let _ = writeln!(std::io::stderr(), "fork_running: probe pidfd_open: {probe_err}");
                        }
                    }
                    // Bare pid is safe: the child is still unreaped, so the pid can't be recycled.
                    // SAFETY: `raw_pid` is our unreaped child.
                    let killed = unsafe { libc::kill(raw_pid, libc::SIGKILL) };
                    let cleanup_err = if killed != 0 {
                        // The child may still be alive: a blocking reap here could hang forever.
                        Some(format!("kill: {}", std::io::Error::last_os_error()))
                    } else {
                        let mut status = 0;
                        let reaped = loop {
                            // SAFETY: `raw_pid` is our unreaped child.
                            let reaped = unsafe { libc::waitpid(raw_pid, &mut status, 0) };
                            if reaped == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                            {
                                continue;
                            }
                            break reaped;
                        };
                        (reaped != raw_pid).then(|| format!("waitpid: {}", std::io::Error::last_os_error()))
                    };
                    // No pre-empting assert: `e` — the reason a guard couldn't be made — is the
                    // point of this panic, and a cleanup failure is additional detail on it, not
                    // a replacement for it.
                    match cleanup_err {
                        None => panic!("pidfd_open its own just-forked child: {e}"),
                        Some(cleanup_err) => {
                            panic!("pidfd_open its own just-forked child: {e} (cleanup also failed: {cleanup_err})")
                        }
                    }
                }
            }
        }
    }
}

/// Exit code of a [`fork_running`] child whose lock-held report `write(2)` failed or was short.
#[cfg(target_os = "linux")]
pub(crate) const REPORT_WRITE_FAILED_EXIT: i32 = 113;

/// SIGKILLs and reaps a forked child on drop unless [`defuse`](Self::defuse)d. Uses a pidfd, not
/// the pid, which the kernel may recycle after a reap.
#[cfg(target_os = "linux")]
#[must_use = "dropping this immediately kills and reaps the child; bind it for as long as the child must live"]
pub(crate) struct KillOnDrop {
    pid: u32,
    pidfd: Option<std::os::fd::OwnedFd>,
}

#[cfg(target_os = "linux")]
impl KillOnDrop {
    /// The guarded pid, without disarming the guard. Don't reap through this pid: it would race
    /// the guard's `Drop`. [`defuse`](Self::defuse) first to take over.
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// Disarm the guard and return the pid; the caller must now reap it.
    #[must_use = "the pid still needs reaping by some other means; dropping it here leaks the child"]
    pub(crate) fn defuse(mut self) -> u32 {
        self.pidfd = None;
        self.pid
    }
}

#[cfg(target_os = "linux")]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        use std::io::Write;
        use std::os::fd::AsFd;

        let Some(pidfd) = self.pidfd.take() else {
            return;
        };
        let panicking = std::thread::panicking();
        // Mid-unwind a panic would abort, so failures are reported to stderr, not asserted
        // (`writeln!` because `eprintln!` panics on a closed stderr). After a failed kill, return
        // without waiting: the child may still be alive.
        let killed = if crate::containment::cgroup::fault::take_force_kill_on_drop_kill_failure() {
            Err(rustix::io::Errno::PERM)
        } else {
            rustix::process::pidfd_send_signal(pidfd.as_fd(), rustix::process::Signal::KILL)
        };
        if killed.is_err() {
            let _ = writeln!(std::io::stderr(), "KillOnDrop: pidfd_send_signal: {killed:?}");
            if !panicking {
                debug_assert!(killed.is_ok(), "pidfd_send_signal: {killed:?}");
            }
            return;
        }

        let reaped = loop {
            if crate::containment::cgroup::fault::take_force_kill_on_drop_waitid_eintr() {
                continue;
            }
            match rustix::process::waitid(
                rustix::process::WaitId::PidFd(pidfd.as_fd()),
                rustix::process::WaitIdOptions::EXITED,
            ) {
                Err(rustix::io::Errno::INTR) => continue,
                other => break other,
            }
        };
        if reaped.is_err() {
            if panicking {
                let _ = writeln!(std::io::stderr(), "KillOnDrop: waitid: {reaped:?}");
            } else {
                debug_assert!(reaped.is_ok(), "waitid: {reaped:?}");
            }
        }
    }
}

/// Reap `pid`, a child of this process.
#[cfg(target_os = "linux")]
pub(crate) fn reap(pid: u32) {
    reap_status(pid);
}

/// [`reap`], returning the raw wait status.
#[cfg(target_os = "linux")]
pub(crate) fn reap_status(pid: u32) -> i32 {
    let mut status = 0;
    // SAFETY: `pid` is this process's own child; `status` is a valid, writable int.
    let reaped = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    assert_eq!(reaped, pid as i32, "waitpid: {}", std::io::Error::last_os_error());
    status
}

/// A forked child that fails inside [`block_on`] cannot say why — no formatted panic, no
/// allocation — so this number is the only diagnostic a hang left blocked on that read gets.
#[cfg(target_os = "linux")]
const BLOCK_ON_READ_FAILED_EXIT: i32 = 111;

/// Block on `gate` until a byte arrives. Async-signal-safe: may run in a forked, pre-exec child.
#[cfg(target_os = "linux")]
pub(crate) fn block_on(gate: std::os::fd::RawFd) {
    let mut byte = 0u8;
    let n = loop {
        // SAFETY: `gate` is an open read end; `byte` is a valid one-byte buffer.
        let n = unsafe { libc::read(gate, (&raw mut byte).cast(), 1) };
        if n == -1 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // A real read failure leaves nothing to retry, and this may run pre-exec in a forked
            // child: no formatted panic (allocates), a distinct exit instead.
            // SAFETY: async-signal-safe.
            unsafe { libc::_exit(BLOCK_ON_READ_FAILED_EXIT) };
        }
        break n;
    };
    debug_assert_eq!(n, 1, "read");
}

/// A copy of `channel`'s child end, standing in for the one a forked child inherits: the parent's
/// own copy closes when the exchange ends, as it does in a real spawn.
#[cfg(target_os = "linux")]
pub(crate) fn childs_copy(
    channel: &crate::containment::cgroup::ReportChannel,
) -> (std::os::fd::OwnedFd, crate::containment::cgroup::ReportSlot) {
    use std::os::fd::{AsRawFd, BorrowedFd};

    // SAFETY: the slot's descriptor is open for as long as `channel` lives, which spans this call.
    let end = unsafe { BorrowedFd::borrow_raw(channel.slot().fd) }
        .try_clone_to_owned()
        .expect("dup the child's end");
    let slot = crate::containment::cgroup::ReportSlot {
        fd: end.as_raw_fd(),
        parent_fd: -1,
    };
    (end, slot)
}

/// Run the test `name` (its full path) alone, in a copy of this test binary, and assert it passed.
/// `true` in the copy, which runs the test's body; `false` in the caller, which returns.
///
/// For a test that closes the parent's end of a channel and needs the child to see that close: any
/// process another test forks meanwhile holds a copy of that end until its own `exec`, and keeps
/// the socket open past the close.
#[cfg(target_os = "linux")]
pub(crate) fn alone(name: &str) -> bool {
    const ALONE: &str = "COSCA_TEST_ALONE";
    if std::env::var_os(ALONE).is_some_and(|alone| alone == name) {
        return true;
    }
    let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([name, "--exact", "--include-ignored", "--nocapture", "--test-threads=1"])
        .env(ALONE, name)
        .output()
        .expect("run the test alone");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    false
}

/// A test leaf at `leaf_path` whose verdict is taken, with the child reported `Placed`: an
/// attached leaf whose `Drop` may kill.
#[cfg(target_os = "linux")]
pub(crate) fn entered_leaf_at(leaf_path: std::path::PathBuf) -> crate::containment::cgroup::CgroupLeaf {
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    // SAFETY: the slot's channel lives as long as `leaf`.
    unsafe { leaf.placement_slot().report_placed_for_test() };
    // The verdict needs a live pid: this process's own stands in for the child.
    leaf.take_placement(std::process::id())
        .expect("decidable")
        .expect("the child reported Placed");
    leaf
}

/// A temp-directory stand-in for a cgroup leaf, `<tempdir>/<name>`.
///
/// Its `cgroup.events` is a symlink to a file outside the leaf, so removing the leaf leaves that
/// file, and every fd and watch on it, untouched: as removing a real leaf neither modifies its
/// `cgroup.events` nor delivers any event on it. [`rmdir`](FakeLeaf::rmdir) answers as cgroupfs
/// does, through [`fault::set_rmdir_hook`](super::fault::set_rmdir_hook).
#[cfg(target_os = "linux")]
pub(crate) struct FakeLeaf {
    _dir: tempfile::TempDir,
    pub(crate) leaf: std::path::PathBuf,
    /// The file the leaf's `cgroup.events` resolves to.
    pub(crate) events: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl FakeLeaf {
    pub(crate) fn new(name: &str, populated: bool) -> FakeLeaf {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf = dir.path().join(name);
        std::fs::create_dir(&leaf).expect("create the leaf");
        let events = dir.path().join(format!("{name}.events"));
        std::fs::write(&events, format!("populated {}\nfrozen 0\n", u8::from(populated))).expect("write cgroup.events");
        std::os::unix::fs::symlink(&events, leaf.join("cgroup.events")).expect("link cgroup.events");
        std::fs::write(leaf.join("cgroup.kill"), b"").expect("create cgroup.kill");
        FakeLeaf {
            _dir: dir,
            leaf,
            events,
        }
    }

    /// Flip `populated` by rewriting its one digit in place: a truncating rewrite could be read
    /// half-done, as an empty file.
    pub(crate) fn set_populated(events: &std::path::Path, populated: bool) {
        use std::os::unix::fs::FileExt as _;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(events)
            .expect("open cgroup.events");
        file.write_all_at(if populated { b"1" } else { b"0" }, "populated ".len() as u64)
            .expect("flip populated");
    }

    pub(crate) fn is_populated(events: &std::path::Path) -> bool {
        let contents = std::fs::read_to_string(events).expect("read cgroup.events");
        contents.lines().any(|l| l.trim() == "populated 1")
    }

    /// What a third party's `rmdir` of the leaf does: the leaf is gone, its `cgroup.events` file
    /// is untouched.
    pub(crate) fn remove(leaf: &std::path::Path) {
        for entry in std::fs::read_dir(leaf).expect("list the leaf") {
            std::fs::remove_file(entry.expect("leaf entry").path()).expect("remove a leaf file");
        }
        std::fs::remove_dir(leaf).expect("remove the leaf");
    }

    /// cgroupfs's `rmdir`: `ENOENT` once gone, `EBUSY` while populated, else the leaf goes.
    pub(crate) fn rmdir(leaf: &std::path::Path, events: &std::path::Path) -> std::io::Result<()> {
        if !leaf.exists() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
        }
        if FakeLeaf::is_populated(events) {
            return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
        }
        FakeLeaf::remove(leaf);
        Ok(())
    }
}

/// Remove a real leaf once it drains, for a test's cleanup after a failure. Blocks on the leaf's
/// own drain watch.
#[cfg(target_os = "linux")]
pub(crate) fn remove_drained_leaf(leaf_path: &std::path::Path) {
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.to_path_buf());
    leaf.wait_drained(None).expect("wait for the drain");
    match std::fs::remove_dir(leaf_path) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        Err(e) => panic!("remove the leaf: {e}"),
    }
}

/// A real child placed in a leaf; `Drop` kills and reaps it so a panic cannot leak it or block
/// the leaf's removal. Declare it after its leaf so it drops first. Field 1 is the piped stdin,
/// held open so `cat` never exits on its own.
#[cfg(target_os = "linux")]
pub(crate) struct Member(
    pub(crate) std::process::Child,
    #[allow(dead_code)] pub(crate) std::process::ChildStdin,
);

#[cfg(target_os = "linux")]
impl Drop for Member {
    fn drop(&mut self) {
        // Already killed and reaped by the test in the common case. If std's own `Child` already
        // observed the exit (a prior `wait`/`try_wait`), `kill` checks its cached status first and
        // returns `Ok` without a syscall — `InvalidInput` never happens on that path. If the child
        // was reaped some other way instead (a foreign `waitpid`, principle 5), the syscall does
        // run, and fails with `ESRCH`. Both are "already gone"; only something outside that set is
        // the real signal/reap failure this guard exists to catch.
        if let Err(e) = self.0.kill() {
            debug_assert_eq!(
                e.raw_os_error(),
                Some(libc::ESRCH),
                "Member::drop's kill failed unexpectedly: {e}"
            );
        }
        if let Err(e) = self.0.wait() {
            debug_assert_eq!(
                e.raw_os_error(),
                Some(libc::ECHILD),
                "Member::drop's wait failed unexpectedly: {e}"
            );
        }
    }
}

/// Installs the drain-wait seams (`set_wait_site_park_notifier`, `set_drain_blocking_notifier`,
/// `set_drain_zero_remaining_notifier`), uninstalling all three on drop — panic-safe, so a panic
/// in the closure passed to [`WaitObserver::run`]/[`WaitObserver::run_with_block_sender`] still
/// leaves this thread's seams clean for whatever runs next.
#[cfg(target_os = "linux")]
struct WaitObserverGuard;

#[cfg(target_os = "linux")]
impl Drop for WaitObserverGuard {
    fn drop(&mut self) {
        crate::containment::cgroup::fault::take_wait_site_park_notifier();
        crate::containment::cgroup::fault::take_drain_blocking_notifier();
        crate::containment::cgroup::fault::take_drain_zero_remaining_notifier();
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct WaitObserver;

#[cfg(target_os = "linux")]
impl WaitObserver {
    /// Run `f` with the seams installed, and return its own result alongside what they saw: each
    /// time the wait site's own wait call returned (see `WaitSitePark`'s own doc for what that
    /// does and doesn't prove), how many times `drain_step` announced it was about to block, and
    /// how many times the zero-remaining shortcut fired.
    pub(crate) fn run<T>(
        f: impl FnOnce() -> T,
    ) -> (T, Vec<crate::containment::cgroup::fault::WaitSitePark>, usize, usize) {
        let (block_tx, block_rx) = std::sync::mpsc::channel();
        let (result, parks, zero_remainings) = Self::run_with_block_sender(block_tx, f);
        (result, parks, block_rx.try_iter().count(), zero_remainings)
    }

    /// Like `run`, but the caller supplies the `drain_blocking` sender itself — so it (or a
    /// receiver on another thread, paired with this same sender) can react to the signal while
    /// the wait is still in progress, before this call returns. The caller owns the count of
    /// whatever it receives on the matching receiver; this returns only the parks and the
    /// zero-remaining count.
    pub(crate) fn run_with_block_sender<T>(
        block_tx: std::sync::mpsc::Sender<()>,
        f: impl FnOnce() -> T,
    ) -> (T, Vec<crate::containment::cgroup::fault::WaitSitePark>, usize) {
        use crate::containment::cgroup::fault;
        let (park_tx, park_rx) = std::sync::mpsc::channel();
        let (zero_tx, zero_rx) = std::sync::mpsc::channel();
        fault::set_wait_site_park_notifier(park_tx);
        fault::set_drain_blocking_notifier(block_tx);
        fault::set_drain_zero_remaining_notifier(zero_tx);
        let _guard = WaitObserverGuard;
        let result = f();
        (result, park_rx.try_iter().collect(), zero_rx.try_iter().count())
    }
}

/// Installs `set_wait_deadline_arg_notifier` on construction, uninstalling it on drop —
/// panic-safe, same pattern as `WaitObserverGuard`. Separate from `WaitObserver` itself: this
/// seam is for the one property `WaitSitePark`'s own `deadline` field can't prove (that a
/// bounded park was armed with the caller's own requested instant, not merely returns it back
/// unread), not something every sync-wait test needs.
#[cfg(target_os = "linux")]
#[must_use]
pub(crate) struct WaitDeadlineArgGuard;

#[cfg(target_os = "linux")]
impl WaitDeadlineArgGuard {
    pub(crate) fn install() -> (Self, std::sync::mpsc::Receiver<std::time::Instant>) {
        let (tx, rx) = std::sync::mpsc::channel();
        crate::containment::cgroup::fault::set_wait_deadline_arg_notifier(tx);
        (Self, rx)
    }
}

#[cfg(target_os = "linux")]
impl Drop for WaitDeadlineArgGuard {
    fn drop(&mut self) {
        crate::containment::cgroup::fault::take_wait_deadline_arg_notifier();
    }
}

/// A bounded call concludes exactly once via the zero-remaining shortcut, and every announced
/// block must show up as a wait-site return (see `WaitSitePark`'s own doc for what that does and
/// doesn't prove — on its own, it does not prove a real park happened; pair this with a real
/// pump-batch count for that). At most one wait-site return times out (event_listener reports
/// "not woken" only at/after its deadline), and it must be last. Earlier ones may be
/// `woken: true` (cgroup.events writes don't imply a membership change). Zero is legitimate: the
/// first check may already find the deadline spent.
#[cfg(target_os = "linux")]
pub(crate) fn assert_bounded_conclusion(
    parks: &[crate::containment::cgroup::fault::WaitSitePark],
    blocks: usize,
    zero_remainings: usize,
    expected_deadline: std::time::Instant,
) {
    assert_eq!(
        zero_remainings, 1,
        "a bounded call that finds a member still alive must conclude exactly once through \
         the zero-remaining shortcut, got {zero_remainings}"
    );
    assert_eq!(
        blocks,
        parks.len(),
        "drain_step announced blocking {blocks} times, but the wait site's own wait call \
         returned {} times — every announced block must show up as a wait-site return",
        parks.len()
    );
    // Structural: elapsed time proves only "not early", not "armed with the right instant".
    assert!(
        parks.iter().all(|p| p.deadline == Some(expected_deadline)),
        "every park in a bounded call must report the caller's own requested deadline instant \
         exactly, got {parks:?}"
    );
    let timed_out = parks.iter().filter(|p| !p.woken).count();
    assert!(
        timed_out <= 1,
        "at most one park can genuinely time out before the call concludes, got {parks:?}"
    );
    if let Some(pos) = parks.iter().rposition(|p| !p.woken) {
        assert_eq!(pos, parks.len() - 1, "a timed-out park must be the last, got {parks:?}");
    }
}

#[cfg(test)]
#[path = "test_support_tests.rs"]
mod test_support_tests;
