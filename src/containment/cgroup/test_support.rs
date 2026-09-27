//! Helpers the cgroup module's tests share.

/// Fork a child that runs `body` and exits with `_exit(0)`. `body` must be async-signal-safe:
/// this process has other threads.
///
/// `body` never `exec`s, so the child inherits every fd this process has open, and, unless it's
/// signal-killed, never exits until `body` returns on its own. Many callers gate that return on a
/// write only they send later (`block_on`/a pipe), so a panic anywhere between the fork and that
/// write would otherwise leave the child running and unreaped: an orphan holding inherited fds
/// hangs any reader of this binary's stdout to EOF (`cargo test | cat`, a wrapping `.output()`).
/// Under `cargo nextest` (what CI runs), the same leak is reported as `LEAK`, not a hang.
///
/// The returned [`KillOnDrop`] guards against exactly that: it SIGKILLs and reaps the child on
/// drop unless [`defused`](KillOnDrop::defuse), so a panic anywhere in the caller cleans it up
/// during unwind.
#[cfg(target_os = "linux")]
#[must_use = "dropping this immediately kills and reaps the child; bind it for as long as the child must live"]
pub(crate) fn fork_running(body: impl FnOnce()) -> KillOnDrop {
    // SAFETY: the child runs only `body`, async-signal-safe by the caller's contract, then
    // `_exit`s without unwinding or running destructors.
    match unsafe { libc::fork() } {
        -1 => panic!("fork: {}", std::io::Error::last_os_error()),
        0 => {
            body();
            // SAFETY: async-signal-safe.
            unsafe { libc::_exit(0) }
        }
        raw_pid => {
            let pid = raw_pid as u32;
            // Race-free: opened immediately after the fork, while the child is guaranteed still
            // unreaped under this exact pid. `pidfd_open` binds to whatever process holds the
            // number at the call moment, and only an unreaped child can hold it here — the same
            // approach `leaf.rs`'s `end_child` uses to name a child it must not mistarget.
            let child = rustix::process::Pid::from_raw(raw_pid).expect("fork returned a positive pid");
            let pidfd = if crate::containment::cgroup::fault::take_force_fork_running_pidfd_failure() {
                Err(rustix::io::Errno::MFILE)
            } else {
                rustix::process::pidfd_open(child, rustix::process::PidfdFlags::empty())
            };
            match pidfd {
                Ok(pidfd) => KillOnDrop {
                    pid,
                    pidfd: Some(pidfd),
                },
                Err(e) => {
                    // No `KillOnDrop` exists yet to protect this child, and none can: a pidfd is
                    // exactly what failed to open. It is still unreaped and this process's only
                    // child under this number, so the bare pid is safe here, this one time,
                    // before anything else could reap or recycle it.
                    //
                    // A test's own probe, opened independently on the same child before it dies,
                    // lets a test confirm this without racing that same reuse window itself.
                    if let Ok(probe) = rustix::process::pidfd_open(child, rustix::process::PidfdFlags::empty()) {
                        crate::containment::cgroup::fault::record_fork_running_pidfd_failure_probe(probe);
                    }
                    // SAFETY: `raw_pid` is this process's own child, forked immediately above.
                    unsafe { libc::kill(raw_pid, libc::SIGKILL) };
                    let mut status = 0;
                    // SAFETY: as above.
                    unsafe { libc::waitpid(raw_pid, &mut status, 0) };
                    panic!("pidfd_open its own just-forked child: {e}");
                }
            }
        }
    }
}

/// SIGKILLs and reaps a not-yet-reaped child on drop, unless [`defuse`](Self::defuse)d.
///
/// Named by a pidfd opened right after the fork, not by the bare pid number: the kernel may
/// recycle that number onto an unrelated process once this one is reaped, and a stale-number kill
/// or reap would then hit the wrong process. Signalling or reaping through the pidfd instead
/// always targets the exact process it was opened on, however the number gets reused after.
#[cfg(target_os = "linux")]
#[must_use = "dropping this immediately kills and reaps the child; bind it for as long as the child must live"]
pub(crate) struct KillOnDrop {
    pid: u32,
    pidfd: Option<std::os::fd::OwnedFd>,
}

#[cfg(target_os = "linux")]
impl KillOnDrop {
    /// The guarded pid, without disarming the guard.
    ///
    /// Callers must not reap through this number: only this guard's own pidfd may reap the child
    /// it names, so an independent `waitpid`/`reap(pid)` on the bare number would race this
    /// guard's `Drop` over the same exit status. Disarm first with
    /// [`defuse`](Self::defuse) if the caller needs to take over.
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// Disarm the guard and hand the pid back: its `Drop` no longer kills or reaps, so the caller
    /// takes over that responsibility, by whatever means it needs (its own pidfd, `waitpid`, ...).
    #[must_use = "the pid still needs reaping by some other means; dropping it here leaks the child"]
    pub(crate) fn defuse(mut self) -> u32 {
        self.pidfd = None;
        self.pid
    }
}

#[cfg(target_os = "linux")]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        use std::os::fd::AsFd;

        let Some(pidfd) = self.pidfd.take() else {
            return;
        };
        let killed = rustix::process::pidfd_send_signal(pidfd.as_fd(), rustix::process::Signal::KILL);
        let reaped = rustix::process::waitid(
            rustix::process::WaitId::PidFd(pidfd.as_fd()),
            rustix::process::WaitIdOptions::EXITED,
        );
        if std::thread::panicking() {
            // Already unwinding a panic: asserting here would abort instead of completing that
            // unwind, so this is surfaced, not asserted.
            eprintln!("KillOnDrop: pidfd_send_signal: {killed:?}, waitid: {reaped:?}");
        } else {
            debug_assert!(killed.is_ok(), "pidfd_send_signal: {killed:?}");
            debug_assert!(reaped.is_ok(), "waitid: {reaped:?}");
        }
    }
}

/// Reap `pid`, a child of this process.
#[cfg(target_os = "linux")]
pub(crate) fn reap(pid: u32) {
    let mut status = 0;
    // SAFETY: `pid` is this process's own child; `status` is a valid, writable int.
    let reaped = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    assert_eq!(reaped, pid as i32, "waitpid: {}", std::io::Error::last_os_error());
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

#[cfg(test)]
#[path = "test_support_tests.rs"]
mod test_support_tests;
