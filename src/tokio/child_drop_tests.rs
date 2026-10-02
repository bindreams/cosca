//! `Child::drop` does bounded work only. A real delegated cgroup needs root, so these use
//! `CgroupLeaf::for_test_at` (real errnos on any Linux host) and `FakeLeaf` (answers `rmdir` as
//! cgroupfs does).

use crate::tokio::child::{fault, Child};

/// A real root that only a kill or a closed stdin ends, in no containment. The write end of its
/// stdin is returned: dropping it lets the root exit.
fn blocker() -> (Child, crate::tokio::ChildStdin) {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

#[cfg(target_os = "linux")]
use crate::containment::cgroup::test_support::alone;
#[cfg(target_os = "linux")]
use crate::test_child::fixture_path;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::{AsFd, OwnedFd};

    use super::Child;
    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};
    use crate::containment::{Attached, Containment};

    /// `child`, contained by `leaf` instead of what it spawned with.
    pub(super) fn contained_by(mut child: Child, leaf: crate::containment::cgroup::CgroupLeaf) -> Child {
        child.os.attached = Attached::Cgroup(leaf);
        child.containment = Containment::CgroupV2;
        child
    }

    /// A `FakeLeaf` whose `rmdir` answers as cgroupfs does, and an entered leaf on it.
    pub(super) fn fake_leaf(name: &str, populated: bool) -> (FakeLeaf, crate::containment::cgroup::CgroupLeaf) {
        crate::log_capture::install();
        let fake = FakeLeaf::new(name, populated);
        let (path, events) = (fake.leaf.clone(), fake.events.clone());
        leaf_fault::set_rmdir_hook(move |_| FakeLeaf::rmdir(&path, &events));
        let leaf = entered_leaf_at(fake.leaf.clone());
        (fake, leaf)
    }

    /// How a root ended.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Ended {
        Exited(i32),
        Signalled(i32),
        /// Reaped before its stdin closed, by tokio's own `Child` drop (its `try_wait` ran after
        /// something had already ended the root), so no status is left to read. It proves only
        /// that the root died with its stdin open. For [`ignoring_blocker`](super::ignoring_blocker),
        /// which ignores every signal but the ones it lists there, that leaves `SIGKILL`, one of
        /// those exceptions, a crash or a foreign kill: never another signal from the drop.
        ReapedWhileStdinOpen,
    }

    /// The root's exit, read through a pidfd opened while the caller still holds the unreaped
    /// child, so it names that process exactly. It never consumes the exit: the root's number
    /// belongs to tokio's reaper once the child is dropped, and a `#[tokio::test]` runtime that
    /// this thread never yields to has not run it. That holds only in a process running this one
    /// test (tokio's orphan queue is process-global, and any runtime that parks drains it), so
    /// [`ended_after_closing`](Self::ended_after_closing) requires `alone()`.
    pub(super) struct Pidfd(OwnedFd);

    impl Pidfd {
        pub(super) fn of(child: &Child) -> Pidfd {
            let pid = rustix::process::Pid::from_raw(child.id().pid() as i32).expect("a positive pid");
            Pidfd(rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open"))
        }

        /// Whether the root has been reaped, by anyone: `waitid` on the pidfd no longer finds a
        /// child. Consumes nothing, and a zombie counts as not reaped.
        pub(super) fn reaped(&self) -> bool {
            loop {
                match rustix::process::waitid(
                    rustix::process::WaitId::PidFd(self.0.as_fd()),
                    rustix::process::WaitIdOptions::EXITED
                        | rustix::process::WaitIdOptions::NOHANG
                        | rustix::process::WaitIdOptions::NOWAIT,
                ) {
                    Ok(_) => return false,
                    Err(rustix::io::Errno::CHILD) => return true,
                    Err(rustix::io::Errno::INTR) => {}
                    Err(e) => panic!("waitid on the root's pidfd: {e}"),
                }
            }
        }

        /// Close the root's stdin, so a root nothing signalled exits on its own, wait for its
        /// exit, and say how it ended. A root a drop killed died of `SIGKILL` before its stdin
        /// closed; one nothing killed exits `0`. The drop's own `try_wait` may reap a root that
        /// something already ended, which leaves no status to read: that is
        /// [`Ended::ReapedWhileStdinOpen`].
        /// The read is exact only under `alone()`: nothing else reaps before this thread yields to
        /// a runtime.
        pub(super) fn ended_after_closing(&self, stdin: crate::tokio::ChildStdin) -> Ended {
            debug_assert!(
                std::env::var_os("COSCA_TEST_ALONE").is_some(),
                "`ended_after_closing` is exact only in a process running this test alone (`alone()`): \
                 tokio's orphan queue is process-global"
            );
            let reaped_while_open = self.reaped();
            drop(stdin);
            if reaped_while_open {
                return Ended::ReapedWhileStdinOpen;
            }
            loop {
                let status = rustix::process::waitid(
                    rustix::process::WaitId::PidFd(self.0.as_fd()),
                    rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
                );
                match status {
                    Ok(Some(status)) => {
                        return match status.terminating_signal() {
                            Some(signal) => Ended::Signalled(signal),
                            None => Ended::Exited(status.exit_status().expect("exited")),
                        }
                    }
                    Ok(None) => unreachable!("a blocking waitid returns a status"),
                    Err(rustix::io::Errno::INTR) => {}
                    Err(e) => panic!("waitid on the root's pidfd: {e}"),
                }
            }
        }
    }

    pub(super) fn kill_file(fake: &FakeLeaf) -> Vec<u8> {
        std::fs::read(fake.leaf.join("cgroup.kill")).expect("read cgroup.kill")
    }

    /// The steps `drop` took and the levels of the records naming `needle`.
    pub(super) fn dropped(child: Child, needle: &str) -> (Vec<String>, Vec<log::Level>) {
        let mark = crate::log_capture::mark();
        leaf_fault::record_leaf_steps();
        drop(child);
        let steps = leaf_fault::take_leaf_steps();
        leaf_fault::take_rmdir_hook();
        (steps, crate::log_capture::levels_since(mark, needle))
    }
}

/// The tids of this process's threads.
#[cfg(target_os = "linux")]
fn thread_ids() -> std::collections::BTreeSet<String> {
    std::fs::read_dir("/proc/self/task")
        .expect("list /proc/self/task")
        .map(|entry| entry.expect("a task entry").file_name().to_string_lossy().into_owned())
        .collect()
}

/// A kill-on-drop drop starts no thread (principle 1): the drop's tree kill, root kill and leaf
/// release run on the dropping thread, and hand nothing to a pool.
///
/// Compares thread ids, not names: `Builder::name` is applied in the new thread's prologue, after
/// `spawn` returns, so a name check can pass spuriously. Runs alone, so no other test's threads
/// come and go between the two reads.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_async_drop_starts_no_thread() {
    if !alone(fixture_path!(an_async_drop_starts_no_thread)) {
        return;
    }
    let (child, _stdin) = blocker();
    let before = thread_ids();
    drop(child);
    let started: Vec<_> = thread_ids().difference(&before).cloned().collect();
    assert!(started.is_empty(), "a drop started threads: {started:?}");
}

/// The parent's end of a piped stdout nobody took is closed by the time `drop` returns. Runs alone,
/// so no other thread can take the descriptor number in between.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_async_drop_closes_the_childs_untaken_stdout() {
    use std::os::fd::AsRawFd as _;

    if !alone(fixture_path!(an_async_drop_closes_the_childs_untaken_stdout)) {
        return;
    }
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    let mut child = cmd.spawn().expect("spawn");
    let _stdin = child.stdin().expect("piped stdin");
    let Some(crate::tokio::child::ProcSource::Tokio { stdout, .. }) = child.os.proc.as_ref() else {
        panic!("a fresh child is a tokio backend");
    };
    let stdout = stdout.as_ref().expect("piped stdout").as_raw_fd();
    // SAFETY: `fcntl(F_GETFD)` reads a flag and changes nothing.
    assert_ne!(
        unsafe { libc::fcntl(stdout, libc::F_GETFD) },
        -1,
        "open while the child lives"
    );
    drop(child);
    // SAFETY: as above.
    let after = unsafe { libc::fcntl(stdout, libc::F_GETFD) };
    assert_eq!(after, -1, "the drop must close the child's untaken stdout");
}

/// Dropping a live, kill-on-drop root returns, on every platform and whatever contains it: the
/// drop signals and releases, and waits for nothing. A wait added to `signal_on_drop`, for the
/// root's exit or for the tree to drain, trips the bounded-section contract here at once.
///
/// Mutants: `block_until_exit(id, None)` or `os.attached.wait_drained(None)` added to
/// `signal_on_drop`.
#[tokio::test]
async fn a_kill_on_drop_drop_of_a_live_blocker_returns() {
    let (child, _stdin) = blocker();
    drop(child);
}

/// `child`, contained by a process group led by its own pid, as a `ProcessGroup` spawn leaves it.
#[cfg(unix)]
fn in_its_own_group(mut child: Child) -> Child {
    child.os.attached = crate::containment::Attached::ProcessGroup(child.id().pid() as i32);
    child
}

/// A live, kill-on-drop root in a process group has its group killed by the drop.
#[cfg(unix)]
#[tokio::test]
async fn a_drop_of_a_live_group_root_kills_its_group() {
    let (child, _stdin) = blocker();
    let child = in_its_own_group(child);
    let pgid = child.id().pid() as i32;
    let killed = crate::containment::unix::fault::record_kill_group();
    drop(child);
    assert_eq!(killed.killed(), [pgid]);
}

/// The drop releases the resources once, on the dropping thread: a release handed to another
/// thread bumps that thread's count, not this one's.
///
/// Mutant: `OsResources::release_without_waiting` moves `self` into a `std::thread::spawn`.
#[tokio::test]
async fn a_drop_releases_its_resources_once_on_the_dropping_thread() {
    let releases = fault::count_releases();
    let backend_drops = fault::count_backend_drops();
    let (child, _stdin) = blocker();
    assert_eq!(releases.get(), 0, "nothing is released before the drop");
    assert_eq!(backend_drops.get(), 0, "nothing is dropped before the drop");
    drop(child);
    assert_eq!(releases.get(), 1, "the dropping thread releases exactly once");
    assert_eq!(
        backend_drops.get(),
        1,
        "the drop hands the backend, and tokio's Child with it, its own drop, on this thread"
    );
}

/// A root that ignores signals 1-8, 10-18 and 20-64 (`trap '' $(seq 1 8) $(seq 10 18) $(seq 20
/// 64)`), blocked on its stdin, and its stdin's write end. Not ignored: `SIGKILL` (9) and
/// `SIGSTOP` (19), which cannot be, and 32 and 33, glibc's reserved real-time signals, which dash
/// accepts in a `trap` without ignoring (`SIGCHLD`, 17, is ignored by default anyway). It says `r`
/// once the `trap` is in place, and the caller reads that before dropping the child: otherwise the
/// drop races the `trap`, and a `SIGTERM` would still kill the root.
#[cfg(target_os = "linux")]
async fn ignoring_blocker() -> (Child, crate::tokio::ChildStdin, crate::tokio::ChildStdout) {
    use ::tokio::io::AsyncReadExt as _;

    let mut cmd = crate::tokio::Command::new();
    cmd.args([
        "sh",
        "-c",
        "trap '' $(seq 1 8) $(seq 10 18) $(seq 20 64); echo r; exec cat >/dev/null",
    ]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let mut stdout = child.stdout().expect("piped stdout");
    let mut ready = [0u8; 2];
    stdout.read_exact(&mut ready).await.expect("the root's `r` handshake");
    assert_eq!(&ready, b"r\n");
    (child, stdin, stdout)
}

/// The drop kills the root itself, and with `SIGKILL`: the root ignores every signal but `SIGKILL`,
/// `SIGSTOP` and 32 and 33 (see [`ignoring_blocker`]), so a drop that sent any other would leave it
/// running until its stdin closes (`Exited(0)`). Mutants: the drop skips the kill, or sends
/// `SIGTERM` or `SIGPROF`.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_kill_on_drop_drop_kills_the_root() {
    if !alone(fixture_path!(a_kill_on_drop_drop_kills_the_root)) {
        return;
    }
    let (child, stdin, _stdout) = ignoring_blocker().await;
    let root = linux::Pidfd::of(&child);
    drop(child);
    let ended = root.ended_after_closing(stdin);
    assert!(
        matches!(
            ended,
            linux::Ended::Signalled(libc::SIGKILL) | linux::Ended::ReapedWhileStdinOpen
        ),
        "the drop must kill the root with SIGKILL, got {ended:?}"
    );
}

/// The drop runs inside a bounded section, which is what turns a wait added to it into a debug
/// panic: a hook run by the leaf's `rmdir`, inside the drop, sees it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_async_drop_runs_inside_a_bounded_section() {
    use crate::containment::cgroup::fault as leaf_fault;

    let name = "cosca-async-drop-in-section";
    crate::log_capture::install();
    let fake = crate::containment::cgroup::test_support::FakeLeaf::new(name, true);
    let seen = std::rc::Rc::new(std::cell::Cell::new(false));
    let saw = seen.clone();
    leaf_fault::set_rmdir_hook(move |_| {
        saw.set(crate::bounded::in_section());
        Err(std::io::Error::from_raw_os_error(libc::EBUSY))
    });
    let leaf = crate::containment::cgroup::test_support::entered_leaf_at(fake.leaf.clone());
    let (child, _stdin) = blocker();
    drop(linux::contained_by(child, leaf));
    leaf_fault::take_rmdir_hook();
    assert!(seen.get(), "Child::drop must enter a bounded section");
    assert!(!crate::bounded::in_section(), "and leave it");
}

/// A leaf that never drains does not hold the drop: it returns, the leaf stays, and a warning names
/// it and points at `wait_tree`. A drop that waited for the drain would panic on the debug
/// contract instead.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_async_drop_never_blocks_on_an_undrained_leaf() {
    let name = "cosca-async-drop-undrained";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let (child, _stdin) = blocker();
    let child = linux::contained_by(child, leaf);
    let mark = crate::log_capture::mark();
    let (steps, levels) = linux::dropped(child, name);

    assert_eq!(
        steps,
        ["kill", "rmdir populated 1", "kill"],
        "tree kill, release, re-fired kill"
    );
    assert!(fake.leaf.exists(), "an undrained leaf is left behind");
    assert_eq!(levels, [log::Level::Warn]);
    assert!(crate::log_capture::records_since(mark, name)[0].contains("wait_tree"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_async_drop_removes_an_already_drained_leaf() {
    let name = "cosca-async-drop-drained";
    let (fake, leaf) = linux::fake_leaf(name, false);
    let (child, _stdin) = blocker();
    let (steps, levels) = linux::dropped(linux::contained_by(child, leaf), name);

    assert_eq!(steps, ["kill", "rmdir populated 0"]);
    assert!(!fake.leaf.exists(), "a drained leaf is removed");
    assert_eq!(levels, Vec::<log::Level>::new());
}

/// `kill_on_drop(false)` on a spawn that has not committed, with a `kill_tree()` behind it, as
/// tokio's `finish_elevated` leaves a handle: the handle no longer signals on drop, but the leaf
/// is still armed and this handle killed it. The tree has not drained, and the drop returns with
/// the kill fired again, a warning, and the root untouched.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_kill_on_drop_false_drop_of_an_armed_leaf_never_blocks() {
    if !alone(fixture_path!(a_kill_on_drop_false_drop_of_an_armed_leaf_never_blocks)) {
        return;
    }
    let name = "cosca-async-drop-opted-out-armed";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let mut cmd = crate::command::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.kill_on_drop(false);
    let mut child = crate::tokio::spawn::spawn_uncommitted(&mut cmd).expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let child = linux::contained_by(child, leaf);
    assert!(!child.kill_on_drop, "the command opted out");
    let root = linux::Pidfd::of(&child);
    // The root stays alive: only the tree is killed.
    child.kill_tree_members_unless_reaped().expect("kill the tree");
    let (steps, levels) = linux::dropped(child, name);

    assert_eq!(steps, ["rmdir populated 1", "kill"]);
    assert!(fake.leaf.exists());
    assert_eq!(levels, [log::Level::Warn]);
    assert_eq!(
        root.ended_after_closing(stdin),
        linux::Ended::Exited(0),
        "an opted-out drop must not signal the root"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_disarmed_never_killed_drop_never_kills_and_logs_at_debug() {
    if !alone(fixture_path!(
        a_disarmed_never_killed_drop_never_kills_and_logs_at_debug
    )) {
        return;
    }
    let name = "cosca-async-drop-disarmed-never-killed";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let (child, stdin) = blocker();
    let mut child = linux::contained_by(child, leaf);
    child.detach();
    let root = linux::Pidfd::of(&child);
    let (steps, levels) = linux::dropped(child, name);

    assert_eq!(steps, ["rmdir populated 1"]);
    assert_eq!(linux::kill_file(&fake), b"", "nothing may write cgroup.kill");
    assert!(fake.leaf.exists());
    assert_eq!(levels, [log::Level::Debug]);
    assert_eq!(root.ended_after_closing(stdin), linux::Ended::Exited(0));
}

/// A root whose kill fails is left running, and nothing waits for it: the drop returns, the root
/// is alive, and it ends only when its stdin closes. A drop that waited for it would panic on the
/// debug contract. The root's number now belongs to tokio's orphan queue, so this test only ever
/// reads it through its own pidfd.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_root_whose_kill_fails_is_handed_off_not_waited_on() {
    if !alone(fixture_path!(a_root_whose_kill_fails_is_handed_off_not_waited_on)) {
        return;
    }
    let name = "cosca-async-drop-handoff";
    let (fake, leaf) = linux::fake_leaf(name, false);
    let (child, stdin) = blocker();
    let mut child = linux::contained_by(child, leaf);
    let root = linux::Pidfd::of(&child);
    let pid = child.id().pid();

    // `kill_tree`'s backstop kill fails, so the root survives it: the tree kill alone does not
    // signal the root.
    let armed = fault::force_kill_failure();
    child.kill_tree().expect_err("the forced backstop failure surfaces");
    drop(armed);

    // Take-once: armed again for the drop's own root kill.
    let _armed = fault::force_kill_failure();
    let backend_drops = fault::count_backend_drops();
    let mark = crate::log_capture::mark();
    let (steps, levels) = linux::dropped(child, name);

    assert_eq!(
        steps,
        ["kill", "rmdir populated 0"],
        "tree kill, then a release that removes"
    );
    assert_eq!(levels, Vec::<log::Level>::new(), "the drained leaf is not warned about");
    let needle = format!("async child {pid} could not be terminated on drop");
    assert_eq!(
        crate::log_capture::levels_since(mark, &needle),
        [log::Level::Warn],
        "the root the drop could not signal is logged once"
    );
    assert_eq!(
        backend_drops.get(),
        1,
        "the drop must hand tokio its own Child to drop, never forget it"
    );
    assert!(!fake.leaf.exists(), "the drained leaf is released");
    // The drop returned with the root alive, so it can only end now, by the close.
    assert_eq!(
        root.ended_after_closing(stdin),
        linux::Ended::Exited(0),
        "neither the tree kill nor the drop may have signalled the root"
    );
}

/// The root a drop leaves to tokio is reaped by tokio: the drop killed it and handed tokio's
/// `Child` its own drop, so tokio's orphan handling owns the reap (principle 3).
///
/// Sequenced on the root's pidfd, opened before the drop, so it names that process whatever
/// happens to its number. The loop yields to the runtime, which does the reaping, and re-checks a
/// condition that becomes true; its expiry proves nothing. A root that is never reaped hangs it,
/// which the nextest override on this test turns into a failure.
///
/// Mutant: `OsResources::release_without_waiting` forgets the backend instead of dropping it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_dropped_root_left_to_tokio_is_reaped() {
    let (child, _stdin) = blocker();
    let root = linux::Pidfd::of(&child);
    let backend_drops = fault::count_backend_drops();
    drop(child);
    // Fails at once for a backend that was forgotten, before the loop could wait on it.
    assert_eq!(backend_drops.get(), 1, "the drop must hand tokio its own Child to drop");
    while !root.reaped() {
        tokio::task::yield_now().await;
    }
}

/// A root the drop could not signal is logged, and the drop returns: it does not wait for a root
/// it could not stop. Closing its stdin afterwards lets it end on its own.
#[tokio::test]
async fn unreaped_root_could_not_be_terminated_on_drop_is_logged() {
    crate::log_capture::install();
    let (child, stdin) = blocker();
    let pid = child.id().pid();
    let _armed = fault::force_kill_failure();
    let mark = crate::log_capture::mark();
    drop(child);

    let needle = format!("async child {pid} could not be terminated on drop");
    assert_eq!(crate::log_capture::levels_since(mark, &needle), [log::Level::Warn]);
    drop(stdin);
}

/// Async twin of the sync `drop_warns_instead_of_asserting_on_a_real_teardown_mechanism_failure`
/// (`child_tests.rs`): a failed `cgroup.kill` write reached during `Child::drop`'s OWN teardown
/// is a real OS outcome: Drop must warn and return normally.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn drop_warns_instead_of_asserting_on_a_real_teardown_mechanism_failure() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-async-drop-kill-fail-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill a directory");
    crate::child::spawn::fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });

    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sleep", "30"]);
    // The override is consumed by this spawn; `kill_on_drop` defaults to true. The tree-kill call
    // in Drop runs on the dropping thread, so no probe is needed to observe it.
    let mut child = cmd.spawn().expect("spawn");

    // Pin that the forced failure is the mechanism class this test claims (a raw `EISDIR` from
    // the `cgroup.kill` write, surfaced as `Error::Io`), so it cannot go vacuous if the forcing
    // stops reaching the kill.
    let forced = child
        .kill_tree()
        .expect_err("the forced cgroup.kill failure must surface from kill_tree");
    assert!(
        matches!(&forced, crate::error::Error::Io(io) if io.raw_os_error() == Some(libc::EISDIR)),
        "the forced failure must be a mechanism-class Error::Io(EISDIR), got {forced:?}"
    );

    let mark = crate::log_capture::mark();
    // A same-text record from ANOTHER thread, fixed before the drop by the join: the thread-filtered
    // scan below must not count it (a concurrent test's identical record would look the same).
    let marker = "Child::drop: contained-tree teardown did not fully succeed";
    std::thread::spawn(move || log::warn!("{marker}: from another thread"))
        .join()
        .expect("emit from another thread");
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(child)));
    assert!(
        unwound.is_ok(),
        "Child::drop must not panic on a real teardown-mechanism failure: {unwound:?}"
    );

    // `Drop` logs on the dropping thread, so the current-thread scan sees exactly its record.
    let records = crate::log_capture::records_since_on_current_thread(mark, marker);
    assert_eq!(
        records.iter().map(|(level, _)| *level).collect::<Vec<_>>(),
        [log::Level::Warn],
        "a real teardown-mechanism failure during Drop must be logged at warn, got {records:?}"
    );
}
