//! `Child::drop` does bounded work only (principle 3): signals, at most one `cgroup.kill` write and
//! one `rmdir`, and no wait. A real delegated cgroup needs root, but `CgroupLeaf::for_test_at`'s
//! directory operations run for real against the kernel's own errnos on any Linux host, and a
//! `FakeLeaf` answers `rmdir` as cgroupfs does. `Child` is built as a struct literal around a real
//! root: this module is a descendant of `crate::tokio::child`, so its private fields are
//! reachable.

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
    }

    /// The root's exit, read through a pidfd opened while the caller still holds the unreaped
    /// child, so it names that process exactly. It never consumes the exit: the root's number
    /// belongs to tokio's reaper once the child is dropped, and a `#[tokio::test]` runtime that
    /// this thread never yields to has not run it.
    pub(super) struct Pidfd(OwnedFd);

    impl Pidfd {
        pub(super) fn of(child: &Child) -> Pidfd {
            let pid = rustix::process::Pid::from_raw(child.id().pid() as i32).expect("a positive pid");
            Pidfd(rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open"))
        }

        /// Close the root's stdin, so a root nothing signalled exits on its own, wait for its
        /// exit, and say how it ended. A root a drop killed died of `SIGKILL` before its stdin
        /// closed; one nothing killed exits `0`. Waiting on the root is waiting on an external
        /// event that always comes, since its stdin is closed: no bound is needed.
        pub(super) fn ended_after_closing(&self, stdin: crate::tokio::ChildStdin) -> Ended {
            drop(stdin);
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

/// The drop hands tokio's `Child` its own drop, never `mem::forget`: the parent's end of a piped
/// stdout, which that `Child` owns, is closed by the time `drop` returns. Runs alone, so no other
/// thread can take the descriptor number in between.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_async_drop_closes_tokios_own_descriptors() {
    use std::os::fd::AsRawFd as _;

    if !alone(fixture_path!(an_async_drop_closes_tokios_own_descriptors)) {
        return;
    }
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    let mut child = cmd.spawn().expect("spawn");
    let _stdin = child.stdin().expect("piped stdin");
    let crate::tokio::child::ProcSource::Tokio(tokio_child) = child.os.proc.as_ref().expect("the backend");
    let stdout = tokio_child.stdout.as_ref().expect("piped stdout").as_raw_fd();
    // SAFETY: `fcntl(F_GETFD)` reads a flag and changes nothing.
    assert_ne!(
        unsafe { libc::fcntl(stdout, libc::F_GETFD) },
        -1,
        "open while the child lives"
    );
    drop(child);
    // SAFETY: as above.
    let after = unsafe { libc::fcntl(stdout, libc::F_GETFD) };
    assert_eq!(after, -1, "tokio's Child must be dropped, not forgotten");
}

/// The drop kills the root itself: it dies of `SIGKILL` before its stdin closes.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_kill_on_drop_drop_kills_the_root() {
    if !alone(fixture_path!(a_kill_on_drop_drop_kills_the_root)) {
        return;
    }
    let (child, stdin) = blocker();
    let root = linux::Pidfd::of(&child);
    drop(child);
    assert_eq!(root.ended_after_closing(stdin), linux::Ended::Signalled(libc::SIGKILL));
}

/// The drop runs inside a bounded section, which is what turns a wait added to it into a debug
/// panic: a hook run by the leaf's `rmdir`, inside the drop, sees it.
#[cfg(all(target_os = "linux", debug_assertions))]
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

/// `kill_on_drop(false)` after a `kill_tree()`, as tokio's `finish_elevated` leaves a handle: the
/// leaf is armed and killed, the tree has not drained, and the drop returns with a warning.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_disarmed_drop_of_an_armed_leaf_never_blocks() {
    let name = "cosca-async-drop-disarmed-armed";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let (child, _stdin) = blocker();
    let mut child = linux::contained_by(child, leaf);
    child.kill_tree().expect("kill the tree and the root");
    child.detach();
    let (steps, levels) = linux::dropped(child, name);

    assert_eq!(steps, ["rmdir populated 1", "kill"]);
    assert!(fake.leaf.exists());
    assert_eq!(levels, [log::Level::Warn]);
}

/// Opted out, the drop signals nothing: the root stays alive. A leaf this handle killed and that
/// has not drained is left behind with a warning.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_disarmed_killed_drop_leaves_its_undrained_leaf_and_warns() {
    if !alone(fixture_path!(
        a_disarmed_killed_drop_leaves_its_undrained_leaf_and_warns
    )) {
        return;
    }
    let name = "cosca-async-drop-disarmed-killed";
    let (fake, leaf) = linux::fake_leaf(name, true);
    leaf.hard_kill().expect("kill the tree");
    let (child, stdin) = blocker();
    let mut child = linux::contained_by(child, leaf);
    child.detach();
    let root = linux::Pidfd::of(&child);
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
async fn a_signalled_root_is_handed_off_not_waited_on() {
    if !alone(fixture_path!(a_signalled_root_is_handed_off_not_waited_on)) {
        return;
    }
    let name = "cosca-async-drop-handoff";
    let (fake, leaf) = linux::fake_leaf(name, false);
    let (child, stdin) = blocker();
    let mut child = linux::contained_by(child, leaf);
    let root = linux::Pidfd::of(&child);

    // `kill_tree`'s backstop kill fails, so the root survives it: the tree kill alone does not
    // signal the root.
    let armed = fault::force_kill_failure();
    child.kill_tree().expect_err("the forced backstop failure surfaces");
    drop(armed);

    // Take-once: armed again for the drop's own root kill.
    let _armed = fault::force_kill_failure();
    let (_steps, _levels) = linux::dropped(child, name);
    assert!(!fake.leaf.exists(), "the drained leaf is released");
    // The drop returned with the root alive, so it can only end now, by the close.
    assert_eq!(
        root.ended_after_closing(stdin),
        linux::Ended::Exited(0),
        "neither the tree kill nor the drop may have signalled the root"
    );
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
