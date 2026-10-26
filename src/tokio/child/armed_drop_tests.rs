//! The armed async drop kills the root through its handle, reaps it, and drains and removes a
//! cgroup leaf before it returns. It waits on the dropping thread whatever the runtime, and warns
//! once if the wait passes 1 s.

use crate::error::ChildFate;
#[cfg(target_os = "linux")]
use crate::test_groups::{tracer_group, Group};
use crate::tokio::child::Child;

/// A kill-on-drop root that only a kill or a closed stdin ends, in no containment.
fn blocker() -> (Child, crate::tokio::ChildStdin) {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout");
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// Names the root for good while the test still holds it unreaped: a pidfd on Linux, the pid on
/// macOS, where nothing else in this process spawns between the drop and the look.
struct Root {
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
    #[cfg(target_os = "macos")]
    pid: u32,
}

impl Root {
    fn of(child: &Child) -> Root {
        let pid = child.id().pid();
        #[cfg(target_os = "linux")]
        {
            let pid = rustix::process::Pid::from_raw(pid as i32).expect("a positive pid");
            Root {
                pidfd: rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open"),
            }
        }
        #[cfg(target_os = "macos")]
        Root { pid }
    }

    /// Whether the root has been reaped: a non-blocking, non-consuming `waitid` answers `ECHILD`.
    fn reaped(&self) -> bool {
        // SAFETY: an all-zero `siginfo_t` is valid, and `waitid` writes only into it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        #[cfg(target_os = "linux")]
        let (idtype, id) = {
            use std::os::fd::AsRawFd as _;
            (libc::P_PIDFD, self.pidfd.as_raw_fd() as libc::id_t)
        };
        #[cfg(target_os = "macos")]
        let (idtype, id) = (libc::P_PID, self.pid as libc::id_t);
        loop {
            // SAFETY: `info` is a valid out-pointer; WNOWAIT consumes nothing.
            let rc = unsafe { libc::waitid(idtype, id, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
            if rc == 0 {
                return false;
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::ECHILD) => return true,
                Some(libc::EINTR) => {}
                _ => panic!("waitid on the root: {e}"),
            }
        }
    }
}

/// The root is reaped when the drop returns, and the teardown says it collected the exit. So does
/// the awaited teardown of a failed run-to-completion helper.
///
/// Mutant: no reap (the drop hands tokio's `Child` to its own drop, as before).
#[skuld::test]
async fn tokio_armed_drop_reaps_before_returning() {
    let (child, _stdin) = blocker();
    let root = Root::of(&child);
    drop(child);
    assert!(root.reaped(), "the armed drop must reap the root before it returns");

    let (mut child, _stdin) = blocker();
    assert_eq!(child.tear_down_now(), ChildFate::Reaped);

    let (mut child, _stdin) = blocker();
    let root = Root::of(&child);
    assert_eq!(child.tear_down_awaiting().await, ChildFate::Reaped);
    assert!(
        root.reaped(),
        "the awaited teardown must reap the root before it returns"
    );
}

/// An awaited teardown that cannot watch the root's exit (the reactor refuses the registration)
/// reaps it as the drop does, on this thread, instead of forgetting a killed child that is ours.
///
/// Mutant: a failed watch forgets the root, which is left an unreaped zombie.
#[skuld::test]
async fn an_awaited_teardown_that_cannot_watch_the_exit_reaps_as_the_drop_does() {
    let (mut child, _stdin) = blocker();
    let root = Root::of(&child);
    let _refused = super::fault::fail_reap_watch();
    assert_eq!(child.tear_down_awaiting().await, ChildFate::Reaped);
    assert!(root.reaped(), "the teardown must reap the root");
}

/// Spawns a blocker on `rt`, drops it there, and says whether the root was reaped by then.
fn dropped_and_reaped_on(rt: &::tokio::runtime::Runtime, local: bool) -> bool {
    let body = async {
        let (child, _stdin) = blocker();
        let root = Root::of(&child);
        drop(child);
        root.reaped()
    };
    if local {
        ::tokio::task::LocalSet::new().block_on(rt, body)
    } else {
        rt.block_on(body)
    }
}

/// On a `current_thread` runtime the drop waits in place: tokio has no `block_in_place` there.
///
/// Mutant: an unconditional `block_in_place` (panics on this runtime).
#[skuld::test]
fn tokio_armed_drop_on_a_current_thread_runtime_reaps() {
    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current_thread runtime");
    assert!(dropped_and_reaped_on(&rt, false));
}

/// Inside a `LocalSet` on a multi-thread runtime the drop waits in place too: tokio panics in
/// `block_in_place` there, and offers no way to ask first.
///
/// Mutant: `block_in_place` whenever the runtime's flavour is multi-thread.
#[skuld::test]
fn tokio_armed_drop_in_a_local_set_on_a_multi_thread_runtime_reaps() {
    let rt = ::tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("multi-thread runtime");
    assert!(dropped_and_reaped_on(&rt, true));
}

/// A contained tree whose member has not exited when the drop's tree kill lands: the drop waits for
/// the leaf to drain, then removes it. The member is the fake leaf's `populated 1`, which only the
/// drop's own drain wait releases (`set_before_drain_block`), so a drop that never waits finds it
/// still there.
///
/// Mutant: `release_without_waiting` on the armed arm (the leaf is left behind with a warn).
#[cfg(target_os = "linux")]
#[skuld::test]
async fn tokio_armed_drop_of_a_tree_with_a_dying_descendant_removes_the_leaf() {
    use super::child_drop_tests::linux;
    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    crate::tokio::test_runtime::assert_current_thread();
    let name = "cosca-armed-drop-dying-member";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let events = fake.events.clone();
    let _release = leaf_fault::set_before_drain_block(move || FakeLeaf::set_populated(&events, false));
    let (child, _stdin) = blocker();
    let (steps, levels) = linux::dropped(linux::contained_by(child, leaf), name);

    assert!(!fake.leaf.exists(), "the drained leaf must be removed: {steps:?}");
    assert_eq!(levels, Vec::<log::Level>::new(), "{steps:?}");
}

/// A root that a foreign tracer holds as a zombie cannot be reaped until the tracer lets go: the
/// drop warns once, naming the pid, and keeps waiting. The tracer lets go only once the drop sleeps
/// in its blocking `waitid`, and the drop then reaps the root.
///
/// Mutants: no warn; warn, then return without reaping.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn tokio_armed_drop_warns_once_when_the_reap_waits_past_1s(#[fixture(tracer_group)] _group: &Group) {
    use crate::test_support::foreign_tracer::{self, await_blocked_or_finished, Holder, REAP};

    crate::log_capture::install();
    let (child, _stdin) = foreign_tracer::spawn_tokio_tracee().await;
    let pid = child.id().pid();
    let root = Root::of(&child);
    let mut tracer = foreign_tracer::spawn_helper(pid);
    let needle = format!("async child {pid}");
    let mark = crate::log_capture::mark();

    // Asserted only after the tracer lets go: a failure inside the scope would join a dropper the
    // tracer still blocks.
    let (holder, warns) = std::thread::scope(|s| {
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let dropper = s.spawn(move || {
            tid_tx
                .send(rustix::thread::gettid().as_raw_nonzero().get())
                .expect("report the tid");
            drop(child);
        });
        let tid = tid_rx.recv().expect("the dropper's tid");
        let holder = await_blocked_or_finished(tid);
        let warns: Vec<_> = crate::log_capture::records_since(mark, &needle)
            .into_iter()
            .filter(|text| text.contains("still waiting"))
            .collect();
        tracer.send(REAP);
        tracer.expect("reaped");
        dropper.join().expect("the dropper");
        (holder, warns)
    });

    assert_eq!(
        holder,
        Holder::Blocked,
        "the drop returned while the tracer still held the zombie"
    );
    assert_eq!(warns.len(), 1, "one warn before the blocking wait: {warns:?}");
    assert!(root.reaped(), "the drop reaps the root once the tracer lets go");
    assert_eq!(
        crate::log_capture::levels_since(mark, "still waiting"),
        [log::Level::Warn],
        "exactly one warn, at warn"
    );
}

/// An armed drop whose tree kill fails, and fails again when fired once more, has nothing to bound
/// the drain: it neither waits for it nor says it is waiting, even once a later `cgroup.kill` (the
/// release's own) lands. The leaf is left behind, and a warning names it. The writes fail until the
/// leaf's first `rmdir`; a drain wait that blocks after it releases the member and records it.
///
/// Mutants: the drain is waited for after a failed kill (the drop says it is still waiting); the
/// leaf's own drop, whose kill then lands, waits for the drain.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn tokio_armed_drop_whose_tree_kill_fails_does_not_wait_for_the_drain() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::child_drop_tests::linux;
    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    crate::tokio::test_runtime::assert_current_thread();
    let name = "cosca-armed-drop-failed-tree-kill";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let failing = Rc::new(RefCell::new(Some(leaf_fault::fail_kill_writes())));
    let (path, events) = (fake.leaf.clone(), fake.events.clone());
    let until_rmdir = Rc::clone(&failing);
    leaf_fault::set_rmdir_hook(move |_| {
        drop(until_rmdir.borrow_mut().take());
        FakeLeaf::rmdir(&path, &events)
    });
    let waited = Rc::new(Cell::new(false));
    let (flag, events) = (Rc::clone(&waited), fake.events.clone());
    let _release = leaf_fault::set_before_drain_block(move || {
        flag.set(true);
        FakeLeaf::set_populated(&events, false);
    });
    let (child, _stdin) = blocker();
    let root = Root::of(&child);
    let mark = crate::log_capture::mark();
    let (steps, levels) = linux::dropped(linux::contained_by(child, leaf), name);
    drop(failing.borrow_mut().take());

    assert!(root.reaped(), "the root's own kill landed, so it is reaped: {steps:?}");
    assert!(!waited.get(), "nothing may wait for the drain: {steps:?}");
    assert!(fake.leaf.exists(), "the undrained leaf is left behind: {steps:?}");
    assert_eq!(
        crate::log_capture::levels_since(mark, "still waiting"),
        Vec::<log::Level>::new(),
        "{steps:?}"
    );
    assert!(
        levels.contains(&log::Level::Warn),
        "the leaf left behind is named: {steps:?}"
    );
}

/// A leaf that has not drained 1 s after the drop's kill: the drop warns once, naming the root's
/// pid and the leaf, and keeps waiting until the leaf drains, then removes it. The fake leaf's member
/// is released only from a drain wait that blocks after the leaf's first `rmdir`, which follows the
/// bounded look that decides the warn; the release records whether the warn was out by then.
///
/// Mutants: no warn on the drain; a drop that waits at most 1 s, then releases the leaf without
/// waiting (the member is never released, and the leaf is left behind).
#[cfg(target_os = "linux")]
#[skuld::test]
async fn tokio_armed_drop_warns_once_when_the_drain_waits_past_1s() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::child_drop_tests::linux;
    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    crate::tokio::test_runtime::assert_current_thread();
    let name = "cosca-armed-drop-slow-drain";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let (child, _stdin) = blocker();
    let needle = format!("async child {}", child.id().pid());
    let mark = crate::log_capture::mark();
    let warned_at_release = Rc::new(Cell::new(None));
    let release: Rc<RefCell<Option<crate::oneshot_hook::Armed>>> = Rc::default();
    let (path, events) = (fake.leaf.clone(), fake.events.clone());
    let (seen, armed) = (Rc::clone(&warned_at_release), Rc::clone(&release));
    leaf_fault::set_rmdir_hook(move |_| {
        if armed.borrow().is_none() {
            let (seen, events, needle) = (Rc::clone(&seen), events.clone(), needle.clone());
            *armed.borrow_mut() = Some(leaf_fault::set_before_drain_block(move || {
                let warns = crate::log_capture::records_since(mark, &needle)
                    .into_iter()
                    .filter(|text| text.contains("still waiting") && text.contains(name))
                    .count();
                seen.set(Some(warns));
                FakeLeaf::set_populated(&events, false);
            }));
        }
        FakeLeaf::rmdir(&path, &events)
    });
    let (steps, _) = linux::dropped(linux::contained_by(child, leaf), name);
    drop(release.borrow_mut().take());

    assert_eq!(
        warned_at_release.get(),
        Some(1),
        "the drop must wait for the drain past its look, with one warn naming the leaf by then: {steps:?}"
    );
    assert!(!fake.leaf.exists(), "the drained leaf is removed: {steps:?}");
    assert_eq!(
        crate::log_capture::levels_since(mark, "still waiting"),
        [log::Level::Warn],
        "exactly one warn"
    );
}

/// A run-to-completion helper that fails after its spawn awaits its teardown instead of blocking
/// the runtime thread: on a `current_thread` runtime another task runs while the teardown waits for
/// the leaf to drain, and it is that task that releases the leaf's member. The task is woken by the
/// drain wait about to block. A teardown that blocks reaches the leaf's own `rmdir` with the member
/// still there, and the `rmdir` releases it instead.
///
/// Mutant: the helper tears the child down as `Drop` does (`tear_down_now`), blocking the thread.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_run_to_completion_helper_awaits_its_teardown() {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::child_drop_tests::linux;
    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current_thread runtime");
    let name = "cosca-awaited-teardown";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let released_by = Rc::new(Cell::new(None));
    let (path, events, by) = (fake.leaf.clone(), fake.events.clone(), Rc::clone(&released_by));
    leaf_fault::set_rmdir_hook(move |_| {
        if by.get().is_none() {
            by.set(Some("the leaf's rmdir"));
            FakeLeaf::set_populated(&events, false);
        }
        FakeLeaf::rmdir(&path, &events)
    });
    let (blocking_tx, blocking_rx) = ::tokio::sync::oneshot::channel();
    // Unsent only if the other task is gone, and then nothing releases the member but the `rmdir`.
    let _wake = leaf_fault::set_before_drain_block(move || {
        _ = blocking_tx.send(());
    });
    let (events, by) = (fake.events.clone(), Rc::clone(&released_by));
    let other_task = async move {
        if blocking_rx.await.is_ok() && by.get().is_none() {
            by.set(Some("another task"));
            FakeLeaf::set_populated(&events, false);
        }
    };
    let error = rt.block_on(async {
        let (child, _stdin) = blocker();
        let mut child = linux::contained_by(child, leaf);
        let failed =
            crate::tokio::command::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), &mut child);
        ::tokio::join!(failed, other_task).0
    });
    leaf_fault::take_rmdir_hook();

    assert_eq!(
        released_by.get(),
        Some("another task"),
        "the runtime must run another task while the teardown waits"
    );
    assert!(!fake.leaf.exists(), "the drained leaf is removed");
    match error {
        crate::error::Error::MayHaveStarted { fate, .. } => assert_eq!(fate, ChildFate::Reaped),
        other => panic!("expected MayHaveStarted, got {other:?}"),
    }
}

/// A helper's teardown dropped while it awaits the reap finishes as the drop would, on the dropping
/// thread: it reaps the root, emits the drop's report (here, of the tree kill that failed), and
/// drains and removes the leaf. The teardown really was awaiting the reap when it was dropped.
///
/// Mutants: the dropped teardown leaves what it holds to the fields' own drops (no report); the
/// teardown reaps by blocking, as the drop does (it never reaches the awaited reap).
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_dropped_awaited_teardown_finishes_as_the_drop_would() {
    use super::child_drop_tests::linux;
    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current_thread runtime");
    let name = "cosca-dropped-awaited-teardown";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let events = fake.events.clone();
    let _release = leaf_fault::set_before_drain_block(move || FakeLeaf::set_populated(&events, false));
    let _tree_kill_fails = leaf_fault::fail_next_kill_write();
    let pending = super::fault::pend_awaited_reap();
    let mark = crate::log_capture::mark();
    let root = rt.block_on(async {
        let (child, _stdin) = blocker();
        let root = Root::of(&child);
        let mut child = linux::contained_by(child, leaf);
        let mut teardown = std::pin::pin!(child.tear_down_awaiting());
        ::tokio::select! {
            biased;
            _ = &mut teardown => panic!("the awaited reap never completes"),
            () = std::future::ready(()) => {}
        }
        root
    });
    leaf_fault::take_rmdir_hook();

    assert!(pending.taken(), "the teardown must have been awaiting the reap");
    assert_eq!(
        crate::log_capture::levels_since(mark, "contained-tree teardown did not fully succeed"),
        [log::Level::Warn],
        "the dropped teardown must still emit the drop's report"
    );
    assert!(root.reaped(), "the dropped teardown must reap the root");
    assert!(!fake.leaf.exists(), "the drained leaf is removed");
}

/// A helper's teardown dropped while it awaits the drain leaves the leaf to a wait on the dropping
/// thread, as the drop does, with the drop's one warn once that wait passes 1 s. The fake leaf's
/// member is released only from a drain wait that blocks after the leaf's first `rmdir`, which
/// follows the bounded look that decides the warn.
///
/// Mutant: the dropped teardown leaves the leaf to its own drop, which blocks with no warn.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_teardown_dropped_during_the_drain_warns_once_past_1s() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::child_drop_tests::linux;
    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current_thread runtime");
    let name = "cosca-teardown-dropped-in-drain";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let warned_at_release = Rc::new(Cell::new(None));
    let release: Rc<RefCell<Option<crate::oneshot_hook::Armed>>> = Rc::default();
    let mark = crate::log_capture::mark();
    let (draining_tx, draining_rx) = ::tokio::sync::oneshot::channel();
    // The awaited drain is about to wait: the test drops the teardown then.
    let _draining = leaf_fault::set_before_drain_block(move || {
        _ = draining_tx.send(());
    });
    let fate = rt.block_on(async {
        let (child, _stdin) = blocker();
        let needle = format!("async child {}", child.id().pid());
        let (path, events) = (fake.leaf.clone(), fake.events.clone());
        let (seen, armed) = (Rc::clone(&warned_at_release), Rc::clone(&release));
        leaf_fault::set_rmdir_hook(move |_| {
            if armed.borrow().is_none() {
                let (seen, events, needle) = (Rc::clone(&seen), events.clone(), needle.clone());
                *armed.borrow_mut() = Some(leaf_fault::set_before_drain_block(move || {
                    let warns = crate::log_capture::records_since(mark, &needle)
                        .into_iter()
                        .filter(|text| text.contains("still waiting") && text.contains(name))
                        .count();
                    seen.set(Some(warns));
                    FakeLeaf::set_populated(&events, false);
                }));
            }
            FakeLeaf::rmdir(&path, &events)
        });
        let mut child = linux::contained_by(child, leaf);
        let teardown = child.tear_down_awaiting();
        ::tokio::select! {
            biased;
            fate = teardown => Some(fate),
            _ = draining_rx => None,
        }
    });
    leaf_fault::take_rmdir_hook();
    drop(release.borrow_mut().take());

    assert_eq!(fate, None, "the teardown must still be awaiting the drain");
    assert_eq!(
        warned_at_release.get(),
        Some(1),
        "the dropped teardown must wait for the drain past its look, with one warn naming the leaf by then"
    );
    assert!(!fake.leaf.exists(), "the drained leaf is removed");
    assert_eq!(
        crate::log_capture::levels_since(mark, "still waiting"),
        [log::Level::Warn],
        "exactly one warn"
    );
}

/// A helper's teardown whose drain cannot be watched hands the leaf to a wait on this thread, as
/// the drop does, with the drop's one warn once that wait passes 1 s. The fake leaf's member is
/// released only from a drain wait that blocks after the leaf's first `rmdir`, which follows the
/// bounded look that decides the warn.
///
/// Mutant: a failed drain watch is ignored and the leaf is dropped at once, so its own drop blocks
/// with no warn.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_teardown_whose_drain_watch_fails_warns_once_past_1s() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::child_drop_tests::linux;
    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current_thread runtime");
    let name = "cosca-teardown-drain-watch-fails";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let warned_at_release = Rc::new(Cell::new(None));
    let release: Rc<RefCell<Option<crate::oneshot_hook::Armed>>> = Rc::default();
    let mark = crate::log_capture::mark();
    let _watch_fails = super::fault::fail_drain_watch();
    let fate = rt.block_on(async {
        let (child, _stdin) = blocker();
        let needle = format!("async child {}", child.id().pid());
        let (path, events) = (fake.leaf.clone(), fake.events.clone());
        let (seen, armed) = (Rc::clone(&warned_at_release), Rc::clone(&release));
        leaf_fault::set_rmdir_hook(move |_| {
            if armed.borrow().is_none() {
                let (seen, events, needle) = (Rc::clone(&seen), events.clone(), needle.clone());
                *armed.borrow_mut() = Some(leaf_fault::set_before_drain_block(move || {
                    let warns = crate::log_capture::records_since(mark, &needle)
                        .into_iter()
                        .filter(|text| text.contains("still waiting") && text.contains(name))
                        .count();
                    seen.set(Some(warns));
                    FakeLeaf::set_populated(&events, false);
                }));
            }
            FakeLeaf::rmdir(&path, &events)
        });
        let mut child = linux::contained_by(child, leaf);
        child.tear_down_awaiting().await
    });
    leaf_fault::take_rmdir_hook();
    drop(release.borrow_mut().take());

    assert_eq!(fate, ChildFate::Reaped);
    assert_eq!(
        warned_at_release.get(),
        Some(1),
        "the teardown must wait for the drain past its look, with one warn naming the leaf by then"
    );
    assert!(!fake.leaf.exists(), "the drained leaf is removed");
    assert_eq!(
        crate::log_capture::levels_since(mark, "still waiting"),
        [log::Level::Warn],
        "exactly one warn"
    );
}

/// A blocker whose root has exited and been reaped: an armed drop of it waits only for the drain.
#[cfg(target_os = "linux")]
async fn reaped_blocker() -> Child {
    let (mut child, stdin) = blocker();
    drop(stdin);
    child.wait().await.expect("the blocker exits once its stdin closes");
    child
}

/// The fake leaf's member is released only from a drain wait that blocks after the leaf's first
/// `rmdir`, so after any look that decides a warn. The release records how many warns naming
/// `needle` and the leaf `name` were out by then. Answers that record, and the release's guard, to
/// drop once the teardown is over.
#[cfg(target_os = "linux")]
#[allow(clippy::type_complexity, reason = "a test helper's two shared cells")]
fn release_from_the_blocking_wait(
    fake: &crate::containment::cgroup::test_support::FakeLeaf,
    name: &'static str,
    needle: String,
    mark: usize,
) -> (
    std::rc::Rc<std::cell::Cell<Option<usize>>>,
    std::rc::Rc<std::cell::RefCell<Option<crate::oneshot_hook::Armed>>>,
) {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    let warned_at_release = Rc::new(Cell::new(None));
    let release: Rc<RefCell<Option<crate::oneshot_hook::Armed>>> = Rc::default();
    let (path, events) = (fake.leaf.clone(), fake.events.clone());
    let (seen, armed) = (Rc::clone(&warned_at_release), Rc::clone(&release));
    leaf_fault::set_rmdir_hook(move |_| {
        if armed.borrow().is_none() {
            let (seen, events, needle) = (Rc::clone(&seen), events.clone(), needle.clone());
            *armed.borrow_mut() = Some(leaf_fault::set_before_drain_block(move || {
                let warns = crate::log_capture::records_since(mark, &needle)
                    .into_iter()
                    .filter(|text| text.contains("still waiting") && text.contains(name))
                    .count();
                seen.set(Some(warns));
                FakeLeaf::set_populated(&events, false);
            }));
        }
        FakeLeaf::rmdir(&path, &events)
    });
    (warned_at_release, release)
}

/// An armed drop whose leaf's drain pump cannot start (a thread limit) still warns once its drain
/// wait passes the threshold, and still waits for the drain: the wait that blocks decides the warn.
///
/// Mutant: the warn is decided by a look through the pump, whose failure skips it.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn tokio_armed_drop_whose_drain_pump_cannot_start_warns_once() {
    use super::child_drop_tests::linux;
    use crate::containment::cgroup::fault as leaf_fault;

    crate::tokio::test_runtime::assert_current_thread();
    let name = "cosca-armed-drop-pump-refused";
    let child = reaped_blocker().await;
    let (fake, leaf) = linux::fake_leaf(name, true);
    let needle = format!("async child {}", child.id().pid());
    let mark = crate::log_capture::mark();
    let (warned_at_release, release) = release_from_the_blocking_wait(&fake, name, needle, mark);
    let _warn = super::fault::warn_slow_teardowns_after(std::time::Duration::ZERO);
    let _no_pump = leaf_fault::fail_pump_starts();
    let (steps, _) = linux::dropped(linux::contained_by(child, leaf), name);
    drop(release.borrow_mut().take());

    assert_eq!(
        warned_at_release.get(),
        Some(1),
        "one warn naming the leaf, out before its member was released: {steps:?}"
    );
    assert!(!fake.leaf.exists(), "the drained leaf is removed: {steps:?}");
}
