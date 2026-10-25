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

/// The root is reaped when the drop returns, and the teardown says it collected the exit.
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
/// the drain: it neither waits for it nor says it is waiting. The leaf is left behind, and a warning
/// names it.
///
/// Mutant: the drain is waited for after a failed kill (the drop says it is still waiting).
#[cfg(target_os = "linux")]
#[skuld::test]
async fn tokio_armed_drop_whose_tree_kill_fails_does_not_wait_for_the_drain() {
    use super::child_drop_tests::linux;
    use crate::containment::cgroup::fault as leaf_fault;

    crate::tokio::test_runtime::assert_current_thread();
    let name = "cosca-armed-drop-failed-tree-kill";
    let (fake, leaf) = linux::fake_leaf(name, true);
    let _failing = leaf_fault::fail_kill_writes();
    let (child, _stdin) = blocker();
    let root = Root::of(&child);
    let mark = crate::log_capture::mark();
    let (steps, levels) = linux::dropped(linux::contained_by(child, leaf), name);

    assert!(root.reaped(), "the root's own kill landed, so it is reaped: {steps:?}");
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
