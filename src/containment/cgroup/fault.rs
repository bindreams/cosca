use std::cell::Cell;

use super::dir::WalkStep;

type Hook = Box<dyn FnOnce()>;

thread_local! {
    static FORCE_CHILD_PROC_DIR_FAILURE: Cell<bool> = const { Cell::new(false) };
    static BETWEEN_CHECK_AND_KILL: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static ON_TAKE_PLACEMENT: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static BEFORE_EXIT_WAIT: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static BEFORE_FRONT_PROBE: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static BEFORE_HANDLE_KILL: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static AFTER_PROCS_READ: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static AFTER_TERMINATE_PIN: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static CHILD_SENDS: std::cell::RefCell<Vec<ChildSend>> = const { std::cell::RefCell::new(Vec::new()) };
    static FORCE_GROUP_KILL_GONE: Cell<bool> = const { Cell::new(false) };
    static MEMBER_TERMS: std::cell::RefCell<Vec<MemberTerm>> = const { std::cell::RefCell::new(Vec::new()) };
    static HOOK_GATE: Cell<Option<std::os::fd::RawFd>> = const { Cell::new(None) };
    static FORCE_CHILD_KILL_DENIED: Cell<bool> = const { Cell::new(false) };
    static FORCE_GROUP_KILL_DENIED: Cell<bool> = const { Cell::new(false) };
    static BACKGROUND_REAP_NOTIFY: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_SHUT_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static WAIT_POLLING: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static ON_WAIT: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static BEFORE_STATE_READ: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static WAITED_PIDFD: Cell<Option<std::os::fd::RawFd>> = const { Cell::new(None) };
    static FORCE_CHILD_PIDFD_FAILURE: Cell<bool> = const { Cell::new(false) };
    static REAPED_ORPHANS: std::cell::RefCell<Vec<(u32, Option<i32>)>> = const { std::cell::RefCell::new(Vec::new()) };
    static FORCE_KILL_SUPPORTED: Cell<bool> = const { Cell::new(false) };
    static FORCE_REPORT_CHANNEL_FAILURE: Cell<bool> = const { Cell::new(false) };
    static FORCE_PLACEMENT_WRITE_RESULT: Cell<Option<isize>> = const { Cell::new(None) };
    static FORCE_OCCUPY_BEFORE_UNWIND: Cell<bool> = const { Cell::new(false) };
    static DRAIN_BLOCKING: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static DRAIN_ZERO_REMAINING: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static WAIT_SITE_PARK: std::cell::RefCell<Option<std::sync::mpsc::Sender<WaitSitePark>>> = const { std::cell::RefCell::new(None) };
    static WAIT_DEADLINE_ARG: std::cell::RefCell<Option<std::sync::mpsc::Sender<std::time::Instant>>> = const { std::cell::RefCell::new(None) };
    static LEAF_STEPS: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
    static FORCE_INOTIFY_FAILURE: Cell<bool> = const { Cell::new(false) };
    static FORCE_KILL_CHECK_ERRNO: Cell<Option<i32>> = const { Cell::new(None) };
    static FORCE_LEAF_OPEN_FAILURE: Cell<bool> = const { Cell::new(false) };
    static FAIL_KILL_WRITES: Cell<bool> = const { Cell::new(false) };
    static REFUSED_KILL_WRITES: Cell<u32> = const { Cell::new(0) };
    static FAIL_NEXT_KILL_WRITE: Cell<bool> = const { Cell::new(false) };
    static FAIL_PUMP_STARTS: Cell<bool> = const { Cell::new(false) };
    static PIDFD_INFO_MISSING: Cell<bool> = const { Cell::new(false) };
    static PROC_HIDDEN: Cell<bool> = const { Cell::new(false) };
    static BEFORE_KILL_WRITE: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static AFTER_KILL_WRITE: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static CHILD_DIES: Cell<Option<ChildDeath>> = const { Cell::new(None) };
    static FORCED_PIDFD_CGROUP_ID: Cell<Option<u64>> = const { Cell::new(None) };
    static BEFORE_WALK_OPEN: std::cell::RefCell<Option<WalkHook>> = const { std::cell::RefCell::new(None) };
    static BEFORE_SWEEP_REMOVE: std::cell::RefCell<Option<WalkHook>> = const { std::cell::RefCell::new(None) };
    static BEFORE_DRAIN_BLOCK: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static AFTER_DRAIN_WARN: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    static WALK_FAILURE: std::cell::RefCell<Option<WalkFailure>> = const { std::cell::RefCell::new(None) };
    static PROC_HIDDEN_AS: Cell<Option<i32>> = const { Cell::new(None) };
    static PIDFD_INFO_FAILS: Cell<bool> = const { Cell::new(false) };
    static PROBE_DUMPABLE: Cell<bool> = const { Cell::new(false) };
    static PROBE_CLOSE_RANGE_ALLOWED: Cell<Option<u32>> = const { Cell::new(None) };
    static PROBE_FD_DIR_FAILS: Cell<bool> = const { Cell::new(false) };
    static BEFORE_PROBE_PIN: crate::oneshot_hook::OneShotHook<libc::pid_t, Option<i32>> = const { crate::oneshot_hook::OneShotHook::new() };
    static BEFORE_PROBE_KILL: crate::oneshot_hook::OneShotHook<libc::pid_t, Option<i32>> = const { crate::oneshot_hook::OneShotHook::new() };
    static PROBE_STEPS: std::cell::RefCell<Vec<ProbeStep>> = const { std::cell::RefCell::new(Vec::new()) };
    static CGROUP_ID_FAILS: Cell<Option<i32>> = const { Cell::new(None) };
    static LIVENESS_READ_FAILS: Cell<Option<i32>> = const { Cell::new(None) };
    static SUBTREE_FAILS: Cell<Option<i32>> = const { Cell::new(None) };
    static TERMINATE_FAILS: Cell<Option<(TerminateStep, i32, bool)>> = const { Cell::new(None) };
    static RMDIR_HOOK: std::cell::RefCell<Option<RmdirHook>> = std::cell::RefCell::new(None);
    static FORCE_FORK_RUNNING_PIDFD_FAILURE: Cell<bool> = const { Cell::new(false) };
    static FORK_RUNNING_PIDFD_FAILURE_PROBE: std::cell::RefCell<Option<std::os::fd::OwnedFd>> =
        const { std::cell::RefCell::new(None) };
    static FORCE_FORK_RUNNING_PROBE_PIDFD_FAILURE: Cell<bool> = const { Cell::new(false) };
    static FORCE_KILL_ON_DROP_WAITID_EINTR: Cell<bool> = const { Cell::new(false) };
    static FORCE_KILL_ON_DROP_KILL_FAILURE: Cell<bool> = const { Cell::new(false) };
    static AFTER_FORK_STILL_LOCKED: std::cell::RefCell<Option<Hook>> = std::cell::RefCell::new(None);
    static ON_FORK_RUNNING_LOCK_CONTENDED: std::cell::RefCell<Option<Hook>> = std::cell::RefCell::new(None);
    static ON_FORK_RUNNING_CLEANUP: std::cell::RefCell<Option<Hook>> = std::cell::RefCell::new(None);
    static FORK_RUNNING_LOCK_HELD_REPORT_FD: Cell<Option<std::os::fd::RawFd>> = const { Cell::new(None) };
}

/// Replaces a leaf's `rmdir`, given the leaf's path.
type RmdirHook = Box<dyn FnMut(&std::path::Path) -> std::io::Result<()>>;

/// While the guard lives, every `cgroup.kill` write on this thread fails with `EIO`, and kills
/// nothing: a failed kill whose members may all still run. A teardown whose kill failed must not
/// wait for the leaf's drain, which such members would never end: a wait that is about to block
/// fails by assertion instead of hanging, as it does when a teardown skips its kill.
///
/// Nor may a teardown block on its child (`set_between_kill_and_wait`) after a kill it took as
/// delivered, when no write was even attempted: a kill route that sends nothing and says it
/// succeeded. That fails by assertion too. A look after a refused kill reaches the same seam, and
/// is allowed.
pub(crate) fn fail_kill_writes() -> FailKillWrites {
    arm_fail_kill_writes(None)
}

/// [`fail_kill_writes`] that also runs `release` before it fails for a kill route that wrote
/// nothing: what the unwind from that failure would otherwise wait for forever, as a drop does for
/// a front only a kill ends.
pub(crate) fn fail_kill_writes_releasing_on_unwritten_kill(release: impl FnOnce() + 'static) -> FailKillWrites {
    arm_fail_kill_writes(Some((Box::new(release), false)))
}

/// [`fail_kill_writes`] that runs `release` whenever the teardown is about to block on its child,
/// for a teardown that must not wait there: a wait ends what only a kill would, and the test sees
/// it, instead of hanging. A look after a refused kill is a reach of this seam too, so this is not
/// for a teardown that makes one.
pub(crate) fn fail_kill_writes_releasing_at_wait(release: impl FnOnce() + 'static) -> FailKillWrites {
    arm_fail_kill_writes(Some((Box::new(release), true)))
}

fn arm_fail_kill_writes(release: Option<(Box<dyn FnOnce()>, bool)>) -> FailKillWrites {
    FAIL_KILL_WRITES.with(|f| f.set(true));
    REFUSED_KILL_WRITES.with(|n| n.set(0));
    FailKillWrites {
        _no_drain_wait: set_before_drain_block(|| {
            fail_once_unwinding(
                "a teardown whose cgroup.kill failed waited for the leaf's drain, which its members may never end",
            );
        }),
        _no_unwritten_kill: crate::child::spawn::fault::set_between_kill_and_wait(move || {
            let unwritten = REFUSED_KILL_WRITES.with(Cell::get) == 0;
            if let Some((release, always)) = release {
                if unwritten || always {
                    release();
                }
            }
            if unwritten {
                fail_once_unwinding(
                    "a teardown took a kill as delivered and waited for its child, though no cgroup.kill was written",
                );
            }
        }),
    }
}

/// Fails the test with `message`, unless it is already unwinding: a second panic from a drop
/// aborts the process.
fn fail_once_unwinding(message: &str) {
    if !std::thread::panicking() {
        panic!("{message}");
    }
}

#[must_use = "the writes succeed again as soon as the guard is dropped"]
pub(crate) struct FailKillWrites {
    _no_drain_wait: crate::oneshot_hook::Armed,
    _no_unwritten_kill: crate::oneshot_hook::Armed,
}

impl Drop for FailKillWrites {
    fn drop(&mut self) {
        FAIL_KILL_WRITES.with(|f| f.set(false));
    }
}

/// Whether this write fails (see [`fail_kill_writes`]); a failure is counted.
pub(crate) fn kill_writes_fail() -> bool {
    let fails = FAIL_KILL_WRITES.with(Cell::get);
    if fails {
        REFUSED_KILL_WRITES.with(|n| n.set(n.get() + 1));
    }
    fails
}

/// A drain pump started on this thread fails to start, with `EAGAIN`, as a spawn at a thread limit
/// does, until the guard drops.
#[cfg(feature = "tokio")]
pub(crate) fn fail_pump_starts() -> FailPumpStarts {
    FAIL_PUMP_STARTS.with(|f| f.set(true));
    FailPumpStarts(())
}

#[cfg(feature = "tokio")]
#[must_use = "pumps start again as soon as the guard is dropped"]
pub(crate) struct FailPumpStarts(());

#[cfg(feature = "tokio")]
impl Drop for FailPumpStarts {
    fn drop(&mut self) {
        FAIL_PUMP_STARTS.with(|f| f.set(false));
    }
}

pub(crate) fn pump_starts_fail() -> bool {
    FAIL_PUMP_STARTS.with(Cell::get)
}

/// The next `cgroup.kill` write on this thread fails with `EIO` and kills nothing; the writes after
/// it succeed. A drop's own kill failing while the leaf's teardown, which writes after it, works.
pub(crate) fn fail_next_kill_write() -> FailNextKillWrite {
    FAIL_NEXT_KILL_WRITE.with(|f| f.set(true));
    FailNextKillWrite(())
}

#[must_use = "the failure is cleared as soon as the guard is dropped"]
pub(crate) struct FailNextKillWrite(());

impl Drop for FailNextKillWrite {
    fn drop(&mut self) {
        FAIL_NEXT_KILL_WRITE.with(|f| f.set(false));
    }
}

pub(crate) fn take_next_kill_write_failure() -> bool {
    FAIL_NEXT_KILL_WRITE.with(|f| f.replace(false))
}

/// While the guard lives, this thread reads `PIDFD_GET_INFO` as missing, as on a kernel before
/// 6.13: a task's cgroup is read through `/proc` instead.
pub(crate) fn miss_pidfd_info() -> MissPidfdInfo {
    PIDFD_INFO_MISSING.with(|f| f.set(true));
    MissPidfdInfo(())
}

#[must_use = "PIDFD_GET_INFO is back as soon as the guard is dropped"]
pub(crate) struct MissPidfdInfo(());

impl Drop for MissPidfdInfo {
    fn drop(&mut self) {
        PIDFD_INFO_MISSING.with(|f| f.set(false));
    }
}

pub(crate) fn pidfd_info_missing() -> bool {
    PIDFD_INFO_MISSING.with(Cell::get)
}

/// While the guard lives, this thread finds no `/proc/<pid>/cgroup` for another task, as a
/// `hidepid` `/proc` hides a task of another user.
pub(crate) fn hide_proc() -> HideProc {
    PROC_HIDDEN.with(|f| f.set(true));
    HideProc(())
}

#[must_use = "/proc is visible again as soon as the guard is dropped"]
pub(crate) struct HideProc(());

impl Drop for HideProc {
    fn drop(&mut self) {
        PROC_HIDDEN.with(|f| f.set(false));
    }
}

/// While the guard lives, this thread's reads of another task's `/proc/<pid>/cgroup` that
/// fail with `errno`, as `hidepid` answers: `EPERM` under `hidepid=1`.
pub(crate) fn hide_proc_as(errno: i32) -> HideProcAs {
    PROC_HIDDEN_AS.with(|f| f.set(Some(errno)));
    HideProcAs(())
}

#[must_use = "/proc is visible again as soon as the guard is dropped"]
pub(crate) struct HideProcAs(());

impl Drop for HideProcAs {
    fn drop(&mut self) {
        PROC_HIDDEN_AS.with(|f| f.set(None));
    }
}

/// The errno a hidden `/proc` answers on this thread: [`hide_proc_as`]'s, `ENOENT` under
/// [`hide_proc`], or `None` while nothing hides it.
pub(crate) fn proc_hidden_as() -> Option<i32> {
    PROC_HIDDEN_AS
        .with(Cell::get)
        .or_else(|| PROC_HIDDEN.with(Cell::get).then_some(libc::ENOENT))
}

/// While the guard lives, `PIDFD_GET_INFO` fails on this thread with `EIO`, as a kernel that has
/// it refusing it.
pub(crate) fn fail_pidfd_info() -> FailPidfdInfo {
    PIDFD_INFO_FAILS.with(|f| f.set(true));
    FailPidfdInfo(())
}

#[must_use = "PIDFD_GET_INFO answers again as soon as the guard is dropped"]
pub(crate) struct FailPidfdInfo(());

impl Drop for FailPidfdInfo {
    fn drop(&mut self) {
        PIDFD_INFO_FAILS.with(|f| f.set(false));
    }
}

pub(crate) fn pidfd_info_fails() -> bool {
    PIDFD_INFO_FAILS.with(Cell::get)
}

/// While the guard lives, the placement probe's child forked from this thread stays dumpable, as
/// one whose `PR_SET_DUMPABLE` failed.
pub(crate) fn keep_probe_dumpable() -> KeepProbeDumpable {
    PROBE_DUMPABLE.with(|f| f.set(true));
    KeepProbeDumpable(())
}

#[must_use = "the probe's child is made non-dumpable again as soon as the guard is dropped"]
pub(crate) struct KeepProbeDumpable(());

impl Drop for KeepProbeDumpable {
    fn drop(&mut self) {
        PROBE_DUMPABLE.with(|f| f.set(false));
    }
}

pub(crate) fn probe_kept_dumpable() -> bool {
    PROBE_DUMPABLE.with(Cell::get)
}

/// While the guard lives, the placement probe's child forked from this thread finds `close_range`
/// refused, as on a kernel before 5.9, and closes its other descriptors by a walk of `/proc`.
pub(crate) fn refuse_probe_close_range() -> RefuseProbeCloseRange {
    refuse_probe_close_range_after(0)
}

/// [`refuse_probe_close_range`], once the child's first `allowed` calls have succeeded.
pub(crate) fn refuse_probe_close_range_after(allowed: u32) -> RefuseProbeCloseRange {
    PROBE_CLOSE_RANGE_ALLOWED.with(|f| f.set(Some(allowed)));
    RefuseProbeCloseRange(())
}

#[must_use = "close_range is allowed again as soon as the guard is dropped"]
pub(crate) struct RefuseProbeCloseRange(());

impl Drop for RefuseProbeCloseRange {
    fn drop(&mut self) {
        PROBE_CLOSE_RANGE_ALLOWED.with(|f| f.set(None));
    }
}

/// Whether the forked probe child's next `close_range` is refused, counting it. Read in the child: a
/// `const` thread-local with no destructor, so async-signal-safe.
pub(crate) fn probe_close_range_refused() -> bool {
    PROBE_CLOSE_RANGE_ALLOWED.with(|f| match f.get() {
        None => false,
        Some(0) => true,
        Some(allowed) => {
            f.set(Some(allowed - 1));
            false
        }
    })
}

/// While the guard lives, the placement probe's child forked from this thread cannot open its
/// `/proc/self/fd`, as under a seccomp filter that refuses `openat2`.
pub(crate) fn fail_probe_fd_dir() -> FailProbeFdDir {
    PROBE_FD_DIR_FAILS.with(|f| f.set(true));
    FailProbeFdDir(())
}

#[must_use = "the directory opens again as soon as the guard is dropped"]
pub(crate) struct FailProbeFdDir(());

impl Drop for FailProbeFdDir {
    fn drop(&mut self) {
        PROBE_FD_DIR_FAILS.with(|f| f.set(false));
    }
}

/// Read in the forked probe child: a `const` thread-local with no destructor, so async-signal-safe.
pub(crate) fn probe_fd_dir_fails() -> bool {
    PROBE_FD_DIR_FAILS.with(Cell::get)
}

/// A hook given the probe child's pid; `Some(errno)` makes the guarded syscall fail with it.
pub(crate) type ProbeHook = crate::oneshot_hook::Armed<libc::pid_t, Option<i32>>;

/// Run `hook` once, in the next placement probe forked from this thread, after the fork and before
/// the child is pinned by a pidfd. `Some(errno)`: the `pidfd_open` fails with it and is not made.
pub(crate) fn set_before_probe_pin(hook: impl FnOnce(libc::pid_t) -> Option<i32> + 'static) -> ProbeHook {
    crate::oneshot_hook::arm_with(&BEFORE_PROBE_PIN, hook)
}

/// Run `hook` once, in the next placement probe forked from this thread, right before its child is
/// killed (through its pidfd, or by its number). `Some(errno)`: the kill fails with it and is not made.
pub(crate) fn set_before_probe_kill(hook: impl FnOnce(libc::pid_t) -> Option<i32> + 'static) -> ProbeHook {
    crate::oneshot_hook::arm_with(&BEFORE_PROBE_KILL, hook)
}

/// A step of a placement probe's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeStep {
    /// A kill of the child (signal number), recorded once the syscall or its seam answered.
    Kill(crate::send_log::Via, i32),
    /// The child's reap and how it ended.
    Reap(crate::send_log::Via, super::reach::ProbeEnd),
}

/// Notes a step of a placement probe's end on this thread.
pub(crate) fn record_probe_step(step: ProbeStep) {
    PROBE_STEPS.with(|s| s.borrow_mut().push(step));
}

/// The steps of the placement probes' ends on this thread since the last call.
pub(crate) fn take_probe_steps() -> Vec<ProbeStep> {
    PROBE_STEPS.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// Runs the [`set_before_probe_kill`] hook, if armed: the errno the kill fails with.
pub(crate) fn run_before_probe_kill(pid: libc::pid_t) -> Option<i32> {
    crate::oneshot_hook::fire_with(&BEFORE_PROBE_KILL, pid).flatten()
}

/// Runs the [`set_before_probe_pin`] hook, if armed: the errno the `pidfd_open` fails with.
pub(crate) fn run_before_probe_pin(pid: libc::pid_t) -> Option<i32> {
    crate::oneshot_hook::fire_with(&BEFORE_PROBE_PIN, pid).flatten()
}

/// Run `hook` once, right before the next `cgroup.kill` write on this thread; the guard clears it.
pub(crate) fn set_before_kill_write(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&BEFORE_KILL_WRITE, hook)
}

pub(crate) fn run_before_kill_write() {
    crate::oneshot_hook::fire(&BEFORE_KILL_WRITE);
}

/// Run `hook` once, right after the next `cgroup.kill` write on this thread that succeeded, before
/// anything waits on its effect. A fixture that only the kill would end is released here, so a kill
/// that sent nothing fails an assertion on how the fixture ended instead of hanging the wait for
/// its drain; a write that fails (or is made to) runs nothing.
pub(crate) fn set_after_kill_write(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&AFTER_KILL_WRITE, hook)
}

pub(crate) fn run_after_kill_write() {
    crate::oneshot_hook::fire(&AFTER_KILL_WRITE);
}

/// Make the NEXT leaf directory made on this thread fail to be held after its `mkdir`, with
/// `EMFILE`, as at `RLIMIT_NOFILE`. Take semantics.
pub(crate) fn set_force_leaf_open_failure(on: bool) {
    FORCE_LEAF_OPEN_FAILURE.with(|f| f.set(on));
}
pub(crate) fn take_force_leaf_open_failure() -> bool {
    FORCE_LEAF_OPEN_FAILURE.with(|f| f.replace(false))
}

/// Make the NEXT leaf creation's `cgroup.kill` lookup on this thread fail with `errno`: a lookup
/// through the held leaf directory fails only on a real error, which a temp directory cannot
/// produce. Take semantics.
pub(crate) fn set_force_kill_check_errno(errno: i32) {
    FORCE_KILL_CHECK_ERRNO.with(|f| f.set(Some(errno)));
}
pub(crate) fn take_force_kill_check_errno() -> Option<i32> {
    FORCE_KILL_CHECK_ERRNO.with(|f| f.take())
}

/// Make the NEXT drain watch on this thread fail to create its inotify instance, as
/// `fs.inotify.max_user_instances` would. Take semantics: assert [`take_force_inotify_failure`]
/// returns `false` afterwards to prove it was consumed.
pub(crate) fn set_force_inotify_failure(on: bool) {
    FORCE_INOTIFY_FAILURE.with(|f| f.set(on));
}
pub(crate) fn take_force_inotify_failure() -> bool {
    FORCE_INOTIFY_FAILURE.with(|f| f.replace(false))
}

/// Replace every leaf `rmdir` on this thread with `hook`, until [`take_rmdir_hook`]. A temp
/// directory gives none of cgroupfs's `rmdir` answers, so a test supplies them.
pub(crate) fn set_rmdir_hook(hook: impl FnMut(&std::path::Path) -> std::io::Result<()> + 'static) {
    RMDIR_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
}
pub(crate) fn take_rmdir_hook() {
    RMDIR_HOOK.with(|h| h.borrow_mut().take());
}
/// Run the rmdir hook, if one is set.
pub(crate) fn run_rmdir_hook(path: &std::path::Path) -> Option<std::io::Result<()>> {
    let mut hook = RMDIR_HOOK.with(|h| h.borrow_mut().take())?;
    let result = hook(path);
    RMDIR_HOOK.with(|h| *h.borrow_mut() = Some(hook));
    Some(result)
}

/// Send on `notify` each time a leaf's drain wait on this thread is about to block: the watch is
/// armed and `populated` last read 1. Kept until [`take_drain_blocking_notifier`].
pub(crate) fn set_drain_blocking_notifier(notify: std::sync::mpsc::Sender<()>) {
    DRAIN_BLOCKING.with(|d| *d.borrow_mut() = Some(notify));
}
pub(crate) fn take_drain_blocking_notifier() {
    DRAIN_BLOCKING.with(|d| d.borrow_mut().take());
}
/// Run `hook` once when the next drain wait on this thread is about to block, before it does: a
/// fixture that only the thing awaited would release can be checked, or released, here, so a
/// mutant that never made it happen fails an assertion instead of hanging the wait.
pub(crate) fn set_before_drain_block(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&BEFORE_DRAIN_BLOCK, hook)
}

/// Run `hook` once right after the next slow-drain warn on this thread, before the wait goes on:
/// a fixture only the drain's end would release is let go here, so a mutant that never warned
/// fails an assertion instead of hanging.
#[cfg(feature = "tokio")]
pub(crate) fn set_after_drain_warn(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&AFTER_DRAIN_WARN, hook)
}

pub(crate) fn run_after_drain_warn() {
    crate::oneshot_hook::fire(&AFTER_DRAIN_WARN);
}

pub(crate) fn notify_drain_blocking() {
    crate::oneshot_hook::fire(&BEFORE_DRAIN_BLOCK);
    DRAIN_BLOCKING.with(|d| {
        if let Some(notify) = d.borrow().as_ref() {
            // The send must always run — `debug_assert!` does not evaluate its condition in a
            // release build, so it cannot gate the call itself, only check its result. A send
            // failure while a notifier is installed means its receiver was dropped early — a
            // contract violation by the test that installed it, not something to swallow.
            let sent = notify.send(());
            debug_assert!(sent.is_ok(), "drain-blocking notifier's receiver was dropped");
        }
    });
}

/// Send on `notify` each time a leaf's drain step on this thread takes its zero-remaining
/// shortcut — answers `MembersRemain` from a step that arms no listener. Kept until
/// [`take_drain_zero_remaining_notifier`].
pub(crate) fn set_drain_zero_remaining_notifier(notify: std::sync::mpsc::Sender<()>) {
    DRAIN_ZERO_REMAINING.with(|d| *d.borrow_mut() = Some(notify));
}
pub(crate) fn take_drain_zero_remaining_notifier() {
    DRAIN_ZERO_REMAINING.with(|d| d.borrow_mut().take());
}
pub(crate) fn notify_drain_zero_remaining() {
    DRAIN_ZERO_REMAINING.with(|d| {
        if let Some(notify) = d.borrow().as_ref() {
            // The send must always run — see `notify_drain_blocking`'s own comment on why the
            // result, not the call, is what `debug_assert!` gates.
            let sent = notify.send(());
            debug_assert!(sent.is_ok(), "zero-remaining notifier's receiver was dropped");
        }
    });
}

/// What `wait_drained`'s own `Block` arm saw when its wait call returned — including a listener
/// already notified at registration, before any real park. `deadline` is the caller's own
/// requested instant for a bounded park, not necessarily the one actually armed (`wait_deadline`
/// consumes the listener, with no way to read that back) — `None` for an unbounded park, whose
/// `woken` is always `true`: it has no timeout to elapse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WaitSitePark {
    pub(crate) deadline: Option<std::time::Instant>,
    pub(crate) woken: bool,
}

/// Send on `notify` each time `wait_drained`'s own `Block` arm's wait call returns — proof the
/// call was reached, not that a real park happened: it also fires for a listener already
/// notified at registration, before `wait_deadline`/`wait` ever parks. Kept until
/// [`take_wait_site_park_notifier`].
pub(crate) fn set_wait_site_park_notifier(notify: std::sync::mpsc::Sender<WaitSitePark>) {
    WAIT_SITE_PARK.with(|p| *p.borrow_mut() = Some(notify));
}
pub(crate) fn take_wait_site_park_notifier() {
    WAIT_SITE_PARK.with(|p| p.borrow_mut().take());
}
pub(crate) fn notify_wait_site_park(park: WaitSitePark) {
    WAIT_SITE_PARK.with(|p| {
        if let Some(notify) = p.borrow().as_ref() {
            // The send must always run — see `notify_drain_blocking`'s own comment on why the
            // result, not the call, is what `debug_assert!` gates.
            let sent = notify.send(park);
            debug_assert!(sent.is_ok(), "wait-site-park notifier's receiver was dropped");
        }
    });
}

/// Send on `notify` the exact instant about to be passed to `listener.wait_deadline(at)`, from
/// `CgroupLeaf::wait_deadline_seamed` — the ONLY place this seam fires, one line above the real
/// call, from the same `at` binding the call itself receives. Closes the sync side's own gap
/// (`wait_deadline` consumes the listener and exposes no way to read back what it actually
/// armed): `wait_deadline_seamed` exists so there is exactly one call site for the real
/// `wait_deadline`, with this notify built in, rather than two separately-maintained lines a
/// mutant could edit one of without the other. Kept until [`take_wait_deadline_arg_notifier`].
pub(crate) fn set_wait_deadline_arg_notifier(notify: std::sync::mpsc::Sender<std::time::Instant>) {
    WAIT_DEADLINE_ARG.with(|p| *p.borrow_mut() = Some(notify));
}
pub(crate) fn take_wait_deadline_arg_notifier() {
    WAIT_DEADLINE_ARG.with(|p| p.borrow_mut().take());
}
pub(crate) fn notify_wait_deadline_arg(at: std::time::Instant) {
    WAIT_DEADLINE_ARG.with(|p| {
        if let Some(notify) = p.borrow().as_ref() {
            // The send must always run — see `notify_drain_blocking`'s own comment on why the
            // result, not the call, is what `debug_assert!` gates.
            let sent = notify.send(at);
            debug_assert!(sent.is_ok(), "wait-deadline-arg notifier's receiver was dropped");
        }
    });
}

/// Record, on this thread, each `cgroup.kill` write (`"kill"`) and each `rmdir` of a leaf, the
/// latter with its `cgroup.events` as read at that moment, until [`take_leaf_steps`].
pub(crate) fn record_leaf_steps() {
    LEAF_STEPS.with(|s| *s.borrow_mut() = Some(Vec::new()));
}
pub(crate) fn take_leaf_steps() -> Vec<String> {
    LEAF_STEPS.with(|s| s.borrow_mut().take()).unwrap_or_default()
}
pub(crate) fn record_leaf_step(step: impl FnOnce() -> String) {
    LEAF_STEPS.with(|s| {
        if let Some(steps) = s.borrow_mut().as_mut() {
            steps.push(step());
        }
    });
}

/// Treat the NEXT created leaf as exposing `cgroup.kill`. Supplies the single fact a temp
/// directory cannot, so every step AFTER the check — the `cgroup.procs` open, the report
/// channel, and the unwind that removes the leaf — runs for real, against the kernel's own
/// errnos, on any Linux host.
pub(crate) fn set_force_kill_supported(on: bool) {
    FORCE_KILL_SUPPORTED.with(|f| f.set(on));
}
pub(crate) fn take_force_kill_supported() -> bool {
    FORCE_KILL_SUPPORTED.with(|f| f.replace(false))
}
pub(crate) fn kill_supported_armed() -> bool {
    FORCE_KILL_SUPPORTED.with(|f| f.get())
}

/// Fail the NEXT `ReportChannel::new` with `EMFILE` — the real exhaustion this channel can hit,
/// which no test may provoke for real: the fd limit is process-wide, and would fail every
/// other test running in this binary.
pub(crate) fn set_force_report_channel_failure(on: bool) {
    FORCE_REPORT_CHANNEL_FAILURE.with(|f| f.set(on));
}
pub(crate) fn take_force_report_channel_failure() -> bool {
    FORCE_REPORT_CHANNEL_FAILURE.with(|f| f.replace(false))
}
pub(crate) fn report_channel_failure_armed() -> bool {
    FORCE_REPORT_CHANNEL_FAILURE.with(|f| f.get())
}

/// Make the NEXT placement write return `ret` without writing — 0, which no file a test can open
/// returns for a one-byte write. A child forked from this thread inherits the flag and takes it.
pub(crate) fn set_force_placement_write_result(ret: isize) {
    FORCE_PLACEMENT_WRITE_RESULT.with(|f| f.set(Some(ret)));
}
pub(crate) fn take_force_placement_write_result() -> Option<isize> {
    FORCE_PLACEMENT_WRITE_RESULT.with(|f| f.take())
}

/// Put a directory inside the NEXT leaf whose creation fails, just before its unwind runs, so
/// that unwind's `rmdir` fails for real (`ENOTEMPTY`).
pub(crate) fn set_force_occupy_before_unwind(on: bool) {
    FORCE_OCCUPY_BEFORE_UNWIND.with(|f| f.set(on));
}
pub(crate) fn take_force_occupy_before_unwind() -> bool {
    FORCE_OCCUPY_BEFORE_UNWIND.with(|f| f.replace(false))
}
pub(crate) fn occupy_before_unwind_armed() -> bool {
    FORCE_OCCUPY_BEFORE_UNWIND.with(|f| f.get())
}

/// Every child a leaf dropped before its verdict reaped on this thread, with the signal that
/// killed it, since the last call — taken, so each test sees only its own.
pub(crate) fn take_reaped_orphans() -> Vec<(u32, Option<i32>)> {
    REAPED_ORPHANS.with(|r| std::mem::take(&mut *r.borrow_mut()))
}
pub(crate) fn record_reaped_orphan(pid: u32, signal: Option<i32>) {
    REAPED_ORPHANS.with(|r| r.borrow_mut().push((pid, signal)));
}

/// Have the NEXT report wait on this thread signal `notify` just before it blocks — the one
/// point a test can know the wait began before the report existed.
pub(crate) fn set_wait_polling_notifier(notify: std::sync::mpsc::Sender<()>) {
    WAIT_POLLING.with(|w| *w.borrow_mut() = Some(notify));
}
pub(crate) fn notify_wait_polling() {
    if let Some(notify) = WAIT_POLLING.with(|w| w.borrow_mut().take()) {
        _ = notify.send(());
    }
}

/// Run `hook` at the start of the NEXT report wait on this thread, before it reads anything. The
/// hook reads which pidfd that wait is given with [`waited_pidfd`], so a test can fail by assertion
/// where a wrong one would block the wait forever.
pub(crate) fn set_on_wait(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&ON_WAIT, hook)
}
pub(crate) fn notify_wait_entry(pidfd: std::os::fd::RawFd) {
    WAITED_PIDFD.with(|p| p.set(Some(pidfd)));
    crate::oneshot_hook::fire(&ON_WAIT);
}
/// The pidfd the report wait was given, as a raw fd number.
pub(crate) fn waited_pidfd() -> Option<std::os::fd::RawFd> {
    WAITED_PIDFD.with(|p| p.get())
}

/// Have the NEXT intent sent on this thread — or in a child forked from it, which inherits the
/// flag — go without a pidfd, as when `pidfd_open` is denied in the child.
pub(crate) fn set_force_child_pidfd_failure(on: bool) {
    FORCE_CHILD_PIDFD_FAILURE.with(|f| f.set(on));
}
pub(crate) fn take_force_child_pidfd_failure() -> bool {
    FORCE_CHILD_PIDFD_FAILURE.with(|f| f.replace(false))
}

/// Run `hook` in the NEXT abandonment on this thread, after it has read what the child sent and
/// before it closes the channel — the window a send must not slip through unread.
pub(crate) fn set_after_shut_read(hook: impl FnOnce() + 'static) {
    AFTER_SHUT_READ.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
}
pub(crate) fn run_after_shut_read() {
    if let Some(hook) = AFTER_SHUT_READ.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

/// Answer the NEXT abandoned child's kill through its handle with `EPERM` in place of the syscall,
/// as a child that exec'd a setuid program denies an unprivileged supervisor — which a root test
/// lane cannot reproduce for real. `end_child` never sees the flag: a send it makes by any other
/// path is real. [`set_force_group_kill_denied`] does the same for its group kill.
pub(crate) fn set_force_child_kill_denied(on: bool) {
    FORCE_CHILD_KILL_DENIED.with(|f| f.set(on));
}
pub(crate) fn take_force_child_kill_denied() -> bool {
    FORCE_CHILD_KILL_DENIED.with(|f| f.replace(false))
}

/// Have the NEXT background reap started on this thread report on `notify` once it has reaped.
pub(crate) fn set_background_reap_notifier(notify: std::sync::mpsc::Sender<()>) {
    BACKGROUND_REAP_NOTIFY.with(|n| *n.borrow_mut() = Some(notify));
}
pub(crate) fn take_background_reap_notifier() -> Option<std::sync::mpsc::Sender<()>> {
    BACKGROUND_REAP_NOTIFY.with(|n| n.borrow_mut().take())
}

/// Hold the NEXT placement hook run by a child forked from this thread — which inherits the flag —
/// until a byte arrives on `gate`, so a test can order the child's hook after the parent's act.
#[cfg(feature = "tokio")]
pub(crate) fn set_hook_gate(gate: std::os::fd::RawFd) {
    HOOK_GATE.with(|g| g.set(Some(gate)));
}
pub(crate) fn take_hook_gate() -> Option<std::os::fd::RawFd> {
    HOOK_GATE.with(|g| g.take())
}

/// Have the NEXT intent sent on this thread — or in a child forked from it — go without its
/// `/proc/self` directory, as when `/proc` is not mounted.
pub(crate) fn set_force_child_proc_dir_failure(on: bool) {
    FORCE_CHILD_PROC_DIR_FAILURE.with(|f| f.set(on));
}
pub(crate) fn take_force_child_proc_dir_failure() -> bool {
    FORCE_CHILD_PROC_DIR_FAILURE.with(|f| f.replace(false))
}

/// Run `hook` in the NEXT abandonment on this thread, between the check that its child is
/// unreaped and the kill.
pub(crate) fn set_between_check_and_kill(hook: impl FnOnce() + 'static) {
    BETWEEN_CHECK_AND_KILL.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
}
pub(crate) fn run_between_check_and_kill() {
    if let Some(hook) = BETWEEN_CHECK_AND_KILL.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

/// Run `hook` in the NEXT abandonment on this thread, after any group kill and right before the
/// kill through the child's handle.
pub(crate) fn set_before_handle_kill(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&BEFORE_HANDLE_KILL, hook)
}
pub(crate) fn run_before_handle_kill() {
    crate::oneshot_hook::fire(&BEFORE_HANDLE_KILL);
}

/// Run `hook` in the NEXT abandonment on this thread, after the child has been signalled (an
/// elevation front: after its leaf's kill reached it) and right before the wait for its exit. A
/// test whose child blocks on a stdin it
/// holds releases it here: a real kill has already landed, so the release changes nothing, while
/// a skipped kill lets the child exit on its own EOF and the test's `SIGKILL` assertion fails
/// at once instead of waiting out the child.
pub(crate) fn set_before_exit_wait(hook: impl FnOnce() + 'static) -> BeforeExitWaitGuard {
    crate::oneshot_hook::arm(&BEFORE_EXIT_WAIT, hook)
}
pub(crate) type BeforeExitWaitGuard = crate::oneshot_hook::Armed;
/// Fire the [`set_before_exit_wait`] hook now, if it has not fired. A test calls this after the
/// code under test returns, so a return before the fire point still releases its fixture.
pub(crate) fn run_before_exit_wait() {
    crate::oneshot_hook::fire(&BEFORE_EXIT_WAIT);
}

/// Run `hook` in the NEXT abandonment of an elevation front on this thread, after it was seen
/// unreaped and placed, right before the probe for its exit.
pub(crate) fn set_before_front_probe(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&BEFORE_FRONT_PROBE, hook)
}
pub(crate) fn run_before_front_probe() {
    crate::oneshot_hook::fire(&BEFORE_FRONT_PROBE);
}

/// RAII: dropping this clears the hook [`set_after_fork_still_locked`] armed, even if
/// `fork_running` never ran it.
#[must_use = "dropping this immediately clears the armed hook; bind it for the scope that needs it"]
pub(crate) struct AfterForkStillLockedGuard(());
impl Drop for AfterForkStillLockedGuard {
    fn drop(&mut self) {
        AFTER_FORK_STILL_LOCKED.with(|h| *h.borrow_mut() = None);
    }
}

/// Run `hook` in the NEXT `fork_running` call on this thread, after `fork()` and `KillOnDrop`
/// construction, still holding `spawn_lock`. Runs on the forking thread, so it may read
/// [`crate::child::spawn::spawn_lock_held_by_this_thread`].
pub(crate) fn set_after_fork_still_locked(hook: impl FnOnce() + 'static) -> AfterForkStillLockedGuard {
    AFTER_FORK_STILL_LOCKED.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    AfterForkStillLockedGuard(())
}
pub(crate) fn run_after_fork_still_locked() {
    if let Some(hook) = AFTER_FORK_STILL_LOCKED.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

/// RAII: dropping this clears the hook [`set_fork_running_lock_contended`] armed.
#[must_use = "dropping this immediately clears the armed hook; bind it for the scope that needs it"]
pub(crate) struct ForkRunningLockContendedGuard(());
impl Drop for ForkRunningLockContendedGuard {
    fn drop(&mut self) {
        ON_FORK_RUNNING_LOCK_CONTENDED.with(|h| *h.borrow_mut() = None);
    }
}

/// Run `hook` in the NEXT `fork_running` call on this thread if `spawn_lock` is already held when
/// it goes to take it, just before it blocks on the lock.
pub(crate) fn set_fork_running_lock_contended(hook: impl FnOnce() + 'static) -> ForkRunningLockContendedGuard {
    ON_FORK_RUNNING_LOCK_CONTENDED.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    ForkRunningLockContendedGuard(())
}
pub(crate) fn run_fork_running_lock_contended() {
    if let Some(hook) = ON_FORK_RUNNING_LOCK_CONTENDED.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

/// RAII: dropping this clears the hook [`set_fork_running_cleanup`] armed.
#[must_use = "dropping this immediately clears the armed hook; bind it for the scope that needs it"]
pub(crate) struct ForkRunningCleanupGuard(());
impl Drop for ForkRunningCleanupGuard {
    fn drop(&mut self) {
        ON_FORK_RUNNING_CLEANUP.with(|h| *h.borrow_mut() = None);
    }
}

/// Run `hook` in the NEXT `fork_running` call on this thread that fails its `pidfd_open`, at the
/// start of the cleanup that kills and reaps the child. Runs on the forking thread.
pub(crate) fn set_fork_running_cleanup(hook: impl FnOnce() + 'static) -> ForkRunningCleanupGuard {
    ON_FORK_RUNNING_CLEANUP.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    ForkRunningCleanupGuard(())
}
pub(crate) fn run_fork_running_cleanup() {
    if let Some(hook) = ON_FORK_RUNNING_CLEANUP.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

/// RAII: dropping this clears the fd [`set_fork_running_lock_held_report_fd`] registered, even if
/// `fork_running` never consumed it, so it can't leak into a later call on this thread.
#[must_use = "dropping this immediately clears the registered fd; bind it for the scope that needs it"]
pub(crate) struct ForkRunningLockHeldReportFdGuard(());
impl Drop for ForkRunningLockHeldReportFdGuard {
    fn drop(&mut self) {
        FORK_RUNNING_LOCK_HELD_REPORT_FD.with(|f| f.set(None));
    }
}

/// Give the NEXT `fork_running` call on this thread a pipe write fd; its child writes one byte
/// (`1`/`0`) for whether it inherited `spawn_lock` as held. `fork_running` takes the fd once,
/// before forking.
pub(crate) fn set_fork_running_lock_held_report_fd(fd: std::os::fd::RawFd) -> ForkRunningLockHeldReportFdGuard {
    FORK_RUNNING_LOCK_HELD_REPORT_FD.with(|f| f.set(Some(fd)));
    ForkRunningLockHeldReportFdGuard(())
}
pub(crate) fn take_fork_running_lock_held_report_fd() -> Option<std::os::fd::RawFd> {
    FORK_RUNNING_LOCK_HELD_REPORT_FD.with(|f| f.take())
}

/// A signal `end_child` sent an abandoned spawn's child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildSend {
    /// Through its pidfd or `/proc` directory.
    Handle,
    /// To the process group it leads, by number.
    Group,
}
/// Note a signal `end_child` sent on this thread.
pub(crate) fn record_child_send(send: ChildSend) {
    CHILD_SENDS.with(|s| s.borrow_mut().push(send));
}
/// The signals `end_child` sent on this thread since the last call, in order.
pub(crate) fn take_child_sends() -> Vec<ChildSend> {
    CHILD_SENDS.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// Answer the NEXT abandoned child's group kill with `EPERM` in place of the syscall (see
/// [`set_force_child_kill_denied`]).
pub(crate) fn set_force_group_kill_denied(on: bool) {
    FORCE_GROUP_KILL_DENIED.with(|f| f.set(on));
}
pub(crate) fn take_force_group_kill_denied() -> bool {
    FORCE_GROUP_KILL_DENIED.with(|f| f.replace(false))
}

/// While the guard lives, answer the NEXT abandoned child's group kill with `ESRCH`, as for a group
/// with no member left.
pub(crate) fn force_group_kill_gone() -> GroupKillGone {
    FORCE_GROUP_KILL_GONE.with(|f| f.set(true));
    GroupKillGone(())
}

#[must_use = "the group kill is made again as soon as the guard is dropped"]
pub(crate) struct GroupKillGone(());

impl Drop for GroupKillGone {
    fn drop(&mut self) {
        FORCE_GROUP_KILL_GONE.with(|f| f.set(false));
    }
}
pub(crate) fn take_force_group_kill_gone() -> bool {
    FORCE_GROUP_KILL_GONE.with(|f| f.replace(false))
}

/// Run `hook` in the NEXT `CgroupLeaf::terminate` on this thread, once it has read `cgroup.procs`
/// and before it signals any member: the window in which a listed member can leave the leaf.
pub(crate) fn set_after_procs_read(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&AFTER_PROCS_READ, hook)
}
pub(crate) fn run_after_procs_read() {
    crate::oneshot_hook::fire(&AFTER_PROCS_READ);
}

/// Run `hook` in the NEXT `CgroupLeaf::terminate` on this thread, once it has pinned its first
/// member by a pidfd and before it places that member: the window in which a pinned member can
/// exit and be reaped.
pub(crate) fn set_after_terminate_pin(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&AFTER_TERMINATE_PIN, hook)
}
pub(crate) fn run_after_terminate_pin() {
    crate::oneshot_hook::fire(&AFTER_TERMINATE_PIN);
}

/// A signal `CgroupLeaf::terminate` sent a member: the pid its pidfd names (`None` once that
/// process is reaped, or where it cannot be read), the route of the send, and the signal's number.
pub(crate) type MemberTerm = (Option<u32>, crate::send_log::Via, i32);

/// Notes a signal `signo` sent to the leaf member `pid` by `sys` on this thread, once answered; the
/// route is the syscall's own, and a pidfd's pid is read from its fdinfo.
pub(crate) fn record_member_term(sys: crate::containment::unix::Sys<'_>, pid: u32, signo: i32) {
    use std::os::fd::AsRawFd as _;

    use crate::containment::unix::Sys;
    use crate::send_log::Via;
    let entry = match sys {
        Sys::Pidfd(pidfd, _) => {
            let pid = std::fs::read_to_string(format!("/proc/thread-self/fdinfo/{}", pidfd.as_raw_fd()))
                .ok()
                .and_then(|fdinfo| {
                    fdinfo
                        .lines()
                        .find_map(|line| line.strip_prefix("Pid:"))
                        .and_then(|pid| pid.trim().parse::<i64>().ok())
                })
                .and_then(|pid| u32::try_from(pid).ok().filter(|&pid| pid > 0));
            (pid, Via::Pidfd, signo)
        }
        Sys::Group(_) | Sys::Process(_) => (Some(pid), Via::Pid, signo),
    };
    MEMBER_TERMS.with(|t| t.borrow_mut().push(entry));
}

/// The `SIGTERM`s this thread's `CgroupLeaf::terminate` sent members since the last call.
pub(crate) fn take_member_terms() -> Vec<MemberTerm> {
    MEMBER_TERMS.with(|t| std::mem::take(&mut *t.borrow_mut()))
}

/// Pumps started and ended, per leaf name, process-wide.
static PUMPS: std::sync::Mutex<Vec<(std::ffi::OsString, bool)>> = std::sync::Mutex::new(Vec::new());

/// Record a pump starting (`ended == false`) or ending on the leaf named `name`.
pub(crate) fn record_pump(name: &std::ffi::OsStr, ended: bool) {
    PUMPS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((name.to_os_string(), ended));
}
/// How many pumps started and ended on the leaf named `name`.
pub(crate) fn pumps_of(name: &str) -> (usize, usize) {
    let pumps = PUMPS.lock().unwrap_or_else(|e| e.into_inner());
    let of = |ended| {
        pumps
            .iter()
            .filter(|(n, e)| n.as_os_str() == name && *e == ended)
            .count()
    };
    (of(false), of(true))
}

/// How many drain watches were armed on each leaf name, process-wide.
static ARMS: std::sync::Mutex<Vec<std::ffi::OsString>> = std::sync::Mutex::new(Vec::new());

pub(crate) fn record_arm(name: &std::ffi::OsStr) {
    ARMS.lock().unwrap_or_else(|e| e.into_inner()).push(name.to_os_string());
}
/// How many drain watches were armed on the leaf named `name`.
#[cfg(feature = "tokio")]
pub(crate) fn arms_of(name: &str) -> usize {
    ARMS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|n| n.as_os_str() == name)
        .count()
}

/// Pump seams, per leaf name, process-wide: a leaf's pump is a thread of its own.
static PUMP_SEAMS: std::sync::Mutex<Vec<(std::ffi::OsString, PumpSeam)>> = std::sync::Mutex::new(Vec::new());

enum PumpSeam {
    /// Fail the pump the next time its watch is readable.
    Fail,
    /// Report, after each batch the pump takes in, whether it notified.
    Batches(std::sync::mpsc::Sender<bool>),
}

/// Make the pump of the leaf named `name` fail the next time its watch is readable, as a failed
/// `read` of the inotify instance would. Take semantics.
pub(crate) fn set_force_pump_failure(name: &str) {
    PUMP_SEAMS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((name.into(), PumpSeam::Fail));
}
pub(crate) fn take_force_pump_failure(name: &std::ffi::OsStr) -> bool {
    let mut seams = PUMP_SEAMS.lock().unwrap_or_else(|e| e.into_inner());
    let at = seams
        .iter()
        .position(|(n, s)| n.as_os_str() == name && matches!(s, PumpSeam::Fail));
    at.map(|at| seams.remove(at)).is_some()
}

/// Send, after each batch the pump of the leaf named `name` takes in, whether it notified.
pub(crate) fn set_pump_batch_notifier(name: &str, notify: std::sync::mpsc::Sender<bool>) {
    PUMP_SEAMS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((name.into(), PumpSeam::Batches(notify)));
}
pub(crate) fn notify_pump_batch(name: &std::ffi::OsStr, notified: bool) {
    for (n, seam) in PUMP_SEAMS.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        if let (true, PumpSeam::Batches(notify)) = (n.as_os_str() == name, seam) {
            _ = notify.send(notified);
        }
    }
}

/// Make the NEXT `fork_running` on this thread fail its `pidfd_open` (as `RLIMIT_NOFILE` would);
/// consumed by that call.
pub(crate) fn set_force_fork_running_pidfd_failure(on: bool) {
    FORCE_FORK_RUNNING_PIDFD_FAILURE.with(|f| f.set(on));
}
pub(crate) fn take_force_fork_running_pidfd_failure() -> bool {
    FORCE_FORK_RUNNING_PIDFD_FAILURE.with(|f| f.replace(false))
}

/// The independent pidfd `fork_running`'s failure path opened on the child before killing it, so
/// a test can confirm the reap without racing pid reuse.
pub(crate) fn take_fork_running_pidfd_failure_probe() -> Option<std::os::fd::OwnedFd> {
    FORK_RUNNING_PIDFD_FAILURE_PROBE.with(|p| p.borrow_mut().take())
}
pub(crate) fn record_fork_running_pidfd_failure_probe(probe: std::os::fd::OwnedFd) {
    FORK_RUNNING_PIDFD_FAILURE_PROBE.with(|p| *p.borrow_mut() = Some(probe));
}

/// Make the NEXT `fork_running` pidfd-failure path's own probe `pidfd_open` fail too, separately
/// from `set_force_fork_running_pidfd_failure`. Consumed by that call.
pub(crate) fn set_force_fork_running_probe_pidfd_failure(on: bool) {
    FORCE_FORK_RUNNING_PROBE_PIDFD_FAILURE.with(|f| f.set(on));
}
pub(crate) fn take_force_fork_running_probe_pidfd_failure() -> bool {
    FORCE_FORK_RUNNING_PROBE_PIDFD_FAILURE.with(|f| f.replace(false))
}

/// Make `KillOnDrop::drop`'s NEXT `waitid` on this thread report one synthetic `EINTR` before its
/// real call, exercising the retry loop deterministically. Consumed by that one iteration.
pub(crate) fn set_force_kill_on_drop_waitid_eintr(on: bool) {
    FORCE_KILL_ON_DROP_WAITID_EINTR.with(|f| f.set(on));
}
pub(crate) fn take_force_kill_on_drop_waitid_eintr() -> bool {
    FORCE_KILL_ON_DROP_WAITID_EINTR.with(|f| f.replace(false))
}

/// Make `KillOnDrop::drop`'s NEXT `pidfd_send_signal` on this thread fail with `EPERM`, without
/// sending a real signal. Consumed by that call.
pub(crate) fn set_force_kill_on_drop_kill_failure(on: bool) {
    FORCE_KILL_ON_DROP_KILL_FAILURE.with(|f| f.set(on));
}
pub(crate) fn take_force_kill_on_drop_kill_failure() -> bool {
    FORCE_KILL_ON_DROP_KILL_FAILURE.with(|f| f.replace(false))
}

/// Run `hook` when the next leaf on this thread starts to settle its placement verdict
/// (`CgroupLeaf::take_placement`); the guard clears it on drop.
pub(crate) fn set_on_take_placement(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&ON_TAKE_PLACEMENT, hook)
}
pub(crate) fn run_on_take_placement() {
    crate::oneshot_hook::fire(&ON_TAKE_PLACEMENT);
}

/// Run `hook` in the NEXT `/proc` state read on this thread, just before it reads: the window in
/// which the child can exit and its number change hands, after the look that found it running.
pub(crate) fn set_before_state_read(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&BEFORE_STATE_READ, hook)
}
pub(crate) fn run_before_state_read() {
    crate::oneshot_hook::fire(&BEFORE_STATE_READ);
}

/// Where the next child forked from this thread kills itself (`SIGKILL`) in its placement hook,
/// before it can run the program: `std`'s spawn then returns `Ok`, as for any child a signal ends
/// before `exec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildDeath {
    /// Before it sends its intent: nothing names it to the leaf.
    BeforeIntent,
    /// After its intent, before its report.
    BeforeReport,
}

/// While the guard lives, the next child forked from this thread — which inherits the flag — dies
/// at `at` (see [`ChildDeath`]).
#[cfg(feature = "tokio")]
pub(crate) fn kill_child_at(at: ChildDeath) -> ChildDies {
    CHILD_DIES.with(|c| c.set(Some(at)));
    ChildDies(())
}

#[cfg(feature = "tokio")]
#[must_use = "children live again as soon as the guard is dropped"]
pub(crate) struct ChildDies(());

#[cfg(feature = "tokio")]
impl Drop for ChildDies {
    fn drop(&mut self) {
        CHILD_DIES.with(|c| c.set(None));
    }
}

/// In a forked child: dies here if this is where it was told to (see [`kill_child_at`]).
/// Async-signal-safe: a thread-local read, `getpid` and `kill`.
pub(crate) fn die_if_at(at: ChildDeath) {
    if CHILD_DIES.with(Cell::get) == Some(at) {
        // SAFETY: `kill` and `getpid` are async-signal-safe; the child dies here.
        unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
    }
}

/// While the guard lives, this thread reads every pidfd's cgroup id as `id`.
pub(crate) fn force_pidfd_cgroup_id(id: u64) -> ForcedPidfdCgroupId {
    FORCED_PIDFD_CGROUP_ID.with(|f| f.set(Some(id)));
    ForcedPidfdCgroupId(())
}

#[must_use = "the id is read again as soon as the guard is dropped"]
pub(crate) struct ForcedPidfdCgroupId(());

impl Drop for ForcedPidfdCgroupId {
    fn drop(&mut self) {
        FORCED_PIDFD_CGROUP_ID.with(|f| f.set(None));
    }
}

pub(crate) fn forced_pidfd_cgroup_id() -> Option<u64> {
    FORCED_PIDFD_CGROUP_ID.with(Cell::get)
}

/// While the guard lives, capturing a leaf's subtree on this thread fails with `errno`, as its
/// cgroup id read does once the leaf's filesystem stops giving ids.
pub(crate) fn fail_subtree(errno: i32) -> FailSubtree {
    SUBTREE_FAILS.with(|f| f.set(Some(errno)));
    FailSubtree(())
}

#[must_use = "the subtree is captured again as soon as the guard is dropped"]
pub(crate) struct FailSubtree(());

impl Drop for FailSubtree {
    fn drop(&mut self) {
        SUBTREE_FAILS.with(|f| f.set(None));
    }
}

/// A step of `CgroupLeaf::terminate`'s `SIGTERM` to one member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminateStep {
    /// The `pidfd_open` that pins the member.
    Pin,
    /// The read of whether the pinned member has exited.
    Exited,
    /// The `pidfd_send_signal`.
    Send,
}

/// While the guard lives, `step` of each member's `SIGTERM` in `CgroupLeaf::terminate` on this
/// thread fails with `errno`, and the call it stands for is not made.
pub(crate) fn fail_terminate(step: TerminateStep, errno: i32) -> FailTerminate {
    TERMINATE_FAILS.with(|f| f.set(Some((step, errno, false))));
    FailTerminate(())
}

/// [`fail_terminate`] for the first member's `step` only: the members after it are not refused.
pub(crate) fn fail_terminate_once(step: TerminateStep, errno: i32) -> FailTerminate {
    TERMINATE_FAILS.with(|f| f.set(Some((step, errno, true))));
    FailTerminate(())
}

#[must_use = "terminate's steps run again as soon as the guard is dropped"]
pub(crate) struct FailTerminate(());

impl Drop for FailTerminate {
    fn drop(&mut self) {
        TERMINATE_FAILS.with(|f| f.set(None));
    }
}

/// The errno `step` fails with, if a [`fail_terminate`] guard is live for it. A
/// [`fail_terminate_once`] refusal is spent by the call that gets it.
pub(crate) fn terminate_fails(step: TerminateStep) -> Option<i32> {
    let (failing, errno, once) = TERMINATE_FAILS.with(Cell::get)?;
    if failing != step {
        return None;
    }
    if once {
        TERMINATE_FAILS.with(|f| f.set(None));
    }
    Some(errno)
}

pub(crate) fn subtree_fails() -> Option<i32> {
    SUBTREE_FAILS.with(Cell::get)
}

/// A hook given the path, relative to the leaf, of each cgroup a descendant walk is about to open.
type WalkHook = Box<dyn FnMut(&std::path::Path)>;

/// While the guard lives, run `hook` with the path, relative to the leaf, of each cgroup a
/// descendant walk on this thread is about to open (`dir::find_descendant`), so a test can remove
/// one mid-walk.
pub(crate) fn set_before_walk_open(hook: impl FnMut(&std::path::Path) + 'static) -> BeforeWalkOpen {
    BEFORE_WALK_OPEN.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    BeforeWalkOpen(())
}

#[must_use = "the hook is cleared as soon as the guard is dropped"]
pub(crate) struct BeforeWalkOpen(());

impl Drop for BeforeWalkOpen {
    fn drop(&mut self) {
        BEFORE_WALK_OPEN.with(|h| h.borrow_mut().take());
    }
}

pub(crate) fn run_before_walk_open(path: &std::path::Path) {
    let hook = BEFORE_WALK_OPEN.with(|h| h.borrow_mut().take());
    if let Some(mut hook) = hook {
        hook(path);
        BEFORE_WALK_OPEN.with(|h| {
            h.borrow_mut().get_or_insert(hook);
        });
    }
}

/// The cgroup, the step, the errno, and how many times the step passes before it fails.
type WalkFailure = (std::path::PathBuf, WalkStep, i32, usize);

/// While the guard lives, `step` of the walk on this thread at the cgroup `path`, relative to the
/// leaf (`.` is the leaf itself), fails with `errno`, as the OS answers a refusal that cannot be
/// provoked on a real cgroup.
pub(crate) fn fail_walk_step(path: &str, step: WalkStep, errno: i32) -> FailWalkStep {
    fail_walk_step_after(path, step, errno, 0)
}

/// [`fail_walk_step`], once the step has passed `passes` times at `path`: for [`WalkStep::Entries`],
/// the failure comes at entry number `passes`, after the entries before it were read.
pub(crate) fn fail_walk_step_after(path: &str, step: WalkStep, errno: i32, passes: usize) -> FailWalkStep {
    WALK_FAILURE.with(|f| *f.borrow_mut() = Some((path.into(), step, errno, passes)));
    FailWalkStep(())
}

#[must_use = "the step succeeds again as soon as the guard is dropped"]
pub(crate) struct FailWalkStep(());

impl Drop for FailWalkStep {
    fn drop(&mut self) {
        WALK_FAILURE.with(|f| f.borrow_mut().take());
    }
}

pub(crate) fn walk_step_failure(path: &std::path::Path, step: WalkStep) -> Option<i32> {
    WALK_FAILURE.with(|f| match &mut *f.borrow_mut() {
        Some((at, failing, errno, passes)) if at == path && *failing == step => {
            if *passes == 0 {
                Some(*errno)
            } else {
                *passes -= 1;
                None
            }
        }
        _ => None,
    })
}

/// While the guard lives, run `hook` with the path, relative to the leaf, of each cgroup the sweep
/// on this thread (`dir::remove_children`) is about to remove, so a test can change the tree
/// between the sweep's listing and its removals.
pub(crate) fn set_before_sweep_remove(hook: impl FnMut(&std::path::Path) + 'static) -> BeforeSweepRemove {
    BEFORE_SWEEP_REMOVE.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    BeforeSweepRemove(())
}

#[must_use = "the hook is cleared as soon as the guard is dropped"]
pub(crate) struct BeforeSweepRemove(());

impl Drop for BeforeSweepRemove {
    fn drop(&mut self) {
        BEFORE_SWEEP_REMOVE.with(|h| h.borrow_mut().take());
    }
}

pub(crate) fn run_before_sweep_remove(path: &std::path::Path) {
    let hook = BEFORE_SWEEP_REMOVE.with(|h| h.borrow_mut().take());
    if let Some(mut hook) = hook {
        hook(path);
        BEFORE_SWEEP_REMOVE.with(|h| {
            h.borrow_mut().get_or_insert(hook);
        });
    }
}

/// While the guard lives, a leaf's cgroup id on this thread fails with `errno`, as
/// `name_to_handle_at` does on a kernel without `CONFIG_FHANDLE` (`ENOSYS`).
pub(crate) fn fail_cgroup_id(errno: i32) -> FailCgroupId {
    CGROUP_ID_FAILS.with(|f| f.set(Some(errno)));
    FailCgroupId(())
}

#[must_use = "the id reads again as soon as the guard is dropped"]
pub(crate) struct FailCgroupId(());

impl Drop for FailCgroupId {
    fn drop(&mut self) {
        CGROUP_ID_FAILS.with(|f| f.set(None));
    }
}

pub(crate) fn cgroup_id_fails() -> Option<i32> {
    CGROUP_ID_FAILS.with(Cell::get)
}

/// While the guard lives, a leaf's read of whether it is live, before its removal on this thread,
/// fails with `errno`, as an `openat` refused `EMFILE` does.
pub(crate) fn fail_liveness_read(errno: i32) -> FailLivenessRead {
    LIVENESS_READ_FAILS.with(|f| f.set(Some(errno)));
    FailLivenessRead(())
}

#[must_use = "the liveness reads again as soon as the guard is dropped"]
pub(crate) struct FailLivenessRead(());

impl Drop for FailLivenessRead {
    fn drop(&mut self) {
        LIVENESS_READ_FAILS.with(|f| f.set(None));
    }
}

pub(crate) fn liveness_read_fails() -> Option<i32> {
    LIVENESS_READ_FAILS.with(Cell::get)
}
