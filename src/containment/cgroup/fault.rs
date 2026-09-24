use std::cell::Cell;

/// A seam's hook, run with the child's pid.
type PidHook = Box<dyn FnOnce(u32)>;

thread_local! {
    static FORCE_LEAF_BUSY: Cell<bool> = const { Cell::new(false) };
    static AFTER_FINAL_READ: std::cell::RefCell<Option<PidHook>> = std::cell::RefCell::new(None);
    static FORCE_CHILD_PROC_DIR_FAILURE: Cell<bool> = const { Cell::new(false) };
    static BETWEEN_CHECK_AND_KILL: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static SIGNALLED_BY_PID: Cell<usize> = const { Cell::new(0) };
    static HOOK_GATE: Cell<Option<std::os::fd::RawFd>> = const { Cell::new(None) };
    static FORCE_CHILD_KILL_DENIED: Cell<bool> = const { Cell::new(false) };
    static BACKGROUND_REAP_NOTIFY: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_SHUT_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static WAIT_POLLING: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static FORCE_CHILD_PIDFD_FAILURE: Cell<bool> = const { Cell::new(false) };
    static REAPED_ORPHANS: std::cell::RefCell<Vec<(u32, Option<i32>)>> = const { std::cell::RefCell::new(Vec::new()) };
    static FORCE_KILL_SUPPORTED: Cell<bool> = const { Cell::new(false) };
    static FORCE_REPORT_CHANNEL_FAILURE: Cell<bool> = const { Cell::new(false) };
    static FORCE_PIDFD_FAILURE: Cell<Option<rustix::io::Errno>> = const { Cell::new(None) };
    static FORCE_SIGNAL_DENIED: Cell<bool> = const { Cell::new(false) };
    static FORCE_MEMBERSHIP_UNREADABLE: Cell<bool> = const { Cell::new(false) };
    static FORCE_PLACEMENT_WRITE_RESULT: Cell<Option<isize>> = const { Cell::new(None) };
    static FORCE_OCCUPY_BEFORE_UNWIND: Cell<bool> = const { Cell::new(false) };
    static DRAIN_BLOCKING: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static LEAF_STEPS: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
    static FORCE_INOTIFY_FAILURE: Cell<bool> = const { Cell::new(false) };
    static FORCE_KILL_CHECK_ERRNO: Cell<Option<i32>> = const { Cell::new(None) };
    static FORCE_LEAF_OPEN_FAILURE: Cell<bool> = const { Cell::new(false) };
    static TURN_QUEUED: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static RMDIR_HOOK: std::cell::RefCell<Option<RmdirHook>> = std::cell::RefCell::new(None);
}

/// Replaces a leaf's `rmdir`, given the leaf's path.
type RmdirHook = Box<dyn FnMut(&std::path::Path) -> std::io::Result<()>>;

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
pub(crate) fn notify_drain_blocking() {
    DRAIN_BLOCKING.with(|d| {
        if let Some(notify) = d.borrow().as_ref() {
            let _ = notify.send(());
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

/// Fail the NEXT `pidfd_open` of a report wait with `EMFILE`. The seccomp denial it also
/// stands for is exercised for real, in a process of its own, by `tests/spawn_io.rs`.
pub(crate) fn set_force_pidfd_failure(on: bool) {
    FORCE_PIDFD_FAILURE.with(|f| f.set(on.then_some(rustix::io::Errno::MFILE)));
}
/// Fail the NEXT `pidfd_open` of a report wait with `errno` — `ESRCH` stands for a child
/// something else already reaped, whose pid a test must never obtain for real: it may
/// already be another process's. Release-only, like its one test: debug builds assert the
/// precondition this breaks.
#[cfg(not(debug_assertions))]
pub(crate) fn set_force_pidfd_errno(errno: rustix::io::Errno) {
    FORCE_PIDFD_FAILURE.with(|f| f.set(Some(errno)));
}
pub(crate) fn take_force_pidfd_failure() -> Option<rustix::io::Errno> {
    FORCE_PIDFD_FAILURE.with(|f| f.take())
}
pub(crate) fn pidfd_failure_armed() -> bool {
    FORCE_PIDFD_FAILURE.with(|f| f.get().is_some())
}

/// Deny the NEXT `fail_closed`'s signals with `EPERM`, as a child that exec'd a setuid program
/// denies an unprivileged supervisor — which a root test lane cannot reproduce for real.
pub(crate) fn set_force_signal_denied(on: bool) {
    FORCE_SIGNAL_DENIED.with(|f| f.set(on));
}
pub(crate) fn take_force_signal_denied() -> bool {
    FORCE_SIGNAL_DENIED.with(|f| f.replace(false))
}
pub(crate) fn signal_denied_armed() -> bool {
    FORCE_SIGNAL_DENIED.with(|f| f.get())
}

/// Fail the NEXT read of a child's `/proc/<pid>/cgroup` with `EACCES`, as a `hidepid` or
/// seccomp-restricted `/proc` can — which a root test lane cannot reproduce for its own child.
pub(crate) fn set_force_membership_unreadable(on: bool) {
    FORCE_MEMBERSHIP_UNREADABLE.with(|f| f.set(on));
}
pub(crate) fn take_force_membership_unreadable() -> bool {
    FORCE_MEMBERSHIP_UNREADABLE.with(|f| f.replace(false))
}
pub(crate) fn membership_unreadable_armed() -> bool {
    FORCE_MEMBERSHIP_UNREADABLE.with(|f| f.get())
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
        let _ = notify.send(());
    }
}

/// Have the NEXT intent sent on this thread — or in a child forked from it, which inherits the
/// flag — go without a pidfd, as when `pidfd_open` is denied in the child.
pub(crate) fn set_force_child_pidfd_failure(on: bool) {
    FORCE_CHILD_PIDFD_FAILURE.with(|f| f.set(on));
}
pub(crate) fn take_force_child_pidfd_failure() -> bool {
    FORCE_CHILD_PIDFD_FAILURE.with(|f| f.replace(false))
}

/// Run `hook` with the child's pid in the NEXT `fail_closed` on this thread, once it has read the
/// child's final report and before it acts on it — the window a late send must not slip through
/// unread.
pub(crate) fn set_after_final_read(hook: impl FnOnce(u32) + 'static) {
    AFTER_FINAL_READ.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
}
pub(crate) fn run_after_final_read(pid: u32) {
    if let Some(hook) = AFTER_FINAL_READ.with(|h| h.borrow_mut().take()) {
        hook(pid);
    }
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

/// Deny the NEXT abandoned child's kill with `EPERM`, as a child that exec'd a setuid program
/// denies an unprivileged supervisor — which a root test lane cannot reproduce for real.
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

/// Have the NEXT verdict on this thread that cannot wait find its leaf busy (`EBUSY`), as one
/// holding another process would, without that process.
pub(crate) fn set_force_leaf_busy(on: bool) {
    FORCE_LEAF_BUSY.with(|f| f.set(on));
}
pub(crate) fn take_force_leaf_busy() -> bool {
    FORCE_LEAF_BUSY.with(|f| f.replace(false))
}

/// Hold the NEXT placement hook run by a child forked from this thread — which inherits the flag —
/// until a byte arrives on `gate`, so a test can order the child's hook after the parent's act.
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

/// Count an abandoned child signalled by its bare pid on this thread.
pub(crate) fn record_signalled_by_pid() {
    SIGNALLED_BY_PID.with(|c| c.set(c.get() + 1));
}
/// How many abandoned children this thread signalled by bare pid since the last call.
pub(crate) fn take_signalled_by_pid() -> usize {
    SIGNALLED_BY_PID.with(|c| c.replace(0))
}

/// Send on `notify` each time a wait on this thread queues for a leaf's drain watch, for the
/// rest of the thread's life.
#[cfg(feature = "tokio")]
pub(crate) fn set_turn_queued_notifier(notify: std::sync::mpsc::Sender<()>) {
    TURN_QUEUED.with(|t| *t.borrow_mut() = Some(notify));
}
pub(crate) fn notify_turn_queued() {
    TURN_QUEUED.with(|t| {
        if let Some(notify) = t.borrow().as_ref() {
            let _ = notify.send(());
        }
    });
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
