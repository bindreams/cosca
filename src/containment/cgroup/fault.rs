use std::cell::Cell;
thread_local! {
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
#[cfg(feature = "tokio")]
pub(crate) fn set_force_child_pidfd_failure(on: bool) {
    FORCE_CHILD_PIDFD_FAILURE.with(|f| f.set(on));
}
pub(crate) fn take_force_child_pidfd_failure() -> bool {
    FORCE_CHILD_PIDFD_FAILURE.with(|f| f.replace(false))
}
