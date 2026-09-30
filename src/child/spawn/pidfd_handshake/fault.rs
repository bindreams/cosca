//! Test seams for the pidfd handshake. Thread-local where the spawning thread reads them; what the
//! helper thread needs is taken on the spawning thread and carried to it in [`HelperSeams`]. Every
//! arming function returns a guard that disarms on drop.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use rustix::io::Errno;

/// What the next child does around its report.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildFault {
    None,
    /// Its hook fails before it reports: the child exits before `exec`, std reports it.
    Fail,
    /// It kills itself before it reports: std reads that as a success.
    Sigkill,
    /// It kills itself after it sent its pidfd, before it reads its verdict.
    SigkillAfterReport,
    /// It reads one byte from this fd, inherited across the fork, before it reports.
    Gate(i32),
}

impl ChildFault {
    /// Before the report. Async-signal-safe.
    pub(super) fn apply(self) -> io::Result<()> {
        match self {
            ChildFault::Fail => Err(io::Error::from_raw_os_error(libc::EIO)),
            ChildFault::Sigkill => kill_self(),
            ChildFault::Gate(fd) => {
                let mut byte = 0u8;
                // SAFETY: a one-byte read into this frame; retried on `EINTR` only.
                while unsafe { libc::read(fd, (&raw mut byte).cast(), 1) } < 0
                    && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
                {}
                Ok(())
            }
            ChildFault::None | ChildFault::SigkillAfterReport => Ok(()),
        }
    }

    /// After the report. Async-signal-safe.
    pub(super) fn apply_after_report(self) -> io::Result<()> {
        match self {
            ChildFault::SigkillAfterReport => kill_self(),
            ChildFault::None | ChildFault::Fail | ChildFault::Sigkill | ChildFault::Gate(_) => Ok(()),
        }
    }
}

fn kill_self() -> io::Result<()> {
    // SAFETY: `kill(getpid(), SIGKILL)` through raw `syscall`s.
    unsafe {
        let pid = libc::syscall(libc::SYS_getpid);
        libc::syscall(libc::SYS_kill, pid, libc::SIGKILL);
    }
    Err(io::Error::from_raw_os_error(libc::EIO))
}

type VerdictHook = Box<dyn FnOnce(Option<u32>)>;

thread_local! {
    static CHILD_FAULT: Cell<ChildFault> = const { Cell::new(ChildFault::None) };
    static SPAWNS: Cell<usize> = const { Cell::new(0) };
    static LEAKED: Cell<Option<Option<u32>>> = const { Cell::new(None) };
    static PROBE: RefCell<Option<HelperProbe>> = const { RefCell::new(None) };
    static SEND_ERRNOS: RefCell<VecDeque<Errno>> = const { RefCell::new(VecDeque::new()) };
    static VERDICT_HOOK: RefCell<Option<VerdictHook>> = const { RefCell::new(None) };
    static HOLDER_ARMED: Cell<bool> = const { Cell::new(false) };
    static HOLDER: RefCell<Option<Holder>> = const { RefCell::new(None) };
    static CHILD_END_SHUT: Cell<Option<bool>> = const { Cell::new(None) };
    static PARENT_END_SHUT: Cell<Option<bool>> = const { Cell::new(None) };
    static BEFORE_AWAITING: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
}

/// Run `hook` once on this thread when the next `run`, its spawn returned, is about to block until
/// the helper is done or the child has exited.
pub(crate) fn before_awaiting_the_child_do(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
    crate::oneshot_hook::arm(&BEFORE_AWAITING, hook)
}

pub(super) fn before_awaiting_the_child() {
    crate::oneshot_hook::fire(&BEFORE_AWAITING);
}

// The child =====

/// Disarms the child fault on drop.
#[must_use = "dropping this disarms the fault at once"]
pub(crate) struct ArmedChildFault(());

/// Make the NEXT spawn's child do `fault`.
pub(crate) fn arm_child_fault(fault: ChildFault) -> ArmedChildFault {
    CHILD_FAULT.with(|f| f.set(fault));
    ArmedChildFault(())
}

impl Drop for ArmedChildFault {
    fn drop(&mut self) {
        CHILD_FAULT.with(|f| f.set(ChildFault::None));
    }
}

/// Taken once by `register`.
pub(super) fn child_fault() -> ChildFault {
    CHILD_FAULT.with(|f| f.replace(ChildFault::None))
}

// Counters =====

/// How many times `run` reached its fork on this thread.
pub(crate) fn spawns() -> usize {
    SPAWNS.with(Cell::get)
}

pub(crate) fn reset_spawns() {
    SPAWNS.with(|c| c.set(0));
}

pub(super) fn count_spawn() {
    SPAWNS.with(|c| c.set(c.get() + 1));
}

pub(crate) fn reset_leaked_pid() {
    LEAKED.with(|c| c.set(None));
}

/// The pid of the last child a spawn left unreaped; `Some(None)` if it had no pid.
pub(crate) fn take_leaked_pid() -> Option<Option<u32>> {
    LEAKED.with(Cell::take)
}

pub(super) fn leaked_pid(pid: Option<u32>) {
    LEAKED.with(|c| c.set(Some(pid)));
}

// A process that holds copies of both ends =====

struct Holder {
    release: OwnedFd,
    pidfd: OwnedFd,
}

/// Releases and reaps the holder on drop, whether or not it was forked.
#[must_use = "dropping this disarms the holder, or releases the one forked"]
pub(crate) struct ArmedHolder(());

/// Make the NEXT `run` on this thread fork, just before its spawn, a process that execs nothing
/// and holds copies of both ends of the channel until this guard drops, as a fork by another
/// thread would.
pub(crate) fn arm_fork_holder() -> ArmedHolder {
    HOLDER_ARMED.with(|a| a.set(true));
    ArmedHolder(())
}

impl Drop for ArmedHolder {
    fn drop(&mut self) {
        HOLDER_ARMED.with(|a| a.set(false));
        if let Some(holder) = HOLDER.with(|h| h.borrow_mut().take()) {
            drop(holder.release);
            let reaped = rustix::process::waitid(
                rustix::process::WaitId::PidFd(holder.pidfd.as_fd()),
                rustix::process::WaitIdOptions::EXITED,
            );
            assert!(reaped.is_ok(), "reap the holder: {reaped:?}");
        }
    }
}

/// Called by `run` with `spawn_lock` held, both ends open, and the helper started.
pub(super) fn fork_holder_if_armed() {
    if !HOLDER_ARMED.with(|a| a.replace(false)) {
        return;
    }
    let (release_r, release_w) = std::io::pipe().expect("pipe");
    let (release_r, release_w) = (OwnedFd::from(release_r), OwnedFd::from(release_w));
    let (r, w) = (release_r.as_raw_fd(), release_w.as_raw_fd());
    // SAFETY: the copy makes only async-signal-safe calls (`close`, `read`, `_exit`), and the
    // caller holds `spawn_lock`.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: as above; it waits for the release end's EOF, then exits.
        unsafe {
            libc::close(w);
            let mut byte = 0u8;
            while libc::read(r, (&raw mut byte).cast(), 1) < 0 && *libc::__errno_location() == libc::EINTR {}
            libc::_exit(0);
        }
    }
    assert!(pid > 0, "fork the holder: {}", io::Error::last_os_error());
    drop(release_r);
    // Blocked on its release end, so it is this process's unreaped child: its number is its own.
    let pidfd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(pid).expect("a forked pid is positive"),
        rustix::process::PidfdFlags::empty(),
    )
    .expect("the holder's pidfd");
    HOLDER.with(|h| {
        *h.borrow_mut() = Some(Holder {
            release: release_w,
            pidfd,
        })
    });
}

// Shutdown probes =====

/// Whether `fd`'s socket is shut both ways (`POLLHUP`, a check that does not block). If not, shuts
/// it, so a mutant that forgot fails its test at an assert rather than hanging it.
fn probe_shut(fd: &OwnedFd) -> bool {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};

    let mut fds = [PollFd::new(fd, PollFlags::empty())];
    poll(&mut fds, Some(&Timespec { tv_sec: 0, tv_nsec: 0 })).expect("poll the channel");
    let shut = fds[0].revents().contains(PollFlags::HUP);
    if !shut {
        _ = rustix::net::shutdown(fd, rustix::net::Shutdown::Both);
    }
    shut
}

pub(super) fn record_child_end_shut(fd: &OwnedFd) {
    CHILD_END_SHUT.with(|c| c.set(Some(probe_shut(fd))));
}

/// Whether the last `run` on this thread had shut the child's end once its spawn returned.
pub(crate) fn child_end_shut() -> Option<bool> {
    CHILD_END_SHUT.with(Cell::take)
}

/// Whether the last `run` on this thread's helper had shut the parent's end when it finished.
pub(crate) fn parent_end_shut() -> Option<bool> {
    PARENT_END_SHUT.with(Cell::take)
}

// The helper =====

/// Disarms the forced errnos on drop.
#[must_use = "dropping this disarms the forced errnos at once"]
pub(crate) struct ForcedGoSend(());

/// Make the NEXT `run`'s sends of GO fail with `errnos`, one per attempt; later attempts are real.
pub(crate) fn force_go_send_errnos(errnos: impl IntoIterator<Item = Errno>) -> ForcedGoSend {
    SEND_ERRNOS.with(|s| *s.borrow_mut() = errnos.into_iter().collect());
    ForcedGoSend(())
}

impl Drop for ForcedGoSend {
    fn drop(&mut self) {
        SEND_ERRNOS.with(|s| s.borrow_mut().clear());
    }
}

/// Disarms the held verdict on drop.
#[must_use = "dropping this disarms the held verdict at once"]
pub(crate) struct HeldVerdict(());

/// Make the NEXT `run`'s helper wait, once it has the child's report, until the spawn has returned
/// and the child's end is shut; `hook` runs on the spawning thread just before the helper goes on,
/// with the child's pid. Only for a child that dies without its verdict: one that waits for it
/// would never let the spawn return.
pub(crate) fn hold_verdict_until_spawn_returns(hook: impl FnOnce(Option<u32>) + 'static) -> HeldVerdict {
    VERDICT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    HeldVerdict(())
}

impl Drop for HeldVerdict {
    fn drop(&mut self) {
        VERDICT_HOOK.with(|h| h.borrow_mut().take());
    }
}

#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<bool>, Condvar)>);

impl Gate {
    fn wait(&self) {
        let (lock, condvar) = &*self.0;
        let mut open = lock.lock().unwrap_or_else(PoisonError::into_inner);
        while !*open {
            open = condvar.wait(open).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn open(&self) {
        let (lock, condvar) = &*self.0;
        *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
        condvar.notify_all();
    }
}

/// One `run`'s seams, taken on the spawning thread.
#[derive(Clone, Default)]
pub(crate) struct HelperSeams {
    probe: Option<HelperProbe>,
    send_errnos: Arc<Mutex<VecDeque<Errno>>>,
    verdict: Option<Gate>,
    parent_end_shut: Arc<Mutex<Option<bool>>>,
}

pub(super) fn take_helper_seams() -> HelperSeams {
    HelperSeams {
        probe: PROBE.with(|p| p.borrow_mut().take()),
        send_errnos: Arc::new(Mutex::new(SEND_ERRNOS.with(|s| std::mem::take(&mut *s.borrow_mut())))),
        verdict: VERDICT_HOOK.with(|h| h.borrow().is_some()).then(Gate::default),
        parent_end_shut: Arc::default(),
    }
}

impl HelperSeams {
    /// The helper, at its very end.
    pub(super) fn finish(&self) {
        if let Some(probe) = &self.probe {
            probe.wait_gate_then_finish();
        }
    }

    /// The spawning thread, where it joins the helper.
    pub(super) fn release_probe(&self) {
        if let Some(probe) = &self.probe {
            probe.release();
        }
    }

    pub(super) fn take_send_errno(&self) -> Option<Errno> {
        self.send_errnos
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }

    /// The helper, once it has the child's report.
    pub(super) fn wait_verdict(&self) {
        if let Some(gate) = &self.verdict {
            gate.wait();
        }
    }

    /// The spawning thread, once the spawn has returned and the child's end is shut.
    pub(super) fn release_verdict(&self, pid: Option<u32>) {
        if let Some(gate) = &self.verdict {
            if let Some(hook) = VERDICT_HOOK.with(|h| h.borrow_mut().take()) {
                hook(pid);
            }
            gate.open();
        }
    }

    /// The helper, as it shuts the parent's end.
    pub(super) fn record_parent_end_shut(&self, fd: &OwnedFd) {
        *self.parent_end_shut.lock().unwrap_or_else(PoisonError::into_inner) = Some(probe_shut(fd));
    }

    /// The spawning thread, after the join.
    pub(super) fn publish(&self) {
        let shut = self
            .parent_end_shut
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        PARENT_END_SHUT.with(|c| c.set(shut));
    }
}

/// Holds the helper at its very end until the spawning thread reaches its join, then records
/// that it finished. A helper nobody joins is still held, and never finishes.
#[derive(Clone)]
pub(crate) struct HelperProbe {
    gate: Gate,
    finished: Arc<AtomicBool>,
}

impl HelperProbe {
    fn wait_gate_then_finish(&self) {
        self.gate.wait();
        self.finished.store(true, Ordering::Release);
    }

    fn release(&self) {
        self.gate.open();
    }

    /// Whether the helper thread has run to its end.
    pub(crate) fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
}

/// Arms a probe for the NEXT spawn's helper.
pub(crate) fn arm_helper_probe() -> HelperProbe {
    let probe = HelperProbe {
        gate: Gate::default(),
        finished: Arc::new(AtomicBool::new(false)),
    };
    PROBE.with(|p| *p.borrow_mut() = Some(probe.clone()));
    probe
}
