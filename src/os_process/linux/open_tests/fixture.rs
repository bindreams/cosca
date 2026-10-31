//! Fork fixture for the reaped-process-group-leader tests.
//!
//! Forked children run only async-signal-safe operations (raw libc calls, no allocation, no
//! panics): the test binary is multithreaded. They need Linux >= 5.9 for `close_range(2)`; a child
//! that fails a step exits with that step's code (see [`ChildStep`]), and the parent reports it as
//! a [`FixtureError`] rather than an opaque short read.

use std::cell::Cell;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use crate::child::spawn::{spawn_lock, SpawnLockGuard};
use crate::containment::cgroup::test_support::{fork_running_locked, KillOnDrop};
use crate::identity::ProcessId;

// Child exit codes ====================================================================

/// The step at which a fixture child exited, encoded as its exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChildStep {
    /// `L`'s `close_range(2)`; ENOSYS on Linux < 5.9.
    CloseRange,
    SetPgid,
    ReportReady,
    AwaitRelease,
    ForkM,
    /// `M`'s `close_range(2)`.
    MCloseRange,
    ReportMPid,
}

impl ChildStep {
    pub(super) const ALL: [ChildStep; 7] = [
        ChildStep::CloseRange,
        ChildStep::SetPgid,
        ChildStep::ReportReady,
        ChildStep::AwaitRelease,
        ChildStep::ForkM,
        ChildStep::MCloseRange,
        ChildStep::ReportMPid,
    ];

    pub(super) const fn exit_code(self) -> i32 {
        120 + self as i32
    }

    pub(super) fn from_exit_code(code: i32) -> Option<ChildStep> {
        ChildStep::ALL.into_iter().find(|step| step.exit_code() == code)
    }

    pub(super) const fn cause(self) -> &'static str {
        match self {
            ChildStep::CloseRange | ChildStep::MCloseRange => {
                "close_range(2) failed (close_range unavailable: kernel < 5.9)"
            }
            ChildStep::SetPgid => "setpgid(0, 0) failed",
            ChildStep::ReportReady => "writing the ready byte to the rendezvous socket failed",
            ChildStep::AwaitRelease => "the rendezvous socket closed before the release byte arrived",
            ChildStep::ForkM => "fork of M failed",
            ChildStep::ReportMPid => "writing M's pid to the m_ready pipe failed",
        }
    }
}

/// A fixture child exited before the handshake completed.
#[derive(Debug)]
pub(super) enum FixtureError {
    /// `L` exited with raw wait status `status` instead of running the handshake to its end.
    LExited { status: i32 },
    /// `M` closed `m_ready` before reporting its pid. `M` is not this process's child, so its exit
    /// code is unobservable; it can only have failed [`ChildStep::MCloseRange`] or
    /// [`ChildStep::ReportMPid`].
    MExited,
}

impl FixtureError {
    /// The step `L` failed, when it exited with a step's code.
    pub(super) fn l_step(&self) -> Option<ChildStep> {
        match self {
            FixtureError::LExited { status } if libc::WIFEXITED(*status) => {
                ChildStep::from_exit_code(libc::WEXITSTATUS(*status))
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for FixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self, self.l_step()) {
            (FixtureError::LExited { .. }, Some(step)) => write!(f, "L exited at {step:?}: {}", step.cause()),
            (FixtureError::LExited { status }, None) => {
                write!(f, "L exited unexpectedly (raw wait status {status:#x})")
            }
            (FixtureError::MExited, _) => write!(
                f,
                "M exited before reporting its pid: {} or {}",
                ChildStep::MCloseRange.cause(),
                ChildStep::ReportMPid.cause()
            ),
        }
    }
}

// Test seams ===========================================================================

thread_local! {
    static FORCE_PANIC: Cell<PanicSeam> = const { Cell::new(PanicSeam::Off) };
    static FORCE_L_CLOSE_RANGE_FAILURE: Cell<bool> = const { Cell::new(false) };
}

#[derive(Clone, Copy)]
enum PanicSeam {
    Off,
    Armed,
    Fired { l_pid: libc::pid_t },
}

/// Disarms [`force_panic_after_fixture`] on drop.
#[must_use = "dropping this immediately disarms the forced panic; bind it for the probe's duration"]
pub(super) struct ForcedPanic(());

/// Make the next [`build_reaped_pgid_leader`] on this thread panic once its fixture exists and `L`
/// is still blocked on the rendezvous socket.
pub(super) fn force_panic_after_fixture() -> ForcedPanic {
    FORCE_PANIC.with(|f| f.set(PanicSeam::Armed));
    ForcedPanic(())
}

impl ForcedPanic {
    /// `L`'s pid, once the forced panic has fired.
    pub(super) fn fired_l_pid(&self) -> Option<libc::pid_t> {
        match FORCE_PANIC.with(Cell::get) {
            PanicSeam::Fired { l_pid } => Some(l_pid),
            _ => None,
        }
    }
}

impl Drop for ForcedPanic {
    fn drop(&mut self) {
        FORCE_PANIC.with(|f| f.set(PanicSeam::Off));
    }
}

/// Disarms [`force_l_close_range_failure`] on drop.
#[must_use = "dropping this immediately disarms the forced failure; bind it for the probe's duration"]
pub(super) struct ForcedLCloseRangeFailure(());

/// Make `L`'s `close_range` step fail in the next [`try_build_reaped_pgid_leader`] on this thread,
/// as it does on Linux < 5.9.
pub(super) fn force_l_close_range_failure() -> ForcedLCloseRangeFailure {
    FORCE_L_CLOSE_RANGE_FAILURE.with(|f| f.set(true));
    ForcedLCloseRangeFailure(())
}

impl Drop for ForcedLCloseRangeFailure {
    fn drop(&mut self) {
        FORCE_L_CLOSE_RANGE_FAILURE.with(|f| f.set(false));
    }
}

// Raw, async-signal-safe helpers =======================================================

/// `std::io::pipe` because `clippy.toml` disallows `libc::pipe`.
fn raw_pipe() -> (RawFd, RawFd) {
    let (r, w) = std::io::pipe().expect("pipe");
    (r.into_raw_fd(), w.into_raw_fd())
}

fn raw_close(fd: RawFd) {
    // SAFETY: `fd` is a descriptor this process owns, opened directly or inherited across `fork`.
    unsafe { libc::close(fd) };
}

fn exit_child(code: i32) -> ! {
    // SAFETY: async-signal-safe.
    unsafe { libc::_exit(code) }
}

/// Write all of `bytes`, retrying `EINTR` and partial writes. Exits the child with
/// `exit_code_on_failure` instead of panicking.
fn write_all_or_exit(fd: RawFd, mut bytes: &[u8], exit_code_on_failure: i32) {
    while !bytes.is_empty() {
        // SAFETY: `fd` is open and writable; `bytes` is a valid buffer of its own length.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n > 0 {
            bytes = &bytes[n as usize..];
        } else if n == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        } else {
            exit_child(exit_code_on_failure);
        }
    }
}

/// Read one byte, retrying `EINTR`. EOF exits the child: the test's end closed, so nothing is left
/// to wait for.
fn read_byte_or_exit(fd: RawFd, exit_code_on_failure: i32) {
    let mut byte = 0u8;
    loop {
        // SAFETY: `fd` is open and readable; `byte` is a valid 1-byte buffer.
        let n = unsafe { libc::read(fd, (&raw mut byte).cast(), 1) };
        if n == 1 {
            return;
        }
        if n == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        exit_child(exit_code_on_failure);
    }
}

/// ASCII decimal digits of `n` into `buf`, returning the filled suffix. No allocation.
fn write_decimal(mut n: u32, buf: &mut [u8; 10]) -> &[u8] {
    if n == 0 {
        buf[9] = b'0';
        return &buf[9..];
    }
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}

/// Close every fd except those in `keep` (sorted ascending, duplicate-free), one `close_range(2)`
/// per gap. Run right after each `fork()`: `spawn_lock()` only serializes this fixture's forks, so
/// a concurrently running test's fds are still in the snapshot, and a lingering child would pin
/// them. `force_failure` skips the syscall and fails the step, as on Linux < 5.9.
fn close_range_except_or_exit(keep: &[RawFd], exit_code_on_failure: i32, force_failure: bool) {
    if force_failure {
        exit_child(exit_code_on_failure);
    }
    let close_gap = |first: RawFd, last: RawFd| {
        if first > last {
            return;
        }
        // SAFETY: close_range(2) with no flags; both bounds are non-negative. rustix has no wrapper.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first as libc::c_long,
                last as libc::c_long,
                0 as libc::c_long,
            )
        };
        if rc != 0 {
            exit_child(exit_code_on_failure);
        }
    };
    let mut prev_end: RawFd = -1;
    for &fd in keep {
        close_gap(prev_end + 1, fd - 1);
        prev_end = fd;
    }
    close_gap(prev_end + 1, RawFd::MAX);
}

/// `waitpid(pid)` for this process's own child, retrying `EINTR`; returns the raw wait status.
fn wait_status(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    loop {
        // SAFETY: `pid` is this process's own unreaped child; `status` is a valid out-param.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return status;
        }
        assert!(
            r == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted,
            "waitpid({pid}): {r} {}",
            std::io::Error::last_os_error()
        );
    }
}

/// One blocking `read` in the test process, retrying `EINTR`; returns the byte count.
fn read_some(fd: RawFd, buf: &mut [u8]) -> isize {
    loop {
        // SAFETY: `fd` is open for the call's duration; `buf` is a valid buffer of its own length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return n;
        }
    }
}

// Fixture ==============================================================================

/// The test-owned resources of the reaped-leader fixture. `L` is guarded by a [`KillOnDrop`], so a
/// panic anywhere after the fork kills and reaps it whatever the field order; the fds close in
/// declaration order, EOFing `M`.
pub(super) struct ReapedLeaderFixture {
    /// Held only for its `Drop`: EOFs `L` if it is still blocked on the handshake.
    #[allow(dead_code, reason = "held only for its Drop; the fd close is the point")]
    rendezvous_test: OwnedFd,
    /// EOFs `M`; `M` closed its own copy right after its fork, so this is the last open one.
    block_w: OwnedFd,
    /// `M`'s pid/exit pipe. `M` never closes its write end itself, so EOF is `M`'s exit.
    m_ready_r: OwnedFd,
    /// `Some` until the explicit reap of `L`.
    #[allow(dead_code, reason = "held only for its Drop; the kill and reap are the point")]
    l: Option<KillOnDrop>,
    /// `M`'s pid, for a caller that verifies `M`'s death itself. `M` is not this process's child,
    /// so a pidfd, not `waitid`, is how.
    pub(super) m_pid: libc::pid_t,
    /// Held from before the pipes exist until after `block_w` is closed (declared last, so it
    /// drops last): no other fork can inherit `block_w` and keep `M` from seeing EOF.
    #[allow(dead_code, reason = "held only for its Drop; the unlock is the point")]
    lock: SpawnLockGuard,
}

impl ReapedLeaderFixture {
    /// Release `M` (EOF on `block`) and block until this process observes `M`'s exit (EOF on
    /// `m_ready`).
    pub(super) fn release_and_confirm_m_exited(self) {
        let m_ready_r_fd = self.m_ready_r.as_raw_fd();
        drop(self.block_w);
        let mut buf = [0u8; 1];
        let n = read_some(m_ready_r_fd, &mut buf);
        assert_eq!(n, 0, "expected EOF on m_ready (M's exit) after releasing M, got n={n}");
    }
}

/// [`try_build_reaped_pgid_leader`], panicking with the [`FixtureError`] on failure.
pub(super) fn build_reaped_pgid_leader() -> (ProcessId, ReapedLeaderFixture) {
    try_build_reaped_pgid_leader().unwrap_or_else(|e| panic!("reaped-leader fixture: {e}"))
}

/// A process-group leader `L` calls `setpgid(0, 0)` and forks a member `M` that stays in `L`'s
/// group and blocks on a pipe this test holds; `L` then exits and is reaped by this test process,
/// its direct parent. While `M` lives, `L`'s pid number stays alive as the group's PGID with no
/// thread-group-leader task attached: the shape `pidfd_open` answers `EINVAL` (< Linux 6.16) or
/// `ESRCH` (>= 6.16) to. Returns `L`'s identity and the fixture that tears down `L`/`M`.
///
/// Takes `spawn_lock()` itself and keeps it in the fixture until `block_w` is closed, so no other
/// fork pins `block_w` and delays `M`'s EOF. Callers must NOT hold it (it is not reentrant), and
/// must not fork or spawn while the fixture lives.
pub(super) fn try_build_reaped_pgid_leader() -> Result<(ProcessId, ReapedLeaderFixture), FixtureError> {
    let lock = spawn_lock();
    // `rendezvous`: test<->L handshake, so L's identity is read while L is alive. `m_ready`: M
    // reports its pid; M holds the write end until `_exit`, so EOF proves M exited. `block`: M
    // reads it; the test closes the write end to release M (no group signals).
    let mut rendezvous = [-1 as RawFd; 2];
    // SAFETY: `rendezvous` is a valid, writable 2-element array.
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                rendezvous.as_mut_ptr(),
            )
        },
        0,
        "socketpair: {}",
        std::io::Error::last_os_error()
    );
    let (rendezvous_test, rendezvous_l) = (rendezvous[0], rendezvous[1]);
    let (m_ready_r, m_ready_w) = raw_pipe();
    let (block_r, block_w) = raw_pipe();
    let force_close_range_failure = FORCE_L_CLOSE_RANGE_FAILURE.with(|f| f.replace(false));

    let l = fork_running_locked(&lock, || {
        let mut keep = [rendezvous_l, block_r, block_w, m_ready_w];
        keep.sort_unstable();
        close_range_except_or_exit(&keep, ChildStep::CloseRange.exit_code(), force_close_range_failure);
        // SAFETY: setpgid has no memory preconditions.
        if unsafe { libc::setpgid(0, 0) } != 0 {
            exit_child(ChildStep::SetPgid.exit_code());
        }
        write_all_or_exit(rendezvous_l, b"R", ChildStep::ReportReady.exit_code());
        read_byte_or_exit(rendezvous_l, ChildStep::AwaitRelease.exit_code());

        // SAFETY: L is single-threaded and freshly forked; M runs only async-signal-safe code.
        let m_pid = unsafe { libc::fork() };
        if m_pid == -1 {
            exit_child(ChildStep::ForkM.exit_code());
        }
        if m_pid == 0 {
            // M stays in L's group (inherited pgid). It must not hold `block`'s write end, or the
            // test's close would never EOF it.
            let mut keep = [block_r, m_ready_w];
            keep.sort_unstable();
            close_range_except_or_exit(&keep, ChildStep::MCloseRange.exit_code(), false);
            // SAFETY: getpid has no preconditions.
            let pid = unsafe { libc::getpid() } as u32;
            let mut digits = [0u8; 10];
            write_all_or_exit(
                m_ready_w,
                write_decimal(pid, &mut digits),
                ChildStep::ReportMPid.exit_code(),
            );
            write_all_or_exit(m_ready_w, b"\n", ChildStep::ReportMPid.exit_code());
            let mut sink = 0u8;
            loop {
                // SAFETY: `block_r` is open; `sink` is a valid 1-byte buffer. Any return other
                // than `EINTR` (EOF included) ends the block.
                let n = unsafe { libc::read(block_r, (&raw mut sink).cast(), 1) };
                if n != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
            exit_child(0);
        }
    });
    let l_pid = l.pid() as libc::pid_t;

    raw_close(rendezvous_l);
    raw_close(m_ready_w);
    raw_close(block_r);
    // Build the fixture before anything can panic: fds close (unblocking L/M) and `l` kills and
    // reaps L on any unwind.
    // SAFETY: each fd came from this process's own successful `socketpair`/`pipe` call above and
    // has not been closed since.
    let mut fixture = unsafe {
        ReapedLeaderFixture {
            rendezvous_test: OwnedFd::from_raw_fd(rendezvous_test),
            block_w: OwnedFd::from_raw_fd(block_w),
            m_ready_r: OwnedFd::from_raw_fd(m_ready_r),
            l: Some(l),
            m_pid: 0,
            lock,
        }
    };

    if matches!(FORCE_PANIC.with(Cell::get), PanicSeam::Armed) {
        FORCE_PANIC.with(|f| f.set(PanicSeam::Fired { l_pid }));
        panic!("forced panic mid-handshake (test seam)");
    }

    let mut ready = 0u8;
    match read_some(fixture.rendezvous_test.as_raw_fd(), std::slice::from_mut(&mut ready)) {
        1 => {}
        0 => {
            let status = wait_status(fixture.l.take().expect("L is still guarded").defuse() as libc::pid_t);
            return Err(FixtureError::LExited { status });
        }
        n => panic!("read L's ready byte: n={n} err={}", std::io::Error::last_os_error()),
    }

    let l_id = ProcessId::of(l_pid as u32)
        .found()
        .expect("L's identity resolves while L is alive and blocked on the rendezvous socket");

    // SAFETY: the fd is open (owned by the fixture); the buffer is a valid 1-byte slice.
    let wrote = unsafe { libc::write(fixture.rendezvous_test.as_raw_fd(), b"R".as_ptr().cast(), 1) };
    assert_eq!(wrote, 1, "release L: {}", std::io::Error::last_os_error());

    // Reap L on a real exit event, removing it from this process's child table while M lives on.
    let status = wait_status(fixture.l.take().expect("L is still guarded").defuse() as libc::pid_t);
    if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
        return Err(FixtureError::LExited { status });
    }

    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match read_some(fixture.m_ready_r.as_raw_fd(), &mut byte) {
            1 if byte[0] == b'\n' => break,
            1 => line.push(byte[0]),
            0 => return Err(FixtureError::MExited),
            n => panic!("read M's ready line: n={n} err={}", std::io::Error::last_os_error()),
        }
    }
    fixture.m_pid = std::str::from_utf8(&line)
        .expect("M's pid is ASCII")
        .parse()
        .expect("M's pid is a plain decimal number");

    Ok((l_id, fixture))
}
