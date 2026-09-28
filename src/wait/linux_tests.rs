//! Unit tests for the pidfd `EINVAL`/`ENOENT` ambiguity `open_verified` resolves via
//! `id.exists()` — see that function's own doc for the full kernel-version detail. This file
//! covers the REAPED-GROUP-LEADER case; the LIVE-NON-LEADER-TID sibling's real-syscall test
//! lives in `tests/linux_pidfd_wait.rs` (an ordinary spawned child works there — this case
//! instead needs a raw `fork()` tree whose direct parent is the process that reaps the leader,
//! which only a unit test forking itself can arrange).
//!
//! Every scenario here has TWO tests: a real-syscall one (whatever the host kernel actually
//! produces) and a forced-errno twin (`fault::force_pidfd_open_errno_once`) that drives
//! `open_verified`'s `EINVAL`/`ENOENT` arm deterministically. Both matter: on a >= 6.16 CI
//! kernel, `pidfd_open` answers `ESRCH` for a reaped leader — the pre-existing arm this PR
//! never touches — so the real-syscall reaped-leader test passes without ever reaching the
//! changed code (measured: GitHub's own `ubuntu-latest`/`ubuntu-24.04-arm` runners are on
//! `6.17.0-1022-azure`). Only the forced-`EINVAL` twin actually exercises the new arm on such a
//! kernel, and is what makes mutant A ("no exists() fallback") observably red in THIS
//! container, independent of the host kernel.
//!
//! The forked children below run ONLY async-signal-safe operations — raw `libc`
//! read/write/fork/setpgid/close_range/_exit calls, no allocation, no panics — the same
//! restriction `containment::cgroup::test_support::fork_running`'s own doc states for a fork
//! out of this multithreaded test binary. `M`'s fork (from `L`, itself already a
//! single-threaded, freshly forked process) carries none of that hazard, but keeps the same
//! discipline for consistency.

use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use crate::identity::{Existence, ProcessId};

// Raw, async-signal-safe helpers ======================================================

/// Create a pipe, returning raw `(read_fd, write_fd)` — `fork()` below duplicates the whole fd
/// table regardless of close-on-exec, and neither `L` nor `M` ever `exec`s, so the flag makes no
/// difference here; `std::io::pipe()` (rather than the close-on-exec-less `libc::pipe`, this
/// crate's own `clippy.toml` disallows it) is simply the least-ceremony atomic constructor.
fn raw_pipe() -> (RawFd, RawFd) {
    let (r, w) = std::io::pipe().expect("pipe");
    (r.into_raw_fd(), w.into_raw_fd())
}

/// Close `fd`. Async-signal-safe.
fn raw_close(fd: RawFd) {
    // SAFETY: `fd` is a descriptor this process owns, either opened directly or inherited
    // across `fork` (which duplicates the whole table) — closing this process's own copy never
    // affects another process's.
    unsafe { libc::close(fd) };
}

/// Write all of `bytes` to `fd`, retrying `EINTR` and partial writes (no cap — this crate's
/// convention for every blocking syscall). Async-signal-safe: exits with a distinct code
/// instead of panicking, since this runs in a forked, pre-`_exit` child that must never unwind.
fn raw_write_all_or_exit(fd: RawFd, mut bytes: &[u8], exit_code_on_failure: i32) {
    while !bytes.is_empty() {
        // SAFETY: `fd` is open and writable; `bytes` is a valid buffer of its own length.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n > 0 {
            bytes = &bytes[n as usize..];
            continue;
        }
        if n == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        // SAFETY: async-signal-safe.
        unsafe { libc::_exit(exit_code_on_failure) };
    }
}

/// Read exactly one byte from `fd`, retrying `EINTR`. Async-signal-safe (see
/// [`raw_write_all_or_exit`]).
fn raw_read_byte_or_exit(fd: RawFd, exit_code_on_failure: i32) {
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
        // SAFETY: async-signal-safe. Covers EOF (n == 0) too: if the test's end of this pipe
        // closed (it panicked before releasing us), there is nothing left to wait for.
        unsafe { libc::_exit(exit_code_on_failure) };
    }
}

/// Format `n` as ASCII decimal digits into `buf` (a `pid_t`/`u32` never needs more than 10),
/// returning the filled suffix. No allocation — safe to call in a forked, pre-`_exit` child.
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

/// Close every open fd in this process except those in `keep` (sorted ascending, duplicate-free)
/// — one `close_range(2)` syscall (Linux 5.9+) per gap between kept fds, covering `[0, keep[0])`,
/// each `(keep[i], keep[i+1])`, and `(keep.last(), MAX]`. Async-signal-safe: no allocation beyond
/// the caller-provided slice.
///
/// Run right after EACH of this file's two `fork()`s, before anything else: `spawn_lock()`
/// (held across both) only serializes this test's OWN forks against each other — it says
/// nothing about fds a CONCURRENTLY running sibling test already had open (its own control
/// socket, say) at the moment either fork snapshotted this process's whole fd table. Left
/// open, such a duplicate could let `L` or `M` — long-lived past this test's own return, if a
/// bug left either an orphan — pin that unrelated fd and hang whatever test owns it. The same
/// hazard `test_child.rs`'s `spawn_a_process_that_exits` doc and `spawn_lock()` itself guard
/// against, for the window `spawn_lock()` alone cannot close.
fn close_range_except_or_exit(keep: &[RawFd], exit_code_on_failure: i32) {
    let close_gap = |first: RawFd, last: RawFd| {
        if first > last {
            return;
        }
        // SAFETY: close_range(2), no flags; `first <= last` so the range is non-empty, and an
        // fd number is never negative once cast to u32 here (both bounds are >= 0 by
        // construction below).
        let rc = unsafe { libc::syscall(libc::SYS_close_range, first as u32, last as u32, 0) };
        if rc != 0 {
            // SAFETY: async-signal-safe.
            unsafe { libc::_exit(exit_code_on_failure) };
        }
    };
    let mut prev_end: RawFd = -1; // "before" fd 0
    for &fd in keep {
        close_gap(prev_end + 1, fd - 1);
        prev_end = fd;
    }
    close_gap(prev_end + 1, RawFd::MAX);
}

// Test-side fixture ====================================================================

/// Reaps `L` — this fixture's direct fork — on drop, unless [`defuse`](Self::defuse)d after an
/// explicit reap already happened. See [`ReapedLeaderFixture`]'s field order for why this is
/// always the LAST field dropped: by the time it runs, `L` is expected to already be exiting
/// (or exited), via the rendezvous socket's or `block`'s own EOF — this wait is bounded by
/// that, not by anything this guard does itself. Reaping is a plain `waitpid` by bare pid, not
/// a pidfd: `L` is this process's own unreaped child for as long as this guard is armed, which
/// is exactly the "unreaped child" exception principle 4 (`docs/principles.md`) documents.
/// Mirrors `fork_running`'s `KillOnDrop` (`containment/cgroup/test_support.rs`, #208) in shape,
/// minus the kill: nothing here needs to SIGNAL `L`, only wait for it.
struct ReapL {
    pid: libc::pid_t,
    armed: bool,
}

impl ReapL {
    /// The explicit, successful reap already happened; `Drop` becomes a no-op.
    fn defuse(&mut self) {
        self.armed = false;
    }
}

impl Drop for ReapL {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut status = 0;
        loop {
            // SAFETY: `self.pid` is this process's own child, unreaped for as long as `armed`.
            let r = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if r != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                break;
            }
        }
    }
}

/// Every test-owned resource for the reaped-leader fixture, in the exact field order teardown
/// needs: earlier fields unblock `L`/`M` via EOF, so by the time the last field's `Drop` runs
/// (waiting for `L`), both are already exiting — never an unbounded wait. Built by
/// [`build_reaped_pgid_leader`]; a passing test additionally calls
/// [`release_and_confirm_m_exited`](Self::release_and_confirm_m_exited) to observe the same
/// teardown as a real event instead of only relying on `Drop`.
struct ReapedLeaderFixture {
    /// Closed FIRST: if `L` is still blocked reading its own end of this socket (the test
    /// panicked before releasing it), `L`'s blocking read returns EOF and it `_exit`s
    /// immediately — see [`raw_read_byte_or_exit`] — instead of orphaning forever. Never read
    /// by name once stored here: only its `Drop` (closing the fd) matters.
    #[allow(dead_code, reason = "held only for its Drop; the fd close is the point")]
    rendezvous_test: OwnedFd,
    /// Closed SECOND: the write end `M` blocks reading until EOF. `M` already closed its own
    /// inherited copy right after being forked (its own `close_range_except_or_exit` keep-list
    /// excludes it), so this is the LAST open copy — closing it is what makes `M`'s blocking
    /// read return.
    block_w: OwnedFd,
    /// Closed THIRD: this process's own read end of `M`'s readiness/exit-observed pipe. Purely
    /// fd hygiene in the test process itself; `M` never observes this closing.
    m_ready_r: OwnedFd,
    /// Reaps `L` LAST — see [`ReapL`]'s own doc for why that ordering makes its wait bounded.
    /// Never read by name once stored here: only its `Drop` matters.
    #[allow(dead_code, reason = "held only for its Drop; the reap is the point")]
    reap_l: ReapL,
    /// `M`'s pid, for a caller that independently verifies `M`'s own death (e.g. under a forced
    /// panic — `M` is not this test's own child, so a pidfd, not `waitid`, is how).
    m_pid: libc::pid_t,
}

impl ReapedLeaderFixture {
    /// Release `M` (EOF on `block`) and block until this process OBSERVES `M`'s own exit (EOF
    /// on `m_ready`, which `M` never closes itself — see [`build_reaped_pgid_leader`]) — a real
    /// event, never inferred from "M was about to block". Consumes the fixture: `reap_l` (a
    /// no-op — [`build_reaped_pgid_leader`] already reaped `L` explicitly and defused it) and
    /// the rest drop normally afterward.
    fn release_and_confirm_m_exited(self) {
        let m_ready_r_fd = self.m_ready_r.as_raw_fd();
        drop(self.block_w); // EOF releases M
        let mut buf = [0u8; 1];
        loop {
            // SAFETY: `m_ready_r_fd` is open — owned by `self.m_ready_r`, alive until this
            // function returns.
            let n = unsafe { libc::read(m_ready_r_fd, buf.as_mut_ptr().cast(), 1) };
            if n == 0 {
                return; // EOF — M is gone
            }
            if n == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            panic!("expected EOF on m_ready (M's exit) after releasing M, got n={n}");
        }
    }
}

/// The reaped-leader half of the `EINVAL`/`ENOENT` ambiguity: a process-group leader `L` calls
/// `setpgid(0, 0)` and forks a member `M` that stays in `L`'s group and blocks on a pipe this
/// test holds; `L` then exits and is reaped by ITS parent — this test process, which forked `L`
/// directly. While `M` is alive, `L`'s former pid number's `struct pid` stays alive as the
/// group's PGID even though no THREAD-GROUP-LEADER task is attached to it anymore — the exact
/// shape `pidfd_open` answers `EINVAL` (< Linux 6.16) or `ESRCH` (>= 6.16, commit 8cf4b738) to.
///
/// Returns `L`'s identity (already confirmed [`Existence::Gone`] would read — callers still
/// assert it themselves, since that assertion IS part of what each test is proving) and the
/// fixture guarding `M`/`L`'s teardown.
fn build_reaped_pgid_leader() -> (ProcessId, ReapedLeaderFixture) {
    // `rendezvous`: a bidirectional handshake with L. L reports "group set up, about to block"
    // over its end; the test then reads L's identity while L is provably still alive (blocked
    // on its own read of the very same socket), and releases it to proceed. `m_ready`: M
    // reports "alive, closed my copy of `block`'s write end, about to block" (with its own pid)
    // — read by the test before it calls `block_until_exit`, so the leader-reaped/member-alive
    // precondition is an observed fact, not an assumption. `M` keeps `m_ready`'s write end open
    // for its whole life (closed only by the kernel, at `M`'s own `_exit`) so a later EOF on it
    // is proof `M` exited, not merely "was about to". `block`: the pipe M blocks reading; the
    // test holds the write end and closes it (EOF) during cleanup — never a process-group
    // signal.
    let mut rendezvous = [-1 as RawFd; 2];
    // SAFETY: `rendezvous` is a valid, writable 2-element array; `AF_UNIX`/`SOCK_STREAM` need no
    // further setup.
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, rendezvous.as_mut_ptr()) },
        0,
        "socketpair: {}",
        std::io::Error::last_os_error()
    );
    let (rendezvous_test, rendezvous_l) = (rendezvous[0], rendezvous[1]);
    let (m_ready_r, m_ready_w) = raw_pipe();
    let (block_r, block_w) = raw_pipe();

    // SAFETY: the forked child (L, and the M it goes on to fork) runs ONLY the async-signal-safe
    // operations in the `0` arm below, always ending in `_exit` — no unwinding, no allocation,
    // no destructors run.
    let l_pid = unsafe { libc::fork() };
    assert_ne!(l_pid, -1, "fork L: {}", std::io::Error::last_os_error());

    if l_pid == 0 {
        // === L ===
        // Drop every fd this process happened to inherit except the four it (or M, via a
        // second fork) needs — see close_range_except_or_exit's own doc for why.
        let mut keep = [rendezvous_l, block_r, block_w, m_ready_w];
        keep.sort_unstable();
        close_range_except_or_exit(&keep, 120);
        // Becomes its own group's leader; M inherits this group at its own fork, below.
        if unsafe { libc::setpgid(0, 0) } != 0 {
            unsafe { libc::_exit(121) };
        }
        // Report ready, then block for the test's release — so the test never reads L's
        // identity while L might already have exited.
        raw_write_all_or_exit(rendezvous_l, b"R", 122);
        raw_read_byte_or_exit(rendezvous_l, 123);

        let m_pid = unsafe { libc::fork() };
        if m_pid == -1 {
            unsafe { libc::_exit(124) };
        }
        if m_pid == 0 {
            // === M === stays in L's group (inherited pgid; no `setpgid` call of its own).
            // block_w is NOT in this keep-list: M must never hold its own copy of the write end
            // `block` — that copy would keep `block` from ever EOF-ing once the test closes ITS
            // copy. m_ready_r isn't needed either — M only writes m_ready.
            let mut keep = [block_r, m_ready_w];
            keep.sort_unstable();
            close_range_except_or_exit(&keep, 125);

            // SAFETY: getpid has no preconditions.
            let pid = unsafe { libc::getpid() } as u32;
            let mut digits = [0u8; 10];
            let text = write_decimal(pid, &mut digits);
            raw_write_all_or_exit(m_ready_w, text, 126);
            raw_write_all_or_exit(m_ready_w, b"\n", 126);
            // m_ready_w stays open (not closed here) until the kernel closes it at `_exit`
            // below — that is the EOF `release_and_confirm_m_exited` waits for.
            let mut sink = 0u8;
            loop {
                // SAFETY: `block_r` is open; `sink` is a valid 1-byte buffer. Any return other
                // than `EINTR` (EOF included) ends the block.
                let n = unsafe { libc::read(block_r, (&raw mut sink).cast(), 1) };
                if n != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
            unsafe { libc::_exit(0) };
        }
        // === L, after forking M === exits immediately; this test process (L's direct parent)
        // reaps it next.
        unsafe { libc::_exit(0) };
    }

    // === test process ===
    raw_close(rendezvous_l);
    raw_close(m_ready_w);
    raw_close(block_r);
    // SAFETY: each fd was just returned by this process's own successful `socketpair`/`pipe`
    // call above and has not been closed since.
    let rendezvous_test = unsafe { OwnedFd::from_raw_fd(rendezvous_test) };
    let block_w = unsafe { OwnedFd::from_raw_fd(block_w) };
    let m_ready_r = unsafe { OwnedFd::from_raw_fd(m_ready_r) };
    let mut reap_l = ReapL {
        pid: l_pid,
        armed: true,
    };

    // Block until L reports its group is set up and it is now blocked awaiting release — only
    // then is reading L's identity race-free (L cannot have exited yet).
    let mut ready = 0u8;
    retry_eintr_one_byte(
        || unsafe { libc::read(rendezvous_test.as_raw_fd(), (&raw mut ready).cast(), 1) },
        "read L's ready byte",
    );

    let l_id = ProcessId::of(l_pid as u32)
        .found()
        .expect("L's identity resolves while L is still alive and blocked on the rendezvous socket");

    // Release L: it forks M, then exits.
    let release_byte = b'R';
    retry_eintr_one_byte(
        || unsafe { libc::write(rendezvous_test.as_raw_fd(), (&raw const release_byte).cast(), 1) },
        "release L",
    );

    // Reap L — a real exit event, never a timer — removing it from this process's own child
    // table while M (which does not share this parent) lives on.
    let mut status = 0;
    let reaped = loop {
        // SAFETY: `l_pid` is this process's own direct child; `status` is a valid out-param.
        let r = unsafe { libc::waitpid(l_pid, &mut status, 0) };
        if r != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break r;
        }
    };
    assert_eq!(reaped, l_pid, "waitpid(L): {}", std::io::Error::last_os_error());
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "L must have exited 0, got raw status {status:#x}"
    );
    reap_l.defuse(); // already reaped above; the guard's own Drop becomes a no-op

    // Block until M reports alive (and past closing its own copy of `block`'s write end) —
    // confirms the "leader reaped, member alive, same group" precondition is real before the
    // caller does anything with `l_id`, and reads M's own pid off the same line.
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        // SAFETY: `m_ready_r` is open; `byte` is a valid 1-byte buffer.
        let n = unsafe { libc::read(m_ready_r.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
        assert_eq!(n, 1, "read M's ready line: {}", std::io::Error::last_os_error());
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    let m_pid: libc::pid_t = std::str::from_utf8(&line)
        .expect("M's pid is ASCII")
        .parse()
        .expect("M's pid is a plain decimal number");

    (
        l_id,
        ReapedLeaderFixture {
            rendezvous_test,
            block_w,
            m_ready_r,
            reap_l,
            m_pid,
        },
    )
}

/// Retry a blocking one-byte `read`/`write` across `EINTR` (no cap) in THIS, the test process —
/// panicking (not `_exit`ing) is fine here, unlike the forked-child helpers above.
fn retry_eintr_one_byte(mut op: impl FnMut() -> isize, what: &str) {
    loop {
        let n = op();
        if n == 1 {
            return;
        }
        let e = std::io::Error::last_os_error();
        if n == -1 && e.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        panic!("{what}: n={n} err={e}");
    }
}

// Tests =================================================================================

/// Mutant: "no exists() fallback" — reverting `open_verified`'s `INVAL`/`NOENT` arm to a bare
/// `Err(Error::Io(..))` (its neighboring, catch-all arm) makes this test fail on a < 6.16
/// kernel with `Err` (EINVAL) instead of `Ok(true)`.
///
/// On a >= 6.16 CI kernel, `pidfd_open` already answers `ESRCH` for `L`'s pid, which
/// `open_verified`'s pre-existing `SRCH` arm already turns into "exited" — this test then
/// passes without ever reaching the `INVAL`/`NOENT` arm this fix adds. That's fine: the
/// assertion (`block_until_exit` reports exited, not `Err`) is the same claim on both kernel
/// generations. [`block_until_exit_reports_exited_for_a_reaped_pgid_leader_with_forced_einval`]
/// is this test's deterministic twin, which DOES exercise the new arm regardless of kernel.
#[test]
fn block_until_exit_reports_exited_for_a_reaped_pgid_leader() {
    let _guard = crate::child::spawn::spawn_lock();
    let (l_id, fixture) = build_reaped_pgid_leader();
    assert_eq!(
        l_id.exists(),
        Existence::Gone,
        "a reaped leader must read Gone even while its pid number stays a live PGID"
    );

    let result = super::block_until_exit(l_id, None);
    assert!(
        matches!(result, Ok(true)),
        "block_until_exit on a reaped group leader whose group lives on must report exited \
         (Ok(true)), not {result:?}"
    );

    fixture.release_and_confirm_m_exited();
}

/// Deterministic twin of the test above: same fixture, but `pidfd_open`'s result is forced to
/// `EINVAL` instead of trusted to the host kernel, so this exercises `open_verified`'s new
/// `INVAL`/`NOENT` arm on every kernel, including a >= 6.16 one where the real syscall would
/// have taken the pre-existing `ESRCH` arm instead (see this file's module doc).
///
/// Mutant: "no exists() fallback" (same as the real-syscall test — this is the twin that
/// actually shows it red in a container whose kernel is already >= 6.16).
#[test]
fn block_until_exit_reports_exited_for_a_reaped_pgid_leader_with_forced_einval() {
    let _guard = crate::child::spawn::spawn_lock();
    let (l_id, fixture) = build_reaped_pgid_leader();
    assert_eq!(
        l_id.exists(),
        Existence::Gone,
        "a reaped leader must read Gone even while its pid number stays a live PGID"
    );

    let forced = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::INVAL);
    let result = super::block_until_exit(l_id, None);
    drop(forced);
    assert!(
        matches!(result, Ok(true)),
        "a forced EINVAL on a reaped group leader whose group lives on must report exited \
         (Ok(true)), not {result:?}"
    );

    fixture.release_and_confirm_m_exited();
}

/// Mutant: "treat EINVAL/ENOENT as gone without the exists() check" — unconditionally reading
/// `EINVAL`/`ENOENT` as "gone" (skipping the `exists()` re-verify) makes this test fail: a
/// forced `ENOENT` against a LIVE non-leader tid would then report `Ok(())` instead of the
/// required `Err`. Forces `ENOENT` specifically (rather than relying on the host kernel, which
/// gives `EINVAL` before 6.16 for the same scenario) so this passes on every kernel — see this
/// file's module doc.
#[test]
fn block_until_exit_on_a_live_non_leader_tid_is_an_error_with_forced_enoent() {
    use std::sync::mpsc;

    let (tid_tx, tid_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        // SAFETY: SYS_gettid takes no arguments and always succeeds.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
        tid_tx.send(tid).expect("send tid to the test thread");
        let _ = stop_rx.recv(); // block until the test releases us
    });
    let tid = tid_rx.recv().expect("recv tid from the worker thread");
    let id = ProcessId::of(tid as u32)
        .found()
        .expect("the live worker thread's tid resolves to an identity");
    assert_ne!(
        id.pid(),
        std::process::id(),
        "the tid must not be this process's own thread-group leader pid"
    );

    let forced = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::NOENT);
    let result = super::block_until_exit(id, None);
    drop(forced);
    match result {
        Err(crate::error::Error::Io(e)) => {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::InvalidInput,
                "wrong error kind for a live non-leader tid: {e}"
            );
            assert!(
                e.to_string().contains("not a thread-group leader"),
                "the error must name the real cause, got: {e}"
            );
        }
        other => panic!("a forced ENOENT on a live non-leader tid must be a descriptive Io error, got {other:?}"),
    }

    let _ = stop_tx.send(());
    worker.join().expect("join the worker thread");
}

/// Stress check for the fixture's own cleanup guards: a panic between building the fixture and
/// releasing it must still tear down both `L` and `M` — no survivor. `catch_unwind`, not a
/// subprocess: the fixture's `Drop` must run on THIS thread's unwind, the exact path a real
/// assertion failure mid-test takes. Verified independently of the fixture's own teardown
/// machinery: a pidfd opened on `M`'s pid while it is confirmedly still alive (just before the
/// forced panic) is polled AFTER the panic unwinds and the fixture drops; `POLLIN` (`M` became
/// a zombie or was reaped by whatever process it reparented to) proves `M` is gone. Mirrors
/// `fork_running`'s own `a_panic_after_fork_running_still_reaps_the_child`
/// (`containment/cgroup/test_support_tests.rs`, #208).
#[test]
fn a_panic_before_release_still_tears_down_l_and_m() {
    let _guard = crate::child::spawn::spawn_lock();
    let probe: std::cell::RefCell<Option<rustix::fd::OwnedFd>> = std::cell::RefCell::new(None);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (_l_id, fixture) = build_reaped_pgid_leader();
        let m_pid = rustix::process::Pid::from_raw(fixture.m_pid).expect("M's pid is positive");
        *probe.borrow_mut() = Some(
            rustix::process::pidfd_open(m_pid, rustix::process::PidfdFlags::empty()).expect("open a probe pidfd on M"),
        );
        panic!("forced panic between building the fixture and releasing it");
        // `fixture` drops here, during unwind: rendezvous_test then block_w then m_ready_r
        // close (EOFing L if it's somehow still blocked, and M), then reap_l waits for L.
    }));
    assert!(unwound.is_err(), "the forced panic must actually unwind");

    let probe = probe.into_inner().expect("the probe pidfd was opened before the panic");
    // Block until M is provably gone (zombie or reaped) — a real kernel event, no timeout: if
    // the cleanup regresses and M survives, this hangs, bounded by nextest's own suite-level
    // timeout (docs/principles.md #8) — the same idiom test_support_tests.rs uses for a
    // structurally identical check.
    let mut fds = [rustix::event::PollFd::new(&probe, rustix::event::PollFlags::IN)];
    rustix::event::poll(&mut fds, None).expect("poll the probe pidfd");
    assert!(
        fds[0].revents().contains(rustix::event::PollFlags::IN),
        "M must have exited (or been reaped) once the panicking fixture unwound and dropped"
    );
}
