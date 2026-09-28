//! Unit tests for the pidfd `EINVAL`/`ENOENT` ambiguity `open_verified` resolves via
//! `id.exists()` — see that function's own doc for the full kernel-version detail. This file
//! covers the REAPED-GROUP-LEADER case; the LIVE-NON-LEADER-TID sibling lives in
//! `tests/linux_pidfd_wait.rs` (an ordinary spawned child works there — this case instead needs
//! a raw `fork()` tree whose direct parent is the process that reaps the leader, which only a
//! unit test forking itself can arrange).
//!
//! The forked children below run ONLY async-signal-safe operations — raw `libc`
//! read/write/fork/setpgid/_exit calls, no allocation, no panics — the same restriction
//! `containment::cgroup::test_support::fork_running`'s own doc states for a fork out of this
//! multithreaded test binary. `M`'s fork (from `L`, itself already a single-threaded, freshly
//! forked process) carries none of that hazard, but keeps the same discipline for consistency.

use crate::identity::{Existence, ProcessId};

/// Create a pipe, returning raw `(read_fd, write_fd)` — `fork()` below duplicates the whole fd
/// table regardless of close-on-exec, and neither `L` nor `M` ever `exec`s, so the flag makes no
/// difference here; `std::io::pipe()` (rather than the close-on-exec-less `libc::pipe`, this
/// crate's own `clippy.toml` disallows it) is simply the least-ceremony atomic constructor.
fn raw_pipe() -> (i32, i32) {
    use std::os::fd::IntoRawFd;
    let (r, w) = std::io::pipe().expect("pipe");
    (r.into_raw_fd(), w.into_raw_fd())
}

/// Close `fd`. Async-signal-safe.
fn raw_close(fd: i32) {
    // SAFETY: `fd` is a descriptor this process owns, either opened directly or inherited
    // across `fork` (which duplicates the whole table) — closing this process's own copy never
    // affects another process's.
    unsafe { libc::close(fd) };
}

/// Write exactly one byte to `fd`, retrying `EINTR` (no cap — this crate's convention for every
/// blocking syscall). Async-signal-safe: exits with a distinct code instead of panicking, since
/// this runs in a forked, pre-`_exit` child that must never unwind.
fn raw_write_byte_or_exit(fd: i32, byte: u8, exit_code_on_failure: i32) {
    loop {
        // SAFETY: `fd` is open and writable; `byte` is a valid 1-byte buffer.
        let n = unsafe { libc::write(fd, (&raw const byte).cast(), 1) };
        if n == 1 {
            return;
        }
        if n == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        // SAFETY: async-signal-safe.
        unsafe { libc::_exit(exit_code_on_failure) };
    }
}

/// Read exactly one byte from `fd`, retrying `EINTR`. Async-signal-safe (see
/// [`raw_write_byte_or_exit`]).
fn raw_read_byte_or_exit(fd: i32, exit_code_on_failure: i32) {
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
        // SAFETY: async-signal-safe.
        unsafe { libc::_exit(exit_code_on_failure) };
    }
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

/// The reaped-leader half of the `EINVAL`/`ENOENT` ambiguity: a process-group leader `L` calls
/// `setpgid(0, 0)` and forks a member `M` that stays in `L`'s group and blocks on a pipe this
/// test holds; `L` then exits and is reaped by ITS parent — this test process, which forked `L`
/// directly. While `M` is alive, `L`'s former pid number's `struct pid` stays alive as the
/// group's PGID even though no THREAD-GROUP-LEADER task is attached to it anymore — the exact
/// shape `pidfd_open` answers `EINVAL` (< Linux 6.16) or `ESRCH` (>= 6.16, commit 8cf4b738) to.
///
/// On a >= 6.16 CI kernel, `pidfd_open` already answers `ESRCH` for `L`'s pid, which
/// `open_verified`'s pre-existing `SRCH` arm already turns into "exited" — this test then
/// passes without ever reaching the `INVAL`/`NOENT` arm this fix adds. That's fine: the
/// assertion (`block_until_exit` reports exited, not `Err`) is the same claim on both kernel
/// generations, and the test is never skipped either way.
///
/// Mutant: "no exists() fallback" — reverting `open_verified`'s `INVAL`/`NOENT` arm to a bare
/// `Err(Error::Io(..))` (its neighboring, catch-all arm) makes this test fail on a < 6.16 kernel
/// with `Err` (EINVAL) instead of `Ok(true)`.
#[test]
fn block_until_exit_reports_exited_for_a_reaped_pgid_leader() {
    // Held for both forks below — see this file's module doc.
    let _guard = crate::child::spawn::spawn_lock();

    // `rendezvous`: a bidirectional handshake with L. L reports "group set up, about to block"
    // over its end; the test then reads L's identity while L is provably still alive (blocked
    // on its own read of the very same socket), and releases it to proceed. `m_ready`: M
    // reports "alive, closed my copy of `block`'s write end, about to block" — read by the test
    // before it calls `block_until_exit`, so the leader-reaped/member-alive precondition is an
    // observed fact, not an assumption. `block`: the pipe M blocks reading; the test holds the
    // write end and closes it (EOF) during cleanup — never a process-group signal.
    let mut rendezvous = [-1i32; 2];
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
        raw_close(rendezvous_test);
        raw_close(m_ready_r);
        // Becomes its own group's leader; M inherits this group at its own fork, below.
        if unsafe { libc::setpgid(0, 0) } != 0 {
            unsafe { libc::_exit(122) };
        }
        // Report ready, then block for the test's release — so the test never reads L's
        // identity while L might already have exited.
        raw_write_byte_or_exit(rendezvous_l, b'R', 123);
        raw_read_byte_or_exit(rendezvous_l, 124);

        let m_pid = unsafe { libc::fork() };
        if m_pid == -1 {
            unsafe { libc::_exit(125) };
        }
        if m_pid == 0 {
            // === M === stays in L's group (inherited pgid; no `setpgid` call of its own).
            raw_close(rendezvous_l);
            raw_close(block_w); // else M's OWN copy would keep `block` from ever EOF-ing
            raw_write_byte_or_exit(m_ready_w, b'R', 126);
            raw_close(m_ready_w);
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

    // Block until L reports its group is set up and it is now blocked awaiting release — only
    // then is reading L's identity race-free (L cannot have exited yet).
    let mut ready = 0u8;
    retry_eintr_one_byte(
        || unsafe { libc::read(rendezvous_test, (&raw mut ready).cast(), 1) },
        "read L's ready byte",
    );

    let l_id = ProcessId::of(l_pid as u32)
        .found()
        .expect("L's identity resolves while L is still alive and blocked on the rendezvous socket");

    // Release L: it forks M, then exits.
    let release_byte = b'R';
    retry_eintr_one_byte(
        || unsafe { libc::write(rendezvous_test, (&raw const release_byte).cast(), 1) },
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

    // Block until M reports alive (and past closing its own copy of `block`'s write end) —
    // confirms the "leader reaped, member alive, same group" precondition is real before calling
    // `block_until_exit`, and that this test's own cleanup close below can actually reach M as
    // EOF (not held open by a second, forgotten copy of the write end).
    retry_eintr_one_byte(
        || unsafe { libc::read(m_ready_r, (&raw mut ready).cast(), 1) },
        "read M's ready byte",
    );

    // L is reaped; M is alive, in L's former group, still holding that pid number as its PGID.
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

    // Cleanup: EOF M via the pipe, never a process-group signal. Whichever process M reparented
    // to when L exited (not this test) reaps it.
    raw_close(block_w);
    raw_close(m_ready_r);
    raw_close(rendezvous_test);
}
