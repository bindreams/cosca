//! Unit tests for the macOS marker EOF edge. In the library because the primitive is
//! `pub(crate)`. Nothing here sleeps: every "the tree drained" event is caused by closing a
//! descriptor a child is blocked on, and every "the tree has not drained" assertion is a
//! ZERO-deadline check, which is exact rather than timed. Where a deadline needs to be seen as
//! ELAPSED without waiting for real time to pass, a `#[cfg(test)]` frozen mock clock
//! (`crate::wait::test_clock::FrozenClockGuard`) is advanced directly instead — see
//! `a_sustained_writer_is_checked_against_the_deadline_every_round`. Where "genuinely blocked,
//! not busy-polling" needs proof, it comes from counting the real `kevent` syscalls
//! `block_on_kqueue` issued (`crate::wait::backend::test_hooks::kevent_calls`), not from
//! sampling CPU time over a fixed wall-clock window. Every test that installs a round hook does
//! so through `test_hooks::HookGuard`, which resets the hook and every counter on `Drop` —
//! including on a panic mid-test, e.g. from a hook's own `assert!` — so one test's seam state
//! can never leak into whatever runs on this thread next.
//!
//! Every test that opens a `marker_pipe()` write end holds `test_spawn_lock()` for its WHOLE
//! body, whether or not that test itself spawns — the same rule `fdmarker_tests.rs` documents:
//! a sibling test's `fork()` elsewhere in this shared, parallel test binary can land while THIS
//! test's write end happens to be open, transiently inheriting a duplicate into a not-yet-`exec`ed
//! child (CLOEXEC only closes it AT exec, not at fork), which then reads as an extra holder and
//! delays the EOF this module exists to detect. `test_spawn_lock()` is `spawn_lock()` itself, not
//! a private mutex, because `crate::Command::spawn()` already takes it on macOS around its own
//! fork+exec — reusing it serializes against every cosca-originated spawn in this binary, not
//! just the ones in this file.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

use super::{block_until_drained, probe};
use crate::containment::TreeDrain;

fn test_spawn_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::child::spawn::spawn_lock()
}

/// A marker pipe: `(read_end, write_end)`, both owned by this process. Built with
/// `std::io::pipe()` (CLOEXEC by default, matching `fdmarker::create_pipe`'s own convention) —
/// NOT `nix::unistd::pipe()` (raw POSIX semantics, not CLOEXEC) — because under a plain `cargo
/// test --lib`, which runs every test in this crate in one shared process, tests run concurrently
/// on separate threads of that process, and a non-CLOEXEC test pipe fd would be inherited by any
/// OTHER concurrently-running test's spawned child, keeping that child a spurious extra "holder"
/// of a pipe this test never intended to share.
fn marker_pipe() -> (OwnedFd, OwnedFd) {
    let (r, w) = std::io::pipe().expect("pipe");
    (OwnedFd::from(r), OwnedFd::from(w))
}

/// A fd number NEVER allocated in this process: using it instead of a real,
/// just-closed fd means these tests cannot race a concurrently-running test that reuses a
/// freed number, and its errno (EBADF) was independently reproduced multiple times, unlike a
/// freshly-closed-then-reused fd's (EINVAL — a different, not-useful-here path).
fn never_allocated_fd() -> BorrowedFd<'static> {
    // SAFETY: this fd number is never used for I/O by this process (nothing opens a million
    // descriptors in a unit test), so it stays unallocated for the lifetime of the borrow;
    // every call through it is expected to fail with EBADF, which is exactly what's tested.
    unsafe { BorrowedFd::borrow_raw(1_000_000) }
}

/// A live tree member: `/bin/sh` holding the marker on fd 3 and blocked on stdin, so a test
/// ends it by closing a descriptor rather than by timing anything. Returns the owned child,
/// the marker read end, and the stdin write end whose close makes it exit.
///
/// Deliberately used even by tests below that just want "the write end is open, held by
/// SOMETHING that isn't me": once `refuse_if_write_end_held` is added to `arm`, a bare second
/// in-process fd (as plain `marker_pipe()` would give) is indistinguishable from the exact
/// supervisor bug the guard exists to catch, and would make `arm`/`probe` refuse rather
/// than report `MembersRemain`. A real holder in ANOTHER process is what "the write end is
/// open" is supposed to mean here.
fn spawn_marker_holder(script: &str) -> (crate::Child, std::io::PipeReader, std::io::PipeWriter) {
    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh").args(["sh", "-c", script]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    let mut child = cmd.spawn().expect("spawn /bin/sh");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    let stdin = child.fd_write_end(crate::Fd::STDIN).expect("stdin write end");
    (child, marker, stdin)
}

/// The `FIONREAD` ioctl: how many bytes are currently buffered and unread on `fd`. Exact,
/// kernel-reported — used to prove a drain did or did not happen, rather than inferring it
/// from a verdict that reports the same thing (`MembersRemain`) either way.
fn fionread(fd: BorrowedFd<'_>) -> i32 {
    let mut n: libc::c_int = 0;
    // SAFETY: FIONREAD via ioctl writes exactly one `c_int`; `fd` is a valid, open descriptor
    // for the duration of this call.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FIONREAD, &mut n) };
    assert_eq!(rc, 0, "FIONREAD ioctl failed: {}", std::io::Error::last_os_error());
    n
}

/// This system's real pipe buffer capacity, MEASURED rather than assumed (the module doc's own
/// "~64 KiB" is a description of what was once observed on one host, not a portable constant):
/// fill a throwaway, non-blocking, in-process pipe until `write` reports `EAGAIN`, and sum what
/// fit. `NOTE_LOWAT`'s clamp (see the module doc) is exactly this number, so a writer told to
/// write precisely this many bytes, then stop, fills the marker pipe to exactly the ready
/// threshold — no more, no less, and no concurrent reader required to avoid deadlock.
fn measure_pipe_capacity() -> usize {
    let (_r, w) = marker_pipe();
    // SAFETY: fcntl(F_GETFL/F_SETFL) on a live, owned fd; no pointer args beyond the flags.
    unsafe {
        let flags = libc::fcntl(w.as_raw_fd(), libc::F_GETFL);
        assert!(flags >= 0, "fcntl F_GETFL failed: {}", std::io::Error::last_os_error());
        let rc = libc::fcntl(w.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        assert_eq!(
            rc,
            0,
            "fcntl F_SETFL O_NONBLOCK failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let chunk = [0u8; 4096];
    let mut total = 0usize;
    loop {
        match nix::unistd::write(&w, &chunk) {
            Ok(got) => total += got,
            Err(nix::errno::Errno::EAGAIN) => return total, // full — this is the capacity
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => panic!("scratch pipe write failed: {e}"),
        }
    }
}

/// Block (real, event-driven, no timer) until `fd` becomes ready again on a FRESH,
/// independently-armed kqueue — used from inside a round hook to know, deterministically, that
/// the pipe has crossed the low-water mark again (e.g. after an earlier round drained it),
/// without racing the writer's own real-time refill speed. A private kqueue composes with
/// `block_on_kqueue`'s own (see `arm`'s doc: "one kqueue per waiter"), so this never disturbs
/// the wait under test.
fn block_until_marker_ready_again(fd: BorrowedFd<'_>) {
    let kq = super::arm(fd, false).expect("arm auxiliary kqueue");
    let mut events = [KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    )];
    loop {
        match kq.kevent(&[], &mut events, None) {
            Ok(n) if n > 0 => return,
            Ok(_) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => panic!("auxiliary kevent failed: {e}"),
        }
    }
}

#[test]
fn probe_reports_drained_when_the_last_write_end_is_gone() {
    let _serialize = test_spawn_lock();
    let (r, w) = marker_pipe();
    drop(w); // the last holder's descriptor closed
    assert_eq!(probe(r.as_fd()).expect("probe"), TreeDrain::AllMarkersClosed);
}

#[test]
fn probe_reports_drained_even_with_bytes_still_buffered() {
    // kqueue(2): EV_EOF is set once the write end is closed even with data pending — checked
    // and returned before any read happens (`interpret_read_event`'s EV_EOF branch), so this
    // does NOT exercise `drain_pending`'s discard path (that needs bytes past the NOTE_LOWAT
    // clamp). What this pins: bytes must never change the verdict — the marker pipe is not a
    // data channel — regardless of which branch produces it.
    let _serialize = test_spawn_lock();
    let (r, w) = marker_pipe();
    nix::unistd::write(&w, b"noise from a member").expect("write");
    drop(w);
    assert_eq!(probe(r.as_fd()).expect("probe"), TreeDrain::AllMarkersClosed);
}

#[test]
fn probe_reports_members_remain_while_the_write_end_is_open() {
    let (_child, marker, _stdin) = spawn_marker_holder("exec cat >/dev/null");
    assert_eq!(probe(marker.as_fd()).expect("probe"), TreeDrain::MembersRemain);
}

#[test]
fn probe_on_an_invalid_descriptor_reports_an_io_error() {
    // A borrowed fd the caller passed after it was already invalid must fail loudly, never
    // silently report a verdict.
    let err = probe(never_allocated_fd()).expect_err("an invalid descriptor must error");
    assert!(
        matches!(err, crate::error::Error::Io(_)),
        "expected Error::Io, got {err:?}"
    );
}

#[test]
fn block_until_drained_with_a_past_deadline_behaves_like_a_one_shot_probe() {
    let (child, marker, stdin) = spawn_marker_holder("exec cat >/dev/null");
    assert_eq!(
        block_until_drained(marker.as_fd(), Some(Some(Instant::now()))).expect("probe"),
        TreeDrain::MembersRemain
    );
    drop(stdin);
    assert_eq!(
        block_until_drained(marker.as_fd(), None).expect("unbounded wait"),
        TreeDrain::AllMarkersClosed
    );
    child.wait().expect("reap");
}

#[test]
fn block_until_drained_with_a_past_deadline_still_reports_an_already_drained_tree() {
    // The equivalence the test above cannot pin: there the true state at the deadline is
    // `MembersRemain`, so a buggy short-circuit that returns `MembersRemain` without ever
    // consulting the kqueue would pass it too. Here the tree has ALREADY, GENUINELY drained
    // before the (already past) deadline is even passed in, so only a real check of the
    // sticky, level-triggered `EV_EOF` — not an assumption keyed on "deadline elapsed" — can
    // produce the right verdict.
    let _serialize = test_spawn_lock();
    let (r, w) = marker_pipe();
    let already_past = Instant::now();
    drop(w); // drained before the deadline below is even evaluated
    assert_eq!(
        block_until_drained(r.as_fd(), Some(Some(already_past))).expect("probe"),
        TreeDrain::AllMarkersClosed,
        "an already-drained tree must be reported as drained even past a stale deadline"
    );
}

#[test]
fn arm_on_an_invalid_descriptor_reports_an_io_error() {
    // Exercises `ensure_nonblocking`'s guard inside `arm` — the actual reachable failure mode
    // for a bad descriptor. `add_with_receipt`'s own EV_ERROR branch (for EVFILT_READ,
    // via `arm`) has no test anywhere in this module: a descriptor that passes
    // `ensure_nonblocking`'s fcntl check yet still fails kqueue's EV_ADD is not something this
    // module found a reliable, portable way to construct.
    let err = super::arm(never_allocated_fd(), false).expect_err("arming an invalid descriptor must error");
    assert!(
        matches!(err, crate::error::Error::Io(_)),
        "expected Error::Io, got {err:?}"
    );
}

#[test]
fn a_retained_supervisor_write_end_is_refused_not_waited_on() {
    // Measured: with the supervisor's own copy of the write end open, the edge NEVER fires
    // though every member exited. A wait here could only ever burn the caller's deadline, so
    // the primitive must refuse instead of pretending to watch.
    let _serialize = test_spawn_lock();
    let (r, w) = marker_pipe();
    assert_eq!(super::write_end_check(r.as_fd()), super::WriteEndCheck::HeldByUs);
    let err = probe(r.as_fd()).expect_err("a retained write end must be refused");
    assert!(
        matches!(err, crate::error::Error::Containment { .. }),
        "expected Error::Containment, got {err:?}"
    );
    drop(w);
    // NOT `assert_eq!(..., Clear)`: under a plain `cargo test` (see `marker_pipe`'s doc), this
    // process's fd table is being churned by every other test running at the same moment. The
    // property under test is that a CLEARED write end is never mistaken for a still-held one.
    assert_ne!(super::write_end_check(r.as_fd()), super::WriteEndCheck::HeldByUs);
    assert_eq!(probe(r.as_fd()).expect("probe"), TreeDrain::AllMarkersClosed);
}

#[test]
fn write_end_check_ignores_unrelated_pipes_this_process_holds() {
    // The check must key on the marker's own kernel object, not on "this process holds some
    // pipe write end" — a supervisor holds many (every child's stdin). Same concurrency note
    // as above: assert the property (not HeldByUs), not an exact Clear.
    let _serialize = test_spawn_lock();
    let (r, w) = marker_pipe();
    let (_other_r, _other_w) = marker_pipe();
    drop(w);
    assert_ne!(super::write_end_check(r.as_fd()), super::WriteEndCheck::HeldByUs);
}

#[test]
fn write_end_check_is_unassessable_for_a_descriptor_that_is_not_a_pipe() {
    // proc_pidfdinfo(PROC_PIDFDPIPEINFO) on a non-pipe fd fails (wrong type) — the check must
    // say "inconclusive", never misreport it as Clear (which `probe`/`arm` would then trust).
    let f = std::fs::File::open("/dev/null").expect("open /dev/null");
    assert_eq!(super::write_end_check(f.as_fd()), super::WriteEndCheck::Unassessable);
}

#[test]
fn an_unassessable_write_end_check_refuses_only_an_unbounded_wait() {
    // `Unassessable` is not evidence of a bug (an ordinary transient
    // scan gap under concurrent spawning), so a BOUNDED wait proceeds — its own deadline
    // already caps the exposure. Only an UNBOUNDED wait is refused, because that combination
    // is exactly the condition under which the primitive could otherwise hang forever with no
    // elevated runtime signal at all.
    let f = std::fs::File::open("/dev/null").expect("open /dev/null");
    assert_eq!(super::write_end_check(f.as_fd()), super::WriteEndCheck::Unassessable);
    // Bounded (a real, already-past deadline): proceeds past the write-end guard, then fails
    // for the ordinary reason (not a pipe, so `EVFILT_READ` cannot be armed on it) — never
    // `Error::Unassessable`.
    let bounded = block_until_drained(f.as_fd(), Some(Some(Instant::now())));
    assert!(
        !matches!(bounded, Err(crate::error::Error::Unassessable { .. })),
        "a bounded wait must not be refused on an Unassessable write-end check, got {bounded:?}"
    );
    // Unbounded: refused outright.
    let unbounded = block_until_drained(f.as_fd(), None);
    assert!(
        matches!(unbounded, Err(crate::error::Error::Unassessable { .. })),
        "an unbounded wait must be refused on an Unassessable write-end check, got {unbounded:?}"
    );
}

#[test]
fn a_live_member_holds_the_edge_shut_and_releases_it_on_exit() {
    // `cat` blocks on stdin and holds the inherited fd 3; closing our stdin write end is the
    // only thing that ends it, so the drain is caused by an event, never awaited on a clock.
    let (child, marker, stdin) = spawn_marker_holder("exec cat >/dev/null");
    assert_eq!(
        block_until_drained(marker.as_fd(), Some(Some(Instant::now()))).expect("probe"),
        TreeDrain::MembersRemain,
        "a live marker holder must hold the edge shut"
    );
    drop(stdin); // cat sees EOF on stdin and exits
    assert_eq!(
        block_until_drained(marker.as_fd(), None).expect("unbounded wait"),
        TreeDrain::AllMarkersClosed
    );
    child.wait().expect("reap");
}

#[test]
fn the_edge_is_sticky_for_a_waiter_that_arrives_late() {
    // kqueue EVFILT_READ is level-triggered on a pipe: a kqueue armed after the drain
    // reports EV_EOF immediately, so a late waiter can never miss the edge.
    let (child, marker, stdin) = spawn_marker_holder("exec cat >/dev/null");
    drop(stdin);
    child.wait().expect("reap");
    assert_eq!(
        block_until_drained(marker.as_fd(), None).expect("late wait"),
        TreeDrain::AllMarkersClosed
    );
}

#[test]
fn a_member_that_closes_the_marker_leaves_the_set_early() {
    // The documented limit, pinned as behaviour rather than prose: `exec 3>&-` drops the
    // descriptor, so the edge fires while the member is demonstrably still running.
    let (child, marker, stdin) = spawn_marker_holder("exec 3>&-; exec cat >/dev/null");
    assert_eq!(
        block_until_drained(marker.as_fd(), None).expect("wait"),
        TreeDrain::AllMarkersClosed,
        "a member that closed the marker must leave the membership set"
    );
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "the false edge is only meaningful if the member is still running"
    );
    drop(stdin);
    child.wait().expect("reap");
}

#[test]
fn an_orphan_reparented_to_launchd_holds_the_edge_shut() {
    // The population no other mechanism on this platform can see. `sh` backgrounds `cat`,
    // reports its pid on fd 4 and exits, so `cat` is reparented to launchd (ppid == 1) while
    // still holding the inherited marker on fd 3 across `sh`'s own exec.
    //
    // `cat` needs an EXPLICIT stdin redirect (`0<&0`) even though it is already fd 0 as
    // inherited: macOS `/bin/sh` (bash 3.2.57) redirects a backgrounded job's stdin to
    // /dev/null when the job has no redirection of its OWN and job control is off (the
    // normal state for a non-interactive `-c` script) — without `0<&0`, this exact fd
    // plumbing produces a `cat` that reads immediate EOF and exits, never becoming the
    // long-lived orphan the test needs; WITH it, the orphan survives and holds the marker.
    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh")
        .args(["sh", "-c", "cat 0<&0 >/dev/null & echo $! >&4"]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    cmd.fd(4, crate::Stdio::pipe_out()).expect("report pipe");
    let mut child = cmd.spawn().expect("spawn /bin/sh");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    let report = child.fd_read_end(4.into()).expect("report read end");
    let stdin = child.fd_write_end(crate::Fd::STDIN).expect("stdin write end");

    let orphan_pid: u32 = {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(report).read_line(&mut line).expect("read pid");
        line.trim().parse().expect("pid")
    };
    child.wait().expect("the root sh exits once it has backgrounded cat");

    // The root is reaped; the only marker holder left is the orphan.
    let parents = crate::containment::enumerate::process_parents();
    let ppid = parents
        .iter()
        .find(|(pid, _)| *pid == orphan_pid)
        .map(|(_, ppid)| *ppid)
        .expect("the orphan is in the process table");
    assert_eq!(ppid, 1, "the orphan must be reparented to launchd");

    assert_eq!(
        block_until_drained(marker.as_fd(), Some(Some(Instant::now()))).expect("probe"),
        TreeDrain::MembersRemain,
        "an orphan at ppid=1 must hold the edge shut after the root is gone"
    );

    drop(stdin); // the orphan's only exit path — no signal, no timer
    assert_eq!(
        block_until_drained(marker.as_fd(), None).expect("unbounded wait"),
        TreeDrain::AllMarkersClosed,
        "the edge must fire when the orphan exits"
    );
}

#[test]
fn all_markers_closed_requires_every_simultaneous_holder_to_exit() {
    // Every test above this one has exactly ONE write-end holder at a time, so none of them can
    // tell "some closed" from "all closed" apart — a bug that reported `AllMarkersClosed` the
    // moment ANY single holder's copy closed, ignoring the rest, would still pass every one of
    // them. This test needs two INDEPENDENTLY closable holders alive at once: a single root
    // `/bin/sh` backgrounds two separate `cat` processes, each with its OWN stdin pipe (fd 0
    // and fd 5) so each can be closed on its own, both inheriting the same fd 3 from the one
    // spawn. The root closes its own fd 3 copy right after backgrounding (`exec 3>&-`) so it is
    // never itself a third holder, then `wait`s for both children instead of exiting — nothing
    // here depends on reparenting, unlike the orphan test above.
    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh").args([
        "sh",
        "-c",
        "cat 0<&0 >/dev/null & cat 0<&5 >/dev/null & exec 3>&-; wait",
    ]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe for holder A");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    cmd.fd(5, crate::Stdio::pipe_in()).expect("stdin pipe for holder B");
    let mut child = cmd.spawn().expect("spawn /bin/sh");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    let stdin_a = child.fd_write_end(crate::Fd::STDIN).expect("holder A stdin write end");
    let stdin_b = child.fd_write_end(5.into()).expect("holder B stdin write end");

    assert_eq!(
        block_until_drained(marker.as_fd(), Some(Some(Instant::now()))).expect("probe"),
        TreeDrain::MembersRemain,
        "two live holders must hold the edge shut"
    );

    drop(stdin_a); // holder A sees EOF on its own stdin and exits; holder B is untouched
    assert_eq!(
        block_until_drained(marker.as_fd(), Some(Some(Instant::now()))).expect("probe"),
        TreeDrain::MembersRemain,
        "one holder exiting while a second remains must not be mistaken for a full drain"
    );

    drop(stdin_b); // holder B sees EOF and exits; no holder remains
    assert_eq!(
        block_until_drained(marker.as_fd(), None).expect("unbounded wait"),
        TreeDrain::AllMarkersClosed,
        "the edge must fire only once the LAST simultaneous holder is gone"
    );
    child
        .wait()
        .expect("reap the root sh, which itself waited for both background cats");
}

#[test]
fn small_bytes_from_a_member_are_not_a_drain() {
    // The verdict-level half of the NOTE_LOWAT claim: a handful of buffered bytes must never
    // read as a drain, gated or not (`interpret_read_event`'s non-EOF branch reports
    // `MembersRemain` either way). The ZERO-deadline check is the exact, correct tool here
    // (matching this file's own header promise), not a multi-second real wait. Whether the
    // wakeup itself is actually suppressed is a SEPARATE, lower-level claim, pinned by the
    // low-water suppression test below (a verdict-only assertion cannot distinguish
    // "suppressed" from "delivered but harmless"). The child
    // signals readiness on a SEPARATE report pipe right after writing to fd 3, so the ordering
    // ("the write already happened") is real synchronization, not assumed.
    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh")
        .args(["sh", "-c", "echo noise >&3; echo ready >&4; exec cat >/dev/null"]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    cmd.fd(4, crate::Stdio::pipe_out()).expect("report pipe");
    let mut child = cmd.spawn().expect("spawn /bin/sh");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    let mut report = child.fd_read_end(4.into()).expect("report read end");
    let stdin = child.fd_write_end(crate::Fd::STDIN).expect("stdin write end");

    use std::io::Read;
    let mut byte = [0u8; 1];
    report
        .read_exact(&mut byte)
        .expect("the child wrote to fd 3 before this returns");

    assert_eq!(
        block_until_drained(marker.as_fd(), Some(Some(Instant::now()))).expect("zero-deadline check"),
        TreeDrain::MembersRemain,
        "a handful of buffered bytes under the low-water clamp must not be mistaken for a drain"
    );
    drop(stdin);
    assert_eq!(
        block_until_drained(marker.as_fd(), None).expect("unbounded wait"),
        TreeDrain::AllMarkersClosed
    );
    child.wait().expect("reap");
}

#[test]
fn note_lowat_suppresses_a_wakeup_for_bytes_under_the_clamp() {
    // The lower-level half of the claim the test above cannot reach: a write under the clamp
    // must not even make the kqueue itself ready, not merely "ready but harmlessly
    // reinterpreted." Polling the KQUEUE'S OWN fd (a kqueue is itself pollable) with a zero
    // timeout reads the raw pending-event state directly, bypassing `drain_kqueue`/
    // `interpret_read_event` — both of whose non-EOF branches report `MembersRemain` whether
    // the underlying event fired or not, which is exactly why a verdict-only assertion cannot
    // tell "suppressed" from "delivered but harmless" apart. No timing is involved: the write
    // completes (kernel-buffered) before the poll call runs, both on this same thread, in
    // program order — nothing is awaited. A real child (not a bare in-process pipe) holds the
    // write end: `arm` itself refuses a write end this process retains, so proving "arm even
    // succeeds here" needs a holder `write_end_check` reports as `Clear`, not `HeldByUs`.
    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh")
        .args(["sh", "-c", "echo noise >&3; echo ready >&4; exec cat >/dev/null"]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    cmd.fd(4, crate::Stdio::pipe_out()).expect("report pipe");
    let mut child = cmd.spawn().expect("spawn /bin/sh");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    let mut report = child.fd_read_end(4.into()).expect("report read end");
    let stdin = child.fd_write_end(crate::Fd::STDIN).expect("stdin write end");

    use std::io::Read;
    let mut byte = [0u8; 1];
    report
        .read_exact(&mut byte)
        .expect("the child wrote to fd 3 before this returns");

    let kq = super::arm(marker.as_fd(), false).expect("arm");
    let mut pfd = libc::pollfd {
        fd: kq.as_fd().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is a single, correctly-initialized `pollfd`; `poll` writes only within its
    // bounds, and the `1` count matches the slice length passed.
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    assert_eq!(
        rc, 0,
        "NOTE_LOWAT must suppress a wakeup for bytes under the clamp, but the kqueue reports ready"
    );
    drop(stdin);
    child.wait().expect("reap");
}

#[test]
fn bytes_past_the_low_water_clamp_are_drained_without_a_wrong_verdict() {
    // Exercises `interpret_read_event`'s discard branch for real (below the clamp it is never
    // entered at all — a handful of bytes, as in the test above, cannot reach it). The member
    // writes >64 KiB via `yes | head`, well past the measured clamp, THEN closes fd 3 itself
    // (`exec 3>&-`) so the test's own completion is event-driven, not a fixed wait for
    // "probably done writing by now." A generous bound is still passed to
    // `block_until_drained` as a FAILURE bound (a real regression here should fail fast, not
    // hang the suite), not as the mechanism the assertion depends on.
    let (child, marker, stdin) = spawn_marker_holder("yes | head -c 200000 >&3; exec 3>&-; exec cat >/dev/null");
    assert_eq!(
        block_until_drained(
            marker.as_fd(),
            Some(Instant::now().checked_add(Duration::from_secs(10)))
        )
        .expect("wait past the low-water clamp"),
        TreeDrain::AllMarkersClosed,
        "closing the marker after writing past the clamp must still report drained, not hang or misfire"
    );
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "the member closed only the marker fd, not itself — same false-edge shape as the small case"
    );
    drop(stdin);
    child.wait().expect("reap");
}

#[test]
fn a_quiet_live_holder_blocks_without_spending_cpu() {
    // The realistic case (nothing in the crate writes to the marker) — this is the claim
    // "poll-free" is actually supposed to stand behind, verified structurally rather than by
    // sampling CPU usage over a fixed window: a live holder that never writes must resolve the
    // whole bounded wait in exactly ONE real `kevent` call that genuinely blocks for the
    // deadline, not merely return the right verdict at the right wall-clock instant.
    //
    // Two checks, but NOT for the reason an earlier draft claimed here: since
    // `block_on_kqueue` re-checks `remaining(deadline)` before trusting a bare `Ok(0)` (closing
    // the never-early gap structurally — see that function's own doc), a spin mutant (forcing a
    // near-zero timeout unconditionally) no longer resolves in one instant call the way it once
    // did; it busy-spins until the REAL deadline genuinely elapses, which the never-early check
    // cannot catch (it keeps correctly passing throughout the spin — the busy-poll never
    // returns EARLY, just wastefully). It is the kevent-call COUNT that catches that mutant now
    // (mutant-tested: forcing the timeout to zero drove the call count into the tens of
    // thousands while the never-early check stayed green the whole time). The never-early check
    // stays here anyway, as the SAME structural guarantee every deadline-bound call in this
    // crate makes (see `block_until_drained_never_returns_before_a_real_deadline`), not as
    // THIS test's own busy-poll proof — that job now belongs to the call count alone.
    //
    // `HookGuard::install` resets `kevent_calls()` to zero before the measured call: without
    // it, a stale count left by whatever last ran a hook on this thread could make a broken
    // implementation look right, or a correct one look wrong.
    let _hook_guard = crate::wait::backend::test_hooks::HookGuard::install(|_round, _kq| {});
    let (child, marker, _stdin) = spawn_marker_holder("exec cat >/dev/null");
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(300))
        .expect("deadline");
    let verdict =
        block_until_drained(marker.as_fd(), Some(Some(deadline))).expect("bounded wait against a quiet holder");
    let now = Instant::now();

    assert_eq!(verdict, TreeDrain::MembersRemain);
    assert!(
        now >= deadline,
        "must never return before the deadline: now={now:?}, deadline={deadline:?}"
    );
    assert_eq!(
        crate::wait::backend::test_hooks::kevent_calls(),
        1,
        "a quiet holder must resolve the wait in exactly one real, blocking kevent call — more \
         would mean a busy-poll, not a genuine kernel block"
    );

    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn block_until_drained_never_returns_before_a_real_deadline() {
    // The never-early half of the deadline contract: cosca promises it never reports a
    // verdict before the deadline (a `now >= deadline` check on a monotonic clock), and never
    // promises an upper bound on how late — so this asserts the lower bound EXACTLY, no slack,
    // against a REAL clock (no mock needed: scheduling can only push a return later, never
    // earlier). `yes` keeps the descriptor continuously ready, so this can only terminate via
    // the deadline path, not a real EOF.
    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh").args(["sh", "-c", "exec yes >&3"]);
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    let mut child = cmd.spawn().expect("spawn yes");
    let marker = child.fd_read_end(3.into()).expect("marker read end");

    let deadline = Instant::now()
        .checked_add(Duration::from_millis(300))
        .expect("deadline");
    let verdict = block_until_drained(marker.as_fd(), Some(Some(deadline))).expect("bounded wait");
    let now = Instant::now();

    assert_eq!(
        verdict,
        TreeDrain::MembersRemain,
        "a sustained writer must still report MembersRemain"
    );
    assert!(
        now >= deadline,
        "must never return before the deadline: now={now:?}, deadline={deadline:?}"
    );

    child.kill().expect("kill the sustained writer");
    child.wait().expect("reap");
}

#[test]
fn a_sustained_writer_is_checked_against_the_deadline_every_round() {
    // The structural half of the deadline contract, proven without any wall-clock upper-bound
    // assertion (cosca promises none) and without any dependence on real elapsed time:
    // `block_until_drained` (via `block_on_kqueue`) checks `remaining(deadline)` before EVERY
    // `kevent` call, so a continuously-ready descriptor (a sustained writer) cannot keep it
    // looping past the deadline. Proven by:
    //
    //   (a) the verdict is still `MembersRemain`;
    //   (b) round 0's requested `kevent` timeout is EXACTLY one year (not "some real value
    //       over 1s", which a slow test-setup could satisfy by accident even under a spin
    //       mutant — see `a_quiet_live_holder_blocks_without_spending_cpu`'s own mutant note):
    //       the mock clock is FROZEN, not merely offset, from before the deadline is even
    //       computed, so round 0 sees exactly `frozen_now + 1yr - frozen_now = 1yr`, with zero
    //       dependence on how long spawning `yes` or setting up this test actually took;
    //   (c) round 1's requested timeout is EXACTLY `Duration::ZERO`, because the round-1 hook
    //       advances the SAME frozen clock past the deadline before round 1's own
    //       `remaining(deadline)` is computed;
    //   (d) the round hook itself asserts `round <= 1` on EVERY firing, so a third round (the
    //       extra-round mutant: removing the `already_elapsed` early return) fails immediately,
    //       from inside the hook, the INSTANT it starts — not eventually, after however many
    //       iterations it takes the call count to look wrong;
    //   (e) round 1 performs NO drain (principle 13: once elapsed, the final check looks for
    //       `EV_EOF` only) — proven with `containment::marker_eof::drain_test_hooks`'s
    //       cumulative, monotonically-increasing drained-bytes counter, NOT a `FIONREAD`
    //       snapshot comparison: `yes` keeps writing throughout this test, so a `FIONREAD`
    //       taken well after round 1 could read the SAME (or a higher) value whether round 1
    //       drained nothing or drained plenty and the writer simply refilled the gap —
    //       indistinguishable from outside. The counter cannot be fooled that way: it only ever
    //       goes up by exactly what `drain_pending` really read, so a baseline taken right when
    //       round 1's precondition (the pipe ready again) is confirmed, compared to the total
    //       after the whole wait concludes, is exact regardless of anything the writer does in
    //       between.
    //
    // The round-1 hook blocks (event-driven, no timer) on its OWN independently-armed kqueue
    // until the pipe is ready again, rather than assuming `yes` has refilled it by some
    // particular real-time instant.
    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh").args(["sh", "-c", "exec yes >&3"]);
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    let mut child = cmd.spawn().expect("spawn yes");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    let raw_fd = marker.as_raw_fd();

    let (_clock_guard, frozen_now) = crate::wait::test_clock::FrozenClockGuard::install();
    let one_year = Duration::from_secs(365 * 24 * 3600);
    let deadline = frozen_now.checked_add(one_year).expect("deadline");

    let drained_baseline = std::rc::Rc::new(std::cell::Cell::new(None::<u64>));
    let drained_baseline_for_hook = std::rc::Rc::clone(&drained_baseline);
    let _hook_guard = crate::wait::backend::test_hooks::HookGuard::install(move |round, _kq| {
        assert!(
            round <= 1,
            "must not start a third round after the deadline has elapsed — extra-round mutant, \
             round={round}"
        );
        if round == 1 {
            // SAFETY: `raw_fd` is `marker`'s descriptor, open for this whole test.
            let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
            block_until_marker_ready_again(fd);
            drained_baseline_for_hook.set(Some(super::drain_test_hooks::drained_bytes()));
            crate::wait::test_clock::advance(one_year + Duration::from_secs(86_400));
        }
    });

    let verdict = block_until_drained(marker.as_fd(), Some(Some(deadline))).expect("bounded wait");

    assert_eq!(
        verdict,
        TreeDrain::MembersRemain,
        "a sustained writer must still report MembersRemain"
    );

    let calls = crate::wait::backend::test_hooks::kevent_calls();
    assert_eq!(
        calls, 2,
        "exactly two real kevent calls: one round that saw the deadline as still open, then one \
         more round whose already_elapsed check (from the frozen, mock-advanced clock) stops \
         the loop — never a third round"
    );

    let requested = crate::wait::backend::test_hooks::requested_timeouts();
    assert_eq!(requested.len(), 2, "one requested timeout recorded per kevent call");
    assert_eq!(
        requested[0],
        Some(one_year),
        "round 0's requested timeout must be EXACTLY the frozen deadline's remaining duration, \
         got {:?}",
        requested[0]
    );
    assert_eq!(
        requested[1],
        Some(Duration::ZERO),
        "round 1's requested timeout must reflect the mock-advanced (already past) deadline, \
         proving it is derived from remaining(deadline) freshly each round, not cached once \
         before the loop"
    );

    let baseline = drained_baseline
        .get()
        .expect("the round-1 hook must have run and recorded a baseline");
    assert_eq!(
        super::drain_test_hooks::drained_bytes(),
        baseline,
        "round 1 must not have drained any bytes once the deadline had elapsed (principle 13) — \
         the cumulative drained-bytes counter moved after round 1's own precondition was set"
    );

    child.kill().expect("kill the sustained writer");
    child.wait().expect("reap");
}

#[test]
fn an_event_that_arrives_after_the_clock_moves_past_the_deadline_mid_round_does_not_drain() {
    // The gap the test above cannot reach: there, the clock is moved BEFORE round 1's own
    // `remaining(deadline)` is computed, so the pre-call `already_elapsed` sample is ALREADY
    // correct — it never needs the post-event re-check to save it. This test moves the clock
    // strictly AFTER the pre-call sample (which is `false`: the deadline is 60s out and hasn't
    // been touched yet) but BEFORE `block_on_kqueue` decides whether to drain — exactly the
    // window a real, long-blocking `kevent` call can straddle a real deadline in production,
    // which `test_hooks::HookGuard::install_with_post_event`'s post-event hook exists to
    // simulate deterministically. Without the post-call re-check this PR's `block_on_kqueue`
    // added, this event would be drained (its `already_elapsed` sample, taken before the call,
    // was still `false`).
    let cap = measure_pipe_capacity();
    let (child, marker, stdin) = spawn_marker_holder(&format!("yes | head -c {cap} >&3; exec cat >/dev/null"));

    let (_clock_guard, frozen_now) = crate::wait::test_clock::FrozenClockGuard::install();
    let deadline = frozen_now.checked_add(Duration::from_secs(60)).expect("deadline");

    let _hook_guard = crate::wait::backend::test_hooks::HookGuard::install_with_post_event(
        |_round, _kq| {},
        |round| {
            if round == 0 {
                // The round-0 event has just arrived (real, non-EOF — the writer already
                // parked with bytes buffered before this call was even armed). Simulate the
                // deadline passing WHILE `block_on_kqueue` was blocked waiting for it, only
                // discovered now that the event is in hand.
                crate::wait::test_clock::advance(Duration::from_secs(120));
            }
        },
    );

    let baseline = super::drain_test_hooks::drained_bytes();
    let verdict = block_until_drained(marker.as_fd(), Some(Some(deadline))).expect("bounded wait");

    assert_eq!(
        verdict,
        TreeDrain::MembersRemain,
        "the writer is still alive and holding the descriptor — the event was non-EOF"
    );
    assert_eq!(
        crate::wait::backend::test_hooks::kevent_calls(),
        1,
        "the deadline is discovered elapsed as soon as the (only) event arrives — no second round"
    );
    assert_eq!(
        super::drain_test_hooks::drained_bytes(),
        baseline,
        "an event that arrives after the deadline has passed, even if that only became true \
         WHILE the kevent call was blocked, must not drain"
    );

    drop(stdin);
    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn an_unbounded_wait_against_a_sustained_writer_blocks_without_spending_cpu() {
    // The unbounded counterpart to the quiet-holder structural test above, and the case the
    // sync death-watch's CPU-proportional accounting explicitly does NOT cover: with
    // `deadline: None` there is no caller-supplied bound to pay a per-round drain against, so
    // (per the module doc) this wait must not drain past the low-water clamp at all — the
    // writer's own `write()` blocks against the full pipe instead, and the wait genuinely
    // blocks in the kernel rather than busy-looping `kevent`-drain-repeat forever.
    //
    // An earlier draft killed the writer from inside round 0's own hook, before round 0's
    // first real `kevent` call — which meant round 0 always resolved via `EV_EOF` directly,
    // NEVER via a non-EOF, undrained event. Two mutants stayed green as a result: dropping the
    // `if !unbounded_wait` guard (draining unconditionally) and dropping `EV_CLEAR` from `arm`
    // — neither ever got exercised, because there was never a non-terminal round for either to
    // matter in. This version instead uses a writer that writes EXACTLY the measured pipe
    // capacity via `head -c`, then PARKS (holds the descriptor, writes nothing more) — so
    // round 0 genuinely observes a non-EOF, ready event with real buffered bytes, and only
    // round 1's hook (not round 0's) ends the wait. Between the two rounds, the round-1 hook
    // directly proves both properties the mutants would break:
    //   - `FIONREAD` still equals round 0's own recorded `event.data()` — nothing was drained;
    //   - a manual, zero-timeout `kevent` on the SAME kqueue (passed into the hook) returns ZERO
    //     events, even though the level condition (bytes still at/above the clamp) is
    //     unchanged — proof `EV_CLEAR` is actually armed, not merely level-triggered.
    // Only after both checks does the hook kill and reap the writer, ending the wait via a real
    // `EV_EOF` on round 1's own (real) `kevent` call — checked unconditionally, ahead of any
    // buffered-bytes branch, so it does not matter that bytes are still sitting there.
    //
    // `spawn_marker_holder` (not a hand-rolled `Command`, as an earlier draft used) gives the
    // child a REAL stdin pipe this test holds open: under nextest, an unredirected stdin is
    // `/dev/null`, so `exec cat >/dev/null` would see immediate EOF and exit at once instead of
    // parking — silently turning "the writer parks, holding the descriptor" into a timing-
    // dependent race against nextest's own process setup. `_stdin` is kept bound (not `_`)
    // until after the wait concludes, so `cat` cannot exit before this test is done with it.
    let cap = measure_pipe_capacity();
    let (child, marker, _stdin) = spawn_marker_holder(&format!("yes | head -c {cap} >&3; exec cat >/dev/null"));
    let raw_fd = marker.as_raw_fd();

    let mut child_opt = Some(child);
    let _hook_guard = crate::wait::backend::test_hooks::HookGuard::install(move |round, kq| {
        assert!(
            round <= 1,
            "the wait should have concluded by round 1, got round={round}"
        );
        if round != 1 {
            return;
        }
        // SAFETY: `raw_fd` is `marker`'s descriptor, open for this whole test.
        let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };

        let round0_data = crate::wait::backend::test_hooks::last_event_data()
            .expect("round 0 must have recorded a non-EOF event's data");
        // A lower bound, NOT `== cap`: XNU pipe buffers grow through several size tiers
        // (512B..256KiB, `sys_pipe.c`) driven by each pipe's OWN write history, so a capacity
        // measured on a SEPARATE scratch pipe (`measure_pipe_capacity`, used only to pick how
        // much the SCRIPT below should write) is not guaranteed to equal what THIS marker pipe
        // actually grew to — only that `head -c cap` written to a fresh pipe crosses the
        // low-water clamp, which a positive `data` already confirms.
        assert!(
            round0_data > 0,
            "round 0's event must report a positive byte count, got {round0_data}"
        );
        assert_eq!(
            fionread(fd) as isize,
            round0_data,
            "an unbounded wait must not drain any bytes in round 0 (decision: unbounded never \
             drains) — FIONREAD dropped below round 0's own reported byte count"
        );

        // EV_CLEAR proof: the SAME level condition (bytes still at/above the clamp, nothing
        // read, nothing newly written since `yes` is now blocked in its own `write()`) must NOT
        // re-fire on a second, independent zero-timeout poll of the wait's OWN kqueue —
        // EV_CLEAR resets per-knote readiness after each delivery, requiring a fresh crossing.
        let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let mut events = [KEvent::new(
            0,
            EventFilter::EVFILT_READ,
            EvFlags::empty(),
            FilterFlag::empty(),
            0,
            0,
        )];
        let n = kq
            .kevent(&[], &mut events, Some(zero))
            .expect("zero-timeout poll on the wait's own kqueue");
        assert_eq!(
            n, 0,
            "EV_CLEAR must suppress a re-poll of the SAME unchanged level — got {n} events, \
             EV_CLEAR appears unset on the armed knote"
        );

        let child = child_opt.take().expect("round 1 fires exactly once");
        child.kill().expect("kill the sustained writer");
        child.wait().expect("reap");
    });

    let verdict = block_until_drained(marker.as_fd(), None).expect("unbounded wait against a sustained writer");

    assert_eq!(
        verdict,
        TreeDrain::AllMarkersClosed,
        "killing the writer closes the marker descriptor, which must still be observed"
    );
    assert_eq!(
        crate::wait::backend::test_hooks::kevent_calls(),
        2,
        "round 0 (the undrained, non-EOF event) plus round 1 (the EOF that ends the wait) — \
         exactly two real kevent calls, not a busy-poll"
    );
}

#[test]
fn arm_sets_ev_clear_so_a_repeated_poll_without_a_new_edge_reports_nothing() {
    // Direct, white-box proof that `arm` requests `EV_CLEAR` (module doc: "arm once per
    // genuinely new edge, not once per `kevent` call while the condition merely holds") —
    // distinct from `note_lowat_suppresses_a_wakeup_for_bytes_under_the_clamp` above, which
    // proves `NOTE_LOWAT` suppresses a wakeup for bytes that never CROSS the clamp at all; this
    // proves `EV_CLEAR` suppresses a REPEATED wakeup for a level that crossed the clamp once
    // and has stayed there ever since, unchanged and undrained.
    let cap = measure_pipe_capacity();
    let (child, marker, _stdin) = spawn_marker_holder(&format!("yes | head -c {cap} >&3; exec cat >/dev/null"));
    let kq = super::arm(marker.as_fd(), false).expect("arm");
    let mut events = [KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    )];

    // Real, blocking (no timeout) first poll: the writer already wrote exactly `cap` bytes
    // before this arms (or finishes doing so shortly after), so this must report the crossing.
    let n = kq.kevent(&[], &mut events, None).expect("initial blocking poll");
    assert_eq!(n, 1, "expected the initial crossing to be ready");
    assert!(
        !events[0].flags().contains(EvFlags::EV_EOF),
        "the writer is still alive and holding the descriptor — this must not be EOF"
    );

    // Second poll, WITHOUT reading or draining anything in between: the level condition (bytes
    // still at/above the clamp) is UNCHANGED, so only `EV_CLEAR` being unset would make this
    // report ready again.
    let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let n2 = kq
        .kevent(&[], &mut events, Some(zero))
        .expect("second, zero-timeout poll");
    assert_eq!(
        n2, 0,
        "EV_CLEAR must suppress a re-poll of an unchanged level — got {n2} events"
    );

    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn interpret_read_event_suppresses_drain_when_told_to() {
    // White-box: `suppress_drain = true` must never consume bytes, regardless of WHY it was
    // requested — an unbounded wait, or a bounded wait whose deadline already elapsed;
    // principle 13 unifies both reasons under the same flag, and this pins the shared
    // mechanics directly rather than through either caller. Exercises the real, non-EOF branch
    // with a REAL event obtained from a REAL writer (not a hand-rolled `KEvent`, which could
    // never expose a bug in how `arm`/`kevent` actually populate `data`).
    let cap = measure_pipe_capacity();
    let (child, marker, _stdin) = spawn_marker_holder(&format!("yes | head -c {cap} >&3; exec cat >/dev/null"));
    let kq = super::arm(marker.as_fd(), true).expect("arm");
    let mut events = [KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    )];
    let n = kq.kevent(&[], &mut events, None).expect("blocking poll");
    assert_eq!(n, 1, "expected the crossing to be ready");

    let before = fionread(marker.as_fd());
    let verdict =
        super::interpret_read_event(&events[0], marker.as_fd(), true).expect("interpret with suppress_drain=true");
    let after = fionread(marker.as_fd());

    assert_eq!(
        verdict, None,
        "a non-EOF event with drain suppressed must stay inconclusive"
    );
    assert_eq!(after, before, "suppress_drain=true must never consume any bytes");

    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn probe_never_drains_even_past_the_low_water_clamp() {
    // `probe` (the sync backend for `wait_tree_deadline`'s zero-duration case) is itself a
    // check AT expiry — the exact same one a bounded `block_until_drained` wait performs on
    // its own final round once the deadline has passed, just reached by a different path (a
    // caller-supplied deadline of `Duration::ZERO` skips `block_on_kqueue`'s loop entirely).
    // Principle 13 applies here just as much as there: it must never drain, proven with the
    // SAME cumulative, monotonically-increasing drained-bytes counter `drain_test_hooks`
    // exposes, against a REAL non-EOF event with real buffered bytes past the clamp.
    let cap = measure_pipe_capacity();
    let (child, marker, _stdin) = spawn_marker_holder(&format!("yes | head -c {cap} >&3; exec cat >/dev/null"));

    let baseline = super::drain_test_hooks::drained_bytes();
    let before = fionread(marker.as_fd());
    let verdict = probe(marker.as_fd()).expect("probe");
    let after = fionread(marker.as_fd());

    assert_eq!(
        verdict,
        TreeDrain::MembersRemain,
        "the writer is still alive and holding the descriptor — the event was non-EOF"
    );
    assert_eq!(after, before, "probe must not consume any bytes from the pipe");
    assert_eq!(
        super::drain_test_hooks::drained_bytes(),
        baseline,
        "probe is a check at expiry (principle 13) and must never drain"
    );

    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_wait_resolves_when_the_last_member_exits() {
    // `join!` polling `watch` before `end` is an implementation detail, not a contract — so
    // ordering is enforced with a real, per-call channel, not assumed from poll order.
    // `armed_rx.recv()` (blocking, moved to a blocking-pool thread) only returns once
    // `wait_tree_drained_for_test` has actually armed its kqueue; `drop(stdin)` happens
    // strictly after that.
    let (child, marker, stdin) = spawn_marker_holder("exec cat >/dev/null");
    let fd = marker.as_fd();
    let (armed_tx, armed_rx) = std::sync::mpsc::channel();
    let watch = crate::tokio::wait::wait_tree_drained_for_test(fd, armed_tx);
    let end = async move {
        ::tokio::task::spawn_blocking(move || armed_rx.recv().expect("watch armed"))
            .await
            .unwrap();
        drop(stdin);
    };
    let (watched, ()) = ::tokio::join!(watch, end);
    watched.expect("async drain watch");
    child.wait().expect("reap");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn two_concurrent_async_waiters_both_observe_the_drain() {
    // Each waiter owns a private kqueue, so their knotes cannot displace each other.
    // Registering the same raw descriptor twice on the reactor instead would park one waiter
    // forever — but that only manifests across a LIVE-to-DRAINED transition (stickiness means
    // an already-drained descriptor resolves both registrations on the spot even with the
    // collision bug present, silently duplicating the already-drained-resolves-immediately test
    // below instead of catching anything). So both waiters get their own armed handshake, and
    // `drop(stdin)` is provably
    // AFTER both have armed — not left to `tokio::join!`'s poll order, the same reasoning the
    // sibling test above this one already applies.
    let (child, marker, stdin) = spawn_marker_holder("exec cat >/dev/null");
    let fd = marker.as_fd();
    let (a_armed_tx, a_armed_rx) = std::sync::mpsc::channel();
    let (b_armed_tx, b_armed_rx) = std::sync::mpsc::channel();
    let a = crate::tokio::wait::wait_tree_drained_for_test(fd, a_armed_tx);
    let b = crate::tokio::wait::wait_tree_drained_for_test(fd, b_armed_tx);
    let end = async move {
        ::tokio::task::spawn_blocking(move || {
            a_armed_rx.recv().expect("waiter a armed");
            b_armed_rx.recv().expect("waiter b armed");
        })
        .await
        .unwrap();
        drop(stdin);
    };
    let (ra, rb, ()) = ::tokio::join!(a, b, end);
    ra.expect("waiter a");
    rb.expect("waiter b");
    child.wait().expect("reap");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_wait_resolves_immediately_for_an_already_drained_tree() {
    let (child, marker, stdin) = spawn_marker_holder("exec cat >/dev/null");
    drop(stdin);
    child.wait().expect("reap");
    crate::tokio::wait::wait_tree_drained(marker.as_fd())
        .await
        .expect("already-drained watch");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_wait_resolves_via_eof_with_small_buffered_bytes() {
    // The async counterpart to the sync small-bytes-are-not-a-drain test above: a few bytes
    // stay below the NOTE_LOWAT clamp, so this resolves via the real EOF from `drop(stdin)`,
    // not via `drain_kqueue`'s discard branch — the test below this one is what exercises that
    // branch, through a write that forces genuine backpressure.
    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh")
        .args(["sh", "-c", "echo noise >&3; echo ready >&4; exec cat >/dev/null"]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    cmd.fd(4, crate::Stdio::pipe_out()).expect("report pipe");
    let mut child = cmd.spawn().expect("spawn /bin/sh");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    let report = child.fd_read_end(4.into()).expect("report read end");
    let stdin = child.fd_write_end(crate::Fd::STDIN).expect("stdin write end");

    let fd = marker.as_fd();
    let watch = crate::tokio::wait::wait_tree_drained(fd);
    let end = async move {
        // Blocking read on the report pipe: real synchronization for "the bytes are on the
        // marker now", off the async executor thread so it can't stall the reactor.
        ::tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut byte = [0u8; 1];
            let mut report = report;
            report
                .read_exact(&mut byte)
                .expect("child wrote to fd 3 before this returns");
        })
        .await
        .unwrap();
        drop(stdin);
    };
    let (watched, ()) = ::tokio::join!(watch, end);
    watched.expect("async drain watch after discarding bytes");
    child.wait().expect("reap");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_wait_never_drains_past_the_low_water_clamp() {
    // The async counterpart to the sync past-the-clamp test above — but with the OPPOSITE
    // expectation, because `wait_tree_drained` has no deadline at all
    // (see its doc): draining on a stuck writer's behalf forever is exactly the unbounded CPU
    // spin this primitive must not have, so past the clamp it does not drain and the writer's
    // own `write()` blocks instead (the marker fd's documented misuse contract). >64 KiB exceeds
    // the pipe's own buffer capacity, so the writer never reaches its own `exec 3>&-` and the
    // future never resolves; the external `tokio::time::timeout` here bounds the TEST's
    // patience, not the primitive's — it is the caller-supplied bound the primitive's doc says a
    // caller wanting one must supply itself.
    let (child, marker, stdin) = spawn_marker_holder("yes | head -c 200000 >&3; exec 3>&-; exec cat >/dev/null");
    let outcome = ::tokio::time::timeout(
        Duration::from_millis(300),
        crate::tokio::wait::wait_tree_drained(marker.as_fd()),
    )
    .await;
    assert!(
        outcome.is_err(),
        "a writer stuck past the low-water clamp must not resolve the wait — it should never be drained"
    );
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "the writer must still be blocked in its own write(), not exited"
    );
    drop(stdin);
    child
        .kill()
        .expect("kill the writer, which can never finish its write() on its own");
    child.wait().expect("reap");
}
