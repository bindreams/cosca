//! Unit tests for the macOS marker EOF edge. In the library because the primitive is
//! `pub(crate)`. Nothing here sleeps: every "the tree drained" event is caused by closing a
//! descriptor a child is blocked on, and every "the tree has not drained" assertion is a
//! ZERO-deadline check, which is exact rather than timed.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::Instant;

use super::{block_until_drained, probe, TreeDrain};

/// A marker pipe: `(read_end, write_end)`, both owned by this process. Built with
/// `std::io::pipe()` (CLOEXEC by default, matching `fdmarker::create_pipe`'s own convention) —
/// NOT `nix::unistd::pipe()` (raw POSIX semantics, not CLOEXEC) — because `cargo test --lib`
/// runs every test in this crate concurrently in one process, and a non-CLOEXEC test pipe fd
/// would be inherited by any OTHER concurrently-running test's spawned child, keeping that
/// child a spurious extra "holder" of a pipe this test never intended to share.
fn marker_pipe() -> (OwnedFd, OwnedFd) {
    let (r, w) = std::io::pipe().expect("pipe");
    (OwnedFd::from(r), OwnedFd::from(w))
}

/// A fd number NEVER allocated in this process (M14/M16): using it instead of a real,
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
/// supervisor bug (M3) the guard exists to catch, and would make `arm`/`probe` refuse rather
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

#[test]
fn probe_reports_drained_when_the_last_write_end_is_gone() {
    let (r, w) = marker_pipe();
    drop(w); // the last holder's descriptor closed
    assert_eq!(probe(r.as_fd()).expect("probe"), TreeDrain::AllMembersExited);
}

#[test]
fn probe_reports_drained_even_with_bytes_still_buffered() {
    // kqueue(2): EV_EOF is set once the write end is closed even with data pending — checked
    // and returned before any read happens (`interpret_read_event`'s EV_EOF branch), so this
    // does NOT exercise `drain_pending`'s discard path (that needs bytes past the NOTE_LOWAT
    // clamp). What this pins: bytes must never change the verdict — the marker pipe is not a
    // data channel — regardless of which branch produces it.
    let (r, w) = marker_pipe();
    nix::unistd::write(&w, b"noise from a member").expect("write");
    drop(w);
    assert_eq!(probe(r.as_fd()).expect("probe"), TreeDrain::AllMembersExited);
}

#[test]
fn probe_reports_members_remain_while_the_write_end_is_open() {
    let (_child, marker, _stdin) = spawn_marker_holder("exec cat >/dev/null");
    assert_eq!(probe(marker.as_fd()).expect("probe"), TreeDrain::MembersRemain);
}

#[test]
fn probe_on_an_invalid_descriptor_reports_an_io_error() {
    // A borrowed fd the caller passed after it was already invalid (e.g. a #59 lifecycle
    // bug) must fail loudly, never silently report a verdict.
    let err = probe(never_allocated_fd()).expect_err("an invalid descriptor must error");
    assert!(matches!(err, crate::error::Error::Io(_)), "expected Error::Io, got {err:?}");
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
        TreeDrain::AllMembersExited
    );
    child.wait().expect("reap");
}

#[test]
fn arm_on_an_invalid_descriptor_reports_an_io_error() {
    // Exercises `ensure_nonblocking`'s guard inside `arm` — the actual reachable failure mode
    // for a bad descriptor (M14). `add_with_receipt`'s own EV_ERROR branch (for EVFILT_READ,
    // via `arm`) has no test anywhere in this module: a descriptor that passes
    // `ensure_nonblocking`'s fcntl check yet still fails kqueue's EV_ADD is not something this
    // module found a reliable, portable way to construct.
    let err = super::arm(never_allocated_fd(), false).expect_err("arming an invalid descriptor must error");
    assert!(matches!(err, crate::error::Error::Io(_)), "expected Error::Io, got {err:?}");
}

#[test]
fn a_retained_supervisor_write_end_is_refused_not_waited_on() {
    // Measured: with the supervisor's own copy of the write end open, the edge NEVER fires
    // though every member exited. A wait here could only ever burn the caller's deadline, so
    // the primitive must refuse instead of pretending to watch.
    let (r, w) = marker_pipe();
    assert_eq!(super::write_end_check(r.as_fd()), super::WriteEndCheck::HeldByUs);
    let err = probe(r.as_fd()).expect_err("a retained write end must be refused");
    assert!(
        matches!(err, crate::error::Error::Containment { .. }),
        "expected Error::Containment, got {err:?}"
    );
    drop(w);
    // NOT `assert_eq!(..., Clear)`: `cargo test` runs concurrently, and this process's fd
    // table is being churned by every other test running at the same moment. The property
    // under test is that a CLEARED write end is never mistaken for a still-held one.
    assert_ne!(super::write_end_check(r.as_fd()), super::WriteEndCheck::HeldByUs);
    assert_eq!(probe(r.as_fd()).expect("probe"), TreeDrain::AllMembersExited);
}

#[test]
fn write_end_check_ignores_unrelated_pipes_this_process_holds() {
    // The check must key on the marker's own kernel object, not on "this process holds some
    // pipe write end" — a supervisor holds many (every child's stdin). Same concurrency note
    // as above: assert the property (not HeldByUs), not an exact Clear.
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
    // Q7's settled behavior: `Unassessable` is not evidence of a bug (an ordinary transient
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
