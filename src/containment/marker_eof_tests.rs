//! Unit tests for the macOS marker EOF edge. In the library because the primitive is
//! `pub(crate)`. Nothing here sleeps: every "the tree drained" event is caused by closing a
//! descriptor a child is blocked on, and every "the tree has not drained" assertion is a
//! ZERO-deadline check, which is exact rather than timed.
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

use super::{block_until_drained, probe, TreeDrain};

fn test_spawn_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::child::spawn::spawn_lock()
}

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
    let _serialize = test_spawn_lock();
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
    let _serialize = test_spawn_lock();
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
        TreeDrain::AllMembersExited
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
        TreeDrain::AllMembersExited,
        "an already-drained tree must be reported as drained even past a stale deadline"
    );
}

#[test]
fn arm_on_an_invalid_descriptor_reports_an_io_error() {
    // Exercises `ensure_nonblocking`'s guard inside `arm` — the actual reachable failure mode
    // for a bad descriptor (M14). `add_with_receipt`'s own EV_ERROR branch (for EVFILT_READ,
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
        TreeDrain::AllMembersExited
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
        TreeDrain::AllMembersExited
    );
}

#[test]
fn a_member_that_closes_the_marker_leaves_the_set_early() {
    // The documented limit, pinned as behaviour rather than prose: `exec 3>&-` drops the
    // descriptor, so the edge fires while the member is demonstrably still running.
    let (child, marker, stdin) = spawn_marker_holder("exec 3>&-; exec cat >/dev/null");
    assert_eq!(
        block_until_drained(marker.as_fd(), None).expect("wait"),
        TreeDrain::AllMembersExited,
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
        TreeDrain::AllMembersExited,
        "the edge must fire when the orphan exits"
    );
}

#[test]
fn small_bytes_from_a_member_are_not_a_drain() {
    // The verdict-level half of the NOTE_LOWAT claim: a handful of buffered bytes must never
    // read as a drain, gated or not (`interpret_read_event`'s non-EOF branch reports
    // `MembersRemain` either way). The ZERO-deadline check is the exact, correct tool here
    // (matching this file's own header promise), not a multi-second real wait. Whether the
    // wakeup itself is actually suppressed is a SEPARATE, lower-level claim, pinned by
    // `note_lowat_suppresses_a_wakeup_for_bytes_under_the_clamp` below (a verdict-only
    // assertion cannot distinguish "suppressed" from "delivered but harmless"). The child
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
        TreeDrain::AllMembersExited
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
        TreeDrain::AllMembersExited,
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
    // "poll-free" is actually supposed to stand behind, verified rather than assumed: a live
    // holder that never writes must genuinely BLOCK in the kernel for the wait's duration, not
    // merely return the right verdict at the right time (a verdict-only assertion cannot tell
    // "blocked" from "busy-polled the whole time" apart — both produce `MembersRemain` at the
    // same instant).
    //
    // The 300ms is a MEASUREMENT WINDOW, not a synchronization timeout: nothing is being
    // awaited here (the holder never exits during this test), it is how long CPU usage is
    // sampled for — there is no shorter, event-driven way to observe "no CPU was spent doing
    // nothing" than watching for a while. This is the one deliberate, named exception to the
    // "no synchronisation via time" global constraint, for exactly this reason.
    //
    // CPU is measured on THIS THREAD specifically (`CLOCK_THREAD_CPUTIME_ID`, not
    // `getrusage(RUSAGE_SELF)`, which is process-wide and would fold in whatever CPU work
    // `cargo test`'s other concurrently-running tests do on other threads during the same
    // window).
    let (child, marker, _stdin) = spawn_marker_holder("exec cat >/dev/null");
    let deadline = Duration::from_millis(300);
    let cpu_before = self_thread_cpu_time();
    let wall_before = Instant::now();
    let verdict = block_until_drained(marker.as_fd(), Some(Instant::now().checked_add(deadline)))
        .expect("bounded wait against a quiet holder");
    let wall_elapsed = wall_before.elapsed();
    let cpu_elapsed = self_thread_cpu_time() - cpu_before;

    assert_eq!(verdict, TreeDrain::MembersRemain);
    // Generous (5%): proving "genuinely blocked, not spinning," not chasing a tight bound
    // that would make this test sensitive to normal scheduling/syscall noise.
    assert!(
        cpu_elapsed < wall_elapsed / 20,
        "CPU time ({cpu_elapsed:?}) too high relative to wall time ({wall_elapsed:?}) for a holder \
         that never writes — looks like a busy-poll, not a genuine kernel block"
    );

    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn a_sustained_writer_never_exceeds_the_deadline() {
    // Distinct from the quiet-holder test above, deliberately NOT claiming low CPU usage
    // here: `yes` refills the pipe to the NOTE_LOWAT clamp about as fast as `drain_pending`
    // can empty it, so this case genuinely IS CPU-proportional to the writer's throughput for
    // the wait's duration — the module doc's own honest accounting, not a defect. What this
    // test pins is the property that must ALWAYS hold regardless: the wait terminates at (not
    // past) the deadline with the correct verdict, whatever it cost to get there —
    // `block_until_drained` checks the deadline explicitly before every `kevent` call
    // specifically so this holds even against a descriptor that stays continuously ready. The
    // slack below is deliberately tight (not the >100ms scheduling margin the sync
    // death-watch tests use elsewhere) because a regression of that fix should show up as a
    // large, easy-to-see overrun, not something a generous slack would quietly absorb.
    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh").args(["sh", "-c", "exec yes >&3"]);
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    let mut child = cmd.spawn().expect("spawn yes");
    let marker = child.fd_read_end(3.into()).expect("marker read end");

    let deadline = Duration::from_millis(300);
    let wall_before = Instant::now();
    let verdict = block_until_drained(marker.as_fd(), Some(Instant::now().checked_add(deadline)))
        .expect("bounded wait against a sustained writer");
    let wall_elapsed = wall_before.elapsed();

    assert_eq!(
        verdict,
        TreeDrain::MembersRemain,
        "a sustained writer must still report MembersRemain"
    );
    assert!(
        wall_elapsed <= deadline + Duration::from_millis(50),
        "must not exceed the deadline by more than one round's drain work: {wall_elapsed:?}"
    );

    child.kill().expect("kill the sustained writer");
    child.wait().expect("reap");
}

/// This CALLING THREAD's own CPU time, via `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` — NOT
/// `getrusage(RUSAGE_SELF)`, which is process-wide and would be contaminated by whatever other
/// tests `cargo test`'s concurrent thread pool happens to be running during the same
/// measurement window. Used only to distinguish "blocked" from "busy-polled" in the
/// quiet-holder test above — no production code depends on it.
fn self_thread_cpu_time() -> Duration {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: clock_gettime writes a fixed-size struct; pointer matches.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    assert_eq!(
        rc,
        0,
        "clock_gettime(CLOCK_THREAD_CPUTIME_ID) failed: {}",
        std::io::Error::last_os_error()
    );
    Duration::from_secs(ts.tv_sec.max(0) as u64) + Duration::from_nanos(ts.tv_nsec.max(0) as u64)
}
