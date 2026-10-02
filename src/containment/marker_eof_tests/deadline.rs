//! The deadline contract (never early, checked every round, no drain past expiry) and the
//! no-spin claim, proven structurally. Deadline-elapsed cases advance `crate::wait::test_clock`
//! instead of waiting; "blocked, not busy-polling" is proven by counting real `kevent` calls,
//! never by sampling CPU time.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

use super::{fill_pipe_to_capacity, fionread, marker_pipe, spawn_marker_holder};
use crate::containment::marker_eof::{arm, block_until_drained, drain_test_hooks, interpret_read_event, probe};
use crate::containment::TreeDrain;
use crate::wait::backend::test_hooks;
use crate::wait::test_clock;

/// This system's real pipe buffer capacity, MEASURED rather than assumed: fill a throwaway,
/// non-blocking, in-process pipe until `write` reports `EAGAIN`, and sum what fit. A writer
/// told to write precisely this many bytes, then stop, fills the marker pipe to at least the
/// ready threshold — no concurrent reader required to avoid deadlock. Used only to pick how
/// much a test's OWN writer script should write; never compared directly against a value
/// measured on the marker pipe itself (a SEPARATE kernel object — see `pipe_blksize`).
fn measure_pipe_capacity() -> usize {
    let (_r, w) = marker_pipe();
    let flags = rustix::fs::fcntl_getfl(&w).unwrap_or_else(|e| panic!("fcntl F_GETFL failed: {e}"));
    rustix::fs::fcntl_setfl(&w, flags | rustix::fs::OFlags::NONBLOCK)
        .unwrap_or_else(|e| panic!("fcntl F_SETFL O_NONBLOCK failed: {e}"));
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

/// The kernel's own record of `fd`'s CURRENT pipe buffer capacity — `fstat`'s `st_blksize` on a
/// macOS pipe reports exactly this (measured: an empty, freshly grown pipe read 16384, then a
/// filled one read 65536, matching `FIONREAD` once full). Unlike [`measure_pipe_capacity`],
/// this queries the SAME kernel object a test is actually asserting about, not a separate
/// scratch pipe — the two can differ, since XNU grows each pipe's buffer independently based on
/// its own write history (`sys_pipe.c`).
fn pipe_blksize(fd: BorrowedFd<'_>) -> isize {
    // SAFETY: `st` is a single, correctly-sized `libc::stat`; `fstat` writes only within it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
    assert_eq!(rc, 0, "fstat failed: {}", std::io::Error::last_os_error());
    st.st_blksize as isize
}

/// Block (real, event-driven, no timer) until `fd` becomes ready again on a FRESH,
/// independently-armed kqueue — used from inside a round hook to know, deterministically, that
/// the pipe has crossed the low-water mark again (e.g. after an earlier round drained it). A
/// private kqueue composes with `block_on_kqueue`'s own (`arm`'s doc: "one kqueue per waiter"),
/// so this never disturbs the wait under test.
fn block_until_marker_ready_again(fd: BorrowedFd<'_>) {
    let kq = arm(fd, false).expect("arm auxiliary kqueue");
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
fn a_quiet_live_holder_resolves_in_one_real_blocking_kevent_call() {
    // A live holder that never writes must resolve the bounded wait in exactly ONE real,
    // blocking `kevent` call; the call count is what catches a busy-poll, not a CPU-time
    // sample. A frozen clock (rather than the real one) makes the count deterministic:
    // `block_on_kqueue`'s `Ok(0)` re-check auto-advances the frozen clock by the round's own
    // real elapsed time (`test_clock::advance_by_elapsed_if_frozen`), and "never early" means
    // that elapsed time is always >= what was requested — so round 0 always concludes by
    // itself. Under the REAL clock, a boundary race (the kernel's own timeout firing a hair
    // before `Instant::now()` agrees) could legitimately need a 2nd, near-instant round.
    let _hook_guard = test_hooks::HookGuard::install(|_round, _kq| {});
    let (child, marker, _stdin) = spawn_marker_holder("exec cat >/dev/null");
    let (_clock_guard, frozen_now) = test_clock::FrozenClockGuard::install();
    let deadline = frozen_now.checked_add(Duration::from_millis(300)).expect("deadline");

    let verdict =
        block_until_drained(marker.as_fd(), Some(Some(deadline))).expect("bounded wait against a quiet holder");

    assert_eq!(verdict, TreeDrain::MembersRemain);
    assert_eq!(
        test_hooks::kevent_calls(),
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
    // assertion (cosca promises none): a frozen clock makes round 0's requested timeout
    // EXACTLY one year (not "some value over 1s", immune to test-setup latency), and the
    // round-1 hook advances that SAME clock past the deadline before round 1's own
    // `remaining(deadline)` is computed, making round 1's requested timeout EXACTLY zero. The
    // round hook asserts `round <= 1` on every firing, so a third round (the extra-round
    // mutant) fails immediately, from inside the hook, the instant it starts.
    //
    // Round 1 must perform NO drain (principle 13). `containment::marker_eof::drain_test_hooks`'s
    // cumulative, monotonically-increasing drained-bytes counter proves this — NOT a `FIONREAD`
    // snapshot, which `yes`'s continued writing could refill between round 1 and the final
    // check, making "drained nothing" indistinguishable from "drained plenty, then refilled".
    // `baseline > 0` additionally proves round 0 genuinely drained something first — otherwise
    // "round 1 matches the baseline" would trivially hold even if draining were broken
    // everywhere. The round-1 hook also directly proves round 1 went through `interpret` with
    // `elapsed == true` (not merely "resolved via Ok(0)"): `last_event_data()` after the wait
    // reflects the MOST RECENT `Ok(n > 0)` event, so a positive value here can only have come
    // from round 1's own real, non-EOF event.
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

    let (_clock_guard, frozen_now) = test_clock::FrozenClockGuard::install();
    let one_year = Duration::from_secs(365 * 24 * 3600);
    let deadline = frozen_now.checked_add(one_year).expect("deadline");

    let drained_baseline = std::rc::Rc::new(std::cell::Cell::new(None::<u64>));
    let drained_baseline_for_hook = std::rc::Rc::clone(&drained_baseline);
    let _hook_guard = test_hooks::HookGuard::install(move |round, _kq| {
        assert!(
            round <= 1,
            "must not start a third round after the deadline has elapsed — extra-round mutant, \
             round={round}"
        );
        if round == 1 {
            // SAFETY: `raw_fd` is `marker`'s descriptor, open for this whole test.
            let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
            block_until_marker_ready_again(fd);
            drained_baseline_for_hook.set(Some(drain_test_hooks::drained_bytes()));
            test_clock::advance(one_year + Duration::from_secs(86_400));
        }
    });

    let verdict = block_until_drained(marker.as_fd(), Some(Some(deadline))).expect("bounded wait");

    assert_eq!(
        verdict,
        TreeDrain::MembersRemain,
        "a sustained writer must still report MembersRemain"
    );

    let calls = test_hooks::kevent_calls();
    assert_eq!(
        calls, 2,
        "exactly two real kevent calls: one round that saw the deadline as still open, then one \
         more round whose already_elapsed check (from the frozen, mock-advanced clock) stops \
         the loop — never a third round"
    );

    let requested = test_hooks::requested_timeouts();
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
    assert!(
        baseline > 0,
        "round 0 must have drained something — otherwise this test can't distinguish 'round 1 \
         correctly drained nothing' from 'draining is broken everywhere'"
    );
    assert_eq!(
        drain_test_hooks::drained_bytes(),
        baseline,
        "round 1 must not have drained any bytes once the deadline had elapsed (principle 13) — \
         the cumulative drained-bytes counter moved after round 1's own precondition was set"
    );
    assert!(
        test_hooks::last_event_data().expect("round 1 must have seen a real event") > 0,
        "round 1 must have gone through interpret() with a genuine non-EOF event (elapsed=true), \
         not merely resolved via a bare Ok(0)"
    );

    child.kill().expect("kill the sustained writer");
    child.wait().expect("reap");
}

#[test]
fn an_event_that_arrives_after_the_clock_moves_past_the_deadline_mid_round_does_not_drain() {
    // The gap the test above cannot reach: there, the clock moves BEFORE round 1's own
    // `remaining(deadline)` is computed, so the pre-call `already_elapsed` sample is already
    // correct. This test moves the clock strictly AFTER the pre-call sample (still `false`:
    // the deadline is 60s out) but BEFORE `block_on_kqueue` decides whether to drain —
    // "deadline passes while kevent was blocking" — via
    // `HookGuard::install_with_post_event`'s post-event hook.
    let cap = measure_pipe_capacity();
    let (child, marker, stdin) = spawn_marker_holder(&format!("yes | head -c {cap} >&3; exec cat >/dev/null"));

    let (_clock_guard, frozen_now) = test_clock::FrozenClockGuard::install();
    let deadline = frozen_now.checked_add(Duration::from_secs(60)).expect("deadline");

    let _hook_guard = test_hooks::HookGuard::install_with_post_event(
        |_round, _kq| {},
        |round| {
            if round == 0 {
                test_clock::advance(Duration::from_secs(120));
            }
        },
    );

    let baseline = drain_test_hooks::drained_bytes();
    let verdict = block_until_drained(marker.as_fd(), Some(Some(deadline))).expect("bounded wait");

    assert_eq!(
        verdict,
        TreeDrain::MembersRemain,
        "the writer is still alive and holding the descriptor — the event was non-EOF"
    );
    assert_eq!(
        test_hooks::kevent_calls(),
        1,
        "the deadline is discovered elapsed as soon as the (only) event arrives — no second round"
    );
    assert_eq!(
        drain_test_hooks::drained_bytes(),
        baseline,
        "an event that arrives after the deadline has passed, even if that only became true \
         WHILE the kevent call was blocked, must not drain"
    );

    drop(stdin);
    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn a_spurious_ok0_under_a_frozen_clock_retries_until_the_clock_advances() {
    // No other test exercises `block_on_kqueue`'s own defensive branch: `Ok(0)` with
    // `remaining(deadline)` still non-zero (see that function's own doc for why it exists — a
    // bug could desync the requested timeout from `remaining`). Constructing this for real
    // would need a REAL, long wait (the requested timeout IS `remaining`, so a genuine `Ok(0)`
    // implies the deadline is genuinely close) — instead, `test_hooks::set_timeout_override`
    // forces round 0's REAL, OS-level timeout to a few milliseconds while `remaining(deadline)`
    // (unaffected by the override) still reports the frozen deadline, a year out, as wide
    // open. Round 0 genuinely, quickly times out; the re-check refuses to trust it (spurious,
    // retried); only round 1's hook — moving the SAME frozen clock past the deadline before its
    // own `remaining` is computed — lets the wait conclude.
    let (child, marker, _stdin) = spawn_marker_holder("exec cat >/dev/null");
    let (_clock_guard, frozen_now) = test_clock::FrozenClockGuard::install();
    let one_year = Duration::from_secs(365 * 24 * 3600);
    let deadline = frozen_now.checked_add(one_year).expect("deadline");

    // `set_timeout_override` AFTER `HookGuard::install`: `install` resets every seam first
    // (including any pending override), so setting it any earlier would be wiped out.
    let _hook_guard = test_hooks::HookGuard::install(move |round, _kq| {
        if round == 1 {
            test_clock::advance(one_year + Duration::from_secs(86_400));
        }
    });
    test_hooks::set_timeout_override(Duration::from_millis(20));

    let verdict = block_until_drained(marker.as_fd(), Some(Some(deadline))).expect("bounded wait");

    assert_eq!(verdict, TreeDrain::MembersRemain);
    assert_eq!(
        test_hooks::kevent_calls(),
        2,
        "round 0's real, short-overridden timeout genuinely expires while remaining(deadline) \
         still reports the far future — spurious, retried; round 1, after the hook moves the \
         clock, genuinely concludes — never more than two calls"
    );
    let requested = test_hooks::requested_timeouts();
    assert_eq!(
        requested[0],
        Some(Duration::from_millis(20)),
        "round 0's requested timeout must be the OVERRIDDEN value, proving the mismatch with \
         remaining(deadline) was real, not incidental"
    );

    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn an_unbounded_wait_against_a_sustained_writer_blocks_without_spending_cpu() {
    // The unbounded counterpart to the quiet-holder test above: with `deadline: None` there is
    // no caller-supplied bound to pay a per-round drain against, so this wait must not drain
    // past the low-water clamp at all — the writer's own `write()` blocks against the full
    // pipe instead, and the wait genuinely blocks in the kernel rather than busy-looping.
    //
    // A writer that writes EXACTLY the measured pipe capacity via `head -c`, then PARKS (holds
    // the descriptor, writes nothing more), so round 0 genuinely observes a non-EOF, ready
    // event with real buffered bytes, and only round 1's hook ends the wait. Between the two
    // rounds, the round-1 hook proves both properties a broken implementation would break:
    //   - `FIONREAD` still equals round 0's own recorded `event.data()` — nothing was drained;
    //   - a manual, zero-timeout `kevent` on the SAME kqueue (passed into the hook) returns ZERO
    //     events, even though the level condition is unchanged — `EV_CLEAR` is actually armed.
    // Only after both checks does the hook kill and reap the writer, ending the wait via a real
    // `EV_EOF` on round 1's own `kevent` call.
    //
    // `spawn_marker_holder` gives the child a REAL stdin pipe this test holds open: under
    // nextest, an unredirected stdin is `/dev/null`, so `exec cat >/dev/null` would see
    // immediate EOF and exit at once instead of parking. `_stdin` stays bound until after the
    // wait concludes.
    let cap = measure_pipe_capacity();
    let (child, marker, _stdin) = spawn_marker_holder(&format!("yes | head -c {cap} >&3; exec cat >/dev/null"));
    let raw_fd = marker.as_raw_fd();

    let mut child_opt = Some(child);
    let _hook_guard = test_hooks::HookGuard::install(move |round, kq| {
        assert!(
            round <= 1,
            "the wait should have concluded by round 1, got round={round}"
        );
        if round != 1 {
            return;
        }
        // SAFETY: `raw_fd` is `marker`'s descriptor, open for this whole test.
        let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };

        let round0_data = test_hooks::last_event_data().expect("round 0 must have recorded a non-EOF event's data");
        // `> 0, not == cap`: XNU pipes grow by their own write history, so a capacity measured
        // on a SEPARATE scratch pipe is not guaranteed to equal what THIS marker pipe grew to.
        // Compare against `pipe_blksize`, the KERNEL's own record for THIS descriptor instead —
        // the clamp `arm`'s `NOTE_LOWAT` actually settled at on the marker pipe itself.
        let blksize = pipe_blksize(fd);
        assert_eq!(
            round0_data, blksize,
            "round 0's event must report exactly the marker pipe's own kernel-reported capacity"
        );
        assert_eq!(
            fionread(fd) as isize,
            round0_data,
            "an unbounded wait must not drain any bytes in round 0 (decision: unbounded never \
             drains) — FIONREAD dropped below round 0's own reported byte count"
        );

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
        test_hooks::kevent_calls(),
        2,
        "round 0 (the undrained, non-EOF event) plus round 1 (the EOF that ends the wait) — \
         exactly two real kevent calls, not a busy-poll"
    );
}

#[test]
fn arm_sets_ev_clear_so_a_repeated_poll_without_a_new_edge_reports_nothing() {
    // White-box proof `arm` requests `EV_CLEAR`: a level that crossed the clamp once and has
    // stayed there ever since, unchanged and undrained, must not re-fire.
    let cap = measure_pipe_capacity();
    let (child, marker, _stdin) = spawn_marker_holder(&format!("yes | head -c {cap} >&3; exec cat >/dev/null"));
    let kq = arm(marker.as_fd(), false).expect("arm");
    let mut events = [KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    )];

    let n = kq.kevent(&[], &mut events, None).expect("initial blocking poll");
    assert_eq!(n, 1, "expected the initial crossing to be ready");
    assert!(
        !events[0].flags().contains(EvFlags::EV_EOF),
        "the writer is still alive and holding the descriptor — this must not be EOF"
    );

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
    // White-box: `suppress_drain = true` must never consume bytes, exercised with a real event.
    let cap = measure_pipe_capacity();
    let (child, marker, _stdin) = spawn_marker_holder(&format!("yes | head -c {cap} >&3; exec cat >/dev/null"));
    let kq = arm(marker.as_fd(), true).expect("arm");
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
    let verdict = interpret_read_event(&events[0], marker.as_fd(), true).expect("interpret with suppress_drain=true");
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
    // `probe` is itself a check AT expiry (principle 13); this fills the pipe in-process BEFORE
    // the holder child exists, so there's no race with an external writer to call `probe` too
    // early against.
    let (marker_r, marker_w) = std::io::pipe().expect("pipe");
    let queued_before = fill_pipe_to_capacity(marker_r.as_fd(), marker_w.as_fd());
    assert!(
        queued_before > 0,
        "the pipe must be filled before this test can prove probe() doesn't drain it"
    );

    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh").args(["sh", "-c", "exec cat >/dev/null"]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    // Moves `marker_w` in — this test's own copy is gone from here on, before `probe` ever
    // runs, so `arm`'s write-end-retained check sees a clean `Clear`, not `HeldByUs`.
    cmd.fd(
        3,
        crate::Stdio::from_file(std::fs::File::from(std::os::fd::OwnedFd::from(marker_w))),
    )
    .expect("marker pipe");
    let child = cmd.spawn().expect("spawn /bin/sh");
    let fd = marker_r.as_fd();
    assert_eq!(
        child.try_wait().expect("try_wait"),
        None,
        "the holder already exited before this test could observe it"
    );

    let baseline = drain_test_hooks::drained_bytes();
    let verdict = probe(fd).expect("probe");
    let queued_after = fionread(fd);

    assert_eq!(
        verdict,
        TreeDrain::MembersRemain,
        "the writer is still alive and holding the descriptor — the event was non-EOF"
    );
    assert_eq!(
        queued_after, queued_before,
        "probe must not consume any bytes from the pipe"
    );
    assert_eq!(
        drain_test_hooks::drained_bytes(),
        baseline,
        "probe is a check at expiry (principle 13) and must never drain"
    );

    child.kill().expect("kill");
    child.wait().expect("reap");
}
