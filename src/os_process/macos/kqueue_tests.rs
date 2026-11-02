//! Unit tests for the shared kqueue arm/drain primitives (macOS CI-only).

use std::os::fd::AsRawFd as _;

use super::{Event, Kqueue, SubscribeOutcome, Subscription};
use crate::identity::ProcessId;

#[skuld::test]
fn drain_reports_none_when_no_event_pending() {
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    // Alive until this test kills it: the arm-then-drain checks below need that.
    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn blocker");
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let kq = super::arm_proc_exit(id).expect("arm").expect("a live child arms");
    assert!(
        super::drain_proc_exit(&kq).expect("drain").is_none(),
        "no exit event yet must drain to None (spurious-readiness input)"
    );
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

/// `block_on_kqueue` with its frozen-clock advance dropped fails at the second round instead of
/// re-arming forever.
///
/// Mutant: drop the `advance_by_elapsed_if_frozen` call in `block_on_kqueue` -> same panic,
/// without the seam. Mutant: drop `block_on_kqueue`'s `check.round()` -> the round hook fails the
/// test with a different message, instead of the loop spinning forever.
#[skuld::test]
#[should_panic(expected = "no progress")]
fn block_on_kqueue_panics_when_its_advance_is_dropped() {
    use crate::wait::test_clock::{FrozenClockGuard, SkipAdvanceGuard};
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    let kq = Kqueue::new().expect("kqueue");
    let (_clock, at) = FrozenClockGuard::install();
    let _skip = SkipAdvanceGuard::install();
    // The frozen clock never advances here, so this deadline can never pass on the test clock,
    // however long a round is preempted; the real `kevent` blocks for it once per round.
    let deadline = Some(at + Duration::from_millis(5));
    // Ends a loop whose check is gone at its second round, with a panic the test rejects.
    let _hooks = super::test_hooks::HookGuard::install(|round, _| {
        assert!(round < 1, "the check let a second round run");
    });
    super::block_on_kqueue(&kq, deadline, false, |_, _| Ok(None)).ok();
}

/// Under a frozen clock a bounded `block_on_kqueue` ends: each real `kevent` advances the clock.
///
/// Mutant: drop the `advance_by_elapsed_if_frozen` call in `block_on_kqueue` -> the second round
/// panics with "no progress" instead of re-arming forever.
#[skuld::test]
fn block_on_kqueue_terminates_under_a_frozen_clock() {
    use crate::wait::test_clock::FrozenClockGuard;
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    let kq = Kqueue::new().expect("kqueue");
    let (_clock, at) = FrozenClockGuard::install();
    let deadline = Some(at + Duration::from_millis(5));
    let verdict = super::block_on_kqueue(&kq, deadline, true, |_, _| Ok(None)).expect("bounded wait");
    assert!(verdict, "an event-less wait ends by its deadline");
}

/// A remaining time above the clamp is re-armed from the real deadline: every `kevent` gets at
/// most the clamp, and the wait still ends only at the deadline. The frozen clock advances only
/// from the round hook, so real round durations cannot change the round count.
///
/// Mutants: drop the clamp -> the first call carries the whole 50ms; halve it -> 5ms calls.
#[skuld::test]
fn a_remaining_time_above_the_clamp_is_rearmed_in_pieces() {
    use crate::wait::test_clock::{advance, FrozenClockGuard, ZeroElapsedGuard};
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    let kq = Kqueue::new().expect("kqueue");
    let (_clock, at) = FrozenClockGuard::install();
    let _zero = ZeroElapsedGuard::install();
    let deadline = Some(at + Duration::from_millis(50));
    // Round 0 sees 50ms left, round 1 sees 30ms, round 2 sees none.
    let _hooks = super::test_hooks::HookGuard::install(|round, _| match round {
        1 => advance(Duration::from_millis(20)),
        2 => advance(Duration::from_millis(30)),
        _ => {}
    });
    let clamp = Duration::from_millis(10);
    super::test_hooks::set_clamp_override(clamp);
    let verdict = super::block_on_kqueue(&kq, deadline, true, |_, _| Ok(None)).expect("bounded wait");
    assert!(verdict, "an event-less wait ends by its deadline");
    let requested = super::test_hooks::requested_timeouts();
    assert_eq!(requested, [Some(clamp), Some(clamp), Some(Duration::ZERO)]);
}

/// The clamp override is reset only by a `HookGuard`'s `Drop`, so setting it without one is a
/// contract violation.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "needs a live HookGuard")]
fn the_clamp_override_requires_a_hook_guard() {
    super::test_hooks::set_clamp_override(std::time::Duration::from_millis(10));
}

/// The override may only lower the clamp: zero makes every `kevent` a poll, and anything above
/// `KEVENT_MAX_SECS` brings back the `EINVAL` the clamp exists to prevent.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "may only lower the clamp to a positive value")]
fn the_clamp_override_rejects_zero() {
    let _hooks = super::test_hooks::HookGuard::install(|_, _| {});
    super::test_hooks::set_clamp_override(std::time::Duration::ZERO);
}

#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "may only lower the clamp to a positive value")]
fn the_clamp_override_rejects_a_value_above_the_kevent_limit() {
    let _hooks = super::test_hooks::HookGuard::install(|_, _| {});
    super::test_hooks::set_clamp_override(std::time::Duration::from_secs(super::KEVENT_MAX_SECS + 1));
}

/// A forced timeout is checked like a computed one: above the limit it is a test bug, not an
/// `EINVAL` from the kernel.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "exceeds XNU's INT32_MAX limit")]
fn a_forced_timeout_above_the_kevent_limit_is_rejected() {
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    let kq = Kqueue::new().expect("kqueue");
    let _hooks = super::test_hooks::HookGuard::install(|_, _| {});
    super::test_hooks::set_timeout_override(Duration::from_secs(super::KEVENT_MAX_SECS + 1));
    super::block_on_kqueue(&kq, None, false, |_, _| Ok(Some(true))).ok();
}

/// `kevent_timeout` at the limit's edges, on the real `KEVENT_MAX_SECS`.
///
/// Mutants: always return the cap; drop `subsec_nanos`; cap at `KEVENT_MAX_SECS + 1`.
#[skuld::test]
fn kevent_timeout_caps_at_the_limit_and_keeps_the_rest() {
    use std::time::Duration;

    let max = super::KEVENT_MAX_SECS;
    let cases = [
        (Duration::ZERO, (0, 0)),
        (Duration::new(3, 123_456_789), (3, 123_456_789)),
        (Duration::new(max - 1, 999_999_999), (max - 1, 999_999_999)),
        (Duration::new(max, 0), (max, 0)),
        (Duration::new(max, 1), (max, 0)),
        (Duration::new(max + 1, 0), (max, 0)),
        (Duration::from_secs(u64::from(u32::MAX)), (max, 0)),
        (Duration::MAX, (max, 0)),
    ];
    for (input, (secs, nanos)) in cases {
        let ts = super::kevent_timeout(input);
        assert_eq!(
            (ts.tv_sec as u64, ts.tv_nsec as u64),
            (secs, nanos as u64),
            "for {input:?}"
        );
    }
}

/// `Ok(0)` with time left is classified: a full-cap timeout is the intended re-arm, anything
/// else is an anomaly. Judged against the cap in force, including a lowered one.
#[skuld::test]
fn a_zero_return_is_a_rearm_only_after_a_full_cap_timeout() {
    use super::ZeroReturn::{Anomaly, Rearm};
    use std::time::Duration;

    let max = Duration::from_secs(super::KEVENT_MAX_SECS);
    assert_eq!(super::classify_zero_return(Some(max)), Rearm);
    assert_eq!(
        super::classify_zero_return(Some(max - Duration::from_nanos(1))),
        Anomaly
    );
    assert_eq!(super::classify_zero_return(Some(Duration::ZERO)), Anomaly);
    assert_eq!(super::classify_zero_return(None), Anomaly);
    let _hooks = super::test_hooks::HookGuard::install(|_, _| {});
    let lowered = Duration::from_millis(10);
    super::test_hooks::set_clamp_override(lowered);
    assert_eq!(super::classify_zero_return(Some(lowered)), Rearm);
    assert_eq!(super::classify_zero_return(Some(max)), Anomaly);
}

/// The two `Ok(0)`-with-time-left dispositions reach the log at their own level: the intended
/// re-arm at debug, a short timeout that woke early at warn. Neither retries silently.
///
/// Mutants: swap the arms; drop either log.
#[skuld::test]
fn a_zero_return_with_time_left_is_logged_by_kind() {
    use crate::wait::test_clock::{advance, FrozenClockGuard, ZeroElapsedGuard};
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    crate::log_capture::install();
    const REARM: &str = "kevent reached its timeout cap with time left";
    const EARLY: &str = "kevent returned 0 after a timeout below the cap";
    let kq = Kqueue::new().expect("kqueue");
    let (_clock, at) = FrozenClockGuard::install();
    let _zero = ZeroElapsedGuard::install();
    let deadline = Some(at + Duration::from_millis(50));
    // Round 0: clamp-sized timeout. Round 1: a forced 1ms timeout (below the clamp). Round 2: done.
    let _hooks = super::test_hooks::HookGuard::install(|round, _| match round {
        1 => super::test_hooks::set_timeout_override(Duration::from_millis(1)),
        2 => advance(Duration::from_millis(50)),
        _ => {}
    });
    super::test_hooks::set_clamp_override(Duration::from_millis(10));
    let mark = crate::log_capture::mark();
    super::block_on_kqueue(&kq, deadline, true, |_, _| Ok(None)).expect("bounded wait");
    let levels = |marker| {
        crate::log_capture::records_since_on_current_thread(mark, marker)
            .into_iter()
            .map(|(level, _)| level)
            .collect::<Vec<_>>()
    };
    assert_eq!(levels(REARM), [log::Level::Debug]);
    assert_eq!(levels(EARLY), [log::Level::Warn]);
}

// The `Kqueue` type ==================================================================

/// Blocks until `kq`'s descriptor reports something pending: the real condition, with no timeout.
fn wait_readable(kq: &Kqueue) {
    let mut fd = libc::pollfd {
        fd: kq.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: one valid `pollfd`.
        let n = unsafe { libc::poll(&mut fd, 1, -1) };
        if n == 1 {
            return;
        }
        let e = std::io::Error::last_os_error();
        assert!(n == -1 && e.raw_os_error() == Some(libc::EINTR), "poll: {e}");
    }
}

/// Reads `kq` whenever it turns readable, accumulating events until `done` holds for all so far.
fn poll_until(kq: &Kqueue, mut done: impl FnMut(&[Event]) -> bool) -> Vec<Event> {
    let mut seen = Vec::new();
    loop {
        wait_readable(kq);
        seen.extend(kq.poll().expect("poll"));
        if done(&seen) {
            return seen;
        }
    }
}

fn exited(seen: &[Event], pid: u32) -> bool {
    seen.iter()
        .any(|e| matches!(e, Event::Process { pid: p, exited: true, .. } if *p == pid))
}

fn spawn_blocker() -> std::process::Child {
    crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn blocker")
}

fn no_events() -> Vec<Event> {
    Vec::new()
}

#[skuld::test]
fn a_process_subscription_on_a_reaped_pid_is_process_gone() {
    let mut child = crate::test_spawn::spawn(&mut std::process::Command::new("true")).expect("spawn true");
    let pid = child.id();
    child.wait().expect("reap");
    let kq = Kqueue::new().expect("kqueue");
    let outcome = kq
        .subscribe(Subscription::Process {
            pid,
            signals: false,
            reap: false,
        })
        .expect("subscribe");
    assert_eq!(outcome, SubscribeOutcome::ProcessGone);
}

#[skuld::test]
fn a_process_subscription_reports_the_exit() {
    let mut child = spawn_blocker();
    let pid = child.id();
    let kq = Kqueue::new().expect("kqueue");
    let sub = Subscription::Process {
        pid,
        signals: false,
        reap: false,
    };
    assert_eq!(kq.subscribe(sub).expect("subscribe"), SubscribeOutcome::Subscribed);
    child.kill().expect("kill");
    poll_until(&kq, |seen| exited(seen, pid));
    child.wait().expect("reap");
}

#[skuld::test]
fn a_signals_subscription_reports_a_signal_before_the_exit() {
    let mut child = spawn_blocker();
    let pid = child.id();
    let kq = Kqueue::new().expect("kqueue");
    let sub = Subscription::Process {
        pid,
        signals: true,
        reap: false,
    };
    assert_eq!(kq.subscribe(sub).expect("subscribe"), SubscribeOutcome::Subscribed);
    // SAFETY: `kill` with a live child's pid and a valid signal.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) }, 0);
    let seen = poll_until(&kq, |seen| exited(seen, pid));
    // The signal was posted before the exit: in an earlier event, or merged into the exit's.
    assert!(
        seen.iter().any(|e| matches!(e, Event::Process { signalled: true, .. })),
        "{seen:?}"
    );
    child.wait().expect("reap");
}

#[skuld::test]
fn a_reap_subscription_reports_the_reap() {
    let mut child = spawn_blocker();
    let pid = child.id();
    let kq = Kqueue::new().expect("kqueue");
    let sub = Subscription::Process {
        pid,
        signals: false,
        reap: true,
    };
    assert_eq!(kq.subscribe(sub).expect("subscribe"), SubscribeOutcome::Subscribed);
    child.kill().expect("kill");
    child.wait().expect("reap");
    poll_until(&kq, |seen| {
        seen.iter()
            .any(|e| matches!(e, Event::Process { pid: p, reaped: true, .. } if *p == pid))
    });
}

#[skuld::test]
fn a_readable_subscription_reports_bytes_once_per_change() {
    use std::io::Write as _;

    let (reader, mut writer) = std::io::pipe().expect("pipe");
    let fd = reader.as_raw_fd();
    let kq = Kqueue::new().expect("kqueue");
    let sub = Subscription::Readable { fd, low_water: 1 };
    assert_eq!(kq.subscribe(sub).expect("subscribe"), SubscribeOutcome::Subscribed);
    writer.write_all(b"abc").expect("write");
    wait_readable(&kq);
    assert_eq!(
        kq.poll().expect("poll"),
        [Event::Readable {
            fd,
            bytes: 3,
            closed: false
        }]
    );
    assert_eq!(kq.poll().expect("poll again"), no_events());
}

#[skuld::test]
fn a_readable_subscription_holds_below_its_low_water() {
    use std::io::Write as _;

    let (reader, mut writer) = std::io::pipe().expect("pipe");
    let fd = reader.as_raw_fd();
    let kq = Kqueue::new().expect("kqueue");
    let sub = Subscription::Readable { fd, low_water: 4 };
    assert_eq!(kq.subscribe(sub).expect("subscribe"), SubscribeOutcome::Subscribed);
    writer.write_all(b"a").expect("write one byte");
    assert_eq!(kq.poll().expect("poll"), no_events());
    writer.write_all(b"bcd").expect("write three more");
    wait_readable(&kq);
    assert_eq!(
        kq.poll().expect("poll"),
        [Event::Readable {
            fd,
            bytes: 4,
            closed: false
        }]
    );
}

#[skuld::test]
fn a_readable_subscription_reports_the_close() {
    let (reader, writer) = std::io::pipe().expect("pipe");
    let fd = reader.as_raw_fd();
    let kq = Kqueue::new().expect("kqueue");
    let sub = Subscription::Readable { fd, low_water: 1 };
    assert_eq!(kq.subscribe(sub).expect("subscribe"), SubscribeOutcome::Subscribed);
    drop(writer);
    wait_readable(&kq);
    let events = kq.poll().expect("poll");
    assert!(
        matches!(events.as_slice(), [Event::Readable { fd: f, closed: true, .. }] if *f == fd),
        "{events:?}"
    );
}

#[skuld::test]
fn a_signal_subscription_counts_deliveries() {
    let kq = Kqueue::new().expect("kqueue");
    assert_eq!(
        kq.subscribe(Subscription::Signal(libc::SIGCHLD)).expect("subscribe"),
        SubscribeOutcome::Subscribed
    );
    let mut child = crate::test_spawn::spawn(&mut std::process::Command::new("true")).expect("spawn true");
    child.wait().expect("reap");
    let seen = poll_until(&kq, |seen| {
        seen.iter()
            .any(|e| matches!(e, Event::Signal { signo, .. } if *signo == libc::SIGCHLD))
    });
    assert!(
        seen.iter()
            .any(|e| matches!(e, Event::Signal { signo, count } if *signo == libc::SIGCHLD && *count >= 1)),
        "{seen:?}"
    );
}

#[skuld::test]
fn unsubscribe_stops_reports_and_accepts_a_delivered_exit() {
    use std::io::Write as _;

    let kq = Kqueue::new().expect("kqueue");

    let (reader, mut writer) = std::io::pipe().expect("pipe");
    let readable = Subscription::Readable {
        fd: reader.as_raw_fd(),
        low_water: 1,
    };
    kq.subscribe(readable).expect("subscribe");
    kq.unsubscribe(readable).expect("unsubscribe");
    writer.write_all(b"abc").expect("write");
    assert_eq!(kq.poll().expect("poll"), no_events());

    // The kernel removes a delivered exit's knote itself; the unsubscribe after it is fine.
    let mut child = spawn_blocker();
    let pid = child.id();
    let process = Subscription::Process {
        pid,
        signals: false,
        reap: false,
    };
    kq.subscribe(process).expect("subscribe");
    child.kill().expect("kill");
    poll_until(&kq, |seen| exited(seen, pid));
    child.wait().expect("reap");
    kq.unsubscribe(process).expect("unsubscribe after the exit");
}

#[skuld::test]
fn poll_on_an_empty_queue_is_empty() {
    assert_eq!(Kqueue::new().expect("kqueue").poll().expect("poll"), no_events());
}

#[skuld::test]
fn from_kevent_maps_each_filter() {
    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

    let map = |ev: KEvent| Event::from_kevent(&ev).expect("map");

    for bits in 0u8..8 {
        let (exit, signal, reap) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
        let mut fflags = FilterFlag::empty();
        if exit {
            fflags |= FilterFlag::NOTE_EXIT;
        }
        if signal {
            fflags |= FilterFlag::NOTE_SIGNAL;
        }
        if reap {
            fflags |= FilterFlag::from_bits_retain(super::NOTE_REAP);
        }
        let ev = KEvent::new(4242, EventFilter::EVFILT_PROC, EvFlags::empty(), fflags, 0, 0);
        assert_eq!(
            map(ev),
            Some(Event::Process {
                pid: 4242,
                exited: exit,
                signalled: signal,
                reaped: reap
            }),
            "fflags {fflags:?}"
        );
    }

    for (flags, closed) in [(EvFlags::empty(), false), (EvFlags::EV_EOF, true)] {
        let ev = KEvent::new(7, EventFilter::EVFILT_READ, flags, FilterFlag::empty(), 3, 0);
        assert_eq!(
            map(ev),
            Some(Event::Readable {
                fd: 7,
                bytes: 3,
                closed
            })
        );
    }

    let ev = KEvent::new(
        libc::SIGCHLD as usize,
        EventFilter::EVFILT_SIGNAL,
        EvFlags::empty(),
        FilterFlag::empty(),
        2,
        0,
    );
    assert_eq!(
        map(ev),
        Some(Event::Signal {
            signo: libc::SIGCHLD,
            count: 2
        })
    );

    let timer = KEvent::new(
        1,
        EventFilter::EVFILT_TIMER,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    );
    assert_eq!(map(timer), None);

    let failed = KEvent::new(
        9,
        EventFilter::EVFILT_READ,
        EvFlags::EV_ERROR,
        FilterFlag::empty(),
        libc::EBADF as isize,
        0,
    );
    let err = Event::from_kevent(&failed).expect_err("EV_ERROR is an error");
    assert_eq!(err.raw_os_error(), Some(libc::EBADF));
}
