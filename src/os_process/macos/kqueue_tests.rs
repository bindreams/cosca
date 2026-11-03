//! Unit tests for the `Kqueue` type and its blocking `wait` (macOS CI-only).

use std::os::fd::AsRawFd as _;

use super::{Event, Kqueue, Subscription, WaitOutcome};
use crate::identity::ProcessId;

#[skuld::test]
fn poll_reports_nothing_while_the_process_lives() {
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    // Alive until this test kills it: the arm-then-poll checks below need that.
    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn blocker");
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let kq = super::arm_proc_exit(id).expect("arm").expect("a live child arms");
    assert!(
        kq.poll().expect("poll").is_empty(),
        "no exit event yet must poll to nothing (spurious-readiness input)"
    );
    child.kill().expect("cleanup");
    child.wait().expect("reap");
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
/// else is an anomaly.
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
}

/// After a `kevent` that delivered nothing the loop ends only when the freshly read remaining time
/// is zero; otherwise it goes round, and the armed timeout says whether that was the intended
/// re-arm.
///
/// Mutants: end on any empty read; ignore `remaining`; classify against `remaining` instead of the
/// armed timeout.
#[skuld::test]
fn after_an_empty_read_the_loop_ends_only_at_the_deadline() {
    use super::Step::{Again, DeadlinePassed};
    use super::ZeroReturn::{Anomaly, Rearm};
    use std::time::Duration;

    let cap = Duration::from_secs(super::KEVENT_MAX_SECS);
    let (zero, one_ns, five_ms, one_s) = (
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_millis(5),
        Duration::from_secs(1),
    );
    let cases = [
        (Some(cap), Some(zero), DeadlinePassed),
        (Some(cap), Some(one_s), Again(Rearm)),
        (Some(cap - one_ns), Some(one_s), Again(Anomaly)),
        (Some(five_ms), Some(zero), DeadlinePassed),
        (Some(five_ms), Some(one_ns), Again(Anomaly)),
        (Some(zero), Some(zero), DeadlinePassed),
        (Some(zero), Some(one_ns), Again(Anomaly)),
        (None, None, Again(Anomaly)),
    ];
    for (armed, remaining, want) in cases {
        assert_eq!(
            super::after_empty_read(armed, remaining),
            want,
            "armed {armed:?}, remaining {remaining:?}"
        );
    }
}

/// Waits on `kq`, accumulating events until `done` holds for all so far.
fn poll_until(kq: &Kqueue, mut done: impl FnMut(&[Event]) -> bool) -> Vec<Event> {
    let mut seen = Vec::new();
    loop {
        seen.extend(wait_events(kq));
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

/// The errno of a kernel refusal: an `Error::Io` carrying it raw, or the test fails.
fn refusal(result: Result<(), crate::error::Error>) -> i32 {
    match result {
        Err(crate::error::Error::Io(e)) => e.raw_os_error().expect("a refusal names its errno"),
        other => panic!("expected the kernel's refusal, got {other:?}"),
    }
}

#[skuld::test]
fn a_process_subscription_on_a_pid_that_names_no_process_is_refused_with_esrch() {
    // macOS pids stay below PID_MAX (99999), so this never names a process, and `proc_find` fails.
    let pid = i32::MAX as u32;
    let kq = Kqueue::new().expect("kqueue");
    let refused = kq.subscribe(Subscription::Process {
        pid,
        signals: false,
        reap: false,
    });
    assert_eq!(refusal(refused), libc::ESRCH);
}

#[skuld::test]
fn a_readable_subscription_on_an_fd_that_is_not_open_is_refused_with_ebadf() {
    // Far above any descriptor limit, so never open. A just-closed fd is not: the next open, such
    // as the kqueue's own, takes its number.
    let fd = std::os::fd::RawFd::MAX;
    let kq = Kqueue::new().expect("kqueue");
    let refused = kq.subscribe(Subscription::Readable { fd, low_water: 1 });
    assert_eq!(refusal(refused), libc::EBADF);
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
    kq.subscribe(sub).expect("subscribe");
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
    kq.subscribe(sub).expect("subscribe");
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
    kq.subscribe(sub).expect("subscribe");
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
    kq.subscribe(sub).expect("subscribe");
    writer.write_all(b"abc").expect("write");
    assert_eq!(
        wait_events(&kq),
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
    kq.subscribe(sub).expect("subscribe");
    writer.write_all(b"a").expect("write one byte");
    assert_eq!(kq.poll().expect("poll"), no_events());
    writer.write_all(b"bcd").expect("write three more");
    assert_eq!(
        wait_events(&kq),
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
    kq.subscribe(sub).expect("subscribe");
    drop(writer);
    let events = wait_events(&kq);
    assert!(
        matches!(events.as_slice(), [Event::Readable { fd: f, closed: true, .. }] if *f == fd),
        "{events:?}"
    );
}

const SIGNAL_COUNT_MARKER: &str = "COSCA_TEST_KQUEUE_SIGNAL_COUNT";
const SIGNAL_COUNT_CASE: &str = "COSCA_TEST_KQUEUE_SIGNAL_COUNT_CASE";

/// Runs re-exec'd: it ignores `SIGUSR1` process-wide.
#[skuld::test]
fn a_signal_subscription_counts_deliveries() {
    const DELIVERIES: usize = 3;

    if !crate::test_child::is_marked_fixture_reexec(SIGNAL_COUNT_MARKER) {
        return crate::test_child::run_fixture_case(
            crate::test_child::fixture_path!(a_signal_subscription_counts_deliveries),
            SIGNAL_COUNT_MARKER,
            SIGNAL_COUNT_CASE,
            "",
        );
    }
    crate::test_child::set_signal_ignored(libc::SIGUSR1, true);
    let kq = Kqueue::new().expect("kqueue");
    kq.subscribe(Subscription::Signal(libc::SIGUSR1)).expect("subscribe");
    for _ in 0..DELIVERIES {
        // SAFETY: `kill` of this process with a valid signal, which is ignored.
        assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGUSR1) }, 0);
    }
    assert_eq!(
        wait_events(&kq),
        [Event::Signal {
            signo: libc::SIGUSR1,
            count: DELIVERIES
        }]
    );
}

#[skuld::test]
fn unsubscribe_stops_the_reports() {
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
}

#[skuld::test]
fn unsubscribing_a_delivered_exit_fails_with_enoent() {
    let kq = Kqueue::new().expect("kqueue");
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
    assert_eq!(refusal(kq.unsubscribe(process)), libc::ENOENT);
}

#[skuld::test]
fn unsubscribing_a_never_registered_subscription_fails_with_enoent() {
    let (reader, _writer) = std::io::pipe().expect("pipe");
    let readable = Subscription::Readable {
        fd: reader.as_raw_fd(),
        low_water: 1,
    };
    let kq = Kqueue::new().expect("kqueue");
    assert_eq!(refusal(kq.unsubscribe(readable)), libc::ENOENT);
}

/// Blocks until `kq` has events and takes them. Fails if the wait reports a deadline, as none was
/// set.
fn wait_events(kq: &Kqueue) -> Vec<Event> {
    match kq.wait(None).expect("wait") {
        WaitOutcome::Events(events) => events,
        WaitOutcome::DeadlinePassed => panic!("a deadline passed, but no deadline was set"),
    }
}

/// A queue with one readable subscription on a pipe that already holds a byte. The pipe's ends stay
/// open with the queue.
fn queue_with_a_pending_event() -> (Kqueue, std::os::fd::RawFd, (std::io::PipeReader, std::io::PipeWriter)) {
    use std::io::Write as _;

    let (reader, mut writer) = std::io::pipe().expect("pipe");
    let fd = reader.as_raw_fd();
    let kq = Kqueue::new().expect("kqueue");
    kq.subscribe(Subscription::Readable { fd, low_water: 1 })
        .expect("subscribe");
    writer.write_all(b"x").expect("write");
    (kq, fd, (reader, writer))
}

fn a_pending_byte(fd: std::os::fd::RawFd) -> Event {
    Event::Readable {
        fd,
        bytes: 1,
        closed: false,
    }
}

#[skuld::test]
fn wait_returns_the_events_of_a_subscription() {
    use std::io::Write as _;

    let (reader, mut writer) = std::io::pipe().expect("pipe");
    let fd = reader.as_raw_fd();
    let kq = Kqueue::new().expect("kqueue");
    kq.subscribe(Subscription::Readable { fd, low_water: 1 })
        .expect("subscribe");
    writer.write_all(b"abc").expect("write");
    assert_eq!(
        kq.wait(None).expect("wait"),
        WaitOutcome::Events(vec![Event::Readable {
            fd,
            bytes: 3,
            closed: false
        }])
    );
}

/// `count` pipes each written once and subscribed on one queue: a single `wait` takes all of their
/// events, however many reads that is, and a `poll` after it finds none. `count` above the batch by
/// one or two leaves `poll`'s remainder a full batch or a short one.
fn wait_takes_every_event(count: usize) {
    use std::io::Write as _;

    let kq = Kqueue::new().expect("kqueue");
    let mut pipes = Vec::new();
    for _ in 0..count {
        let (reader, mut writer) = std::io::pipe().expect("pipe");
        let fd = reader.as_raw_fd();
        kq.subscribe(Subscription::Readable { fd, low_water: 1 })
            .expect("subscribe");
        writer.write_all(b"x").expect("write");
        pipes.push((reader, writer));
    }
    let mut got: Vec<_> = wait_events(&kq)
        .into_iter()
        .map(|e| match e {
            Event::Readable {
                fd,
                bytes: 1,
                closed: false,
            } => fd,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    got.sort_unstable();
    let mut want: Vec<_> = pipes.iter().map(|(reader, _)| reader.as_raw_fd()).collect();
    want.sort_unstable();
    assert_eq!(got, want);
    assert_eq!(kq.poll().expect("poll again"), no_events());
}

#[skuld::test]
fn wait_returns_every_pending_event_when_the_last_batch_is_full() {
    wait_takes_every_event(super::POLL_BATCH + 1);
}

#[skuld::test]
fn wait_returns_every_pending_event_when_the_last_batch_is_short() {
    wait_takes_every_event(super::POLL_BATCH + 2);
}

/// An event that is pending when the deadline has already passed is returned.
///
/// Mutant: an elapsed deadline returns `DeadlinePassed` before looking.
#[skuld::test]
fn wait_with_an_elapsed_deadline_still_returns_a_pending_event() {
    let (kq, fd, _pipe) = queue_with_a_pending_event();
    assert_eq!(
        kq.wait(Some(std::time::Instant::now())).expect("wait"),
        WaitOutcome::Events(vec![a_pending_byte(fd)])
    );
}

#[skuld::test]
fn wait_with_an_elapsed_deadline_and_nothing_pending_is_deadline_passed() {
    let kq = Kqueue::new().expect("kqueue");
    assert_eq!(
        kq.wait(Some(std::time::Instant::now())).expect("wait"),
        WaitOutcome::DeadlinePassed
    );
}

/// The real clock, so the check is `now >= deadline` after the wait; scheduling can only push a
/// return later. No upper bound is asserted (principle 13).
#[skuld::test]
fn wait_never_returns_deadline_passed_before_the_deadline() {
    use std::time::{Duration, Instant};

    let kq = Kqueue::new().expect("kqueue");
    let deadline = Instant::now() + Duration::from_millis(50);
    assert_eq!(kq.wait(Some(deadline)).expect("wait"), WaitOutcome::DeadlinePassed);
    let now = Instant::now();
    assert!(
        now >= deadline,
        "returned before the deadline: now={now:?}, deadline={deadline:?}"
    );
}

/// A deadline beyond XNU's `tv_sec` limit still returns a pending event.
///
/// Mutant: drop the cap in `kevent_timeout` -> `Io(EINVAL)` at once.
#[skuld::test]
fn wait_with_a_deadline_beyond_the_kevent_limit_returns_the_pending_event() {
    use std::time::Duration;

    let (kq, fd, _pipe) = queue_with_a_pending_event();
    let deadline = crate::wait::deadline_from(Duration::from_secs(u64::from(u32::MAX)))
        .expect("a deadline this far is still finite");
    assert_eq!(
        kq.wait(Some(deadline)).expect("a far deadline is not an error"),
        WaitOutcome::Events(vec![a_pending_byte(fd)])
    );
}

/// Under a frozen clock a bounded `wait` ends: each real `kevent` advances the clock.
///
/// Mutant: drop the `advance_by_elapsed_if_frozen` call in `wait` -> the second round panics with
/// "no progress" instead of re-arming forever.
#[skuld::test]
fn wait_terminates_under_a_frozen_clock() {
    use crate::wait::test_clock::FrozenClockGuard;
    use std::time::Duration;

    let kq = Kqueue::new().expect("kqueue");
    let (_clock, at) = FrozenClockGuard::install();
    let deadline = Some(at + Duration::from_millis(5));
    assert_eq!(kq.wait(deadline).expect("bounded wait"), WaitOutcome::DeadlinePassed);
}

#[skuld::test]
fn wait_reports_a_process_exit() {
    let mut child = spawn_blocker();
    let pid = child.id();
    let kq = Kqueue::new().expect("kqueue");
    kq.subscribe(Subscription::Process {
        pid,
        signals: false,
        reap: false,
    })
    .expect("subscribe");
    child.kill().expect("kill");
    let mut seen = Vec::new();
    while !exited(&seen, pid) {
        seen.extend(wait_events(&kq));
    }
    child.wait().expect("reap");
}

/// Two pipes written in turn: `poll` returns the first one's event first, unsorted.
#[skuld::test]
fn poll_returns_events_in_the_order_they_became_pending() {
    use std::io::Write as _;

    let kq = Kqueue::new().expect("kqueue");
    let mut pipes = Vec::new();
    for _ in 0..2 {
        let (reader, writer) = std::io::pipe().expect("pipe");
        kq.subscribe(Subscription::Readable {
            fd: reader.as_raw_fd(),
            low_water: 1,
        })
        .expect("subscribe");
        pipes.push((reader, writer));
    }
    // Written in the reverse of the subscription order, so a sort by subscription shows.
    for (_, writer) in pipes.iter_mut().rev() {
        writer.write_all(b"x").expect("write");
    }
    let want: Vec<_> = pipes
        .iter()
        .rev()
        .map(|(reader, _)| a_pending_byte(reader.as_raw_fd()))
        .collect();
    assert_eq!(kq.poll().expect("poll"), want);
}

#[skuld::test]
fn poll_on_an_empty_queue_is_empty() {
    assert_eq!(Kqueue::new().expect("kqueue").poll().expect("poll"), no_events());
}

#[skuld::test]
fn from_kevent_maps_each_filter() {
    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

    let map = |ev: KEvent| Event::from_kevent(&ev);

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
}

/// A read or signal event whose `data` is negative, which no kernel reports.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "never negative")]
fn a_negative_read_count_breaks_the_contract() {
    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

    let ev = KEvent::new(
        7,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        -1,
        0,
    );
    Event::from_kevent(&ev);
}

#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "never negative")]
fn a_negative_signal_count_breaks_the_contract() {
    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

    let ev = KEvent::new(
        libc::SIGUSR1 as usize,
        EventFilter::EVFILT_SIGNAL,
        EvFlags::empty(),
        FilterFlag::empty(),
        -1,
        0,
    );
    Event::from_kevent(&ev);
}

/// A filter no subscription asks for: the backoff timer, which a `Kqueue` never holds.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "no subscription asked for")]
fn an_event_of_an_unnamed_filter_breaks_the_contract() {
    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

    let ev = KEvent::new(
        1,
        EventFilter::EVFILT_TIMER,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    );
    Event::from_kevent(&ev);
}

/// An `EV_ERROR` event, which the kernel sets only while attaching a knote and reports through the
/// registration's `EV_RECEIPT`, so a read never carries it.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "no subscription asked for")]
fn an_ev_error_event_breaks_the_contract() {
    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

    let ev = KEvent::new(
        9,
        EventFilter::EVFILT_READ,
        EvFlags::EV_ERROR,
        FilterFlag::empty(),
        libc::EBADF as isize,
        0,
    );
    Event::from_kevent(&ev);
}

/// Without `debug_assertions` a negative count is clamped to 0, and an unnamed filter or an
/// `EV_ERROR` event is dropped, each with a warning.
#[cfg(not(debug_assertions))]
#[skuld::test]
fn release_warns_about_a_negative_count_an_unnamed_filter_and_an_ev_error_event() {
    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let negative = KEvent::new(
        7,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        -1,
        0,
    );
    assert_eq!(
        Event::from_kevent(&negative),
        Some(Event::Readable {
            fd: 7,
            bytes: 0,
            closed: false
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
    assert_eq!(Event::from_kevent(&timer), None);
    let failed = KEvent::new(
        9,
        EventFilter::EVFILT_READ,
        EvFlags::EV_ERROR,
        FilterFlag::empty(),
        libc::EBADF as isize,
        0,
    );
    assert_eq!(Event::from_kevent(&failed), None);
    let levels = |marker| {
        crate::log_capture::records_since_on_current_thread(mark, marker)
            .into_iter()
            .map(|(level, _)| level)
            .collect::<Vec<_>>()
    };
    assert_eq!(levels("negative data field"), [log::Level::Warn]);
    assert_eq!(
        levels("no subscription asked for"),
        [log::Level::Warn, log::Level::Warn]
    );
}
