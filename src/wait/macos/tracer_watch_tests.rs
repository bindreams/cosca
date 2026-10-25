//! `TracerWatch`, with forced `link` answers and real processes to register on. Whether a pid is
//! registered is seen by a `SIGCONT` to it (harmless to a running `cat`): its `NOTE_SIGNAL` is
//! pending on the kqueue only while a registration on it exists.

use std::time::Duration;

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

use super::{seams::force_links, OnTracer, TracerWatch};
use crate::child::spawn::identity_macos_tests::{other_unique_id, std_blocker_with_unique};
use crate::identity::{uniq_fault, Link, ReadPurpose, UniqRead};
use crate::wait::backend::test_hooks::{event_pending, send_signal};

/// A live blocker on a held stdin, and its unique id. Dropping it ends and reaps the blocker.
struct Live {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    unique: u64,
}

impl Live {
    fn new() -> Live {
        let (child, stdin, unique) = std_blocker_with_unique();
        Live {
            child,
            stdin: Some(stdin),
            unique,
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// What `link` reads for it with no tracer.
    fn untraced(&self) -> Link {
        Link::Found {
            unique: self.unique,
            parent: std::process::id(),
            at_attach: 0,
        }
    }

    /// What `link` reads for it while `tracer` holds it.
    fn traced_by(&self, tracer: u32) -> Link {
        Link::Found {
            unique: self.unique,
            parent: tracer,
            at_attach: std::process::id(),
        }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        drop(self.stdin.take());
        self.child.wait().expect("reap the blocker");
    }
}

/// Takes every pending event off `kq`.
fn drain(kq: &Kqueue) {
    let blank = KEvent::new(0, EventFilter::EVFILT_PROC, EvFlags::empty(), FilterFlag::empty(), 0, 0);
    let mut events = [blank; 8];
    while kq
        .kevent(
            &[],
            &mut events,
            Some(crate::wait::backend::kevent_timeout(Duration::ZERO)),
        )
        .expect("drain the kqueue")
        > 0
    {}
}

/// Whether a registration on `pid` exists: a `SIGCONT` to it is reported on `kq`.
fn registered(kq: &Kqueue, pid: u32) -> bool {
    drain(kq);
    send_signal(pid, libc::SIGCONT);
    let pending = event_pending(kq);
    drain(kq);
    pending
}

/// One walk, which must not fail.
fn walk(watch: &mut TracerWatch, kq: &Kqueue, tracer: u32) -> OnTracer {
    watch.held_by(kq, tracer).expect("no read is refused")
}

const MS: Duration = Duration::from_millis(1);

// The registrations =====

/// A walk that finds a registered pid gone deletes its registration, so the next walk that finds a
/// process there registers it afresh: an `EV_ADD` onto a knote left detached by a reaped tracer would
/// attach to nothing.
///
/// Mutant: the walk sends no `EV_DELETE`.
#[skuld::test]
fn a_tracer_found_gone_is_unregistered_before_it_is_registered_again() {
    let tracer = Live::new();
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    let links = force_links([tracer.untraced()]);
    assert_eq!(walk(&mut watch, &kq, tracer.pid()), OnTracer::Recheck(Duration::ZERO));
    assert!(registered(&kq, tracer.pid()), "the walk registers the tracer");
    links.then([Link::Gone]);
    assert_eq!(walk(&mut watch, &kq, tracer.pid()), OnTracer::Recheck(Duration::ZERO));
    assert!(
        !registered(&kq, tracer.pid()),
        "a tracer found gone must be unregistered"
    );
    links.then([tracer.untraced()]);
    assert_eq!(
        walk(&mut watch, &kq, tracer.pid()),
        OnTracer::Recheck(Duration::ZERO),
        "a process found at the pid again is registered afresh"
    );
    assert!(registered(&kq, tracer.pid()));
}

/// A registration whose re-read shows another process at the pid is deleted, and the walk checks
/// again; the next walk registers the pid afresh.
///
/// Mutants: a mismatched registration is kept; the walk takes it for armed.
#[skuld::test]
fn a_tracer_on_another_unique_id_after_its_registration_is_unregistered() {
    let tracer = Live::new();
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    let links = force_links([tracer.untraced()]);
    let _other = uniq_fault::force_uniq_read_once(ReadPurpose::Link, other_unique_id(tracer.pid()));
    assert_eq!(walk(&mut watch, &kq, tracer.pid()), OnTracer::Recheck(Duration::ZERO));
    assert!(
        !registered(&kq, tracer.pid()),
        "a registration that may name another process must be deleted"
    );
    links.then([tracer.untraced()]);
    assert_eq!(
        walk(&mut watch, &kq, tracer.pid()),
        OnTracer::Recheck(Duration::ZERO),
        "the next walk registers the tracer afresh"
    );
    assert!(registered(&kq, tracer.pid()));
}

/// A tracer's `NOTE_EXIT` deletes its one-shot registration, so the next walk registers the pid
/// again rather than blocking on nothing.
///
/// Mutant: `fired` keeps the pid armed.
#[skuld::test]
fn a_tracer_is_registered_again_after_its_note_exit() {
    let tracer = Live::new();
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    let links = force_links([tracer.untraced(), tracer.untraced()]);
    assert_eq!(walk(&mut watch, &kq, tracer.pid()), OnTracer::Recheck(Duration::ZERO));
    assert_eq!(walk(&mut watch, &kq, tracer.pid()), OnTracer::Block);
    let exit = KEvent::new(
        tracer.pid() as usize,
        EventFilter::EVFILT_PROC,
        EvFlags::empty(),
        FilterFlag::NOTE_EXIT,
        0,
        0,
    );
    assert!(
        watch.fired(&exit, std::process::id()),
        "a tracer's exit is the watch's event"
    );
    links.then([tracer.untraced()]);
    assert_eq!(
        walk(&mut watch, &kq, tracer.pid()),
        OnTracer::Recheck(Duration::ZERO),
        "the walk after the tracer's exit registers it again"
    );
}

/// A chain that meets itself ends there: each process is walked once, and a second walk that
/// registers nothing new blocks.
///
/// Mutant: the walk has no cycle guard, so it takes every queued answer.
#[skuld::test]
fn a_chain_that_meets_itself_is_walked_once() {
    let (a, b) = (Live::new(), Live::new());
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    let cycle = [a.traced_by(b.pid()), b.traced_by(a.pid())];
    let links = force_links(cycle.iter().copied().cycle().take(6));
    assert_eq!(walk(&mut watch, &kq, a.pid()), OnTracer::Recheck(Duration::ZERO));
    assert_eq!(links.left(), 4, "the walk reads each process on the cycle once");
    assert_eq!(walk(&mut watch, &kq, a.pid()), OnTracer::Block);
    assert_eq!(links.left(), 2);
}

// The backoff =====

/// Walks that keep finding a tracer gone check again at once, then after 1 ms, doubling to a 50 ms
/// cap.
///
/// Mutants: the backoff stays at zero (a busy loop) or at 1 ms; it has no cap.
#[skuld::test]
fn walks_that_find_a_tracer_gone_back_off_from_zero_doubling_to_50_ms() {
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    let _links = force_links([Link::Gone; 9]);
    let waits: Vec<_> = (0..9)
        .map(|_| watch.held_by(&kq, u32::MAX - 1).expect("a gone tracer is no error"))
        .collect();
    let expected = [0, 1, 2, 4, 8, 16, 32, 50, 50].map(|ms| OnTracer::Recheck(MS * ms));
    assert_eq!(waits, expected);
}

/// A tracer that is exiting while launchd holds it is checked again on the same backoff.
///
/// Mutant: a launchd-held tracer is taken for the end of the chain, so the walk blocks.
#[skuld::test]
fn a_tracer_launchd_holds_is_checked_again_on_the_backoff() {
    let tracer = Live::new();
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    let held = tracer.traced_by(crate::identity::LAUNCHD);
    let _links = force_links([held, held]);
    assert_eq!(walk(&mut watch, &kq, tracer.pid()), OnTracer::Recheck(Duration::ZERO));
    assert_eq!(walk(&mut watch, &kq, tracer.pid()), OnTracer::Recheck(MS));
}

/// A walk that reaches the end of the chain resets the backoff.
///
/// Mutant: a good walk leaves the backoff where it was.
#[skuld::test]
fn a_good_walk_resets_the_backoff() {
    let tracer = Live::new();
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    let _links = force_links([Link::Gone, Link::Gone, tracer.untraced(), Link::Gone]);
    let waits: Vec<_> = (0..4)
        .map(|_| watch.held_by(&kq, tracer.pid()).expect("no read is refused"))
        .collect();
    let zero = OnTracer::Recheck(Duration::ZERO);
    assert_eq!(waits, [zero, OnTracer::Recheck(MS), zero, zero]);
}

// The refusals =====

/// A refused unique-id read of a tracer is an error carrying its errno, never a tracer gone.
///
/// Mutant: the refusal is taken for a tracer gone.
#[skuld::test]
fn a_refused_read_of_a_tracer_is_an_error() {
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    let _links = force_links([Link::Refused(libc::EPERM)]);
    let err = watch
        .held_by(&kq, u32::MAX - 1)
        .expect_err("a refused read is an error");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
}

/// A refused `kinfo_proc` read of a tracer is an error.
///
/// Mutant: the refusal is taken for a tracer gone.
#[skuld::test]
fn an_unreadable_tracer_is_an_error() {
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    let _links = force_links([Link::Unreadable]);
    let err = watch
        .held_by(&kq, u32::MAX - 1)
        .expect_err("an unreadable tracer is an error");
    assert!(err.to_string().contains("kinfo_proc refused"), "{err}");
}

/// A refused re-read after the registration is an error carrying its errno.
///
/// Mutant: the refusal is taken for another process at the pid.
#[skuld::test]
fn a_refused_re_read_after_the_registration_is_an_error() {
    let tracer = Live::new();
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    let _links = force_links([tracer.untraced()]);
    let _refused = uniq_fault::force_uniq_read_once(ReadPurpose::Link, UniqRead::Refused(libc::EPERM));
    let err = watch
        .held_by(&kq, tracer.pid())
        .expect_err("a refused re-read is an error");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
}
