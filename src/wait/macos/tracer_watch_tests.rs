//! `TracerWatch`, over a kernel whose rows state what the tracers' links read, and real processes to
//! register on. Whether a pid is registered is seen by a `SIGCONT` to it (harmless to a running
//! `cat`): its `NOTE_SIGNAL` is pending on the kqueue only while a registration on it exists.

use std::time::Duration;

use super::{watched, OnTracer, TracerWatch, WalkError};
use crate::child::spawn::identity_macos_tests::{other_unique_id, std_blocker_with_unique};
use crate::identity::kinfo::kinfo_proc;
use crate::identity::{FakeKernel, HostKernel, Kernel, UniqRead};
use crate::os_process::macos::kqueue::test_hooks::send_signal;
use crate::os_process::macos::kqueue::{Event, Kqueue};
use crate::wait::exit_only::macos_tests::found;

/// A live blocker and its unique id. Dropping it kills and reaps the blocker.
struct Live {
    child: crate::test_child::StdChild,
    unique: u64,
}

impl Live {
    fn new() -> Live {
        let (child, unique) = std_blocker_with_unique();
        Live { child, unique }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// What a unique-id read of it finds.
    fn found(&self) -> UniqRead {
        found(self.unique)
    }

    /// Its `kinfo_proc` while `tracer` holds it: the parent now is `tracer`, and the parent when a
    /// tracer attached is this process.
    fn traced_by(&self, tracer: u32) -> kinfo_proc {
        kinfo_proc::of_host_held_by(self.pid(), std::process::id() as libc::pid_t, tracer as libc::pid_t)
    }
}

/// A kernel whose first `count` unique-id reads of `pid` say it is gone, and the host's after.
fn gone(pid: u32, count: usize) -> FakeKernel<'static> {
    (0..count).fold(FakeKernel::over(&HostKernel), |kernel, _| {
        kernel.on_unique_info(pid, UniqRead::Gone)
    })
}

/// Takes every pending event off `kq`.
fn drain(kq: &Kqueue) {
    kq.poll().expect("drain the kqueue");
}

/// Whether a registration on `pid` exists: a `SIGCONT` to it is reported on `kq`.
fn registered(kq: &Kqueue, pid: u32) -> bool {
    drain(kq);
    send_signal(pid, libc::SIGCONT);
    let pending = crate::os_process::poll::look_readable(std::os::fd::AsFd::as_fd(kq)).expect("poll the kqueue");
    drain(kq);
    pending
}

/// One walk through `kernel`, which must not fail.
fn walk(watch: &mut TracerWatch, kq: &Kqueue, tracer: u32, kernel: &dyn Kernel) -> OnTracer {
    watch.held_by(kernel, kq, tracer).expect("no read is refused")
}

/// The identity error a walk that must fail on a read returned.
#[track_caller]
fn identity_error(walked: Result<OnTracer, WalkError>) -> std::io::Error {
    match walked {
        Err(WalkError::Identity(e)) => e,
        other => panic!("a refused read is an identity error: {other:?}"),
    }
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
    assert_eq!(
        walk(&mut watch, &kq, tracer.pid(), &HostKernel),
        OnTracer::Recheck(Duration::ZERO)
    );
    assert!(registered(&kq, tracer.pid()), "the walk registers the tracer");
    assert_eq!(
        walk(&mut watch, &kq, tracer.pid(), &gone(tracer.pid(), 1)),
        OnTracer::Recheck(Duration::ZERO)
    );
    assert!(
        !registered(&kq, tracer.pid()),
        "a tracer found gone must be unregistered"
    );
    assert_eq!(
        walk(&mut watch, &kq, tracer.pid(), &HostKernel),
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
    // The link's two reads of the tracer, then the read after the registration, which names another.
    let kernel = FakeKernel::over(&HostKernel)
        .on_unique_info(tracer.pid(), tracer.found())
        .on_unique_info(tracer.pid(), tracer.found())
        .on_unique_info(tracer.pid(), other_unique_id(tracer.pid()));
    assert_eq!(
        walk(&mut watch, &kq, tracer.pid(), &kernel),
        OnTracer::Recheck(Duration::ZERO)
    );
    assert!(
        !registered(&kq, tracer.pid()),
        "a registration that may name another process must be deleted"
    );
    assert_eq!(
        walk(&mut watch, &kq, tracer.pid(), &HostKernel),
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
    assert_eq!(
        walk(&mut watch, &kq, tracer.pid(), &HostKernel),
        OnTracer::Recheck(Duration::ZERO)
    );
    assert_eq!(walk(&mut watch, &kq, tracer.pid(), &HostKernel), OnTracer::Block);
    let exit = Event::Process {
        pid: tracer.pid(),
        exited: true,
        signalled: false,
        reaped: false,
    };
    assert!(
        watch.fired(&exit, std::process::id()),
        "a tracer's exit is the watch's event"
    );
    assert_eq!(
        walk(&mut watch, &kq, tracer.pid(), &HostKernel),
        OnTracer::Recheck(Duration::ZERO),
        "the walk after the tracer's exit registers it again"
    );
}

/// A chain that meets itself ends there: each process is walked once, and a second walk that
/// registers nothing new blocks. Each process's holder is stated for the two walks, its registration
/// is made once, and every unique-id read finds it; a walk of a process reads its `kinfo_proc` once, so
/// the count of those reads is the count of walks of it. A process stated for no third walk is read
/// from the host after it, which ends the walk, so the count fails the test where a hang would not.
///
/// Mutant: the walk has no cycle guard.
#[skuld::test]
fn a_chain_that_meets_itself_is_walked_once() {
    let (a, b) = (Live::new(), Live::new());
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    let mut kernel = FakeKernel::over(&HostKernel);
    for (held, holder) in [(&a, &b), (&b, &a)] {
        let unique = held.unique;
        kernel = kernel
            .on_every_unique_info(held.pid(), move || found(unique))
            .on_kinfo(held.pid(), held.traced_by(holder.pid()))
            .on_kinfo(held.pid(), held.traced_by(holder.pid()))
            .on_subscribe(watched(held.pid()));
    }
    assert_eq!(
        walk(&mut watch, &kq, a.pid(), &kernel),
        OnTracer::Recheck(Duration::ZERO)
    );
    assert_eq!(walk(&mut watch, &kq, a.pid(), &kernel), OnTracer::Block);
    for process in [&a, &b] {
        assert_eq!(kernel.kinfo_reads(process.pid()), 2, "one read per walk of it");
    }
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
    const NO_PROCESS: u32 = u32::MAX - 1;
    let kernel = gone(NO_PROCESS, 9);
    let waits: Vec<_> = (0..9)
        .map(|_| {
            watch
                .held_by(&kernel, &kq, NO_PROCESS)
                .expect("a gone tracer is no error")
        })
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
    let kernel = FakeKernel::over(&HostKernel)
        .on_kinfo(tracer.pid(), tracer.traced_by(crate::identity::LAUNCHD))
        .on_kinfo(tracer.pid(), tracer.traced_by(crate::identity::LAUNCHD));
    assert_eq!(
        walk(&mut watch, &kq, tracer.pid(), &kernel),
        OnTracer::Recheck(Duration::ZERO)
    );
    assert_eq!(walk(&mut watch, &kq, tracer.pid(), &kernel), OnTracer::Recheck(MS));
}

/// A walk that reaches the end of the chain resets the backoff.
///
/// Mutant: a good walk leaves the backoff where it was.
#[skuld::test]
fn a_good_walk_resets_the_backoff() {
    let tracer = Live::new();
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    // The tracer is found gone by the first, second and fourth walks, and found by the third.
    let gones = gone(tracer.pid(), 3);
    let host: &dyn Kernel = &HostKernel;
    let waits: Vec<_> = [&gones as &dyn Kernel, &gones, host, &gones]
        .into_iter()
        .map(|kernel| watch.held_by(kernel, &kq, tracer.pid()).expect("no read is refused"))
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
    const NO_PROCESS: u32 = u32::MAX - 1;
    let kernel = FakeKernel::new().on_unique_info(NO_PROCESS, UniqRead::Refused(libc::EPERM));
    let err = identity_error(watch.held_by(&kernel, &kq, NO_PROCESS));
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err}");
}

/// A refused `kinfo_proc` read of a tracer is an error.
///
/// Mutant: the refusal is taken for a tracer gone.
#[skuld::test]
fn an_unreadable_tracer_is_an_error() {
    let kq = Kqueue::new().expect("kqueue");
    let mut watch = TracerWatch::default();
    const NO_PROCESS: u32 = u32::MAX - 1;
    let kernel = FakeKernel::new()
        .on_unique_info(NO_PROCESS, found(1))
        .on_kinfo_refused(NO_PROCESS, libc::EPERM);
    let err = identity_error(watch.held_by(&kernel, &kq, NO_PROCESS));
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
    // The link's two reads of the tracer, then the read after the registration, which is refused.
    let kernel = FakeKernel::over(&HostKernel)
        .on_unique_info(tracer.pid(), tracer.found())
        .on_unique_info(tracer.pid(), tracer.found())
        .on_unique_info(tracer.pid(), UniqRead::Refused(libc::EPERM));
    let err = identity_error(watch.held_by(&kernel, &kq, tracer.pid()));
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err}");
}
