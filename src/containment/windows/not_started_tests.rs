//! The proof that a strict Windows root never ran, against real suspended children.

use windows::Win32::Foundation::HANDLE;

use super::{loader_started, prove_not_started, unproved};
use crate::containment::windows::fault::{force_next, Step};
use crate::test_frozen::{inject_suspended_thread_into_std_child, raw, spawn_suspended_blocker, InitialThread};

const ERROR_ACCESS_DENIED: u32 = 5;

fn dispose(mut child: std::process::Child) {
    child.kill().expect("kill the test child");
    child.wait().expect("reap the test child");
}

/// A root nothing touched is proved not started, and the proof keeps its suspend: the initial
/// thread is at count 2 (the creator's and the proof's) while the proof is held and after it is
/// dropped, which resumes nothing.
///
/// Mutants: the proof resumes the thread it suspended; the proof refuses an untouched root.
#[skuld::test]
fn an_untouched_suspended_root_is_proved_not_started_and_stays_suspended() {
    let child = spawn_suspended_blocker();
    let thread = InitialThread::of(child.id());

    let proven = prove_not_started(raw(&child)).expect("an untouched suspended root is proved");

    assert_eq!(thread.suspend_count(), 2, "the proof holds its own suspend");
    drop(proven);
    assert_eq!(thread.suspend_count(), 2, "dropping the proof resumes nothing");
    dispose(child);
}

/// A root whose thread something resumed is not proved, and nothing the read suspended stays
/// suspended. (A running root may have started threads by now, so the reason is not asserted: the
/// proof's reasons are pinned apart.)
///
/// Mutants: the root is proved though it ran; the read's suspend is kept.
#[skuld::test]
fn a_root_whose_initial_thread_was_resumed_is_not_proved_and_is_left_as_found() {
    let child = spawn_suspended_blocker();
    let thread = InitialThread::of(child.id());
    assert_eq!(thread.release_one(), 1, "the root was created suspended");

    prove_not_started(raw(&child)).expect_err("a running root is not proved");

    assert_eq!(thread.suspend_count(), 0, "the read's suspend was undone");
    dispose(child);
}

/// A second thread in the root (started by an EDR agent or a debugger, here suspended at birth)
/// runs the loader's initialisation when released, so the initial thread's count proves nothing.
///
/// Mutant: the proof looks at the initial thread only.
#[skuld::test]
fn a_root_with_a_second_thread_is_not_proved() {
    let child = spawn_suspended_blocker();
    let thread = InitialThread::of(child.id());
    let _injected = inject_suspended_thread_into_std_child(&child);

    let why = prove_not_started(raw(&child)).expect_err("a root with two threads is not proved");

    assert!(why.contains("2 threads"), "{why}");
    assert_eq!(thread.suspend_count(), 1, "nothing was suspended by the read");
    dispose(child);
}

/// The loader's state reads as set once the root's thread has run, and not before.
///
/// Mutant: the read answers the wrong way round, or never reads the PEB's `Ldr`.
#[skuld::test]
fn the_loader_state_reads_unset_in_a_suspended_root_and_set_once_it_ran() {
    let child = spawn_suspended_blocker();
    let process = HANDLE(raw(&child));
    let thread = InitialThread::of(child.id());
    assert!(
        !loader_started(process).expect("read a suspended root"),
        "the loader has not run in a root nobody resumed"
    );
    thread.release_one();
    // Waits for the real condition, with no cap: the loader sets `Ldr` early in the first run.
    while !loader_started(process).expect("read a running root") {
        std::thread::yield_now();
    }
    dispose(child);
}

/// What the proof makes of the reads it took after its suspend: a thread that was running, a
/// loader that ran, or one that cannot be read, is not proved; a suspended thread and an unset
/// loader are. A running thread's loader is not read.
///
/// Mutants: a set loader is taken as proof; a failed read is taken as proof; the loader is read for
/// a running thread.
#[skuld::test]
fn a_root_is_proved_only_while_its_thread_is_suspended_and_its_loader_has_not_run() {
    assert!(unproved(1, || Ok(false)).is_none());
    assert!(unproved(2, || Ok(false)).is_none(), "someone else suspended it too");
    assert!(unproved(1, || Ok(true))
        .expect("a set loader")
        .contains("loader had initialised"));
    assert!(unproved(0, || panic!("a running thread's loader is not read"))
        .expect("a running thread")
        .contains("running"));
    let why = unproved(1, || Err(std::io::Error::from_raw_os_error(5))).expect("an unreadable loader");
    assert!(why.contains("the loader's state failed"), "{why}");
}

/// A read the proof needs that fails proves nothing, and the read's suspend is undone: the thread's
/// open for the loader's state, the loader's state.
///
/// Mutants: a failed read is taken as "not started"; the suspend taken before the failure is kept.
#[skuld::test]
fn a_root_whose_state_cannot_be_read_is_not_proved() {
    let child = spawn_suspended_blocker();
    let thread = InitialThread::of(child.id());

    let forced = force_next(Step::LoaderRead, ERROR_ACCESS_DENIED);
    let why = prove_not_started(raw(&child)).expect_err("an unreadable loader state proves nothing");
    drop(forced);
    assert!(why.contains("the loader's state"), "{why}");
    assert_eq!(thread.suspend_count(), 1, "the read's suspend was undone");

    let _forced = force_next(Step::ResumeOpen, ERROR_ACCESS_DENIED);
    let why = prove_not_started(raw(&child)).expect_err("an unopenable thread proves nothing");
    assert!(why.contains("OpenThread"), "{why}");
    assert_eq!(thread.suspend_count(), 1, "nothing was suspended");
    dispose(child);
}
