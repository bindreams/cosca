//! The proof that a strict Windows root never ran, against real suspended children.

use windows::Win32::Foundation::HANDLE;

use super::{loader_started, prove_not_started, unproved, NotProved, Reason};
use crate::containment::windows::fault::{force_next, Step};
use crate::error::{first_os_code, said, Error};
use crate::test_frozen::{inject_suspended_thread_into_std_child, raw, spawn_suspended_blocker, InitialThread};

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_HANDLE: u32 = 6;
/// Distinct from the assignment's and the undo's codes.
const ERROR_READ_FAULT: u32 = 30;

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

    let not_proved = prove_not_started(raw(&child)).expect_err("a root with two threads is not proved");

    let Reason::Observed(saw) = &not_proved.reason else {
        panic!("a thread count is an observation: {not_proved:?}");
    };
    assert!(saw.contains("2 threads"), "{saw}");
    assert!(
        not_proved.undo.is_none(),
        "nothing was suspended, so nothing was undone"
    );
    assert_eq!(thread.suspend_count(), 1, "nothing was suspended by the read");
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
    let Some(Reason::Observed(saw)) = unproved(1, || Ok(true)) else {
        panic!("a set loader is an observation");
    };
    assert!(saw.contains("loader had initialised"), "{saw}");
    let Some(Reason::Observed(saw)) = unproved(0, || panic!("a running thread's loader is not read")) else {
        panic!("a running thread is an observation");
    };
    assert!(saw.contains("running"), "{saw}");
    let Some(Reason::Unread(read)) = unproved(1, || Err(std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32)))
    else {
        panic!("an unreadable loader is a failed read, not an observation");
    };
    assert!(said(&read).contains("reading the loader's state failed"), "{read:?}");
    assert_eq!(
        first_os_code(&read),
        Some(ERROR_ACCESS_DENIED as i32),
        "the read's code is the reason's"
    );
}

/// A read the proof needs that fails proves nothing, and the read's suspend is undone: the thread's
/// open for the loader's state, the loader's state. The reason names the call and holds the read's OS
/// error as its source, not only in its words.
///
/// Mutants: a failed read is taken as "not started"; the suspend taken before the failure is kept;
/// the read's OS error is folded into the reason's text.
#[skuld::test]
fn a_root_whose_state_cannot_be_read_is_not_proved() {
    let child = spawn_suspended_blocker();
    let thread = InitialThread::of(child.id());

    let forced = force_next(Step::LoaderRead, ERROR_ACCESS_DENIED);
    let not_proved = prove_not_started(raw(&child)).expect_err("an unreadable loader state proves nothing");
    drop(forced);
    let why = unread(&not_proved);
    assert!(said(why).contains("the loader's state"), "{why:?}");
    assert_eq!(first_os_code(why), Some(ERROR_ACCESS_DENIED as i32), "{why:?}");
    assert!(not_proved.undo.is_none(), "the undo worked");
    assert_eq!(thread.suspend_count(), 1, "the read's suspend was undone");

    let _forced = force_next(Step::ResumeOpen, ERROR_ACCESS_DENIED);
    let not_proved = prove_not_started(raw(&child)).expect_err("an unopenable thread proves nothing");
    let why = unread(&not_proved);
    assert!(said(why).contains("OpenThread"), "{why:?}");
    assert_eq!(first_os_code(why), Some(ERROR_ACCESS_DENIED as i32), "{why:?}");
    assert_eq!(thread.suspend_count(), 1, "nothing was suspended");
}

/// The failed read of the state the proof needs, from a `NotProved`; panics when it is an observation.
fn unread(not_proved: &NotProved) -> &Error {
    match &not_proved.reason {
        Reason::Unread(read) => read,
        Reason::Observed(saw) => panic!("expected a failed read, saw: {saw}"),
    }
}

/// When the undo of the read's suspend fails too, the root is left suspended once more than it was
/// found, and the undo's failure is another failure of the call: beside the assignment's and the
/// read's, in that order, each with its own OS code, and never the source of one of them.
///
/// Mutants: the undo's failure is dropped; the undo's failure replaces the read's.
#[skuld::test]
fn a_failed_undo_of_the_reads_suspend_is_another_failure_beside_the_read_and_the_assignment() {
    let child = spawn_suspended_blocker();
    let thread = InitialThread::of(child.id());

    let _read = force_next(Step::LoaderRead, ERROR_READ_FAULT);
    let _undo = force_next(Step::Resume, ERROR_INVALID_HANDLE);
    let not_proved = prove_not_started(raw(&child)).expect_err("an unreadable loader state proves nothing");

    assert_eq!(
        first_os_code(unread(&not_proved)),
        Some(ERROR_READ_FAULT as i32),
        "{not_proved:?}"
    );
    let undo = not_proved.undo.as_deref().expect("the undo failed");
    assert_eq!(first_os_code(undo), Some(ERROR_INVALID_HANDLE as i32), "{undo:?}");
    assert!(said(undo).contains("undoing the read's suspend"), "{undo:?}");
    assert_eq!(thread.suspend_count(), 2, "the failed undo left the read's suspend");

    let error = not_proved.into_error("the child could not be put in its Job Object", failed_assignment());
    let [assignment, read, undo] = error.failures_below()[..] else {
        panic!("the assignment, the read and the undo, in that order: {error:?}");
    };
    assert_eq!(first_os_code(assignment), Some(ERROR_ACCESS_DENIED as i32), "{error:?}");
    assert_eq!(first_os_code(read), Some(ERROR_READ_FAULT as i32), "{error:?}");
    assert_eq!(first_os_code(undo), Some(ERROR_INVALID_HANDLE as i32), "{error:?}");
    assert_eq!(
        first_os_code(&error),
        Some(ERROR_ACCESS_DENIED as i32),
        "the assignment's code stays the error's"
    );
}

/// What the proof saw is the error's own words, not a failure of the call: it is in the detail, and
/// the failed assignment is the error's source, with the undo's failure beside it, not below it.
///
/// Mutants: the observation is a second failure beside the assignment; the undo's failure is the
/// observation's source; the undo's failure is dropped.
#[skuld::test]
fn an_observation_is_in_the_detail_and_a_failed_undo_stands_beside_the_assignment() {
    let observed = NotProved {
        reason: Reason::Observed("the child's initial thread was running".to_owned()),
        undo: Some(Error::io_cause(std::io::Error::from_raw_os_error(
            ERROR_INVALID_HANDLE as i32,
        ))),
    };
    let error = observed.into_error("the child could not be put in its Job Object", failed_assignment());

    let Error::Containment { detail, .. } = &error else {
        panic!("a Containment: {error:?}");
    };
    assert_eq!(
        detail,
        "the child could not be put in its Job Object, and it could not be shown that the program did not run: the child's initial thread was running"
    );
    let [assignment, undo] = error.failures_below()[..] else {
        panic!("the assignment and the undo, and no failure for the observation: {error:?}");
    };
    assert_eq!(first_os_code(assignment), Some(ERROR_ACCESS_DENIED as i32), "{error:?}");
    assert_eq!(first_os_code(undo), Some(ERROR_INVALID_HANDLE as i32), "{error:?}");

    let alone = NotProved {
        reason: Reason::Observed("the loader had initialised the child".to_owned()),
        undo: None,
    }
    .into_error("the child could not be put in its Job Object", failed_assignment());
    let [only] = alone.failures_below()[..] else {
        panic!("the assignment alone: {alone:?}");
    };
    assert_eq!(first_os_code(only), Some(ERROR_ACCESS_DENIED as i32), "{alone:?}");
}

/// Mutant: the detail claims the program may have run, which is a thing the proof did not see.
#[skuld::test]
fn a_failed_read_says_whether_the_program_ran_could_not_be_told() {
    let not_proved = NotProved {
        reason: Reason::Unread(Error::Unassessable {
            detail: "OpenThread failed".to_owned(),
            source: Some(Error::io_cause(std::io::Error::from_raw_os_error(
                ERROR_READ_FAULT as i32,
            ))),
        }),
        undo: None,
    };
    let error = not_proved.into_error("the child could not be put in its Job Object", failed_assignment());

    let Error::Containment { detail, .. } = &error else {
        panic!("a Containment: {error:?}");
    };
    assert_eq!(
        detail,
        "the child could not be put in its Job Object, and whether the program ran could not be told"
    );
    let [assignment, read] = error.failures_below()[..] else {
        panic!("the assignment and the read, in that order: {error:?}");
    };
    assert_eq!(first_os_code(assignment), Some(ERROR_ACCESS_DENIED as i32), "{error:?}");
    assert_eq!(first_os_code(read), Some(ERROR_READ_FAULT as i32), "{error:?}");
}

/// A failed Job assignment, as `attach_job` holds it.
fn failed_assignment() -> std::sync::Arc<Error> {
    Error::io_cause(std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32))
}
