//! `settle`'s loop, driven by scripted reads (see [`Script`]).

use std::collections::VecDeque;

use super::{settle, AttachError, Stop};

/// A read's script: answers in order, panics once exhausted, and panics on drop if any answer
/// was left, so `settle` must read exactly as often as the test scripted.
struct Script<T> {
    what: &'static str,
    answers: VecDeque<T>,
}

impl<T> Script<T> {
    fn next(&mut self) -> T {
        self.answers
            .pop_front()
            .unwrap_or_else(|| panic!("{} was read more often than the test scripted", self.what))
    }
}

impl<T> Drop for Script<T> {
    fn drop(&mut self) {
        assert!(
            std::thread::panicking() || self.answers.is_empty(),
            "{} was read less often than the test scripted",
            self.what
        );
    }
}

fn scripted<T>(what: &'static str, answers: Vec<T>) -> impl FnMut() -> T {
    let mut script = Script {
        what,
        answers: answers.into(),
    };
    move || script.next()
}

fn record(si_pid: i32, si_code: i32, si_status: i32) -> libc::siginfo_t {
    // SAFETY: `siginfo_t` is plain data; all-zero is a valid value.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    info.si_pid = si_pid;
    info.si_code = si_code;
    info.si_status = si_status;
    info
}

fn never<T>(what: &'static str) -> impl FnMut() -> T {
    scripted(what, Vec::new())
}

/// Mutant: the exit check is deleted, so a tracee that exited before it stopped is polled again
/// and again (here: the `stop` script runs out).
#[skuld::test]
fn an_exit_record_ends_the_wait_with_its_code_and_status() {
    let result = settle(
        scripted("stop", vec![Ok(Stop::Running)]),
        scripted("exited", vec![Ok(record(7, libc::CLD_KILLED, libc::SIGKILL))]),
    );
    assert!(
        matches!(result, Err(AttachError::Exited { code, status }) if code == libc::CLD_KILLED && status == libc::SIGKILL),
        "{result:?}"
    );
}

/// Mutants: a normal exit and a core dump are not taken for exits.
#[skuld::test]
fn every_exit_kind_ends_the_wait() {
    for code in [libc::CLD_EXITED, libc::CLD_KILLED, libc::CLD_DUMPED] {
        let result = settle(
            scripted("stop", vec![Ok(Stop::Settling)]),
            scripted("exited", vec![Ok(record(7, code, 0))]),
        );
        assert!(
            matches!(result, Err(AttachError::Exited { code: c, .. }) if c == code),
            "{code}: {result:?}"
        );
    }
}

/// Mutant: any record with a pid counts as an exit, which macOS's `WEXITED` peek also fills for a
/// stop.
#[skuld::test]
fn a_stop_record_is_not_an_exit() {
    let result = settle(
        scripted("stop", vec![Ok(Stop::Running), Ok(Stop::Stopped(libc::SIGSTOP))]),
        scripted("exited", vec![Ok(record(7, libc::CLD_TRAPPED, libc::SIGSTOP))]),
    );
    assert!(result.is_ok(), "{result:?}");
}

/// Mutant: no pid check, so an empty record (`si_pid == 0`, `si_code` 0) is read as an event.
#[skuld::test]
fn an_empty_record_is_not_an_exit() {
    let result = settle(
        scripted("stop", vec![Ok(Stop::Running), Ok(Stop::Stopped(libc::SIGSTOP))]),
        scripted("exited", vec![Ok(record(0, libc::CLD_KILLED, 0))]),
    );
    assert!(result.is_ok(), "{result:?}");
}

/// Mutant: the exit peek runs before the stop is considered, so a settled stop waits on it.
#[skuld::test]
fn a_settled_stop_ends_the_wait_without_an_exit_peek() {
    let result = settle(
        scripted("stop", vec![Ok(Stop::Stopped(libc::SIGSTOP))]),
        never("exited"),
    );
    assert!(result.is_ok(), "{result:?}");
}

/// Mutant: `Settling` counts as settled, so the caller acts on a stop no request can reach yet.
#[skuld::test]
fn a_settling_stop_is_polled_again() {
    let result = settle(
        scripted(
            "stop",
            vec![Ok(Stop::Settling), Ok(Stop::Settling), Ok(Stop::Stopped(libc::SIGSTOP))],
        ),
        scripted("exited", vec![Ok(record(0, 0, 0)), Ok(record(0, 0, 0))]),
    );
    assert!(result.is_ok(), "{result:?}");
}

/// Mutant: a failed stop peek is swallowed and retried.
#[skuld::test]
fn a_failed_stop_peek_is_its_errno() {
    let result = settle(scripted("stop", vec![Err(libc::EPERM)]), never("exited"));
    assert!(matches!(result, Err(AttachError::Errno(libc::EPERM))), "{result:?}");
}

/// Mutant: a failed exit peek is swallowed and retried.
#[skuld::test]
fn a_failed_exit_peek_is_its_errno() {
    let result = settle(
        scripted("stop", vec![Ok(Stop::Running)]),
        scripted("exited", vec![Err(libc::ECHILD)]),
    );
    assert!(matches!(result, Err(AttachError::Errno(libc::ECHILD))), "{result:?}");
}
