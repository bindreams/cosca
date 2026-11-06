//! Windows: a failed async spawn's teardown warns once when its wait for the process it terminated
//! passes its threshold, and keeps waiting until the process is gone (principle 2). No test can make
//! `TerminateProcess` slow. The std spawn's row (`ProcSource::reap_now`) makes the seam
//! `fault::set_late_exit` find the one check of the exit late; the wait after it is real and ends at
//! once. The raw rows (`OwnedChild::tear_down`) refuse the kill as an exit under way and use a zero
//! threshold, so the child is really running at the first look, and close its stdin once the wait
//! blocks; they check that the kill reached `TerminateProcess` to be refused. The unoverridden look
//! is tested against real handles in `windows_teardown_tests` and `proc_tests`.
//!
//! In the std row the process ends only by `TerminateProcess`, or by its stdin closing. The teardown's
//! thread drops the stdin writer once the kill returned (`teardown_blocker_parts`), so a kill that
//! sent nothing leaves a process that exits `0`, and the test fails on `assert_killed` instead of
//! hanging.

use crate::child::spawn::fault;
use crate::error::ChildFate;
use crate::test_child::Console;

/// The "still waiting" warns logged since `mark`.
fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since(mark, "still waiting")
}

/// A command for the `more.com` blocker of `teardown_blocker_parts`, and the guard that releases it
/// after the teardown's kill.
fn blocker_command() -> (crate::tokio::Command, fault::TeardownBlocker) {
    let fault::TeardownBlockerParts {
        argv,
        stdin,
        stdout,
        guard,
    } = fault::teardown_blocker_parts();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(argv);
    cmd.stdin(stdin).expect("set stdin pipe");
    if let Some(stdout) = stdout {
        cmd.stdout(stdout).expect("set stdout");
    }
    (cmd, guard)
}

/// Fails a spawn of `cmd` with `force` (a fault seam that fails the attach or the identity read),
/// with its exit found late, and answers the teardown's fate and warns.
fn teardown_with_a_late_exit(mut cmd: crate::tokio::Command, force: fn(bool)) -> (ChildFate, Vec<String>) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let _warn = crate::tokio::child::fault::warn_slow_teardowns();
    let _late = fault::set_late_exit();
    force(true);
    let spawned = cmd.spawn();
    force(false);
    let (_, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        spawned.expect_err("the forced failure fails the spawn"),
    );
    (fate, warns_since(mark))
}

/// The teardown of a spawn through tokio (`ProcSource::reap_now`).
///
/// Mutant: `reap_now` waits for the process handle with no warn.
#[skuld::test]
async fn a_teardown_after_a_failed_attach_warns_once_past_its_threshold() {
    let (cmd, guard) = blocker_command();
    let (fate, warns) = teardown_with_a_late_exit(cmd, fault::set_force_attach_failure);
    assert_eq!(warns.len(), 1, "one warn, and the wait goes on: {warns:?}");
    assert_eq!(fate, ChildFate::Reaped, "the wait goes on past the threshold");
    guard.assert_killed();
}

/// Fails a spawn of a blocker through the raw backend with `force`, with a zero threshold and the
/// kill refused as an exit under way, so the child is still running when the teardown first looks
/// and nothing but its stdin closing ends it: closed once the wait blocks, which is after the warn.
/// Answers the teardown's fate and warns.
fn raw_teardown_with_an_exit_under_way(force: fn(bool)) -> (ChildFate, Vec<String>) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.executable(crate::test_child::BLOCKER_ARGV[0]);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin pipe");
    cmd.stdout(crate::stdio::Stdio::null()).expect("set stdout");
    let _warn = crate::tokio::child::fault::warn_slow_teardowns_after(std::time::Duration::ZERO);
    let _end = crate::wait::block_probe::on_blocking(move || drop(writer));
    let refusal = crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    force(true);
    let spawned = cmd.spawn();
    force(false);
    let (_, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        spawned.expect_err("the forced failure fails the spawn"),
    );
    // The refusal stands in for the kill's `TerminateProcess`, so the teardown did send its kill.
    refusal.assert_fired();
    (fate, warns_since(mark))
}

/// The teardown of a spawn through the raw backend (`raw_spawn_teardown`).
///
/// Mutants: the raw teardown waits with no warn; the async raw spawn hands it no threshold.
#[skuld::test]
async fn a_raw_teardown_after_a_failed_attach_warns_once_past_its_threshold() {
    let (fate, warns) = raw_teardown_with_an_exit_under_way(fault::set_force_attach_failure);
    assert_eq!(warns.len(), 1, "one warn, and the wait goes on: {warns:?}");
    assert_eq!(fate, ChildFate::Reaped, "the wait goes on past the threshold");
}

/// As above, for the raw backend's other teardown: the identity read fails, so no identity is known.
///
/// Mutant: the async raw spawn hands the identity-failure teardown no threshold.
#[skuld::test]
async fn a_raw_teardown_after_a_failed_identity_read_warns_once_past_its_threshold() {
    let (fate, warns) = raw_teardown_with_an_exit_under_way(fault::set_force_identity_vanished);
    assert_eq!(warns.len(), 1, "one warn, and the wait goes on: {warns:?}");
    assert_eq!(fate, ChildFate::Reaped, "the wait goes on past the threshold");
}

/// A running blocker and a handle to it.
fn running_blocker() -> std::process::Child {
    let mut cmd = std::process::Command::new(crate::test_child::BLOCKER_ARGV[0]);
    cmd.args(&crate::test_child::BLOCKER_ARGV[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null());
    crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker")
}

/// The check itself: a process that has not exited by its deadline is found running, one that has
/// is found exited.
///
/// Mutants: the check answers "running" whatever the handle says; it answers "exited".
#[skuld::test]
fn the_check_finds_a_running_process_running_and_an_exited_one_exited() {
    use std::os::windows::io::AsRawHandle as _;

    use crate::wait::teardown_warn::handle_signaled_by;
    use windows::Win32::Foundation::HANDLE;

    let mut child = running_blocker();
    let handle = HANDLE(child.as_raw_handle());

    assert!(
        !handle_signaled_by(handle, crate::wait::now()),
        "a running process is found running"
    );

    child.kill().expect("terminate the blocker");
    child.wait().expect("reap the blocker");
    assert!(
        handle_signaled_by(handle, crate::wait::now()),
        "an exited process is found exited"
    );
}

/// A process still running when a deadline ahead of now passes is found running. Only the answer is
/// asserted, never how long the check took.
///
/// Mutant: the check answers "exited" once its deadline has passed.
#[skuld::test]
fn the_check_finds_a_running_process_running_when_its_deadline_elapses() {
    use std::os::windows::io::AsRawHandle as _;

    use crate::wait::teardown_warn::handle_signaled_by;
    use windows::Win32::Foundation::HANDLE;

    let mut child = running_blocker();
    let found = handle_signaled_by(
        HANDLE(child.as_raw_handle()),
        crate::wait::now() + std::time::Duration::from_millis(50),
    );
    child.kill().expect("terminate the blocker");
    child.wait().expect("reap the blocker");
    assert!(!found, "a running process is found running at its deadline");
}

/// A handle that cannot be waited on (it lacks `SYNCHRONIZE`) is left to the wait that follows: the
/// check answers "exited" and logs why.
///
/// Mutants: a failed look answers "running", which warns for a child it knows nothing about; it logs
/// nothing.
#[skuld::test]
fn the_check_leaves_a_handle_it_cannot_wait_on_to_the_wait() {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

    use crate::wait::teardown_warn::handle_signaled_by;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    // SAFETY: plain OpenProcess on our own pid.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, std::process::id()) }
        .expect("open ourselves without SYNCHRONIZE");
    // SAFETY: a fresh owned handle from OpenProcess.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };

    assert!(
        handle_signaled_by(HANDLE(handle.as_raw_handle()), crate::wait::now()),
        "a look that failed is left to the wait"
    );
    let logged = crate::log_capture::records_since_on_current_thread(mark, "a look at a killed child's exit failed");
    assert_eq!(logged.len(), 1, "{logged:?}");
}
