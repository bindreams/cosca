//! Windows twin of the unix `test_own_process`: runs a test that must change process-global state
//! (the environment, here) in a process of its own. Mounted by `#[path]` into `tests/common` as
//! `test_own_process`, so a caller names the same items on both platforms.
//!
//! The role marker, argv and gate are shared with the unix module: see
//! [`super::test_own_process_gate`]. The transport differs. The parent reads the child's suite
//! events (`--format json`, part of the shared argv) and requires a successful exit and exactly one
//! test, which passed: a filter that matches no test, or a body that exits the process, fails the
//! run.

use std::process::Stdio;

use super::test_own_process_gate::{child_args, child_role, env_value, gate, test_filter};
pub(crate) use super::test_own_process_gate::{test_path, Completion, Spawn};

/// The marker's transport field: the parent reads the child's suite events.
const TRANSPORT: &str = "json";

/// The pid of this process's real parent, `0` (never a parent's pid) if it has exited.
fn parent_pid() -> u32 {
    cosca::Process::current()
        .parent()
        .expect("find the parent process")
        .map_or(0, |parent| parent.id().pid())
}

/// Call first in a test that changes process-global state.
///
/// In the parent this re-executes the test binary to run only this test, waits for it, and
/// panics with its output unless it passed; it returns `None`. In the child it returns the
/// [`Completion`], and the body runs alone in its process.
#[must_use = "`let Some(done) = own_process(..) else { return };`: without the witness the test is not isolated"]
pub(crate) fn own_process(path: &str, spawn: Spawn) -> Option<Completion> {
    let test = test_filter(path);
    if let Some(done) = child_completion(test) {
        return Some(done);
    }
    let mut command = super::test_reexec::command(std::env::current_exe().expect("current_exe"));
    command
        .args(child_args(test))
        .env(super::test_own_process_gate::ENV, env_value(TRANSPORT, test))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = spawn(&mut command).expect("re-execute the test binary");
    let output = child.wait_with_output().expect("wait for the isolated run");
    if let Err(why) = super::test_reexec::suite_passed_exactly_one(&output) {
        panic!(
            "test {test} did not pass in its own process: {why}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    None
}

/// The [`Completion`] if this process was re-executed for `test` by its real parent, else `None`.
fn child_completion(test: &str) -> Option<Completion> {
    child_role(test, parent_pid(), |inherited, parent_pid, args, test| {
        gate(inherited, parent_pid, args, test)
            .filter(|&transport| transport == TRANSPORT)
            .map(|_| Completion(()))
    })
}
