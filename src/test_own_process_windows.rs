//! Windows twin of the unix `test_own_process`: runs a test that must change process-global state
//! (the environment, here) in a process of its own. Mounted by `#[path]` into `tests/common` as
//! `test_own_process`, so a caller names the same items on both platforms.
//!
//! The parent re-executes the test binary as
//! `<exe> --exact <test> --test-threads=1 --nocapture --format json` with [`ENV`] set to the test's
//! filter. A process takes the child role only if [`ENV`] names this test and its argv is exactly
//! that shape, so libtest was told to run this one test on one thread and the process is the
//! test's own. An [`ENV`] naming the test under any other argv (a shell export, an outer harness)
//! panics rather than run the body in a shared process, and never re-executes, so it cannot
//! recurse.
//!
//! The parent requires a successful exit and the child's suite events to show exactly one test,
//! which passed: a filter that matches no test, or a body that exits the process, fails the run.
//!
//! [`own_process`] returns the [`Completion`] only in the child. A guard that changes
//! process-global state takes `&Completion`, so a test that forgot `own_process` does not compile.

use std::ffi::OsString;
use std::process::{Child, Command, Stdio};

/// Forks `command` with `spawn_lock` held for the fork alone: `common::spawn_locked`.
pub(crate) type Spawn = fn(&mut Command) -> std::io::Result<Child>;

/// The role marker: the filter of the test the child was re-executed for.
pub(crate) const ENV: &str = "COSCA_TEST_OWN_PROCESS";

/// The path of the test fn `$name`, for [`own_process`]. `let _ = $name;` makes a stale name a
/// compile error rather than a filter that matches nothing.
#[allow(
    unused_macros,
    reason = "unused in the integration binaries that mount this file only for `tests/common`"
)]
macro_rules! test_path {
    ($name:ident) => {{
        let _ = $name;
        concat!(module_path!(), "::", stringify!($name))
    }};
}

/// libtest's filter for a [`test_path!`]: `module_path!()` always leads with a crate segment, which
/// the filter has none of.
pub(crate) fn test_filter(path: &str) -> &str {
    path.split_once("::")
        .unwrap_or_else(|| panic!("{path:?} has no crate segment"))
        .1
}

/// The argv (after the program name) of a re-executed test.
///
/// `--nocapture` keeps skuld's fd-level capture from swallowing the child's output, which the
/// parent reports; `--format json` gives the parent the suite events it checks.
pub(crate) fn child_args(test: &str) -> [&str; 6] {
    let [format, json] = super::test_reexec::JSON_FORMAT;
    [
        "--exact",
        test,
        "--test-threads=1",
        super::test_reexec::NOCAPTURE,
        format,
        json,
    ]
}

/// Proof that this process is an `own_process` child. A guard that changes process-global state
/// takes `&Completion`.
#[must_use = "bind it for the whole body; a guard that changes process-global state takes it"]
pub(crate) struct Completion(());

/// Call first in a test that changes process-global state:
/// `let Some(done) = own_process(test_path!(this_fn), spawn) else { return };`.
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
        .env(ENV, test)
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

/// The [`Completion`] if this process was re-executed for `test`, else `None`.
fn child_completion(test: &str) -> Option<Completion> {
    let inherited = std::env::var(ENV).ok()?;
    if inherited != test {
        return None;
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    assert!(
        args.iter()
            .map(OsString::as_os_str)
            .eq(child_args(test).iter().map(std::ffi::OsStr::new)),
        "{ENV}={inherited:?} names this test, but argv is not the re-executed shape: got {args:?}, expected {:?}",
        child_args(test)
    );
    Some(Completion(()))
}

pub(crate) use test_path;
