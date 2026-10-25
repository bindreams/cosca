//! What every `test_own_process` shares, whatever carries the completion report: the role marker,
//! the argv, the gate that decides who takes the child role, and the [`Completion`] witness.
//!
//! Also mounted by `#[path]` into `tests/common`, so it names nothing of its crate.
//!
//! # The gate
//!
//! The parent re-executes the test binary as `<exe> <`[`child_args`]`>` with
//! `COSCA_TEST_OWN_PROCESS=<parent pid>:<transport>:<test>`. A process takes the child role only if
//! all of these hold at once: the value's pid is its real parent's, its test is the one being
//! gated, and its argv is exactly [`child_args`]. An environment variable alone is forgeable and
//! inheritable (a shell export, an outer harness, a grandchild); the parent pid binds the value to
//! the process that set it, and the argv proves libtest was told to run this one test on one
//! thread, so the process is the test's own. Any other argv under that variable panics instead of
//! re-executing, so it cannot recurse ([`child_role`]).

use std::ffi::{OsStr, OsString};
use std::process::{Child, Command};

/// Forks `command` with `spawn_lock` held for the fork alone: `test_spawn::spawn` in the library's
/// tests, `common::spawn_locked` in the integration tests.
pub(crate) type Spawn = fn(&mut Command) -> std::io::Result<Child>;

/// The role marker: `<parent pid>:<transport>:<test>`. See the module doc.
pub(crate) const ENV: &str = "COSCA_TEST_OWN_PROCESS";

/// The path of the test fn `$name` (sync or `async`), for `own_process`. `let _ = $name;` makes a
/// stale name a compile error rather than a filter that matches nothing.
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
/// `--nocapture` keeps skuld's fd-level capture from swallowing the child's stdout and stderr,
/// which the parent reports. On Windows the parent also reads the child's suite events, so
/// `--format json` is part of the shape.
pub(crate) fn child_args(test: &str) -> Vec<&str> {
    let mut args = vec!["--exact", test, "--test-threads=1", super::test_reexec::NOCAPTURE];
    if cfg!(windows) {
        args.extend(super::test_reexec::JSON_FORMAT);
    }
    args
}

/// The [`ENV`] value for the current process re-executing `test`; `transport` is what the
/// platform's completion report needs to find the child (the token fd on unix).
pub(crate) fn env_value(transport: &str, test: &str) -> String {
    format!("{}:{transport}:{test}", std::process::id())
}

/// The transport field of `inherited` if this process was re-executed for `test` by its real
/// parent with exactly [`child_args`]; see the module doc.
pub(crate) fn gate<'a>(inherited: Option<&'a str>, parent_pid: u32, args: &[OsString], test: &str) -> Option<&'a str> {
    let mut parts = inherited?.splitn(3, ':');
    let (Some(pid), Some(transport), Some(named)) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    let exact_argv = args
        .iter()
        .map(OsString::as_os_str)
        .eq(child_args(test).into_iter().map(OsStr::new));
    (pid == parent_pid.to_string() && named == test && exact_argv).then_some(transport)
}

/// Whether `inherited` says this very process was re-executed for `test` by its real parent. Such a
/// process that was not accepted as the child is a bug in the gate; re-executing again would
/// recurse without end.
pub(crate) fn is_reexecution(inherited: Option<&str>, parent_pid: u32, test: &str) -> bool {
    let mut parts = inherited.unwrap_or_default().splitn(3, ':');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(pid), Some(_), Some(named)) if pid == parent_pid.to_string() && named == test
    )
}

/// What `classify` (the platform's wrapper of [`gate`]) makes of this process's [`ENV`], real
/// parent and argv; `None` for a parent. A re-executed process that `classify` does not accept
/// panics rather than re-execute.
pub(crate) fn child_role<T>(
    test: &str,
    parent_pid: u32,
    classify: impl FnOnce(Option<&str>, u32, &[OsString], &str) -> Option<T>,
) -> Option<T> {
    let inherited = std::env::var(ENV).ok();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if let Some(role) = classify(inherited.as_deref(), parent_pid, &args, test) {
        return Some(role);
    }
    assert!(
        !is_reexecution(inherited.as_deref(), parent_pid, test),
        "re-executed for {test} but not accepted as its own process: got {args:?} with {ENV}={inherited:?}, \
         expected {:?}",
        child_args(test)
    );
    None
}

/// What the child reports its completion through: the token pipe's write end on unix; Windows needs
/// none, since the parent reads the child's suite events.
#[cfg(unix)]
pub(crate) type Reporter = std::fs::File;
#[cfg(windows)]
pub(crate) type Reporter = ();

/// Proof that this process is an `own_process` child, and on unix the report that its body returned.
/// A guard that changes process-global state takes `&Completion`, so a test that forgot
/// `own_process` does not compile.
///
/// On unix, dropped by a panicking body, or never dropped by one that exits the process, it reports
/// nothing.
#[must_use = "the body's completion is reported when this drops; bind it for the whole body"]
pub(crate) struct Completion(pub(crate) Reporter);

pub(crate) use test_path;
