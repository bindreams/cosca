//! Unit tests for the async builder mirror — assert the wrapped sync request records the
//! configured values (the integration suite only proves the spawn path).

use crate::containment::Nesting;
use crate::ContainMode;

#[skuld::test]
fn contain_with_and_nesting_recorded() {
    let mut cmd = super::Command::new();
    cmd.contain_with(ContainMode::TreeWalk).nesting(Nesting::Opaque);
    let req = cmd.inner.contain_request();
    assert_eq!(req.mode, Some(ContainMode::TreeWalk));
    assert_eq!(req.nesting, Nesting::Opaque);
}

#[skuld::test]
fn tokio_elevate_forwards_to_inner_request() {
    let mut c = super::Command::new();
    c.args(["id", "-u"]).elevation_backend(crate::elevation::Backend::Sudo);
    // command_tests is a child module of tokio::command, so it can read the private inner.
    let req = c.inner.elevation_request();
    assert!(req.enabled);
    assert_eq!(req.backend, crate::elevation::Backend::Sudo);
}

#[cfg(unix)]
#[skuld::test]
async fn tokio_child_elevation_is_none_without_elevate() {
    let mut c = super::Command::new();
    c.args(["true"]);
    let child = c.spawn().expect("spawn");
    assert!(child.elevation().is_none());
}

/// The async builder hand-mirrors the sync one and parity is not compiler-enforced (see this
/// module's own doc), so a delegate can silently go missing. This test pins that `raw_executable`
/// exists and forwards correctly.
///
/// Asserted over the RECORDED spec rather than "a method was called", so it also pins that the
/// delegate forwards to `raw_executable` and not to `executable`.
#[skuld::test]
fn tokio_raw_executable_records_an_exact_spec() {
    use crate::command::ExecutableSpec;
    use std::path::Path;

    let mut c = super::Command::new();
    c.raw_executable("helper");
    assert!(
        matches!(c.inner.executable_spec(), Some(ExecutableSpec::Exact(p)) if p == Path::new("helper")),
        "raw_executable must record Exact, got {:?}",
        c.inner.executable_spec()
    );

    // And the sibling setter still records Search through the same wrapper, so the two are not
    // accidentally wired to the same inner method.
    let mut s = super::Command::new();
    s.executable("helper");
    assert!(matches!(s.inner.executable_spec(), Some(ExecutableSpec::Search(_))));
}

// A failure after the spawn reports what became of the child =====

/// A live blocker whose stdin this test holds, and that writer.
#[cfg(unix)]
fn held_blocker(kill_on_drop: bool) -> (super::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = super::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.kill_on_drop(kill_on_drop);
    (cmd.spawn().expect("spawn"), writer)
}

/// A run-to-completion helper that fails after its spawn signals the child, as its drop would, and
/// says so: tokio collects the exit later.
///
/// Mutant: the failure reports `Unknown` without tearing the child down.
#[cfg(unix)]
#[skuld::test]
async fn a_failure_after_the_spawn_signals_the_child_and_says_so() {
    let (mut child, _writer) = held_blocker(true);
    let error = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), &mut child);
    assert_eq!(error.fate(), Some(crate::error::ChildFate::Killed), "{error}");
}

/// A child `kill_on_drop(false)` keeps is left alone, and the failure names it.
///
/// Mutant: the failure signals a child that opted out of it.
#[cfg(unix)]
#[skuld::test]
async fn a_failure_after_the_spawn_leaves_a_child_that_opted_out() {
    let (mut child, writer) = held_blocker(false);
    let id = child.id();
    let error = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), &mut child);
    assert_eq!(
        error.fate(),
        Some(crate::error::ChildFate::Running { id: Some(id) }),
        "{error}"
    );
    // The child exits once its stdin closes, and tokio collects it.
    drop(writer);
}

/// Async twin of the sync `a_failure_after_the_spawn_notes_the_elevated_program_only_behind_a_backend`.
#[cfg(unix)]
#[skuld::test]
async fn a_failure_after_the_spawn_notes_the_elevated_program_only_behind_a_backend() {
    use crate::elevation::{Backend, ElevatedVia};
    let note = "an elevated program behind it may still run";
    let (mut plain, _w1) = held_blocker(true);
    let plain = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), &mut plain);
    assert!(!plain.to_string().contains(note), "{plain}");

    let (mut wrapped, _w2) = held_blocker(true);
    wrapped.set_elevation(crate::child::front_kill_tests::report(ElevatedVia::Wrapped(
        Backend::Sudo,
    )));
    let wrapped = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), &mut wrapped);
    assert_eq!(wrapped.fate(), Some(crate::error::ChildFate::Killed), "{wrapped}");
    assert!(wrapped.to_string().contains(note), "{wrapped}");
}

// A run-to-completion helper that fails after its spawn =====

/// The answer of a run-to-completion helper that failed after its spawn: the program may have
/// started, the fate is `fate`, the wrapper flag is `wrapper`, and the cause is the seam's.
#[track_caller]
fn assert_failed_after_the_spawn(error: crate::error::Error, fate: crate::error::ChildFate, wrapper: bool) {
    let crate::error::Error::MayHaveStarted {
        fate: got,
        wrapper_elevated,
        source,
    } = &error
    else {
        panic!("expected MayHaveStarted, got {error:?}");
    };
    assert_eq!(*got, fate, "{error}");
    assert_eq!(*wrapper_elevated, wrapper, "{error}");
    assert!(
        matches!(**source, crate::error::Error::Io(ref e) if e.to_string() == crate::child::spawn::failure::seams::FAILURE),
        "{source:?}"
    );
}

/// Async twin of the sync `output_status_and_read_fail_as_may_have_started_after_the_spawn`. The
/// fate is `Killed`: the drop signals the child and tokio collects it.
///
/// Mutants: a helper returns the cause bare; drops the fate; drops the wrapper flag.
#[skuld::test]
async fn output_status_and_read_fail_as_may_have_started_after_the_spawn() {
    use crate::child::spawn::failure::seams;
    use crate::error::ChildFate;
    crate::tokio::test_runtime::assert_current_thread();
    for wrapper in [false, true] {
        let _wrapper = wrapper.then(seams::pretend_wrapper);
        let mut cmd = super::Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        let _pump = seams::fail_the_next_pump();
        assert_failed_after_the_spawn(
            cmd.output().await.expect_err("a failed pump fails `output`"),
            ChildFate::Killed,
            wrapper,
        );
        let _pump = seams::fail_the_next_pump();
        assert_failed_after_the_spawn(
            cmd.read().await.expect_err("a failed pump fails `read`"),
            ChildFate::Killed,
            wrapper,
        );
        let _wait = seams::fail_the_next_wait();
        assert_failed_after_the_spawn(
            cmd.status().await.expect_err("a failed wait fails `status`"),
            ChildFate::Killed,
            wrapper,
        );
    }
}

/// Async twin of the sync `read_of_invalid_utf8_behind_a_wrapper_keeps_the_wrapper_flag`.
///
/// Mutant: `read` builds the invalid-UTF-8 error without the child's wrapper flag.
#[cfg(unix)]
#[skuld::test]
async fn read_of_invalid_utf8_behind_a_wrapper_keeps_the_wrapper_flag() {
    crate::tokio::test_runtime::assert_current_thread();
    for wrapper in [false, true] {
        let _wrapper = wrapper.then(crate::child::spawn::failure::seams::pretend_wrapper);
        let mut cmd = super::Command::new();
        cmd.args(["printf", "\\377"]);
        let error = cmd.read().await.expect_err("invalid UTF-8 fails `read`");
        let crate::error::Error::MayHaveStarted {
            fate,
            wrapper_elevated,
            source,
        } = &error
        else {
            panic!("expected MayHaveStarted, got {error:?}");
        };
        assert_eq!(*fate, crate::error::ChildFate::Reaped, "`read` collected the exit");
        assert_eq!(*wrapper_elevated, wrapper, "{error}");
        assert!(
            matches!(**source, crate::error::Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData),
            "{source:?}"
        );
    }
}
