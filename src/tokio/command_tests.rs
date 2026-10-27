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

/// The run-to-completion helpers' futures are `Send`, so a caller can `tokio::spawn` them: the
/// teardown they await on a failure holds the child's resources across its waits.
///
/// Mutant: a `!Send` value held across the teardown's waits (fails to compile).
#[skuld::test]
fn run_to_completion_futures_are_send() {
    fn assert_send<T: Send>(_: T) {}
    let mut cmd = super::Command::new();
    assert_send(cmd.status());
    assert_send(cmd.output());
    assert_send(cmd.read());
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

#[cfg(target_os = "linux")]
use crate::containment::cgroup::test_support::alone;
#[cfg(target_os = "linux")]
use crate::test_child::fixture_path;
#[cfg(target_os = "linux")]
use crate::tokio::child::child_drop_tests::linux::{Ended, Pidfd};

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

/// A killed blocker `pid`: `sends` (logged after the syscall) holds the `SIGKILL` to it. On Linux
/// it also died of `SIGKILL`, or was reaped while its stdin was open, read through a pidfd opened
/// before the teardown. Its stdin `writer` is released only here, so a teardown that sent nothing
/// leaves the blocker to exit `0`. Needs `alone()` on Linux.
#[cfg(unix)]
#[track_caller]
fn assert_the_teardown_killed(
    #[cfg(target_os = "linux")] root: &Pidfd,
    writer: std::io::PipeWriter,
    sends: &crate::send_log::Capture,
    pid: u32,
) {
    #[cfg(target_os = "linux")]
    {
        let ended = root.ended_after_closing(writer);
        assert!(
            matches!(ended, Ended::Signalled(libc::SIGKILL) | Ended::ReapedWhileStdinOpen),
            "the teardown must kill the child with SIGKILL, got {ended:?}"
        );
    }
    #[cfg(not(target_os = "linux"))]
    drop(writer);
    assert!(
        sends.sent(pid, crate::signal::Sig::Kill),
        "the teardown must send the child SIGKILL: {:?}",
        sends.entries()
    );
}

/// What `after_the_spawn` answers for a failed pump on `child`, a held blocker whose stdin `writer`
/// is released only once the teardown's kill is checked. The teardown sends its signals on its first
/// poll and awaits the reap after, so a kill that sent nothing fails that check by assertion instead
/// of leaving the reap to hang on a blocker that never exits. Needs `alone()` on Linux.
#[cfg(unix)]
async fn after_a_pump_failure(child: &mut super::Child, writer: std::io::PipeWriter) -> crate::error::Error {
    use std::future::Future as _;
    use std::task::Poll;

    #[cfg(target_os = "linux")]
    let root = Pidfd::of(child);
    let pid = child.id().pid();
    let sends = crate::send_log::Capture::start();
    let mut teardown = std::pin::pin!(super::after_the_spawn(
        crate::error::Error::Io(std::io::Error::other("pump")),
        child
    ));
    let first = std::future::poll_fn(|cx| Poll::Ready(teardown.as_mut().poll(cx))).await;
    #[cfg(target_os = "linux")]
    assert_the_teardown_killed(&root, writer, &sends, pid);
    #[cfg(not(target_os = "linux"))]
    assert_the_teardown_killed(writer, &sends, pid);
    match first {
        Poll::Ready(error) => error,
        Poll::Pending => teardown.await,
    }
}

/// A run-to-completion helper that fails after its spawn kills and reaps the child, as its drop
/// would, and says so.
///
/// Mutants: the failure reports `Unknown` without tearing the child down; the teardown's kill sends
/// nothing.
#[cfg(unix)]
#[skuld::test]
async fn a_failure_after_the_spawn_signals_the_child_and_says_so() {
    #[cfg(target_os = "linux")]
    if !alone(fixture_path!(a_failure_after_the_spawn_signals_the_child_and_says_so)) {
        return;
    }
    let (mut child, writer) = held_blocker(true);
    let error = after_a_pump_failure(&mut child, writer).await;
    assert_eq!(error.fate(), Some(crate::error::ChildFate::Reaped), "{error}");
}

/// A child `kill_on_drop(false)` keeps is left alone, and the failure names it.
///
/// Mutant: the failure signals a child that opted out of it.
#[cfg(unix)]
#[skuld::test]
async fn a_failure_after_the_spawn_leaves_a_child_that_opted_out() {
    let (mut child, writer) = held_blocker(false);
    let id = child.id();
    let error = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), &mut child).await;
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
    #[cfg(target_os = "linux")]
    if !alone(fixture_path!(
        a_failure_after_the_spawn_notes_the_elevated_program_only_behind_a_backend
    )) {
        return;
    }
    let note = "an elevated program behind it may still run";
    let (mut plain, w1) = held_blocker(true);
    let plain = after_a_pump_failure(&mut plain, w1).await;
    assert!(!plain.to_string().contains(note), "{plain}");

    let (mut wrapped, w2) = held_blocker(true);
    wrapped.set_elevation(crate::child::front_kill_tests::report(ElevatedVia::Wrapped(
        Backend::Sudo,
    )));
    let wrapped = after_a_pump_failure(&mut wrapped, w2).await;
    assert_eq!(wrapped.fate(), Some(crate::error::ChildFate::Reaped), "{wrapped}");
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
/// fate is the drop's: `Reaped` on Unix, where it kills and reaps the child; `Killed` on Windows,
/// where it terminates the child and closes its handle.
///
/// Mutants: a helper returns the cause bare; drops the fate; drops the wrapper flag.
#[skuld::test]
async fn output_status_and_read_fail_as_may_have_started_after_the_spawn() {
    use crate::child::spawn::failure::seams;
    use crate::error::ChildFate;
    crate::tokio::test_runtime::assert_current_thread();
    let torn_down = if cfg!(unix) {
        ChildFate::Reaped
    } else {
        ChildFate::Killed
    };
    for wrapper in [false, true] {
        let _wrapper = wrapper.then(seams::pretend_wrapper);
        let mut cmd = super::Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        let _pump = seams::fail_the_next_pump();
        assert_failed_after_the_spawn(
            cmd.output().await.expect_err("a failed pump fails `output`"),
            torn_down,
            wrapper,
        );
        let _pump = seams::fail_the_next_pump();
        assert_failed_after_the_spawn(
            cmd.read().await.expect_err("a failed pump fails `read`"),
            torn_down,
            wrapper,
        );
        let _wait = seams::fail_the_next_wait();
        assert_failed_after_the_spawn(
            cmd.status().await.expect_err("a failed wait fails `status`"),
            torn_down,
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
