//! Unit tests for the async builder mirror — assert the wrapped sync request records the
//! configured values (the integration suite only proves the spawn path).

use crate::containment::Nesting;
use crate::test_child::Console;
use crate::ContainMode;

#[skuld::test]
fn contain_with_and_nesting_recorded() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
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
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    assert_send(cmd.status());
    assert_send(cmd.output());
    assert_send(cmd.read());
}

/// Outside a runtime, a tokio spawn is refused before anything is made: the failure says the program
/// did not start, and no child is made to be reaped.
///
/// Mutants: the refusal answers that the program may have started; the check is gone (the sync
/// spawn then succeeds).
#[cfg(unix)]
#[skuld::test]
fn a_spawn_outside_a_runtime_did_not_start_the_program() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    let refused = match crate::tokio::spawn::spawn(&mut cmd.inner) {
        Ok(child) => panic!("no runtime, no spawn, got a child {}", child.pid()),
        Err(refused) => refused,
    };
    assert!(matches!(refused.expect_not_started(), crate::error::Error::Io(_)));
}

/// The graceful futures are `Send`, so a caller can `tokio::spawn` them: neither the look at the
/// root's group nor the hold that keeps its reaps off is in the future's state.
///
/// Mutant: a std lock guard held across the future's awaits (fails to compile).
#[skuld::test]
async fn graceful_futures_are_send() {
    fn assert_send<T: Send>(_: T) {}
    let grace = std::time::Duration::ZERO;
    let (mut child, _stdin) = crate::test_child::held_blocker_async(crate::Stdio::null(), Console::Hidden, |_| {});
    assert_send(child.graceful_shutdown(grace));
    assert_send(child.graceful_shutdown_tree(grace));
}

#[skuld::test]
fn tokio_elevate_forwards_to_inner_request() {
    let mut c = crate::test_child::tokio_command(Console::Hidden);
    c.args(["id", "-u"]).elevation_backend(crate::elevation::Backend::Sudo);
    // command_tests is a child module of tokio::command, so it can read the private inner.
    let req = c.inner.elevation_request();
    assert!(req.enabled);
    assert_eq!(req.backend, crate::elevation::Backend::Sudo);
}

#[cfg(unix)]
#[skuld::test]
async fn tokio_child_elevation_is_none_without_elevate() {
    let mut c = crate::test_child::tokio_command(Console::Hidden);
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

    let mut c = crate::test_child::tokio_command(Console::Hidden);
    c.raw_executable("helper");
    assert!(
        matches!(c.inner.executable_spec(), Some(ExecutableSpec::Exact(p)) if p == Path::new("helper")),
        "raw_executable must record Exact, got {:?}",
        c.inner.executable_spec()
    );

    // And the sibling setter still records Search through the same wrapper, so the two are not
    // accidentally wired to the same inner method.
    let mut s = crate::test_child::tokio_command(Console::Hidden);
    s.executable("helper");
    assert!(matches!(s.inner.executable_spec(), Some(ExecutableSpec::Search(_))));
}

// A failure after the spawn reports what became of the child =====

/// A live blocker whose stdin this test holds, and that writer.
#[cfg(unix)]
fn held_blocker(kill_on_drop: bool) -> (super::Child, crate::PipeWriter) {
    held_blocker_reporting(kill_on_drop, None)
}

/// [`held_blocker`] whose spawn reports `elevation`: a child launched behind that backend.
#[cfg(unix)]
fn held_blocker_reporting(
    kill_on_drop: bool,
    elevation: Option<crate::elevation::ElevationReport>,
) -> (super::Child, crate::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.kill_on_drop(kill_on_drop);
    cmd.set_elevation_report(elevation);
    (cmd.spawn().expect("spawn"), writer)
}

/// What `after_the_spawn` answers for a failed pump on `child`, a held blocker whose stdin `writer`
/// is dropped between the teardown's kill and its reap, so a teardown that sent nothing leaves the
/// blocker to exit `0`: the reap's status must be `SIGKILL`, and the kill is in the send log.
#[cfg(unix)]
async fn after_a_pump_failure(child: super::Child, writer: crate::PipeWriter) -> crate::error::Error {
    let released = crate::child::spawn::fault::release_between_kill_and_wait(writer);
    let pid = child.pid();
    let sends = crate::send_log::Capture::start();
    let error = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), child).await;
    assert!(
        sends.sent(pid, crate::signal::Sig::Kill),
        "the teardown must send the child SIGKILL: {:?}",
        sends.entries()
    );
    released.assert_killed();
    error
}

/// A run-to-completion helper that fails after its spawn kills and reaps the child, as its drop
/// would, and says so.
///
/// Mutants: the failure reports `Unknown` without tearing the child down; the teardown's kill sends
/// nothing.
#[cfg(unix)]
#[skuld::test]
async fn a_failure_after_the_spawn_signals_the_child_and_says_so() {
    let (child, writer) = held_blocker(true);
    let error = after_a_pump_failure(child, writer).await;
    assert_eq!(error.fate(), Some(crate::error::ChildFate::Reaped), "{error}");
}

/// A child `kill_on_drop(false)` keeps is left alone, and the failure names it.
///
/// Mutant: the failure signals a child that opted out of it.
#[cfg(unix)]
#[skuld::test]
async fn a_failure_after_the_spawn_leaves_a_child_that_opted_out() {
    let (child, writer) = held_blocker(false);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let error = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), child).await;
    assert_eq!(
        error.fate(),
        Some(crate::error::ChildFate::Running { id: Some(id) }),
        "{error}"
    );
    // The child exits once its stdin closes.
    drop(writer);
}

/// A child whose teardown after a failed run had its kills refused, handed back as the caller gets it,
/// with the child's id, its stdin writer, and the log mark from before the teardown. The refusals are
/// stated to the child's process (`FakeProcess`) over the real one: the teardown's kill, then the
/// one a let-go drop makes.
async fn handed_back_after_refused_kills() -> (
    crate::Unreaped,
    crate::identity::ProcessId,
    crate::tokio::ChildStdin,
    usize,
) {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = crate::test_child::held_blocker_async(crate::Stdio::null(), Console::Hidden, |_| {});
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let refused = || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    child.inner.proc.script_over(|f| f.signals([refused(), refused()]));
    let mark = crate::log_capture::mark();

    let error = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), child).await;

    let crate::error::Error::MayHaveStarted {
        fate,
        unreaped: Some(unreaped),
        ..
    } = error
    else {
        panic!("expected a handed-back child, got {error:?}");
    };
    assert_eq!(fate, crate::error::ChildFate::Running { id: Some(id) });
    (*unreaped, id, writer, mark)
}

/// A teardown whose kill is refused hands the child back as an [`Unreaped`](crate::Unreaped), as the
/// sync helpers do, and warns once in the words of a teardown, not of a drop.
///
/// Mutants: the child is left, not handed back; the fate is not `Running`; the warn is prefixed
/// `Child::drop`.
#[skuld::test]
async fn a_failure_after_the_spawn_whose_kill_is_refused_hands_the_child_back_and_warns() {
    let (unreaped, id, writer, mark) = handed_back_after_refused_kills().await;

    assert_eq!(unreaped.pid(), Some(id.pid()));
    let warns = crate::log_capture::records_since(mark, "handed back to the caller");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].starts_with("teardown after a failed run: ")
            && warns[0].contains(&id.pid().to_string())
            && !warns[0].contains("leaving it running"),
        "{warns:?}"
    );
    // The child exits once its stdin closes, and the caller settles what it was handed.
    drop(writer);
    unreaped.wait_async().await.expect("the child exits on EOF");
}

/// What the handed-back child is, when its caller drops it, is the async spawn's: it is let go, not
/// waited for. The child's stdin closes first, so a drop that waited would end rather than hang; the
/// line it logs says which it was.
///
/// Mutant: the hand-back builds its `Unreaped` with the sync drop kind.
#[skuld::test]
async fn the_child_a_failed_async_run_hands_back_is_let_go_when_dropped() {
    let (unreaped, _id, writer, mark) = handed_back_after_refused_kills().await;
    drop(writer);

    drop(unreaped);

    let said = crate::log_capture::records_since(mark, "dropped without wait or leak");
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        !said[0].contains("waited for it"),
        "a let-go drop does not wait for the child: {said:?}"
    );
}

/// Async twin of the sync `a_failure_after_the_spawn_notes_the_elevated_program_only_behind_a_front`:
/// an ended front is reaped with the note, a running one is sent no kill and handed back running.
#[cfg(unix)]
#[skuld::test]
async fn a_failure_after_the_spawn_notes_the_elevated_program_only_behind_a_front() {
    let note = "an elevated program behind it may still run";
    let (plain, w1) = held_blocker(true);
    let plain = after_a_pump_failure(plain, w1).await;
    assert!(!plain.to_string().contains(note), "{plain}");

    let (ended, writer) = held_blocker_reporting(true, crate::child::front_kill_tests::sudo_report());
    drop(writer);
    crate::test_child::wait_until_zombie(ended.pid());
    let ended = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), ended).await;
    assert!(ended.to_string().contains(note), "{ended}");
    assert_eq!(ended.fate(), Some(crate::error::ChildFate::Reaped), "{ended}");

    let (front, writer) = held_blocker_reporting(true, crate::child::front_kill_tests::sudo_report());
    let id = front.id().expect(crate::test_child::IDENTITY_READ);
    let error = super::after_the_spawn(crate::error::Error::Io(std::io::Error::other("pump")), front).await;
    assert!(!error.to_string().contains(note), "{error}");
    let crate::error::Error::MayHaveStarted {
        fate,
        unreaped: Some(unreaped),
        ..
    } = error
    else {
        panic!("expected a handed-back front, got {error:?}");
    };
    assert_eq!(fate, crate::error::ChildFate::Running { id: Some(id) });
    // The front exits on its own once its stdin closes: nothing signalled it.
    drop(writer);
    let status = unreaped.wait_async().await.expect("the front exits on EOF");
    assert!(status.success(), "a front is sent no kill: {status:?}");
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
        ..
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

/// A root that only a kill or the drop of its release pipe ends, and the guard that drops that pipe
/// once the teardown's kill returned, before its reap. The root reads fd 4, which `output`, `read`
/// and `status` leave alone: they set the child's stdin, stdout and stderr themselves, so none of
/// those can hold it.
#[cfg(unix)]
fn releasable_root() -> (super::Command, crate::child::spawn::fault::TeardownBlocker) {
    let (gate, release) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(["sh", "-c", "exec cat <&4 4<&-"]);
    cmd.fd(4, gate).expect("set the root's release pipe");
    (cmd, crate::child::spawn::fault::release_between_kill_and_wait(release))
}

/// Windows has no release point in the drop and no pipe a run-to-completion helper leaves to the
/// caller, so the kill is not witnessed there: this test pins the error's shape, and the kill is
/// pinned by the sync `lifecycle_tests::drop_kills_and_reaps_the_child`.
#[cfg(windows)]
fn releasable_root() -> (super::Command, Released) {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    (cmd, Released)
}

#[cfg(windows)]
struct Released;
#[cfg(windows)]
impl Released {
    fn assert_killed(&self) {}
}

/// Async twin of the sync `output_status_and_read_fail_as_may_have_started_after_the_spawn`, for the
/// wiring of the three async helpers to their teardown. The fate is the drop's: `Reaped`, as the
/// teardown kills and reaps the child, which the test checks on Unix (the root is `SIGKILL`ed, not
/// ended by its release).
///
/// Mutants: a helper returns the cause bare; drops the fate; the teardown's kill sends nothing.
#[skuld::test]
async fn output_status_and_read_fail_as_may_have_started_after_the_spawn() {
    use crate::child::spawn::failure::seams;
    use crate::error::ChildFate;
    crate::tokio::test_runtime::assert_current_thread();
    let torn_down = ChildFate::Reaped;
    {
        let (mut cmd, killed) = releasable_root();
        let _pump = seams::fail_the_next_pump();
        assert_failed_after_the_spawn(
            cmd.output().await.expect_err("a failed pump fails `output`"),
            torn_down,
            false,
        );
        killed.assert_killed();
    }
    {
        let (mut cmd, killed) = releasable_root();
        let _pump = seams::fail_the_next_pump();
        assert_failed_after_the_spawn(
            cmd.read().await.expect_err("a failed pump fails `read`"),
            torn_down,
            false,
        );
        killed.assert_killed();
    }
    {
        let (mut cmd, killed) = releasable_root();
        let _wait = seams::fail_the_next_wait();
        assert_failed_after_the_spawn(
            cmd.status().await.expect_err("a failed wait fails `status`"),
            torn_down,
            false,
        );
        killed.assert_killed();
    }
}

/// Async twin of the sync
/// `a_failure_after_the_spawn_of_a_child_reported_without_a_front_sets_no_wrapper_flag`.
///
/// Mutants: a helper sets the flag from `report.is_some()` or from `may_run_as_another_user()`.
#[skuld::test]
async fn a_failure_after_the_spawn_of_a_child_reported_without_a_front_sets_no_wrapper_flag() {
    use crate::child::spawn::failure::seams;
    use crate::elevation::elevation_tests::VIAS_WITHOUT_A_FRONT;
    use crate::error::ChildFate;
    crate::tokio::test_runtime::assert_current_thread();
    let note = "an elevated program behind it may still run";
    for via in VIAS_WITHOUT_A_FRONT {
        let mut cmd = crate::test_child::tokio_command(Console::Hidden);
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.set_elevation_report(Some(crate::elevation::elevation_tests::report(via.clone())));
        let _pump = seams::fail_the_next_pump();
        let output = cmd.output().await.expect_err("a failed pump fails `output`");
        let _pump = seams::fail_the_next_pump();
        let read = cmd.read().await.expect_err("a failed pump fails `read`");
        let _wait = seams::fail_the_next_wait();
        let status = cmd.status().await.expect_err("a failed wait fails `status`");
        for error in [output, read, status] {
            assert!(!error.to_string().contains(note), "{via:?}: {error}");
            assert_failed_after_the_spawn(error, ChildFate::Reaped, false);
        }
    }
}

/// Async twin of the sync `output_status_and_read_hand_a_live_front_back_after_the_spawn`: a live
/// `sudo` front is sent no kill, handed back running, and the error carries the wrapper flag.
///
/// Mutants: a helper drops the wrapper flag of a front; the teardown kills the front.
#[cfg(unix)]
#[skuld::test]
async fn output_status_and_read_hand_a_live_front_back_after_the_spawn() {
    use crate::child::spawn::failure::seams;
    crate::tokio::test_runtime::assert_current_thread();
    // The root reads fd 4, which the helpers leave alone, so only the test's release ends it.
    let front = || {
        let (gate, release) = crate::test_child::held_writer_stdin();
        let mut cmd = crate::test_child::tokio_command(Console::Hidden);
        cmd.args(["sh", "-c", "exec cat <&4 4<&-"]);
        cmd.fd(4, gate).expect("set the front's release pipe");
        cmd.set_elevation_report(crate::child::front_kill_tests::sudo_report());
        (cmd, release)
    };
    for name in ["output", "read", "status"] {
        let (mut cmd, release) = front();
        let _armed = if name == "status" {
            seams::fail_the_next_wait()
        } else {
            seams::fail_the_next_pump()
        };
        let error = match name {
            "output" => cmd.output().await.map(drop),
            "read" => cmd.read().await.map(drop),
            _ => cmd.status().await.map(drop),
        }
        .expect_err("the armed failure fails the helper");
        let crate::error::Error::MayHaveStarted {
            fate,
            wrapper_elevated,
            unreaped: Some(unreaped),
            ..
        } = error
        else {
            panic!("{name}: expected a handed-back front, got {error:?}");
        };
        assert!(wrapper_elevated, "{name}");
        assert!(
            matches!(fate, crate::error::ChildFate::Running { .. }),
            "{name}: a front is left running: {fate:?}"
        );
        drop(release);
        let status = unreaped.wait_async().await.expect("the front exits once released");
        assert!(status.success(), "{name}: a front is sent no kill: {status:?}");
    }
}

/// Async twin of the sync `read_of_invalid_utf8_behind_a_front_keeps_the_wrapper_flag`.
///
/// Mutants: `read` builds the invalid-UTF-8 error without the child's wrapper flag, or sets it
/// from `report.is_some()`.
#[cfg(unix)]
#[skuld::test]
async fn read_of_invalid_utf8_behind_a_front_keeps_the_wrapper_flag() {
    use crate::elevation::{Backend, ElevatedVia};
    crate::tokio::test_runtime::assert_current_thread();
    let reports = [
        (None, false),
        (Some(ElevatedVia::Wrapped(Backend::Pkexec)), false),
        (Some(ElevatedVia::AlreadyElevated), false),
        (Some(ElevatedVia::Wrapped(Backend::Sudo)), true),
    ];
    for (via, wrapper) in reports {
        let mut cmd = crate::test_child::tokio_command(Console::Hidden);
        cmd.args(["printf", "\\377"]);
        if let Some(via) = via {
            cmd.set_elevation_report(Some(crate::elevation::elevation_tests::report(via)));
        }
        let error = cmd.read().await.expect_err("invalid UTF-8 fails `read`");
        let crate::error::Error::MayHaveStarted {
            fate,
            wrapper_elevated,
            source,
            ..
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
