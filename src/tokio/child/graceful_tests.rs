//! The async `Child`'s own waits for `graceful_shutdown_tree` (`impl Waits for Child`), and the async lone
//! `graceful_shutdown`. What the tree call answers is pinned once, through the sync driver, in
//! `child/graceful_tests.rs`: the sequence is one function, so a row here pins what only awaiting changes.

use std::time::Duration;

use crate::test_child::Console;
#[cfg(target_os = "linux")]
use crate::test_groups::{cgroup, Group};

use crate::child::graceful::fault as term_fault;
#[cfg(unix)]
use crate::wait::fault;

/// What keeps a [`kill_only_blocker`] running while the caller holds it.
#[cfg(unix)]
type Held = crate::tokio::ChildStdin;

/// Async twin of `child::graceful_tests::kill_only_blocker`.
#[cfg(unix)]
async fn kill_only_blocker() -> (crate::tokio::Child, Held) {
    crate::test_child::term_ignoring_blocker_async().await
}

#[cfg(unix)]
#[skuld::test]
async fn async_graceful_lone_watch_error_still_escalates_and_reaps() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = kill_only_blocker().await;
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    fault::set_force_watch_error(true);
    // Released between the kill and the reap (see `release_at`).
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
    let err = child
        .graceful_shutdown(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(
        !fault::armed(),
        "seam not consumed — the watch did not run on this thread"
    );
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "child must be killed AND reaped despite the watch error (a zombie would still exist)"
    );
    let status = child
        .wait()
        .await
        .expect("cached status — already reaped by the graceful op");
    crate::test_child::assert_killed("the escalated child", status);
}

#[cfg(unix)]
#[skuld::test]
async fn async_graceful_shutdown_graceful_path() {
    use std::os::unix::process::ExitStatusExt;
    crate::tokio::test_runtime::assert_current_thread();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    let mut child = cmd.spawn().await.expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let _release = term_fault::release_at(term_fault::HookPoint::AfterTerminate, stdin);
    let status = child
        .graceful_shutdown(Duration::from_secs(30))
        .await
        .expect("graceful_shutdown");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "graceful path must exit via SIGTERM, got {status:?}"
    );
}

/// An untaken piped stdin stays open through the grace, so the signal or the kill, not an EOF on
/// stdin, ends a child that reads it. The child ends on EOF with status 0 (Unix: it ignores `SIGTERM`
/// and only the kill ends it), so a grace that closed stdin shows as a clean exit. The reap closes
/// the stdin: `tree` is the call's `graceful_shutdown_tree`, whose reap is `Waits::reap`.
async fn keeps_an_untaken_stdin_open_through_the_grace(tree: bool) {
    crate::tokio::test_runtime::assert_current_thread();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    #[cfg(unix)]
    {
        cmd.args(crate::test_child::TERM_IGNORING_BLOCKER_ARGV.iter().copied());
        cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
        // `contain_without_cgroup_async` asks for `Session` on Linux: no cgroup, so the row needs no delegated one.
        crate::test_child::contain_without_cgroup_async(&mut cmd);
    }
    #[cfg(windows)]
    {
        cmd.executable(crate::test_child::windows_more()).args(["more"]);
        cmd.stdout(crate::Stdio::null()).expect("null stdout");
        cmd.contain();
    }
    cmd.stdin(crate::Stdio::pipe_in()).expect("set stdin pipe");
    let mut child = cmd.spawn().await.expect("spawn");
    #[cfg(unix)]
    {
        use ::tokio::io::AsyncReadExt as _;
        let mut ready = [0u8; 1];
        child
            .stdout()
            .expect("piped stdout")
            .read_exact(&mut ready)
            .await
            .expect("the readiness byte: the trap is installed");
    }

    let grace = Duration::from_secs(1);
    let status = if tree {
        child.graceful_shutdown_tree(grace).await
    } else {
        child.graceful_shutdown(grace).await
    }
    .expect("the shutdown");

    #[cfg(unix)]
    crate::test_child::assert_killed("the SIGTERM-ignoring child", status);
    #[cfg(windows)]
    assert!(
        !status.success(),
        "the child must not end by an EOF on its stdin: {status:?}"
    );
    assert!(child.stdin().is_none(), "the reap closed the untaken stdin");
}

/// Mutant: `graceful_shutdown` closes the untaken stdin before or during the grace.
#[skuld::test]
async fn async_graceful_shutdown_keeps_an_untaken_stdin_open_through_the_grace() {
    keeps_an_untaken_stdin_open_through_the_grace(false).await;
}

/// Mutant: the reap of `graceful_shutdown_tree` leaves the untaken stdin open, or the grace closes it.
#[skuld::test]
async fn async_graceful_shutdown_tree_keeps_an_untaken_stdin_open_through_the_grace() {
    keeps_an_untaken_stdin_open_through_the_grace(true).await;
}

/// The grace watch of the root alone (a mechanism with no drain edge) resolves on the root's exit, and
/// the reap follows.
#[cfg(unix)]
#[skuld::test]
async fn async_graceful_shutdown_tree_graceful_root_sigterm() {
    let _warns = crate::log_capture::warn_watch();
    use std::os::unix::process::ExitStatusExt;
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = crate::test_child::held_contained_blocker_without_cgroup_async(crate::Stdio::pipe()).await;
    let _release = term_fault::release_at(term_fault::HookPoint::AfterTerminate, stdin);
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("tree graceful");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "root must exit via SIGTERM, got {status:?}"
    );
}

/// The sweep's wait reaches a survivor the root left, with the root already gone.
// Async twin of `child_graceful_shutdown_tree_sweeps_survivor_after_graceful_root_exit` in
// `src/child/graceful_tests.rs` — see there for the full rationale.
#[cfg(unix)]
#[skuld::test]
async fn async_graceful_shutdown_tree_sweeps_survivor_after_graceful_root_exit() {
    let _warns = crate::log_capture::warn_watch();
    use ::tokio::io::AsyncReadExt as _;
    crate::tokio::test_runtime::assert_current_thread();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::TERM_SURVIVOR_TREE_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    crate::test_child::contain_without_cgroup_async(&mut cmd);
    let mut child = cmd.spawn().await.expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let mut stdout = child.stdout().expect("piped stdout");
    let mut ready = [0u8; 2];
    stdout.read_exact(&mut ready).await.expect("readiness line");
    assert_eq!(&ready, b"r\n");

    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
    child
        .graceful_shutdown_tree(Duration::from_secs(1))
        .await
        .expect("tree graceful with survivor");

    let mut rest = Vec::new();
    stdout
        .read_to_end(&mut rest)
        .await
        .expect("every member is gone, so the pipe ends");
    assert!(rest.is_empty(), "the sweep missed the grandchild: {rest:?}");
}

#[cfg(unix)]
#[skuld::test]
async fn async_graceful_shutdown_escalates() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = crate::test_child::term_ignoring_blocker_async().await;
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
    let status = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect("graceful_shutdown escalates");
    crate::test_child::assert_killed("the SIGTERM-ignoring child", status);
}

/// A `SIGTERM`-ignoring `cat` this test owns, uncontained, reported as launched by `via` when it is
/// given, and the write end of its stdin, which ends it.
#[cfg(unix)]
async fn reported_blocker(
    via: Option<crate::elevation::ElevatedVia>,
) -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    use ::tokio::io::AsyncReadExt as _;

    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::TERM_IGNORING_BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.set_elevation_report(via.map(crate::elevation::elevation_tests::report));
    let mut child = cmd.spawn().await.expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let mut readiness = [0u8; 1];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut readiness)
        .await
        .expect("readiness byte");
    (child, stdin)
}

/// Closes the `cat`'s stdin and reaps it: it must exit 0, so nothing signalled it.
#[cfg(unix)]
async fn assert_ends_unsignalled(child: &mut crate::tokio::Child, stdin: crate::tokio::ChildStdin) {
    drop(stdin);
    let status = child.wait().await.expect("wait");
    assert!(status.success(), "the child was signalled: {status:?}");
}

/// Async twin of `child::front_kill_tests::a_refused_escalation_of_a_child_that_cannot_run_as_another_user_is_the_io_and_the_watch_failure_a_warn`.
#[cfg(unix)]
#[skuld::test]
async fn async_a_refused_escalation_is_the_io_and_the_watch_failure_a_warn_naming_the_call() {
    use crate::error::Error;
    use crate::os_process::fake::failed_signal;

    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (mut child, stdin) = reported_blocker(None).await;
    child
        .inner
        .proc
        .script_over(|f| f.signals([Ok(crate::signal::Sent::Delivered), failed_signal(libc::EPERM)]));
    fault::set_force_watch_error(true);

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect_err("the kill is refused");

    match &err {
        Error::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}"),
        other => panic!("expected the raw Io(PermissionDenied), got {other:?}"),
    }
    let logged = crate::log_capture::records_since_on_current_thread(mark, "forced grace-watch failure");
    let call = format!("graceful_shutdown({})", child.pid());
    assert!(
        matches!(&logged[..], [(log::Level::Warn, line)] if line.starts_with(&call)),
        "{logged:?}"
    );
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// Async twin of `child::front_kill_tests::a_pkexec_childs_refused_escalation_is_unkillable_as_for_kill`.
#[cfg(unix)]
#[skuld::test]
async fn async_a_pkexec_childs_refused_escalation_is_unkillable_with_the_watch_failure_below_it() {
    use crate::elevation::{Backend, ElevatedVia};
    use crate::error::{ElevationErrorKind, Error};
    use crate::os_process::fake::failed_signal;
    use crate::signal::Sig;

    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = reported_blocker(Some(ElevatedVia::Wrapped(Backend::Pkexec))).await;
    let fake = child
        .inner
        .proc
        .script_over(|f| f.signals([Ok(crate::signal::Sent::Delivered), failed_signal(libc::EPERM)]));
    fault::set_force_watch_error(true);

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect_err("the kill is refused");

    assert!(
        matches!(
            &err,
            Error::Elevation {
                kind: ElevationErrorKind::Unkillable,
                ..
            }
        ),
        "{err:?}"
    );
    let below = err.failures_below();
    assert!(
        matches!(&below[..], [Error::Io(e), watch]
            if e.kind() == std::io::ErrorKind::PermissionDenied
                && crate::error::said(*watch).contains("forced grace-watch failure")),
        "{below:?}"
    );
    assert_eq!(
        fake.signal_calls(),
        [Sig::Term, Sig::Kill],
        "the escalation was reached"
    );
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// Async twin of `child::front_kill_tests::graceful_shutdown_of_a_front_whose_grace_wait_failed_is_unkillable_with_the_watch_failure_as_its_cause`.
#[cfg(unix)]
#[skuld::test]
async fn async_graceful_shutdown_of_a_front_whose_grace_wait_failed_is_unkillable_with_the_watch_failure_as_its_cause()
{
    use crate::elevation::{Backend, ElevatedVia};
    use crate::error::{ElevationErrorKind, Error};

    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = reported_blocker(Some(ElevatedVia::Wrapped(Backend::Sudo))).await;
    fault::set_force_watch_error(true);

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect_err("a live front is not killed");

    match &err {
        Error::Elevation {
            kind: ElevationErrorKind::Unkillable,
            source: Some(cause),
            ..
        } => assert!(
            crate::error::said(&**cause).contains("forced grace-watch failure"),
            "{err:?}"
        ),
        other => panic!("expected Unkillable with the watch failure as its cause, got {other:?}"),
    }
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// A reap that fails after the kill is the answer, and the grace wait's failure beside it is logged
/// at warn, naming the call: the reap's failure is an `Io`, which holds nothing.
///
/// Mutant: the watch failure is dropped when the reap fails.
#[cfg(unix)]
#[skuld::test]
async fn async_a_failed_reap_is_the_answer_and_the_watch_failure_a_warn_naming_the_call() {
    use crate::error::Error;

    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (mut child, stdin) = reported_blocker(None).await;
    fault::set_force_watch_error(true);
    let _armed = crate::child::spawn::failure::seams::fail_the_next_wait();

    let err = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect_err("the reap failed");

    assert!(
        matches!(&err, Error::Io(e) if e.to_string().contains(crate::child::spawn::failure::seams::FAILURE)),
        "{err:?}"
    );
    let logged = crate::log_capture::records_since_on_current_thread(mark, "forced grace-watch failure");
    let call = format!("graceful_shutdown({})", child.pid());
    assert!(
        matches!(&logged[..], [(log::Level::Warn, line)] if line.starts_with(&call)),
        "{logged:?}"
    );
    // The kill landed: the seam consumed, this wait reaps what it killed.
    let status = child.wait().await.expect("reap the killed child");
    crate::test_child::assert_killed("the escalated child", status);
    drop(stdin);
}

/// The tree's drain edge, awaited, answers that the tree drained: the sweep is skipped. See
/// `child::graceful_tests::drained_tree_sweep_decision` for the same decision through the sync driver.
#[cfg(any(windows, target_os = "linux"))]
async fn drained_tree_skips_the_sweep(contain: impl FnOnce(&mut crate::tokio::Command), expected: crate::Containment) {
    crate::tokio::test_runtime::assert_current_thread();
    // Asked on Windows: the test sends a console-group break to a child that registered with the
    // console; a unix child has no console, so the argument is moot there.
    let mut cmd = crate::test_child::tokio_command(Console::Asked);
    #[cfg(unix)]
    {
        cmd.args(["sh", "-c", "echo r; exec cat"]);
        cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
        cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    }
    #[cfg(windows)]
    let (listener, addr) = crate::test_child::registration_rendezvous();
    #[cfg(windows)]
    {
        cmd.executable(std::env::current_exe().expect("current_exe"))
            .args(crate::test_child::fixture_argv(
                crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_TEST,
            ));
        cmd.env(crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV, addr);
        crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
        cmd.env(crate::test_child::ack::ACK_ENV, "1");
    }
    contain(&mut cmd);
    let mut child = cmd.spawn().await.expect("spawn");
    assert_eq!(child.containment(), expected);
    #[cfg(unix)]
    let stdin = child.stdin().expect("piped stdin");
    #[cfg(unix)]
    {
        use tokio::io::AsyncReadExt;
        let mut readiness = [0u8; 1];
        child
            .stdout()
            .expect("piped stdout")
            .read_exact(&mut readiness)
            .await
            .expect("readiness byte");
    }
    // Blocking `std::net::TcpListener`, exactly like the sibling Windows test above: a bounded
    // wait for a real connection, not a poll loop.
    #[cfg(windows)]
    let _sock = {
        use std::io::Read;
        let mut sock = crate::test_child::accept_or_die(&listener, child.id().expect(crate::test_child::IDENTITY_READ));
        let mut tag = [0u8; 1];
        sock.read_exact(&mut tag).expect("registration tag");
        sock
    };
    let armed = term_fault::ArmedKillTreeError::arm();
    // Released once `terminate_tree` has returned, before any watch: SIGTERM is then already
    // pending on the root, so it beats the EOF this release causes.
    #[cfg(unix)]
    let _release = term_fault::release_at(term_fault::HookPoint::AfterTerminate, stdin);
    // Windows: assert the break was sent once `terminate_tree` returns, so a missing one fails
    // here and not when the grace runs out.
    #[cfg(windows)]
    let check = {
        let pid = child.pid();
        term_fault::at_checked(term_fault::HookPoint::AfterTerminate, move || {
            crate::test_child::ctrl_break::assert_break_sent_to(pid)
        })
    };
    let result = child.graceful_shutdown_tree(Duration::from_secs(30)).await;
    #[cfg(windows)]
    check.assert_fired();
    let status = result.expect("an authoritatively-drained tree must not invoke the sweep at all");
    assert!(
        term_fault::kill_tree_armed(),
        "the forced kill_tree failure must still be armed — the sweep was never entered"
    );
    drop(armed); // disarm now that this branch's own assertion above has run
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "graceful root exit, got {status:?}"
        );
    }
    #[cfg(windows)]
    assert_eq!(
        status.code(),
        Some(0xC000013A_u32 as i32),
        "the root must die to the console event, not to a loader-init kill or the sweep, got {status:?}"
    );
}

#[cfg(windows)]
#[skuld::test]
async fn async_graceful_tree_drained_skips_sweep_in_a_job_object() {
    drained_tree_skips_the_sweep(|cmd| _ = cmd.contain(), crate::Containment::JobObject).await;
}

#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_graceful_tree_drained_skips_sweep_in_a_cgroup(#[fixture(cgroup)] _group: &Group) {
    drained_tree_skips_the_sweep(|cmd| _ = cmd.contain(), crate::Containment::CgroupV2).await;
}

// Async twin of `members_remain_still_reaps_an_already_exited_root`; see there for the fixture's
// rationale (`exited_through_handle`, like the sync wait, does not reap) and for `mode` and `swept`.
#[cfg(unix)]
async fn members_remain_still_reaps_an_already_exited_root(
    mode: crate::ContainMode,
    swept: impl FnOnce(&mut crate::tokio::Child),
) {
    crate::tokio::test_runtime::assert_current_thread();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args([
        "sh",
        "-c",
        "trap '' TERM; exec 3<&0; cat <&3 >/dev/null 3<&- & echo r; read _ <&4; exit 0",
    ]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.fd(4, crate::Stdio::pipe_in()).expect("set exit-gate pipe");
    cmd.contain_with(mode);
    let mut child = cmd.spawn().await.expect("spawn");
    // Held for the test's whole body — see `child::graceful_tests`'s sync twin for why.
    let stdin = child.stdin().expect("piped stdin");
    let mut exit_gate = child.fd_write_end(4).expect("exit-gate write end");
    let mut readiness = [0u8; 1];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut readiness)
        .await
        .expect("readiness byte");
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    // The root is still blocked on `read _ <&4`: release it, then wait for its exit WITHOUT
    // reaping.
    exit_gate.write_all(b"x\n").await.expect("release the root's exit 0");
    drop(exit_gate);
    child.exited_through_handle(None).await.expect("the root must exit");
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Present,
        "the exited root must still be an unreaped zombie before graceful_shutdown_tree runs"
    );
    let drainable = child.containment().can_observe_drain();
    term_fault::set_force_kill_tree_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(2))
        .await
        .expect_err("the forced sweep failure must surface");
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    assert!(
        !term_fault::kill_tree_armed(),
        "the sweep must have consumed the forced-failure seam"
    );
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "an already-exited root must be best-effort reaped even when the sweep fails"
    );
    // The forced sweep failure was a stub, so the TERM-ignoring descendant is still alive, and the
    // call above reaped the root.
    swept(&mut child);
    // The descendant's stdin is released before the drain wait: it ends by itself when the sweep
    // sent nothing, and the wait cannot be left unbounded.
    drop(stdin);
    // Drain and remove the leaf here: the drop is not under test, and would leave a `cosca-*` leaf.
    if drainable {
        child.wait_tree().await.expect("the swept tree drains");
    }
}

/// The root probe after a drain verdict that does not clear the tree, awaited: the root has exited, so
/// the best-effort reap follows a failed sweep. The leaf is swept by its own handle.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_graceful_tree_members_remain_still_reaps_an_already_exited_root_in_a_cgroup(
    #[fixture(cgroup)] _group: &Group,
) {
    members_remain_still_reaps_an_already_exited_root(crate::ContainMode::Strongest, |child| {
        assert_eq!(child.containment(), crate::containment::Containment::CgroupV2);
        child.send_kill_tree().expect("the leaf is swept by its own handle");
    })
    .await;
}

/// A reaped root's group is not signalled by its number. The TERM-ignoring member keeps the group's
/// number its own while the call runs. On macOS the tree is the fd marker: the drain verdict is
/// `AllMarkersClosed` or members remain, never proof to skip the sweep, and the root probe follows.
#[cfg(unix)]
#[skuld::test]
async fn async_graceful_tree_members_remain_still_reaps_an_already_exited_root_in_a_process_group() {
    members_remain_still_reaps_an_already_exited_root(crate::ContainMode::Session, |child| {
        assert_eq!(child.containment(), crate::test_child::session_gives());
        // Below Linux 6.9 a group is signalled by its number alone.
        #[cfg(target_os = "linux")]
        let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
        let err = child
            .send_kill_tree()
            .expect_err("a reaped root's group is not signalled by its number");
        assert!(matches!(err, crate::error::Error::Unassessable { .. }), "got {err:?}");
    })
    .await;
}

// Async twin of `windows_graceful_tree_members_remain_surfaces_the_forced_sweep_failure` — see
// there for the full rationale, including why the Unix twin's reap postcondition does not
// translate to Windows (no Windows-observable difference between the fixed code and the bug it
// was meant to catch, so none is asserted here), the `test_child::fixture_survives_group_signal`
// fixture that plays the Unix root shell's role, and why the readiness tag travels over a raw
// TCP socket rather than stdout. Blocking `std::net::TcpListener` (not an async socket), exactly
// like `tests/common::spawn_tree_async`'s own synchronous accept — a short, bounded wait for a
// real connection, not a poll loop, and the same shape already accepted for an async test. It is the
// Windows row of the job's drain wait, awaited, answering that members remain.
#[cfg(windows)]
#[skuld::test]
async fn windows_async_graceful_tree_members_remain_surfaces_the_forced_sweep_failure() {
    crate::tokio::test_runtime::assert_current_thread();
    use std::io::Read;

    use tokio::io::AsyncWriteExt as _;

    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = std_listener.local_addr().expect("local_addr").to_string();
    std_listener.set_nonblocking(true).expect("nonblocking listener");
    let listener = tokio::net::TcpListener::from_std(std_listener).expect("tokio listener");

    // Asked: `graceful_shutdown_tree` breaks the root's console group, which a hidden root would
    // not be in.
    let mut cmd = crate::test_child::tokio_command(Console::Asked);
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(crate::test_child::fixture_argv(
            crate::test_child::FIXTURE_SURVIVES_GROUP_SIGNAL_TEST,
        ));
    cmd.env(crate::test_child::FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV, addr);
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    cmd.env(crate::test_child::ack::ACK_ENV, "1");
    cmd.contain();
    let mut child = cmd.spawn().await.expect("spawn");
    // The fixture exits at once and its group-signal-immune descendant is the one that connects,
    // so the fixture's own pid cannot be watched: the job draining is the death of every possible
    // connector. The connector waits for the ack, so a drain with nothing accepted is a failure.
    let mut sock = tokio::select! {
        biased;
        accepted = listener.accept() => accepted.expect("accept the readiness connection").0,
        drained = child.wait_tree() => match drained {
            Ok(drain) => panic!("the tree drained ({drain:?}) before anything connected"),
            Err(e) => panic!("wait_tree failed while waiting for a connection: {e}"),
        },
    };
    sock.write_all(&[crate::test_child::ack::ACK_BYTE])
        .await
        .expect("ack the readiness connection");
    let mut sock = sock.into_std().expect("into std");
    sock.set_nonblocking(false).expect("blocking stream");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("readiness tag");
    term_fault::set_force_kill_tree_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(2))
        .await
        .expect_err("the forced sweep failure must surface");
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    assert!(
        !term_fault::kill_tree_armed(),
        "the sweep must have consumed the forced-failure seam"
    );
    // Cleanup: the forced sweep failure was a stub, so the group-signal-immune descendant is
    // still alive — a real sweep now (the seam is already consumed) actually kills it.
    _ = child.kill_tree().await;
}

// `TreeWalk` has no drain edge to observe, so the grace-wait of `graceful_shutdown_tree` watches the
// root alone. Here the root has exited and been waited for: the watch must resolve at once, not
// spend the grace.
//
// Mutant: the `TreeWalk` arm never reaches the driver (e.g. hollowed to `sleep(grace)`). Killed by
// the paused clock not moving across the call: any expiring tokio timer advances it.
//
// A driver that waits on the exited root's handle anyway returns at once, as the handle is
// signalled: no check can tell it from the driver that looks first.
#[cfg(windows)]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn windows_async_treewalk_grants_no_grace_window_once_the_root_has_been_waited() {
    const GRACE: Duration = Duration::from_secs(30);
    let (mut child, stdin) = crate::test_child::windows_blocker_on_console_async(|cmd| {
        cmd.contain_with(crate::ContainMode::TreeWalk);
    })
    .await;
    assert_eq!(
        child.containment(),
        crate::Containment::TreeWalk,
        "the subject must be the mechanism that has no drain edge to watch"
    );
    child.kill().expect("kill");
    // Released only after the kill, so a no-op kill fails `assert_killed`.
    drop(stdin);
    crate::test_child::assert_killed("the blocker", child.wait().await.expect("reap"));

    let before = ::tokio::time::Instant::now();
    let outcome = child.graceful_shutdown_tree(GRACE).await;
    assert_eq!(
        ::tokio::time::Instant::now() - before,
        Duration::ZERO,
        "the root-only watch must never advance the virtual clock — any use of `tokio::time` \
         (a hollowed-out grace-wait sleeping the grace instead of watching the process, for \
         instance) would move it: {outcome:?}"
    );
}

// A refusal that never addresses a pid survives the reap. An uncontained Windows child records
// `GracefulMechanism::None` — permanent and pid-independent — so it keeps answering `Unsupported`
// (what its own doc promises, and what the sync mirror returns for the identical child) after the
// reap, not `Unassessable`, which is documented as a transient could-not-determine condition a
// caller may retry.
#[cfg(windows)]
#[skuld::test]
async fn windows_async_lone_terminate_keeps_a_pid_independent_refusal_after_a_reap() {
    // Uncontained: leads no group of its own.
    let (mut child, stdin) = crate::test_child::windows_blocker_on_console_async(|_| {}).await;
    assert_eq!(
        child.graceful_mechanism(),
        crate::graceful::GracefulMechanism::None,
        "the subject must be a child whose refusal is permanent, not pid-dependent"
    );
    child.kill().expect("kill");
    // Released only after the kill, so a no-op kill fails `assert_killed`.
    drop(stdin);
    crate::test_child::assert_killed("the blocker", child.wait().await.expect("reap"));
    let err = child.terminate().expect_err("a child that leads no group is refused");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
}

/// The holders-only escalation of `graceful_shutdown_tree` (a macOS fd marker whose root's number may
/// name another process) awaits each member its kill reached: the sibling that ends the member finds
/// the call still pending, and no runtime thread blocks on it. The call is made on the escalation
/// itself, over a mechanism that states the member, because only an fd marker ends in it and nothing
/// holds a real marker member after its `SIGKILL`.
///
/// Mutants: `finish_async` returns the error without its wait; `finish_async` waits through the
/// blocking `wait`.
#[cfg(unix)]
#[skuld::test]
async fn a_holders_only_escalation_awaits_each_member_its_kill_reached() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::identity::Liveness;
    use crate::os_process::fake::Answer;
    use crate::test_child::over_fake::{holders_only_skip, live_member, root_looking, tokio_child_reaching};

    crate::tokio::test_runtime::assert_current_thread();
    let (member, writer, id) = live_member();
    let root = root_looking([Answer::Exited]);
    let child = tokio_child_reaching(&root, &[id]);
    let skip = holders_only_skip(&child.inner);
    let writer = Rc::new(Cell::new(Some(writer)));
    let blocked = Rc::new(Cell::new(false));
    // A wait that blocks the thread ends the member from inside the block, so the row fails instead of
    // hanging.
    let _blocking = crate::wait::block_probe::on_blocking({
        let (writer, blocked) = (writer.clone(), blocked.clone());
        move || {
            blocked.set(true);
            drop(writer.take());
        }
    });
    let done = Cell::new(false);

    let (error, ()) = ::tokio::join!(
        async {
            let error = crate::child::graceful::shutdown::holders_only(&child, skip, Duration::ZERO).await;
            done.set(true);
            error
        },
        async {
            ::tokio::task::yield_now().await;
            assert!(
                !done.get(),
                "the escalation resolved while a member its kill reached was running"
            );
            drop(writer.take());
        }
    );

    assert!(!blocked.get(), "the escalation blocked a runtime thread");
    assert!(
        matches!(error, crate::error::Error::Unassessable { .. }),
        "the holders alone are not the tree: {error}"
    );
    assert_eq!(
        id.is_alive(),
        Liveness::Dead,
        "the member has exited when the escalation resolves"
    );
    _ = member.wait();
}
