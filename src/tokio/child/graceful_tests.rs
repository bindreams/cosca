//! Async twin of `child/graceful_tests.rs` — watch-failure ordering via the shared seam.

use std::time::Duration;

use super::fault as term_fault;
use crate::wait::fault;

#[tokio::test]
async fn async_graceful_tree_watch_error_still_sweeps_and_reaps() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(
        crate::log_capture::contains_since(mark, &format!("graceful_shutdown_tree({pid})", pid = id.pid())),
        "the subsumption trace must fire on the forced watch error"
    );
    assert!(
        !fault::armed(),
        "seam not consumed — the watch did not run on this thread"
    );
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    // The reap is proven by identity on all Unix (procfs / `sysctl KERN_PROC` are both
    // zombie-inclusive); Windows skips the assert — exists() stays true there while
    // `child` still holds the process handle.
    #[cfg(unix)]
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "root must be swept AND reaped despite the watch error (a zombie would still exist)"
    );
    #[cfg(windows)]
    let _ = id;
    let status = child
        .wait()
        .await
        .expect("cached status — already reaped by the graceful op");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_lone_watch_error_still_escalates_and_reaps() {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sleep", "30"]);
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(
        crate::log_capture::contains_since(mark, &format!("graceful_shutdown({pid})", pid = id.pid())),
        "the subsumption trace must fire on the forced watch error"
    );
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
    assert!(
        !status.success(),
        "escalated child cannot report success, got {status:?}"
    );
}

// Async twin of `graceful_tree_terminate_refusal_still_sweeps_and_reaps` in
// `src/child/graceful_tests.rs` — see there for the full rationale.
#[tokio::test]
async fn async_graceful_tree_terminate_refusal_still_sweeps_and_reaps() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    term_fault::set_force_terminate(term_fault::Forced::Containment);
    // A successful sweep is fresher, positive proof the group cleared, superseding the held
    // refusal — the call must report `Ok`, not resurface the disproved `Containment` error.
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("a successful sweep must supersede the forced terminate refusal");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
    assert!(
        crate::log_capture::contains_since(
            mark,
            &format!("graceful_shutdown_tree({pid}): terminate_tree refused", pid = id.pid())
        ),
        "the terminate-refusal trace specifically must fire"
    );
    assert!(
        crate::log_capture::contains_since(
            mark,
            &format!(
                "graceful_shutdown_tree({pid}): tree confirmed clear; discarding the superseded terminate_tree refusal",
                pid = id.pid()
            )
        ),
        "the refusal must be logged as discarded, not silently dropped"
    );
    #[cfg(unix)]
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "root must be swept AND reaped despite the forced terminate refusal"
    );
    #[cfg(windows)]
    let _ = id;
}

// Async twin of `graceful_tree_unassessable_per_member_still_sweeps_and_reaps`.
#[tokio::test]
async fn async_graceful_tree_unassessable_per_member_still_sweeps_and_reaps() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    term_fault::set_force_terminate(term_fault::Forced::UnassessablePerMember);
    // Same supersession as the `Containment` test above: the sweep's success disproves the
    // held per-member-unconfirmed state, so the call must report `Ok`.
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("a successful sweep must supersede the forced unassessable state");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
    assert!(
        crate::log_capture::contains_since(
            mark,
            &format!("graceful_shutdown_tree({pid}): terminate_tree refused", pid = id.pid())
        ),
        "the terminate-refusal trace specifically must fire"
    );
    assert!(
        crate::log_capture::contains_since(
            mark,
            &format!(
                "graceful_shutdown_tree({pid}): tree confirmed clear; discarding the superseded terminate_tree refusal",
                pid = id.pid()
            )
        ),
        "the refusal must be logged as discarded, not silently dropped"
    );
    #[cfg(unix)]
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "root must be swept AND reaped despite the forced unassessable state"
    );
    #[cfg(windows)]
    let _ = id;
}

// Async twin of `graceful_tree_unassessable_mechanism_failure_fails_fast`.
#[tokio::test]
async fn async_graceful_tree_unassessable_mechanism_failure_fails_fast() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    term_fault::set_force_terminate(term_fault::Forced::UnassessableMechanism);
    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect_err("the forced listing-mechanism failure must surface immediately");
    assert!(
        matches!(err, crate::error::Error::Unassessable { source: Some(_), .. }),
        "got {err:?}"
    );
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Present,
        "a listing-mechanism failure must return before any grace wait or sweep"
    );
    // Clean up: the child is still running by design (no sweep happened above).
    let _ = child.kill_tree();
    let _ = child.wait().await;
}

// Async twin of `graceful_tree_drained_skips_sweep_only_when_the_mechanism_is_authoritative` —
// see there for the full rationale.
#[tokio::test]
async fn async_graceful_tree_drained_skips_sweep_only_when_the_mechanism_is_authoritative() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    {
        cmd.args(["sh", "-c", "echo r; exec sleep 30"]);
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
    }
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
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
        let (mut sock, _) = listener.accept().expect("accept rendezvous connection");
        let mut tag = [0u8; 1];
        sock.read_exact(&mut tag).expect("registration tag");
        sock
    };
    let authoritative = matches!(
        child.containment(),
        crate::containment::Containment::CgroupV2 | crate::containment::Containment::JobObject
    );
    let armed = term_fault::ArmedKillTreeError::arm();
    let result = child.graceful_shutdown_tree(Duration::from_secs(30)).await;
    if authoritative {
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
    } else {
        let err = result.expect_err("a non-authoritative mechanism must always run the sweep");
        assert!(
            !term_fault::kill_tree_armed(),
            "the sweep must have consumed the forced-failure seam"
        );
        drop(armed); // already disarmed by the sweep above; this is a no-op, kept for symmetry
        assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
        let _ = child.kill_tree(); // cleanup: the forced failure means the real sweep never ran
        let _ = child.wait().await;
    }
}

// Async twin of `graceful_tree_members_remain_still_reaps_an_already_exited_root` — see there
// for the full rationale, including the readiness handshake that closes the root's own
// trap-installation race.
#[cfg(unix)]
#[tokio::test]
async fn async_graceful_tree_members_remain_still_reaps_an_already_exited_root() {
    use tokio::io::AsyncReadExt;

    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sh", "-c", "trap '' TERM; sleep 30 & echo r; exit 0"]);
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let mut readiness = [0u8; 1];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut readiness)
        .await
        .expect("readiness byte");
    let id = child.id();
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
        "an already-exited root must be best-effort reaped even when the sweep fails ({})",
        if drainable {
            "MembersRemain branch"
        } else {
            "non-drain-observable fallback branch — pre-existing, unaffected behavior"
        }
    );
    // Cleanup: the forced sweep failure was a stub, so the SIGTERM-ignoring descendant is
    // still alive — a real sweep now (the seam is already consumed) actually kills it.
    let _ = child.kill_tree();
}

// Async twin of `windows_graceful_tree_members_remain_surfaces_the_forced_sweep_failure` — see
// there for the full rationale, including why the Unix twin's reap postcondition does not
// translate to Windows (no Windows-observable difference between the fixed code and the bug it
// was meant to catch, so none is asserted here), the `test_child::fixture_survives_group_signal`
// fixture that plays the Unix root shell's role, and why the readiness tag travels over a raw
// TCP socket rather than stdout. Blocking `std::net::TcpListener` (not an async socket), exactly
// like `tests/common::spawn_tree_async`'s own synchronous accept — a short, bounded wait for a
// real connection, not a poll loop, and the same shape already accepted for an async test.
#[cfg(windows)]
#[tokio::test]
async fn windows_async_graceful_tree_members_remain_surfaces_the_forced_sweep_failure() {
    use std::io::Read;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = listener.local_addr().expect("local_addr").to_string();

    let mut cmd = crate::tokio::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(crate::test_child::fixture_argv(
            crate::test_child::FIXTURE_SURVIVES_GROUP_SIGNAL_TEST,
        ));
    cmd.env(crate::test_child::FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV, addr);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let (mut sock, _) = listener.accept().expect("accept readiness connection");
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
    let _ = child.kill_tree();
}

// The lone graceful ops must not fire a pid-addressed console event once the backend has reaped:
// tokio replaces its inner state on `wait`, dropping the guard that holds the process handle, and
// the OS may reissue that pid to a process leading a group in this console.
//
// `.contain()` is load-bearing — an uncontained child reports `GracefulMechanism::None` and would
// be refused before the pid ever mattered, which is the wrong reason. Both assertions read the
// error's VARIANT, not merely that one exists: an unguarded call returns `Ok` or the OS's `Io`,
// never `Unassessable`, whichever way the recycled pid falls.
#[cfg(windows)]
#[tokio::test]
async fn windows_async_lone_graceful_ops_refuse_once_the_backend_has_reaped() {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(
        child.graceful_mechanism(),
        crate::graceful::GracefulMechanism::ConsoleGroup,
        "the subject must be a child the signal would otherwise be sent to"
    );
    child.kill().expect("kill");
    child.wait().await.expect("reap"); // tokio unpins the pid here
    let err = child.terminate().expect_err("an unpinned pid must not be signalled");
    assert!(
        matches!(err, crate::error::Error::Unassessable { source: None, .. }),
        "got {err:?}"
    );
    let err = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect_err("the escalation trio inherits the refusal from its cooperative half");
    assert!(
        matches!(err, crate::error::Error::Unassessable { source: None, .. }),
        "got {err:?}"
    );
}

// Async twin of `graceful_tree_non_containment_terminate_error_fails_fast`.
#[tokio::test]
async fn async_graceful_tree_non_containment_terminate_error_fails_fast() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    term_fault::set_force_terminate(term_fault::Forced::Unsupported);
    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect_err("the forced Unsupported error must surface immediately");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Present,
        "a non-containment terminate error must return before any grace wait or sweep"
    );
    // Clean up: the child is still running by design (no sweep happened above).
    let _ = child.kill_tree();
    let _ = child.wait().await;
}
