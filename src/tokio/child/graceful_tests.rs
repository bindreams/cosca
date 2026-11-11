//! Async twin of `child/graceful_tests.rs` — watch-failure ordering via the shared seam.

use std::time::Duration;

use crate::test_child::Console;
#[cfg(target_os = "linux")]
use crate::test_groups::{cgroup, Group};

use crate::child::graceful::fault as term_fault;
use crate::wait::fault;

/// Async twin of `child::graceful_tests::blocker`.
fn blocker() -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    crate::test_child::held_contained_blocker_on_console_async(crate::Stdio::pipe())
}

/// What keeps a [`kill_only_blocker`] running while the caller holds it.
#[cfg(unix)]
type Held = crate::tokio::ChildStdin;
#[cfg(windows)]
type Held = std::net::TcpStream;

/// Async twin of `child::graceful_tests::kill_only_blocker`.
async fn kill_only_blocker() -> (crate::tokio::Child, Held) {
    #[cfg(unix)]
    {
        crate::test_child::term_ignoring_blocker_async().await
    }
    #[cfg(windows)]
    {
        crate::test_child::ctrl_break::spawn_ignoring_root_async()
    }
}

/// Async twin of `child::graceful_tests::assert_still_running`; consumes `stdin` and reaps the child.
async fn assert_still_running(child: &mut crate::tokio::Child, mut stdin: crate::tokio::ChildStdin) {
    use ::tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    #[cfg(unix)]
    {
        let mut stdout = child.stdout().expect("piped stdout");
        stdin.write_all(b"x").await.expect("write to the blocker");
        let mut echo = [0u8; 1];
        stdout
            .read_exact(&mut echo)
            .await
            .expect("the blocker must still be alive to echo");
        assert_eq!(&echo, b"x");
    }
    #[cfg(windows)]
    {
        stdin.write_all(b"x\r\n").await.expect("write to the blocker");
        drop(stdin); // EOF: findstr can now finish reading and exit
        let mut output = Vec::new();
        child
            .stdout()
            .expect("piped stdout")
            .read_to_end(&mut output)
            .await
            .expect("read stdout to EOF");
        let status = child.wait().await.expect("the blocker must exit after stdin closes");
        assert!(
            status.success(),
            "the blocker must exit 0 (findstr's own 'a match was found' code), got {status:?}"
        );
        assert!(
            output.windows(1).any(|w| w == b"x"),
            "the blocker's stdout must contain the echoed match, got {output:?}"
        );
    }
}

/// Sweeps the tree and reaps the child. Windows discards errors: `assert_still_running` already
/// reaped the child there, so a second kill or wait has nothing to act on.
async fn cleanup(child: &mut crate::tokio::Child) {
    #[cfg(unix)]
    {
        child.kill_tree().expect("cleanup sweep");
        child.wait().await.expect("reap");
    }
    #[cfg(windows)]
    {
        _ = child.kill_tree();
        _ = child.wait().await;
    }
}

#[skuld::test]
async fn async_graceful_tree_watch_error_still_sweeps_and_reaps() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = kill_only_blocker().await;
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    // Released between the sweep and the reap (see `release_at`).
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
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
    crate::test_child::assert_killed("the swept root", status);
}

#[cfg(unix)]
#[skuld::test]
async fn async_graceful_lone_watch_error_still_escalates_and_reaps() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = kill_only_blocker().await;
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    // Released between the kill and the reap (see `release_at`).
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
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
    let mut child = cmd.spawn().expect("spawn");
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
/// the stdin.
///
/// Mutant: `graceful_shutdown` closes the untaken stdin before or during the grace.
#[skuld::test]
async fn async_graceful_shutdown_keeps_an_untaken_stdin_open_through_the_grace() {
    crate::tokio::test_runtime::assert_current_thread();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    #[cfg(unix)]
    {
        cmd.args(crate::test_child::TERM_IGNORING_BLOCKER_ARGV.iter().copied());
        cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    }
    #[cfg(windows)]
    {
        cmd.executable(crate::test_child::windows_more()).args(["more"]);
        cmd.stdout(crate::Stdio::null()).expect("null stdout");
    }
    cmd.stdin(crate::Stdio::pipe_in()).expect("set stdin pipe");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
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

    let status = child
        .graceful_shutdown(Duration::from_secs(1))
        .await
        .expect("graceful_shutdown");

    #[cfg(unix)]
    crate::test_child::assert_killed("the SIGTERM-ignoring child", status);
    #[cfg(windows)]
    assert!(
        !status.success(),
        "the child must not end by an EOF on its stdin: {status:?}"
    );
    assert!(child.stdin().is_none(), "the reap closed the untaken stdin");
}

#[cfg(unix)]
#[skuld::test]
async fn async_graceful_shutdown_tree_graceful_root_sigterm() {
    let _warns = crate::log_capture::warn_watch();
    use std::os::unix::process::ExitStatusExt;
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = crate::test_child::held_contained_blocker_without_cgroup_async(crate::Stdio::pipe());
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

#[cfg(unix)]
#[skuld::test]
async fn async_graceful_shutdown_tree_tears_down_tree() {
    let _warns = crate::log_capture::warn_watch();
    use std::os::unix::process::ExitStatusExt;

    use ::tokio::io::AsyncReadExt as _;
    crate::tokio::test_runtime::assert_current_thread();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args([
        "sh",
        "-c",
        "exec 3<&0; sh -c 'echo r; read -r _; echo leaf' <&3 3<&- & exec cat",
    ]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    crate::test_child::contain_without_cgroup_async(&mut cmd);
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let mut stdout = child.stdout().expect("piped stdout");
    let mut ready = [0u8; 2];
    stdout.read_exact(&mut ready).await.expect("readiness line");
    assert_eq!(&ready, b"r\n");

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
    let mut rest = Vec::new();
    stdout
        .read_to_end(&mut rest)
        .await
        .expect("both members are gone, so the pipe ends");
    assert!(rest.is_empty(), "nothing was written: {rest:?}");
}

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
    let mut child = cmd.spawn().expect("spawn");
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

#[cfg(unix)]
#[skuld::test]
async fn async_graceful_shutdown_tree_escalates_with_a_surviving_grandchild() {
    let _warns = crate::log_capture::warn_watch();
    use ::tokio::io::AsyncReadExt as _;
    crate::tokio::test_runtime::assert_current_thread();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::TERM_IGNORING_TREE_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    crate::test_child::contain_without_cgroup_async(&mut cmd);
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let mut stdout = child.stdout().expect("piped stdout");
    let mut ready = [0u8; 2];
    stdout.read_exact(&mut ready).await.expect("readiness line");
    assert_eq!(
        &ready,
        b"r
"
    );

    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("tree escalates");

    crate::test_child::assert_killed("the SIGTERM-ignoring root", status);
    let mut rest = Vec::new();
    stdout
        .read_to_end(&mut rest)
        .await
        .expect("every member is gone, so the pipe ends");
    assert!(rest.is_empty(), "the sweep missed a grandchild: {rest:?}");
}

// Async twin of `graceful_tree_terminate_refusal_still_sweeps_and_reaps` in
// `src/child/graceful_tests.rs` — see there for the full rationale.
#[skuld::test]
async fn async_graceful_tree_terminate_refusal_still_sweeps_and_reaps() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = kill_only_blocker().await;
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    term_fault::set_force_terminate(term_fault::Forced::Containment);
    // A successful sweep is fresher, positive proof the group cleared, superseding the held
    // refusal — the call must report `Ok`, not resurface the disproved `Containment` error.
    // Released between the sweep and the reap (see `release_at`).
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("a successful sweep must supersede the forced terminate refusal");
    crate::test_child::assert_killed("the root", status);
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
#[skuld::test]
async fn async_graceful_tree_unassessable_per_member_still_sweeps_and_reaps() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = kill_only_blocker().await;
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    term_fault::set_force_terminate(term_fault::Forced::UnassessablePerMember);
    // Same supersession as the `Containment` test above: the sweep's success disproves the
    // held per-member-unconfirmed state, so the call must report `Ok`.
    // Released between the sweep and the reap (see `release_at`).
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, stdin);
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("a successful sweep must supersede the forced unassessable state");
    crate::test_child::assert_killed("the root", status);
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
#[skuld::test]
async fn async_graceful_tree_unassessable_mechanism_failure_fails_fast() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = blocker();
    term_fault::set_force_terminate(term_fault::Forced::UnassessableMechanism);
    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect_err("the forced listing-mechanism failure must surface immediately");
    assert!(
        matches!(err, crate::error::Error::Unassessable { source: Some(_), .. }),
        "got {err:?}"
    );
    // Fails fast: no grace was waited, no sweep ran, so the child is STILL ALIVE.
    assert_still_running(&mut child, stdin).await;
    cleanup(&mut child).await;
}

// Async twin of `child::graceful_tests::drained_tree_sweep_decision` — see there for the full
// rationale, `contain` and `expected`.
async fn drained_tree_sweep_decision(contain: impl FnOnce(&mut crate::tokio::Command), expected: crate::Containment) {
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
    let mut child = cmd.spawn().expect("spawn");
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
    let authoritative = matches!(
        expected,
        crate::containment::Containment::CgroupV2 | crate::containment::Containment::JobObject
    );
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
        _ = child.kill_tree(); // cleanup: the forced failure means the real sweep never ran
        let status = child
            .wait()
            .await
            .expect("the root was observed exited, so it is reaped");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(libc::SIGTERM),
                "the root must die to the SIGTERM, not exit on its own, got {status:?}"
            );
        }
        #[cfg(windows)]
        assert_eq!(
            status.code(),
            Some(0xC000013A_u32 as i32),
            "the root must die to the console event, not to the cleanup sweep, got {status:?}"
        );
    }
}

#[cfg(windows)]
#[skuld::test]
async fn async_graceful_tree_drained_skips_sweep_in_a_job_object() {
    drained_tree_sweep_decision(|cmd| _ = cmd.contain(), crate::Containment::JobObject).await;
}

#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_graceful_tree_drained_skips_sweep_in_a_cgroup(#[fixture(cgroup)] _group: &Group) {
    drained_tree_sweep_decision(|cmd| _ = cmd.contain(), crate::Containment::CgroupV2).await;
}

#[cfg(unix)]
#[skuld::test]
async fn async_graceful_tree_drained_still_sweeps_without_an_authoritative_mechanism() {
    drained_tree_sweep_decision(
        |cmd| _ = crate::test_child::contain_without_cgroup_async(cmd),
        crate::test_child::contain_without_cgroup_gives(),
    )
    .await;
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
    let mut child = cmd.spawn().expect("spawn");
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
        "an already-exited root must be best-effort reaped even when the sweep fails ({})",
        if drainable {
            "MembersRemain branch"
        } else {
            "non-drain-observable fallback branch — pre-existing, unaffected behavior"
        }
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

/// The leaf is swept by its own handle.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_graceful_tree_members_remain_still_reaps_an_already_exited_root_in_a_cgroup(
    #[fixture(cgroup)] _group: &Group,
) {
    members_remain_still_reaps_an_already_exited_root(crate::ContainMode::Strongest, |child| {
        assert_eq!(child.containment(), crate::containment::Containment::CgroupV2);
        child.kill_tree().expect("the leaf is swept by its own handle");
    })
    .await;
}

/// A reaped root's group is not signalled by its number.
#[cfg(unix)]
#[skuld::test]
async fn async_graceful_tree_members_remain_still_reaps_an_already_exited_root_in_a_process_group() {
    members_remain_still_reaps_an_already_exited_root(crate::ContainMode::Session, |child| {
        // Below Linux 6.9 a group is signalled by its number alone.
        #[cfg(target_os = "linux")]
        let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
        let err = child
            .kill_tree()
            .expect_err("a reaped root's group is not signalled by its number");
        assert!(matches!(err, crate::error::Error::Unassessable { .. }), "got {err:?}");
    })
    .await;
}

// Async twin of `graceful_tree_that_left_a_descendant_reaps_the_root_the_backstop_killed_and_returns_the_error`.
#[cfg(all(unix, not(target_os = "macos")))]
#[skuld::test]
async fn async_graceful_tree_that_left_a_descendant_reaps_the_root_the_backstop_killed_and_returns_the_error() {
    use ::tokio::io::AsyncReadExt as _;

    use crate::containment::treewalk::fault::{self, LeftBehind};

    crate::tokio::test_runtime::assert_current_thread();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::TERM_IGNORING_BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    let _stdin = child.stdin().expect("piped stdin");
    let mut readiness = [0u8; 1];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut readiness)
        .await
        .expect("readiness byte");
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Present,
        "precondition: the root runs"
    );

    fault::force_incomplete_once(LeftBehind::Descendant);
    let err = child
        .graceful_shutdown_tree(Duration::from_millis(200))
        .await
        .expect_err("a descendant was left");

    assert!(matches!(err, crate::error::Error::MemberNotKilled { .. }), "{err:?}");
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "the root the backstop killed must be reaped before the error returns"
    );
    crate::test_child::assert_killed(
        "the root",
        child.wait().await.expect("the reaped root's status is kept"),
    );
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
    let mut child = cmd.spawn().expect("spawn");
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
    _ = child.kill_tree();
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
    });
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
    let (mut child, stdin) = crate::test_child::windows_blocker_on_console_async(|_| {});
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

// Async twin of `graceful_tree_non_containment_terminate_error_fails_fast`.
#[skuld::test]
async fn async_graceful_tree_non_containment_terminate_error_fails_fast() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin) = blocker();
    term_fault::set_force_terminate(term_fault::Forced::Unsupported);
    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect_err("the forced Unsupported error must surface immediately");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    // Fails fast: no grace was waited, no sweep ran, so the child is STILL ALIVE.
    assert_still_running(&mut child, stdin).await;
    cleanup(&mut child).await;
}
