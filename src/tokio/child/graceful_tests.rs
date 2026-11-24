//! The async `Child`'s own waits for `graceful_shutdown` and `graceful_shutdown_tree` (`impl Waits for
//! Child`). What either call answers is pinned once, through the sync driver, in `child/graceful_tests.rs`
//! and the tests beside it: each sequence is one function, so a row here pins what only awaiting changes.

use std::time::Duration;

use crate::test_child::over_fake::killed_root;
use crate::test_child::Console;
#[cfg(target_os = "linux")]
use crate::test_groups::{cgroup, Group};

use crate::child::graceful::fault as term_fault;
use crate::tokio::test_runtime::never_blocking;

/// An untaken piped stdin stays open through the grace, so the signal or the kill, not an EOF on
/// stdin, ends a child that reads it. The child ends on EOF with status 0 (Unix: it ignores `SIGTERM`
/// and only the kill ends it), so a grace that closed stdin shows as a clean exit. The reap closes
/// the stdin: `tree` is the call's `graceful_shutdown_tree`; both reap through `Waits::reap`. The
/// call's grace watch and reap are awaited, and block no runtime thread.
async fn keeps_an_untaken_stdin_open_through_the_grace(tree: bool) {
    let mut child = contained_child_ignoring_the_signal(contain_without_cgroup).await;
    let grace = Duration::from_secs(1);
    let status = if tree {
        never_blocking(child.graceful_shutdown_tree(grace)).await
    } else {
        never_blocking(child.graceful_shutdown(grace)).await
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

/// Contains `cmd` with no cgroup (a `Session` on Linux), so a row needs no delegated one.
fn contain_without_cgroup(cmd: &mut crate::tokio::Command) {
    #[cfg(unix)]
    crate::test_child::contain_without_cgroup_async(cmd);
    #[cfg(windows)]
    cmd.contain();
}

/// A child, contained as `contain` says, that outlives the grace: it ignores `SIGTERM` (Unix, ready once
/// the trap is set) or reads its untaken piped stdin to EOF (Windows).
async fn contained_child_ignoring_the_signal(contain: impl FnOnce(&mut crate::tokio::Command)) -> crate::tokio::Child {
    crate::tokio::test_runtime::assert_current_thread();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    #[cfg(unix)]
    {
        cmd.args(crate::test_child::TERM_IGNORING_BLOCKER_ARGV.iter().copied());
        cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    }
    #[cfg(windows)]
    {
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        // `executable` routes the spawn to the raw `CreateProcessW` backend, whose untaken piped stdin this covers.
        cmd.executable(crate::test_child::BLOCKER_ARGV[0]);
        cmd.stdout(crate::Stdio::null()).expect("null stdout");
    }
    contain(&mut cmd);
    // The child's console is its own, which the default would reach through the proxy and end by the
    // break: the subject of these rows is the grace and the stdin, so the stop sends nothing.
    #[cfg(windows)]
    cmd.graceful_stop(|_| Box::pin(async { Ok(()) }));
    cmd.stdin(crate::Stdio::pipe_in()).expect("set stdin pipe");
    #[cfg_attr(
        windows,
        allow(unused_mut, reason = "only the Unix readiness read takes `stdout` mutably")
    )]
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
    child
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

/// A tree call whose grace runs out awaits the grace watch and the sweep's wait, and blocks no runtime
/// thread. Its reap finds the root dead, so it never waits: [`async_the_reap_of_a_running_root_awaits_its_exit`]
/// pins that wait.
async fn awaits_the_grace_and_the_sweep(contain: impl FnOnce(&mut crate::tokio::Command)) {
    let mut child = contained_child_ignoring_the_signal(contain).await;
    let status = never_blocking(child.graceful_shutdown_tree(Duration::from_secs(1)))
        .await
        .expect("the shutdown");
    #[cfg(unix)]
    crate::test_child::assert_killed("the SIGTERM-ignoring child", status);
    #[cfg(windows)]
    assert!(
        !status.success(),
        "the child must not end by an EOF on its stdin: {status:?}"
    );
}

/// The grace watch is the root's alone on Linux (a session: no drain edge) and the job's drain on Windows.
///
/// Mutants: `Waits::root_exited` (Linux), or `tree_drained` or `sweep` (Windows), of the async `Child`
/// calls its blocking twin.
#[skuld::test]
async fn async_graceful_shutdown_tree_awaits_the_grace_and_the_sweep() {
    awaits_the_grace_and_the_sweep(contain_without_cgroup).await;
}

/// The grace watch is the cgroup's drain.
///
/// Mutants: `Waits::tree_drained` or `sweep` of the async `Child` calls its blocking twin.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_graceful_shutdown_tree_awaits_the_grace_and_the_sweep_in_a_cgroup(#[fixture(cgroup)] _group: &Group) {
    awaits_the_grace_and_the_sweep(|cmd| _ = cmd.contain()).await;
}

/// The async `Child`'s reap of a root still running awaits its exit: the sibling that ends the root finds
/// the call pending, and no runtime thread blocks on it.
///
/// Mutant: `Waits::reap` of the async `Child` calls the blocking `wait`.
#[skuld::test]
async fn async_the_reap_of_a_running_root_awaits_its_exit() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::child::graceful::shutdown::Waits as _;

    crate::tokio::test_runtime::assert_current_thread();
    // A held root: it runs until its stdin's write end is dropped.
    let (member, writer, _) = crate::test_child::over_fake::live_member();
    let mut child = crate::tokio::Child { inner: member };
    let stdin = Rc::new(Cell::new(Some(writer)));
    let blocked = Rc::new(Cell::new(false));
    // A wait that blocks the thread ends the root from inside the block, so the row fails instead of
    // hanging.
    let _blocking = crate::wait::block_probe::on_blocking({
        let (stdin, blocked) = (stdin.clone(), blocked.clone());
        move || {
            blocked.set(true);
            drop(stdin.take());
        }
    });

    let (reaped, ()) = ::tokio::join!(child.reap(None), async {
        ::tokio::task::yield_now().await;
        drop(stdin.take());
    });

    assert!(!blocked.get(), "the reap blocked a runtime thread");
    reaped.expect("reap");
}

/// The root-through-its-pidfd path (a root whose number may name another process) awaits the grace
/// through the root's handle and blocks no runtime thread. The call is made on the path itself, since
/// only a reused pid leads the public call there.
///
/// Mutant: `Waits::root_exited` of the async `Child` calls its blocking twin.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_the_root_through_its_pidfd_awaits_the_grace() {
    use std::os::unix::process::ExitStatusExt;

    use crate::child::graceful::SignalTreeCooperativelyOutcome;
    use crate::containment::fake::FakeContains;
    use crate::containment::{Containment, Mechanism, Refusal, Skip, TerminateOutcome, Tree, Why};

    crate::tokio::test_runtime::assert_current_thread();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    let mut child = cmd.spawn().await.expect("spawn");
    let skip = Skip {
        action: "signal its process group".to_owned(),
        why: Why::MayNameAnother(Refusal::Unpinned(child.pid()), None),
        root_alone: true,
        no_holder_reached: false,
        holders: None,
    };

    // The mechanism names no tree but the root's pidfd: the child's default stop, run as the call runs it,
    // sends the `SIGTERM` through the pidfd and records the outcome for the call.
    let (tree, _) = FakeContains::new(Containment::Session, false);
    child.inner.tree = Tree::contained(Mechanism::Fake(
        tree.answering_terminates([TerminateOutcome::RootThroughPidfd(skip)]),
    ));
    let SignalTreeCooperativelyOutcome::RootThroughPidfd(skip, started, _, acted) =
        crate::child::graceful::shutdown::signal_tree_cooperatively(&child, None).await
    else {
        panic!("the default stop did not end on the root's pidfd");
    };
    assert!(acted.is_none(), "the default action answered Ok: {acted:?}");
    let error = never_blocking(crate::child::graceful::shutdown::root_through_pidfd(
        &child,
        &skip,
        started,
        crate::signal::Sig::Graceful(crate::signal::Signal::Term),
        Duration::from_secs(30),
        None,
    ))
    .await;

    assert!(
        matches!(error, crate::error::Error::Unassessable { .. }),
        "the root alone was signalled, not the tree: {error}"
    );
    let status = child.wait().await.expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "the root ends by the SIGTERM the call sent through its pidfd: {status:?}"
    );
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
    assert!(rest.is_empty(), "the sweep missed a survivor: {rest:?}");
}

/// A `TreeWalk` tree on one stdin pipe over `argv`, which prints `r\n` once its descendants exist, and
/// the identities of the root's descendants. Linux only: on macOS a `TreeWalk` root is an fd marker.
#[cfg(target_os = "linux")]
async fn treewalk_tree(argv: &[&str]) -> (crate::tokio::Child, Vec<crate::identity::ProcessId>) {
    use ::tokio::io::AsyncReadExt as _;
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(argv.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mut child = cmd.spawn().await.expect("spawn");
    assert_eq!(child.containment(), crate::Containment::TreeWalk);
    let mut ready = [0u8; 2];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut ready)
        .await
        .expect("readiness line");
    assert_eq!(&ready, b"r\n");
    let members = child
        .id()
        .expect(crate::test_child::IDENTITY_READ)
        .children(crate::Recursive::Yes)
        .expect("the root's descendants");
    assert!(!members.is_empty(), "the subshell is a descendant of the root");
    (child, members)
}

/// Async twin of `graceful_shutdown_tree_kills_the_members_its_sigterm_walk_found_after_the_root_exits`
/// in `child/treewalk_exited_root_tests.rs`: the root ends on the `SIGTERM`, the sweep cannot walk to
/// the members that ignore it, and kills by identity those its own walk found.
///
/// Mutant: the async driver's sweep carries no call, so the settlement holds nothing the call may stand
/// on.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_treewalk_graceful_shutdown_tree_kills_the_members_its_sigterm_walk_found_after_the_root_exits() {
    use std::os::unix::process::ExitStatusExt;
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, members) = treewalk_tree(crate::test_child::TERM_SURVIVOR_TREE_ARGV).await;
    let _stdin = child.stdin().expect("piped stdin");

    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("every member its walk found is killed");

    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "the root ended on the SIGTERM: {status:?}"
    );
    for member in &members {
        assert_eq!(
            member.is_alive(),
            crate::identity::Liveness::Dead,
            "{member:?} ignored the SIGTERM and must be killed by identity"
        );
    }
}

/// Async twin of `graceful_shutdown_tree_kills_a_member_reparented_while_the_root_outlives_the_grace`: the
/// member is reparented before the sweep, which kills it by identity and the root by the sweep.
///
/// Mutant: the async driver's sweep kills only what the walk from the live root finds.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_treewalk_graceful_shutdown_tree_kills_a_member_reparented_while_the_root_outlives_the_grace() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, members) = treewalk_tree(crate::test_child::ROOT_OUTLIVING_THE_GRACE_ARGV).await;
    let _stdin = child.stdin().expect("piped stdin");
    let reparented = crate::test_child::wait_for_the_middle_to_exit_after_the_term(
        child.id().expect(crate::test_child::IDENTITY_READ),
    );

    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("every member the walk reached is killed");

    reparented.assert_fired();
    crate::test_child::assert_killed("the root", status);
    for member in &members {
        assert_eq!(
            member.is_alive(),
            crate::identity::Liveness::Dead,
            "{member:?} is killed or ended by the SIGTERM"
        );
    }
}

/// The tree's drain edge, awaited, answers that the tree drained: the sweep is skipped. See
/// `child::graceful_tests::drained_tree_sweep_decision` for the same decision through the sync driver.
/// The wait blocks no runtime thread.
///
/// Mutant (Windows; a cgroup that has drained by the first look blocks nothing, see
/// [`async_graceful_shutdown_tree_awaits_the_grace_and_the_sweep_in_a_cgroup`]): `Waits::tree_drained` of
/// the async `Child` calls its blocking twin.
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
    let result = never_blocking(child.graceful_shutdown_tree(Duration::from_secs(30))).await;
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

/// Linux: the awaited tree shutdown given a timeout watches the grace through the cgroup's drain edge, on tokio's
/// clock, and arms that wait at the timeout, not for the grace: on a paused runtime a grace of an hour under a
/// timeout of 30 s first arms the drain's wait for the instant 30 s after the call's start. The child ignores the
/// signal, so the call goes on to the sweep once that wait is over; only what the wait was armed for is asserted.
///
/// Mutant: `Waits::tree_drained` of the async `Child` arms from the grace alone (the wait is armed for the hour).
#[cfg(target_os = "linux")]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn a_timed_async_tree_shutdown_arms_its_cgroup_drain_wait_at_the_timeout_not_the_grace(
    #[fixture(cgroup)] _group: &Group,
) {
    use crate::tokio::wait::armed_deadline_seam::{install, Armed};
    use crate::tokio::wait::tokio_now;

    let timeout = Duration::from_secs(30);
    let mut child = contained_child_ignoring_the_signal(|cmd| _ = cmd.contain()).await;
    assert_eq!(child.containment(), crate::Containment::CgroupV2);
    let (tx, rx) = std::sync::mpsc::channel();
    let _installed = install(tx);
    let start = tokio_now();

    // The answer is the sweep's and the reap's, which this row does not pin.
    _ = child
        .graceful_shutdown_tree_timeout(Duration::from_secs(3600), timeout)
        .await;

    let armed: Vec<_> = rx.try_iter().collect();
    assert_eq!(armed.first(), Some(&Armed::At(start + timeout)), "{armed:?}");
}

/// Windows: the awaited tree shutdown given a timeout watches the grace through the Job's registered wait, and arms
/// that wait at the timeout, not for the grace: a grace of an hour under a timeout of 2 s first arms an awaited wait
/// for at most 2 s. The registered waits are on the real clock, so the runtime is the default one. The child ignores
/// the signal and the stop sends nothing, so the wait runs out at the call's own deadline; only what the first wait
/// was armed for is asserted, by the hook, as the wait is armed (a wait armed for no bound would not end).
///
/// Mutants: `job_wait_tree_drained` passes `None` to `wait_any` (the hook sees `None`), arms from the grace alone
/// (the hook sees about an hour), or `wait_any` reports no arming (the call ends and no awaited wait was seen).
#[cfg(windows)]
#[skuld::test]
async fn a_timed_async_tree_shutdown_arms_its_job_drain_wait_at_the_timeout_not_the_grace() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::wait::block_probe::{on_each_block, WaitObject};

    let timeout = Duration::from_secs(2);
    let mut child = contained_child_ignoring_the_signal(|cmd| _ = cmd.contain()).await;
    assert_eq!(child.containment(), crate::Containment::JobObject);
    let seen = Rc::new(Cell::new(false));
    let _blocks = on_each_block({
        let seen = seen.clone();
        move |block| {
            if matches!(block.on, WaitObject::Await) && !seen.replace(true) {
                assert!(
                    block.armed.is_some_and(|armed| armed <= timeout),
                    "the first awaited wait was armed for {:?}, not for at most {timeout:?}",
                    block.armed
                );
            }
        }
    });

    // The answer is the sweep's and the reap's, which this row does not pin.
    _ = child
        .graceful_shutdown_tree_timeout(Duration::from_secs(3600), timeout)
        .await;

    assert!(seen.get(), "the call armed no awaited wait");
}

// Async twin of `members_remain_still_reaps_an_already_exited_root`; see there for the fixture's
// rationale (`drive::exited_held`, like the sync wait, does not reap) and for `mode` and `swept`.
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
    crate::tokio::drive::exited_held(child.inner.proc.os_process(), None)
        .await
        .expect("the root must exit");
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
    assert!(
        child.inner.proc.exit_seen(),
        "an already-exited root's exit must be seen even when the sweep fails"
    );
    // The forced sweep failure was a stub, so the TERM-ignoring descendant is still alive, and the
    // call above saw the root's exit.
    swept(&mut child);
    // The descendant's stdin is released before the drain wait: it ends by itself when the sweep
    // sent nothing, and the wait cannot be left unbounded.
    drop(stdin);
    // Drain and remove the leaf here: the drop is not under test, and would leave a `cosca-*` leaf.
    if drainable {
        child.wait_tree().await.expect("the swept tree drains");
    }
}

/// A tree whose members remain after a drain verdict, awaited: the root has exited, so the call's one look
/// after a failed sweep sees it. The leaf is swept by its own handle. A pump that never broadcasts hangs this
/// test; `a_changed_batch_notifies_a_listener_that_was_there_before_it` fails it by assertion.
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

/// The root whose exit the shutdown saw is still a zombie that pins its group's number, so the group
/// is signalled by it, and the TERM-ignoring member dies. On macOS the tree is the fd marker: the drain
/// verdict is `AllMarkersClosed` or members remain, never proof to skip the sweep.
#[cfg(unix)]
#[skuld::test]
async fn async_graceful_tree_members_remain_still_reaps_an_already_exited_root_in_a_process_group() {
    members_remain_still_reaps_an_already_exited_root(crate::ContainMode::Session, |child| {
        assert_eq!(child.containment(), crate::test_child::session_gives());
        // Below Linux 6.9 a group is signalled by its number alone.
        #[cfg(target_os = "linux")]
        let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
        child
            .send_kill_tree()
            .expect("the root's zombie pins the group's number: the group is killed by it");
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
// real connection, not a poll loop, and the same shape already accepted for an async test.
//
// Mutants: `Waits::tree_drained` or `reap` of the async `Child` calls its blocking twin.
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
    let err = never_blocking(child.graceful_shutdown_tree(Duration::from_secs(2)))
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
    let (mut child, stdin) = crate::test_child::held_blocker_async(crate::Stdio::null(), Console::Asked, |cmd| {
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
// no group — permanent and pid-independent — so the direct send keeps answering `Unsupported`
// (what its own doc promises, and what the sync mirror returns for the identical child) after the
// reap, not `Unassessable`, which is documented as a transient could-not-determine condition a
// caller may retry. The child stops by the direct send: the default asks the proxy for it, which finds
// a reaped root gone.
#[cfg(windows)]
#[skuld::test]
async fn windows_async_lone_terminate_keeps_a_pid_independent_refusal_after_a_reap() {
    // Uncontained: leads no group of its own.
    let (mut child, stdin) = crate::test_child::held_blocker_async(crate::Stdio::null(), Console::Asked, |cmd| {
        cmd.graceful_stop(|target| Box::pin(crate::tokio::stop::send_ctrl_break_to_group(target)));
    })
    .await;
    assert!(
        !child.inner.console.group,
        "the subject must be a child whose refusal is permanent, not pid-dependent"
    );
    child.kill().expect("kill");
    // Released only after the kill, so a no-op kill fails `assert_killed`.
    drop(stdin);
    crate::test_child::assert_killed("the blocker", child.wait().await.expect("reap"));
    let err = child
        .terminate()
        .await
        .expect_err("a child that leads no group is refused");
    assert!(
        matches!(err.error(), crate::error::Error::Unsupported { .. }),
        "got {err:?}"
    );
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
            let error = crate::child::graceful::shutdown::holders_only(
                &child,
                skip,
                crate::signal::Sig::Graceful(crate::signal::Signal::Term),
                Duration::ZERO,
                None,
            )
            .await;
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

/// The awaited holders-only escalation whose deadline has passed names the holder its kill reached and that runs,
/// with the holders-only error below the timeout. A sibling ends the holder after one yield, so a wait that ignored
/// the deadline is still pending and then resolves without the timeout, which fails the assertion (no hang).
///
/// Mutants: `finish_async` takes no deadline; a wait that ran out is only logged.
#[cfg(unix)]
#[skuld::test]
async fn a_timed_holders_only_escalation_names_the_holder_still_running() {
    use crate::os_process::fake::Answer;
    use crate::stop::Deadline;
    use crate::test_child::over_fake::{holders_only_skip, live_member, root_looking, tokio_child_reaching};

    crate::tokio::test_runtime::assert_current_thread();
    let (member, writer, id) = live_member();
    let root = root_looking([Answer::Exited]);
    let child = tokio_child_reaching(&root, &[id]);
    let skip = holders_only_skip(&child.inner);

    let (error, ()) = ::tokio::join!(
        async {
            never_blocking(crate::child::graceful::shutdown::holders_only(
                &child,
                skip,
                crate::signal::Sig::Graceful(crate::signal::Signal::Term),
                Duration::ZERO,
                Deadline::tokio(Duration::ZERO),
            ))
            .await
        },
        async {
            ::tokio::task::yield_now().await;
            drop(writer);
        }
    );

    let crate::error::Error::TimedOut { members, .. } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(members, &[id]);
    assert!(
        error.failures_below().iter().any(|cause| matches!(cause,
            crate::error::Error::Unassessable { detail, .. }
                if detail.contains("sent the SIGTERM only to the marker holders"))),
        "the holders-only error is below the timeout: {error:?}"
    );
    _ = member.wait();
}

// A graceful shutdown given a timeout =====

/// The awaited lone shutdown whose timeout has passed when its grace would start kills the root and answers
/// `TimedOut` naming it, with no runtime thread blocked: the reap is awaited to the deadline, which is one look.
///
/// Mutants: the awaited reap has no deadline (it takes its second look and answers `Ok`); no kill once the deadline
/// has passed.
#[skuld::test]
async fn a_timed_async_lone_shutdown_past_its_timeout_kills_and_names_the_root() {
    use crate::os_process::fake::Answer;
    use crate::signal::Sig;
    use crate::test_child::over_fake::tokio_child_reaching;

    let root = killed_root([Answer::Running]);
    let mut child = tokio_child_reaching(&root, &[]);

    let error = never_blocking(child.graceful_shutdown_timeout(Duration::from_secs(3600), Duration::ZERO))
        .await
        .expect_err("the root was not seen to exit");

    let crate::error::Error::TimedOut { members, .. } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(members, &child.id().into_iter().collect::<Vec<_>>());
    assert_eq!(
        root.signal_calls().last(),
        Some(&Sig::Kill),
        "the root was killed whatever the deadline"
    );
}

/// With time left the same call waits for the root's exit and answers its status.
///
/// Mutant: a set deadline is treated as already passed.
#[skuld::test]
async fn a_timed_async_lone_shutdown_with_time_left_answers_the_roots_status() {
    use crate::os_process::fake::Answer;
    use crate::test_child::over_fake::tokio_child_reaching;

    let root = killed_root([Answer::Running]);
    let mut child = tokio_child_reaching(&root, &[]);

    let status = never_blocking(child.graceful_shutdown_timeout(Duration::ZERO, Duration::from_secs(3600)))
        .await
        .expect("the root exited");

    assert_eq!(status, std::process::ExitStatus::default());
}

/// The awaited tree shutdown whose timeout has passed when its grace would start still sweeps, awaits nothing past
/// the deadline and names the member the kill reached and the root, which a runtime thread never blocks on.
///
/// Mutants: the awaited sweep's wait ignores the deadline (it waits until the sibling ends the member, and the call
/// answers `Ok`); the root is not named.
#[skuld::test]
async fn a_timed_async_tree_shutdown_past_its_timeout_names_what_it_did_not_see_exit() {
    use crate::os_process::fake::{Answer, ReapAnswer};
    use crate::test_child::over_fake::{live_member, root_looking, tokio_child_reaching};

    crate::tokio::test_runtime::assert_current_thread();
    let (member, writer, id) = live_member();
    let root = root_looking([Answer::Running, Answer::Running]).reaps([ReapAnswer::Running]);
    let mut child = tokio_child_reaching(&root, &[id]);

    // A sibling ends the member after one yield: a sweep wait with no bound is then still pending and resolves `Ok`,
    // which the assertion on the error fails, with no hang.
    let ((error, alive), ()) = ::tokio::join!(
        async {
            let error = never_blocking(child.graceful_shutdown_tree_timeout(Duration::from_secs(3600), Duration::ZERO))
                .await
                .expect_err("a member and the root were not seen to exit");
            (error, id.is_alive())
        },
        async {
            ::tokio::task::yield_now().await;
            drop(writer);
        }
    );

    let crate::error::Error::TimedOut { members, .. } = &error else {
        panic!("{error:?}");
    };
    let mut named = vec![id];
    named.extend(child.id());
    assert_eq!(members, &named);
    assert_eq!(alive, crate::identity::Liveness::Alive, "the fake killed nothing");
    _ = member.wait();
}

/// An awaited call's deadline is on tokio's clock, and the action's `wait_exit` is timed on the real one, so a
/// paused runtime does not move the deadline while the wait runs out: the wait the deadline cut is still the call's
/// deadline running out, and the call goes on to the kill. The real clock is frozen, and the hook moves it on by
/// what the wait's block is armed for; tokio's clock is never advanced by the test. The action blocks, by design,
/// so the call is not wrapped in a helper that forbids a block.
///
/// Mutant: the deadline's passing is read off the deadline's own clock after the action (tokio's, which says it has
/// not passed), so no kill is sent.
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn a_timed_async_shutdown_goes_on_to_the_kill_when_the_deadline_cut_a_wait_on_the_real_clock() {
    use crate::os_process::fake::Answer;
    use crate::signal::Sig;
    use crate::stop::StopAction;
    use crate::test_child::over_fake::tokio_child_reaching;
    use crate::wait::block_probe::on_each_block;
    use crate::wait::test_clock::{advance, FrozenClockGuard};

    crate::tokio::test_runtime::assert_current_thread();
    let (_clock, _) = FrozenClockGuard::install();
    let _blocks = on_each_block(|block| {
        if let Some(armed) = block.armed {
            advance(armed);
        }
    });
    let root = killed_root([Answer::Running, Answer::Running, Answer::Running, Answer::Running]);
    let mut child = tokio_child_reaching(&root, &[]);
    child.inner.stop = StopAction::asynchronous(|target| {
        Box::pin(async move { target.wait_exit(Duration::from_secs(3600)).map(|_| ()) })
    });

    let status = child
        .graceful_shutdown_timeout(Duration::ZERO, Duration::from_secs(10))
        .await
        .expect("the deadline cut the action's wait, and the kill followed");

    assert_eq!(status, std::process::ExitStatus::default());
    assert_eq!(root.signal_calls().last(), Some(&Sig::Kill), "the root was killed");
}

/// With time left the awaited tree shutdown waits for the member, which a sibling task ends, and answers the root's
/// status.
///
/// Mutant: a set deadline is treated as already passed.
#[skuld::test]
async fn a_timed_async_tree_shutdown_with_time_left_waits_for_the_members() {
    use std::cell::Cell;

    use crate::os_process::child::ExitRecord;
    use crate::os_process::fake::{Answer, ReapAnswer};
    use crate::test_child::over_fake::{live_member, root_looking, tokio_child_reaching};

    crate::tokio::test_runtime::assert_current_thread();
    let (member, writer, id) = live_member();
    let root = root_looking([Answer::Running, Answer::Exited]).reaps([ReapAnswer::Exited(ExitRecord::Status(
        std::process::ExitStatus::default(),
    ))]);
    let mut child = tokio_child_reaching(&root, &[id]);
    let done = Cell::new(false);

    let (shut_down, ()) = ::tokio::join!(
        async {
            let shut_down =
                never_blocking(child.graceful_shutdown_tree_timeout(Duration::ZERO, Duration::from_secs(3600))).await;
            done.set(true);
            shut_down
        },
        async {
            ::tokio::task::yield_now().await;
            assert!(
                !done.get(),
                "the shutdown resolved while a member its sweep killed was running"
            );
            drop(writer);
        }
    );

    assert_eq!(
        shut_down.expect("the tree was shut down"),
        std::process::ExitStatus::default()
    );
    assert_eq!(id.is_alive(), crate::identity::Liveness::Dead);
    _ = member.wait();
}

/// Unix: the awaited shutdown reads its timeout on tokio's clock, and cuts the grace by it: on a paused runtime a
/// grace of an hour under a timeout of 10 s arms its wait for the instant 10 s after the call's start, and a grace
/// of 5 s under a timeout of an hour for 5 s after it.
///
/// Mutants: the grace is not cut (the wait is armed for the hour); the timeout replaces the grace.
#[cfg(unix)]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn a_timed_async_shutdown_arms_its_grace_wait_on_tokios_clock_at_the_nearer_bound() {
    use crate::os_process::fake::Answer;
    use crate::tokio::wait::armed_deadline_seam::{install, Armed};
    use crate::tokio::wait::tokio_now;

    let (tx, rx) = std::sync::mpsc::channel();
    let _installed = install(tx);
    for (grace, timeout, nearer) in [
        (
            Duration::from_secs(3600),
            Duration::from_secs(10),
            Duration::from_secs(10),
        ),
        (
            Duration::from_secs(5),
            Duration::from_secs(3600),
            Duration::from_secs(5),
        ),
    ] {
        let root = killed_root([Answer::Running, Answer::Exited]);
        let mut child = crate::test_child::over_fake::tokio_child_reaching(&root, &[]);
        let start = tokio_now();
        _ = rx.try_iter().count();

        child
            .graceful_shutdown_timeout(grace, timeout)
            .await
            .expect("the root exited within the grace");

        let armed: Vec<_> = rx.try_iter().collect();
        assert_eq!(
            armed.first(),
            Some(&Armed::At(start + nearer)),
            "grace {grace:?}, timeout {timeout:?}: {armed:?}"
        );
    }
}
