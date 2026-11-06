//! Unit tests for the async spawn error-path teardown, driven by the shared `fault` seam
//! (`crate::child::spawn::fault`). In the library (not `tests/`) because the seam is
//! `pub(crate)`/`#[cfg(test)]` and only reachable from within the crate.

use crate::child::spawn::failure::{expect_may_have_started_with, expect_not_started};
use crate::child::spawn::fault;
use crate::error::{ChildFate, Error};
use crate::test_child::Console;
#[cfg(target_os = "linux")]
use crate::test_groups::{cgroup, setuid, Group};
use crate::tokio::Command;

/// [`blocker`] for a kill-then-blocking-reap test; see [`fault::teardown_blocker_stdin`].
fn teardown_blocker() -> (Command, fault::TeardownBlocker) {
    let fault::TeardownBlockerParts {
        argv,
        stdin,
        stdout,
        guard,
    } = fault::teardown_blocker_parts();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(argv);
    cmd.stdin(stdin).expect("set stdin pipe");
    if let Some(stdout) = stdout {
        cmd.stdout(stdout).expect("set stdout");
    }
    (cmd, guard)
}

// A failed async spawn must fully reap its child, not leak it. Each error arm is forced via the seam
// (which records the child's real identity); `fault::assert_child_reaped` then proves it was reaped
// (reap_now uses WNOWAIT, leaving the zombie for tokio's field-drop to collect).

#[skuld::test]
async fn identity_failure_reaps_the_spawned_child() {
    fault::set_force_identity_vanished(true);
    let (mut cmd, teardown) = teardown_blocker();
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);

    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        err.expect("forced identity-vanish must make spawn return Err"),
    );
    assert_eq!(
        fate,
        crate::error::ChildFate::Reaped,
        "the teardown killed and reaped the child"
    );
    assert!(
        matches!(err, Error::Io(_)),
        "identity-vanish surfaces as an Io error, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    teardown.assert_killed();
}

/// macOS: the identity failure of a session root kills and reaps the root through its unique id and
/// sends its process group nothing, as macOS has no exact kill of a group. The teardown's one warn
/// says the group's members may be left running.
///
/// Mutant: the group's note is dropped.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_identity_failure_of_a_group_root_warns_that_its_members_may_be_left_running() {
    crate::log_capture::install();
    fault::set_force_identity_vanished(true);
    let (mut cmd, teardown) = teardown_blocker();
    cmd.contain_with(crate::ContainMode::Session);
    let mark = crate::log_capture::mark();
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);
    let _ = expect_may_have_started_with(err.expect("forced identity-vanish must make spawn return Err"));
    let Some(crate::identity::Resolved::Found(id)) = fault::take_captured() else {
        panic!("the seam must have captured the child's identity");
    };
    teardown.assert_killed();
    let note = format!("members of the process group of pid {} may be left running", id.pid());
    let warns = crate::log_capture::warns_since(mark, &note);
    assert_eq!(
        warns.len(),
        1,
        "one warn says the group's members may be left running: {warns:?}"
    );
}

// macOS: the attach cannot fail; see `macos_tokio_a_failed_attach_kills_and_reaps_a_child_that_is_not_a_front`.
#[cfg(not(target_os = "macos"))]
#[skuld::test]
async fn attach_failure_reaps_the_spawned_child() {
    fault::set_force_attach_failure(true);
    let (mut cmd, teardown) = teardown_blocker();
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);

    let (err, fate) = expect_may_have_started_with(err.expect("forced attach failure must make spawn return Err"));
    assert_eq!(fate, ChildFate::Reaped, "the teardown killed and reaped the child");
    assert!(
        matches!(err, Error::Containment { .. }),
        "a real attach failure surfaces as Error::Containment, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    teardown.assert_killed();
}

/// The async mirror of `child::spawn::exact_posix_tests`: tokio builds its command through the
/// same `build_std_command`, so a bare `raw_executable()` must load the child-cwd file here too.
#[cfg(unix)]
#[skuld::test]
async fn a_bare_exact_name_loads_the_file_in_the_childs_cwd_not_one_on_path() {
    use crate::test_child::{cwd_and_path_tools, CWD_TOOL_EXIT};
    let (cwd, on_path) = cwd_and_path_tools();
    let mut c = crate::test_child::tokio_command(Console::Hidden);
    c.raw_executable("tool")
        .args(["tool"])
        .current_dir(cwd.path())
        .env("PATH", on_path.path());
    let status = c.spawn().expect("spawn").wait().await.expect("wait");
    assert_eq!(status.code(), Some(CWD_TOOL_EXIT));
}

/// tokio can fail a spawn after its fork succeeded (`build_child`: stdio registration, its pidfd
/// reaper, its signal driver), dropping the child neither killed nor reaped. The spawn's handshake
/// pidfd then kills and reaps it, so no live child is left in the spawn's cgroup leaf, and the
/// answer says it was reaped.
///
/// Mutant: the handshake leaves the dropped child, or answers another fate.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn cgroup_a_post_fork_tokio_failure_leaves_no_live_child_in_a_leaked_leaf(#[fixture(cgroup)] _group: &Group) {
    let (mut cmd, teardown) = teardown_blocker();
    cmd.contain();
    let (_err, fate) = {
        let _failing = fault::fail_tokio_spawns_after_fork();
        expect_may_have_started_with(cmd.spawn().expect_err("the forced failure must fail the spawn"))
    };
    assert_eq!(fate, ChildFate::Reaped, "killed and reaped through its pidfd");
    teardown.assert_killed();
    let pid = fault::take_forgotten_pid().expect("the seam dropped a child");
    let leaf = fault::take_forgotten_leaf().expect("the dropped spawn was contained in a leaf");

    let pidfd = fault::take_forgotten_pidfd().expect("the seam took a pidfd for the child");
    assert!(reaped_through(&pidfd), "the child {pid} must be reaped");
    // An empty leaf `Drop` could not remove right after its kill is a known exit-lag gap, not this:
    // no leaf of this spawn may still hold a live process.
    if leaf.exists() {
        let events = std::fs::read_to_string(leaf.join("cgroup.events")).expect("read cgroup.events");
        assert!(
            events.lines().any(|line| line == "populated 0"),
            "{} still holds a process",
            leaf.display()
        );
        std::fs::remove_dir(&leaf).expect("remove the drained leaf");
    }
}

/// A failed kill in the async spawn's error teardown is not waited on, and EPERM — a setuid
/// child refusing SIGKILL — is not asserted, because it is reachable without a bug; any other
/// kind is. The child is left alive, blocked on stdin, and exits when the failed spawn drops the
/// pipe's parent end. macOS: tokio's own `Child` drop hands it to the runtime's orphan reaper,
/// which the test drives until the child is reaped. Linux: tokio's `Child` is forgotten and the
/// child is torn down again through its pidfd (the seam refuses only the first kill), so it is reaped through
/// its pidfd and never released to tokio's by-pid reap.
#[skuld::test]
fn a_failed_teardown_kill_in_the_async_spawn_asserts_all_but_eperm() {
    use crate::stdio::Stdio;
    use std::io::ErrorKind;
    for (kind, asserted) in [(ErrorKind::PermissionDenied, false), (ErrorKind::Other, true)] {
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let releases = crate::tokio::child::fault::count_backend_drops();
        // Linux: the pidfd teardown kills and reaps the child, so its stdin is released once that
        // kill returned (a kill that sent nothing then fails the SIGKILL assertion below). Elsewhere
        // tokio's orphan queue reaps it once the failed spawn drops the pipe's parent end.
        #[cfg(target_os = "linux")]
        let (stdin, reaps) = fault::teardown_blocker_stdin();
        #[cfg(not(target_os = "linux"))]
        let (stdin, reaps) = (Stdio::pipe_in(), fault::record_teardown_reaps());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async {
                let mut cmd = crate::test_child::tokio_command(Console::Hidden);
                cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
                cmd.stdin(stdin).unwrap().stdout(Stdio::null()).unwrap();
                // The attach, except on macOS, where it cannot fail: the identity check's failure
                // reaches the same teardown.
                let force: fn(bool) = if cfg!(target_os = "macos") {
                    fault::set_force_identity_vanished
                } else {
                    fault::set_force_attach_failure
                };
                force(true);
                fault::set_force_kill_failure_leaving_child_alive_as("cosca-async-kill-fail-5d2c", kind);
                let err = cmd.spawn().err();
                force(false);
                err
            })
        }));
        assert_eq!(
            fault::take_force_kill_failure(),
            None,
            "{kind:?}: the kill failure must be consumed"
        );
        assert_eq!(
            outcome.is_err(),
            asserted && cfg!(debug_assertions),
            "{kind:?}: the debug_assert fires in exactly the builds that keep it, and never for EPERM"
        );
        if let Ok(err) = outcome {
            err.expect("the forced arm must fail the spawn");
        }
        // Asserted before the driver below. macOS: the driver only ends when tokio's orphan queue
        // reaps the child, so a refused kill must have handed it to tokio. Linux: it must not have.
        assert_eq!(
            releases.get(),
            usize::from(!cfg!(target_os = "linux")),
            "{kind:?}: the refused-kill arm releases the child to tokio exactly when there is no pidfd"
        );
        // Linux: the pidfd teardown has reaped the child by now. Asserted before the driver, which
        // would spin on a missing hand-off.
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                reaps.recorded().len(),
                1,
                "{kind:?}: the refused-kill arm must have reaped the child through its pidfd"
            );
            reaps.assert_killed();
        }
        drop(reaps);
        let captured = fault::take_captured().expect("seam captured the child's identity");
        drive_until_reaped(&runtime, &captured);
        fault::assert_child_reaped(captured);
    }
}

/// A failed async spawn whose child refuses the kill, through its handle and again through its pidfd
/// (a setuid-root helper refuses every kill of this process), leaves it running and says so in the one
/// warn, which names the kill that was refused. Nothing reaps it behind the caller's back: the child
/// is still this process's unreaped child until the test reaps it.
///
/// The helper is fully root once it has written its ready byte, which is read before the identity
/// check.
///
/// Mutants: a refused kill reports the child reaped; the second teardown starts a thread that reaps
/// it; the warn says it was torn down.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_child_whose_teardown_kill_is_refused_twice_stays_running_and_unreaped(#[fixture(setuid)] _group: &Group) {
    use crate::child::front_kill_tests::reap;

    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut cmd, writer, _root) = setuid_blocker_ready_before_identity();
    fault::set_force_attach_failure(true);
    let mark = crate::log_capture::mark();

    let err = cmd.spawn().err();

    fault::set_force_attach_failure(false);
    let Some(crate::identity::Resolved::Found(id)) = fault::take_captured() else {
        panic!("the seam captured the child's identity");
    };
    let (_, fate) = expect_may_have_started_with(err.expect("the forced attach failure fails the spawn"));
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    let warns = crate::log_capture::warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("could not be terminated"), "{warns:?}");
    assert!(warns[0].contains("leaving it running"), "{warns:?}");
    assert!(!warns[0].contains("torn down"), "{warns:?}");
    // The helper exits once its stdin closes; the test reaps it.
    drop(writer);
    let status = reap(id.pid()).expect("the child is still unreaped");
    assert!(status.success(), "{status:?}");
}

/// A setuid-root helper that blocks on its stdin, ready to be spawned, the write end of its stdin,
/// and the hook that waits for the helper's ready byte before the identity check (it is fully root
/// once it has written it), armed for the spawn's `BeforeIdentity` point.
#[cfg(target_os = "linux")]
fn setuid_blocker_ready_before_identity() -> (Command, std::io::PipeWriter, crate::oneshot_hook::Armed) {
    use crate::child::spawn::fault::SpawnPoint;

    let (cmd, writer, until_root) = setuid_blocker_with_ready();
    (cmd, writer, fault::set_at(SpawnPoint::BeforeIdentity, until_root))
}

/// A setuid-root helper that blocks on its stdin, ready to be spawned, the write end of its stdin,
/// and the function that waits for the helper's ready byte (it is fully root once it has written
/// it), for the caller to run where a refused kill is to be refused.
#[cfg(target_os = "linux")]
fn setuid_blocker_with_ready() -> (Command, std::io::PipeWriter, impl FnOnce() + 'static) {
    use std::io::Read as _;

    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let (mut ready, ready_end) = std::io::pipe().expect("pipe");
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.executable(crate::test_privilege::setuid::setuid_helper()).args([
        "cosca_testbin",
        "setuid-stdin-block",
        "root",
    ]);
    cmd.stdin(stdin).expect("set stdin");
    cmd.stdout(crate::Stdio::from_file(std::fs::File::from(
        std::os::fd::OwnedFd::from(ready_end),
    )))
    .expect("set stdout");
    cmd.stderr(crate::Stdio::null()).expect("null stderr");
    let until_root = move || {
        let mut byte = [0u8; 1];
        ready.read_exact(&mut byte).expect("the helper reports ready");
        assert_eq!(byte, *b"+");
    };
    (cmd, writer, until_root)
}

/// A failed async spawn whose identity check cannot answer, of a child that refuses every kill (a
/// setuid-root helper), is torn down through its pidfd, which refuses too: the child is left
/// running, and the fate says so, not `Reaped`. One warn says it all, under the failed spawn's name:
/// the forget, and that the teardown could not terminate it and left it running. The test, not a
/// thread, reaps it.
///
/// CI only (the `setuid` group).
///
/// Mutants: the identity-unknown arm answers `Reaped`, or sends the child no kill through its pidfd
/// and leaves it unreaped; the refused teardown's warn leaves out the clause, or is a second warn.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn an_identity_unknown_child_whose_kill_is_refused_stays_running_and_is_said_so(
    #[fixture(setuid)] _group: &Group,
) {
    use crate::child::front_kill_tests::reap;

    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut cmd, writer, _root) = setuid_blocker_ready_before_identity();
    fault::set_force_identity_unknown(true);
    let mark = crate::log_capture::mark();

    let err = cmd.spawn().err();

    fault::set_force_identity_unknown(false);
    let Some(crate::identity::Resolved::Found(id)) = fault::take_captured() else {
        panic!("the seam captured the child's pid");
    };
    let (_, fate) = expect_may_have_started_with(err.expect("the forced unknown identity fails the spawn"));
    assert_eq!(fate, ChildFate::Running { id: None });
    let warns = crate::log_capture::warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
    let warn = &warns[0];
    assert!(warn.starts_with("teardown after a failed spawn: "), "{warns:?}");
    assert!(warn.contains("cannot be shown to be ours"), "{warns:?}");
    assert!(warn.contains("could not be terminated"), "{warns:?}");
    assert!(warn.contains("leaving it running"), "{warns:?}");
    assert!(!warn.contains("reaped it"), "{warns:?}");
    drop(writer);
    let status = reap(id.pid()).expect("the child is still unreaped");
    assert!(status.success(), "{status:?}");
}

/// Turn `runtime`'s driver, whose every turn reaps tokio's exited orphans, until the child
/// `captured` names is reaped (Windows: has exited). Ends on the child's own exit, and never
/// before: no interval, no bound.
fn drive_until_reaped(
    runtime: &::tokio::runtime::Runtime,
    captured: &crate::identity::Resolved<crate::identity::ProcessId>,
) {
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    #[cfg(unix)]
    let pending = || id.exists() == crate::identity::Existence::Present;
    #[cfg(windows)]
    let pending = || id.is_alive() != crate::identity::Liveness::Dead;
    while pending() {
        runtime.block_on(::tokio::task::yield_now());
    }
}

/// A tokio spawn that fails after its fork, with no cgroup leaf, is torn down by the handshake's
/// pidfd, and says so: the child was reaped, at `debug`. Here the failure comes under a tree walk,
/// which holds no leaf.
///
/// Mutant: the abandonment warns that the child "was left running and nothing can reach it" or
/// "may be left unreaped", or says nothing.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_post_fork_tokio_failure_without_a_leaf_says_the_handshake_reaped_the_child() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut cmd, teardown) = teardown_blocker();
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mark = crate::log_capture::mark();
    let (_err, fate) = {
        let _failing = fault::fail_tokio_spawns_after_fork();
        expect_may_have_started_with(cmd.spawn().expect_err("the forced failure must fail the spawn"))
    };
    assert_eq!(fate, ChildFate::Reaped, "killed and reaped through its pidfd");
    teardown.assert_killed();
    let pid = fault::take_forgotten_pid().expect("the seam dropped a child");
    let said = crate::log_capture::records_since_on_current_thread(mark, "tokio spawn failed");
    assert_eq!(
        said.iter().map(|(level, _)| *level).collect::<Vec<_>>(),
        [log::Level::Debug],
        "{said:?}"
    );
    assert!(said[0].1.contains("its child was reaped"), "{said:?}");
    assert!(
        !said[0].1.contains("left running") && !said[0].1.contains("unreaped"),
        "{said:?}"
    );
    let pidfd = fault::take_forgotten_pidfd().expect("the seam took a pidfd for the child");
    assert!(reaped_through(&pidfd), "the child {pid} must be reaped");
}

/// The abandoned-child warning is at `warn` on every call, including a repeat, through the real
/// entry point.
#[skuld::test]
fn the_unreachable_child_warning_is_every_time() {
    use crate::containment::AbandonedChild;

    crate::log_capture::install();
    let error = || Error::Io(std::io::Error::other("cosca-abandoned-warn-probe-6f21"));
    let marker = "cosca-abandoned-warn-probe-6f21";

    for child in [AbandonedChild::MaybeUnreachable, AbandonedChild::MaybeUnreaped] {
        let mark = crate::log_capture::mark();
        super::warn_for_abandoned(&child, &error(), None);
        super::warn_for_abandoned(&child, &error(), None);

        assert_eq!(
            crate::log_capture::levels_since(mark, marker),
            [log::Level::Warn, log::Level::Warn]
        );
    }
}

/// With no word from the handshake, each abandonment answer hedges what it cannot know: the child
/// "may be" left running or unreaped, never "was".
///
/// Mutant: a message states as fact what the abandonment cannot know.
#[skuld::test]
fn an_abandonment_nothing_answered_for_hedges() {
    use crate::containment::AbandonedChild;

    crate::log_capture::install();
    let marker = "cosca-abandoned-hedge-probe-5d02";
    let error = Error::Io(std::io::Error::other(marker));
    for (child, says) in [
        (
            AbandonedChild::MaybeUnreachable,
            "may be left running and nothing can reach it",
        ),
        (
            AbandonedChild::MaybeUnreaped,
            "may be left unreaped, since it never reached",
        ),
    ] {
        let mark = crate::log_capture::mark();
        super::warn_for_abandoned(&child, &error, None);
        let said = crate::log_capture::records_since_on_current_thread(mark, marker);
        assert_eq!(said.len(), 1, "{child:?}: {said:?}");
        assert_eq!(said[0].0, log::Level::Warn, "{child:?}");
        assert!(said[0].1.contains(says), "{child:?}: {said:?}");
        assert!(!said[0].1.contains("  "), "{child:?}: {said:?}");
    }
}

/// A cgroup-leaf spawn that tokio failed for a child never told to go, which no leaf could say more
/// of (`MaybeUnreachable`), says what is known: the child never ran the program, and it may be left
/// unreaped. It does not hedge that the child "may be left running". A failure that does not hold
/// that fact keeps the hedge.
///
/// Mutant: the arm hedges "may be left running and nothing can reach it" for a child never told to
/// go, or every failure gets the never-ran wording.
#[cfg(target_os = "linux")]
#[skuld::test]
fn an_unreachable_child_never_told_to_go_is_said_to_have_never_run() {
    use crate::child::spawn::failure::SpawnFailure;
    use crate::containment::AbandonedChild;

    crate::log_capture::install();
    let marker = "cosca-abandoned-never-told-probe-2c7e";
    let abandon = |failure: SpawnFailure| {
        let mark = crate::log_capture::mark();
        let _ = super::abandoned_after_handshake(AbandonedChild::MaybeUnreachable, failure, None, false);
        crate::log_capture::records_since_on_current_thread(mark, marker)
    };
    let error = || Error::Io(std::io::Error::other(marker));

    let said = abandon(SpawnFailure::NotStartedUnreaped(error()));
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(said[0].0, log::Level::Warn, "{said:?}");
    let text = &said[0].1;
    assert!(text.contains("the child never ran the program"), "{said:?}");
    assert!(text.contains("may be left unreaped"), "{said:?}");
    assert!(
        !text.contains("left running") && !text.contains("nothing can reach it"),
        "{said:?}"
    );
    assert!(!text.contains("  "), "{said:?}");

    let said = abandon(SpawnFailure::NotStarted(error()));
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].1.contains("may be left running and nothing can reach it"),
        "{said:?}"
    );
}

/// A child which the handshake's pidfd reached and its teardown left uncollected (`Uncollected`) is
/// worded as that: the teardown's clause under the failed spawn's label, one warn, whatever the
/// failure was. It answers the fate its teardown established.
///
/// Mutant: `Uncollected` is worded as a child out of the leaf's reach; it answers `Running`
/// whatever its teardown found.
#[cfg(target_os = "linux")]
#[skuld::test]
fn an_uncollected_child_is_said_left_by_its_teardown() {
    use crate::child::owned::teardown::{Expect, HandleTeardown, Past, TeardownOutcome};
    use crate::child::spawn::failure::SpawnFailure;
    use crate::containment::AbandonedChild;
    use crate::os_process::child::KillRefusal;

    crate::log_capture::install();
    let marker = "cosca-abandoned-uncollected-probe-4e19";
    let clause = "child could not be terminated (Operation not permitted); leaving it running";
    let error = || Error::Io(std::io::Error::other(marker));
    let uncollected = |fate| {
        let expect = Expect {
            refusal: KillRefusal::Permission,
            past: Past::WaitMayFail,
        };
        let torn = HandleTeardown::new(TeardownOutcome::left_uncollected(fate, clause.into()), expect);
        AbandonedChild::Uncollected(torn.uncollected().expect("an uncollected teardown is left"))
    };
    let abandon = |failure: SpawnFailure| {
        let mark = crate::log_capture::mark();
        let _ = super::abandoned_after_handshake(uncollected(ChildFate::Unknown), failure, None, false);
        crate::log_capture::records_since_on_current_thread(mark, marker)
    };

    // The fate the teardown established, not a constant.
    for fate in [ChildFate::Killed, ChildFate::Unknown, ChildFate::Running { id: None }] {
        let failure = SpawnFailure::started(error(), ChildFate::Unknown, None);
        let answered = super::abandoned_after_handshake(uncollected(fate), failure, None, true);
        assert_eq!(answered.expect_may_have_started_with().1, fate);
    }

    for failure in [
        SpawnFailure::NotStartedUnreaped(error()),
        SpawnFailure::NotStarted(error()),
    ] {
        let said = abandon(failure);
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(said[0].0, log::Level::Warn, "{said:?}");
        assert!(
            said[0].1.contains(&format!("teardown after a failed spawn: {clause}")),
            "{said:?}"
        );
        assert!(
            !said[0].1.contains("cgroup v2 leaf") && !said[0].1.contains("nothing can reach it"),
            "{said:?}"
        );
    }
}

/// When the handshake already killed and reaped the child, the abandonment does not say it is left
/// running or unreaped: it states the handshake's answer at `debug`.
///
/// Mutant: the abandonment's text ignores what the handshake did.
#[skuld::test]
fn an_abandonment_after_a_handshake_that_ended_the_child_says_so() {
    use crate::containment::AbandonedChild;

    crate::log_capture::install();
    let marker = "cosca-abandoned-ended-probe-8b41";
    let error = Error::Io(std::io::Error::other(marker));
    for fate in [ChildFate::Reaped, ChildFate::Killed, ChildFate::Gone] {
        for child in [AbandonedChild::MaybeUnreachable, AbandonedChild::MaybeUnreaped] {
            let mark = crate::log_capture::mark();
            super::warn_for_abandoned(&child, &error, Some(fate));
            let said = crate::log_capture::records_since_on_current_thread(mark, marker);
            assert_eq!(said.len(), 1, "{child:?} after {fate:?}: {said:?}");
            assert_eq!(said[0].0, log::Level::Debug, "{child:?} after {fate:?}");
            assert!(
                said[0].1.contains(&fate.to_string()),
                "{child:?} after {fate:?}: {said:?}"
            );
        }
    }
}

/// `AbandonedChild::Ended` means nothing of the child runs and it is reaped or will be — not a
/// degraded guarantee, so it logs nothing at all.
#[skuld::test]
fn ended_abandoned_child_logs_nothing() {
    use crate::containment::AbandonedChild;

    crate::log_capture::install();
    let error = Error::Io(std::io::Error::other("cosca-abandoned-ended-probe-3a17"));
    let marker = "cosca-abandoned-ended-probe-3a17";

    let mark = crate::log_capture::mark();
    super::warn_for_abandoned(&AbandonedChild::Ended(ChildFate::Reaped), &error, None);

    assert_eq!(crate::log_capture::levels_since(mark, marker), Vec::<log::Level>::new());
}

/// Whether the child `pidfd` names has been reaped — which a pidfd, unlike a pid, can answer after
/// the reap.
#[cfg(target_os = "linux")]
fn reaped_through(pidfd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsFd;

    use rustix::process::{waitid, WaitId, WaitIdOptions};

    matches!(
        waitid(
            WaitId::PidFd(pidfd.as_fd()),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ),
        Err(rustix::io::Errno::CHILD)
    )
}

/// A post-fork tokio failure ends its child whether or not it entered its leaf: cosca kills and
/// reaps it through the pidfd the handshake left the leaf, and warns about nothing. Its stdin is
/// held, so a kill that sent nothing hangs the wait.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn cgroup_a_post_fork_tokio_failure_ends_its_child_in_or_out_of_its_leaf(#[fixture(cgroup)] _group: &Group) {
    use std::os::unix::process::ExitStatusExt as _;

    crate::tokio::test_runtime::assert_current_thread();
    use crate::containment::cgroup::fault as cgroup_fault;
    crate::log_capture::install();
    for placed in [true, false] {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = crate::test_child::tokio_command(Console::Hidden);
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin pipe");
        cmd.contain();
        let mark = crate::log_capture::mark();
        // Armed in this thread, inherited by the child it forks, which takes it.
        if !placed {
            cgroup_fault::set_force_placement_write_result(0);
        }
        let reaps = fault::record_teardown_reaps();
        let failing = fault::fail_tokio_spawns_after_fork();
        assert!(cmd.spawn().is_err(), "the forced failure must fail the spawn");
        drop(failing);
        // This thread's own copy of the child's seam was never taken.
        let _ = cgroup_fault::take_force_placement_write_result();
        let pid = fault::take_forgotten_pid().expect("the seam dropped a child");
        let pidfd = fault::take_forgotten_pidfd().expect("the seam took a pidfd for the child");
        let _ = fault::take_forgotten_leaf();

        let case = format!("placed: {placed}");
        assert_eq!(
            crate::log_capture::warns_since(mark, ""),
            Vec::<String>::new(),
            "{case}: nothing is warned about"
        );
        assert_eq!(
            reaps
                .recorded()
                .into_iter()
                .map(|(_, status)| status.signal())
                .collect::<Vec<_>>(),
            [Some(libc::SIGKILL)],
            "{case}: the child must be killed through its pidfd (pid {pid})"
        );
        assert!(reaped_through(&pidfd), "{case}: the child must be reaped");
        drop(writer);
    }
}

/// A post-fork tokio failure of a child that refuses every kill of this process (a setuid-root
/// helper) and is outside its leaf — its placement write fails — leaves it running, and says so:
/// one warn, for the child, which the teardown could not terminate and left running, and for its
/// group, which refused too. Nothing reaps it behind the caller's back: the test does.
///
/// CI only (the `cgroup` and `setuid` groups).
///
/// Mutants: a refused kill reports the child reaped; the child's refusal is not warned of; the
/// group's refusal is warned of beside the child's.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn cgroup_a_post_fork_tokio_failure_of_a_child_that_refuses_its_kill_leaves_it_running(
    #[fixture(cgroup)] _group: &Group,
    #[fixture(setuid)] _setuid: &Group,
) {
    use crate::child::front_kill_tests::reap;
    use crate::containment::cgroup::fault as cgroup_fault;

    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut cmd, writer, until_root) = setuid_blocker_with_ready();
    cmd.contain();
    cgroup_fault::set_force_placement_write_result(0);
    let mark = crate::log_capture::mark();
    // The kill is refused only once the helper is root, which it says by its ready byte.
    let failing = fault::fail_tokio_spawns_after_fork_then(move |_| until_root());
    let err = cmd.spawn().err();
    drop(failing);
    let _ = cgroup_fault::take_force_placement_write_result();
    let pid = fault::take_forgotten_pid().expect("the seam dropped a child");
    let _ = fault::take_forgotten_pidfd();
    let _ = fault::take_forgotten_leaf();
    let (_, fate) = expect_may_have_started_with(err.expect("the forced failure fails the spawn"));

    assert_eq!(fate, ChildFate::Running { id: None });
    let warns = crate::log_capture::warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains(&format!("process group {pid}"))
            && warns[0].contains("could not be terminated")
            && warns[0].contains("leaving it running"),
        "the refused group kill and the refused kill of the child are one warn: {warns:?}"
    );
    // The helper exits once its stdin closes; the test reaps it.
    drop(writer);
    let status = reap(pid).expect("the child is still unreaped");
    assert!(status.success(), "{status:?}");
}

/// On the identity-failure path tokio still owns the child, and reaps it: the leaf takes its
/// verdict first, so it has no child to reap as an abandoned spawn's — which would race tokio's
/// own reap for the same pid.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn cgroup_an_identity_failure_leaves_the_child_to_tokio(#[fixture(cgroup)] _group: &Group) {
    fault::set_force_identity_vanished(true);
    let (mut cmd, teardown) = teardown_blocker();
    cmd.contain();
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);

    err.expect("forced identity-vanish must make spawn return Err");
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    teardown.assert_killed();
}

/// As the sync twin: a spawn whose identity check fails ends the leaf's placement exchange before
/// it kills the child.
///
/// Mutant: the identity-failure arm settles the verdict after the kill, or not at all.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn cgroup_tokio_identity_failure_settles_the_leaf_verdict_before_the_kill(#[fixture(cgroup)] _group: &Group) {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::send_log::Capture;
    use crate::signal::Sig;

    let (mut cmd, teardown) = teardown_blocker();
    cmd.contain();
    let capture = Rc::new(Capture::start());
    let sends_at_settle = Rc::new(Cell::new(None));
    let _hook = crate::containment::cgroup::fault::set_on_take_placement({
        let (capture, sends_at_settle) = (Rc::clone(&capture), Rc::clone(&sends_at_settle));
        move || sends_at_settle.set(Some(capture.entries().len()))
    });
    fault::set_force_identity_vanished(true);
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);
    err.expect("a vanished identity must fail the spawn");

    let Some(crate::identity::Resolved::Found(child)) = fault::take_captured() else {
        panic!("the seam must capture the child's identity");
    };
    assert_eq!(
        sends_at_settle.get(),
        Some(0),
        "the verdict must be settled, and before anything is sent to the child"
    );
    assert!(
        capture
            .entries()
            .iter()
            .any(|&(pid, sig, _)| pid == child.pid() && sig == Sig::Kill),
        "the child must be killed after the verdict: {:?}",
        capture.entries()
    );
    teardown.assert_killed();
}

/// On the identity-failure path, a child tokio could not kill (`EPERM`) goes to tokio's orphan
/// queue, which reaps it once it exits. The leaf, having taken its verdict first, answers only for
/// the tree — its kill through the leaf — and has no child to reap as an abandoned spawn's, which
/// would race tokio's reap for the same pid.
///
/// The leaf may still be left behind: its `Drop` does wait for the kill to drain before its
/// retried `rmdir` (see `CgroupLeaf`'s `Drop`), so this is not that exit-lag gap — a leftover here
/// would mean the retried `rmdir` itself still failed once the leaf drained.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn cgroup_an_identity_failure_whose_kill_is_refused_leaves_the_child_to_tokio(#[fixture(cgroup)] _group: &Group) {
    fault::set_force_identity_vanished(true);
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-identity-eperm-4c19",
        std::io::ErrorKind::PermissionDenied,
    );
    // The leaf's kill ends the child, not a landed root kill; the writer is released with the guard.
    let (mut cmd, _teardown) = teardown_blocker();
    cmd.contain();
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);
    err.expect("forced identity-vanish must make spawn return Err");
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    let _ = fault::take_captured();
}

// kill_on_drop(false) commits only with the spawn -----
// Async twins of the sync `spawn_tests` of the same name.

/// The sync command `spawn_uncommitted` takes: a [`blocker`] on `stdin` with `kill_on_drop(false)`.
#[cfg(target_os = "linux")]
fn opted_out_blocker(stdin: crate::stdio::Stdio) -> crate::command::Command {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin pipe");
    cmd.kill_on_drop(false);
    cmd
}

/// [`teardown_blocker`] with `kill_on_drop(false)`, as a sync command for `spawn_uncommitted`.
#[cfg(target_os = "linux")]
fn opted_out_teardown_blocker() -> (crate::command::Command, fault::TeardownBlocker) {
    let fault::TeardownBlockerParts {
        argv,
        stdin,
        stdout: _,
        guard,
    } = fault::teardown_blocker_parts();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(argv);
    cmd.stdin(stdin).expect("set stdin pipe");
    cmd.kill_on_drop(false);
    (cmd, guard)
}

/// An occupied temp leaf whose child entered it, attached to the next spawn on this thread.
#[cfg(target_os = "linux")]
fn attach_entered_leaf(leaf_path: &std::path::Path) {
    std::fs::create_dir(leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.to_path_buf(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
}

#[cfg(target_os = "linux")]
#[skuld::test]
async fn kill_on_drop_false_disarms_the_leaf_only_when_the_spawn_commits() {
    for commit in [false, true] {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf_path = dir.path().join("cosca-async-commit-leaf");
        attach_entered_leaf(&leaf_path);
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = opted_out_blocker(stdin);
        let mut child = super::spawn_uncommitted(&mut cmd).expect("spawn");
        if commit {
            child.commit_kill_on_drop();
        }
        child.kill().expect("end the stand-in root");
        // Released only after the kill, so a child that exits 0 was not killed.
        drop(writer);
        let status = child.wait().await.expect("reap the stand-in root");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL),
            "the stand-in root must die of the kill, got {status:?}"
        );
        drop(child);

        let expected: &[u8] = if commit { b"" } else { b"1" };
        assert_eq!(
            std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
            expected,
            "committed: {commit}"
        );
    }
}

/// A failed password write kills the contained tree through the leaf: checked on the step log and
/// on `cgroup.kill`'s raw bytes.
///
/// The `detach` below disarms the leaf, but this handle has killed it, so `child`'s `Drop`
/// releases it like an armed one, with no second write.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_failed_password_write_kills_the_contained_tree() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-async-password-leaf");
    attach_entered_leaf(&leaf_path);
    let (mut cmd, teardown) = opted_out_teardown_blocker();
    let mut child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    // Disarm the leaf, so the failure path's own kill is the only armed one.
    child.detach();

    crate::containment::cgroup::fault::record_leaf_steps();
    let mark = crate::log_capture::mark();
    let (err, fate) = super::finish_elevated(child, failed_write())
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
    assert_eq!(fate, ChildFate::Reaped);
    teardown.assert_killed();

    assert!(
        matches!(
            err,
            Error::Elevation {
                kind: crate::error::ElevationErrorKind::AuthFailed,
                ..
            }
        ),
        "got {err:?}"
    );
    // The failure path's own kill comes first.
    let steps = crate::containment::cgroup::fault::take_leaf_steps();
    assert_eq!(
        steps.first().map(String::as_str),
        Some("kill"),
        "the failed spawn must kill its tree through the leaf, got {steps:?}"
    );
    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        crate::containment::cgroup::KILL_PAYLOAD,
        "the failed spawn must kill its tree through the leaf"
    );
    // A teardown that worked is not warned about.
    assert_eq!(
        crate::log_capture::levels_since(mark, &crate::child::spawn::teardown_warn_marker(&leaf_path)),
        Vec::<log::Level>::new(),
        "a successful tree kill must not warn"
    );
}

/// A failed password write leaves no leaf behind once the killed tree has drained: `finish_elevated`
/// may block, so it waits for the drain before the handle drops, and the drop's first `rmdir`
/// succeeds. The members of the fake leaf exit when the wait is about to block, not before.
///
/// Mutant: `finish_elevated` does not wait for the drain after `kill_tree_members_unless_reaped`.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_failed_password_write_removes_the_leaf_once_the_tree_drains() {
    crate::tokio::test_runtime::assert_current_thread();
    use crate::containment::cgroup::fault as leaf_fault;
    use crate::containment::cgroup::test_support::{entered_leaf_at, FakeLeaf};

    crate::log_capture::install();
    let name = "cosca-async-password-drains-leaf";
    let fake = FakeLeaf::new(name, true);
    let (path, events) = (fake.leaf.clone(), fake.events.clone());
    leaf_fault::set_rmdir_hook(move |_| FakeLeaf::rmdir(&path, &events));
    let (blocking, wait_reached) = std::sync::mpsc::channel();
    leaf_fault::set_drain_blocking_notifier(blocking);
    let members = fake.events.clone();
    let exiting = std::thread::spawn(move || {
        // A closed channel means the wait never blocked: nothing to release.
        if wait_reached.recv().is_ok() {
            FakeLeaf::set_populated(&members, false);
        }
    });
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(entered_leaf_at(fake.leaf.clone())),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let (mut cmd, teardown) = opted_out_teardown_blocker();
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");

    let mark = crate::log_capture::mark();
    let (err, fate) = super::finish_elevated(child, failed_write())
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
    assert_eq!(fate, ChildFate::Reaped);
    teardown.assert_killed();
    leaf_fault::take_drain_blocking_notifier();
    exiting.join().expect("the exiting thread");
    leaf_fault::take_rmdir_hook();

    assert!(matches!(err, Error::Elevation { .. }), "got {err:?}");
    assert!(
        !fake.leaf.exists(),
        "the drained leaf must be removed by the handle's drop"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, name),
        Vec::<log::Level>::new(),
        "a leaf that was removed must not be warned about"
    );
}

/// Async twin of the sync `a_failed_password_write_warns_when_the_tree_kill_fails`: the teardown
/// failure is logged at `warn`, not only embedded in the error's `detail`.
///
/// A refused `cgroup.kill` never sets the leaf's `killed`, so the disarmed `Child::drop` that
/// follows kills nothing again.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_failed_password_write_warns_when_the_tree_kill_fails() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-async-password-kill-fail-leaf");
    attach_entered_leaf(&leaf_path);
    let (mut cmd, teardown) = opted_out_teardown_blocker();
    let mut child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    // Disarm the leaf, so the failure path's own kill is the only armed one.
    child.detach();

    // Not ENOENT/ENODEV, so `hard_kill` treats it as a real failure: `open(O_WRONLY)` on a
    // directory fails EISDIR.
    std::fs::remove_file(leaf_path.join("cgroup.kill")).expect("remove the fixture's cgroup.kill file");
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill a directory");
    let mark = crate::log_capture::mark();
    let (err, fate) = super::finish_elevated(child, failed_write())
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
    assert_eq!(fate, ChildFate::Reaped);
    teardown.assert_killed();
    assert!(
        matches!(
            err,
            Error::Elevation {
                kind: crate::error::ElevationErrorKind::AuthFailed,
                ..
            }
        ),
        "got {err:?}"
    );
    let marker = crate::child::spawn::teardown_warn_marker(&leaf_path);
    assert_eq!(
        crate::log_capture::levels_since(mark, &marker),
        [log::Level::Warn],
        "a forced tree-kill failure must be logged at warn"
    );
    let errno_text = std::io::Error::from_raw_os_error(libc::EISDIR).to_string();
    let records = crate::log_capture::records_since(mark, &marker);
    assert!(
        records[0].contains(&errno_text),
        "the warning must name the OS reason the write failed, got {records:?}"
    );
}

/// Whether `pid`, a child of this process, has been reaped: `waitpid` no longer knows it.
#[cfg(target_os = "linux")]
fn reaped(pid: u32) -> bool {
    let mut status = 0;
    // SAFETY: a non-blocking query on a pid this process spawned; `status` is a valid int.
    let r = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
    r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
}

/// The error a failed password write returns.
#[cfg(target_os = "linux")]
fn failed_write() -> Result<(), Error> {
    Err(Error::Elevation {
        kind: crate::error::ElevationErrorKind::AuthFailed,
        detail: "forced password-write failure".into(),
    })
}

/// A `Delegated` spawn has no tree teardown of its own, but its root is still this spawn's child:
/// a failed password write kills and reaps it.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_failed_password_write_kills_and_reaps_a_delegated_root() {
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::Delegated,
        attached: crate::containment::Attached::Delegated,
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let (mut cmd, teardown) = opted_out_teardown_blocker();
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    let pid = child.id().pid();

    let err = super::finish_elevated(child, failed_write())
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
    let (err, fate) = err;
    assert_eq!(fate, crate::error::ChildFate::Reaped, "killed and reaped");
    teardown.assert_killed();

    let reaped = reaped(pid);
    if !reaped {
        // SAFETY: `pid` is this process's own unreaped child; do not leak it past the test.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    assert!(reaped, "the root must be killed and reaped, got {err:?}");
    assert!(err.to_string().contains("was terminated"), "got {err:?}");
}

/// A tree kill that fails does not stop the root's own kill and reap: the two are separate.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_failed_password_write_reaps_the_root_when_the_tree_kill_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-unkillable-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    // A directory: writing `cgroup.kill` fails with EISDIR, as a refused kill would.
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill unwritable");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let (mut cmd, teardown) = opted_out_teardown_blocker();
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    let pid = child.id().pid();

    let (err, fate) = super::finish_elevated(child, failed_write())
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
    assert_eq!(fate, ChildFate::Reaped);
    teardown.assert_killed();

    assert!(reaped(pid), "the root was killed, so it must be reaped, got {err:?}");
    let detail = err.to_string();
    assert!(detail.contains("was terminated"), "the root was killed, got {detail}");
    assert!(
        detail.contains("its contained tree could not be killed"),
        "the tree's failure is reported, got {detail}"
    );
}

/// A tree kill that fails and a root whose handle cannot say whether it was reaped (`Unknown`) are
/// one event: the cleanup warns once, naming both.
///
/// Mutant: the tree's failure is logged on its own, beside the cleanup's warn.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_failed_tree_kill_and_an_unknown_root_share_one_warn() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-unkillable-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    // A directory: writing `cgroup.kill` fails with EISDIR, as a refused kill would.
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill unwritable");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let (mut cmd, teardown) = opted_out_teardown_blocker();
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    let mark = crate::log_capture::mark();
    let _unsure = crate::wait::exit_only::seams::force_peeks([
        Err(std::io::Error::other("forced peek failure 7a2e")),
        Err(std::io::Error::other("forced peek failure 7a2e")),
    ]);

    let (_err, _fate) = super::finish_elevated(child, failed_write())
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();

    teardown.assert_killed();
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        // (The leaf's own removal failure is another resource's event.)
        .filter(|(level, text)| *level <= log::Level::Warn && !text.contains("was not removed"))
        .collect();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0]
            .1
            .contains("tree teardown after a failed password write failed")
            && warns[0].1.contains("RootState::Unknown"),
        "the one warn names the tree's failure and the unknown root: {warns:?}"
    );
}

/// A process-group child that someone else reaped is never `killpg`ed by the failure teardown: its
/// group number may name another group by now, and the error says the tree kill was skipped. The
/// async twin of the sync `finish_elevated`'s test.
///
/// Mutant: `finish_elevated` runs the tree kill before it learns the root was reaped.
#[cfg(unix)]
#[skuld::test]
async fn finish_elevated_after_a_foreign_reap_sends_no_killpg_to_a_process_group() {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::tokio::test_runtime::assert_current_thread();
    let recorder = crate::containment::unix::fault::record_kill_group();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin pipe");
    cmd.contain_with(crate::ContainMode::Session);
    let child = cmd.spawn().expect("spawn");
    assert!(
        child.signals_a_group(),
        "the test needs a group named by the root's pid, which ContainMode::Session makes"
    );
    let pid = child.id().pid();
    drop(writer);
    crate::test_child::wait_until_zombie(pid);
    let mut status = 0;
    // SAFETY: `pid` is this test's own zombie child; this plays the application that reaps it.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());

    let err = super::finish_elevated(
        child,
        Err(Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("the spawn fails")
    .expect_may_have_started_with();
    let (err, fate) = err;
    assert_eq!(fate, crate::error::ChildFate::Gone, "reaped by someone else");

    let Error::Elevation { detail, .. } = err else {
        panic!("expected an Elevation error, got {err:?}");
    };
    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "a reaped root's group number may name another group: no killpg ({detail})"
    );
    assert!(detail.contains("process group"), "{detail}");
    assert!(detail.contains("already reaped"), "{detail}");
}

// Whether the program could have started =====

/// A refusal before the fork, here of a merge into a merge, did not start the program.
///
/// Mutant: stdio resolution answers that the program may have started.
#[skuld::test]
async fn a_refused_stdio_setup_did_not_start_the_program() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdout(crate::stdio::Stdio::merge(crate::stdio::Fd::STDERR))
        .expect("stdout");
    cmd.stderr(crate::stdio::Stdio::merge(crate::stdio::Fd::STDOUT))
        .expect("stderr");
    let err = expect_not_started(cmd.spawn().expect_err("a merge into a merge is refused"));
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
}

/// A failed exec through tokio may have started the program, on every platform: tokio can fail a
/// spawn after std's succeeded, and its error does not say which failed.
///
/// Mutant: a failed tokio spawn answers that the program did not start.
#[skuld::test]
async fn a_failed_exec_may_have_started_the_program() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(["cosca-no-such-program-142"]);
    let (err, fate) = expect_may_have_started_with(cmd.spawn().expect_err("a missing program fails the spawn"));
    // Linux's handshake finds std had collected the child whose exec failed. Elsewhere nothing holds
    // it, so it may be running.
    let expected = if cfg!(target_os = "linux") {
        ChildFate::Gone
    } else {
        ChildFate::Running { id: None }
    };
    assert_eq!(fate, expected);
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound),
        "{err:?}"
    );
}

/// `output`, `status` and `read` say the program may have started for any failure after the spawn:
/// here `read`'s invalid UTF-8.
///
/// Mutant: a failure after the spawn returns its cause bare.
#[cfg(unix)]
#[skuld::test]
async fn run_to_completion_failures_after_the_spawn_may_have_started() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(["printf", "\\377"]);
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        cmd.read().await.expect_err("invalid UTF-8 fails `read`"),
    );
    assert_eq!(fate, crate::error::ChildFate::Reaped, "`read` collected the exit");
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData),
        "{err:?}"
    );
}

/// Outside a runtime, a tokio spawn is refused before anything is made.
///
/// Mutant: the refusal answers that the program may have started.
#[skuld::test]
fn a_spawn_outside_a_runtime_did_not_start_the_program() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    expect_not_started(cmd.spawn().expect_err("no runtime, no spawn"));
}

/// A command with no program is refused before anything is made.
///
/// Mutant: building the `std` command answers that the program may have started.
#[skuld::test]
async fn a_command_with_no_program_did_not_start() {
    let err = expect_not_started(
        crate::test_child::tokio_command(Console::Hidden)
            .spawn()
            .expect_err("no program, no spawn"),
    );
    assert!(matches!(err, Error::Io(_)), "{err:?}");
}

/// An elevated spawn its backend cannot express is refused before any backend runs.
///
/// Mutant: the elevation rewrite answers that the program may have started.
#[cfg(unix)]
#[skuld::test]
async fn an_elevation_refused_for_its_shape_did_not_start() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(["/bin/sh", "-c", "true"]).elevate();
    cmd.fd(3, crate::stdio::Stdio::null()).expect("fd 3");
    let err = expect_not_started(cmd.spawn().expect_err("fd >= 3 is refused under elevation"));
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
}

/// Linux: a pidfd handshake whose channel cannot be made fails before the fork.
///
/// Mutant: the handshake's `open` answers that the program may have started.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_handshake_that_cannot_open_did_not_start() {
    let _armed = crate::child::spawn::pidfd_handshake::fault::fail_done_fd(rustix::io::Errno::MFILE);
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    let err = expect_not_started(cmd.spawn().expect_err("a failed open fails the spawn"));
    assert!(
        matches!(err, Error::Io(ref e) if e.to_string() == format!("eventfd: {}", std::io::Error::from_raw_os_error(libc::EMFILE))),
        "{err:?}"
    );
}

/// Windows: a creation flag the std path refuses is refused in `prepare`, before `CreateProcess`.
///
/// Mutant: `prepare` answers that the program may have started.
#[cfg(windows)]
#[skuld::test]
async fn a_refused_creation_flag_did_not_start_the_program() {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    let err = expect_not_started(cmd.spawn().expect_err("a reserved bit must be refused"));
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
}

// The fate of a child a failed spawn abandoned with no handle on it =====

/// Off Linux nothing says more of an abandoned child than that it may be running out of reach.
///
/// Mutant: the arm answers another fate, or drops the identity-less `Running`.
#[cfg(not(target_os = "linux"))]
#[skuld::test]
fn an_abandoned_child_nothing_reaches_may_be_running() {
    use crate::containment::AbandonedChild;
    assert_eq!(
        super::abandoned_fate(AbandonedChild::MaybeUnreachable),
        ChildFate::Running { id: None }
    );
}

/// Only a Linux cgroup leaf abandons a child as ended or unreaped; elsewhere each is a contract
/// breach, asserted in debug. It claims nothing (`Unknown`), and in particular never `Killed`.
///
/// Mutants: `Ended` is `Killed`, which says a kill was delivered; any arm is silent.
#[cfg(not(target_os = "linux"))]
#[skuld::test]
fn an_abandoned_child_only_a_linux_leaf_can_report_asserts() {
    use crate::containment::AbandonedChild;
    for abandoned in [AbandonedChild::Ended(ChildFate::Reaped), AbandonedChild::MaybeUnreaped] {
        let outcome = std::panic::catch_unwind(|| super::abandoned_fate(abandoned.clone()));
        if cfg!(debug_assertions) {
            assert!(outcome.is_err(), "{abandoned:?} must assert");
        } else {
            assert_eq!(outcome.expect("no assertion in release"), ChildFate::Unknown);
        }
    }
}

/// macOS and Windows: tokio can fail a spawn after its fork, dropping the child neither killed nor
/// reaped. Nothing holds it, so the spawn answers that the program may have started, and that the
/// child may be running with no identity read.
///
/// Mutant: the arm answers another fate (`Killed`, as an ended child would be), or the spawn answers
/// that the program did not start.
#[cfg(not(target_os = "linux"))]
#[skuld::test]
async fn a_tokio_spawn_failing_after_the_fork_leaves_the_child_running_and_says_so() {
    crate::tokio::test_runtime::assert_current_thread();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let error = {
        let _failing = fault::fail_tokio_spawns_after_fork();
        cmd.spawn().expect_err("the forced failure fails the spawn")
    };
    let (_error, fate) = expect_may_have_started_with(error);
    assert_eq!(fate, ChildFate::Running { id: None });
    let pid = fault::take_forgotten_pid().expect("the seam forked a child");
    // The forgotten child exits once its stdin closes; here it is ours to collect.
    #[cfg(unix)]
    {
        drop(writer);
        let mut status = 0;
        // SAFETY: reaps this test's own forgotten child, which nothing else reaps.
        let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        assert_eq!(
            reaped, pid as libc::pid_t,
            "the forgotten child is still ours to collect"
        );
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        drop(writer);
    }
}

/// What a leaf's abandonment found of an elevation front is what the spawn answers: reaped through
/// the leaf is `Reaped`, left running is `Running`, and a place that cannot be read or a front that
/// cannot be waited on is `Unknown`, never `Running` or `Killed`.
///
/// Mutant: an arm answers another fate.
#[skuld::test]
fn a_front_the_leaf_found_is_answered_by_what_became_of_it() {
    use crate::child::spawn::FrontFate;
    assert_eq!(super::front_child_fate(FrontFate::Reaped), ChildFate::Reaped);
    assert_eq!(
        super::front_child_fate(FrontFate::LeftUnreaped),
        ChildFate::Running { id: None }
    );
    assert_eq!(super::front_child_fate(FrontFate::Unplaced), ChildFate::Unknown);
    assert_eq!(super::front_child_fate(FrontFate::Unaccounted), ChildFate::Unknown);
}

/// The async `spawn()` refuses an elevated `executable()` or `raw_executable()` before any launch,
/// on the gate in `elevation_argv`; `spawn_uncommitted`'s raw-backend branch asserts that no
/// elevated request reaches it. The argv[0] is extensionless, so with the gate gone a later check
/// refuses it as `InvalidInput`: still no launch, and the test fails on the error kind.
///
/// Mutant: `elevation_argv` stops refusing a program set by either setter.
#[cfg(windows)]
#[skuld::test]
async fn an_elevated_executable_or_raw_executable_is_refused_by_the_async_spawn() {
    let program = r"C:\no-such-dir\tool";
    for setter in ["executable", "raw_executable"] {
        let mut c = crate::test_child::tokio_command(Console::Hidden);
        match setter {
            "executable" => c.executable(program),
            _ => c.raw_executable(program),
        };
        c.args([program]).elevate();
        match c.spawn() {
            Err(Error::Unsupported { op, detail, .. }) => {
                assert!(op.contains(&format!("{setter}()")), "{setter}: {op}");
                assert_eq!(detail, crate::elevation::SETTER_REFUSAL, "{setter}");
            }
            other => panic!("{setter}: expected Unsupported, got {:?}", other.map(|_| "a child")),
        }
    }
}
