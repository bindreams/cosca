//! Unit tests for `child.rs`.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::test_child::Console;

/// Regression test: the group-signal step's ordinary refusal outcomes (`Error::Containment` /
/// `Error::Unassessable { source: None, .. }`, distinguished from a failed listing since #61) were
/// being stringified into an opaque `Error::Io` on the way out of `Marker::sweep`.
///
/// `fdmarker_tests.rs` calls `Marker::hard_kill`/`terminate` DIRECTLY, bypassing
/// the tree's dispatch to its marker mechanism where the laundering sat, so none of those tests
/// could catch this. This test goes through the real public path instead: `Command::spawn` →
/// the marker mechanism's `Tree` → `Child::kill_tree`/`Drop`.
///
/// A live cross-uid refuser needs real root to construct (see `tests/group_teardown_setuid.rs`
/// for why that is not reliably provisionable on macOS: SIP). This instead drives the group
/// channel's OTHER real, privilege-free refusal path: `containment::unix::signal_group`'s
/// `pgid <= 0` guard, reached via `Child::test_force_fdmarker_pgid` the same way this codebase's
/// other otherwise-untriggerable branches already are (`force_blind_snapshot_for_next_call` and
/// friends).
#[cfg(target_os = "macos")]
#[skuld::test]
fn kill_tree_reports_an_ordinary_group_refusal_through_the_real_dispatch_path() {
    let mut child = crate::test_child::command(Console::Hidden)
        .executable("/usr/bin/true")
        .arg("true") // argv[0]; `executable` alone selects the loaded image, not argv
        .contain_with(crate::ContainMode::Strongest)
        .spawn()
        .expect("spawn a contained macOS root");
    child.test_force_fdmarker_pgid(0);

    let err = child
        .kill_tree()
        .expect_err("an unsignallable (pgid 0) group channel must report Err, not silently succeed");
    assert!(
        matches!(err, crate::error::Error::Unassessable { source: None, .. }),
        "an invalid-pgid refusal is the ORDINARY, expected outcome unix::signal_group's own \
         guard documents — got {err:?} instead"
    );

    // `Drop` (`kill_on_drop` defaults to true) re-runs the teardown with the forced pgid: it must
    // return normally. The variant assert above is the sole guard for the laundering bug.
    drop(child);
}

/// A blocker whose contained tree is a cgroup leaf whose `cgroup.kill` write always fails, forced via
/// the EISDIR technique of `hard_kill_propagates_a_kill_the_kernel_refused`
/// (`containment/cgroup/leaf_tests.rs`): `open(O_WRONLY)` on a directory always fails. `kill_on_drop`
/// is its default, true. The directory holds the leaf: keep it until the child is gone.
#[cfg(target_os = "linux")]
fn child_whose_tree_kill_fails() -> (crate::Child, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-drop-kill-fail-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill a directory");

    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    child.tree = crate::containment::Tree::contained(crate::containment::Mechanism::Cgroup(
        crate::containment::cgroup::test_support::entered_leaf_at(leaf_path),
    ));
    (child, dir)
}

/// The teardown a helper runs after its failed run (`output`, `status`) is a run's, not a drop's: a
/// tree kill that fails in it is an error among its failures, which the helper's error carries as
/// its `cleanup`, and the call returns normally.
///
/// Mutant: the tree kill's failure is only logged.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_runs_teardown_returns_its_tree_kills_failure() {
    crate::log_capture::install();
    let (mut child, _leaf) = child_whose_tree_kill_fails();
    let stdin = child.stdin().expect("piped stdin");
    let blocker = crate::child::spawn::fault::release_between_kill_and_wait(stdin);

    let torn = child.tear_down_or_hand_back(crate::child::owned::teardown::Disposition::HandBack);

    blocker.assert_killed();
    assert_eq!(torn.fate, crate::error::ChildFate::Reaped);
    assert!(torn.unreaped.is_none());
    let cleanup = torn.cleanup.expect("the tree kill's failure is the teardown's");
    assert_eq!(cleanup.iter().len(), 1, "{cleanup:?}");
    assert!(
        matches!(&**cleanup.first(), crate::error::Error::Containment { .. })
            && crate::error::first_os_code(&**cleanup.first()) == Some(libc::EISDIR),
        "{cleanup:?}"
    );
}

/// A failed `cgroup.kill` write during `Child::drop`'s own teardown is a real OS outcome: Drop
/// must warn, not panic.
#[cfg(target_os = "linux")]
#[skuld::test]
fn drop_warns_instead_of_asserting_on_a_real_teardown_mechanism_failure() {
    crate::log_capture::install();
    let (mut child, _leaf) = child_whose_tree_kill_fails();
    // Released once the drop's root kill has returned: the drop blocks until the root is reaped.
    let stdin = child.stdin().expect("piped stdin");
    let blocker = crate::child::spawn::fault::release_at_drop_kill(stdin);

    // Pin that the forced failure is the mechanism class this test claims (a raw `EISDIR` from
    // the `cgroup.kill` write, surfaced as `Error::Containment` over it), so it cannot go vacuous if
    // the forcing stops reaching the kill.
    let forced = child
        .kill_tree()
        .expect_err("the forced cgroup.kill failure must surface from kill_tree");
    assert!(
        matches!(&forced, crate::error::Error::Containment { .. })
            && crate::error::first_os_code(&forced) == Some(libc::EISDIR),
        "the forced failure must be a mechanism-class Error::Containment over EISDIR, got {forced:?}"
    );

    let mark = crate::log_capture::mark();
    // A same-text record from ANOTHER thread, fixed before the drop by the join: the thread-filtered
    // scan below must not count it (a concurrent test's identical record would look the same).
    let marker = "Child::drop: contained-tree teardown did not fully succeed";
    std::thread::spawn(move || log::warn!("{marker}: from another thread"))
        .join()
        .expect("emit from another thread");
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(child)));
    assert!(
        unwound.is_ok(),
        "Child::drop must not panic on a real teardown-mechanism failure: {unwound:?}"
    );
    blocker.assert_killed();

    // `Drop` logs on the dropping thread (the tree kill runs there before any reaper hand-off),
    // so the current-thread scan sees exactly its record.
    let records = crate::log_capture::records_since_on_current_thread(mark, marker);
    assert_eq!(
        records.iter().map(|(level, _)| *level).collect::<Vec<_>>(),
        [log::Level::Warn],
        "a real teardown-mechanism failure during Drop must be logged at warn, got {records:?}"
    );
}

/// `Child::kill`'s refusal is the OS's own: the error carries the raw errno (`EPERM`, or Windows'
/// `ERROR_ACCESS_DENIED`), not a message about it.
///
/// Mutant: the error is wrapped in a new `io::Error`, or its payload is stringified.
#[skuld::test]
fn child_kill_error_keeps_the_raw_errno() {
    use crate::os_process::child::PeekOutcome;
    use crate::os_process::fake::FakeProcess;

    #[cfg(unix)]
    const REFUSED: i32 = libc::EPERM;
    #[cfg(windows)]
    const REFUSED: i32 = 5;
    // macOS reads the root's state first; nothing else peeks.
    let fake = FakeProcess::new([])
        .peeks([Ok(PeekOutcome::Running)])
        .signals([Err(std::io::Error::from_raw_os_error(REFUSED))]);
    let child = crate::test_child::over_fake::child_over(&fake);

    let err = child.kill().expect_err("the scripted signal is refused");

    assert!(
        matches!(&err, crate::error::Error::Io(e) if e.raw_os_error() == Some(REFUSED)),
        "{err:?}"
    );
    assert_eq!(fake.signal_calls(), [crate::signal::Sig::Kill]);
}

/// The parent's end of a piped stdout nobody took is closed by the time `drop` returns, for the
/// sync `Child` and the async one it holds. Runs alone, so no other thread can take the descriptor
/// number in between.
///
/// Mutant: the drop leaves the untaken pipe open (handed to a thread, or forgotten).
#[cfg(target_os = "linux")]
#[skuld::test]
fn drop_closes_the_childs_untaken_stdout() {
    use std::os::fd::AsRawFd as _;

    if !crate::containment::cgroup::test_support::alone(crate::test_child::fixture_path!(
        drop_closes_the_childs_untaken_stdout
    )) {
        return;
    }
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe_in()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe_out()).expect("set stdout pipe");
    let mut child = cmd.spawn().expect("spawn");
    let teardown = crate::child::spawn::fault::release_between_kill_and_wait(child.stdin().expect("piped stdin"));
    let Some(crate::pipe::ParentEnd::Reader(stdout)) = child.pipes.get(&crate::stdio::Fd::STDOUT) else {
        panic!("piped stdout");
    };
    let stdout = stdout.as_raw_fd();
    // SAFETY: `fcntl(F_GETFD)` reads a flag and changes nothing.
    assert_ne!(
        unsafe { libc::fcntl(stdout, libc::F_GETFD) },
        -1,
        "open while the child lives"
    );
    drop(child);
    // SAFETY: as above.
    let after = unsafe { libc::fcntl(stdout, libc::F_GETFD) };
    assert_eq!(after, -1, "the drop must close the child's untaken stdout");
    teardown.assert_killed();
}

/// A `TreeWalk` child's `kill_tree` sends the root's kill through the child's own handle, with no
/// second open of the root's identity: the walk's send, then the backstop's. The scripted handle
/// answers both. On Unix the sends log shows none by identity, and the live process behind the handle
/// still runs, which a kill by its number or identity would end.
/// Not macOS, where a `TreeWalk` root is an fd marker. Gap: on Windows no row shows the real root was
/// not killed by its identity, because the walk's console-host kill ends the root either way.
///
/// Mutant: the walk opens its root by identity (the handle is sent only the backstop's kill).
#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn a_tree_walk_kill_tree_sends_the_roots_kill_through_the_childs_handle() {
    use crate::signal::{Sent, Sig};

    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    // The kill is delivered, so the call waits for the root through the same handle: it states its exit.
    let fake = child.proc.script_over(|f| {
        f.signals([Ok(Sent::Delivered), Ok(Sent::Delivered)])
            .exits([crate::os_process::fake::Answer::Exited])
    });

    #[cfg(unix)]
    let sends = crate::send_log::Capture::start();

    child.kill_tree().expect("the handle took both kills");

    // A walk that opened the root by identity would leave the handle only the backstop's kill. (On
    // Windows the real root's own state is not asserted: the walk also kills its console host, which
    // ends the root of its own accord.)
    assert_eq!(
        fake.signal_calls(),
        vec![Sig::Kill, Sig::Kill],
        "the walk's, then the backstop's"
    );
    // On Unix the root was sent nothing by its identity, and the real root still runs: its kills went
    // to the fake handle.
    #[cfg(unix)]
    {
        assert_eq!(
            sends.by_identity(),
            vec![],
            "the root was sent a signal by its identity"
        );
        assert!(
            child.try_wait().expect("look at the live process").is_none(),
            "the real root exited (a kill by its number or identity would do this)"
        );
    }
}

/// A `TreeWalk` child's `terminate_tree` sends the root's `SIGTERM` through the child's own handle.
/// Mutant: the walk opens its root by identity (the handle is sent nothing).
#[cfg(all(unix, not(target_os = "macos")))]
#[skuld::test]
fn a_tree_walk_terminate_tree_sends_the_roots_term_through_the_childs_handle() {
    use crate::signal::{Sent, Sig};

    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    let fake = child.proc.script_over(|f| f.signals([Ok(Sent::Delivered)]));
    let sends = crate::send_log::Capture::start();

    child.terminate_tree().expect("the handle took the SIGTERM");

    assert_eq!(fake.signal_calls(), vec![Sig::Term]);
    // A `SIGTERM` the walk sent the root by its identity is a send the log holds at once; the root's
    // exit, below, follows it only when the kernel gets to it.
    assert_eq!(
        sends.by_identity(),
        vec![],
        "the root was sent a signal by its identity"
    );
    assert!(
        child.try_wait().expect("look at the live process").is_none(),
        "the real root exited (a SIGTERM by its identity would do this)"
    );
}
