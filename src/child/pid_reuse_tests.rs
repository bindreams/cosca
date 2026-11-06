//! The sync twins of `tokio::child::pid_reuse_tests`: a sync child reaped behind its back, its pid
//! reused, then killed or dropped. The sync `OwnedChild` signals through its held pidfd. They pin
//! that against a rewrite of its signal path.

use crate::test_child::pid_reuse::{in_fresh_pid_ns, reap_behind_and_reuse, reuser_id, sigusr1_and_wait};
use crate::test_child::reaped_elsewhere::{assert_one_reaped_elsewhere_warn, REAPED_ELSEWHERE};
use crate::test_child::Console;
use crate::test_groups::{namespaces, pidfd_group_signal};

fn spawn_blocker() -> (crate::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    (cmd.spawn().expect("spawn"), writer)
}

/// Mutant: sync `kill` by `kill(pid)`.
fn kill_after_foreign_reap_and_reuse_body() {
    let (child, writer) = spawn_blocker();
    drop(writer);
    let reuser = reap_behind_and_reuse(child.pid());
    child.kill().expect("a kill of a foreign-reaped child answers Ok");
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
in_fresh_pid_ns!(
    namespaces_sync_kill_after_foreign_reap_and_reuse_signals_nothing,
    fixture_sync_kill_reuse_driver,
    fixture_sync_kill_reuse_init,
    kill_after_foreign_reap_and_reuse_body
);

/// Mutant: sync `Drop` kill by `kill(pid)`.
fn drop_kill_after_foreign_reap_and_reuse_body() {
    let (child, writer) = spawn_blocker();
    drop(writer);
    let reuser = reap_behind_and_reuse(child.pid());
    drop(child);
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
in_fresh_pid_ns!(
    namespaces_sync_drop_kill_after_foreign_reap_and_reuse_signals_nothing,
    fixture_sync_drop_reuse_driver,
    fixture_sync_drop_reuse_init,
    drop_kill_after_foreign_reap_and_reuse_body
);

// The attach =====

/// A child reaped behind its back, and its pid reused by a stranger, after the spawn verified the
/// child's identity and before it attached the containment. The attach takes the verified identity
/// and reads nothing by pid, so the tree-walk root is the child itself and `kill_tree` reaches no
/// one: the stranger's pidfd has an inode of its own, so a read of the root by pid finds another
/// identity. Runs where that is true: Linux 6.9+ (the `pidfd_group_signal` group), in the fresh pid
/// namespace the macro makes.
///
/// Mutant: the attach re-reads the root by pid.
fn treewalk_root_is_the_verified_identity_body() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::spawn::fault;

    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::TreeWalk);

    let stranger = Rc::new(RefCell::new(None));
    let _hook = fault::set_at(fault::SpawnPoint::BeforeAttach, {
        let stranger = Rc::clone(&stranger);
        move || {
            let pid = fault::spawn_pid();
            drop(writer);
            *stranger.borrow_mut() = Some(reap_behind_and_reuse(pid));
        }
    });
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => panic!("a reap after the verified identity read must not fail the spawn: {e:?}"),
    };
    let stranger = stranger.borrow_mut().take().expect("the hook must have run");
    assert_eq!(stranger.id(), child.pid(), "the stranger must hold the child's pid");
    assert_eq!(
        child.test_treewalk_root(),
        child.id(),
        "the walk's root must be the verified identity, not whoever holds the pid now"
    );
    let err = child
        .kill_tree()
        .expect_err("a never-settled tree whose root was reaped is not assessable");
    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        sigusr1_and_wait(stranger),
        Some(libc::SIGUSR1),
        "the stranger must have been signalled by the test alone"
    );
}
in_fresh_pid_ns!(
    namespaces_sync_treewalk_root_is_the_verified_identity,
    fixture_sync_treewalk_root_driver,
    fixture_sync_treewalk_root_init,
    treewalk_root_is_the_verified_identity_body,
    pidfs
);

// Tree signals after a reap and a reuse =====

/// A blocker in its own session (`Attached::ProcessGroup`), which exits once `writer` is dropped.
fn spawn_group_blocker() -> (crate::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    let child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), crate::Containment::Session);
    (child, writer)
}

/// A root reaped behind its handle's back, its pid reused: `kill_tree` sends no `killpg` by the
/// number and answers `Unassessable`, with one `warn` naming the group. The reap is foreign, so a
/// correct call reads no number. The root's number is forced, after the reap and the reuse, to read
/// as the reuser: with the root's own start token (`same_tick`) or the next one, so a mutant that
/// reads it fails here whichever tick the real reuser started in.
///
/// Mutants: the precondition assert kept (a debug panic on the later-tick read); `killpg` sent;
/// the decision taken on the number alone (the same-tick read reads as the root).
fn kill_tree_after_a_foreign_reap_and_reuse(same_tick: bool) {
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let recorder = crate::containment::unix::fault::record_kill_group();
    let (child, writer) = spawn_group_blocker();
    let pid = child.pid();
    drop(writer);
    let reuser = reap_behind_and_reuse(pid);
    let _read = crate::child::fault::force_root_reads(reuser_id(
        child.id().expect(crate::test_child::IDENTITY_READ),
        same_tick,
    ));

    let mark = crate::log_capture::mark();
    let err = child
        .kill_tree()
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_one_reaped_elsewhere_warn(mark, pid);
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
fn kill_tree_after_a_foreign_reap_and_reuse_body() {
    kill_tree_after_a_foreign_reap_and_reuse(false);
}
fn kill_tree_after_a_foreign_reap_and_same_tick_reuse_body() {
    kill_tree_after_a_foreign_reap_and_reuse(true);
}
in_fresh_pid_ns!(
    namespaces_kill_tree_after_a_foreign_reap_and_reuse_sends_no_killpg,
    fixture_sync_kill_tree_reuse_driver,
    fixture_sync_kill_tree_reuse_init,
    kill_tree_after_a_foreign_reap_and_reuse_body
);
in_fresh_pid_ns!(
    namespaces_kill_tree_after_a_foreign_reap_and_same_tick_reuse_sends_no_killpg,
    fixture_sync_kill_tree_same_tick_driver,
    fixture_sync_kill_tree_same_tick_init,
    kill_tree_after_a_foreign_reap_and_same_tick_reuse_body
);

/// `terminate_tree`'s twin of [`kill_tree_after_a_foreign_reap_and_reuse`], with the later-tick
/// read forced. Same mutants.
fn terminate_tree_after_a_foreign_reap_and_reuse_body() {
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let recorder = crate::containment::unix::fault::record_term_group();
    let (child, writer) = spawn_group_blocker();
    let pid = child.pid();
    drop(writer);
    let reuser = reap_behind_and_reuse(pid);
    let _read =
        crate::child::fault::force_root_reads(reuser_id(child.id().expect(crate::test_child::IDENTITY_READ), false));

    let mark = crate::log_capture::mark();
    let err = child
        .terminate_tree()
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        recorder.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a reaped root's number"
    );
    assert_one_reaped_elsewhere_warn(mark, pid);
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
in_fresh_pid_ns!(
    namespaces_terminate_tree_after_a_foreign_reap_and_reuse_sends_no_signal,
    fixture_sync_terminate_tree_reuse_driver,
    fixture_sync_terminate_tree_reuse_init,
    terminate_tree_after_a_foreign_reap_and_reuse_body
);

/// A root this handle reaped itself, whose pid now names another process: its group is empty (a
/// pid is not reissued while it is some group's id), so `kill_tree` sends nothing and is `Ok`.
///
/// The reuser reads as another process (a later tick) or as the root (the same tick): either way
/// the root is gone, so the pid names someone else.
///
/// Mutants: the precondition assert kept (a debug panic); our own reap answered as foreign
/// (`Unassessable`); `killpg` sent; the number trusted when it reads as the root (same tick); the
/// tree not marked killed, so the drop warns.
fn kill_tree_after_own_wait_and_reuse(same_tick: bool) {
    crate::log_capture::install();
    let recorder = crate::containment::unix::fault::record_kill_group();
    let (child, writer) = spawn_group_blocker();
    let pid = child.pid();
    let reuser_read = reuser_id(child.id().expect(crate::test_child::IDENTITY_READ), same_tick);
    drop(writer);
    child.wait().expect("this handle reaps the root");
    let reuser = crate::test_child::pid_reuse::reuse(pid);
    let _read = crate::child::fault::force_root_reads(reuser_read);

    let mark = crate::log_capture::mark();
    child
        .kill_tree()
        .expect("a tree whose root this handle reaped answers Ok");

    assert_eq!(
        recorder.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_eq!(
        crate::log_capture::records_since_on_current_thread(mark, REAPED_ELSEWHERE),
        [],
        "our own reap is not a foreign one"
    );
    let dropped = crate::log_capture::mark();
    drop(child);
    assert_eq!(
        crate::log_capture::warns_since(dropped, ""),
        Vec::<String>::new(),
        "the group is empty, so the tree counts as killed: the drop does not warn"
    );
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
fn kill_tree_after_own_wait_and_reuse_body() {
    kill_tree_after_own_wait_and_reuse(false);
}
fn kill_tree_after_own_wait_and_same_tick_reuse_body() {
    kill_tree_after_own_wait_and_reuse(true);
}
in_fresh_pid_ns!(
    namespaces_kill_tree_after_own_wait_and_reuse_is_ok_and_sends_nothing,
    fixture_sync_kill_tree_own_wait_driver,
    fixture_sync_kill_tree_own_wait_init,
    kill_tree_after_own_wait_and_reuse_body
);
in_fresh_pid_ns!(
    namespaces_kill_tree_after_own_wait_and_same_tick_reuse_is_ok_and_sends_nothing,
    fixture_sync_kill_tree_own_wait_same_tick_driver,
    fixture_sync_kill_tree_own_wait_same_tick_init,
    kill_tree_after_own_wait_and_same_tick_reuse_body
);

/// `graceful_shutdown_tree` of a root this handle reaped itself, whose pid now names another
/// process: the group is empty, so neither the `SIGTERM` nor the sweep goes out by the number, and
/// the call answers the root's own status, with no warn.
///
/// Mutant: the shutdown's look at the reaped root is ignored, so its `SIGTERM` goes to the group by
/// the number, the reuser's.
fn graceful_shutdown_tree_after_own_wait_and_reuse_body() {
    crate::log_capture::install();
    let killed = crate::containment::unix::fault::record_kill_group();
    let termed = crate::containment::unix::fault::record_term_group();
    let (child, writer) = spawn_group_blocker();
    let pid = child.pid();
    let reuser_read = reuser_id(child.id().expect(crate::test_child::IDENTITY_READ), false);
    drop(writer);
    let status = child.wait().expect("this handle reaps the root");
    let reuser = crate::test_child::pid_reuse::reuse(pid);
    let _read = crate::child::fault::force_root_reads(reuser_read);

    let mark = crate::log_capture::mark();
    let shut_down = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect("a tree whose root this handle reaped answers its status");

    assert_eq!(shut_down, status, "the root's own status");
    assert_eq!(
        termed.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a reaped root's number"
    );
    assert_eq!(
        killed.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_eq!(
        crate::log_capture::warns_since(mark, ""),
        Vec::<String>::new(),
        "the group is empty: nothing to warn about"
    );
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
in_fresh_pid_ns!(
    namespaces_graceful_shutdown_tree_after_own_wait_and_reuse_sends_nothing,
    fixture_sync_graceful_own_wait_driver,
    fixture_sync_graceful_own_wait_init,
    graceful_shutdown_tree_after_own_wait_and_reuse_body
);

/// `terminate_tree` of a root this handle reaped itself, whose pid now names another process: the
/// group is empty, so no `SIGTERM` goes out by the number, and the call is `Ok` with no warn.
///
/// Mutant: an own reap whose pid names another process answered as `Trusted`.
fn terminate_tree_after_own_wait_and_reuse_body() {
    crate::log_capture::install();
    let termed = crate::containment::unix::fault::record_term_group();
    let (child, writer) = spawn_group_blocker();
    let pid = child.pid();
    let reuser_read = reuser_id(child.id().expect(crate::test_child::IDENTITY_READ), false);
    drop(writer);
    child.wait().expect("this handle reaps the root");
    let reuser = crate::test_child::pid_reuse::reuse(pid);
    let _read = crate::child::fault::force_root_reads(reuser_read);

    let mark = crate::log_capture::mark();
    child
        .terminate_tree()
        .expect("a tree whose root this handle reaped answers Ok");

    assert_eq!(
        termed.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a reaped root's number"
    );
    assert_eq!(
        crate::log_capture::warns_since(mark, ""),
        Vec::<String>::new(),
        "the group is empty: nothing to warn about"
    );
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
in_fresh_pid_ns!(
    namespaces_terminate_tree_after_own_wait_and_reuse_sends_nothing,
    fixture_sync_terminate_own_wait_driver,
    fixture_sync_terminate_own_wait_init,
    terminate_tree_after_own_wait_and_reuse_body
);

/// `graceful_shutdown_tree` of a root reaped behind its handle's back, its pid reused: neither the
/// `SIGTERM` nor a kill goes out by the number, and the call ends at once with one `warn` naming
/// the group. The root's number is forced, after the reap and the reuse, to read as a later-tick
/// reuser, so a foreign reap answered as `Trusted` is caught whichever tick the real reuser started
/// in.
///
/// Mutant: a foreign reap answered as `Trusted`.
fn graceful_shutdown_tree_after_a_foreign_reap_and_reuse_body() {
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let killed = crate::containment::unix::fault::record_kill_group();
    let termed = crate::containment::unix::fault::record_term_group();
    let (child, writer) = spawn_group_blocker();
    let pid = child.pid();
    drop(writer);
    let reuser = reap_behind_and_reuse(pid);
    let _read =
        crate::child::fault::force_root_reads(reuser_id(child.id().expect(crate::test_child::IDENTITY_READ), false));

    let mark = crate::log_capture::mark();
    let err = child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        termed.termed(),
        Vec::<i32>::new(),
        "no SIGTERM by a reaped root's number"
    );
    assert_eq!(
        killed.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_one_reaped_elsewhere_warn(mark, pid);
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
in_fresh_pid_ns!(
    namespaces_graceful_shutdown_tree_after_a_foreign_reap_and_reuse_sends_nothing,
    fixture_sync_graceful_foreign_reuse_driver,
    fixture_sync_graceful_foreign_reuse_init,
    graceful_shutdown_tree_after_a_foreign_reap_and_reuse_body
);
