//! The sync twins of `tokio::child::pid_reuse_tests`: a sync child reaped behind its back, its pid
//! reused, then killed or dropped. The sync `SharedChild` signals through its held pidfd. They pin
//! that against a rewrite of its signal path.

use crate::test_child::pid_reuse::{in_fresh_pid_ns, reap_behind_and_reuse, sigusr1_and_wait};
use crate::test_child::reaped_elsewhere::{assert_one_reaped_elsewhere_warn, REAPED_ELSEWHERE};
use crate::test_groups::namespaces;
use crate::Command;

fn spawn_blocker() -> (crate::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    (cmd.spawn().expect("spawn"), writer)
}

/// Mutant: sync `kill` by `kill(pid)`.
fn kill_after_foreign_reap_and_reuse_body() {
    let (child, writer) = spawn_blocker();
    drop(writer);
    let reuser = reap_behind_and_reuse(child.id().pid());
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
    let reuser = reap_behind_and_reuse(child.id().pid());
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

// The spawn's identity read =====

/// A spawn whose child is reaped behind its back, and its pid reused by a stranger whose start
/// token aliases the child's (a same-tick reuse), between the fork and the identity read. The read
/// finds the stranger, so only the check against the child's own pidfd shows it is not the child:
/// the spawn fails as vanished and the stranger is signalled by the test alone.
///
/// Mutant: `resolve_identity` skips the peek through the handle.
fn spawn_identity_after_foreign_reap_and_reuse_is_gone_body() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::spawn::fault;
    use crate::identity::fault::alias_token;
    use crate::identity::{ProcessId, Resolved, StartToken};

    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");

    let stranger = Rc::new(RefCell::new(None));
    let alias: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(fault::SpawnPoint::BeforeIdentity, {
        let (stranger, alias) = (Rc::clone(&stranger), Rc::clone(&alias));
        move || {
            let pid = fault::spawn_pid();
            let Resolved::Found(id) = ProcessId::of(pid) else {
                panic!("the child must be readable before it is reaped")
            };
            let token = StartToken::from_raw(id.start_token_raw());
            drop(writer);
            let reuser = reap_behind_and_reuse(pid);
            *alias.borrow_mut() = Some(Box::new(alias_token(reuser.id(), token)));
            *stranger.borrow_mut() = Some(reuser);
        }
    });
    let (err, fate) = match cmd.spawn() {
        Ok(child) => panic!("the spawn took the stranger for its child: {:?}", child.id()),
        Err(e) => crate::child::spawn::failure::expect_may_have_started_with(e),
    };
    assert_eq!(fate, crate::error::ChildFate::Gone, "the child was reaped elsewhere");
    let stranger = stranger.borrow_mut().take().expect("the hook must have run");
    assert!(
        matches!(&err, crate::error::Error::Io(e) if e.to_string().contains("reaped by another party")),
        "a child reaped before its identity was read is Gone, not Unassessable: {err:?}"
    );
    assert_eq!(
        sigusr1_and_wait(stranger),
        Some(libc::SIGUSR1),
        "the stranger must have been signalled by the test alone"
    );
    drop(alias);
}
in_fresh_pid_ns!(
    namespaces_sync_spawn_identity_after_foreign_reap_and_reuse_is_gone,
    fixture_sync_spawn_identity_driver,
    fixture_sync_spawn_identity_init,
    spawn_identity_after_foreign_reap_and_reuse_is_gone_body
);

// The attach =====

/// A child reaped behind its back, and its pid reused by a stranger, after the spawn verified the
/// child's identity and before it attached the containment. The attach takes the verified identity
/// and reads nothing by pid, so the tree-walk root is the child itself and `kill_tree` reaches no
/// one: the stranger's start token is its own (aliased to differ from the child's, as a reuse in a
/// later clock tick has it, since the tick it really started in may match).
///
/// Mutant: the attach re-reads the root by pid.
fn treewalk_root_is_the_verified_identity_body() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::spawn::fault;
    use crate::identity::fault::alias_token;
    use crate::identity::{ProcessId, Resolved, StartToken};

    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::TreeWalk);

    let stranger = Rc::new(RefCell::new(None));
    let alias: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(fault::SpawnPoint::BeforeAttach, {
        let (stranger, alias) = (Rc::clone(&stranger), Rc::clone(&alias));
        move || {
            let pid = fault::spawn_pid();
            let Resolved::Found(id) = ProcessId::of(pid) else {
                panic!("the child must be readable before it is reaped")
            };
            drop(writer);
            let reuser = reap_behind_and_reuse(pid);
            // A reuse in a later clock tick, whichever tick the reuser really started in.
            let token = StartToken::from_raw(id.start_token_raw() + 1);
            *alias.borrow_mut() = Some(Box::new(alias_token(reuser.id(), token)));
            *stranger.borrow_mut() = Some(reuser);
        }
    });
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => panic!("a reap after the verified identity read must not fail the spawn: {e:?}"),
    };
    let stranger = stranger.borrow_mut().take().expect("the hook must have run");
    assert_eq!(
        stranger.id(),
        child.id().pid(),
        "the stranger must hold the child's pid"
    );
    assert_eq!(
        child.test_treewalk_root(),
        Some(child.id()),
        "the walk's root must be the verified identity, not whoever holds the pid now"
    );
    child.kill_tree().expect("a tree whose root was reaped answers Ok");
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
    treewalk_root_is_the_verified_identity_body
);

// Tree signals after a reap and a reuse =====

/// A blocker in its own session (`Attached::ProcessGroup`), which exits once `writer` is dropped.
fn spawn_group_blocker() -> (crate::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    let child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), crate::Containment::Session);
    (child, writer)
}

/// The token a reuser of `child`'s pid is made to read with: `child`'s own (a reuse in the same
/// clock tick, which only the handle can tell apart) or the next one (a later tick, which the
/// number shows).
fn reuser_token(child: &crate::Child, same_tick: bool) -> crate::identity::StartToken {
    let raw = child.id().start_token_raw();
    crate::identity::StartToken::from_raw(if same_tick { raw } else { raw + 1 })
}

/// A root reaped behind its handle's back, its pid reused: `kill_tree` sends no `killpg` by the
/// number and answers `Unassessable`, with one `warn` naming the group.
///
/// Mutants: the precondition assert kept (a debug panic on the later-tick reuse); `killpg` sent;
/// the decision taken on the number alone (the same-tick reuse reads as the root).
fn kill_tree_after_a_foreign_reap_and_reuse(same_tick: bool) {
    crate::log_capture::install();
    let recorder = crate::containment::unix::fault::record_kill_group();
    let (child, writer) = spawn_group_blocker();
    let pid = child.id().pid();
    let token = reuser_token(&child, same_tick);
    drop(writer);
    let reuser = reap_behind_and_reuse(pid);
    let _alias = crate::identity::fault::alias_token(reuser.id(), token);

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

/// `terminate_tree`'s twin of [`kill_tree_after_a_foreign_reap_and_reuse`]. Same mutants.
fn terminate_tree_after_a_foreign_reap_and_reuse_body() {
    crate::log_capture::install();
    let recorder = crate::containment::unix::fault::record_term_group();
    let (child, writer) = spawn_group_blocker();
    let pid = child.id().pid();
    let token = reuser_token(&child, false);
    drop(writer);
    let reuser = reap_behind_and_reuse(pid);
    let _alias = crate::identity::fault::alias_token(reuser.id(), token);

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
/// (`Unassessable`); `killpg` sent; the number trusted when it reads as the root (same tick).
fn kill_tree_after_own_wait_and_reuse(same_tick: bool) {
    crate::log_capture::install();
    let recorder = crate::containment::unix::fault::record_kill_group();
    let (child, writer) = spawn_group_blocker();
    let pid = child.id().pid();
    let token = reuser_token(&child, same_tick);
    drop(writer);
    child.wait().expect("this handle reaps the root");
    let reuser = crate::test_child::pid_reuse::reuse(pid);
    let _alias = crate::identity::fault::alias_token(reuser.id(), token);

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
