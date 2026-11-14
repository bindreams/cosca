//! A `TreeWalk` tree whose root has exited (unreaped, so its pid is still pinned): the kernel
//! reparented its children at the exit, so a walk from the root's pid finds none of them. A tree
//! call must not answer `Ok` for that, and a graceful shutdown kills the members its `SIGTERM` walk
//! found while the root was alive, by identity (#940). Linux only: on macOS a `TreeWalk` root is an fd
//! marker.

use std::io::Read as _;
use std::time::Duration;

use crate::error::Error;
use crate::identity::{Liveness, ProcessId};
use crate::test_child::{wait_until_zombie, Console, TERM_SURVIVOR_TREE_ARGV};
use crate::{ContainMode, Containment, Recursive, Stdio};

/// The drop's warn over a tree the settlement could not vouch for.
const DROP_WARN: &str = "Child::drop: contained-tree teardown did not fully succeed";

/// A `TreeWalk` tree on one stdin pipe, which the test holds: a root (`cat`) that a `SIGTERM` ends, and
/// below it a subshell and its `cat` that ignore `SIGTERM`. The subshell is forked when `r` is read.
/// Returns the child, the stdin writer (dropping it ends every member on its own) and the identities of
/// the root's descendants.
fn survivor_tree() -> (crate::Child, crate::PipeWriter, Vec<ProcessId>) {
    tree_of(TERM_SURVIVOR_TREE_ARGV)
}

/// [`survivor_tree`] over `argv`, which prints `r\n` once its descendants are forked.
fn tree_of(argv: &[&str]) -> (crate::Child, crate::PipeWriter, Vec<ProcessId>) {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(argv.iter().copied());
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    cmd.stdout(Stdio::pipe_out()).expect("stdout pipe");
    cmd.contain_with(ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::TreeWalk);
    let stdin = child.stdin().expect("stdin pipe");
    let mut ready = [0u8; 2];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut ready)
        .expect("the readiness line");
    assert_eq!(&ready, b"r\n");
    let survivors = child
        .id()
        .expect("the root's identity")
        .children(Recursive::Yes)
        .expect("the root's descendants");
    assert!(!survivors.is_empty(), "the subshell is a descendant of the root");
    for survivor in &survivors {
        assert_eq!(survivor.is_alive(), Liveness::Alive, "premise: {survivor:?} runs");
    }
    (child, stdin, survivors)
}

/// [`survivor_tree`] whose root is then killed through its own handle and is a zombie: the survivors
/// were reparented, and run on.
fn tree_with_exited_root() -> (crate::Child, crate::PipeWriter, Vec<ProcessId>) {
    let (child, stdin, survivors) = survivor_tree();
    child.kill().expect("kill the root alone");
    wait_until_zombie(child.pid());
    for survivor in &survivors {
        assert_eq!(survivor.is_alive(), Liveness::Alive, "{survivor:?} outlives the root");
    }
    (child, stdin, survivors)
}

/// A walk from a root that has exited finds nothing, so `kill_tree` says it could not see the tree
/// instead of `Ok`, naming the root and why.
///
/// Mutant: the walk's `Ok` for an exited root stands.
#[skuld::test]
fn kill_tree_over_an_exited_root_is_unassessable_and_names_why() {
    let (child, stdin, _survivors) = tree_with_exited_root();

    let err = child
        .kill_tree()
        .expect_err("a walk from an exited root finds no member");

    let Error::Unassessable { detail, .. } = &err else {
        panic!("expected Unassessable, got {err:?}");
    };
    assert!(
        detail.contains(&format!("pid {}", child.pid()))
            && detail.contains("has exited")
            && detail.contains("reparented")
            && detail.contains("no walk ran"),
        "{detail}"
    );
    drop(stdin);
    child.wait().expect("reap the root");
}

/// The drop of such a child warns once, naming the root's pid, where it logged a debug line.
///
/// Mutant: the drop's tree kill is `Ok` for an exited root.
#[skuld::test]
fn dropping_a_tree_walk_child_whose_root_exited_warns_once_naming_the_pid() {
    crate::log_capture::install();
    let (child, stdin, _survivors) = tree_with_exited_root();
    let pid = child.pid();

    let mark = crate::log_capture::mark();
    drop(child);

    let warns = crate::log_capture::records_since_on_current_thread(mark, DROP_WARN);
    assert_eq!(warns.len(), 1, "exactly one warn, got {warns:?}");
    let (level, text) = &warns[0];
    assert_eq!(*level, log::Level::Warn);
    assert!(text.contains(&format!("pid {pid}")), "the warn names the root: {text}");
    drop(stdin);
}

/// What a root that a `SIGTERM` ended leaves as its status.
fn assert_sigtermed(status: std::process::ExitStatus) {
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
}

/// The warns of dropping `child`: none when the call that came before vouched for the tree.
fn drop_warns(child: crate::Child) -> Vec<String> {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    drop(child);
    crate::log_capture::warns_since(mark, "Child::drop")
}

/// The root ends on the `SIGTERM` and its descendants that ignore it are left. The sweep that follows
/// the grace cannot walk from the exited root, so it kills the members the call's own `SIGTERM` walk
/// found while the root was alive, by identity, and waits for them: the call's listing is then clear,
/// and it answers the root's status. The drop afterwards has nothing to warn of.
///
/// Mutants: the sweep walks from the exited root, finds nothing and answers `Ok` with the members
/// running; the held members are killed and the call still answers `Unassessable`.
#[skuld::test]
fn graceful_shutdown_tree_kills_the_members_its_sigterm_walk_found_after_the_root_exits() {
    let (child, stdin, survivors) = survivor_tree();

    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect("every member its walk found is killed");

    assert_sigtermed(status);
    for survivor in &survivors {
        assert_eq!(
            survivor.is_alive(),
            Liveness::Dead,
            "{survivor:?} ignored the SIGTERM and must be killed by identity"
        );
    }
    assert_eq!(drop_warns(child), Vec::<String>::new());
    drop(stdin);
}

/// A tree every member of which ends on the `SIGTERM` is the common case: the call answers the root's
/// status, and the drop does not warn.
///
/// Mutant: the root's exit leaves the call `Unassessable`, with the status lost.
#[skuld::test]
fn graceful_shutdown_tree_of_a_tree_that_ends_on_the_sigterm_is_ok_with_the_roots_status() {
    let (child, stdin, members) = tree_of(crate::test_child::CAT_TREE_ARGV);

    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect("the tree ended on the SIGTERM");

    assert_sigtermed(status);
    for member in &members {
        assert_eq!(member.is_alive(), Liveness::Dead, "{member:?} ends on the SIGTERM");
    }
    assert_eq!(drop_warns(child), Vec::<String>::new());
    drop(stdin);
}

/// A root with no descendants that exits within the grace is an empty listing, not an unwalkable
/// tree: the call answers its status.
///
/// Mutant: an empty `SIGTERM` walk holds nothing, so the sweep over the exited root answers
/// `Unassessable`.
#[skuld::test]
fn graceful_shutdown_tree_of_a_root_with_no_descendants_is_ok_with_its_status() {
    let (child, stdin) = crate::test_child::held_treewalk_blocker();

    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect("the root ended on the SIGTERM");

    assert_sigtermed(status);
    assert_eq!(drop_warns(child), Vec::<String>::new());
    drop(stdin);
}

/// The vouching holds inside the one call. Members a separate `terminate_tree` reached are held, and a
/// `kill_tree` met after the root exited kills them by identity and still cannot vouch for what they
/// forked: `Unassessable`.
///
/// Mutant: held members vouch outside the call that walked them.
#[skuld::test]
fn kill_tree_after_a_separate_terminate_tree_kills_the_held_members_and_is_unassessable() {
    let (child, stdin, survivors) = survivor_tree();
    child.terminate_tree().expect("the walk found the whole tree");
    wait_until_zombie(child.pid());

    let err = child.kill_tree().expect_err("the held members are all it can name");

    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    for survivor in &survivors {
        assert_eq!(
            survivor.is_alive(),
            Liveness::Dead,
            "{survivor:?} is killed by identity"
        );
    }
    drop(stdin);
    child.wait().expect("reap the root");
}

/// The drop of such a child warns once, as for any tree it cannot vouch for.
///
/// Mutant: a held member that is gone excuses the drop.
#[skuld::test]
fn dropping_a_child_after_a_separate_terminate_tree_and_the_roots_exit_warns_once() {
    let (child, stdin, _survivors) = survivor_tree();
    child.terminate_tree().expect("the walk found the whole tree");
    wait_until_zombie(child.pid());

    assert_eq!(drop_warns(child).len(), 1);

    // The drop only sends, so the members end on their own once the stdin they read closes.
    drop(stdin);
}

/// `terminate_tree` over a root that has exited, whose walk finds no member, answers
/// `Unassessable` and sends nothing: its children were reparented, so a walk from its pid says
/// nothing of the tree.
///
/// Mutant: the empty walk is `Ok`.
#[skuld::test]
fn terminate_tree_over_an_exited_root_with_an_empty_walk_is_unassessable_and_sends_nothing() {
    let (child, stdin) = crate::test_child::held_treewalk_blocker();
    child.kill().expect("kill the root");
    wait_until_zombie(child.pid());
    let sends = crate::send_log::Capture::start();

    let err = child
        .terminate_tree()
        .expect_err("a walk from an exited root finds no member");

    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(sends.entries(), vec![], "nothing was sent");
    drop(stdin);
    child.wait().expect("reap the root");
}

/// A `graceful_shutdown_tree` whose root exited before the call does not end at the refused `SIGTERM`:
/// it answers what `kill_tree` answers, so the members an earlier `terminate_tree` reached are killed.
///
/// Mutant: the refused `SIGTERM` ends the call with the held members running.
#[skuld::test]
fn graceful_shutdown_tree_over_an_exited_root_kills_the_held_members() {
    let (child, stdin, survivors) = survivor_tree();
    child.terminate_tree().expect("the walk found the whole tree");
    wait_until_zombie(child.pid());

    let err = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect_err("a root that exited before the call cannot vouch for the tree");

    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    for survivor in &survivors {
        assert_eq!(
            survivor.is_alive(),
            Liveness::Dead,
            "{survivor:?} is killed by identity"
        );
    }
    drop(stdin);
}
