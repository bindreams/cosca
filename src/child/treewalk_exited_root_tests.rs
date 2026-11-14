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

/// The root ends on the `SIGTERM` and its descendants that ignore it are left. The sweep that follows
/// the grace cannot walk from the exited root, so it kills the members the `SIGTERM` walk found while
/// the root was alive, by identity, and answers that the tree could not be vouched for.
///
/// Mutant: the sweep walks from the exited root, finds nothing and answers `Ok`, with the members
/// running.
#[skuld::test]
fn graceful_shutdown_tree_kills_the_members_its_sigterm_walk_found_after_the_root_exits() {
    let (child, stdin, survivors) = survivor_tree();

    let err = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect_err("the tree cannot be vouched for");

    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    for survivor in &survivors {
        assert_eq!(
            survivor.is_alive(),
            Liveness::Dead,
            "{survivor:?} ignored the SIGTERM and must be killed by identity"
        );
    }
    drop(stdin);
}

/// A tree every member of which ends on the `SIGTERM` is no different: the root's exit leaves the
/// sweep nothing to walk, and what the members forked since the `SIGTERM` walk was never looked for.
/// The call is `Unassessable` with the whole tree gone.
#[skuld::test]
fn graceful_shutdown_tree_of_a_tree_that_ends_on_the_sigterm_is_unassessable_too() {
    let (child, stdin, members) = tree_of(crate::test_child::CAT_TREE_ARGV);

    let err = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .expect_err("the tree cannot be vouched for");

    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    for member in &members {
        assert_eq!(member.is_alive(), Liveness::Dead, "{member:?} ends on the SIGTERM");
    }
    drop(stdin);
}
