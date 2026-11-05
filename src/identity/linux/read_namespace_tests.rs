//! The identity reads against a REAL outer procfs, in re-exec'd children (see
//! `test_child::namespaces` for the group's gating).

use super::kernel::HostKernel;
use super::proc_view::{proc_view_with, ProcView};
use crate::identity::{Existence, Liveness, ProcessId, Resolved};
use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;
use crate::test_groups::{namespaces, pidfd_group_signal, Group};

/// pid 1 of a new pid namespace whose `/proc` is still the outer one: `/proc/1` is the outer
/// init. Also an inner-namespace child, whose pid the outer `/proc` may not hold or may give
/// to another process, and a spawn, whose child cannot be identified.
///
/// On pidfs (Linux 6.9+) every one of these reads works, since none asks `/proc`.
///
/// Mutants: "`current` reads `/proc/<getpid()>/stat`" - it carries the outer init's token, not a
/// pidfd inode; "`of` reads `/proc`" - `of(1)` resolves the outer init, or a live child is `Gone`
/// or `Unknown`; "a spawn reads its child's identity from `/proc`" - the spawn fails.
#[skuld::test]
fn namespaces_an_outer_procfs_does_not_matter_to_a_pidfs_identity(
    #[fixture(namespaces)] _group: &Group,
    #[fixture(pidfd_group_signal)] _pidfs: &Group,
) {
    ns::run(fixture_path!(fixture_outer_procfs_outer));
}

#[skuld::test]
fn fixture_outer_procfs_outer() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_outer_procfs_inner));
}

#[skuld::test]
fn fixture_outer_procfs_inner() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    assert_eq!(
        std::process::id(),
        1,
        "the fixture must be pid 1 of its own pid namespace"
    );
    let view = proc_view_with(&HostKernel);
    assert!(matches!(view, ProcView::Diverged), "got {view:?}");

    // On pidfs a process is told by its pidfd's inode, so the outer `/proc` is never read and the
    // reads that answered `Unknown` below Linux 6.9 (`/proc` rows: `read_tests`) answer.
    let current = ProcessId::current();
    assert_eq!(current.pid(), 1);
    assert!(
        current.pidfs_ino().is_some(),
        "a pidfs host gives current() its pidfd's inode"
    );

    assert_eq!(
        ProcessId::of(1),
        Resolved::Found(current),
        "pid 1 is this process, whatever /proc shows"
    );
    assert_eq!(current.exists(), Existence::Present);
    assert_eq!(current.is_alive(), Liveness::Alive);

    // A live child of the inner namespace: the outer `/proc` may not hold its pid or may give it to
    // another process; its pidfd does not care.
    let mut child = crate::test_spawn::spawn(std::process::Command::new("cat").stdin(std::process::Stdio::piped()))
        .expect("spawn cat");
    let got = ProcessId::of(child.id());
    let Resolved::Found(id) = got else {
        panic!("an inner-namespace child: got {got:?}")
    };
    assert_eq!(id.exists(), Existence::Present);
    assert_eq!(id.is_alive(), Liveness::Alive);
    child.kill().expect("kill the child");
    child.wait().expect("reap the child");
    assert_eq!(id.exists(), Existence::Gone);

    // A pid no process can hold is gone whatever `/proc` shows.
    assert!(matches!(
        ProcessId::of(super::read_tests::NO_PROCESS_CAN_HOLD),
        Resolved::Gone
    ));

    // A spawn identifies its child by its pidfd, so it succeeds.
    let mut cmd = crate::command::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    cmd.stdin(stdin).expect("set stdin pipe");
    let spawned = cmd.spawn().expect("a spawn needs no /proc view on pidfs");
    // Released after the drop's kill: a kill that sent nothing exits 0.
    let teardown = crate::child::spawn::fault::release_at_drop_kill(writer);
    drop(spawned);
    teardown.assert_killed();
}
