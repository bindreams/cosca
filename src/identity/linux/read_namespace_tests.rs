//! The identity reads against a REAL outer procfs, in re-exec'd children (see
//! `test_child::namespaces` for the group's gating).

use super::proc_view::{proc_view, ProcDir, ProcView};
use crate::identity::stat_parse::parse_starttime_jiffies;
use crate::identity::{Existence, Liveness, ProcessId, Resolved};
use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;
use crate::test_groups::{namespaces, Group};

/// pid 1 of a new pid namespace whose `/proc` is still the outer one: `/proc/1` is the outer
/// init. Also an inner-namespace child, whose pid the outer `/proc` may not hold or may give
/// to another process, and a spawn, whose child cannot be identified.
///
/// Mutants: "`current_token` reads `/proc/<getpid()>/stat`" — the outer init's token;
/// "`read_stat` ignores the view" — `of(1)` resolves the outer init; "an unavailable view
/// resolves a live child to `Gone`" - `of(child)` is `Gone`; "`spawn_identity_error` names no
/// cause" - the spawn's error carries no view.
#[skuld::test]
fn namespaces_an_outer_procfs_gives_current_its_own_token_and_reads_unknown(#[fixture(namespaces)] _group: &Group) {
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
    let view = proc_view();
    assert!(matches!(view, ProcView::Diverged), "got {view:?}");

    let dir = ProcDir::open().expect("/proc opens");
    let stat_token = |path: &str| {
        let stat = dir.read(path).expect("read stat");
        parse_starttime_jiffies(&stat).expect("starttime parses")
    };
    let own = stat_token("self/stat");
    let outer_init = stat_token("1/stat");
    assert_ne!(
        own, outer_init,
        "the fixture needs an outer init that started at another time"
    );

    let current = ProcessId::current();
    assert_eq!(current.pid(), 1);
    assert_eq!(
        current.start_token_raw(),
        own,
        "current() must carry this process's own token"
    );

    assert!(matches!(ProcessId::of(1), Resolved::Unknown));
    assert_eq!(current.exists(), Existence::Unknown);
    assert_eq!(current.is_alive(), Liveness::Unknown);

    // A live child of the inner namespace: `kill(pid, 0)` finds it, the outer `/proc` says
    // nothing reliable about it.
    let mut child = crate::test_spawn::spawn(std::process::Command::new("cat").stdin(std::process::Stdio::piped()))
        .expect("spawn cat");
    let got = ProcessId::of(child.id());
    child.kill().expect("kill the child");
    child.wait().expect("reap the child");
    assert!(
        matches!(got, Resolved::Unknown),
        "an inner-namespace child: got {got:?}"
    );

    // A pid no process can hold is gone whatever `/proc` shows.
    assert!(matches!(
        ProcessId::of(super::read_tests::NO_PROCESS_CAN_HOLD),
        Resolved::Gone
    ));

    // A spawn cannot identify its child, and says the view is why.
    let mut cmd = crate::command::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::test_child::leaked_writer_stdin())
        .expect("set stdin pipe");
    let (error, fate) =
        crate::child::spawn::failure::expect_may_have_started_with(cmd.spawn().expect_err("the spawn fails"));
    assert_eq!(
        fate,
        crate::error::ChildFate::Reaped,
        "the pidfd pins the child, so it is killed and reaped"
    );
    match error {
        crate::error::Error::Unassessable { detail, .. } => assert!(
            detail.contains(
                "the spawned child identity could not be read: this process's /proc is an outer pid namespace's"
            ),
            "{detail}"
        ),
        other => panic!("expected Unassessable naming the view, got {other:?}"),
    }
}
