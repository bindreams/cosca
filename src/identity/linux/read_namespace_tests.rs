//! The identity reads against a REAL outer procfs, in re-exec'd children (see
//! `test_child::namespaces` for the group's gating).

use super::proc_view::{proc_view, ProcDir, ProcView};
use crate::identity::stat_parse::parse_starttime_jiffies;
use crate::identity::{Existence, Liveness, ProcessId, Resolved};
use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;

/// pid 1 of a new pid namespace whose `/proc` is still the outer one: `/proc/1` is the outer
/// init. `current()` must carry this process's own start token, not the outer init's, and the
/// by-pid re-reads must be `Unknown`, not the outer init's token compared and found different.
///
/// Mutants: "`current_token` reads `/proc/<getpid()>/stat`" — the outer init's token;
/// "`read_stat` ignores the view" — `of(1)` resolves the outer init.
#[test]
fn namespaces_an_outer_procfs_gives_current_its_own_token_and_reads_unknown() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_outer_procfs_outer));
}

#[test]
fn fixture_outer_procfs_outer() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_outer_procfs_inner));
}

#[test]
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
}
