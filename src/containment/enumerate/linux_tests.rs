use super::process_parents;
use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};

type Records = Vec<(log::Level, String)>;

fn snapshot_with(view: ForcedView) -> (Result<Vec<(u32, u32)>, crate::error::Error>, Records) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let forced = force_proc_view_once(view);
    let got = process_parents();
    drop(forced);
    (
        got,
        crate::log_capture::records_since_on_current_thread(mark, "enumerate::process_parents"),
    )
}

fn assert_unassessable_naming(got: Result<Vec<(u32, u32)>, crate::error::Error>, cause: &str) {
    match got {
        Err(crate::error::Error::Unassessable { detail, .. }) => {
            assert!(detail.contains(cause), "the error must name {cause:?}: {detail}")
        }
        other => panic!("expected Unassessable naming {cause:?}, got {other:?}"),
    }
}

/// An outer namespace's `/proc` lists processes whose pids mean nothing here, and the tree walk
/// signals by pid: the snapshot is `Unassessable` naming the view (and logged at `warn`), never
/// an empty list a walk would read as "no descendants". Mutants: "scan `/proc` by path whatever
/// the view"; "return an empty snapshot for a view that is not `Same`".
#[test]
fn a_diverged_view_is_unassessable_and_warned_about() {
    let (got, records) = snapshot_with(ForcedView::Diverged);
    assert_unassessable_naming(got, "outer pid namespace");
    assert!(
        records
            .iter()
            .any(|(level, m)| *level == log::Level::Warn && m.contains("outer pid namespace")),
        "{records:?}"
    );
}

#[test]
fn an_unassessable_view_is_unassessable_and_warned_about_naming_the_cause() {
    let (got, records) = snapshot_with(ForcedView::Unassessable);
    assert_unassessable_naming(got, "forced by a test");
    assert!(
        records
            .iter()
            .any(|(level, m)| *level == log::Level::Warn && m.contains("forced by a test")),
        "{records:?}"
    );
}

/// The ordinary snapshot lists this process under its real parent.
#[test]
fn the_ordinary_snapshot_lists_this_process_with_its_parent() {
    let me = std::process::id();
    let ppid = std::os::unix::process::parent_id();
    assert!(process_parents().expect("the snapshot").contains(&(me, ppid)));
}
