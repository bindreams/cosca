use super::process_parents;
use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};

fn snapshot_with(view: ForcedView) -> (Vec<(u32, u32)>, Vec<(log::Level, String)>) {
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

/// An outer namespace's `/proc` lists processes whose pids mean nothing here, and the tree walk
/// signals by pid: the snapshot is empty, at `warn`, naming the view. Mutant: "scan `/proc` by
/// path whatever the view".
#[test]
fn a_diverged_view_yields_an_empty_snapshot_and_a_warning() {
    let (got, records) = snapshot_with(ForcedView::Diverged);
    assert!(got.is_empty(), "{} entries", got.len());
    assert!(
        records
            .iter()
            .any(|(level, m)| *level == log::Level::Warn && m.contains("outer pid namespace")),
        "{records:?}"
    );
}

#[test]
fn an_unassessable_view_yields_an_empty_snapshot_and_a_warning_naming_the_cause() {
    let (got, records) = snapshot_with(ForcedView::Unassessable);
    assert!(got.is_empty(), "{} entries", got.len());
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
    assert!(process_parents().contains(&(me, ppid)));
}
