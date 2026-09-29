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

const OPENAT2_REQUIRED: &str = "cosca requires openat2 (Linux \u{2265} 5.6), refused here: openat2 answered ";

/// Without `openat2` no view can be checked: the snapshot is `Unsupported`, naming the requirement
/// as a spawn does, and logged at `warn` with it. Mutant: "report every unreadable view as
/// `Unassessable`" - the requirement is missing from both the error and the warning.
#[test]
fn a_snapshot_without_openat2_is_unsupported_naming_it_and_warned_about() {
    for (errno, name) in [(rustix::io::Errno::NOSYS, "ENOSYS"), (rustix::io::Errno::PERM, "EPERM")] {
        crate::log_capture::install();
        let mark = crate::log_capture::mark();
        let forced = crate::identity::proc_view_fault::force_openat2_errno(errno);
        let got = process_parents();
        drop(forced);
        let records = crate::log_capture::records_since_on_current_thread(mark, "enumerate::process_parents");

        match got {
            Err(crate::error::Error::Unsupported { op, detail, platform }) => {
                assert_eq!(platform, "linux");
                assert_eq!(detail, format!("{OPENAT2_REQUIRED}{name}"), "{errno}");
                assert!(!op.contains("foreign"), "{op}");
            }
            other => panic!("{errno}: expected Unsupported, got {other:?}"),
        }
        assert!(
            records
                .iter()
                .any(|(level, m)| *level == log::Level::Warn && m.contains(&format!("{OPENAT2_REQUIRED}{name}"))),
            "{errno}: {records:?}"
        );
    }
}

/// Another `/proc` open failure is not the requirement. Mutant: "every open failure is
/// `Unsupported`".
#[test]
fn a_snapshot_with_another_open_failure_is_not_unsupported() {
    let forced = crate::identity::proc_view_fault::force_openat2_errno(rustix::io::Errno::NOENT);
    let got = process_parents();
    drop(forced);
    assert!(matches!(got, Err(crate::error::Error::Unassessable { .. })), "{got:?}");
}
