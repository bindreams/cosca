//! The async twin of `child/kill_tree_view_tests.rs`. Linux only.

use std::os::unix::process::ExitStatusExt;

use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};

fn treewalk_blocker() -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), crate::containment::Containment::TreeWalk);
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// Mutant: "run the handle backstop after a snapshot failure".
#[tokio::test]
async fn kill_tree_over_an_untrusted_view_errors_and_leaves_the_root_alive() {
    let (mut child, stdin) = treewalk_blocker();
    let forced = force_proc_view_once(ForcedView::Diverged);
    let result = child.kill_tree();
    drop(forced);
    assert!(
        matches!(&result, Err(crate::error::Error::Unassessable { detail, .. }) if detail.contains("outer pid namespace")),
        "{result:?}"
    );
    drop(stdin);
    let status = child.wait().await.expect("reap the root");
    assert_eq!(status.signal(), None, "the root must not have been killed");
    assert_eq!(status.code(), Some(0));
}

/// Mutant: "skip the root kill on a snapshot failure".
#[tokio::test]
async fn drop_over_an_untrusted_view_warns_of_orphans_and_still_kills_the_root() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, _stdin) = treewalk_blocker();
    let id = child.id();
    let forced = force_proc_view_once(ForcedView::Diverged);
    drop(child);
    drop(forced);
    let records = crate::log_capture::records_since_on_current_thread(mark, "Child::drop");
    assert!(
        records
            .iter()
            .any(|(level, m)| *level == log::Level::Warn && m.contains("may be orphaned")),
        "{records:?}"
    );
    // The root outlives nothing else here (its stdin is held), so its death is the kill's doing.
    // Awaiting an exit that a mutant would never cause: the bound is the failure report.
    let exited = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        crate::tokio::Process::from_id(id).wait(),
    )
    .await;
    assert!(
        matches!(exited, Ok(Ok(()))),
        "the root must be killed by the drop: {exited:?}"
    );
}
