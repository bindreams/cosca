//! `Child::kill_tree` and `Drop` over a `TreeWalk` child whose process snapshot cannot be taken.
//! Linux only: the view seam is `identity::proc_view_fault`.

use std::os::unix::process::ExitStatusExt;

use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};

fn treewalk_blocker() -> (crate::Child, std::io::PipeWriter) {
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), crate::containment::Containment::TreeWalk);
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// The walk could not find the descendants, and killing the root first would reparent them out of
/// any retry's reach: nothing is killed, the root included, and the error is returned. Mutant: "run
/// the handle backstop after a snapshot failure".
#[skuld::test]
fn kill_tree_over_an_untrusted_view_errors_and_leaves_the_root_alive() {
    let (child, stdin) = treewalk_blocker();
    let forced = force_proc_view_once(ForcedView::Diverged);
    let result = child.kill_tree();
    drop(forced);
    assert!(
        matches!(&result, Err(crate::error::Error::Unassessable { detail, .. }) if detail.contains("outer pid namespace")),
        "{result:?}"
    );
    drop(stdin);
    let status = child.wait().expect("reap the root");
    assert_eq!(status.signal(), None, "the root must not have been killed");
    assert_eq!(status.code(), Some(0));
}

/// A retry once the view recovers finds the tree and kills it.
#[skuld::test]
fn kill_tree_succeeds_on_a_retry_after_the_view_recovers() {
    let (child, _stdin) = treewalk_blocker();
    let forced = force_proc_view_once(ForcedView::Diverged);
    child.kill_tree().expect_err("the first attempt fails");
    drop(forced);
    child.kill_tree().expect("the retry finds the tree");
    assert_eq!(child.wait().expect("reap").signal(), Some(libc::SIGKILL));
}

/// `Drop` cannot retry, so it still kills the root through its handle, and says descendants may be
/// orphaned. Mutant: "skip the root kill on a snapshot failure" (the root would outlive its
/// handle).
#[skuld::test]
fn drop_over_an_untrusted_view_kills_the_root_and_warns_of_orphans() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, _stdin) = treewalk_blocker();
    let id = child.id();
    // The drop reads the root's number first, which would consume the one-shot forced view before
    // the tree kill sees it: pin that read to "still this root".
    let _root_read = crate::child::fault::force_next_root_read(crate::identity::Resolved::Found(id));
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
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "the root must be killed and reaped"
    );
}
