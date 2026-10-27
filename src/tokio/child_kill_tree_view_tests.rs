//! The async twin of `child/kill_tree_view_tests.rs`. Linux only.

use std::os::unix::process::ExitStatusExt;

use super::child_drop_tests::linux;
use crate::containment::cgroup::test_support::alone;
use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};
use crate::test_child::fixture_path;

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
#[skuld::test]
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

/// Mutant: "skip the root kill on a snapshot failure". The root's own status is the evidence: it is
/// read through a pidfd opened before the drop, and a root nothing killed exits `0` once its stdin
/// closes.
#[skuld::test]
async fn drop_over_an_untrusted_view_warns_of_orphans_and_still_kills_the_root() {
    if !alone(fixture_path!(
        drop_over_an_untrusted_view_warns_of_orphans_and_still_kills_the_root
    )) {
        return;
    }
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, stdin) = treewalk_blocker();
    let id = child.id();
    let root = linux::Pidfd::of(&child);
    // The drop reads the root's number first, which would consume the one-shot forced view before
    // the tree kill sees it: pin that read to "still this root".
    let _root_read = crate::child::fault::force_next_root_read(crate::identity::Resolved::Found(id));
    let forced = force_proc_view_once(ForcedView::Diverged);
    let sends = crate::send_log::Capture::start();
    drop(child);
    drop(forced);
    let records = crate::log_capture::records_since_on_current_thread(mark, "Child::drop");
    assert!(
        records
            .iter()
            .any(|(level, m)| *level == log::Level::Warn && m.contains("may be orphaned")),
        "{records:?}"
    );
    // Released after the drop, which does not wait: the root's stdin never ends it on its own here.
    let ended = root.ended_after_closing(stdin);
    assert!(
        matches!(
            ended,
            linux::Ended::Signalled(libc::SIGKILL) | linux::Ended::ReapedWhileStdinOpen
        ),
        "the drop must kill the root with SIGKILL, got {ended:?}"
    );
    assert!(
        sends
            .entries()
            .contains(&(id.pid(), crate::signal::Sig::Kill, crate::send_log::Via::Pidfd)),
        "the root must be killed through its pidfd: {:?}",
        sends.entries()
    );
}
