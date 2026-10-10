//! One event, one warn: the sync `Child`'s drop and `finish_elevated` report an event once,
//! however many steps (the unsettled root, the refused kill, the failed reap) each had to say. Each
//! test forces the looks it counts on and asserts they were all made.

use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
use crate::{Command, ContainMode};

/// Every record at `warn` or above that this thread logged since `mark`.
fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

fn session_blocker() -> (crate::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(ContainMode::Session);
    (cmd.spawn().expect("spawn"), writer)
}

fn failed_write() -> Result<(), crate::error::Error> {
    Err(crate::error::Error::Io(std::io::Error::other("w")))
}

/// An unknown root whose kill the OS refuses: the unknown state and the refusal are one event, so
/// one warn that names both. (macOS: a refused unique-id read on a setuid child spawned without
/// `.elevate()` is this case.)
///
/// Mutant: `teardown_on_drop` warns of the refusal on its own, besides the drop's.
#[skuld::test]
fn an_unknown_root_with_a_refused_kill_warns_once() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, writer) = session_blocker();
    let mark = crate::log_capture::mark();
    let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    let _refused = crate::signal::seams::refuse_kills();

    drop(child);
    drop(writer);

    assert_peeks_exhausted();
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].starts_with("Child::drop:")
            && warns[0].contains("RootState::Unknown")
            && warns[0].contains("permission denied"),
        "{warns:?}"
    );
}

/// A failed spawn's cleanup on an unknown root whose reap fails after the kill: the unknown state
/// and the failed reap are one event, so one warn that names both.
///
/// Mutant: the failed reap warns on its own, besides the unknown state's.
#[skuld::test]
fn finish_elevated_with_an_unknown_root_and_a_failed_reap_warns_once() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker();
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));
    crate::child::spawn::fault::set_force_reap_failure("cosca-unknown-reap-9d1c");

    let err = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");

    assert_peeks_exhausted();
    assert!(
        crate::child::spawn::fault::take_force_reap_failure().is_none(),
        "the cleanup consumed the forced failure"
    );
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
    assert!(
        warns[0].starts_with("finish_elevated:")
            && warns[0].contains("RootState::Unknown")
            && warns[0].contains(&format!("could not reap the killed elevated child pid {pid}")),
        "{warns:?}"
    );
}

/// A failed spawn's cleanup whose root kill is refused has not settled the root, so it leaves the
/// handle armed and the handle's drop retries the kill. The cleanup said nothing, so the retry's
/// refusal is the one warn.
///
/// Mutant: the cleanup disarms the handle whatever became of the root.
#[skuld::test]
fn finish_elevated_leaves_the_handle_armed_when_the_root_kill_was_refused() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, writer) = session_blocker();
    let teardowns = crate::child::fault::record_root_teardowns();
    let mark = crate::log_capture::mark();
    let refused = crate::signal::seams::refuse_kills();

    let err = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");

    assert_eq!(
        teardowns.count(),
        1,
        "the handle's drop retries the refused root kill ({err:?})"
    );
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("permission denied"), "{warns:?}");
    drop(refused);
    drop(writer);
}

/// A tree kill that fails once, in a cleanup that then kills the root: the tree is not settled, so
/// the handle stays armed and its drop writes the kill again, now that it can succeed. The failed
/// kill is the one warn.
///
/// Mutant: the cleanup disarms the handle whatever became of the tree.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_transient_tree_kill_failure_is_retried_by_the_drop() {
    use crate::child::spawn::fault;

    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-retry-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    let kill_file = leaf_path.join("cgroup.kill");
    // A write to a directory fails: the leaf's first kill is refused.
    std::fs::create_dir(&kill_file).expect("make cgroup.kill a directory");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let child = crate::child::spawn::spawn_uncommitted(&mut cmd).expect("spawn");
    // Rule out the leaf's own `Drop`: only the handle's drop may retry.
    child.attached.disarm();
    // The failure ends once the root is killed: the retry finds a file it can write.
    let healed = kill_file.clone();
    let _hook = fault::set_between_kill_and_wait(move || {
        std::fs::remove_dir(&healed).expect("remove the directory");
        std::fs::write(&healed, b"").expect("create cgroup.kill");
    });
    let mark = crate::log_capture::mark();

    let err = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");

    assert_eq!(
        std::fs::read(&kill_file).expect("read cgroup.kill"),
        crate::containment::cgroup::KILL_PAYLOAD,
        "the handle's drop must retry the tree kill ({err:?})"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, &crate::child::spawn::teardown_warn_marker(&leaf_path)),
        [log::Level::Warn],
        "the failed kill is reported once, and the retry adds nothing"
    );
}
