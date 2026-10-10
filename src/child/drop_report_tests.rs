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

/// A cleanup that warned and then left its handle armed (the root kill was refused): the handle's
/// drop retries, and the retry does not warn of the same event again.
///
/// Mutant: the drop's report ignores that the cleanup already warned.
#[skuld::test]
fn a_retried_cleanup_does_not_warn_of_its_event_twice() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, writer) = session_blocker();
    let teardowns = crate::child::fault::record_root_teardowns();
    let mark = crate::log_capture::mark();
    let err_peek = || Err(std::io::Error::other("forced peek failure"));
    // The cleanup's read, then the drop's.
    let _looks = crate::wait::exit_only::seams::force_peeks([err_peek(), err_peek()]);
    let refused = crate::signal::seams::refuse_kills();

    let err = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");

    assert_peeks_exhausted();
    assert_eq!(teardowns.count(), 1, "the handle's drop retries ({err:?})");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].starts_with("finish_elevated:") && warns[0].contains("RootState::Unknown"),
        "{warns:?}"
    );
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

/// A handle that could not say, when the root's number shows it reaped: the doubt is not dropped
/// silently. The `debug` record names the caller and the handle's error.
///
/// Mutant: `DropView::read` discards the handle's `Unknown` once the number shows the reap.
#[skuld::test]
fn a_handle_that_could_not_say_is_logged_when_the_number_shows_the_reap() {
    crate::log_capture::install();
    let (child, _writer) = session_blocker();
    let mark = crate::log_capture::mark();
    let _number = crate::child::fault::force_next_root_read(crate::identity::Resolved::Gone);
    let _failed = force_peek_once(Err(std::io::Error::other("handle doubt 6e2")));

    let view =
        crate::containment::DropView::read("labelled-reader", child.id, || child.proc.state(), &child.tree_killed);

    assert_peeks_exhausted();
    assert!(
        matches!(view.root, crate::containment::dispatch::RootView::Reaped),
        "{:?}",
        view.root
    );
    let records = crate::log_capture::records_since_on_current_thread(mark, "handle doubt 6e2");
    assert_eq!(records.len(), 1, "{records:?}");
    assert!(
        records[0].0 == log::Level::Debug && records[0].1.starts_with("labelled-reader:"),
        "{records:?}"
    );
}

/// A trusted root's number is never untrusted, so nothing asks why: the answer would be a lie. A
/// debug build asserts it.
///
/// Mutant: the `Trusted` arm answers "already reaped".
#[skuld::test]
fn asking_why_a_trusted_root_is_untrusted_is_a_contract_breach() {
    let view = crate::containment::DropView {
        root_pid: 1,
        root: crate::containment::dispatch::RootView::Trusted,
        tree_killed: false,
    };

    let asked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| view.why_number_untrusted()));

    assert!(asked.is_err(), "a trusted root has no untrusted number to explain");
}
