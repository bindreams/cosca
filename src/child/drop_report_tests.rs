//! One event, one warn: the sync `Child`'s drop and `finish_elevated` report an event once,
//! however many steps (the unsettled root, the refused kill, the failed reap) each had to say. Each
//! test forces the looks it counts on and asserts they were all made.

use crate::test_child::Console;
use crate::ContainMode;

/// Every record at `warn` or above that this thread logged since `mark`.
fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

/// One scripted refusal of a kill: the `EPERM` the kernel answers a signal to another user's process.
fn refused() -> crate::os_process::fake::SignalAnswer {
    crate::os_process::fake::failed_signal(libc::EPERM)
}

/// The OS's words for the `EPERM` that [`refused`] answers: the warn names the refusal as the OS
/// gave it.
fn refusal() -> String {
    std::io::Error::from_raw_os_error(libc::EPERM).to_string()
}

fn contained_blocker(mode: ContainMode) -> (crate::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(mode);
    (cmd.spawn().expect("spawn"), writer)
}

/// A child with no containment: nothing sweeps it before the root kill under test, on any platform
/// (a macOS fd marker's sweep kills the root, which holds the marker).
fn bare_blocker() -> (crate::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    (cmd.spawn().expect("spawn"), writer)
}

fn failed_write() -> Result<(), crate::error::Error> {
    Err(crate::error::Error::Io(std::io::Error::other("w")))
}

/// An unknown root whose kill the OS refuses: the unknown state and the refusal are one event, so
/// one warn that names both. (macOS: a refused unique-id read on a setuid child spawned without
/// `.elevate()` is this case.)
///
/// Mutant: `tear_down` warns of the refusal on its own, besides the drop's.
#[skuld::test]
fn an_unknown_root_with_a_refused_kill_warns_once() {
    crate::log_capture::install();
    let (mut child, writer) = bare_blocker();
    let mark = crate::log_capture::mark();
    let fake = child.proc.script_over(|f| {
        f.peeks([Err(std::io::Error::other("forced peek failure"))])
            .signals([refused()])
    });

    drop(child);
    drop(writer);

    fake.assert_peeks_exhausted();
    assert_eq!(fake.signal_calls(), [crate::signal::Sig::Kill], "the drop's kill");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].starts_with("Child::drop:")
            && warns[0].contains("RootState::Unknown")
            && warns[0].contains(&refusal()),
        "{warns:?}"
    );
}

/// The teardown of a root says what became of it under the caller's own name: a teardown after a
/// failed run leads its `debug` reap line with that name, not a drop's.
///
/// Mutant: `Child::tear_down` leads the clause with `TeardownCaller::Drop.label()`, whoever called.
#[skuld::test]
fn a_roots_reap_is_said_under_the_name_of_the_caller_that_tore_it_down() {
    use crate::containment::dispatch::TeardownCaller;

    crate::log_capture::install();
    let (mut child, writer) = bare_blocker();
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();

    let torn = child.tear_down(
        TeardownCaller::FailedRun,
        crate::child::owned::teardown::Disposition::Leave,
    );

    assert_eq!(torn.fate, crate::error::ChildFate::Reaped);
    assert_eq!(
        crate::log_capture::records_since_on_current_thread(mark, ""),
        [(
            log::Level::Debug,
            format!("teardown after a failed run: teardown of child {pid}: reaped it after the kill")
        )]
    );
    drop(writer);
}

/// A failed spawn's cleanup on an unknown root whose reap fails after the kill: the unknown state
/// and the failed reap are one event, so one warn that names both.
///
/// Mutant: the failed reap warns on its own, besides the unknown state's.
#[skuld::test]
fn finish_elevated_with_an_unknown_root_and_a_failed_reap_warns_once() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (mut child, writer) = contained_blocker(ContainMode::Session);
    let pid = child.id().pid();
    // Released once the cleanup's root kill returned, before its reap (the forced failure comes
    // after the reap, which records nothing): the root must be a zombie that died of `SIGKILL`.
    let _released = crate::child::spawn::fault::set_between_kill_and_wait(move || {
        drop(writer);
        crate::test_child::assert_zombie_sigkilled("the root", pid);
    });
    let mark = crate::log_capture::mark();
    let fake = child
        .proc
        .script_over(|f| f.peeks([Err(std::io::Error::other("forced peek failure"))]));
    crate::child::spawn::fault::set_force_reap_failure("cosca-unknown-reap-9d1c");

    let err = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");

    fake.assert_peeks_exhausted();
    assert!(
        crate::child::spawn::fault::take_force_reap_failure().is_none(),
        "the cleanup consumed the forced failure"
    );
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
    assert!(
        warns[0].starts_with("finish_elevated:")
            && warns[0].contains("RootState::Unknown")
            && warns[0].contains(&format!("the elevated child pid {pid}: the wait failed")),
        "{warns:?}"
    );
}

/// A failed spawn's cleanup on a `TreeWalk` child whose walk left only the root: the cleanup's own
/// kill of the root ends it, so the tree is settled. The error says nothing of a tree that could not
/// be killed, the cleanup warns of none, and the handle is disarmed. A walk that left a descendant is
/// still reported, in the error and the warn. Not on macOS, where `TreeWalk` mode is an fd marker.
///
/// Mutant: the cleanup reports the walk's error before the root's kill.
#[cfg(target_os = "linux")]
#[skuld::test]
fn finish_elevated_settles_a_walk_that_left_only_the_root_by_its_own_kill_of_the_root() {
    use crate::containment::treewalk::fault::LeftBehind;
    crate::log_capture::install();
    for (left, reported) in [(LeftBehind::Root, false), (LeftBehind::Descendant, true)] {
        let (child, writer) = crate::test_child::held_treewalk_blocker_leaving(left);
        let mark = crate::log_capture::mark();
        let drop_looks = crate::graceful_hooks::watch_for_a_second_look();

        let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
        let (cause, fate, _) = crate::test_child::expect_may_have_started_parts(failure.into(), writer);

        assert!(fate.not_running(), "{left:?}: {fate:?}");
        // A settled tree disarms the handle; an unsettled one is looked at again when it drops, and
        // that look is the armed drop's first act, whatever it then logs.
        assert_eq!(
            drop_looks.seen(),
            reported,
            "{left:?}: the handle is armed iff the tree was left"
        );
        let cause = cause.to_string();
        assert_eq!(
            cause.contains("its contained tree could not be killed"),
            reported,
            "{left:?}: {cause}"
        );
        // The handle left armed by an unsettled tree warns again when it drops; the cleanup's own
        // warn is the one counted.
        let warns: Vec<_> = warns_since(mark)
            .into_iter()
            .filter(|warn| warn.starts_with("finish_elevated:"))
            .collect();
        assert_eq!(warns.len(), usize::from(reported), "{left:?}: {warns:?}");
    }
}

/// A teardown whose walk left only the root, and whose root someone else had reaped when the
/// teardown's kill of it came, warns of nothing (the root is not running, whoever ended it) but does
/// not vouch for the tree: the walk saw the root running.
///
/// Mutants: the root counts as ended only when this handle's own kill ended it (`Reaped`, `Killed`);
/// the tree is marked killed.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_walk_that_left_only_the_root_is_settled_by_a_root_someone_else_reaped() {
    use crate::containment::treewalk::fault::LeftBehind;
    crate::log_capture::install();
    let (mut child, writer) = crate::test_child::held_treewalk_blocker_leaving(LeftBehind::Root);
    let mark = crate::log_capture::mark();
    child.proc.script_over(|f| {
        f.signals([refused()])
            .reaps([crate::os_process::fake::ReapAnswer::Foreign(
                crate::os_process::child::Foreign::Gone,
            )])
    });

    let torn = child.tear_down(
        crate::containment::dispatch::TeardownCaller::FailedRun,
        crate::child::owned::teardown::Disposition::Leave,
    );
    child.kill_on_drop = false;

    assert_eq!(torn.fate, crate::error::ChildFate::Gone);
    assert_eq!(warns_since(mark), Vec::<String>::new());
    assert!(!child.tree_killed.is_set(), "the walk saw the root running");
    drop(writer);
}

/// A failed spawn's cleanup whose root kill is refused, and whose root still runs, hands the root
/// back in the error and disarms the handle: the caller owns the root now, and the handle's drop does
/// not retry the kill. The cleanup's one warn is the refusal.
///
/// Mutants: the cleanup leaves the handle armed (the drop retries) and drops the root; the root is
/// not handed back.
#[skuld::test]
fn finish_elevated_hands_back_a_root_whose_kill_was_refused() {
    crate::log_capture::install();
    let (mut child, writer) = bare_blocker();
    let teardowns = crate::child::owned::seams::record_root_teardowns();
    let mark = crate::log_capture::mark();
    let fake = child.proc.script_over(|f| f.signals([refused()]));

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (_, fate, handed_back) = crate::test_child::expect_handed_back(failure.into(), writer);

    assert!(matches!(fate, crate::error::ChildFate::Running { .. }), "{fate:?}");
    assert_eq!(teardowns.count(), 0, "the handle is disarmed: its drop does not retry");
    assert_eq!(fake.signal_calls().len(), 1, "the cleanup's kill alone");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains(&refusal()), "{warns:?}");
    let status = handed_back.wait();
    assert!(status.success(), "the root exits on EOF: {status:?}");
}

/// A failed spawn's cleanup whose root kill is refused and whose look then fails: the root is
/// uncollected and the caller's, so it is handed back and the handle disarmed, though its fate is
/// `Unknown`.
///
/// Mutant: only a `Running` fate hands back (the handle's drop then retries and leaks the root).
#[skuld::test]
fn finish_elevated_hands_back_a_root_whose_kill_was_refused_and_look_failed() {
    crate::log_capture::install();
    let (mut child, writer) = bare_blocker();
    let teardowns = crate::child::owned::seams::record_root_teardowns();
    child.proc.script_over(|f| {
        f.signals([refused()])
            .reaps([crate::os_process::fake::ReapAnswer::Err(std::io::ErrorKind::Other)])
    });

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (_, fate, handed_back) = crate::test_child::expect_handed_back(failure.into(), writer);

    assert_eq!(fate, crate::error::ChildFate::Unknown);
    assert_eq!(teardowns.count(), 0, "the handle is disarmed: its drop does not retry");
    let status = handed_back.wait();
    assert!(status.success(), "the root exits on EOF: {status:?}");
}

/// A root whose kill was refused and whose look failed: the look's failure is in the cleanup's one
/// warn and in the error's detail, as the refusal is.
///
/// Mutant: the cleanup keeps the fate of the look and drops its error.
#[skuld::test]
fn finish_elevated_names_the_failure_of_the_look_after_a_refused_kill() {
    crate::log_capture::install();
    let (mut child, writer) = bare_blocker();
    let mark = crate::log_capture::mark();
    child.proc.script_over(|f| {
        f.signals([refused()])
            .reaps([crate::os_process::fake::ReapAnswer::Err(std::io::ErrorKind::Other)])
    });

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (cause, _, handed_back) = crate::test_child::expect_handed_back(failure.into(), writer);

    let failed_look = std::io::Error::from(std::io::ErrorKind::Other).to_string();
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains(&format!("the wait failed: {failed_look}")),
        "{warns:?}"
    );
    assert!(
        cause.to_string().contains(&format!("the wait failed: {failed_look}")),
        "{cause}"
    );
    handed_back.wait();
}

/// A root someone else reaped between the delivered kill and its reap is not the cleanup's to hand
/// back: the error carries no child, and the handle is disarmed.
///
/// Mutant: a failed wait hands the root back whatever failed it.
#[skuld::test]
fn finish_elevated_hands_back_nothing_when_the_root_was_reaped_elsewhere_after_the_kill() {
    crate::log_capture::install();
    let (mut child, writer) = bare_blocker();
    let teardowns = crate::child::owned::seams::record_root_teardowns();
    child.proc.script_over(|f| {
        f.signals([Ok(crate::signal::Sent::Delivered)])
            .reaps([crate::os_process::fake::ReapAnswer::Foreign(
                crate::os_process::child::Foreign::Gone,
            )])
    });

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (_, fate, handed_back) = crate::test_child::expect_may_have_started_parts(failure.into(), writer);

    assert_eq!(fate, crate::error::ChildFate::Killed);
    assert!(handed_back.is_none(), "a root reaped elsewhere is not handed back");
    assert_eq!(teardowns.count(), 0, "the handle is disarmed: its drop does not retry");
}

/// A root whose reap someone else made after the kill is not a failed kill or reap: the cleanup says
/// so at `debug` (principle 5) and warns of nothing.
///
/// Mutant: the cleanup lists the foreign reap among the leftovers, which the one warn reports.
#[skuld::test]
fn finish_elevated_logs_a_root_reaped_elsewhere_after_the_kill_at_debug() {
    crate::log_capture::install();
    let (mut child, writer) = bare_blocker();
    let mark = crate::log_capture::mark();
    child.proc.script_over(|f| {
        f.signals([Ok(crate::signal::Sent::Delivered)])
            .reaps([crate::os_process::fake::ReapAnswer::Foreign(
                crate::os_process::child::Foreign::Gone,
            )])
    });

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (_, _, handed_back) = crate::test_child::expect_may_have_started_parts(failure.into(), writer);

    assert!(handed_back.is_none());
    assert_eq!(warns_since(mark), Vec::<String>::new());
    let debug = crate::log_capture::records_since_on_current_thread(mark, "reaped by someone else");
    assert!(
        debug.len() == 1 && debug[0].0 == log::Level::Debug,
        "one debug record names the foreign reap: {debug:?}"
    );
}

/// A root whose kill was refused and which someone else had reaped when the look came: nothing is
/// handed back, `debug` says so, and the refusal stays in the debug line and in the error.
///
/// Mutant: the refusal's note is replaced by the wording of the foreign reap, which has no
/// refusal in it.
#[skuld::test]
fn finish_elevated_keeps_the_refusal_when_the_look_finds_the_root_reaped_elsewhere() {
    crate::log_capture::install();
    let (mut child, writer) = bare_blocker();
    let mark = crate::log_capture::mark();
    child.proc.script_over(|f| {
        f.signals([refused()])
            .reaps([crate::os_process::fake::ReapAnswer::Foreign(
                crate::os_process::child::Foreign::Gone,
            )])
    });

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (cause, fate, handed_back) = crate::test_child::expect_may_have_started_parts(failure.into(), writer);

    assert_eq!(fate, crate::error::ChildFate::Gone);
    assert!(handed_back.is_none());
    assert_eq!(warns_since(mark), Vec::<String>::new());
    let cause = cause.to_string();
    assert!(
        cause.contains(&format!(
            "could not be terminated ({}): reaped by someone else",
            refusal()
        )),
        "{cause}"
    );
    let debug = crate::log_capture::records_since_on_current_thread(mark, "reaped by someone else");
    assert!(
        debug.len() == 1 && debug[0].0 == log::Level::Debug && debug[0].1.contains(&refusal()),
        "{debug:?}"
    );
}

/// A root whose kill was refused and whose zombie launchd held when the look came (macOS): the one
/// warn and the error's note both say it is not ours to reap, and both keep the refusal.
///
/// Mutants: the launchd line replaces the refusal in the warn; or in the error's note.
#[skuld::test]
fn finish_elevated_keeps_the_refusal_when_the_look_finds_launchd_holding_the_root() {
    crate::log_capture::install();
    let (mut child, writer) = bare_blocker();
    let mark = crate::log_capture::mark();
    child.proc.script_over(|f| {
        f.signals([refused()])
            .reaps([crate::os_process::fake::ReapAnswer::Foreign(
                crate::os_process::child::Foreign::Orphaned,
            )])
    });

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (cause, fate, handed_back) = crate::test_child::expect_may_have_started_parts(failure.into(), writer);

    assert_eq!(fate, crate::error::ChildFate::Gone);
    assert!(handed_back.is_none());
    let clause = format!("could not be terminated ({}): not ours to reap (launchd", refusal());
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains(&clause), "{warns:?}");
    let cause = cause.to_string();
    assert!(cause.contains(&clause), "{cause}");
}

/// A root a delivered kill reached whose zombie launchd held when the wait came (macOS): the one
/// warn says it is not ours to reap, led by the root's name, and the root is `Killed`.
///
/// Mutant: the launchd line is not led by the root's name.
#[skuld::test]
fn finish_elevated_names_the_root_when_launchd_holds_it_after_a_delivered_kill() {
    crate::log_capture::install();
    let (mut child, writer) = bare_blocker();
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    child.proc.script_over(|f| {
        f.signals([Ok(crate::signal::Sent::Delivered)])
            .reaps([crate::os_process::fake::ReapAnswer::Foreign(
                crate::os_process::child::Foreign::Orphaned,
            )])
    });

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (cause, fate, handed_back) = crate::test_child::expect_may_have_started_parts(failure.into(), writer);

    assert_eq!(fate, crate::error::ChildFate::Killed);
    assert!(handed_back.is_none());
    let clause = format!("the elevated child pid {pid}: not ours to reap (launchd");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains(&clause), "{warns:?}");
    let cause = cause.to_string();
    assert!(cause.contains(&clause), "{cause}");
}

/// A failed spawn's cleanup whose reap fails after a delivered kill: the root is not shown
/// collected, so it is handed back and the handle is disarmed, and the handle's drop does not retry.
///
/// Mutant: the cleanup leaves the handle armed and drops the root (a retry that fails leaks it).
#[skuld::test]
fn finish_elevated_hands_back_a_root_whose_reap_failed_after_a_delivered_kill() {
    crate::log_capture::install();
    let (mut child, writer) = bare_blocker();
    let teardowns = crate::child::owned::seams::record_root_teardowns();
    let mark = crate::log_capture::mark();
    // The kill is scripted as delivered and sends nothing: the root exits when released, below.
    let fake = child.proc.script_over(|f| {
        f.signals([Ok(crate::signal::Sent::Delivered)])
            .reaps([crate::os_process::fake::ReapAnswer::Err(std::io::ErrorKind::Other)])
    });

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (_, fate, handed_back) = crate::test_child::expect_handed_back(failure.into(), writer);

    assert_eq!(fate, crate::error::ChildFate::Killed);
    assert_eq!(teardowns.count(), 0, "the handle is disarmed: its drop does not retry");
    assert_eq!(fake.signal_calls().len(), 1, "the cleanup's kill alone");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("the elevated child pid")
            && warns[0].contains(": the wait failed: ")
            && warns[0].ends_with("handed back to the caller in the error"),
        "{warns:?}"
    );
    let status = handed_back.wait();
    assert!(status.success(), "the root exits on EOF: {status:?}");
}

/// A child in a stand-in cgroup leaf whose first `cgroup.kill` write fails (a write to a directory),
/// with the write end of its stdin, the leaf's path and its `cgroup.kill`. The leaf's own `Drop` is
/// disarmed, so only the handle's drop may retry the kill. The directory is returned to outlive them.
#[cfg(target_os = "linux")]
fn child_in_a_leaf_whose_kill_fails() -> (
    crate::Child,
    std::io::PipeWriter,
    std::path::PathBuf,
    std::path::PathBuf,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-retry-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    let kill_file = leaf_path.join("cgroup.kill");
    std::fs::create_dir(&kill_file).expect("make cgroup.kill a directory");
    crate::child::spawn::fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let child = crate::child::spawn::spawn_uncommitted(&mut cmd).expect("spawn");
    child.attached.disarm();
    (child, writer, leaf_path, kill_file, dir)
}

/// A tree kill that fails in a cleanup that then kills the root: the tree is not settled, so the
/// handle stays armed, and its drop writes the kill again. The drop's kill fails again with what the
/// cleanup already warned of, so the drop's record is `debug`, and the cleanup's is the one warn.
///
/// Mutant: the drop's report warns again of what the cleanup warned of.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_retry_that_only_repeats_the_cleanups_warn_is_debug() {
    use crate::child::spawn::fault;

    crate::log_capture::install();
    let (child, writer, leaf_path, _kill_file, _dir) = child_in_a_leaf_whose_kill_fails();
    // The root is released once killed: a kill that sent nothing exits 0.
    let reaps = fault::record_teardown_reaps();
    let _hook = fault::set_between_kill_and_wait(move || drop(writer));
    let mark = crate::log_capture::mark();

    let err = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    drop(err);

    reaps.assert_killed();
    let marker = crate::child::spawn::teardown_warn_marker(&leaf_path);
    assert_eq!(
        crate::log_capture::levels_since(mark, &marker),
        [log::Level::Warn],
        "the cleanup's warn is the only one"
    );
    let drop_records = crate::log_capture::records_since_on_current_thread(mark, "Child::drop:");
    assert!(
        drop_records
            .iter()
            .any(|(level, text)| *level == log::Level::Debug && text.contains("contained-tree teardown")),
        "the drop retried the kill and said so at debug: {drop_records:?}"
    );
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
    let (child, writer, leaf_path, kill_file, _dir) = child_in_a_leaf_whose_kill_fails();
    // The failure ends once the root is killed: the retry finds a file it can write. The root is
    // released there too: a kill that sent nothing exits 0.
    let reaps = fault::record_teardown_reaps();
    let healed = kill_file.clone();
    let _hook = fault::set_between_kill_and_wait(move || {
        std::fs::remove_dir(&healed).expect("remove the directory");
        std::fs::write(&healed, b"").expect("create cgroup.kill");
        drop(writer);
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
    reaps.assert_killed();
}

/// A tree kill that fails in a cleanup whose root kill is refused: the root is handed back and the
/// handle disarmed, so no drop retries the tree kill. The cleanup retries it before it hands the
/// root back.
///
/// Mutant: the cleanup hands the root back without retrying a failed tree kill.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_tree_kill_is_retried_before_the_root_is_handed_back() {
    use crate::child::spawn::fault;

    crate::log_capture::install();
    let (mut child, writer, _leaf_path, kill_file, _dir) = child_in_a_leaf_whose_kill_fails();
    child.proc.script_over(|f| f.signals([refused()]));
    // The failure ends once the root's kill is refused: the retry finds a file it can write.
    let healed = kill_file.clone();
    let _hook = fault::set_between_kill_and_wait(move || {
        std::fs::remove_dir(&healed).expect("remove the directory");
        std::fs::write(&healed, b"").expect("create cgroup.kill");
    });

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (_, fate, handed_back) = crate::test_child::expect_handed_back(failure.into(), writer);

    assert!(matches!(fate, crate::error::ChildFate::Running { .. }), "{fate:?}");
    assert_eq!(
        std::fs::read(&kill_file).expect("read cgroup.kill"),
        crate::containment::cgroup::KILL_PAYLOAD,
        "the cleanup must retry the tree kill"
    );
    handed_back.wait();
}

/// A retry that killed the tree is not reported as a failed teardown: the one warn says the kill took
/// a retry and names the first failure, and the error no longer says the tree was not killed.
///
/// Mutant: the warn keeps the first failure's text, or the error keeps its note.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_tree_kill_that_worked_on_the_retry_is_reported_as_a_retry_not_a_failure() {
    use crate::child::spawn::fault;

    crate::log_capture::install();
    let (mut child, writer, leaf_path, kill_file, _dir) = child_in_a_leaf_whose_kill_fails();
    child.proc.script_over(|f| f.signals([refused()]));
    let healed = kill_file.clone();
    let _hook = fault::set_between_kill_and_wait(move || {
        std::fs::remove_dir(&healed).expect("remove the directory");
        std::fs::write(&healed, b"").expect("create cgroup.kill");
    });
    let mark = crate::log_capture::mark();

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (cause, _, handed_back) = crate::test_child::expect_handed_back(failure.into(), writer);

    let first = std::io::Error::from_raw_os_error(libc::EISDIR).to_string();
    let warns = warns_since(mark);
    let warn = warns
        .iter()
        .find(|warn| warn.contains(&leaf_path.display().to_string()))
        .unwrap_or_else(|| panic!("no warn names the tree: {warns:?}"));
    assert!(
        warn.contains("took a retry") && warn.contains(&first),
        "the warn says the kill took a retry, after: {first}: {warn}"
    );
    assert!(
        !warn.contains(crate::child::spawn::TREE_TEARDOWN_WARN),
        "the tree was killed: {warn}"
    );
    assert!(
        !cause.to_string().contains("could not be killed"),
        "the error blames no tree: {cause}"
    );
    handed_back.wait();
}

/// A retry that fails again puts its error in the one warn and in the error, after the first's.
///
/// Mutant: the retry's error is dropped.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_tree_kill_that_failed_on_the_retry_too_names_both_failures() {
    crate::log_capture::install();
    let (mut child, writer, leaf_path, _kill_file, _dir) = child_in_a_leaf_whose_kill_fails();
    child.proc.script_over(|f| f.signals([refused()]));
    // The first write fails with `EIO`, the retry's with `EISDIR` (`cgroup.kill` is a directory).
    let _first = crate::containment::cgroup::fault::fail_next_kill_write();
    let mark = crate::log_capture::mark();

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (cause, _, handed_back) = crate::test_child::expect_handed_back(failure.into(), writer);

    let first = std::io::Error::from_raw_os_error(libc::EIO).to_string();
    let retry = std::io::Error::from_raw_os_error(libc::EISDIR).to_string();
    let warns = warns_since(mark);
    let warn = warns
        .iter()
        .find(|warn| warn.contains(&leaf_path.display().to_string()))
        .unwrap_or_else(|| panic!("no warn names the tree: {warns:?}"));
    for text in [warn.as_str(), cause.to_string().as_str()] {
        assert!(
            text.contains(&first) && text.contains(&format!("the retry failed too ({retry})")),
            "both failures, first then the retry's: {text}"
        );
    }
    handed_back.wait();
}

/// A tree kill skipped because the root's state is unknown, and a root whose kill is refused and
/// which is handed back: the retry skips again and kills nothing, so the error still says the tree
/// was not killed. The tree is a ppid walk from the root's number, which an unknown root skips on
/// every kernel; a process group does not skip on Linux 6.9+, where the root's pidfd names it.
///
/// Mutant: the retry's `Ok` clears the note whether or not it killed the tree.
#[skuld::test]
fn a_skipped_tree_kill_keeps_its_note_when_the_root_is_handed_back() {
    crate::log_capture::install();
    let (mut child, writer) = contained_blocker(ContainMode::TreeWalk);
    child.proc.script_over(|f| {
        f.peeks([Err(std::io::Error::other("forced peek failure"))])
            .signals([refused()])
    });

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (cause, _, handed_back) = crate::test_child::expect_handed_back(failure.into(), writer);

    assert!(
        cause.to_string().contains("its contained tree was not killed"),
        "nothing killed the tree: {cause}"
    );
    handed_back.wait();
}

/// A tree kill skipped because the root's state is unknown has not killed the tree: a failed spawn's
/// cleanup leaves the handle armed, so its drop tries again. A killed root does not change that.
///
/// Mutant: a skipped kill marks the tree killed, which disarms the handle.
#[skuld::test]
fn finish_elevated_leaves_the_handle_armed_after_a_skipped_tree_kill() {
    crate::log_capture::install();
    let (mut child, writer) = contained_blocker(ContainMode::TreeWalk);
    child
        .proc
        .script_over(|f| f.peeks([Err(std::io::Error::other("forced peek failure"))]));
    let mark = crate::log_capture::mark();

    let failure = crate::child::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");
    let (cause, _, _) = crate::test_child::expect_may_have_started_parts(failure.into(), writer);

    assert!(
        cause.to_string().contains("its contained tree was not killed"),
        "nothing killed the tree: {cause}"
    );
    // An armed handle's drop looks at the tree again, at `debug` at least; a disarmed one says nothing.
    let drops = crate::log_capture::records_since_on_current_thread(mark, "Child::drop:");
    assert!(!drops.is_empty(), "the handle was disarmed by a kill that did not run");
}

/// A drop that skipped the tree kill (the root's state is unknown) has not killed the tree, so it
/// does not mark it.
///
/// Mutant: `settle` marks the tree killed for a kill that was skipped.
#[skuld::test]
fn a_teardown_that_skipped_the_tree_kill_does_not_mark_the_tree_killed() {
    crate::log_capture::install();
    let (mut child, writer) = contained_blocker(ContainMode::TreeWalk);
    child
        .proc
        .script_over(|f| f.peeks([Err(std::io::Error::other("forced peek failure"))]));

    let torn = child.tear_down(
        crate::containment::dispatch::TeardownCaller::FailedRun,
        crate::child::owned::teardown::Disposition::Leave,
    );

    assert!(torn.fate.not_running(), "{:?}", torn.fate);
    assert!(
        !child.tree_killed.is_set(),
        "a skipped kill does not mark the tree killed"
    );
    drop(writer);
}

/// A handle that could not say, when the root's number shows it reaped: the doubt is not dropped
/// silently. The `debug` record names the caller and the handle's error.
///
/// Mutant: `DropView::read` discards the handle's `Unknown` once the number shows the reap.
#[skuld::test]
fn a_handle_that_could_not_say_is_logged_when_the_number_shows_the_reap() {
    crate::log_capture::install();
    let (mut child, _writer) = contained_blocker(ContainMode::Session);
    let mark = crate::log_capture::mark();
    let _number = crate::child::fault::force_next_root_read(crate::identity::Resolved::Gone);
    let fake = child
        .proc
        .script_over(|f| f.peeks([Err(std::io::Error::other("handle doubt 6e2"))]));

    let view = crate::containment::DropView::read(
        crate::containment::dispatch::TeardownCaller::FailedRun,
        child.id,
        || child.proc.state(),
        &child.tree_killed,
    );

    fake.assert_peeks_exhausted();
    assert!(
        matches!(view.root, crate::containment::dispatch::RootView::Reaped),
        "{:?}",
        view.root
    );
    let records = crate::log_capture::records_since_on_current_thread(mark, "handle doubt 6e2");
    assert_eq!(records.len(), 1, "{records:?}");
    assert!(
        records[0].0 == log::Level::Debug && records[0].1.starts_with("teardown after a failed run:"),
        "{records:?}"
    );
}

/// A trusted root's number is never untrusted, so nothing asks why: the answer would be a lie. A
/// debug build asserts it.
///
/// Mutant: the `Trusted` arm answers "already reaped".
#[cfg(debug_assertions)] // the contract is a debug assertion: release has none to trigger
#[skuld::test]
fn asking_why_a_trusted_root_is_untrusted_is_a_contract_breach() {
    let view = crate::containment::DropView {
        caller: crate::containment::dispatch::TeardownCaller::Drop,
        root_pid: 1,
        root: crate::containment::dispatch::RootView::Trusted,
        tree_killed: false,
    };

    let asked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| view.why_number_untrusted()));

    assert!(asked.is_err(), "a trusted root has no untrusted number to explain");
}
