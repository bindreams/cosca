//! The async `Child`'s backend answers [`RootState`] from its own handle, and tells its own reap
//! from a reap by someone else.

use crate::signal::RootState;
use crate::tokio::Command;

/// Every record at `warn` or above that this thread logged since `mark`.
pub(super) fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

/// This handle's own reap is `Reaped`, is not a reap by someone else, and nothing around it warns.
///
/// Mutant: `elsewhere` has no `id().is_some()` guard, so `forget_if_foreign` forgets tokio's own reap.
#[skuld::test]
async fn state_after_own_wait_is_reaped_without_a_warn() {
    crate::log_capture::install();
    let mut child = Command::new().args(["true"]).spawn().expect("spawn");
    child.wait().await.expect("wait");

    let mark = crate::log_capture::mark();
    let state = child.proc_mut().state();
    let forgot = child.proc_mut().forget_if_foreign();
    drop(child);

    assert!(matches!(state, RootState::Reaped), "{state:?}");
    assert_eq!(forgot, None, "this handle reaped the child itself");
    assert_eq!(warns_since(mark), Vec::<String>::new());
}

/// A `kill` after a completed `wait` is `Ok` and leaves the cached status for the next `wait`.
///
/// Mutant: `elsewhere` includes tokio's own reap, so the kill forgets tokio's `Child` and
/// the second `wait` answers `ECHILD`.
#[skuld::test]
async fn tokio_kill_after_a_completed_wait_keeps_the_cached_status() {
    crate::log_capture::install();
    let mut child = Command::new().args(["true"]).spawn().expect("spawn");
    let status = child.wait().await.expect("wait");

    let mark = crate::log_capture::mark();
    child.kill().expect("a kill after the child's own reap answers Ok");
    let again = child.wait().await.expect("the cached status survives the kill");

    assert_eq!(again, status);
    assert_eq!(warns_since(mark), Vec::<String>::new());
}

#[cfg(target_os = "linux")]
pub(super) fn session_blocker(kill_on_drop: bool) -> (crate::tokio::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    cmd.kill_on_drop(kill_on_drop);
    (cmd.spawn().expect("spawn"), writer)
}

#[cfg(target_os = "linux")]
pub(super) fn failed_peek(what: &str) -> std::io::Result<crate::wait::exit_only::Peek> {
    Err(std::io::Error::other(what.to_owned()))
}

/// A tokio drop whose root stays `Unknown` through both looks warns once, and the warn carries
/// what forgetting tokio's `Child` leaks. The drop makes exactly two looks (the read and the
/// second look), so exactly two peeks are forced.
///
/// Mutants: the skip warns; the second look warns; the forget warns; the warn omits the leak.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_tokio_drop_with_an_unknown_root_warns_once() {
    use crate::wait::exit_only::seams::force_peeks;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    let _failed = force_peeks([failed_peek("forced"), failed_peek("forced")]);

    drop(child);

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "one warn for the event: {warns:?}");
    assert!(
        warns[0].contains("RootState::Unknown")
            && warns[0].contains(&format!("pgid {pid}"))
            && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// An unknown root behind a live elevation front the drop leaves running is one event, so one
/// warn: it names the unknown state, the front and the leak.
///
/// Mutants: the drop warns of the front apart from the unknown root; the one warn omits the front.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_tokio_drop_with_an_unknown_root_behind_a_closed_front_gate_warns_once() {
    use crate::wait::exit_only::seams::force_peeks;
    use crate::wait::exit_only::Peek;

    crate::log_capture::install();
    let recorder = crate::containment::unix::fault::record_kill_group();
    let (mut child, _writer) = session_blocker(true);
    child.set_front(Some(crate::elevation::front::Front::Sudo));
    let mark = crate::log_capture::mark();
    // The read, then the gate's look at the front (it runs), then the second look.
    let _failed = force_peeks([failed_peek("forced"), Ok(Peek::Running), failed_peek("forced")]);

    drop(child);

    assert_eq!(recorder.killed(), Vec::<i32>::new());
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "one warn for the event: {warns:?}");
    assert!(
        warns[0].contains("RootState::Unknown") && warns[0].contains("left running") && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// One forget policy: an unsettled root is forgotten quietly, the leak left to the caller's one
/// warn; any other root only on evidence, with a warn of its own; a root still shown ours is not
/// forgotten.
///
/// Mutants: `forget_for` forgets an unsettled root loudly; forgets a trusted root quietly; forgets
/// without evidence.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn forget_for_forgets_an_unsettled_root_quietly_and_any_other_with_its_own_warn() {
    use crate::containment::dispatch::RootView;
    use crate::containment::DropView;
    use crate::wait::exit_only::seams::force_peek_once;

    crate::log_capture::install();
    let view = |root| DropView {
        root_pid: 1,
        root,
        tree_killed: false,
    };

    let (mut child, _writer) = session_blocker(false);
    let mark = crate::log_capture::mark();
    let _failed = force_peek_once(failed_peek("forced"));
    let forgot = child
        .proc_mut()
        .forget_for(&view(RootView::Unknown(std::io::Error::other("first look"))))
        .expect("an unsettled root the second look cannot show ours is forgotten");
    assert!(forgot.quiet && forgot.now.is_some(), "{forgot:?}");
    assert_eq!(warns_since(mark), Vec::<String>::new());

    let (mut child, _writer) = session_blocker(false);
    let mark = crate::log_capture::mark();
    let _failed = force_peek_once(failed_peek("forced"));
    let forgot = child
        .proc_mut()
        .forget_for(&view(RootView::Trusted))
        .expect("a trusted root the second look cannot show ours is forgotten");
    assert!(!forgot.quiet, "{forgot:?}");
    let warns = warns_since(mark);
    assert!(warns.len() == 1 && warns[0].contains(forgot.leak), "{warns:?}");

    let (mut child, _writer) = session_blocker(false);
    assert!(child.proc_mut().forget_for(&view(RootView::Trusted)).is_none());
    assert!(child
        .proc_mut()
        .forget_for(&view(RootView::Unknown(std::io::Error::other("x"))))
        .is_none());
}

/// A refused root kill with an unknown root forgets tokio's `Child` once, under the same one warn.
///
/// Mutant: the failed-kill path forgets with its own warn, besides the drop's.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_tokio_drop_whose_kill_fails_on_an_unknown_root_warns_once() {
    use crate::wait::exit_only::seams::force_peeks;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let mark = crate::log_capture::mark();
    let _failed = force_peeks([failed_peek("forced"), failed_peek("forced")]);
    let _kill = crate::tokio::child::fault::force_kill_failure();

    drop(child);

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("RootState::Unknown") && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// An `Unknown` seen only on the second look is logged with its error.
///
/// Mutant: the second look is quiet.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn an_unknown_seen_only_on_the_second_look_names_its_error() {
    use crate::wait::exit_only::seams::force_peeks;
    use crate::wait::exit_only::Peek;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let mark = crate::log_capture::mark();
    let _failed = force_peeks([Ok(Peek::Running), failed_peek("second look failure 91")]);

    drop(child);

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("second look failure 91"), "{warns:?}");
}

/// A disarmed drop kills nothing, so its warn does not speak of a skipped kill.
///
/// Mutant: the warn always says "so it does not".
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_disarmed_drop_with_an_unknown_root_does_not_claim_a_skipped_kill() {
    use crate::wait::exit_only::seams::force_peeks;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(false);
    let mark = crate::log_capture::mark();
    let _failed = force_peeks([failed_peek("forced"), failed_peek("forced")]);

    drop(child);

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(!warns[0].contains("does not"), "{warns:?}");
}

/// A failed spawn's cleanup whose root kill is refused, on an `Unknown` root: tokio's `Child` is
/// forgotten once, under the one warn, which carries the leak.
///
/// Mutant: the refused-kill arm forgets with its own warn, besides the cleanup's.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn finish_elevated_with_an_unknown_root_and_a_refused_kill_warns_once() {
    use crate::wait::exit_only::seams::force_peeks;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let mark = crate::log_capture::mark();
    let _failed = force_peeks([failed_peek("forced"), failed_peek("forced")]);
    let _kill = crate::tokio::child::fault::force_kill_failure();

    let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
        .expect_err("the spawn fails");

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
    assert!(
        warns[0].starts_with("finish_elevated:")
            && warns[0].contains("RootState::Unknown")
            && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// A failed spawn's cleanup whose wait finds the child reaped behind its back, on an `Unknown`
/// root: tokio's `Child` is forgotten once, under the one warn, which carries the leak.
///
/// Mutants: the wait's forget warns on its own; the cleanup forgets with `forget_foreign`.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn finish_elevated_with_an_unknown_root_and_a_foreign_reap_during_the_wait_warns_once() {
    use crate::wait::exit_only::seams::force_peeks;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    let _failed = force_peeks([failed_peek("forced")]);
    let _reap = crate::child::spawn::fault::set_between_kill_and_wait(move || {
        super::child_reap_tests::reap_behind_the_owner(pid);
    });

    let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
        .expect_err("the spawn fails");

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
    assert!(
        warns[0].starts_with("finish_elevated:")
            && warns[0].contains("RootState::Unknown")
            && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// A failed spawn's cleanup whose wait finds a trusted root reaped behind its back: tokio's `Child`
/// is forgotten once, under one warn that names the foreign reap and carries the leak.
///
/// Mutants: the wait's forget logs nothing and the cleanup's warn omits it; the wait's forget warns
/// on its own, besides the cleanup's.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn finish_elevated_with_a_trusted_root_and_a_foreign_reap_during_the_wait_warns_once() {
    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let pid = child.id().pid();
    let mark = crate::log_capture::mark();
    let _reap = crate::child::spawn::fault::set_between_kill_and_wait(move || {
        super::child_reap_tests::reap_behind_the_owner(pid);
    });

    let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
        .expect_err("the spawn fails");

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
    assert!(
        warns[0].starts_with("finish_elevated:")
            && warns[0].contains("reaped by someone else")
            && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// The same for a root already gone when the kill is sent (`Sent::Gone`): the cleanup forgets
/// tokio's `Child` and carries the leak in its own warn, not the handle's drop's.
///
/// Mutants: the `Gone` arm leaves the forget to the drop of the handle; the kill's own forget warns.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn finish_elevated_with_an_unknown_root_that_is_already_gone_warns_once() {
    use crate::wait::exit_only::seams::force_peeks;

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, writer) = session_blocker(true);
    drop(writer);
    super::child_reap_tests::reap_behind_the_owner(child.id().pid());
    let mark = crate::log_capture::mark();
    // The number still reads as the root, as after a same-tick reuse.
    let _number = crate::child::fault::force_next_root_read(crate::identity::Resolved::Found(child.id()));
    let _failed = force_peeks([failed_peek("forced"), failed_peek("forced")]);

    let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
        .expect_err("the spawn fails");

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
    assert!(
        warns[0].starts_with("finish_elevated:") && warns[0].contains("leaks"),
        "{warns:?}"
    );
}

/// When the second look shows the child reaped by someone else, the warn says so rather than
/// "could not say whether it was reaped".
///
/// Mutant: the warn names only the first look.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_second_look_that_shows_a_foreign_reap_is_named() {
    use crate::wait::exit_only::seams::force_peeks;
    use crate::wait::exit_only::{Foreign, Peek};

    crate::log_capture::install();
    let _recorder = crate::containment::unix::fault::record_kill_group();
    let (child, _writer) = session_blocker(true);
    let mark = crate::log_capture::mark();
    let _looks = force_peeks([failed_peek("forced"), Ok(Peek::Foreign(Foreign::Gone))]);

    drop(child);

    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("reaped by someone else"), "{warns:?}");
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use crate::send_log::{Capture, Via};
    use crate::signal::Sig;
    use crate::wait::exit_only::seams::force_peeks;
    use crate::wait::exit_only::{Foreign, Peek};

    fn walked_blocker() -> (crate::tokio::Child, std::io::PipeWriter) {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        cmd.contain_with(crate::ContainMode::TreeWalk);
        (cmd.spawn().expect("spawn"), writer)
    }

    /// A root launchd holds is not pinned by this process: nothing is sent to it, tokio's `Child`
    /// is forgotten, and the one warn names the leak.
    ///
    /// Mutant: `Unpinned` is `Unknown` (the drop kills by pid).
    #[skuld::test]
    async fn an_orphaned_root_is_not_signalled_and_warns_once() {
        crate::log_capture::install();
        let (child, _writer) = walked_blocker();
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        let orphaned = || Ok(Peek::Foreign(Foreign::Orphaned));
        let _orphaned = force_peeks([orphaned(), orphaned()]);

        drop(child);

        assert_eq!(sends.entries(), vec![], "nothing may be sent to a root we do not pin");
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(warns[0].contains("launchd") && warns[0].contains("leaks"), "{warns:?}");
    }

    /// Any other root we cannot get an answer for is still our unreaped child: still killed through
    /// its handle.
    ///
    /// Mutant: every `Unknown` leaves the root alone.
    #[skuld::test]
    async fn an_unknown_root_we_pin_is_still_killed_through_its_handle() {
        crate::log_capture::install();
        let (child, _writer) = walked_blocker();
        let pid = child.id().pid();
        let sends = Capture::start();
        let _failed = force_peeks([Err(std::io::Error::other("forced peek failure"))]);

        drop(child);

        assert_eq!(sends.entries(), vec![(pid, Sig::Kill, Via::Pid)]);
    }

    fn session_blocker() -> (crate::tokio::Child, std::io::PipeWriter) {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        cmd.contain_with(crate::ContainMode::Session);
        (cmd.spawn().expect("spawn"), writer)
    }

    /// Mutants: the holders-only sweep does not exclude the unpinned root; the sweep signals no
    /// holder at all (the control fails).
    #[skuld::test]
    async fn an_orphaned_root_in_a_session_tree_is_not_signalled_by_the_sweep() {
        crate::log_capture::install();
        let _groups = crate::containment::unix::fault::record_kill_group();
        let holders = crate::containment::fdmarker::fault::record_holder_kills();
        // Control: a root that is a marker holder is swept when the handle says it is reaped, so
        // the assertion below is not vacuous.
        let (control, _control_writer) = session_blocker();
        let control_pid = control.id().pid();
        let gone = force_peeks([Ok(Peek::Foreign(Foreign::Gone))]);
        drop(control);
        drop(gone);
        assert!(holders.killed().contains(&control_pid), "{:?}", holders.killed());

        let (child, _writer) = session_blocker();
        let pid = child.id().pid();
        let sends = Capture::start();
        let orphaned = || Ok(Peek::Foreign(Foreign::Orphaned));
        let _orphaned = force_peeks([orphaned(), orphaned()]);

        drop(child);

        assert_eq!(sends.entries(), vec![]);
        assert!(
            !holders.killed().contains(&pid),
            "swept the root: {:?}",
            holders.killed()
        );
    }

    /// Mutants: `finish_elevated` signals and waits on the root regardless; it leaves the forget and
    /// warn to the handle's drop.
    #[skuld::test]
    async fn finish_elevated_leaves_an_orphaned_root_alone() {
        crate::log_capture::install();
        let (child, _writer) = walked_blocker();
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        // The cleanup's first look, then the second look of its own `forget_unsettled`.
        let orphaned = || Ok(Peek::Foreign(Foreign::Orphaned));
        let _orphaned = force_peeks([orphaned(), orphaned()]);

        let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
            .expect_err("the spawn fails");

        assert_eq!(sends.entries(), vec![]);
        assert!(err.to_string().contains("left alone"), "{err}");
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(warns[0].contains("launchd") && warns[0].contains("leaks"), "{warns:?}");
    }
}
