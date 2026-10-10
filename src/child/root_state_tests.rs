//! The sync `Child` asks its own handle whether the root is still its child: [`RootState`]. The
//! drop and the failed-spawn cleanup act on that answer, not on the root's start token alone.

use crate::signal::RootState;
use crate::Command;

/// Every record at `warn` or above that this thread logged since `mark`.
fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

/// This handle's own reap is `Reaped`, and nothing around it warns.
///
/// Mutants: `SharedChild::state` reads its own recorded reap as `Unreaped`; it has no check of the
/// recorded reap (the peek decides).
#[skuld::test]
fn state_after_own_wait_is_reaped_without_a_warn() {
    crate::log_capture::install();
    let child = Command::new().args(["true"]).spawn().expect("spawn");
    child.wait().expect("wait");

    let mark = crate::log_capture::mark();
    // A peek would say `Running`: only the recorded reap says `Reaped`.
    let running = crate::wait::exit_only::seams::force_peek_once(Ok(crate::wait::exit_only::Peek::Running));
    let state = child.proc.state();
    drop(running);
    drop(child);

    assert!(matches!(state, RootState::Reaped), "{state:?}");
    assert_eq!(warns_since(mark), Vec::<String>::new());
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::containment::unix::fault::record_kill_group;
    use crate::identity::fault::alias_token;
    use crate::identity::StartToken;
    use crate::send_log::{Capture, Via};
    use crate::signal::Sig;
    use crate::test_child::pid_reuse::{in_fresh_pid_ns, reap_behind_and_reuse, sigusr1_and_wait};
    use crate::test_groups::namespaces;
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    use crate::ContainMode;

    fn session_blocker() -> (crate::Child, std::io::PipeWriter) {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        cmd.contain_with(ContainMode::Session);
        (cmd.spawn().expect("spawn"), writer)
    }

    /// A process-group child reaped behind its back, its pid reused, and the reuser's start token
    /// aliased to the child's (a same-tick reuse): the number still reads as the root, so only the
    /// child's own pidfd shows the reap. The drop sends no `killpg` by the group's number.
    ///
    /// Mutant: the drop takes no evidence from the handle (`DropView::read` ignores
    /// `proc.state()`).
    fn drop_after_foreign_reap_and_same_tick_reuse_body() {
        let recorder = record_kill_group();
        let (child, writer) = session_blocker();
        assert!(
            child.attached.carries_recyclable_pgid(),
            "the test needs a number-named group kill"
        );
        let token = StartToken::from_raw(child.id().start_token_raw());
        drop(writer);
        let reuser = reap_behind_and_reuse(child.id().pid());
        let _alias = alias_token(reuser.id(), token);

        drop(child);

        assert_eq!(
            recorder.killed(),
            Vec::<i32>::new(),
            "no killpg by a reaped root's number"
        );
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
    }
    in_fresh_pid_ns!(
        namespaces_sync_pgroup_drop_after_foreign_reap_and_same_tick_reuse_sends_no_killpg,
        fixture_sync_pgroup_drop_alias_driver,
        fixture_sync_pgroup_drop_alias_init,
        drop_after_foreign_reap_and_same_tick_reuse_body
    );

    /// A peek that fails on the root's own pidfd cannot show the root is reaped or not: the drop
    /// names `RootState::Unknown`, skips the channels that name the tree by the root's number, and
    /// still kills the root, through its pidfd.
    ///
    /// Mutant: `Unknown` is taken as `Reaped` (no root kill, and the log names no `Unknown`).
    #[skuld::test]
    fn a_failed_root_peek_skips_number_named_channels_and_still_kills_the_root() {
        crate::log_capture::install();
        let recorder = record_kill_group();
        let (child, writer) = session_blocker();
        let pid = child.id().pid();
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));

        drop(child);
        drop(writer);

        assert_peeks_exhausted();
        assert!(
            crate::log_capture::contains_since(mark, "RootState::Unknown"),
            "the drop must name the unknown root state"
        );
        assert_eq!(
            recorder.killed(),
            Vec::<i32>::new(),
            "no killpg by an unconfirmed root's number"
        );
        assert_eq!(sends.entries(), vec![(pid, Sig::Kill, Via::Pidfd)]);
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "one warn for the event: {warns:?}");
        assert!(
            warns[0].contains(&format!("pgid {pid}")),
            "the warn names the group left alone: {warns:?}"
        );
        assert!(
            !crate::log_capture::contains_since(mark, "kill_tree()"),
            "no wait happened and kill_tree has no RootState gate: no remedy to name"
        );
    }

    /// The records are labelled by the caller: a failed spawn's cleanup does not call itself a drop,
    /// in the warn or in the read's `debug` line.
    ///
    /// Mutants: the report hardcodes "Child::drop"; `DropView::read` hardcodes "Child::drop"; the
    /// cleanup leaves the handle armed, so its drop warns "already reaped" about a `Child` the
    /// caller never received.
    #[skuld::test]
    fn the_unknown_warn_names_its_caller() {
        crate::log_capture::install();
        let _recorder = record_kill_group();
        let (child, _writer) = session_blocker();
        let mark = crate::log_capture::mark();
        // The number is unreadable too, so the read says so in a `debug` line of its own.
        let _number = crate::child::fault::force_next_root_read(crate::identity::Resolved::Unknown);
        let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));

        let err = crate::child::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
            .expect_err("the spawn fails");

        assert_peeks_exhausted();
        // The cleanup's error and the Unknown warn report it; the handle it drops afterwards is
        // disarmed and says nothing more.
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
        assert!(warns[0].starts_with("finish_elevated:"), "{warns:?}");
        let read = crate::log_capture::records_since_on_current_thread(mark, "could not be read either");
        assert_eq!(read.len(), 1, "{read:?}");
        assert!(read[0].1.starts_with("finish_elevated:"), "{read:?}");
    }

    /// An unknown root behind a live elevation front the drop leaves running is one event, so one
    /// warn: it names the unknown state and the front.
    ///
    /// Mutants: the drop warns of the unknown root before it checks the front's gate, then again
    /// of the front; the one warn omits the front.
    #[skuld::test]
    fn an_unknown_root_behind_a_closed_front_gate_warns_once() {
        crate::log_capture::install();
        let recorder = record_kill_group();
        let (mut child, writer) = session_blocker();
        child.set_front(Some(crate::elevation::front::Front::Sudo));
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        // The read sees the failed peek; the gate's own look at the front is real and sees it run.
        let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));

        drop(child);
        drop(writer);

        assert_peeks_exhausted();
        assert_eq!(recorder.killed(), Vec::<i32>::new());
        assert!(sends.entries().is_empty(), "{:?}", sends.entries());
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "one warn for the event: {warns:?}");
        assert!(
            warns[0].contains("RootState::Unknown") && warns[0].contains("left running"),
            "{warns:?}"
        );
    }

    /// With the root's number unreadable too, the debug line does not claim the root is treated as
    /// not reaped: its handle could not say, and the number-named kills are skipped.
    ///
    /// Mutant: the line keeps its "treating the root as not reaped" text.
    #[skuld::test]
    fn an_unknown_root_with_an_unreadable_number_does_not_claim_not_reaped() {
        crate::log_capture::install();
        let _recorder = record_kill_group();
        let (child, _writer) = session_blocker();
        let mark = crate::log_capture::mark();
        let _number = crate::child::fault::force_next_root_read(crate::identity::Resolved::Unknown);
        let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));

        drop(child);

        assert_peeks_exhausted();
        assert!(
            !crate::log_capture::contains_since(mark, "treating the root as not reaped"),
            "{:?}",
            crate::log_capture::records_since(mark, "number")
        );
        assert!(
            crate::log_capture::contains_since(mark, "could not be read either; kills by that number are skipped"),
            "the line must say what happens instead: {:?}",
            crate::log_capture::records_since(mark, "number")
        );
    }

    /// The same read, for a failed spawn's cleanup: the tree kill is skipped and the tree is not
    /// marked killed, so a later drop still warns about what was left.
    ///
    /// Mutant: the skip marks the tree killed (or runs the kill, which marks it).
    #[skuld::test]
    fn a_failed_root_peek_does_not_mark_the_tree_killed() {
        let recorder = record_kill_group();
        let (child, _writer) = session_blocker();
        let killed = crate::containment::TreeKilled::default();
        let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));
        let view = crate::containment::DropView::read("test", child.id, || child.proc.state(), &child.tree_killed);
        assert_peeks_exhausted();
        assert!(
            matches!(view.root, crate::containment::dispatch::RootView::Unknown(_)),
            "{:?}",
            view.root
        );

        let skipped = child
            .attached
            .hard_kill_marking_unless_reaped(&view, &killed)
            .expect("a skip is not an error");

        assert!(skipped.is_some(), "the number-named kill must be skipped");
        assert!(!killed.is_set(), "a skipped kill must not mark the tree killed");
        assert_eq!(recorder.killed(), Vec::<i32>::new());
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use crate::send_log::{Capture, Via};
    use crate::signal::Sig;
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once, force_peeks};
    use crate::wait::exit_only::{Foreign, Peek};
    use crate::ContainMode;

    /// A tree-walk child: the walk names no marker holder, so the only sends are the root's own.
    fn walked_blocker() -> (crate::Child, std::io::PipeWriter) {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        cmd.contain_with(ContainMode::TreeWalk);
        (cmd.spawn().expect("spawn"), writer)
    }

    /// A root launchd holds is not pinned by this process: it is neither signalled nor waited on by
    /// its pid, and the drop warns once.
    ///
    /// Mutant: `Unpinned` is `Unknown` (the drop kills by pid, and waits).
    #[skuld::test]
    fn an_orphaned_root_is_neither_signalled_nor_waited_on_and_warns_once() {
        crate::log_capture::install();
        let (child, writer) = walked_blocker();
        let pid = child.id().pid();
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        let _orphaned = force_peek_once(Ok(Peek::Foreign(Foreign::Orphaned)));

        drop(child);

        assert_peeks_exhausted();
        assert_eq!(sends.entries(), vec![], "nothing may be sent to a root we do not pin");
        assert!(
            crate::test_child::is_unreaped_child(pid),
            "the root was waited on: this process does not pin it"
        );
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(warns[0].contains("launchd"), "{warns:?}");
        // The test's own child ended and collected, since the drop left it alone.
        drop(writer);
        crate::test_child::wait_until_zombie(pid);
        // SAFETY: `pid` is this test's own zombie child.
        unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0) };
    }

    /// A root launchd holds, behind a live elevation front: the front is left running and the root
    /// is not pinned, which is one event, so one warn that names both.
    ///
    /// Mutants: the drop warns of the front apart from the unpinned root; the one warn omits the
    /// front.
    #[skuld::test]
    fn an_orphaned_root_behind_a_closed_front_gate_warns_once() {
        crate::log_capture::install();
        let (mut child, writer) = walked_blocker();
        let pid = child.id().pid();
        child.set_front(Some(crate::elevation::front::Front::Sudo));
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        // The read, then the gate's look at the front, which sees it run.
        let _looks = force_peeks([Ok(Peek::Foreign(Foreign::Orphaned)), Ok(Peek::Running)]);

        drop(child);

        assert_peeks_exhausted();
        assert_eq!(sends.entries(), vec![]);
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("launchd") && warns[0].contains("left running"),
            "{warns:?}"
        );
        drop(writer);
        crate::test_child::wait_until_zombie(pid);
        // SAFETY: `pid` is this test's own zombie child.
        unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0) };
    }

    /// Any other root we cannot get an answer for is still our unreaped child, pinned by us: the
    /// drop still kills it through its handle (the pid, checked against its unique id).
    ///
    /// Mutant: every `Unknown` leaves the root alone.
    #[skuld::test]
    fn an_unknown_root_we_pin_is_still_killed_through_its_handle() {
        crate::log_capture::install();
        let (child, writer) = walked_blocker();
        let pid = child.id().pid();
        let sends = Capture::start();
        let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));

        drop(child);
        drop(writer);

        assert_peeks_exhausted();
        assert_eq!(sends.entries(), vec![(pid, Sig::Kill, Via::Pid)]);
    }

    /// A Session (fd-marker) tree: its holders-only sweep must not signal the root, which holds the
    /// marker like any member but is not pinned by this process.
    fn session_blocker() -> (crate::Child, std::io::PipeWriter) {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        cmd.contain_with(ContainMode::Session);
        let child = cmd.spawn().expect("spawn");
        assert!(
            matches!(child.attached, crate::containment::Attached::FdMarker(_)),
            "the test needs an fd marker"
        );
        (child, writer)
    }

    /// Mutants: the holders-only sweep does not exclude the unpinned root; the sweep signals no
    /// holder at all (the control fails).
    #[skuld::test]
    fn an_orphaned_root_in_a_session_tree_is_not_signalled_by_the_sweep() {
        crate::log_capture::install();
        let _groups = crate::containment::unix::fault::record_kill_group();
        let holders = crate::containment::fdmarker::fault::record_holder_kills();
        // Control: a root that is a marker holder is swept when the handle says it is reaped, so
        // the assertion below is not vacuous.
        let (control, control_writer) = session_blocker();
        let control_pid = control.id().pid();
        let gone = force_peek_once(Ok(Peek::Foreign(Foreign::Gone)));
        drop(control);
        assert_peeks_exhausted();
        drop(gone);
        drop(control_writer);
        assert!(holders.killed().contains(&control_pid), "{:?}", holders.killed());

        let (child, writer) = session_blocker();
        let pid = child.id().pid();
        let sends = Capture::start();
        let _orphaned = force_peek_once(Ok(Peek::Foreign(Foreign::Orphaned)));

        drop(child);
        drop(writer);

        assert_peeks_exhausted();
        assert!(sends.entries().is_empty(), "{:?}", sends.entries());
        assert!(
            !holders.killed().contains(&pid),
            "swept the root: {:?}",
            holders.killed()
        );
    }

    /// A failed spawn's cleanup leaves an unpinned root alone, and its error says so.
    ///
    /// Mutant: `finish_elevated` signals and waits on the root regardless.
    #[skuld::test]
    fn finish_elevated_leaves_an_orphaned_root_alone() {
        crate::log_capture::install();
        let (child, writer) = walked_blocker();
        let sends = Capture::start();
        let mark = crate::log_capture::mark();
        let _orphaned = force_peek_once(Ok(Peek::Foreign(Foreign::Orphaned)));

        let (err, fate) =
            crate::child::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
                .expect_err("the spawn fails")
                .expect_may_have_started_with();
        drop(writer);

        assert_peeks_exhausted();
        assert!(sends.entries().is_empty(), "{:?}", sends.entries());
        assert!(err.to_string().contains("left alone"), "{err}");
        assert_eq!(
            fate,
            crate::error::ChildFate::Gone,
            "a launchd-held zombie, sent nothing, is gone"
        );
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(warns[0].contains("launchd"), "{warns:?}");
    }
}
