//! One event, one warn: every path of the async `Child`'s drop and of `finish_elevated` reports an
//! event once, however many steps (the front, the skipped kills, the forget, the failed signal)
//! each had to say. Each test forces the looks it counts on and asserts they were all made.

#[cfg(target_os = "linux")]
mod linux {
    use super::super::root_state_tests::{failed_peek, session_blocker, warns_since};
    use crate::os_process::child::{Foreign, PeekOutcome};
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peeks};

    fn gone() -> std::io::Result<PeekOutcome> {
        Ok(PeekOutcome::Foreign(Foreign::Gone))
    }

    fn running() -> std::io::Result<PeekOutcome> {
        Ok(PeekOutcome::Running)
    }

    /// A trusted root behind a closed front gate whose second look shows a foreign reap: the forget is
    /// the one event, so one warn, and it does not claim the root is left running.
    ///
    /// Mutants: the forget warns on its own, besides the drop's; the drop's "left running" warn follows
    /// a second look that showed the reap.
    #[skuld::test]
    async fn a_closed_front_and_a_second_look_that_shows_a_reap_warn_once_without_claiming_it_runs() {
        crate::log_capture::install();
        let _recorder = crate::containment::unix::fault::record_kill_group();
        let (mut child, _writer) = session_blocker(true);
        child.set_front(Some(crate::elevation::front::Front::Sudo));
        let mark = crate::log_capture::mark();
        // The gate's two looks at the front, the read, then the second look.
        let _looks = force_peeks([running(), running(), running(), gone()]);

        drop(child);

        assert_peeks_exhausted();
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("reaped by someone else") && warns[0].contains("leaks"),
            "{warns:?}"
        );
        assert!(
            !warns[0].contains("elevation front pid"),
            "the reap was seen: {warns:?}"
        );
    }

    /// The same drop whose second look shows the root still ours: the front is left running, and that is
    /// the one warn. Nothing is forgotten.
    ///
    /// Mutant: the second look forgets a root it shows ours.
    #[skuld::test]
    async fn a_closed_front_and_a_second_look_that_shows_the_root_ours_warn_once_about_the_front() {
        crate::log_capture::install();
        let _recorder = crate::containment::unix::fault::record_kill_group();
        let (mut child, _writer) = session_blocker(true);
        child.set_front(Some(crate::elevation::front::Front::Sudo));
        let forgets = crate::tokio::child::drop_fault::record();
        let mark = crate::log_capture::mark();
        let _looks = force_peeks([running(), running(), running(), running()]);

        drop(child);

        assert_peeks_exhausted();
        assert_eq!(forgets.forgets(), 0);
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("elevation front pid") && !warns[0].contains("leaks"),
            "{warns:?}"
        );
    }

    /// A root the handle shows reaped behind a closed front gate: the forget on that evidence is the one
    /// event, so one warn, and a reaped root is not "left running".
    ///
    /// Mutants: the forget warns on its own; the front's "left running" warn follows.
    #[skuld::test]
    async fn a_reaped_root_behind_a_closed_front_gate_warns_once_without_claiming_it_runs() {
        crate::log_capture::install();
        let _recorder = crate::containment::unix::fault::record_kill_group();
        let (mut child, _writer) = session_blocker(true);
        child.set_front(Some(crate::elevation::front::Front::Sudo));
        let mark = crate::log_capture::mark();
        // The gate's two looks at the front see it run; the read shows the reap.
        let _looks = force_peeks([running(), running(), gone()]);

        drop(child);

        assert_peeks_exhausted();
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("reaped by someone else") && warns[0].contains("leaks"),
            "{warns:?}"
        );
        assert!(!warns[0].contains("elevation front pid"), "{warns:?}");
    }

    /// A reaped root in a process group: the skipped `killpg` and the forget of tokio's `Child` are one
    /// event, so one warn that names both.
    ///
    /// Mutants: the skip warns on its own; the forget warns on its own.
    #[skuld::test]
    async fn a_reaped_root_in_a_process_group_warns_once_for_the_skip_and_the_forget() {
        #[cfg(target_os = "linux")]
        let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
        crate::log_capture::install();
        let recorder = crate::containment::unix::fault::record_kill_group();
        let (child, _writer) = session_blocker(true);
        let mark = crate::log_capture::mark();
        let _looks = force_peeks([gone()]);

        drop(child);

        assert_peeks_exhausted();
        assert_eq!(
            recorder.killed(),
            Vec::<i32>::new(),
            "no killpg by a reaped root's number"
        );
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("does not kill its process group") && warns[0].contains("leaks"),
            "{warns:?}"
        );
    }

    /// A trusted root whose second look shows a foreign reap, with no front: the forget is the one
    /// warn, and it names the reap and the leak.
    ///
    /// Mutant: the forget warns on its own and the drop adds a second.
    #[skuld::test]
    async fn a_second_look_that_shows_a_reap_after_the_kills_warns_once() {
        crate::log_capture::install();
        let _recorder = crate::containment::unix::fault::record_kill_group();
        let (child, _writer) = session_blocker(true);
        let mark = crate::log_capture::mark();
        let _looks = force_peeks([running(), gone()]);

        drop(child);

        assert_peeks_exhausted();
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].starts_with("Child::drop:")
                && warns[0].contains("reaped by someone else")
                && warns[0].contains("leaks"),
            "{warns:?}"
        );
    }

    /// A refused root kill on an unknown root that the second look shows ours: the refusal and the
    /// unknown state are one event, so one warn.
    ///
    /// Mutant: the refusal warns on its own ("could not be terminated on drop"), besides the unknown
    /// state's.
    #[skuld::test]
    async fn a_refused_kill_on_an_unknown_root_that_stays_ours_warns_once() {
        crate::log_capture::install();
        let _recorder = crate::containment::unix::fault::record_kill_group();
        let (child, _writer) = session_blocker(true);
        let pid = child.id().pid();
        let mark = crate::log_capture::mark();
        let _looks = force_peeks([failed_peek("forced"), running()]);
        let _kill = crate::tokio::child::fault::force_kill_failure();

        drop(child);

        assert_peeks_exhausted();
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("RootState::Unknown")
                && warns[0].contains(&format!("async child {pid} could not be terminated on drop")),
            "{warns:?}"
        );
    }

    /// A failed spawn's cleanup with a closed front and a foreign reap seen by the second look: one
    /// warn, which names the reap and carries the leak.
    ///
    /// Mutant: the forget warns on its own, besides the cleanup's.
    #[skuld::test]
    async fn finish_elevated_with_a_closed_front_and_a_foreign_reap_warns_once() {
        crate::log_capture::install();
        let _recorder = crate::containment::unix::fault::record_kill_group();
        let (mut child, _writer) = session_blocker(true);
        child.set_front(Some(crate::elevation::front::Front::Sudo));
        let mark = crate::log_capture::mark();
        let _looks = force_peeks([running(), running(), running(), gone()]);

        let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
            .expect_err("the spawn fails");

        assert_peeks_exhausted();
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
        assert!(
            warns[0].starts_with("finish_elevated:")
                && warns[0].contains("reaped by someone else")
                && warns[0].contains("leaks"),
            "{warns:?}"
        );
    }

    /// A failed spawn's cleanup on a `TreeWalk` child whose walk left only the root: the cleanup's own
    /// kill of the root ends it, but the walk saw the root running, so the tree is not vouched for. The
    /// cleanup says so once, in the error and the warn, and disarms the handle, so its drop does not
    /// say it again. A walk that left a descendant is a failed kill: reported, and the handle stays
    /// armed to try again.
    ///
    /// Mutants: the cleanup reports the walk's error before the root's kill; the handle stays armed
    /// over an unvouched tree (its drop warns again).
    #[skuld::test]
    async fn finish_elevated_reports_a_walk_that_left_only_the_root_as_unvouched_once() {
        use crate::containment::treewalk::fault::LeftBehind;
        crate::log_capture::install();
        for (left, failed) in [(LeftBehind::Root, false), (LeftBehind::Descendant, true)] {
            let (child, _writer) = crate::test_child::held_treewalk_blocker_leaving_async(left);
            let mark = crate::log_capture::mark();
            let drop_looks = crate::graceful_hooks::watch_for_a_second_look();

            let failure =
                crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
                    .expect_err("the spawn fails");
            let (cause, fate, _) = crate::test_child::expect_may_have_started_parts(failure.into(), ());

            assert!(fate.not_running(), "{left:?}: {fate:?}");
            // A failed kill leaves the handle armed to try again: the look at the tree when it drops
            // is the armed drop's first act, whatever it then logs. An unvouched tree is not retried.
            assert_eq!(drop_looks.seen(), failed, "{left:?}: armed only over a failed kill");
            let cause = cause.to_string();
            assert_eq!(
                cause.contains("its contained tree could not be killed"),
                failed,
                "{left:?}: {cause}"
            );
            assert_eq!(cause.contains("could not be vouched for"), !failed, "{left:?}: {cause}");
            let warns = warns_since(mark);
            let cleanup = warns.iter().filter(|warn| warn.starts_with("finish_elevated:")).count();
            assert_eq!(cleanup, 1, "{left:?}: {warns:?}");
            // The cleanup's one warn, and no drop's after it.
            let unvouched = warns
                .iter()
                .filter(|warn| warn.contains("could not be vouched for"))
                .count();
            assert_eq!(unvouched, usize::from(!failed), "{left:?}: {warns:?}");
        }
    }

    /// A tree kill skipped because the root's state is unknown has not killed the tree: the cleanup's
    /// settle does not mark it, so the failed spawn's handle stays armed.
    ///
    /// Mutant: a skipped kill marks the tree killed.
    #[skuld::test]
    async fn a_skipped_tree_kill_does_not_mark_the_tree_killed() {
        use crate::containment::dispatch::{RootView, TeardownCaller};
        crate::log_capture::install();
        let (child, _writer) = crate::test_child::held_treewalk_blocker_async();
        let view = crate::containment::DropView {
            caller: TeardownCaller::FinishElevated,
            root_pid: child.id().pid(),
            root: RootView::Unknown(std::io::Error::other("forced")),
            tree_killed: false,
        };

        let kill = child.kill_tree_members_unless_reaped(&view);

        assert!(
            kill.skipped().is_some(),
            "the walk from the root's number is skipped: {kill:?}"
        );
        child.settle_tree(kill, true).expect("a skip leaves nothing to report");
        assert!(!child.tree_killed(), "a skipped kill does not mark the tree killed");
    }

    /// The wait's failure is named in the one warn: the cause of a foreign wait result is carried, not
    /// only logged at `debug`.
    ///
    /// Mutant: the cause is dropped on the way to the warn.
    #[skuld::test]
    async fn finish_elevated_names_why_the_wait_found_the_child_foreign() {
        crate::log_capture::install();
        let _recorder = crate::containment::unix::fault::record_kill_group();
        let (child, writer) = session_blocker(true);
        let pid = child.id().pid();
        let mark = crate::log_capture::mark();
        let _reap = crate::child::spawn::fault::set_between_kill_and_wait(move || {
            crate::tokio::child::child_reap_tests::release_then_reap_behind_the_owner(pid, writer);
        });

        let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
            .expect_err("the spawn fails");

        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
        assert!(
            warns[0].contains("waitid"),
            "the wait's cause is in the warn: {warns:?}"
        );
    }

    /// `wait_and_reap_at` logs a wait that failed at the level it is given. The failure is a contract
    /// breach, asserted in debug builds, after the log.
    ///
    /// Mutant: the pidfd wait logs at `warn` whatever the level.
    #[cfg(debug_assertions)] // the failure is a debug assertion: release has none to catch
    #[skuld::test]
    async fn a_failed_pidfd_wait_is_logged_at_the_level_the_caller_gave() {
        use crate::signal::Sig;
        use crate::wait::exit_only::seams::force_visible_errno_once;

        crate::log_capture::install();
        let _recorder = crate::containment::unix::fault::record_kill_group();
        let (mut child, _writer) = session_blocker(true);
        let pid = child.id().pid();
        child.proc_mut().signal(Sig::Kill).expect("kill the blocker");
        let mark = crate::log_capture::mark();
        let _errno = force_visible_errno_once(libc::EIO);

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            child.proc_mut().wait_and_reap_at(pid, log::Level::Debug)
        }));

        assert!(
            panicked.is_err(),
            "a failed wait on the child's own pidfd is asserted in debug"
        );
        assert_eq!(warns_since(mark), Vec::<String>::new());
        assert!(
            crate::log_capture::contains_since(mark, "waitid on child"),
            "the failure is still logged, at the level given"
        );
    }

    /// A failed spawn's cleanup whose root kill is refused leaves the handle armed, so its drop retries
    /// the kill: the cleanup did not settle the root. The retry adds no second warn.
    ///
    /// Mutant: the cleanup disarms the handle whatever became of the root.
    #[skuld::test]
    async fn finish_elevated_leaves_the_handle_armed_when_the_root_kill_was_refused() {
        crate::log_capture::install();
        let _recorder = crate::containment::unix::fault::record_kill_group();
        let (child, writer) = session_blocker(true);
        // Released once the handle's drop killed the root, before its reap.
        let teardown = crate::child::spawn::fault::release_between_kill_and_wait(writer);
        let drops = crate::tokio::child::drop_fault::record();
        let mark = crate::log_capture::mark();
        let _kill = crate::tokio::child::fault::force_kill_failure();

        let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
            .expect_err("the spawn fails");

        assert_eq!(
            drops.kills(),
            1,
            "the handle's drop retries the refused root kill ({err:?})"
        );
        assert_eq!(warns_since(mark), Vec::<String>::new());
        teardown.assert_killed();
    }

    /// The cleanup's `debug` lines name the cleanup, not a drop: the read of the root's number says
    /// so in its own record.
    ///
    /// Mutant: `DropView::read` hardcodes "Child::drop" for the async cleanup.
    #[skuld::test]
    async fn the_cleanups_read_names_the_cleanup() {
        crate::log_capture::install();
        let _recorder = crate::containment::unix::fault::record_kill_group();
        let (child, writer) = session_blocker(true);
        // Released once the cleanup's root kill returned, before its reap.
        let teardown = crate::child::spawn::fault::release_between_kill_and_wait(writer);
        let mark = crate::log_capture::mark();
        // The number is unreadable too, so the read says so in a `debug` line of its own.
        let _number = crate::child::fault::force_next_root_read(crate::identity::Resolved::Unknown);
        let _looks = force_peeks([failed_peek("forced")]);

        let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
            .expect_err("the spawn fails");

        assert_peeks_exhausted();
        teardown.assert_killed();
        let read = crate::log_capture::records_since_on_current_thread(mark, "could not be read either");
        assert_eq!(read.len(), 1, "{read:?} ({err:?})");
        assert!(read[0].1.starts_with("finish_elevated:"), "{read:?}");
    }

    /// A cleanup that warned and then left its handle armed (the root kill was refused): the
    /// handle's drop reads the forgotten root as reaped and skips the tree kill, and does not warn of
    /// the same event again.
    ///
    /// Mutant: the drop's report ignores that the cleanup already warned.
    #[skuld::test]
    async fn a_retried_cleanup_does_not_warn_of_its_event_twice() {
        #[cfg(target_os = "linux")]
        let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
        crate::log_capture::install();
        let recorder = crate::containment::unix::fault::record_kill_group();
        let (child, _writer) = session_blocker(true);
        let mark = crate::log_capture::mark();
        // The cleanup's read, then the second look of the refused kill's forget.
        let _looks = force_peeks([failed_peek("forced"), failed_peek("forced")]);
        let _kill = crate::tokio::child::fault::force_kill_failure();

        let err = crate::tokio::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
            .expect_err("the spawn fails");

        assert_peeks_exhausted();
        assert_eq!(
            recorder.killed(),
            Vec::<i32>::new(),
            "no killpg by an unconfirmed root's number"
        );
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?} ({err:?})");
        assert!(
            warns[0].starts_with("finish_elevated:") && warns[0].contains("RootState::Unknown"),
            "{warns:?}"
        );
    }

    /// A failed spawn's teardown whose wait finds the child reaped behind its back forgets tokio's
    /// `Child` under one warn, which names the cause of the wait and carries the leak.
    ///
    /// Mutants: the wait logs a warn of its own besides the forget's; the forget's warn omits the
    /// wait's cause.
    #[skuld::test]
    async fn reap_now_warns_once_for_a_foreign_reap_during_its_wait() {
        crate::log_capture::install();
        let _recorder = crate::containment::unix::fault::record_kill_group();
        let (mut child, writer) = session_blocker(false);
        let pid = child.id().pid();
        let proc = child.os.proc.take().expect("the backend");
        let mark = crate::log_capture::mark();
        let _reap = crate::child::spawn::fault::set_between_kill_and_wait(move || {
            crate::tokio::child::child_reap_tests::release_then_reap_behind_the_owner(pid, writer);
        });

        proc.reap_now(pid, None);

        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("waitid") && warns[0].contains("leaks"),
            "the one warn carries the wait's cause and the leak: {warns:?}"
        );
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::super::root_state_tests::warns_since;
    use crate::os_process::child::{Foreign, PeekOutcome};
    use crate::test_child::Console;
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};

    /// A failed spawn's teardown whose wait finds the zombie held by launchd (its tracer died)
    /// forgets tokio's `Child` under one warn, which names launchd and carries the leak.
    ///
    /// Mutants: the wait warns on its own besides the forget's; the forget's warn omits the wait's
    /// cause.
    #[skuld::test]
    async fn reap_now_warns_once_for_an_orphaned_zombie_during_its_wait() {
        crate::log_capture::install();
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = crate::test_child::tokio_command(Console::Hidden);
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        cmd.contain_with(crate::ContainMode::TreeWalk);
        cmd.kill_on_drop(false);
        let mut child = cmd.spawn().expect("spawn");
        let pid = child.id().pid();
        let proc = child.os.proc.take().expect("the backend");
        let mark = crate::log_capture::mark();
        let _orphaned = force_peek_once(Ok(PeekOutcome::Foreign(Foreign::Orphaned)));

        proc.reap_now(pid, None);

        assert_peeks_exhausted();
        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].contains("launchd") && warns[0].contains("leaks"),
            "the one warn carries the wait's cause and the leak: {warns:?}"
        );
        // The kill was delivered; the zombie is the test's to collect.
        drop(writer);
        crate::tokio::child::child_reap_tests::reap_behind_the_owner(pid);
    }
}
