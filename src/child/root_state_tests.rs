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
    use crate::wait::exit_only::seams::force_peek_once;
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

    /// The warn is labelled by the caller: a failed spawn's cleanup does not call itself a drop.
    ///
    /// Mutant: `DropView::read` hardcodes "Child::drop".
    #[skuld::test]
    fn the_unknown_warn_names_its_caller() {
        crate::log_capture::install();
        let _recorder = record_kill_group();
        let (child, _writer) = session_blocker();
        let mark = crate::log_capture::mark();
        let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));

        let err = crate::child::spawn::finish_elevated(child, Err(crate::error::Error::Io(std::io::Error::other("w"))))
            .expect_err("the spawn fails");

        // The cleanup's own drop afterwards reads a reaped root: another event, with its own warn.
        let unknown: Vec<String> = warns_since(mark)
            .into_iter()
            .filter(|w| w.contains("RootState::Unknown"))
            .collect();
        assert_eq!(unknown.len(), 1, "{unknown:?} ({err:?})");
        assert!(unknown[0].starts_with("finish_elevated:"), "{unknown:?}");
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

        assert!(
            !crate::log_capture::contains_since(mark, "treating the root as not reaped"),
            "{:?}",
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
        let view = crate::containment::DropView::read(
            "test",
            child.id,
            &child.attached,
            || child.proc.state(),
            &child.tree_killed,
        );
        assert!(matches!(view.root, RootState::Unknown(_)), "{:?}", view.root);

        let skipped = child
            .attached
            .hard_kill_marking_unless_reaped(&view, &killed)
            .expect("a skip is not an error");

        assert!(skipped.is_some(), "the number-named kill must be skipped");
        assert!(!killed.is_set(), "a skipped kill must not mark the tree killed");
        assert_eq!(recorder.killed(), Vec::<i32>::new());
    }
}
