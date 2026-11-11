//! The teardown policy of `OwnedChild` over a `FakeProcess` (see `owned::teardown`).

use std::process::ExitStatus;
use std::time::Duration;

use super::teardown_lines::said_of;
use super::teardown_look::FakeReach;
use crate::child::lifecycle::Wording;
use crate::child::owned::teardown::{BeginOutcome, Disposition, Kill, TeardownOutcome};
use crate::child::owned::OwnedChild;
use crate::error::ChildFate;
use crate::identity::ProcessId;
use crate::os_process::child::{ExitRecord, Foreign};
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::signal::Sent;

pub(super) const PID: u32 = 4242;

pub(super) fn id() -> ProcessId {
    ProcessId::from_parts_for_test(PID, crate::identity::Key::for_test(1))
}

/// A fake that states the pid, and nothing else.
pub(super) fn fake() -> FakeProcess {
    FakeProcess::new([]).with_pid(PID)
}

pub(super) fn exit() -> ExitRecord {
    ExitRecord::Status(ExitStatus::default())
}

/// A child whose reap consumed the zombie and read no exit record, so every wait on it answers
/// `Exited(Unreadable)`. A debug build asserts that contract breach after it caches the record; a
/// release build returns.
pub(super) fn child_with_an_unreadable_exit() -> OwnedChild {
    let child = OwnedChild::new(Box::new(
        fake().reaps([ReapAnswer::Reaped(ExitRecord::Unreadable { si_code: 7 })]),
    ));
    _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| child.wait(None)));
    child
}

/// The text of `torn`'s clause if it is a warn: what a caller with one warn folds into it.
pub(super) fn warn_of(torn: &TeardownOutcome) -> Option<&str> {
    match torn.said() {
        Some(Wording::Uncollected(text) | Wording::Collected(log::Level::Warn, text)) => Some(text),
        _ => None,
    }
}

/// What `tear_down(id, Kill, warn_after)` returned over `fake`, and everything it logged on this
/// thread.
fn tear_down_logged(
    fake: &FakeProcess,
    id: Option<ProcessId>,
    warn_after: Option<Duration>,
) -> (TeardownOutcome, Vec<(log::Level, String)>) {
    crate::log_capture::install();
    let child = OwnedChild::new(Box::new(fake.clone()));
    let mark = crate::log_capture::mark();
    let torn = child.tear_down(
        id,
        Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        warn_after,
    );
    (torn, crate::log_capture::records_since_on_current_thread(mark, ""))
}

/// [`tear_down_logged`] for a child of identity [`id`] and no threshold, with the levels it logged
/// for its child.
fn teardown(fake: &FakeProcess) -> (TeardownOutcome, Vec<log::Level>) {
    let (torn, records) = tear_down_logged(fake, Some(id()), None);
    let levels = records
        .into_iter()
        .filter(|(_, text)| text.contains(&PID.to_string()))
        .map(|(level, _)| level)
        .collect();
    (torn, levels)
}

/// [`teardown`] with the kill delivered and the reap after it answering `reap`.
fn teardown_when_the_reap_answers(reap: ReapAnswer) -> (TeardownOutcome, Vec<log::Level>) {
    teardown(&fake().reaps([reap]).signals([Ok(Sent::Delivered)]))
}

/// Turns a wait that blocks into a recorded fact: the fake's wait is fired as the block begins, so
/// a teardown that waits where it must not fails the count instead of hanging. The count starts
/// empty: a block an earlier test left on this thread is dropped.
pub(crate) fn fire_on_block(fake: &FakeProcess) -> crate::wait::block_probe::Armed {
    crate::wait::block_probe::take();
    let fake = fake.clone();
    crate::wait::block_probe::on_blocking(move || fake.wake())
}

/// A live blocker as a spawn's teardown holds it: its root, answering as `script` says (see
/// `script_over`), with the handle inert, as `into_unreaped` leaves it, so the teardown owns the
/// root. The write end of its stdin comes with it.
#[cfg(any(target_os = "linux", windows))]
pub(crate) fn held_owned_blocker(script: impl FnOnce(FakeProcess) -> FakeProcess) -> (OwnedChild, crate::PipeWriter) {
    let (mut child, stdin) = crate::test_child::held_uncontained_blocker(true);
    child.proc.script_over(script);
    child.kill_on_drop = false;
    let owned = child.proc.take().expect("the child holds its root");
    (owned, stdin)
}

/// A leftover about a child whose reap consumed the zombie but read no exit record: the child is
/// collected, so a caller that hands children back has none to hand back, and the leftover does not
/// say it did.
#[track_caller]
fn assert_collected_with_an_unreadable_record(torn: &TeardownOutcome, disposition: Disposition, wanted: &str) {
    let text = warn_of(torn).unwrap_or_default();
    assert!(text.contains(wanted) && text.contains("unreadable"), "{torn:?}");
    assert!(!text.contains("handed back"), "{torn:?}");
    assert!(!torn.uncollected(), "{torn:?}");
    assert!(!disposition.hands_back(&torn.remains()), "{torn:?}");
}

/// A reap after a kill that consumed the zombie without an exit record leaves nothing to hand back,
/// though the wait reports an error: the child was reaped, and the leftover says so.
///
/// Mutants: any failed wait is uncollected; the leftover says the reap failed; the fate is `Killed`.
#[skuld::test]
fn a_reap_after_a_kill_whose_exit_record_was_unreadable_leaves_nothing_uncollected() {
    for disposition in [Disposition::Leave, Disposition::HandBack] {
        let child = child_with_an_unreadable_exit();
        let torn = child.reap_after_tree_kill(&child.teardown_subject(), disposition, None);
        assert_eq!(torn.fate(), ChildFate::Reaped, "{torn:?}");
        assert_collected_with_an_unreadable_record(&torn, disposition, "reaped it after the kill");
        assert!(!warn_of(&torn).unwrap_or_default().contains("failed"), "{torn:?}");
    }
}

/// The same through the entry point: a kill sent nothing to a child already reaped, and the wait after
/// it meets the unreadable record. No kill reached the child, so the leftover does not say "after the
/// kill".
///
/// Mutants: any failed wait is uncollected; the leftover says the reap failed, or says "after the
/// kill" of a kill that sent nothing; the fate is `Unknown`.
#[skuld::test]
fn a_teardown_of_a_child_with_an_unreadable_exit_leaves_nothing_uncollected() {
    for disposition in [Disposition::Leave, Disposition::HandBack] {
        let torn = child_with_an_unreadable_exit().tear_down(
            Some(id()),
            Kill {
                disposition,
                tree: None,
            },
            None,
        );
        assert_eq!(torn.fate(), ChildFate::Reaped, "{torn:?}");
        assert_collected_with_an_unreadable_record(&torn, disposition, "reaped it");
        assert!(!warn_of(&torn).unwrap_or_default().contains("failed"), "{torn:?}");
        assert!(
            !warn_of(&torn).unwrap_or_default().contains("after the kill"),
            "{torn:?}"
        );
    }
}

/// A refused kill whose look consumed the zombie without an exit record leaves nothing to hand back,
/// and the child is reaped.
///
/// Mutant: a look that ended with an unreadable record is a failed look, `Unknown` and uncollected.
#[skuld::test]
fn a_refused_kill_whose_look_found_the_exit_record_unreadable_leaves_nothing_uncollected() {
    for disposition in [Disposition::Leave, Disposition::HandBack] {
        let refused = crate::error::Error::Io(std::io::Error::other("refused"));
        let torn = child_with_an_unreadable_exit().look_after_refused_kill(Some(id()), refused, disposition);
        assert_eq!(torn.fate(), ChildFate::Reaped, "{torn:?}");
        assert_collected_with_an_unreadable_record(&torn, disposition, "reaped it");
        assert!(!warn_of(&torn).unwrap_or_default().contains("failed"), "{torn:?}");
    }
}

/// A reap that fails after the kill is not dropped silently: it is returned for the caller's one
/// warn, and logged by nobody here.
///
/// Mutants: `_ = s.wait()`; the teardown warns on its own.
#[skuld::test]
fn a_failed_teardown_reap_is_returned_and_not_logged() {
    let (torn, levels) = teardown_when_the_reap_answers(ReapAnswer::Err(std::io::ErrorKind::Other));
    assert!(
        warn_of(&torn).is_some_and(|text| text.contains("the wait failed")),
        "{torn:?}"
    );
    assert_eq!(torn.fate(), ChildFate::Killed, "the kill was delivered: {torn:?}");
    assert_eq!(levels, Vec::<log::Level>::new());
}

/// A reap that finds the child collected by someone else comes back as a `debug` clause, and the
/// teardown logs nothing.
///
/// Mutants: the clause is a warn, or missing; the teardown logs it.
#[skuld::test]
fn a_teardown_reap_that_meets_a_foreign_reap_is_a_debug_clause() {
    let (torn, levels) = teardown_when_the_reap_answers(ReapAnswer::Foreign(Foreign::Gone));
    assert_eq!(
        said_of(&torn),
        Some((
            log::Level::Debug,
            format!("teardown of child {PID}: reaped by someone else")
        ))
    );
    assert_eq!(levels, Vec::<log::Level>::new());
}

/// A reap after a delivered kill that finds launchd holding the child's zombie: the child is
/// `Killed`, and the launchd note comes back for the caller's one warn, not logged here.
///
/// Mutants: the foreign arm drops the note; the teardown warns of it on its own.
#[skuld::test]
fn a_reap_after_a_delivered_kill_that_meets_launchd_returns_the_note_and_logs_nothing_above_debug() {
    let (torn, levels) = teardown_when_the_reap_answers(ReapAnswer::Foreign(Foreign::Orphaned));
    assert_eq!(torn.fate(), ChildFate::Killed, "{torn:?}");
    assert!(
        warn_of(&torn).is_some_and(|text| text.contains(&PID.to_string()) && text.contains("launchd")),
        "{torn:?}"
    );
    assert!(levels.iter().all(|level| *level >= log::Level::Debug), "{levels:?}");
}

/// A reap after a tree kill that was delivered meets a foreign reap: someone else collected the
/// exit after the kill, which is `Killed`, never `Gone` (the fate of a child cosca delivered
/// nothing to).
///
/// Mutant: the foreign arm answers `Gone`.
#[cfg(unix)]
#[skuld::test]
fn a_reap_after_a_delivered_tree_kill_that_meets_a_foreign_reap_is_killed() {
    let fake = fake().reaps([ReapAnswer::Foreign(Foreign::Gone)]);
    let child = OwnedChild::new(Box::new(fake));
    let torn = child.reap_after_tree_kill(&child.teardown_subject(), Disposition::Leave, None);
    assert_eq!(torn.fate(), ChildFate::Killed);
    assert_eq!(
        said_of(&torn),
        Some((
            log::Level::Debug,
            "teardown of child 4242: reaped by someone else".to_owned()
        ))
    );
}

/// A reap after a tree kill reaps the child once, with a blocking wait, and says so.
///
/// Mutant: the reap is a look at the present moment, so a child still dying is `Running`.
#[cfg(unix)]
#[skuld::test]
fn a_reap_after_a_tree_kill_waits_for_the_exit() {
    let fake = fake().reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())]);
    let _fire = fire_on_block(&fake);
    let child = OwnedChild::new(Box::new(fake.clone()));
    let torn = child.reap_after_tree_kill(&child.teardown_subject(), Disposition::Leave, None);
    assert_eq!(torn.fate(), ChildFate::Reaped);
    assert_eq!(warn_of(&torn), None);
    assert_eq!(crate::wait::block_probe::take(), [None], "one unbounded block");
}

/// A kill that delivered nothing (the child was reaped behind the handle's back), then a wait that
/// fails for another reason, shows nothing of what became of the child: `Unknown`, not `Killed`.
/// The same on every OS.
///
/// Mutant: a failed wait is `Killed` whatever the kill did.
#[skuld::test]
fn a_failed_wait_after_a_kill_that_delivered_nothing_is_unknown() {
    let fake = fake()
        .reaps([ReapAnswer::Err(std::io::ErrorKind::Other)])
        .signals([Ok(Sent::Gone)]);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate(), ChildFate::Unknown);
}

/// A kill that was delivered is followed by a blocking wait through the child's own `try_reap`, and
/// the exit it finds is `Reaped`.
///
/// Mutants: the wait is a look at the present moment; the teardown never waits.
#[skuld::test]
fn teardown_after_a_delivered_kill_waits_through_try_reap() {
    let fake = fake()
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let _fire = fire_on_block(&fake);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate(), ChildFate::Reaped);
    assert_eq!(
        said_of(&torn),
        Some((
            log::Level::Debug,
            "teardown of child 4242: reaped it after the kill".to_owned()
        ))
    );
    assert_eq!(fake.looks(), 2, "a look, then the look the wait woke to");
    assert_eq!(crate::wait::block_probe::take(), [None], "one unbounded block");
}

/// A kill that found nothing to signal (the child is exiting or reaped) is followed by the same
/// blocking wait.
///
/// Mutant: the wait follows `Delivered` only.
#[skuld::test]
fn teardown_after_a_kill_that_found_nothing_to_signal_waits_too() {
    let fake = fake()
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Gone)]);
    let _fire = fire_on_block(&fake);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate(), ChildFate::Reaped);
    assert_eq!(fake.looks(), 2);
}

/// The warn clause of a teardown whose kill is refused and whose child still runs, under `disposition`.
fn left_of_a_refused_kill_of_a_running_child(disposition: Disposition) -> String {
    let fake = fake()
        .reaps([ReapAnswer::Running])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let child = OwnedChild::new(Box::new(fake));
    let torn = child.tear_down(
        Some(id()),
        Kill {
            disposition,
            tree: None,
        },
        None,
    );
    assert_eq!(torn.fate(), ChildFate::Running { id: Some(id()) }, "{torn:?}");
    warn_of(&torn)
        .expect("a refused kill of a running child is warned of")
        .to_owned()
}

/// `tear_down(Kill)` over a child whose kill is refused and which is running, with `tree` saying
/// whether a kill sent through its containment reached it. The fake answers a look "running", then
/// the exit.
fn refused_kill_with_a_tree_kill(tree: &FakeReach) -> (TeardownOutcome, FakeProcess) {
    let fake = fake()
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let child = OwnedChild::new(Box::new(fake.clone()));
    let torn = child.tear_down(
        Some(id()),
        Kill {
            disposition: Disposition::HandBack,
            tree: Some(tree),
        },
        None,
    );
    (torn, fake)
}

/// A refused kill of a child that a kill sent through its containment reached is not a child that
/// still runs: that kill is asynchronous, so one look at the present moment races it. The exit is
/// waited for, bounded by the kill, and nothing is left or handed back.
///
/// Mutants: the refused kill is followed by the one look; the wait is bounded; the reach is not asked
/// about this child.
#[skuld::test]
fn a_refused_kill_of_a_child_the_tree_kill_reached_is_waited_for_and_reaped() {
    let reach = FakeReach::answering(Ok(true));
    let fake = fake()
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let _fire = fire_on_block(&fake);
    let child = OwnedChild::new(Box::new(fake.clone()));

    let torn = child.tear_down(
        Some(id()),
        Kill {
            disposition: Disposition::HandBack,
            tree: Some(&reach),
        },
        None,
    );

    assert_eq!(torn.fate(), ChildFate::Reaped, "{torn:?}");
    assert_eq!(warn_of(&torn), None, "{torn:?}");
    assert_eq!(reach.asked(), [Some(PID)]);
    assert_eq!(crate::wait::block_probe::take(), [None], "one unbounded block");
}

/// A refusal is classified by what the OS refused with: an I/O error is its own kind, any other
/// error is another reason.
///
/// Mutant: every error that is not `Io` is another reason.
#[skuld::test]
fn a_refusal_is_classified_by_what_it_is() {
    use crate::error::Error;
    let denied = || Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    let contained = || Error::Containment {
        detail: "refused".into(),
        source: None,
    };
    let kinds = [
        (denied(), std::io::ErrorKind::PermissionDenied),
        (contained(), std::io::ErrorKind::Other),
    ];
    for (refused, kind) in kinds {
        let described = refused.to_string();
        let child = OwnedChild::new(Box::new(fake().reaps([ReapAnswer::Reaped(exit())])));
        let torn = child.look_after_refused_kill(Some(id()), refused, Disposition::Leave);
        assert_eq!(torn.remains().refused, Some(kind), "{described}");
    }
}

/// A refused kill of a child that no tree kill reached is looked at once, never waited for: nothing
/// asked it to exit. A reach that cannot say is the same.
///
/// Mutants: `Ok(false)` or `Err` is taken for `Ok(true)`.
#[skuld::test]
fn a_refused_kill_of_a_child_the_tree_kill_did_not_reach_is_looked_at_once() {
    for answer in [Ok(false), Err(std::io::ErrorKind::Other)] {
        let reach = FakeReach::answering(answer);
        let (torn, fake) = refused_kill_with_a_tree_kill(&reach);

        assert_eq!(
            torn.fate(),
            ChildFate::Running { id: Some(id()) },
            "{answer:?}: {torn:?}"
        );
        assert!(
            warn_of(&torn).is_some_and(|left| left.contains("handed back")),
            "{answer:?}: {torn:?}"
        );
        assert_eq!(reach.asked(), [Some(PID)], "{answer:?}");
        assert_eq!(fake.looks(), 1, "{answer:?}: one look");
    }
}

/// A child to be handed back says so, and does not say it is left running.
///
/// Mutants: the text ignores the disposition; it drops the child or the refusal.
#[skuld::test]
fn a_refused_kill_of_a_child_to_be_handed_back_says_so() {
    let refusal = std::io::Error::from(std::io::ErrorKind::PermissionDenied).to_string();
    let left = left_of_a_refused_kill_of_a_running_child(Disposition::HandBack);
    assert!(
        left.contains(&PID.to_string()) && left.contains(&refusal) && left.contains("handed back to the caller"),
        "{left}"
    );
    assert!(!left.contains("leaving it running"), "{left}");
}

/// A child to be left says so.
///
/// Mutant: the text always says the child is handed back.
#[skuld::test]
fn a_refused_kill_of_a_child_to_be_left_says_it_is_left_running() {
    let left = left_of_a_refused_kill_of_a_running_child(Disposition::Leave);
    assert!(left.contains("leaving it running"), "{left}");
    assert!(!left.contains("handed back"), "{left}");
}

/// A kill that failed, whatever the error, is followed by one look and no wait, and a child still
/// running is `Running` with the failure named for the caller's one warn.
///
/// Mutants: the failed kill is followed by a wait; the look is skipped; only `PermissionDenied`
/// names its error; the warn drops the error or the pid.
#[skuld::test]
fn teardown_after_a_refused_kill_looks_once_and_never_waits() {
    use std::io::ErrorKind::{InvalidInput, NotFound, Other, PermissionDenied};

    for kind in [PermissionDenied, NotFound, InvalidInput, Other] {
        let fake = fake()
            .reaps([ReapAnswer::Running])
            .signals([Err(std::io::Error::new(kind, "refused for the test"))]);
        let _fire = fire_on_block(&fake);
        let (torn, _) = teardown(&fake);
        assert_eq!(torn.fate(), ChildFate::Running { id: Some(id()) }, "{kind:?}: {torn:?}");
        let left = warn_of(&torn).unwrap_or_default();
        assert!(
            left.contains(&PID.to_string()) && left.contains("refused for the test"),
            "{kind:?}: the warning names the child and the error: {torn:?}"
        );
        assert_eq!(fake.looks(), 1, "{kind:?}: one look");
        assert_eq!(
            crate::wait::block_probe::take(),
            [],
            "{kind:?}: a failed kill is never followed by a wait"
        );
    }
}

/// A kill that failed on a child that has exited: the look collects it, and there is nothing to
/// warn of: the clause is a `debug` one that names the refusal.
///
/// Mutant: the warning is returned whenever the kill failed.
#[skuld::test]
fn teardown_after_a_refused_kill_of_an_exited_child_reaps_it_at_debug() {
    let refusal = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let fake = fake()
        .reaps([ReapAnswer::Reaped(exit())])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate(), ChildFate::Reaped);
    assert_eq!(
        said_of(&torn),
        Some((
            log::Level::Debug,
            format!("child 4242 could not be terminated ({refusal}: {refusal}): reaped it")
        ))
    );
    assert_eq!(fake.looks(), 1);
}

/// The look after a failed kill that fails itself is `Unknown`, and the warning names the look's
/// error: the child is not shown to be running, so it does not claim to leave it running.
///
/// Mutants: a failed look is read as an exit; the warning claims the child runs, or drops the look's
/// error.
#[skuld::test]
fn teardown_after_a_refused_kill_with_a_failed_look_is_unknown() {
    let look_error = std::io::Error::from(std::io::ErrorKind::Other).to_string();
    let fake = fake()
        .reaps([ReapAnswer::Err(std::io::ErrorKind::Other)])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate(), ChildFate::Unknown);
    let left = warn_of(&torn).expect("a failed look is warned of");
    assert!(
        left.contains(&PID.to_string()) && left.contains(&look_error),
        "{torn:?}"
    );
    assert!(!left.contains("leaving it running"), "{torn:?}");
}

/// A kill that failed on a child someone else already reaped: the look finds `ECHILD`, the child is
/// `Gone`, and there is no warning that it is left running: the clause is a `debug` one.
///
/// Mutant: the warning is returned for every look that did not collect an exit; the fate of a look
/// that found the child reaped elsewhere is `Unknown`.
#[skuld::test]
fn teardown_after_a_refused_kill_of_a_child_reaped_elsewhere_is_gone_at_debug() {
    let refusal = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let fake = fake()
        .reaps([ReapAnswer::Foreign(Foreign::Gone)])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, _) = teardown(&fake);
    assert_eq!(torn.fate(), ChildFate::Gone);
    assert_eq!(
        said_of(&torn),
        Some((
            log::Level::Debug,
            format!("child 4242 could not be terminated ({refusal}: {refusal}): reaped by someone else")
        ))
    );
    assert_eq!(fake.looks(), 1);
}

/// A kill that failed on a child launchd holds the zombie of: the look finds `Orphaned`, the child is
/// `Gone`, the launchd note comes back for the caller's one warn after the refusal it names, and
/// nothing is logged above `debug`.
///
/// Mutants: the look drops the launchd note, or logs it itself; the note replaces the refusal; the
/// look reads the child as `Unknown`.
#[skuld::test]
fn teardown_after_a_refused_kill_of_a_child_launchd_holds_is_gone_and_returns_the_note() {
    let refusal = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let fake = fake()
        .reaps([ReapAnswer::Foreign(Foreign::Orphaned)])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, levels) = teardown(&fake);
    assert_eq!(torn.fate(), ChildFate::Gone);
    assert_eq!(
        warn_of(&torn),
        Some(
            format!(
                "child 4242 could not be terminated ({refusal}: {refusal}): not ours to reap (launchd holds its zombie, because \
                 its tracer died)"
            )
            .as_str()
        )
    );
    assert!(levels.iter().all(|level| *level >= log::Level::Debug), "{levels:?}");
    assert_eq!(fake.looks(), 1);
}

/// A threshold that has already passed when the wait starts: the wait warns unless the child has
/// exited.
pub(super) fn due_now() -> Duration {
    Duration::ZERO
}

/// The records that are the slow-teardown warn.
pub(super) fn slow_warns(records: &[(log::Level, String)]) -> Vec<&String> {
    records
        .iter()
        .filter(|(level, text)| *level == log::Level::Warn && text.contains("after its kill"))
        .map(|(_, text)| text)
        .collect()
}

/// A child that is visible but cannot be reaped until after the threshold (a zombie a tracer holds:
/// the reap answers `Recheck`) is warned of once, past the threshold, and then reaped.
///
/// Mutant: the warn watches whether the child exited, not the handle's own wait, so it never warns.
#[skuld::test]
fn a_child_not_reapable_until_after_the_threshold_warns_once_and_is_reaped() {
    let fake = fake()
        .reaps([ReapAnswer::Recheck, ReapAnswer::Recheck, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let (torn, records) = tear_down_logged(&fake, Some(id()), Some(due_now()));
    assert_eq!(torn.fate(), ChildFate::Reaped, "{torn:?}");
    assert_eq!(slow_warns(&records).len(), 1, "{records:?}");
}

/// A child reaped within the bounded wait is the result: nothing warns.
///
/// Mutant: the warn is not conditional on the bounded wait's outcome.
#[skuld::test]
fn a_child_reaped_within_the_threshold_is_not_waited_for_again() {
    let fake = fake()
        .reaps([ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let (torn, records) = tear_down_logged(&fake, Some(id()), Some(due_now()));
    assert_eq!(torn.fate(), ChildFate::Reaped, "{torn:?}");
    assert_eq!(slow_warns(&records), Vec::<&String>::new(), "{records:?}");
}

/// A refused kill with no identity read leaves a running child without one.
///
/// Mutant: the outcome carries a made-up identity.
#[skuld::test]
fn a_kill_teardown_without_an_id_leaves_a_running_child_without_one() {
    let fake = fake()
        .reaps([ReapAnswer::Running])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, _) = tear_down_logged(&fake, None, None);
    assert_eq!(torn.fate(), ChildFate::Running { id: None });
}

/// A child with no pid is named without a number.
///
/// Mutants: a pid is made up; the message is built with a number.
#[skuld::test]
fn a_pidless_child_is_named_without_a_number() {
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, _) = tear_down_logged(&fake, None, None);
    let left = warn_of(&torn).expect("a refused kill is warned of");
    assert!(left.contains(crate::os_process::PIDLESS_CHILD), "{left}");
    assert!(!left.chars().any(|c| c.is_ascii_digit()), "{left}");
}

/// Without a threshold the wait is the blocking wait alone: nothing looks for the exit first.
///
/// Mutant: the teardown looks for the exit whatever the threshold (the empty `exited` table
/// panics).
#[skuld::test]
fn a_teardown_without_a_threshold_never_looks_for_the_exit() {
    let fake = fake()
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let _fire = fire_on_block(&fake);
    let (torn, _) = tear_down_logged(&fake, Some(id()), None);
    assert_eq!(torn.fate(), ChildFate::Reaped);
    assert_eq!(fake.looks(), 2);
}

/// A child that has not exited by the threshold is warned of once, before the wait blocks, and the
/// wait still ends with its exit.
///
/// Mutants: the warn comes after the block; no warn; the wait ends at the threshold.
#[skuld::test]
fn a_teardown_past_its_threshold_warns_once_before_it_blocks() {
    let fake = fake()
        .reaps([ReapAnswer::Running, ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let _fire = fire_on_block(&fake);
    let (torn, records) = tear_down_logged(&fake, Some(id()), Some(due_now()));
    assert_eq!(torn.fate(), ChildFate::Reaped);
    let warns = slow_warns(&records);
    assert!(
        warns.len() == 1 && warns[0].contains(&format!("child {PID}")),
        "{records:?}"
    );
    assert_eq!(crate::wait::block_probe::take(), [None], "one unbounded block");
}

/// A child that exits before the threshold is not warned of.
///
/// Mutant: the warn is not conditional on the bounded wait.
#[skuld::test]
fn a_wait_that_ends_before_the_threshold_does_not_warn() {
    let fake = fake()
        .reaps([ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let (torn, records) = tear_down_logged(&fake, Some(id()), Some(due_now()));
    assert_eq!(torn.fate(), ChildFate::Reaped);
    assert_eq!(slow_warns(&records), Vec::<&String>::new());
}

/// A refused kill is followed by one look and never a wait, so it never looks for the exit, whatever
/// the threshold.
///
/// Mutant: the refused kill's look goes through the threshold's wait (the empty `exited` table
/// panics).
#[skuld::test]
fn a_refused_kill_never_looks_for_the_exit_whatever_the_threshold() {
    let fake = fake()
        .reaps([ReapAnswer::Running])
        .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let (torn, records) = tear_down_logged(&fake, Some(id()), Some(due_now()));
    assert_eq!(torn.fate(), ChildFate::Running { id: Some(id()) });
    assert_eq!(fake.looks(), 1);
    assert_eq!(slow_warns(&records), Vec::<&String>::new());
}

/// A kill teardown counts as one root teardown.
///
/// Mutant: the count is dropped from the policy.
#[skuld::test]
fn a_kill_teardown_counts_one_root_teardown() {
    let recorder = crate::child::owned::seams::record_root_teardowns();
    let fake = fake()
        .reaps([ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let _ = teardown(&fake);
    assert_eq!(recorder.count(), 1);
}

/// A bounded wait that fails is the result: the failure comes back as a failed reap, nothing warns
/// of a slow wait, and nothing waits a second time (a second reap past the script panics).
///
/// Mutant: a failed bounded wait is followed by the unbounded one.
#[skuld::test]
fn a_failed_bounded_wait_is_the_result_and_is_not_repeated() {
    let fake = fake()
        .reaps([ReapAnswer::Err(std::io::ErrorKind::Other)])
        .signals([Ok(Sent::Delivered)]);
    let (torn, records) = tear_down_logged(&fake, Some(id()), Some(due_now()));
    assert_eq!(torn.fate(), ChildFate::Killed, "{torn:?}");
    assert!(
        warn_of(&torn).is_some_and(|text| text.contains("the wait failed")),
        "{torn:?}"
    );
    assert_eq!(slow_warns(&records), Vec::<&String>::new());
}

/// The first half of a teardown of a child that has already exited and been reaped ends there: it
/// answers `Done`, and no wait is left for the caller to make.
///
/// Mutant: `begin_tear_down` always answers a pending wait.
#[skuld::test]
fn the_first_half_of_a_teardown_of_a_reaped_child_is_done() {
    let fake = fake().reaps([ReapAnswer::Reaped(exit())]);
    let child = OwnedChild::new(Box::new(fake.clone()));
    child.wait(None).expect("the fake reaps the child");
    let looks = fake.looks();
    let begun = child.begin_tear_down(
        Some(id()),
        Kill {
            disposition: Disposition::Leave,
            tree: None,
        },
        Some(due_now()),
    );
    let BeginOutcome::Done(torn) = begun else {
        panic!("a reaped child has nothing to wait for: {begun:?}");
    };
    assert_eq!(torn.fate(), ChildFate::Reaped, "{torn:?}");
    assert_eq!(fake.looks(), looks, "the first half looked at a reaped child");
}

/// The slow-teardown warns that `step` logs on this thread.
pub(crate) fn slow_warns_during(step: impl FnOnce()) -> usize {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    step();
    slow_warns(&crate::log_capture::records_since_on_current_thread(mark, "")).len()
}

/// A fake that is still running when its wait starts, then exits once the wait blocks.
fn fake_slow_to_exit() -> FakeProcess {
    fake().reaps([ReapAnswer::Running, ReapAnswer::Running, ReapAnswer::Reaped(exit())])
}

/// The wait a delivered kill leaves, settled apart from its first half, warns past the threshold the
/// first half was given.
///
/// Mutant: `TeardownWait` does not keep its threshold.
#[skuld::test]
fn a_wait_left_by_a_delivered_kill_warns_past_the_threshold_it_was_begun_with() {
    let fake = fake_slow_to_exit().signals([Ok(Sent::Delivered)]);
    let _fire = fire_on_block(&fake);
    let child = OwnedChild::new(Box::new(fake));
    let kill = Kill {
        disposition: Disposition::Leave,
        tree: None,
    };
    let begun = child.begin_tear_down(Some(id()), kill, Some(due_now()));
    let BeginOutcome::Wait(wait) = begun else {
        panic!("a delivered kill leaves the reap pending: {begun:?}");
    };
    let mut torn = None;
    let warns = slow_warns_during(|| torn = Some(wait.settle(&child)));
    assert_eq!(torn.expect("settled").fate(), ChildFate::Reaped);
    assert_eq!(warns, 1);
}

/// A wait carried across an await is settled on the child it began on, and the child's handle says
/// so: a pid cannot, for children that have none.
///
/// Mutant: the check compares the children's pids, which agree when neither has one.
#[skuld::test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "a wait is settled on the child it began on")
)]
fn a_wait_settled_on_another_child_is_a_breach_even_for_children_without_a_pid() {
    let pidless = || OwnedChild::new(Box::new(FakeProcess::new([]).reaps([ReapAnswer::Reaped(exit())])));
    let (began_on, other) = (pidless(), pidless());
    let wait = began_on.begin_reap_after_tree_kill(None, "the child".to_owned(), Disposition::Leave, None);

    _ = wait.settle(&other);
}

/// The wait a refused kill leaves when a kill sent through the containment reached the child warns
/// past the threshold the teardown was given.
///
/// Mutant: `begin_tear_down`'s tree-kill arm begins the wait with no threshold.
#[skuld::test]
fn the_wait_after_a_refused_kill_a_tree_kill_reached_warns_past_the_threshold() {
    let fake = fake_slow_to_exit().signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]);
    let _fire = fire_on_block(&fake);
    let reach = FakeReach::answering(Ok(true));
    let child = OwnedChild::new(Box::new(fake));
    let kill = Kill {
        disposition: Disposition::Leave,
        tree: Some(&reach),
    };
    let begun = child.begin_tear_down(Some(id()), kill, Some(due_now()));
    let BeginOutcome::Wait(wait) = begun else {
        panic!("a tree kill that reached the child leaves the reap pending: {begun:?}");
    };
    let mut torn = None;
    let warns = slow_warns_during(|| torn = Some(wait.settle(&child)));
    assert_eq!(torn.expect("settled").fate(), ChildFate::Reaped);
    assert_eq!(warns, 1);
}

/// The reap of a child a tree kill has just ended warns past the threshold it is given.
///
/// Mutant: `reap_after_tree_kill` begins the wait with no threshold.
#[cfg(unix)]
#[skuld::test]
fn the_reap_after_a_tree_kill_warns_past_the_threshold() {
    let fake = fake_slow_to_exit();
    let _fire = fire_on_block(&fake);
    let child = OwnedChild::new(Box::new(fake));
    let mut torn = None;
    let warns = slow_warns_during(|| {
        torn = Some(child.reap_after_tree_kill(&child.teardown_subject(), Disposition::Leave, Some(due_now())));
    });
    assert_eq!(torn.expect("settled").fate(), ChildFate::Reaped);
    assert_eq!(warns, 1);
}

/// The wait for a front a kill sent elsewhere is ending, settled apart from the look that found it
/// dying, warns past the threshold the look was given. A front no kill reached has no wait.
///
/// Mutants: `FrontWait` does not keep its threshold; `begin_look_at_front` answers `Done` for a
/// front the kill reached, or a wait for one it did not.
#[skuld::test]
fn the_wait_for_a_front_a_kill_reached_warns_past_the_threshold_the_look_was_given() {
    let fake = fake_slow_to_exit();
    let _fire = fire_on_block(&fake);
    let child = OwnedChild::new(Box::new(fake));
    let reach = FakeReach::answering(Ok(true));
    let begun = child.begin_look_at_front(Some(id()), Ok(Some(&reach)), Some(due_now()));
    let BeginOutcome::Wait(wait) = begun else {
        panic!("a front the kill reached is waited for: {begun:?}");
    };
    let mut look = None;
    let warns = slow_warns_during(|| look = Some(wait.settle(&child)));
    assert_eq!(look.expect("settled").fate, ChildFate::Reaped);
    assert_eq!(warns, 1);

    let child = OwnedChild::new(Box::new(fake_slow_to_exit()));
    let reach = FakeReach::answering(Ok(false));
    let begun = child.begin_look_at_front(Some(id()), Ok(Some(&reach)), Some(due_now()));
    assert!(
        matches!(begun, BeginOutcome::Done(_)),
        "a front no kill reached is left: {begun:?}"
    );
}
