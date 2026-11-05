//! The look arm of the teardown policy of `OwnedChild` over a `FakeProcess`: an elevation front,
//! which is sent nothing (see `owned::teardown`). The signals table of every fake is empty, so a
//! signal panics.

use std::cell::RefCell;
use std::io;

use super::teardown::{child_with_an_unreadable_exit, due_now, exit, fake, fire_on_block, id, slow_warns, PID};
use crate::child::lifecycle::Wording;
use crate::child::owned::teardown::{FrontLook, LookOutcome, Reach};
use crate::child::owned::OwnedChild;
use crate::error::ChildFate;
use crate::identity::ProcessId;
use crate::os_process::child::Foreign;
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::wait::teardown_warn::Due;

/// A [`Reach`] with a stated answer, and the pids of the children it was asked about.
pub(super) struct FakeReach {
    answer: Result<bool, io::ErrorKind>,
    asked: RefCell<Vec<Option<u32>>>,
}

impl FakeReach {
    pub(super) fn answering(answer: Result<bool, io::ErrorKind>) -> Self {
        Self {
            answer,
            asked: RefCell::default(),
        }
    }

    pub(super) fn asked(&self) -> Vec<Option<u32>> {
        self.asked.borrow().clone()
    }
}

impl Reach for FakeReach {
    fn reached(&self, child: &OwnedChild) -> io::Result<bool> {
        self.asked.borrow_mut().push(child.pid());
        self.answer.map_err(io::Error::from)
    }
}

/// What the look at a front is given to tell whether a kill sent elsewhere reached it: a reach, or
/// none; or the failure of reading the subtree that kill went through.
type Reaches<'a> = Result<Option<&'a dyn Reach>, io::Error>;

/// `look_at_front(id, reach, due)` over `fake`, and everything it logged on this thread.
fn look_logged(
    fake: &FakeProcess,
    id: Option<ProcessId>,
    reach: Reaches<'_>,
    due: Option<Due>,
) -> (FrontLook, Vec<(log::Level, String)>) {
    crate::log_capture::install();
    let child = OwnedChild::new(Box::new(fake.clone()));
    let mark = crate::log_capture::mark();
    let torn = child.look_at_front(id, reach, due);
    (torn, crate::log_capture::records_since_on_current_thread(mark, ""))
}

fn look(fake: &FakeProcess, reach: Option<&dyn Reach>) -> FrontLook {
    look_logged(fake, Some(id()), Ok(reach), None).0
}

/// How the look at a front went, as far as the tests tell it apart.
#[derive(Debug, PartialEq, Eq)]
enum Went {
    /// The look, or the wait after it, ended; the fate and `uncollected` say how.
    Ended,
    LeftRunning,
    PlaceUnreadable,
    SubtreeUnreadable,
}

fn went(torn: &FrontLook) -> Went {
    match &torn.look {
        LookOutcome::Ended(_) => Went::Ended,
        LookOutcome::LeftRunning => Went::LeftRunning,
        LookOutcome::PlaceUnreadable(_) => Went::PlaceUnreadable,
        LookOutcome::SubtreeUnreadable(_) => Went::SubtreeUnreadable,
    }
}

/// Whether the look left the front uncollected, as the wording of the look says: a look that did
/// not end is a front still running.
fn uncollected(torn: &FrontLook) -> bool {
    match &torn.look {
        LookOutcome::Ended(settlement) => {
            matches!(settlement.wording("", None, None), Wording::Uncollected(_))
        }
        _ => true,
    }
}

/// The policy words nothing of a front: what the drop says is its own, from the typed look.
#[track_caller]
fn assert_outcome(torn: &FrontLook, fate: ChildFate, went_as: Went) {
    assert_eq!((&torn.fate, went(torn)), (&fate, went_as), "{torn:?}");
}

/// A front that has exited at the look is reaped, and nothing asks where it is.
///
/// Mutant: the reach is asked first.
#[skuld::test]
fn a_front_that_has_exited_is_reaped_without_asking_where_it_is() {
    let fake = fake().reaps([ReapAnswer::Reaped(exit())]);
    let reach = FakeReach::answering(Ok(true));
    let torn = look(&fake, Some(&reach));
    assert_outcome(&torn, ChildFate::Reaped, Went::Ended);
    assert_eq!(reach.asked(), []);
}

/// A running front with no reach is left running, not waited for, and not worded by the policy.
///
/// Mutants: it is waited for; it is called reaped; the policy words it.
#[skuld::test]
fn a_running_front_with_no_reach_is_left_running_and_not_waited_for() {
    let fake = fake().reaps([ReapAnswer::Running]);
    let _fire = fire_on_block(&fake);
    let torn = look(&fake, None);
    assert_outcome(&torn, ChildFate::Running { id: Some(id()) }, Went::LeftRunning);
    assert_eq!(fake.looks(), 1);
    assert_eq!(crate::wait::block_probe::take(), [], "no wait");
}

/// A running front the kill did not reach is left, as with no reach, and the reach was asked once
/// about this child.
///
/// Mutant: `Ok(false)` is taken for `Ok(true)`.
#[skuld::test]
fn a_running_front_the_kill_did_not_reach_is_left_running() {
    let fake = fake().reaps([ReapAnswer::Running]);
    let _fire = fire_on_block(&fake);
    let reach = FakeReach::answering(Ok(false));
    let torn = look(&fake, Some(&reach));
    assert_outcome(&torn, ChildFate::Running { id: Some(id()) }, Went::LeftRunning);
    assert_eq!(reach.asked(), [Some(PID)]);
    assert_eq!(crate::wait::block_probe::take(), [], "no wait");
}

/// A running front the kill reached is dying: it is waited for, without a bound, and reaped.
///
/// Mutants: it is left; the wait is a look; the wait is bounded.
#[skuld::test]
fn a_running_front_the_kill_reached_is_waited_for_and_reaped() {
    let fake = fake().reaps([ReapAnswer::Running, ReapAnswer::Running, ReapAnswer::Reaped(exit())]);
    let _fire = fire_on_block(&fake);
    let torn = look(&fake, Some(&FakeReach::answering(Ok(true))));
    assert_outcome(&torn, ChildFate::Reaped, Went::Ended);
    assert_eq!(fake.looks(), 3, "the look, the wait's look, the look the wait woke to");
    assert_eq!(crate::wait::block_probe::take(), [None], "one unbounded block");
}

/// A wait for a dying front that fails leaves it unaccounted for and uncollected. The kill landed,
/// so the fate is `Killed`.
///
/// Mutant: the failure is dropped; the fate is `Unknown`; the front is collected.
#[skuld::test]
fn a_failed_wait_for_a_reached_front_is_unaccounted_for() {
    let fake = fake().reaps([ReapAnswer::Running, ReapAnswer::Err(io::ErrorKind::Other)]);
    let _fire = fire_on_block(&fake);
    let torn = look(&fake, Some(&FakeReach::answering(Ok(true))));
    assert_outcome(&torn, ChildFate::Killed, Went::Ended);
    assert!(uncollected(&torn), "{torn:?}");
}

/// A front reaped by someone else between the look and the wait is `Killed` (the cgroup kill landed
/// first), unaccounted for, and nothing above `debug` is logged.
///
/// Mutants: the foreign reap is warned of; it is `Gone`.
#[skuld::test]
fn a_front_reaped_elsewhere_between_the_look_and_the_wait_is_killed_and_silent() {
    let fake = fake().reaps([ReapAnswer::Running, ReapAnswer::Foreign(Foreign::Gone)]);
    let _fire = fire_on_block(&fake);
    let (torn, records) = look_logged(&fake, Some(id()), Ok(Some(&FakeReach::answering(Ok(true)))), None);
    assert_outcome(&torn, ChildFate::Killed, Went::Ended);
    assert!(!uncollected(&torn), "{torn:?}");
    assert!(
        records.iter().all(|(level, _)| *level >= log::Level::Debug),
        "{records:?}"
    );
}

/// A front reaped by someone else in the wait for it, whose zombie launchd holds, is `Killed`, as for
/// any foreign reap after the kill, and the policy logs nothing above `debug`: the note is the
/// wording's.
///
/// Mutant: the policy logs the launchd note itself.
#[skuld::test]
fn a_dying_front_launchd_holds_is_killed_and_not_logged_by_the_policy() {
    let fake = fake().reaps([ReapAnswer::Running, ReapAnswer::Foreign(Foreign::Orphaned)]);
    let _fire = fire_on_block(&fake);
    let (torn, records) = look_logged(&fake, Some(id()), Ok(Some(&FakeReach::answering(Ok(true)))), None);
    assert_outcome(&torn, ChildFate::Killed, Went::Ended);
    assert!(
        records.iter().all(|(level, _)| *level < log::Level::Warn),
        "{records:?}"
    );
}

/// A front whose place cannot be read is not waited for. The look saw it running, so its fate is
/// `Running`, and it is left for an unreadable place.
///
/// Mutants: an unreadable place is taken for reached; the fate is `Unknown`.
#[skuld::test]
fn a_front_whose_place_cannot_be_read_is_left_running_and_not_waited_for() {
    let fake = fake().reaps([ReapAnswer::Running]);
    let _fire = fire_on_block(&fake);
    let torn = look(&fake, Some(&FakeReach::answering(Err(io::ErrorKind::Other))));
    assert_outcome(&torn, ChildFate::Running { id: Some(id()) }, Went::PlaceUnreadable);
    assert_eq!(fake.looks(), 1);
    assert_eq!(crate::wait::block_probe::take(), [], "no wait");
}

/// What the test reads an error back by, to tell the error that went in from a copy of it.
#[derive(Debug)]
struct Original;

impl std::fmt::Display for Original {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the leaf cannot be read")
    }
}

impl std::error::Error for Original {}

/// A front whose leaf's subtree cannot be read is left running for that, not for an unreadable
/// place, with the very error it was given.
///
/// Mutants: an unreadable subtree is reported as an unreadable place; the error is rebuilt from its
/// kind and text; the fate is `Unknown`.
#[skuld::test]
fn a_front_whose_subtree_cannot_be_read_is_left_for_the_subtree_with_its_own_error() {
    let fake = fake().reaps([ReapAnswer::Running]);
    let unreadable = io::Error::new(io::ErrorKind::PermissionDenied, Original);
    let (torn, _) = look_logged(&fake, Some(id()), Err(unreadable), None);
    assert_outcome(&torn, ChildFate::Running { id: Some(id()) }, Went::SubtreeUnreadable);
    let LookOutcome::SubtreeUnreadable(e) = &torn.look else {
        panic!("{torn:?}");
    };
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    assert!(e.get_ref().is_some_and(|inner| inner.is::<Original>()), "{e:?}");
}

/// A front that has exited is reaped whatever the subtree: the subtree is asked about only for a
/// front still running.
///
/// Mutant: an unreadable subtree is looked at before the front.
#[skuld::test]
fn a_front_that_has_exited_is_reaped_though_its_subtree_cannot_be_read() {
    let fake = fake().reaps([ReapAnswer::Reaped(exit())]);
    let (torn, _) = look_logged(&fake, Some(id()), Err(io::Error::from(io::ErrorKind::Other)), None);
    assert_outcome(&torn, ChildFate::Reaped, Went::Ended);
}

/// What a drop says of each way it ends a front, word for word as the drop on `azhukova/dev` does:
/// the front's pid, then the cause, with `why` in the running one's. The wording goes through the
/// drop's own rendering, over what `tear_down` returned.
#[cfg(unix)]
mod worded {
    use super::super::teardown::warn_of;
    use super::super::teardown_lines::said_of;
    use super::*;
    use crate::child::lifecycle::Settlement;
    use crate::child::owned::teardown::{Disposition, TeardownOutcome};
    use crate::child::owned::ChildWaitOutcome;
    use crate::os_process::child::ExitRecord;

    const WHY: &str = "the front is not in a cgroup this drop killed";

    /// The two things a caller can do with a front still running. An outcome that hands nothing
    /// back is worded the same under both.
    const BOTH: [Disposition; 2] = [Disposition::Leave, Disposition::HandBack];

    /// The outcome of `tear_down` over `fake`, as the drop words it for a caller that does
    /// `disposition`, and what the wording logged: nothing, the caller logs the clause.
    fn worded_by_the_drop(
        disposition: Disposition,
        fake: &FakeProcess,
        reach: Reaches<'_>,
    ) -> (TeardownOutcome, Vec<(log::Level, String)>) {
        let (torn, _) = look_logged(fake, Some(id()), reach, None);
        let mark = crate::log_capture::mark();
        let worded = crate::child::word_front(PID, &WHY, disposition, torn);
        (
            worded,
            crate::log_capture::records_since_on_current_thread(mark, "elevation front pid"),
        )
    }

    fn cause() -> String {
        io::Error::from(io::ErrorKind::Other).to_string()
    }

    /// The clause is a warn that says `wanted`, for the caller's one warn.
    #[track_caller]
    fn assert_left(disposition: Disposition, reach: Reaches<'_>, fake: &FakeProcess, wanted: &str) {
        let _fire = fire_on_block(fake);
        let (worded, records) = worded_by_the_drop(disposition, fake, reach);
        assert_eq!(warn_of(&worded), Some(wanted), "{disposition:?}: {worded:?}");
        assert_eq!(records, [], "the wording logs nothing: the caller does");
    }

    /// The clause is a `debug` line that says `wanted`.
    #[track_caller]
    fn assert_debug(disposition: Disposition, reach: Reaches<'_>, fake: &FakeProcess, wanted: &str) {
        let _fire = fire_on_block(fake);
        let (worded, records) = worded_by_the_drop(disposition, fake, reach);
        assert_eq!(
            said_of(&worded),
            Some((log::Level::Debug, wanted.to_owned())),
            "{disposition:?}: {worded:?}"
        );
        assert_eq!(records, [], "the wording logs nothing: the caller does");
    }

    #[skuld::test]
    fn a_front_left_running_is_worded_with_why() {
        assert_left(
            Disposition::Leave,
            Ok(None),
            &fake().reaps([ReapAnswer::Running]),
            "elevation front pid 4242 is left running and unreaped: the front is not in a cgroup this drop killed, and a kill of the front would orphan the elevated program",
        );
        assert_left(
            Disposition::Leave,
            Ok(Some(&FakeReach::answering(Ok(false)))),
            &fake().reaps([ReapAnswer::Running]),
            "elevation front pid 4242 is left running and unreaped: the front is not in a cgroup this drop killed, and a kill of the front would orphan the elevated program",
        );
    }

    /// A caller that hands the front back says so, where the one that leaves it says it is left.
    ///
    /// Mutant: the wording ignores the disposition.
    #[skuld::test]
    fn a_front_left_running_is_worded_as_handed_back_for_a_caller_that_hands_it_back() {
        assert_left(
            Disposition::HandBack,
            Ok(None),
            &fake().reaps([ReapAnswer::Running]),
            "elevation front pid 4242 is running and unreaped: the front is not in a cgroup this drop killed, and a kill of the front would orphan the elevated program; handed back to the caller in the error",
        );
        assert_left(
            Disposition::HandBack,
            Ok(Some(&FakeReach::answering(Ok(false)))),
            &fake().reaps([ReapAnswer::Running]),
            "elevation front pid 4242 is running and unreaped: the front is not in a cgroup this drop killed, and a kill of the front would orphan the elevated program; handed back to the caller in the error",
        );
    }

    /// Mutant: `Leave` words the front as handed back.
    #[skuld::test]
    fn a_front_whose_place_cannot_be_read_is_worded_as_left_for_a_caller_that_leaves_it() {
        assert_left(
            Disposition::Leave,
            Ok(Some(&FakeReach::answering(Err(io::ErrorKind::Other)))),
            &fake().reaps([ReapAnswer::Running]),
            &format!("elevation front pid 4242 is left unreaped: where it is cannot be read ({}), so it is not known whether the cgroup kill ended it", cause()),
        );
    }

    /// Mutant: `HandBack` words the front as left.
    #[skuld::test]
    fn a_front_whose_place_cannot_be_read_is_worded_as_handed_back_for_a_caller_that_hands_it_back() {
        assert_left(
            Disposition::HandBack,
            Ok(Some(&FakeReach::answering(Err(io::ErrorKind::Other)))),
            &fake().reaps([ReapAnswer::Running]),
            &format!("elevation front pid 4242 is running and unreaped: where it is cannot be read ({}), so it is not known whether the cgroup kill ended it; handed back to the caller in the error", cause()),
        );
    }

    /// Mutant: `Leave` words the front as handed back.
    #[skuld::test]
    fn a_front_whose_subtree_cannot_be_read_is_worded_as_left_for_a_caller_that_leaves_it() {
        assert_left(
            Disposition::Leave,
            Err(io::Error::from(io::ErrorKind::Other)),
            &fake().reaps([ReapAnswer::Running]),
            &format!("elevation front pid 4242 is left unreaped: its leaf's subtree cannot be read ({}), so it is not known whether the cgroup kill ended it", cause()),
        );
    }

    /// Mutant: `HandBack` words the front as left.
    #[skuld::test]
    fn a_front_whose_subtree_cannot_be_read_is_worded_as_handed_back_for_a_caller_that_hands_it_back() {
        assert_left(
            Disposition::HandBack,
            Err(io::Error::from(io::ErrorKind::Other)),
            &fake().reaps([ReapAnswer::Running]),
            &format!("elevation front pid 4242 is running and unreaped: its leaf's subtree cannot be read ({}), so it is not known whether the cgroup kill ended it; handed back to the caller in the error", cause()),
        );
    }

    /// The suffix of an uncollected front: handed back by a caller that hands it back, left by one
    /// that leaves it.
    ///
    /// Mutant: the wording ignores the disposition.
    fn handed_back(disposition: Disposition) -> &'static str {
        match disposition {
            Disposition::Leave => crate::child::owned::owned_tests::teardown_lines::LEFT,
            Disposition::HandBack => crate::child::owned::owned_tests::teardown_lines::HANDED_BACK,
        }
    }

    /// A look that failed, and a wait that failed after the kill, are the same failed wait.
    #[skuld::test]
    fn a_front_whose_wait_failed_is_worded() {
        let worded = |disposition: Disposition| {
            format!(
                "elevation front pid 4242: the wait failed: {}{}",
                cause(),
                handed_back(disposition)
            )
        };
        for disposition in BOTH {
            assert_left(
                disposition,
                Ok(None),
                &fake().reaps([ReapAnswer::Err(io::ErrorKind::Other)]),
                &worded(disposition),
            );
            assert_left(
                disposition,
                Ok(Some(&FakeReach::answering(Ok(true)))),
                &fake().reaps([ReapAnswer::Running, ReapAnswer::Err(io::ErrorKind::Other)]),
                &worded(disposition),
            );
        }
    }

    /// A front the cgroup kill ended, whose reap consumed the zombie but read no exit record, is
    /// worded as reaped with an unreadable record: not as a reap that failed, and with no hand-back
    /// the caller has no child for. (A debug build asserts on the reap that produces it, so the
    /// outcome is stated.)
    ///
    /// Mutant: an unreadable record is worded as a failed wait.
    #[skuld::test]
    fn a_front_reaped_with_an_unreadable_exit_record_is_worded_as_reaped() {
        for disposition in BOTH {
            let answer = Ok(ChildWaitOutcome::Exited(ExitRecord::Unreadable { si_code: 7 }));
            let torn = FrontLook {
                fate: ChildFate::Reaped,
                look: LookOutcome::Ended(Settlement::new(answer, true)),
            };
            let worded = crate::child::word_front(PID, &WHY, disposition, torn);
            assert_eq!(
                warn_of(&worded),
                Some(
                    "elevation front pid 4242: reaped it after the kill; the child's exit record was unreadable \
                     (si_code 7)"
                ),
                "{disposition:?}"
            );
        }
    }

    /// A front collected with its exit record unreadable at the first look is worded as reaped, without
    /// a hand-back the caller has no child for.
    ///
    /// Mutant: a look that ended with an unreadable record is worded as a failure.
    #[skuld::test]
    fn a_front_collected_with_an_unreadable_exit_record_is_worded_without_a_hand_back() {
        for disposition in BOTH {
            let torn = child_with_an_unreadable_exit().look_at_front(Some(id()), Ok(None), None);
            let worded = crate::child::word_front(PID, &WHY, disposition, torn);
            let left = warn_of(&worded).expect("a warn to say");
            assert!(left.contains("reaped it;") && left.contains("unreadable"), "{left}");
            assert!(
                !left.contains("failed") && !left.contains("handed back"),
                "{disposition:?}: {left}"
            );
        }
    }

    /// A front reaped with a status is said at `debug` as reaped, "after the kill" only after a wait
    /// that a kill sent elsewhere bounded.
    ///
    /// Mutants: the clause is a warn, or missing; "after the kill" ignores the kill.
    #[skuld::test]
    fn a_front_reaped_with_a_status_is_said_at_debug() {
        for disposition in BOTH {
            assert_debug(
                disposition,
                Ok(None),
                &fake().reaps([ReapAnswer::Reaped(exit())]),
                "elevation front pid 4242: reaped it",
            );
            assert_debug(
                disposition,
                Ok(Some(&FakeReach::answering(Ok(true)))),
                &fake().reaps([ReapAnswer::Running, ReapAnswer::Running, ReapAnswer::Reaped(exit())]),
                "elevation front pid 4242: reaped it after the kill",
            );
        }
    }

    /// A front whose zombie launchd holds is warned of at the first look and in the wait for it, led
    /// by its name.
    ///
    /// Mutant: the wording is quiet about launchd, or says it at `debug`.
    #[skuld::test]
    fn a_front_launchd_holds_is_warned_of_in_the_wording() {
        let note = "elevation front pid 4242: not ours to reap (launchd holds its zombie, because its tracer died)";
        for disposition in BOTH {
            assert_left(
                disposition,
                Ok(None),
                &fake().reaps([ReapAnswer::Foreign(Foreign::Orphaned)]),
                note,
            );
            assert_left(
                disposition,
                Ok(Some(&FakeReach::answering(Ok(true)))),
                &fake().reaps([ReapAnswer::Running, ReapAnswer::Foreign(Foreign::Orphaned)]),
                note,
            );
        }
    }

    #[skuld::test]
    fn a_front_reaped_by_someone_else_is_said_at_debug() {
        for disposition in BOTH {
            assert_debug(
                disposition,
                Ok(None),
                &fake().reaps([ReapAnswer::Foreign(Foreign::Gone)]),
                "elevation front pid 4242: reaped by someone else",
            );
            assert_debug(
                disposition,
                Ok(Some(&FakeReach::answering(Ok(true)))),
                &fake().reaps([ReapAnswer::Running, ReapAnswer::Foreign(Foreign::Gone)]),
                "elevation front pid 4242: reaped by someone else",
            );
        }
    }
}

/// A front someone else reaped is gone, unaccounted for, and nothing is warned of.
///
/// Mutant: the look reads it as running.
#[skuld::test]
fn a_front_reaped_by_someone_else_is_gone() {
    let fake = fake().reaps([ReapAnswer::Foreign(Foreign::Gone)]);
    let reach = FakeReach::answering(Ok(true));
    let torn = look(&fake, Some(&reach));
    assert_outcome(&torn, ChildFate::Gone, Went::Ended);
    assert!(!uncollected(&torn), "{torn:?}");
    assert_eq!(reach.asked(), []);
}

/// A front whose zombie launchd holds is gone and collected, and the policy logs nothing above
/// `debug`: the launchd note is the wording's.
///
/// Mutant: the policy logs that launchd holds the zombie.
#[skuld::test]
fn a_front_launchd_holds_is_gone_and_not_logged_by_the_policy() {
    let fake = fake().reaps([ReapAnswer::Foreign(Foreign::Orphaned)]);
    let (torn, records) = look_logged(&fake, Some(id()), Ok(None), None);
    assert_outcome(&torn, ChildFate::Gone, Went::Ended);
    assert!(
        records.iter().all(|(level, _)| *level < log::Level::Warn),
        "{records:?}"
    );
}

/// A front with no pid that launchd holds is as quiet in the policy.
///
/// Mutant: the note is built for a pid-less front.
#[skuld::test]
fn a_pidless_front_launchd_holds_is_gone_and_not_logged_by_the_policy() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Foreign(Foreign::Orphaned)]);
    let (torn, records) = look_logged(&fake, None, Ok(None), None);
    assert_outcome(&torn, ChildFate::Gone, Went::Ended);
    assert!(
        records.iter().all(|(level, _)| *level < log::Level::Warn),
        "{records:?}"
    );
}

/// A look that fails leaves the front unaccounted for, uncollected, with an unknown fate.
///
/// Mutants: the failed look is read as an exit or as running; the front is collected.
#[skuld::test]
fn a_failed_look_at_a_front_is_unknown() {
    let fake = fake().reaps([ReapAnswer::Err(io::ErrorKind::Other)]);
    let reach = FakeReach::answering(Ok(true));
    let torn = look(&fake, Some(&reach));
    assert_outcome(&torn, ChildFate::Unknown, Went::Ended);
    assert!(uncollected(&torn), "{torn:?}");
    assert_eq!(reach.asked(), []);
}

/// A look sends nothing, whatever it finds.
///
/// Mutant: the front is signalled (the empty `signals` table panics, and the send is recorded).
#[skuld::test]
fn a_look_teardown_sends_nothing() {
    let fake = fake().reaps([ReapAnswer::Running]);
    let _ = look(&fake, None);
    assert_eq!(fake.signal_calls(), []);
}

/// The identity the caller read, or its absence, is the one a running front keeps.
///
/// Mutant: the outcome carries a made-up identity.
#[skuld::test]
fn the_identity_passes_into_a_front_left_running() {
    for given in [Some(id()), None] {
        let fake = fake().reaps([ReapAnswer::Running]);
        let (torn, _) = look_logged(&fake, given, Ok(None), None);
        assert_eq!(torn.fate, ChildFate::Running { id: given });
    }
}

/// A front with no pid is left running like any other.
///
/// Mutant: a pid is made up.
#[skuld::test]
fn a_pidless_front_is_left_running() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Running]);
    let torn = look(&fake, None);
    assert_eq!(went(&torn), Went::LeftRunning, "{torn:?}");
}

/// A front waited for past the threshold is warned of once before the wait blocks; one that exits
/// before it is not.
///
/// Mutants: no warn; the warn is not conditional on the bounded wait.
#[skuld::test]
fn a_front_waited_for_past_its_threshold_warns_once() {
    // The look sees it running; then the bounded wait either finds it still running (the warn) or
    // reaps it.
    for (reaps, warned) in [
        (
            vec![ReapAnswer::Running, ReapAnswer::Running, ReapAnswer::Reaped(exit())],
            1,
        ),
        (vec![ReapAnswer::Running, ReapAnswer::Reaped(exit())], 0),
    ] {
        let fake = fake().reaps(reaps);
        let _fire = fire_on_block(&fake);
        let (torn, records) = look_logged(
            &fake,
            Some(id()),
            Ok(Some(&FakeReach::answering(Ok(true)))),
            Some(due_now()),
        );
        assert_outcome(&torn, ChildFate::Reaped, Went::Ended);
        assert_eq!(slow_warns(&records).len(), warned, "{records:?}");
    }
}

/// A front whose look consumed the zombie without an exit record is reaped and collected: only its
/// record is lost, and nothing is left to hand back.
///
/// Mutant: a look that ended with an unreadable record is a failed look, `Unknown` and uncollected.
#[skuld::test]
fn a_front_whose_look_found_the_exit_record_unreadable_is_reaped_and_collected() {
    let torn = child_with_an_unreadable_exit().look_at_front(Some(id()), Ok(None), None);
    assert_eq!((went(&torn), &torn.fate), (Went::Ended, &ChildFate::Reaped), "{torn:?}");
    assert!(!uncollected(&torn), "{torn:?}");
}

/// A front left running is never waited for, so a threshold never has it look for the exit.
///
/// Mutant: the threshold's watch runs whatever the reach said (the empty `exited` table panics).
#[skuld::test]
fn a_front_left_running_never_looks_for_the_exit() {
    let fake = fake().reaps([ReapAnswer::Running]);
    let (torn, records) = look_logged(&fake, Some(id()), Ok(None), Some(due_now()));
    assert_eq!(went(&torn), Went::LeftRunning, "{torn:?}");
    assert_eq!(fake.looks(), 1);
    assert_eq!(slow_warns(&records).len(), 0);
}

/// A look is not a root teardown; a kill is.
///
/// Mutant: the count is taken at the entry point.
#[skuld::test]
fn a_look_teardown_counts_no_root_teardown() {
    let recorder = crate::child::owned::seams::record_root_teardowns();
    let fake = fake().reaps([ReapAnswer::Reaped(exit())]);
    let _ = look(&fake, None);
    assert_eq!(recorder.count(), 0);
}
