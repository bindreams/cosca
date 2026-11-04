//! The look arm of the teardown policy of `OwnedChild` over a `FakeProcess`: an elevation front,
//! which is sent nothing (see `owned::teardown`). The signals table of every fake is empty, so a
//! signal panics.

use std::cell::RefCell;
use std::io;

use super::teardown::{due_now, exit, fake, fire_on_block, id, slow_warns, PID};
use crate::child::owned::teardown::{Reach, TeardownKind, TeardownOutcome};
use crate::child::owned::OwnedChild;
use crate::child::spawn::FrontFate;
use crate::error::ChildFate;
use crate::identity::ProcessId;
use crate::os_process::child::Foreign;
use crate::os_process::fake::{Answer, FakeProcess, ReapAnswer};
use crate::wait::teardown_warn::Due;

/// A [`Reach`] with a stated answer, and the pids of the children it was asked about.
struct FakeReach {
    answer: Result<bool, io::ErrorKind>,
    asked: RefCell<Vec<Option<u32>>>,
}

impl FakeReach {
    fn answering(answer: Result<bool, io::ErrorKind>) -> Self {
        Self {
            answer,
            asked: RefCell::default(),
        }
    }

    fn asked(&self) -> Vec<Option<u32>> {
        self.asked.borrow().clone()
    }
}

impl Reach for FakeReach {
    fn reached(&self, child: &OwnedChild) -> io::Result<bool> {
        self.asked.borrow_mut().push(child.pid());
        self.answer.map_err(io::Error::from)
    }
}

/// `tear_down(id, Look(reach), due)` over `fake`, and everything it logged on this thread.
fn look_logged(
    fake: &FakeProcess,
    id: Option<ProcessId>,
    reach: Option<&dyn Reach>,
    due: Option<Due>,
) -> (TeardownOutcome, Vec<(log::Level, String)>) {
    crate::log_capture::install();
    let child = OwnedChild::new(Box::new(fake.clone()));
    let mark = crate::log_capture::mark();
    let torn = child.tear_down(id, TeardownKind::Look(reach), due);
    (torn, crate::log_capture::records_since_on_current_thread(mark, ""))
}

fn look(fake: &FakeProcess, reach: Option<&dyn Reach>) -> TeardownOutcome {
    look_logged(fake, Some(id()), reach, None).0
}

#[track_caller]
fn assert_outcome(torn: &TeardownOutcome, fate: ChildFate, front: FrontFate) {
    assert_eq!((&torn.fate, torn.front), (&fate, Some(front)), "{torn:?}");
}

/// A front that has exited at the look is reaped, and nothing asks where it is.
///
/// Mutant: the reach is asked first.
#[skuld::test]
fn a_front_that_has_exited_is_reaped_without_asking_where_it_is() {
    let fake = fake().reaps([ReapAnswer::Reaped(exit())]);
    let reach = FakeReach::answering(Ok(true));
    let torn = look(&fake, Some(&reach));
    assert_outcome(&torn, ChildFate::Reaped, FrontFate::Reaped);
    assert_eq!(torn.left, None);
    assert_eq!(reach.asked(), []);
}

/// A running front with no reach is left running, unreaped, with a warn that says so, and is not
/// waited for.
///
/// Mutants: it is waited for; it is called reaped; the warn omits what was left.
#[skuld::test]
fn a_running_front_with_no_reach_is_left_running_and_not_waited_for() {
    let fake = fake().reaps([ReapAnswer::Running]);
    let _fire = fire_on_block(&fake);
    let torn = look(&fake, None);
    assert_outcome(&torn, ChildFate::Running { id: Some(id()) }, FrontFate::LeftUnreaped);
    let left = torn.left.as_deref().expect("a front left running is warned of");
    assert!(
        left.contains(&PID.to_string()) && left.contains("left running and unreaped"),
        "{left}"
    );
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
    assert_outcome(&torn, ChildFate::Running { id: Some(id()) }, FrontFate::LeftUnreaped);
    assert!(
        torn.left
            .as_deref()
            .is_some_and(|left| left.contains("left running and unreaped")),
        "{torn:?}"
    );
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
    assert_outcome(&torn, ChildFate::Reaped, FrontFate::Reaped);
    assert_eq!(torn.left, None);
    assert_eq!(fake.looks(), 3, "the look, the wait's look, the look the wait woke to");
    assert_eq!(crate::wait::block_probe::take(), [None], "one unbounded block");
}

/// A wait for a dying front that fails leaves it unaccounted for, and the warn names the failed
/// reap. The kill landed, so the fate is `Killed`.
///
/// Mutant: the failure is dropped; the fate is `Unknown`.
#[skuld::test]
fn a_failed_wait_for_a_reached_front_is_unaccounted_for() {
    let fake = fake().reaps([ReapAnswer::Running, ReapAnswer::Err(io::ErrorKind::Other)]);
    let _fire = fire_on_block(&fake);
    let torn = look(&fake, Some(&FakeReach::answering(Ok(true))));
    assert_outcome(&torn, ChildFate::Killed, FrontFate::Unaccounted);
    assert!(
        torn.left
            .as_deref()
            .is_some_and(|left| left.contains("the reap after the kill failed")),
        "{torn:?}"
    );
}

/// A front reaped by someone else between the look and the wait is `Killed` (the cgroup kill landed
/// first), unaccounted for, and only the debug log says so.
///
/// Mutants: the foreign reap is warned of; it is `Gone`.
#[skuld::test]
fn a_front_reaped_elsewhere_between_the_look_and_the_wait_is_killed_and_silent() {
    let fake = fake().reaps([ReapAnswer::Running, ReapAnswer::Foreign(Foreign::Gone)]);
    let _fire = fire_on_block(&fake);
    let (torn, records) = look_logged(&fake, Some(id()), Some(&FakeReach::answering(Ok(true))), None);
    assert_outcome(&torn, ChildFate::Killed, FrontFate::Unaccounted);
    assert_eq!(torn.left, None);
    assert!(
        records.iter().all(|(level, _)| *level >= log::Level::Debug),
        "{records:?}"
    );
}

/// A front whose place cannot be read is neither waited for nor called running: its fate is
/// `Unknown` and the warn says where it is cannot be read.
///
/// Mutants: an unreadable place is taken for running, or for reached.
#[skuld::test]
fn a_front_whose_place_cannot_be_read_is_not_called_running_nor_waited_for() {
    let fake = fake().reaps([ReapAnswer::Running]);
    let _fire = fire_on_block(&fake);
    let torn = look(&fake, Some(&FakeReach::answering(Err(io::ErrorKind::Other))));
    assert_outcome(&torn, ChildFate::Unknown, FrontFate::Unplaced);
    let left = torn.left.as_deref().expect("an unplaced front is warned of");
    assert!(
        left.contains("cannot be read") && !left.contains("left running"),
        "{left}"
    );
    assert_eq!(fake.looks(), 1);
    assert_eq!(crate::wait::block_probe::take(), [], "no wait");
}

/// A front someone else reaped is gone, unaccounted for, and nothing is warned of.
///
/// Mutant: the look reads it as running.
#[skuld::test]
fn a_front_reaped_by_someone_else_is_gone() {
    let fake = fake().reaps([ReapAnswer::Foreign(Foreign::Gone)]);
    let reach = FakeReach::answering(Ok(true));
    let torn = look(&fake, Some(&reach));
    assert_outcome(&torn, ChildFate::Gone, FrontFate::Unaccounted);
    assert_eq!(torn.left, None);
    assert_eq!(reach.asked(), []);
}

/// A front whose zombie launchd holds is gone, unaccounted for, and the warn says why it is not
/// ours to reap.
///
/// Mutant: the launchd note is dropped.
#[skuld::test]
fn a_front_launchd_holds_is_gone_with_the_launchd_note() {
    let fake = fake().reaps([ReapAnswer::Foreign(Foreign::Orphaned)]);
    let torn = look(&fake, None);
    assert_outcome(&torn, ChildFate::Gone, FrontFate::Unaccounted);
    assert!(
        torn.left.as_deref().is_some_and(|left| left.contains("launchd")),
        "{torn:?}"
    );
}

/// A look that fails leaves the front unaccounted for with an unknown fate, and the warn names the
/// failure.
///
/// Mutants: the failed look is read as an exit or as running.
#[skuld::test]
fn a_failed_look_at_a_front_is_unknown() {
    let fake = fake().reaps([ReapAnswer::Err(io::ErrorKind::Other)]);
    let reach = FakeReach::answering(Ok(true));
    let torn = look(&fake, Some(&reach));
    assert_outcome(&torn, ChildFate::Unknown, FrontFate::Unaccounted);
    let failure = io::Error::from(io::ErrorKind::Other).to_string();
    assert!(
        torn.left.as_deref().is_some_and(|left| left.contains(&failure)),
        "{torn:?}"
    );
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
        let (torn, _) = look_logged(&fake, given, None, None);
        assert_eq!(torn.fate, ChildFate::Running { id: given });
    }
}

/// A front with no pid is named without a number.
///
/// Mutants: a pid is made up; the message is built with a number.
#[skuld::test]
fn a_pidless_front_is_named_without_a_number() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Running]);
    let torn = look(&fake, None);
    let left = torn.left.as_deref().expect("a front left running is warned of");
    assert!(left.contains("pid unknown"), "{left}");
    assert!(!left.chars().any(|c| c.is_ascii_digit()), "{left}");
}

/// A front waited for past the threshold is warned of once before the wait blocks; one that exits
/// before it is not.
///
/// Mutants: no warn; the warn is not conditional on the look.
#[skuld::test]
fn a_front_waited_for_past_its_threshold_warns_once() {
    for (exits, warned) in [(Answer::Running, 1), (Answer::Exited, 0)] {
        let fake = FakeProcess::new([exits]).with_pid(PID).reaps([
            ReapAnswer::Running,
            ReapAnswer::Running,
            ReapAnswer::Reaped(exit()),
        ]);
        let _fire = fire_on_block(&fake);
        let (torn, records) = look_logged(
            &fake,
            Some(id()),
            Some(&FakeReach::answering(Ok(true))),
            Some(due_now()),
        );
        assert_outcome(&torn, ChildFate::Reaped, FrontFate::Reaped);
        assert_eq!(slow_warns(&records).len(), warned, "{records:?}");
    }
}

/// A front left running is never waited for, so a threshold never has it look for the exit.
///
/// Mutant: the threshold's watch runs whatever the reach said (the empty `exited` table panics).
#[skuld::test]
fn a_front_left_running_never_looks_for_the_exit() {
    let fake = fake().reaps([ReapAnswer::Running]);
    let (torn, records) = look_logged(&fake, Some(id()), None, Some(due_now()));
    assert_eq!(torn.front, Some(FrontFate::LeftUnreaped));
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
