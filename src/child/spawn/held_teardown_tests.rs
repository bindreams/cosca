//! The sync spawn's teardown of the child it holds after the handshake (`tear_down_held`), over a
//! real child with scripted answers (`script_over`). Unprivileged: the leaf's subtree is stated, not
//! read from a cgroup.

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use super::Diagnosis;
use crate::child::owned::OwnedChild;
use crate::containment::cgroup::{fault, PlacedAtRemoval, Subtree, Swept};
use crate::elevation::front::Front;
use crate::error::{ChildFate, Error};
use crate::os_process::child::Foreign;
use crate::os_process::fake::{failed_signal, FakeProcess, ReapAnswer};
use crate::test_child::{held_uncontained_blocker, tear_down_held_holding};

/// The `Error` a failed spawn arm tears down after.
fn failed() -> Error {
    Error::Io(io::Error::other("the spawn failed"))
}

/// A live blocker the sync spawn would hold, the write end of its stdin, and the script the test
/// gives its answers through.
fn held_blocker(script: impl FnOnce(FakeProcess) -> FakeProcess) -> (OwnedChild, std::io::PipeWriter) {
    let (mut child, stdin) = held_uncontained_blocker(true);
    child.proc.script_over(script);
    // What `into_unreaped` does: the teardown below owns the root, so the handle drops inert.
    child.kill_on_drop = false;
    let owned = child.proc.take().expect("the child holds its root");
    (owned, stdin)
}

/// Every record at `warn` or above that this thread logged since `mark`.
fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

/// A subtree of a leaf with id 7, killed through, which places a task by its pidfd's cgroup id.
fn killed_subtree() -> Subtree {
    Subtree::new(
        Some(7),
        None,
        None,
        Swept::default(),
        PlacedAtRemoval::default(),
        Arc::new(AtomicBool::new(true)),
    )
}

/// A child whose kill is refused and whose look then fails is uncollected and still ours: the arm
/// hands it back though its fate is `Unknown`.
///
/// Mutant: only a `Running` fate hands back.
#[skuld::test]
fn a_refused_kill_whose_look_failed_is_handed_back() {
    let (owned, stdin) = held_blocker(|f| {
        f.signals([Err(io::Error::from(io::ErrorKind::PermissionDenied))])
            .reaps([ReapAnswer::Err(io::ErrorKind::Other)])
    });

    let (_, fate, handed_back) =
        tear_down_held_holding(owned, None, None, None, &mut Diagnosis::default(), stdin, failed());

    assert_eq!(fate, ChildFate::Unknown);
    handed_back.unreaped();
    handed_back.wait();
}

/// A front whose look fails is uncollected and still ours: handed back, and the error says so.
///
/// Mutants: only a `Running` fate hands back; the note does not say it is handed back.
#[skuld::test]
fn a_front_whose_look_failed_is_handed_back_and_the_error_says_so() {
    let (owned, stdin) = held_blocker(|f| f.reaps([ReapAnswer::Err(io::ErrorKind::Other)]));

    let (error, fate, handed_back) = tear_down_held_holding(
        owned,
        Some(Front::Sudo),
        None,
        None,
        &mut Diagnosis::default(),
        stdin,
        failed(),
    );

    assert_eq!(fate, ChildFate::Unknown);
    handed_back.unreaped();
    let error = error.to_string();
    assert!(
        error.contains("could not be waited on") && error.contains("handed back to the caller"),
        "{error}"
    );
    handed_back.wait();
}

/// A front whose place cannot be read is handed back, and the error says where it is cannot be read.
///
/// Mutant: `PlaceUnreadable` maps to `LeftUnreaped`, which words a front that is not placed.
#[skuld::test]
fn a_front_whose_place_cannot_be_read_is_handed_back_and_the_error_says_so() {
    let (owned, stdin) = held_blocker(|f| f.reaps([ReapAnswer::Running]));
    let subtree = killed_subtree();

    let (error, fate, handed_back) = {
        let _unreadable = fault::fail_pidfd_info();
        tear_down_held_holding(
            owned,
            Some(Front::Sudo),
            None,
            Some(&subtree),
            &mut Diagnosis::default(),
            stdin,
            failed(),
        )
    };

    assert!(matches!(fate, ChildFate::Running { .. }), "{fate:?}");
    handed_back.unreaped();
    let error = error.to_string();
    assert!(
        error.contains("where it is cannot be read") && error.contains("handed back to the caller"),
        "{error}"
    );
    handed_back.wait();
}

/// A front its leaf's kill reached, whose reap then fails, is `Killed`, uncollected and still ours:
/// handed back, and the error says it could not be waited on, not that it was reaped.
///
/// Mutant: a wait that failed after the kill reads as `Reaped`, or is not handed back.
#[skuld::test]
fn a_front_whose_reap_failed_after_the_leaf_kill_is_handed_back_and_the_error_says_so() {
    let (owned, stdin) = held_blocker(|f| f.reaps([ReapAnswer::Running, ReapAnswer::Err(io::ErrorKind::Other)]));
    let subtree = killed_subtree();

    let (error, fate, handed_back) = {
        let _placed = fault::force_pidfd_cgroup_id(7);
        tear_down_held_holding(
            owned,
            Some(Front::Sudo),
            None,
            Some(&subtree),
            &mut Diagnosis::default(),
            stdin,
            failed(),
        )
    };

    assert_eq!(fate, ChildFate::Killed);
    handed_back.unreaped();
    let error = error.to_string();
    assert!(
        error.contains("could not be waited on") && error.contains("handed back to the caller"),
        "{error}"
    );
    handed_back.wait();
}

/// A child that is not a front is killed and reaped: nothing is handed back, the error is the
/// spawn's own, and nothing warns.
///
/// Mutant: the arm hands back whatever the teardown left.
#[skuld::test]
fn a_child_that_is_not_a_front_is_killed_and_reaped_and_nothing_is_handed_back() {
    crate::log_capture::install();
    let (owned, stdin) = held_blocker(|f| f);
    let pid = owned.pid().expect("the held child has a pid");
    let mark = crate::log_capture::mark();

    let (error, fate, handed_back) =
        tear_down_held_holding(owned, None, None, None, &mut Diagnosis::default(), stdin, failed());

    assert_eq!(fate, ChildFate::Reaped);
    assert!(handed_back.is_none(), "a reaped child is not handed back");
    assert_eq!(
        error.to_string(),
        failed().to_string(),
        "a child that is not a front adds no note"
    );
    assert_eq!(warns_since(mark), Vec::<String>::new());
    assert_eq!(
        crate::child::front_kill_tests::reap(pid),
        None,
        "the teardown reaped it"
    );
}

/// A front someone else reaped is noted as it is for a caller that leaves it, not as handed back, and
/// nothing is handed back.
///
/// Mutant: the note is always the hand-back's.
#[skuld::test]
fn a_front_reaped_elsewhere_is_noted_without_a_hand_back() {
    let (owned, stdin) = held_blocker(|f| f.reaps([ReapAnswer::Foreign(Foreign::Gone)]));

    let (error, fate, handed_back) = tear_down_held_holding(
        owned,
        Some(Front::Sudo),
        None,
        None,
        &mut Diagnosis::default(),
        stdin,
        failed(),
    );

    assert_eq!(fate, ChildFate::Gone);
    assert!(handed_back.is_none());
    let error = error.to_string();
    assert!(
        error.contains("could not be waited on") && !error.contains("handed back"),
        "{error}"
    );
}

/// A front with no leaf subtree to say its kill reached it is left running, so it is handed back, and
/// the error says so in the words of a front handed back.
///
/// Mutant: the note says the front is left unreaped.
#[skuld::test]
fn a_running_front_with_no_subtree_is_handed_back_and_the_error_says_so() {
    let (owned, stdin) = held_blocker(|f| f.reaps([ReapAnswer::Running]));

    let (error, fate, handed_back) = tear_down_held_holding(
        owned,
        Some(Front::Sudo),
        None,
        None,
        &mut Diagnosis::default(),
        stdin,
        failed(),
    );

    assert!(matches!(fate, ChildFate::Running { .. }), "{fate:?}");
    handed_back.unreaped();
    let error = error.to_string();
    assert!(
        error.contains("the elevated program may be running; it is handed back to the caller"),
        "{error}"
    );
    handed_back.wait();
}

/// The check that failed the spawn leads the teardown's one warn, for a child killed and for a front
/// looked at.
///
/// Mutant: the arm warns the teardown's text alone, and the diagnosis is logged apart.
#[skuld::test]
fn the_diagnosis_leads_the_one_warn_of_the_teardown() {
    crate::log_capture::install();
    for front in [None, Some(Front::Sudo)] {
        let (owned, stdin) = held_blocker(|f| {
            f.signals([failed_signal(libc::EPERM)])
                .reaps([ReapAnswer::Err(io::ErrorKind::Other)])
        });
        let mut why = Diagnosis::default();
        why.add("diagnosis 7c2e");
        let mark = crate::log_capture::mark();

        let (_, _, handed_back) = tear_down_held_holding(owned, front, None, None, &mut why, stdin, failed());
        drop(why);

        let warns = warns_since(mark);
        assert_eq!(warns.len(), 1, "{front:?}: {warns:?}");
        assert!(warns[0].starts_with("diagnosis 7c2e; "), "{front:?}: {warns:?}");
        handed_back.wait();
    }
}

/// A front that is already a zombie when the teardown looks, because it exited on its own, is reaped
/// by the look: the error says it was reaped and nothing is handed back. The test waits for the
/// front's exit through its handle, so the zombie is there before the look.
///
/// Mutant: a zombie front is left unreaped.
#[skuld::test]
fn a_front_that_has_exited_is_reaped_without_waiting() {
    let (owned, stdin) = held_blocker(|f| f);
    let pid = owned.pid().expect("the held child has a pid");
    drop(stdin);
    assert!(owned.exited_by(None).expect("watch the front"), "the front exited");

    let (error, fate, handed_back) = tear_down_held_holding(
        owned,
        Some(Front::Sudo),
        None,
        None,
        &mut Diagnosis::default(),
        (),
        failed(),
    );

    assert_eq!(fate, ChildFate::Reaped);
    assert!(handed_back.is_none());
    let error = error.to_string();
    assert!(error.contains("and it was reaped"), "{error}");
    assert_eq!(
        crate::child::front_kill_tests::reap(pid),
        None,
        "the teardown reaped the front"
    );
}
