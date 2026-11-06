//! The sync spawn's teardown of the child it holds after the handshake (`tear_down_held`), over a
//! real child with scripted answers (`script_over`). Unprivileged: the leaf's subtree is stated, not
//! read from a cgroup.

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use super::held_teardown::{tear_down_held, HeldTeardown};
use super::Diagnosis;
use crate::child::owned::owned_tests::teardown_lines::{self, Found, Kill};
use crate::child::owned::teardown::{Disposition, Expect, HandleTeardown};
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
        error.contains("the elevated program may be running; handed back to the caller in the error"),
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
        assert!(
            warns[0].starts_with("teardown after a failed spawn: diagnosis 7c2e; "),
            "{front:?}: {warns:?}"
        );
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

/// `tear_down_held` for a caller that leaves what it could not end: `front`, with what the teardown
/// is told of the rest as `HeldTeardown` says, over `owned`.
fn tear_down_leaving(
    owned: OwnedChild,
    front: Option<Front>,
    why: &mut Diagnosis,
) -> (Error, ChildFate, Option<crate::Unreaped>) {
    let how = HeldTeardown {
        front,
        id: None,
        subtree: None,
        disposition: Disposition::Leave,
        due: None,
    };
    tear_down_held(owned, how, why, failed())
}

/// A child whose kill is refused, under a caller that leaves it, is left running and warned of, and
/// nothing is handed back. The child is the caller's to reap, and the test does.
///
/// Mutants: the arm hands back what a `Leave` caller leaves; the warn says it is handed back; the child
/// is reported reaped.
#[skuld::test]
fn a_refused_kill_under_leave_is_left_running_and_warned_and_nothing_is_handed_back() {
    crate::log_capture::install();
    let (owned, stdin) = held_blocker(|f| {
        f.signals([Err(io::Error::from(io::ErrorKind::PermissionDenied))])
            .reaps([ReapAnswer::Running])
    });
    let pid = owned.pid().expect("the held child has a pid");
    let mark = crate::log_capture::mark();

    let (_, fate, unreaped) = tear_down_leaving(owned, None, &mut Diagnosis::default());

    assert_eq!(fate, ChildFate::Running { id: None });
    assert!(unreaped.is_none(), "a caller that leaves it is handed nothing back");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("leaving it running") && !warns[0].contains("handed back"),
        "{warns:?}"
    );
    // The test's own cleanup: the blocker exits on its stdin's close, and is the test's to reap.
    drop(stdin);
    crate::child::front_kill_tests::reap(pid).expect("the left child is still unreaped");
}

/// A front still running, under a caller that leaves it, is noted as left unreaped, and nothing is
/// handed back.
///
/// Mutants: the note says it is handed back; the front is handed back.
#[skuld::test]
fn a_running_front_under_leave_is_noted_as_left_unreaped_and_nothing_is_handed_back() {
    crate::log_capture::install();
    let (owned, stdin) = held_blocker(|f| f.reaps([ReapAnswer::Running]));
    let pid = owned.pid().expect("the held child has a pid");
    let mark = crate::log_capture::mark();

    let (error, fate, unreaped) = tear_down_leaving(owned, Some(Front::Sudo), &mut Diagnosis::default());

    assert_eq!(fate, ChildFate::Running { id: None });
    assert!(unreaped.is_none());
    let error = error.to_string();
    assert!(
        error.contains("the elevated program may be running; left unreaped") && !error.contains("handed back"),
        "{error}"
    );
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("is left running and unreaped") && !warns[0].contains("handed back"),
        "{warns:?}"
    );
    drop(stdin);
    crate::child::front_kill_tests::reap(pid).expect("the left front is still unreaped");
}

/// A front whose pid is not known (tokio's spawn failed before it returned one) is named so, in the
/// error and in the warn.
///
/// Mutant: the front is named `pid 0`.
#[skuld::test]
fn a_front_with_no_pid_is_named_as_such() {
    crate::log_capture::install();
    let (owned, stdin) = held_blocker(|f| f);
    let pid = owned.pid().expect("the held child has a pid");
    // The same child, named by its pidfd alone: the copy is the pid-less handle's own.
    let pidfd = owned.pidfd().expect("a Linux child has its pidfd");
    let pidless = OwnedChild::new(Box::new(crate::os_process::linux::LinuxProcess::new(
        None,
        pidfd.try_clone_to_owned().expect("dup the pidfd"),
    )));
    let mark = crate::log_capture::mark();

    let (error, _, unreaped) = tear_down_leaving(pidless, Some(Front::Sudo), &mut Diagnosis::default());

    assert!(unreaped.is_none());
    let error = error.to_string();
    assert!(error.contains("the spawned child is what sudo left"), "{error}");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].starts_with("teardown after a failed spawn: the elevation front (pid unknown)"),
        "{warns:?}"
    );
    drop(stdin);
    drop(owned);
    crate::child::front_kill_tests::reap(pid).expect("the left front is still unreaped");
}

/// The teardown of the table's row `kill` and `found`, as a caller that leaves the child expects
/// `expect` of it, and the clause its row says.
fn teardown_of(kill: teardown_lines::Kill, found: teardown_lines::Found, expect: Expect) -> (HandleTeardown, String) {
    let row = teardown_lines::rows()
        .into_iter()
        .find(|row| row.kill == kill && row.found == found)
        .expect("the table has the row");
    let torn = HandleTeardown::new(teardown_lines::outcome(&row, Disposition::Leave), expect);
    (torn, row.leave)
}

/// The teardown whose kill was delivered and whose wait then failed: uncollected, and `Killed`, as a
/// failed wait on a pidfd leaves it.
fn after_a_failed_wait(expect: Expect) -> HandleTeardown {
    teardown_of(Kill::Delivered, Found::WaitFailed, expect).0
}

/// A failed wait on a pidfd no look failed on is a breach of the contract, asserted where the warn is
/// logged, whoever the caller is.
///
/// Mutant: `warn_teardown` asserts nothing.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "a wait on a child's own handle failed")]
fn a_failed_wait_on_a_pidfd_nothing_looked_at_breaks_the_contract() {
    crate::log_capture::install();
    after_a_failed_wait(Expect::Waited).say_as_failed_spawn(&mut Diagnosis::default());
}

/// A kill of a child that never ran the program is not refused: a child left running breaks the
/// contract.
///
/// Mutant: `Expect::Unexecuted` asserts no more than `Expect::Waited`.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "never ran the program was refused")]
fn a_refused_kill_of_a_child_that_never_ran_breaks_the_contract() {
    crate::log_capture::install();
    let (torn, _) = teardown_of(Kill::Refused, Found::Running, Expect::Unexecuted);
    torn.say_as_failed_spawn(&mut Diagnosis::default());
}

/// A caller that knows a look on the pidfd failed expects nothing of a wait on it: the same
/// teardown is no breach.
///
/// Mutant: `Expect::Anything` asserts like `Expect::Waited`.
#[skuld::test]
fn a_failed_wait_on_a_pidfd_a_look_failed_on_is_not_a_breach() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    after_a_failed_wait(Expect::Anything).say_as_failed_spawn(&mut Diagnosis::default());
    assert_eq!(warns_since(mark).len(), 1);
}

/// A teardown that collected the child, said with a diagnosis still owed, is the event's one warn:
/// the diagnosis leads it, and the clause that stands alone at `debug` says what became of the child
/// in it, under the failed spawn's name.
///
/// Mutant: the clause is logged apart at `debug` and the diagnosis warns unlabelled when dropped.
#[skuld::test]
fn a_clean_teardown_with_a_diagnosis_owed_is_one_labelled_warn() {
    crate::log_capture::install();
    let (torn, clause) = teardown_of(Kill::Delivered, Found::Exited, Expect::Waited);
    let mut why = Diagnosis::default();
    why.add("the identity check failed");
    let mark = crate::log_capture::mark();

    torn.say_as_failed_spawn(&mut why);
    drop(why);

    assert_eq!(
        warns_since(mark),
        [format!(
            "teardown after a failed spawn: the identity check failed; {clause}"
        )]
    );
}
