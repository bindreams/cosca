//! The note a late child's sweeps owe its teardown's `warn` ([`LateSweeps::failure_note`]), and the
//! one warn of its slow wait.

use super::{abandon_boxed_late_child, sweep_and_tear_down, LateSweeps};
use crate::child::owned::owned_tests::teardown::{fire_on_block, slow_warns_during};
use crate::child::owned::OwnedChild;
use crate::child::spawn::failure::SpawnFailure;
use crate::child::spawn::policy::SpawnPolicy;
use crate::containment::dispatch::{TreeKillOutcome, Unkilled};
use crate::containment::fake::FakeContains;
use crate::containment::{Containment, Mechanism, Refusal, Skip, Tree, Why};
use crate::error::{ChildFate, Error};
use crate::os_process::child::{ExitRecord, KillRefusal, PeekOutcome};
use crate::os_process::fake::{Answer, FakeProcess, ReapAnswer};
use crate::signal::{Sent, Sig};

/// A tree with no sweeps run yet.
fn sweeps(swept: Vec<Result<(), Unkilled>>) -> LateSweeps {
    LateSweeps {
        tree: None,
        id: None,
        sweeps: swept,
        notes: Vec::new(),
        failures: Vec::new(),
    }
}

/// A sweep that left a member it could not kill.
fn member_left() -> Result<(), Unkilled> {
    Err(Unkilled {
        members: vec![crate::error::Error::MemberNotKilled {
            pid: 4242,
            source: std::sync::Arc::new(crate::error::Error::Containment {
                detail: "refused".into(),
                source: None,
            }),
        }],
        root: None,
        resolved: Vec::new(),
    })
}

/// A later sweep that succeeded does not show it reached what the first one missed: the note says the
/// tree may not be fully killed, where a first failure that nothing followed says it was not.
///
/// Mutant: the later success erases the first failure, or the note does not tell the two apart.
#[skuld::test]
fn the_note_hedges_a_failed_sweep_a_later_sweep_followed() {
    let note = sweeps(vec![member_left(), Ok(())])
        .failure_note(true)
        .expect("the first sweep failed");
    assert!(note.contains("its tree may not be fully killed"), "{note}");
    let note = sweeps(vec![member_left()])
        .failure_note(true)
        .expect("the sweep failed");
    assert!(note.contains("its tree was not fully killed"), "{note}");
}

/// A walk that left only the root is settled by the root's kill only when that kill ended the root.
/// A root whose kill was refused is still running, so the note names it.
///
/// Mutant: `failure_note` treats the root as ended whatever its kill did.
#[skuld::test]
fn the_note_names_a_root_the_walk_left_unless_the_root_kill_ended_it() {
    let root_left = || {
        sweeps(vec![Err(Unkilled {
            members: Vec::new(),
            root: Some(Box::new(crate::error::Error::MemberNotKilled {
                pid: 4242,
                source: std::sync::Arc::new(crate::error::Error::Containment {
                    detail: "refused".into(),
                    source: None,
                }),
            })),
            resolved: Vec::new(),
        })])
    };

    let mut ended = root_left();
    assert_eq!(ended.failure_note(true), None, "the root's kill ended it");
    assert!(ended.failures.is_empty(), "{:?}", ended.failures);
    let mut running = root_left();
    let named = running.failure_note(false).expect("the root is still running");
    assert!(named.contains("pid 4242 was not killed"), "{named}");
    assert_eq!(running.failures.len(), 1, "{:?}", running.failures);
    // The held error says its own layer (a member left); the member is below it, with its cause.
    let held = crate::error::said(&*running.failures[0]);
    assert!(
        held.contains("pid 4242 was not killed") && held.contains("refused"),
        "the failure is held as an error: {held}"
    );
}

/// A late child whose root is slow to end, past the policy's threshold (here, at once), is warned of
/// once: the wait for its zombie carries the threshold and the reap after it none. The box is a fake
/// whose zombie wait is still running at the threshold and whose first reap says it is not reapable
/// yet; the child is uncontained, so only the root's teardown runs.
///
/// Mutants: the zombie wait carries no threshold (no warn); the reap carries it too (two).
#[skuld::test]
fn a_late_childs_slow_wait_warns_once_and_the_child_is_reaped() {
    const PID: u32 = 4242;
    let record = ExitRecord::Status(std::process::ExitStatus::default());
    let fake = delivered_kill(PID, [Answer::Running, Answer::Exited])
        .peeks([Ok(PeekOutcome::Exit(record))])
        .reaps([ReapAnswer::Running, ReapAnswer::Exited(record)]);
    let _fire = fire_on_block(&fake);

    let (failure, warns) = abandon_over(&fake, PID);

    let SpawnFailure::MayHaveStarted { fate, unreaped, .. } = failure else {
        panic!("a late child's failure says the program may have started: {failure:?}");
    };
    assert_eq!(fate, ChildFate::Reaped);
    assert!(unreaped.is_none(), "a reaped child is not handed back");
    assert_eq!(fake.signal_calls(), [Sig::Kill], "the root's own kill");
    assert_eq!(warns, 1);
}

/// A root whose exit the zombie wait counted but that is not reapable (a tracer holds its zombie: the
/// peek still reads it running) has not been warned of, so the reap after the wait keeps the
/// threshold and warns once. The wait saw the exit within the threshold, so it asked the box once:
/// its table holds one answer, and a second look past it panics.
///
/// Mutants: the zombie wait is taken to have waited with the threshold whenever a kill was sent (the
/// reap carries none, so no warn); the wait looks a second time after the bounded look that saw the
/// exit.
#[skuld::test]
fn a_root_exited_but_not_reapable_after_its_kill_is_warned_of_at_the_reap() {
    const PID: u32 = 4243;
    let record = ExitRecord::Status(std::process::ExitStatus::default());
    let fake = delivered_kill(PID, [Answer::Exited])
        .peeks([Ok(PeekOutcome::Running)])
        .reaps([ReapAnswer::Running, ReapAnswer::Exited(record)]);
    let _fire = fire_on_block(&fake);

    let (failure, warns) = abandon_over(&fake, PID);

    let SpawnFailure::MayHaveStarted { fate, .. } = failure else {
        panic!("a late child's failure says the program may have started: {failure:?}");
    };
    assert_eq!(fate, ChildFate::Reaped);
    assert_eq!(warns, 1);
}

/// A zombie wait that fails is not swallowed: the one warn says so, and the error is in the failure's
/// `cleanup`. The reap after it still runs, so the child is ended.
///
/// Mutant: the failed wait is read as "not a zombie" and dropped.
#[skuld::test]
fn a_failed_wait_for_the_killed_root_is_recorded() {
    const PID: u32 = 4244;
    let record = ExitRecord::Status(std::process::ExitStatus::default());
    // The bounded look fails, and so does the unbounded one it is left to.
    let fake = delivered_kill(
        PID,
        [
            Answer::Err(std::io::ErrorKind::PermissionDenied),
            Answer::Err(std::io::ErrorKind::PermissionDenied),
        ],
    )
    .reaps([ReapAnswer::Exited(record)]);
    crate::log_capture::install();
    let mark = crate::log_capture::mark();

    let (failure, _) = abandon_over(&fake, PID);

    let SpawnFailure::MayHaveStarted { cleanup, .. } = failure else {
        panic!("a late child's failure says the program may have started: {failure:?}");
    };
    let cleanup = cleanup.expect("the failed wait is a failure of the teardown");
    assert!(
        cleanup
            .iter()
            .any(|failure| crate::error::said(failure).contains("waiting for the killed root")),
        "{cleanup:?}"
    );
    let warns = crate::log_capture::warns_since(mark, "the wait for its killed root to exit failed");
    assert_eq!(warns.len(), 1, "{warns:?}");
}

// The table of a late teardown's outcomes =====

/// What the root's kill came to.
#[derive(Clone, Copy)]
enum RootKilled {
    /// Sent; then the wait for the zombie ends as `Waited` says.
    Landed(Waited),
    /// Refused, and the root still runs.
    Refused,
    /// Not sent: this handle had reaped the root already.
    AlreadyReaped,
}

/// How the wait for the killed root's zombie ended.
#[derive(Clone, Copy)]
enum Waited {
    /// The root is shown a zombie of ours.
    Zombie,
    /// The look failed.
    Failed,
}

/// What a sweep of the fake tree answers.
#[derive(Clone, Copy)]
enum Swept {
    /// It killed what it found and left nothing.
    Clean,
    /// It skipped what the root's number names: the root is not shown ours, a reason a kill of the
    /// tree does not outlive.
    Untrusted,
    /// As `Untrusted`, and its marker's holders were not all killed.
    UntrustedHoldersFailed,
    /// It skipped what the root's number names, for a reason that outlives the root's kill (the
    /// root was reaped elsewhere).
    ReapedElsewhere,
}

/// One outcome of a late teardown: what each step came to, and what the teardown says of it.
struct Row {
    name: &'static str,
    kill: RootKilled,
    first: Swept,
    second: Swept,
    /// The tree is a walk: a walk from a root shown a zombie is not made.
    walk: bool,
    /// Fragments of the one warn, in the order it says them.
    notes: &'static [&'static str],
    /// Fragments of the warn that must not be there.
    absent: &'static [&'static str],
    /// A fragment of each failure in the spawn's `cleanup`, in order.
    cleanup: &'static [&'static str],
    /// The sweeps the tree was asked for.
    sweeps: usize,
}

const SKIPPED: &str = "the root could not be shown to be ours, so its tree did not kill its process group (pgid 7)";
const HOLDER: &str = "a holder refused the kill";
const HOLDERS_NOTE: &str = "its marker's holders were not all killed after its kill";
const NOT_SWEPT_AGAIN: &str = "its tree was not killed again by its pid";
const MAY_NOT: &str = "its tree may not be fully killed";
const NOT_FULLY: &str = "its tree was not fully killed";
const WAIT_NOTE: &str = "the wait for its killed root to exit failed";
const WAIT_STEP: &str = "waiting for the killed root";
const REFUSED: &str = "killing the child";

const ROWS: &[Row] = &[
    Row {
        name: "a clean tree, a landed kill",
        kill: RootKilled::Landed(Waited::Zombie),
        first: Swept::Clean,
        second: Swept::Clean,
        walk: false,
        notes: &[],
        absent: &[NOT_SWEPT_AGAIN, NOT_FULLY, MAY_NOT, WAIT_NOTE],
        cleanup: &[],
        sweeps: 2,
    },
    Row {
        name: "a first sweep skipped, a second clean",
        kill: RootKilled::Landed(Waited::Zombie),
        first: Swept::Untrusted,
        second: Swept::Clean,
        walk: false,
        notes: &[MAY_NOT, SKIPPED],
        absent: &[NOT_SWEPT_AGAIN],
        cleanup: &[SKIPPED],
        sweeps: 2,
    },
    Row {
        name: "a first sweep that left holders, a second clean",
        kill: RootKilled::Landed(Waited::Zombie),
        first: Swept::UntrustedHoldersFailed,
        second: Swept::Clean,
        walk: false,
        notes: &[MAY_NOT, HOLDER],
        absent: &[NOT_SWEPT_AGAIN],
        cleanup: &[HOLDER],
        sweeps: 2,
    },
    Row {
        name: "a second sweep the kill made moot",
        kill: RootKilled::Landed(Waited::Zombie),
        first: Swept::Clean,
        second: Swept::Untrusted,
        walk: false,
        notes: &[NOT_SWEPT_AGAIN],
        absent: &[NOT_FULLY, MAY_NOT, HOLDERS_NOTE],
        cleanup: &[],
        sweeps: 2,
    },
    Row {
        name: "a second sweep the kill made moot, whose holders were not all killed",
        kill: RootKilled::Landed(Waited::Zombie),
        first: Swept::Clean,
        second: Swept::UntrustedHoldersFailed,
        walk: false,
        notes: &[HOLDERS_NOTE, HOLDER, NOT_SWEPT_AGAIN],
        absent: &[NOT_FULLY, MAY_NOT],
        cleanup: &[HOLDER],
        sweeps: 2,
    },
    Row {
        name: "a first sweep skipped, a second moot with holders left",
        kill: RootKilled::Landed(Waited::Zombie),
        first: Swept::Untrusted,
        second: Swept::UntrustedHoldersFailed,
        walk: false,
        notes: &[HOLDERS_NOTE, HOLDER, NOT_SWEPT_AGAIN, NOT_FULLY, SKIPPED],
        absent: &[MAY_NOT],
        cleanup: &[SKIPPED, HOLDER],
        sweeps: 2,
    },
    Row {
        name: "a second sweep skipped for a reason the kill outlives",
        kill: RootKilled::Landed(Waited::Zombie),
        first: Swept::Clean,
        second: Swept::ReapedElsewhere,
        walk: false,
        notes: &[NOT_FULLY, SKIPPED],
        absent: &[NOT_SWEPT_AGAIN],
        cleanup: &[SKIPPED],
        sweeps: 2,
    },
    Row {
        name: "a failed wait, clean sweeps",
        kill: RootKilled::Landed(Waited::Failed),
        first: Swept::Clean,
        second: Swept::Clean,
        walk: false,
        notes: &[WAIT_NOTE],
        absent: &[NOT_SWEPT_AGAIN, NOT_FULLY, MAY_NOT],
        cleanup: &[WAIT_STEP],
        sweeps: 2,
    },
    Row {
        name: "a failed wait, then a second sweep with holders left",
        kill: RootKilled::Landed(Waited::Failed),
        first: Swept::Clean,
        second: Swept::UntrustedHoldersFailed,
        walk: false,
        notes: &[WAIT_NOTE, HOLDERS_NOTE, HOLDER, NOT_SWEPT_AGAIN],
        absent: &[NOT_FULLY, MAY_NOT],
        cleanup: &[WAIT_STEP, HOLDER],
        sweeps: 2,
    },
    Row {
        name: "a walk from a root shown a zombie is not made again",
        kill: RootKilled::Landed(Waited::Zombie),
        first: Swept::Clean,
        second: Swept::Clean,
        walk: true,
        notes: &[],
        absent: &[NOT_SWEPT_AGAIN, NOT_FULLY, MAY_NOT],
        cleanup: &[],
        sweeps: 1,
    },
    Row {
        name: "a refused kill, clean sweeps",
        kill: RootKilled::Refused,
        first: Swept::Clean,
        second: Swept::Clean,
        walk: false,
        notes: &[],
        absent: &[NOT_SWEPT_AGAIN, NOT_FULLY, MAY_NOT],
        cleanup: &[REFUSED],
        sweeps: 2,
    },
    Row {
        name: "a refused kill, a second sweep skipped",
        kill: RootKilled::Refused,
        first: Swept::Clean,
        second: Swept::Untrusted,
        walk: false,
        notes: &[NOT_FULLY, SKIPPED],
        absent: &[NOT_SWEPT_AGAIN],
        cleanup: &[SKIPPED, REFUSED],
        sweeps: 2,
    },
    Row {
        name: "a refused kill, both sweeps skipped",
        kill: RootKilled::Refused,
        first: Swept::Untrusted,
        second: Swept::Untrusted,
        walk: false,
        notes: &[NOT_FULLY, SKIPPED],
        absent: &[NOT_SWEPT_AGAIN, MAY_NOT],
        cleanup: &[SKIPPED, REFUSED],
        sweeps: 2,
    },
    Row {
        name: "a root this handle had reaped, a second sweep skipped",
        kill: RootKilled::AlreadyReaped,
        first: Swept::Clean,
        second: Swept::Untrusted,
        walk: false,
        notes: &[NOT_FULLY, SKIPPED],
        absent: &[NOT_SWEPT_AGAIN],
        cleanup: &[SKIPPED],
        sweeps: 2,
    },
];

/// What a fake tree's sweep of `swept` answers.
fn swept_answer(swept: Swept) -> TreeKillOutcome {
    let skip = |why, holders| {
        TreeKillOutcome::Skipped(Skip {
            action: "kill its process group (pgid 7)".into(),
            why,
            root_alone: false,
            holders,
        })
    };
    let untrusted = || Why::Untrusted {
        why: "it is not pinned".into(),
        cause: None,
    };
    let holders_left = || {
        Some(Err(Error::Containment {
            detail: HOLDER.into(),
            source: None,
        }))
    };
    match swept {
        Swept::Clean => TreeKillOutcome::Ran(Ok(())),
        Swept::Untrusted => skip(untrusted(), None),
        Swept::UntrustedHoldersFailed => skip(untrusted(), holders_left()),
        Swept::ReapedElsewhere => skip(Why::MayNameAnother(Refusal::ReapedElsewhere(4300), None), None),
    }
}

/// The fake box of a root that `kill` happens to.
fn root_killed(kill: RootKilled, pid: u32) -> FakeProcess {
    let record = ExitRecord::Status(std::process::ExitStatus::default());
    let root = |exits: Vec<Answer>| {
        FakeProcess::new(exits)
            .with_pid(pid)
            .with_kill_refusal(KillRefusal::Any)
    };
    match kill {
        RootKilled::Landed(Waited::Zombie) => root(vec![Answer::Exited])
            .signals([Ok(Sent::Delivered)])
            .peeks([Ok(PeekOutcome::Exit(record))])
            .reaps([ReapAnswer::Exited(record)]),
        RootKilled::Landed(Waited::Failed) => root(vec![Answer::Err(std::io::ErrorKind::PermissionDenied)])
            .signals([Ok(Sent::Delivered)])
            .reaps([ReapAnswer::Exited(record)]),
        RootKilled::Refused => root(Vec::new())
            .signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))])
            .reaps_always(ReapAnswer::Running),
        RootKilled::AlreadyReaped => root(Vec::new()).reaps([ReapAnswer::Exited(record)]),
    }
}

/// Every outcome of the teardown of a late child whose tree was swept around its root's kill: the
/// warn's notes in the order the steps happened, and the failures the spawn's `cleanup` holds. The
/// box is a fake root, and the tree a fake that answers what each sweep is stated to.
///
/// Mutants: a sweep after a refused kill is judged as after a landed one; a skip is decided by
/// anything but its reason ([`Skip::moot_after_kill`]); the wait's failure is said after the sweep
/// that followed it.
#[skuld::test]
fn a_late_teardowns_notes_and_cleanup_follow_what_each_step_came_to() {
    const PID: u32 = 4300;
    crate::log_capture::install();
    for row in ROWS {
        let fake = root_killed(row.kill, PID);
        let owned = OwnedChild::new(Box::new(fake.clone()));
        if matches!(row.kill, RootKilled::AlreadyReaped) {
            owned.wait(None).expect("the fake reaps it");
        }
        let kind = if row.walk {
            Containment::TreeWalk
        } else {
            Containment::FdMarker
        };
        let (tree, sends) = FakeContains::new(kind, false);
        let tree = tree.answering_kills([swept_answer(row.first), swept_answer(row.second)]);
        let sweeps = LateSweeps {
            tree: Some(Tree::contained(Mechanism::Fake(tree))),
            id: None,
            sweeps: Vec::new(),
            notes: Vec::new(),
            failures: Vec::new(),
        };
        let error = Error::Io(std::io::Error::other("the late child was not adopted"));
        let mark = crate::log_capture::mark();

        let failure = sweep_and_tear_down(owned, PID, sweeps, error, SpawnPolicy::SYNC);

        let SpawnFailure::MayHaveStarted {
            fate,
            unreaped,
            cleanup,
            ..
        } = failure
        else {
            panic!(
                "{}: a late child's failure says the program may have started: {failure:?}",
                row.name
            );
        };
        if let Some(unreaped) = unreaped {
            unreaped.leak();
        }
        let expected_fate = match row.kill {
            RootKilled::Refused => ChildFate::Running { id: None },
            _ => ChildFate::Reaped,
        };
        assert_eq!(fate, expected_fate, "{}", row.name);
        let name = row.name;
        assert_eq!(
            fake.signal_calls(),
            if matches!(row.kill, RootKilled::AlreadyReaped) {
                Vec::new()
            } else {
                vec![Sig::Kill]
            },
            "{name}: the root's own kill"
        );
        let swept = sends
            .lock()
            .expect("the sends")
            .iter()
            .filter(|send| **send == "kill")
            .count();
        assert_eq!(swept, row.sweeps, "{name}: the sweeps made");

        let warns = crate::log_capture::warns_since(mark, "descriptors 0 to 2 were closed");
        assert_eq!(warns.len(), 1, "{name}: one event, one warn: {warns:?}");
        let warn = &warns[0];
        let mut at = 0;
        for note in row.notes {
            let found = warn[at..]
                .find(note)
                .unwrap_or_else(|| panic!("{name}: {note:?} is not said, or not in order, after {at}: {warn}"));
            at += found + note.len();
        }
        for note in row.absent {
            assert!(!warn.contains(note), "{name}: {note:?} is said: {warn}");
        }

        let cleanup: Vec<String> = cleanup
            .iter()
            .flat_map(|failures| failures.iter())
            .map(|failure| crate::error::said(failure))
            .collect();
        assert_eq!(cleanup.len(), row.cleanup.len(), "{name}: the cleanup: {cleanup:?}");
        for (said, wanted) in cleanup.iter().zip(row.cleanup) {
            assert!(said.contains(wanted), "{name}: {said:?} does not say {wanted:?}");
        }
    }
}

/// A fake root that answers `exits` to its looks and takes the kill, for a late child of `pid`.
fn delivered_kill(pid: u32, exits: impl IntoIterator<Item = Answer>) -> FakeProcess {
    FakeProcess::new(exits)
        .with_pid(pid)
        .with_kill_refusal(KillRefusal::Any)
        .signals([Ok(Sent::Delivered)])
}

/// The teardown of an uncontained late child over `fake`, under a policy that warns at once: the
/// failure it answers, and how many slow-wait warns it logged.
fn abandon_over(fake: &FakeProcess, pid: u32) -> (SpawnFailure, usize) {
    let box_ = OwnedChild::new(Box::new(fake.clone()));
    let prepared = crate::containment::Prepared {
        mode: None,
        is_root: true,
        marker: None,
    };
    let error = crate::error::Error::Io(std::io::Error::other("the late child was not adopted"));
    let mut failure = None;
    let warns = slow_warns_during(|| {
        failure = Some(abandon_boxed_late_child(
            box_,
            pid,
            error,
            None,
            prepared,
            SpawnPolicy::WARNS_AT_ONCE,
        ));
    });
    (failure.expect("the teardown ran"), warns)
}
