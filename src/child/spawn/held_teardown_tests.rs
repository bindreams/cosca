//! The sync spawn's teardown of the child it holds after the handshake (`tear_down_held`), over a
//! real child with scripted answers (`script_over`). Unprivileged: the leaf's subtree is stated, not
//! read from a cgroup.

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use super::held_teardown::tear_down_held;
use super::Diagnosis;
use crate::child::owned::OwnedChild;
use crate::containment::cgroup::{fault, PlacedAtRemoval, Subtree, Swept};
use crate::elevation::front::Front;
use crate::error::{ChildFate, Error};
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::test_child::held_uncontained_blocker;

/// The `Error` a failed spawn arm tears down after.
fn failed() -> Error {
    Error::Io(io::Error::other("the spawn failed"))
}

/// A live blocker the sync spawn would hold, its pid, the write end of its stdin, and the script
/// the test gives its answers through.
fn held_blocker(script: impl FnOnce(FakeProcess) -> FakeProcess) -> (OwnedChild, u32, std::io::PipeWriter) {
    let (mut child, stdin) = held_uncontained_blocker(true);
    child.proc.script_over(script);
    // What `into_unreaped` does: the teardown below owns the root, so the handle drops inert.
    child.kill_on_drop = false;
    let pid = child.id().pid();
    let owned = child.proc.take().expect("the child holds its root");
    (owned, pid, stdin)
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

/// The message of the one `Error` the arm returns, with its hand-back, settled.
fn settle(torn: (Error, ChildFate, Option<crate::Unreaped>), stdin: std::io::PipeWriter) -> (String, ChildFate, bool) {
    let (error, fate, unreaped) = torn;
    let handed_back = unreaped.is_some();
    drop(stdin);
    if let Some(unreaped) = unreaped {
        unreaped.wait().expect("the handed-back child exits once released");
    }
    (error.to_string(), fate, handed_back)
}

/// A child whose kill is refused and whose look then fails is uncollected and still ours: the arm
/// hands it back though its fate is `Unknown`.
///
/// Mutant: only a `Running` fate hands back.
#[skuld::test]
fn a_refused_kill_whose_look_failed_is_handed_back() {
    let (owned, pid, stdin) = held_blocker(|f| {
        f.signals([Err(io::Error::from(io::ErrorKind::PermissionDenied))])
            .reaps([ReapAnswer::Err(io::ErrorKind::Other)])
    });

    let torn = tear_down_held(owned, pid, None, None, None, &mut Diagnosis::default(), failed());

    let (_, fate, handed_back) = settle(torn, stdin);
    assert_eq!(fate, ChildFate::Unknown);
    assert!(handed_back, "the arm handed nothing back");
}

/// A front whose look fails is uncollected and still ours: handed back, and the error says so.
///
/// Mutants: only a `Running` fate hands back; the note does not say it is handed back.
#[skuld::test]
fn a_front_whose_look_failed_is_handed_back_and_the_error_says_so() {
    let (owned, pid, stdin) = held_blocker(|f| f.reaps([ReapAnswer::Err(io::ErrorKind::Other)]));

    let torn = tear_down_held(
        owned,
        pid,
        Some(Front::Sudo),
        None,
        None,
        &mut Diagnosis::default(),
        failed(),
    );

    let (error, fate, handed_back) = settle(torn, stdin);
    assert_eq!(fate, ChildFate::Unknown);
    assert!(handed_back, "the arm handed nothing back");
    assert!(
        error.contains("could not be waited on") && error.contains("handed back to the caller"),
        "{error}"
    );
}

/// A front whose place cannot be read is handed back, and the error says where it is cannot be read.
///
/// Mutant: `PlaceUnreadable` maps to `LeftUnreaped`, which words a front that is not placed.
#[skuld::test]
fn a_front_whose_place_cannot_be_read_is_handed_back_and_the_error_says_so() {
    let (owned, pid, stdin) = held_blocker(|f| f.reaps([ReapAnswer::Running]));
    let subtree = killed_subtree();

    let torn = {
        let _unreadable = fault::fail_pidfd_info();
        tear_down_held(
            owned,
            pid,
            Some(Front::Sudo),
            None,
            Some(&subtree),
            &mut Diagnosis::default(),
            failed(),
        )
    };

    let (error, fate, handed_back) = settle(torn, stdin);
    assert!(matches!(fate, ChildFate::Running { .. }), "{fate:?}");
    assert!(handed_back, "the arm handed nothing back");
    assert!(
        error.contains("where it is cannot be read") && error.contains("handed back to the caller"),
        "{error}"
    );
}

/// A front its leaf's kill reached, whose reap then fails, is `Killed`, uncollected and still ours:
/// handed back, and the error says it could not be waited on, not that it was reaped.
///
/// Mutant: `ReapFailed` maps to `Reaped`.
#[skuld::test]
fn a_front_whose_reap_failed_after_the_leaf_kill_is_handed_back_and_the_error_says_so() {
    let (owned, pid, stdin) = held_blocker(|f| f.reaps([ReapAnswer::Running, ReapAnswer::Err(io::ErrorKind::Other)]));
    let subtree = killed_subtree();

    let torn = {
        let _placed = fault::force_pidfd_cgroup_id(7);
        tear_down_held(
            owned,
            pid,
            Some(Front::Sudo),
            None,
            Some(&subtree),
            &mut Diagnosis::default(),
            failed(),
        )
    };

    let (error, fate, handed_back) = settle(torn, stdin);
    assert_eq!(fate, ChildFate::Killed);
    assert!(handed_back, "the arm handed nothing back");
    assert!(
        error.contains("could not be waited on") && error.contains("handed back to the caller"),
        "{error}"
    );
}
