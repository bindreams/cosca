// Unit tests for dispatch root-detection and mechanism-selection logic.
// These test pure functions directly — no process-env mutation required.

use super::is_nested;
use crate::test_child::Console;
#[cfg(unix)]
use crate::test_groups::setuid;

/// Without the marker the process is the root (not nested).
#[skuld::test]
fn is_nested_without_marker_is_false() {
    assert!(!is_nested(false));
}

/// With the marker the process is already inside a contained tree (nested).
#[skuld::test]
fn is_nested_with_marker_is_true() {
    assert!(is_nested(true));
}

// unix_setup_for mutual-exclusivity tests (S3) =====

/// `ContainMode::Session` must select `UnixSetup::Session` (setsid) — never
/// `ProcessGroup`. This is the critical S3 invariant: calling both setsid AND
/// setpgid/process_group(0) on the same Command would cause EPERM.
#[cfg(unix)]
#[skuld::test]
fn unix_setup_for_session_selects_setsid() {
    use super::{unix_setup_for, UnixSetup};
    use crate::containment::ContainMode;
    assert_eq!(unix_setup_for(Some(ContainMode::Session)), UnixSetup::Session);
}

/// `ContainMode::Strongest` must select `UnixSetup::ProcessGroup` — never Session.
#[cfg(unix)]
#[skuld::test]
fn unix_setup_for_strongest_selects_process_group() {
    use super::{unix_setup_for, UnixSetup};
    use crate::containment::ContainMode;
    assert_eq!(unix_setup_for(Some(ContainMode::Strongest)), UnixSetup::ProcessGroup);
}

/// `ContainMode::TreeWalk` must select `UnixSetup::None` — NO pre-spawn process
/// group. TreeWalk exists to catch children that escape a process group via
/// `setsid`/`setpgid`, so the root must not be put in a group; teardown is by
/// identity at kill time.
#[cfg(unix)]
#[skuld::test]
fn unix_setup_for_treewalk_selects_none() {
    use super::{unix_setup_for, UnixSetup};
    use crate::containment::ContainMode;
    assert_eq!(unix_setup_for(Some(ContainMode::TreeWalk)), UnixSetup::None);
}

/// Uncontained (`None` mode) must select `UnixSetup::ProcessGroup` (the
/// prepare path gates on `mode.is_some()` before calling this, but the
/// default fallback is well-defined).
#[cfg(unix)]
#[skuld::test]
fn unix_setup_for_none_mode_selects_process_group() {
    use super::{unix_setup_for, UnixSetup};
    assert_eq!(unix_setup_for(None), UnixSetup::ProcessGroup);
}

// Attached actionability + nested delegation =====

#[skuld::test]
fn attached_is_actionable() {
    use super::Attached;
    // No teardown mechanism -> not actionable (the _tree guard rejects these).
    assert!(!Attached::None.is_actionable()); // uncontained / lone
    assert!(!Attached::Delegated.is_actionable());
    // Every real mechanism is actionable. Cheap variants are built inline; Cgroup/JobObject
    // need an OS handle, so a test-only constructor builds one (asserted on its own platform).
    assert!(Attached::TreeWalk(crate::identity::ProcessId::current()).is_actionable());
    #[cfg(unix)]
    assert!(Attached::ProcessGroup(0).is_actionable());
    #[cfg(target_os = "linux")]
    assert!(Attached::Cgroup(crate::containment::cgroup::CgroupLeaf::placeholder_for_test()).is_actionable());
    #[cfg(windows)]
    assert!(Attached::JobObject(crate::containment::windows::JobHandle::create_empty_for_test()).is_actionable());
}

/// `kill_tree`/`terminate_tree`'s check of a reaped root (`child::tree_call::root_number`) gates on this
/// predicate: a mechanism that reaches its tree through the root's number, with nothing of its own
/// that checks the root first.
#[cfg(unix)]
#[skuld::test]
fn attached_needs_root_check() {
    use super::Attached;
    assert!(!Attached::None.needs_root_check());
    assert!(!Attached::Delegated.needs_root_check());
    assert!(!Attached::TreeWalk(crate::identity::ProcessId::current()).needs_root_check());
    assert!(Attached::ProcessGroup(0).needs_root_check());
    #[cfg(target_os = "linux")]
    assert!(!Attached::Cgroup(crate::containment::cgroup::CgroupLeaf::placeholder_for_test()).needs_root_check());
}

/// The macOS half of `attached_needs_root_check`: an `FdMarker` needs the check with or without a
/// pgid, since every sweep walks from the root's pid.
///
/// Mutant: the check gated on the marker's pgid.
#[cfg(target_os = "macos")]
#[skuld::test]
fn attached_fd_marker_needs_root_check_with_or_without_a_pgid() {
    use std::os::fd::{AsFd, AsRawFd};

    use super::Attached;

    fn marker_with_pgid(pgid: Option<i32>) -> crate::containment::fdmarker::Marker {
        let (read, write) = std::io::pipe().expect("pipe");
        let handle = crate::containment::fdmarker::pipe_handle_of(write.as_fd()).expect("handle");
        let read_handle = crate::containment::fdmarker::pipe_handle_of(read.as_fd()).expect("read handle");
        let prepared = crate::containment::fdmarker::PreparedMarker {
            read: std::os::fd::OwnedFd::from(read),
            handle,
            read_handle,
            fd: write.as_fd().as_raw_fd(),
        };
        crate::containment::fdmarker::Marker::new(
            prepared,
            crate::containment::fdmarker::fdmarker_tests::inert_root(),
            pgid,
        )
    }

    assert!(Attached::FdMarker(marker_with_pgid(Some(1234))).needs_root_check());
    assert!(Attached::FdMarker(marker_with_pgid(None)).needs_root_check());
}

/// Drives the real `attach()` nested arms (not a hand-built variant): a nested
/// (`!is_root`) contained spawn must yield BOTH halves of the delegated pair —
/// `Containment::Delegated` and `Attached::Delegated` — for a kernel mechanism
/// (Strongest) and TreeWalk, so `containment()` predicts the `_tree` error.
#[skuld::test]
fn nested_attach_is_delegated() {
    use super::{attach, Attached, Prepared};
    use crate::containment::{ContainMode, Containment};

    fn spawn_trivial() -> std::process::Child {
        // attach()'s nested arms don't touch the child, so an exited child is fine. Held for
        // the fork itself: a fork landing while a `fdmarker_tests.rs` test's marker write end
        // is transiently open would inherit it into this not-yet-`exec`'d process, and a
        // concurrent sweep could then find and SIGKILL it.
        #[cfg(unix)]
        return crate::test_spawn::spawn(&mut std::process::Command::new("true")).expect("spawn true");
        #[cfg(windows)]
        return crate::test_spawn::spawn(std::process::Command::new("cmd").args(["/C", "exit"])).expect("spawn cmd");
    }

    for mode in [ContainMode::Strongest, ContainMode::TreeWalk] {
        let mut child = spawn_trivial();
        let prepared = Prepared {
            mode: Some(mode),
            is_root: false, // nested member
            #[cfg(target_os = "linux")]
            cgroup_leaf: None,
            #[cfg(all(target_os = "linux", feature = "tokio"))]
            teardown_warn_after: None,
            #[cfg(target_os = "macos")]
            marker: None,
            #[cfg(windows)]
            graceful: crate::containment::windows::mechanism_from_flags(crate::containment::windows::group_flags()),
            #[cfg(windows)]
            frozen: false,
        };
        #[cfg(windows)]
        let proc_handle = {
            use std::os::windows::io::AsRawHandle;
            child.as_raw_handle()
        };
        let crate::identity::Resolved::Found(id) = crate::identity::ProcessId::of(child.id()) else {
            panic!("the helper child must be readable");
        };
        let attachment = attach(
            id,
            #[cfg(target_os = "linux")]
            crate::containment::cgroup::test_support::handle_of(
                child.id(),
                &crate::containment::cgroup::test_support::pidfd_of(child.id()),
            ),
            #[cfg(windows)]
            proc_handle,
            prepared,
        )
        .expect("attach nested");
        let (containment, attached) = (attachment.containment, attachment.attached);
        // Reap before asserting: `attached` is owned and independent of `child`, so a
        // failing assertion must not leak the helper (the nested arms don't touch it).
        _ = child.kill();
        _ = child.wait();
        assert_eq!(
            containment,
            Containment::Delegated,
            "nested member ({mode:?}) must report Containment::Delegated, got {containment:?}"
        );
        assert!(
            matches!(attached, Attached::Delegated),
            "nested member ({mode:?}) must be Attached::Delegated, got {attached:?}"
        );
    }
}

// kill_tree handle-backstop (treewalk / macOS fd-marker fault seam) =====

// A long-lived TreeWalk-contained child; no descendants, so with the root identity-kill
// seam-disabled the ONLY killer is kill_tree's handle backstop. Armed AFTER the fallible
// spawn so a spawn panic cannot leak the flag.
//
// On macOS, `ContainMode::TreeWalk` still attaches `Containment::FdMarker` (decision 2: the
// marker installs for every contained root regardless of requested mode) — its `sweep` calls
// `treewalk::kill_by_identity` directly, never `treewalk::hard_kill`, so `treewalk::fault`'s
// seam is never consumed there; `fdmarker::fault` provides the matching seam instead.
#[skuld::test]
fn sync_kill_tree_backstop_is_load_bearing() {
    #[cfg(not(target_os = "macos"))]
    use super::super::treewalk::fault;
    #[cfg(target_os = "macos")]
    use crate::containment::fdmarker::fault;
    let mut cmd = crate::test_child::command(Console::Hidden);
    #[cfg(unix)]
    cmd.args(["cat"]);
    #[cfg(windows)]
    cmd.args([crate::test_child::windows_more()]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    #[cfg(windows)]
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    // Closed right after the kill: a no-op backstop exits 0.
    let stdin = child.stdin().expect("piped stdin");
    fault::set_force_root_kill_noop(true);
    let result = child.kill_tree();
    assert!(
        !fault::armed(),
        "seam not consumed — hard_kill did not run on the arming thread"
    );
    result.expect("kill_tree via backstop");
    drop(stdin);
    let status = child.wait().expect("reap");
    assert!(
        !status.success(),
        "the handle backstop must be what killed the root, got {status:?}"
    );
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_kill_tree_backstop_is_load_bearing() {
    #[cfg(not(target_os = "macos"))]
    use super::super::treewalk::fault;
    #[cfg(target_os = "macos")]
    use crate::containment::fdmarker::fault;
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    #[cfg(unix)]
    cmd.args(["cat"]);
    #[cfg(windows)]
    cmd.args([crate::test_child::windows_more()]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    #[cfg(windows)]
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mut child = cmd.spawn().expect("spawn");
    // Closed right after the kill: a no-op backstop exits 0.
    let stdin = child.stdin().expect("piped stdin");
    fault::set_force_root_kill_noop(true);
    let result = child.kill_tree();
    assert!(
        !fault::armed(),
        "seam not consumed — hard_kill did not run on the arming thread"
    );
    result.expect("kill_tree via backstop");
    drop(stdin);
    let status = child.wait().await.expect("reap");
    assert!(
        !status.success(),
        "the handle backstop must be what killed the root, got {status:?}"
    );
}

/// A `TreeWalk` walk that killed what it could and left a member is not a refusal to walk: the
/// handle backstop still runs and kills the root. A walk that left only the root is settled by that
/// backstop (`Ok`, the tree marked killed); one that left a descendant is still the error naming it.
/// (macOS `TreeWalk` mode is an fd marker, which has no such walk. The fault seam is Unix's; the
/// settling code is shared.)
/// Mutants: the incomplete walk's error is taken for a refusal to walk, so `kill_tree` returns it
/// without the backstop; the backstop's kill of the root does not settle a walk that left only the
/// root; it settles a walk that left a descendant.
#[cfg(all(unix, not(target_os = "macos")))]
#[skuld::test]
fn sync_kill_tree_after_an_incomplete_walk_still_runs_the_handle_backstop() {
    use super::super::treewalk::fault::{self, LeftBehind};
    for left in [LeftBehind::Root, LeftBehind::Descendant, LeftBehind::RootAndDescendant] {
        let mut cmd = crate::test_child::command(Console::Hidden);
        cmd.args(["cat"]);
        cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
        cmd.contain_with(crate::ContainMode::TreeWalk);
        let mut child = cmd.spawn().expect("spawn");
        // Closed right after the kill: a no-op backstop exits 0.
        let stdin = child.stdin().expect("piped stdin");
        fault::set_force_root_kill_noop(true);
        fault::force_incomplete_once(left);
        let result = child.kill_tree();
        match left {
            LeftBehind::Root => result.expect("only the root was left, and the backstop killed it"),
            LeftBehind::Descendant | LeftBehind::RootAndDescendant => {
                let err = result.expect_err("a descendant was left");
                assert!(matches!(err, crate::error::Error::MemberNotKilled { .. }), "{err:?}");
            }
        }
        drop(stdin);
        let status = child.wait().expect("reap");
        assert!(
            !status.success(),
            "{left:?}: the handle backstop must be what killed the root, got {status:?}"
        );
    }
}

#[cfg(all(unix, not(target_os = "macos"), feature = "tokio"))]
#[skuld::test]
async fn async_kill_tree_after_an_incomplete_walk_still_runs_the_handle_backstop() {
    use super::super::treewalk::fault::{self, LeftBehind};
    for left in [LeftBehind::Root, LeftBehind::Descendant, LeftBehind::RootAndDescendant] {
        let mut cmd = crate::test_child::tokio_command(Console::Hidden);
        cmd.args(["cat"]);
        cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
        cmd.contain_with(crate::ContainMode::TreeWalk);
        let mut child = cmd.spawn().expect("spawn");
        // Closed right after the kill: a no-op backstop exits 0.
        let stdin = child.stdin().expect("piped stdin");
        fault::set_force_root_kill_noop(true);
        fault::force_incomplete_once(left);
        let result = child.kill_tree();
        match left {
            LeftBehind::Root => result.expect("only the root was left, and the backstop killed it"),
            LeftBehind::Descendant | LeftBehind::RootAndDescendant => {
                let err = result.expect_err("a descendant was left");
                assert!(matches!(err, crate::error::Error::MemberNotKilled { .. }), "{err:?}");
            }
        }
        drop(stdin);
        let status = child.wait().await.expect("reap");
        assert!(
            !status.success(),
            "{left:?}: the handle backstop must be what killed the root, got {status:?}"
        );
    }
}

// What a tree kill comes to =====

/// `settle` over every kind of outcome, with and without a member or the root left, and with the
/// root not running or not: what it answers, and whether it marks the tree killed. A kill that did not
/// run marks nothing and answers with what its sweep by identity left.
///
/// A walk that saw the root running vouches for nothing, whatever ended the root afterwards (it may
/// have forked first), but the answer follows the root's end.
///
/// Mutants: a skipped kill marks; a skip drops its sweep's error; the root is dropped from the report
/// whatever the root's end; the root is kept when the root is not running; a root the backstop ended
/// marks the tree killed.
#[skuld::test]
fn settle_answers_and_marks_by_what_ran_what_was_left_and_the_root_s_end() {
    use super::{Attached, SettleOutcome, TreeKillOutcome, TreeKilled, Unkilled, UnvouchedKind};
    use crate::error::Error;
    let left = |pid| Error::MemberNotKilled {
        pid,
        source: Box::new(Error::Containment {
            detail: "refused".into(),
        }),
        note: None,
    };
    let unkilled = |members: &[u32], root: Option<u32>| Unkilled {
        members: members.iter().map(|pid| left(*pid)).collect(),
        root: root.map(left),
        resolved: Vec::new(),
    };
    let skipped = |holders| TreeKillOutcome::Skipped {
        action: "walk".into(),
        holders,
    };
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());

    // (outcome, root_ended, answer: Ok(outcome) or Err((first, others)), marked)
    type Answer = Result<SettleOutcome, (u32, Vec<u32>)>;
    let table: Vec<(TreeKillOutcome, bool, Answer, bool)> = vec![
        (TreeKillOutcome::Ran(Ok(())), false, Ok(SettleOutcome::Killed), true),
        (skipped(Ok(())), true, Ok(SettleOutcome::Skipped), false),
        (skipped(Err(unkilled(&[7], None))), true, Err((7, vec![])), false),
        (
            TreeKillOutcome::Ran(Err(unkilled(&[], Some(1)))),
            false,
            Err((1, vec![])),
            false,
        ),
        (
            TreeKillOutcome::Ran(Err(unkilled(&[], Some(1)))),
            true,
            Ok(SettleOutcome::Unvouched {
                kind: UnvouchedKind::RootSeenRunning,
            }),
            false,
        ),
        (
            TreeKillOutcome::Ran(Err(unkilled(&[2, 3], None))),
            true,
            Err((2, vec![3])),
            false,
        ),
        (
            TreeKillOutcome::Ran(Err(unkilled(&[2], Some(1)))),
            true,
            Err((2, vec![])),
            false,
        ),
        (
            TreeKillOutcome::Ran(Err(unkilled(&[2], Some(1)))),
            false,
            Err((2, vec![1])),
            false,
        ),
    ];
    let pid_of = |error: &Error| match error {
        Error::MemberNotKilled { pid, .. } => *pid,
        other => panic!("expected MemberNotKilled, got {other:?}"),
    };
    for (outcome, root_ended, want, marked) in table {
        let label = format!("{outcome:?}, root_ended {root_ended}");
        let killed = TreeKilled::default();

        let got = attached.settle(&killed, outcome, root_ended);

        let got = got.map_err(|left| (pid_of(&left.first), left.others.iter().map(pid_of).collect::<Vec<_>>()));
        assert_eq!(got, want, "{label}");
        assert_eq!(killed.is_set(), marked, "{label}");
    }
}

/// A walk that was not made, or found no root, killed nothing: `settle` answers it with an error
/// (`Unassessable`; the snapshot's error as it was) and marks nothing, for a reader of any kind.
///
/// Mutants: either is answered `Ok`; either marks the tree killed.
#[skuld::test]
fn settle_answers_a_walk_that_was_not_made_with_an_error_and_marks_nothing() {
    use super::{Attached, TreeKillOutcome, TreeKilled};
    use crate::error::Error;
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    for outcome in [
        TreeKillOutcome::NoRoot,
        TreeKillOutcome::Unwalked(Error::Unassessable {
            detail: "the snapshot could not be taken".into(),
            source: None,
        }),
    ] {
        let label = format!("{outcome:?}");
        let killed = TreeKilled::default();

        let left = attached
            .settle(&killed, outcome, true)
            .expect_err("nothing was killed, whatever became of the root");

        assert!(matches!(left.first, Error::Unassessable { .. }), "{label}: {left}");
        assert!(left.others.is_empty(), "{label}: {left}");
        assert!(!killed.is_set(), "{label}");
    }
}

/// A root that is gone leaves nothing to walk once this handle has killed the tree: a later kill or
/// drop that finds no root is settled, not an error. Mutant: it is `Unassessable` whatever the mark
/// says (the drop after a `kill_tree` and a `wait` then warns, on Windows).
#[skuld::test]
fn settle_answers_a_gone_root_as_killed_once_the_handle_killed_the_tree() {
    use super::{Attached, SettleOutcome, TreeKillOutcome, TreeKilled};
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    let killed = TreeKilled::default();
    attached
        .settle(&killed, TreeKillOutcome::Ran(Ok(())), false)
        .expect("the tree is killed");

    let later = attached
        .settle(&killed, TreeKillOutcome::NoRoot, false)
        .expect("the tree was killed already");

    assert_eq!(later, SettleOutcome::Killed);
}

// The tree's settlement: every state, every outcome =====

/// Where a tree's settlement stands: never settled, killed, left these members (their pids, in
/// order), or unvouched.
#[derive(Debug, PartialEq)]
enum Standing {
    Never,
    Killed,
    Left(Vec<u32>),
    Unvouched,
}

/// The state of `killed`.
fn standing(killed: &super::TreeKilled) -> Standing {
    standing_of(&killed.lock())
}

/// `state`, as a `Standing`.
fn standing_of(state: &super::TreeState) -> Standing {
    use crate::containment::treewalk::Left;
    match state {
        super::TreeState::Never => Standing::Never,
        super::TreeState::Killed => Standing::Killed,
        super::TreeState::Unvouched(_) => Standing::Unvouched,
        super::TreeState::Left(held) => {
            assert!(!held.is_empty(), "a tree left holds a member");
            Standing::Left(
                held.iter()
                    .map(|left| match left {
                        Left::Resolved(id) => id.pid(),
                        Left::Unread { pid, .. } => *pid,
                    })
                    .collect(),
            )
        }
    }
}

/// `next` over every state and every combination of facts that can occur: a walk or not, members left
/// with identities or none, something left running or not. A member left with an identity is
/// something left running.
///
/// Mutants: a fact that walked nothing vouches; a member seen running leaves a state as it was
/// (`Never` included: it means only that nothing has settled the tree); a held `Left` outlives its
/// members.
#[skuld::test]
fn next_is_the_one_transition_of_state_and_facts() {
    use super::{TreeState, UnvouchedKind};
    use crate::containment::treewalk::Left;
    let unread = |pid| Left::Unread {
        pid,
        said: "its identity could not be read".into(),
    };
    let prev_names = ["Never", "Killed", "Left(7)", "Unvouched"];
    let prev_at = |at: usize| match at {
        0 => TreeState::Never,
        1 => TreeState::Killed,
        2 => TreeState::Left(vec![unread(7)]),
        _ => TreeState::Unvouched(UnvouchedKind::Earlier),
    };
    // (label, walked, left_now, running, next from [Never, Killed, Left(7), Unvouched])
    type Row = (&'static str, bool, Vec<Left>, bool, [Standing; 4]);
    let left_8 = || Standing::Left(vec![8]);
    #[rustfmt::skip]
    let facts: Vec<Row> = vec![
        ("walk, nothing left", true, vec![], false,
            [Standing::Killed, Standing::Killed, Standing::Killed, Standing::Killed]),
        ("walk, something running with no identity", true, vec![], true,
            [Standing::Unvouched, Standing::Unvouched, Standing::Unvouched, Standing::Unvouched]),
        ("no walk, nothing left", false, vec![], false,
            [Standing::Never, Standing::Killed, Standing::Unvouched, Standing::Unvouched]),
        ("no walk, something running with no identity", false, vec![], true,
            [Standing::Unvouched, Standing::Unvouched, Standing::Unvouched, Standing::Unvouched]),
        ("walk, member 8 left", true, vec![unread(8)], true,
            [left_8(), left_8(), left_8(), left_8()]),
        ("no walk, member 8 left", false, vec![unread(8)], true,
            [left_8(), left_8(), left_8(), left_8()]),
    ];
    for (label, walked, left_now, running, wants) in facts {
        for (at, want) in wants.into_iter().enumerate() {
            let got = super::next(
                &prev_at(at),
                walked,
                left_now.clone(),
                running,
                UnvouchedKind::RootSeenRunning,
            );

            assert_eq!(standing_of(&got), want, "{} x {label}", prev_names[at]);
            // The kind the settlement names is the one the state keeps.
            if let TreeState::Unvouched(kind) = got {
                assert_eq!(kind, UnvouchedKind::RootSeenRunning, "{} x {label}", prev_names[at]);
            }
        }
    }
}

/// The five outcomes of the table, fresh.
fn table_outcomes() -> [(&'static str, super::TreeKillOutcome); 5] {
    use super::{TreeKillOutcome, Unkilled};
    [
        ("Ran(Ok)", TreeKillOutcome::Ran(Ok(()))),
        (
            "Ran(Err member 8)",
            TreeKillOutcome::Ran(Err(Unkilled {
                members: vec![member_left(8)],
                root: None,
                resolved: Vec::new(),
            })),
        ),
        ("NoRoot", TreeKillOutcome::NoRoot),
        (
            "Unwalked",
            TreeKillOutcome::Unwalked(crate::error::Error::Unassessable {
                detail: "the snapshot failed".into(),
                source: None,
            }),
        ),
        (
            "Skipped",
            TreeKillOutcome::Skipped {
                action: "walk the process table".into(),
                holders: Ok(()),
            },
        ),
    ]
}

/// A tree whose walk left the member `pid` (its identity read when `resolved`).
fn tree_left_with(pid: u32, resolved: Vec<crate::identity::ProcessId>) -> super::TreeKilled {
    use super::{Attached, TreeKillOutcome, TreeKilled, Unkilled};
    let killed = TreeKilled::default();
    Attached::TreeWalk(crate::identity::ProcessId::current())
        .settle(
            &killed,
            TreeKillOutcome::Ran(Err(Unkilled {
                members: vec![member_left(pid)],
                root: None,
                resolved,
            })),
            true,
        )
        .expect_err("a member was left");
    killed
}

/// What a `settle` answers, and the state it leaves.
type Want = (Result<super::SettleOutcome, Vec<String>>, Standing);

/// Each outcome of the table settled over a tree that `enter` makes fresh: the answer (the
/// errors' names, first to last) and the state left, against the row of `rows`. `enter` returns the
/// tree, the pid it holds (or 0), and what to run once the row has settled.
fn check_table(
    state: &str,
    rows: impl Fn(u32) -> [Want; 5],
    enter: impl Fn() -> (super::TreeKilled, u32, Box<dyn FnOnce()>),
) {
    use super::Attached;
    use crate::error::Error;
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    let name = |error: &Error| match error {
        Error::MemberNotKilled { pid, .. } => format!("pid {pid}"),
        Error::Unassessable { .. } => "unassessable".to_owned(),
        other => panic!("unexpected error {other:?}"),
    };
    for (at, (outcome_name, outcome)) in table_outcomes().into_iter().enumerate() {
        let (killed, pid, after) = enter();
        let (want_answer, want_standing) = rows(pid).into_iter().nth(at).expect("a row per outcome");

        let got = attached.settle(&killed, outcome, true).map_err(|left| {
            std::iter::once(&left.first)
                .chain(&left.others)
                .map(name)
                .collect::<Vec<_>>()
        });

        assert_eq!(got, want_answer, "{state} x {outcome_name}: answer");
        assert_eq!(standing(&killed), want_standing, "{state} x {outcome_name}: next state");
        after();
    }
}

fn gone() -> Vec<String> {
    vec!["unassessable".to_owned()]
}

/// A tree that holds the member `pid`, which no outcome shows killed: every answer starts with it, a
/// gone root adds nothing of its own, and the tree stays left.
fn holding_rows(pid: u32) -> [Want; 5] {
    let held = format!("pid {pid}");
    let two = vec![held.clone(), "pid 8".to_owned()];
    let walk_not_made = vec![held.clone(), "unassessable".to_owned()];
    [
        (Err(vec![held.clone()]), Standing::Left(vec![pid])),
        (Err(two), Standing::Left(vec![pid, 8])),
        (Err(vec![held.clone()]), Standing::Left(vec![pid])),
        (Err(walk_not_made), Standing::Left(vec![pid])),
        (Err(vec![held]), Standing::Left(vec![pid])),
    ]
}

/// `settle` over a tree no walk has settled, one that is killed, and one left an unread member: what
/// each outcome answers, and the state it leaves. The held member is answered first; a gone root adds
/// no error of its own once a walk covered the tree; a member seen running moves a killed tree to
/// left; the state is one value, so no row can be killed and holding at once.
///
/// Mutants: a gone root over a covered tree adds its own error; a tree stays killed while it holds a
/// member; an outcome skips the held member.
#[skuld::test]
fn settle_answers_each_outcome_over_a_tree_never_settled_killed_or_left_an_unread_member() {
    use super::{
        Attached,
        SettleOutcome::{Killed, Skipped},
        TreeKillOutcome, TreeKilled,
    };
    let nothing = || -> Box<dyn FnOnce()> { Box::new(|| {}) };

    check_table(
        "never settled",
        |_| {
            [
                (Ok(Killed), Standing::Killed),
                (Err(vec!["pid 8".to_owned()]), Standing::Left(vec![8])),
                (Err(gone()), Standing::Never),
                (Err(gone()), Standing::Never),
                (Ok(Skipped), Standing::Never),
            ]
        },
        || (TreeKilled::default(), 0, nothing()),
    );
    check_table(
        "killed",
        |_| {
            [
                (Ok(Killed), Standing::Killed),
                (Err(vec!["pid 8".to_owned()]), Standing::Left(vec![8])),
                (Ok(Killed), Standing::Killed),
                (Err(gone()), Standing::Killed),
                (Ok(Skipped), Standing::Killed),
            ]
        },
        || {
            let killed = TreeKilled::default();
            Attached::TreeWalk(crate::identity::ProcessId::current())
                .settle(&killed, TreeKillOutcome::Ran(Ok(())), true)
                .expect("a complete kill");
            (killed, 0, nothing())
        },
    );
    check_table("left, unread", holding_rows, || {
        (tree_left_with(7, Vec::new()), 7, nothing())
    });
}

/// A member whose kill by identity succeeds is gone after any outcome, but only an outcome that
/// walked shows the tree killed: the member ran on after its kill was refused and may have forked,
/// and killing it again does not reach its children. A gone root, a walk not made and a skipped kill
/// each walked nothing, so the answer is the outcome's own (a gone root says the tree could not be
/// walked) and the state is unvouched. Mutants: as the table above; a held member is not killed by
/// an outcome that did not run; an outcome that walked nothing settles the tree as killed or as
/// never settled.
#[skuld::test]
fn settle_answers_each_outcome_over_a_tree_left_a_member_that_can_be_killed() {
    use super::{
        SettleOutcome::{Killed, Unvouched},
        UnvouchedKind,
    };
    check_table(
        "left, killable",
        |_| {
            [
                (Ok(Killed), Standing::Killed),
                (Err(vec!["pid 8".to_owned()]), Standing::Left(vec![8])),
                (Err(gone()), Standing::Unvouched),
                (Err(gone()), Standing::Unvouched),
                (
                    Ok(Unvouched {
                        kind: UnvouchedKind::HeldMembersGone,
                    }),
                    Standing::Unvouched,
                ),
            ]
        },
        || {
            let (blocker, stdin) = crate::test_child::held_uncontained_blocker(false);
            let id = blocker.id();
            let killed = tree_left_with(id.pid(), vec![id]);
            let after: Box<dyn FnOnce()> = Box::new(move || {
                drop(stdin);
                crate::test_child::assert_killed("the member", blocker.wait().expect("reap the member"));
            });
            (killed, id.pid(), after)
        },
    );
}

/// A tree whose walk left a member that a gone root's settlement then killed again: unvouched. The
/// returned closure reaps the member, which is held by `stdin` until then.
fn unvouched_tree() -> (super::TreeKilled, Box<dyn FnOnce()>) {
    use super::{Attached, TreeKillOutcome};
    let (blocker, stdin) = crate::test_child::held_uncontained_blocker(false);
    let id = blocker.id();
    let killed = tree_left_with(id.pid(), vec![id]);
    Attached::TreeWalk(crate::identity::ProcessId::current())
        .settle(&killed, TreeKillOutcome::NoRoot, true)
        .expect_err("a gone root walked nothing");
    assert_eq!(standing(&killed), Standing::Unvouched);
    let after: Box<dyn FnOnce()> = Box::new(move || {
        drop(stdin);
        crate::test_child::assert_killed("the member", blocker.wait().expect("reap the member"));
    });
    (killed, after)
}

/// A tree whose every member a walk left is gone, and no walk since has vouched for it, is
/// unvouched: only a walk that leaves nothing settles it as killed, a member seen running leaves it
/// holding that member, and any other outcome leaves it unvouched, a gone root answering with the
/// honest error each time. Mutants: an outcome that walked nothing settles it as killed or as never
/// settled; a walk that left nothing does not settle it as killed.
#[skuld::test]
fn settle_answers_each_outcome_over_an_unvouched_tree() {
    use super::{
        SettleOutcome::{Killed, Unvouched},
        UnvouchedKind,
    };
    check_table(
        "unvouched",
        |_| {
            [
                (Ok(Killed), Standing::Killed),
                (Err(vec!["pid 8".to_owned()]), Standing::Left(vec![8])),
                (Err(gone()), Standing::Unvouched),
                (Err(gone()), Standing::Unvouched),
                (
                    Ok(Unvouched {
                        kind: UnvouchedKind::HeldMembersGone,
                    }),
                    Standing::Unvouched,
                ),
            ]
        },
        || {
            let (killed, after) = unvouched_tree();
            (killed, 0, after)
        },
    );
}

/// A member whose kill by identity is refused stays left after any outcome. A setuid-root helper
/// refuses the kill of its caller.
#[cfg(unix)]
#[skuld::test]
fn settle_answers_each_outcome_over_a_tree_left_a_member_that_refuses_the_kill(
    #[fixture(setuid)] _group: &crate::test_groups::Group,
) {
    check_table("left, refusing", holding_rows, || {
        let (child, stdin) = crate::test_privilege::spawn_setuid_blocker();
        let id = child.id();
        let killed = tree_left_with(id.pid(), vec![id]);
        let after: Box<dyn FnOnce()> = Box::new(move || {
            // The helper exits at EOF: nothing killed it.
            drop(stdin);
            assert!(child.wait().expect("the helper exits on EOF").success());
        });
        (killed, id.pid(), after)
    });
}

/// A handle that is not a `TreeWalk` holds no members, so a kill that runs and leaves a member leaves
/// the tree unvouched (a kill happened, and the member seen running may have forked), whether the tree
/// was killed or never settled. Mutants: the tree stays killed; it stays or goes to never settled,
/// after which a gone root would say nothing was killed.
#[skuld::test]
fn a_kill_that_leaves_a_member_after_a_killed_tree_of_a_handle_that_is_not_a_walk_unvouches_it() {
    use super::{Attached, TreeKillOutcome, TreeKilled, Unkilled};
    let attached = Attached::None;
    let killed = TreeKilled::default();
    attached
        .settle(&killed, TreeKillOutcome::Ran(Ok(())), true)
        .expect("a complete kill");
    assert_eq!(standing(&killed), Standing::Killed);

    let left = attached
        .settle(
            &killed,
            TreeKillOutcome::Ran(Err(Unkilled {
                members: vec![member_left(8)],
                root: None,
                resolved: Vec::new(),
            })),
            true,
        )
        .expect_err("a member was left");

    assert_eq!(pid_left(&left.first), 8);
    assert_eq!(standing(&killed), Standing::Unvouched);

    // The same for a skipped kill whose sweep of the holders left a member.
    attached
        .settle(&killed, TreeKillOutcome::Ran(Ok(())), true)
        .expect("a complete kill");
    assert_eq!(standing(&killed), Standing::Killed);
    let skipped_with_a_member = || TreeKillOutcome::Skipped {
        action: "walk".into(),
        holders: Err(Unkilled {
            members: vec![member_left(9)],
            root: None,
            resolved: Vec::new(),
        }),
    };
    attached
        .settle(&killed, skipped_with_a_member(), true)
        .expect_err("a member was left");
    assert_eq!(standing(&killed), Standing::Unvouched);

    // Over a tree never settled, the sweep that left the member unvouches it too.
    let never = TreeKilled::default();
    attached
        .settle(&never, skipped_with_a_member(), true)
        .expect_err("a member was left");
    assert_eq!(standing(&never), Standing::Unvouched);
}

// What a `TreeWalk` handle remembers of the members a kill left =====

/// A `MemberNotKilled` for `pid`, as a walk reports a member it left.
fn member_left(pid: u32) -> crate::error::Error {
    crate::error::Error::MemberNotKilled {
        pid,
        source: Box::new(crate::error::Error::Unassessable {
            detail: "its identity could not be read".into(),
            source: None,
        }),
        note: None,
    }
}

/// The pid a `MemberNotKilled` names.
fn pid_left(error: &crate::error::Error) -> u32 {
    match error {
        crate::error::Error::MemberNotKilled { pid, .. } => *pid,
        other => panic!("expected MemberNotKilled, got {other:?}"),
    }
}

/// A member whose identity was never read stays left: a later kill whose walk finds nothing does not
/// settle the tree as killed, but answers with the same member and marks nothing. Once a later kill
/// names it itself, it is not repeated.
///
/// Mutants: a later walk that finds less settles the tree as killed; the member is forgotten after
/// one report; the member is reported twice when the walk names it again.
#[skuld::test]
fn a_member_whose_identity_was_never_read_is_reported_again_until_a_kill_shows_it_killed() {
    use super::{Attached, TreeKillOutcome, TreeKilled, Unkilled};
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    let killed = TreeKilled::default();
    let left = |pids: &[u32]| {
        TreeKillOutcome::Ran(Err(Unkilled {
            members: pids.iter().copied().map(member_left).collect(),
            root: None,
            resolved: Vec::new(),
        }))
    };

    let first = attached
        .settle(&killed, left(&[7]), true)
        .expect_err("a member was left");
    assert_eq!(pid_left(&first.first), 7);

    let later = attached
        .settle(&killed, TreeKillOutcome::Ran(Ok(())), true)
        .expect_err("a walk that finds nothing does not show the member killed");
    assert_eq!((pid_left(&later.first), later.others.len()), (7, 0));
    assert!(!killed.is_set());

    let named_again = attached
        .settle(&killed, left(&[7, 8]), true)
        .expect_err("two members are left");
    assert_eq!(pid_left(&named_again.first), 7);
    assert_eq!(named_again.others.iter().map(pid_left).collect::<Vec<_>>(), [8]);
}

/// Whatever the next kill found, a held member is answered first: a gone root, a walk that could not
/// be made and a skipped kill each leave it reported, and none marks the tree. Mutant: the held
/// members are retried only when the new kill ran.
#[skuld::test]
fn a_held_member_is_answered_first_whatever_the_next_kill_found() {
    use super::{Attached, TreeKillOutcome, TreeKilled, Unkilled};
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    let unwalked = || {
        TreeKillOutcome::Unwalked(crate::error::Error::Unassessable {
            detail: "the snapshot failed".into(),
            source: None,
        })
    };
    let skipped = || TreeKillOutcome::Skipped {
        action: "walk the process table".into(),
        holders: Ok(()),
    };
    let outcomes: [(&str, &dyn Fn() -> TreeKillOutcome); 3] = [
        ("NoRoot", &|| TreeKillOutcome::NoRoot),
        ("Unwalked", &unwalked),
        ("Skipped", &skipped),
    ];
    for (label, outcome) in outcomes {
        let killed = TreeKilled::default();
        attached
            .settle(
                &killed,
                TreeKillOutcome::Ran(Err(Unkilled {
                    members: vec![member_left(7)],
                    root: None,
                    resolved: Vec::new(),
                })),
                true,
            )
            .expect_err("a member was left");

        let again = attached
            .settle(&killed, outcome(), true)
            .expect_err("the member is not shown killed");

        assert_eq!(pid_left(&again.first), 7, "{label}: {again}");
        assert!(!killed.is_set(), "{label}");
    }
}

/// A tree this handle already killed does not excuse a gone root from answering the member a later
/// kill left: the mark shortcut applies only when nothing is held. Mutant: `NoRoot` with the mark set
/// returns `Killed` before the held members are read.
#[skuld::test]
fn a_gone_root_over_a_marked_tree_still_answers_a_held_member() {
    use super::{Attached, SettleOutcome, TreeKillOutcome, TreeKilled, Unkilled};
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    let killed = TreeKilled::default();
    attached
        .settle(&killed, TreeKillOutcome::Ran(Ok(())), true)
        .expect("a complete kill");
    assert!(killed.is_set());
    attached
        .settle(
            &killed,
            TreeKillOutcome::Ran(Err(Unkilled {
                members: vec![member_left(7)],
                root: None,
                resolved: Vec::new(),
            })),
            true,
        )
        .expect_err("a later kill left a member");

    let again = attached
        .settle(&killed, TreeKillOutcome::NoRoot, true)
        .expect_err("the member is not shown killed");
    assert_eq!(pid_left(&again.first), 7, "{again}");

    let nothing_held = TreeKilled::default();
    attached
        .settle(&nothing_held, TreeKillOutcome::Ran(Ok(())), true)
        .expect("a complete kill");
    assert!(matches!(
        attached.settle(&nothing_held, TreeKillOutcome::NoRoot, true),
        Ok(SettleOutcome::Killed)
    ));
}

/// The early return of both `kill_tree`s: a walk not made is answered here, over a held member, with
/// the tree unmarked; every other walk is handed back untouched for the backstop.
#[skuld::test]
fn only_a_walk_not_made_is_answered_before_the_backstop() {
    use super::{Attached, TreeKillOutcome, TreeKilled, Unkilled};
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    let killed = TreeKilled::default();
    attached
        .settle(
            &killed,
            TreeKillOutcome::Ran(Err(Unkilled {
                members: vec![member_left(7)],
                root: None,
                resolved: Vec::new(),
            })),
            true,
        )
        .expect_err("a member was left");

    let handed_back = attached.unless_unwalked("kill_tree", &killed, TreeKillOutcome::Ran(Ok(())));
    assert!(
        matches!(handed_back, Ok(TreeKillOutcome::Ran(Ok(())))),
        "a walk made is the backstop's to settle"
    );

    let Err(failure) = attached.unless_unwalked(
        "kill_tree",
        &killed,
        TreeKillOutcome::Unwalked(crate::error::Error::Unassessable {
            detail: "the snapshot failed".into(),
            source: None,
        }),
    ) else {
        panic!("a walk not made is an error");
    };
    assert_eq!(pid_left(&failure.error), 7, "{:?}", failure.error);
    assert!(!failure.root_ended);
    assert!(!killed.is_set());
}

/// A member whose identity was read and whose kill was refused is killed by identity again by the
/// next kill that runs, and the tree is then settled and marked. Mutants: the retry does not kill it;
/// it kills it and still answers with the earlier error.
#[skuld::test]
fn a_member_whose_kill_was_refused_is_killed_again_by_identity_and_then_settled() {
    use super::{Attached, TreeKillOutcome, TreeKilled, Unkilled};
    let (blocker, stdin) = crate::test_child::held_uncontained_blocker(false);
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    let killed = TreeKilled::default();
    let id = blocker.id();

    let first = attached
        .settle(
            &killed,
            TreeKillOutcome::Ran(Err(Unkilled {
                members: vec![member_left(id.pid())],
                root: None,
                resolved: vec![id],
            })),
            true,
        )
        .expect_err("the member was left");
    assert_eq!(pid_left(&first.first), id.pid());
    assert!(!killed.is_set());

    attached
        .settle(&killed, TreeKillOutcome::Ran(Ok(())), true)
        .expect("the retry killed the member by its identity");

    assert!(killed.is_set());
    // Released after the kill: a retry that sent nothing lets the member exit on EOF, so the
    // assertion fails instead of the wait hanging.
    drop(stdin);
    crate::test_child::assert_killed("the member", blocker.wait().expect("reap the member"));
}

/// A gone root over members an earlier kill left, which are gone now, says so each time, in the same
/// words: the tree could not be walked, but "nothing was killed" and "killed again" are each false for
/// a member that exited on its own. `exits_on_its_own`: the member exits at EOF before the
/// settlement instead of being killed by it.
fn gone_root_answers_over_gone_members_each_time(exits_on_its_own: bool) {
    use super::{Attached, TreeKillOutcome, TreeKilled, Unkilled};
    let (blocker, stdin) = crate::test_child::held_uncontained_blocker(false);
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    let killed = TreeKilled::default();
    let id = blocker.id();
    attached
        .settle(
            &killed,
            TreeKillOutcome::Ran(Err(Unkilled {
                members: vec![member_left(id.pid())],
                root: None,
                resolved: vec![id],
            })),
            true,
        )
        .expect_err("the member was left");
    let mut held = Some(stdin);
    if exits_on_its_own {
        drop(held.take());
        blocker.wait().expect("the member exits on its own and is reaped");
    }

    let texts: Vec<String> = (0..2)
        .map(|_| {
            let left = attached
                .settle(&killed, TreeKillOutcome::NoRoot, true)
                .expect_err("a gone root walked nothing");
            assert!(left.others.is_empty(), "{left}");
            assert_eq!(standing(&killed), Standing::Unvouched);
            left.first.to_string()
        })
        .collect();

    if !exits_on_its_own {
        drop(held.take());
        crate::test_child::assert_killed("the member", blocker.wait().expect("reap the member"));
    }
    assert_eq!(texts[0], texts[1]);
    for text in &texts {
        assert!(text.contains("are gone"), "{text}");
        assert!(!text.contains("nothing was killed"), "{text}");
        assert!(!text.contains("killed again"), "{text}");
    }
}

/// Mutant: the answer is `no_root_error`, or says the members were killed again, or changes with the
/// second call.
#[skuld::test]
fn a_gone_root_over_members_killed_by_the_settlement_says_they_are_gone_each_time() {
    gone_root_answers_over_gone_members_each_time(false);
}

/// Mutant: the answer says the members were killed.
#[skuld::test]
fn a_gone_root_over_a_member_that_exited_on_its_own_says_it_is_gone_each_time() {
    gone_root_answers_over_gone_members_each_time(true);
}

/// A drop that skips the kill over a tree it cannot vouch for warns of it, in words true of what
/// `settle` found: members an earlier kill left that are gone now (a held member that exited or was
/// killed by the settlement), or, when the cause is no longer known (an earlier kill left the root,
/// members never identified, or members since gone), only that something was left running and no walk
/// has checked what it forked. A tree that was killed, or never settled (a skipped kill has its own
/// warn), says nothing here.
///
/// Mutants: the drop is silent over an unvouched tree; a text speaks of members after a walk left only
/// the root; a text says "no longer tracked" of members known gone.
#[skuld::test]
fn a_drop_over_an_unvouched_tree_warns_of_what_settle_found() {
    use super::{Attached, TreeKillOutcome, TreeKilled, Unkilled};
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    let skipped = || TreeKillOutcome::Skipped {
        action: "walk the process table".into(),
        holders: Ok(()),
    };

    // Held members that the settlement found gone.
    let (blocker, stdin) = crate::test_child::held_uncontained_blocker(false);
    let id = blocker.id();
    let held_gone = tree_left_with(id.pid(), vec![id]);
    let warn = attached
        .settle_for_drop(&held_gone, skipped(), true)
        .expect("an unvouched tree is warned of");
    drop(stdin);
    crate::test_child::assert_killed("the member", blocker.wait().expect("reap the member"));
    assert!(warn.contains("could not be vouched for"), "{warn}");
    assert!(warn.contains("skipped the kill"), "{warn}");
    assert!(warn.contains("are gone"), "{warn}");
    assert!(!warn.contains("no longer tracked"), "{warn}");

    // Something left running that no settlement has seen end: the root, whose end the call did not see.
    let root_left = || {
        TreeKillOutcome::Ran(Err(Unkilled {
            members: Vec::new(),
            root: Some(member_left(1)),
            resolved: Vec::new(),
        }))
    };
    let earlier = TreeKilled::default();
    attached
        .settle(&earlier, root_left(), false)
        .expect_err("the root is running");
    let warn = attached
        .settle_for_drop(&earlier, skipped(), true)
        .expect("an unvouched tree is warned of");
    assert!(warn.contains("could not be vouched for"), "{warn}");
    assert!(warn.contains("skipped the kill"), "{warn}");
    assert!(warn.contains("left something running"), "{warn}");
    assert!(!warn.contains("members"), "{warn}");

    // A walk that left only the root, then a `kill_tree` that answered `Ok`: the drop says what that
    // call found, every time, not that it skipped a kill over something an earlier kill left.
    let root_only = TreeKilled::default();
    attached.settle(&root_only, root_left(), true).expect("the root ended");
    for _ in 0..2 {
        let warn = attached
            .settle_for_drop(&root_only, skipped(), true)
            .expect("an unvouched tree is warned of");
        assert!(warn.contains("could not be vouched for"), "{warn}");
        assert!(warn.contains("found the root running"), "{warn}");
        assert!(warn.contains("the root had ended by then"), "{warn}");
        assert!(!warn.contains("members"), "{warn}");
        assert!(!warn.contains("skipped the kill"), "{warn}");
        assert!(!warn.contains("earlier kill"), "{warn}");
    }

    // The drop's own walk saw the root running, and its root kill ended it: no later settlement
    // warns, so this one does.
    let warn = attached
        .settle_for_drop(
            &TreeKilled::default(),
            TreeKillOutcome::Ran(Err(Unkilled {
                members: Vec::new(),
                root: Some(member_left(1)),
                resolved: Vec::new(),
            })),
            true,
        )
        .expect("a walk that left the root is warned of");
    assert!(warn.contains("could not be vouched for"), "{warn}");
    assert!(warn.contains("found the root running"), "{warn}");
    assert!(warn.contains("the root had ended by then"), "{warn}");
    assert!(!warn.contains("members"), "{warn}");
    assert!(!warn.contains("skipped the kill"), "{warn}");

    let killed = TreeKilled::default();
    attached
        .settle(&killed, TreeKillOutcome::Ran(Ok(())), true)
        .expect("a complete kill");
    assert_eq!(attached.settle_for_drop(&killed, skipped(), true), None);
    assert_eq!(attached.settle_for_drop(&TreeKilled::default(), skipped(), true), None);
}

/// A walk that saw the root running and left it un-vouches the tree, from any state and whatever
/// ended the root afterwards (the root may have forked between the snapshot and the backstop): a kill
/// happened, so a gone root afterwards says the tree could not be walked, not that nothing was
/// killed. The answer follows the root's end: `Ok` once it ended, the root's error while it runs.
///
/// Mutants: the state goes to or stays never settled, after which a gone root says nothing was
/// killed; the state stays or becomes killed once the backstop ended the root.
#[skuld::test]
fn a_walk_that_saw_the_root_running_unvouches_the_tree_whatever_ended_it_afterwards() {
    use super::{Attached, TreeKillOutcome, TreeKilled, Unkilled};
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    let root_left = || {
        TreeKillOutcome::Ran(Err(Unkilled {
            members: Vec::new(),
            root: Some(member_left(1)),
            resolved: Vec::new(),
        }))
    };
    for start in ["never", "killed", "unvouched"] {
        for root_ended in [false, true] {
            let label = format!("{start}, root_ended {root_ended}");
            let killed = TreeKilled::default();
            if start != "never" {
                attached
                    .settle(&killed, TreeKillOutcome::Ran(Ok(())), true)
                    .expect("a complete kill");
            }
            if start == "unvouched" {
                attached
                    .settle(&killed, root_left(), false)
                    .expect_err("the root is left");
            }
            let want_start = match start {
                "never" => Standing::Never,
                "killed" => Standing::Killed,
                _ => Standing::Unvouched,
            };
            assert_eq!(standing(&killed), want_start, "{label}: start");

            let answer = attached.settle(&killed, root_left(), root_ended);

            match answer {
                Ok(outcome) => {
                    assert!(root_ended, "{label}: the root is running");
                    assert_eq!(
                        outcome,
                        super::SettleOutcome::Unvouched {
                            kind: super::UnvouchedKind::RootSeenRunning
                        },
                        "{label}"
                    );
                }
                Err(left) => {
                    assert!(!root_ended, "{label}: the root ended");
                    assert_eq!(pid_left(&left.first), 1, "{label}");
                }
            }
            assert_eq!(standing(&killed), Standing::Unvouched, "{label}");

            // The kind the state stores is the latest one named: a root seen running and ended names
            // `RootSeenRunning`; one still running leaves only that something was.
            let want = if root_ended {
                "found running"
            } else {
                "left something running"
            };
            let mut texts = Vec::new();
            for _ in 0..2 {
                let gone = attached
                    .settle(&killed, TreeKillOutcome::NoRoot, true)
                    .expect_err("a gone root walked nothing");
                let text = gone.first.to_string();
                assert!(!text.contains("nothing was killed"), "{label}: {gone}");
                assert!(!text.contains("members"), "{label}: {gone}");
                assert!(text.contains(want), "{label}: {gone}");
                assert_eq!(standing(&killed), Standing::Unvouched, "{label}");
                texts.push(text);
            }
            assert_eq!(texts[0], texts[1], "{label}");
        }
    }
}

/// A member whose identity was read and that has exited since stops failing the call: nothing is
/// signalled, and the tree is settled. Mutant: the earlier error is returned whatever became of the
/// member.
#[skuld::test]
fn a_member_that_exited_since_it_was_left_stops_failing_the_call() {
    use super::{Attached, TreeKillOutcome, TreeKilled, Unkilled};
    let (blocker, stdin) = crate::test_child::held_uncontained_blocker(false);
    let attached = Attached::TreeWalk(crate::identity::ProcessId::current());
    let killed = TreeKilled::default();
    let id = blocker.id();
    attached
        .settle(
            &killed,
            TreeKillOutcome::Ran(Err(Unkilled {
                members: vec![member_left(id.pid())],
                root: None,
                resolved: vec![id],
            })),
            true,
        )
        .expect_err("the member was left");
    drop(stdin);
    blocker.wait().expect("the member exits on its own and is reaped");

    attached
        .settle(&killed, TreeKillOutcome::Ran(Ok(())), true)
        .expect("a member that is gone is not left");

    assert!(killed.is_set());
}

// A tree call's report names the call =====

/// The members a call's walk left besides the first are warned of under the name of the call that
/// made it, not under `kill_tree`. Mutant: `SweepFailure::of` words every call as `kill_tree`.
#[skuld::test]
fn a_sweeps_report_of_the_other_members_it_left_names_its_call() {
    use super::{Attached, SweepFailure, TreeKillOutcome, TreeKilled, Unkilled};
    use crate::error::Error;
    let member = |pid| Error::MemberNotKilled {
        pid,
        source: Box::new(Error::Containment {
            detail: "refused".into(),
        }),
        note: None,
    };
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let failure = SweepFailure::of(
        "graceful_shutdown_tree",
        &Attached::None,
        &TreeKilled::default(),
        TreeKillOutcome::Ran(Err(Unkilled {
            members: vec![member(1), member(2)],
            root: None,
            resolved: Vec::new(),
        })),
        Ok(()),
        false,
    )
    .expect_err("two members were left");
    assert!(
        matches!(failure.error, Error::MemberNotKilled { pid: 1, .. }),
        "{:?}",
        failure.error
    );
    let warned = crate::log_capture::records_since_on_current_thread(mark, "pid 2 was not killed");
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].1.starts_with("graceful_shutdown_tree: "), "{warned:?}");
}

// fd marker install policy (macOS) =====

/// The install policy, exhaustively: every mode installs a marker for a ROOT spawn, no
/// nested spawn ever does (it inherits the root's), no uncontained spawn does, and an
/// elevation-derived spawn does not (its `sudo` wrapper closes every descriptor >= 3).
#[cfg(target_os = "macos")]
#[skuld::test]
fn marker_wanted_installs_for_every_contained_root_and_nothing_else() {
    use crate::containment::fdmarker::marker_wanted;
    use crate::containment::ContainMode;
    for mode in [ContainMode::Strongest, ContainMode::Session, ContainMode::TreeWalk] {
        assert!(
            marker_wanted(Some(mode), true, false),
            "{mode:?} root installs a marker"
        );
        assert!(
            !marker_wanted(Some(mode), false, false),
            "{mode:?} nested inherits, never installs"
        );
        assert!(
            !marker_wanted(Some(mode), true, true),
            "{mode:?} elevated root must not install"
        );
    }
    assert!(
        !marker_wanted(None, true, false),
        "an uncontained spawn installs no marker"
    );
}

/// The marker mechanism is actionable: `kill_tree`/`terminate_tree` act on it.
#[cfg(target_os = "macos")]
#[skuld::test]
fn attached_fd_marker_is_actionable() {
    use std::os::fd::{AsFd, AsRawFd};

    use super::Attached;
    let (read, write) = std::io::pipe().expect("pipe");
    let handle = crate::containment::fdmarker::pipe_handle_of(write.as_fd()).expect("handle");
    let read_handle = crate::containment::fdmarker::pipe_handle_of(read.as_fd()).expect("read handle");
    let prepared = crate::containment::fdmarker::PreparedMarker {
        read: std::os::fd::OwnedFd::from(read),
        handle,
        read_handle,
        fd: write.as_fd().as_raw_fd(),
    };
    let marker = crate::containment::fdmarker::Marker::new(
        prepared,
        crate::containment::fdmarker::fdmarker_tests::inert_root(),
        None,
    );
    assert!(Attached::FdMarker(marker).is_actionable());
}

/// `prepare` must thread the caller's reserved child fds through to the placement, or a user
/// fd mapping would dup2 over the marker in the child.
#[cfg(target_os = "macos")]
#[skuld::test]
fn prepare_places_the_marker_above_the_callers_reserved_fds() {
    use crate::containment::{ContainMode, ContainRequest, Nesting};
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let prepared = super::prepare(
        &mut cmd,
        &mut crate::child::spawn::in_child::InChild::default(),
        &ContainRequest {
            mode: Some(ContainMode::Strongest),
            nesting: Nesting::Mark,
        },
        &crate::command::flags::FlagsRequest::default(),
        &[3, 4, 5, 6, 7, 8, 9, 10],
        false,
        &[],
    )
    .expect("prepare is infallible off Windows");
    let marker = prepared.marker.as_ref().expect("a contained macOS root gets a marker");
    assert!(
        marker.fd > 10,
        "prepare placed the marker on fd {}, which a user mapping would dup2 over",
        marker.fd
    );
}

/// A failed install degrades to the pre-existing mechanism rather than failing the spawn.
#[cfg(target_os = "macos")]
#[skuld::test]
fn a_failed_marker_install_leaves_prepare_without_one() {
    use crate::containment::fdmarker::fault::{lock_for_log_assertion, set_fault, Fault};
    use crate::containment::{ContainMode, ContainRequest, Nesting};
    // This test doesn't assert on log content itself, but triggering `Fault::Pipe` DOES emit
    // "fd marker: pipe() failed" into the shared `log_capture` buffer once any test has called
    // `log_capture::install()` — held for the whole body so it cannot land inside the sibling
    // fd-marker test module's fault-injection log-scanning test's scanned window on another
    // thread.
    let _serialize = lock_for_log_assertion();
    let mut cmd = std::process::Command::new("/usr/bin/true");
    set_fault(Some(Fault::Pipe));
    let prepared = super::prepare(
        &mut cmd,
        &mut crate::child::spawn::in_child::InChild::default(),
        &ContainRequest {
            mode: Some(ContainMode::Strongest),
            nesting: Nesting::Mark,
        },
        &crate::command::flags::FlagsRequest::default(),
        &[],
        false,
        &[],
    )
    .expect("prepare is infallible off Windows");
    assert!(prepared.marker.is_none(), "the forced failure must yield no marker");
}

/// An elevation-derived spawn must not install a marker: `sudo` closes every descriptor >= 3.
#[cfg(target_os = "macos")]
#[skuld::test]
fn prepare_installs_no_marker_for_an_elevation_derived_spawn() {
    use crate::containment::{ContainMode, ContainRequest, Nesting};
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let prepared = super::prepare(
        &mut cmd,
        &mut crate::child::spawn::in_child::InChild::default(),
        &ContainRequest {
            mode: Some(ContainMode::Strongest),
            nesting: Nesting::Mark,
        },
        &crate::command::flags::FlagsRequest::default(),
        &[],
        true,
        &[],
    )
    .expect("prepare is infallible off Windows");
    assert!(
        prepared.marker.is_none(),
        "an elevated spawn must not claim marker containment"
    );
}

/// The spawn's identity read tells an OS refusal from a vanished pid: denial must not read as
/// vanishing, and absence must not read as denial.
#[cfg(windows)]
#[skuld::test]
fn spawn_identity_distinguishes_a_denied_pid_from_a_vanished_one() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(spawn_identity_distinguishes_a_denied_pid_from_a_vanished_one),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use crate::child::spawn::{resolve_identity_unchecked, spawn_identity_error};
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    let child = crate::identity::windows_fixture::spawn_restricted(&done, PROCESS_SYNCHRONIZE.0);
    assert!(child.is_running(), "precondition: the subject must be live");

    let (read, cause) = resolve_identity_unchecked(&crate::identity::HostKernel, child.pid());
    let denied = spawn_identity_error(read, cause);
    assert!(
        matches!(denied, crate::error::Error::Unassessable { .. }),
        "a pid we may not query must not read as vanished: {denied:?}"
    );

    // Contrast: a pid no process holds.
    let (read, cause) = resolve_identity_unchecked(&crate::identity::HostKernel, 0xFFFF_FFF0);
    let absent = spawn_identity_error(read, cause);
    assert!(
        matches!(&absent, crate::error::Error::Io(e) if e.to_string().contains("reaped by another party")),
        "absence must not read as denial: {absent:?}"
    );
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn wait_drained_is_unsupported_without_a_marker() {
    // Mirrors `require_contained`: a mechanism that cannot answer says so, rather than
    // implying a guarantee it has not got.
    use super::Attached;
    for attached in [Attached::None, Attached::Delegated] {
        let err = attached
            .wait_drained(Some(std::time::Instant::now()))
            .expect_err("a mechanism with no drain edge must be Unsupported");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn wait_drained_reports_members_remain_then_all_markers_closed() {
    use super::Attached;
    use crate::containment::fdmarker::{pipe_handle_of, Marker, PreparedMarker};
    use crate::containment::TreeDrain;
    use std::os::fd::{AsFd, OwnedFd};

    // A real holder in a separate process, mirroring marker_eof_tests.rs's
    // spawn_marker_holder: the marker's write end lives in the child, not in-process, so
    // wait_drained observes a genuinely open, then genuinely closed, write end.
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.executable("/bin/sh").args(["sh", "-c", "exec cat >/dev/null"]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    let mut child = cmd.spawn().expect("spawn /bin/sh");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    let stdin = child.fd_write_end(crate::Fd::STDIN).expect("stdin write end");

    // wait_drained now consults read_handle too (Marker::wait_drained calls
    // check_read_end_still_valid first, same as hard_kill/terminate) — so this uses the read
    // end's REAL current handle for both fields, standing in for install()'s full write-end
    // capture sequence without replicating it.
    let handle = pipe_handle_of(marker.as_fd()).expect("handle");
    let prepared = PreparedMarker {
        read: OwnedFd::from(marker),
        handle,
        read_handle: handle,
        fd: 3,
    };
    let attached = Attached::FdMarker(Marker::new(
        prepared,
        crate::containment::fdmarker::fdmarker_tests::inert_root(),
        None,
    ));

    assert_eq!(
        attached
            .wait_drained(Some(std::time::Instant::now()))
            .expect("bounded wait while the holder is alive"),
        TreeDrain::MembersRemain
    );

    drop(stdin); // cat's stdin EOFs, so cat exits, closing its inherited marker write end
    child.wait().expect("reap");

    assert_eq!(
        attached
            .wait_drained(None)
            .expect("unbounded wait after the holder exits"),
        TreeDrain::AllMarkersClosed
    );
}

/// The UAC-elevated attachment bypasses `mechanism_from_flags` entirely — nothing in the flag
/// matrix covers it — so its three fields are pinned here. `Unknown`, not the `None` a flagless
/// spawn yields nor the `OtherConsoleGroup` a suppressed one does: a copy-paste of either must
/// fail. What the dispatcher then does with the value is
/// `signal_refuses_a_child_cosca_did_not_create`, in `src/graceful_tests.rs`.
#[cfg(windows)]
#[skuld::test]
fn uac_elevated_attachment_has_no_in_process_route() {
    use super::{Attached, Attachment};
    use crate::containment::Containment;
    use crate::graceful::GracefulMechanism;

    let a = Attachment::uac_elevated();
    assert_eq!(a.containment, Containment::None);
    assert!(matches!(a.attached, Attached::None), "got {:?}", a.attached);
    assert_eq!(a.graceful, GracefulMechanism::Unknown);
}

// The cgroup placement decision =====
// `attach_tree` decides whether a Strongest root's leaf owns its tree. The child's own
// self-placement report is the oracle: a later `cgroup.procs` read lists only LIVE tasks, so a
// placed child that has already exited reads back as absent. Real filesystem, no cgroupfs: each
// leaf is a temp directory shaped with ordinary files. These tests are about what the decision
// does with a report, not how a child earns one: a failed write is made for real, in-process,
// but `Placed` is stored directly, since a successful write to anything but a real `cgroup.procs`
// is the very false report the live cgroup lane guards against.

/// What the child's `pre_exec` closure reported, if it ran at all.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum ChildReport {
    Placed,
    WriteFailed,
    NotReported,
}

/// Run the decision for a leaf at `leaf_path` whose child reported `report`.
#[cfg(target_os = "linux")]
fn decide(leaf_path: &std::path::Path, report: ChildReport) -> (crate::containment::Containment, super::Attached) {
    use crate::containment::cgroup::{place_self_in_cgroup_pre_exec, CgroupLeaf};

    let leaf = CgroupLeaf::for_test_at(leaf_path.to_path_buf());
    match report {
        // SAFETY: the slot's pipe lives as long as `leaf`.
        ChildReport::Placed => unsafe { leaf.placement_slot().report_placed_for_test() },
        ChildReport::WriteFailed => {
            // SAFETY: fd -1 is never writable, so the write fails with EBADF; closing -1 is a
            // no-op. The slot's pipe lives as long as `leaf`.
            _ = unsafe { place_self_in_cgroup_pre_exec(-1, leaf.placement_slot()) };
        }
        ChildReport::NotReported => {}
    }
    let prepared = super::Prepared {
        mode: Some(crate::containment::ContainMode::Strongest),
        is_root: true,
        cgroup_leaf: Some(leaf),
        #[cfg(all(target_os = "linux", feature = "tokio"))]
        teardown_warn_after: None,
    };
    super::attach_tree(
        crate::identity::ProcessId::current(),
        crate::containment::cgroup::test_support::handle_of(
            std::process::id(),
            &crate::containment::cgroup::test_support::pidfd_of(std::process::id()),
        ),
        prepared,
    )
    .expect("attach_tree")
}

/// A leaf directory whose `cgroup.procs` lists some OTHER pid, never this test's.
#[cfg(target_os = "linux")]
fn leaf_listing_another_pid(dir: &std::path::Path) -> std::path::PathBuf {
    let leaf_path = dir.join("cosca-decision-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let other = std::process::id().wrapping_add(1);
    std::fs::write(leaf_path.join("cgroup.procs"), format!("{other}\n")).expect("write cgroup.procs");
    leaf_path
}

/// A child that reported its write accepted, and has since exited: `cgroup.procs` no longer
/// lists it. Anything it forked is still in the leaf, so the leaf owns the tree.
#[cfg(target_os = "linux")]
#[skuld::test(labels = [crate::test_harness::CGROUP])]
fn a_placed_report_outranks_a_cgroup_procs_that_omits_the_child() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = leaf_listing_another_pid(dir.path());

    let (containment, attached) = decide(&leaf_path, ChildReport::Placed);

    assert_eq!(containment, crate::containment::Containment::CgroupV2);
    let super::Attached::Cgroup(leaf) = &attached else {
        panic!("got {attached:?}");
    };
    assert!(
        !leaf.holds_spawn_resources(),
        "a live child's leaf must not hold its cgroup.procs fd or report pipe past the verdict"
    );
    assert!(
        !leaf_path.join("cgroup.kill").exists(),
        "the leaf owns a live tree; nothing may kill it at spawn time"
    );
}

/// Membership that cannot be read is unknown, not absent — and the child's own report already
/// answers it.
#[cfg(target_os = "linux")]
#[skuld::test(labels = [crate::test_harness::CGROUP])]
fn a_placed_report_outranks_an_unreadable_cgroup_procs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-decision-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf (no cgroup.procs inside)");

    let (containment, attached) = decide(&leaf_path, ChildReport::Placed);

    assert_eq!(containment, crate::containment::Containment::CgroupV2);
    assert!(matches!(attached, super::Attached::Cgroup(_)), "got {attached:?}");
}

/// A child whose write failed never entered the leaf, so neither did anything it forked: the
/// spawn degrades and the empty leaf is removed.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_write_degrades_and_removes_the_leaf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-decision-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");

    let (containment, attached) = decide(&leaf_path, ChildReport::WriteFailed);

    assert_eq!(containment, crate::containment::Containment::ProcessGroup);
    assert!(matches!(attached, super::Attached::ProcessGroup(_)), "got {attached:?}");
    assert!(!leaf_path.exists(), "the degrade must remove the leaf it created");
}

/// Removing a leaf the child never entered must never write `cgroup.kill`, even when the leaf
/// will not go away: whatever is in it, cosca did not put there. The leaf left behind is
/// reported.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_degrade_never_kills_through_the_leaf() {
    crate::log_capture::install();
    for report in [ChildReport::WriteFailed, ChildReport::NotReported] {
        let dir = tempfile::tempdir().expect("tempdir");
        // A `cgroup.procs` file makes the directory non-empty, so its `rmdir` fails.
        let leaf_path = leaf_listing_another_pid(dir.path());

        let mark = crate::log_capture::mark();
        let (containment, _attached) = decide(&leaf_path, report);

        assert_eq!(containment, crate::containment::Containment::ProcessGroup);
        assert!(
            !leaf_path.join("cgroup.kill").exists(),
            "a degrade wrote cgroup.kill: it would kill a tree cosca had just been asked to contain"
        );
        let left_behind: Vec<String> = crate::log_capture::records_since(mark, &leaf_path.to_string_lossy())
            .into_iter()
            .filter(|record| record.contains("was not removed"))
            .collect();
        assert_eq!(
            left_behind.len(),
            1,
            "the unremoved leaf is reported once: {left_behind:?}"
        );
    }
}

// kill_on_drop's reach into the containment resource =====
// See `Attached::honor_kill_on_drop`.

/// A leaf standing in for a live contained tree: occupied (so `rmdir` fails and `Drop` would
/// reach for `cgroup.kill`) and carrying an empty `cgroup.kill` to read the write back from.
#[cfg(target_os = "linux")]
fn occupied_leaf_for_test(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let leaf_path = dir.join(name);
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("stand in for the live tree");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");
    leaf_path
}

#[cfg(target_os = "linux")]
fn cgroup_attachment_for_test(leaf_path: &std::path::Path) -> super::Attachment {
    super::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: super::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.to_path_buf(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    }
}

/// `kill_on_drop(false)` must disarm the cgroup leaf. Without it the handle's own teardown is
/// skipped and the leaf's `Drop` kills the tree anyway — the opposite of the opt-out.
#[cfg(target_os = "linux")]
#[skuld::test(labels = [crate::test_harness::CGROUP])]
fn kill_on_drop_false_disarms_a_cgroup_leaf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = occupied_leaf_for_test(dir.path(), "cosca-kill-on-drop-false-leaf");

    let attachment = cgroup_attachment_for_test(&leaf_path);
    attachment.attached.honor_kill_on_drop(false);
    drop(attachment);

    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"",
        "kill_on_drop(false) opts out of the teardown; a tree it killed anyway is the opposite"
    );
}

/// The same leaf under `kill_on_drop(true)` DOES fire `cgroup.kill`, so the test above pins
/// the disarm rather than an inert path.
#[cfg(target_os = "linux")]
#[skuld::test(labels = [crate::test_harness::CGROUP])]
fn kill_on_drop_true_leaves_a_cgroup_leaf_armed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = occupied_leaf_for_test(dir.path(), "cosca-kill-on-drop-true-leaf");

    let attachment = cgroup_attachment_for_test(&leaf_path);
    attachment.attached.honor_kill_on_drop(true);
    drop(attachment);

    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"1",
        "the default is still a kill-on-drop teardown"
    );
}

// ===== frozen attach (Windows) =====

#[cfg(windows)]
mod frozen_attach {
    use crate::containment::dispatch::{attach, Attached, Attachment, Prepared};
    use crate::containment::windows::fault::{force_next, Step};
    use crate::containment::{ContainMode, Containment};
    use crate::error::Error;
    use crate::test_frozen::{
        assert_not_released, limit_flags, raw, release, spawn_suspended_blocker, spawn_suspended_releasable,
        InitialThread,
    };
    use windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    const ERROR_ACCESS_DENIED: u32 = 5;

    fn prepared(mode: Option<ContainMode>, is_root: bool, frozen: bool) -> Prepared {
        Prepared {
            mode,
            is_root,
            graceful: crate::graceful::GracefulMechanism::None,
            frozen,
        }
    }

    fn attach_suspended(child: &std::process::Child, prepared: Prepared) -> Result<Attachment, Error> {
        let crate::identity::Resolved::Found(id) = crate::identity::ProcessId::of(child.id()) else {
            panic!("the suspended child must be readable");
        };
        attach(id, raw(child), prepared)
    }

    fn dispose(mut child: std::process::Child) {
        child.kill().expect("kill the test child");
        child.wait().expect("reap the test child");
    }

    /// A frozen Strongest root is assigned its containment job and stays suspended.
    #[skuld::test]
    fn death_watch_attach_frozen_assigns_a_strongest_roots_job_and_leaves_the_thread_suspended() {
        let mut child = spawn_suspended_releasable();
        let thread = InitialThread::of(child.id());

        let attachment = attach_suspended(&child, prepared(Some(ContainMode::Strongest), true, true)).expect("attach");

        assert_eq!(attachment.containment, Containment::JobObject);
        let Attached::JobObject(job) = &attachment.attached else {
            panic!("expected a job, got {:?}", attachment.attached);
        };
        assert_ne!(
            limit_flags(job).0 & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0,
            0,
            "the job must kill on close: the frozen child never runs, so nothing else ends it"
        );
        assert_eq!(thread.suspend_count(), 1, "a frozen attach must not resume");
        drop(attachment);
        // The close's kill ended it. A close that killed nothing leaves a frozen child that never
        // runs, so it is released to run to its end, which `assert_not_released` rejects.
        release(&mut child, &thread);
        assert_not_released("the frozen child", child.wait().expect("reap the frozen child"));
    }

    /// A frozen root needs its job to be held, so a failed assignment fails the attach instead of
    /// falling back to `TreeWalk`, which would leave nothing to kill it.
    #[skuld::test]
    fn attach_frozen_fails_when_the_strongest_assignment_fails_instead_of_falling_back_to_treewalk() {
        let child = spawn_suspended_blocker();
        let _forced = force_next(Step::Assign, ERROR_ACCESS_DENIED);

        let err = attach_suspended(&child, prepared(Some(ContainMode::Strongest), true, true))
            .err()
            .expect("a frozen attach with no job must fail");

        assert!(matches!(err, Error::Containment { .. }), "got {err:?}");
        dispose(child);
    }

    /// The ordinary attach is unchanged: it resumes, and a failed assignment still degrades to
    /// `TreeWalk`.
    #[skuld::test]
    fn attach_without_hold_still_resumes_and_still_falls_back_to_treewalk() {
        let child = spawn_suspended_blocker();
        let thread = InitialThread::of(child.id());
        let _forced = force_next(Step::Assign, ERROR_ACCESS_DENIED);

        let attachment = attach_suspended(&child, prepared(Some(ContainMode::Strongest), true, false)).expect("attach");

        assert_eq!(attachment.containment, Containment::TreeWalk);
        assert_eq!(thread.suspend_count(), 0, "the ordinary attach resumes the child");
        dispose(child);
    }

    /// Every shape without a cosca job of its own (`TreeWalk` root, nested member, uncontained) is
    /// left frozen and unjobbed: `attach` adds no job and keeps the containment it would report if
    /// the child were not frozen.
    #[skuld::test]
    fn attach_frozen_gives_treewalk_nested_and_uncontained_shapes_no_job_and_leaves_them_suspended() {
        let shapes = [
            (
                "treewalk root",
                Some(ContainMode::TreeWalk),
                true,
                Containment::TreeWalk,
            ),
            (
                "nested strongest member",
                Some(ContainMode::Strongest),
                false,
                Containment::Delegated,
            ),
            (
                "nested treewalk member",
                Some(ContainMode::TreeWalk),
                false,
                Containment::Delegated,
            ),
            ("uncontained", None, false, Containment::None),
        ];
        for (name, mode, is_root, expected) in shapes {
            let child = spawn_suspended_blocker();
            let thread = InitialThread::of(child.id());

            let attachment = attach_suspended(&child, prepared(mode, is_root, true)).expect(name);

            assert_eq!(attachment.containment, expected, "{name}");
            assert!(
                !matches!(attachment.attached, Attached::JobObject(_)),
                "{name}: no job of its own"
            );
            assert_eq!(thread.suspend_count(), 1, "{name}: a frozen attach must not resume");
            drop(attachment);
            dispose(child);
        }
    }
}
