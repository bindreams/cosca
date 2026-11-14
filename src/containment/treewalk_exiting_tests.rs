//! A root whose exit has begun while its children still name it as their parent: the walk finds them,
//! but the kernel reparents the rest at the exit's next step, so a walk from the root's pid cannot say
//! it reached the tree. Linux only: the root shows `PF_EXITING` in every thread's `stat`, stated as a
//! [`FakeKernel`] row; these rows are about what a walk does once it reads the flag.

use std::io::Read as _;
use std::os::unix::process::ExitStatusExt as _;

use crate::containment::dispatch::{TreeKillOutcome, TreeKilled};
use crate::identity::{FakeKernel, HostKernel, ProcessId};
use crate::test_child::{live_exiting_member as live_member, release_unsignalled as release};

use super::treewalk_view_tests::{assert_unassessable_naming, live_member_with_descendant, walks};

/// The flags of a thread inside `do_exit`, as measured on Linux 6.12.113: `PF_EXITING`, and `0x8` with it.
const EXITING: u32 = 0x40_014c;

/// A kernel in which `root`, whose only thread is its own, has begun to exit.
fn exiting_root(root: ProcessId) -> FakeKernel<'static> {
    with_exiting_root(FakeKernel::over(&HostKernel), root)
}

/// `kernel`, in which `root`, whose only thread is its own, has begun to exit.
pub(super) fn with_exiting_root(kernel: FakeKernel<'static>, root: ProcessId) -> FakeKernel<'static> {
    let pid = root.pid();
    let stat = format!("{pid} (sh) S 1 {pid} {pid} 0 -1 {EXITING} 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0");
    kernel
        .on_tids(pid, Ok(&[pid]))
        .on_read(&format!("{pid}/task/{pid}/stat"), Ok(stat.as_bytes()))
}

/// What a signalled root and descendant leave: the descendant printed nothing, and the root died of
/// `signo`. The stdin is released first, so a descendant that was not signalled prints and fails the
/// assertion instead of blocking the read.
#[track_caller]
fn assert_both_signalled(who: &str, mut child: std::process::Child, signo: i32) {
    drop(child.stdin.take());
    let mut printed = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut printed)
        .expect("read to EOF");
    assert_eq!(printed, "", "{who}: the descendant must have been signalled");
    assert_eq!(child.wait().expect("reap the root").signal(), Some(signo), "{who}");
}

/// The root's members are killed, and the answer is not `Ok`: children the exit had already reparented
/// are beyond the walk, so a kill that returned `Ok` would say it reached a tree it only partly did.
/// Mutants: "the check runs only when the walk found no member" (`Ok`); "a root that has begun to exit
/// reads as running".
#[skuld::test]
fn a_kill_of_a_root_that_has_begun_to_exit_kills_its_members_and_is_unassessable() {
    for (name, walk) in walks().into_iter().filter(|(name, _)| name.contains("kill")) {
        let (child, root, _descendant) = live_member_with_descendant();
        let kernel = exiting_root(root);
        let result = walk(&kernel, root);
        assert_unassessable_naming(result, &["had begun to exit", &format!("pid {}", root.pid())]);
        assert_both_signalled(name, child, libc::SIGKILL);
    }
}

/// The `SIGTERM` walk signals the root and its members, and its listing says it cannot vouch for the
/// tree, so the sweep that follows does not take the members for the whole of it. Mutant: the listing
/// is `complete`.
#[skuld::test]
fn a_terminate_of_a_root_that_has_begun_to_exit_signals_its_members_and_lists_them_incomplete() {
    let (child, root, descendant) = live_member_with_descendant();
    let kernel = exiting_root(root);
    let walked = super::terminate(&kernel, root, &super::ByIdentity::new(&kernel, root)).expect("the table reads");
    let super::Terminated::Walked(listing) = walked else {
        panic!("the members were walked");
    };
    assert_eq!(listing.members, [descendant]);
    assert!(
        !listing.complete,
        "the exit's reparenting may have taken members out of the walk"
    );
    assert_both_signalled("terminate", child, libc::SIGTERM);
}

/// A root that has begun to exit and has no member is an exited root: nothing is sent, as for a
/// zombie, for the exit's reparenting may have taken every child. Mutant: the check runs only for a
/// root the table shows as a zombie.
#[skuld::test]
fn a_root_that_has_begun_to_exit_with_no_member_is_no_root_and_nothing_is_sent() {
    let (child, id) = live_member();
    let kernel = exiting_root(id);
    assert!(
        matches!(
            super::hard_kill(&kernel, id, &super::ByIdentity::new(&kernel, id)).outcome(),
            TreeKillOutcome::NoRoot(..)
        ),
        "the root has no tree to walk"
    );
    let termed = super::terminate(&kernel, id, &super::ByIdentity::new(&kernel, id));
    assert!(
        matches!(termed, Ok(super::Terminated::RootExited(_))),
        "nothing is sent"
    );
    // Never signalled: the member ends by its own clean exit.
    release(child);
}

/// A kernel in which the threads of `root` cannot be read, so whether its exit has begun cannot be told.
fn flag_unreadable(root: ProcessId) -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel).on_tids_failing_after_open(root.pid(), libc::EIO)
}

/// A flag that cannot be read leaves the walk as it was before the flag was read: the members found are
/// killed, with the root, and the answer is the read's error, not `Ok`. Mutants: the unreadable flag
/// fails the walk before any kill (`Unwalked`) whatever it found; the error is dropped (`Ok`).
#[skuld::test]
fn a_kill_whose_exit_flag_cannot_be_read_kills_its_members_and_answers_with_the_read_error() {
    for (name, walk) in walks().into_iter().filter(|(name, _)| name.contains("kill")) {
        let (child, root, _descendant) = live_member_with_descendant();
        let kernel = flag_unreadable(root);
        let result = walk(&kernel, root);
        assert_unassessable_naming(
            result,
            &["exit has begun could not be read", &format!("pid {}", root.pid())],
        );
        assert_both_signalled(name, child, libc::SIGKILL);
    }
}

/// The same for the `SIGTERM` walk: members and root are signalled, and the listing cannot vouch for the
/// tree. Mutant: the walk is `NotSent` with nothing signalled, or its listing is `complete`.
#[skuld::test]
fn a_terminate_whose_exit_flag_cannot_be_read_signals_its_members_and_lists_them_incomplete() {
    let (child, root, descendant) = live_member_with_descendant();
    let kernel = flag_unreadable(root);
    let walked = super::terminate(&kernel, root, &super::ByIdentity::new(&kernel, root)).expect("members were found");
    let super::Terminated::Walked(listing) = walked else {
        panic!("the members were walked");
    };
    assert_eq!(listing.members, [descendant]);
    assert!(
        !listing.complete,
        "a listing with an unread flag cannot vouch for the tree"
    );
    assert_both_signalled("terminate", child, libc::SIGTERM);
}

/// With no member found, a flag that cannot be read is a walk not made: nothing is killed or sent, the
/// root included, and a retry can read it.
#[skuld::test]
fn a_walk_with_no_member_whose_exit_flag_cannot_be_read_sends_nothing() {
    let (child, root) = live_member();
    let kernel = flag_unreadable(root);
    assert!(
        matches!(
            super::hard_kill(&kernel, root, &super::ByIdentity::new(&kernel, root)).outcome(),
            TreeKillOutcome::Unwalked(crate::error::Error::Unassessable { .. })
        ),
        "no member was found and the flag is unread"
    );
    let termed = super::terminate(&kernel, root, &super::ByIdentity::new(&kernel, root));
    assert!(
        matches!(termed, Err(crate::error::Error::Unassessable { .. })),
        "nothing is sent"
    );
    release(child);
}

/// A root whose exit has begun, with candidates the walk could not read and no member, is not `Ok` for
/// want of members to answer for: the answer says the exit had begun, as `terminate`'s `RootExited` does.
/// Mutant: the entry is added only when members were found.
#[skuld::test]
fn a_kill_of_a_root_that_has_begun_to_exit_with_only_unread_candidates_says_so() {
    let (child, root, descendant) = live_member_with_descendant();
    let kernel = with_exiting_root(
        FakeKernel::over(&HostKernel).on_pidfd_open(descendant.pid(), Err(rustix::io::Errno::MFILE)),
        root,
    );
    let TreeKillOutcome::Ran(Err(left)) =
        super::hard_kill(&kernel, root, &super::ByIdentity::new(&kernel, root)).outcome()
    else {
        panic!("the unread candidate is left");
    };
    let said = left
        .members
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    assert!(
        said.contains(&format!("pid {}", descendant.pid())),
        "the candidate is named: {said}"
    );
    assert!(said.contains("had begun to exit"), "the root's exit is named: {said}");
    // The root was killed; the candidate was not, and ends on the EOF.
    release_candidate(child);
}

/// The root of `live_member_with_descendant`, killed, and the descendant released by the EOF of its
/// stdin: it prints, so it was not signalled.
fn release_candidate(mut child: std::process::Child) {
    use std::os::unix::process::ExitStatusExt as _;
    let mut printed = String::new();
    drop(child.stdin.take());
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut printed)
        .expect("read to EOF");
    assert_eq!(
        printed, "released\n",
        "the unread candidate must not have been signalled"
    );
    assert_eq!(child.wait().expect("reap the root").signal(), Some(libc::SIGKILL));
}

/// The tree-walk mechanism of a tree rooted at `root`.
fn walker(root: ProcessId) -> crate::containment::mechanism::Mechanism {
    crate::containment::mechanism::Mechanism::Walk(super::Walker::new(root))
}

/// What `entries` hold of the root's begun exit: the entry that names it.
fn names_the_exit(entries: &[crate::error::Error]) -> bool {
    entries.iter().any(|entry| {
        matches!(entry, crate::error::Error::Unassessable { detail, .. } if detail.contains("had begun to exit"))
    })
}

/// A root whose exit had begun, whose members were found and whose own kill was left, is not `Ok` when a
/// later kill ends the root: the settlement drops the root's entry, and the exit's must outlive it.
/// Mutant: the exit's entry is added only when nothing but members is left.
#[skuld::test]
fn a_begun_root_whose_own_kill_was_left_is_not_ok_once_a_later_kill_ends_it() {
    use super::fault::{force_incomplete_once, LeftBehind};
    let (child, root, _descendant) = live_member_with_descendant();
    let kernel = exiting_root(root);
    force_incomplete_once(LeftBehind::Root);

    let outcome = super::hard_kill(&kernel, root, &super::ByIdentity::new(&kernel, root)).outcome();
    let answer = TreeKilled::default().settle(Some(&walker(root)), outcome, true).answer;

    assert!(
        matches!(&answer, Err(crate::error::Error::Unassessable { detail, .. }) if detail.contains("had begun to exit")),
        "{answer:?}"
    );
    assert_both_signalled("hard_kill", child, libc::SIGKILL);
}

/// A root whose exit had begun, with a member whose kill was refused, says the exit had begun beside
/// the member it left. Mutant: the entry is added only for unread candidates with no member.
#[skuld::test]
fn a_kill_of_a_begun_root_that_leaves_a_member_says_the_exit_had_begun() {
    use super::fault::{force_incomplete_once, LeftBehind};
    let (child, root, _descendant) = live_member_with_descendant();
    let kernel = exiting_root(root);
    force_incomplete_once(LeftBehind::Descendant);

    let TreeKillOutcome::Ran(Err(left)) =
        super::hard_kill(&kernel, root, &super::ByIdentity::new(&kernel, root)).outcome()
    else {
        panic!("a member is left");
    };

    assert!(names_the_exit(&left.members), "{:?}", left.members);
    assert_both_signalled("hard_kill", child, libc::SIGKILL);
}

/// A flag that cannot be read, with every member and the root killed, left nothing running: the
/// settlement does not take the read's error for a member seen running, so a later kill that finds the
/// root gone does not say a kill left something running. Mutant: any non-member error counts as running.
#[skuld::test]
fn an_unreadable_exit_flag_with_everything_killed_is_not_something_left_running() {
    let (child, root, _descendant) = live_member_with_descendant();
    let kernel = flag_unreadable(root);
    let killed = TreeKilled::default();

    let outcome = super::hard_kill(&kernel, root, &super::ByIdentity::new(&kernel, root)).outcome();
    let first = killed.settle(Some(&walker(root)), outcome, true).answer;
    assert!(
        matches!(&first, Err(crate::error::Error::Unassessable { detail, .. }) if detail.contains("could not be read")),
        "the read's error is the answer: {first:?}"
    );

    let later = killed
        .settle(Some(&walker(root)), TreeKillOutcome::NoRoot(root.pid(), None), true)
        .answer;
    if let Err(error) = &later {
        let said = error.to_string();
        assert!(
            !said.contains("a kill left something running"),
            "nothing was left running: {said}"
        );
    }
    assert_both_signalled("hard_kill", child, libc::SIGKILL);
}

/// A graceful call's own complete `SIGTERM` listing vouches for the tree over a root that its sweep
/// catches between the exit flag and the reparent, as it does a moment later, when the root is a
/// zombie: the sweep's members are killed, the listed ones are killed by identity, and the answer is
/// `Ok`. Mutant: a root seen exiting with members found is `Unassessable` whatever the call listed.
#[skuld::test]
fn a_graceful_sweep_over_a_root_caught_exiting_stands_on_its_own_listing() {
    let tree = crate::test_child::foreign::tree_of(crate::test_child::TERM_IGNORING_TREE_ARGV);
    let crate::test_child::foreign::SurvivorTree {
        mut child,
        process,
        members,
        ..
    } = tree;
    let settling = process.begin_graceful().expect("the SIGTERM walk");
    let kernel = with_exiting_root(FakeKernel::over(&HostKernel), process.id());

    process
        .kill_tree_settling("graceful_shutdown_tree", &kernel, Some(&settling))
        .expect("every member the call's own listing reached is killed");

    for member in &members {
        assert_eq!(
            member.is_alive(),
            crate::identity::Liveness::Dead,
            "{member:?} ignored the SIGTERM and is killed"
        );
    }
    assert_eq!(child.wait().expect("reap the root").signal(), Some(libc::SIGKILL));
}
