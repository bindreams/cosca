//! A root whose exit has begun while its children still name it as their parent: the walk finds them,
//! but the kernel reparents the rest at the exit's next step, so a walk from the root's pid cannot say
//! it reached the tree. Linux only: the root shows `PF_EXITING` in every thread's `stat`, stated as a
//! [`FakeKernel`] row. The kernel's order, the flag before the reparent, is measured (the held exit
//! needs root and a FUSE mount); these rows are about what a walk does once it reads the flag.

use std::io::Read as _;
use std::os::unix::process::ExitStatusExt as _;

use crate::containment::dispatch::TreeKillOutcome;
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
/// `signo`.
#[track_caller]
fn assert_both_signalled(who: &str, mut child: std::process::Child, signo: i32) {
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
