//! `origin`: whether a pid was forked by this process, before its unique id is known.

use super::{origin, Origin};

/// A child of this process, untraced, is ours by its parent.
///
/// Mutant: the parent is not read, only the parent at a tracer's attach.
#[skuld::test]
fn a_child_of_this_process_is_ours() {
    let mut cmd = std::process::Command::new("/bin/cat");
    cmd.stdin(std::process::Stdio::piped());
    let guard = crate::child::spawn::spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `guard`")]
    let mut child = cmd.spawn().expect("spawn cat");
    drop(guard);
    assert_eq!(origin(child.id()), Origin::Ours);
    drop(child.stdin.take());
    child.wait().expect("reap cat");
}

/// This process's own parent was not forked by it.
///
/// Mutant: every live pid is ours.
#[skuld::test]
fn the_parent_of_this_process_is_not_ours() {
    // SAFETY: `getppid` has no preconditions.
    let parent = unsafe { libc::getppid() } as u32;
    assert_eq!(origin(parent), Origin::NotOurs);
}
