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
    assert_eq!(
        origin(child.id()),
        Origin::Ours {
            parent: std::process::id()
        }
    );
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

/// A process created before this one is not ours, though its `p_oppid` names this process's pid: an
/// earlier holder of the pid left it. This process's parent is forced to show it.
///
/// Mutant: `origin` does not compare unique ids.
#[skuld::test]
fn a_stale_parent_at_attach_does_not_make_an_older_process_ours() {
    // SAFETY: `getppid` has no preconditions.
    let parent = unsafe { libc::getppid() } as u32;
    super::kinfo::fault::force_oppid_once(std::process::id() as libc::pid_t);
    assert_eq!(origin(parent), Origin::NotOurs);
}

/// A live `cat` child of this test on a held stdin, and the stdin. Dropping the stdin ends it.
fn live_child() -> (std::process::Child, std::process::ChildStdin) {
    let mut cmd = std::process::Command::new("/bin/cat");
    cmd.stdin(std::process::Stdio::piped());
    let guard = crate::child::spawn::spawn_lock();
    #[allow(clippy::disallowed_methods, reason = "spawn_lock is held by `guard`")]
    let mut child = cmd.spawn().expect("spawn cat");
    drop(guard);
    let stdin = child.stdin.take().expect("piped stdin");
    (child, stdin)
}

fn end(mut child: std::process::Child, stdin: std::process::ChildStdin) {
    drop(stdin);
    child.wait().expect("reap cat");
}

/// A pid whose unique-id read finds no process is `Gone`, for `origin` and for `link`.
///
/// Mutant: a vanished pid is `NotOurs` (`origin`) or `Unreadable` (`link`).
#[skuld::test]
fn a_pid_with_no_process_is_gone() {
    use super::{link, uniq_fault, Link, ReadPurpose, UniqRead};
    let (child, stdin) = live_child();
    {
        let _gone = uniq_fault::force_uniq_read_once(ReadPurpose::Origin, UniqRead::Gone);
        assert_eq!(origin(child.id()), Origin::Gone);
    }
    {
        let _gone = uniq_fault::force_uniq_read_once(ReadPurpose::Link, UniqRead::Gone);
        assert_eq!(link(child.id()), Link::Gone);
    }
    end(child, stdin);
}

/// A refused unique-id read is `Refused` with its errno, for `origin` and for `link`.
///
/// Mutant: a refusal is `Gone`.
#[skuld::test]
fn a_refused_unique_id_read_is_refused() {
    use super::{link, uniq_fault, Link, ReadPurpose, UniqRead};
    let (child, stdin) = live_child();
    {
        let _refused = uniq_fault::force_uniq_read_once(ReadPurpose::Origin, UniqRead::Refused(libc::EPERM));
        assert_eq!(origin(child.id()), Origin::Refused(libc::EPERM));
    }
    {
        let _refused = uniq_fault::force_uniq_read_once(ReadPurpose::Link, UniqRead::Refused(libc::EPERM));
        assert_eq!(link(child.id()), Link::Refused(libc::EPERM));
    }
    end(child, stdin);
}

/// A refused `kinfo_proc` read is `Unreadable`, for `origin` and for `link`.
///
/// Mutant: a refused `kinfo_proc` read is `Gone`.
#[skuld::test]
fn a_refused_kinfo_read_is_unreadable() {
    use super::{link, Link};
    let (child, stdin) = live_child();
    super::kinfo::fault::force_unreadable_once();
    assert_eq!(origin(child.id()), Origin::Unreadable);
    super::kinfo::fault::force_unreadable_once();
    assert_eq!(link(child.id()), Link::Unreadable);
    end(child, stdin);
}

/// An untraced child of this process links to this process, with no parent at an attach.
///
/// Mutant: `link` reads `p_oppid` as the parent now.
#[skuld::test]
fn an_untraced_child_links_to_this_process() {
    use super::{link, uniq_info, Link, ReadPurpose, UniqRead};
    let (child, stdin) = live_child();
    let UniqRead::Found(info) = uniq_info(child.id(), ReadPurpose::Kill) else {
        panic!("the child's unique id must be readable")
    };
    assert_eq!(
        link(child.id()),
        Link::Found {
            unique: info.unique_id,
            parent: std::process::id(),
            at_attach: 0,
        }
    );
    end(child, stdin);
}
