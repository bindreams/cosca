//! `open_verified` against REAL namespace layouts, in re-exec'd children that own private
//! mount or pid namespaces (see `test_child::namespaces` for the group's gating).

use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;

use super::linux_tests::LiveNonLeaderTid;
use crate::error::Error;
use crate::identity::{proc_view, ProcDir, ProcView, ProcessId};
use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;
use crate::test_groups::{namespaces, Group};

/// A status file mounted over `/proc/<pid>/status` is a mount below the checked `/proc`, which no
/// read crosses: the view is `Unassessable` naming the refused crossing. A live foreign kill does
/// not depend on the view (the success path proves its target through the pidfd's fdinfo), so it
/// keeps working.
///
/// Mutants: "the success path requires a `Same` `proc_view()`" — every live `open_verified` is
/// then `Unassessable`; "read `status` with a plain `openat`" — the fake status is read as real.
#[skuld::test]
fn namespaces_a_status_mounted_over_below_proc_keeps_live_foreign_kills_working(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_status_mounted_over));
}

#[skuld::test]
fn fixture_status_mounted_over() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    // A live foreign process: killed through `kill`, which goes through `open_verified`. Its
    // identity is read before the mount: `of` answers `Unknown` once a file is mounted over `/proc`.
    let mut child = crate::test_spawn::spawn(std::process::Command::new("cat").stdin(std::process::Stdio::piped()))
        .expect("spawn cat");
    let id = ProcessId::of(child.id())
        .found()
        .expect("the live child has an identity");
    let scratch = tempfile::tempdir().expect("tempdir");
    let status = scratch.path().join("status");
    std::fs::write(&status, "Name:\tcosca\nState:\tR (running)\n").expect("write the fake status");
    ns::bind_over(&status, &PathBuf::from(format!("/proc/{}/status", std::process::id())));

    super::kill(id).expect("a live foreign kill must not depend on the /proc view");
    let status = child.wait().expect("reap the killed child");
    assert!(!status.success(), "the child must have been killed, got {status:?}");

    let own = super::open_verified(ProcessId::current(), super::PidfdOp::Wait);
    assert!(matches!(own, Ok(Some(_))), "got {own:?}");

    match proc_view() {
        ProcView::Unassessable(why) => {
            assert!(why.reason.contains("self/status could not be read"), "{why}");
            assert_eq!(
                why.source.as_ref().and_then(|e| e.raw_os_error()),
                Some(libc::EXDEV),
                "{why}"
            );
        }
        other => panic!("a status mounted over below /proc must not be read, got {other:?}"),
    }
}

/// A REAL outer procfs: a process that is pid 1 of a new pid namespace, whose `/proc` is still
/// the outer one. Its `NSpid` has two entries, and the pidfd's fdinfo numbers it differently
/// from its own `getpid()`.
///
/// Mutant: "ignore the fdinfo mismatch" — the outer `/proc/1` is the outer init, whose start
/// token differs from this `ProcessId`'s, so `open_verified` answers `Ok(None)` (gone) for a live
/// target.
#[skuld::test]
fn namespaces_an_outer_procfs_is_diverged_and_unassessable(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_pid_ns_outer));
}

#[skuld::test]
fn fixture_pid_ns_outer() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_pid_ns_inner));
}

#[skuld::test]
fn fixture_pid_ns_inner() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    assert_eq!(
        std::process::id(),
        1,
        "the fixture must be pid 1 of its own pid namespace"
    );
    let view = proc_view();
    assert!(matches!(view, ProcView::Diverged), "got {view:?}");

    // `pidfd_open(1)` opens this very process; the outer procfs numbers it differently.
    match super::open_verified(ProcessId::current(), super::PidfdOp::Wait) {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(detail.contains("outer pid namespace"), "{detail}");
            assert!(
                !detail.contains("numbers the target 1 "),
                "the outer procfs must number this process differently from its own pid 1: {detail}"
            );
        }
        other => panic!("the success path under an outer procfs must be Unassessable, got {other:?}"),
    }
}

fn fake_stat(pid: u32) -> String {
    let zeros = ["0"; 18].join(" ");
    format!("{pid} (fake) S {zeros} 999999999999 0 0\n")
}

/// Mount a tmpfs over `/proc` holding a `{pid}/stat` whose start token is not `pid`'s real one:
/// what a `/proc` looked up by PATH would show if it changed after the view was checked.
fn overmount_proc_with_a_foreign_stat(pid: u32) {
    ns::mount_tmpfs(std::path::Path::new("/proc"));
    let dir = PathBuf::from(format!("/proc/{pid}"));
    std::fs::create_dir(&dir).expect("mkdir the fake pid dir");
    std::fs::write(dir.join("stat"), fake_stat(pid)).expect("write the fake stat");
}

/// Bind a file with a foreign start token over `/proc/{pid}/stat` alone, leaving the rest of
/// `/proc` as it was: a mount BELOW `/proc`, which a dirfd on `/proc` still crosses unless every
/// read forbids it.
fn overmount_stat_with_a_foreign_file(pid: u32) {
    let scratch = tempfile::tempdir().expect("tempdir");
    let file = scratch.path().join("stat");
    std::fs::write(&file, fake_stat(pid)).expect("write the fake stat");
    ns::bind_over(&file, &PathBuf::from(format!("/proc/{pid}/stat")));
    // The bind keeps the file alive after the tempdir goes.
    std::mem::forget(scratch);
}

/// A hook that runs `mount` and records that it ran, so a fixture whose hook never fired cannot
/// pass vacuously.
fn recording_hook(mount: impl FnOnce() + 'static) -> (Rc<Cell<bool>>, impl FnOnce() + 'static) {
    let fired = Rc::new(Cell::new(false));
    let flag = Rc::clone(&fired);
    (fired, move || {
        mount();
        flag.set(true);
    })
}

fn assert_by_path_stat_is_fake(pid: u32) {
    let by_path = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read /proc/{pid}/stat by path");
    assert!(
        by_path.contains("(fake)"),
        "the overmount must be visible by path, else the fixture proves nothing: {by_path:?}"
    );
}

fn assert_unassessable_existence(result: Result<Option<rustix::fd::OwnedFd>, Error>) {
    match result {
        Err(Error::Unassessable { detail, .. }) => assert!(detail.contains("existence query"), "{detail}"),
        other => panic!("a stat that cannot be read through the checked dirfd must be Unassessable, got {other:?}"),
    }
}

/// The start-token read goes through the `/proc` dirfd that was checked, not through `/proc`
/// looked up by path again. After the pidfd's fdinfo confirms the mounted `/proc`, a different
/// `/proc` is mounted over it; the read must still see the checked one.
///
/// Mutant: "read `/proc/{pid}/stat` by path" — the fake stat has another start token, so a
/// live target reads as gone (`Ok(None)`).
#[skuld::test]
fn namespaces_the_success_path_reads_through_the_checked_proc_dirfd(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_overmount_success));
}

#[skuld::test]
fn fixture_overmount_success() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    let pid = std::process::id();
    let (fired, hook) = recording_hook(move || overmount_proc_with_a_foreign_stat(pid));
    let _hook = super::fault::between_check_and_read(hook);
    let result = super::open_verified(ProcessId::current(), super::PidfdOp::Wait);
    assert!(fired.get(), "the between-check-and-read hook must have run");
    assert_by_path_stat_is_fake(pid);
    assert!(matches!(result, Ok(Some(_))), "got {result:?}");
}

/// Same for the `EINVAL`/`ENOENT` arm, against a live non-leader tid.
#[skuld::test]
fn namespaces_the_einval_arm_reads_through_the_checked_proc_dirfd(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_overmount_einval));
}

#[skuld::test]
fn fixture_overmount_einval() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    let worker = LiveNonLeaderTid::spawn();
    let tid = worker.id.pid();
    let (fired, hook) = recording_hook(move || overmount_proc_with_a_foreign_stat(tid));
    let _hook = super::fault::between_check_and_read(hook);
    let _errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::NOENT);
    let result = super::open_verified(worker.id, super::PidfdOp::Wait);
    assert!(fired.get(), "the between-check-and-read hook must have run");
    assert_by_path_stat_is_fake(tid);
    match result {
        Err(Error::NotThreadGroupLeader { pid, .. }) => assert_eq!(pid, tid),
        other => panic!("a live non-leader tid must stay NotThreadGroupLeader, got {other:?}"),
    }
}

/// A mount BELOW the checked `/proc`, over the very file that is read: crossing it would hand
/// the fake token to the comparison. The read refuses to cross, and a live target whose stat
/// cannot be read is `Unassessable`, never `Gone`.
///
/// Mutant: "open sub-paths with a plain `openat`" — the fake token is read and a live target
/// reads as gone (`Ok(None)`).
#[skuld::test]
fn namespaces_a_stat_mounted_over_below_proc_is_not_read_on_the_success_path(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_stat_overmount_success));
}

#[skuld::test]
fn fixture_stat_overmount_success() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    let pid = std::process::id();
    let (fired, hook) = recording_hook(move || overmount_stat_with_a_foreign_file(pid));
    let _hook = super::fault::between_check_and_read(hook);
    let result = super::open_verified(ProcessId::current(), super::PidfdOp::Wait);
    assert!(fired.get(), "the between-check-and-read hook must have run");
    assert_by_path_stat_is_fake(pid);
    assert_unassessable_existence(result);
}

/// Same for the `EINVAL`/`ENOENT` arm.
#[skuld::test]
fn namespaces_a_stat_mounted_over_below_proc_is_not_read_on_the_einval_arm(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_stat_overmount_einval));
}

#[skuld::test]
fn fixture_stat_overmount_einval() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    let worker = LiveNonLeaderTid::spawn();
    let tid = worker.id.pid();
    let (fired, hook) = recording_hook(move || overmount_stat_with_a_foreign_file(tid));
    let _hook = super::fault::between_check_and_read(hook);
    let _errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::NOENT);
    let result = super::open_verified(worker.id, super::PidfdOp::Wait);
    assert!(fired.get(), "the between-check-and-read hook must have run");
    assert_by_path_stat_is_fake(tid);
    assert_unassessable_existence(result);
}

/// A tmpfs mounted at `/proc` before the dirfd is opened is not procfs. Mutant: "no `fstatfs`
/// magic check" — the fake `/proc` is trusted and its reads are taken for the kernel's.
#[skuld::test]
fn namespaces_a_tmpfs_at_proc_is_not_procfs(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_tmpfs_at_proc));
}

#[skuld::test]
fn fixture_tmpfs_at_proc() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    let id = ProcessId::current();
    ns::mount_tmpfs(std::path::Path::new("/proc"));
    let opened = ProcDir::open();
    assert!(
        matches!(&opened, Err(why) if why.reason.contains("not procfs")),
        "got {opened:?}"
    );
    match proc_view() {
        ProcView::Unassessable(why) => assert!(why.reason.contains("not procfs"), "{why}"),
        other => panic!("a tmpfs at /proc must be Unassessable, got {other:?}"),
    }
    match super::open_verified(id, super::PidfdOp::Wait) {
        Err(Error::Unassessable { detail, .. }) => assert!(detail.contains("not procfs"), "{detail}"),
        other => panic!("a tmpfs at /proc must be Unassessable, got {other:?}"),
    }
}

/// A procfs subtree bound over `/proc` has procfs's magic but is not its root. Mutant: "check
/// the magic but not the root inode".
#[skuld::test]
fn namespaces_a_procfs_subtree_bound_over_proc_is_not_the_procfs_root(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_subtree_at_proc));
}

#[skuld::test]
fn fixture_subtree_at_proc() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    ns::bind_over(std::path::Path::new("/proc/sys"), std::path::Path::new("/proc"));
    let opened = ProcDir::open();
    assert!(
        matches!(&opened, Err(why) if why.reason.contains("not the root of procfs")),
        "got {opened:?}"
    );
}
