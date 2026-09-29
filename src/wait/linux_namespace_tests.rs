//! `open_verified` against REAL namespace layouts, in re-exec'd children that own private
//! mount or pid namespaces (see `test_child::namespaces` for the group's gating).

use std::path::PathBuf;

use super::linux_tests::LiveNonLeaderTid;
use crate::error::Error;
use crate::identity::{proc_view, ProcView, ProcessId};
use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;

const NO_NSPID_MARKER: &str = "COSCA_FIXTURE_STATUS_WITHOUT_NSPID";
const OUTER_MARKER: &str = "COSCA_FIXTURE_PID_NS_OUTER";
const INNER_MARKER: &str = "COSCA_FIXTURE_PID_NS_INNER";

/// A kernel whose `self/status` has no `NS*` lines (no `CONFIG_PID_NS`; gVisor) must not break a
/// live foreign wait or kill: the success path proves its target through the pidfd's fdinfo, not
/// `NSpid`. Reproduced by bind-mounting an `NS*`-less status file over `/proc/<pid>/status`.
///
/// Mutant: "the success path requires a `Same` `proc_view()`" — every live `open_verified` is
/// then `Unassessable`.
#[test]
fn namespaces_a_status_file_without_nspid_keeps_live_foreign_kills_working() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_status_file_without_nspid), NO_NSPID_MARKER);
}

#[test]
fn fixture_status_file_without_nspid() {
    if !ns::is_child(NO_NSPID_MARKER) {
        return;
    }
    ns::enter_private_mount_ns();
    let scratch = tempfile::tempdir().expect("tempdir");
    let status = scratch.path().join("status");
    std::fs::write(&status, "Name:\tcosca\nState:\tR (running)\n").expect("write the NS*-less status");
    ns::bind_over(&status, &PathBuf::from(format!("/proc/{}/status", std::process::id())));

    // A live foreign process: killed through `kill`, which goes through `open_verified`.
    let mut child = {
        let _guard = crate::child::spawn::spawn_lock();
        std::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("spawn cat")
    };
    let id = ProcessId::of(child.id())
        .found()
        .expect("the live child has an identity");
    super::kill(id).expect("a live foreign kill must work without NSpid");
    let status = child.wait().expect("reap the killed child");
    assert!(!status.success(), "the child must have been killed, got {status:?}");

    let own = super::open_verified(ProcessId::current(), "test probe");
    assert!(matches!(own, Ok(Some(_))), "got {own:?}");

    // Without a pidfd `NSpid` is all there is to go on. This kernel has pid namespaces
    // (`self/ns/pid` exists), so an absent `NSpid` cannot be told from gVisor's: `Unassessable`.
    match proc_view() {
        ProcView::Unassessable(why) => assert!(why.reason.contains("NSpid"), "{why}"),
        other => panic!("NSpid absent with pid namespaces present must be Unassessable, got {other:?}"),
    }

    // Hide `self/ns/pid` too: now the kernel has no pid namespaces to diverge into.
    let empty = scratch.path().join("empty-ns");
    std::fs::create_dir(&empty).expect("mkdir");
    ns::bind_over(&empty, &PathBuf::from(format!("/proc/{}/ns", std::process::id())));
    match proc_view() {
        ProcView::Same(_) => {}
        other => panic!("no NSpid and no self/ns/pid is Same, got {other:?}"),
    }
}

/// A REAL outer procfs: a process that is pid 1 of a new pid namespace, whose `/proc` is still
/// the outer one. Its `NSpid` has two entries, and the pidfd's fdinfo numbers it differently
/// from its own `getpid()`.
///
/// Mutant: "ignore the fdinfo mismatch" — the outer `/proc/1` is init, whose token equals this
/// `ProcessId`'s, so `open_verified` answers `Ok(Some(pidfd))`.
#[test]
fn namespaces_an_outer_procfs_is_diverged_and_unassessable() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_pid_ns_outer), OUTER_MARKER);
}

#[test]
fn fixture_pid_ns_outer() {
    if !ns::is_child(OUTER_MARKER) {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_pid_ns_inner), INNER_MARKER);
}

#[test]
fn fixture_pid_ns_inner() {
    if !ns::is_child(INNER_MARKER) {
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
    match super::open_verified(ProcessId::current(), "test probe") {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(detail.contains("outer pid namespace"), "{detail}");
        }
        other => panic!("the success path under an outer procfs must be Unassessable, got {other:?}"),
    }
}

const OVERMOUNT_SUCCESS_MARKER: &str = "COSCA_FIXTURE_OVERMOUNT_SUCCESS";
const OVERMOUNT_EINVAL_MARKER: &str = "COSCA_FIXTURE_OVERMOUNT_EINVAL";

/// Mount a tmpfs over `/proc` holding a `{pid}/stat` whose start token is not `pid`'s real one:
/// what a `/proc` looked up by PATH would show if it changed after the view was checked.
fn overmount_proc_with_a_foreign_stat(pid: u32) {
    ns::mount_tmpfs(std::path::Path::new("/proc"));
    let dir = PathBuf::from(format!("/proc/{pid}"));
    std::fs::create_dir(&dir).expect("mkdir the fake pid dir");
    let zeros = ["0"; 18].join(" ");
    std::fs::write(dir.join("stat"), format!("{pid} (fake) S {zeros} 999999999999 0 0\n"))
        .expect("write the fake stat");
}

/// The start-token read goes through the `/proc` dirfd that was checked, not through `/proc`
/// looked up by path again. After the pidfd's fdinfo confirms the mounted `/proc`, a different
/// `/proc` is mounted over it; the read must still see the checked one.
///
/// Mutant: "read `/proc/{pid}/stat` by path" — the fake stat has another start token, so a
/// live target reads as gone (`Ok(None)`).
#[test]
fn namespaces_the_success_path_reads_through_the_checked_proc_dirfd() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_overmount_success), OVERMOUNT_SUCCESS_MARKER);
}

#[test]
fn fixture_overmount_success() {
    if !ns::is_child(OVERMOUNT_SUCCESS_MARKER) {
        return;
    }
    ns::enter_private_mount_ns();
    let pid = std::process::id();
    let _hook = super::fault::between_check_and_read(move || overmount_proc_with_a_foreign_stat(pid));
    let result = super::open_verified(ProcessId::current(), "overmount probe");
    assert!(matches!(result, Ok(Some(_))), "got {result:?}");
}

/// Same for the `EINVAL`/`ENOENT` arm, against a live non-leader tid.
#[test]
fn namespaces_the_einval_arm_reads_through_the_checked_proc_dirfd() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_overmount_einval), OVERMOUNT_EINVAL_MARKER);
}

#[test]
fn fixture_overmount_einval() {
    if !ns::is_child(OVERMOUNT_EINVAL_MARKER) {
        return;
    }
    ns::enter_private_mount_ns();
    let worker = LiveNonLeaderTid::spawn();
    let tid = worker.id.pid();
    let _hook = super::fault::between_check_and_read(move || overmount_proc_with_a_foreign_stat(tid));
    let _errno = super::fault::force_pidfd_open_errno_once(rustix::io::Errno::NOENT);
    let result = super::open_verified(worker.id, "overmount probe");
    match result {
        Err(Error::NotThreadGroupLeader { pid, .. }) => assert_eq!(pid, tid),
        other => panic!("a live non-leader tid must stay NotThreadGroupLeader, got {other:?}"),
    }
}
