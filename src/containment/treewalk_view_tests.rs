//! A tree walk whose `/proc` view cannot be trusted errors instead of walking an empty snapshot,
//! and never walks from a root that no longer holds its pid. Every read a walk makes, the
//! per-pid ones included, goes through the kernel it is given. Linux only: the view is a
//! [`FakeKernel`]'s `self/status` row.
//!
//! A live root must come out of every failing walk unsignalled: [`release`] proves it by its exit
//! status.

use crate::child::front_cgroup_tests::pidfd_of;
use crate::error::Error;
use crate::identity::{
    ticks_host, ticks_id, unreadable, FakeKernel, HostKernel, Kernel, Key, ProcessId, UNREADABLE_STATUS_REASON,
};
use crate::test_child::{
    live_exiting_member as live_member, open_live, release_unsignalled as release, stat_of_a_new_owner,
};
use crate::test_groups::{pidfd_group_signal, Group};
use crate::Recursive;

use super::treewalk_pidfs_tests::{children_of, descendants};

/// An identity for this process's pid that this process no longer holds: its children are the
/// children of the pid's new owner.
fn stale_root() -> ProcessId {
    let me = ProcessId::current();
    me.with_other_value()
}

fn assert_unassessable_naming(result: Result<(), Error>, causes: &[&str]) {
    match result {
        Err(Error::Unassessable { detail, .. }) => {
            for cause in causes {
                assert!(detail.contains(cause), "the error must name {cause:?}: {detail}");
            }
        }
        other => panic!("expected Unassessable naming {causes:?}, got {other:?}"),
    }
}

/// How a view fails, and what its error names.
#[derive(Clone, Copy)]
enum View {
    Diverged,
    Unreadable,
}

impl View {
    /// `kernel` whose `self/status` reads fail this way from the read that follows `earlier` reads.
    fn fail<'a>(self, kernel: FakeKernel<'a>, earlier: usize) -> FakeKernel<'a> {
        match self {
            View::Diverged => kernel.diverged_view_after(earlier),
            View::Unreadable => kernel.unreadable_view_after(earlier),
        }
    }

    fn cause(self) -> &'static str {
        match self {
            View::Diverged => "outer pid namespace",
            View::Unreadable => UNREADABLE_STATUS_REASON,
        }
    }
}

const VIEWS: [View; 2] = [View::Diverged, View::Unreadable];

type Walk = fn(&dyn Kernel, ProcessId) -> Result<(), Error>;

/// The walks that take an identity.
fn id_walks() -> [(&'static str, Walk); 2] {
    [
        ("hard_kill", |k, id| super::hard_kill(k, id).map(|_| ())),
        ("terminate", |k, id| super::terminate(k, id)),
    ]
}

/// Every walk, `Process`'s included, over an open handle on the live `id`.
fn walks() -> [(&'static str, Walk); 4] {
    [
        ("hard_kill", |k, id| super::hard_kill(k, id).map(|_| ())),
        ("terminate", |k, id| super::terminate(k, id)),
        ("kill_tree", |k, id| open_live(id).kill_tree_with(k)),
        ("terminate_tree", |k, id| open_live(id).terminate_tree_with(k)),
    ]
}

// An untrusted view =====

/// Mutant: "`process_parents` yields an empty snapshot when the view is not `Same`", or "signal
/// the root, then return the error": the walk reports success, or kills the root.
#[skuld::test]
fn every_walk_over_an_untrusted_view_errors_and_signals_nothing() {
    for (name, walk) in walks() {
        for view in VIEWS {
            let (child, id) = live_member();
            let kernel = view.fail(FakeKernel::over(&HostKernel), 0);
            let result = walk(&kernel, id);
            assert!(
                matches!(&result, Err(Error::Unassessable { detail, .. }) if detail.contains(view.cause())),
                "{name}: {result:?}"
            );
            release(child);
        }
    }
}

// The snapshot precedes the anchor =====

type Query = fn(&ProcessId, &dyn Kernel) -> Result<(), Error>;

fn queries() -> [(&'static str, Query); 3] {
    [
        ("parent", |p, k| p.parent_with(k).map(|_| ())),
        ("children(No)", |p, k| p.children_with(k, Recursive::No).map(|_| ())),
        ("children(Yes)", |p, k| p.children_with(k, Recursive::Yes).map(|_| ())),
    ]
}

/// The snapshot is the first view read, so the anchor that follows it vouches for the pid across
/// the whole snapshot. Mutant: "the anchor is checked before the snapshot" - the failing view lands
/// on the anchor and the error blames the wrong read.
#[skuld::test]
fn parent_and_children_take_the_snapshot_before_the_anchor() {
    let me = ProcessId::current();
    for (_, query) in queries() {
        for view in VIEWS {
            let kernel = view.fail(FakeKernel::over(&HostKernel), 0);
            let result = query(&me, &kernel);
            assert_unassessable_naming(result, &["the process snapshot could not be taken", view.cause()]);
        }
    }
}

/// The anchor failing after a good snapshot names the view that failed it (the one the failing read
/// used, not a second look), and the pid. Mutants: "`unqueryable` re-derives the cause" (the view
/// has recovered by then, so the error blames access); "the table read's error is dropped".
#[skuld::test]
fn an_anchor_read_that_fails_names_the_view_that_failed_it() {
    // The `/proc` path: only a `starttime` anchor is read through the view.
    let me = ticks_id(std::process::id());
    let pid = me.pid();
    for (_, query) in queries() {
        for view in VIEWS {
            let kernel = view.fail(ticks_host(pid).same_view(), 1);
            let result = query(&me, &kernel);
            assert_unassessable_naming(
                result,
                &[&format!("pid {pid} identity could not be read"), view.cause()],
            );
        }
    }
}

// The anchor guards the walk =====

/// A root that no longer holds its pid has no descendants: its pid's new owner's children are not
/// its own, and are never signalled. Mutant: "walk without an anchor". A stale identity cannot be
/// opened, so only the identity-level walks run.
#[skuld::test]
fn every_walk_from_a_root_that_lost_its_pid_is_ok_and_signals_nothing() {
    for (name, walk) in id_walks() {
        let (child, _) = live_member();
        let result = walk(&HostKernel, stale_root());
        assert!(result.is_ok(), "{name}: {result:?}");
        release(child);
    }
}

/// A root whose pid cannot be queried is an error naming the pid and the view, with nothing
/// signalled. Mutants: "an unqueryable root is treated as gone"; "the anchor is skipped".
#[skuld::test]
fn every_walk_from_a_root_that_cannot_be_queried_errors_and_signals_nothing() {
    for (_, walk) in walks() {
        let (child, id) = live_member();
        let kernel = View::Unreadable.fail(FakeKernel::over(&HostKernel).same_view(), 1);
        let result = walk(&kernel, id);
        assert_unassessable_naming(
            result,
            &[
                &format!("pid {} identity could not be read", id.pid()),
                UNREADABLE_STATUS_REASON,
            ],
        );
        release(child);
    }
}

// A live process missing from the table =====

/// This process is live, so a table without it is not "no parent" / "no children": the entry was
/// omitted, not the process gone. `EACCES` on the scan's read of `self` makes it skip this pid; the
/// anchor's read after it succeeds. Mutant: "a `self` missing from the table is `Ok(None)` /
/// `Ok(vec![])`".
#[skuld::test]
fn a_live_self_missing_from_the_table_is_unassessable() {
    let me = ProcessId::current();
    let stat = std::fs::read("/proc/self/stat").expect("this process's stat");
    let path = format!("{}/stat", me.pid());
    for (_, query) in queries() {
        let kernel =
            FakeKernel::listing_unreadable_pid(&HostKernel, me.pid(), libc::EACCES).on_read_after(&path, 1, Ok(&stat));
        assert_unassessable_naming(query(&me, &kernel), &[&format!("pid {} is live but absent", me.pid())]);
    }
}

// The per-pid reads go through the walk's kernel =====

/// A pid the kernel refuses to read is dropped from the walk and warned about, as a pid it cannot
/// find would be. Mutant: "`resolve_or_drop` resolves through `HostKernel`".
#[skuld::test]
fn a_pid_the_kernel_cannot_read_is_dropped_and_warned_about() {
    crate::log_capture::install();
    let (child, id) = live_member();
    let (kernel, _guard) = unreadable(id.pid());
    let mark = crate::log_capture::mark();
    assert!(super::resolve_or_drop(&kernel, id.pid(), ProcessId::current()).is_err());
    let warned = crate::log_capture::records_since_on_current_thread(
        mark,
        &format!("pid {} exists but could not be queried", id.pid()),
    );
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert_eq!(warned[0].0, log::Level::Warn);
    release(child);
}

/// The warn names why the read failed when the read knows, so an unreadable view is not reported as
/// access. The candidate's own read fails with the view, and its parent is held, so the warn names
/// the candidate and its cause.
/// Mutants: "`resolve_or_drop` drops the cause": the warn says "access denied?"; "a held parent's
/// proof blames the parent": the warn names `ppid`.
#[skuld::test]
fn the_warn_for_a_dropped_pid_names_the_cause_of_its_own_read_under_a_held_parent() {
    crate::log_capture::install();
    let (child, id) = live_member();
    let me = ProcessId::current();
    let parent = ProcessId::from_parts_for_test(me.pid(), Key::Pidfs(9));
    let kernel = View::Unreadable.fail(
        FakeKernel::over(&HostKernel)
            .on_pidfd_open(me.pid(), Ok(pidfd_of(me.pid())))
            .on_pidfs_ino(me.pid(), Ok(Some(9))),
        0,
    );
    let mark = crate::log_capture::mark();
    assert!(super::resolve_or_drop(&kernel, id.pid(), parent).is_err());
    let warned = crate::log_capture::records_since_on_current_thread(
        mark,
        &format!("pid {} identity could not be read", id.pid()),
    );
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].1.contains(View::Unreadable.cause()), "{warned:?}");
    assert!(!warned[0].1.contains("access denied?"), "{warned:?}");
    assert!(!warned[0].1.contains("ppid"), "{warned:?}");
    assert!(
        !warned[0].1.contains(&format!("pid {} dropped", id.pid())),
        "{warned:?}"
    );
    release(child);
}

/// The view fails every read, the parent's proof too (a `Ticks` id is proved by its `stat`), so the
/// warn blames the parent and names the dropped candidate after it. Mutants: "`resolve_or_drop`
/// drops the cause"; "`resolve_or_drop` does not name the dropped candidate": no `pid N dropped`.
#[skuld::test]
fn the_warn_for_a_dropped_pid_names_the_cause_of_its_parents_proof() {
    crate::log_capture::install();
    let (child, id) = live_member();
    let me = ProcessId::current();
    let parent = ticks_id(me.pid());
    let kernel = View::Unreadable.fail(FakeKernel::over(&HostKernel), 0);
    let mark = crate::log_capture::mark();
    assert!(super::resolve_or_drop(&kernel, id.pid(), parent).is_err());
    let warned = crate::log_capture::records_since_on_current_thread(
        mark,
        &format!("ppid {} identity could not be read", me.pid()),
    );
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].1.contains(View::Unreadable.cause()), "{warned:?}");
    assert!(!warned[0].1.contains("access denied?"), "{warned:?}");
    assert!(warned[0].1.contains(&format!("pid {} dropped", id.pid())), "{warned:?}");
    release(child);
}

/// Mutants: "`descendants` resolves through `HostKernel`", "`children_of` resolves through
/// `HostKernel`": the unreadable child is found.
#[skuld::test]
fn descendants_and_children_the_kernel_cannot_read_are_dropped() {
    let (child, id) = live_member();
    let me = ProcessId::current();
    // `me` has a row, as a live root does in a snapshot.
    let parents = [(me.pid(), 1), (id.pid(), me.pid())];
    let (kernel, _guard) = unreadable(id.pid());
    assert!(descendants(&kernel, me, &parents)
        .expect("a readable anchor")
        .is_empty());
    assert!(children_of(&kernel, me, &parents)
        .expect("a readable anchor")
        .is_empty());
    release(child);
}

/// A kill re-verifies through the kernel: a pid it cannot read is not signalled and counts as
/// not attempted; one it shows with another start time is already gone. The member's own pidfd
/// passes the proof's fdinfo check, so the `stat` is what the row is about. Mutants:
/// "`kill_by_identity` re-verifies through `HostKernel`": the member is signalled; "the re-verify
/// ignores the start time": `Terminated` for the new owner.
#[skuld::test]
fn kill_by_identity_spares_a_pid_the_kernel_cannot_read_or_shows_as_another_process() {
    let (child, id) = live_member();
    // The `/proc` path: a `starttime` id is re-verified by its `stat`.
    let id = ticks_id(id.pid());
    let pid = id.pid();
    let unreadable_kernel = FakeKernel::over(&HostKernel)
        .live_without_pidfs(pid, pidfd_of(pid))
        .on_read(&format!("{pid}/stat"), Err(libc::EACCES));
    assert_eq!(
        super::kill_by_identity(&unreadable_kernel, id, nix::sys::signal::Signal::SIGTERM),
        super::KillOutcome::NotAttempted
    );
    let new_owner = FakeKernel::over(&HostKernel)
        .live_without_pidfs(pid, pidfd_of(pid))
        .on_read(&format!("{pid}/stat"), Ok(&stat_of_a_new_owner(pid)));
    assert_eq!(
        super::kill_by_identity(&new_owner, id, nix::sys::signal::Signal::SIGTERM),
        super::KillOutcome::AlreadyGone
    );
    release(child);
}

/// The same re-verify of a `pidfs` id asks the kernel's pidfd: a pid it cannot open is not
/// signalled and counts as not attempted; one it opens to another inode is already gone.
#[skuld::test]
fn kill_by_identity_spares_a_pidfs_pid_the_kernel_cannot_open_or_shows_as_another_process(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    let (child, id) = live_member();
    let pid = id.pid();
    let ino = id.pidfs_ino().expect("a pidfs host makes pidfs ids");
    let refusing = FakeKernel::over(&HostKernel).on_pidfd_open(pid, Err(rustix::io::Errno::MFILE));
    assert_eq!(
        super::kill_by_identity(&refusing, id, nix::sys::signal::Signal::SIGTERM),
        super::KillOutcome::NotAttempted
    );
    let new_owner = FakeKernel::over(&HostKernel).on_pidfs_ino(pid, Ok(Some(ino + 1)));
    assert_eq!(
        super::kill_by_identity(&new_owner, id, nix::sys::signal::Signal::SIGTERM),
        super::KillOutcome::AlreadyGone
    );
    release(child);
}

/// The root's `stat` is read three times: by the snapshot, by the anchor, and by the kill's
/// re-verify, which finds another start time. Nothing is signalled. The root's own pidfd passes the
/// proof's fdinfo check, so the `stat` is what the row is about. Mutants: "the walk's kill
/// re-verifies through `HostKernel`"; "the kill ignores a start time that differs".
#[skuld::test]
fn every_walk_re_verifies_its_kill_through_its_kernel() {
    for (name, walk) in walks() {
        let (child, id) = live_member();
        // The `/proc` path, as above.
        let id = ticks_id(id.pid());
        let kernel = FakeKernel::over(&HostKernel)
            .live_without_pidfs(id.pid(), pidfd_of(id.pid()))
            .on_read_after(&format!("{}/stat", id.pid()), 2, Ok(&stat_of_a_new_owner(id.pid())));
        let result = walk(&kernel, id);
        assert!(result.is_ok(), "{name}: {result:?}");
        release(child);
    }
}

// A descendant's reads go through the walk's kernel =====

/// A live root `sh` that has announced its pid, its identity, and the identity of the `sh` it
/// forked. That descendant prints `released` and exits at the EOF of its stdin, which the test
/// holds the write end of; the root waits for it.
fn live_member_with_descendant() -> (std::process::Child, ProcessId, ProcessId) {
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("exec 3<&0; sh -c 'read _ignored; echo released' <&3 3<&- & echo $$; wait")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the root");
    crate::test_child::await_member_ready(&mut child);
    let root = ProcessId::of(child.id()).found().expect("the live root resolves");
    let descendants = root
        .children_with(&HostKernel, Recursive::No)
        .expect("the root's children are readable");
    let [descendant] = descendants[..] else {
        panic!("the root has exactly one child, got {descendants:?}");
    };
    (child, root, descendant)
}

/// The root was signalled with `signo` and the descendant was not: released by EOF, it still
/// prints. A signalled descendant has nothing to print, and the read ends at EOF without it.
fn release_with_a_signalled_root(who: &str, mut child: std::process::Child, signo: i32) {
    use std::io::Read as _;
    use std::os::unix::process::ExitStatusExt as _;
    drop(child.stdin.take());
    let mut printed = String::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_string(&mut printed)
        .expect("read to EOF");
    assert_eq!(
        printed, "released\n",
        "{who}: the descendant must not have been signalled"
    );
    let status = child.wait().expect("reap the root");
    assert_eq!(
        status.signal(),
        Some(signo),
        "{who}: the walk must have signalled the root"
    );
}

/// The descendant's `stat` is read by the snapshot, then by the walk's resolve of it, then by the
/// kill's re-verify, which the kernel refuses or shows as another start time. Only the root is
/// signalled. Each member's own pidfd passes the proof's fdinfo check, so the `stat` is what the
/// row is about. Mutants: "`descendants` resolves through `HostKernel`" (the re-verify becomes the
/// second read, which the row lets through), "the descendant loop's kill re-verifies through
/// `HostKernel`", "the kill ignores a start time that differs", each in `hard_kill` and in
/// `terminate`: the descendant is signalled.
#[skuld::test]
fn every_id_walk_re_verifies_a_descendants_kill_through_its_kernel() {
    for ((name, walk), signo) in id_walks().into_iter().zip([libc::SIGKILL, libc::SIGTERM]) {
        for shows_a_new_owner in [false, true] {
            let (child, root, descendant) = live_member_with_descendant();
            // The `/proc` path: the walk's ids are `starttime` ids.
            let root = ticks_id(root.pid());
            let new_owner = stat_of_a_new_owner(descendant.pid());
            let answer = if shows_a_new_owner {
                Ok(new_owner.as_slice())
            } else {
                Err(libc::EACCES)
            };
            let kernel = FakeKernel::over(&HostKernel)
                .live_without_pidfs(root.pid(), pidfd_of(root.pid()))
                .live_without_pidfs(descendant.pid(), pidfd_of(descendant.pid()))
                .on_read_after(&format!("{}/stat", descendant.pid()), 2, answer);
            let result = walk(&kernel, root);
            assert!(result.is_ok(), "{name}, new owner {shows_a_new_owner}: {result:?}");
            release_with_a_signalled_root(name, child, signo);
        }
    }
}

/// A live root with one live descendant, and a kernel in which the descendant's identity cannot be
/// read (`EMFILE` on its pidfd). The `/proc` path: the root's id is a `starttime` id.
fn root_with_an_unreadable_descendant() -> (std::process::Child, ProcessId, ProcessId, FakeKernel<'static>) {
    let (child, root, descendant) = live_member_with_descendant();
    let root = ticks_id(root.pid());
    let kernel = FakeKernel::over(&HostKernel)
        .live_without_pidfs(root.pid(), pidfd_of(root.pid()))
        .on_pidfd_open(descendant.pid(), Err(rustix::io::Errno::MFILE));
    (child, root, descendant, kernel)
}

/// A descendant the walk cannot read is not signalled, and `hard_kill` says it did not reach every
/// member (`Ok(false)`), so its caller does not mark the tree killed. `terminate` is best effort and
/// stays `Ok`. Mutants: "an `Unknown` read is dropped as `Gone`": `Ok(true)`; "`terminate` reports
/// the incomplete walk".
#[skuld::test]
fn a_descendant_that_cannot_be_read_makes_hard_kill_incomplete_and_leaves_terminate_ok() {
    let (child, root, _, kernel) = root_with_an_unreadable_descendant();
    assert!(!super::hard_kill(&kernel, root).expect("the walk ran"));
    release_with_a_signalled_root("hard_kill", child, libc::SIGKILL);

    let (child, root, _, kernel) = root_with_an_unreadable_descendant();
    super::terminate(&kernel, root).expect("best effort");
    release_with_a_signalled_root("terminate", child, libc::SIGTERM);
}

/// `children` of a root with a descendant the walk cannot read is an error naming that pid and why,
/// never the short list. Mutant: "`children` takes the members and ignores `unassessed`".
#[skuld::test]
fn children_of_a_root_with_a_descendant_that_cannot_be_read_is_an_error_naming_it() {
    for recursive in [Recursive::No, Recursive::Yes] {
        let (child, root, descendant, kernel) = root_with_an_unreadable_descendant();
        assert_unassessable_naming(
            root.children_with(&kernel, recursive).map(|_| ()),
            &[&format!("pid {} identity could not be read", descendant.pid())],
        );
        release(child);
    }
}

/// The candidate's own `stat` names its parent, and the walk accepts it only under the parent the
/// snapshot gave it: a pid that exited and was reused since the snapshot, by a process of another
/// parent, is dropped. Mutants: "the resolver ignores the parent", "the resolver always drops".
#[skuld::test]
fn a_candidate_whose_stat_shows_another_parent_is_dropped() {
    const PID: u32 = 4242;
    use crate::identity::Key;

    let stat = crate::identity::stat_parse::stat_fixture("S", 777);
    let kernel = ticks_host(PID)
        .same_view()
        .on_read(&format!("{PID}/stat"), Ok(&stat))
        .on_read("1/stat", Ok(&crate::identity::stat_parse::stat_fixture("S", 5)));
    let parent = |pid| ProcessId::from_parts_for_test(pid, Key::for_test(5));
    // `stat_fixture` shows parent 1.
    assert_eq!(super::resolve_or_drop(&kernel, PID, parent(99)).expect("a read"), None);
    assert!(super::resolve_or_drop(&kernel, PID, parent(1))
        .expect("a read")
        .is_some());
}
