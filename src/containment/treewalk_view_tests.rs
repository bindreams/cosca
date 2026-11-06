//! A tree walk whose `/proc` view cannot be trusted errors instead of walking an empty snapshot,
//! and never walks from a root that no longer holds its pid. Every read a walk makes, the
//! per-pid ones included, goes through the kernel it is given. Linux only: the view is a
//! [`FakeKernel`]'s `self/status` row.
//!
//! A live root must come out of every failing walk unsignalled: [`release`] proves it by its exit
//! status.

use crate::child::front_cgroup_tests::pidfd_of;
use crate::containment::dispatch::Unkilled;
use crate::error::Error;
use crate::identity::{
    ticks_host, ticks_id, unreadable, FakeKernel, HostKernel, Kernel, Key, ProcessId, Unread, UNREADABLE_STATUS_REASON,
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

/// `result` is the error of a walk that left `pid` unkilled because its identity could not be read
/// ([`Error::Unassessable`]), and its message says each of `causes`.
#[track_caller]
fn assert_not_killed(result: Result<(), Error>, pid: u32, causes: &[&str]) {
    match result {
        Err(Error::MemberNotKilled { pid: named, source, .. }) => {
            assert_eq!(named, pid, "the first member left behind");
            assert!(matches!(*source, Error::Unassessable { .. }), "{source:?}");
            let said = source.to_string();
            for cause in causes {
                assert!(said.contains(cause), "the error must name {cause:?}: {said}");
            }
        }
        other => panic!("expected MemberNotKilled for pid {pid} naming {causes:?}, got {other:?}"),
    }
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
        ("hard_kill", |k, id| {
            super::hard_kill(k, id).map_err(Unkilled::into_error)
        }),
        ("terminate", |k, id| super::terminate(k, id)),
    ]
}

/// Every walk, `Process`'s included, over an open handle on the live `id`.
fn walks() -> [(&'static str, Walk); 4] {
    [
        ("hard_kill", |k, id| {
            super::hard_kill(k, id).map_err(Unkilled::into_error)
        }),
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

/// The queries that take the process snapshot. `parent` does not: it reads `self` alone.
fn children_queries() -> [(&'static str, Query); 2] {
    [
        ("children(No)", |p, k| p.children_with(k, Recursive::No).map(|_| ())),
        ("children(Yes)", |p, k| p.children_with(k, Recursive::Yes).map(|_| ())),
    ]
}

/// The snapshot is the first view read, so the anchor that follows it vouches for the pid across
/// the whole snapshot. Mutant: "the anchor is checked before the snapshot" - the failing view lands
/// on the anchor and the error blames the wrong read.
#[skuld::test]
fn children_take_the_snapshot_before_the_anchor() {
    let me = ProcessId::current();
    for (_, query) in children_queries() {
        for view in VIEWS {
            let kernel = view.fail(FakeKernel::over(&HostKernel), 0);
            let result = query(&me, &kernel);
            assert_unassessable_naming(result, &["the process snapshot could not be taken", view.cause()]);
        }
    }
}

/// The anchor failing after a good snapshot names the view that failed it (the one the failing read
/// used, not a second look), and the pid. `parent` reads no snapshot: its first view read is the
/// anchor's. Mutants: "`unqueryable` re-derives the cause" (the view has recovered by then, so the
/// error blames access); "the table read's error is dropped".
#[skuld::test]
fn an_anchor_read_that_fails_names_the_view_that_failed_it() {
    // The `/proc` path: only a `starttime` anchor is read through the view.
    let me = ticks_id(std::process::id());
    let pid = me.pid();
    let parent: (&str, Query) = ("parent", |p, k| p.parent_with(k).map(|_| ()));
    let queries = std::iter::once((parent, 0)).chain(children_queries().map(|query| (query, 1)));
    for ((_, query), snapshot_reads) in queries {
        for view in VIEWS {
            let kernel = view.fail(ticks_host(pid).same_view(), snapshot_reads);
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
/// signalled. Mutants: "an unqueryable root is treated as gone"; "the anchor is skipped". The
/// `/proc` path: only a `starttime` id is proved through the view; a `pidfs` id is proved by its
/// pidfd, in `treewalk_pidfs_tests`.
#[skuld::test]
fn every_walk_from_a_root_that_cannot_be_queried_errors_and_signals_nothing() {
    for (_, walk) in walks() {
        let (child, host_id) = live_member();
        let id = ticks_id(host_id.pid());
        let kernel = View::Unreadable.fail(
            FakeKernel::over(&HostKernel)
                .live_without_pidfs(id.pid(), pidfd_of(id.pid()))
                .same_view(),
            1,
        );
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

// A live root missing from the table =====

/// A live root with no row in the table has its children walked and killed: the walk reads only the
/// rows that name the root as their parent, and the root's own row says nothing about them. The
/// table lists the descendant alone, so the walk reaches no other host process. Mutant: "a root
/// absent from the table is `Unassessable`, or walks nothing" (`hard_kill` then leaves the
/// descendant, and the root, running).
#[skuld::test]
fn a_live_root_missing_from_the_table_still_has_its_descendant_walked_and_killed() {
    use std::os::unix::process::ExitStatusExt as _;
    let (mut child, root, descendant) = live_member_with_descendant();
    // The `/proc` path: the walk's ids are `starttime` ids.
    let root = ticks_id(root.pid());
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_pids(Ok(&[descendant.pid()]))
        .live_without_pidfs(root.pid(), pidfd_of(root.pid()))
        .live_without_pidfs(descendant.pid(), pidfd_of(descendant.pid()));
    for recursive in [Recursive::No, Recursive::Yes] {
        let members = root.children_with(&kernel, recursive).expect("the root's children");
        let pids: Vec<u32> = members.iter().map(ProcessId::pid).collect();
        assert_eq!(pids, [descendant.pid()], "{recursive:?}");
    }
    super::hard_kill(&kernel, root).expect("the walk ran");
    // Both were killed: the root by its signal, the descendant before it could print.
    let mut printed = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take().expect("piped stdout"), &mut printed).expect("read to EOF");
    assert_eq!(printed, "", "the descendant must have been killed");
    assert_eq!(child.wait().expect("reap the root").signal(), Some(libc::SIGKILL));
}

// The per-pid reads go through the walk's kernel =====

/// A pid the kernel refuses to read is an error, as a pid it cannot find would not be, and the walk
/// itself says nothing of it: its caller reports it, once. Mutant: "`resolve_or_drop` resolves
/// through `HostKernel`"; "`resolve_or_drop` warns" (the first member left behind is then reported
/// twice, by the walk and by the error that names it).
#[skuld::test]
fn a_pid_the_kernel_cannot_read_is_an_error_the_walk_does_not_warn_of() {
    crate::log_capture::install();
    let (child, id) = live_member();
    let (kernel, _guard) = unreadable(id.pid());
    let mark = crate::log_capture::mark();
    let Err(Unread {
        why: Error::Unassessable { detail, .. },
        ..
    }) = super::resolve_or_drop(&kernel, id.pid(), ProcessId::current(), None)
    else {
        panic!("an unreadable pid is Unassessable");
    };
    assert!(
        detail.contains(&format!("pid {} exists but could not be queried", id.pid())),
        "{detail}"
    );
    let warned = crate::log_capture::records_since_on_current_thread(mark, "treewalk:");
    assert_eq!(warned, [], "the walk's caller reports the member");
    release(child);
}

/// The error names why the read failed when the read knows, so an unreadable view is not reported as
/// access. The candidate's own read fails with the view, and its parent is held, so the error names
/// the candidate and its cause.
/// Mutants: "`resolve_or_drop` drops the cause": the error says "access denied?"; "a held parent's
/// proof blames the parent": the error names `ppid`.
#[skuld::test]
fn the_error_for_a_dropped_pid_names_the_cause_of_its_own_read_under_a_held_parent() {
    let (child, id) = live_member();
    let me = ProcessId::current();
    let parent = ProcessId::from_parts_for_test(me.pid(), Key::Pidfs(9));
    let kernel = View::Unreadable.fail(
        FakeKernel::over(&HostKernel)
            .on_pidfd_open(me.pid(), Ok(pidfd_of(me.pid())))
            .on_pidfs_ino(me.pid(), Ok(Some(9))),
        0,
    );
    let Err(Unread {
        why: Error::Unassessable { detail, .. },
        parent_blamed: false,
    }) = super::resolve_or_drop(&kernel, id.pid(), parent, None)
    else {
        panic!("an unreadable pid is Unassessable");
    };
    assert!(
        detail.contains(&format!("pid {} identity could not be read", id.pid())),
        "{detail}"
    );
    assert!(detail.contains(View::Unreadable.cause()), "{detail}");
    assert!(!detail.contains("access denied?"), "{detail}");
    assert!(!detail.contains("ppid"), "{detail}");
    release(child);
}

/// The view fails every read, the parent's proof too (a `Ticks` id is proved by its `stat`), so the
/// error blames the parent. Mutant: "`resolve_or_drop` drops the cause".
#[skuld::test]
fn the_error_for_a_dropped_pid_names_the_cause_of_its_parents_proof() {
    let (child, id) = live_member();
    let me = ProcessId::current();
    let parent = ticks_id(me.pid());
    let kernel = View::Unreadable.fail(FakeKernel::over(&HostKernel), 0);
    let Err(Unread {
        why: Error::Unassessable { detail, .. },
        parent_blamed: true,
    }) = super::resolve_or_drop(&kernel, id.pid(), parent, None)
    else {
        panic!("an unreadable parent proof is Unassessable, blaming the parent");
    };
    assert!(
        detail.contains(&format!("ppid {} identity could not be read", me.pid())),
        "{detail}"
    );
    assert!(detail.contains(View::Unreadable.cause()), "{detail}");
    assert!(!detail.contains("access denied?"), "{detail}");
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
    let outcome = super::kill_by_identity(&unreadable_kernel, id, nix::sys::signal::Signal::SIGTERM);
    assert!(matches!(outcome, super::KillOutcome::NotAttempted(_)), "{outcome:?}");
    let new_owner = FakeKernel::over(&HostKernel)
        .live_without_pidfs(pid, pidfd_of(pid))
        .on_read(&format!("{pid}/stat"), Ok(&stat_of_a_new_owner(pid)));
    let outcome = super::kill_by_identity(&new_owner, id, nix::sys::signal::Signal::SIGTERM);
    assert!(matches!(outcome, super::KillOutcome::AlreadyGone), "{outcome:?}");
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
    // The reason is the refusal's own, so an error built from it names the process and why.
    let outcome = super::kill_by_identity(&refusing, id, nix::sys::signal::Signal::SIGTERM);
    let super::KillOutcome::NotAttempted(why) = outcome else {
        panic!("expected NotAttempted, got {outcome:?}");
    };
    // An identity that could not be read is `Unassessable`, with the refusal as its source.
    let Error::Unassessable { detail, source } = &why else {
        panic!("expected Unassessable, got {why:?}");
    };
    assert!(detail.contains("pidfd"), "{detail}");
    assert_eq!(
        source.as_ref().and_then(std::io::Error::raw_os_error),
        Some(libc::EMFILE),
        "{why:?}"
    );
    let new_owner = FakeKernel::over(&HostKernel).on_pidfs_ino(pid, Ok(Some(ino + 1)));
    let outcome = super::kill_by_identity(&new_owner, id, nix::sys::signal::Signal::SIGTERM);
    assert!(matches!(outcome, super::KillOutcome::AlreadyGone), "{outcome:?}");
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
///
/// A member whose identity cannot be read at kill time is `Unassessable`. `hard_kill` returns it and
/// warns of nothing; `terminate`, which cannot, warns.
#[skuld::test]
fn every_id_walk_re_verifies_a_descendants_kill_through_its_kernel() {
    crate::log_capture::install();
    for ((name, walk), signo) in id_walks().into_iter().zip([libc::SIGKILL, libc::SIGTERM]) {
        for shows_a_new_owner in [false, true] {
            let (child, root, descendant) = live_member_with_descendant();
            let mark = crate::log_capture::mark();
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
            // A refused kill leaves the descendant running, so `hard_kill` names it; `terminate` is
            // best effort. A descendant shown as another process is gone, not left behind.
            let warned: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "treewalk:")
                .into_iter()
                .filter(|(level, said)| *level == log::Level::Warn && said.contains(&descendant.pid().to_string()))
                .collect();
            if name == "hard_kill" && !shows_a_new_owner {
                assert_not_killed(result, descendant.pid(), &[]);
                assert_eq!(warned, [], "the error is the report");
            } else {
                assert!(result.is_ok(), "{name}, new owner {shows_a_new_owner}: {result:?}");
                assert_eq!(
                    warned.len(),
                    usize::from(name == "terminate" && !shows_a_new_owner),
                    "{name}, new owner {shows_a_new_owner}: {warned:?}"
                );
            }
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

/// A descendant the walk cannot read is not signalled, and `hard_kill` and `Process::kill_tree`
/// are an error naming it and why, so a caller does not take the tree for killed. `terminate` is best
/// effort and stays `Ok`. Mutants: "an `Unknown` read is dropped as `Gone`": `Ok`; "`kill_tree`
/// drops the walk's error"; "`terminate` reports the incomplete walk".
#[skuld::test]
fn a_descendant_that_cannot_be_read_makes_hard_kill_and_kill_tree_err_naming_it_and_leaves_terminate_ok() {
    let (child, root, descendant, kernel) = root_with_an_unreadable_descendant();
    let cause = format!("pid {} identity could not be read", descendant.pid());
    let left = super::hard_kill(&kernel, root).expect_err("a descendant was left");
    assert!(!left.members.is_empty(), "a descendant was left, not only the root");
    assert_not_killed(Err(left.into_error()), descendant.pid(), &[&cause]);
    release_with_a_signalled_root("hard_kill", child, libc::SIGKILL);

    let (child, root, descendant, kernel) = root_with_an_unreadable_descendant();
    let cause = format!("pid {} identity could not be read", descendant.pid());
    assert_not_killed(open_live(root).kill_tree_with(&kernel), descendant.pid(), &[&cause]);
    release_with_a_signalled_root("kill_tree", child, libc::SIGKILL);

    let (child, root, _, kernel) = root_with_an_unreadable_descendant();
    super::terminate(&kernel, root).expect("best effort");
    release_with_a_signalled_root("terminate", child, libc::SIGTERM);
}

/// A member the walk could not read is reported once, wherever it is reported from: through the real
/// `resolve_or_drop`, `hard_kill` and `children` name it in their error and the walk warns of nothing;
/// `terminate`, which returns none, warns of it once, with its pid and why. Mutant: "the walk warns of
/// a candidate it drops" (the error that names it then reports it a second time).
#[skuld::test]
fn a_descendant_that_cannot_be_read_is_reported_once() {
    crate::log_capture::install();
    let warns_naming = |mark, descendant: ProcessId| -> Vec<String> {
        crate::log_capture::warns_since_on_current_thread(mark, &format!("pid {}", descendant.pid()))
            .into_iter()
            .map(|(_, said)| said)
            .collect()
    };

    let (child, root, descendant, kernel) = root_with_an_unreadable_descendant();
    let mark = crate::log_capture::mark();
    super::hard_kill(&kernel, root).expect_err("a descendant was left");
    assert_eq!(
        warns_naming(mark, descendant),
        Vec::<String>::new(),
        "the error is the report"
    );
    release_with_a_signalled_root("hard_kill", child, libc::SIGKILL);

    let (child, root, descendant, kernel) = root_with_an_unreadable_descendant();
    let mark = crate::log_capture::mark();
    root.children_with(&kernel, Recursive::Yes)
        .expect_err("a descendant was not read");
    assert_eq!(
        warns_naming(mark, descendant),
        Vec::<String>::new(),
        "the error is the report"
    );
    release(child);

    let (child, root, descendant, kernel) = root_with_an_unreadable_descendant();
    let mark = crate::log_capture::mark();
    super::terminate(&kernel, root).expect("best effort");
    let warned = warns_naming(mark, descendant);
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(
        warned[0].contains(&format!("pid {} dropped from the walk", descendant.pid())),
        "{warned:?}"
    );
    assert!(warned[0].contains("identity could not be read"), "{warned:?}");
    release_with_a_signalled_root("terminate", child, libc::SIGTERM);
}

/// Every member left behind is in what `hard_kill` returns, the one that could not be read first, and
/// `hard_kill` warns of none: its caller reports, once. The made-up second member is `fault`'s, as no
/// real second descendant refuses a kill without setuid. Mutants: "`hard_kill` drops every member after
/// the first"; "`hard_kill` warns of the members after the first".
#[skuld::test]
fn every_member_left_behind_is_returned_and_none_is_warned_of() {
    use super::fault::{self, LeftBehind};
    crate::log_capture::install();
    let (child, root, descendant, kernel) = root_with_an_unreadable_descendant();
    let second = root.pid().wrapping_add(1);
    let mark = crate::log_capture::mark();
    fault::force_incomplete_once(LeftBehind::Descendant);
    let left = super::hard_kill(&kernel, root).expect_err("two members were left");
    let warned = crate::log_capture::warns_since_on_current_thread(mark, "treewalk:");
    let pids: Vec<u32> = left
        .members
        .iter()
        .map(|error| match error {
            Error::MemberNotKilled { pid, .. } => *pid,
            other => panic!("expected MemberNotKilled, got {other:?}"),
        })
        .collect();
    assert_eq!(pids, [descendant.pid(), second], "{left:?}");
    assert!(left.root.is_none(), "{left:?}");
    assert_eq!(warned, [], "the caller reports");
    release_with_a_signalled_root("hard_kill", child, libc::SIGKILL);
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
    assert_eq!(
        super::resolve_or_drop(&kernel, PID, parent(99), None).expect("a read"),
        None
    );
    assert!(super::resolve_or_drop(&kernel, PID, parent(1), None)
        .expect("a read")
        .is_some());
}
