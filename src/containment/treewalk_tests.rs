//! Tests for the identity-aware descendant filters. Most are pure and run on every host: synthetic
//! `(pid, ppid)` edges plus a stub resolver closure drive the filters'
//! structure: the subtree, the dedup, the unassessed list, and what the resolver is handed. The
//! stub applies no order rule: the rule is the read's (`identity_tests`, `keeps` and `judged`),
//! whose answers the stub states. The anchor row reads this live process; the `cfg(windows)` rows
//! below run only on Windows, with their own short-lived children.

use super::{descendants_with, Resolution, Walk};
use crate::error::Error;
use crate::identity::{Key, OrderKey, ProcessId, RawPid, UnknownCause};
#[cfg(unix)]
use crate::test_groups::setuid;
use std::collections::HashMap;

const ROOT_PID: RawPid = 100;
const ROOT_TOKEN: u64 = 1_000;

fn id(pid: RawPid, token: u64) -> ProcessId {
    ProcessId::from_parts_for_test(pid, Key::for_test(token))
}

/// The bound a candidate's children follow, as a resolver hands it out where the platform orders.
fn bound_of(token: u64) -> Option<OrderKey> {
    Some(OrderKey::for_test(token))
}

/// What the live resolver returns for a process whose identity token and order key agree.
fn resolved(pid: RawPid, token: u64) -> (ProcessId, Option<OrderKey>) {
    (id(pid, token), bound_of(token))
}

/// Build a resolver from a (pid -> token) table. A pid absent from the table is
/// unresolvable (`Ok(None)`, modelling an already-gone process, or one the read found out of order).
fn resolver(tokens: &HashMap<RawPid, u64>) -> impl Fn(RawPid, ProcessId, Option<OrderKey>) -> Resolution + '_ {
    move |pid, _parent, _bound| Ok(tokens.get(&pid).map(|&t| resolved(pid, t)))
}

/// What the live resolver returns for a pid whose read was `Unknown`.
fn unreadable(pid: RawPid) -> Error {
    crate::identity::unqueryable_read("pid", pid, UnknownCause::default())
}

/// Collect the member pids into a sorted Vec for order-independent comparison.
fn pids(walk: Walk) -> Vec<RawPid> {
    let mut v = walk.members;
    v.sort_by_key(|i| i.pid());
    v.into_iter().map(|i| i.pid()).collect()
}

/// The pids a walk could not assess, sorted.
fn unassessed(walk: &Walk) -> Vec<RawPid> {
    let mut v: Vec<RawPid> = walk.unassessed.iter().map(|&(pid, _)| pid).collect();
    v.sort_unstable();
    v
}

fn root() -> ProcessId {
    id(ROOT_PID, ROOT_TOKEN)
}

fn root_bound() -> Option<OrderKey> {
    bound_of(ROOT_TOKEN)
}

// Deep trees recurse =====

#[skuld::test]
fn recurses_into_deep_tree() {
    // root(100) -> 200 -> 300 -> 400, all created after the root.
    let parents = [(200, ROOT_PID), (300, 200), (400, 300)];
    let tokens = HashMap::from([
        (200u32, ROOT_TOKEN + 1),
        (300u32, ROOT_TOKEN + 2),
        (400u32, ROOT_TOKEN + 3),
    ]);
    let got = descendants_with(root(), root_bound(), &parents, resolver(&tokens));
    assert_eq!(pids(got), [200, 300, 400]);
}

// A reparented orphan (ppid no longer == root) is honestly missed =====

#[skuld::test]
fn reparented_orphan_is_missed() {
    // 300 was a grandchild, but its parent 200 exited and 300 was reparented to
    // pid 1; its ppid no longer chains to the root, so the walk cannot reach it.
    let parents = [(300, 1)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 9)]);
    let got = descendants_with(root(), root_bound(), &parents, resolver(&tokens));
    assert!(
        got.members.is_empty(),
        "reparented orphan is honestly missed (documented)"
    );
}

// The root itself is never included =====

#[skuld::test]
fn root_is_never_included() {
    // An edge naming the root as its own child would be degenerate; ensure the
    // root pid never appears in the descendant set even if such an edge exists.
    let parents = [(ROOT_PID, ROOT_PID), (200, ROOT_PID)];
    let tokens = HashMap::from([(ROOT_PID, ROOT_TOKEN), (200u32, ROOT_TOKEN + 1)]);
    let got = descendants_with(root(), root_bound(), &parents, resolver(&tokens));
    assert_eq!(pids(got), [200], "root excluded; genuine child kept");
}

// A duplicate edge enumerates the pid only once =====

#[skuld::test]
fn duplicate_edge_yields_pid_once() {
    // A snapshot that lists the same (pid, ppid) edge twice must not enumerate
    // (or later double-kill) the same process twice.
    let parents = [(200, ROOT_PID), (200, ROOT_PID)];
    let tokens = HashMap::from([(200u32, ROOT_TOKEN + 1)]);
    let got = descendants_with(root(), root_bound(), &parents, resolver(&tokens));
    assert_eq!(pids(got), [200], "duplicate edge collapses to a single result");
}

// An unresolvable candidate (already gone) is skipped =====

#[skuld::test]
fn unresolvable_candidate_is_skipped() {
    // 200 chains to the root but is absent from the resolver (it exited between
    // snapshot and resolve); it is dropped along with anything under it.
    let parents = [(200, ROOT_PID), (300, 200)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 5)]); // 200 missing
    let got = descendants_with(root(), root_bound(), &parents, resolver(&tokens));
    assert!(got.members.is_empty(), "gone candidate and its subtree are skipped");
    assert!(got.unassessed.is_empty(), "a gone candidate is not unassessed");
}

// A candidate the resolver cannot read is unassessed, and its subtree is pruned =====

#[skuld::test]
fn an_unreadable_candidate_and_its_subtree_are_out_of_the_walk_and_it_is_unassessed() {
    // 200 is unreadable; 300 under it is unreachable through it. 400 is a sibling that reads.
    let parents = [(200, ROOT_PID), (300, 200), (400, ROOT_PID)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 5), (400u32, ROOT_TOKEN + 6)]);
    let read = resolver(&tokens);
    let got = descendants_with(root(), root_bound(), &parents, |pid, parent, bound| {
        if pid == 200 {
            Err(unreadable(200))
        } else {
            read(pid, parent, bound)
        }
    });
    assert_eq!(unassessed(&got), [200]);
    assert!(matches!(&got.unassessed[0].1, Error::Unassessable { detail, .. } if detail.contains("pid 200")));
    assert_eq!(pids(got), [400]);
}

/// `complete_members` is the first unassessed candidate's error, and each other's pid and cause.
/// Mutant: "the others' causes are dropped".
#[skuld::test]
fn complete_members_names_every_unassessed_candidate_with_its_cause() {
    let parents = [(200, ROOT_PID), (300, ROOT_PID), (400, ROOT_PID)];
    let got = descendants_with(root(), root_bound(), &parents, |pid, _, _| {
        Err(Error::Unassessable {
            detail: format!("cause of {pid}"),
            source: None,
        })
    });
    let first = got.unassessed[0].0;
    let error = got.complete_members().expect_err("three candidates were not assessed");
    let said = error.to_string();
    assert!(said.contains(&format!("cause of {first}")), "{said}");
    for other in [200, 300, 400].into_iter().filter(|pid| *pid != first) {
        let entry = note_entry(&said, other);
        assert_eq!(entry, format!("pid {other} (cause of {other})"), "{said}");
    }
}

/// The note's entry for `pid`: from its `pid {pid} (` to the next entry, or the end.
fn note_entry(said: &str, pid: RawPid) -> &str {
    let start = said
        .find(&format!("pid {pid} ("))
        .unwrap_or_else(|| panic!("no entry for pid {pid} in: {said}"));
    said[start..].split("; pid ").next().expect("split yields one piece")
}

/// The note on `complete_members` carries each other candidate's whole chain, its OS error included.
#[skuld::test]
fn complete_members_note_keeps_the_os_error_of_each_other_candidate() {
    let parents = [(200, ROOT_PID), (300, ROOT_PID), (400, ROOT_PID)];
    // A code per pid, so an entry paired with another candidate's error fails.
    let os_error = |pid: RawPid| {
        std::io::Error::from_raw_os_error(match pid {
            200 => 2,
            300 => 3,
            _ => 5,
        })
    };
    let got = descendants_with(root(), root_bound(), &parents, |pid, _, _| {
        Err(Error::Unassessable {
            detail: format!("cause of {pid}"),
            source: Some(Error::io_cause(os_error(pid))),
        })
    });
    let first = got.unassessed[0].0;
    let error = got.complete_members().expect_err("three candidates were not assessed");
    let said = error.to_string();
    for other in [200, 300, 400].into_iter().filter(|pid| *pid != first) {
        let os_text = os_error(other).to_string();
        assert!(note_entry(&said, other).contains(&os_text), "{said}");
    }
}

/// A snapshot that lists the unreadable pid twice reads it once and counts it once.
#[skuld::test]
fn a_duplicate_edge_to_an_unreadable_candidate_is_one_unassessed_entry() {
    let parents = [(200, ROOT_PID), (200, ROOT_PID)];
    let got = descendants_with(root(), root_bound(), &parents, |pid, _, _| Err(unreadable(pid)));
    assert_eq!(unassessed(&got), [200]);
    assert!(got.members.is_empty());
}

/// Only a candidate the resolver finds gone is logged as "gone, or an impostor"; one it errs on was
/// warned where the read was made, and the filters say nothing more of it. The pids are this row's
/// own, as the capture is shared by parallel rows. Mutant: the `Err` arm logs the same line.
#[skuld::test]
fn only_a_gone_candidate_is_logged_as_gone_or_an_impostor() {
    use super::children_of_with;
    const UNREADABLE: RawPid = 61_001;
    const GONE: RawPid = 61_002;
    crate::log_capture::install();
    let parents = [(UNREADABLE, ROOT_PID), (GONE, ROOT_PID)];
    let resolve = |pid: RawPid, _parent: ProcessId, _bound: Option<OrderKey>| -> Resolution {
        if pid == UNREADABLE {
            Err(unreadable(pid))
        } else {
            Ok(None)
        }
    };
    let mark = crate::log_capture::mark();
    descendants_with(root(), root_bound(), &parents, resolve);
    children_of_with(root(), root_bound(), &parents, resolve);
    assert!(crate::log_capture::contains_since(
        mark,
        &format!("pid {GONE} gone, or an impostor")
    ));
    assert!(!crate::log_capture::contains_since(
        mark,
        &format!("pid {UNREADABLE} gone, or an impostor")
    ));
}

#[skuld::test]
fn an_unreadable_direct_child_is_unassessed_in_the_one_level_filter_too() {
    use super::children_of_with;
    let parents = [(200, ROOT_PID), (200, ROOT_PID), (300, ROOT_PID), (400, 200)];
    let tokens = HashMap::from([(300u32, ROOT_TOKEN + 5)]);
    let read = resolver(&tokens);
    let got = children_of_with(root(), root_bound(), &parents, |pid, parent, bound| {
        if pid == 200 {
            Err(unreadable(200))
        } else {
            read(pid, parent, bound)
        }
    });
    assert_eq!(unassessed(&got), [200]);
    assert_eq!(pids(got), [300]);
}

/// A pid is resolved once however many edges list it: when its first read finds it and a second
/// would be `Unknown`, it is a member, listed once, and not unassessed. Mutant: the one-level filter
/// resolves each duplicate edge again.
#[skuld::test]
fn a_duplicate_edge_is_resolved_once_in_both_filters() {
    use super::children_of_with;
    use std::cell::Cell;

    let parents = [(200, ROOT_PID), (200, ROOT_PID)];
    let reads = Cell::new(0);
    let first_reads_second_does_not = |pid: RawPid, _parent: ProcessId, _bound: Option<OrderKey>| {
        reads.set(reads.get() + 1);
        if reads.get() == 1 {
            Ok(Some(resolved(pid, ROOT_TOKEN + 5)))
        } else {
            Err(unreadable(pid))
        }
    };
    let got = children_of_with(root(), root_bound(), &parents, first_reads_second_does_not);
    assert_eq!((pids(got), reads.get()), (vec![200], 1), "one level");

    reads.set(0);
    let got = descendants_with(root(), root_bound(), &parents, first_reads_second_does_not);
    assert!(got.unassessed.is_empty(), "{:?}", got.unassessed);
    assert_eq!((pids(got), reads.get()), (vec![200], 1), "whole subtree");
}

// One-level child filter keeps only genuine direct children =====

#[skuld::test]
fn children_of_keeps_one_level_genuine_children_only() {
    use super::children_of_with;
    // root 100; direct child 101; grandchild 102 (ppid 101, not one level); 103 ppid 100, which the
    // resolver finds gone (an impostor, or exited).
    let root = id(100, 50);
    let parents = [(101, 100), (102, 101), (103, 100)];
    let tokens = HashMap::from([(101u32, 60), (102u32, 70)]);
    let got = children_of_with(root, bound_of(50), &parents, resolver(&tokens));
    assert!(got.unassessed.is_empty());
    assert_eq!(pids(got), [101]);
}

// A duplicate edge enumerates a direct child only once =====

#[skuld::test]
fn children_of_duplicate_edge_yields_pid_once() {
    use super::children_of_with;
    // A snapshot listing the same (pid, ppid) edge twice must not enumerate (or later
    // double-kill) the same child twice.
    let root = id(100, ROOT_TOKEN);
    let parents = [(101, 100), (101, 100)];
    let tokens = HashMap::from([(101u32, ROOT_TOKEN + 1)]);
    assert_eq!(
        pids(children_of_with(root, root_bound(), &parents, resolver(&tokens))),
        [101],
        "duplicate edge collapses to a single child"
    );
}

/// The resolver is told the accepted process the snapshot made each candidate's parent, so a backend
/// can drop a candidate whose parent's number has another holder now, and the bound it must follow:
/// the accepted parent's, which the resolver handed out with it. The parent of a grandchild is the
/// id the walk accepted for the child. Mutants: "the resolver is asked the root for every
/// candidate"; "the bound is the root's for a deeper candidate".
#[skuld::test]
fn the_resolver_is_asked_for_each_candidates_accepted_parent() {
    use std::cell::RefCell;

    use super::children_of_with;

    let asked = RefCell::new(Vec::new());
    let resolve = |pid: u32, parent: ProcessId, bound: Option<OrderKey>| -> Resolution {
        asked.borrow_mut().push((pid, parent, bound));
        Ok(Some(resolved(pid, ROOT_TOKEN + 1)))
    };
    let parents = [(200, ROOT_PID), (300, 200)];
    descendants_with(root(), root_bound(), &parents, resolve);
    assert_eq!(
        asked.take(),
        [
            (200, root(), root_bound()),
            (300, id(200, ROOT_TOKEN + 1), bound_of(ROOT_TOKEN + 1))
        ]
    );

    children_of_with(root(), root_bound(), &parents, resolve);
    assert_eq!(asked.take(), [(200, root(), root_bound())]);
}

/// The bound the filters hand the resolver for the root's children is the `root_bound` argument,
/// not the root id's token: here the root's token is `ROOT_TOKEN` and its bound is another number,
/// or none, as where no order is relied on. Mutants: "the filters hand out `root.key()`"; "the
/// filters hand out a bound the platform did not give".
#[skuld::test]
fn the_bound_is_the_roots_bound_not_its_id_token() {
    use std::cell::RefCell;

    use super::children_of_with;
    let parents = [(200, ROOT_PID)];
    let asked = RefCell::new(Vec::new());
    let resolve = |pid: u32, _parent: ProcessId, bound: Option<OrderKey>| -> Resolution {
        asked.borrow_mut().push((pid, bound));
        Ok(None)
    };
    for bound in [bound_of(ROOT_TOKEN - 500), None] {
        descendants_with(root(), bound, &parents, resolve);
        assert_eq!(asked.take(), [(200, bound)], "descendants_with");
        children_of_with(root(), bound, &parents, resolve);
        assert_eq!(asked.take(), [(200, bound)], "children_of_with");
    }
}

/// What the live anchor hands the walk as its children's bound: where the platform orders by
/// creation (Windows) the root's order key, elsewhere none, read through `anchor` itself (this
/// process, live) and not stated. Mutants: the anchor hands out a bound off Windows; it hands out
/// none on Windows.
#[skuld::test]
fn the_anchor_hands_out_a_bound_only_on_windows() {
    let proof = super::anchor(&crate::identity::HostKernel, ProcessId::current())
        .expect("this process reads")
        .expect("this process is live");
    assert_eq!(proof.bound.is_some(), crate::identity::ORDER_AFTER_PARENT);
}

/// `resolve_or_drop` is a named discard site: an access-denied descendant must be dropped
/// from the walk as an error naming it, never be silently folded in with a gone pid. The walk's
/// caller reports it ([`super::warn_unassessed`]), so the walk itself logs nothing.
#[cfg(windows)]
#[skuld::test]
fn resolve_or_drop_drops_an_access_denied_pid_as_an_error() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(resolve_or_drop_drops_an_access_denied_pid_as_an_error),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
    crate::log_capture::install();
    let denied = crate::identity::windows_fixture::spawn_restricted(&done, PROCESS_SYNCHRONIZE.0);
    assert!(denied.is_running(), "precondition: the subject must be live");
    let mark = crate::log_capture::mark();
    let Err(Error::Unassessable { detail, .. }) =
        super::resolve_or_drop(&crate::identity::HostKernel, denied.pid(), ProcessId::current(), None)
    else {
        panic!("the walk cannot keep what it cannot verify, and an unread pid is not a gone one");
    };
    assert!(
        detail.contains(&format!("pid {} exists but could not be queried", denied.pid())),
        "{detail}"
    );
    assert!(
        !crate::log_capture::contains_since(mark, &format!("treewalk: pid {}", denied.pid())),
        "the walk's caller reports it, not the walk"
    );
    assert!(denied.is_running(), "and dropping it must not have touched it");
}

/// The text of `resolve_or_drop`'s warn for a candidate whose creator-pid query was refused: the
/// cause reaches `unqueryable_read`, which words it, so the warn names the pid and the query, and
/// it does not fall back to "access denied?".
///
/// The failed query itself is not driven through the walk: forcing one needs a hook in production
/// code, and Windows has no `FakeKernel` methods to state it in.
///
/// Mutant: `into_error` drops the creator status.
#[cfg(windows)]
#[skuld::test]
fn a_refused_creator_query_is_worded_with_its_status_in_the_walks_warn_on_windows() {
    let refused = windows::Win32::Foundation::NTSTATUS(0xC000_0004_u32 as i32);
    let cause = crate::identity::UnknownCause::default().with_creator_status(refused);
    let error = crate::identity::unqueryable_read("pid", 7, cause);
    let crate::error::Error::Unassessable { detail, .. } = &error else {
        panic!("a refused creator query is Unassessable");
    };
    assert_eq!(detail, "pid 7 exists but its creator process id query failed");
    // `STATUS_INFO_LENGTH_MISMATCH` as its Win32 code, `ERROR_BAD_LENGTH`.
    assert_eq!(
        error.raw_os_error(),
        Some(windows::Win32::Foundation::ERROR_BAD_LENGTH.0 as i32)
    );
}

/// The Windows wiring of the walk to the creator read, through `walk_from` with real
/// processes: `x` and `y` are both children of the root (this process). A snapshot that names `x` as
/// `y`'s parent is a stale creator edge: `y`'s own creator is the root, so it is dropped under `x`
/// and kept under the root. `x` is spawned first, so `y`'s key follows `x`'s and the parent-order
/// rule passes the edge: only the creator read drops `y`. (A real edge that breaks the rule names a
/// creator that is not the process's, which the creator read catches first, so the `judged` and
/// bound rows pin that rule.)
/// Mutant: `resolve_or_drop` passes no parent to the read.
#[cfg(windows)]
#[skuld::test]
fn a_real_candidate_is_dropped_under_a_parent_that_is_not_its_creator_on_windows() {
    use crate::identity::HostKernel;
    use crate::test_child::{live_findstr_blocker, release_findstr_unterminated};

    use crate::Recursive;

    let root = ProcessId::current();
    let (x_child, x) = live_findstr_blocker();
    let (y_child, y) = live_findstr_blocker();

    // The root's own row is not read, only the rows that name it as a parent.
    let stale_creator = [(x.pid(), root.pid()), (y.pid(), x.pid())];
    let dropped = super::walk_from(&HostKernel, root, &stale_creator, Recursive::Yes)
        .expect("the root reads")
        .expect("the root is live");
    let genuine = [(x.pid(), root.pid()), (y.pid(), root.pid())];
    let kept = super::walk_from(&HostKernel, root, &genuine, Recursive::Yes)
        .expect("the root reads")
        .expect("the root is live");

    release_findstr_unterminated(x_child);
    release_findstr_unterminated(y_child);
    // A stale creator is dropped as `Gone`, not as unassessed: both of this process's children read.
    assert!(dropped.unassessed.is_empty() && kept.unassessed.is_empty());
    assert_eq!(dropped.members, vec![x]);
    assert_eq!(kept.members, vec![x, y]);
}

/// A root that exits while its handle is held is walked, and its running child is killed. Windows
/// does not reparent: the child's creator pid is still the root's. Toolhelp does not list an exited
/// process whose handle is held (measured on Windows 11 26100.9711), so the snapshot has no row for
/// the root while the walk's edges, which name it as the child's parent, are intact: a missing root
/// row says nothing about them. The root's order key and creator are read from its own handle, which
/// is held.
///
/// The root is a `cmd.exe` that holds its `ping` child, and the child ends by itself after 30
/// seconds: a kill that did not happen fails the assertion on its exit code, and a failed row leaves
/// the child running for that long at most.
///
/// Mutant: a root with no row in the snapshot is `Unassessable`, or walks nothing.
#[cfg(windows)]
#[skuld::test]
fn a_root_that_exited_while_its_handle_is_held_is_walked_and_its_child_killed() {
    use std::process::Stdio;

    use windows::Win32::Foundation::WAIT_OBJECT_0;
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    use crate::identity::{windows_close, windows_open_classified, HostKernel, Opened};
    use crate::Recursive;

    // The std `Child` holds the root's process handle until it is dropped, at the end of the row.
    let mut shell = crate::test_spawn::spawn(
        std::process::Command::new("cmd.exe")
            .args(["/c", "ping.exe", "-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped()),
    )
    .expect("spawn the root");
    let root = ProcessId::of(shell.id()).found().expect("the live root resolves");
    // The `ping` inherits the root's output pipe and prints its banner as it starts, so the first
    // byte read says it exists. The pipe stays open in `shell`: a closed one would end the `ping`.
    let mut first = [0u8; 1];
    let read = std::io::Read::read(shell.stdout.as_mut().expect("piped stdout"), &mut first).expect("read the banner");
    assert_eq!(read, 1, "the root closed its output before its child printed");
    // The root's children are its console host and its `ping`.
    let is_ping = |id: &ProcessId| {
        crate::identity::windows_fixture::image_file_name(id.pid()).is_some_and(|image| {
            std::path::Path::new(&image)
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("ping.exe"))
        })
    };
    let children = root.children(Recursive::No).expect("the root's children");
    let ping = children
        .into_iter()
        .find(is_ping)
        .expect("the root has a `ping` child")
        .pid();
    let Opened::Found(ping_handle) =
        windows_open_classified(ping, PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)
    else {
        panic!("the child is ours and openable");
    };
    shell.kill().expect("terminate the root");
    shell.wait().expect("the root's exit is recorded");

    let parents = crate::test_child::parents_once_unlisted(root.pid());
    assert!(
        parents.iter().any(|&(pid, ppid)| pid == ping && ppid == root.pid()),
        "precondition: the running child must still name the exited root as its creator"
    );

    let children = root.children(Recursive::No).expect("the exited root's children");
    assert!(
        children.iter().any(|id| id.pid() == ping),
        "{ping} not among {children:?}"
    );
    super::hard_kill(&HostKernel, root)
        .into_result()
        .expect("an exited root whose handle is held is walked completely");

    // SAFETY: `ping_handle` is our live handle with the synchronize right. The wait ends with the
    // kill just asked for, or with the child's own exit.
    let waited = unsafe { WaitForSingleObject(ping_handle, INFINITE) };
    assert_eq!(waited, WAIT_OBJECT_0, "the wait on the child returned {waited:?}");
    let mut code = 0u32;
    // SAFETY: `ping_handle` is live with the query right; `code` is a u32.
    unsafe { GetExitCodeProcess(ping_handle, &mut code) }.expect("the child's exit code");
    windows_close(ping_handle);
    assert_eq!(
        code,
        crate::identity::WINDOWS_TERMINATE_EXIT_CODE,
        "the walk must have terminated the child"
    );
}

/// `kill_by_identity`-s pre-open Denied arm - the outcome that can leave a process running.
#[cfg(windows)]
#[skuld::test]
fn kill_by_identity_reports_not_attempted_when_the_open_is_denied() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(kill_by_identity_reports_not_attempted_when_the_open_is_denied),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let child = crate::identity::windows_fixture::spawn_unkillable(&done);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    let outcome = super::kill_by_identity(id);
    assert!(matches!(outcome, super::KillOutcome::NotAttempted(_)), "{outcome:?}");
    assert!(child.is_running(), "a denied open must leave the process running");
}

/// A root the walk may read but not terminate is left running, and `hard_kill` is an error naming it
/// and why. Mutant: `hard_kill` drops a `NotAttempted` outcome.
#[cfg(windows)]
#[skuld::test]
fn hard_kill_of_a_root_whose_open_is_denied_is_an_error_naming_it() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(hard_kill_of_a_root_whose_open_is_denied_is_an_error_naming_it),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    // Readable by pid, but not terminable: the walk anchors on it, and its kill is refused.
    let child = crate::identity::windows_fixture::spawn_query_only(&done);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    assert!(child.is_running(), "precondition: the subject must be live");
    match super::hard_kill(&crate::identity::HostKernel, id).into_result() {
        Err(super::Unkilled {
            members,
            root: Some(crate::error::Error::MemberNotKilled { pid, source, .. }),
            ..
        }) if members.is_empty() => {
            assert_eq!(pid, child.pid());
            assert!(
                matches!(*source, crate::error::Error::Unassessable { source: Some(_), .. }),
                "an identity that could not be read is Unassessable, carrying the OS error: {source:?}"
            );
            let said = source.to_string();
            assert!(said.contains("could not be queried"), "{said}");
        }
        other => panic!("expected MemberNotKilled for the root, got {other:?}"),
    }
    assert!(child.is_running(), "a denied open must leave the process running");
}

/// A member the OS refuses the signal is left running, and `hard_kill`'s error carries the refusal's
/// OS error, so a caller can tell it from one that could not be read. A setuid-root helper refuses
/// the kill of its caller. Mutant: the refusal is flattened to text.
#[cfg(unix)]
#[skuld::test]
fn hard_kill_of_a_root_that_refuses_the_signal_is_an_error_carrying_the_errno(
    #[fixture(setuid)] _group: &crate::test_groups::Group,
) {
    let (child, stdin) = crate::test_privilege::spawn_setuid_blocker();
    let left = super::hard_kill(
        &crate::identity::HostKernel,
        child.id().expect(crate::test_child::IDENTITY_READ),
    )
    .into_result()
    .expect_err("the kill is refused");
    assert!(left.members.is_empty(), "the root is the only member the walk left");
    let err = left.root.expect("the root was left");
    // The message reads once: the pid, then the OS's own words.
    let os = std::io::Error::from_raw_os_error(libc::EPERM);
    assert_eq!(err.to_string(), format!("pid {} was not killed: {os}", child.pid()));
    match err {
        crate::error::Error::MemberNotKilled { pid, source, .. } => {
            assert_eq!(pid, child.pid());
            assert!(
                matches!(*source, crate::error::Error::Io(ref e) if e.raw_os_error() == Some(libc::EPERM)),
                "{source:?}"
            );
        }
        other => panic!("expected MemberNotKilled, got {other:?}"),
    }
    // The helper exits at EOF: nothing killed it.
    drop(stdin);
    assert!(child.wait().expect("the helper exits on EOF").success());
}

/// A descendant the OS refuses the signal is left running by the walk's own loop: the error names it,
/// with the refusal's OS error, and the root, which was killed, is not among what is left. A
/// setuid-root helper under a plain root refuses the kill of its caller.
///
/// Mutants: the loop drops a refused descendant's error; the root is reported left beside it.
#[cfg(unix)]
#[skuld::test]
fn hard_kill_of_a_descendant_that_refuses_the_signal_is_an_error_naming_it_with_the_errno(
    #[fixture(setuid)] _group: &crate::test_groups::Group,
) {
    let (child, stdin) = crate::test_privilege::root_over_setuid_blockers(1, |_| {});

    let left = super::hard_kill(
        &crate::identity::HostKernel,
        child.id().expect(crate::test_child::IDENTITY_READ),
    )
    .into_result()
    .expect_err("the helper refuses the kill");

    assert!(left.root.is_none(), "the root was killed: {:?}", left.root);
    assert_eq!(left.members.len(), 1, "{:?}", left.members);
    match &left.members[0] {
        crate::error::Error::MemberNotKilled { pid, source, .. } => {
            assert_ne!(*pid, child.pid(), "the helper, not the root");
            assert!(
                matches!(**source, crate::error::Error::Io(ref e) if e.raw_os_error() == Some(libc::EPERM)),
                "{source:?}"
            );
        }
        other => panic!("expected MemberNotKilled, got {other:?}"),
    }
    // The helper exits at EOF: nothing killed it.
    drop(stdin);
    crate::test_child::assert_killed("the root", child.wait().expect("reap the root"));
}

/// `Process::kill_tree` of a root that refuses the signal: nothing after the walk kills the root, so
/// it is left, and the error names it with the refusal's OS error.
///
/// Mutant: a root the walk left is dropped from the report as if its kill had ended it.
#[cfg(unix)]
#[skuld::test]
fn process_kill_tree_of_a_root_that_refuses_the_signal_names_the_root(
    #[fixture(setuid)] _group: &crate::test_groups::Group,
) {
    let (child, stdin) = crate::test_privilege::spawn_setuid_blocker();
    let process = crate::Process::open_pid(child.pid()).expect("open").expect("running");

    let err = process.kill_tree().expect_err("the root refuses the kill");

    match err {
        crate::error::Error::MemberNotKilled { pid, source, .. } => {
            assert_eq!(pid, child.pid());
            assert!(
                matches!(*source, crate::error::Error::Io(ref e) if e.raw_os_error() == Some(libc::EPERM)),
                "{source:?}"
            );
        }
        other => panic!("expected MemberNotKilled, got {other:?}"),
    }
    drop(stdin);
    assert!(child.wait().expect("the helper exits on EOF").success());
}

/// `Process::kill_tree` of a tree with two members that refuse the signal: the error names the first,
/// and the call warns of the other once, under its own name.
///
/// Mutants: the other member is dropped; it is warned of by the walk as well as by the call.
#[cfg(unix)]
#[skuld::test]
fn process_kill_tree_names_the_first_refusing_member_and_warns_of_the_other_once(
    #[fixture(setuid)] _group: &crate::test_groups::Group,
) {
    crate::log_capture::install();
    let (child, stdin) = crate::test_privilege::root_over_setuid_blockers(2, |_| {});
    let process = crate::Process::open_pid(child.pid()).expect("open").expect("running");
    let mark = crate::log_capture::mark();

    let err = process.kill_tree().expect_err("two members refuse the kill");

    let crate::error::Error::MemberNotKilled { pid: first, .. } = err else {
        panic!("expected MemberNotKilled, got {err:?}");
    };
    let warned = crate::log_capture::warns_since(mark, "was not killed");
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].starts_with("Process::kill_tree: pid "), "{warned:?}");
    assert!(
        !warned[0].contains(&format!("pid {first} ")),
        "the warn names the other member, not the first: {warned:?}"
    );
    drop(stdin);
    crate::test_child::assert_killed("the root", child.wait().expect("reap the root"));
}

/// `terminate` is best effort: a member that refuses the `SIGTERM` is warned of once, with its pid and
/// the OS's refusal, and the call is `Ok`.
///
/// Mutants: the refusal is not warned of; it is warned of twice.
#[cfg(unix)]
#[skuld::test]
fn terminate_warns_once_of_a_member_that_refuses_the_signal(#[fixture(setuid)] _group: &crate::test_groups::Group) {
    crate::log_capture::install();
    let (child, stdin) = crate::test_privilege::root_over_setuid_blockers(1, |_| {});
    let mark = crate::log_capture::mark();

    super::terminate(
        &crate::identity::HostKernel,
        child.id().expect(crate::test_child::IDENTITY_READ),
    )
    .expect("best effort");

    let os = std::io::Error::from_raw_os_error(libc::EPERM);
    let warned = crate::log_capture::warns_since(mark, "was sent no SIGTERM");
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(warned[0].starts_with("treewalk: pid "), "{warned:?}");
    assert!(warned[0].contains(&os.to_string()), "{warned:?}");
    drop(stdin);
    child.wait().expect("reap the root");
}

/// `kill_by_identity` must terminate only the process whose START TOKEN matches. A stale
/// identity names a recycled pid, and killing it would kill a stranger.
#[cfg(windows)]
#[skuld::test]
fn kill_by_identity_spares_a_stale_identity_and_kills_a_matching_one() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(kill_by_identity_spares_a_stale_identity_and_kills_a_matching_one),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
    // The ACE must grant QUERY_LIMITED as well as TERMINATE: kill_by_identity opens for
    // both, and a combined-mask OpenProcess fails entirely if ANY requested bit is ungranted.
    let (child, stdin) =
        crate::identity::windows_fixture::spawn_restricted_releasable(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
    let real = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    let stale = real.with_other_value();

    let outcome = super::kill_by_identity(stale);
    assert!(
        matches!(outcome, super::KillOutcome::AlreadyGone),
        "a stale identity names a process that is gone - nothing to terminate: {outcome:?}"
    );
    assert!(
        child.is_running(),
        "a stale identity must never terminate the pid-s occupant"
    );

    let outcome = super::kill_by_identity(real);
    assert!(
        matches!(outcome, super::KillOutcome::Terminated),
        "a matching identity must reach TerminateProcess: {outcome:?}"
    );
    // The child reads `stdin` to its end and exits 0, so a kill that sent nothing ends the wait
    // below with that code, not with the kill's `1`.
    drop(stdin);
    child.await_exit();
    assert_eq!(
        child.exit_code(),
        1,
        "a matching identity must terminate the process, not leave it to exit when released"
    );
}

/// A member that exits between `kill_by_identity`'s identity check and its `TerminateProcess`
/// is gone, not a failed kill: Windows refuses `TerminateProcess` on an exited process with
/// `ERROR_ACCESS_DENIED`. Mutant: the error arm warns and answers `NotAttempted` unconditionally.
#[cfg(windows)]
#[skuld::test]
fn kill_by_identity_reports_a_member_that_exits_before_the_terminate_as_gone() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(kill_by_identity_reports_a_member_that_exits_before_the_terminate_as_gone),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
    let _watch = crate::log_capture::warn_watch();
    let (child, _stdin) =
        crate::identity::windows_fixture::spawn_restricted_releasable(&done, PROCESS_QUERY_LIMITED_INFORMATION.0);
    let child = std::rc::Rc::new(child);
    let id = crate::identity::windows_identity_from_handle(child.handle(), child.pid())
        .expect("the owned handle always yields an identity");
    let exiter = std::rc::Rc::clone(&child);
    super::fault::set_before_terminate(move || exiter.terminate());

    let outcome = super::kill_by_identity(id);
    assert!(
        matches!(outcome, super::KillOutcome::AlreadyGone),
        "a member that exited before the terminate has nothing left to kill: {outcome:?}"
    );
    assert!(!child.is_running(), "precondition: the hook ended the member");
}

/// A member whose exit is under way but not yet signalled is gone, not a failed kill, and
/// `hard_kill` stays complete.
///
/// Mutant: a refusal is gone only once the process reads signalled, so this one warns and answers
/// `NotAttempted`.
#[cfg(windows)]
#[skuld::test]
fn kill_by_identity_reports_a_member_that_is_exiting_but_not_signalled_as_gone() {
    use std::os::windows::io::AsRawHandle;
    let mut child = crate::test_spawn::spawn(
        std::process::Command::new("cmd")
            .args(["/C", "more"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn cmd /C more");
    let id = crate::identity::windows_identity_from_handle(
        windows::Win32::Foundation::HANDLE(child.as_raw_handle()),
        child.id(),
    )
    .expect("the owned handle always yields an identity");
    let _refusal = crate::identity::windows_fault::refuse_next_terminate_as_exiting();
    let outcome = super::kill_by_identity(id);
    // The seam sent no terminate: end the fixture before asserting.
    child.kill().expect("end the fixture");
    child.wait().expect("reap the fixture");

    assert!(matches!(outcome, super::KillOutcome::AlreadyGone), "{outcome:?}");
}

/// A walk guards itself by proving its root still holds its pid, so off macOS `kill_tree` and
/// `terminate_tree` walk whatever the root's state says; on macOS they skip a root the handle cannot
/// vouch for (`Unpinned`, `Unknown`) and walk the rest. The root here holds no such pid, so a walk
/// that ran finds no root and kills nothing.
///
/// Mutant: `skipped_walk` skips on `Unknown` or `Reaped` off macOS.
#[cfg(unix)]
#[skuld::test]
fn a_walk_is_skipped_by_the_roots_state_only_on_macos() {
    use crate::containment::dispatch::TreeKillOutcome;
    use crate::containment::TerminateOutcome;
    use crate::signal::RootState;
    use crate::test_support::stated_root::StatedRoot;

    /// A state, and whether macOS cannot vouch for a root in it.
    type Case = (&'static str, fn() -> RootState, bool);
    let states: [Case; 5] = [
        ("unreaped", || RootState::Unreaped, false),
        ("reaped, own", || RootState::Reaped { own: true }, false),
        ("reaped elsewhere", || RootState::Reaped { own: false }, false),
        ("unknown", || RootState::Unknown(std::io::Error::other("forced")), true),
        ("unpinned", || RootState::Unpinned, true),
    ];
    for (name, state, untrusted) in states {
        let skipped = untrusted && cfg!(target_os = "macos");
        let root = StatedRoot::with_state(ROOT_PID, state);
        let killed = super::kill_tree(self::root(), Some(&root));
        assert_eq!(
            matches!(killed, TreeKillOutcome::Skipped(_)),
            skipped,
            "kill, {name}: {killed:?}"
        );
        if !skipped {
            assert!(matches!(killed, TreeKillOutcome::NoRoot), "kill, {name}: {killed:?}");
        }
        let termed = super::terminate_tree(self::root(), Some(&root));
        assert_eq!(
            matches!(termed, TerminateOutcome::End(_)),
            skipped,
            "terminate, {name}: {termed:?}"
        );
    }
}
