//! The tree walk over `pidfs` ids (and, at the end, `ticks` ids), on a [`FakeKernel`] that states
//! the table. A process's key
//! (its start time, from `stat`) and its identity (its pidfd's inode) are different numbers here, so
//! a wrapper that hands the filter one for the other fails.
//!
//! Rows run on every Linux that has `pidfd_open`; none needs pidfs.

use std::os::fd::OwnedFd;

use rustix::io::Errno;
use rustix::process::Pid;

use crate::error::Error;
use crate::identity::{FakeKernel, HostKernel, Kernel, Key, OrderKey, ProcessId};
use crate::Recursive;

const ROOT: u32 = 4242;
const CHILD: u32 = 4243;
/// The inodes and start times: the child's inode is below the root's start time, and the root
/// started before the child.
const ROOT_INO: u64 = 900;
const CHILD_INO: u64 = 5;
const ROOT_START: u64 = 1_000;
const CHILD_START: u64 = 2_000;

fn stand_in() -> OwnedFd {
    OwnedFd::from(std::fs::File::open("/dev/null").expect("/dev/null opens"))
}

/// `pid`'s `stat`, with parent `ppid` and start time `start`.
fn stat(pid: u32, ppid: u32, start: u64) -> Vec<u8> {
    format!("{pid} (x) S {ppid} {ppid} 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0").into_bytes()
}

fn root() -> ProcessId {
    ProcessId::from_parts_for_test(ROOT, Key::Pidfs(ROOT_INO))
}

fn child() -> ProcessId {
    ProcessId::from_parts_for_test(CHILD, Key::Pidfs(CHILD_INO))
}

/// A kernel in which `ROOT` has inode `ROOT_INO` and `CHILD` (its child) has `CHILD_INO`, each
/// showing its start time, and which lists those two pids and no other: a walk through it reaches no
/// host process, whichever host pids those numbers are.
fn table() -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel)
        .same_view()
        .on_pids(Ok(&[ROOT, CHILD]))
        .on_pidfd_open(ROOT, Ok(stand_in()))
        .on_pidfs_ino(ROOT, Ok(Some(ROOT_INO)))
        .on_pidfd_open(CHILD, Ok(stand_in()))
        .on_pidfs_ino(CHILD, Ok(Some(CHILD_INO)))
        .on_read(&format!("{ROOT}/stat"), Ok(&stat(ROOT, 1, ROOT_START)))
        .on_read(&format!("{CHILD}/stat"), Ok(&stat(CHILD, ROOT, CHILD_START)))
}

/// The snapshot: the root has a row, as a live root does.
const EDGES: [(u32, u32); 2] = [(ROOT, 1), (CHILD, ROOT)];

/// The members of the walk from `root`, whole subtree. Empty, not an error, for a root that is
/// gone; an error for one that cannot be read.
pub(super) fn descendants(kernel: &dyn Kernel, root: ProcessId, edges: &[(u32, u32)]) -> Result<Vec<ProcessId>, Error> {
    Ok(super::walk_from(kernel, root, edges, Recursive::Yes)?
        .unwrap_or_default()
        .members)
}

/// [`descendants`], one level.
pub(super) fn children_of(
    kernel: &dyn Kernel,
    parent: ProcessId,
    edges: &[(u32, u32)],
) -> Result<Vec<ProcessId>, Error> {
    Ok(super::walk_from(kernel, parent, edges, Recursive::No)?
        .unwrap_or_default()
        .members)
}

/// The resolver hands the filter the child's identity (its inode) and its key (its start time), each
/// in its place. Mutants: "the id carries the start time", "the key is the inode" (5 orders before
/// the root's 1000, so the child is dropped).
#[skuld::test]
fn resolve_or_drop_pairs_a_pidfs_id_with_its_start_time() {
    assert_eq!(
        super::resolve_or_drop(&table(), CHILD, root(), OrderKey::for_test(ROOT_START)).expect("the child reads"),
        Some((child(), OrderKey::for_test(CHILD_START)))
    );
}

#[skuld::test]
fn descendants_and_children_of_keep_the_child_of_a_pidfs_root_by_start_time() {
    assert_eq!(
        descendants(&table(), root(), &EDGES).expect("a readable root"),
        vec![child()]
    );
    assert_eq!(
        children_of(&table(), root(), &EDGES).expect("a readable root"),
        vec![child()]
    );
}

/// A child that started before the root is a recycled pid or a stale parent, whatever its inode.
/// Mutant: "the root's key is its inode" (a start time of 500 is below 1000, but above 5).
#[skuld::test]
fn a_child_that_started_before_a_pidfs_root_is_dropped() {
    let kernel = table().on_read(&format!("{CHILD}/stat"), Ok(&stat(CHILD, ROOT, 500)));
    assert!(descendants(&kernel, root(), &EDGES).unwrap().is_empty());
    assert!(children_of(&kernel, root(), &EDGES).unwrap().is_empty());
}

/// A root whose start time is gone from `/proc` while its pidfd still opens (it was reaped between)
/// has nothing to walk, and that is not an error.
#[skuld::test]
fn the_walk_of_a_pidfs_root_whose_stat_is_gone_is_empty() {
    let kernel = table()
        .on_read(&format!("{ROOT}/stat"), Err(libc::ENOENT))
        .on_signal_probe(Pid::from_raw(ROOT as i32).unwrap(), Err(Errno::SRCH));
    assert!(descendants(&kernel, root(), &EDGES).unwrap().is_empty());
    assert!(children_of(&kernel, root(), &EDGES).unwrap().is_empty());
}

/// A root whose start time cannot be read (`hidepid`) is an error, never an empty walk: an empty one
/// would let a caller kill the root and leave its descendants running.
#[skuld::test]
fn the_walk_of_a_pidfs_root_whose_stat_cannot_be_read_is_unassessable() {
    let kernel = table()
        .on_read(&format!("{ROOT}/stat"), Err(libc::EACCES))
        .on_signal_probe(Pid::from_raw(ROOT as i32).unwrap(), Ok(()));
    for result in [
        descendants(&kernel, root(), &EDGES),
        children_of(&kernel, root(), &EDGES),
    ] {
        match result {
            Err(Error::Unassessable { detail, .. }) => {
                assert!(
                    detail.contains(&format!("pid {ROOT} exists but could not be queried")),
                    "{detail}"
                );
            }
            other => panic!("expected Unassessable, got {other:?}"),
        }
    }
}

// The accepted parent is proved again after its child's read =====

const GRAND: u32 = 4244;
const GRAND_INO: u64 = 7;
const GRAND_START: u64 = 3_000;

/// [`table`], and `GRAND` (a child of `CHILD`) with inode `GRAND_INO`.
fn table_with_a_grandchild() -> FakeKernel<'static> {
    table()
        .on_pidfd_open(GRAND, Ok(stand_in()))
        .on_pidfs_ino(GRAND, Ok(Some(GRAND_INO)))
        .on_read(&format!("{GRAND}/stat"), Ok(&stat(GRAND, CHILD, GRAND_START)))
}

const EDGES_WITH_A_GRANDCHILD: [(u32, u32); 3] = [(ROOT, 1), (CHILD, ROOT), (GRAND, CHILD)];

/// The child's `ppid` names the root's number, and only the root's number: after the child's read
/// the number may belong to a process that reaped the root and took it. So the root is proved again
/// then, and a number that opens to another inode is not the root. Mutant: "the parent is not
/// proved again".
#[skuld::test]
fn a_child_read_after_its_parents_number_changed_hands_is_dropped() {
    // A kernel per walk: the row waits for a read of the child's `stat`, which a walk makes.
    let kernel = || table().on_pidfs_ino_after_read(ROOT, &format!("{CHILD}/stat"), Ok(Some(ROOT_INO + 1)));
    assert!(descendants(&kernel(), root(), &EDGES).unwrap().is_empty());
    assert!(children_of(&kernel(), root(), &EDGES).unwrap().is_empty());
}

/// The same for a parent that the walk accepted itself, deeper down. Mutant: "only the root is
/// proved again".
#[skuld::test]
fn a_grandchild_read_after_its_accepted_parents_number_changed_hands_is_dropped() {
    let kernel =
        table_with_a_grandchild().on_pidfs_ino_after_read(CHILD, &format!("{GRAND}/stat"), Ok(Some(CHILD_INO + 1)));
    assert_eq!(
        descendants(&kernel, root(), &EDGES_WITH_A_GRANDCHILD).unwrap(),
        vec![child()]
    );
    let kept = descendants(&table_with_a_grandchild(), root(), &EDGES_WITH_A_GRANDCHILD).unwrap();
    assert_eq!(
        kept.len(),
        2,
        "with the parent still holding its number the grandchild is kept"
    );
}

/// The parent-order rule is off here: `GRAND` started after the root but before its listed parent
/// `CHILD`, and is kept, as `walk_from` passes `ORDER_AFTER_PARENT`. Mutant:
/// `ORDER_AFTER_PARENT` is true off Windows.
#[skuld::test]
fn a_grandchild_that_started_before_its_listed_parent_is_kept_off_windows() {
    let kernel = table_with_a_grandchild().on_read(
        &format!("{GRAND}/stat"),
        Ok(&stat(GRAND, CHILD, (ROOT_START + CHILD_START) / 2)),
    );
    let grand = ProcessId::from_parts_for_test(GRAND, Key::Pidfs(GRAND_INO));
    assert_eq!(
        descendants(&kernel, root(), &EDGES_WITH_A_GRANDCHILD).unwrap(),
        vec![child(), grand]
    );
}

/// A parent whose proof cannot be made (here: its pidfd's inode cannot be read) verifies nothing, so
/// the child is dropped like a pid the walk cannot query, not walked.
#[skuld::test]
fn a_child_whose_parent_cannot_be_proved_again_is_dropped() {
    let kernel = || table().on_pidfs_ino_after_read(ROOT, &format!("{CHILD}/stat"), Err(Errno::BADF));
    assert!(descendants(&kernel(), root(), &EDGES).unwrap().is_empty());
    assert!(children_of(&kernel(), root(), &EDGES).unwrap().is_empty());
}

/// That child is not a gone one: the walk lists it as unassessed, with the parent's proof as the
/// reason, in both filters. A child whose pid is gone is listed in neither. Mutants: "an `Unknown`
/// read is dropped as `Gone`"; "a gone read is counted".
#[skuld::test]
fn a_child_whose_parent_cannot_be_proved_again_is_unassessed_and_a_gone_child_is_not() {
    let unproved = || table().on_pidfs_ino_after_read(ROOT, &format!("{CHILD}/stat"), Err(Errno::BADF));
    let walk = |kernel: &FakeKernel, depth| {
        super::walk_from(kernel, root(), &EDGES, depth)
            .unwrap()
            .expect("the root is live")
    };
    let found = walk(&unproved(), Recursive::Yes);
    let [(pid, Error::Unassessable { detail, .. })] = &found.unassessed[..] else {
        panic!("expected one Unassessable entry, got {:?}", found.unassessed);
    };
    assert_eq!(*pid, CHILD);
    assert!(
        detail.contains(&format!("ppid {ROOT} identity could not be read")),
        "{detail}"
    );
    assert!(found.members.is_empty());
    let children = walk(&unproved(), Recursive::No);
    assert_eq!(children.unassessed.len(), 1, "{:?}", children.unassessed);

    let gone = table()
        .on_pidfd_open(CHILD, Err(Errno::SRCH))
        .on_read(&format!("{CHILD}/stat"), Err(libc::ENOENT));
    for depth in [Recursive::Yes, Recursive::No] {
        let found = walk(&gone, depth);
        assert!(found.members.is_empty() && found.unassessed.is_empty(), "{found:?}");
    }
}

/// A child that started before the root cannot be the root's child, so the root's proof, which cannot
/// be made here, is never asked for: the child is gone, listed in neither `members` nor `unassessed`.
/// Mutant: "the order rule is checked after the parent's proof": the child is unassessed.
#[skuld::test]
fn a_child_that_started_before_its_parent_is_gone_before_the_parents_proof_is_asked() {
    let kernel = || {
        table()
            .on_read(&format!("{CHILD}/stat"), Ok(&stat(CHILD, ROOT, ROOT_START - 1)))
            .on_pidfs_ino_after_read(ROOT, &format!("{CHILD}/stat"), Err(Errno::BADF))
    };
    for depth in [Recursive::Yes, Recursive::No] {
        let found = super::walk_from(&kernel(), root(), &EDGES, depth)
            .unwrap()
            .expect("the root is live");
        assert!(found.members.is_empty() && found.unassessed.is_empty(), "{found:?}");
    }
}

/// The warn for that child names the parent whose proof failed, and the child's pid once. Mutant:
/// "the warn blames the child's pid".
#[skuld::test]
fn the_warn_for_a_child_whose_parent_cannot_be_proved_names_the_parent() {
    crate::log_capture::install();
    let kernel = table().on_pidfs_ino_after_read(ROOT, &format!("{CHILD}/stat"), Err(Errno::BADF));
    let mark = crate::log_capture::mark();
    assert!(super::resolve_or_drop(&kernel, CHILD, root(), OrderKey::for_test(ROOT_START)).is_err());
    let warned = crate::log_capture::records_since_on_current_thread(mark, &format!("pid {CHILD}"));
    assert_eq!(warned.len(), 1, "{warned:?}");
    let (level, message) = &warned[0];
    assert_eq!(*level, log::Level::Warn);
    assert!(
        message.contains(&format!("ppid {ROOT} identity could not be read")),
        "{message}"
    );
    assert_eq!(message.matches(&format!("pid {CHILD}")).count(), 1, "{message}");
}

/// On a host whose pidfds have no inode the proof is the ticks compare: the root's `stat` shows the
/// ticks the id has, or another process's.
fn ticks_table(root_start_now: u64) -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel)
        .same_view()
        .on_pidfd_open(CHILD, Ok(stand_in()))
        .on_pidfs_ino(CHILD, Ok(None))
        .on_read(&format!("{ROOT}/stat"), Ok(&stat(ROOT, 1, root_start_now)))
        .on_read(&format!("{CHILD}/stat"), Ok(&stat(CHILD, ROOT, CHILD_START)))
}

fn ticks_root() -> ProcessId {
    ProcessId::from_parts_for_test(ROOT, Key::Ticks(ROOT_START))
}

/// Mutant: "the parent is not proved again" (ticks).
#[skuld::test]
fn on_a_ticks_host_a_child_is_kept_only_while_its_parent_shows_its_ticks() {
    let kept = ticks_table(ROOT_START);
    assert_eq!(descendants(&kept, ticks_root(), &EDGES).unwrap().len(), 1);
    assert_eq!(children_of(&kept, ticks_root(), &EDGES).unwrap().len(), 1);

    let changed_hands = ticks_table(ROOT_START + 1);
    assert!(descendants(&changed_hands, ticks_root(), &EDGES).unwrap().is_empty());
    assert!(children_of(&changed_hands, ticks_root(), &EDGES).unwrap().is_empty());
}

// The root's key read is its proof =====

/// A kernel in which `ROOT` holds its pid until its `stat` is read for its key, and then does not.
fn root_changes_hands_at_its_key_read() -> FakeKernel<'static> {
    table().on_pidfs_ino_after_read(ROOT, &format!("{ROOT}/stat"), Ok(Some(ROOT_INO + 1)))
}

/// A kernel in which `ROOT` holds its pid until its `stat` is read for its key, and then cannot be proved.
fn root_proof_fails_at_its_key_read() -> FakeKernel<'static> {
    table().on_pidfs_ino_after_read(ROOT, &format!("{ROOT}/stat"), Err(Errno::BADF))
}

/// A root that held its pid when the walk began and whose key read finds another process there
/// walks nothing, whatever each entry point read before: the answer is the key read's. Mutants: "the
/// walk goes on after a `Gone` key read" (`hard_kill` and `terminate` record a walk, as they do
/// when the key is read after the walk has begun); "the root is signalled".
#[skuld::test]
fn a_root_whose_key_read_finds_another_process_walks_nothing() {
    let sends = crate::send_log::Capture::start();
    let walks = super::fault::record_walks();
    assert!(super::hard_kill(&root_changes_hands_at_its_key_read(), root()).expect("a gone root is Ok"));
    super::terminate(&root_changes_hands_at_its_key_read(), root()).expect("a gone root is Ok");
    for recursive in [Recursive::No, Recursive::Yes] {
        let children = root().children_with(&root_changes_hands_at_its_key_read(), recursive);
        assert_eq!(children.expect("a gone root is Ok"), vec![], "{recursive:?}");
    }
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk began");
    assert!(sends.by_identity().is_empty(), "{:?}", sends.by_identity());
}

/// A root whose key read cannot be made is an error from every entry point, never an empty walk:
/// an empty one would let a caller kill the root and leave its descendants running. Mutants: "an
/// `Unknown` key read is an empty walk"; "the root is signalled"; "the walk begins before the key
/// is read" (`hard_kill` and `terminate` record a walk).
#[skuld::test]
fn a_root_whose_key_read_cannot_be_made_is_unassessable_and_signals_nothing() {
    let sends = crate::send_log::Capture::start();
    let walks = super::fault::record_walks();
    let results = [
        super::hard_kill(&root_proof_fails_at_its_key_read(), root()).map(|_| ()),
        super::terminate(&root_proof_fails_at_its_key_read(), root()),
        root()
            .children_with(&root_proof_fails_at_its_key_read(), Recursive::No)
            .map(|_| ()),
        root()
            .children_with(&root_proof_fails_at_its_key_read(), Recursive::Yes)
            .map(|_| ()),
    ];
    for result in results {
        match result {
            Err(Error::Unassessable { detail, .. }) => {
                assert!(detail.contains(&format!("pid {ROOT}")), "{detail}");
            }
            other => panic!("expected Unassessable, got {other:?}"),
        }
    }
    assert_eq!(walks.walked(), Vec::<u32>::new(), "no walk began");
    assert!(sends.by_identity().is_empty(), "{:?}", sends.by_identity());
}

// The kill goes through the proved pidfd =====

const KILLED_INO: u64 = 77;

/// A `cat` that lives until its stdin closes, its pidfd, and a kernel in which that pid is `KILLED_INO`.
/// The child is the pidfd's real target, so a signal sent through it is observable.
fn live_child_in_a_table() -> (std::process::Child, ProcessId, FakeKernel<'static>) {
    use std::process::{Command, Stdio};
    let child =
        crate::test_spawn::spawn(Command::new("cat").stdin(Stdio::piped()).stdout(Stdio::null())).expect("cat spawns");
    let pid = child.id();
    let kernel = FakeKernel::over(&HostKernel)
        .on_pidfd_open(pid, Ok(crate::child::front_cgroup_tests::pidfd_of(pid)))
        .on_pidfs_ino(pid, Ok(Some(KILLED_INO)));
    (
        child,
        ProcessId::from_parts_for_test(pid, Key::Pidfs(KILLED_INO)),
        kernel,
    )
}

/// Linux sends through the pidfd the identity was proved on, never by the pid's number, which could
/// name another process the instant after the proof. Mutant: "send `kill(2)` by number after the
/// proof": the send route is `Number` and no pidfd step is recorded.
#[skuld::test]
fn a_kill_by_identity_is_sent_through_the_proved_pidfd() {
    use nix::sys::signal::Signal;
    use std::os::unix::process::ExitStatusExt as _;
    let (mut child, id, kernel) = live_child_in_a_table();
    let sends = crate::send_log::Capture::start();
    assert_eq!(
        super::kill_by_identity(&kernel, id, Signal::SIGTERM),
        super::KillOutcome::Terminated
    );
    assert_eq!(
        sends.group_steps(),
        vec![crate::send_log::GroupStep::Member(
            crate::send_log::Route::Pidfd,
            id.pid(),
            libc::SIGTERM
        )]
    );
    assert_eq!(
        child.wait().expect("the child exits").signal(),
        Some(libc::SIGTERM),
        "the signal reached the process the pidfd names"
    );
}

/// A process that was reaped after the proof is gone: the pidfd answers `ESRCH`. Mutant: "`ESRCH` is
/// not attempted".
#[skuld::test]
fn a_kill_by_identity_of_a_process_reaped_after_the_proof_is_already_gone() {
    let (mut child, id, kernel) = live_child_in_a_table();
    drop(child.stdin.take());
    child.wait().expect("the child exits at EOF");
    assert_eq!(
        super::kill_by_identity(&kernel, id, nix::sys::signal::Signal::SIGTERM),
        super::KillOutcome::AlreadyGone
    );
}
