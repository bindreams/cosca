//! `ppid_of`'s two kinds of `Unknown`: the transient fork-in-progress window is re-read until it
//! resolves, and only the persistent sysctl refusal is `Unknown`, also when a walk's candidate is
//! read under a parent. The rows for a candidate and its parent that run on every platform are in
//! `identity::tree_tests`.

use super::{fault, resolve_ppid, PpidRead};
use crate::identity::{Key, ProcessId, Resolved};
use crate::test_child::{live_exiting_member, release_unsignalled};

/// The start key of the record the ppid was read from, as a stated value.
fn key() -> Key {
    Key::for_test(5)
}

/// A scripted read that fails the test, rather than hanging it, if asked for more than `script`.
fn scripted(script: &[PpidRead]) -> (impl FnMut() -> PpidRead + '_, impl Fn() -> usize) {
    let reads = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let counted = reads.clone();
    let read = move || {
        let i = counted.get();
        counted.set(i + 1);
        *script
            .get(i)
            .unwrap_or_else(|| panic!("read #{i} was not scripted: the read was retried"))
    };
    (read, move || reads.get())
}

/// A fork in progress is re-read, with a pause before each re-read that grows with the attempt.
/// Mutant: "`Forking` is `Unknown`" (a busy host's transient window fails every walk).
#[skuld::test]
fn a_fork_in_progress_is_reread_until_it_resolves() {
    let (read, count) = scripted(&[PpidRead::Forking, PpidRead::Forking, PpidRead::Found(7, key())]);
    let mut pauses = Vec::new();
    assert_eq!(resolve_ppid(read, |a| pauses.push(a)), Resolved::Found((7, key())));
    assert_eq!(count(), 3);
    assert_eq!(pauses, [0, 1]);
}

/// The pid exiting mid-fork ends the wait as `Gone`.
#[skuld::test]
fn a_pid_that_exits_while_forking_is_gone() {
    let (read, _) = scripted(&[PpidRead::Forking, PpidRead::Gone]);
    assert_eq!(resolve_ppid(read, |_| {}), Resolved::Gone);
}

/// A fork always finishes, so the wait has no count cap. Mutant: "give up after N re-reads".
#[skuld::test]
fn the_wait_for_a_fork_has_no_count_cap() {
    let mut script = vec![PpidRead::Forking; 100_000];
    script.push(PpidRead::Found(7, key()));
    let (read, count) = scripted(&script);
    assert_eq!(resolve_ppid(read, |_| {}), Resolved::Found((7, key())));
    assert_eq!(count(), 100_001);
}

/// A refused sysctl does not change on a re-read: `Unknown`, read once. Mutant: "a persistent
/// refusal is retried" (the unscripted second read fails the test instead of hanging it).
#[skuld::test]
fn a_refused_sysctl_is_unknown_after_one_read() {
    let (read, count) = scripted(&[PpidRead::Refused]);
    assert_eq!(
        resolve_ppid(read, |_| panic!("a refusal is not waited on")),
        Resolved::Unknown
    );
    assert_eq!(count(), 1);
}

/// A candidate whose record cannot be read for its parent (the sysctl is refused) is `Unknown`,
/// blaming the candidate and not the parent: not `Gone`, which would drop a live process from the
/// walk, and not a match.
///
/// Mutant: `of_ordered_with` reads a refused parent read as `Gone` or as the named parent.
#[skuld::test]
fn a_candidate_whose_parent_read_is_refused_is_unknown() {
    let (child, kid) = live_exiting_member();
    let _forced = fault::force_ppid_reads(kid.pid(), &[PpidRead::Refused]);
    let (read, cause) = ProcessId::of_ordered_with(&crate::identity::HostKernel, kid.pid(), Some(ProcessId::current()));
    release_unsignalled(child);
    assert_eq!(read, Resolved::Unknown);
    assert_eq!(cause.blamed_parent(), None);
}
