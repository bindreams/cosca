//! `ppid_of`'s two kinds of `Unknown`: the transient fork-in-progress window is re-read until it
//! resolves, and only the persistent sysctl refusal is `Unknown`.

use super::{resolve_ppid, PpidRead};
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

fn ordered_under(pid: u32, parent: ProcessId) -> Resolved<(ProcessId, crate::identity::OrderKey)> {
    ProcessId::of_ordered_with(&crate::identity::HostKernel, pid, Some(parent)).0
}

/// A live process that did not fork the candidate is not its parent, though it is a real process
/// holding a real pid: the candidate's own record is read, not the listing's claim.
///
/// Mutant: `of_ordered_with` ignores `parent` on macOS.
#[skuld::test]
fn a_candidate_is_gone_under_a_parent_that_did_not_fork_it() {
    let (x_child, x) = live_exiting_member();
    let (y_child, y) = live_exiting_member();
    let read = ordered_under(y.pid(), x);
    release_unsignalled(y_child);
    release_unsignalled(x_child);
    assert_eq!(read, Resolved::Gone);
}

/// The record names the right parent pid, but another process holds it: the proof of the parent
/// after the read fails.
///
/// Mutant: the parent is not proved again after the candidate's read.
#[skuld::test]
fn a_candidate_is_gone_under_the_right_parent_pid_with_another_key() {
    let (child, kid) = live_exiting_member();
    let read = ordered_under(kid.pid(), ProcessId::current().with_other_value());
    release_unsignalled(child);
    assert_eq!(read, Resolved::Gone);
}

/// The real parent is accepted, with the id and order key of the record that named it.
///
/// Mutant: the parent comparison rejects the real parent, or the id is not the record's key.
#[skuld::test]
fn a_candidate_is_found_under_its_real_parent() {
    let (child, kid) = live_exiting_member();
    let read = ordered_under(kid.pid(), ProcessId::current());
    release_unsignalled(child);
    let Resolved::Found((id, order)) = read else {
        panic!("a child of this process is found under it, got {read:?}");
    };
    assert_eq!(id, kid);
    assert_eq!(order, crate::identity::OrderKey::for_test(kid.key().raw()));
}
