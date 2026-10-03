//! `ppid_of`'s two kinds of `Unknown`: the transient fork-in-progress window is re-read until it
//! resolves, and only the persistent sysctl refusal is `Unknown`.

use super::{resolve_ppid, PpidRead};
use crate::identity::Resolved;

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
    let (read, count) = scripted(&[PpidRead::Forking, PpidRead::Forking, PpidRead::Found(7)]);
    let mut pauses = Vec::new();
    assert_eq!(resolve_ppid(read, |a| pauses.push(a)), Resolved::Found(7));
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
    script.push(PpidRead::Found(7));
    let (read, count) = scripted(&script);
    assert_eq!(resolve_ppid(read, |_| {}), Resolved::Found(7));
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
