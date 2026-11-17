//! `ppid_of`'s two kinds of `Unknown`: the transient fork-in-progress window is re-read until it
//! resolves, and only the persistent sysctl refusal is `Unknown`, also when a walk's candidate is
//! read under a parent; and the pids whose parent number is `0` and not a fork in progress. The rows
//! for a candidate and its parent that run on every platform are in `identity::tree_tests`.

use super::{read_ppid_once, resolve_ppid, trusted_ppid, PpidRead};
use crate::identity::{FakeKernel, HostKernel, Kernel, Key, ProcessId, Resolved};
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
    let script = [PpidRead::Forking, PpidRead::Forking, PpidRead::Found(7, key())];
    let (read, count) = scripted(&script);
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
    // libproc misses (`EPERM`, as for a cross-user process) and the sysctl fallback is refused.
    let kernel = FakeKernel::over(&HostKernel).on_record_refused(kid.pid());
    let parent = Some(ProcessId::current());
    let (read, cause) = ProcessId::of_ordered_with(&kernel, kid.pid(), parent, None, None);
    release_unsignalled(child);
    assert_eq!(read, Resolved::Unknown);
    assert_eq!(cause.blamed_parent(), None);
}

/// A parent number of `0` is a fork in progress for every pid but the two no `fork()` makes: pid 0
/// (`kernel_task`, the kernel itself) and pid 1 (launchd, whose parent is the kernel). Waiting on
/// either would never end.
///
/// Mutants: `trusted_ppid` trusts `0` for pid 1 only, or for pid 0 only, or for every pid.
#[skuld::test]
fn a_zero_parent_is_trusted_only_for_the_kernel_and_launchd() {
    assert_eq!(trusted_ppid(0, 0), Some(0));
    assert_eq!(trusted_ppid(1, 0), Some(0));
    assert_eq!(trusted_ppid(7, 0), None);
    assert_eq!(trusted_ppid(7, 3), Some(3));
}

/// One parent read of launchd (pid 1, parent number `0`) finds its parent `0`, not a fork in
/// progress. One read, so a regression fails by assertion, where `ordered_read` would re-read the
/// `0` forever. Pid 0's rule is `trusted_ppid`'s own row.
///
/// Mutants: `Record::ppid` is `(raw != 0).then_some(raw)`, whatever the pid; `read_ppid_once` judges
/// the record under another pid.
#[skuld::test]
fn one_parent_read_of_launchd_finds_its_parent_zero() {
    let read = read_ppid_once(&HostKernel, 1);
    // Any user can read launchd's record (unsandboxed, as CI's runners are).
    let PpidRead::Found(0, key) = read else {
        panic!("one parent read of launchd must find parent 0, got {read:?}");
    };
    assert_eq!(
        super::start_token(&HostKernel, 1),
        Resolved::Found(key),
        "the parent read's key is launchd's"
    );
}

/// An ordered read waits out a fork-in-progress parent number only when it asks for the parent: one
/// that names none reads the record once, whatever its parent number says, and one that names a parent
/// reads again. The record states parent number `0`, which is a fork in progress for a pid other than
/// 0 and 1. Neither kernel has a host behind it: a read no row states panics.
///
/// Mutants: every ordered read goes through the parent read (the first kernel, with its one row,
/// would read again and panic); the read under a parent trusts the `0` (the candidate is then
/// `Gone`, its parent number not being the parent's).
#[skuld::test]
fn an_ordered_read_reads_the_parent_number_only_when_asked() {
    let (child, kid) = live_exiting_member();
    let me = std::process::id();
    let record = |pid| match HostKernel.bsd_info(pid) {
        Ok(record) => record,
        Err(e) => panic!("the live process {pid} has a record: {e:?}"),
    };
    let forking = || {
        let mut record = record(kid.pid());
        record.pbi_ppid = 0;
        Ok(record)
    };
    let alone_kernel = FakeKernel::new().on_bsd_info(kid.pid(), forking());
    let (alone, _) = ProcessId::of_ordered_with(&alone_kernel, kid.pid(), None, None, None);
    assert!(matches!(alone, Resolved::Found(_)), "{alone:?}");
    // The candidate's two reads (parent number `0`, then the real one), then the proof of the parent.
    let under_kernel = FakeKernel::new()
        .on_bsd_info(kid.pid(), forking())
        .on_bsd_info(kid.pid(), Ok(record(kid.pid())))
        .on_bsd_info(me, Ok(record(me)));
    let parent = Some(ProcessId::current());
    let (under, _) = ProcessId::of_ordered_with(&under_kernel, kid.pid(), parent, None, None);
    release_unsignalled(child);
    assert!(matches!(under, Resolved::Found(_)), "{under:?}");
}

/// A record whose key is not the `expected` one is another process's: `Gone`, with or without a
/// parent named. The record with the expected key is found.
///
/// Mutant: `ordered_read` ignores `expected`.
#[skuld::test]
fn a_record_with_another_key_than_the_expected_one_is_gone() {
    let (child, kid) = live_exiting_member();
    let host = &crate::identity::HostKernel;
    let read = |expected: Key, parent| ProcessId::of_ordered_with(host, kid.pid(), parent, Some(expected), None).0;
    let other = kid.with_other_value().key();
    let found = read(kid.key(), None);
    let gone_alone = read(other, None);
    let gone_under = read(other, Some(ProcessId::current()));
    release_unsignalled(child);
    assert!(matches!(found, Resolved::Found(_)), "{found:?}");
    assert_eq!(gone_alone, Resolved::Gone);
    assert_eq!(gone_under, Resolved::Gone);
}
