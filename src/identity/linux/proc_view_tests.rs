use std::io;

use std::os::fd::AsFd;

use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;
use crate::test_groups::{namespaces, Group};

use super::{
    classify_ns_links, classify_status, cross_check_with_init_ns, parse_fdinfo_pid, pidfd_pid_in, proc_view_with,
    PidfdTarget, ProcView, Verdict, ViewUnreadable, UNREADABLE_STATUS_REASON,
};
use crate::identity::{FakeKernel, HostKernel, Kernel, OwnUnreadable, ProcDir, ReadFailure};

/// What `self/ns/pid` yields: its target, `None` for a kernel with no pid namespaces.
type OwnLink = Result<Option<Vec<u8>>, OwnUnreadable>;

fn ns_pid(link: OwnLink) -> impl FnOnce() -> OwnLink {
    move || link
}

fn unreachable_ns_pid() -> OwnLink {
    panic!("self/ns/pid must be consulted only when NSpid is absent")
}

/// An own file's failure at its `openat2`, as the kernel states it.
fn denied(errno: i32) -> OwnUnreadable {
    OwnUnreadable::of(ReadFailure::Open(io::Error::from_raw_os_error(errno)))
}

/// The ordinary view of this test binary, derived independently of `NSpid`: `/proc` is this
/// namespace's exactly when it numbers this namespace's pid 1 as `1`. An outer procfs numbers
/// that init otherwise (its own `1` is its own init, in another namespace), and one that cannot
/// see it prints `0`. Comparing this thread's own ids instead can coincide.
#[skuld::test]
fn proc_view_matches_how_proc_numbers_our_own_init() {
    let dir = ProcDir::open().expect("/proc opens");
    let init = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(1).expect("1 is nonzero"),
        rustix::process::PidfdFlags::empty(),
    )
    .expect("pidfd_open(1)");
    let numbered = pidfd_pid_in(&HostKernel, &dir, init.as_fd()).expect("read pid 1's pidfd fdinfo");
    let view = proc_view_with(&HostKernel);
    assert_eq!(
        matches!(view, ProcView::Same(_)),
        numbered == PidfdTarget::Pid(1),
        "got {view:?}, while /proc numbers this namespace's init {numbered:?}"
    );
}

#[skuld::test]
fn one_nspid_entry_is_same() {
    let verdict = classify_status("Name:\tcosca\nNSpid:\t1234\nState:\tR\n", unreachable_ns_pid);
    assert!(matches!(verdict, Verdict::Same), "got {verdict:?}");
}

#[skuld::test]
fn several_nspid_entries_are_diverged() {
    let verdict = classify_status("NSpid:\t99\t5\t1\n", unreachable_ns_pid);
    assert!(matches!(verdict, Verdict::Diverged), "got {verdict:?}");
}

#[skuld::test]
fn an_empty_nspid_line_is_unassessable() {
    let verdict = classify_status("NSpid:\t\n", unreachable_ns_pid);
    assert!(matches!(verdict, Verdict::Unassessable(_)), "got {verdict:?}");
}

/// A kernel without `CONFIG_PID_NS` has no `NSpid` and no `self/ns/pid`: no namespace to
/// diverge into, so `Same`. Mutant: "an absent NSpid is always Unassessable" (the regression
/// that made every live foreign wait fail on such kernels).
#[skuld::test]
fn no_nspid_and_no_ns_pid_is_same() {
    let verdict = classify_status("Name:\tcosca\nState:\tR\n", ns_pid(Ok(None)));
    assert!(matches!(verdict, Verdict::Same), "got {verdict:?}");
}

/// gVisor: no `NSpid` but pid namespaces exist, so the status file alone cannot decide; the
/// namespace cross-check does, with the link that was read. Mutant: "an absent NSpid is always Same".
#[skuld::test]
fn no_nspid_but_ns_pid_exists_needs_the_cross_check() {
    let verdict = classify_status("Name:\tcosca\n", ns_pid(Ok(Some(b"pid:[1]".to_vec()))));
    assert!(
        matches!(&verdict, Verdict::NoNspid(own) if own == b"pid:[1]"),
        "got {verdict:?}"
    );
}

#[skuld::test]
fn no_nspid_and_an_unreadable_ns_pid_is_unassessable_with_the_cause() {
    let Verdict::Unassessable(why) = classify_status("Name:\tcosca\n", ns_pid(Err(denied(libc::EACCES)))) else {
        panic!("expected Unassessable");
    };
    assert!(why.source.is_some(), "the OS error must be carried: {why}");
    assert!(why.to_string().contains("could not be checked"), "{why}");
}

#[skuld::test]
fn fdinfo_pid_is_parsed() {
    assert_eq!(
        parse_fdinfo_pid("pos:\t0\nflags:\t02000000\nPid:\t4321\nNSpid:\t4321\n"),
        Some(PidfdTarget::Pid(4321))
    );
    assert_eq!(parse_fdinfo_pid("Pid:\t0\n"), Some(PidfdTarget::Pid(0)));
    assert_eq!(parse_fdinfo_pid("pos:\t0\n"), None);
    assert_eq!(parse_fdinfo_pid("Pid:\tx\n"), None);
}

/// The kernel prints `Pid: -1` when the pidfd's target was reaped (`pidfd_show_fdinfo`). Mutant:
/// "a negative `Pid:` is unparseable".
#[skuld::test]
fn fdinfo_pid_minus_one_is_reaped() {
    assert_eq!(parse_fdinfo_pid("Pid:\t-1\n"), Some(PidfdTarget::Reaped));
}

/// Only `-1` is the kernel's reaped marker. Mutant: "any negative is Reaped".
#[skuld::test]
fn fdinfo_pid_other_negatives_are_unparseable() {
    assert_eq!(parse_fdinfo_pid("Pid:\t-2\n"), None);
    assert_eq!(parse_fdinfo_pid("Pid:\t-4294967296\n"), None);
}

/// Mutant: "truncate to u32" would turn 2^32 into pid 0.
#[skuld::test]
fn fdinfo_pid_beyond_u32_is_unparseable() {
    assert_eq!(parse_fdinfo_pid("Pid:\t4294967296\n"), None);
    assert_eq!(parse_fdinfo_pid("Pid:\t4294967295\n"), Some(PidfdTarget::Pid(u32::MAX)));
}

#[skuld::test]
fn fdinfo_pid_with_an_empty_value_is_unparseable() {
    assert_eq!(parse_fdinfo_pid("Pid:\n"), None);
    assert_eq!(parse_fdinfo_pid("Pid:\t\n"), None);
}

/// Only the exact `Pid:` key counts: `NSpid:` and `Pidfd:`-like keys carry other numbers. Mutant:
/// "match any line containing `Pid:`".
#[skuld::test]
fn fdinfo_pid_ignores_similarly_prefixed_keys() {
    assert_eq!(parse_fdinfo_pid("NSpid:\t9\nPidx:\t8\nxPid:\t7\n"), None);
    assert_eq!(
        parse_fdinfo_pid("NSpid:\t9\nPidx:\t8\nPid:\t3\n"),
        Some(PidfdTarget::Pid(3))
    );
}

/// A `self/status` that is not UTF-8 is a view that cannot be read, not a panic. Mutant:
/// "`utf8` unwraps".
#[skuld::test]
fn proc_view_with_is_unassessable_for_a_status_that_is_not_utf8() {
    let kernel = FakeKernel::over(&HostKernel).on_read("self/status", Ok(&[0xff]));
    match proc_view_with(&kernel) {
        ProcView::Unassessable(why) => assert!(why.reason.contains(UNREADABLE_STATUS_REASON), "{why}"),
        other => panic!("got {other:?}"),
    }
}

/// Each own file that establishes the view hands its refusal to the view, as a refused `/proc` open
/// does: `self/status`, `self/ns/pid`. A `read(2)` failure of `self/status` is
/// no refusal, though its errno is in the table. Mutant: "a read that establishes the view and is
/// refused is only an unreadable view"; "`read(2)`'s errno is the `openat2`'s".
#[skuld::test]
fn a_refused_own_file_is_a_refused_openat2_of_the_view() {
    let refusal_of = |why: &ViewUnreadable| {
        why.refusal()
            .map(|refusal| crate::error::first_os_code(&refusal.cause()))
    };

    let kernel = FakeKernel::over(&HostKernel).on_read("self/status", Err(libc::EPERM));
    let ProcView::Unassessable(why) = proc_view_with(&kernel) else {
        panic!("a status that cannot be read is Unassessable");
    };
    assert_eq!(refusal_of(&why), Some(Some(libc::EPERM)), "self/status");

    let Verdict::Unassessable(why) = classify_status("Name:\tcosca\n", ns_pid(Err(denied(libc::ENOSYS)))) else {
        panic!("expected Unassessable");
    };
    assert_eq!(refusal_of(&why), Some(Some(libc::ENOSYS)), "self/ns/pid");

    let kernel = FakeKernel::over(&HostKernel).on_read_failing_after_open("self/status", libc::EPERM);
    let ProcView::Unassessable(why) = proc_view_with(&kernel) else {
        panic!("a status that cannot be read is Unassessable");
    };
    assert!(why.refusal().is_none(), "self/status read(2): {why:?}");
    assert_eq!(
        why.source.and_then(|e| e.raw_os_error()),
        Some(libc::EPERM),
        "the failure's own errno is the source"
    );
}

/// The verdict of the namespace-link cross-check over `kernel`, with this process's own link read and
/// `kernel`'s rows answering for pid 1. Every call with no row panics.
fn init_link_verdict(kernel: FakeKernel<'_>) -> Verdict {
    let dir = HostKernel.open_proc().expect("/proc opens");
    cross_check_with_init_ns(&kernel, &dir, b"pid:[4026531836]".to_vec())
}

/// Pid 1 is a foreign pid to most readers, so its `1/ns/pid` follows the pid-file rule, not the
/// own-file one: `EPERM` is `hidepid`'s answer when the checked directory still reads `self/stat`
/// (the view is unestablished, and no refusal), unknown when the re-check fails without refusing, and
/// a refusal only when the re-check is refused; an `openat2` errno in the table is a refusal as it
/// stands. Mutant: "`1/ns/pid`'s `EPERM` is a refusal with no re-check" (the own-file rule).
#[skuld::test]
fn pid_1s_namespace_link_follows_the_pid_file_rule() {
    let cause_of = |verdict: Verdict| match verdict {
        Verdict::Unassessable(why) => why,
        other => panic!("expected Unassessable, got {other:?}"),
    };

    let hidden = cause_of(init_link_verdict(
        FakeKernel::new()
            .on_read("1/ns/pid", Err(libc::EPERM))
            .on_read("self/stat", Ok(b"")),
    ));
    assert!(
        hidden.refusal().is_none(),
        "EPERM with a re-check that answers: {hidden:?}"
    );
    assert_eq!(crate::error::first_os_code(&hidden), Some(libc::EPERM));
    assert!(hidden.reason.contains("1/ns/pid"), "{hidden}");
    assert!(
        crate::error::said(&hidden).contains("hidden"),
        "pid 1's verdict is kept: {}",
        crate::error::said(&hidden)
    );

    let unknown = cause_of(init_link_verdict(
        FakeKernel::new()
            .on_read("1/ns/pid", Err(libc::EPERM))
            .on_read("self/stat", Err(libc::EMFILE)),
    ));
    assert!(unknown.refusal().is_none(), "EPERM with a failed re-check: {unknown:?}");
    assert_eq!(crate::error::first_os_code(&unknown), Some(libc::EMFILE));
    assert!(
        crate::error::said(&unknown).contains("re-check of self/stat failed"),
        "{}",
        crate::error::said(&unknown)
    );

    let refused = cause_of(init_link_verdict(
        FakeKernel::new()
            .on_read("1/ns/pid", Err(libc::EPERM))
            .on_read("self/stat", Err(libc::ENOSYS)),
    ));
    let refusal = refused.refusal().expect("a refused re-check is a refusal");
    assert_eq!(crate::error::first_os_code(&refusal.cause()), Some(libc::ENOSYS));
    let chain = crate::error::said(refused.source.as_ref().expect("a refusal's chain is the view's source"));
    for errno in [libc::ENOSYS, libc::EPERM] {
        let said = io::Error::from_raw_os_error(errno).to_string();
        assert!(chain.contains(&said), "the source names {said:?}: {chain}");
    }

    let refused = cause_of(init_link_verdict(
        FakeKernel::new().on_read("1/ns/pid", Err(libc::ENODEV)),
    ));
    let refusal = refused.refusal().expect("an openat2 errno in the table is a refusal");
    assert_eq!(crate::error::first_os_code(&refusal.cause()), Some(libc::ENODEV));

    let failed = cause_of(init_link_verdict(
        FakeKernel::new().on_read_failing_after_open("1/ns/pid", libc::ENOSYS),
    ));
    assert!(
        failed.refusal().is_none(),
        "a readlinkat errno is no refusal: {failed:?}"
    );
}

/// Pid 1's link that the `openat2` does not show says what the pid-file rule says of it: gone
/// (`ESRCH`) or hidden (`ENOENT`, `EACCES`); any other errno says nothing about pid 1. None is a
/// refusal. Mutant: "every failure of `1/ns/pid` is a bare errno".
#[skuld::test]
fn pid_1s_namespace_link_that_the_open_does_not_show_says_why() {
    let rows = [
        (libc::ENOENT, "hidden"),
        (libc::EACCES, "hidden"),
        (libc::ESRCH, "exited"),
        (libc::EMFILE, "1/ns/pid could not be read"),
    ];
    for (errno, says) in rows {
        let Verdict::Unassessable(why) = init_link_verdict(FakeKernel::new().on_read("1/ns/pid", Err(errno))) else {
            panic!("{errno}: expected Unassessable");
        };
        // The words are the layer below the view's reason, which already says "could not be read".
        let source = why.source.as_ref().expect("pid 1's verdict is the view's source");
        let said = crate::error::said(source);
        assert!(why.refusal().is_none(), "{errno}: {why:?}");
        assert!(said.contains(says), "{errno}: {said}");
        assert_eq!(crate::error::first_os_code(&why), Some(errno), "{errno}: {said}");
    }
}

/// `self/ns/pid`'s existence is asked of the kernel like every other read: an `openat2` the kernel
/// refuses leaves the view refused, an `openat2` that finds no link is a kernel with no pid namespaces
/// (`Same`), and a failure of the `readlinkat` is no refusal and no such kernel, whatever its errno:
/// an `ENOENT` after the open is a link whose task has no namespace, which says nothing of the
/// kernel. Mutant: "the existence check opens `/proc` by itself"; "any `ENOENT` is no pid namespaces".
#[skuld::test]
fn self_ns_pid_is_asked_of_the_kernel() {
    let no_nspid = || {
        FakeKernel::over(&HostKernel)
            .on_read("self/status", Ok(b"Name:\tcosca\n"))
            .on_read("1/ns/pid", Ok(b"pid:[4026531836]"))
    };

    let kernel = no_nspid().on_read("self/ns/pid", Err(libc::EPERM));
    let ProcView::Unassessable(why) = proc_view_with(&kernel) else {
        panic!("a refused existence check is Unassessable");
    };
    let refusal = why.refusal().expect("an openat2 errno in the table is a refusal");
    assert_eq!(crate::error::first_os_code(&refusal.cause()), Some(libc::EPERM));

    let kernel = no_nspid().on_read("self/ns/pid", Err(libc::ENOENT));
    assert!(
        matches!(proc_view_with(&kernel), ProcView::Same(_)),
        "no self/ns/pid is a kernel with no pid namespaces"
    );

    for errno in [libc::EPERM, libc::ENOENT] {
        let kernel = no_nspid().on_read_failing_after_open("self/ns/pid", errno);
        let ProcView::Unassessable(why) = proc_view_with(&kernel) else {
            panic!("{errno}: a failed existence check is Unassessable, never a view of no pid namespaces");
        };
        assert!(
            why.refusal().is_none(),
            "{errno}: a readlinkat errno is no refusal: {why:?}"
        );
        assert_eq!(crate::error::first_os_code(&why), Some(errno), "{errno}: {why:?}");
    }
}

/// With no `NSpid`, the link that showed `self/ns/pid` exists is this process's pid namespace, which
/// the cross-check compares with pid 1's: it is not read a second time as `thread-self/ns/pid`. The
/// rows name a namespace this process is not in, so a read of any other own link would differ.
/// Mutant: "the cross-check reads the own link again".
#[skuld::test]
fn the_link_that_shows_self_ns_pid_exists_is_the_own_link_of_the_cross_check() {
    let own = b"pid:[4026539999]";
    let no_nspid = |init: &'static [u8]| {
        FakeKernel::over(&HostKernel)
            .on_read("self/status", Ok(b"Name:\tcosca\n"))
            .on_read("self/ns/pid", Ok(own))
            .on_read("1/ns/pid", Ok(init))
    };
    assert!(matches!(proc_view_with(&no_nspid(own)), ProcView::Same(_)));
    assert!(matches!(
        proc_view_with(&no_nspid(b"pid:[4026539998]")),
        ProcView::Diverged
    ));
}

// Namespace-link cross-check (no NSpid) =====

const NO_NSPID: &str = "Name:\tcosca\nState:\tR (running)\n";

fn link<E>(target: &str) -> Result<Vec<u8>, E> {
    Ok(target.as_bytes().to_vec())
}

fn own(target: &str) -> Vec<u8> {
    target.as_bytes().to_vec()
}

#[skuld::test]
fn a_procfs_whose_pid_1_shares_this_processs_namespace_is_same() {
    let verdict = classify_ns_links(own("pid:[4026531836]"), || link("pid:[4026531836]"));
    assert!(matches!(verdict, Verdict::Same), "got {verdict:?}");
}

/// Mutant: "any two readable links are Same".
#[skuld::test]
fn a_procfs_whose_pid_1_is_in_another_namespace_is_diverged() {
    let verdict = classify_ns_links(own("pid:[4026532831]"), || link("pid:[4026532830]"));
    assert!(matches!(verdict, Verdict::Diverged), "got {verdict:?}");
}

#[skuld::test]
fn an_unreadable_pid_1_link_is_unassessable_with_the_cause() {
    let Verdict::Unassessable(why) = classify_ns_links(own("pid:[4026531836]"), || Err(denied(libc::EACCES).into()))
    else {
        panic!("expected Unassessable");
    };
    assert!(why.reason.contains("1/ns/pid"), "{why}");
    assert_eq!(why.source.and_then(|e| e.raw_os_error()), Some(libc::EACCES));
}

/// Two equal non-namespace targets (say, both empty) prove nothing. Mutant: "compare the raw
/// targets".
#[skuld::test]
fn a_link_that_names_no_pid_namespace_is_unassessable() {
    for (own_link, init) in [("", ""), ("net:[1]", "net:[1]"), ("pid:[1]", "pid:[1")] {
        let verdict = classify_ns_links(own(own_link), || link(init));
        assert!(
            matches!(verdict, Verdict::Unassessable(_)),
            "{own_link:?} {init:?}: got {verdict:?}"
        );
    }
}

// pidfd fdinfo =====

/// A pidfd whose target has been reaped prints `Pid: -1` (real kernel, no forcing).
#[skuld::test]
fn the_fdinfo_of_a_reaped_targets_pidfd_is_reaped() {
    let (mut child, pidfd) = spawn_exited_child_with_pidfd();
    child.wait().expect("reap the child");
    let dir = ProcDir::open().expect("/proc opens");
    let got = pidfd_pid_in(&HostKernel, &dir, pidfd.as_fd());
    assert!(matches!(got, Ok(PidfdTarget::Reaped)), "got {got:?}");
}

/// Before the reap the same pidfd names the child under its pid.
#[skuld::test]
fn the_fdinfo_of_an_unreaped_targets_pidfd_names_its_pid() {
    let (mut child, pidfd) = spawn_exited_child_with_pidfd();
    let dir = ProcDir::open().expect("/proc opens");
    let got = pidfd_pid_in(&HostKernel, &dir, pidfd.as_fd());
    let pid = child.id();
    child.wait().expect("reap the child");
    assert!(
        matches!(got, Ok(PidfdTarget::Pid(p)) if p == pid),
        "got {got:?}, pid {pid}"
    );
}

/// The pidfd's fdinfo is read at `thread-self/fdinfo/<fd>`, and one with no `Pid:` line is an
/// unreadable view.
#[skuld::test]
fn pidfd_pid_in_reads_thread_self_fdinfo_and_names_a_missing_pid_line() {
    use std::os::fd::AsRawFd as _;

    let (mut child, pidfd) = spawn_exited_child_with_pidfd();
    let dir = ProcDir::open().expect("/proc opens");
    let path = format!("thread-self/fdinfo/{}", pidfd.as_raw_fd());
    // A pid the real fdinfo never gives this fd, so a read of any other path cannot match.
    let stated_pid = child.id() + 1;
    let stated = FakeKernel::over(&HostKernel).on_read(&path, Ok(format!("Pid:\t{stated_pid}\n").as_bytes()));
    let got = pidfd_pid_in(&stated, &dir, pidfd.as_fd());
    let no_pid = FakeKernel::over(&HostKernel).on_read(&path, Ok(b"pos:\t0\n"));
    let err = pidfd_pid_in(&no_pid, &dir, pidfd.as_fd()).expect_err("no Pid line");
    child.wait().expect("reap the child");
    assert!(matches!(got, Ok(PidfdTarget::Pid(p)) if p == stated_pid), "got {got:?}");
    assert!(err.reason.contains("no parseable Pid line"), "{err}");
}

/// The fdinfo read is an `openat2` through the view, so a refusal of it is the view's `openat2`
/// refusal, with the errno as its source; a `read(2)` failure of it is no refusal. Mutant: "a failed
/// fdinfo read is only an unreadable view"; "`read(2)`'s errno is the `openat2`'s".
#[skuld::test]
fn a_refused_fdinfo_read_is_a_refused_openat2() {
    use std::os::fd::AsRawFd as _;

    let (mut child, pidfd) = spawn_exited_child_with_pidfd();
    let dir = ProcDir::open().expect("/proc opens");
    let path = format!("thread-self/fdinfo/{}", pidfd.as_raw_fd());

    let kernel = FakeKernel::over(&HostKernel).on_read(&path, Err(libc::EPERM));
    let why = pidfd_pid_in(&kernel, &dir, pidfd.as_fd()).expect_err("an unreadable fdinfo");
    let got = why
        .refusal()
        .map(|refusal| crate::error::first_os_code(&refusal.cause()));
    assert_eq!(got, Some(Some(libc::EPERM)));

    let kernel = FakeKernel::over(&HostKernel).on_read_failing_after_open(&path, libc::EPERM);
    let why = pidfd_pid_in(&kernel, &dir, pidfd.as_fd()).expect_err("an unreadable fdinfo");
    assert!(why.refusal().is_none(), "{why:?}");
    assert_eq!(why.source.and_then(|e| e.raw_os_error()), Some(libc::EPERM));
    child.wait().expect("reap the child");
}

fn spawn_exited_child_with_pidfd() -> (std::process::Child, rustix::fd::OwnedFd) {
    let child = crate::test_spawn::spawn(&mut std::process::Command::new("true")).expect("spawn true");
    let pid = rustix::process::Pid::from_raw(child.id() as i32).expect("child pid is nonzero");
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open");
    (child, pidfd)
}

/// A thread that unshared its fd table has fds the leader's `self/fdinfo` does not know; the
/// fdinfo must be read through `thread-self`. Mutant: "read `self/fdinfo`" — the leader's table
/// has no such fd (or a different file at that number).
///
/// In the namespaces group: `unshare` is refused by default container seccomp profiles.
#[skuld::test]
fn namespaces_the_fdinfo_is_read_through_the_calling_threads_fd_table(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_fdinfo_after_unshare_files));
}

#[skuld::test]
fn fixture_fdinfo_after_unshare_files() {
    if !ns::is_child() {
        return;
    }
    let dir = ProcDir::open().expect("/proc opens");
    let own = rustix::process::Pid::from_raw(std::process::id() as i32).expect("own pid");
    let got = std::thread::scope(|s| {
        s.spawn(|| {
            // SAFETY: this thread is fresh; it opens the pidfd after the unshare and hands nothing
            // to another thread.
            unsafe { rustix::thread::unshare_unsafe(rustix::thread::UnshareFlags::FILES) }.expect("unshare(FILES)");
            let pidfd = rustix::process::pidfd_open(own, rustix::process::PidfdFlags::empty()).expect("pidfd_open");
            pidfd_pid_in(&HostKernel, &dir, pidfd.as_fd())
        })
        .join()
        .expect("thread")
    });
    assert!(
        matches!(got, Ok(PidfdTarget::Pid(p)) if p == std::process::id()),
        "got {got:?}"
    );
}

// No-NSpid cross-check against real pid namespaces =====

/// No `NSpid`, and `/proc` is an outer pid namespace's procfs that numbers the calling thread
/// exactly as `gettid()` does: the numbers agree, the namespaces do not. `Diverged`.
///
/// Mutant: "compare `thread-self/stat`'s id with `gettid()`" — the coincidence reads as `Same`.
#[skuld::test]
fn namespaces_no_nspid_under_an_outer_procfs_numbering_this_thread_alike_is_diverged(
    #[fixture(namespaces)] _group: &Group,
) {
    ns::run(fixture_path!(fixture_coinciding_tid_driver));
}

#[skuld::test]
fn fixture_coinciding_tid_driver() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_coinciding_tid_outer_init));
}

/// Pid 1 of a fresh namespace P with P's own procfs on `/proc`; its next child is pid 1 of a
/// namespace C below P and keeps P's procfs. P holds only this fixture chain, so nothing else
/// allocates pids in it.
#[skuld::test]
fn fixture_coinciding_tid_outer_init() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    ns::enter_private_mount_ns();
    ns::mount_proc(std::path::Path::new("/proc"));
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_coinciding_tid_inner));
}

#[skuld::test]
fn fixture_coinciding_tid_inner() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    // P's last allocation is this process's latest thread; point C's cursor at the same number so
    // the next thread gets one number in both namespaces.
    let last_in_proc = std::thread::spawn(ns::tid_in_proc).join().expect("probe thread");
    ns::set_last_pid(last_in_proc);
    let view = std::thread::spawn(|| {
        let tid = rustix::thread::gettid().as_raw_nonzero().get() as u32;
        assert_eq!(
            ns::tid_in_proc(),
            tid,
            "precondition: /proc must number this thread as gettid() does"
        );
        proc_view_with(&FakeKernel::over(&HostKernel).on_read("self/status", Ok(NO_NSPID.as_bytes())))
    })
    .join()
    .expect("verdict thread");
    assert!(matches!(view, ProcView::Diverged), "got {view:?}");
}

/// No `NSpid`, and `/proc` is this namespace's own procfs: `Same`. A process that cannot read the
/// procfs's pid 1 namespace link (here a non-dumpable `nobody`, against a root pid 1) is
/// `Unassessable`, naming that link: its own link it still reads.
///
/// Mutants: "an absent NSpid with namespaces present is Unassessable" (the first half);
/// "compare `thread-self/stat`'s id with `gettid()`" (the second: it needs no permission, so it
/// answers `Same`).
#[skuld::test]
fn namespaces_no_nspid_under_this_namespaces_own_procfs_is_same(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_own_procfs_driver));
}

#[skuld::test]
fn fixture_own_procfs_driver() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_own_procfs_init));
}

#[skuld::test]
fn fixture_own_procfs_init() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    ns::enter_private_mount_ns();
    ns::mount_proc(std::path::Path::new("/proc"));
    let view = proc_view_with(&FakeKernel::over(&HostKernel).on_read("self/status", Ok(NO_NSPID.as_bytes())));
    assert!(matches!(view, ProcView::Same(_)), "got {view:?}");
    ns::run_dropping_to_nobody(fixture_path!(fixture_own_procfs_unprivileged));
}

#[skuld::test]
fn fixture_own_procfs_unprivileged() {
    if !ns::is_child() {
        return;
    }
    ns::drop_to_nobody();
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable).expect("PR_SET_DUMPABLE 0");
    match proc_view_with(&FakeKernel::over(&HostKernel).on_read("self/status", Ok(NO_NSPID.as_bytes()))) {
        ProcView::Unassessable(why) => {
            assert!(why.reason.contains("1/ns/pid"), "{why}");
            // The `readlinkat`'s `EACCES` is ptrace denied: pid 1 is hidden from this reader, and the
            // errno is below that.
            assert!(
                crate::error::said(why.source.as_ref().expect("a source")).contains("hidden"),
                "{why}"
            );
            assert_eq!(crate::error::first_os_code(&why), Some(libc::EACCES), "{why}");
        }
        other => panic!("an unreadable pid 1 namespace link must be Unassessable, got {other:?}"),
    }
}

/// The OS error behind an unusable view is its `source()`; a view with none has no source.
#[skuld::test]
fn an_unusable_view_has_its_os_error_as_its_source() {
    let with = ViewUnreadable::new("boom", Some(io::Error::from_raw_os_error(libc::EIO)));
    let source = std::error::Error::source(&with).expect("a view with an OS error has a source");
    assert_eq!(
        source.downcast_ref::<io::Error>().and_then(io::Error::raw_os_error),
        Some(libc::EIO)
    );
    assert!(std::error::Error::source(&ViewUnreadable::new("boom", None)).is_none());
}

/// An unusable view says its reason and not the OS error behind it, which is its `source()`.
#[skuld::test]
fn an_unusable_view_says_its_reason_and_not_its_os_error() {
    let why = ViewUnreadable::new("boom", Some(io::Error::from_raw_os_error(libc::EIO)));
    assert_eq!(why.to_string(), "boom");
}

/// `into_dir` yields the directory of a `Same` view and names the cause of any other.
#[skuld::test]
fn into_dir_names_why_a_view_is_not_usable() {
    let same = ProcView::Same(ProcDir::open().expect("/proc opens"));
    assert!(same.into_dir().is_ok());
    let diverged = ProcView::Diverged.into_dir().expect_err("diverged");
    assert!(diverged.reason.contains("outer pid namespace"), "{diverged}");
    let why = ViewUnreadable::new("boom", None);
    let unassessable = ProcView::Unassessable(why).into_dir().expect_err("unassessable");
    assert_eq!(unassessable.reason, "boom");
}
