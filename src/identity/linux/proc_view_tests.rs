use std::io;

use std::os::fd::AsFd;

use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;

use super::fault::{force_proc_view_once, force_status_once, ForcedView};
use super::{
    classify_ns_links, classify_status, collect_pids, parse_fdinfo_pid, pidfd_pid_in_view, proc_view, PidfdTarget,
    ProcDir, ProcView, Verdict, ViewUnreadable,
};

fn ns_pid(exists: io::Result<bool>) -> impl FnOnce() -> io::Result<bool> {
    move || exists
}

fn unreachable_ns_pid() -> io::Result<bool> {
    panic!("self/ns/pid must be consulted only when NSpid is absent")
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
    let numbered = pidfd_pid_in_view(&dir, init.as_fd()).expect("read pid 1's pidfd fdinfo");
    let view = proc_view();
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
    let verdict = classify_status("Name:\tcosca\nState:\tR\n", ns_pid(Ok(false)));
    assert!(matches!(verdict, Verdict::Same), "got {verdict:?}");
}

/// gVisor: no `NSpid` but pid namespaces exist, so the status file alone cannot decide; the
/// stat cross-check does. Mutant: "an absent NSpid is always Same".
#[skuld::test]
fn no_nspid_but_ns_pid_exists_needs_the_cross_check() {
    let verdict = classify_status("Name:\tcosca\n", ns_pid(Ok(true)));
    assert!(matches!(verdict, Verdict::NoNspid), "got {verdict:?}");
}

#[skuld::test]
fn no_nspid_and_an_unreadable_ns_pid_is_unassessable_with_the_cause() {
    let Verdict::Unassessable(why) = classify_status(
        "Name:\tcosca\n",
        ns_pid(Err(io::Error::from_raw_os_error(libc::EACCES))),
    ) else {
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

/// A forced `Same` still opens the real `/proc`, so the dirfd it carries is usable.
#[skuld::test]
fn a_forced_same_view_carries_the_real_proc_dirfd() {
    let forced = force_proc_view_once(ForcedView::Same);
    let ProcView::Same(dir) = proc_view() else {
        panic!("a forced Same must be Same");
    };
    drop(forced);
    let status = dir.read_to_string("self/status").expect("read through the dirfd");
    assert!(status.contains("Name:"), "{status}");
}

/// The forced seam overrides the real read exactly once, then falls back to it.
#[skuld::test]
fn a_forced_view_is_consumed_once() {
    let forced = force_proc_view_once(ForcedView::Diverged);
    assert!(matches!(proc_view(), ProcView::Diverged));
    assert!(
        matches!(proc_view(), ProcView::Same(_)),
        "a second call must reach the real read again"
    );
    drop(forced);
}

/// The guard disarms on drop even if the forced view was never consumed.
#[skuld::test]
fn a_forced_view_disarms_on_drop_even_if_unconsumed() {
    drop(force_proc_view_once(ForcedView::Unassessable));
    assert!(
        matches!(proc_view(), ProcView::Same(_)),
        "the forced view must not survive an unconsumed drop"
    );
}

// Checked /proc dirfd =====

#[skuld::test]
fn the_proc_dir_reads_a_file_beneath_it() {
    let status = ProcDir::open()
        .expect("/proc opens")
        .read_to_string("thread-self/status")
        .expect("read");
    assert!(status.contains("Name:"), "{status}");
}

/// A path that leaves the directory it is opened under is refused. Mutant: "plain `openat`
/// without `RESOLVE_BENEATH`" — `..` reaches `/`.
#[skuld::test]
fn the_proc_dir_refuses_a_path_that_climbs_out_of_it() {
    let dir = ProcDir::open().expect("/proc opens");
    let err = dir.read("../etc/passwd").expect_err("must not leave /proc");
    assert_eq!(err.raw_os_error(), Some(libc::EXDEV), "{err}");
}

/// An absolute path names another tree entirely. Mutant: "no `RESOLVE_BENEATH`" — the path
/// resolves from the root, and `NO_XDEV` alone allows it (the root filesystem is one mount).
#[skuld::test]
fn the_proc_dir_refuses_an_absolute_path() {
    let dir = ProcDir::open().expect("/proc opens");
    let err = dir.read("/etc/passwd").expect_err("must not leave /proc");
    assert_eq!(err.raw_os_error(), Some(libc::EXDEV), "{err}");
}

/// A magic link (`self/exe`, `self/fd/N`) jumps out of the tree, so it is refused. Mutant:
/// "no `RESOLVE_NO_MAGICLINKS`".
#[skuld::test]
fn the_proc_dir_refuses_a_magic_link() {
    let dir = ProcDir::open().expect("/proc opens");
    let err = dir.read("self/exe").expect_err("a magic link must not be followed");
    assert_eq!(err.raw_os_error(), Some(libc::ELOOP), "{err}");
}

// Namespace-link cross-check (no NSpid) =====

const NO_NSPID: &str = "Name:\tcosca\nState:\tR (running)\n";

fn link(target: &str) -> io::Result<Vec<u8>> {
    Ok(target.as_bytes().to_vec())
}

#[skuld::test]
fn a_procfs_whose_pid_1_shares_this_threads_namespace_is_same() {
    let verdict = classify_ns_links(link("pid:[4026531836]"), || link("pid:[4026531836]"));
    assert!(matches!(verdict, Verdict::Same), "got {verdict:?}");
}

/// Mutant: "any two readable links are Same".
#[skuld::test]
fn a_procfs_whose_pid_1_is_in_another_namespace_is_diverged() {
    let verdict = classify_ns_links(link("pid:[4026532831]"), || link("pid:[4026532830]"));
    assert!(matches!(verdict, Verdict::Diverged), "got {verdict:?}");
}

#[skuld::test]
fn an_unreadable_pid_1_link_is_unassessable_with_the_cause() {
    let Verdict::Unassessable(why) = classify_ns_links(link("pid:[4026531836]"), || {
        Err(io::Error::from_raw_os_error(libc::EACCES))
    }) else {
        panic!("expected Unassessable");
    };
    assert!(why.reason.contains("1/ns/pid"), "{why}");
    assert_eq!(why.source.and_then(|e| e.raw_os_error()), Some(libc::EACCES));
}

/// An unreadable own link is reported as such, and the pid 1 link is then not read.
#[skuld::test]
fn an_unreadable_own_link_is_unassessable_without_reading_pid_1() {
    let Verdict::Unassessable(why) = classify_ns_links(Err(io::Error::from_raw_os_error(libc::ENOENT)), || {
        panic!("pid 1's link must not be read once the own link failed")
    }) else {
        panic!("expected Unassessable");
    };
    assert!(why.reason.contains("thread-self/ns/pid"), "{why}");
}

/// Two equal non-namespace targets (say, both empty) prove nothing. Mutant: "compare the raw
/// targets".
#[skuld::test]
fn a_link_that_names_no_pid_namespace_is_unassessable() {
    for (own, init) in [("", ""), ("net:[1]", "net:[1]"), ("pid:[1]", "pid:[1")] {
        let verdict = classify_ns_links(link(own), || link(init));
        assert!(
            matches!(verdict, Verdict::Unassessable(_)),
            "{own:?} {init:?}: got {verdict:?}"
        );
    }
}

/// The real links through the real `/proc` read as pid namespace links.
#[skuld::test]
fn this_threads_own_namespace_link_reads_through_the_proc_dir() {
    let dir = ProcDir::open().expect("/proc opens");
    let own = dir.read_link("thread-self/ns/pid").expect("read own link");
    assert!(own.starts_with(b"pid:["), "{:?}", String::from_utf8_lossy(&own));
}

// pidfd fdinfo =====

/// A pidfd whose target has been reaped prints `Pid: -1` (real kernel, no forcing).
#[skuld::test]
fn the_fdinfo_of_a_reaped_targets_pidfd_is_reaped() {
    let (mut child, pidfd) = spawn_exited_child_with_pidfd();
    child.wait().expect("reap the child");
    let dir = ProcDir::open().expect("/proc opens");
    let got = pidfd_pid_in_view(&dir, pidfd.as_fd());
    assert!(matches!(got, Ok(PidfdTarget::Reaped)), "got {got:?}");
}

/// Before the reap the same pidfd names the child under its pid.
#[skuld::test]
fn the_fdinfo_of_an_unreaped_targets_pidfd_names_its_pid() {
    let (mut child, pidfd) = spawn_exited_child_with_pidfd();
    let dir = ProcDir::open().expect("/proc opens");
    let got = pidfd_pid_in_view(&dir, pidfd.as_fd());
    let pid = child.id();
    child.wait().expect("reap the child");
    assert!(
        matches!(got, Ok(PidfdTarget::Pid(p)) if p == pid),
        "got {got:?}, pid {pid}"
    );
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
fn namespaces_the_fdinfo_is_read_through_the_calling_threads_fd_table() {
    if !ns::enabled() {
        return;
    }
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
            pidfd_pid_in_view(&dir, pidfd.as_fd())
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
fn namespaces_no_nspid_under_an_outer_procfs_numbering_this_thread_alike_is_diverged() {
    if !ns::enabled() {
        return;
    }
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
        let _status = force_status_once(NO_NSPID);
        proc_view()
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
fn namespaces_no_nspid_under_this_namespaces_own_procfs_is_same() {
    if !ns::enabled() {
        return;
    }
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
    let view = {
        let _status = force_status_once(NO_NSPID);
        proc_view()
    };
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
    let _status = force_status_once(NO_NSPID);
    match proc_view() {
        ProcView::Unassessable(why) => {
            assert!(why.reason.contains("1/ns/pid"), "{why}");
            assert_eq!(
                why.source.as_ref().and_then(io::Error::raw_os_error),
                Some(libc::EACCES),
                "{why}"
            );
        }
        other => panic!("an unreadable pid 1 namespace link must be Unassessable, got {other:?}"),
    }
}

// Listing =====

/// The real `/proc` holds `self`, `thread-self`, `net`, `sys`, ...; listing it must skip them, not
/// fail on them. Mutant: "every entry is a pid" — the first non-numeric name aborts the listing.
#[skuld::test]
fn pids_lists_the_numeric_entries_including_this_process() {
    let pids = ProcDir::open().expect("/proc opens").pids().expect("list");
    assert!(pids.contains(&std::process::id()), "{pids:?}");
}

fn names(list: &[&[u8]]) -> Vec<io::Result<Vec<u8>>> {
    list.iter().map(|n| Ok(n.to_vec())).collect()
}

/// Non-pid names are excluded, not errors. Mutant: "keep every name that parses" / "abort on the
/// first name that is not a pid".
#[skuld::test]
fn collect_pids_excludes_names_that_are_not_pids() {
    let listed: &[&[u8]] = &[
        b"1",
        b"self",
        b"thread-self",
        b"net",
        b"sys",
        b"",
        b"+5",
        b"-5",
        b"1a",
        b" 7",
        b"\xff\xfe",
        b"4194304",
    ];
    assert_eq!(collect_pids(names(listed)).expect("list"), vec![1, 4_194_304]);
}

/// An all-digit name that is no `u32` is a corrupt listing, never a member dropped in silence.
/// Mutant: "`.parse().ok()` drops it".
#[skuld::test]
fn collect_pids_is_an_error_for_an_all_digit_name_that_overflows() {
    for name in [&b"4294967296"[..], b"99999999999999999999"] {
        let err = collect_pids(names(&[b"1", name])).expect_err("a corrupt listing is an error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(err.to_string().contains(std::str::from_utf8(name).unwrap()), "{err}");
    }
}

/// A listing failure part-way is the listing's failure, not a shorter list.
#[skuld::test]
fn collect_pids_propagates_a_listing_error() {
    let items = vec![Ok(b"1".to_vec()), Err(io::Error::from_raw_os_error(libc::EIO))];
    let err = collect_pids(items).expect_err("listing error");
    assert_eq!(err.raw_os_error(), Some(libc::EIO));
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
