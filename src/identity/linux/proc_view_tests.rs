use std::io;

use std::os::fd::AsFd;

use crate::test_child::fixture_path;
use crate::test_child::namespaces as ns;

use super::fault::{force_proc_view_once, force_status_once, force_thread_stat_once, ForcedView};
use super::{
    classify_status, classify_thread_stat, parse_fdinfo_pid, pidfd_pid_in_view, proc_view, PidfdTarget, ProcDir,
    ProcView, Verdict,
};

fn ns_pid(exists: io::Result<bool>) -> impl FnOnce() -> io::Result<bool> {
    move || exists
}

fn unreachable_ns_pid() -> io::Result<bool> {
    panic!("self/ns/pid must be consulted only when NSpid is absent")
}

/// The ordinary view of this test binary, derived from `thread-self/stat`'s pid against
/// `gettid()`: the two agree exactly when `/proc` numbers this thread as the thread itself does,
/// so the view is `Same`, and `Diverged` otherwise (a container without its own `/proc`).
#[test]
fn proc_view_matches_what_thread_self_stat_says_about_this_thread() {
    let stat = ProcDir::open()
        .expect("/proc opens")
        .read_to_string("thread-self/stat")
        .expect("thread-self/stat reads");
    let same = stat.split(' ').next() == Some(&rustix::thread::gettid().as_raw_nonzero().to_string());
    let view = proc_view();
    assert_eq!(
        matches!(view, ProcView::Same(_)),
        same,
        "got {view:?} for stat {stat:?}"
    );
}

#[test]
fn one_nspid_entry_is_same() {
    let verdict = classify_status("Name:\tcosca\nNSpid:\t1234\nState:\tR\n", unreachable_ns_pid);
    assert!(matches!(verdict, Verdict::Same), "got {verdict:?}");
}

#[test]
fn several_nspid_entries_are_diverged() {
    let verdict = classify_status("NSpid:\t99\t5\t1\n", unreachable_ns_pid);
    assert!(matches!(verdict, Verdict::Diverged), "got {verdict:?}");
}

#[test]
fn an_empty_nspid_line_is_unassessable() {
    let verdict = classify_status("NSpid:\t\n", unreachable_ns_pid);
    assert!(matches!(verdict, Verdict::Unassessable(_)), "got {verdict:?}");
}

/// A kernel without `CONFIG_PID_NS` has no `NSpid` and no `self/ns/pid`: no namespace to
/// diverge into, so `Same`. Mutant: "an absent NSpid is always Unassessable" (the regression
/// that made every live foreign wait fail on such kernels).
#[test]
fn no_nspid_and_no_ns_pid_is_same() {
    let verdict = classify_status("Name:\tcosca\nState:\tR\n", ns_pid(Ok(false)));
    assert!(matches!(verdict, Verdict::Same), "got {verdict:?}");
}

/// gVisor: no `NSpid` but pid namespaces exist, so the status file alone cannot decide; the
/// stat cross-check does. Mutant: "an absent NSpid is always Same".
#[test]
fn no_nspid_but_ns_pid_exists_needs_the_cross_check() {
    let verdict = classify_status("Name:\tcosca\n", ns_pid(Ok(true)));
    assert!(matches!(verdict, Verdict::NoNspid), "got {verdict:?}");
}

#[test]
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

#[test]
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
#[test]
fn fdinfo_pid_minus_one_is_reaped() {
    assert_eq!(parse_fdinfo_pid("Pid:\t-1\n"), Some(PidfdTarget::Reaped));
}

/// Only `-1` is the kernel's reaped marker. Mutant: "any negative is Reaped".
#[test]
fn fdinfo_pid_other_negatives_are_unparseable() {
    assert_eq!(parse_fdinfo_pid("Pid:\t-2\n"), None);
    assert_eq!(parse_fdinfo_pid("Pid:\t-4294967296\n"), None);
}

/// Mutant: "truncate to u32" would turn 2^32 into pid 0.
#[test]
fn fdinfo_pid_beyond_u32_is_unparseable() {
    assert_eq!(parse_fdinfo_pid("Pid:\t4294967296\n"), None);
    assert_eq!(parse_fdinfo_pid("Pid:\t4294967295\n"), Some(PidfdTarget::Pid(u32::MAX)));
}

#[test]
fn fdinfo_pid_with_an_empty_value_is_unparseable() {
    assert_eq!(parse_fdinfo_pid("Pid:\n"), None);
    assert_eq!(parse_fdinfo_pid("Pid:\t\n"), None);
}

/// Only the exact `Pid:` key counts: `NSpid:` and `Pidfd:`-like keys carry other numbers. Mutant:
/// "match any line containing `Pid:`".
#[test]
fn fdinfo_pid_ignores_similarly_prefixed_keys() {
    assert_eq!(parse_fdinfo_pid("NSpid:\t9\nPidx:\t8\nxPid:\t7\n"), None);
    assert_eq!(
        parse_fdinfo_pid("NSpid:\t9\nPidx:\t8\nPid:\t3\n"),
        Some(PidfdTarget::Pid(3))
    );
}

/// A forced `Same` still opens the real `/proc`, so the dirfd it carries is usable.
#[test]
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
#[test]
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
#[test]
fn a_forced_view_disarms_on_drop_even_if_unconsumed() {
    drop(force_proc_view_once(ForcedView::Unassessable));
    assert!(
        matches!(proc_view(), ProcView::Same(_)),
        "the forced view must not survive an unconsumed drop"
    );
}

// Checked /proc dirfd =====

#[test]
fn the_proc_dir_reads_a_file_beneath_it() {
    let status = ProcDir::open()
        .expect("/proc opens")
        .read_to_string("thread-self/status")
        .expect("read");
    assert!(status.contains("Name:"), "{status}");
}

/// A path that leaves the directory it is opened under is refused. Mutant: "plain `openat`
/// without `RESOLVE_BENEATH`" — `..` reaches `/`.
#[test]
fn the_proc_dir_refuses_a_path_that_climbs_out_of_it() {
    let dir = ProcDir::open().expect("/proc opens");
    let err = dir.read("../etc/passwd").expect_err("must not leave /proc");
    assert_eq!(err.raw_os_error(), Some(libc::EXDEV), "{err}");
}

/// An absolute path names another tree entirely. Mutant: "no `RESOLVE_BENEATH`" — the path
/// resolves from the root, and `NO_XDEV` alone allows it (the root filesystem is one mount).
#[test]
fn the_proc_dir_refuses_an_absolute_path() {
    let dir = ProcDir::open().expect("/proc opens");
    let err = dir.read("/etc/passwd").expect_err("must not leave /proc");
    assert_eq!(err.raw_os_error(), Some(libc::EXDEV), "{err}");
}

/// A magic link (`self/exe`, `self/fd/N`) jumps out of the tree, so it is refused. Mutant:
/// "no `RESOLVE_NO_MAGICLINKS`".
#[test]
fn the_proc_dir_refuses_a_magic_link() {
    let dir = ProcDir::open().expect("/proc opens");
    let err = dir.read("self/exe").expect_err("a magic link must not be followed");
    assert_eq!(err.raw_os_error(), Some(libc::ELOOP), "{err}");
}

// thread-self cross-check (no NSpid) =====

const NO_NSPID: &str = "Name:\tcosca\nState:\tR (running)\n";

/// `thread-self/stat` numbers this thread as `gettid()` does: same namespace.
#[test]
fn a_thread_stat_naming_this_tid_is_same() {
    let verdict = classify_thread_stat("4242 (cosca) R 1 4242", 4242);
    assert!(matches!(verdict, Verdict::Same), "got {verdict:?}");
}

/// Mutant: "compare the tgid, not the tid" and "any parseable stat is Same".
#[test]
fn a_thread_stat_naming_another_tid_is_diverged() {
    let verdict = classify_thread_stat("7 (cosca) R 1 7", 4242);
    assert!(matches!(verdict, Verdict::Diverged), "got {verdict:?}");
}

#[test]
fn an_unparseable_thread_stat_is_unassessable() {
    for stat in ["", "x (cosca) R", "(cosca) R"] {
        let verdict = classify_thread_stat(stat, 4242);
        assert!(matches!(verdict, Verdict::Unassessable(_)), "{stat:?}: got {verdict:?}");
    }
}

/// No `NSpid` although pid namespaces exist (gVisor): the real `thread-self/stat` decides, so an
/// ordinary process is `Same`. Mutant: "an absent NSpid with namespaces present is Unassessable".
#[test]
fn a_status_without_nspid_is_decided_by_the_real_thread_stat() {
    let _forced = force_status_once(NO_NSPID);
    let view = proc_view();
    assert!(matches!(view, ProcView::Same(_)), "got {view:?}");
}

/// The same arm against a thread stat that names another tid: an outer namespace's `/proc`.
#[test]
fn a_status_without_nspid_and_a_foreign_thread_stat_is_diverged() {
    let _status = force_status_once(NO_NSPID);
    let _stat = force_thread_stat_once("1 (init) S 0 1");
    let view = proc_view();
    assert!(matches!(view, ProcView::Diverged), "got {view:?}");
}

// pidfd fdinfo =====

/// A pidfd whose target has been reaped prints `Pid: -1` (real kernel, no forcing).
#[test]
fn the_fdinfo_of_a_reaped_targets_pidfd_is_reaped() {
    let (mut child, pidfd) = spawn_exited_child_with_pidfd();
    child.wait().expect("reap the child");
    let dir = ProcDir::open().expect("/proc opens");
    let got = pidfd_pid_in_view(&dir, pidfd.as_fd());
    assert!(matches!(got, Ok(PidfdTarget::Reaped)), "got {got:?}");
}

/// Before the reap the same pidfd names the child under its pid.
#[test]
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
    let child = {
        let _guard = crate::child::spawn::spawn_lock();
        std::process::Command::new("true").spawn().expect("spawn true")
    };
    let pid = rustix::process::Pid::from_raw(child.id() as i32).expect("child pid is nonzero");
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open");
    (child, pidfd)
}

/// A thread that unshared its fd table has fds the leader's `self/fdinfo` does not know; the
/// fdinfo must be read through `thread-self`. Mutant: "read `self/fdinfo`" — the leader's table
/// has no such fd (or a different file at that number).
///
/// In the namespaces group: `unshare` is refused by default container seccomp profiles.
#[test]
fn namespaces_the_fdinfo_is_read_through_the_calling_threads_fd_table() {
    if !ns::enabled() {
        return;
    }
    ns::run(fixture_path!(fixture_fdinfo_after_unshare_files));
}

#[test]
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
