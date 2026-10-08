//! `proc_state` reads a child's state only through the checked `/proc` view.

use super::{proc_state, read_proc_state, StateUnknown};
use crate::containment::cgroup::test_support::{handle_of, pidfd_of};
use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};
use crate::test_child::namespaces as ns;
use crate::test_child::{fixture_path, member_command};
use crate::test_groups::{namespaces, Group};

#[skuld::test]
fn a_live_process_has_a_state_under_the_ordinary_view() {
    assert!(proc_state(handle_of(std::process::id(), &pidfd_of(std::process::id()))).is_some());
}

/// Mutant: "the state is the field after the state" (`Z` becomes the next field).
#[skuld::test]
fn an_unreaped_exited_child_is_a_zombie() {
    let mut child = crate::test_spawn::spawn(&mut std::process::Command::new("true")).expect("spawn true");
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: a well-formed `waitid`; `info` is an owned, zeroed `siginfo_t`. WNOWAIT leaves
        // the child unreaped.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            break;
        }
        let err = std::io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::EINTR), "waitid: {err}");
    }
    assert_eq!(read_proc_state(child.id()).ok(), Some('Z'));
    assert_eq!(
        proc_state(handle_of(child.id(), &pidfd_of(child.id()))),
        Some('Z'),
        "its pidfd says it exited"
    );
    child.wait().expect("reap");
}

/// The highest pid the kernel allows is never handed out (`pid_max` is at most 2^22).
#[skuld::test]
fn a_nonexistent_pid_has_no_state_under_the_ordinary_view() {
    let pid = u32::MAX - 1;
    assert_eq!(proc_state(handle_of(pid, &pidfd_of(std::process::id()))), None);
    let Err(StateUnknown::Unreadable(e)) = read_proc_state(pid) else {
        panic!("expected Unreadable");
    };
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
}

#[skuld::test]
fn an_unparsable_stat_is_named() {
    assert!(matches!(
        super::state_from_stat(String::from("garbage")),
        Err(StateUnknown::Unparsable(s)) if s == "garbage"
    ));
}

/// Mutant: "read `/proc/{pid}/stat` by path whatever the view", and "every non-Same view is
/// the same cause".
#[skuld::test]
fn no_state_is_read_when_the_view_is_diverged_or_unassessable() {
    for (view, wanted) in [
        (ForcedView::Diverged, "outer"),
        (ForcedView::Unassessable, "unassessable"),
    ] {
        let _forced = force_proc_view_once(view);
        let why = read_proc_state(std::process::id()).expect_err("no state");
        match (wanted, &why) {
            ("outer", StateUnknown::OuterProcfs) => {}
            ("unassessable", StateUnknown::ViewUnassessable(v)) => assert_eq!(v.reason, "forced by a test"),
            _ => panic!("{view:?}: {why:?}"),
        }
        let _forced = force_proc_view_once(view);
        assert_eq!(
            proc_state(handle_of(std::process::id(), &pidfd_of(std::process::id()))),
            None,
            "{view:?}"
        );
    }
}

/// pid 1 of a new pid namespace whose `/proc` is still the outer one: `/proc/1` is the outer
/// init, whose state says nothing about this process.
#[skuld::test]
fn namespaces_an_outer_procfs_gives_no_state(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_state_outer));
}

#[skuld::test]
fn fixture_state_outer() {
    if !ns::is_child() {
        return;
    }
    ns::enter_new_pid_ns_for_children();
    ns::run(fixture_path!(fixture_state_inner));
}

#[skuld::test]
fn fixture_state_inner() {
    if !ns::is_child_in_new_pid_ns() {
        return;
    }
    let outer = std::fs::read_to_string("/proc/1/stat").expect("the outer /proc/1/stat is readable by path");
    assert!(
        super::parse_proc_stat_state(&outer).is_some(),
        "control: read by path, pid 1 has a state: {outer:?}"
    );
    assert_eq!(proc_state(handle_of(1, &pidfd_of(1))), None);
}

/// A file mounted over a child's `stat` is not read.
#[skuld::test]
fn namespaces_a_stat_mounted_over_gives_no_state(#[fixture(namespaces)] _group: &Group) {
    ns::run(fixture_path!(fixture_state_overmount));
}

#[skuld::test]
fn fixture_state_overmount() {
    if !ns::is_child() {
        return;
    }
    ns::enter_private_mount_ns();
    let mut child = KillOnDrop(Some(
        crate::test_spawn::spawn(&mut member_command(0)).expect("spawn the member"),
    ));
    crate::test_child::await_member_ready(child.0.as_mut().expect("child"));
    let pid = child.0.as_ref().expect("child").id();
    assert!(
        proc_state(handle_of(pid, &pidfd_of(pid))).is_some(),
        "the member has a state before the mount"
    );
    let scratch = tempfile::tempdir().expect("tempdir");
    let fake = scratch.path().join("stat");
    let zeros = ["0"; 16].join(" ");
    std::fs::write(&fake, format!("{pid} (fake) Z 1 1 {zeros} 1 0\n")).expect("write the fake stat");
    ns::bind_over(&fake, std::path::Path::new(&format!("/proc/{pid}/stat")));
    assert_eq!(proc_state(handle_of(pid, &pidfd_of(pid))), None);
}

/// Kills and reaps the child when dropped, so a failing assertion cannot leak it.
struct KillOnDrop(Option<std::process::Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            _ = child.kill();
            _ = child.wait();
        }
    }
}

/// A pidfd that cannot be polled says nothing about the child: no state, not "exited".
///
/// Mutant: any ready poll reads as exit (`POLLNVAL` included).
#[skuld::test]
fn a_pidfd_that_cannot_be_polled_gives_no_state() {
    use std::os::fd::{AsRawFd, BorrowedFd};

    let file = std::fs::File::open("/dev/null").expect("open /dev/null");
    let closed = file.as_raw_fd();
    drop(file);
    // SAFETY: `closed` is no longer open, and the borrow lives only for the poll, which reports
    // that (`POLLNVAL`) and reads nothing.
    let pidfd = unsafe { BorrowedFd::borrow_raw(closed) };
    let child = crate::containment::ChildHandle {
        pid: std::process::id(),
        pidfd,
    };
    assert_eq!(proc_state(child), None);
}

/// A thread-group leader that exits while other threads run reads `Z` in `/proc` with the pidfd
/// unexited: the group has not exited, so that is no state of the child.
///
/// Mutant: a `/proc` state of `Z` is returned as it reads.
#[skuld::test]
fn a_thread_group_whose_leader_exited_has_no_state() {
    use std::io::BufRead;

    let mut cmd = crate::test_child::fixture_command(fixture_path!(fixture_leader_exits));
    cmd.stdin(std::process::Stdio::piped());
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the fixture");
    let pid = child.id();
    let pidfd = pidfd_of(pid);
    // The fixture announces once its leader is a zombie: its first stderr line is the gate's.
    let mut stderr = std::io::BufReader::new(child.stderr.take().expect("piped stderr"));
    let mut seen = String::new();
    loop {
        let mut line = String::new();
        let read = stderr.read_line(&mut line).expect("read the fixture");
        seen.push_str(&line);
        assert_ne!(read, 0, "the fixture ended before its leader exited: {seen}");
        if line.trim() == LEADER_EXITED {
            break;
        }
    }

    assert_eq!(
        read_proc_state(pid).ok(),
        Some('Z'),
        "control: /proc shows the leader's state"
    );
    assert_eq!(proc_state(handle_of(pid, &pidfd)), None);

    // Ends the group: the thread reads EOF and exits the process.
    drop(child.stdin.take());
    child.wait().expect("reap the fixture");
}

const LEADER_EXITED: &str = "COSCA_LEADER_EXITED";

/// `SIGUSR2`'s handler: ends the one thread it runs on. `exit` (not `exit_group`) leaves the rest of
/// the group running.
extern "C" fn end_this_thread(_: libc::c_int) {
    // SAFETY: a raw `exit` of the calling thread; no other state is touched.
    unsafe { libc::syscall(libc::SYS_exit, 0) };
}

#[skuld::test]
fn fixture_leader_exits() {
    if !ns::is_child() {
        return;
    }
    let pid = std::process::id();
    // The harness runs this on a thread of its own, with the process's main thread (the group's
    // leader) waiting for it. The leader is ended by a signal to it alone.
    // SAFETY: installs a handler that only makes a raw `exit` system call.
    unsafe {
        libc::signal(
            libc::SIGUSR2,
            end_this_thread as extern "C" fn(libc::c_int) as libc::sighandler_t,
        )
    };
    // SAFETY: signals the leader thread of this process, whose tid is the pid.
    let sent = unsafe { libc::syscall(libc::SYS_tgkill, pid, pid, libc::SIGUSR2) };
    assert_eq!(sent, 0, "tgkill: {}", std::io::Error::last_os_error());
    // The leader is a zombie only once it has exited, which this thread cannot otherwise observe.
    while super::read_proc_state(pid).ok() != Some('Z') {
        std::thread::yield_now();
    }
    eprintln!("{LEADER_EXITED}");
    // Holds the group until the test closes stdin.
    let mut sink = Vec::new();
    _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut sink);
    // SAFETY: ends the process, whose leader is long gone.
    unsafe { libc::_exit(0) };
}
