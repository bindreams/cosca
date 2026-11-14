//! [`ProcessId::exit_begun_with`] over real processes, on every Unix: a running process has not begun to
//! exit, a zombie has (Linux: its threads show `PF_EXITING`, which a zombie keeps; macOS: `P_WEXIT`, or
//! `SZOMB`), and a reaped one is gone. The held exit, where the flag shows before the children are
//! reparented, is measured (the findings the platform modules name) and needs root on Linux; the rows
//! that state it are the Linux module's.

use crate::identity::{HostKernel, Resolved};
use crate::test_child::live_exiting_member;

/// Waits until `pid` has exited, reaping nothing: it stays a zombie for the reads.
#[track_caller]
fn await_exit_without_reaping(pid: u32) {
    // SAFETY: an all-zero `siginfo_t` is a valid value, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `pid` is this test's own unreaped child; `WNOWAIT` leaves it a zombie.
    let waited = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(waited, 0, "waitid(WNOWAIT): {}", std::io::Error::last_os_error());
}

/// Mutants: a live process reads as begun; a zombie reads as not begun; a reaped process is not
/// `Gone`.
#[skuld::test]
fn a_running_process_has_not_begun_to_exit_a_zombie_has_and_a_reaped_one_is_gone() {
    let (mut child, id) = live_exiting_member();
    assert_eq!(id.exit_begun_with(&HostKernel).0, Resolved::Found(false), "running");

    // The member exits at the EOF of its stdin.
    drop(child.stdin.take());
    await_exit_without_reaping(child.id());
    assert_eq!(id.exit_begun_with(&HostKernel).0, Resolved::Found(true), "a zombie");

    child.wait().expect("reap the member");
    assert_eq!(id.exit_begun_with(&HostKernel).0, Resolved::Gone, "reaped");
}
