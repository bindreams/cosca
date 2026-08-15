// Unit tests for process-group membership listing and the identity it carries.

use super::{members, Member};
use crate::identity::{Liveness, ProcessId};

fn is_alive(m: &Member) -> bool {
    matches!(ProcessId::from_parts(m.pid, m.token).is_alive(), Liveness::Alive)
}

/// Block until `pid` has exited, leaving it UNREAPED so it is a zombie the
/// kernel still lists in its process group. `waitid(WEXITED | WNOWAIT)` is the
/// real primitive for this — nothing here is timed. `nix` does not expose
/// `waitid` on macOS (0.31 configures it out), so call `libc` directly,
/// following `src/tokio/child.rs:488-506`'s idiom — including its EINTR
/// retry, so a stray signal to the test process fails the wait, not the test.
fn await_zombie(pid: u32) {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: a well-formed `waitid` call; `info` is a valid, owned, zeroed
        // `siginfo_t` the kernel fills in. WNOWAIT leaves the child reapable.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            return;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        panic!("waitid failed: {err}");
    }
}

/// A group we lead lists the member we put in it, with a token that resolves to Alive.
#[test]
fn members_lists_a_live_owned_group() {
    use std::os::unix::process::CommandExt;
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .expect("spawn sleep");
    let pgid = child.id() as i32;

    let listed = members(pgid).expect("list the group");
    let leader = listed
        .iter()
        .find(|m| m.pid == child.id())
        .unwrap_or_else(|| panic!("leader {} missing from {listed:?}", child.id()));
    assert!(is_alive(leader), "a running leader's token must resolve to Alive");

    let _ = child.kill();
    let _ = child.wait();
}

/// Once the leader has exited unreaped, the kernel still lists it in the group,
/// and its token must resolve to Dead (zombie) — the state that makes an EPERM
/// answer meaningless.
#[test]
fn members_marks_an_unreaped_leader_as_dead() {
    use std::os::unix::process::CommandExt;
    let child = std::process::Command::new("true")
        .process_group(0)
        .spawn()
        .expect("spawn true");
    let pid = child.id();
    await_zombie(pid);

    let listed = members(pid as i32).expect("list the group");
    let leader = listed
        .iter()
        .find(|m| m.pid == pid)
        .unwrap_or_else(|| panic!("unreaped leader {pid} missing from {listed:?}"));
    assert!(!is_alive(leader), "an exited, unreaped leader's token must resolve to Dead, not Alive");

    let mut child = child;
    child.wait().expect("reap");
}

/// A pgid with no members at all lists nothing, and that is not an error. Uses `i32::MAX`
/// (2147483647), not a forward scan from the test's own pid: an earlier draft scanned
/// upward and asserted on the exact predicate the scan itself already satisfied — a
/// tautology proving nothing beyond what the helper's own loop condition already
/// established, AND a genuine (if narrow) check-then-act gap, since the scanned range is
/// exactly where the kernel's allocator is likely to hand out a NEW pid next, including to
/// this crate's own sibling tests, several of which spawn `process_group(0)` children whose
/// pgid == their pid. `i32::MAX` cannot collide: measured directly on this host,
/// `sysctl(KERN_PROC_PGRP, i32::MAX)` returns `rc=0` with zero actual records (confirming no
/// real pid/pgid is ever allocated anywhere near it — `kern.maxproc`/`pid_max` stay far
/// below `2^31` on every real system), so this is a fixed value, not a scan, and the
/// assertion is a genuine independent check rather than a restatement of the fixture.
#[test]
fn members_of_an_absent_group_is_empty() {
    assert_eq!(members(i32::MAX).expect("list an absent group"), vec![]);
}

/// The token the listing carries is the SAME encoding a live read of the pid would produce —
/// not a different, incompatible one — so a later `ProcessId::from_parts` re-check is
/// comparing like with like. (macOS: pinned across `proc_pidinfo` and `sysctl` by the
/// existing `kinfo_tests` cross-source oracle; this test pins the listing itself against
/// `ProcessId::of`'s live read, on both platforms.)
#[test]
fn members_token_matches_a_live_read_of_the_same_pid() {
    use std::os::unix::process::CommandExt;
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .expect("spawn sleep");
    let pgid = child.id() as i32;

    let listed = members(pgid).expect("list the group");
    let leader = listed.iter().find(|m| m.pid == child.id()).expect("leader listed");
    let live = ProcessId::of(child.id()).found().expect("resolve the live leader");
    assert_eq!(leader.token, live.start_token_raw(), "listing token must match a fresh live read");

    let _ = child.kill();
    let _ = child.wait();
}
