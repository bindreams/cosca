// Unit tests for the Unix process-group signal wrappers.
// Substantive end-to-end coverage is in the integration test
// (`unix_kill_tree_reaps_the_grandchild` in `tests/spawn_io.rs`).

use super::{kill_group, term_group};

// This file deliberately has NO "absent group" test that calls kill_group/term_group on a
// scanned-forward or freshly-reaped pgid. Once these functions unconditionally verify (this
// task's note above), they always list whatever pgid they are given and SIGNAL whatever
// `converge` finds there — so aiming one at a guessed-empty pgid is a check-then-act race
// against the kernel's own pid allocator (which favors exactly the small, recently-used
// numbers such a guess would produce) and against this crate's own sibling tests, several of
// which spawn `process_group(0)` children (pgid == pid). A collision would deliver a REAL
// SIGKILL to an unrelated process. That coverage is not missing: `converge`'s "empty result
// list ⇒ Cleared" path is identical whether the listing found zero members or one member
// `classify_member` immediately drops as `NotASurvivor` (the pure
// `classify_member_is_total_over_liveness` test proves the classification directly, with no
// listing involved at all), and `kill_group_on_an_all_zombie_group_is_ok`/
// `term_group_on_an_all_zombie_group_is_ok` below exercise that exact shape through the real
// public API, end to end, without ever risking a signal to a pgid this test does not own.

// Block until `pid` has exited WITHOUT reaping it, so it stays a zombie the
// kernel still lists in its process group. Nothing here is timed. Retries on
// EINTR, matching the `waitid(WEXITED | WNOWAIT)` idiom `reap_now` uses in
// `src/tokio/child.rs`, so a stray signal to the test process fails the wait,
// not the test.
fn await_zombie(pid: u32) {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: a well-formed `waitid` call; `info` is a valid, owned, zeroed
        // `siginfo_t` the kernel fills in. WNOWAIT leaves the child reapable.
        let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
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

/// `pgid <= 0` must be rejected before any signal is sent — 0 addresses the CALLER's own
/// process group (POSIX), and a negative value is the broadcast/double-negation hazard this
/// plan's Background measures. Safe to test directly: no real process or process group is
/// involved, and a correct implementation never reaches the `killpg`/`signal_direct` calls
/// this guards, so there is nothing to signal even if the test is wrong.
#[test]
fn kill_group_and_term_group_reject_non_positive_pgid() {
    for pgid in [0, -1, i32::MIN] {
        let kill_err = kill_group(pgid).expect_err("kill_group(non-positive) must be Err");
        assert!(
            matches!(kill_err, crate::error::Error::Unassessable { .. }),
            "got {kill_err:?}"
        );
        let term_err = term_group(pgid).expect_err("term_group(non-positive) must be Err");
        assert!(
            matches!(term_err, crate::error::Error::Unassessable { .. }),
            "got {term_err:?}"
        );
    }
}

/// kill_group on a real owned process group succeeds, and really did kill it.
#[test]
fn kill_group_on_owned_group_succeeds() {
    use std::os::unix::process::CommandExt;
    // Spawn a child in its own private group (pgid == child pid) so we can
    // SIGKILL it without disturbing the test runner's own group.
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .expect("spawn sleep");
    let pgid = child.id() as i32;
    assert!(kill_group(pgid).is_ok(), "kill_group on owned group must succeed");
    let status = child.wait().expect("wait after kill_group");
    assert!(
        !status.success(),
        "kill_group must have actually killed the leader, got {status:?}"
    );
}

/// `term_group` on a real owned, LIVE (non-zombie) group succeeds, and the leader really did
/// exit because of the delivered `SIGTERM` — not merely because it stayed reachable.
/// Previously undertested (review): the only prior `term_group` coverage besides the
/// pgid-guard test was the all-zombie case; the actual real-delivery half of `term_group` —
/// the initial `killpg(pgid, SIGTERM)` inside `signal_group`, which is the ONLY place a real
/// SIGTERM is ever sent (`converge`'s own SIGTERM path deliberately only probes,
/// never resends) — had no test proving delivery landed. Without this, a broken initial
/// `killpg` call (wrong signal constant, call removed, argument order swapped) would still
/// pass every other `term_group` test: the probe would confirm the leader is reachable,
/// `converge` would report `Cleared`, and `term_group` would return `Ok(())` while the leader
/// stayed alive — exactly the false-`Ok` class #61 exists to close, on the one path with no
/// closer until now.
#[test]
fn term_group_on_owned_group_succeeds() {
    use std::os::unix::process::CommandExt;
    // `sleep` has no SIGTERM handler of its own, so a delivered SIGTERM actually ends it —
    // distinguishing "exited because of the signal" from "merely stayed reachable".
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .expect("spawn sleep");
    let pgid = child.id() as i32;
    assert!(term_group(pgid).is_ok(), "term_group on owned group must succeed");
    let status = child.wait().expect("wait after term_group");
    assert!(
        !status.success(),
        "term_group must have actually delivered SIGTERM and ended the leader, got {status:?}"
    );
}

/// The benign half of the bug. A group whose only member is an unreaped zombie
/// has nothing left to kill, so teardown of it is honestly `Ok`.
///
/// On macOS this is the arm that made the bug hard: xnu excludes zombies from
/// the pgrp iteration before counting, so `killpg` reports EPERM for what is
/// really an empty group. The assertion below pins that, so the test cannot
/// quietly stop exercising the interesting path.
#[test]
fn kill_group_on_an_all_zombie_group_is_ok() {
    use std::os::unix::process::CommandExt;
    let child = std::process::Command::new("true")
        .process_group(0)
        .spawn()
        .expect("spawn true");
    let pid = child.id();
    await_zombie(pid);

    #[cfg(target_os = "macos")]
    assert_eq!(
        nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid as i32), None),
        Err(nix::errno::Errno::EPERM),
        "macOS reports EPERM for an all-zombie group; if this changed, the arm under test moved"
    );

    assert!(
        kill_group(pid as i32).is_ok(),
        "a group holding only a zombie is already down"
    );
    let mut child = child;
    child.wait().expect("reap");
}

/// Same, for the graceful signal. Same arm-pinning assertion as
/// `kill_group_on_an_all_zombie_group_is_ok` above, for the same reason: without it, a
/// future change to macOS's zombie-exclusion behavior (or a Linux-vs-macOS divergence
/// change) could leave this test passing on `term_group`'s own answer alone while silently
/// no longer exercising the branch it documents.
#[test]
fn term_group_on_an_all_zombie_group_is_ok() {
    use std::os::unix::process::CommandExt;
    let child = std::process::Command::new("true")
        .process_group(0)
        .spawn()
        .expect("spawn true");
    let pid = child.id();
    await_zombie(pid);

    #[cfg(target_os = "macos")]
    assert_eq!(
        nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGTERM
        ),
        Err(nix::errno::Errno::EPERM),
        "macOS reports EPERM for an all-zombie group; if this changed, the arm under test moved"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGTERM
        ),
        Ok(()),
        "Linux reports Ok for an all-zombie group (no live member to refuse); if this changed, \
         the arm under test moved"
    );

    assert!(
        term_group(pid as i32).is_ok(),
        "a group holding only a zombie is already down"
    );
    let mut child = child;
    child.wait().expect("reap");
}
