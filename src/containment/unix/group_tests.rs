// Unit tests for process-group membership listing and the identity it carries.

use super::{members, state, GroupState, Member};
use crate::identity::{Liveness, ProcessId};
use nix::sys::signal::Signal;

fn is_alive(m: &Member) -> bool {
    matches!(ProcessId::from_parts(m.pid, m.token).is_alive(), Liveness::Alive)
}

/// Block until `pid` has exited, leaving it UNREAPED so it is a zombie the
/// kernel still lists in its process group. `waitid(WEXITED | WNOWAIT)` is the
/// real primitive for this — nothing here is timed. `nix` does not expose
/// `waitid` on macOS (0.31 configures it out), so call `libc` directly,
/// following the same `waitid(WEXITED | WNOWAIT)` idiom `reap_now` uses in
/// `src/tokio/child.rs` — including its EINTR retry, so a stray signal to the
/// test process fails the wait, not the test.
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

/// A group we lead lists the member we put in it, with a token that resolves to Alive.
#[test]
fn members_lists_a_live_owned_group() {
    use std::os::unix::process::CommandExt;
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let _guard = crate::child::spawn::spawn_lock();
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
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let _guard = crate::child::spawn::spawn_lock();
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
    assert!(
        !is_alive(leader),
        "an exited, unreaped leader's token must resolve to Dead, not Alive"
    );

    let mut child = child;
    child.wait().expect("reap");
}

/// A pgid with no members at all lists nothing, and that is not an error. Uses `i32::MAX`
/// (2147483647), not a forward scan from the test's own pid: a forward scan would assert on
/// the exact predicate the scan itself already satisfied — a tautology proving nothing beyond
/// what the loop condition already established — AND a genuine (if narrow) check-then-act
/// gap, since the scanned range is exactly where the kernel's allocator is likely to hand out
/// a NEW pid next, including to this crate's own sibling tests, several of which spawn
/// `process_group(0)` children whose pgid == their pid. `i32::MAX` cannot collide: measured
/// directly on this host,
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
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let _guard = crate::child::spawn::spawn_lock();
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .expect("spawn sleep");
    let pgid = child.id() as i32;

    let listed = members(pgid).expect("list the group");
    let leader = listed.iter().find(|m| m.pid == child.id()).expect("leader listed");
    let live = ProcessId::of(child.id()).found().expect("resolve the live leader");
    assert_eq!(
        leader.token,
        live.start_token_raw(),
        "listing token must match a fresh live read"
    );

    let _ = child.kill();
    let _ = child.wait();
}

/// A group we own holds no refusers once SIGKILLed — and `state` really did deliver the
/// signal, not just classify: the leader is dead afterward.
#[test]
fn state_of_an_owned_group_is_cleared_and_the_signal_was_real() {
    use std::os::unix::process::CommandExt;
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let _guard = crate::child::spawn::spawn_lock();
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .expect("spawn sleep");
    let pgid = child.id() as i32;
    assert!(
        matches!(state(pgid, Signal::SIGKILL), GroupState::Cleared),
        "a group we own must never report refusers"
    );
    let status = child.wait().expect("wait after state()'s own SIGKILL");
    assert!(
        !status.success(),
        "state() must have actually delivered SIGKILL, not just probed, got {status:?}"
    );
}

/// A group whose only member is our own unreaped zombie is cleared: there is nothing left
/// running. This is the benign case macOS reports as EPERM.
#[test]
fn state_of_an_all_zombie_group_is_cleared() {
    use std::os::unix::process::CommandExt;
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let _guard = crate::child::spawn::spawn_lock();
    let child = std::process::Command::new("true")
        .process_group(0)
        .spawn()
        .expect("spawn true");
    let pid = child.id();
    await_zombie(pid);
    assert!(
        matches!(state(pid as i32, Signal::SIGKILL), GroupState::Cleared),
        "a group holding only a zombie has nothing left to kill"
    );
    let mut child = child;
    child.wait().expect("reap");
}

/// `classify_member`'s pure decision. Only `Liveness::Dead` skips the attempt (a panicking
/// closure proves it); `Alive` AND `Unknown` both proceed to `reached()` and are classified
/// identically from its answer — the fix for a guard-then-do inversion review caught
/// (`classify_member`'s own doc comment has the full account). `Reached::Unknown` still needs
/// a real permission-denying host (`hidepid`) to construct for real; exercised here directly.
#[test]
fn classify_member_is_total_over_liveness_and_reached() {
    use super::{classify_member, MemberOutcome, Reached};
    use crate::identity::Liveness;

    assert!(matches!(
        classify_member(1, Liveness::Dead, || panic!("must not reach for Dead")),
        MemberOutcome::NotASurvivor
    ));
    for liveness in [Liveness::Alive, Liveness::Unknown] {
        assert!(matches!(
            classify_member(1, liveness, || Reached::Yes),
            MemberOutcome::NotASurvivor
        ));
        assert!(matches!(
            classify_member(1, liveness, || Reached::No),
            MemberOutcome::Survivor(1)
        ));
        assert!(matches!(
            classify_member(1, liveness, || Reached::Unknown),
            MemberOutcome::Unassessable(1)
        ));
    }
}

/// `reconfirm_survivor`'s pure re-check, isolated from any real signal delivery: a
/// `Survivor` is downgraded ONLY on a positive `Dead` disagreement — a denied reconfirmation
/// (`Liveness::Unknown`) does NOT overturn the already-observed, authoritative `EPERM` a
/// `Survivor` carries (see this function's own doc comment for why `Unknown` and `Dead` are
/// not equivalent here). `NotASurvivor`/`Unassessable` pass through untouched (the panicking
/// closure proves no second check runs for them at all — there is nothing to reconfirm).
#[test]
fn reconfirm_survivor_downgrades_only_on_dead() {
    use super::{reconfirm_survivor, MemberOutcome};
    use crate::identity::Liveness;

    assert!(matches!(
        reconfirm_survivor(MemberOutcome::Survivor(1), || Liveness::Alive),
        MemberOutcome::Survivor(1)
    ));
    assert!(matches!(
        reconfirm_survivor(MemberOutcome::Survivor(1), || Liveness::Dead),
        MemberOutcome::NotASurvivor
    ));
    // Unknown does NOT downgrade: a denied reconfirmation is weaker evidence than the
    // already-observed EPERM, not a disagreement with it.
    assert!(matches!(
        reconfirm_survivor(MemberOutcome::Survivor(1), || Liveness::Unknown),
        MemberOutcome::Survivor(1)
    ));
    assert!(matches!(
        reconfirm_survivor(MemberOutcome::NotASurvivor, || panic!("must not recheck NotASurvivor")),
        MemberOutcome::NotASurvivor
    ));
    assert!(matches!(
        reconfirm_survivor(MemberOutcome::Unassessable(1), || panic!(
            "must not recheck Unassessable"
        )),
        MemberOutcome::Unassessable(1)
    ));
}

/// `decide`'s pure priority ordering, isolated from any real listing: a known refusal beats
/// an unresolved member, which beats a clean group — and neither a refuser nor an
/// unassessable member is ever silently dropped when both are present at once.
#[test]
fn decide_prioritizes_refused_over_unassessable_over_cleared() {
    use super::{decide, GroupState};

    assert!(matches!(
        decide(1, Signal::SIGKILL, vec![], vec![]),
        GroupState::Cleared
    ));
    match decide(1, Signal::SIGKILL, vec![], vec![5]) {
        GroupState::Unlistable { detail, .. } => assert!(detail.contains('5'), "got {detail:?}"),
        other => panic!("expected Unlistable, got {other:?}"),
    }
    match decide(1, Signal::SIGKILL, vec![7], vec![5]) {
        GroupState::Refused { refused, unassessable } => {
            assert_eq!(
                refused,
                vec![7],
                "a known refuser must not be lost to an unassessable member"
            );
            assert_eq!(
                unassessable,
                vec![5],
                "the unassessable member must not be silently dropped either"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
}

/// `excluded_from_sigkill_resend`'s pure predicate, isolated from any real listing or signal:
/// pid 1 is excluded regardless of `system`, a `system`-flagged pid is excluded regardless of
/// its number, and an ordinary user pid is excluded by neither rule.
#[test]
fn excluded_from_sigkill_resend_covers_pid_1_and_system_independently() {
    use super::excluded_from_sigkill_resend;

    assert!(excluded_from_sigkill_resend(1, false), "pid 1 must be excluded");
    assert!(
        excluded_from_sigkill_resend(1, true),
        "pid 1 must be excluded even if also flagged system"
    );
    assert!(
        excluded_from_sigkill_resend(12345, true),
        "a system-flagged pid other than 1 must be excluded"
    );
    assert!(
        !excluded_from_sigkill_resend(12345, false),
        "an ordinary, non-system pid must not be excluded"
    );
}

/// `term_group`'s probe path against pid 1 — the one live, unsignalable-by-an-unprivileged-
/// caller process every Unix host has. Safe to run for real: `state(pgid, SIGTERM)` on this
/// pgid only ever *probes* (`kill(pid, 0)`) because `SIGTERM` never triggers this task's
/// resend path — no signal is delivered to `launchd`/`init` or its group siblings, on any
/// host, root or not. This exercises the ACTUAL production `state` function, not a parallel
/// test-only probe. The expectation comes from POSIX (an unprivileged process may not signal
/// one owned by another user) plus the host's own answer to "who owns pid 1", and it is
/// total: a root caller, or a host where pid 1 is ours, gets the complementary assertion.
///
/// **`reachable` is asked directly of the kernel, not derived from a hand-reconstructed
/// permission rule.**
#[test]
fn term_group_probe_reports_pid_1_as_a_refuser_unless_reachable() {
    let pgid = nix::unistd::getpgid(Some(nix::unistd::Pid::from_raw(1)))
        .expect("pid 1 has a process group")
        .as_raw();
    // SAFETY: pid 1 always exists; signal 0 sends no signal, only performs the kernel's own
    // permission check — this is the independent oracle, a syscall issued directly by the
    // test, not a call into any function this plan adds or modifies.
    let reachable = unsafe { libc::kill(1, 0) } == 0;
    match (state(pgid, Signal::SIGTERM), reachable) {
        (GroupState::Refused { refused, .. }, false) => {
            assert!(
                refused.contains(&1),
                "pid 1 must be reported as a refuser, got {refused:?}"
            );
        }
        (GroupState::Cleared, true) => {}
        (got, reachable) => panic!("pid 1 owned by uid {}, reachable={reachable}: got {got:?}", pid1_uid()),
    }
}

/// The real uid of pid 1, read from an oracle independent of this module.
#[cfg(target_os = "linux")]
fn pid1_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/1/status").expect("read /proc/1/status");
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .expect("Uid: line in /proc/1/status")
}

/// macOS pid 1 is always `launchd`, started by the kernel as root.
#[cfg(target_os = "macos")]
fn pid1_uid() -> u32 {
    0
}
