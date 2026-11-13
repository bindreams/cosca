// Unit tests for process-group membership listing and the identity it carries.

use super::{members, state, GroupState, Member};
#[cfg(target_os = "linux")]
use crate::identity::{FakeKernel, UNREADABLE_STATUS_REASON};
use crate::identity::{HostKernel, Liveness, ProcessId};
use crate::test_groups::{stray_signal, Group};
use nix::sys::signal::Signal;

fn is_alive(m: &Member) -> bool {
    matches!(m.id.is_alive(), Liveness::Alive)
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

use crate::test_child::{await_member_ready, member_command};

/// A group we lead lists the member we put in it, with a token that resolves to Alive.
#[skuld::test]
fn members_lists_a_live_owned_group() {
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let mut child = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn leader");
    await_member_ready(&mut child);
    let pgid = child.id() as i32;

    let listed = members(&HostKernel, pgid).expect("list the group");
    let leader = listed
        .iter()
        .find(|m| m.id.pid() == child.id())
        .unwrap_or_else(|| panic!("leader {} missing from {listed:?}", child.id()));
    assert!(is_alive(leader), "a running leader's token must resolve to Alive");

    _ = child.kill();
    _ = child.wait();
}

/// Once the leader has exited unreaped, the kernel still lists it in the group,
/// and its token must resolve to Dead (zombie) — the state that makes an EPERM
/// answer meaningless.
#[skuld::test]
fn members_marks_an_unreaped_leader_as_dead() {
    use std::os::unix::process::CommandExt;
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let child = crate::test_spawn::spawn(std::process::Command::new("true").process_group(0)).expect("spawn true");
    let pid = child.id();
    await_zombie(pid);

    let listed = members(&HostKernel, pid as i32).expect("list the group");
    let leader = listed
        .iter()
        .find(|m| m.id.pid() == pid)
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
#[skuld::test]
fn members_of_an_absent_group_is_empty() {
    assert_eq!(members(&HostKernel, i32::MAX).expect("list an absent group"), vec![]);
}

/// The id the listing carries equals `ProcessId::of`'s live read of the pid, so a later re-check compares like with like.
#[skuld::test]
fn members_id_matches_a_live_read_of_the_same_pid() {
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let mut child = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn leader");
    await_member_ready(&mut child);
    let pgid = child.id() as i32;

    let listed = members(&HostKernel, pgid).expect("list the group");
    let leader = listed.iter().find(|m| m.id.pid() == child.id()).expect("leader listed");
    let live = ProcessId::of(child.id()).found().expect("resolve the live leader");
    assert_eq!(leader.id, live, "listing id must match a fresh live read");

    _ = child.kill();
    _ = child.wait();
}

/// A group we own holds no refusers once SIGKILLed — and `state` really did deliver the
/// signal, not just classify: the leader is dead afterward.
#[skuld::test]
fn state_of_an_owned_group_is_cleared_and_the_signal_was_real() {
    use std::os::unix::process::ExitStatusExt;

    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let mut child = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn leader");
    await_member_ready(&mut child);
    let pgid = child.id() as i32;
    assert!(
        matches!(
            state(
                pgid,
                Signal::SIGKILL,
                Some(&crate::test_support::stated_root::StatedRoot::unreaped()),
                &mut Vec::new()
            ),
            GroupState::Cleared
        ),
        "a group we own must never report refusers"
    );
    let status = child.wait().expect("wait after state()'s own SIGKILL");
    // Not `!status.success()`: `Child::wait()` closes the piped stdin (see `member_command`), so
    // the leader exits non-zero on EOF even if `state()` never signalled it.
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "state() must have actually delivered SIGKILL, not just probed, got {status:?}"
    );
}

/// The members a group kill names for the wait after it leave out the root, which its owner waits for:
/// the group's leader is the root here, and its `SIGKILL` is delivered all the same.
///
/// Mutant: `converge` names every member whose resend was delivered, the root's included.
#[skuld::test]
fn a_group_kill_names_no_root_among_the_members_it_reached() {
    use std::os::unix::process::ExitStatusExt;

    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let mut child = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn leader");
    await_member_ready(&mut child);
    let pgid = child.id() as i32;
    let root =
        crate::test_support::stated_root::StatedRoot::with_state(child.id(), || crate::signal::RootState::Unreaped);

    let mut killed = Vec::new();
    let verdict = state(pgid, Signal::SIGKILL, Some(&root), &mut killed);

    assert!(matches!(verdict, GroupState::Cleared), "got {verdict:?}");
    assert_eq!(
        child.wait().expect("reap").signal(),
        Some(libc::SIGKILL),
        "the root was sent its kill"
    );
    assert!(
        killed.is_empty(),
        "the root is waited for through its owner: {killed:?}"
    );
}

/// A group whose only member is our own unreaped zombie is cleared: there is nothing left
/// running. This is the benign case macOS reports as EPERM.
#[skuld::test]
fn state_of_an_all_zombie_group_is_cleared() {
    use std::os::unix::process::CommandExt;
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let child = crate::test_spawn::spawn(std::process::Command::new("true").process_group(0)).expect("spawn true");
    let pid = child.id();
    await_zombie(pid);
    assert!(
        matches!(
            state(
                pid as i32,
                Signal::SIGKILL,
                Some(&crate::test_support::stated_root::StatedRoot::unreaped()),
                &mut Vec::new()
            ),
            GroupState::Cleared
        ),
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
#[skuld::test]
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
        // The cause the answer carried is the member's.
        assert!(matches!(
            classify_member(1, liveness, || Reached::No(cause(libc::EPERM))),
            MemberOutcome::Survivor(1, ref why) if first_os_code(why) == Some(libc::EPERM)
        ));
        assert!(matches!(
            classify_member(1, liveness, || Reached::Unknown(cause(libc::EIO))),
            MemberOutcome::Unassessable(1, ref why) if first_os_code(why) == Some(libc::EIO)
        ));
    }
}

/// An error that says what a member's signal or probe answered: the OS error `code`.
fn cause(code: i32) -> crate::error::Error {
    crate::error::Error::Io(std::io::Error::from_raw_os_error(code))
}

fn first_os_code(error: &crate::error::Error) -> Option<i32> {
    crate::error::first_os_code(error)
}

/// `reconfirm_survivor`'s pure re-check, isolated from any real signal delivery: a
/// `Survivor` is downgraded ONLY on a positive `Dead` disagreement — a denied reconfirmation
/// (`Liveness::Unknown`) does NOT overturn the already-observed, authoritative `EPERM` a
/// `Survivor` carries (see this function's own doc comment for why `Unknown` and `Dead` are
/// not equivalent here). `NotASurvivor`/`Unassessable` pass through untouched (the panicking
/// closure proves no second check runs for them at all — there is nothing to reconfirm).
#[skuld::test]
fn reconfirm_survivor_downgrades_only_on_dead() {
    use super::{reconfirm_survivor, MemberOutcome};
    use crate::identity::Liveness;

    let survivor = || MemberOutcome::Survivor(1, cause(libc::EPERM));
    assert!(matches!(
        reconfirm_survivor(survivor(), || Liveness::Alive),
        MemberOutcome::Survivor(1, ref why) if first_os_code(why) == Some(libc::EPERM)
    ));
    assert!(matches!(
        reconfirm_survivor(survivor(), || Liveness::Dead),
        MemberOutcome::NotASurvivor
    ));
    // Unknown does NOT downgrade: a denied reconfirmation is weaker evidence than the
    // already-observed EPERM, not a disagreement with it.
    assert!(matches!(
        reconfirm_survivor(survivor(), || Liveness::Unknown),
        MemberOutcome::Survivor(1, ref why) if first_os_code(why) == Some(libc::EPERM)
    ));
    assert!(matches!(
        reconfirm_survivor(MemberOutcome::NotASurvivor, || panic!("must not recheck NotASurvivor")),
        MemberOutcome::NotASurvivor
    ));
    assert!(matches!(
        reconfirm_survivor(MemberOutcome::Unassessable(1, cause(libc::EIO)), || panic!(
            "must not recheck Unassessable"
        )),
        MemberOutcome::Unassessable(1, _)
    ));
}

/// `decide`'s pure priority ordering, isolated from any real listing: a known refusal beats
/// an unresolved member, which beats a clean group — and neither a refuser nor an
/// unassessable member is ever silently dropped when both are present at once.
#[skuld::test]
fn decide_prioritizes_refused_over_unassessable_over_cleared() {
    use super::{decide, GroupState};

    assert!(matches!(decide(vec![], vec![]), GroupState::Cleared));
    match decide(vec![], vec![(5, cause(libc::EIO))]) {
        GroupState::Unassessed { members } => {
            let pids: Vec<_> = members.iter().map(|(pid, _)| *pid).collect();
            assert_eq!(pids, [5]);
            assert_eq!(
                first_os_code(&members[0].1),
                Some(libc::EIO),
                "the member keeps its cause"
            );
        }
        other => panic!("expected Unassessed, got {other:?}"),
    }
    match decide(vec![(7, cause(libc::EPERM))], vec![(5, cause(libc::EIO))]) {
        GroupState::Refused { refused, unassessable } => {
            let pids = |members: &[(u32, crate::error::Error)]| members.iter().map(|(pid, _)| *pid).collect::<Vec<_>>();
            assert_eq!(
                pids(&refused),
                [7],
                "a known refuser must not be lost to an unassessable member"
            );
            assert_eq!(
                pids(&unassessable),
                [5],
                "the unassessable member must not be silently dropped either"
            );
            assert_eq!(first_os_code(&refused[0].1), Some(libc::EPERM));
            assert_eq!(first_os_code(&unassessable[0].1), Some(libc::EIO));
        }
        other => panic!("expected Refused, got {other:?}"),
    }
}

/// `excluded_from_sigkill_resend`'s pure predicate, isolated from any real listing or signal:
/// pid 1 is excluded regardless of `system`, a `system`-flagged pid is excluded regardless of
/// its number, and an ordinary user pid is excluded by neither rule.
#[skuld::test]
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
#[skuld::test]
fn term_group_probe_reports_pid_1_as_a_refuser_unless_reachable(#[fixture(stray_signal)] _stray: &Group) {
    let pgid = nix::unistd::getpgid(Some(nix::unistd::Pid::from_raw(1)))
        .expect("pid 1 has a process group")
        .as_raw();
    // SAFETY: pid 1 always exists; signal 0 sends no signal, only performs the kernel's own
    // permission check — this is the independent oracle, a syscall issued directly by the
    // test, not a call into any function this plan adds or modifies.
    let reachable = unsafe { libc::kill(1, 0) } == 0;
    match (
        state(
            pgid,
            Signal::SIGTERM,
            Some(&crate::test_support::stated_root::StatedRoot::unreaped()),
            &mut Vec::new(),
        ),
        reachable,
    ) {
        (GroupState::Refused { refused, .. }, false) => {
            assert!(
                refused.iter().any(|(pid, _)| *pid == 1),
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

/// A member whose `pidfd_open` is refused or fails (`EMFILE`) is unassessable and nothing is sent to
/// it, by its pid or any route: without a pidfd nothing proves that its pid still names the listed
/// member, and the identity is told through a pidfd on every kernel. The warn names the failure.
///
/// Mutants: the stated errno is ignored; a failed open falls back to `kill(2)` by number (the
/// member then dies, and its resend is in the log).
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_member_whose_pidfd_cannot_be_opened_is_unassessable_and_nothing_is_sent() {
    use crate::containment::cgroup::test_support::{block_on, fork_running};
    use crate::send_log::Capture;

    crate::log_capture::install();
    let (gate_r, gate_w) = std::io::pipe().expect("pipe");
    let gate_r_fd = std::os::fd::AsRawFd::as_raw_fd(&gate_r);
    let child = fork_running(&[gate_r_fd], || block_on(gate_r_fd));
    let id = ProcessId::of(child.pid()).found().expect("the live child resolves");

    for (errno, text) in [
        (
            rustix::io::Errno::PERM,
            "process open is not supported on linux: cosca requires pidfd_open (Linux \u{2265} 5.3), \
             refused here: pidfd_open answered EPERM",
        ),
        (rustix::io::Errno::MFILE, "pidfd_open: Too many open files"),
    ] {
        let mark = crate::log_capture::mark();
        let kernel = FakeKernel::over(&HostKernel).on_pidfd_open(child.pid(), Err(errno));
        let capture = Capture::start();
        let reached = super::resend_sigkill(
            &kernel,
            id,
            Some(&crate::test_support::stated_root::StatedRoot::unreaped()),
        );

        // The member's cause is the open's error, with its errno.
        assert!(
            matches!(&reached, super::Reached::Unknown(why) if first_os_code(why) == Some(errno.raw_os_error())),
            "{errno}: got {reached:?}"
        );
        assert_eq!(capture.by_identity(), [], "{errno}: nothing was sent");
        assert!(capture.group_steps().is_empty(), "{errno}: nothing was sent by number");
        let lines = crate::log_capture::records_since_on_current_thread(mark, "could not be opened by identity");
        assert_eq!(lines.len(), 1, "{errno}: {lines:?}");
        assert_eq!(lines[0].0, log::Level::Warn);
        assert!(lines[0].1.contains(text), "{errno}: {lines:?}");
    }
    drop(gate_w);
}

/// A pass reads each member through the kernel it is given. On the `/proc` path (below Linux 6.9)
/// the leader's `stat` is read by the listing, then by the member's identity, then by the look at
/// its liveness, then by the re-verify before the probe.
///
/// A re-verify the kernel refuses leaves the member unassessable. Mutant: "`probe_member`
/// re-verifies through `HostKernel`": the probe reaches it and the group is `Cleared`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn converge_re_verifies_a_member_through_its_kernel() {
    let mut child = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn leader");
    await_member_ready(&mut child);
    let pid = child.id();

    let kernel = crate::identity::ticks_host(pid).on_read_after(&format!("{pid}/stat"), 3, Err(libc::EACCES));
    let state = super::converge(
        &kernel,
        pid as i32,
        Signal::SIGTERM,
        Some(&crate::test_support::stated_root::StatedRoot::unreaped()),
        &mut Vec::new(),
    );

    assert!(
        matches!(&state, Ok(GroupState::Unassessed { members }) if members.len() == 1
            && members[0].0 == pid
            && first_os_code(&members[0].1).is_none()),
        "got {state:?}"
    );
    _ = child.kill();
    _ = child.wait();
}

/// A member the kernel shows as another process (its pid's new owner) is not alive, so the pass
/// attempts nothing on it: the root is not even checked. The new owner shows from the third read of
/// the `stat`: after the scan's and the identity's. Mutant: "the liveness look reads through
/// `HostKernel`".
#[cfg(target_os = "linux")]
#[skuld::test]
fn converge_looks_at_a_members_liveness_through_its_kernel() {
    let mut child = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn leader");
    await_member_ready(&mut child);
    let pid = child.id();

    let kernel = crate::identity::ticks_host(pid).on_read_after(
        &format!("{pid}/stat"),
        2,
        Ok(&crate::test_child::stat_of_a_new_owner(pid)),
    );
    let checks = std::cell::Cell::new(0);
    let root = crate::test_support::stated_root::StatedRoot::with_state(pid, || {
        checks.set(checks.get() + 1);
        crate::signal::RootState::Unreaped
    });
    let state = super::converge(&kernel, pid as i32, Signal::SIGTERM, Some(&root), &mut Vec::new());

    assert!(matches!(state, Ok(GroupState::Cleared)), "got {state:?}");
    assert_eq!(checks.get(), 0, "nothing was attempted on a member that is not alive");
    _ = child.kill();
    _ = child.wait();
}

/// A member that refused the probe (`EPERM`) is looked at once more before it counts as a survivor,
/// through the kernel the pass reads through. Its `stat` is read by the listing, the member's
/// identity, the first look, the re-verify before the probe and then the second look, which finds
/// its pid's new owner: the member is gone. Mutant: "`reconfirm_survivor`'s look reads through
/// `HostKernel`": the member is still alive and the group is `Refused`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn converge_looks_again_at_a_refusing_member_through_its_kernel() {
    let mut child = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn leader");
    await_member_ready(&mut child);
    let pid = child.id();

    let kernel = crate::identity::ticks_host(pid).on_read_after(
        &format!("{pid}/stat"),
        4,
        Ok(&crate::test_child::stat_of_a_new_owner(pid)),
    );
    let refusing = crate::containment::unix::fault::refuse_probes();
    let state = super::converge(
        &kernel,
        pid as i32,
        Signal::SIGTERM,
        Some(&crate::test_support::stated_root::StatedRoot::unreaped()),
        &mut Vec::new(),
    );
    drop(refusing);

    assert!(matches!(state, Ok(GroupState::Cleared)), "got {state:?}");
    _ = child.kill();
    _ = child.wait();
}

/// A pass lists the group through the kernel it is given, and a member's identity is made by
/// opening its pidfd: where that kernel refuses the open, the group cannot be listed, and nothing
/// is sent. Mutant: "`converge` hands `HostKernel` to the listing": the open succeeds and the kill
/// goes through the pidfd.
#[cfg(target_os = "linux")]
#[skuld::test]
fn converge_sigkill_lists_through_its_kernel_and_sends_nothing_when_a_pidfd_cannot_be_opened() {
    use crate::send_log::Capture;

    let mut child = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn leader");
    await_member_ready(&mut child);
    let pid = child.id();

    let kernel = FakeKernel::over(&HostKernel).on_pidfd_open(pid, Err(rustix::io::Errno::MFILE));
    let capture = Capture::start();
    let state = super::converge(
        &kernel,
        pid as i32,
        Signal::SIGKILL,
        Some(&crate::test_support::stated_root::StatedRoot::unreaped()),
        &mut Vec::new(),
    );
    let sent = (capture.group_steps(), capture.by_identity());
    drop(capture);

    assert!(state.is_err(), "the group cannot be listed: {state:?}");
    assert!(sent.0.is_empty() && sent.1.is_empty(), "nothing was sent: {sent:?}");
    _ = child.kill();
    _ = child.wait();
}

/// A member that is a live non-leader thread is `Unknown`, with a warn naming that cause, and is
/// never signalled by its number (a `kill` on a tid signals its whole thread group).
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_live_non_leader_thread_member_is_unknown_and_never_falls_back_to_kill() {
    crate::log_capture::install();

    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        // SAFETY: SYS_gettid takes no arguments and always succeeds.
        tid_tx.send(unsafe { libc::syscall(libc::SYS_gettid) } as u32).unwrap();
        _ = stop_rx.recv();
    });
    let tid = tid_rx.recv().unwrap();
    let id = ProcessId::of(tid).found().expect("the live worker's tid resolves");
    let mark = crate::log_capture::mark();

    // A thread that leads no group opens only with `PIDFD_THREAD`, and its leader-style open answers
    // `ENOENT` (Linux 6.16+); the retry goes to the real kernel.
    let kernel = crate::identity::FakeKernel::over(&crate::identity::HostKernel).on_pidfd_open_flags(
        tid,
        rustix::process::PidfdFlags::empty(),
        Err(rustix::io::Errno::NOENT),
    );
    let reached = super::resend_sigkill(
        &kernel,
        id,
        Some(&crate::test_support::stated_root::StatedRoot::unreaped()),
    );

    assert!(
        matches!(
            &reached,
            super::Reached::Unknown(crate::error::Error::NotThreadGroupLeader { .. })
        ),
        "got {reached:?}"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, &format!("pid {tid} is a live thread, not a thread-group leader")),
        vec![log::Level::Warn]
    );
    _ = stop_tx.send(());
    worker.join().unwrap();
}

/// What `resend_sigkill` answers for a live member whose send the kernel answers as `errno` (`None`:
/// a real send, which ends the member).
fn resend_answer(errno: Option<i32>) -> super::Reached {
    let mut child = crate::test_spawn::spawn(&mut member_command(0)).expect("spawn the member");
    await_member_ready(&mut child);
    let id = ProcessId::of(child.id()).found().expect("the live member resolves");
    let answering = errno.map(crate::signal::seams::fail_kills_with);
    let reached = super::resend_sigkill(
        &HostKernel,
        id,
        Some(&crate::test_support::stated_root::StatedRoot::unreaped()),
    );
    drop(answering);
    _ = child.kill();
    _ = child.wait();
    reached
}

/// The send's answer is the member's: delivered, or already gone (`ESRCH`), reached it; `EPERM` is a
/// confirmed refusal; any other errno says nothing about the member. Mutants: "`EPERM` is
/// `Unknown`", "another errno is `No`", "`Gone` is `Unknown`".
#[skuld::test]
fn a_resends_answer_is_the_members_reached() {
    assert!(matches!(resend_answer(None), super::Reached::Killed), "delivered");
    assert!(matches!(resend_answer(Some(libc::ESRCH)), super::Reached::Yes), "gone");
    // A refusal and an anomalous answer keep the error the send answered.
    assert!(
        matches!(resend_answer(Some(libc::EPERM)), super::Reached::No(ref why) if first_os_code(why) == Some(libc::EPERM)),
        "EPERM"
    );
    assert!(
        matches!(resend_answer(Some(libc::EIO)), super::Reached::Unknown(ref why) if first_os_code(why) == Some(libc::EIO)),
        "EIO"
    );
}

// Checked /proc view (Linux) =====

/// An outer namespace's `/proc` lists another namespace's processes: their pgids mean nothing
/// here, so the listing is an error naming the view, never an answer about `pgid`. Mutant:
/// "scan `/proc` by path whatever the view".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_is_an_error_when_the_proc_view_is_diverged() {
    let kernel = FakeKernel::over(&HostKernel).diverged_view();
    let err = members(&kernel, i32::MAX).expect_err("a diverged view lists nothing");
    assert!(err.to_string().contains("outer pid namespace"), "{err}");
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn members_is_an_error_naming_the_cause_when_the_proc_view_is_unassessable() {
    let kernel = FakeKernel::over(&HostKernel).unreadable_view();
    let err = members(&kernel, i32::MAX).expect_err("an unassessable view lists nothing");
    assert!(err.to_string().contains(UNREADABLE_STATUS_REASON), "{err}");
    // The view's read error is the source, with its code, and not repeated in the text.
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EIO), "{err:?}");
    let os_error = std::io::Error::from_raw_os_error(libc::EIO).to_string();
    assert!(!err.to_string().contains(&os_error), "{err}");
}

// Per-pid stat read failures =====

/// The pid the stat rows list and read.
#[cfg(target_os = "linux")]
const PID: u32 = 4242;

/// The failures that mean "this pid says nothing about the group": it exited mid-scan (ENOENT,
/// ESRCH) or `hidepid` hides it (EACCES, and EPERM while the checked directory still answers).
/// The pgid matches nothing, so the honest answer is an empty listing. Mutant: "propagate every
/// read error".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_excludes_a_pid_whose_stat_read_says_it_is_gone_or_hidden() {
    for errno in [libc::ENOENT, libc::ESRCH, libc::EACCES, libc::EPERM] {
        let kernel = FakeKernel::listing_unreadable_pid(&HostKernel, PID, errno);
        let listed = members(&kernel, i32::MAX).unwrap_or_else(|e| panic!("errno {errno} is an exclusion: {e}"));
        assert!(listed.is_empty(), "errno {errno}: {listed:?}");
    }
}

/// Every other failure says nothing about the pid, so it cannot clear the group: the listing is an
/// error naming the pid and the errno. Mutant: "exclude every read error" (the group reads as
/// `Cleared` while alive; EMFILE from a full fd table hits every pid at once).
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_is_an_error_naming_pid_and_errno_for_any_other_stat_read_failure() {
    for errno in [
        libc::EXDEV,
        libc::ELOOP,
        libc::EMFILE,
        libc::ENFILE,
        libc::ENOMEM,
        libc::EIO,
    ] {
        let kernel = FakeKernel::listing_unreadable_pid(&HostKernel, PID, errno);
        let err = members(&kernel, i32::MAX).expect_err("an unexplained read failure lists nothing");
        // The listing's own words do not fold in the layer's (`to_string` is this layer alone).
        let own = err.to_string();
        assert!(!own.contains("/stat"), "{errno}: {own}");
        // The read's error is below the `Unreadable` layer, with its code.
        assert_eq!(crate::error::first_os_code(&err), Some(errno), "{errno}: {err:?}");
        let text = crate::error::Report(&err).to_string();
        if matches!(errno, libc::EXDEV | libc::ELOOP) {
            assert!(text.contains("beyond a mount"), "{errno}: {text}");
        }
        let pid = text.split("/stat").next().unwrap().rsplit(' ').next().unwrap();
        assert_eq!(
            pid.parse::<u32>().ok(),
            Some(PID),
            "{errno}: the error must name the pid before `/stat`: {text}"
        );
    }
}

/// EPERM is `hidepid`'s answer, and also a seccomp filter's for `openat2` installed mid-scan. Only
/// the checked directory answering afterwards tells them apart. A re-check that fails without
/// refusing (`EMFILE`, `ENOMEM`, `EIO`) is the re-check's own error, with the pid's `EPERM` kept as
/// a second cause. Mutant: "exclude EPERM without the re-check"; "every failed re-check is a
/// refusal".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_is_an_error_for_eperm_when_the_checked_directory_fails_without_refusing() {
    for recheck in [libc::EMFILE, libc::ENOMEM, libc::EIO] {
        let kernel =
            FakeKernel::listing_unreadable_pid(&HostKernel, PID, libc::EPERM).on_read("self/stat", Err(recheck));
        let err =
            members(&kernel, i32::MAX).expect_err("a pid whose stat is refused and whose re-check fails lists nothing");
        let text = crate::error::Report(&err).to_string();
        assert_eq!(err.kind(), std::io::ErrorKind::Other, "{recheck}: {text}");
        assert!(text.contains("re-check of self/stat failed"), "{recheck}: {text}");
        assert_eq!(crate::error::first_os_code(&err), Some(recheck), "{recheck}: {text}");
        let (_, second) = text
            .split_once("(2) ")
            .unwrap_or_else(|| panic!("{recheck}: the second failure is kept: {text}"));
        assert!(
            second.contains(&std::io::Error::from_raw_os_error(libc::EPERM).to_string()),
            "{recheck}: the pid's EPERM is the second cause: {text}"
        );
    }
}

/// An `openat2` refused after the view opened (a seccomp filter installed mid-scan) is the same host
/// condition as a refused view-open: `ErrorKind::Unsupported` naming `openat2`, with the refusing
/// errno as the source and the pid's own failure, which names the pid, as a second cause when the
/// refusal is the directory's. The refusal shows as the pid's `stat` answering `ENOSYS`/`ENODEV`, or
/// as `EPERM` beside a checked directory that refuses `self/stat` too. It is warned about once, as
/// the process snapshot's is. Mutant: "a refusal mid-scan is `Other`"; "the pid's `EPERM` is the
/// source of a refusal the directory made"; "the pid's `EPERM` is dropped"; "the refusal is not
/// warned about".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_is_unsupported_when_the_scan_meets_a_refused_openat2() {
    crate::log_capture::install();
    // The pid's `stat` answer, the `self/stat` answer where there is one, and the refusing errno.
    for (stat, recheck, refusing) in [
        (libc::EPERM, Some(libc::EPERM), libc::EPERM),
        (libc::EPERM, Some(libc::ENOSYS), libc::ENOSYS),
        (libc::EPERM, Some(libc::ENODEV), libc::ENODEV),
        (libc::ENOSYS, None, libc::ENOSYS),
        (libc::ENODEV, None, libc::ENODEV),
    ] {
        let mut kernel = FakeKernel::listing_unreadable_pid(&HostKernel, PID, stat);
        if let Some(recheck) = recheck {
            kernel = kernel.on_read("self/stat", Err(recheck));
        }
        let mark = crate::log_capture::mark();
        let err = members(&kernel, i32::MAX).expect_err("a refused openat2 lists nothing");
        let text = crate::error::Report(&err).to_string();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::Unsupported,
            "{stat}/{recheck:?}: {text}"
        );
        assert!(text.contains("requires openat2"), "{stat}/{recheck:?}: {text}");
        assert_eq!(
            crate::error::first_os_code(&err),
            Some(refusing),
            "{stat}/{recheck:?}: {text}"
        );
        match (recheck, text.split_once("(2) ")) {
            (Some(_), Some((_, second))) => {
                assert!(second.contains(&format!("{PID}/stat")), "{stat}/{recheck:?}: {text}");
                assert!(
                    second.contains(&std::io::Error::from_raw_os_error(stat).to_string()),
                    "{stat}/{recheck:?}: {text}"
                );
            }
            (Some(_), None) => panic!("{stat}/{recheck:?}: the pid's own failure is kept: {text}"),
            (None, second) => assert!(second.is_none(), "{stat}/{recheck:?}: a lone refusal: {text}"),
        }
        let warned = crate::log_capture::records_since_on_current_thread(mark, "containment::unix::group::members");
        assert_eq!(
            warned.iter().filter(|(level, _)| *level == log::Level::Warn).count(),
            1,
            "{stat}/{recheck:?}: {warned:?}"
        );
    }
}

/// The member's own identity read goes through the `stat` of the pid again, and a refusal there is the
/// same `Unsupported` as a refusal in the scan, with the pid's own failure beside it when the refusal
/// is the directory's. Mutant: "a refused read of the member's own `stat` excludes the member".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_is_unsupported_when_the_members_own_stat_read_is_refused() {
    use rustix::process::Pid;

    crate::log_capture::install();
    for (stat, recheck, refusing) in [
        (libc::EPERM, Some(libc::EPERM), libc::EPERM),
        (libc::EPERM, Some(libc::ENOSYS), libc::ENOSYS),
        (libc::EPERM, Some(libc::ENODEV), libc::ENODEV),
        (libc::ENOSYS, None, libc::ENOSYS),
        (libc::ENODEV, None, libc::ENODEV),
    ] {
        let (kernel, _writer) = scan_shows_group_1234();
        let mut kernel = kernel
            .on_signal_probe(Pid::from_raw(PID as i32).expect("a pid"), Ok(()))
            .on_read_after(&format!("{PID}/stat"), 1, Err(stat));
        if let Some(recheck) = recheck {
            kernel = kernel.on_read("self/stat", Err(recheck));
        }
        let mark = crate::log_capture::mark();
        let err = members(&kernel, 1234).expect_err("a refused own read lists nothing");
        let text = crate::error::Report(&err).to_string();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::Unsupported,
            "{stat}/{recheck:?}: {text}"
        );
        assert!(text.contains("requires openat2"), "{stat}/{recheck:?}: {text}");
        assert_eq!(
            crate::error::first_os_code(&err),
            Some(refusing),
            "{stat}/{recheck:?}: {text}"
        );
        match (recheck, text.split_once("(2) ")) {
            (Some(_), Some((_, second))) => {
                assert!(second.contains(&format!("{PID}/stat")), "{stat}/{recheck:?}: {text}");
                assert!(
                    second.contains(&std::io::Error::from_raw_os_error(libc::EPERM).to_string()),
                    "{stat}/{recheck:?}: the pid's EPERM is below the second cause: {text}"
                );
            }
            (Some(_), None) => panic!("{stat}/{recheck:?}: the pid's own failure is kept: {text}"),
            (None, second) => assert!(second.is_none(), "{stat}/{recheck:?}: a lone refusal: {text}"),
        }
        assert_eq!(
            crate::log_capture::warns_since(mark, "").len(),
            1,
            "{stat}/{recheck:?}: warned once"
        );
    }
}

/// A read of the member's own `stat` that fails without refusing and is no absence fails the listing,
/// naming the pid and carrying the errno, because excluding a live member could clear a live group:
/// `EIO`, `EMFILE`, a mount crossing, or `EPERM` beside a `self/stat` that fails too. Mutant: "a failed
/// own read excludes the member".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_fails_when_the_members_own_stat_read_is_unreadable() {
    use rustix::process::Pid;

    for (stat, recheck, below) in [
        (libc::EIO, None, libc::EIO),
        (libc::EMFILE, None, libc::EMFILE),
        (libc::EXDEV, None, libc::EXDEV),
        (libc::ELOOP, None, libc::ELOOP),
        (libc::EPERM, Some(libc::EMFILE), libc::EMFILE),
    ] {
        let (kernel, _writer) = scan_shows_group_1234();
        let mut kernel = kernel
            .on_signal_probe(Pid::from_raw(PID as i32).expect("a pid"), Ok(()))
            .on_read_after(&format!("{PID}/stat"), 1, Err(stat));
        if let Some(recheck) = recheck {
            kernel = kernel.on_read("self/stat", Err(recheck));
        }
        let err = members(&kernel, 1234).expect_err("an unreadable own read lists nothing");
        let text = crate::error::Report(&err).to_string();
        assert_eq!(err.kind(), std::io::ErrorKind::Other, "{stat}/{recheck:?}: {text}");
        assert!(text.contains(&format!("pid {PID}")), "{stat}/{recheck:?}: {text}");
        assert_eq!(
            crate::error::first_os_code(&err),
            Some(below),
            "{stat}/{recheck:?}: {text}"
        );
    }
}

/// A read of the member's own `stat` that is no more than an absence stays an exclusion with no cause:
/// `ENOENT` or `EACCES` of a pid `kill(pid, 0)` does not say is gone, or `EPERM` while the checked
/// directory still answers (`hidepid`). Mutant: "any failed own read fails the listing".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_excludes_a_pid_whose_own_stat_read_is_an_absence() {
    use rustix::process::Pid;

    for (stat, recheck) in [
        (libc::ENOENT, None),
        (libc::EACCES, None),
        (libc::EPERM, Some(Ok(&b""[..]))),
    ] {
        let (kernel, _writer) = scan_shows_group_1234();
        let mut kernel = kernel
            .on_signal_probe(Pid::from_raw(PID as i32).expect("a pid"), Ok(()))
            .on_read_after(&format!("{PID}/stat"), 1, Err(stat));
        if let Some(recheck) = recheck {
            kernel = kernel.on_read("self/stat", recheck);
        }
        assert!(
            members(&kernel, 1234)
                .unwrap_or_else(|e| panic!("{stat}: an exclusion, not an error: {e}"))
                .is_empty(),
            "{stat}"
        );
    }
}

/// An `openat2` refused where the listing begins is the same `Unsupported`: the `/proc` listing
/// (`ENOSYS`, `EPERM`, `ENODEV` of the open), and the read of `self/status` that establishes the view.
/// Each is warned about once. Any other listing failure stays an error with its own errno. Mutant:
/// "an `openat2` refused before any pid is read is `Other`".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_is_unsupported_when_the_listing_or_the_view_read_is_refused() {
    crate::log_capture::install();
    for errno in [libc::ENOSYS, libc::EPERM, libc::ENODEV] {
        let listing = FakeKernel::over(&HostKernel).same_view().on_pids(Err(errno));
        let status = FakeKernel::over(&HostKernel).on_read("self/status", Err(errno));
        for (what, kernel) in [("listing", listing), ("self/status", status)] {
            let mark = crate::log_capture::mark();
            let err = members(&kernel, i32::MAX).expect_err("a refused openat2 lists nothing");
            let text = crate::error::Report(&err).to_string();
            assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "{what} {errno}: {text}");
            assert!(text.contains("requires openat2"), "{what} {errno}: {text}");
            assert_eq!(crate::error::first_os_code(&err), Some(errno), "{what} {errno}: {text}");
            assert_eq!(
                crate::log_capture::warns_since(mark, "").len(),
                1,
                "{what} {errno}: warned once"
            );
        }
    }
    let kernel = FakeKernel::over(&HostKernel).same_view().on_pids(Err(libc::EIO));
    let err = members(&kernel, i32::MAX).expect_err("an unlistable /proc lists nothing");
    assert_ne!(err.kind(), std::io::ErrorKind::Unsupported, "{err}");
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EIO), "{err:?}");
}

/// `PID` is in group 1234 by the scan's `stat`; the identity read that follows makes its own.
/// `stat_fixture` puts the process in group 1234.
#[cfg(target_os = "linux")]
fn scan_shows_group_1234() -> (FakeKernel<'static>, std::io::PipeWriter) {
    use crate::identity::stat_parse::stat_fixture;

    let (reader, writer) = std::io::pipe().expect("a pipe");
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_pids(Ok(&[PID]))
        .on_read(&format!("{PID}/stat"), Ok(&stat_fixture("S", 777)))
        .on_pidfd_open(PID, Ok(reader.into()))
        .on_pidfs_ino(PID, Ok(Some(100)));
    (kernel, writer)
}

/// The scan's `stat` is a record of whoever held the pid then: the identity read's own `stat`,
/// which shows another group, wins, and the pid is no member. Mutant: "the listing keeps the scan's
/// membership".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_excludes_a_pid_whose_own_stat_shows_another_group() {
    let (kernel, _writer) = scan_shows_group_1234();
    // The own read's pgrp is field 5; `stat_fixture` has 1234 there.
    let moved = String::from_utf8(crate::identity::stat_parse::stat_fixture("S", 777))
        .expect("a fixture is text")
        .replacen(" S 1 1234 1234 ", " S 1 99 99 ", 1);
    let kernel = kernel.on_read_after(&format!("{PID}/stat"), 1, Ok(moved.as_bytes()));
    assert!(members(&kernel, 1234).expect("an exclusion, not an error").is_empty());
}

/// A pid that is gone by the identity read is no member. Mutant: "a gone member fails the listing".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_excludes_a_pid_whose_identity_read_finds_it_gone() {
    let (kernel, _writer) = scan_shows_group_1234();
    let kernel = kernel.on_pidfd_open(PID, Err(rustix::io::Errno::SRCH));
    assert!(members(&kernel, 1234).expect("an exclusion, not an error").is_empty());
}

/// An identity read that fails with no cause the read knows (on a host whose pidfds have no inode:
/// a `stat` without a start time) excludes the pid; it does not fail the listing. Mutant: "an
/// unknown read with no cause fails the listing".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_excludes_a_pid_whose_identity_read_is_unknown_with_no_cause() {
    let (kernel, _writer) = scan_shows_group_1234();
    let kernel =
        kernel
            .on_pidfs_ino(PID, Ok(None))
            .on_read_after(&format!("{PID}/stat"), 1, Ok(b"4242 (x) S 1 1234 1234"));
    assert!(members(&kernel, 1234).expect("an exclusion, not an error").is_empty());
}

/// The same table lists the member when nothing moves. Mutant: "the listing excludes every pid".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_lists_a_pid_whose_scan_and_identity_read_agree() {
    let (kernel, _writer) = scan_shows_group_1234();
    let listed = members(&kernel, 1234).expect("a readable table");
    assert_eq!(
        listed,
        vec![Member {
            id: ProcessId::from_parts_for_test(PID, crate::identity::Key::Pidfs(100)),
            system: false
        }]
    );
}

/// A member whose pidfd cannot be opened fails the listing: a refused `pidfd_open` stays
/// `Unsupported` (the caller reports it so), a transient one is `Other`. Mutant: "the listing error
/// is always `Other`", "the member is excluded".
#[cfg(target_os = "linux")]
#[skuld::test]
fn members_fails_for_a_member_whose_pidfd_cannot_be_opened_and_keeps_a_refusal_unsupported() {
    use rustix::io::Errno;

    use crate::identity::stat_parse::stat_fixture;

    for (errno, kind) in [
        (Errno::PERM, std::io::ErrorKind::Unsupported),
        (Errno::MFILE, std::io::ErrorKind::Other),
    ] {
        let kernel = FakeKernel::over(&HostKernel)
            .same_view()
            .on_pids(Ok(&[PID]))
            .on_read(&format!("{PID}/stat"), Ok(&stat_fixture("S", 777)))
            .on_pidfd_open(PID, Err(errno));
        // `stat_fixture` puts the process in group 1234.
        let err = members(&kernel, 1234).expect_err("an unopenable member lists nothing");
        assert_eq!(err.kind(), kind, "{errno}: {err}");
        assert!(err.to_string().contains(&format!("pid {PID}")), "{errno}: {err}");
    }
}
