//! `Unreaped`'s contract, on a child held as a spawn teardown holds it: `wait` reaps and returns
//! the status, `leak` gives the child up unreaped, and `Drop` blocks until the child exits.

#[cfg(unix)]
use super::Retained;
use super::{Held, Unreaped};
use crate::identity::{ProcessId, Resolved};

/// A child blocked reading stdin until the returned end drops, and its identity.
fn blocked_child() -> (std::process::Child, std::process::ChildStdin, ProcessId) {
    let mut child = {
        // Raw std bypasses cosca's spawn path and its internal `spawn_lock()`, so it is taken here
        // by hand: a macOS fork must not transiently inherit another test's fd-marker write end.
        let _guard = crate::child::spawn::spawn_lock();
        let mut cmd = if cfg!(windows) {
            let mut cmd = std::process::Command::new("findstr");
            cmd.arg("x");
            cmd
        } else {
            std::process::Command::new("cat")
        };
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child blocked on stdin")
    };
    let stdin = child.stdin.take().expect("piped stdin");
    let Resolved::Found(id) = ProcessId::of(child.id()) else {
        panic!("an unreaped child resolves");
    };
    (child, stdin, id)
}

/// `releases_ownership` is cosca's single Unix ownership classification: only `ECHILD` — something
/// else already reaped the child — says the pid may now name another process. Every other errno,
/// including a too-old kernel's `EINVAL` from `waitid(P_PIDFD)`, and any non-OS `io::Error` —
/// including `tokio_wait_blocking`'s own "reapable, yet nothing waiting" error (see
/// `wait_does_not_release_ownership_when_its_own_reap_finds_no_exit_waiting`), which tokio 1.53 never reports
/// as a genuine foreign reap — says nothing about ownership and must not release the child.
#[cfg(unix)]
#[test]
fn releases_ownership_is_true_only_for_echild() {
    assert!(
        super::releases_ownership(&std::io::Error::from_raw_os_error(libc::ECHILD)),
        "ECHILD means something else already reaped the child"
    );
    assert!(
        !super::releases_ownership(&std::io::Error::from_raw_os_error(libc::EINVAL)),
        "EINVAL (a too-old kernel's waitid(P_PIDFD)) says nothing about ownership"
    );
    assert!(
        !super::releases_ownership(&std::io::Error::from_raw_os_error(libc::EAGAIN)),
        "a transient errno says nothing about ownership"
    );
    assert!(
        !super::releases_ownership(&std::io::Error::other("transient failure")),
        "a non-OS error says nothing about ownership"
    );
}

/// `wait_status_raw` is `bare_wait`'s pure encoding of a `waitid` result as `waitpid` would report
/// it. A signalled exit's core-dump bit (`0x80`) must survive alongside the signal number, not be
/// dropped by the `& 0x7f` mask: `status.dumped()` (rustix's `WaitIdStatus::dumped`) is the only
/// input that tells the two apart, since a coredumped exit still reports the signal that caused it.
#[cfg(target_os = "linux")]
#[test]
fn wait_status_raw_sets_the_coredump_bit_only_when_the_child_dumped() {
    use std::os::unix::process::ExitStatusExt;

    let dumped = std::process::ExitStatus::from_raw(super::wait_status_raw(None, Some(libc::SIGSEGV), true));
    assert_eq!(dumped.signal(), Some(libc::SIGSEGV), "{dumped:?}");
    assert!(
        dumped.core_dumped(),
        "the core-dump bit must survive the encoding: {dumped:?}"
    );

    let not_dumped = std::process::ExitStatus::from_raw(super::wait_status_raw(None, Some(libc::SIGSEGV), false));
    assert_eq!(not_dumped.signal(), Some(libc::SIGSEGV), "{not_dumped:?}");
    assert!(
        !not_dumped.core_dumped(),
        "a signalled exit that did not dump core must not report one: {not_dumped:?}"
    );

    let exited = std::process::ExitStatus::from_raw(super::wait_status_raw(Some(0), None, false));
    assert_eq!(exited.code(), Some(0), "{exited:?}");
    assert!(!exited.core_dumped(), "a clean exit never dumps core: {exited:?}");

    // Raw status `0` is indistinguishable from a real clean exit: `WIFEXITED(0)` is true (the
    // low 7 bits are 0) and `WEXITSTATUS(0)` is 0, on every POSIX encoding, so `wait_status_raw`'s
    // `(None, None)` fallback decodes as `code() == Some(0)`, not as "nothing happened".
    let neither = std::process::ExitStatus::from_raw(super::wait_status_raw(None, None, false));
    assert_eq!(neither.code(), Some(0), "{neither:?}");
    assert_eq!(neither.signal(), None, "{neither:?}");
}

#[test]
fn wait_blocks_until_the_child_exits_and_reaps_it() {
    let (child, stdin, id) = blocked_child();
    let unreaped = Unreaped::new(Held::Std(child));
    assert_eq!(unreaped.pid(), id.pid());
    drop(stdin);
    let status = unreaped.wait().expect("wait for the child");
    // Its own exit, on end of input: `cat` succeeds, and `findstr` finds no match.
    assert_eq!(status.code(), Some(if cfg!(windows) { 1 } else { 0 }), "{status:?}");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// `Drop` waits: the child is still running when the `Unreaped` drops, and reaped once it returns
/// — a `Drop` that did not wait would leave it running, or a zombie still holding its identity.
#[test]
fn drop_blocks_until_the_child_exits_and_reaps_it() {
    let (child, stdin, id) = blocked_child();
    let unreaped = Unreaped::new(Held::Std(child));
    drop(stdin);
    drop(unreaped);
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// `Drop` is the implicit path, unlike `wait`: it logs one line on the success path too, not only
/// on a failed wait (see `drop_blocks_until_the_child_exits_and_reaps_it` for the reap itself).
#[test]
fn drop_logs_when_it_reaps_the_child() {
    crate::log_capture::install();
    let child = crate::test_child::spawn_a_process_that_exits();
    let pid = child.id();
    let unreaped = Unreaped::new(Held::Std(child));
    let mark = crate::log_capture::mark();
    drop(unreaped);
    assert!(
        crate::log_capture::contains_since(mark, &format!("reaped unkillable child {pid}")),
        "an implicit drop must be logged even when the wait succeeds"
    );
}

/// `leak` gives the child up without reaping it, and says so: here the child, once it exits, is
/// still this process's to reap, which only an unreaped child is.
#[cfg(unix)]
#[test]
fn leak_gives_the_child_up_unreaped_and_logs_it() {
    crate::log_capture::install();
    let (child, stdin, id) = blocked_child();
    let unreaped = Unreaped::new(Held::Std(child));
    let mark = crate::log_capture::mark();
    unreaped.leak();
    assert!(
        crate::log_capture::contains_since(mark, &format!("leaking unkillable child {}", id.pid())),
        "a leak must be logged"
    );
    drop(stdin);
    let pid = nix::unistd::Pid::from_raw(id.pid() as i32);
    nix::sys::wait::waitpid(pid, None).expect("a leaked child is left unreaped");
}

/// Regression test for the pid/pgid recycle hazard `sweep_recyclable_pgid_before_reap` fixes:
/// before that fix, `wait`'s own `held.wait()` reaped the root FIRST, and only then dropped
/// `self.retained` — whose `Drop for Marker` (armed, unconditionally) fires `hard_kill`'s pass-1
/// `killpg` (see its own doc) on a pgid the OS was, by then, already free to have recycled onto an
/// unrelated, live process group. This observes the sweep from the inside — a hook fired from
/// within `Marker::hard_kill` itself (see `fault::set_hard_kill_hook`'s doc) — and asserts the
/// root pid was still a reapable zombie, never yet actually reaped (so its pgid could not yet
/// have been recycled), at the exact moment the sweep ran.
#[cfg(target_os = "macos")]
#[test]
fn wait_sweeps_a_retained_recyclable_marker_while_its_root_pid_is_still_a_zombie() {
    use std::os::unix::process::CommandExt;

    // See `blocked_child`'s own guard: a real install()+spawn() must not race a concurrent
    // fork elsewhere in this shared test binary while the marker's write end is open.
    let _guard = crate::child::spawn::spawn_lock();
    let mut cmd = std::process::Command::new("cat");
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .process_group(0); // a fresh pgid == this child's own pid, with no other members
    let prepared = crate::containment::fdmarker::install(&mut cmd, &[]).expect("install");
    let mut child = cmd.spawn().expect("spawn a child blocked on stdin");
    // `install`'s own contract: drop `cmd` promptly, so this supervisor's copy of the marker's
    // write end (which `cmd` itself still owns post-spawn) does not linger and get found as a
    // "holder" by this marker's own sweep below.
    drop(cmd);
    let stdin = child.stdin.take().expect("piped stdin");
    let pid = child.id();

    let marker = crate::containment::fdmarker::Marker::new(prepared, None, Some(pid as i32), false);
    let key = marker.hard_kill_test_key();

    let zombie_at_sweep: std::sync::Arc<std::sync::Mutex<Option<bool>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let flag = std::sync::Arc::clone(&zombie_at_sweep);
    crate::containment::fdmarker::fault::set_hard_kill_hook(
        key,
        Box::new(move || {
            // SAFETY: a well-formed `waitid`; `info` is an owned, zeroed `siginfo_t`. `WNOWAIT`
            // never reaps, so this can never disturb `wait`'s own reap a few lines below. `WNOHANG`
            // makes this a genuine PROBE rather than a second wait: without it, a mutant that
            // deletes the confirmatory `block_until_reapable` this hook exists to catch would just
            // have this call block until the same exit instead, still observing a zombie and
            // passing regardless (round-3 finding 1's test-quality gap) — `si_pid` stays `0` on a
            // `WNOHANG` call that found nothing yet, which is what actually distinguishes "already
            // a zombie" from "not yet", not merely `rc == 0`.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                )
            };
            *flag.lock().unwrap_or_else(|e| e.into_inner()) = Some(rc == 0 && info.si_pid == pid as libc::pid_t);
        }),
    );

    let retained = Retained {
        attached: crate::containment::Attached::FdMarker(marker),
    };
    let unreaped = Unreaped::with_retained(Held::Std(child), Some(retained));
    // Closing stdin BEFORE calling `wait()` (an earlier version of this test did) leaves the
    // window between that and `block_until_reapable`'s own `waitid` call unaccounted for: the
    // child becoming a zombie in time for the sweep below is then really an assertion on the OS
    // scheduler, not on this crate's own ordering (round-4 test-quality finding). Closing it from
    // a hook fired exactly as `block_until_reapable` is entered — not merely before `wait()` is
    // called — ties it to this crate's own ordering instead.
    crate::child::spawn::fault::set_before_block_until_reapable_hook(move || drop(stdin));
    let status = unreaped.wait().expect("wait for the child");

    assert_eq!(
        crate::containment::fdmarker::fault::take_hard_kill_calls(key),
        1,
        "the retained marker must be swept exactly once on this path"
    );
    assert_eq!(
        *zombie_at_sweep.lock().unwrap_or_else(|e| e.into_inner()),
        Some(true),
        "the sweep must run while the root pid is still a zombie (reapable, unrecycled) — before \
         wait's own reap frees it for a new process group to take. Got the pid already reaped \
         (Some(false)), or the sweep never ran at all (None)."
    );
    assert_eq!(
        status.code(),
        Some(0),
        "the child exited normally on EOF ({status:?}); a sweep that reached the root itself \
         (rather than only what it retained) would show up here as a signal, not a normal exit"
    );
}

/// Regression test for adversarial round-3 finding 1: before the fix,
/// `sweep_recyclable_pgid_before_reap` swept "regardless" even when its own confirmatory
/// `block_until_reapable` failed — sending a real `killpg` to a pgid it could no longer confirm
/// was still an unrecycled zombie's. Forces that confirmatory check to fail deterministically
/// (see `fault::set_force_block_until_reapable_error`'s doc for why a real recycle race cannot be
/// staged safely at all) against a REAL, still-running child in its own process group, so an
/// incorrect sweep would kill it for real.
#[cfg(unix)]
#[test]
fn sweep_skips_hard_kill_when_it_cannot_confirm_the_root_is_still_a_zombie() {
    use std::os::unix::process::CommandExt;

    let _guard = crate::child::spawn::spawn_lock();
    let mut cmd = std::process::Command::new("cat");
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .process_group(0); // a fresh pgid == this child's own pid, with no other members
    let mut child = cmd.spawn().expect("spawn a child blocked on stdin");
    let pid = child.id();
    let stdin = child.stdin.take().expect("piped stdin");

    crate::child::spawn::fault::set_force_block_until_reapable_error("forced: cannot confirm zombie");
    let retained = Box::new(Retained {
        attached: crate::containment::Attached::ProcessGroup(pid as i32),
    });
    let result = super::sweep_recyclable_pgid_before_reap(pid, retained);

    assert!(
        matches!(
            result.as_deref(),
            Some(Retained {
                attached: crate::containment::Attached::ProcessGroup(g)
            }) if *g == pid as i32
        ),
        "a confirmatory failure must hand the retention back unswept, for the caller's own \
         failed-wait branch to abandon: got {result:?}"
    );
    // A liveness probe (`kill(pid, 0)`) would be vacuous here: a `SIGKILL`ed-but-unreaped zombie
    // still answers `Ok(())`, same as a genuinely running process — round-4's own test-quality
    // finding. Reaping it and checking ITS signal is the only real proof an incorrect sweep did
    // not send it a real `SIGKILL` through `killpg` despite the confirmatory check having failed.
    drop(stdin); // let the child exit on EOF
    use std::os::unix::process::ExitStatusExt;
    let status = child.wait().expect("the child exits once stdin closes");
    assert_eq!(
        status.code(),
        Some(0),
        "the child must have exited normally, not been killed: got {status:?}"
    );
    assert_eq!(
        status.signal(),
        None,
        "the child must not have been signalled: got {status:?}"
    );
}

/// Positive twin of the skip test above, and of `wait_sweeps_a_retained_recyclable_marker_...`
/// (macOS's `FdMarker`): a `ProcessGroup` retention is the one Unix mechanism whose own `Drop`
/// never kills anything on its own (a bare pgid, no kernel resource) — the pre-reap sweep is its
/// ONLY kill-through path, not merely a safety net over some other backstop. This proves the
/// sweep actually reaches a SECOND process sharing the swept pgid, not only the root: a `hard_kill`
/// that only signalled the (already-dying) root and returned `None` regardless would pass every
/// other test here without ever killing anything through the group.
#[cfg(unix)]
#[test]
fn sweep_kills_through_a_live_process_group_when_it_confirms_the_root_is_still_a_zombie() {
    use std::os::unix::process::CommandExt;

    let _guard = crate::child::spawn::spawn_lock();
    let mut leader_cmd = std::process::Command::new("cat");
    leader_cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .process_group(0); // a fresh pgid == this child's own pid
    let mut leader = leader_cmd.spawn().expect("spawn the group leader");
    let pgid = leader.id();
    let leader_stdin = leader.stdin.take().expect("piped stdin");

    let mut member_cmd = std::process::Command::new("cat");
    member_cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .process_group(pgid as i32); // joins the leader's group, not a leader itself
    let mut member = member_cmd.spawn().expect("spawn a second member of the same group");
    let _member_stdin = member.stdin.take().expect("piped stdin"); // held open: member stays alive

    drop(leader_stdin); // let the leader exit on EOF, becoming a reapable zombie
    crate::child::unreaped::block_until_reapable(pgid).expect("wait for the leader's own exit");

    let retained = Box::new(Retained {
        attached: crate::containment::Attached::ProcessGroup(pgid as i32),
    });
    let result = super::sweep_recyclable_pgid_before_reap(pgid, retained);

    assert!(
        result.is_none(),
        "a confirmed sweep must fully consume the retention (nothing left to sweep again): got \
         {result:?}"
    );

    // A liveness probe (`kill(pid, 0)`) is not the right check here: a killed-but-unreaped
    // process is still a ZOMBIE, which `kill(pid, 0)` reports as alive (`Ok(())`) until
    // something actually reaps it — not `ESRCH`. Reaping it and checking ITS signal is the real
    // proof the group's `killpg` reached it, not only the root.
    use std::os::unix::process::ExitStatusExt;
    let member_status = member.wait().expect("reap the killed second member");
    assert_eq!(
        member_status.signal(),
        Some(libc::SIGKILL),
        "the second member of the swept group must have been killed: the sweep's killpg must \
         reach the whole group, not only the root; got {member_status:?}"
    );

    leader.wait().expect("reap the already-signalled zombie leader");
}

/// A group leader and a second member sharing its pgid, the leader's stdin piped (closing it lets
/// the leader exit on EOF while the member — blocked on its own, separately piped stdin — stays
/// alive) — the fixture round-4's per-call-site `ProcessGroup` sweep tests share: each drives a
/// REAL `Unreaped`/`Drop`/`wait` path (not `sweep_recyclable_pgid_before_reap` directly, as
/// `sweep_kills_through_a_live_process_group_when_it_confirms_the_root_is_still_a_zombie` above
/// does) and then asserts the MEMBER died by `SIGKILL` — the only proof a mutant that removes a
/// specific call site's sweep actually fails: a `kill(pid, 0)` liveness probe cannot tell a killed
/// zombie from a running one, so it is never used here.
#[cfg(unix)]
fn leader_and_member_in_one_process_group() -> (std::process::Child, std::process::ChildStdin, std::process::Child) {
    use std::os::unix::process::CommandExt;

    let _guard = crate::child::spawn::spawn_lock();
    let mut leader_cmd = std::process::Command::new("cat");
    leader_cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .process_group(0);
    let mut leader = leader_cmd.spawn().expect("spawn the group leader");
    let pgid = leader.id();
    let leader_stdin = leader.stdin.take().expect("piped stdin");

    let mut member_cmd = std::process::Command::new("cat");
    member_cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .process_group(pgid as i32);
    // Its own stdin is left `Some(..)` inside `member`, deliberately never taken or dropped: an
    // untaken piped stdin stays open, so the member has no EOF to exit on and stays genuinely
    // alive until something actually kills it.
    let member = member_cmd.spawn().expect("spawn a second member of the same group");
    (leader, leader_stdin, member)
}

/// Assert `member` was killed by `SIGKILL` (reaping it), the one proof a pre-reap `ProcessGroup`
/// sweep actually reached the whole group and not only the root.
#[cfg(unix)]
fn assert_member_was_sigkilled(mut member: std::process::Child) {
    use std::os::unix::process::ExitStatusExt;
    let status = member.wait().expect("reap the (hopefully killed) second member");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the second member of the swept group must have been killed by the sweep's killpg, not \
         merely the root — got {status:?}"
    );
}

/// Round-4 finding (mutant M1): the pre-reap `ProcessGroup` sweep removed from the sync `wait`
/// call site specifically — see `leader_and_member_in_one_process_group`'s own doc for why a
/// `kill(pid, 0)` probe cannot catch this, only reaping the member and checking its signal can.
#[cfg(unix)]
#[test]
fn wait_sweeps_a_retained_process_group_while_its_root_pid_is_still_a_zombie() {
    let (leader, leader_stdin, member) = leader_and_member_in_one_process_group();
    let pid = leader.id();
    let retained = Retained {
        attached: crate::containment::Attached::ProcessGroup(pid as i32),
    };
    let unreaped = Unreaped::with_retained(Held::Std(leader), Some(retained));
    drop(leader_stdin); // let the leader exit on EOF
    unreaped.wait().expect("wait for the leader");
    assert_member_was_sigkilled(member);
}

/// Round-4 finding (mutant M2): the pre-reap `ProcessGroup` sweep removed from the sync `Drop`
/// fallback call site specifically.
#[cfg(unix)]
#[test]
fn drop_sweeps_a_retained_process_group_while_its_root_pid_is_still_a_zombie() {
    let (leader, leader_stdin, member) = leader_and_member_in_one_process_group();
    let pid = leader.id();
    let retained = Retained {
        attached: crate::containment::Attached::ProcessGroup(pid as i32),
    };
    let unreaped = Unreaped::with_retained(Held::Std(leader), Some(retained));
    drop(leader_stdin); // let the leader exit on EOF
    drop(unreaped); // blocks until the leader exits, then reaps it — sweeping first
    assert_member_was_sigkilled(member);
}

/// A tokio child that exits promptly, needing no external binary: this same test binary, re-run
/// with a `--exact` filter that matches nothing, so libtest runs zero tests and exits 0. Mirrors
/// `crate::test_child::spawn_a_process_that_exits`'s std-`Command` twin and
/// `crate::tokio::child::child_reap_tests`'s own copy of this idiom (private to each, so neither
/// can share it with this file).
#[cfg(all(unix, feature = "tokio"))]
fn spawn_a_tokio_child_that_exits() -> ::tokio::process::Child {
    // Raw tokio bypasses cosca's spawn path and its internal `spawn_lock()`, so it is taken here
    // by hand: a macOS fork must not transiently inherit another test's fd-marker write end.
    let _guard = crate::child::spawn::spawn_lock();
    ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "__cosca_no_such_test__"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn")
}

/// `Unreaped::wait`'s sync blocking path (`tokio_wait_blocking`) can find the child confirmed
/// reapable (`block_until_reapable`), then its own `try_wait` reports no exit waiting for it. That
/// is NOT a foreign reap: tokio 1.53's `try_wait`, like std's, reports a genuine foreign reap as
/// `ECHILD`, not `Ok(None)` — so this condition must not classify as ownership-uncertain. Doing so
/// (the bug this regression test guards against) would release the child by forgetting it, which
/// leaks the zombie for good, since nothing else in fact reaped it.
#[cfg(all(unix, feature = "tokio"))]
#[tokio::test]
async fn wait_does_not_release_ownership_when_its_own_reap_finds_no_exit_waiting() {
    let child = spawn_a_tokio_child_that_exits();
    let pid = child.id().expect("tokio owns an un-reaped child");
    let Resolved::Found(id) = ProcessId::of(pid) else {
        panic!("an unreaped child resolves");
    };
    // Real: the child must already be a genuine zombie before the seam below makes
    // `tokio_wait_blocking`'s OWN `try_wait` miss it, or this would not reproduce the condition.
    super::block_until_reapable(pid).expect("the child exits promptly");
    crate::child::spawn::fault::set_force_tokio_wait_blocking_miss();
    let unreaped = Unreaped::new(Held::Tokio(Box::new(child)));
    let err = unreaped.wait().expect_err("the forced miss must fail the wait");
    assert!(
        !super::releases_ownership(&err),
        "a reapable-yet-missed exit is not a foreign reap, and must not release ownership: {err}"
    );
    // Not forgotten: `settle_after_wait` released (not `release_uncertain`'d) the child, which for
    // a tokio child means a normal `drop` of the boxed `tokio::process::Child`. That drops tokio's
    // own `Reaper`/`PidfdReaper` (src/process/unix/{reap,pidfd_reaper}.rs in tokio 1.53.1), whose
    // `Drop` calls `try_wait` synchronously and only falls back to tokio's orphan queue if that
    // comes back empty. The child was already confirmed reapable above, so that synchronous
    // `try_wait` — which runs inside `wait()`, before it returns, not on tokio's signal driver
    // afterward — reaps it right there. Proving no leak (the bug this test guards against forgets
    // the child, leaving nothing to ever reap it) is therefore a direct assertion right after
    // `wait()` returns, not a poll: the reap has already happened by then, or not at all.
    assert!(
        !matches!(ProcessId::of(pid), Resolved::Found(found) if found == id),
        "tokio never reaped the child: forgetting it (the bug this test guards against) leaks it exactly like this"
    );
}
