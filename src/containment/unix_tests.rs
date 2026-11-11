// Unit tests for the Unix process-group signal wrappers.
// Substantive end-to-end coverage is in the integration test
// (`unix_kill_tree_reaps_the_grandchild` in `tests/spawn_io.rs`).

use super::{kill_group, term_group};
use crate::test_support::stated_root::StatedRoot;

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
#[skuld::test]
fn kill_group_and_term_group_reject_non_positive_pgid() {
    for pgid in [0, -1, i32::MIN] {
        let kill_err =
            kill_group(pgid, Some(&StatedRoot::unreaped())).expect_err("kill_group(non-positive) must be Err");
        assert!(
            matches!(kill_err, crate::error::Error::Unassessable { .. }),
            "got {kill_err:?}"
        );
        let term_err =
            term_group(pgid, Some(&StatedRoot::unreaped())).expect_err("term_group(non-positive) must be Err");
        assert!(
            matches!(term_err, crate::error::Error::Unassessable { .. }),
            "got {term_err:?}"
        );
    }
}

/// kill_group on a real owned process group succeeds, and really did kill it.
#[skuld::test]
fn kill_group_on_owned_group_succeeds() {
    use std::os::unix::process::CommandExt;
    use std::os::unix::process::ExitStatusExt as _;
    // Spawn a child in its own private group (pgid == child pid) so we can
    // SIGKILL it without disturbing the test runner's own group.
    let mut child = crate::test_spawn::spawn(
        std::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .process_group(0),
    )
    .expect("spawn cat");
    // Closed right after the kill: a `kill_group` that signals nothing exits 0.
    let stdin = child.stdin.take().expect("piped stdin");
    let pgid = child.id() as i32;
    assert!(
        kill_group(pgid, Some(&StatedRoot::unreaped())).is_ok(),
        "kill_group on owned group must succeed"
    );
    drop(stdin);
    let status = child.wait().expect("wait after kill_group");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "kill_group must have actually killed the leader, got {status:?}"
    );
}

/// `kill_group`'s `killpg` dooms the group BEFORE `converge` lists it: a member cannot fork once
/// its `SIGKILL` is pending, so the process the listing never saw is never created. Without that
/// first `killpg`, `converge`'s per-member resend is the only delivery, and a member that forks
/// in the window between the listing and its own signal leaves a survivor no one signals.
///
/// The leader is a shell that forks a process, writing `spawned`, for each line it reads. The
/// hook, fired in `converge` right after the listing, feeds it one line and reads one back from a
/// stdout only the group holds. With the first `killpg` the shell is already dead, so the write
/// finds no reader (`EPIPE`, ignored) and the read is EOF: empty. Without it the shell forks, and
/// the read returns `spawned`.
///
/// Linux only: `fork` refuses once a fatal signal is pending; no such guarantee is asserted elsewhere.
#[cfg(target_os = "linux")]
#[skuld::test]
fn kill_group_dooms_the_group_before_it_is_listed() {
    use std::io::BufRead as _;
    use std::os::unix::process::CommandExt;
    use std::os::unix::process::ExitStatusExt as _;

    let mut child = crate::test_spawn::spawn(
        std::process::Command::new("sh")
            .arg("-c")
            .arg("while read x; do (echo spawned; exec cat) & done")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .process_group(0),
    )
    .expect("spawn the leader");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let pgid = child.id() as i32;

    let seen = std::rc::Rc::new(std::cell::RefCell::new(None::<String>));
    let record = seen.clone();
    let _armed = super::group::fault::set_after_listing(move || {
        crate::test_child::write_to_possibly_dead_stdin(&mut stdin, b"x\n");
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read to a line or EOF");
        *record.borrow_mut() = Some(line);
    });
    kill_group(pgid, Some(&StatedRoot::unreaped())).expect("kill_group on an owned group");

    let status = child.wait().expect("reap the leader");
    let line = seen.borrow_mut().take().expect("the hook ran in converge");
    assert_eq!(
        line, "",
        "a member forked after the listing: the first killpg did not doom the group"
    );
    assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
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
#[skuld::test]
fn term_group_on_owned_group_succeeds() {
    use std::os::unix::process::{CommandExt, ExitStatusExt as _};
    // `cat` installs no SIGTERM handler of its own, so a delivered SIGTERM actually ends it —
    // distinguishing "exited because of the signal" from "merely stayed reachable". Its stdin is
    // closed right after the call: a `term_group` that delivers nothing exits 0.
    let mut child = crate::test_spawn::spawn(
        std::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .process_group(0),
    )
    .expect("spawn cat");
    let stdin = child.stdin.take().expect("piped stdin");
    let pgid = child.id() as i32;
    assert!(
        term_group(pgid, Some(&StatedRoot::unreaped())).is_ok(),
        "term_group on owned group must succeed"
    );
    drop(stdin);
    let status = child.wait().expect("wait after term_group");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
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
#[skuld::test]
fn kill_group_on_an_all_zombie_group_is_ok() {
    use std::os::unix::process::CommandExt;
    let child = crate::test_spawn::spawn(std::process::Command::new("true").process_group(0)).expect("spawn true");
    let pid = child.id();
    await_zombie(pid);

    #[cfg(target_os = "macos")]
    assert_eq!(
        nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid as i32), None),
        Err(nix::errno::Errno::EPERM),
        "macOS reports EPERM for an all-zombie group; if this changed, the arm under test moved"
    );

    assert!(
        kill_group(pid as i32, Some(&StatedRoot::unreaped())).is_ok(),
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
#[skuld::test]
fn term_group_on_an_all_zombie_group_is_ok() {
    use std::os::unix::process::CommandExt;
    let child = crate::test_spawn::spawn(std::process::Command::new("true").process_group(0)).expect("spawn true");
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
        term_group(pid as i32, Some(&StatedRoot::unreaped())).is_ok(),
        "a group holding only a zombie is already down"
    );
    let mut child = child;
    child.wait().expect("reap");
}

// What a group's kill and terminate decide on one look at the root -----

mod group_kill_and_terminate {
    use super::super::{fault, kill_group_tree, term_group_tree};
    use crate::containment::dispatch::TreeKillOutcome;
    use crate::containment::{Refusal, TerminateOutcome, Why};
    use crate::identity::{ProcessId, Resolved};
    use crate::signal::RootState;
    use crate::test_support::stated_root::StatedRoot;

    /// A pgid no test process holds: the recorders stand in for the sends.
    const PGID: i32 = 999_999;

    /// How the root's own handle and its pid read, for a row.
    #[derive(Clone, Copy, Debug)]
    enum Root {
        Unreaped,
        ReapedElsewhere,
        OwnReapGone,
        OwnReapTaken,
        OwnReapUnreadable,
        Unknown,
    }

    fn stated(root: Root) -> StatedRoot<'static> {
        StatedRoot::with_state(PGID as u32, move || match root {
            Root::Unreaped => RootState::Unreaped,
            Root::ReapedElsewhere => RootState::Reaped { own: false },
            Root::OwnReapGone | Root::OwnReapTaken | Root::OwnReapUnreadable => RootState::Reaped { own: true },
            Root::Unknown => RootState::Unknown(std::io::Error::other("a failed peek")),
        })
    }

    /// Arms what the root's pid reads as for `root`, until the guard drops.
    fn read(root: Root) -> Option<crate::child::fault::ForcedRootReads> {
        let other = ProcessId::from_parts_for_test(PGID as u32, crate::identity::Key::for_test(1));
        let read = match root {
            Root::OwnReapGone => Resolved::Gone,
            Root::OwnReapTaken => Resolved::Found(other),
            Root::OwnReapUnreadable => Resolved::Unknown,
            _ => return None,
        };
        Some(crate::child::fault::force_root_reads(read))
    }

    /// What a skipped kill or terminate says it did not do, and why.
    fn assert_skip(skip: &crate::containment::Skip, verb: &str, root: Root) {
        assert_eq!(
            skip.action,
            format!("{verb} its process group (pgid {PGID})"),
            "{root:?}"
        );
        assert!(skip.holders.is_none(), "a group has no holders: {root:?}");
        match (&skip.why, root) {
            (Why::MayNameAnother(Refusal::ReapedElsewhere(_)), Root::ReapedElsewhere)
            | (Why::MayNameAnother(Refusal::ReapedPidGone(_)), Root::OwnReapGone)
            | (Why::MayNameAnother(Refusal::ReapedPidUnread(_)), Root::OwnReapUnreadable) => {
                assert!(!skip.root_alone, "{root:?}");
            }
            (Why::MayNameAnother(Refusal::Unsure(..)), Root::Unknown) => {
                assert_eq!(skip.root_alone, cfg!(target_os = "linux"), "{root:?}");
            }
            // macOS trusts no number its root's handle cannot answer for.
            (Why::Untrusted(_), Root::Unknown) if cfg!(target_os = "macos") => {}
            (why, _) => panic!("{root:?} was skipped for {why:?}"),
        }
    }

    /// The kill: sent as usual while the root's number names it; nothing is sent once the group is
    /// empty ([`TreeKillOutcome::Answered`]); and skipped, nothing sent by the number, when the number
    /// may name another process.
    #[skuld::test]
    fn a_group_kill_sends_or_skips_by_the_roots_state() {
        for root in [
            Root::Unreaped,
            Root::ReapedElsewhere,
            Root::OwnReapGone,
            Root::OwnReapTaken,
            Root::OwnReapUnreadable,
            Root::Unknown,
        ] {
            let _read = read(root);
            let recorder = fault::record_kill_group();
            let outcome = kill_group_tree(PGID, Some(&stated(root)));
            let sent = recorder.killed();
            match (root, outcome) {
                (Root::Unreaped, TreeKillOutcome::Ran(Ok(()))) => assert_eq!(sent, [PGID], "{root:?}"),
                (Root::OwnReapTaken, TreeKillOutcome::Answered(Ok(()))) => {
                    assert_eq!(sent, Vec::<i32>::new(), "{root:?}");
                }
                (_, TreeKillOutcome::Skipped(skip)) => {
                    assert_eq!(sent, Vec::<i32>::new(), "{root:?}");
                    assert_skip(&skip, "kill", root);
                }
                (_, outcome) => panic!("{root:?} was answered {outcome:?}"),
            }
        }
    }

    /// With no root there is nothing to look at: the kill is sent as asked.
    #[skuld::test]
    fn a_group_kill_with_no_root_is_sent_as_asked() {
        let recorder = fault::record_kill_group();
        // Not a debug build's `check_number` contract breach: the recorder answers before any send.
        let outcome = kill_group_tree(PGID, None);
        assert!(matches!(outcome, TreeKillOutcome::Ran(Ok(()))), "{outcome:?}");
        assert_eq!(recorder.killed(), [PGID]);
    }

    /// The terminate: the same decisions, with a skip ending the call, and on Linux, for a root its
    /// handle cannot answer for, leaving the root alone to the caller through its handle.
    #[skuld::test]
    fn a_group_terminate_sends_or_skips_by_the_roots_state() {
        for root in [
            Root::Unreaped,
            Root::ReapedElsewhere,
            Root::OwnReapGone,
            Root::OwnReapTaken,
            Root::OwnReapUnreadable,
            Root::Unknown,
        ] {
            let _read = read(root);
            let recorder = fault::record_term_group();
            let outcome = term_group_tree(PGID, Some(&stated(root)));
            let sent = recorder.termed();
            match (root, outcome) {
                (
                    Root::Unreaped,
                    TerminateOutcome::Sent {
                        result: Ok(()),
                        earlier: Some("the SIGTERM"),
                    },
                ) => assert_eq!(sent, [PGID], "{root:?}"),
                (
                    Root::OwnReapTaken,
                    TerminateOutcome::Sent {
                        result: Ok(()),
                        earlier: None,
                    },
                ) => assert_eq!(sent, Vec::<i32>::new(), "{root:?}"),
                // Only Linux has a pidfd to name the root with.
                (Root::Unknown, TerminateOutcome::RootThroughPidfd(skip)) if cfg!(target_os = "linux") => {
                    assert_eq!(sent, Vec::<i32>::new(), "{root:?}");
                    assert_skip(&skip, "signal", root);
                }
                (_, TerminateOutcome::End(skip)) => {
                    assert_eq!(sent, Vec::<i32>::new(), "{root:?}");
                    assert_skip(&skip, "signal", root);
                }
                (_, outcome) => panic!("{root:?} was answered {outcome:?}"),
            }
        }
    }
}
