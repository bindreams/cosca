// Unit tests for the Unix process-group signal wrappers.
// Substantive end-to-end coverage is in the integration test
// (`unix_kill_tree_reaps_the_grandchild` in `tests/spawn_io.rs`).

use super::{kill_group, term_group};
use crate::test_groups::{stray_signal, Group};
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
fn kill_group_and_term_group_reject_non_positive_pgid(#[fixture(stray_signal)] _stray: &Group) {
    for pgid in [0, -1, i32::MIN] {
        let kill_err = kill_group(pgid, Some(&StatedRoot::unreaped()), &mut Vec::new())
            .expect_err("kill_group(non-positive) must be Err");
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

/// A `pgid <= 0` refusal is a terminate that sent nothing: the tree call ends with it, with no grace.
///
/// Mutant: the refusal is a `Sent { result: Err(..) }`, which `graceful_shutdown_tree` holds for.
#[skuld::test]
fn term_group_tree_of_a_non_positive_pgid_says_nothing_was_sent(#[fixture(stray_signal)] _stray: &Group) {
    for pgid in [0, -1, i32::MIN] {
        match super::term_group_tree(pgid, Some(&StatedRoot::unreaped())) {
            crate::containment::TerminateOutcome::NotSent(crate::error::Error::Unassessable {
                source: None, ..
            }) => {}
            other => panic!("pgid {pgid}: expected NotSent(Unassessable), got {other:?}"),
        }
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
        kill_group(pgid, Some(&StatedRoot::unreaped()), &mut Vec::new()).is_ok(),
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
    kill_group(pgid, Some(&StatedRoot::unreaped()), &mut Vec::new()).expect("kill_group on an owned group");

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
        kill_group(pid as i32, Some(&StatedRoot::unreaped()), &mut Vec::new()).is_ok(),
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
            Root::Unknown => RootState::Unknown(std::sync::Arc::new(std::io::Error::other("a failed peek"))),
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
            (Why::MayNameAnother(Refusal::ReapedElsewhere(_), _), Root::ReapedElsewhere)
            | (Why::MayNameAnother(Refusal::ReapedPidGone(_), _), Root::OwnReapGone)
            | (Why::MayNameAnother(Refusal::ReapedPidUnread(..), _), Root::OwnReapUnreadable) => {
                assert!(!skip.root_alone, "{root:?}");
            }
            (Why::MayNameAnother(Refusal::Unsure(..), _), Root::Unknown) => {
                assert_eq!(skip.root_alone, cfg!(target_os = "linux"), "{root:?}");
            }
            // macOS trusts no number its root's handle cannot answer for.
            (Why::Untrusted { .. }, Root::Unknown) if cfg!(target_os = "macos") => {}
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
            let outcome = kill_group_tree(PGID, Some(&stated(root))).outcome();
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
                        ..
                    },
                ) => assert_eq!(sent, [PGID], "{root:?}"),
                (
                    Root::OwnReapTaken,
                    TerminateOutcome::Sent {
                        result: Ok(()),
                        earlier: None,
                        ..
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

/// A group's send refused because its root's handle could not say whether the root was reaped is
/// `Unassessable` with the handle's error as its `source()`, so the OS code is reachable, and not in
/// the `detail`. Nothing is sent: the check fails first.
///
/// Mutant: the error is folded into the text and no source is kept.
#[skuld::test]
fn a_send_refused_for_an_unsure_root_has_the_handles_error_as_its_source() {
    use super::send_to_group;
    use crate::error::Error;
    use crate::signal::RootState;

    let os_error = std::io::Error::from_raw_os_error(libc::EPERM).to_string();
    let root = StatedRoot::with_state(999_999, || {
        RootState::Unknown(std::sync::Arc::new(std::io::Error::from_raw_os_error(libc::EPERM)))
    });

    let refused = send_to_group(999_999, nix::sys::signal::Signal::SIGTERM, Some(&root))
        .expect_err("a root that cannot say is no check that passes");

    let Error::Unassessable { detail, .. } = &refused else {
        panic!("got {refused:?}");
    };
    assert_eq!(crate::error::first_os_code(&refused), Some(libc::EPERM), "{refused:?}");
    assert!(!detail.contains(&os_error), "{detail}");
}

/// A skip over an untrusted root (macOS reads it; the answer is built on every Unix) answers
/// `Unassessable` with the handle's error as its `source()`, and not in the `detail`.
#[skuld::test]
fn a_skip_over_an_untrusted_root_has_the_handles_error_as_its_source() {
    use super::skipped_group;
    use crate::containment::dispatch::TreeSignal;
    use crate::containment::root::NumberLook;
    use crate::containment::{SkipCall, Tree};
    use crate::error::Error;
    use crate::signal::RootState;

    let os_error = std::io::Error::from_raw_os_error(libc::EPERM).to_string();
    let call = SkipCall {
        op: "skip_untrusted_probe_4c2",
        pid: 999_999,
        signal: TreeSignal::Term,
        earlier: None,
    };
    let skip = skipped_group(
        999_999,
        "kill",
        NumberLook::Untrusted(RootState::Unknown(std::sync::Arc::new(
            std::io::Error::from_raw_os_error(libc::EPERM),
        ))),
    );

    let answer = call
        .answer(&Tree::none(), skip, None)
        .answer
        .expect_err("a skipped call is no success");

    let Error::Unassessable { detail, .. } = &answer else {
        panic!("got {answer:?}");
    };
    assert_eq!(crate::error::first_os_code(&answer), Some(libc::EPERM), "{answer:?}");
    assert!(!detail.contains(&os_error), "{detail}");
}

/// The handle's error of an untrusted root (macOS: `RootState::Unknown`, whose error is an
/// `io_context` over the OS error) keeps its OS code in the copy the skip holds, so the answer's
/// `source()` reaches it.
///
/// Mutant: the copy reads the code of the outer error only.
#[skuld::test]
fn a_skip_over_an_untrusted_root_with_a_context_error_keeps_its_os_code() {
    use super::skipped_group;
    use crate::containment::dispatch::TreeSignal;
    use crate::containment::root::NumberLook;
    use crate::containment::{SkipCall, Tree};
    use crate::signal::RootState;

    let call = SkipCall {
        op: "skip_untrusted_context_probe",
        pid: 999_999,
        signal: TreeSignal::Term,
        earlier: None,
    };
    let handle_error = crate::error::io_context(
        "the root could not be peeked",
        std::io::Error::from_raw_os_error(libc::EPERM),
    );
    let skip = skipped_group(
        999_999,
        "kill",
        NumberLook::Untrusted(RootState::Unknown(std::sync::Arc::new(handle_error))),
    );

    let answer = call
        .answer(&Tree::none(), skip, None)
        .answer
        .expect_err("a skipped call is no success");

    assert_eq!(crate::error::first_os_code(&answer), Some(libc::EPERM), "{answer:?}");
}

// What a group that was not cleared answers =====

/// A member's cause: the OS error `code`.
fn member_cause(code: i32) -> crate::error::Error {
    crate::error::Error::Io(std::io::Error::from_raw_os_error(code))
}

/// The members of the `Several` an error holds as its `source`, as `(pid named, OS code)`.
fn members_below(error: &crate::error::Error) -> Vec<(String, Option<i32>)> {
    use std::error::Error as _;
    let source = error.source().and_then(|s| s.downcast_ref::<crate::error::Error>());
    let Some(crate::error::Error::Several(list)) = source else {
        panic!("expected a Several below the variant: {error:?}");
    };
    list.iter()
        .map(|member| (member.to_string(), crate::error::first_os_code(&**member)))
        .collect()
}

/// A group with refusers and unassessable members answers `Containment`, with each member's own
/// cause as a member of the `Several` below it, the refusers first, and none of their words in the
/// detail.
///
/// Mutants: the members are reduced to a list of pids; the unassessable members are dropped when a
/// refuser settles the verdict; a cause is put in the detail.
#[skuld::test]
fn a_group_with_refusers_answers_containment_with_every_members_cause() {
    use super::group::GroupState;
    use crate::error::Error;

    let answer = super::answer_of(
        GroupState::Refused {
            refused: vec![(7, member_cause(libc::EPERM)), (8, member_cause(libc::EACCES))],
            unassessable: vec![(9, member_cause(libc::EIO))],
        },
        42,
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect_err("the group was not cleared");

    let Error::Containment { detail, .. } = &answer else {
        panic!("{answer:?}");
    };
    assert!(detail.contains("SIGKILL") && detail.contains("42"), "{detail}");
    assert!(
        !detail.contains(&std::io::Error::from_raw_os_error(libc::EPERM).to_string()),
        "{detail}"
    );
    let members = members_below(&answer);
    let codes: Vec<_> = members.iter().map(|(_, code)| *code).collect();
    assert_eq!(codes, [Some(libc::EPERM), Some(libc::EACCES), Some(libc::EIO)]);
    for ((said, _), pid) in members.iter().zip([7, 8, 9]) {
        assert!(said.contains(&format!("pid {pid}")), "{said}");
    }
}

/// One member that refused is the whole cause: no list of one.
#[skuld::test]
fn a_group_with_one_refuser_has_that_member_as_its_cause() {
    use super::group::GroupState;
    use crate::error::Error;
    use std::error::Error as _;

    let answer = super::answer_of(
        GroupState::Refused {
            refused: vec![(7, member_cause(libc::EPERM))],
            unassessable: vec![],
        },
        42,
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect_err("the group was not cleared");

    let source = answer.source().and_then(|s| s.downcast_ref::<Error>());
    assert!(
        matches!(source, Some(Error::Containment { detail, .. }) if detail.contains("pid 7")),
        "{answer:?}"
    );
    assert_eq!(crate::error::first_os_code(&answer), Some(libc::EPERM));
}

/// A group whose members could only not be assessed answers `Unassessable`, with each member's cause.
#[skuld::test]
fn a_group_with_only_unassessable_members_answers_unassessable_with_every_cause() {
    use super::group::GroupState;
    use crate::error::Error;

    let answer = super::answer_of(
        GroupState::Unassessed {
            members: vec![(5, member_cause(libc::EIO)), (6, member_cause(libc::EACCES))],
        },
        42,
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect_err("the group was not cleared");

    let Error::Unassessable { detail, .. } = &answer else {
        panic!("{answer:?}");
    };
    assert!(
        !detail.contains(&std::io::Error::from_raw_os_error(libc::EIO).to_string()),
        "{detail}"
    );
    let codes: Vec<_> = members_below(&answer).iter().map(|(_, code)| *code).collect();
    assert_eq!(codes, [Some(libc::EIO), Some(libc::EACCES)]);
}

/// A group whose listing is refused answers `Unsupported` naming the listing and the requirement, as a
/// wait, a spawn or the process snapshot does. Mutant: "a refused listing is an unassessable group".
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_group_whose_listing_is_refused_answers_unsupported() {
    use rustix::io::Errno;

    use super::group::{GroupState, ListingFailure};
    use crate::error::Error;

    let refusal = crate::identity::FailedCall::openat2(Errno::PERM)
        .refusal()
        .expect("an openat2 answering EPERM is a refusal");
    let answer = super::answer_of(
        GroupState::Unlistable {
            detail: "process group 42 could not be listed".to_owned(),
            source: ListingFailure::Unsupported(refusal.unsupported("listing process group 42")),
        },
        42,
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect_err("the group was not cleared");
    let Error::Unsupported { op, detail, .. } = &answer else {
        panic!("{answer:?}");
    };
    assert_eq!(op, "listing process group 42");
    assert!(detail.contains("requires openat2"), "{detail}");
    assert_eq!(crate::error::first_os_code(&answer), Some(libc::EPERM));
}

/// A listing that failed is no refusal, whatever its error's kind: std maps `ENOSYS` to `Unsupported`,
/// and a listing that answers `ENOSYS` of its own is an unassessable group. Mutant: "an `io::Error` of
/// kind `Unsupported` is a refusal".
#[skuld::test]
fn a_group_whose_listing_failed_with_an_enosys_of_its_own_answers_unassessable() {
    use super::group::{GroupState, ListingFailure};
    use crate::error::Error;

    let source = std::io::Error::from_raw_os_error(libc::ENOSYS);
    assert_eq!(
        source.kind(),
        std::io::ErrorKind::Unsupported,
        "std maps ENOSYS to Unsupported"
    );
    let answer = super::answer_of(
        GroupState::Unlistable {
            detail: "process group 42 could not be listed".to_owned(),
            source: ListingFailure::Failed(source),
        },
        42,
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect_err("the group was not cleared");
    assert!(matches!(answer, Error::Unassessable { .. }), "{answer:?}");
    assert_eq!(crate::error::first_os_code(&answer), Some(libc::ENOSYS));
}

/// End to end, from a `/proc` listing: `members`, `state` and `answer_of` answer `Unassessable` carrying
/// the errno. Mutant: "a failure after the open that std maps to `Unsupported` is a refusal".
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_listing_that_fails_after_its_open_with_enosys_answers_unassessable() {
    use crate::error::Error;
    use crate::identity::{FakeKernel, HostKernel};

    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_pids_failing_after_open(libc::ENOSYS);
    let signal = nix::sys::signal::Signal::SIGKILL;
    let answer = super::answer_of(
        super::group::state(&kernel, 42, signal, None, &mut Vec::new()),
        42,
        signal,
    )
    .expect_err("a group that cannot be listed is not cleared");
    assert!(matches!(answer, Error::Unassessable { .. }), "{answer:?}");
    assert_eq!(crate::error::first_os_code(&answer), Some(libc::ENOSYS), "{answer:?}");
}
