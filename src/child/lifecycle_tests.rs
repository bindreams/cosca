//! Unit tests for the public `Child::wait_tree`/`wait_tree_timeout`. Every test branches on
//! `Containment::can_observe_drain()` and asserts a real, non-trivial outcome on BOTH sides
//! rather than skipping either — this crate's "never silently skip" testing convention.

use std::time::Duration;

/// The `TreeDrain` variant a fully-drained tree reports on `containment`'s mechanism:
/// `AllMembersExited` everywhere authoritative (cgroup v2, Windows job object), but
/// `AllMarkersClosed` on macOS's advisory fd marker — see `TreeDrain`'s own doc for why the two
/// are not interchangeable. Centralized here so every test below asserts the SAME real,
/// mechanism-correct verdict rather than assuming the authoritative one everywhere.
fn expected_drained_verdict(containment: crate::containment::Containment) -> crate::containment::TreeDrain {
    match containment {
        crate::containment::Containment::FdMarker => crate::containment::TreeDrain::AllMarkersClosed,
        _ => crate::containment::TreeDrain::AllMembersExited,
    }
}

/// A quick, self-terminating contained child: the drain edge (when the mechanism has one)
/// fires almost immediately, so an UNBOUNDED `wait_tree()` call below is safe — it is a real
/// blocking wait on a genuinely-terminating event, not an indefinite one.
fn quick_contained_child() -> crate::Child {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["true"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "exit 0"]);
    cmd.contain();
    cmd.spawn().expect("spawn")
}

/// A contained blocker and its stdin writer, which the caller must keep for exactly as long as the
/// child must stay running. On Windows it is `more.com`, not the `findstr` of
/// [`crate::test_child::BLOCKER_ARGV`]: released stdin must not look like a kill to
/// [`crate::test_child::assert_killed`].
fn long_lived_contained_child() -> (crate::Child, std::io::PipeWriter) {
    #[cfg(unix)]
    {
        crate::test_child::held_contained_blocker(crate::Stdio::null())
    }
    #[cfg(windows)]
    {
        crate::test_child::windows_blocker()
    }
}

/// Kill, release stdin, reap. Releasing after the kill makes a no-op `kill_tree` fail the status
/// assertion.
fn kill_then_release(child: crate::Child, stdin: std::io::PipeWriter) {
    child.kill_tree().expect("kill_tree");
    drop(stdin);
    crate::test_child::assert_killed("the blocker", child.wait().expect("reap the blocker"));
}

/// Drained case: on a drain-observable mechanism, an unbounded `wait_tree()` against a tree
/// that fully exits on its own reports the mechanism-correct drained verdict
/// (`expected_drained_verdict`). On a mechanism with no kernel drain edge, the SAME call must
/// fail `Unsupported` instead — both are real, exercised assertions.
#[skuld::test]
fn wait_tree_reports_the_drained_verdict_when_the_tree_drains() {
    let child = quick_contained_child();
    let containment = child.containment();
    let drainable = containment.can_observe_drain();
    let result = child.wait_tree();
    if drainable {
        assert_eq!(
            result.expect("a fully-exited tree must report a drained verdict"),
            expected_drained_verdict(containment)
        );
    } else {
        let err = result.expect_err("a non-drainable mechanism must refuse wait_tree");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
    // wait_tree never reaps — the root's exit still needs collecting either way.
    _ = child.wait();
}

/// Deadline-not-met case: on a drain-observable mechanism, `wait_tree_timeout` against a tree
/// that is still alive at expiry reports `MembersRemain` — NOT an error, per its own doc. On a
/// non-drainable mechanism the same call must still fail `Unsupported`.
#[skuld::test]
fn wait_tree_timeout_reports_members_remain_before_the_deadline() {
    let (child, stdin) = long_lived_contained_child();
    let drainable = child.containment().can_observe_drain();
    let result = child.wait_tree_timeout(Duration::from_millis(200));
    if drainable {
        assert_eq!(
            result.expect("an unmet deadline on a live tree must not be an error"),
            crate::containment::TreeDrain::MembersRemain
        );
    } else {
        let err = result.expect_err("a non-drainable mechanism must refuse wait_tree_timeout");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
    kill_then_release(child, stdin);
}

/// `Duration::ZERO` against a still-alive tree: a one-shot, non-blocking probe (see
/// `crate::wait::deadline_from`/`remaining`'s own docs) — `MembersRemain`, not an error, and
/// returned without ever entering the backend's blocking wait (every `wait_drained`
/// implementation checks `remaining == Duration::ZERO` before its first blocking syscall).
#[skuld::test]
fn wait_tree_timeout_zero_reports_members_remain_on_a_live_tree() {
    let (child, stdin) = long_lived_contained_child();
    let drainable = child.containment().can_observe_drain();
    let result = child.wait_tree_timeout(Duration::ZERO);
    if drainable {
        assert_eq!(
            result.expect("a ZERO probe against a live tree must not be an error"),
            crate::containment::TreeDrain::MembersRemain
        );
    } else {
        let err = result.expect_err("a non-drainable mechanism must refuse wait_tree_timeout");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
    kill_then_release(child, stdin);
}

/// `Duration::ZERO` against an ALREADY-drained tree: the one-shot probe must still observe and
/// report the real, mechanism-correct drained verdict — not `MembersRemain` by default, and not
/// blocked on by the deadline being in the past (see `marker_eof::block_until_drained`'s own doc
/// on why a past deadline still performs exactly one check). The unbounded `wait_tree()` call
/// first is the genuine happens-before edge that the tree has fully drained before the ZERO
/// probe below ever runs.
#[skuld::test]
fn wait_tree_timeout_zero_reports_the_drained_verdict_after_the_tree_has_already_drained() {
    let child = quick_contained_child();
    let containment = child.containment();
    let drainable = containment.can_observe_drain();
    let first = child.wait_tree();
    if drainable {
        first.expect("a fully-exited tree must report a drained verdict");
        assert_eq!(
            child
                .wait_tree_timeout(Duration::ZERO)
                .expect("a ZERO probe against an already-drained tree must not be an error"),
            expected_drained_verdict(containment),
            "a ZERO probe must observe the SAME drained state an unbounded wait already found, \
             not report MembersRemain just because the deadline is already past"
        );
    } else {
        first.expect_err("a non-drainable mechanism must refuse wait_tree");
        let err = child.wait_tree_timeout(Duration::ZERO);
        assert!(
            matches!(err, Err(crate::error::Error::Unsupported { .. })),
            "got {err:?}"
        );
    }
    _ = child.wait();
}

/// `Unsupported` on a non-drainable mechanism — explicitly REQUESTING `ContainMode::TreeWalk`,
/// the one mode with no kernel drain edge on every platform where it is actually honored as
/// requested (`Attached::TreeWalk` carries no `#[cfg]` gate reserving it to one OS, unlike the
/// per-OS drainable variants). **Not** portable to a single unconditional assertion, though:
/// on macOS the fd marker is installed for every contained root regardless of the requested
/// mode (`dispatch.rs`'s `attach()`, macOS branch — it is what survives `setsid`/reparenting/
/// `exec` that a mode-specific mechanism does not), so a macOS `TreeWalk` request still comes
/// back `Containment::FdMarker`, which IS drainable. Branches on the actual reported
/// `can_observe_drain()` like the two tests above, rather than assuming a platform from the
/// requested mode, so this asserts something real and non-tautological on every platform: the
/// `Unsupported` refusal where `TreeWalk` is honored as non-drainable, and — on macOS — that
/// an explicit `TreeWalk` request still drains correctly through the marker it was promoted to.
#[skuld::test]
fn wait_tree_is_unsupported_on_a_non_drainable_mechanism() {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["true"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "exit 0"]);
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let treewalk_child = cmd.spawn().expect("spawn");
    let containment = treewalk_child.containment();
    let drainable = containment.can_observe_drain();
    let err = treewalk_child.wait_tree_timeout(Duration::from_millis(200));
    if drainable {
        assert_eq!(
            err.expect("macOS promotes an explicit TreeWalk request to the drainable fd marker"),
            expected_drained_verdict(containment),
            "a quick-exiting tree must still be observed as drained through the promoted mechanism"
        );
    } else {
        let err = err.expect_err("TreeWalk, honored as requested, has no kernel drain edge");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
        let err2 = treewalk_child
            .wait_tree()
            .expect_err("TreeWalk, honored as requested, has no kernel drain edge");
        assert!(matches!(err2, crate::error::Error::Unsupported { .. }), "got {err2:?}");
    }
    _ = treewalk_child.wait();
}

// `Child::wait_deadline` (portable) =====

use std::time::Instant;

/// A live, uncontained child that blocks on its piped stdin until EOF.
fn spawn_never_exiting() -> (crate::Child, std::io::PipeWriter) {
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe_in()).expect("configure piped stdin");
    cmd.stdout(crate::Stdio::null()).expect("configure null stdout");
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin was just configured above");
    (child, stdin)
}

/// A deadline in the past against an already-exited child still reports the exit.
///
/// Mutant: return `None` when `remaining` is zero before asking the backend.
#[skuld::test]
fn wait_deadline_in_the_past_reports_an_exited_child() {
    let child = quick_contained_child();
    let waited = child.wait().expect("wait");
    let status = child
        .wait_deadline(Instant::now())
        .expect("an exited child must not fail");
    assert_eq!(status, Some(waited));
}

/// The frozen clock advances by the real elapsed time of each wait exactly once, so a second wait
/// never returns before its own deadline.
fn assert_consecutive_frozen_waits_never_early(child: &crate::Child) {
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    let first = at + Duration::from_millis(50);
    let second = at + Duration::from_millis(100);
    assert!(child.wait_deadline(first).expect("first wait").is_none());
    assert!(child.wait_deadline(second).expect("second wait").is_none());
    assert!(Instant::now() >= second, "the second wait returned before its deadline");
}

/// Mutant (Windows): a second clock advance around `drive::block`'s own `wait_until`.
#[skuld::test]
fn std_child_consecutive_frozen_waits_never_return_early() {
    let (child, _stdin) = spawn_never_exiting();
    assert_consecutive_frozen_waits_never_early(&child);
}

/// Dropping a `Child` kills it and reaps it, by the kill: its stdin is released only once the drop's
/// kill returned.
#[skuld::test]
fn drop_kills_and_reaps_the_child() {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    // `more.com` exits 0 on EOF, unlike the `findstr` blocker, whose exit 1 is the kill's code.
    #[cfg(windows)]
    {
        cmd.args([crate::test_child::windows_more()]);
        cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    }
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    cmd.stdin(stdin).expect("set stdin");
    let teardown = crate::child::spawn::fault::release_at_drop_kill(writer);
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    assert_eq!(
        id.is_alive(),
        crate::identity::Liveness::Alive,
        "child runs while its stdin stays open"
    );

    drop(child); // kill_on_drop default true => SIGKILL/TerminateProcess + reap

    teardown.assert_killed();
    assert_eq!(
        id.is_alive(),
        crate::identity::Liveness::Dead,
        "child must be dead (and reaped) after drop"
    );
}

/// Dropping a `Child` whose tree is contained kills the whole tree, the grandchild too. The tree's
/// stdin is released once the drop's root kill returned, so a drop that sent nothing lets the
/// root exit 0 and the grandchild print `eof`, and fails the assertions instead of hanging in the
/// drop. Both members hold the stdout pipe, so its end is the moment both are gone.
#[cfg(unix)]
#[skuld::test]
fn drop_kills_a_contained_tree() {
    use std::io::Read as _;
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::CAT_TREE_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let mut stdout = child.stdout().expect("piped stdout");
    let mut ready = [0u8; 2];
    stdout.read_exact(&mut ready).expect("readiness line");
    assert_eq!(&ready, b"r\n");
    // Containment was established, so a tree that survives the drop is a missing kill and not a
    // missing mechanism.
    let got = child.containment();
    let established = if cfg!(target_os = "linux") {
        matches!(got, crate::Containment::CgroupV2 | crate::Containment::ProcessGroup)
    } else {
        matches!(
            got,
            crate::Containment::ProcessGroup | crate::Containment::Session | crate::Containment::FdMarker
        )
    };
    assert!(
        established,
        "unexpected containment for a contained tree on this host: {got:?}"
    );
    let teardown = crate::child::spawn::fault::release_at_drop_kill(stdin);

    drop(child);

    teardown.assert_killed();
    let mut rest = Vec::new();
    stdout
        .read_to_end(&mut rest)
        .expect("both members are gone, so the pipe ends");
    assert!(rest.is_empty(), "the drop missed the grandchild: {rest:?}");
}

// A zombie launchd holds =====

/// A child whose every reap answers that launchd holds the zombie (macOS: its tracer died).
fn child_of_an_orphaned_zombie(waits: usize) -> crate::Child {
    use crate::os_process::child::Foreign;
    use crate::os_process::fake::{FakeProcess, ReapAnswer};
    crate::test_child::over_fake::child_over(
        &FakeProcess::new([]).reaps(std::iter::repeat_n(ReapAnswer::Foreign(Foreign::Orphaned), waits)),
    )
}

/// The `warn`s this thread logged since `mark` that say a zombie is not ours to reap.
fn orphan_warns_since(mark: usize) -> usize {
    crate::log_capture::records_since_on_current_thread(mark, "not ours to reap")
        .into_iter()
        .filter(|(level, _)| *level == log::Level::Warn)
        .count()
}

/// The error every wait on a child someone else reaped answers.
fn assert_reaped_elsewhere(result: Result<impl std::fmt::Debug, crate::error::Error>) {
    match result {
        Err(crate::error::Error::Io(e)) => {
            #[cfg(unix)]
            assert_eq!(e.raw_os_error(), Some(libc::ECHILD), "{e}");
            #[cfg(windows)]
            assert!(e.to_string().contains("reaped elsewhere"), "{e}");
        }
        other => panic!("expected the reaped-elsewhere error, got {other:?}"),
    }
}

/// `wait`, `wait_deadline` and `wait_timeout` each warn once of a zombie launchd holds.
///
/// Mutant: `Child` writes the warn for some of them only, or for none.
#[skuld::test]
fn a_loud_wait_warns_of_an_orphaned_zombie() {
    crate::log_capture::install();
    let hour = Duration::from_secs(3600);
    for name in ["wait", "wait_deadline", "wait_timeout"] {
        let child = child_of_an_orphaned_zombie(1);
        let mark = crate::log_capture::mark();
        match name {
            "wait" => assert_reaped_elsewhere(child.wait()),
            "wait_deadline" => assert_reaped_elsewhere(child.wait_deadline(crate::wait::now() + hour)),
            _ => assert_reaped_elsewhere(child.wait_timeout(hour)),
        }
        assert_eq!(orphan_warns_since(mark), 1, "{name}");
    }
}

/// `try_wait` and a quiet `wait_timeout` leave the zombie launchd holds unreported: their callers
/// report it with the refusal they go on to make.
///
/// Mutant: `Child` warns whatever the caller asked.
#[cfg(unix)]
#[skuld::test]
fn a_quiet_wait_does_not_warn_of_an_orphaned_zombie() {
    crate::log_capture::install();
    let child = child_of_an_orphaned_zombie(2);
    let mark = crate::log_capture::mark();
    assert_reaped_elsewhere(child.try_wait());
    assert_reaped_elsewhere(child.wait_timeout_quiet(Duration::from_secs(3600)));
    assert_eq!(orphan_warns_since(mark), 0);
}

// `Settlement`: one row per answer of the table in its doc =====

mod settlement {
    use std::io;
    use std::process::ExitStatus;

    use crate::child::lifecycle::Settlement;
    use crate::child::owned::teardown::Disposition;
    use crate::child::owned::ChildWaitOutcome;
    use crate::child::spawn::FrontFate;
    use crate::error::{ChildFate, Error};
    use crate::identity::ProcessId;
    use crate::os_process::child::{ExitRecord, Foreign};

    const PID: u32 = 4242;
    const BOTH: [Disposition; 2] = [Disposition::Leave, Disposition::HandBack];
    const RUNNING: &str = "the caller's running clause";
    const HANDED_BACK: &str = "; handed back to the caller in the error";

    fn id() -> ProcessId {
        ProcessId::from_parts(PID, 1)
    }

    fn failure() -> Error {
        Error::Io(io::Error::other("cosca-wait-e5a1"))
    }

    fn exited() -> Result<ChildWaitOutcome, Error> {
        Ok(ChildWaitOutcome::Exited(ExitRecord::Status(ExitStatus::default())))
    }

    fn unreadable() -> Result<ChildWaitOutcome, Error> {
        Ok(ChildWaitOutcome::Exited(ExitRecord::Unreadable { si_code: 7 }))
    }

    fn foreign(foreign: Foreign) -> Result<ChildWaitOutcome, Error> {
        Ok(ChildWaitOutcome::Foreign(foreign))
    }

    fn failed() -> Result<ChildWaitOutcome, Error> {
        Err(failure())
    }

    fn passed() -> Result<ChildWaitOutcome, Error> {
        Ok(ChildWaitOutcome::DeadlinePassed)
    }

    /// The three facts every row states besides the wording.
    #[track_caller]
    fn assert_row(settlement: &Settlement, fate: ChildFate, uncollected: bool, front: FrontFate) {
        assert_eq!(settlement.fate(Some(id())), fate, "{settlement:?}");
        assert_eq!(settlement.uncollected(), uncollected, "{settlement:?}");
        assert_eq!(settlement.front_fate(), front, "{settlement:?}");
    }

    /// What the settlement says of the child "S" under `disposition`, with the running clause
    /// [`RUNNING`].
    fn worded(settlement: &Settlement, disposition: Disposition) -> Option<(log::Level, String)> {
        settlement.wording("S", Some(RUNNING), disposition)
    }

    /// A child that exited with a status is reaped and nothing is said, whether or not a kill reached it.
    ///
    /// Mutants: it is uncollected; it is worded.
    #[skuld::test]
    fn an_exit_with_a_status_is_reaped_and_silent() {
        for killed in [false, true] {
            let settlement = Settlement::new(exited(), killed);
            assert_row(&settlement, ChildFate::Reaped, false, FrontFate::Reaped);
            for disposition in BOTH {
                assert_eq!(worded(&settlement, disposition), None, "{killed}");
            }
        }
    }

    /// An exit whose record was unreadable was reaped, whether or not a kill reached it: the
    /// consuming reap took the zombie. Only a kill that reached it is "after the kill".
    ///
    /// Mutants: the fate is `Killed` after a kill, or `Unknown`; it is uncollected; it is a front
    /// unaccounted for; the wording says "after the kill" without one.
    #[skuld::test]
    fn an_unreadable_exit_is_reaped_and_warned_of() {
        for (killed, said) in [
            (
                false,
                "S: reaped it; the child's exit record was unreadable (si_code 7)",
            ),
            (
                true,
                "S: reaped it after the kill; the child's exit record was unreadable (si_code 7)",
            ),
        ] {
            let settlement = Settlement::new(unreadable(), killed);
            assert_row(&settlement, ChildFate::Reaped, false, FrontFate::Reaped);
            for disposition in BOTH {
                assert_eq!(
                    worded(&settlement, disposition),
                    Some((log::Level::Warn, said.to_owned()))
                );
            }
        }
    }

    /// Someone else reaped it: not collected by this handle, so nothing to hand back. The fate says
    /// whether a kill reached it, and the line is `debug`.
    ///
    /// Mutants: the line is a warn; the fate ignores the kill; it is uncollected.
    #[skuld::test]
    fn a_foreign_reap_is_gone_or_killed_and_said_at_debug() {
        for foreign_reap in [Foreign::Gone, Foreign::Other] {
            for (killed, fate) in [(false, ChildFate::Gone), (true, ChildFate::Killed)] {
                let settlement = Settlement::new(foreign(foreign_reap), killed);
                assert_row(&settlement, fate, false, FrontFate::Unaccounted);
                for disposition in BOTH {
                    assert_eq!(
                        worded(&settlement, disposition),
                        Some((log::Level::Debug, "S: reaped by someone else".to_owned()))
                    );
                }
            }
        }
    }

    /// A zombie launchd holds is the same, but warned of, as a clause after the caller's subject.
    ///
    /// Mutants: the line is `debug`; it is not led by the caller's subject, so a subject that names
    /// a refusal loses it.
    #[skuld::test]
    fn a_zombie_launchd_holds_is_gone_or_killed_and_warned_of() {
        for (killed, fate) in [(false, ChildFate::Gone), (true, ChildFate::Killed)] {
            let settlement = Settlement::new(foreign(Foreign::Orphaned), killed);
            assert_row(&settlement, fate, false, FrontFate::Unaccounted);
            for disposition in BOTH {
                assert_eq!(
                    worded(&settlement, disposition),
                    Some((
                        log::Level::Warn,
                        "S: not ours to reap (launchd holds its zombie, because its tracer died)".to_owned()
                    ))
                );
            }
        }
    }

    /// A wait that failed after a kill reached the child: `Killed`, uncollected, and the warn says
    /// where the child goes under the disposition.
    ///
    /// Mutants: the fate is `Unknown`; it is collected; the suffix ignores the disposition.
    #[skuld::test]
    fn a_failed_wait_after_a_kill_is_killed_uncollected_and_warned_of() {
        let settlement = Settlement::new(failed(), true);
        assert_row(&settlement, ChildFate::Killed, true, FrontFate::Unaccounted);
        let said = "S: the wait failed: cosca-wait-e5a1";
        assert_eq!(
            worded(&settlement, Disposition::Leave),
            Some((log::Level::Warn, said.to_owned()))
        );
        assert_eq!(
            worded(&settlement, Disposition::HandBack),
            Some((log::Level::Warn, format!("{said}{HANDED_BACK}")))
        );
    }

    /// A wait that failed with no kill having reached the child shows nothing of what became of it:
    /// `Unknown`, otherwise the row above.
    ///
    /// Mutant: the fate ignores whether a kill reached the child.
    #[skuld::test]
    fn a_failed_wait_without_a_kill_is_unknown_uncollected_and_warned_of() {
        let settlement = Settlement::new(failed(), false);
        assert_row(&settlement, ChildFate::Unknown, true, FrontFate::Unaccounted);
        let said = "S: the wait failed: cosca-wait-e5a1";
        assert_eq!(
            worded(&settlement, Disposition::Leave),
            Some((log::Level::Warn, said.to_owned()))
        );
        assert_eq!(
            worded(&settlement, Disposition::HandBack),
            Some((log::Level::Warn, format!("{said}{HANDED_BACK}")))
        );
    }

    /// A deadline that passed, with no kill having reached the child: it is running, uncollected, a
    /// front left unreaped, and the caller's running clause is the warn, as it is.
    ///
    /// Mutants: the fate keeps no identity; it is collected; the clause is prefixed.
    #[skuld::test]
    fn a_deadline_that_passed_is_running_uncollected_and_the_callers_clause() {
        let settlement = Settlement::new(passed(), false);
        assert_row(
            &settlement,
            ChildFate::Running { id: Some(id()) },
            true,
            FrontFate::LeftUnreaped,
        );
        assert_eq!(settlement.fate(None), ChildFate::Running { id: None });
        for disposition in BOTH {
            assert_eq!(
                worded(&settlement, disposition),
                Some((log::Level::Warn, RUNNING.to_owned()))
            );
        }
    }

    /// A wait with no deadline that still answers a deadline passed (a contract breach that a debug
    /// build asserts on elsewhere) is not worded as an empty line in a release build: the caller has
    /// no running clause, so the line names the subject.
    ///
    /// Mutant: the wording returns the caller's clause whether or not there is one, so it is empty.
    #[skuld::test]
    fn a_deadline_that_passed_in_a_wait_with_no_deadline_says_the_wait_ended_with_no_exit() {
        let settlement = Settlement::new(passed(), false);
        for disposition in BOTH {
            assert_eq!(
                settlement.wording("S", None, disposition),
                Some((log::Level::Warn, "S: its wait ended with no exit".to_owned()))
            );
        }
    }

    /// `ended` is every answer but a deadline that passed, and `status` the status of an exit whose
    /// record was read.
    ///
    /// Mutants: `ended` reads the fate; an unreadable record has a status.
    #[skuld::test]
    fn ended_and_status_state_the_answer() {
        for (settlement, ended, status) in [
            (Settlement::new(exited(), false), true, Some(ExitStatus::default())),
            (Settlement::new(unreadable(), false), true, None),
            (Settlement::new(foreign(Foreign::Gone), true), true, None),
            (Settlement::new(failed(), false), true, None),
            (Settlement::new(passed(), false), false, None),
        ] {
            assert_eq!(settlement.ended(), ended, "{settlement:?}");
            assert_eq!(settlement.status(), status, "{settlement:?}");
        }
    }

    /// A line at warn is the leftover for the caller's one warn; one below it is logged, led as the
    /// caller says; a silent answer is neither.
    ///
    /// Mutants: a debug line is returned; a warn is logged; the lead is dropped.
    #[skuld::test]
    fn a_leftover_is_the_warn_and_anything_below_is_logged() {
        crate::log_capture::install();
        let mark = crate::log_capture::mark();

        let gone = Settlement::new(foreign(Foreign::Gone), false);
        assert_eq!(gone.leftover("S", None, Disposition::Leave, "lead: "), None);
        let logged = crate::log_capture::records_since_on_current_thread(mark, "S:");
        assert_eq!(
            logged,
            vec![(log::Level::Debug, "lead: S: reaped by someone else".to_owned())]
        );

        let mark = crate::log_capture::mark();
        let failed = Settlement::new(failed(), false);
        assert_eq!(
            failed.leftover("S", None, Disposition::Leave, "lead: ").as_deref(),
            Some("S: the wait failed: cosca-wait-e5a1")
        );
        assert_eq!(
            Settlement::new(exited(), false).leftover("S", None, Disposition::Leave, "lead: "),
            None
        );
        assert_eq!(
            crate::log_capture::records_since_on_current_thread(mark, "S:"),
            Vec::<(log::Level, String)>::new()
        );
    }

    /// A kill reached the child, and the wait that follows has no deadline: an answer that the
    /// deadline passed breaks that contract.
    ///
    /// Mutant: the contract is not asserted.
    #[cfg(debug_assertions)]
    #[skuld::test]
    fn a_deadline_that_passed_after_a_kill_breaks_the_contract() {
        let built = std::panic::catch_unwind(|| Settlement::new(passed(), true));
        assert!(built.is_err(), "a deadline cannot pass in an unbounded wait");
    }
}
