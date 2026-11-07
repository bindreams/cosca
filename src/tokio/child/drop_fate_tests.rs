//! What the drop's teardown says became of a child (`Child::tear_down_now`): a fate never claims
//! more than the evidence shows. `Gone` needs proof that something else reaped the child; a handle
//! that merely cannot say (a failed peek) leaves the child possibly running.

use crate::containment::dispatch::TeardownCaller;
use crate::error::ChildFate;
use crate::test_child::Console;
use crate::wait::exit_only::seams::force_peeks;

fn live(kill_on_drop: bool) -> (crate::tokio::Child, crate::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.kill_on_drop(kill_on_drop);
    (cmd.spawn().expect("spawn"), writer)
}

/// Collects a forgotten child the test still owns: ends its stdin, waits for its exit, and answers
/// how it ended.
fn collect(id: crate::identity::ProcessId, writer: crate::PipeWriter) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt as _;
    drop(writer);
    let mut status = 0;
    // SAFETY: reaps this test's own forgotten child, which nothing else reaps.
    let reaped = unsafe { libc::waitpid(id.pid() as libc::pid_t, &mut status, 0) };
    assert_eq!(
        reaped,
        id.pid() as libc::pid_t,
        "the forgotten child is still ours to collect"
    );
    std::process::ExitStatus::from_raw(status)
}

/// A failed peek cannot show the child ours, but proves nothing about a reap either. Armed, the drop
/// signals through the handle and the child is `Killed`; disarmed, nothing is signalled and the child
/// may be running. Neither is `Gone`.
///
/// Mutants: the unshown-ownership case is read as a foreign reap (`Gone`), armed or disarmed.
fn a_failed_peek_answers_what_the_drop_did(kill_on_drop: bool) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = live(kill_on_drop);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let looks = force_peeks((0..4).map(|_| Err(std::io::Error::other("forced peek failure 5d1b"))));
    let fate = child.tear_down_now(TeardownCaller::Drop);
    drop(looks);
    // The child was forgotten: end it and collect it here (an armed drop on Linux has killed it
    // through its pidfd, which a failed peek does not stop; the zombie is ours to collect).
    collect(id, writer);
    assert_eq!(
        fate,
        expected_fate_of_a_failed_peek(kill_on_drop, id),
        "kill_on_drop={kill_on_drop}"
    );
}

/// What the drop of a child whose peeks all fail answers. A root whose handle cannot say is killed
/// through that handle like any other (Linux: the pidfd names it whatever any peek said; macOS: the
/// signal's own id read is not a peek), and then the child is dead but not collected: `Killed`.
/// Nothing armed, nothing signalled: the child may be running.
fn expected_fate_of_a_failed_peek(kill_on_drop: bool, id: crate::identity::ProcessId) -> ChildFate {
    if kill_on_drop {
        ChildFate::Killed
    } else {
        ChildFate::Running { id: Some(id) }
    }
}

/// A disarmed drop of a child whose ownership cannot be shown warns once. It looks twice: the read
/// that finds the handle cannot say, and the forget's own look, which a reap landing after the read
/// needs. The forget is one warn.
///
/// Mutants: a third look; the forget warns more than once.
#[skuld::test]
async fn a_disarmed_teardown_with_a_failed_peek_looks_and_warns_once() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = live(false);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let looks = force_peeks((0..4).map(|_| Err(std::io::Error::other("forced peek failure 8e2a"))));
    let mark = crate::log_capture::mark();
    let fate = child.tear_down_now(TeardownCaller::Drop);
    let left = crate::wait::exit_only::seams::forced_peeks_left();
    drop(looks);
    collect(id, writer);
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert_eq!(left, 2, "two peeks were taken: the read and the forget's own look");
    assert_eq!(
        crate::log_capture::records_since(mark, "forced peek failure 8e2a").len(),
        1,
        "exactly one warning"
    );
}

#[skuld::test]
async fn an_armed_teardown_with_a_failed_peek_says_killed_not_gone() {
    a_failed_peek_answers_what_the_drop_did(true);
}

#[skuld::test]
async fn a_disarmed_teardown_with_a_failed_peek_says_running_not_gone() {
    a_failed_peek_answers_what_the_drop_did(false);
}

/// A live child whose backend was forgotten, shown reaped elsewhere (`true`) or not shown to be
/// ours (`false`).
fn forgotten(reaped_elsewhere: bool) -> (crate::tokio::Child, crate::PipeWriter) {
    let (mut child, writer) = live(true);
    child.os.proc_mut().forget_as(
        "was forgotten by a test",
        if reaped_elsewhere {
            super::proc_source::Forgotten::ReapedElsewhere
        } else {
            super::proc_source::Forgotten::Unproven
        },
    );
    (child, writer)
}

/// A backend forgotten as reaped elsewhere answers `Reaped`, and not as this handle's own reap.
///
/// Mutant: `ProcSource::state` reads a foreign reap as `own: true`.
#[skuld::test]
async fn a_backend_forgotten_as_reaped_elsewhere_is_not_an_own_reap() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = forgotten(true);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let state = child.os.proc_mut().state();
    let _fate = child.tear_down_now(TeardownCaller::Drop);
    collect(id, writer);
    assert!(
        matches!(state, crate::signal::RootState::Reaped { own: false }),
        "{state:?}"
    );
}

/// A backend forgotten without proof of a foreign reap says nothing of a reap at its drop: no status
/// of ours was collected. On Linux the armed drop kills the child through the pidfd the backend
/// kept; on macOS nothing reaches it, and it may be running.
///
/// Mutants: a forgotten backend reads as `Reaped`; one not shown ours reads as `Gone`; (Linux) the
/// kill through its pidfd is not reported.
#[skuld::test]
async fn the_drop_of_a_child_forgotten_unproven_claims_no_reap() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = forgotten(false);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let fate = child.tear_down_now(TeardownCaller::Drop);
    // Released after the drop's kill, so a kill that sent nothing fails the assertion on how the
    // child ended.
    let status = collect(id, writer);
    #[cfg(target_os = "linux")]
    {
        assert_eq!(fate, ChildFate::Killed);
        crate::test_child::assert_killed("the child", status);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = status;
    #[cfg(target_os = "macos")]
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
}

/// Linux: a root another reaper took, whose handle then forgot it as not shown to be ours (a kill
/// whose peek failed), is shown gone by the drop's own kill through the kept pidfd (`ESRCH`). The
/// pidfd names the root exactly, so the drop says `Gone`, not the forgotten backend's `Running`.
///
/// Mutant: the forgotten backend's `Running` overrides the drop's own `Gone`.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn the_drop_of_an_unproven_backend_whose_root_its_pidfd_shows_gone_says_gone() {
    use crate::wait::exit_only::seams::{assert_peeks_exhausted, force_peek_once};
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = live(true);
    let pid = child.pid();
    child.kill().expect("kill the root");
    // Released after the kill, so a kill that sent nothing fails the assertion on how the root ended.
    drop(writer);
    crate::test_child::assert_killed("the root", crate::test_child::reaped_elsewhere::reap_behind_status(pid));
    let failed = force_peek_once(Err(std::io::Error::other("forced peek failure 3c7f")));
    child.kill().expect("a root reaped elsewhere has nothing left to kill");
    assert_peeks_exhausted();
    drop(failed);
    let fate = child.tear_down_now(TeardownCaller::Drop);
    assert_eq!(fate, ChildFate::Gone);
}

/// Linux: a kill refused through the kept pidfd of a backend forgotten unproven leaves the child
/// possibly running, and the drop's one warn names the refused kill and says it is left running and
/// unreaped: tokio's `Child` was forgotten, so nothing reaps it.
///
/// Mutants: the backend counts as reaped, so the refused kill is not named; the warn says only that
/// the child is left running.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_refused_kill_of_an_unproven_backend_at_drop_is_named() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = forgotten(false);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let refused = super::fault::force_kill_failure();
    let mark = crate::log_capture::mark();
    let fate = child.tear_down_now(TeardownCaller::Drop);
    drop(refused);
    collect(id, writer);
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    let warns = crate::log_capture::records_since(mark, "could not be terminated on drop");
    assert_eq!(warns.len(), 1, "the refused kill is named once: {warns:?}");
    let wording = format!(
        "async child {} could not be terminated on drop{}",
        id.pid(),
        crate::child::owned::teardown::LEAVING_RUNNING
    );
    assert!(warns[0].contains(&wording), "the warn says {wording:?}: {warns:?}");
}

/// Linux: a refused kill of a child whose handle cannot be asked at the drop's own look (it could
/// not say ours at the read, showed ours at the forget's look, and cannot say at the gate of the
/// `try_wait`) leaves the child to the forget that follows, so its warn says it is left running and
/// unreaped.
///
/// Mutant: the warn says only "leaving it running", which tokio's orphan queue would make true of a
/// child it holds.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_refused_kill_whose_look_at_drop_fails_is_left_running_and_unreaped() {
    use crate::os_process::child::PeekOutcome;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = live(true);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let refused = super::fault::force_kill_failure();
    let fail = || Err(std::io::Error::other("forced peek failure 6c4e"));
    let looks = force_peeks([fail(), Ok(PeekOutcome::Running), fail(), fail()]);
    let mark = crate::log_capture::mark();
    let fate = child.tear_down_now(TeardownCaller::Drop);
    let left = crate::wait::exit_only::seams::forced_peeks_left();
    drop(looks);
    drop(refused);
    collect(id, writer);
    assert_eq!(
        fate,
        ChildFate::Unknown,
        "a look that failed shows nothing of the child"
    );
    assert_eq!(
        left, 0,
        "the read, the forget's look, the gate and the forget's second look"
    );
    let warns = crate::log_capture::records_since(mark, "could not be terminated on drop");
    assert_eq!(warns.len(), 1, "{warns:?}");
    let wording = format!(
        "async child {} could not be terminated on drop{}",
        id.pid(),
        crate::child::owned::teardown::LEAVING_RUNNING
    );
    assert!(warns[0].contains(&wording), "the warn says {wording:?}: {warns:?}");
}

/// Linux: a refused kill of a child every look shows running and ours is not followed by a forget:
/// the drop releases tokio's `Child`, whose orphan queue reaps it once it exits. The warn says only
/// that it is left running, not that it is unreaped.
///
/// Mutant: the warn says "and unreaped" whatever became of tokio's `Child`.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_refused_kill_of_a_child_released_to_tokio_is_left_running_and_not_unreaped() {
    use crate::os_process::child::PeekOutcome;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = live(true);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let refused = super::fault::force_kill_failure();
    let looks = force_peeks((0..4).map(|_| Ok(PeekOutcome::Running)));
    let mark = crate::log_capture::mark();
    let fate = child.tear_down_now(TeardownCaller::Drop);
    drop(looks);
    drop(refused);
    // Tokio's orphan queue collects the child once its stdin closes.
    drop(writer);
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    let warns = crate::log_capture::records_since(mark, "could not be terminated on drop");
    assert_eq!(warns.len(), 1, "{warns:?}");
    let wording = format!(
        "async child {} could not be terminated on drop; leaving it running",
        id.pid()
    );
    assert!(warns[0].ends_with(&wording), "the warn ends {wording:?}: {warns:?}");
}

/// Linux: a refused kill of a child the drop's own look shows reaped by someone else is gone: the
/// warn does not call it running.
///
/// Mutant: the warn says "leaving it running" of a child the gate showed reaped elsewhere.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_refused_kill_of_a_child_shown_reaped_elsewhere_at_drop_says_it_is_gone() {
    use crate::os_process::child::{Foreign, PeekOutcome};
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = live(true);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let refused = super::fault::force_kill_failure();
    // The read and the forget's look show it ours; the gate shows it reaped elsewhere.
    let looks = force_peeks([
        Ok(PeekOutcome::Running),
        Ok(PeekOutcome::Running),
        Ok(PeekOutcome::Foreign(Foreign::Gone)),
    ]);
    let mark = crate::log_capture::mark();
    let fate = child.tear_down_now(TeardownCaller::Drop);
    let left = crate::wait::exit_only::seams::forced_peeks_left();
    drop(looks);
    drop(refused);
    // The gate forgot tokio's `Child`, so the real child is ours to collect.
    collect(id, writer);
    assert_eq!(fate, ChildFate::Gone);
    assert_eq!(left, 0, "the read, the forget's look and the gate");
    let warns = crate::log_capture::records_since(mark, "could not be terminated on drop");
    assert_eq!(warns.len(), 1, "{warns:?}");
    let wording = format!(
        "async child {} could not be terminated on drop; it is already gone",
        id.pid()
    );
    assert!(warns[0].ends_with(&wording), "the warn ends {wording:?}: {warns:?}");
}

/// Linux: a backend forgotten unproven is asked of its kept pidfd whether the child runs, so a
/// kill or terminate gate does not read it as gone while it lives.
///
/// Mutant: a forgotten backend answers `false` whatever its pidfd shows.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn an_unproven_backend_reads_its_kept_pidfd_for_whether_the_child_runs() {
    use crate::signal::Sig;
    crate::tokio::test_runtime::assert_current_thread();
    let (child, writer) = forgotten(false);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let proc = child.os.proc.as_ref().expect("backend");
    assert!(proc.is_running().expect("the pidfd answers"), "the child lives");
    proc.signal(Sig::Kill).expect("kill through the pidfd");
    crate::test_child::assert_killed("the child", collect(id, writer));
    assert!(!proc.is_running().expect("the pidfd answers"), "the child is gone");
}

/// A backend forgotten on proof of a foreign reap is `Gone`, not `Reaped`: this handle collected
/// no status.
///
/// Mutant: a forgotten backend reads as `Reaped`.
#[skuld::test]
async fn the_drop_of_a_child_forgotten_as_reaped_elsewhere_says_gone() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = forgotten(true);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let fate = child.tear_down_now(TeardownCaller::Drop);
    collect(id, writer);
    assert_eq!(fate, ChildFate::Gone);
}

/// A kill of a forgotten backend is `Gone` only when the forgetting had proof of a foreign reap.
/// Otherwise, on Linux, it goes through the pidfd the backend kept; on macOS nothing is sent, and the
/// child may be running.
///
/// Mutants: `Foreign` answers `Gone` whatever the forgetting knew; (Linux) it sends nothing through
/// the pidfd.
#[skuld::test]
async fn a_kill_of_a_forgotten_backend_is_gone_only_with_proof() {
    use crate::signal::{Sent, Sig};
    crate::tokio::test_runtime::assert_current_thread();
    let (unproven, w1) = forgotten(false);
    let (proven, w2) = forgotten(true);
    assert_eq!(
        unproven
            .os
            .proc
            .as_ref()
            .expect("backend")
            .signal(Sig::Kill)
            .expect("the kill is answered"),
        if cfg!(target_os = "linux") {
            Sent::Delivered
        } else {
            Sent::Unverified
        }
    );
    assert_eq!(
        proven
            .os
            .proc
            .as_ref()
            .expect("backend")
            .signal(Sig::Kill)
            .expect("sends nothing"),
        Sent::Gone
    );
    collect(unproven.id().expect(crate::test_child::IDENTITY_READ), w1);
    collect(proven.id().expect(crate::test_child::IDENTITY_READ), w2);
}

/// The failed password write of an elevated child whose backend was forgotten: `Gone` only with
/// proof the root was reaped by someone else. Otherwise, on Linux, the root is killed through the
/// pidfd the backend kept; on macOS nothing reaches it.
///
/// Mutants: a kill that sent nothing is read as a foreign reap (`Gone`) for a child not shown ours;
/// (Linux) the kill through its pidfd is not reported.
#[skuld::test]
async fn a_failed_password_write_on_a_forgotten_backend_is_gone_only_with_proof() {
    crate::tokio::test_runtime::assert_current_thread();
    let unproven = if cfg!(target_os = "linux") {
        Some(ChildFate::Killed)
    } else {
        None
    };
    for (reaped_elsewhere, expected) in [(false, unproven), (true, Some(ChildFate::Gone))] {
        let (child, writer) = forgotten(reaped_elsewhere);
        let id = child.id().expect(crate::test_child::IDENTITY_READ);
        let (_err, fate) = crate::tokio::spawn::finish_elevated(
            child,
            Err(crate::error::Error::Elevation {
                kind: crate::error::ElevationErrorKind::AuthFailed,
                detail: "forced password-write failure".into(),
            }),
        )
        .expect_err("a failed write fails the spawn")
        .expect_may_have_started_with();
        collect(id, writer);
        assert_eq!(
            fate,
            expected.unwrap_or(ChildFate::Running { id: Some(id) }),
            "reaped_elsewhere={reaped_elsewhere}"
        );
    }
}

/// Whether the child's exit record is still waiting to be collected. `waitid` with `WNOWAIT` leaves
/// it in place; `ECHILD` is a record someone has collected.
fn record_waits(id: crate::identity::ProcessId) -> bool {
    // SAFETY: an all-zero `siginfo_t` is valid, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: peeks at this test's own exited child without consuming it.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            id.pid() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc == 0 {
        // SAFETY: `si_pid` is set by a successful `waitid`: zero when nothing was waiting.
        return unsafe { info.si_pid() } != 0;
    }
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
    false
}

/// `Reaped` is said of a status that was collected: the wait only sees the exit, so the status is
/// collected before the fate is reported, not when tokio's `Child` drops later.
///
/// Mutants: `reap_now` or `wait_and_reap_blocking` report `Reaped` on the exit the wait saw.
#[skuld::test]
async fn reaped_is_reported_only_for_a_status_that_was_collected() {
    crate::tokio::test_runtime::assert_current_thread();
    // `wait_and_reap_blocking`, after a kill.
    let (mut child, writer) = live(true);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    child.kill().expect("kill");
    // Released after the kill, so a `kill` that sent nothing fails the assertion on how the child
    // ended, not the blocking wait below.
    drop(writer);
    crate::test_child::assert_zombie_sigkilled("the killed child", id.pid());
    let (fate, _) = child.wait_and_reap_blocking();
    let waiting = record_waits(id);
    assert_eq!(fate, ChildFate::Reaped);
    assert!(
        !waiting,
        "wait_and_reap_blocking reported Reaped with the record uncollected"
    );

    // `reap_now`, which kills itself.
    let (mut child, _writer) = live(true);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let proc = child.os.proc.take().expect("backend");
    let fate = proc.reap_now(id.pid(), Some(id));
    let waiting = record_waits(id);
    assert_eq!(fate, ChildFate::Reaped);
    assert!(!waiting, "reap_now reported Reaped with the record uncollected");
}

/// macOS: a child held by launchd after its tracer died has exited and is not ours to reap. The drop
/// forgets it and says it is gone.
///
/// Mutant: an `Orphaned` peek is read as unknown ownership, so the drop says it may be running.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn macos_an_orphaned_child_at_drop_is_gone() {
    use crate::os_process::child::{Foreign, PeekOutcome};
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = live(false);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let looks = force_peeks((0..4).map(|_| Ok(PeekOutcome::Foreign(Foreign::Orphaned))));
    let fate = child.tear_down_now(TeardownCaller::Drop);
    drop(looks);
    collect(id, writer);
    assert_eq!(fate, ChildFate::Gone);
}

/// A teardown named a failed run's (a failed `resume`) words its warn as one, not as a drop's.
///
/// Mutant: `tear_down_now` ignores its caller and names every teardown a drop.
#[skuld::test]
async fn a_teardown_named_a_failed_run_words_its_warn_as_one() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = live(true);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let refused = super::fault::force_kill_failure();
    let mark = crate::log_capture::mark();

    let fate = child.tear_down_now(TeardownCaller::FailedRun);

    drop(refused);
    // The child exits once its stdin closes, and tokio collects it.
    drop(writer);
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    let warns = crate::log_capture::records_since(mark, "leaving it running");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].starts_with("teardown after a failed run: "), "{warns:?}");
}
