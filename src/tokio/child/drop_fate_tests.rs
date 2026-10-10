//! What the drop's teardown says became of a child (`Child::tear_down_now`): a fate never claims
//! more than the evidence shows. `Gone` needs proof that something else reaped the child; a handle
//! that merely cannot say (a failed peek) leaves the child possibly running.

use crate::error::ChildFate;
use crate::tokio::Command;
use crate::wait::exit_only::seams::force_peeks;

fn live(kill_on_drop: bool) -> (crate::tokio::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.kill_on_drop(kill_on_drop);
    (cmd.spawn().expect("spawn"), writer)
}

/// Collects a forgotten child the test still owns: ends its stdin, waits for its exit.
fn collect(id: crate::identity::ProcessId, writer: std::io::PipeWriter) {
    drop(writer);
    let mut status = 0;
    // SAFETY: reaps this test's own forgotten child, which nothing else reaps.
    let reaped = unsafe { libc::waitpid(id.pid() as libc::pid_t, &mut status, 0) };
    assert_eq!(
        reaped,
        id.pid() as libc::pid_t,
        "the forgotten child is still ours to collect"
    );
}

/// A failed peek cannot show the child ours, but proves nothing about a reap either: the child runs.
///
/// Mutants: the unshown-ownership case is read as a foreign reap (`Gone`), armed or disarmed.
fn a_failed_peek_leaves_the_child_running(kill_on_drop: bool) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = live(kill_on_drop);
    let id = child.id();
    let looks = force_peeks((0..4).map(|_| Err(std::io::Error::other("forced peek failure 5d1b"))));
    let fate = child.tear_down_now();
    drop(looks);
    // The child was forgotten, not signalled: end it and collect it here.
    collect(id, writer);
    assert_eq!(fate, ChildFate::Running { id: Some(id) }, "kill_on_drop={kill_on_drop}");
}

/// A disarmed drop of a child whose ownership cannot be shown looks once and warns once: the second
/// look after the kill is for a child the first look did not already give up on.
///
/// Mutant: the second look runs unconditionally (two peeks, two warnings).
#[skuld::test]
async fn a_disarmed_teardown_with_a_failed_peek_looks_and_warns_once() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut child, writer) = live(false);
    let id = child.id();
    let looks = force_peeks((0..4).map(|_| Err(std::io::Error::other("forced peek failure 8e2a"))));
    let mark = crate::log_capture::mark();
    let fate = child.tear_down_now();
    let left = crate::wait::exit_only::seams::forced_peeks_left();
    drop(looks);
    collect(id, writer);
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert_eq!(left, 3, "exactly one peek was taken");
    assert_eq!(
        crate::log_capture::records_since(mark, "forced peek failure 8e2a").len(),
        1,
        "exactly one warning"
    );
}

#[skuld::test]
async fn an_armed_teardown_with_a_failed_peek_says_running_not_gone() {
    a_failed_peek_leaves_the_child_running(true);
}

#[skuld::test]
async fn a_disarmed_teardown_with_a_failed_peek_says_running_not_gone() {
    a_failed_peek_leaves_the_child_running(false);
}

/// A live child whose backend was forgotten, shown reaped elsewhere (`true`) or not shown to be
/// ours (`false`).
fn forgotten(reaped_elsewhere: bool) -> (crate::tokio::Child, std::io::PipeWriter) {
    let (mut child, writer) = live(true);
    child
        .os
        .proc_mut()
        .forget_as("was forgotten by a test", reaped_elsewhere);
    (child, writer)
}

/// A backend forgotten without proof of a foreign reap says nothing of a reap at its drop: the
/// child may be running, and no status of ours was collected.
///
/// Mutants: a forgotten backend reads as `Reaped`; one not shown ours reads as `Gone`.
#[skuld::test]
async fn the_drop_of_a_child_forgotten_unproven_says_running() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = forgotten(false);
    let id = child.id();
    let fate = child.tear_down_now();
    collect(id, writer);
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
}

/// A backend forgotten on proof of a foreign reap is `Gone`, not `Reaped`: this handle collected
/// no status.
///
/// Mutant: a forgotten backend reads as `Reaped`.
#[skuld::test]
async fn the_drop_of_a_child_forgotten_as_reaped_elsewhere_says_gone() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = forgotten(true);
    let id = child.id();
    let fate = child.tear_down_now();
    collect(id, writer);
    assert_eq!(fate, ChildFate::Gone);
}

/// A kill of a forgotten backend sends nothing. It is `Gone` only when the forgetting had proof of a
/// foreign reap; otherwise the child may be running.
///
/// Mutant: `Foreign` answers `Gone` whatever the forgetting knew.
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
            .expect("sends nothing"),
        Sent::Unverified
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
    collect(unproven.id(), w1);
    collect(proven.id(), w2);
}

/// The failed password write of an elevated child whose root cannot be signalled: `Gone` only with
/// proof the root was reaped by someone else.
///
/// Mutants: a kill that sent nothing is read as a foreign reap (`Gone`) for a child not shown ours.
#[skuld::test]
async fn a_failed_password_write_on_an_unproven_backend_leaves_the_child_running() {
    crate::tokio::test_runtime::assert_current_thread();
    for (reaped_elsewhere, expected) in [(false, None), (true, Some(ChildFate::Gone))] {
        let (child, writer) = forgotten(reaped_elsewhere);
        let id = child.id();
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
    let (mut child, _writer) = live(true);
    let id = child.id();
    child.kill().expect("kill");
    let fate = child.wait_and_reap_blocking();
    let waiting = record_waits(id);
    assert_eq!(fate, ChildFate::Reaped);
    assert!(
        !waiting,
        "wait_and_reap_blocking reported Reaped with the record uncollected"
    );

    // `reap_now`, which kills itself.
    let (mut child, _writer) = live(true);
    let id = child.id();
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
    use crate::wait::exit_only::{Foreign, Peek};
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = live(false);
    let id = child.id();
    let looks = force_peeks((0..4).map(|_| Ok(Peek::Foreign(Foreign::Orphaned))));
    let fate = child.tear_down_now();
    drop(looks);
    collect(id, writer);
    assert_eq!(fate, ChildFate::Gone);
}
