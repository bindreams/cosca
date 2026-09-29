//! The feasibility facts, and one test per row of the helper's transition table (`machine.rs`).
//! Each test asserts every report up to each point where the helper waits, so a broken row
//! fails an assertion there rather than passing through another row's identical final report,
//! and names the mutant that fails it.
//!
//! These are `TRACER`-group tests. Rows that no real event reaches deterministically are driven
//! by `COSCA_UH_FORCE` injections. Where an injected result may leave the tracee stopped, the
//! test ends it by EOF or lets XNU kill it when the helper exits, rather than by `SIGKILL`
//! through the handle. Each test closes the tracee's stdin before it looks at how the tracee
//! ended, so a tracee a mutant left running exits instead of blocking the test.

use std::os::unix::process::ExitStatusExt as _;

use super::{sys, Cause, Mode, Report, TracerHelper, Until};

/// The tracee and its stdin, or `None` with the `TRACER` group turned off.
fn tracee() -> Option<(crate::Child, std::io::PipeWriter)> {
    tracee_with(false)
}

/// [`tracee`], catching `SIGTERM` if `catch_sigterm` (see [`super::spawn_tracee`]).
fn tracee_with(catch_sigterm: bool) -> Option<(crate::Child, std::io::PipeWriter)> {
    if !crate::test_support::require_group("TRACER") {
        return None;
    }
    let mut child = super::spawn_tracee(catch_sigterm);
    let stdin = child.stdin().expect("the tracee's stdin is piped");
    Some((child, stdin))
}

/// A report as the helper wrote it.
fn label(report: Report) -> String {
    match report {
        Report::Attached => "attached".to_string(),
        Report::Exited => "exited".to_string(),
        Report::Reaped => "reaped".to_string(),
        Report::Detached => "detached".to_string(),
        Report::Error {
            cause: Cause::Errno(errno),
            state,
        } => format!("error {errno} {state}"),
        Report::Error {
            cause: Cause::Event(event),
            state,
        } => format!("error {event} {state}"),
        Report::State(state) => state,
        Report::Blocking { state, until } => match until {
            Until::Eof => format!("blocking {state} eof"),
            Until::Exit => format!("blocking {state} exit"),
        },
    }
}

/// Reads reports, matching each against `pattern` as it arrives, until `pattern` is used up.
/// `<report>*` matches any number of that report in a row: only a backoff whose rounds the
/// kernel counts (`EBUSY` until a stop lands) is starred. Panics at the first mismatch.
fn expect(th: &mut TracerHelper<'_>, pattern: &[&str]) {
    debug_assert!(
        pattern.last().is_some_and(|last| !last.ends_with('*')),
        "a pattern ends with a report: {pattern:?}"
    );
    let mut seen = Vec::new();
    let mut at = 0;
    while at < pattern.len() {
        let report = th
            .session
            .next_report()
            .unwrap_or_else(|| panic!("the helper exited after {seen:?}; expected {pattern:?}"));
        let report = label(report);
        loop {
            match pattern[at].strip_suffix('*') {
                Some(repeated) if repeated == report => break,
                Some(_) => at += 1,
                None => {
                    assert_eq!(report, pattern[at], "after {seen:?}, expecting {pattern:?}");
                    at += 1;
                    break;
                }
            }
        }
        seen.push(report);
    }
}

fn err(cause: impl std::fmt::Display, state: &str) -> String {
    format!("error {cause} {state}")
}

/// The first wait after the attach, with the tracee held (`S1:hold`).
const HELD: [&str; 5] = ["S0", "S1", "S1h", "S1hs", "blocking S1h eof"];
/// S2 releasing the tracee from its settled stop: no backoff.
const RELEASED: [&str; 4] = ["S2", "attached", "S3", "blocking S3 eof"];
/// The pid line to S3's wait. S2's real `PT_CONTINUE` meets `EBUSY` until the attach's stop
/// lands (measured on CI).
const TO_S3: [&str; 7] = ["S0", "S1", "S2", "S2b*", "attached", "S3", "blocking S3 eof"];
/// S4's real detach: `PT_DETACH` meets `EBUSY` until S4's own stop lands.
const DETACHED: [&str; 4] = ["S4", "S4b*", "detached", DONE];
const REAPED: [&str; 4] = ["S5", "blocking S5 exit", "reaped", DONE];
const DONE: &str = "blocking done eof";

/// `kill(2)` to this test's own, unreaped child.
fn send(pid: u32, signal: i32) {
    assert_eq!(sys::kill(pid, signal), Ok(()), "kill({pid}, {signal})");
}

/// Blocks until the tracee, this test's child again, has exited or stopped, and returns that
/// record without consuming it. The test has closed the tracee's stdin, so a running tracee
/// exits.
fn await_change(pid: u32) -> libc::siginfo_t {
    sys::peek(pid, libc::WEXITED | libc::WSTOPPED).expect("waitid the tracee")
}

/// The tracee's own clean exit (stdin EOF).
fn assert_exited_cleanly(tracee: crate::Child) {
    let status = tracee.wait().expect("wait for the tracee");
    assert!(status.success(), "expected the tracee's own clean exit, got {status:?}");
}

/// The tracee was killed with `SIGKILL`: by XNU when its tracer exited while tracing it, or by
/// this test.
fn assert_sigkilled(tracee: crate::Child) {
    let info = await_change(tracee.id().pid());
    if info.si_code == libc::CLD_STOPPED {
        tracee.kill().expect("kill the stopped tracee");
        panic!("expected SIGKILL, but the tracee is stopped by {}", info.si_status);
    }
    let status = tracee.wait().expect("wait for the tracee");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "expected SIGKILL, got {status:?}");
}

/// The tracee was ended by `SIGTERM`, a signal the helper passed on.
fn assert_terminated(tracee: crate::Child) {
    let status = tracee.wait().expect("wait for the tracee");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "expected SIGTERM, got {status:?}");
}

/// After `detached`: the tracee may stay stopped (measured on CI on macOS 26), so it is ended
/// with `SIGKILL` through its handle.
fn end_detached(tracee: crate::Child) {
    tracee.kill().expect("kill the detached tracee");
    assert_sigkilled(tracee);
}

/// With the helper alive: `Ok(si_pid)` of the tracee's exit, which this test sees only once the
/// zombie is handed back, or the errno.
fn peek_exit(pid: u32) -> Result<libc::pid_t, i32> {
    sys::peek(pid, libc::WEXITED | libc::WNOHANG).map(|info| info.si_pid)
}

/// After `reaped`, with the helper still alive: the zombie is already this test's.
fn assert_handed_back(pid: u32) {
    assert_eq!(
        peek_exit(pid),
        Ok(pid as libc::pid_t),
        "the reaped tracee's zombie is not this test's"
    );
}

/// With the helper alive and the zombie still on its list: this test cannot see it.
fn assert_not_handed_back(pid: u32) {
    assert_eq!(peek_exit(pid), Err(libc::ECHILD), "the tracee came back without a reap");
}

/// After `detached`, with the helper still alive: the tracee is this test's child again. A
/// traced tracee is not: the parent's `waitid` gets `ECHILD` (measured on CI).
fn assert_is_our_child(pid: u32) {
    assert_eq!(
        sys::peek_child(pid),
        Ok(()),
        "the detached tracee is not this test's child"
    );
}

/// The panic message `f` fails with.
fn panic_of(f: impl FnOnce()) -> String {
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).expect_err("no panic");
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => payload
            .downcast::<&str>()
            .map(|message| message.to_string())
            .expect("a string panic payload"),
    }
}

// Feasibility ==================================================================================

/// What the helper relies on. A held tracee settles to `SSTOP` and is not this test's child
/// while traced. The helper's `WSTOPPED` peek sees the attach's `SIGSTOP`: S2 releases the
/// tracee only for a peeked `SIGSTOP`, so `attached` shows it. After the detach the tracee is
/// this test's child again, a `SIGSTOP` job-stops it, and `SIGKILL` ends it.
#[test]
fn feasibility_facts() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S1:hold").attach(&mut tracee);
    expect(&mut th, &HELD);
    assert_eq!(sys::pbi_status(pid), Ok(libc::SSTOP), "the held tracee's status");
    assert_eq!(
        sys::peek_child(pid),
        Err(libc::ECHILD),
        "the traced tracee's parent peek"
    );
    th.signal();
    expect(&mut th, &RELEASED);
    th.signal();
    expect(&mut th, &DETACHED);
    drop(th);
    send(pid, libc::SIGSTOP);
    drop(stdin);
    let info = await_change(pid);
    assert_eq!(
        (info.si_code, info.si_status),
        (libc::CLD_STOPPED, libc::SIGSTOP),
        "the detached tracee after SIGSTOP"
    );
    end_detached(tracee);
}

// Client ======================================================================================

/// A client's helper: no `state` reports, and `recv` skips `blocking` ones. Mutant: `start`
/// enables the traces.
#[test]
fn a_client_helper_reports_only_the_protocol() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start(Mode::Auto).attach(&mut tracee);
    assert_eq!(th.recv(), Report::Attached);
    drop(stdin);
    assert_eq!(th.recv(), Report::Reaped);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: `attach` sends a reaped child's pid.
#[test]
fn attach_refuses_a_reaped_tracee() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    drop(stdin);
    let status = tracee.wait().expect("wait for the tracee");
    assert!(status.success(), "expected the tracee's own clean exit, got {status:?}");
    let pending = super::start(Mode::Auto);
    let message = panic_of(|| drop(pending.attach(&mut tracee)));
    assert!(message.contains("not this process's unreaped child"), "{message}");
}

/// Mutant: the teardown drains a helper that waits for the tracee's exit.
#[test]
fn dropping_a_helper_that_awaits_the_tracees_exit_kills_it_and_fails() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = at_s4(&mut tracee, "S4:ESRCH");
    expect(&mut th, &["S4", "S6", "blocking S6 exit"]);
    // A mutant that drains instead then ends, rather than hanging.
    drop(stdin);
    let message = panic_of(|| drop(th));
    assert!(message.contains("waited in S6"), "{message}");
    // Killed, exited on its own, or not handed back, depending on when the helper died: its
    // handle's drop copes with each, and nothing is asserted.
    drop(tracee);
}

// S-1 ==========================================================================================

/// Sends `line`, closes the signal pipe, and expects the malformed-line exit.
fn malformed(line: &[u8]) {
    if !crate::test_support::require_group("TRACER") {
        return;
    }
    let mut pending = super::start_forced(Mode::Auto, "");
    std::io::Write::write_all(pending.session.signal_tx(), line).expect("write the line");
    drop(pending.session.signal_tx.take());
    assert_eq!(pending.session.next_report(), None);
    let status = pending.session.finish();
    assert_eq!(
        status.code(),
        Some(super::machine::MALFORMED_PID_LINE),
        "after {:?}: {status}",
        String::from_utf8_lossy(line)
    );
}

/// Mutant: a malformed line exits as EOF does.
#[test]
fn s_minus_1_a_stray_line_is_malformed() {
    malformed(b"not a pid\n");
}

#[test]
fn s_minus_1_a_non_numeric_pid_is_malformed() {
    malformed(b"pid abc\n");
}

#[test]
fn s_minus_1_an_empty_pid_is_malformed() {
    malformed(b"pid \n");
}

/// `kill(0, …)` would signal the helper's own process group. Mutant: a pid of 0 is accepted.
#[test]
fn s_minus_1_pid_0_is_malformed() {
    malformed(b"pid 0\n");
}

/// Mutant: a negative pid, a process group to `kill(2)`, is accepted.
#[test]
fn s_minus_1_a_negative_pid_is_malformed() {
    malformed(b"pid -1\n");
}

#[test]
fn s_minus_1_non_utf8_is_malformed() {
    malformed(b"pid \xff\n");
}

/// A pid no process has, so a mutant that takes it fails at S0. Mutant: S-1 takes a line cut
/// short by EOF.
#[test]
fn s_minus_1_eof_inside_the_line_is_malformed() {
    malformed(b"pid 99999998");
}

/// Mutant: S-1 treats EOF as a pid.
#[test]
fn s_minus_1_eof_exits_without_a_report() {
    if !crate::test_support::require_group("TRACER") {
        return;
    }
    let mut pending = super::start_forced(Mode::Auto, "");
    drop(pending.session.signal_tx.take());
    assert_eq!(pending.session.next_report(), None);
    assert!(pending.session.finish().success());
}

// S0, S1 =======================================================================================

/// Mutant: S0 ignores a receipt error.
#[test]
fn s0_a_receipt_error_fails() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = super::start_forced(Mode::Auto, "S0:ESRCH").attach(&mut tracee);
    expect(&mut th, &["S0", &err(libc::ESRCH, "S0"), DONE]);
    drop(th);
    drop(stdin);
    assert_exited_cleanly(tracee);
}

/// Mutant: S1 treats an attach error as success.
#[test]
fn s1_an_attach_error_fails() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = super::start_forced(Mode::Auto, "S1:EPERM").attach(&mut tracee);
    expect(&mut th, &["S0", "S1", &err(libc::EPERM, "S1"), DONE]);
    drop(th);
    drop(stdin);
    assert_exited_cleanly(tracee);
}

// S1h ==========================================================================================

/// Mutant: S1h's signal byte goes straight to S3.
#[test]
fn s1h_a_signal_byte_goes_to_release() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S1:hold").attach(&mut tracee);
    expect(&mut th, &HELD);
    th.signal();
    expect(&mut th, &RELEASED);
    drop(stdin);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S1h's EOF goes to S2.
#[test]
fn s1h_eof_exits_and_xnu_kills_the_tracee() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = super::start_forced(Mode::Auto, "S1:hold").attach(&mut tracee);
    expect(&mut th, &HELD);
    drop(th.session.signal_tx.take());
    expect(&mut th, &[DONE]);
    assert_eq!(th.session.next_report(), None);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// The injected `NOTE_EXIT` arrives while the tracee is really held, so S5's result is injected
/// too, and XNU kills the tracee when the helper exits. Mutant: S1h's `NOTE_EXIT` goes to S2.
#[test]
fn s1h_note_exit_goes_to_reap() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = super::start_forced(Mode::Auto, "S1:hold,S1h:NOTE_EXIT,S5:ok").attach(&mut tracee);
    expect(&mut th, &["S0", "S1", "S1h", "S5", "reaped", DONE]);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Runs S1h's peeks under `force`, the last of which fails the run.
fn s1h_peeks_until_the_error(force: &str) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = super::start_forced(Mode::Auto, force).attach(&mut tracee);
    expect(&mut th, &["S0", "S1", "S1h", &err(libc::EINVAL, "S1h"), DONE]);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: S1h retries a failed peek.
#[test]
fn s1h_a_failed_stop_peek_fails() {
    s1h_peeks_until_the_error("S1:hold,S1hstop:EINVAL");
}

/// Mutant: S1h holds a tracee that is not stopped.
#[test]
fn s1h_a_tracee_not_stopped_yet_backs_off() {
    s1h_peeks_until_the_error("S1:hold,S1hstop:none,S1hstop:EINVAL");
}

/// Mutant: S1h holds a stop that has not settled.
#[test]
fn s1h_a_settling_stop_backs_off() {
    s1h_peeks_until_the_error("S1:hold,S1hstop:settling,S1hstop:EINVAL");
}

/// Mutant: a lone `SIGCHLD` counts as a signal byte in S1h.
#[test]
fn s1h_a_lone_sigchld_reads_as_the_timeout() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = super::start_forced(Mode::Auto, "S1:hold,S1h:SIGCHLD").attach(&mut tracee);
    expect(&mut th, &HELD);
    drop(th.session.signal_tx.take());
    expect(&mut th, &[DONE]);
    assert_eq!(th.session.next_report(), None);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

// S2 ===========================================================================================

/// Holds the tracee, then releases it into S2 under `force` (which must hold `S1:hold`).
fn from_held<'a>(tracee: &'a mut crate::Child, force: &str) -> TracerHelper<'a> {
    let mut th = super::start_forced(Mode::Auto, force).attach(tracee);
    expect(&mut th, &HELD);
    th.signal();
    th
}

/// Mutant: S2 treats `EBUSY` as a failure.
#[test]
fn s2_ebusy_backs_off_then_retries() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = from_held(&mut tracee, "S1:hold,S2:EBUSY");
    expect(&mut th, &["S2", "S2b", "attached", "S3", "blocking S3 eof"]);
    drop(stdin);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutants: S2 releases a tracee its peek finds not stopped; S2 fails on it.
#[test]
fn s2_a_tracee_not_stopped_yet_backs_off() {
    s2_backs_off_before_the_release("S1:hold,S2stop:none");
}

/// Mutant: S2 releases a stop that has not settled.
#[test]
fn s2_a_settling_stop_backs_off() {
    s2_backs_off_before_the_release("S1:hold,S2stop:settling");
}

fn s2_backs_off_before_the_release(force: &str) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = from_held(&mut tracee, force);
    expect(&mut th, &["S2", "S2b", "attached", "S3", "blocking S3 eof"]);
    drop(stdin);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// The peek is injected, the `PT_CONTINUE` real, and the tracee exits in S2b. The real stop is
/// the attach's `SIGSTOP`, and XNU acts on a signal `PT_CONTINUE` passes from it with the stop
/// signal's properties (`issignal`): it discards a default-action one, so this tracee catches
/// `SIGTERM`. Mutants: S2 releases any stop without its signal; S2 passes on signal 0.
#[test]
fn s2_passes_a_stopping_signal_through() {
    let Some((mut tracee, stdin)) = tracee_with(true) else {
        return;
    };
    let mut th = from_held(&mut tracee, "S1:hold,S2stop:SIGTERM");
    expect(&mut th, &["S2", "S2s"]);
    // A tracee released without the signal then exits on its own instead.
    drop(stdin);
    expect(&mut th, &["S2b", "S2b*", &err("NOTE_EXIT", "S2b"), DONE]);
    drop(th);
    let status = tracee.wait().expect("wait for the tracee");
    assert_eq!(
        status.code(),
        Some(super::SIGTERM_EXIT),
        "expected the SIGTERM handler's exit, got {status:?}"
    );
}

/// The peek is injected; the test's own `SIGSTOP`, pending on the held tracee, stands in for the
/// attach's one that a real stop signal would have beaten. Mutants: S2 passes a stop signal on;
/// the kept signal is not re-sent.
#[test]
fn s2_keeps_a_stop_signal_until_after_the_detach() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S1:hold,S2stop:SIGTSTP").attach(&mut tracee);
    expect(&mut th, &HELD);
    send(pid, libc::SIGSTOP);
    th.signal();
    expect(
        &mut th,
        &["S2", "S2k", "S2b", "S2b*", "attached", "S3", "blocking S3 eof"],
    );
    th.signal();
    expect(&mut th, &["S4", "S4b*", "S4r", "detached", DONE]);
    drop(th);
    drop(stdin);
    assert_job_stopped(pid, libc::SIGTSTP);
    end_detached(tracee);
}

fn s2_fails(force: &str) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = super::start_forced(Mode::Auto, force).attach(&mut tracee);
    expect(&mut th, &["S0", "S1", "S2", &err(libc::EINVAL, "S2"), DONE]);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: S2 treats a failed stop peek as "not stopped yet".
#[test]
fn s2_a_failed_stop_peek_fails() {
    s2_fails("S2stop:EINVAL");
}

/// Mutant: S2 ignores a failed pass-through.
#[test]
fn s2_a_failed_pass_through_fails() {
    s2_fails("S2stop:SIGTERM,S2cont:EINVAL");
}

/// Mutant: S2 treats `EINVAL` as `EBUSY`.
#[test]
fn s2_another_errno_fails() {
    s2_fails("S2:EINVAL");
}

fn s2b_event_fails(event: &str) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let force = format!("S2:EBUSY,S2b:{event}");
    let mut th = super::start_forced(Mode::Auto, &force).attach(&mut tracee);
    expect(&mut th, &["S0", "S1", "S2", "S2b", &err(event, "S2b"), DONE]);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: S2b retries on `NOTE_EXIT`.
#[test]
fn s2b_note_exit_fails() {
    s2b_event_fails("NOTE_EXIT");
}

/// Mutant: S2b retries on a signal byte.
#[test]
fn s2b_a_signal_byte_fails() {
    s2b_event_fails("SIGNAL");
}

/// Mutant: S2b retries on EOF.
#[test]
fn s2b_eof_fails() {
    s2b_event_fails("EOF");
}

/// Mutant: a lone `SIGCHLD` counts as an event in S2b.
#[test]
fn s2b_a_lone_sigchld_reads_as_the_timeout() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = from_held(&mut tracee, "S1:hold,S2:EBUSY,S2b:SIGCHLD");
    expect(&mut th, &["S2", "S2b", "attached", "S3", "blocking S3 eof"]);
    drop(stdin);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

// S3 auto, S5 ==================================================================================

/// The organic path: S-1's pid line, S0, S1, S2's `attached`, S3's real `NOTE_EXIT`, and S5's
/// reap, which hands the zombie back with its real status. Mutants: S3 `auto` takes
/// `NOTE_EXIT` to S4; S5 reports `reaped` without reaping.
#[test]
fn s3_auto_note_exit_goes_to_reap() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S3 `auto` checks the signal byte before `NOTE_EXIT`.
#[test]
fn s3_auto_note_exit_wins_over_a_signal_byte_in_the_same_batch() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S3:NOTE_EXIT+SIGNAL").attach(&mut tracee);
    expect(
        &mut th,
        &["S0", "S1", "S2", "S2b*", "attached", "S3", "S5", "blocking S5 exit"],
    );
    drop(stdin);
    expect(&mut th, &["reaped", DONE]);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Also S4's real `SIGSTOP` and `PT_DETACH`. Mutants: S3 `auto` takes a signal byte to S5; S4
/// reports `detached` without detaching.
#[test]
fn s3_auto_a_signal_byte_goes_to_detach() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    th.signal();
    expect(&mut th, &DETACHED);
    assert_is_our_child(pid);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// Mutant: S3 treats EOF as `NOTE_EXIT`.
#[test]
fn s3_auto_eof_goes_to_detach() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(th.session.signal_tx.take());
    expect(&mut th, &DETACHED);
    assert_is_our_child(pid);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// Mutant: S5 fails on `EINTR`.
#[test]
fn s5_eintr_retries() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S5:EINTR").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S5 retries any error.
#[test]
fn s5_another_errno_fails() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S5:ECHILD").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &["S5", &err(libc::ECHILD, "S5"), DONE]);
    assert_not_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// `NOTE_EXIT` is injected while the tracee runs, then this test stops it, and S5's `wait4`
/// returns the traced stop. Mutant: S5 takes any record for a reap.
#[test]
fn s5_a_stop_is_not_a_reap() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S3:NOTE_EXIT").attach(&mut tracee);
    expect(
        &mut th,
        &["S0", "S1", "S2", "S2b*", "attached", "S3", "S5", "blocking S5 exit"],
    );
    send(pid, libc::SIGSTOP);
    expect(&mut th, &[&err(libc::EINVAL, "S5"), DONE]);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

// S3 hold, S3x =================================================================================

/// S3 `hold` confirming the zombie, then S3x's wait.
const EXITED: [&str; 4] = ["blocking S3 exit", "exited", "S3x", "blocking S3x eof"];

/// Mutant: S3 `hold` reaps at once.
#[test]
fn s3_hold_note_exit_reports_exited_then_a_signal_byte_reaps() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &EXITED);
    assert_not_handed_back(pid);
    th.signal();
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S3x ignores EOF.
#[test]
fn s3x_eof_reaps() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &EXITED);
    drop(th.session.signal_tx.take());
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// S3x's event arrives as an injected batch.
fn s3x_injected_release(event: &str) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, &format!("S3x:{event}")).attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &["blocking S3 exit", "exited", "S3x"]);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S3x takes only a real signal byte.
#[test]
fn s3x_an_injected_signal_byte_reaps() {
    s3x_injected_release("SIGNAL");
}

/// Mutant: S3x takes only a real EOF.
#[test]
fn s3x_an_injected_eof_reaps() {
    s3x_injected_release("EOF");
}

/// Mutant: S3x takes an injected `NOTE_EXIT` for a release.
#[test]
fn s3x_note_exit_fails() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "S3x:NOTE_EXIT").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(
        &mut th,
        &["blocking S3 exit", "exited", "S3x", &err("NOTE_EXIT", "S3x"), DONE],
    );
    assert_not_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// The second injection fails S3x, which the test sees only if the first left it waiting.
/// Mutant: a lone `SIGCHLD` releases S3x.
#[test]
fn s3x_a_lone_sigchld_is_ignored() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "S3x:SIGCHLD,S3x:NOTE_EXIT").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(
        &mut th,
        &["blocking S3 exit", "exited", "S3x", &err("NOTE_EXIT", "S3x"), DONE],
    );
    assert_not_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// `NOTE_EXIT` is injected while the tracee runs, then this test stops it: the helper's
/// `WEXITED` wait returns the stop record (measured on CI), which is not an exit. Mutant: S3
/// `hold` reports `exited` without checking the record.
#[test]
fn s3_hold_a_zombie_wait_that_finds_no_exit_fails() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "S3:NOTE_EXIT").attach(&mut tracee);
    expect(
        &mut th,
        &["S0", "S1", "S2", "S2b*", "attached", "S3", "blocking S3 exit"],
    );
    send(pid, libc::SIGSTOP);
    expect(&mut th, &[&err(libc::EINVAL, "S3"), DONE]);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: S3 `hold` takes a signal byte to S3x.
#[test]
fn s3_hold_a_signal_byte_without_note_exit_goes_to_detach() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    th.signal();
    expect(&mut th, &DETACHED);
    assert_is_our_child(pid);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// Mutant: S3 `hold` waits on after EOF.
#[test]
fn s3_hold_eof_without_note_exit_goes_to_detach() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(th.session.signal_tx.take());
    expect(&mut th, &DETACHED);
    assert_is_our_child(pid);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// The injected batch is taken on S3's entry; S3 then waits for the real zombie.
fn s3_hold_batch_passes_s3x(event: &str) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let force = format!("S3:NOTE_EXIT+{event}");
    let mut th = super::start_forced(Mode::Hold, &force).attach(&mut tracee);
    expect(
        &mut th,
        &["S0", "S1", "S2", "S2b*", "attached", "S3", "blocking S3 exit"],
    );
    drop(stdin);
    expect(&mut th, &["exited", "S3x", "S5", "blocking S5 exit", "reaped", DONE]);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: the batch's signal byte is dropped.
#[test]
fn s3_hold_note_exit_and_a_signal_byte_in_one_batch_pass_s3x_to_reap() {
    s3_hold_batch_passes_s3x("SIGNAL");
}

/// Mutant: the batch's EOF is dropped.
#[test]
fn s3_hold_note_exit_and_eof_in_one_batch_pass_s3x_to_reap() {
    s3_hold_batch_passes_s3x("EOF");
}

// S4, S4b, S6 ==================================================================================

/// Drives a traced, running tracee to S4 with a signal byte.
fn at_s4<'a>(tracee: &'a mut crate::Child, force: &str) -> TracerHelper<'a> {
    let mut th = super::start_forced(Mode::Auto, force).attach(tracee);
    expect(&mut th, &TO_S3);
    th.signal();
    th
}

/// Mutant: S4 treats `EBUSY` as a failure.
#[test]
fn s4_ebusy_backs_off_then_retries() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, "S4:EBUSY,S4sigstop:1");
    expect(&mut th, &["S4", "S4b", "S4b*", "detached", DONE]);
    assert_is_our_child(pid);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// Mutants: S4 detaches a tracee its peek finds not stopped; S4 fails on it.
#[test]
fn s4_a_tracee_not_stopped_yet_backs_off() {
    s4_backs_off_before_the_detach("none");
}

/// Mutant: S4 detaches a stop that has not settled.
#[test]
fn s4_a_settling_stop_backs_off() {
    s4_backs_off_before_the_detach("settling");
}

/// The tracee stays in the attach's settled stop (`S2:ok` skips the release), so the only
/// backoff is the injected answer's.
fn s4_backs_off_before_the_detach(stop: &str) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let force = format!("S1:hold,S2:ok,S3:SIGNAL,S4sigstop:0,S4stop:{stop}");
    let mut th = from_held(&mut tracee, &force);
    expect(&mut th, &["S2", "attached", "S3", "S4", "S4b", "detached", DONE]);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// Mutant: S4b ignores `NOTE_EXIT` (with no `SIGSTOP` sent, S4 finds the tracee running and
/// backs off again).
#[test]
fn s4b_note_exit_goes_to_reap() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, "S4:EBUSY,S4b:NOTE_EXIT");
    expect(&mut th, &["S4", "S4b", "S5", "blocking S5 exit"]);
    drop(stdin);
    expect(&mut th, &["reaped", DONE]);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

fn s4b_ignores(event: &str) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, &format!("S4:EBUSY,S4sigstop:1,S4b:{event}"));
    expect(&mut th, &["S4", "S4b", "S4b*", "detached", DONE]);
    assert_is_our_child(pid);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// Mutant: S4b fails on a signal byte.
#[test]
fn s4b_a_signal_byte_is_ignored() {
    s4b_ignores("SIGNAL");
}

/// Mutant: S4b fails on EOF.
#[test]
fn s4b_eof_is_ignored() {
    s4b_ignores("EOF");
}

/// Mutant: S4b fails on a lone `SIGCHLD`.
#[test]
fn s4b_a_lone_sigchld_is_ignored() {
    s4b_ignores("SIGCHLD");
}

/// Reaches S6 with S4's injections, then lets the tracee really exit: S6's `NOTE_EXIT` row.
fn s4_goes_to_s6(force: &str) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, force);
    expect(&mut th, &["S4", "S6", "blocking S6 exit"]);
    drop(stdin);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S4 treats `ESRCH` as a failure.
#[test]
fn s4_esrch_goes_to_exiting() {
    s4_goes_to_s6("S4:ESRCH");
}

/// Mutant: S4 ignores its `SIGSTOP`'s result.
#[test]
fn s4_a_sigstop_esrch_goes_to_exiting() {
    s4_goes_to_s6("S4sigstop:ESRCH,S4:EINVAL");
}

/// Mutant: S4 fails when the pass-through meets an exiting tracee.
#[test]
fn s4_a_pass_through_on_an_exiting_tracee_goes_to_exiting() {
    s4_goes_to_s6("S4sigstop:0,S4stop:SIGTERM,S4cont:ESRCH");
}

/// The "else S5" branch, reached only with `seed:NOTE_EXIT`. Mutant: S4's `ESRCH` ignores a
/// seen `NOTE_EXIT`.
#[test]
fn s4_esrch_after_note_exit_goes_to_reap() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, "seed:NOTE_EXIT,S4:ESRCH");
    expect(&mut th, &["S4", "S5", "blocking S5 exit"]);
    drop(stdin);
    expect(&mut th, &["reaped", DONE]);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

fn s4_fails(force: &str, errno: i32) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = at_s4(&mut tracee, force);
    expect(&mut th, &["S4", &err(errno, "S4"), DONE]);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: S4 takes `EPERM` for an exiting tracee.
#[test]
fn s4_eperm_fails() {
    s4_fails("S4:EPERM", libc::EPERM);
}

/// Mutant: S4 treats `EINVAL` as `EBUSY`.
#[test]
fn s4_another_errno_fails() {
    s4_fails("S4:EINVAL", libc::EINVAL);
}

/// Mutant: S4 ignores a failed `SIGSTOP`.
#[test]
fn s4_a_sigstop_error_fails() {
    s4_fails("S4sigstop:EPERM,S4:EINVAL", libc::EPERM);
}

/// Mutant: S4 treats a failed stop peek as "not stopped yet".
#[test]
fn s4_a_failed_stop_peek_fails() {
    s4_fails("S4stop:EINVAL", libc::EINVAL);
}

/// Mutant: S4 ignores a failed pass-through.
#[test]
fn s4_a_failed_pass_through_fails() {
    s4_fails("S4sigstop:0,S4stop:SIGTERM,S4cont:EINVAL", libc::EINVAL);
}

fn s6_ignores(eof: bool) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, "S4:ESRCH");
    expect(&mut th, &["S4", "S6", "blocking S6 exit"]);
    if eof {
        drop(th.session.signal_tx.take());
    } else {
        th.signal();
    }
    expect(&mut th, &["S6", "blocking S6 exit"]);
    drop(stdin);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S6 takes a signal byte to S5.
#[test]
fn s6_a_signal_byte_is_ignored() {
    s6_ignores(false);
}

/// Mutant: S6 exits on EOF.
#[test]
fn s6_eof_is_ignored() {
    s6_ignores(true);
}

/// Mutant: S6 re-enters on a lone `SIGCHLD`.
#[test]
fn s6_a_lone_sigchld_is_ignored() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = at_s4(&mut tracee, "S4:ESRCH,S6:SIGCHLD");
    expect(&mut th, &["S4", "S6", "blocking S6 exit"]);
    drop(stdin);
    expect(&mut th, &REAPED);
    drop(th);
    assert_exited_cleanly(tracee);
}

// Signals ======================================================================================

/// After the detach, with the tracee's stdin closed: it is job-stopped by the kept `signal`, or
/// by the detach's own `SIGSTOP`, which XNU discards the re-sent signal against when it leaves
/// the tracee stopped (measured on CI: sometimes on macOS 26, never on macOS 15).
fn assert_job_stopped(pid: u32, signal: i32) {
    let info = await_change(pid);
    assert!(
        info.si_code == libc::CLD_STOPPED && [signal, libc::SIGSTOP].contains(&info.si_status),
        "the detached tracee is not stopped by {signal} or SIGSTOP: si_code {}, si_status {}",
        info.si_code,
        info.si_status
    );
}

/// Holds the tracee at S1hs, posts it `signal` (a traced, stopped tracee only posts it;
/// measured on CI), and releases it: its first act on resuming is a traced stop for `signal`.
fn released_with_pending<'a>(tracee: &'a mut crate::Child, force: &str, signal: i32) -> TracerHelper<'a> {
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, force).attach(tracee);
    expect(&mut th, &HELD);
    send(pid, signal);
    th.signal();
    expect(&mut th, &["S2", "attached", "S3"]);
    th
}

/// Mutant: S3 passes on signal 0.
#[test]
fn s3_passes_a_stopping_signal_through() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = released_with_pending(&mut tracee, "S1:hold", libc::SIGTERM);
    expect(&mut th, &["blocking S3 eof", "S3s", "blocking S3 eof"]);
    // A tracee released without the signal then exits on its own instead.
    drop(stdin);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_terminated(tracee);
}

/// Mutants: S3 passes a stop signal on; the kept signal is not re-sent after the detach.
#[test]
fn s3_keeps_a_stop_signal_until_after_the_detach() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    send(pid, libc::SIGTSTP);
    expect(&mut th, &["S3k", "blocking S3 eof"]);
    th.signal();
    expect(&mut th, &["S4", "S4b*", "S4r", "detached", DONE]);
    drop(th);
    drop(stdin);
    assert_job_stopped(pid, libc::SIGTSTP);
    end_detached(tracee);
}

/// Mutant: a later stop signal replaces the kept one.
#[test]
fn s3_keeps_only_the_first_stop_signal() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    send(pid, libc::SIGTSTP);
    expect(&mut th, &["S3k", "blocking S3 eof"]);
    send(pid, libc::SIGTTIN);
    expect(&mut th, &["S3k", "blocking S3 eof"]);
    th.signal();
    expect(&mut th, &["S4", "S4b*", "S4r", "detached", DONE]);
    drop(th);
    drop(stdin);
    assert_job_stopped(pid, libc::SIGTSTP);
    end_detached(tracee);
}

/// Mutant: a `SIGCONT` passed on leaves the kept stop signal.
#[test]
fn s3_a_sigcont_drops_a_kept_stop_signal() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    send(pid, libc::SIGTSTP);
    expect(&mut th, &["S3k", "blocking S3 eof"]);
    send(pid, libc::SIGCONT);
    expect(&mut th, &["S3s", "blocking S3 eof"]);
    th.signal();
    expect(&mut th, &DETACHED);
    drop(th);
    drop(stdin);
    let info = await_change(pid);
    assert!(
        info.si_code != libc::CLD_STOPPED || info.si_status != libc::SIGTSTP,
        "the dropped SIGTSTP stopped the tracee"
    );
    if info.si_code == libc::CLD_STOPPED {
        end_detached(tracee);
    } else {
        assert_exited_cleanly(tracee);
    }
}

/// Mutants: S4 passes a stop signal on; S4 detaches from any stop.
#[test]
fn s4_keeps_a_stop_signal_until_after_the_detach() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    // S3's injected byte takes it to S4 before the SIGTSTP stop is handled there, and S4 sends no
    // SIGSTOP until the test does, after S4k: SIGSTOP (17) would otherwise beat SIGTSTP (18).
    let mut th = released_with_pending(&mut tracee, "S1:hold,S3:SIGNAL,S4sigstop:0", libc::SIGTSTP);
    expect(&mut th, &["S4", "S4b*", "S4k"]);
    send(pid, libc::SIGSTOP);
    expect(&mut th, &["S4b*", "S4r", "detached", DONE]);
    drop(th);
    drop(stdin);
    assert_job_stopped(pid, libc::SIGTSTP);
    end_detached(tracee);
}

/// Mutant: S4 ignores a failed re-send.
#[test]
fn s4_a_failed_resend_fails() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S4r:EPERM").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    send(pid, libc::SIGTSTP);
    expect(&mut th, &["S3k", "blocking S3 eof"]);
    th.signal();
    expect(&mut th, &["S4", "S4b*", &err(libc::EPERM, "S4"), DONE]);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// Mutant: S3 takes a `SIGCHLD` with no stop for a signal byte.
#[test]
fn s3_a_sigchld_without_a_stop_changes_nothing() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S3:SIGCHLD").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S3 fails when the pass-through meets an exiting tracee.
#[test]
fn s3_a_pass_through_on_an_exiting_tracee_waits_for_note_exit() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S3:SIGCHLD,S3stop:SIGTERM,S3cont:ESRCH").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &REAPED);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

fn s3_fails(force: &str) {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = super::start_forced(Mode::Auto, force).attach(&mut tracee);
    expect(
        &mut th,
        &[
            "S0",
            "S1",
            "S2",
            "S2b*",
            "attached",
            "S3",
            &err(libc::EINVAL, "S3"),
            DONE,
        ],
    );
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: S3 ignores a failed stop peek.
#[test]
fn s3_a_failed_stop_peek_fails() {
    s3_fails("S3:SIGCHLD,S3stop:EINVAL");
}

/// The re-peek after the backoff meets the injected error. Mutant: S3 waits for another
/// `SIGCHLD` after a settling stop.
#[test]
fn s3_a_settling_stop_peeks_again() {
    s3_fails("S3:SIGCHLD,S3stop:settling,S3stop:EINVAL");
}

/// Mutant: S3 ignores a failed pass-through.
#[test]
fn s3_a_failed_pass_through_fails() {
    s3_fails("S3:SIGCHLD,S3stop:SIGTERM,S3cont:EINVAL");
}

/// The injected byte takes S3 to S4 before the `SIGTERM` stop is handled there. Mutant: S4
/// detaches from whatever stop holds the tracee.
#[test]
fn s4_passes_a_stopping_signal_through_before_detaching() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = released_with_pending(&mut tracee, "S1:hold,S3:SIGNAL", libc::SIGTERM);
    expect(
        &mut th,
        &["S4", "S4b*", "S4s", "S4b*", "S5", "blocking S5 exit", "reaped", DONE],
    );
    assert_handed_back(pid);
    drop(th);
    drop(stdin);
    assert_terminated(tracee);
}

// Any state ====================================================================================

/// The report pipe is closed while the helper holds the tracee (libtest's own banner needs it
/// earlier), so the next write, S2's `state` line, fails and the helper exits while still
/// tracing: XNU kills the tracee. Mutant: a failed report write is ignored.
#[test]
fn a_failed_report_write_exits() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = super::start_forced(Mode::Auto, "S1:hold").attach(&mut tracee);
    expect(&mut th, &HELD);
    th.session.reports = None;
    th.signal();
    drop(th.session.signal_tx.take());
    th.session.finish();
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// `gone:attached`: the helper goes to done still tracing. Mutant: `report_then` ignores a
/// failed write.
#[test]
fn a_failed_attached_write_ends_the_run() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = from_held(&mut tracee, "S1:hold,gone:attached");
    expect(&mut th, &["S2", DONE]);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: the pass-through's trace ignores a failed write.
#[test]
fn a_failed_pass_through_trace_write_ends_the_run() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = from_held(&mut tracee, "S1:hold,S2stop:SIGTERM,S2cont:ok,gone:state S2s");
    expect(&mut th, &["S2", DONE]);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: S3's pass-through ignores a failed trace write.
#[test]
fn a_failed_s3_pass_through_trace_write_ends_the_run() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th =
        super::start_forced(Mode::Auto, "S3:SIGCHLD,S3stop:SIGTERM,S3cont:ok,gone:state S3s").attach(&mut tracee);
    expect(&mut th, &["S0", "S1", "S2", "S2b*", "attached", "S3", DONE]);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: a failed `exited` write is ignored.
#[test]
fn a_failed_exited_write_ends_the_run() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "gone:exited").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &["blocking S3 exit", DONE]);
    assert_not_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: a failed `blocking` write is ignored.
#[test]
fn a_failed_blocking_write_ends_the_run() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "gone:blocking S5 exit").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &["S5", DONE]);
    assert_not_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: a failed `reaped` write is ignored.
#[test]
fn a_failed_reaped_write_ends_the_run() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "gone:reaped").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &["S5", "blocking S5 exit", DONE]);
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: a failed `detached` write is ignored.
#[test]
fn a_failed_detached_write_ends_the_run() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let mut th = at_s4(&mut tracee, "gone:detached");
    expect(&mut th, &["S4", "S4b*", DONE]);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// `fail` ends the run whether or not its report is written.
#[test]
fn a_failed_error_write_ends_the_run() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let force = format!("S0:ESRCH,gone:{}", err(libc::ESRCH, "S0"));
    let mut th = super::start_forced(Mode::Auto, &force).attach(&mut tracee);
    expect(&mut th, &["S0", DONE]);
    drop(th);
    drop(stdin);
    assert_exited_cleanly(tracee);
}

/// After a terminal report the helper holds until EOF. Mutant: a signal byte ends it.
#[test]
fn done_ignores_a_signal_byte_and_holds() {
    let Some((mut tracee, stdin)) = tracee() else { return };
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S5:ECHILD").attach(&mut tracee);
    expect(&mut th, &TO_S3);
    drop(stdin);
    expect(&mut th, &["S5", &err(libc::ECHILD, "S5"), DONE]);
    th.signal();
    expect(&mut th, &["done", DONE]);
    assert_not_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}
