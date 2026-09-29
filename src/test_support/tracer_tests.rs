//! The feasibility probe, and one test per row of the helper's transition table
//! (`machine.rs`). Each test asserts the whole `state` path, so a broken row cannot pass through
//! another row's identical final report, and names the mutant that fails it.
//!
//! These are `TRACER`-group tests (docs/principles.md, principles 9 and 10). Rows that no real
//! event reaches deterministically are driven by `COSCA_UH_FORCE` injections. Where an injected
//! result may leave the tracee stopped, the test ends it by EOF or lets XNU kill it when the
//! helper exits, rather than by the client obligation's `SIGKILL`.

use std::os::unix::process::ExitStatusExt as _;

use super::{Cause, Mode, Report, TracerHelper};

fn tracee() -> (crate::Child, std::io::PipeWriter) {
    crate::test_support::require_group("TRACER");
    let mut child = super::spawn_tracee();
    let stdin = child.stdin().expect("the tracee's stdin is piped");
    (child, stdin)
}

/// Reports up to and including `state <until>`: states by name, other reports by their
/// lowercase name. Panics on a terminal report.
fn path_to(th: &mut TracerHelper<'_>, until: &str) -> Vec<String> {
    let mut path = Vec::new();
    loop {
        let entry = match th.recv() {
            Report::State(state) => state,
            Report::Attached => "attached".to_string(),
            Report::Exited => "exited".to_string(),
            terminal => panic!("{terminal:?} before state {until}; path so far: {path:?}"),
        };
        let done = entry == until;
        path.push(entry);
        if done {
            return path;
        }
    }
}

/// Reports up to the terminal one, which is returned separately.
fn path_to_end(th: &mut TracerHelper<'_>) -> (Vec<String>, Report) {
    let mut path = Vec::new();
    loop {
        match th.recv() {
            Report::State(state) => path.push(state),
            Report::Attached => path.push("attached".to_string()),
            Report::Exited => path.push("exited".to_string()),
            terminal => return (path, terminal),
        }
    }
}

fn path(states: &[&str]) -> Vec<String> {
    states.iter().map(|s| s.to_string()).collect()
}

/// `path` without the backoff states in `backoffs`: a real `PT_CONTINUE` or `PT_DETACH` meets
/// `EBUSY` until the tracee's stop lands (measured on CI), and how often is the kernel's choice.
/// Their rows have their own tests, which inject `EBUSY`.
fn without(path: Vec<String>, backoffs: &[&str]) -> Vec<String> {
    path.into_iter().filter(|s| !backoffs.contains(&s.as_str())).collect()
}

/// `path_to(th, "S3")` without S2's real backoff rounds.
fn to_s3(th: &mut TracerHelper<'_>) -> Vec<String> {
    without(path_to(th, "S3"), &["S2b"])
}

/// `path_to_end`, without S4's real backoff rounds.
fn detach_path(th: &mut TracerHelper<'_>) -> (Vec<String>, Report) {
    let (states, end) = path_to_end(th);
    (without(states, &["S4b"]), end)
}

/// `path` with consecutive repeats collapsed: how many backoff rounds a real retry needs is the
/// kernel's choice.
fn dedup(mut path: Vec<String>) -> Vec<String> {
    path.dedup();
    path
}

fn error(errno: i32, state: &str) -> Report {
    Report::Error {
        cause: Cause::Errno(errno),
        state: state.to_string(),
    }
}

fn event_error(event: &str, state: &str) -> Report {
    Report::Error {
        cause: Cause::Event(event.to_string()),
        state: state.to_string(),
    }
}

/// The tracee exited on its own (stdin EOF) and is this test's child again.
fn assert_exited_cleanly(tracee: crate::Child) {
    let status = tracee.wait().expect("wait for the tracee");
    assert!(status.success(), "expected the tracee's own clean exit, got {status:?}");
}

/// The tracee was killed with `SIGKILL`: by XNU when its tracer exited while tracing it, or by
/// this test.
fn assert_sigkilled(tracee: crate::Child) {
    let status = tracee.wait().expect("wait for the tracee");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "expected SIGKILL, got {status:?}");
}

/// The tracee was ended by `SIGTERM`, a signal the helper passed through.
fn assert_terminated(tracee: crate::Child) {
    let status = tracee.wait().expect("wait for the tracee");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "expected SIGTERM, got {status:?}");
}

/// This test's non-reaping peek at its tracee's exit: `Ok(si_pid)` or the errno.
fn peek_exit(pid: u32) -> Result<libc::pid_t, i32> {
    // SAFETY: `siginfo_t` is plain data; all-zero is a valid value.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid out-pointer; WNOWAIT leaves the zombie in place.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc == 0 {
        Ok(info.si_pid)
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().expect("errno"))
    }
}

/// After `detached`, with the helper still alive: the tracee is this test's child again. A
/// traced tracee is not: the parent's `waitid` gets `ECHILD` (measured on CI).
fn assert_is_our_child(pid: u32) {
    // SAFETY: `siginfo_t` is plain data; all-zero is a valid value.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid out-pointer; WNOWAIT leaves any record in place.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    assert_eq!(
        rc,
        0,
        "the detached tracee is not this test's child: {}",
        std::io::Error::last_os_error()
    );
}

/// The client obligation after `detached`: a detached tracee may stay stopped (measured on CI on
/// macOS 26), so it is ended with `SIGKILL` through its handle.
fn end_detached(tracee: crate::Child) {
    tracee.kill().expect("kill the detached tracee");
    assert_sigkilled(tracee);
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

const TO_S3: [&str; 5] = ["S0", "S1", "S2", "attached", "S3"];

// Task 1: feasibility =========================================================================

/// Prints what this runner does on attach (`@@cosca-uh-probe@@` lines on stderr, shown by the
/// nextest override): the attach result, `pbi_status` before and after the stop settles, the
/// helper's own `WSTOPPED` peek, and whether `SIGKILL` ends a job-stopped, untraced child.
/// Asserts no measured value, only that each step completes.
#[test]
fn uh_feasibility_probe() {
    let (mut tracee, stdin) = tracee();
    let tracee_pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S1:hold").attach(&mut tracee);
    assert_eq!(path_to(&mut th, "S1hs"), ["S0", "S1", "S1h", "S1hs"]);
    th.signal();
    assert_eq!(to_s3(&mut th), ["S2", "attached", "S3"]);
    th.signal();
    assert_eq!(detach_path(&mut th), (path(&["S4"]), Report::Detached));
    let status = super::sys::pbi_status(tracee_pid);
    let stop = super::sys::stop_signal(tracee_pid);
    eprintln!("@@cosca-uh-probe@@ detached_pbi_status={status:?} parent_wstopped_peek={stop:?}");
    drop(th);

    let pid = tracee.id().pid() as libc::pid_t;
    // SAFETY: plain kill(2) to this test's own, unreaped child.
    assert_eq!(
        unsafe { libc::kill(pid, libc::SIGSTOP) },
        0,
        "SIGSTOP the detached tracee"
    );
    tracee.kill().expect("SIGKILL the job-stopped tracee");
    let status = tracee.wait().expect("wait for the job-stopped tracee");
    eprintln!(
        "@@cosca-uh-probe@@ sigkill_of_jobstop=exited signal={:?}",
        status.signal()
    );
    drop(stdin);
}

// S-1 ==========================================================================================

/// Mutant: S-1 takes any line for a pid line (would report `state S0`).
#[test]
fn s_minus_1_a_stray_line_exits_without_a_report() {
    crate::test_support::require_group("TRACER");
    let mut pending = super::start_forced(Mode::Auto, "");
    std::io::Write::write_all(pending.session.signal_tx(), b"not a pid\n").expect("write a stray line");
    drop(pending.session.signal_tx.take());
    assert_eq!(pending.session.next_report(), None);
}

/// Mutant: S-1 treats EOF as a pid of 0 (would report `state S0`).
#[test]
fn s_minus_1_eof_exits_without_a_report() {
    crate::test_support::require_group("TRACER");
    let mut pending = super::start_forced(Mode::Auto, "");
    drop(pending.session.signal_tx.take());
    assert_eq!(pending.session.next_report(), None);
}

// S0, S1 =======================================================================================

/// Mutant: S0 ignores a receipt error (would go on to S1).
#[test]
fn s0_a_receipt_error_fails() {
    let (mut tracee, stdin) = tracee();
    let mut th = super::start_forced(Mode::Auto, "S0:ESRCH").attach(&mut tracee);
    assert_eq!(path_to_end(&mut th), (path(&["S0"]), error(libc::ESRCH, "S0")));
    drop(th);
    drop(stdin);
    assert_exited_cleanly(tracee);
}

/// Mutant: S1 treats an attach error as success (would go on to S2).
#[test]
fn s1_an_attach_error_fails() {
    let (mut tracee, stdin) = tracee();
    let mut th = super::start_forced(Mode::Auto, "S1:EPERM").attach(&mut tracee);
    assert_eq!(path_to_end(&mut th), (path(&["S0", "S1"]), error(libc::EPERM, "S1")));
    drop(th);
    drop(stdin);
    assert_exited_cleanly(tracee);
}

// S1h ==========================================================================================

/// Mutant: S1h's signal byte goes straight to S3 (the path would lack S2 and `attached`).
#[test]
fn s1h_a_signal_byte_goes_to_release() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S1:hold").attach(&mut tracee);
    assert_eq!(path_to(&mut th, "S1hs"), ["S0", "S1", "S1h", "S1hs"]);
    th.signal();
    assert_eq!(to_s3(&mut th), ["S2", "attached", "S3"]);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S1h's EOF goes to S2 (the helper would report `attached`).
#[test]
fn s1h_eof_exits_and_xnu_kills_the_tracee() {
    let (mut tracee, stdin) = tracee();
    let mut th = super::start_forced(Mode::Auto, "S1:hold").attach(&mut tracee);
    assert_eq!(path_to(&mut th, "S1hs"), ["S0", "S1", "S1h", "S1hs"]);
    drop(th.session.signal_tx.take());
    assert_eq!(th.session.next_report(), None);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// The injected `NOTE_EXIT` arrives while the tracee is really held, so S5's result is injected
/// too, and XNU kills the tracee when the helper exits. Mutant: S1h's `NOTE_EXIT` goes to S2
/// (the path would show S2).
#[test]
fn s1h_note_exit_goes_to_reap() {
    let (mut tracee, stdin) = tracee();
    let mut th = super::start_forced(Mode::Auto, "S1:hold,S1h:NOTE_EXIT,S5:ok").attach(&mut tracee);
    assert_eq!(path_to_end(&mut th), (path(&["S0", "S1", "S1h", "S5"]), Report::Reaped));
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: the batch's EOF is dropped (S3x would wait for a byte on the real signal pipe, which
/// stays open; the test hangs until the nextest bound).
#[test]
fn s3_hold_note_exit_and_eof_in_one_batch_pass_s3x_to_reap() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "S3:NOTE_EXIT+EOF").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["exited", "S3x", "S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// The second injection fails S3x, which the test sees only if the first left it waiting.
/// Mutant: a lone `SIGCHLD` releases S3x (the helper would reap, leave the second injection
/// unused and fail).
#[test]
fn s3x_a_lone_sigchld_is_ignored() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "S3x:SIGCHLD,S3x:NOTE_EXIT").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(
        path_to_end(&mut th),
        (path(&["exited", "S3x"]), event_error("NOTE_EXIT", "S3x"))
    );
    assert_not_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

// S2 ===========================================================================================

/// Mutant: S2 treats `EBUSY` as a failure (would report `error`).
#[test]
fn s2_ebusy_backs_off_then_retries() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S2:EBUSY").attach(&mut tracee);
    assert_eq!(
        dedup(path_to(&mut th, "S3")),
        ["S0", "S1", "S2", "S2b", "attached", "S3"]
    );
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S2 releases any stop without its signal (the path would lack S2s).
#[test]
fn s2_passes_a_stopping_signal_through() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S2stop:SIGTERM,S2cont:ok").attach(&mut tracee);
    assert_eq!(
        without(path_to(&mut th, "S3"), &["S2b"]),
        ["S0", "S1", "S2", "S2s", "attached", "S3"]
    );
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

fn s2_fails(force: &str) {
    let (mut tracee, stdin) = tracee();
    let mut th = super::start_forced(Mode::Auto, force).attach(&mut tracee);
    assert_eq!(
        path_to_end(&mut th),
        (path(&["S0", "S1", "S2"]), error(libc::EINVAL, "S2"))
    );
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: S2 treats a failed stop peek as "not stopped yet" (would release and report
/// `attached`).
#[test]
fn s2_a_failed_stop_peek_fails() {
    s2_fails("S2stop:EINVAL");
}

/// Mutant: S2 ignores a failed pass-through (would release and report `attached`).
#[test]
fn s2_a_failed_pass_through_fails() {
    s2_fails("S2stop:SIGTERM,S2cont:EINVAL");
}

fn s2b_event_fails(event: &str) {
    let (mut tracee, stdin) = tracee();
    let force = format!("S2:EBUSY,S2b:{event}");
    let mut th = super::start_forced(Mode::Auto, &force).attach(&mut tracee);
    assert_eq!(
        path_to_end(&mut th),
        (path(&["S0", "S1", "S2", "S2b"]), event_error(event, "S2b"))
    );
    drop(th);
    drop(stdin);
    // Never released after the attach, so XNU killed it when the helper exited.
    assert_sigkilled(tracee);
}

/// Mutant: S2b retries on `NOTE_EXIT` (would report `attached`).
#[test]
fn s2b_note_exit_fails() {
    s2b_event_fails("NOTE_EXIT");
}

/// Mutant: S2b retries on a signal byte (would report `attached`).
#[test]
fn s2b_a_signal_byte_fails() {
    s2b_event_fails("SIGNAL");
}

/// Mutant: S2b retries on EOF (would report `attached`).
#[test]
fn s2b_eof_fails() {
    s2b_event_fails("EOF");
}

/// Mutant: S2 treats `EINVAL` as `EBUSY` (would retry the real `PT_CONTINUE` and report
/// `attached`).
#[test]
fn s2_another_errno_fails() {
    let (mut tracee, stdin) = tracee();
    let mut th = super::start_forced(Mode::Auto, "S2:EINVAL").attach(&mut tracee);
    assert_eq!(
        path_to_end(&mut th),
        (path(&["S0", "S1", "S2"]), error(libc::EINVAL, "S2"))
    );
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

// S3 auto, S5 ==================================================================================

/// The organic path: S-1's pid line, S0, S1, S2's `attached`, S3's real `NOTE_EXIT`, and S5's
/// reap, which hands the zombie back with its real status. Mutant: S3 `auto` takes `NOTE_EXIT`
/// to S4 (the path would show S4).
#[test]
fn s3_auto_note_exit_goes_to_reap() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S3 `auto` checks the signal byte before `NOTE_EXIT` (the path would show S4).
#[test]
fn s3_auto_note_exit_wins_over_a_signal_byte_in_the_same_batch() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S3:NOTE_EXIT+SIGNAL").attach(&mut tracee);
    assert_eq!(
        without(path_to(&mut th, "S5"), &["S2b"]),
        ["S0", "S1", "S2", "attached", "S3", "S5"]
    );
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&[]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Also S4's real `SIGSTOP` and `PT_DETACH`. Mutant: S3 `auto` takes a signal byte to S5
/// (would block in `wait4` on a live tracee; the test hangs until the nextest bound).
#[test]
fn s3_auto_a_signal_byte_goes_to_detach() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    th.signal();
    assert_eq!(detach_path(&mut th), (path(&["S4"]), Report::Detached));
    assert_is_our_child(pid);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// Mutant: S3 treats EOF as `NOTE_EXIT` (would block in `wait4` on a live tracee).
#[test]
fn s3_auto_eof_goes_to_detach() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(th.session.signal_tx.take());
    assert_eq!(detach_path(&mut th), (path(&["S4"]), Report::Detached));
    assert_is_our_child(pid);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// Mutant: S5 fails on `EINTR` (would report `error`).
#[test]
fn s5_eintr_retries() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S5:EINTR").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S5 retries any error (the real `wait4` would succeed and report `reaped`).
#[test]
fn s5_another_errno_fails() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S5:ECHILD").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), error(libc::ECHILD, "S5")));
    assert_not_handed_back(pid);
    drop(th);
    // Its tracer exited without reaping it; XNU hands the zombie back.
    assert_exited_cleanly(tracee);
}

// S3 hold, S3x =================================================================================

/// Mutant: S3 `hold` reaps at once (would report no `exited`).
#[test]
fn s3_hold_note_exit_reports_exited_then_a_signal_byte_reaps() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(path_to(&mut th, "S3x"), ["exited", "S3x"]);
    // Held: the zombie is still on the helper's list.
    assert_not_handed_back(pid);
    th.signal();
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S3x ignores EOF (would wait forever; the test hangs until the nextest bound).
#[test]
fn s3x_eof_reaps() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(path_to(&mut th, "S3x"), ["exited", "S3x"]);
    drop(th.session.signal_tx.take());
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S3x takes an injected `NOTE_EXIT` for a release (would report `reaped`).
#[test]
fn s3x_note_exit_fails() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "S3x:NOTE_EXIT").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(
        path_to_end(&mut th),
        (path(&["exited", "S3x"]), event_error("NOTE_EXIT", "S3x"))
    );
    assert_not_handed_back(pid);
    drop(th);
    // Its tracer exited without reaping it; XNU hands the zombie back.
    assert_exited_cleanly(tracee);
}

/// `NOTE_EXIT` is injected while the tracee runs, then this test stops it: the helper's
/// `WEXITED` wait returns the stop record (measured on CI), which is not an exit. Mutant: S3
/// `hold` reports `exited` without checking the record (would report `exited`).
#[test]
fn s3_hold_a_zombie_wait_that_finds_no_exit_fails() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid() as libc::pid_t;
    let mut th = super::start_forced(Mode::Hold, "S3:NOTE_EXIT").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    // SAFETY: plain kill(2) to this test's own, unreaped child.
    assert_eq!(
        unsafe { libc::kill(pid, libc::SIGSTOP) },
        0,
        "SIGSTOP the traced tracee"
    );
    assert_eq!(path_to_end(&mut th), (path(&[]), error(libc::EINVAL, "S3")));
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: S3 `hold` takes a signal byte to S3x (would report `exited`).
#[test]
fn s3_hold_a_signal_byte_without_note_exit_goes_to_detach() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    th.signal();
    assert_eq!(detach_path(&mut th), (path(&["S4"]), Report::Detached));
    assert_is_our_child(pid);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// The injected batch is taken on S3's entry; S3 then waits for the real zombie. Mutant: the
/// batch's signal byte is dropped (S3x would wait for another; the test hangs until the nextest
/// bound).
#[test]
fn s3_hold_note_exit_and_a_signal_byte_in_one_batch_pass_s3x_to_reap() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Hold, "S3:NOTE_EXIT+SIGNAL").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["exited", "S3x", "S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

// S4, S4b, S6 ==================================================================================

/// Drives a traced, running tracee to S4 with a signal byte.
fn at_s4<'a>(tracee: &'a mut crate::Child, force: &str) -> TracerHelper<'a> {
    let mut th = super::start_forced(Mode::Auto, force).attach(tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    th.signal();
    th
}

/// Mutant: S4 treats `EBUSY` as a failure (would report `error`).
#[test]
fn s4_ebusy_backs_off_then_retries() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, "S4:EBUSY,S4sigstop:1");
    let (states, end) = path_to_end(&mut th);
    assert_eq!((dedup(states), end), (path(&["S4", "S4b"]), Report::Detached));
    assert_is_our_child(pid);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// Mutant: S4b ignores `NOTE_EXIT` (with no `SIGSTOP` sent, S4 would find the tracee never
/// stopped and back off forever; the test hangs until the nextest bound).
#[test]
fn s4b_note_exit_goes_to_reap() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, "S4:EBUSY,S4b:NOTE_EXIT");
    assert_eq!(path_to(&mut th, "S5"), ["S4", "S4b", "S5"]);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&[]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

fn s4b_ignores(event: &str) {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, &format!("S4:EBUSY,S4sigstop:1,S4b:{event}"));
    let (states, end) = path_to_end(&mut th);
    assert_eq!((dedup(states), end), (path(&["S4", "S4b"]), Report::Detached));
    assert_is_our_child(pid);
    drop(th);
    drop(stdin);
    end_detached(tracee);
}

/// Mutant: S4b fails on a signal byte (would report `error`).
#[test]
fn s4b_a_signal_byte_is_ignored() {
    s4b_ignores("SIGNAL");
}

/// Mutant: S4b fails on EOF (would report `error`).
#[test]
fn s4b_eof_is_ignored() {
    s4b_ignores("EOF");
}

/// Reaches S6 with S4's injections, then lets the tracee really exit: S6's `NOTE_EXIT` row.
fn s4_goes_to_s6(force: &str) {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, force);
    assert_eq!(path_to(&mut th, "S6"), ["S4", "S6"]);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S4 treats `ESRCH` as a failure (would report `error`).
#[test]
fn s4_esrch_goes_to_exiting() {
    s4_goes_to_s6("S4:ESRCH");
}

/// Mutant: S4 ignores its `SIGSTOP`'s result (would go on to the injected `EINVAL`).
#[test]
fn s4_a_sigstop_esrch_goes_to_exiting() {
    s4_goes_to_s6("S4sigstop:ESRCH,S4:EINVAL");
}

/// Mutant: S4's `EPERM` is always a failure (would report `error`).
#[test]
fn s4_eperm_with_the_tracee_gone_goes_to_exiting() {
    s4_goes_to_s6("S4:EPERM,S4pidinfo:ESRCH");
}

/// The "else S5" branch, reached only with `seed:NOTE_EXIT`. Mutant: S4's `ESRCH` ignores a
/// seen `NOTE_EXIT` (would go to S6).
#[test]
fn s4_esrch_after_note_exit_goes_to_reap() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, "seed:NOTE_EXIT,S4:ESRCH");
    assert_eq!(path_to(&mut th, "S5"), ["S4", "S5"]);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&[]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

fn s4_fails(force: &str, errno: i32) {
    let (mut tracee, stdin) = tracee();
    let mut th = at_s4(&mut tracee, force);
    assert_eq!(path_to_end(&mut th), (path(&["S4"]), error(errno, "S4")));
    drop(th);
    drop(stdin);
    // Still traced when the helper exited, so XNU killed it.
    assert_sigkilled(tracee);
}

/// Mutant: S4's `EPERM` is always `ESRCH` (would go to S6).
#[test]
fn s4_eperm_with_the_tracee_alive_fails() {
    s4_fails("S4:EPERM,S4pidinfo:ok", libc::EPERM);
}

/// Mutant: S4 treats `EINVAL` as `EBUSY` (would retry the real `PT_DETACH`).
#[test]
fn s4_another_errno_fails() {
    s4_fails("S4:EINVAL", libc::EINVAL);
}

/// Mutant: S4 ignores a failed `SIGSTOP` (would go on to the injected `EINVAL`).
#[test]
fn s4_a_sigstop_error_fails() {
    s4_fails("S4sigstop:EPERM,S4:EINVAL", libc::EPERM);
}

fn s6_ignores(eof: bool) {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = at_s4(&mut tracee, "S4:ESRCH");
    assert_eq!(path_to(&mut th, "S6"), ["S4", "S6"]);
    if eof {
        drop(th.session.signal_tx.take());
    } else {
        th.signal();
    }
    assert_eq!(path_to(&mut th, "S6"), ["S6"]);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S6 takes a signal byte to S5 (the path would show S5 where S6 re-enters).
#[test]
fn s6_a_signal_byte_is_ignored() {
    s6_ignores(false);
}

/// Mutant: S6 exits on EOF (the path would end without re-entering S6).
#[test]
fn s6_eof_is_ignored() {
    s6_ignores(true);
}

// Signal pass-through =========================================================================

/// Holds the tracee at S1hs, posts it `SIGTERM` (a traced, stopped tracee only posts it; measured
/// on CI), and releases it: its first act on resuming is a traced stop for `SIGTERM`.
fn released_with_sigterm_pending<'a>(tracee: &'a mut crate::Child, force: &str) -> TracerHelper<'a> {
    let pid = tracee.id().pid() as libc::pid_t;
    let mut th = super::start_forced(Mode::Auto, force).attach(tracee);
    assert_eq!(path_to(&mut th, "S1hs"), ["S0", "S1", "S1h", "S1hs"]);
    // SAFETY: plain kill(2) to this test's own, unreaped child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0, "SIGTERM the held tracee");
    th.signal();
    assert_eq!(to_s3(&mut th), ["S2", "attached", "S3"]);
    th
}

/// Mutant: S3 continues a signal stop without its signal (the tracee would run on, blocked on
/// stdin; the test hangs until the nextest bound).
#[test]
fn s3_passes_a_stopping_signal_through() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = released_with_sigterm_pending(&mut tracee, "S1:hold");
    assert_eq!(path_to_end(&mut th), (path(&["S3s", "S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    drop(stdin);
    assert_terminated(tracee);
}

/// Mutant: S3 takes a `SIGCHLD` with no stop for a signal byte (the path would show S4).
#[test]
fn s3_a_sigchld_without_a_stop_changes_nothing() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S3:SIGCHLD").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: S3 fails when the pass-through meets an exiting tracee (would report `error`).
#[test]
fn s3_a_pass_through_on_an_exiting_tracee_waits_for_note_exit() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S3:SIGCHLD,S3stop:SIGTERM,S3cont:ESRCH").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    assert_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}

fn s3_fails(force: &str) {
    let (mut tracee, stdin) = tracee();
    let mut th = super::start_forced(Mode::Auto, force).attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    assert_eq!(path_to_end(&mut th), (path(&[]), error(libc::EINVAL, "S3")));
    drop(th);
    drop(stdin);
    // Still traced when the helper exited, so XNU killed it.
    assert_sigkilled(tracee);
}

/// Mutant: S3 ignores a failed stop peek (would wait on; the test hangs until the nextest bound).
#[test]
fn s3_a_failed_stop_peek_fails() {
    s3_fails("S3:SIGCHLD,S3stop:EINVAL");
}

/// Mutant: S3 ignores a failed pass-through (would wait on; the test hangs until the nextest
/// bound).
#[test]
fn s3_a_failed_pass_through_fails() {
    s3_fails("S3:SIGCHLD,S3stop:SIGTERM,S3cont:EINVAL");
}

/// The injected signal byte takes S3 to S4 at once, before the `SIGTERM` stop is handled there.
/// Mutant: S4 detaches from whatever stop holds the tracee (would report `detached`, the
/// `SIGTERM` discarded and S4's own `SIGSTOP` left pending).
#[test]
fn s4_passes_a_stopping_signal_through_before_detaching() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = released_with_sigterm_pending(&mut tracee, "S1:hold,S3:SIGNAL");
    let (states, end) = path_to_end(&mut th);
    assert_eq!(
        (without(states, &["S4b"]), end),
        (path(&["S4", "S4s", "S5"]), Report::Reaped)
    );
    assert_handed_back(pid);
    drop(th);
    drop(stdin);
    assert_terminated(tracee);
}

/// Mutant: S4 fails when the pass-through meets an exiting tracee (would report `error`).
#[test]
fn s4_a_pass_through_on_an_exiting_tracee_goes_to_exiting() {
    s4_goes_to_s6("S4sigstop:0,S4stop:SIGTERM,S4cont:ESRCH");
}

/// Mutant: S4 treats a failed stop peek as "not stopped yet" (would detach once stopped).
#[test]
fn s4_a_failed_stop_peek_fails() {
    s4_fails("S4stop:EINVAL", libc::EINVAL);
}

/// Mutant: S4 ignores a failed pass-through (would wait for a stop that never comes; the test
/// hangs until the nextest bound).
#[test]
fn s4_a_failed_pass_through_fails() {
    s4_fails("S4sigstop:0,S4stop:SIGTERM,S4cont:EINVAL", libc::EINVAL);
}

// SIGCHLD alone ================================================================================

/// Mutant: a lone `SIGCHLD` counts as an event in S2b (would report `error SIGCHLD`, or treat it
/// as `EOF`).
#[test]
fn s2b_a_lone_sigchld_reads_as_the_timeout() {
    let (mut tracee, stdin) = tracee();
    let mut th = super::start_forced(Mode::Auto, "S2:EBUSY,S2b:SIGCHLD").attach(&mut tracee);
    assert_eq!(
        dedup(path_to(&mut th, "S3")),
        ["S0", "S1", "S2", "S2b", "attached", "S3"]
    );
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    drop(th);
    assert_exited_cleanly(tracee);
}

/// Mutant: a lone `SIGCHLD` counts as an event in S1h (would take it for a signal byte and go
/// to S2).
#[test]
fn s1h_a_lone_sigchld_reads_as_the_timeout() {
    let (mut tracee, stdin) = tracee();
    let mut th = super::start_forced(Mode::Auto, "S1:hold,S1h:SIGCHLD").attach(&mut tracee);
    assert_eq!(path_to(&mut th, "S1hs"), ["S0", "S1", "S1h", "S1hs"]);
    drop(th.session.signal_tx.take());
    assert_eq!(th.session.next_report(), None);
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// Mutant: S4b fails on a lone `SIGCHLD` (would report `error`).
#[test]
fn s4b_a_lone_sigchld_is_ignored() {
    s4b_ignores("SIGCHLD");
}

/// Mutant: S6 re-enters on a lone `SIGCHLD` (the path would show S6 again).
#[test]
fn s6_a_lone_sigchld_is_ignored() {
    let (mut tracee, stdin) = tracee();
    let mut th = at_s4(&mut tracee, "S4:ESRCH,S6:SIGCHLD");
    assert_eq!(path_to(&mut th, "S6"), ["S4", "S6"]);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), Report::Reaped));
    drop(th);
    assert_exited_cleanly(tracee);
}

/// `NOTE_EXIT` is injected while the tracee runs, then this test stops it, and S5's `wait4`
/// returns the traced stop. Mutant: S5 takes any record for a reap (would report `reaped`).
#[test]
fn s5_a_stop_is_not_a_reap() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid() as libc::pid_t;
    let mut th = super::start_forced(Mode::Auto, "S3:NOTE_EXIT").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    // SAFETY: plain kill(2) to this test's own, unreaped child.
    assert_eq!(
        unsafe { libc::kill(pid, libc::SIGSTOP) },
        0,
        "SIGSTOP the traced tracee"
    );
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), error(libc::EINVAL, "S5")));
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

// Any state ====================================================================================

/// The report pipe is closed while the helper holds the tracee (libtest's own banner needs it
/// earlier), so the next write, S2's `state` line, fails and the helper exits while still
/// tracing: XNU kills the tracee. Mutant: a failed report write is ignored (the helper would go
/// on to S3 and detach on EOF, leaving the tracee alive, blocked on its stdin or stopped; the
/// test's wait hangs until the nextest bound).
#[test]
fn a_failed_report_write_exits() {
    let (mut tracee, stdin) = tracee();
    let mut th = super::start_forced(Mode::Auto, "S1:hold").attach(&mut tracee);
    assert_eq!(path_to(&mut th, "S1hs"), ["S0", "S1", "S1h", "S1hs"]);
    th.session.reports = None;
    th.signal();
    drop(th.session.signal_tx.take());
    th.session.helper.wait().expect("wait for the helper");
    drop(th);
    drop(stdin);
    assert_sigkilled(tracee);
}

/// After a terminal report the helper holds until EOF. Mutant: a signal byte ends it (no `done`
/// report would come, and its exit would hand the zombie back).
#[test]
fn done_ignores_a_signal_byte_and_holds() {
    let (mut tracee, stdin) = tracee();
    let pid = tracee.id().pid();
    let mut th = super::start_forced(Mode::Auto, "S5:ECHILD").attach(&mut tracee);
    assert_eq!(to_s3(&mut th), TO_S3);
    drop(stdin);
    assert_eq!(path_to_end(&mut th), (path(&["S5"]), error(libc::ECHILD, "S5")));
    th.signal();
    assert_eq!(path_to(&mut th, "done"), ["done"]);
    assert_not_handed_back(pid);
    drop(th);
    assert_exited_cleanly(tracee);
}
