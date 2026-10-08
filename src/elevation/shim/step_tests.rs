use super::super::codes;
use super::super::protocol::{Errno, Frame, NotExecuted, Signal};
use super::{conclude, decide, Actions, Control, Events, ExecEvent, LoopState, ToChild};

fn state() -> LoopState {
    LoopState::new(false)
}

fn control(byte: u8) -> Events {
    Events {
        control: Control::Byte(byte),
        ..Events::NONE
    }
}

fn signal(to: ToChild) -> Actions {
    Actions {
        signal: Some(to),
        ..Actions::default()
    }
}

// decide -------------------------------------------------------------------------------------

#[skuld::test]
fn k_with_exec_pending_signals_the_child() {
    let mut st = state();
    assert!(st.exec_pending, "the child starts before exec");
    assert_eq!(decide(&mut st, &control(b'K')), signal(ToChild::Kill));
    assert!(st.exec_pending, "a control byte says nothing about exec");
}

#[skuld::test]
fn t_with_exec_pending_signals_the_child_with_term() {
    let mut st = state();
    assert_eq!(decide(&mut st, &control(b'T')), signal(ToChild::Term));
}

#[skuld::test]
fn owner_exit_kills_an_armed_program_once() {
    let mut st = state();
    let owner = Events {
        owner_exited: true,
        ..Events::NONE
    };
    assert_eq!(decide(&mut st, &owner), signal(ToChild::Kill));
    assert!(!st.owner_watched);
    assert_eq!(
        decide(&mut st, &owner),
        Actions::default(),
        "the watch has fired already"
    );
}

#[skuld::test]
fn owner_exit_after_disarm_leaves_the_program() {
    let mut st = state();
    assert_eq!(decide(&mut st, &control(b'D')), Actions::default());
    assert!(!st.armed);
    let owner = Events {
        owner_exited: true,
        ..Events::NONE
    };
    assert_eq!(decide(&mut st, &owner), Actions::default());
}

#[skuld::test]
fn eof_after_disarm_leaves_the_program_and_eof_before_it_kills() {
    let eof = Events {
        control: Control::Eof,
        ..Events::NONE
    };
    let mut armed = state();
    assert_eq!(decide(&mut armed, &eof), signal(ToChild::Kill));
    assert!(!armed.conn_open);
    let mut disarmed = state();
    decide(&mut disarmed, &control(b'D'));
    assert_eq!(decide(&mut disarmed, &eof), Actions::default());
    assert!(!disarmed.conn_open);
}

#[skuld::test]
fn t_after_an_owner_exit_stays_a_kill() {
    let mut st = state();
    let both = Events {
        owner_exited: true,
        ..control(b'T')
    };
    assert_eq!(decide(&mut st, &both), signal(ToChild::Kill));
}

#[skuld::test]
fn status_pipe_eof_and_report_clear_exec_pending() {
    for exec in [ExecEvent::Eof, ExecEvent::Report] {
        let mut st = state();
        let events = Events { exec, ..Events::NONE };
        assert_eq!(decide(&mut st, &events), Actions::default());
        assert!(!st.exec_pending, "{exec:?}");
    }
    let mut st = state();
    decide(&mut st, &Events::NONE);
    assert!(st.exec_pending, "silence leaves exec pending");
}

#[skuld::test]
fn unknown_byte_is_a_violation_and_kills() {
    for byte in [0u8, b'x', 0xff, b'A', b'N'] {
        let mut st = state();
        let expected = Actions {
            violation: true,
            ..signal(ToChild::Kill)
        };
        assert_eq!(decide(&mut st, &control(byte)), expected, "{byte:#04x}");
        // Disarming does not make a violation harmless.
        let mut disarmed = state();
        decide(&mut disarmed, &control(b'D'));
        assert_eq!(decide(&mut disarmed, &control(byte)), expected, "{byte:#04x} after D");
    }
}

#[skuld::test]
fn ping_without_test_hooks_is_a_violation() {
    let mut st = LoopState::new(false);
    let expected = Actions {
        violation: true,
        ..signal(ToChild::Kill)
    };
    assert_eq!(decide(&mut st, &control(b'P')), expected);
}

#[skuld::test]
fn ping_with_test_hooks_pongs_only() {
    let mut st = LoopState::new(true);
    let expected = Actions {
        pong: true,
        ..Actions::default()
    };
    assert_eq!(decide(&mut st, &control(b'P')), expected);
}

#[skuld::test]
fn a_fired_child_is_reaped_and_forced_failure_is_lost() {
    let mut st = state();
    let exited = Events {
        child_exited: true,
        ..Events::NONE
    };
    assert_eq!(
        decide(&mut st, &exited),
        Actions {
            reap: true,
            ..Actions::default()
        }
    );
    let forced = Events {
        forced_failure: true,
        ..control(b'K')
    };
    assert_eq!(
        decide(&mut st, &forced),
        Actions {
            lost: true,
            ..Actions::default()
        }
    );
}

// conclude -----------------------------------------------------------------------------------

const REPORT: NotExecuted = NotExecuted::ExecFailed(Errno(2));
const FRAME_F: Frame = Frame::NotExecuted(REPORT);

#[skuld::test]
fn f_over_u() {
    let verdict = conclude(Some(REPORT), None, false);
    assert_eq!((verdict.frame, verdict.exit_code), (FRAME_F, codes::NOT_EXECUTED));
}

#[skuld::test]
fn f_over_l_and_over_s() {
    for lost in [false, true] {
        let verdict = conclude(Some(REPORT), Some(0), lost);
        assert_eq!(
            (verdict.frame, verdict.exit_code),
            (FRAME_F, codes::NOT_EXECUTED),
            "lost {lost}"
        );
    }
}

#[skuld::test]
fn f_over_u_on_the_lost_path() {
    let verdict = conclude(Some(NotExecuted::TerminatedBeforeExec(Signal(15))), None, true);
    assert_eq!(
        (verdict.frame, verdict.exit_code),
        (
            Frame::NotExecuted(NotExecuted::TerminatedBeforeExec(Signal(15))),
            codes::NOT_EXECUTED
        )
    );
}

#[skuld::test]
fn u_over_l() {
    for lost in [false, true] {
        let verdict = conclude(None, None, lost);
        assert_eq!(
            (verdict.frame, verdict.exit_code),
            (Frame::StatusLost, codes::STATUS_LOST),
            "lost {lost}"
        );
    }
}

#[skuld::test]
fn l_carries_the_status_and_exits_118() {
    let verdict = conclude(None, Some(9), true);
    assert_eq!((verdict.frame, verdict.exit_code), (Frame::Lost(9), codes::SUPERVISION));
}

#[skuld::test]
fn s_exit_and_signal_codes() {
    // (wait status, exit code): exit(42), exit(0), SIGKILL, SIGSEGV with a core dump.
    for (status, code) in [(42 << 8, 42), (0, 0), (9, 137), (11 | 0x80, 139)] {
        let verdict = conclude(None, Some(status), false);
        assert_eq!(
            (verdict.frame, verdict.exit_code),
            (Frame::Status(status), code),
            "{status:#x}"
        );
    }
}
