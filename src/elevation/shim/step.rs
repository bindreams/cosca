//! The shim's supervision step and its final verdict, as pure functions: no I/O and no system calls.
//! The run loop polls, gathers what is ready into [`Events`], calls [`decide`] and performs the
//! returned [`Actions`]; at the end it calls [`conclude`] and writes the one frame it returns.

use super::codes;
use super::protocol::{Command, Frame, NotExecuted};

/// What the loop is still doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoopState {
    /// A control connection that ends, or an owner that exits, kills the program.
    pub(crate) armed: bool,
    pub(crate) conn_open: bool,
    pub(crate) owner_watched: bool,
    /// The child may not have reached `exec` yet: the status pipe has said nothing.
    pub(crate) exec_pending: bool,
    /// Test hooks are installed: `P` is a valid byte.
    pub(crate) test_hooks: bool,
}

impl LoopState {
    pub(crate) fn new(test_hooks: bool) -> LoopState {
        LoopState {
            armed: true,
            conn_open: true,
            owner_watched: true,
            exec_pending: true,
            test_hooks,
        }
    }
}

/// What cosca's connection gave this round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Control {
    Nothing,
    Byte(u8),
    /// The connection ended.
    Eof,
}

/// What the status pipe gave this round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecEvent {
    Nothing,
    /// The child's `exec` succeeded: the pipe closed with no report.
    Eof,
    Report,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Events {
    pub(crate) control: Control,
    pub(crate) owner_exited: bool,
    pub(crate) child_exited: bool,
    pub(crate) exec: ExecEvent,
    /// A signal reached the shim (D8d): any signal stops the program.
    pub(crate) signaled: bool,
    /// Test hook: supervision is forced to fail.
    pub(crate) forced_failure: bool,
}

impl Events {
    pub(crate) const NONE: Events = Events {
        control: Control::Nothing,
        owner_exited: false,
        child_exited: false,
        exec: ExecEvent::Nothing,
        signaled: false,
        forced_failure: false,
    };
}

/// A signal to the child, through its handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToChild {
    Kill,
    Term,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Actions {
    pub(crate) signal: Option<ToChild>,
    /// Collect the child's status through its handle.
    pub(crate) reap: bool,
    /// Supervision failed: kill, reap, conclude.
    pub(crate) lost: bool,
    /// Test hook: answer the ordering ping.
    pub(crate) pong: bool,
    /// cosca sent a byte outside the protocol: logged, and the child is killed.
    pub(crate) violation: bool,
}

/// One supervision step. Control is served whether or not the child has reached `exec`.
pub(crate) fn decide(state: &mut LoopState, events: &Events) -> Actions {
    let mut actions = Actions::default();
    if events.forced_failure {
        actions.lost = true;
        return actions;
    }
    if events.exec != ExecEvent::Nothing {
        state.exec_pending = false;
    }
    if events.owner_exited && state.owner_watched {
        state.owner_watched = false;
        if state.armed {
            actions.signal = Some(ToChild::Kill);
        }
    }
    if events.signaled {
        actions.signal = Some(ToChild::Kill);
    }
    match events.control {
        Control::Nothing => {}
        Control::Eof => {
            state.conn_open = false;
            if state.armed {
                actions.signal = Some(ToChild::Kill);
            }
        }
        Control::Byte(byte) => match Command::decode(byte) {
            Ok(Command::Kill) => actions.signal = Some(ToChild::Kill),
            Ok(Command::Terminate) => {
                if actions.signal != Some(ToChild::Kill) {
                    actions.signal = Some(ToChild::Term);
                }
            }
            Ok(Command::Disarm) => state.armed = false,
            Ok(Command::Ping) if state.test_hooks => actions.pong = true,
            // `A` and `N` are valid only once, as the first byte; `P` only with hooks.
            Ok(Command::Allow | Command::Deny | Command::Ping) | Err(_) => {
                actions.signal = Some(ToChild::Kill);
                actions.violation = true;
            }
        },
    }
    actions.reap = events.child_exited;
    actions
}

/// The one frame and the shim's exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Verdict {
    pub(crate) frame: Frame,
    pub(crate) exit_code: i32,
}

/// Chooses the frame from what the shim knows at the end. The precedence is F, U, L, S: a report
/// from the status pipe is positive evidence the program never ran, whatever the reap gave.
///
/// - `report`: the status pipe's report.
/// - `reaped`: the child's wait status; `None` when someone else collected it.
/// - `lost`: supervision failed, and the shim killed the child itself.
pub(crate) fn conclude(report: Option<NotExecuted>, reaped: Option<i32>, lost: bool) -> Verdict {
    if let Some(not_executed) = report {
        return Verdict {
            frame: Frame::NotExecuted(not_executed),
            exit_code: codes::NOT_EXECUTED,
        };
    }
    let Some(status) = reaped else {
        return Verdict {
            frame: Frame::StatusLost,
            exit_code: codes::STATUS_LOST,
        };
    };
    if lost {
        return Verdict {
            frame: Frame::Lost(status),
            exit_code: codes::SUPERVISION,
        };
    }
    Verdict {
        frame: Frame::Status(status),
        exit_code: exit_code_of(status),
    }
}

/// The program's own exit code, or `128 + signo`.
fn exit_code_of(wait_status: i32) -> i32 {
    match wait_status & 0x7f {
        0 => (wait_status >> 8) & 0xff,
        signal => 128 + signal,
    }
}

#[cfg(test)]
#[path = "step_tests.rs"]
mod step_tests;
