//! The console-event proxy's wire format: its argv and its exit codes, the cause of a failed step
//! among them. Pure: no I/O, no system calls.
//!
//! Whether a process is a proxy is not in the argv: a caller says so with the environment variable
//! [`role::HELPER_ENV`](crate::role::HELPER_ENV), and the argv is then data only.
//!
//! Every value has exactly one encoding, so a decoder never accepts two spellings of one thing.

use std::ffi::{OsStr, OsString};
use std::num::NonZeroU16;

use crate::role::decimal;

/// The protocol version this cosca speaks.
pub(crate) const VERSION: u32 = 4;

/// A console control event that can be sent to a child's console: Ctrl+C or Ctrl+Break.
///
/// What [`stop::send_console_event_via_proxy`](crate::stop::send_console_event_via_proxy) sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtrlEvent {
    /// `CTRL_C_EVENT`.
    CtrlC,
    /// `CTRL_BREAK_EVENT`.
    CtrlBreak,
}

impl CtrlEvent {
    /// The event's Win32 name, as an error or a log says what was sent: "CTRL_C", "CTRL_BREAK".
    #[cfg_attr(not(windows), allow(dead_code, reason = "only a Windows stop names its event"))]
    pub(crate) fn name(self) -> &'static str {
        match self {
            CtrlEvent::CtrlC => "CTRL_C",
            CtrlEvent::CtrlBreak => "CTRL_BREAK",
        }
    }

    #[cfg_attr(
        not(windows),
        allow(dead_code, reason = "only the Windows caller side starts a proxy")
    )]
    fn token(self) -> &'static str {
        match self {
            CtrlEvent::CtrlC => "c",
            CtrlEvent::CtrlBreak => "break",
        }
    }

    fn from_token(token: &str) -> Option<CtrlEvent> {
        match token {
            "c" => Some(CtrlEvent::CtrlC),
            "break" => Some(CtrlEvent::CtrlBreak),
            _ => None,
        }
    }
}

/// What the proxy is told on its command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProxyArgs {
    /// The pid of the process whose console gets the event, and the key that names it among the
    /// processes that have had that pid (a [`ProcessIdRecord`]'s `pid` and `token`): the proxy
    /// opens the target by both before it attaches, so a pid reissued since the caller read it is
    /// not attached to.
    ///
    /// [`ProcessIdRecord`]: crate::identity::ProcessIdRecord
    pub(crate) target: u32,
    pub(crate) target_key: u64,
    pub(crate) event: CtrlEvent,
    /// The pid of the process that started the proxy. The proxy sends nothing to a console this
    /// process is attached to.
    pub(crate) caller: u32,
}

/// Why argv is not a valid proxy argv.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProxyArgsError {
    #[error("the caller speaks protocol version {theirs}, this proxy {ours}")]
    VersionMismatch { ours: u32, theirs: u32 },
    #[error("the first argument is not a protocol version (a decimal number)")]
    BadVersion,
    #[error("expected a protocol version, a target pid, its key, an event and a caller pid")]
    WrongArgumentCount,
    #[error("a pid or a key is not a decimal number")]
    BadNumber,
    #[error("the event is neither `c` nor `break`")]
    BadEvent,
}

impl ProxyArgsError {
    /// What the proxy answers for this error.
    pub(crate) fn answer(self) -> ProxyAnswer {
        match self {
            ProxyArgsError::VersionMismatch { .. } => ProxyAnswer::VersionMismatch,
            _ => ProxyAnswer::Usage,
        }
    }
}

impl ProxyArgs {
    /// The full argv, `argv[0]` included: `[exe, version, target, target_key, "c" | "break", caller]`,
    /// the version a plain decimal.
    #[cfg_attr(
        not(windows),
        allow(dead_code, reason = "only the Windows caller side starts a proxy")
    )]
    pub(crate) fn to_argv(self, exe: &OsStr) -> Vec<OsString> {
        vec![
            exe.to_owned(),
            VERSION.to_string().into(),
            self.target.to_string().into(),
            self.target_key.to_string().into(),
            self.event.token().into(),
            self.caller.to_string().into(),
        ]
    }

    /// Reads `argv` (`argv[0]` included), the arguments of a process that the environment said is a proxy.
    /// The version is judged before the rest: another version may lay its tail out differently.
    pub(crate) fn parse(argv: &[OsString]) -> Result<ProxyArgs, ProxyArgsError> {
        let Some(version) = argv.get(1) else {
            return Err(ProxyArgsError::WrongArgumentCount);
        };
        match version.to_str().and_then(|v| decimal::<u32>(v.as_bytes())) {
            Some(VERSION) => {}
            Some(theirs) => return Err(ProxyArgsError::VersionMismatch { ours: VERSION, theirs }),
            None => return Err(ProxyArgsError::BadVersion),
        }
        let [_exe, _version, target, target_key, event, caller] = argv else {
            return Err(ProxyArgsError::WrongArgumentCount);
        };
        let number = |a: &OsString| {
            a.to_str()
                .and_then(|a| decimal::<u64>(a.as_bytes()))
                .ok_or(ProxyArgsError::BadNumber)
        };
        let pid = |a: &OsString| u32::try_from(number(a)?).map_err(|_| ProxyArgsError::BadNumber);
        let event = event
            .to_str()
            .and_then(CtrlEvent::from_token)
            .ok_or(ProxyArgsError::BadEvent)?;
        Ok(ProxyArgs {
            target: pid(target)?,
            target_key: number(target_key)?,
            event,
            caller: pid(caller)?,
        })
    }
}

/// What the proxy exits with. Each code is an answer; 0 is not one. The codes are 150 to 159: the
/// elevation shim's are 112 to 125, and the shim is a role of the same program, so a code read from
/// either never means the other.
///
/// `Sent` and `Unconfirmed` say whether the generated event arrived: the first says it did, the second
/// that it may have.
///
/// A proxy that fails a step before it generates the event, or cannot read its target, exits with a
/// [`Cause`] instead of an answer: the caller's error says which call failed and with which Win32 error
/// ([`ProxyExit`]). Nothing was sent then, but for the wait after the generate
/// ([`Step::WaitForOwnCopy`]), which means what `Unconfirmed` means. 156 and 160 are left unused: a caller
/// reads them as no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyAnswer {
    /// The event was generated on the target's console and the proxy saw its own copy of it.
    Sent = 150,
    /// The arguments are not a valid invocation.
    Usage = 151,
    /// The caller speaks another protocol version.
    VersionMismatch = 152,
    /// No process has the target's identity: its pid is held by no process, or by another one.
    TargetGone = 153,
    /// The target has no console to attach to, or has not set it up yet.
    TargetHasNoConsole = 154,
    /// The target's console is one the caller is attached to: nothing was sent.
    ConsoleIsCallers = 155,
    /// The OS refused the attach for a reason other than "no console" or "no such process": an
    /// exited process whose handle is still held answers this.
    AttachDenied = 157,
    /// The event was generated, and the proxy did not see its own copy of it: the console closed. The
    /// target may have received it. A wait that failed is the cause [`Step::WaitForOwnCopy`] instead.
    Unconfirmed = 158,
    /// This platform has no proxy.
    NoProxyHere = 159,
}

impl ProxyAnswer {
    pub(crate) const fn code(self) -> i32 {
        self as i32
    }

    #[cfg_attr(
        not(windows),
        allow(dead_code, reason = "only the Windows caller side reads a proxy's answer")
    )]
    pub(crate) fn from_code(code: i32) -> Option<ProxyAnswer> {
        [
            ProxyAnswer::Sent,
            ProxyAnswer::Usage,
            ProxyAnswer::VersionMismatch,
            ProxyAnswer::TargetGone,
            ProxyAnswer::TargetHasNoConsole,
            ProxyAnswer::ConsoleIsCallers,
            ProxyAnswer::AttachDenied,
            ProxyAnswer::Unconfirmed,
            ProxyAnswer::NoProxyHere,
        ]
        .into_iter()
        .find(|answer| answer.code() == code)
    }
}

/// The call that failed when the proxy sent nothing for a reason of its own, or, for
/// [`WaitForOwnCopy`](Step::WaitForOwnCopy), the one that failed after it generated the event.
#[cfg_attr(not(windows), allow(dead_code, reason = "only the Windows proxy fails a step"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// The target's identity record was refused (not a missing process).
    TargetIdentity = 1,
    /// The target could not be opened, or its identity could not be read to check it.
    OpenTarget = 2,
    /// `FreeConsole` before the attach.
    FreeConsole = 3,
    /// `AttachConsole`, refused for a reason that is none of "no console", "denied" or "no such process".
    AttachConsole = 4,
    /// `SetConsoleCtrlHandler(NULL, FALSE)`, which re-enables Ctrl+C.
    ReenableCtrlC = 5,
    /// `GetConsoleProcessList`.
    ConsoleProcessList = 6,
    /// `CreateEventW`, for either of the two events the handler routine signals.
    CreateEvent = 7,
    /// `SetConsoleCtrlHandler`, installing the handler routine.
    InstallHandler = 8,
    /// `ResetEvent`, before the generate.
    ResetEvent = 9,
    /// The console was already closing before the generate. There is no OS code.
    ConsoleClosing = 10,
    /// `GenerateConsoleCtrlEvent`.
    Generate = 11,
    /// `WaitForMultipleObjects`, for the proxy's own copy of the event, after the generate succeeded: the
    /// event was generated, and whether the target received it is unknown.
    WaitForOwnCopy = 12,
}

#[cfg_attr(not(windows), allow(dead_code, reason = "only the Windows proxy fails a step"))]
impl Step {
    /// Every step, in the order of its number.
    pub(crate) const ALL: [Step; 12] = [
        Step::TargetIdentity,
        Step::OpenTarget,
        Step::FreeConsole,
        Step::AttachConsole,
        Step::ReenableCtrlC,
        Step::ConsoleProcessList,
        Step::CreateEvent,
        Step::InstallHandler,
        Step::ResetEvent,
        Step::ConsoleClosing,
        Step::Generate,
        Step::WaitForOwnCopy,
    ];

    /// The step in words, as an error says where the proxy failed.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Step::TargetIdentity => "reading the target's identity record",
            Step::OpenTarget => "opening the target or reading its identity",
            Step::FreeConsole => "FreeConsole before the attach",
            Step::AttachConsole => "AttachConsole",
            Step::ReenableCtrlC => "SetConsoleCtrlHandler, re-enabling Ctrl+C",
            Step::ConsoleProcessList => "GetConsoleProcessList",
            Step::CreateEvent => "CreateEventW",
            Step::InstallHandler => "SetConsoleCtrlHandler, installing the handler routine",
            Step::ResetEvent => "ResetEvent",
            Step::ConsoleClosing => "the generate, which found the console closing",
            Step::Generate => "GenerateConsoleCtrlEvent",
            Step::WaitForOwnCopy => "WaitForMultipleObjects for the proxy's own copy, after the generate",
        }
    }

    /// Whether the event had been generated when this step failed: only the wait after the generate.
    pub(crate) fn event_generated(self) -> bool {
        match self {
            Step::TargetIdentity
            | Step::OpenTarget
            | Step::FreeConsole
            | Step::AttachConsole
            | Step::ReenableCtrlC
            | Step::ConsoleProcessList
            | Step::CreateEvent
            | Step::InstallHandler
            | Step::ResetEvent
            | Step::ConsoleClosing
            | Step::Generate => false,
            Step::WaitForOwnCopy => true,
        }
    }

    fn from_number(number: i32) -> Option<Step> {
        Step::ALL.into_iter().find(|step| *step as i32 == number)
    }
}

/// Why a step of the proxy failed: the step, and the Win32 error code when the failure has one that fits 16
/// bits and is not 0 (0 is no code).
///
/// It travels in the proxy's exit code ([`Cause::code`]), the one channel no other process can hold open,
/// and is for cosca's own decoder only: its layout is not a contract of a program that is not cosca's
/// proxy.
///
/// ```text
/// bit 31, 30     clear: a positive i32, and no NTSTATUS or crash status
/// bit 29         set: the customer bit, which no system exit status sets
/// bits 28 to 24  clear
/// bits 23 to 17  the step's number, 1 to 12
/// bit 16         an OS code is present
/// bits 15 to 0   the Win32 code, 1 to 0xFFFF, or 0 when bit 16 is clear
/// ```
#[cfg_attr(not(windows), allow(dead_code, reason = "only the Windows proxy fails a step"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cause {
    pub(crate) step: Step,
    pub(crate) os_code: Option<NonZeroU16>,
}

const CAUSE_MARKER: i32 = 0x2000_0000;
const CAUSE_STRAY_BITS: i32 = 0xDF00_0000_u32 as i32;
const CAUSE_HAS_CODE: i32 = 0x1_0000;
const CAUSE_STEP_SHIFT: u32 = 17;
const CAUSE_STEP_MASK: i32 = 0x7F;
const CAUSE_CODE_MASK: i32 = 0xFFFF;

#[cfg_attr(not(windows), allow(dead_code, reason = "only the Windows proxy fails a step"))]
impl Cause {
    /// A failure of `step` whose error became an `io::Error` with the raw OS error `code`. The code travels
    /// when it is 1 to `0xFFFF`; any other value, 0 included, gives a cause with no code.
    pub(crate) fn new(step: Step, code: Option<i32>) -> Cause {
        Cause {
            step,
            os_code: code.and_then(|code| u16::try_from(code).ok()).and_then(NonZeroU16::new),
        }
    }

    /// The failure's Win32 error as an `io::Error` with that raw OS error, when the cause has a code.
    #[cfg(windows)]
    pub(crate) fn os_error(self) -> Option<std::io::Error> {
        self.os_code
            .map(|code| std::io::Error::from_raw_os_error(i32::from(code.get())))
    }

    /// The error-text clause for a cause with no Win32 code; empty when it has one.
    #[cfg(windows)]
    pub(crate) fn no_code_clause(self) -> &'static str {
        if self.os_code.is_some() {
            ""
        } else {
            ", with no Win32 code the exit code can carry"
        }
    }

    /// The exit code the proxy ends with: one encoding per cause.
    pub(crate) fn code(self) -> i32 {
        CAUSE_MARKER
            | (self.step as i32) << CAUSE_STEP_SHIFT
            | self.os_code.map_or(0, |code| CAUSE_HAS_CODE | i32::from(code.get()))
    }

    /// The cause `code` encodes; `None` for any value that [`code`](Cause::code) does not produce.
    pub(crate) fn from_code(code: i32) -> Option<Cause> {
        if code & CAUSE_MARKER == 0 || code & CAUSE_STRAY_BITS != 0 {
            return None;
        }
        let step = Step::from_number((code >> CAUSE_STEP_SHIFT) & CAUSE_STEP_MASK)?;
        let raw = code & CAUSE_CODE_MASK;
        // A code of 0 is no code, so a flagged 0 is no cause either: one spelling each.
        let os_code = match (code & CAUSE_HAS_CODE != 0, raw) {
            (true, raw) => Some(NonZeroU16::new(raw as u16)?),
            (false, 0) => None,
            (false, _) => return None,
        };
        Some(Cause { step, os_code })
    }
}

/// An exit code as a message says it. Answers print in decimal. Anything at or above the cause marker (as
/// `u32`: a cause, a malformed one, an `NTSTATUS`) is a bit pattern and prints in hex; smaller codes stay
/// decimal.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only the Windows proxy and its caller print an exit")
)]
pub(crate) fn exit_text(code: i32) -> String {
    if code as u32 >= CAUSE_MARKER as u32 {
        format!("{code:#x}")
    } else {
        code.to_string()
    }
}

/// What the proxy exits with: an answer, or the [`Cause`] of a step that failed. Each value has one
/// exit code, and each exit code of the protocol one value.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only the Windows caller side reads a proxy's exit")
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyExit {
    Answer(ProxyAnswer),
    Cause(Cause),
}

impl From<ProxyAnswer> for ProxyExit {
    fn from(answer: ProxyAnswer) -> ProxyExit {
        ProxyExit::Answer(answer)
    }
}

impl From<Cause> for ProxyExit {
    fn from(cause: Cause) -> ProxyExit {
        ProxyExit::Cause(cause)
    }
}

#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only the Windows caller side reads a proxy's exit")
)]
impl ProxyExit {
    pub(crate) fn code(self) -> i32 {
        match self {
            ProxyExit::Answer(answer) => answer.code(),
            ProxyExit::Cause(cause) => cause.code(),
        }
    }

    /// The exit `code` is: an answer's code or a cause's; `None` for any other.
    pub(crate) fn from_code(code: i32) -> Option<ProxyExit> {
        ProxyAnswer::from_code(code)
            .map(ProxyExit::Answer)
            .or_else(|| Cause::from_code(code).map(ProxyExit::Cause))
    }

    /// The line the proxy writes to its stderr for this exit: `None` for `Sent`, which has nothing to say.
    #[cfg(windows)]
    pub(crate) fn stderr_line(self) -> Option<String> {
        match self {
            ProxyExit::Answer(ProxyAnswer::Sent) => None,
            ProxyExit::Answer(answer) => Some(format!("answering {answer:?} (exit {})", exit_text(self.code()))),
            ProxyExit::Cause(cause) => Some(format!(
                "failed a step, {}: {cause:?} (exit {})",
                if cause.step.event_generated() {
                    "the event was generated"
                } else {
                    "nothing sent"
                },
                exit_text(self.code())
            )),
        }
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod protocol_tests;
