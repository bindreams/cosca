//! The console-event proxy's wire format: its argv and its exit codes. Pure: no I/O, no system
//! calls.
//!
//! Every value has exactly one encoding, so a decoder never accepts two spellings of one thing.

use std::ffi::{OsStr, OsString};

use crate::role::decimal;

/// The protocol version this cosca speaks.
pub(crate) const VERSION: u32 = 1;

/// What `argv[1]` of a proxy invocation starts with, whatever the version.
const FLAG_PREFIX: &str = "--cosca-ctrl-proxy";

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

/// Why argv is not a valid proxy invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProxyArgsError {
    #[error("the caller speaks protocol version {theirs}, this proxy {ours}")]
    VersionMismatch { ours: u32, theirs: u32 },
    #[error("the flag is not `{FLAG_PREFIX}=<version>`")]
    BadFlag,
    #[error("expected a target pid, its key, an event and a caller pid after the flag")]
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
    /// The full argv, `argv[0]` included: `[exe, "--cosca-ctrl-proxy=1", target, target_key, "c" |
    /// "break", caller]`.
    #[cfg_attr(
        not(windows),
        allow(dead_code, reason = "only the Windows caller side starts a proxy")
    )]
    pub(crate) fn to_argv(self, exe: &OsStr) -> Vec<OsString> {
        vec![
            exe.to_owned(),
            format!("{FLAG_PREFIX}={VERSION}").into(),
            self.target.to_string().into(),
            self.target_key.to_string().into(),
            self.event.token().into(),
            self.caller.to_string().into(),
        ]
    }

    /// `Ok(None)` when `argv` is not a proxy invocation at all (`argv[1]` does not start with the
    /// flag); an error when it claims to be one and is not valid. `argv` includes `argv[0]`.
    pub(crate) fn parse(argv: &[OsString]) -> Result<Option<ProxyArgs>, ProxyArgsError> {
        let Some(flag) = argv.get(1) else { return Ok(None) };
        let flag = flag.to_string_lossy();
        let Some(version) = flag.strip_prefix(FLAG_PREFIX) else {
            return Ok(None);
        };
        // The version is judged before the rest: another version may lay its tail out differently.
        match version.strip_prefix('=').and_then(|v| decimal::<u32>(v.as_bytes())) {
            Some(VERSION) => {}
            Some(theirs) => return Err(ProxyArgsError::VersionMismatch { ours: VERSION, theirs }),
            None => return Err(ProxyArgsError::BadFlag),
        }
        let [_exe, _flag, target, target_key, event, caller] = argv else {
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
        Ok(Some(ProxyArgs {
            target: pid(target)?,
            target_key: number(target_key)?,
            event,
            caller: pid(caller)?,
        }))
    }
}

/// What the proxy exits with. Each code is an answer; 0 is not one. The codes are 150 to 160: the
/// elevation shim's are 112 to 125, and the shim is a role of the same program, so a code read from
/// either never means the other.
///
/// `Sent`, `NothingSent` and `Unconfirmed` say whether anything was generated: the first says it
/// was and arrived, the second that nothing was, the third that it may have been.
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
    /// A step failed before the event was generated (or the generating call failed): nothing was
    /// sent.
    NothingSent = 156,
    /// The OS refused the attach for a reason other than "no console" or "no such process": an
    /// exited process whose handle is still held answers this.
    AttachDenied = 157,
    /// The event was generated, and the proxy did not see its own copy of it: the wait failed or
    /// the console closed. The target may have received it.
    Unconfirmed = 158,
    /// This platform has no proxy.
    NoProxyHere = 159,
    /// The target exists, and the proxy could not open it or read its identity to check it: nothing
    /// was sent.
    TargetUnreadable = 160,
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
            ProxyAnswer::NothingSent,
            ProxyAnswer::AttachDenied,
            ProxyAnswer::Unconfirmed,
            ProxyAnswer::NoProxyHere,
            ProxyAnswer::TargetUnreadable,
        ]
        .into_iter()
        .find(|answer| answer.code() == code)
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod protocol_tests;
