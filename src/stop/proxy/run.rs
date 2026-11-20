//! The proxy's own sequence (Windows): attach to the target's console, send the event to that whole
//! console, and answer. The order of the calls is the measured one: a call moved, added or dropped
//! is a different measurement.
//!
//! 1. Open the target by its identity (pid and key; [`Process::open`]) and hold the handle until the
//!    process ends, which pins the pid: a pid the caller read and that was reissued since is
//!    [`ProxyAnswer::TargetGone`], one that cannot be opened or read to check fails the step
//!    [`Step::OpenTarget`].
//! 2. `FreeConsole`, for a proxy that was started with a console: a process attached to one cannot
//!    attach to another.
//! 3. `AttachConsole(target)`. A refusal is answered by its error ([`answer_for_failed_attach`]); one with no
//!    answer fails the step [`Step::AttachConsole`].
//! 4. A handler routine, installed first after the attach, so that a control event between the
//!    attach and the generate does not end the proxy by the default handler (this order ran green on
//!    both Windows CI lanes). It signals an event object when the requested event arrives, and
//!    answers every other control event as handled. For the console's close and shutdown it must
//!    not return (Windows ends the process then): it tells the main thread and blocks, and the main
//!    thread answers and exits. A logoff is handled and otherwise ignored, because Microsoft's
//!    documentation says it does not name the user who logs off and that services receive it, and
//!    the proxy's main use is in session 0 under a service; this follows the documentation and was
//!    not measured in a session-0 proxy.
//! 5. For Ctrl+C, `SetConsoleCtrlHandler(NULL, FALSE)`: a process that inherited "Ctrl+C is
//!    ignored" would never see its own copy of the event.
//! 6. The caller-console check: if the attached console's process list holds the caller, nothing is
//!    sent.
//! 7. The event object is reset, so a control event that arrived since step 4 is not taken for the
//!    proxy's own copy.
//! 8. `GenerateConsoleCtrlEvent(event, 0)`, which reaches every process on the console, this one
//!    included. A close seen before the call sends nothing ([`Step::ConsoleClosing`]); one that
//!    races the call is answered [`ProxyAnswer::Unconfirmed`] by the wait.
//! 9. A wait, with no cap, for the routine to see this process's own copy: only then has the console
//!    host handed the event out, so only then may the console be left. The wait also ends when the
//!    console closes. Measured on CI, on both Windows architectures, for both events, with one other
//!    process on a hidden console (`.tmp/claude/findings/2026-11-17-997-measure4.md`): the proxy saw
//!    its own copy and answered `Sent` in 2600 of 2600 runs, at the speed of the control (a handler that
//!    returns at once), while that process was in a handler that never returns (200 runs), had every
//!    thread suspended (200), was stopped under a debugger (400), or exited as the event was generated
//!    (1600). So another process on the console did not keep the proxy from seeing its own copy in
//!    those states. Not measured: a process frozen by a job or created suspended, a handler blocked in
//!    a close event, several such processes at once, a Windows Terminal console, a session-0 console.
//! 10. `FreeConsole`; the answer.
//!
//! Residual: a control event from another source while the proxy is attached can end it or be taken
//! for its own copy; the caller then gets no answer or an early one, never a false `Sent` for an
//! event that was not generated.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering};

use windows::core::{BOOL, HRESULT};
use windows::Win32::Foundation::{
    SetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, HANDLE, WAIT_EVENT, WAIT_FAILED,
    WAIT_OBJECT_0, WIN32_ERROR,
};
use windows::Win32::System::Console::{
    AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, GetConsoleProcessList, SetConsoleCtrlHandler,
    CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_SHUTDOWN_EVENT,
};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects, INFINITE};

use super::protocol::{Cause, CtrlEvent, ProxyAnswer, ProxyArgs, ProxyExit, Step};
use crate::error::{win32_io_error, Error, RecordErrorKind};
use crate::identity::{Platform, ProcessId, ProcessIdRecord, RECORD_VERSION};
use crate::process::Process;
use crate::role;

/// Runs the sequence for `args` and returns what the proxy exits with: its answer, and for a failed step
/// the [`Cause`] that carries the step and the Win32 error.
pub(crate) fn run(args: &ProxyArgs) -> ProxyExit {
    match send(args) {
        Ok(()) => ProxyAnswer::Sent.into(),
        Err(exit) => exit,
    }
}

fn send(args: &ProxyArgs) -> Result<(), ProxyExit> {
    let _target = open_target(args)?;
    // Fails with `ERROR_INVALID_HANDLE` for a process with no console, which is the usual proxy; any
    // other failure leaves the proxy attached, and the attach below would be refused for that.
    // SAFETY: no preconditions.
    if let Err(e) = unsafe { FreeConsole() } {
        if e.code() != HRESULT::from_win32(ERROR_INVALID_HANDLE.0) {
            return Err(failed(Step::FreeConsole, "FreeConsole before the attach", e).into());
        }
    }
    let _attached = Attached::attach(args.target)?;
    let event = match args.event {
        CtrlEvent::CtrlC => CTRL_C_EVENT,
        CtrlEvent::CtrlBreak => CTRL_BREAK_EVENT,
    };
    let watch = Watch::install(event)?;
    if args.event == CtrlEvent::CtrlC {
        // SAFETY: no preconditions.
        unsafe { SetConsoleCtrlHandler(None, false) }
            .map_err(|e| failed(Step::ReenableCtrlC, "re-enabling Ctrl+C", e))?;
    }
    let holds = console_holds(args.caller).map_err(|e| {
        role::line(
            role::PROXY,
            format_args!("reading the console's process list failed: {e}"),
        );
        Cause::new(Step::ConsoleProcessList, e.raw_os_error())
    })?;
    if holds {
        return Err(ProxyAnswer::ConsoleIsCallers.into());
    }
    watch.generate(event)?;
    Ok(watch.wait()?)
}

/// The cause of a failed `what`, a call of `step`: says so on standard error and carries the Win32 code of `e`.
/// Every site whose failure is a `windows::core::Error` builds its cause here, so the code is the `io::Error` one
/// ([`win32_io_error`]) and never the raw HRESULT, which no 16-bit code could hold.
fn failed(step: Step, what: impl std::fmt::Display, e: windows::core::Error) -> Cause {
    role::line(role::PROXY, format_args!("{what} failed: {e}"));
    Cause::new(step, win32_io_error(e).raw_os_error())
}

/// Opens the process `args` names by its identity and holds it, so its pid stays its own.
fn open_target(args: &ProxyArgs) -> Result<Process, ProxyExit> {
    let record = ProcessIdRecord {
        version: RECORD_VERSION,
        platform: Platform::Windows,
        pid: args.target,
        token: args.target_key,
        boot_id: None,
        pid_ns: None,
        token_kind: None,
    };
    let id = match ProcessId::try_from(&record) {
        Ok(id) => id,
        // Pid 0 names no process.
        Err(Error::IdentityRecord {
            kind: RecordErrorKind::InvalidPid,
            ..
        }) => return Err(ProxyAnswer::TargetGone.into()),
        Err(e) => {
            debug_assert!(
                false,
                "a Windows record of this version is refused only for its pid: {e}"
            );
            role::line(role::PROXY, format_args!("the target's identity is refused: {e}"));
            return Err(Cause::new(Step::TargetIdentity, crate::error::first_os_code(&e)).into());
        }
    };
    match Process::open(id) {
        Ok(Some(target)) => Ok(target),
        Ok(None) => Err(ProxyAnswer::TargetGone.into()),
        Err(e) => {
            role::line(
                role::PROXY,
                format_args!(
                    "the target cannot be opened or its identity read: {}",
                    crate::error::Report(&e)
                ),
            );
            Err(Cause::new(Step::OpenTarget, crate::error::first_os_code(&e)).into())
        }
    }
}

/// The answer to a refused `AttachConsole`, by its error. Measured: no console, a GUI program, a
/// `DETACHED_PROCESS` child and a child that has not set its console up yet are 6; an exited process
/// whose handle is still held is 5; a pid no process has is 87. Any other error is a refusal that
/// sent nothing, which has no answer (`None`): it fails a step.
pub(super) fn answer_for_failed_attach(code: HRESULT) -> Option<ProxyAnswer> {
    if code == HRESULT::from_win32(ERROR_INVALID_HANDLE.0) {
        Some(ProxyAnswer::TargetHasNoConsole)
    } else if code == HRESULT::from_win32(ERROR_ACCESS_DENIED.0) {
        Some(ProxyAnswer::AttachDenied)
    } else if code == HRESULT::from_win32(ERROR_INVALID_PARAMETER.0) {
        Some(ProxyAnswer::TargetGone)
    } else {
        None
    }
}

/// This process's attachment to the target's console, until dropped.
struct Attached;

impl Attached {
    /// Attaches once: a second try would race the target's own console setup, and the answer is
    /// the caller's to act on.
    fn attach(target: u32) -> Result<Attached, ProxyExit> {
        // SAFETY: no preconditions.
        match unsafe { AttachConsole(target) } {
            Ok(()) => Ok(Attached),
            Err(e) => match answer_for_failed_attach(e.code()) {
                Some(answer) => Err(answer.into()),
                None => Err(failed(Step::AttachConsole, format_args!("AttachConsole({target})"), e).into()),
            },
        }
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        // SAFETY: no preconditions. A failure leaves nothing to do but say so: the process exits next.
        if let Err(e) = unsafe { FreeConsole() } {
            role::line(role::PROXY, format_args!("FreeConsole after the answer failed: {e}"));
        }
    }
}

/// Whether the attached console's process list holds `pid`. An error: the list cannot be read (the
/// call answers 0, though this process is on the console it attached to).
pub(crate) fn console_holds(pid: u32) -> std::io::Result<bool> {
    // Grown to the count the API reports: a buffer too small gets the required count back unfilled.
    let mut list = vec![0u32; 16];
    loop {
        // SAFETY: `list` is a valid writable slice. The last error is cleared first, so that a zero
        // return reads the code of this call and never one an earlier call left.
        let n = unsafe {
            SetLastError(WIN32_ERROR(0));
            GetConsoleProcessList(&mut list)
        } as usize;
        if n == 0 {
            let e = std::io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(0) {
                std::io::Error::other("GetConsoleProcessList returned no list and set no error")
            } else {
                e
            });
        }
        if n <= list.len() {
            return Ok(list[..n].contains(&pid));
        }
        list.resize(n, 0);
    }
}

/// Raw handle of the event the routine signals for the wanted event (0: none yet).
static OWN_COPY: AtomicIsize = AtomicIsize::new(0);
/// The event the routine signals for.
static WANTED: AtomicU32 = AtomicU32::new(u32::MAX);
/// Raw handle of the event it signals when the console closes (0: none yet).
static CLOSING_EVENT: AtomicIsize = AtomicIsize::new(0);
/// Whether the console is closing: the routine saw `CTRL_CLOSE_EVENT` or `CTRL_SHUTDOWN_EVENT`.
static CLOSING: AtomicBool = AtomicBool::new(false);

fn signal(handle: &AtomicIsize) {
    let handle = handle.load(Ordering::Acquire);
    if handle != 0 {
        // SAFETY: the handle is an event [`Watch::install`] made.
        if let Err(e) = unsafe { SetEvent(HANDLE(handle as *mut c_void)) } {
            role::line(role::PROXY, format_args!("SetEvent in the handler routine failed: {e}"));
        }
    }
}

/// Handles every event, so none ends the proxy before it has answered, and signals [`OWN_COPY`] for
/// the wanted one. Runs on a thread the OS creates, and must not unwind.
///
/// For the console's close and shutdown it does not return: Windows ends the process when a routine
/// returns for these. It tells the main thread through [`CLOSING_EVENT`] and blocks, and the main
/// thread answers and exits the process. A logoff is handled and nothing more: it does not say which
/// user logs off, and a service proxy receives every user's.
unsafe extern "system" fn routine(event: u32) -> BOOL {
    if matches!(event, CTRL_CLOSE_EVENT | CTRL_SHUTDOWN_EVENT) {
        CLOSING.store(true, Ordering::Release);
        signal(&CLOSING_EVENT);
        loop {
            std::thread::park();
        }
    }
    if event == WANTED.load(Ordering::Acquire) {
        signal(&OWN_COPY);
    }
    BOOL(1)
}

/// The proxy's watch for its own copy of the event it sends, and for the console closing. Its event
/// objects are never closed: the process exits next, and a routine thread may still be about to
/// signal them.
struct Watch {
    own_copy: HANDLE,
    closing: HANDLE,
}

impl Watch {
    /// Installs [`routine`], signalling for `event`. One per process: the routine's state is static.
    fn install(event: u32) -> Result<Watch, ProxyExit> {
        debug_assert_eq!(OWN_COPY.load(Ordering::Relaxed), 0, "the proxy watches once");
        // SAFETY: no preconditions. Manual reset, so an event that arrives before the wait is not lost.
        let make = || {
            unsafe { CreateEventW(None, true, false, None) }.map_err(|e| failed(Step::CreateEvent, "CreateEventW", e))
        };
        let (own_copy, closing) = (make()?, make()?);
        WANTED.store(event, Ordering::Release);
        OWN_COPY.store(own_copy.0 as isize, Ordering::Release);
        CLOSING_EVENT.store(closing.0 as isize, Ordering::Release);
        // SAFETY: `routine` is an `extern "system"` handler that never unwinds.
        unsafe { SetConsoleCtrlHandler(Some(routine), true) }
            .map_err(|e| failed(Step::InstallHandler, "installing the handler routine", e))?;
        Ok(Watch { own_copy, closing })
    }

    /// Generates `event` on the attached console, every process on it included. A close the routine
    /// saw before the call sends nothing ([`Step::ConsoleClosing`]); one that arrives between
    /// the check and the call is let through, and [`wait`](Self::wait) answers it `Unconfirmed`. A
    /// failed call generated nothing.
    fn generate(&self, event: u32) -> Result<(), ProxyExit> {
        // SAFETY: `self.own_copy` is the live event `install` made. Reset: a control event that
        // arrived since the routine was installed must not pass for the proxy's own copy.
        unsafe { ResetEvent(self.own_copy) }.map_err(|e| failed(Step::ResetEvent, "ResetEvent", e))?;
        if CLOSING.load(Ordering::Acquire) {
            return Err(Cause::new(Step::ConsoleClosing, None).into());
        }
        // SAFETY: no preconditions; group 0 is every process on the attached console.
        unsafe { GenerateConsoleCtrlEvent(event, 0) }
            .map_err(|e| failed(Step::Generate, "GenerateConsoleCtrlEvent", e).into())
    }

    /// Waits, with no cap, until the routine has seen the event it was installed for (`Ok`). The
    /// console closing, or a failed wait, is `Unconfirmed`: the event was generated.
    fn wait(&self) -> Result<(), ProxyAnswer> {
        // The own copy is first, so it wins when both are signalled.
        // SAFETY: both are live events `install` made.
        let waited = unsafe { WaitForMultipleObjects(&[self.own_copy, self.closing], false, INFINITE) };
        match waited {
            WAIT_OBJECT_0 => Ok(()),
            w if w == WAIT_EVENT(WAIT_OBJECT_0.0 + 1) => Err(ProxyAnswer::Unconfirmed),
            WAIT_FAILED => {
                role::line(
                    role::PROXY,
                    format_args!("WaitForMultipleObjects failed: {}", std::io::Error::last_os_error()),
                );
                Err(ProxyAnswer::Unconfirmed)
            }
            // Two manual-reset events and no timeout: nothing else is a result of this wait.
            other => {
                debug_assert!(false, "WaitForMultipleObjects returned {other:?}");
                role::line(role::PROXY, format_args!("WaitForMultipleObjects returned {other:?}"));
                Err(ProxyAnswer::Unconfirmed)
            }
        }
    }
}

#[cfg(test)]
#[path = "run_tests.rs"]
mod run_tests;
