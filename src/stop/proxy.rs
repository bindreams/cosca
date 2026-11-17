//! The console-event proxy: a role of the host program (`cosca::init()`) or of the
//! `cosca-ctrl-proxy` executable. It attaches to a child's console, sends Ctrl+C or Ctrl+Break to
//! that whole console, and answers by exit code.
//!
//! [`protocol`] is the argv a caller starts it with and the exit codes it answers with; [`run`] is
//! its own sequence; the rest of this file is the caller's side (Windows): the program a stop starts
//! ([`CtrlProxy`]), and [`send`], which starts it, waits for its answer and maps the answer to the stop's
//! result.

pub(crate) mod protocol;
#[cfg(windows)]
pub(crate) mod run;

#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use protocol::{CtrlEvent, ProxyAnswer, ProxyArgs, VERSION};

#[cfg(windows)]
use super::{conclude, refuse, unsupported, StopTarget, ELEVATED_REFUSAL};
#[cfg(windows)]
use crate::containment::SendOutcome;
#[cfg(windows)]
use crate::error::Error;
#[cfg(windows)]
use crate::identity::ProcessId;

/// Which program a stop starts as the console-event proxy
/// ([`stop::send_console_event_via_proxy`](crate::stop::send_console_event_via_proxy)), as
/// [`Command::ctrl_proxy`](crate::Command::ctrl_proxy) sets it.
///
/// The proxy needs no console of its own, and attaches to the child's. It is cosca's own code, started
/// from a program that carries it: the host program, which plays the role when it is started with the
/// proxy's arguments, or the `cosca-ctrl-proxy` executable.
#[cfg(windows)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CtrlProxy {
    /// The file at the host program's path ([`std::env::current_exe`]) when the stop runs, started as the
    /// proxy. The host must have called [`cosca::init()`](crate::init) first thing in `main`: the copy
    /// then plays the proxy and exits instead of running the host's own `main`. A host that has not
    /// called `init` is refused, with nothing started ([`installed`](crate::installed) says whether it
    /// has). So cosca never starts a second copy of a program that would run as itself, while the file at
    /// that path is the one this process was loaded from: a program that replaces its own image while
    /// it runs sets [`Executable`](CtrlProxy::Executable).
    #[default]
    HostExecutable,
    /// This file, which is the `cosca-ctrl-proxy` executable (`cargo install cosca --bin
    /// cosca-ctrl-proxy`) or another program that calls `cosca::init()` first thing in `main`. It is
    /// loaded exactly as written, as [`Command::raw_executable`](crate::Command::raw_executable) does:
    /// no `PATH` search and no `.exe` appended, and a relative path is read against this process's
    /// working directory.
    Executable(PathBuf),
}

/// The warning for a proxy that has not answered after `after`.
#[cfg(windows)]
fn warn_still_waiting(proxy: Option<u32>, child: u32, event: CtrlEvent, after: Duration) {
    log::warn!(
        "the console-event proxy (pid {}) for child {child} has not answered {after:?} after it was started; \
         still waiting for it to send {}",
        proxy.map_or_else(|| "unknown".to_owned(), |pid| pid.to_string()),
        event.name()
    );
}

#[cfg(windows)]
const NO_IDENTITY_REFUSAL: &str = "this child has no identity (Child::id() is None), and the proxy names its \
     target by identity, so that a pid the system has reused is never sent an event: it cannot be named \
     exactly. Use Child::kill for a hard teardown, or Command::graceful_stop with a stop of your own.";

#[cfg(windows)]
const NOT_INSTALLED_REFUSAL: &str = "CtrlProxy::HostExecutable starts a copy of this program as the proxy, and \
     this program has not called cosca::init(), so a copy would run as itself. Call cosca::init() first \
     thing in main, or set Command::ctrl_proxy(CtrlProxy::Executable(..)) to the cosca-ctrl-proxy executable.";

/// The remedies a refusal that leaves the child running names, in this order.
#[cfg(windows)]
const REMEDIES: &str = "Use Child::kill for a hard teardown, or Command::graceful_stop with a stop of your own.";

/// The possible causes of the answer `TargetHasNoConsole`, which cosca cannot tell apart.
#[cfg(windows)]
const NO_CONSOLE_CAUSES: &str =
    "The child may have no console (it was created without one, or gave it up), or may not \
     have started running yet: a child that was just created looks like one without a console until it has \
     set its own up.";

/// The possible cause of the answers `AttachDenied` and `TargetGone` for a child that has not exited.
#[cfg(windows)]
const ATTACH_DENIED_CAUSE: &str = "The child may still be running, on a console that refused the proxy.";

/// The proxy's send, as [`send_console_event_via_proxy`](crate::stop::send_console_event_via_proxy)
/// documents it.
#[cfg(windows)]
pub(crate) fn send(target: &StopTarget<'_>, event: CtrlEvent) -> Result<(), Error> {
    let console = target.child().console;
    if console.elevated {
        return Err(refuse(target, ELEVATED_REFUSAL));
    }
    let Some(id) = target.id() else {
        return Err(refuse(target, NO_IDENTITY_REFUSAL));
    };
    let exe = match target.ctrl_proxy() {
        CtrlProxy::HostExecutable if !crate::installed() => return Err(refuse(target, NOT_INSTALLED_REFUSAL)),
        CtrlProxy::HostExecutable => match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => return conclude(target, event, exe_unreadable(e)),
        },
        CtrlProxy::Executable(exe) => exe.clone(),
    };
    conclude(target, event, ask(target, event, &id, &exe))
}

/// Starts `exe` as the proxy for `event` to the console of the child `id` names, waits for its
/// answer, and returns what it came to.
#[cfg(windows)]
fn ask(target: &StopTarget<'_>, event: CtrlEvent, id: &ProcessId, exe: &Path) -> SendOutcome {
    let record = match id.to_record() {
        Ok(record) => record,
        Err(e) => return SendOutcome::NotSent(e),
    };
    debug_assert_eq!(record.pid, target.pid(), "the child's identity names the child");
    let args = ProxyArgs {
        target: record.pid,
        target_key: record.token,
        event,
        caller: std::process::id(),
    };
    // The target borrows the child, which holds its process handle: the pid stays this child's until
    // the call returns, whatever the child does.
    let proxy = match start(exe, &args) {
        Ok(proxy) => proxy,
        Err(e) => return start_failed(exe, e),
    };
    let proxy_pid = proxy.pid();
    let status = match proxy.wait_saying(crate::wait::teardown_warn::LATE, |after| {
        warn_still_waiting(Some(proxy_pid), record.pid, event, after)
    }) {
        Ok(status) => status,
        Err(e) => return wait_failed(proxy_pid, event, e),
    };
    let Some(code) = status.code() else {
        return SendOutcome::Sent(Err(Error::Unassessable {
            detail: format!(
                "the console-event proxy (pid {proxy_pid}) ended without an exit code ({status}), so whether {} \
                 was sent is unknown",
                event.name()
            ),
            source: None,
        }));
    };
    let Some(answer) = ProxyAnswer::from_code(code) else {
        return SendOutcome::Sent(Err(Error::Unassessable {
            detail: format!(
                "the console-event proxy {} (pid {proxy_pid}) exited with code {code}, which is no answer of its \
                 protocol, so whether {} was sent is unknown",
                exe.display(),
                event.name()
            ),
            source: None,
        }));
    };
    #[cfg(test)]
    crate::containment::windows::observe::record_ctrl_send(crate::containment::windows::observe::CtrlSend::Proxy {
        target: record.pid,
        event,
        answer,
    });
    result_of(target, event, exe, answer)
}

/// Starts `exe` as the proxy for `args`: uncontained, with no console of its own (a process attached to
/// one cannot attach to another), and null standard streams.
#[cfg(windows)]
fn start(exe: &Path, args: &ProxyArgs) -> Result<crate::Child, Error> {
    let mut command = crate::Command::new();
    command.raw_executable(exe).args(args.to_argv(exe.as_os_str()));
    command.detached();
    command
        .stdin(crate::Stdio::null())?
        .stdout(crate::Stdio::null())?
        .stderr(crate::Stdio::null())?;
    command.spawn()
}

/// This program's own path cannot be read, to start it as the proxy.
#[cfg(windows)]
fn exe_unreadable(e: std::io::Error) -> SendOutcome {
    SendOutcome::NotSent(Error::Io(crate::error::io_context(
        "nothing was sent: this program's own path cannot be read, to start it as the proxy",
        e,
    )))
}

/// The proxy could not be started, as `e` says. A proxy that may have started may have sent, so its error
/// keeps that meaning.
#[cfg(windows)]
fn start_failed(exe: &Path, e: Error) -> SendOutcome {
    match e {
        may_have_started @ Error::MayHaveStarted { .. } => SendOutcome::Sent(Err(may_have_started)),
        not_started => SendOutcome::NotSent(not_started.in_step(&format!(
            "nothing was sent: the console-event proxy {} could not be started",
            exe.display()
        ))),
    }
}

/// The wait for the proxy `proxy_pid` failed, as `e` says. The proxy's [`Child`](crate::Child) is dropped
/// with the failure, which kills it.
#[cfg(windows)]
fn wait_failed(proxy_pid: u32, event: CtrlEvent, e: Error) -> SendOutcome {
    SendOutcome::Sent(Err(Error::Unassessable {
        detail: format!(
            "the wait for the console-event proxy (pid {proxy_pid}) failed, so whether {} was sent is \
             unknown; cosca ended the proxy when the wait failed",
            event.name()
        ),
        source: Some(Arc::new(e)),
    }))
}

/// What the proxy's `answer` came to as the stop's send.
#[cfg(windows)]
fn result_of(target: &StopTarget<'_>, event: CtrlEvent, exe: &Path, answer: ProxyAnswer) -> SendOutcome {
    let code = answer.code();
    let sent = event.name();
    // The attach did not succeed, and the child had not exited when cosca looked: the child's own exit
    // is the one thing the proxy's answer cannot say.
    let attach_refused = |cause: &str| {
        SendOutcome::NotSent(unsupported(format!(
            "the console-event proxy's attach to the child's console did not succeed (answer {answer:?}, exit \
             {code}), and the child had not exited when cosca looked, so nothing was sent. {cause} {REMEDIES}"
        )))
    };
    let not_sent = |error: Error| SendOutcome::NotSent(error);
    match answer {
        ProxyAnswer::Sent => SendOutcome::Sent(Ok(())),
        ProxyAnswer::TargetGone | ProxyAnswer::AttachDenied | ProxyAnswer::TargetHasNoConsole => {
            match target.wait_exit(Duration::ZERO) {
                Err(look_failed) => not_sent(look_failed),
                Ok(true) => SendOutcome::RootExited(Error::Unassessable {
                    detail: format!(
                        "the console-event proxy's attach to the console of the child (pid {}) did not succeed \
                         (answer {answer:?}, exit {code}), and the child had exited when cosca looked: nothing \
                         was sent, and the proxy cannot reach a member of its tree that outlived it",
                        target.pid()
                    ),
                    source: None,
                }),
                Ok(false) => attach_refused(match answer {
                    ProxyAnswer::TargetHasNoConsole => NO_CONSOLE_CAUSES,
                    _ => ATTACH_DENIED_CAUSE,
                }),
            }
        }
        ProxyAnswer::ConsoleIsCallers => not_sent(unsupported(format!(
            "the child's console is this process's own, so an event sent there would reach this process and \
             everything attached to it as well: nothing was sent. {}",
            if target.child().console.group {
                "The child leads a console process group: send it Ctrl+Break with stop::send_ctrl_break_to_group."
            } else {
                "Create it with Command::new_process_group(true), and send it Ctrl+Break with \
                 stop::send_ctrl_break_to_group."
            }
        ))),
        ProxyAnswer::VersionMismatch | ProxyAnswer::Usage => not_sent(unsupported(format!(
            "the program started as the console-event proxy ({}) did not accept this cosca's invocation \
             (answer {answer:?}, exit {code}); this cosca speaks proxy protocol version {VERSION}, so \
             nothing was sent. Start a proxy built from the same cosca: CtrlProxy::HostExecutable, or the \
             cosca-ctrl-proxy executable that belongs to it.",
            exe.display()
        ))),
        ProxyAnswer::NoProxyHere => not_sent(unsupported(format!(
            "the program started as the console-event proxy ({}) has no proxy here (answer {answer:?}, \
             exit {code}), so nothing was sent",
            exe.display()
        ))),
        // `io::ErrorKind::Other`: the proxy names no OS error of its own, and its reason is not available.
        ProxyAnswer::NothingSent | ProxyAnswer::TargetUnreadable => {
            not_sent(Error::Io(std::io::Error::other(format!(
                "nothing was sent: the console-event proxy answered {answer:?} (exit {code}), so no {sent} was \
             sent; the proxy's own reason is not available"
            ))))
        }
        ProxyAnswer::Unconfirmed => SendOutcome::Sent(Err(Error::Unassessable {
            detail: format!(
                "the console-event proxy generated the {sent} and did not see its own copy of it (answer \
                 {answer:?}, exit {code}), so whether the child received it is unknown"
            ),
            source: None,
        })),
    }
}

#[cfg(all(test, windows))]
#[path = "proxy_tests.rs"]
mod proxy_tests;

#[cfg(all(test, windows))]
#[path = "proxy_real_tests.rs"]
mod proxy_real_tests;
