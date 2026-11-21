//! The console-event proxy: a role of the host program (`cosca::init_helpers()`) or of the
//! `cosca-ctrl-proxy` executable, which a caller starts with the environment variable
//! [`HELPER_ENV`](crate::role::HELPER_ENV) set to `ctrl-proxy`. It attaches to a child's console, sends
//! Ctrl+C or Ctrl+Break to that whole console, and answers by exit code.
//!
//! [`protocol`] is the argv a caller starts it with and the exit codes it answers with; [`run`] is
//! its own sequence; the rest of this file is the caller's side (Windows): the program a stop starts
//! ([`CtrlProxy`]), and [`send`], which starts it, waits for its answer and maps the answer to the stop's
//! result. `send` is written once, over the `StopWaits` that start and wait for the proxy: the sync
//! stop blocks, the async stop awaits.

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
use protocol::{exit_text, Cause, CtrlEvent, ProxyAnswer, ProxyArgs, ProxyExit, VERSION};

#[cfg(windows)]
use super::{conclude, refuse, root_exited, unsupported, StopTarget, StopWaits, ELEVATED_REFUSAL, REMEDIES};
#[cfg(windows)]
use crate::containment::SendAnswer;
#[cfg(windows)]
use crate::error::Error;
#[cfg(windows)]
use crate::identity::ProcessId;

/// Which program a stop starts as the console-event proxy
/// ([`stop::send_console_event_via_proxy`](crate::stop::send_console_event_via_proxy)), as
/// [`Command::ctrl_proxy`](crate::Command::ctrl_proxy) sets it.
///
/// The proxy needs no console of its own, and attaches to the child's. It is cosca's own code, started
/// from a program that carries it: the host program, which plays the role when it is started with
/// `__COSCA_HELPER=ctrl-proxy`, or the `cosca-ctrl-proxy` executable.
#[cfg(windows)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CtrlProxy {
    /// The file at the host program's path ([`std::env::current_exe`]) when the stop runs, started as the
    /// proxy. The host must have called [`cosca::init_helpers()`](crate::init_helpers) first thing in
    /// `main`: the copy then plays the proxy and exits instead of running the host's own `main`. A host
    /// that has not called `init_helpers` panics in a stop that would start it as the proxy
    /// ([`stop::default`](crate::stop::default#panics)); [`helpers_initialized`](crate::helpers_initialized)
    /// says whether it has called it. So cosca never starts a second copy of a program that would run as
    /// itself, while the file at that path is the one this process was loaded from: a program that replaces
    /// its own image while it runs sets [`Executable`](CtrlProxy::Executable).
    #[default]
    HostExecutable,
    /// This file, which is the `cosca-ctrl-proxy` executable (`cargo install cosca --bin
    /// cosca-ctrl-proxy`) or another program that calls `cosca::init_helpers()` first thing in `main`. The
    /// host program itself needs no call. It is
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
const NO_IDENTITY_REASON: &str = "this child has no identity (Child::id() is None), and the proxy names its \
     target by identity, so that a pid the system has reused is never sent an event: it cannot be named \
     exactly.";

/// The remedy for a program that is no proxy of this cosca's protocol.
#[cfg(windows)]
const SAME_COSCA_PROXY: &str = "Start a proxy built from the same cosca: CtrlProxy::HostExecutable, or the \
     cosca-ctrl-proxy executable that belongs to it.";

/// [`REMEDIES`] for the answer `TargetHasNoConsole`, whose child may be a GUI program, which has windows to
/// ask instead.
#[cfg(windows)]
const NO_CONSOLE_REMEDIES: &str = "Use Child::kill for a hard teardown, stop::send_wm_close for a GUI child that \
     shows a window, or Command::graceful_stop with a stop of your own.";

/// The possible causes of the answer `TargetHasNoConsole`, which cosca cannot tell apart.
#[cfg(windows)]
const NO_CONSOLE_CAUSES: &str =
    "The child may have no console (it was created without one, or gave it up), or may not \
     have started running yet: a child that was just created looks like one without a console until it has \
     set its own up.";

/// The possible cause of the answers `AttachDenied` and `TargetGone` for a child that has not exited.
#[cfg(windows)]
const ATTACH_DENIED_CAUSE: &str = "The child may still be running, on a console that refused the proxy.";

/// What `send` would do with a target, decided by the facts fixed at the spawn (so not by the child's
/// timing): the one classification both the missing-hook panic and `send`'s refusals read.
#[cfg(windows)]
enum Plan<'a> {
    /// A child a system service created on a UAC consent.
    RefuseElevated,
    /// A child with no identity to name it by.
    RefuseNoIdentity,
    /// Start this program ([`CtrlProxy::HostExecutable`]) as the proxy for the child `ProcessId` names.
    StartHost(ProcessId),
    /// Start the program a command named ([`CtrlProxy::Executable`]).
    StartExecutable(ProcessId, &'a Path),
}

/// Classifies what `send` would do with `target`.
#[cfg(windows)]
fn plan<'a>(target: &'a StopTarget<'_>) -> Plan<'a> {
    if target.child().console.elevated {
        return Plan::RefuseElevated;
    }
    let Some(id) = target.id() else {
        return Plan::RefuseNoIdentity;
    };
    match target.ctrl_proxy() {
        CtrlProxy::HostExecutable => Plan::StartHost(id),
        CtrlProxy::Executable(exe) => Plan::StartExecutable(id, exe),
    }
}

/// Panics when `plan` starts this program as its own proxy and the program never called
/// `init_helpers`: the copy would run as the program. Other plans pass through. `send` calls it before
/// looking at the child.
#[cfg(windows)]
fn require_helpers_initialized(plan: &Plan<'_>, helpers_initialized: bool) {
    if matches!(plan, Plan::StartHost(_)) && !helpers_initialized {
        panic!(
            "CtrlProxy::HostExecutable starts a copy of this program as the console-event proxy, and this \
             program did not call cosca::init_helpers(), so the copy would run as the program itself. Call \
             cosca::init_helpers() first thing in main, or set Command::ctrl_proxy(CtrlProxy::Executable(..)) \
             to the cosca-ctrl-proxy executable."
        );
    }
}

/// The proxy's send, as [`send_console_event_via_proxy`](crate::stop::send_console_event_via_proxy)
/// documents it, for any [`StopWaits`]: the waits are the driver's.
#[cfg(windows)]
pub(crate) async fn send<D: StopWaits>(driver: &D, target: &StopTarget<'_>, event: CtrlEvent) -> Result<(), Error> {
    let plan = plan(target);
    require_helpers_initialized(&plan, crate::helpers_initialized());
    // An exited child is answered before any refusal.
    match driver.root_exited(Duration::ZERO).await {
        Ok(false) => {}
        Ok(true) => {
            return conclude(
                target,
                event.name(),
                SendAnswer::RootExited(root_exited(
                    &format!(
                        "the child (pid {}) had exited when cosca looked, before the console-event proxy was started",
                        target.pid()
                    ),
                    PROXY_CANNOT_REACH_OUTLIVERS,
                )),
            )
        }
        Err(look_failed) => return conclude(target, event.name(), SendAnswer::NotSent(look_failed)),
    }
    let (id, exe): (ProcessId, std::borrow::Cow<'_, Path>) = match plan {
        Plan::RefuseElevated => return Err(refuse(target, ELEVATED_REFUSAL)),
        Plan::RefuseNoIdentity => return Err(refuse(target, format!("{NO_IDENTITY_REASON} {REMEDIES}"))),
        Plan::StartHost(id) => match std::env::current_exe() {
            Ok(exe) => (id, exe.into()),
            Err(e) => return conclude(target, event.name(), exe_unreadable(e)),
        },
        Plan::StartExecutable(id, exe) => (id, exe.into()),
    };
    conclude(target, event.name(), ask(driver, target, event, &id, &exe).await)
}

/// What an exited root's answer says the proxy cannot do for the root's descendants.
#[cfg(windows)]
const PROXY_CANNOT_REACH_OUTLIVERS: &str = "the proxy cannot reach a member of its tree that outlived it";

/// Starts `exe` as the proxy for `event` to the console of the child `id` names, waits for its
/// answer, and returns what it came to.
#[cfg(windows)]
async fn ask<D: StopWaits>(
    driver: &D,
    target: &StopTarget<'_>,
    event: CtrlEvent,
    id: &ProcessId,
    exe: &Path,
) -> SendAnswer {
    let record = match id.to_record() {
        Ok(record) => record,
        Err(e) => return SendAnswer::NotSent(e),
    };
    debug_assert_eq!(record.pid, target.pid(), "the child's identity names the child");
    let args = ProxyArgs {
        target: record.pid,
        target_key: record.token,
        event,
        caller: std::process::id(),
    };
    // From the start the proxy may send, and a dropped call never reaches `conclude`: the record says so
    // until `conclude` replaces it.
    target.note_may_have_sent(event.name());
    // The target borrows the child, which holds its process handle: the pid stays this child's until
    // the call returns, whatever the child does.
    let (proxy_pid, mut proxy) = match driver.start_proxy(exe, &args).await {
        Ok(started) => started,
        Err(e) => return start_failed(exe, e),
    };
    // The wait is the driver's; the warning is this body's policy.
    let status = driver
        .wait_proxy(&mut proxy, crate::wait::teardown_warn::LATE, |after| {
            warn_still_waiting(Some(proxy_pid), record.pid, event, after)
        })
        .await;
    // Dropped before the match so a failed wait has ended the proxy before the error returns.
    drop(proxy);
    let status = match status {
        Ok(status) => status,
        Err(e) => return wait_failed(proxy_pid, event, e),
    };
    let Some(code) = status.code() else {
        return SendAnswer::Unknown(Error::Unassessable {
            detail: format!(
                "the console-event proxy (pid {proxy_pid}) ended without an exit code ({status}), so whether {} \
                 was sent is unknown",
                event.name()
            ),
            source: None,
        });
    };
    if code == crate::role::UNKNOWN_HELPER_ROLE {
        // The helper refused the role cosca named: it never played one, so nothing was sent.
        return SendAnswer::NotSent(unsupported(
            format!(
                "the program started as the console-event proxy ({}) refused the helper role this cosca named \
             (exit {code}): it knows no `{}` role, so nothing was sent. {SAME_COSCA_PROXY}",
                exe.display(),
                crate::role::CTRL_PROXY
            ),
            None,
        ));
    }
    let Some(exit) = ProxyExit::from_code(code) else {
        return SendAnswer::Unknown(Error::Unassessable {
            detail: format!(
                "the console-event proxy {} (pid {proxy_pid}) exited with code {}, which is no answer of its \
                 protocol, so whether {} was sent is unknown",
                exe.display(),
                exit_text(code),
                event.name()
            ),
            source: None,
        });
    };
    #[cfg(test)]
    crate::containment::windows::observe::record_ctrl_send(crate::containment::windows::observe::CtrlSend::Proxy {
        target: record.pid,
        event,
        exit,
    });
    result_of(driver, target, event, exe, exit).await
}

/// Sets `command` up to start `exe` as the proxy for `args`: told by the environment that it is the
/// proxy, uncontained, with no console of its own (a process attached to one cannot attach to another),
/// and null standard streams.
#[cfg(windows)]
pub(crate) fn configure_start(command: &mut crate::Command, exe: &Path, args: &ProxyArgs) -> Result<(), Error> {
    command
        .raw_executable(exe)
        .args(args.to_argv(exe.as_os_str()))
        .env(crate::role::HELPER_ENV, crate::role::CTRL_PROXY);
    command.detached();
    command
        .stdin(crate::Stdio::null())?
        .stdout(crate::Stdio::null())?
        .stderr(crate::Stdio::null())?;
    Ok(())
}

/// This program's own path cannot be read, to start it as the proxy.
#[cfg(windows)]
fn exe_unreadable(e: std::io::Error) -> SendAnswer {
    SendAnswer::NotSent(Error::Io(crate::error::io_context(
        "nothing was sent: this program's own path cannot be read, to start it as the proxy",
        e,
    )))
}

/// The proxy could not be started, as `e` says. A proxy that may have started may have sent, so its error
/// keeps that meaning.
#[cfg(windows)]
fn start_failed(exe: &Path, e: Error) -> SendAnswer {
    match e {
        may_have_started @ Error::MayHaveStarted { .. } => SendAnswer::Unknown(may_have_started),
        not_started => SendAnswer::NotSent(not_started.in_step(&format!(
            "nothing was sent: the console-event proxy {} could not be started",
            exe.display()
        ))),
    }
}

/// The wait for the proxy `proxy_pid` failed, as `e` says. The proxy's [`Child`](crate::Child) is dropped
/// with the failure, which kills it.
#[cfg(windows)]
fn wait_failed(proxy_pid: u32, event: CtrlEvent, e: Error) -> SendAnswer {
    SendAnswer::Unknown(Error::Unassessable {
        detail: format!(
            "the wait for the console-event proxy (pid {proxy_pid}) failed, so whether {} was sent is \
             unknown; cosca ended the proxy when the wait failed",
            event.name()
        ),
        source: Some(Arc::new(e)),
    })
}

/// The error of a proxy that sent nothing because a step failed. See [`send_console_event_via_proxy`](crate::stop::send_console_event_via_proxy) for its text, kind
/// and source.
#[cfg(windows)]
fn failed_step(cause: Cause, sent: &str) -> std::io::Error {
    let text = format!(
        "nothing was sent: the console-event proxy failed a step (exit {}), so no {sent} was sent; it \
         failed at {}{}",
        exit_text(cause.code()),
        cause.step.name(),
        if cause.os_code.is_some() {
            ""
        } else {
            ", with no Win32 code the exit code can carry"
        }
    );
    crate::error::io_context_or_other(
        text,
        cause
            .os_code
            .map(|code| std::io::Error::from_raw_os_error(i32::from(code.get()))),
    )
}

/// What the proxy's `exit` came to as the stop's send.
#[cfg(windows)]
async fn result_of<D: StopWaits>(
    driver: &D,
    target: &StopTarget<'_>,
    event: CtrlEvent,
    exe: &Path,
    exit: ProxyExit,
) -> SendAnswer {
    let sent = event.name();
    let answer = match exit {
        ProxyExit::Answer(answer) => answer,
        ProxyExit::Cause(cause) => return SendAnswer::NotSent(Error::Io(failed_step(cause, sent))),
    };
    let code = answer.code();
    // The attach did not succeed, and the child had not exited when cosca looked: the child's own exit
    // is the one thing the proxy's answer cannot say.
    let attach_refused = |cause: &str, remedies: &str| {
        SendAnswer::NotSent(unsupported(
            format!(
                "the console-event proxy's attach to the child's console did not succeed (answer {answer:?}, exit \
             {code}), and the child had not exited when cosca looked, so nothing was sent. {cause} {remedies}"
            ),
            None,
        ))
    };
    let not_sent = |error: Error| SendAnswer::NotSent(error);
    match answer {
        ProxyAnswer::Sent => SendAnswer::Sent(Ok(())),
        ProxyAnswer::TargetGone | ProxyAnswer::AttachDenied | ProxyAnswer::TargetHasNoConsole => {
            match driver.root_exited(Duration::ZERO).await {
                Err(look_failed) => not_sent(look_failed),
                Ok(true) => SendAnswer::RootExited(root_exited(
                    &format!(
                        "the console-event proxy's attach to the console of the child (pid {}) did not succeed \
                         (answer {answer:?}, exit {code}), and the child had exited when cosca looked",
                        target.pid()
                    ),
                    PROXY_CANNOT_REACH_OUTLIVERS,
                )),
                Ok(false) => match answer {
                    ProxyAnswer::TargetHasNoConsole => attach_refused(NO_CONSOLE_CAUSES, NO_CONSOLE_REMEDIES),
                    _ => attach_refused(ATTACH_DENIED_CAUSE, REMEDIES),
                },
            }
        }
        ProxyAnswer::ConsoleIsCallers => not_sent(unsupported(
            format!(
                "the child's console is this process's own, so an event sent there would reach this process and \
             everything attached to it as well: nothing was sent. {}",
                if target.child().console.group {
                    "The child leads a console process group: send it Ctrl+Break with stop::send_ctrl_break_to_group."
                } else {
                    "Create it with Command::new_process_group(true), and send it Ctrl+Break with \
                 stop::send_ctrl_break_to_group."
                }
            ),
            None,
        )),
        ProxyAnswer::VersionMismatch | ProxyAnswer::Usage => not_sent(unsupported(
            format!(
                "the program started as the console-event proxy ({}) did not accept this cosca's invocation \
             (answer {answer:?}, exit {code}); this cosca speaks proxy protocol version {VERSION}, so \
             nothing was sent. {SAME_COSCA_PROXY}",
                exe.display()
            ),
            None,
        )),
        ProxyAnswer::NoProxyHere => not_sent(unsupported(
            format!(
                "the program started as the console-event proxy ({}) has no proxy here (answer {answer:?}, \
             exit {code}), so nothing was sent",
                exe.display()
            ),
            None,
        )),
        ProxyAnswer::Unconfirmed => SendAnswer::Unknown(Error::Unassessable {
            detail: format!(
                "the console-event proxy generated the {sent} and did not see its own copy of it (answer \
                 {answer:?}, exit {code}), so whether the child received it is unknown"
            ),
            source: None,
        }),
    }
}

#[cfg(all(test, windows))]
#[path = "proxy_tests.rs"]
pub(crate) mod proxy_tests;

#[cfg(all(test, windows))]
#[path = "proxy_real_tests.rs"]
mod proxy_real_tests;
