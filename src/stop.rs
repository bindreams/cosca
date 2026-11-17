//! A child's cooperative stop: what [`Child::terminate`](crate::Child::terminate),
//! [`graceful_shutdown`](crate::Child::graceful_shutdown),
//! [`terminate_tree`](crate::Child::terminate_tree) and
//! [`graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree) send before they wait, as an action
//! the caller chooses ([`Command::graceful_stop`](crate::Command::graceful_stop)) and the functions it is
//! composed of.
//!
//! An action is a function of a [`StopTarget`], which stands for the child's root or for its tree. The
//! functions here are the prepared actions, each callable on its own from an action of the caller's:
//! [`default`] is what a child does when none is set, and is written as a caller would write it. The
//! functions here that wait block the calling thread; their awaited forms are in `cosca::tokio::stop`
//! (feature `tokio`).
//!
//! A prepared function does the sending, inside the rules a child's `terminate` applies, whoever calls
//! it: the same front gate meets a send to the root and a send to the tree. What a prepared send answers
//! is what the call that runs it answers, and a call that waits afterwards (the graceful shutdowns) goes
//! on from the last prepared send.
//!
//! In each tree call a prepared send answers what that call does with the route's outcome. Where
//! nothing names the tree (a root reaped by something else, on a mechanism with no other channel) that
//! is the answer the call computes: an error, with nothing sent and the call ended, so an action
//! composed of sends stops at its first `?`; or `Ok` for a tree this handle already killed. Only the
//! outcomes the call alone can finish, the root reachable only through its pidfd and an fd marker's
//! holders alone, answer `Ok` and defer to the call, which finishes them after the action returns.

mod action;
pub(crate) mod proxy;
mod target;
mod waits;

pub(crate) use action::StopAction;
pub use target::StopTarget;
pub(crate) use target::{RootRecord, Scope, TreeCall, TreeRecord};
pub(crate) use waits::StopWaits;

#[cfg(windows)]
use crate::containment::SendOutcome;
#[cfg(windows)]
use proxy::protocol::CtrlEvent;

use crate::error::Error;

/// The stop a child does when its command set none: on Unix, `send_signal` with
/// `Signal::Term`; on Windows, `send_ctrl_break_to_group`.
pub fn default(target: &StopTarget<'_>) -> Result<(), Error> {
    #[cfg(unix)]
    return send_signal(target, crate::Signal::Term);
    #[cfg(windows)]
    return send_ctrl_break_to_group(target);
}

/// Unix: sends `signal`, and does not wait.
///
/// A send is made inside the rules `terminate` applies, whoever calls this function, to the root and to
/// the tree alike: an elevation front that does not relay `signal` to its program is refused with
/// nothing sent (see below), and on a root target a macOS root that launchd holds is refused too.
///
/// On a root target the signal goes to the root alone, through the child's own handle, which names the
/// process exactly: it cannot reach another process that took a reaped child's number.
///
/// On a tree target the signal goes to every member of the contained tree, by the mechanism's own route
/// (a cgroup leaf's listing, a process group, a session, a walk, an fd marker's sweep; see the module
/// doc for what the calling tree call does with the outcome).
///
/// # Elevation fronts
///
/// A child started through a `sudo`, `doas` or macOS `osascript` front is tracked by the front, not by
/// the program it launched, and a signal to the front is the program's only if the front relays it.
/// What each front relays was measured (sudo 1.9.16p2, opendoas 6.8.2, polkit 126, Debian 13):
///
/// | Front | Signals it relays to the program |
/// |---|---|
/// | `sudo` | `HUP`, `INT`, `QUIT`, `USR1`, `USR2`, `TERM`, `TSTP`, `WINCH` |
/// | `doas` | `TERM` |
/// | `pkexec` | none needed: the front becomes the program, so every signal reaches the program itself, and the kernel refuses what a caller that is not root may not send (`EPERM`, as for [`Child::kill`](crate::Child::kill)) |
/// | `osascript` | none |
///
/// Any other signal to a live `sudo` or `doas` front is refused with [`Error::Unsupported`] naming the
/// front, the signal and the signals the front relays, and nothing is sent: it would end the front and
/// leave the elevated program running. A live `osascript` front is refused every signal, as `terminate`
/// refuses it. Other versions of these programs were not measured.
///
/// # Errors
///
/// A refused send, or one the OS refused, as [`Child::terminate`](crate::Child::terminate) answers it.
#[cfg(unix)]
pub fn send_signal(target: &StopTarget<'_>, signal: crate::Signal) -> Result<(), Error> {
    let child = target.child();
    // A front's refusal outranks a root launchd holds, as for `kill`: every send, to the root or to the
    // tree, runs only once the rule has let it. The outer `Err` is the refusal, the inner `Result` the
    // send's own answer.
    let gated = child.proc.terminate_by(signal, || {
        Ok(match target.scope() {
            Scope::Root => child
                .refuse_unpinned("terminate", None)
                .and_then(|()| child.proc.signal(crate::signal::Sig::Graceful(signal)).map(drop)),
            Scope::Tree(call) => target.send_tree(call, crate::containment::TreeStop::of(signal)),
        })
    });
    match (gated, target.scope()) {
        (Err(refusal), _) => {
            target.note_refused(&refusal);
            Err(refusal)
        }
        (Ok(sent), Scope::Root) => {
            match &sent {
                Ok(()) => target.note_root_went_out(signal.name()),
                Err(refusal) => target.note_refused(refusal),
            }
            sent
        }
        (Ok(sent), Scope::Tree(_)) => sent,
    }
}

/// Windows: sends `CTRL_BREAK` to the child's console process group from this process, and does not wait.
///
/// The event reaches every process in the group, so a descendant that stayed in the group is told to stop
/// too, and a nested contained descendant, which by default leads a group of its own, is not. Windows reports
/// success for an event aimed at a group in another console and delivers nothing, and this process
/// cannot rule that case out: a child created with `no_window` has a console of its own, and the send
/// answers `Ok` and reaches nobody; so does a child created with `detached`, which has none. Each call
/// also leaves a dead entry in the caller's console process list.
///
/// The caller must have a console: [`Error::NoConsole`] otherwise (a GUI program, a service, a detached
/// process). A tree target is sent the same event; the group is the same.
///
/// Between the spawn returning and the child executing its first instructions it has not registered with
/// any console, and an event delivered in that window ends it during loader init rather than through its
/// own handler. That is an abrupt end, reported `Ok`.
///
/// # Errors
///
/// [`Error::Unsupported`] for a child created without the process-group flag (set it with
/// [`Command::new_process_group`](crate::Command::new_process_group)), which can be sent no
/// console event alone, and for a child a system service created on a UAC consent (cosca cannot know
/// whether it leads a group of its own); [`Error::NoConsole`] as above.
#[cfg(windows)]
pub fn send_ctrl_break_to_group(target: &StopTarget<'_>) -> Result<(), Error> {
    let child = target.child();
    let console = child.console;
    let refusal = if console.elevated {
        Some(ELEVATED_REFUSAL)
    } else if !console.group {
        Some(
            "this child leads no console process group of its own, so no console control \
             event can be addressed to it by any process; group leadership is fixed at \
             creation. Spawn it with Command::new_process_group(true) (contain() sets it \
             unless told otherwise) to give it one, or use kill() for a hard teardown.",
        )
    } else {
        None
    };
    if let Some(detail) = refusal {
        return Err(refuse(target, detail));
    }
    conclude(
        target,
        CtrlEvent::CtrlBreak,
        SendOutcome::direct(crate::containment::windows::terminate(child.pid())),
    )
}

/// Windows: why a prepared send refuses a child cosca did not create.
#[cfg(windows)]
const ELEVATED_REFUSAL: &str = "cosca did not create this child — a system elevation service did — so \
     whether it leads a console process group of its own is unknown, and an \
     event addressed to its pid would reach its leader's whole group instead. \
     Use kill() for a hard teardown.";

/// Windows: [`Error::Unsupported`] for a graceful stop, with `detail`. Nothing was sent.
#[cfg(windows)]
fn unsupported(detail: impl Into<String>) -> Error {
    Error::Unsupported {
        op: "graceful terminate".into(),
        platform: std::env::consts::OS,
        detail: detail.into(),
        source: None,
    }
}

/// Windows: a prepared send's refusal before it sent anything: the error, left as what the last send
/// did, for either kind of target.
#[cfg(windows)]
fn refuse(target: &StopTarget<'_>, detail: impl Into<String>) -> Error {
    let refusal = unsupported(detail);
    target.note_refused(&refusal);
    refusal
}

/// Windows: a prepared send's end: `sent`, what the send of `event` came to ([`SendOutcome`] says what
/// each outcome means), left as what the last send did, and, on a tree target, handed to the mechanism's
/// route, whose answer is the call's.
#[cfg(windows)]
fn conclude(target: &StopTarget<'_>, event: CtrlEvent, sent: SendOutcome) -> Result<(), Error> {
    match target.scope() {
        Scope::Root => match sent {
            SendOutcome::Sent(answer) => {
                target.note_root_went_out(event.name());
                answer
            }
            SendOutcome::RootExited(_) => {
                target.note_root_went_out(event.name());
                Ok(())
            }
            SendOutcome::NotSent(not_sent) => {
                target.note_refused(&not_sent);
                Err(not_sent)
            }
        },
        Scope::Tree(call) => target.send_tree(call, crate::containment::TreeStop::of_event(event, sent)),
    }
}

/// Windows: sends `event` to the console of the child, from a process of its own, and does not wait
/// for the child.
///
/// A Windows process can send a console event only to the console it is attached to, and a process
/// attached to one console cannot attach to another. A stop that must reach a child outside this
/// process's console (a child created with `no_window`, or this process having no console at all, as a
/// service has none) starts a helper, the proxy, that has no console of its own: the proxy attaches to
/// the child's console, sends `event` to it, and answers by its exit code. This function starts it
/// (see [`CtrlProxy`](crate::CtrlProxy) and [`Command::ctrl_proxy`](crate::Command::ctrl_proxy)), waits
/// for its answer, and returns what the answer means. It runs inside the rules
/// [`send_ctrl_break_to_group`] runs inside, and a tree target is handed the answer as that function
/// hands its own.
///
/// # What it reaches
///
/// The event goes to **every process on the child's console**: the child, its descendants that share the
/// console, and any other process attached to it, in whatever process group. [`CtrlEvent::CtrlBreak`]
/// ends a process that has no handler for it. A child created with the process-group flag
/// ([`Command::new_process_group`](crate::Command::new_process_group), which `contain` sets) starts
/// with Ctrl+C ignored, and so do its descendants unless one re-enables it, so [`CtrlEvent::CtrlC`]
/// does nothing to such a child. The proxy re-enables Ctrl+C for itself and nothing else.
///
/// The child must have a console to attach to. A stop sent before the child has set one up (a child
/// that was just created and has shown the caller no output or handshake) can find none: that is
/// answered [`Error::Unsupported`], as for a child that never has one.
///
/// # Waits
///
/// The call waits, with no cap, for the proxy's answer, warning once after one second. No state of
/// another process on the child's console was found to hold the proxy: a handler that never returns,
/// every thread suspended, a debugger holding the process, and an exit as the event is generated were
/// measured, and other states were not. A [`CtrlProxy::Executable`](crate::CtrlProxy::Executable) that
/// is not a proxy and does not exit holds the call, and [`Child::kill`](crate::Child::kill) does not
/// release it: the wait is for the proxy, not for the child.
///
/// The wait blocks the calling thread. An async action awaits
/// `cosca::tokio::stop::send_console_event_via_proxy` (feature `tokio`) instead.
///
/// # Errors
///
/// [`Error::Unsupported`], with nothing sent and, for the first three, nothing started:
/// - the child is one a system service created on a UAC consent;
/// - the child has no identity ([`Child::id`](crate::Child::id) is `None`), which the proxy names its
///   target by, so that a reused pid is never sent an event;
/// - [`CtrlProxy::HostExecutable`](crate::CtrlProxy::HostExecutable) is set and the host program has
///   not called [`init`](crate::init);
/// - the proxy found no console to attach to for the child (the child has none, as a child created
///   with [`detached`](crate::Command::detached) has none, or has not set it up yet), and the child had
///   not exited when cosca looked;
/// - the child's console is this process's own, which an event would reach as well (send
///   [`Ctrl+Break` to the child's group](send_ctrl_break_to_group) instead);
/// - the proxy's attach to the child's console was refused, and the child had not exited when cosca
///   looked;
/// - the program started does not speak this cosca's protocol version, or is no proxy.
///
/// An [`Error::Io`] says nothing was sent: the proxy could not be started, or it failed before it
/// generated the event. [`Error::Unassessable`] says whether the event was sent is unknown: the proxy
/// ended without a known answer, or generated the event and did not see its own copy. So does an
/// [`Error::MayHaveStarted`] from the start of the proxy, which says the proxy may have run.
///
/// On a tree target, an error that says the event may have been sent still goes on to the grace and
/// sweep, with that error as the cooperative error; every other error, `Unsupported` included, ends the
/// call as a refused send.
///
/// # A child that has exited
///
/// When the proxy cannot attach and cosca's look finds the child exited, nothing was sent. On a root
/// target the answer is `Ok`, as [`send_ctrl_break_to_group`] answers an exited child. On a tree target
/// `terminate_tree` answers an error, and `graceful_shutdown_tree` goes on to its grace, sweep and
/// reap with no event sent: members that outlived the root are ended by the sweep without a console
/// event, where the direct send to the group would have reached them.
#[cfg(windows)]
pub fn send_console_event_via_proxy(target: &StopTarget<'_>, event: CtrlEvent) -> Result<(), Error> {
    crate::child::graceful::shutdown::run_ready(proxy::send(
        &crate::child::graceful::shutdown::BlockingDriver(target.child()),
        target,
        event,
    ))
}

#[cfg(test)]
#[path = "stop_tests.rs"]
mod stop_tests;
