//! A child's cooperative stop: what [`Child::terminate`](crate::Child::terminate),
//! [`graceful_shutdown`](crate::Child::graceful_shutdown),
//! [`terminate_tree`](crate::Child::terminate_tree) and
//! [`graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree) send before they wait, as an action
//! the caller chooses ([`Command::graceful_stop`](crate::Command::graceful_stop)) and the functions it is
//! composed of.
//!
//! An action is a function of a [`StopTarget`], which stands for the child's root or for its tree. The
//! functions here are the prepared actions, each callable on its own from an action of the caller's:
//! [`default`] is what a child does when none is set, and is written as a caller would write it.
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

pub(crate) use action::StopAction;
pub use target::StopTarget;
pub(crate) use target::{RootRecord, Scope, TreeCall, TreeRecord};

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
            target.note_root_send(signal.name(), &sent);
            sent
        }
        (Ok(sent), Scope::Tree(_)) => sent,
    }
}

/// Windows: sends `CTRL_BREAK` to the child's console process group from this process, and does not wait.
///
/// The event reaches every process in the group, so a descendant that stayed in the group is told to stop
/// too, and a nested contained descendant, which leads a group of its own, is not. Windows reports
/// success for an event aimed at a group in another console and delivers nothing, and this process
/// cannot rule that case out: a child created with `no_window`, or `detached`, has a console of its own,
/// and the send answers `Ok` and reaches nobody. Each call also leaves a dead entry in the caller's
/// console process list.
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
/// [`Error::Unsupported`] for a child created without the process-group flag, which can be sent no
/// console event alone, and for a child a system service created on a UAC consent (cosca cannot know
/// whether it leads a group of its own); [`Error::NoConsole`] as above.
#[cfg(windows)]
pub fn send_ctrl_break_to_group(target: &StopTarget<'_>) -> Result<(), Error> {
    let child = target.child();
    let console = child.console;
    let refusal = if console.elevated {
        Some(
            "cosca did not create this child — a system elevation service did — so \
             whether it leads a console process group of its own is unknown, and an \
             event addressed to its pid would reach its leader's whole group instead. \
             Use kill() for a hard teardown.",
        )
    } else if !console.group {
        Some(
            "this child leads no console process group of its own, so no console control \
             event can be addressed to it by any process; group leadership is fixed at \
             creation. Spawn it with contain() to give it one, or use kill() for a hard \
             teardown.",
        )
    } else {
        None
    };
    if let Some(detail) = refusal {
        let refusal = Error::Unsupported {
            op: "graceful terminate".into(),
            platform: std::env::consts::OS,
            detail: detail.into(),
            source: None,
        };
        target.note_refused(&refusal);
        return Err(refusal);
    }
    let sent = crate::containment::windows::terminate(child.pid());
    match target.scope() {
        Scope::Root => {
            target.note_root_send(crate::containment::CTRL_BREAK, &sent);
            sent
        }
        Scope::Tree(call) => target.send_tree(call, crate::containment::TreeStop::of_break(sent)),
    }
}

#[cfg(test)]
#[path = "stop_tests.rs"]
mod stop_tests;
