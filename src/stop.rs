//! A child's cooperative stop: what [`Child::terminate`](crate::Child::terminate),
//! [`graceful_shutdown`](crate::Child::graceful_shutdown),
//! [`terminate_tree`](crate::Child::terminate_tree) and
//! [`graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree) send to ask the child to stop (the
//! graceful shutdowns then wait, and the other two return), as an action the caller chooses
//! ([`Command::graceful_stop`](crate::Command::graceful_stop)) and the functions it is composed of.
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
//! Every prepared send also leaves how it went on the target, whatever it answered, for the call to read
//! after the action returns: `terminate` and `terminate_tree` fail with a [`StopError`], which holds the
//! action's error and the [`SendOutcome`] of its last prepared send. An action that made no prepared send
//! and failed is [`SendOutcome::Unknown`]; `SendOutcome` says what each value claims. A foreign
//! [`Process::terminate_tree`](crate::Process::terminate_tree) (sync and tokio) fails with one too, though it has
//! no stop action and no record: its outcome is that of its walk's send.
//!
//! In each tree call a prepared send answers what that call does with the route's outcome. Where
//! nothing names the tree (a root reaped by something else, on a mechanism with no other channel) that
//! is the answer the call computes: an error, with nothing sent and the call ended, so an action
//! composed of sends stops at its first `?`; or `Ok` for a tree this handle already killed. Only the
//! outcomes the call alone can finish, the root reachable only through its pidfd and an fd marker's
//! holders alone, answer `Ok` and defer to the call, which finishes them after the action returns.
//!
//! # The default
//!
//! A child whose command set no action does [`default`]: `SIGTERM` on Unix, `Ctrl+Break` on Windows.
//! `default` lists which child is sent how, and which it refuses.
//!
//! # What a stop reaches
//!
//! A stop is a request, which a process may handle or ignore. What it is sent to depends on the target
//! and, on Unix, on the child's containment mechanism.
//!
//! **Unix.** A route that lists the tree (`CgroupV2`, `TreeWalk`) signals the members it listed when the
//! pass began; a process that enters the tree later is not signalled.
//!
//! | Target | Containment | The signal reaches |
//! |---|---|---|
//! | root (`terminate`, `graceful_shutdown`) | any | the root alone (`send_signal` says how the handle names it) |
//! | tree (`terminate_tree`, `graceful_shutdown_tree`) | [`CgroupV2`](crate::Containment::CgroupV2) | the processes in the leaf itself, each pinned by a pidfd before it is signalled; not one in a cgroup under the leaf, nor one in a pid namespace this process cannot see (that one makes the call an error), which `kill_tree` reaches |
//! | tree | [`ProcessGroup`](crate::Containment::ProcessGroup), [`Session`](crate::Containment::Session) | the members of the process group the root leads (for a session, its first group) when the signal is sent; a member that left the group, as a `setsid` child does, is not reached |
//! | tree | [`TreeWalk`](crate::Containment::TreeWalk) | the root and every descendant the walk finds from the root's identity; a process reparented away from the tree, or whose identity cannot be read, is not reached |
//! | tree | [`FdMarker`](crate::Containment::FdMarker) (macOS) | the process group, the root's descendants and the marker's holders; a member of the group that is also a descendant or a holder is sent the signal twice (see [`Containment::FdMarker`](crate::Containment::FdMarker)) |
//!
//! A tree call on a child that owns no tree (uncontained, or a member of an ancestor's containment) is
//! [`Error::Unsupported`] before the action runs.
//!
//! A Unix root that something else reaped can change what the routes named by the root's pid reach (a
//! process group, a session, a macOS fd marker's group and walk): see the section on a child reaped by
//! something else in [`Command::contain`](crate::Command::contain).
//!
//! **Windows.** The containment mechanism sends nothing of its own. The two console-event sends reach the
//! same processes for a root target and for a tree target, since the event addresses a group or a console;
//! `send_wm_close` reaches only the windows it is given, so it takes the tree's members from the
//! mechanism:
//!
//! | Send | The event reaches |
//! |---|---|
//! | direct (`send_ctrl_break_to_group`) | when the child is on this process's console, every process in its console process group: the child, and the descendants that stayed in the group, not a nested contained descendant, which leads a group of its own. A child with a console of its own, or with none, is sent nothing, and the send still answers `Ok` |
//! | through the proxy (`send_console_event_via_proxy`) | every process on the child's console, in whatever process group: the child, its descendants that share the console, and any other process attached to it |
//! | `WM_CLOSE` (`send_wm_close`) | a root target: the visible unowned windows of the child. A tree target: those of every member of the contained tree, the root included, as the mechanism lists them (a job's members, or the descendants a tree walk finds from the root's identity) |
//!
//! Neither console event reaches a descendant that has a console of its own or was started detached. A
//! root that has already exited changes what the proxy reaches: it sends nothing, even to descendants on
//! the root's console, which `graceful_shutdown_tree`'s sweep ends, where the direct send to the group
//! would still reach them (see `send_console_event_via_proxy`). `send_wm_close` on a tree target asks the
//! members the mechanism lists, so a window of a descendant that outlived its root is reached.
//!
//! # Choosing an action
//!
//! [`Command::graceful_stop`](crate::Command::graceful_stop) takes a function of a [`StopTarget`]; it
//! gives the signature and says what the call does with the function's answer. Five ways to write one:
//!
//! - **Another signal (Unix).** `stop::send_signal(target, Signal::Int)` sends the signal `Signal` names
//!   in place of `SIGTERM`, to the root or the tree as the target says. A `sudo` or `doas` front relays
//!   only some signals and an `osascript` front none: `send_signal` lists them.
//! - **Ctrl+C in place of Ctrl+Break (Windows).**
//!   `stop::send_console_event_via_proxy(target, CtrlEvent::CtrlC)`. A child created with a console
//!   process group starts with Ctrl+C ignored, and `contain` creates one: give the child none with
//!   `Command::new_process_group(false)`, and see `send_console_event_via_proxy` for when Ctrl+C then
//!   reaches it. The proxy sends to a whole console and refuses one that is this process's own, so this
//!   suits a child with a console of its own (`no_window()`) or a caller with no console.
//! - **A GUI child (Windows).** `stop::send_wm_close(target)` posts `WM_CLOSE` to the child's visible
//!   top-level windows that have no owner, which is what asks a program with no console to close: pick it
//!   with `Command::graceful_stop(stop::send_wm_close)`. It never posts to a console's window, and a program
//!   that shows no such window is refused.
//! - **A composition.** [`StopTarget::wait_exit`] waits up to a grace for the root to exit, so an action
//!   can ask, wait, and ask harder. [`covers_tree`](StopTarget::covers_tree) tells the action which kind
//!   of target it has.
//! - **An action of your own.** Write to a control pipe, call a service's stop.
//!
//! ```no_run
//! # #[cfg(unix)] fn demo() {
//! use std::time::Duration;
//!
//! use cosca::{stop, Command, Signal};
//!
//! let mut command = Command::new();
//! command.arg("my-service");
//! command.graceful_stop(|target| {
//!     stop::send_signal(target, Signal::Int)?;
//!     if !target.wait_exit(Duration::from_secs(5))? {
//!         stop::send_signal(target, Signal::Term)?;
//!     }
//!     Ok(())
//! });
//! # }
//! ```
//!
//! ```no_run
//! # #[cfg(windows)] fn demo() {
//! use cosca::{stop, Command, CtrlEvent};
//!
//! // `cosca::init_helpers()` is the first call of this program's `main`.
//! let mut command = Command::new();
//! command.arg("worker.exe").contain().no_window().new_process_group(false);
//! command.graceful_stop(|target| stop::send_console_event_via_proxy(target, CtrlEvent::CtrlC));
//! # }
//! ```
//!
//! # Limits
//!
//! Each is stated in full where it is linked.
//!
//! - **The proxy needs a host that called [`init_helpers`](crate::init_helpers)**, or a
//!   `Command::ctrl_proxy` naming the `cosca-ctrl-proxy` executable. A stop that would start the host as
//!   the proxy panics in a host that did neither: see [`default`]'s `# Panics`.
//! - **A stop sent before the child has set its console up** (it has not run, or is early in its start-up) finds no console to
//!   attach to and is answered [`NotYet`](SendOutcome::NotYet), which the caller asks again: see [`default`] and
//!   `send_console_event_via_proxy`. A child of a layout that was not measured is not told apart from one
//!   that finished without a console.
//! - **The wait for the proxy has no cap unless the call was given a timeout
//!   ([`Child::terminate_timeout`](crate::Child::terminate_timeout),
//!   [`Child::graceful_shutdown_timeout`](crate::Child::graceful_shutdown_timeout) or their tree forms), which does
//!   not bound the proxy's start,
//!   and the grace starts when the action returns:** see `send_console_event_via_proxy` and
//!   [`Child::graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree).
//! - **A front that does not relay the signal.** An elevated child behind such a front is refused the
//!   signal, with nothing sent: see `send_signal`.
//! - **A direct send's success does not prove delivery:** see [`Child::terminate`](crate::Child::terminate).
//! - **`send_wm_close` asks only visible windows without an owner, on the calling thread's desktop:** see
//!   `send_wm_close`.

mod action;
mod outcome;
pub(crate) mod proxy;
mod target;
mod waits;
#[cfg(windows)]
mod wm_close;

pub(crate) use action::StopAction;
pub use outcome::{SendOutcome, StopError};
pub(crate) use target::root_exited_within;
#[cfg(feature = "tokio")]
pub(crate) use target::wait_exit_with;
pub use target::StopTarget;
pub(crate) use target::{ClockKind, Deadline, RootRecord, Scope, TreeCall, TreeRecord};
pub(crate) use waits::StopWaits;

#[cfg(windows)]
use crate::containment::SendAnswer;
use crate::containment::UnsentKind;
#[cfg(windows)]
use proxy::protocol::CtrlEvent;

use crate::error::Error;

/// The stop a child does when its command set none: on Unix, `send_signal` with `Signal::Term`; on
/// Windows, `CTRL_BREAK`, sent the way that can reach the child, which what the spawn recorded of its
/// console decides (`StopTarget::leads_group_on_our_console` and what it reads). A child is *created on this
/// process's console* when it was spawned with none of [`no_window`](crate::Command::no_window),
/// `detached` and a console of its own, by a process that had a console.
///
/// 1. The child was created on this process's console and leads a console process group there (a child
///    spawned with [`contain`](crate::Command::contain) does by default, a nested contained one too, and an
///    uncontained child only if `Command::new_process_group(true)` asked for it):
///    `send_ctrl_break_to_group`, which reaches every member of that group.
/// 2. The child was created on this process's console and leads no group (an uncontained child by default,
///    a contained one given `Command::new_process_group(false)`): `send_ctrl_break_to_group` too, which
///    refuses it. No proxy is started.
/// 3. Any other child (one created with `no_window`, `detached` or a console of its own, a child of a
///    caller that had no console, a child cosca did not create): `send_console_event_via_proxy` with
///    `CtrlEvent::CtrlBreak`, which blocks the calling thread for the proxy's answer and reaches every
///    process on the child's console. It needs the host program to have called
///    [`cosca::init_helpers()`](crate::init_helpers) (see `# Panics`).
///
/// The second case cannot be written with the public functions (`leads_group_on_our_console` is the only
/// public fact), so a hand-written `if leads { direct } else { proxy }` sends that child to the proxy.
///
/// # Refusals on Windows
///
/// Each is an [`Error::Unsupported`] with nothing sent and nothing killed. [`Child::kill`](crate::Child::kill)
/// is the always-available alternative, and [`graceful_shutdown`](crate::Child::graceful_shutdown) and
/// [`graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree) end at a refusal with the child running,
/// without going on to the kill.
///
/// - Case 2: the error names `Command::new_process_group`, because no console event can be addressed to the
///   child alone, and one sent to the console would reach this process as well. No proxy is started. The
///   direct send refuses before it looks at the child, so the refusal is the same for a child that has
///   exited, where every other child that has exited is answered `Ok` (see
///   [`Child::terminate`](crate::Child::terminate)).
/// - Case 3, the child has no identity to name it by: the error names `Child::kill`. Nothing is started.
/// - Case 3, a child a system elevation service created on a UAC consent: the error names `kill()`. Nothing
///   is started.
/// - Case 3, the child has no console to attach to (`detached()`, or a GUI-subsystem program given
///   `no_window`), and its start-up is over: the proxy finds none and the error names `Child::kill`, and
///   `stop::send_wm_close` as the action that fits a GUI child. The outcome is `NotSent`.
/// - Case 3, the child had not set its console up when the proxy asked (it had not run, or was early in its start-up): not a
///   refusal to act on, though the error is also an [`Error::Unsupported`]. Nothing was sent, the outcome is
///   [`NotYet`](SendOutcome::NotYet), and asking again can succeed.
/// - Case 3, cosca could not tell which of the two (a child of a layout that was not measured, a failed
///   read): the outcome is `NotSent`, and the error names `Child::kill` too.
/// - Case 3, the child's console is also this process's own (one changed console after the spawn): an event
///   sent there would reach this process too. The error names `stop::send_ctrl_break_to_group`, and
///   `Command::new_process_group` for a child that leads no group.
///
/// **Before the child has finished starting.** cosca neither waits nor asks again
/// itself; the caller asks again, within a bound of its own. `send_console_event_via_proxy` gives the
/// measured length of that window and the limit for a child of another layout. A caller that wants the
/// child gone before it has run at all uses `Child::kill`.
///
/// The route is chosen from what was true at the spawn, so a caller that changes its own console
/// afterwards (frees it, attaches another) sets an explicit action. A child that was created on this
/// process's console and later moved to a console of its own is not reached: the default refuses one that
/// leads no group, and sends one that leads a group a break that reaches nobody (see
/// `send_ctrl_break_to_group`). It stays reachable through an explicit
/// `graceful_stop(|t| stop::send_console_event_via_proxy(t, CtrlEvent::CtrlBreak))`.
///
/// # Panics
///
/// On Windows, panics when the stop would start this program as the console-event proxy and the program
/// never called [`cosca::init_helpers()`](crate::init_helpers). The stop would do that when the child is
/// outside the caller's console (case 3), cosca created it and read its identity, and the command's proxy
/// is the default `CtrlProxy::HostExecutable`: the proxy would be a second copy of this program running as
/// itself. That is a broken contract of the program, not a refusal, so it is a panic in every build
/// profile.
///
/// The check is the first thing the proxy route does, before it looks at whether the child has exited,
/// so the missing call shows by the route alone and not by the child's timing. It does not panic for a stop
/// that starts no copy of this program: a child on our console (which gets the direct send or its refusal),
/// a child cosca did not create or one without an identity, and a command that sets
/// `Command::ctrl_proxy(CtrlProxy::Executable(..))`. Call `cosca::init_helpers()` first thing in `main`, or
/// set the `Executable` proxy to the `cosca-ctrl-proxy` executable. Other platforms have no proxy and
/// nothing here panics.
pub fn default(target: &StopTarget<'_>) -> Result<(), Error> {
    #[cfg(unix)]
    return send_signal(target, crate::Signal::Term);
    #[cfg(windows)]
    return crate::child::graceful::shutdown::run_ready(default_with(
        &crate::child::graceful::shutdown::BlockingDriver(target.child()),
        target,
    ));
}

/// Windows: the one body of [`default`], for the driver that blocks (`stop::default`) and the one that awaits
/// (`tokio::stop::default`): the two cannot differ. A child created on our console is sent the direct break
/// whether it leads a group (the send) or not (the send's refusal, which names the setter); any other goes
/// through the proxy, whose waits are the driver's.
#[cfg(windows)]
pub(crate) async fn default_with<D: StopWaits>(driver: &D, target: &StopTarget<'_>) -> Result<(), Error> {
    if target.created_on_our_console() {
        send_ctrl_break_to_group(target)
    } else {
        proxy::send(driver, target, CtrlEvent::CtrlBreak).await
    }
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
/// On a macOS [`FdMarker`](crate::Containment::FdMarker) tree that has a process group, a member can be sent
/// the signal twice (see there). A handler that must run once per request tolerates a repeat, or the caller
/// sends to the root target.
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
            Scope::Root => {
                let sent = child
                    .refuse_unpinned("terminate", None)
                    .and_then(|()| child.proc.signal(crate::signal::Sig::Graceful(signal)))
                    .and_then(|sent| match sent {
                        // A contract breach, as for a walk's send (`KillOutcome::of`): a child's handle always
                        // holds what it verifies its pid against (macOS: the unique id it sends with).
                        crate::signal::Sent::Unverified => {
                            debug_assert!(false, "a child's handle always verifies its root");
                            Err(Error::Unassessable {
                                detail: format!(
                                    "the root (pid {}) could not be verified, so no {} was sent",
                                    child.pid(),
                                    signal.name()
                                ),
                                source: None,
                            })
                        }
                        sent => Ok(sent),
                    });
                match &sent {
                    Ok(crate::signal::Sent::Delivered) => target.note_root_sent(signal.name()),
                    // Not delivered: the root was gone, or its exit had begun. Nothing was sent.
                    Ok(_) => target.note_root_gone(),
                    Err(refusal) => target.note_not_sent(refusal, UnsentKind::NotSent),
                }
                sent.map(drop)
            }
            Scope::Tree(call) => target.send_tree(call, crate::containment::TreeStop::of(signal)),
        })
    });
    match gated {
        Err(refusal) => {
            target.note_not_sent(&refusal, UnsentKind::NotSent);
            Err(refusal)
        }
        Ok(sent) => sent,
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
        CtrlEvent::CtrlBreak.name(),
        SendAnswer::direct(crate::containment::windows::terminate(child.pid())),
    )
}

/// Windows: why a prepared send refuses a child cosca did not create.
#[cfg(windows)]
const ELEVATED_REFUSAL: &str = "cosca did not create this child — a system elevation service did — so \
     whether it leads a console process group of its own is unknown, and an \
     event addressed to its pid would reach its leader's whole group instead. \
     Use kill() for a hard teardown.";

/// Windows: what a refusal that leaves the child running says to use instead, in this order.
#[cfg(windows)]
const REMEDIES: &str = "Use Child::kill for a hard teardown, or Command::graceful_stop with a stop of your own.";

/// Windows: [`Error::Unsupported`] for a graceful stop, with `detail` and the error behind it, if there
/// is one. Nothing was sent.
#[cfg(windows)]
fn unsupported(detail: impl Into<String>, source: Option<std::sync::Arc<Error>>) -> Error {
    Error::Unsupported {
        op: "graceful terminate".into(),
        platform: std::env::consts::OS,
        detail: detail.into(),
        source,
    }
}

/// Windows: the answer of a send whose root had exited when cosca looked, with nothing sent: `cause` says
/// where the look was and `outliving` what the send cannot do for a member of the tree that outlived the
/// root.
#[cfg(windows)]
fn root_exited(cause: &str, outliving: &str) -> Error {
    Error::Unassessable {
        detail: format!("{cause}: nothing was sent, and {outliving}"),
        source: None,
    }
}

/// Windows: a prepared send's refusal before it sent anything: the error, left as what the last send
/// did, for either kind of target.
#[cfg(windows)]
fn refuse(target: &StopTarget<'_>, detail: impl Into<String>) -> Error {
    let refusal = unsupported(detail, None);
    target.note_not_sent(&refusal, UnsentKind::NotSent);
    refusal
}

/// Windows: a prepared send's end: `sent`, what the send named `name` (`CTRL_BREAK`, `WM_CLOSE`) came to
/// ([`SendAnswer`] says what each outcome means), left as what the last send did, and, on a tree
/// target, handed to the mechanism's route, whose answer is the call's.
#[cfg(windows)]
fn conclude(target: &StopTarget<'_>, name: &'static str, sent: SendAnswer) -> Result<(), Error> {
    match target.scope() {
        Scope::Root => {
            // Only a Unix mechanism's send can reach no process: a root send that did reads as one that sent
            // nothing.
            debug_assert!(
                !matches!(sent, SendAnswer::NoneReached(_)),
                "a Windows send is never `NoneReached`: {sent:?}"
            );
            match sent {
                SendAnswer::Sent(answer) => {
                    target.note_root_sent(name);
                    answer
                }
                // The event may have gone out, and the answer cannot say.
                SendAnswer::Unknown(unknown) => {
                    target.note_root_unknown(name);
                    Err(unknown)
                }
                // Nothing was sent, no stop is named as sent, and no refusal is logged for a root that had exited.
                SendAnswer::RootExited(_) | SendAnswer::NoneReached(Ok(())) => {
                    target.note_root_gone();
                    Ok(())
                }
                SendAnswer::NotSent(not_sent, kind) => {
                    target.note_not_sent(&not_sent, kind);
                    Err(not_sent)
                }
                SendAnswer::NoneReached(Err(not_sent)) => {
                    target.note_not_sent(&not_sent, UnsentKind::NotSent);
                    Err(not_sent)
                }
            }
        }
        Scope::Tree(call) => target.send_tree(call, crate::containment::TreeStop::named(name, sent)),
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
/// does nothing to such a child. A child created without the flag inherits this process's own state, which
/// is ignored when this process was itself created with the flag (a contained cosca child is, by default).
/// [`CtrlEvent::CtrlC`] therefore reaches a child only when its Ctrl+C is not ignored: a child created
/// without the flag by a process whose own is not ignored, or one that re-enables it itself. The proxy
/// re-enables Ctrl+C for itself and nothing else.
///
/// The child must have a console to attach to. A stop sent before the child has connected its console (it
/// has not run, or its start-up has not got that far) finds none, and so does a child that never has one.
/// The start-up connects the console before the child's own image runs any code (measured), so from then on
/// the attach succeeds and the event is sent, though the start-up is not over. When the attach finds none,
/// or fails as a child on this process's console fails it before its setup (Win32 error 31), and the child
/// has not exited, the call reads the child once, through the handle it holds, to tell the two apart:
///
/// - a child that finished starting without a console (`detached`, a GUI-subsystem program given
///   `no_window`, a program that freed its console): [`NotSent`](SendOutcome::NotSent). For an attach that
///   found no console the answer is an [`Error::Unsupported`] whose text says the child finished starting
///   without one, and not that it will never have one: a program can create or attach a console later. For
///   an attach that failed with Win32 error 31 it is the failed step's [`Error::Io`] (see `# Errors`);
/// - a child that had not set its console up when the proxy asked (it had not connected it yet, or did so
///   just after the attach): an [`Error::Unsupported`] with outcome
///   [`NotYet`](SendOutcome::NotYet). Nothing was sent, and asking again can succeed. The caller owns how
///   often and for how long it asks: cosca makes one read and one answer, starts nothing more and waits for
///   nothing;
/// - a read that cannot tell: the limit below. A read that fails is followed by one more look at whether the
///   child has exited, and a child that has is answered as one that had exited at the first look (see
///   `# A child that has exited`); a second look that itself fails is answered with that look's error, as a
///   failed first look is.
///
/// # How long "not yet" lasted
///
/// Measured, not promised: from the first read of a child as not yet started to the first attach that
/// succeeded, the median was 1.6 to 179 ms by setup on an idle host (longest 322 ms), 12.9 to 278 ms under
/// load (longest 387 ms). A child held before its console is connected (created suspended, or stopped that early by a debugger) is
/// not yet for as long as it is held.
///
/// # A limit: a child whose layout was not measured
///
/// The read is of a child native to the host, by a build of cosca for the host's architecture (x64 or
/// ARM64): the only layouts measured. For any other child (a 32-bit program, or an x64 program emulated on
/// ARM64), and when the read fails (on an ARM64 build it needs Windows 11, so on Windows 10 it always
/// fails; no version is checked and nothing falls back), cosca cannot tell whether the child had
/// finished starting, and guesses neither way. When the child has not exited, the answer for an attach that
/// found no console is [`Error::Unsupported`], outcome [`NotSent`](SendOutcome::NotSent), whose text says so
/// and whose `source()` is the failed read. The caller asks again, or ends the child with
/// [`Child::kill`](crate::Child::kill). When the look at the child's exit that follows a failed
/// read itself fails, the answer is that look's error, not this one, as it is for a failed first look.
///
/// # Waits
///
/// The call waits for the proxy's answer, with no cap unless the call that runs it was given a timeout
/// ([`Child::terminate_timeout`](crate::Child::terminate_timeout),
/// [`Child::terminate_tree_timeout`](crate::Child::terminate_tree_timeout),
/// [`Child::graceful_shutdown_timeout`](crate::Child::graceful_shutdown_timeout),
/// [`Child::graceful_shutdown_tree_timeout`](crate::Child::graceful_shutdown_tree_timeout)), warning once after
/// one second.
/// No state of
/// another process on the child's console was found to hold the proxy: a handler that never returns,
/// every thread suspended, a debugger holding the process, and an exit as the event is generated were
/// measured, and other states were not. A [`CtrlProxy::Executable`](crate::CtrlProxy::Executable) that
/// is not a proxy and does not exit holds a call given no timeout, and [`Child::kill`](crate::Child::kill) does not
/// release it: the wait is for the proxy, not for the child.
///
/// The wait blocks the calling thread. An async action awaits
/// `cosca::tokio::stop::send_console_event_via_proxy` (feature `tokio`) instead.
///
/// # Errors
///
/// Whether the event went out is the [`SendOutcome`] of the `terminate` or `terminate_tree` that runs this
/// function ([`StopError::outcome`]), not the error's variant: it is
/// [`Unknown`](SendOutcome::Unknown) for a proxy that ran and did not confirm its event, one that may have
/// run ([`Error::MayHaveStarted`]), one whose exit is no answer, and one that had not answered by the call's
/// timeout ([`Error::TimedOut`]), and
/// [`NotYet`](SendOutcome::NotYet) for a child that had not set its console up when the proxy asked (below), and
/// [`NotSent`](SendOutcome::NotSent) for every other error, whatever its variant (an
/// [`Error::Unassessable`] for a child that had exited among them, and an [`Error::TimedOut`] for a timeout
/// that was past before the proxy was started). The variants:
///
/// [`Error::Unsupported`], with, for the first two, nothing started (for a child that has not exited; see
/// below):
/// - the child is one a system service created on a UAC consent;
/// - the child has no identity ([`Child::id`](crate::Child::id) is `None`), which the proxy names its
///   target by, so that a reused pid is never sent an event;
/// - the proxy found no console to attach to for the child, the child had not exited when cosca looked,
///   and the read found that it had finished starting without one, as a child created with
///   [`detached`](crate::Command::detached) has none ([`NotSent`](SendOutcome::NotSent));
/// - the same, and the read found that the child had not set its console up when the proxy asked
///   ([`NotYet`](SendOutcome::NotYet)); the same for an attach that failed with Win32 error 31, which a
///   child on this process's console gives before its setup;
/// - the same for the attach that found no console, and cosca could not tell whether the child had finished
///   starting (the read failed, or the child's layout was not measured: see the limit above), with the
///   failed read as the `source()` ([`NotSent`](SendOutcome::NotSent)); for the attach that failed with
///   Win32 error 31 it is the failed step's `Io` below;
/// - the child's console is this process's own, which an event would reach as well (send
///   [`Ctrl+Break` to the child's group](send_ctrl_break_to_group) instead);
/// - the proxy's attach to the child's console was refused, and the child had not exited when cosca
///   looked;
/// - the program started does not speak this cosca's protocol version, or is no proxy.
///
/// An [`Error::Io`]: the proxy could not be started, or it failed before it
/// generated the event. For a proxy that failed a step (`FreeConsole`, `AttachConsole`, the generate, the
/// open of the child, and the like), the error's text names the step. When the failure was a Win32
/// error of 16 bits (nearly all are) that is not 0, it is the `source()` of the error, as an `io::Error`
/// with that OS code, and the error has that code's [`io::ErrorKind`](std::io::ErrorKind);
/// [`first_os_code`](crate::error::first_os_code) reads the code from the chain. A failure with no such
/// code has the kind `Other` and no source. The proxy carries step
/// and code in its exit code, so no output of the proxy is read. The failed-step answers that are not an
/// `Io` are those of `AttachConsole` with Win32 error 31 (the child's own console, before its setup): the
/// [`Unsupported`](Error::Unsupported) above with outcome [`NotYet`](SendOutcome::NotYet) for a child that
/// had not set its console up, and, for a child that had exited (at either look: see
/// `# A child that has exited`), the answer given there, as for every refused attach; the look's own error,
/// if the look fails, is the answer in its place. When the child had not exited and the read of it cannot
/// tell (it failed, or the layout was not measured), or finds it finished starting without a console, the
/// answer is the failed step's `Io`, with the OS code 31 as its `source()` (the read's failure is not in the chain).
/// Every other step that fails before the event is generated is an `Io`.
///
/// [`Error::Unassessable`]: the proxy ended without a known answer, or generated the event and did not see
/// its own copy: the console closed, or the proxy's wait for the copy failed. For the failed wait the
/// error's text names the call (`WaitForMultipleObjects`) and, when the failure was a Win32 error of 16 bits
/// that is not 0, the `source()` is an [`Error::Io`] holding an `io::Error` with that OS code
/// ([`first_os_code`](crate::error::first_os_code) reads it); with no such code the error has no source.
/// [`Error::MayHaveStarted`], from the start of the proxy, says the proxy may have run.
///
/// [`Error::TimedOut`], from a call given a timeout: the proxy had not answered by it and cosca ended it
/// (the proxy may have sent: no member is named), or the timeout was past before the proxy was started
/// (nothing was started or sent).
///
/// On a tree target, an error whose outcome is [`Unknown`](SendOutcome::Unknown) still goes on to the grace
/// and sweep, with that error as the cooperative error; every other error, `Unsupported` included, ends the
/// call as a refused send.
///
/// # A child that has exited
///
/// After the check under `# Panics`, the call's first act is one look at the child through its handle,
/// which reaps nothing. A child that has exited is answered then, before any rule above and with nothing
/// started: nothing was sent. On a root target the answer is `Ok`, as
/// [`send_ctrl_break_to_group`] answers an exited child that leads a group. On a tree target
/// `terminate_tree` answers an error, and `graceful_shutdown_tree` goes on to its grace, sweep and reap
/// with no event sent: members that outlived the root are ended by the sweep without a console event,
/// where the direct send to the group would have reached them.
///
/// A child that exits after that look is answered the same way when the proxy's attach does not succeed
/// (no console, refused, or Win32 error 31) and a look made after the proxy's answer finds the child
/// exited: one look before the read of the child, and, when that read fails (as the read of an exited
/// process does), one more after it. A read that succeeds needs no second look.
///
/// # Panics
///
/// Panics when this call would start this program as the proxy and `init_helpers` was never called; see
/// [`default`](crate::stop::default#panics) for the condition.
#[cfg(windows)]
pub fn send_console_event_via_proxy(target: &StopTarget<'_>, event: CtrlEvent) -> Result<(), Error> {
    crate::child::graceful::shutdown::run_ready(proxy::send(
        &crate::child::graceful::shutdown::BlockingDriver(target.child()),
        target,
        event,
    ))
}

/// Windows: asks the child's windows to close, and does not wait.
///
/// It posts `WM_CLOSE` to the top-level windows of the target's processes that are **visible and have no
/// owner**: a tool window is one of them, a hidden window and an owned one (a dialog, an input-method
/// helper) are not. A window of a console (class `ConsoleWindowClass` or `PseudoConsoleWindow`) is never
/// posted to, whichever process it is listed under: the system turns a close of a `ConsoleWindowClass`
/// window into `CTRL_CLOSE_EVENT` for every process on that console, and what a post to the other class does
/// was not established. A window whose class cannot be read is not asked.
/// A GUI program that handles `WM_CLOSE` by default closes its main window and exits; one that handles it
/// itself may prompt, or refuse. The call does not wait for the program: wait with
/// [`StopTarget::wait_exit`], or let `graceful_shutdown` do it.
///
/// On a root target the windows are the child's. On a tree target they are those of every member of the
/// contained tree, as its mechanism lists them (the root among them), so a descendant's window may be
/// asked to close though its parent would also have sent it a close.
///
/// This is not what [`default`] does for a child with no console: pick it with
/// `Command::graceful_stop(|target| stop::send_wm_close(target))`.
///
/// # What the windows are
///
/// The send reads the windows of the calling thread's desktop once, and asks each window of a process in
/// turn. A process is opened by its identity and held while its windows are asked, so its pid cannot be
/// taken by another program meanwhile, and right before each post the window's owning process is read
/// again and must still be that process. Windows has no call that posts only to a window that belongs to a
/// given process, so the owner check and the post are back to back. A window that was destroyed in between,
/// or whose handle value another program's window took, is told by the check; what is left is a window
/// destroyed and replaced by another program's after that read. A handle value recurs only after 32765
/// reallocations of its slot.
///
/// # Errors
///
/// A send went out when at least one window was posted to. A window that was refused or failed while another
/// was posted to, and a member that could not be named or opened, is warned of, and the call is `Ok`.
/// Otherwise nothing was sent, each other miss is warned of, and the answer is the
/// first row that applies:
///
/// - the child has no identity ([`Child::id`](crate::Child::id) is `None`): [`Error::Unsupported`];
/// - the windows of the desktop, or the members of the tree, could not be listed: [`Error::Io`] or the
///   listing's own error;
/// - a post failed with an error other than a refusal, or a member could not be named or opened:
///   [`Error::Io`], with that error as its cause;
/// - every post was refused (`ERROR_ACCESS_DENIED`: the window belongs to a program of higher integrity, or
///   has a message filter, which is set per window): [`Error::Unsupported`], whose
///   [`source`](std::error::Error::source) is that error;
/// - no window was asked and the child had exited when cosca looked: `Ok` on a root target whose child has an
///   identity, and on a tree target the tree call's own answer (see the module doc). A child with no identity
///   is refused as above, exited or not;
/// - no window was asked: [`Error::Unsupported`], which says the process shows no visible top-level window
///   without an owner on this desktop, and names [`Child::kill`](crate::Child::kill).
///
/// # Limits
///
/// Each is an [`Error::Unsupported`] with nothing sent, or a window that is not asked, and
/// [`Child::kill`](crate::Child::kill) is the alternative.
///
/// - **A program with no visible window without an owner is not asked:** one that keeps its window hidden or
///   lives in the notification area. Hidden windows are not a fallback.
/// - **Before the child has shown its window,** it has none to ask. A child that was just created can be
///   refused as one with no window; a caller that has observed output or a handshake from the child is past
///   that window. A caller that wants the child gone before it has run at all uses `Child::kill`.
/// - **The calling thread's desktop only.** A window on another desktop or in another session is not
///   listed, so a child that moved itself to one is refused as one with no window.
#[cfg(windows)]
pub fn send_wm_close(target: &StopTarget<'_>) -> Result<(), Error> {
    crate::child::graceful::shutdown::run_ready(send_wm_close_with(
        &crate::child::graceful::shutdown::BlockingDriver(target.child()),
        target,
    ))
}

/// Windows: the one body of [`send_wm_close`], for the driver that blocks and the one that awaits, which
/// make only looks at the root.
#[cfg(windows)]
pub(crate) async fn send_wm_close_with<D: StopWaits>(driver: &D, target: &StopTarget<'_>) -> Result<(), Error> {
    wm_close::send(driver, target).await
}

#[cfg(test)]
#[path = "stop_tests.rs"]
mod stop_tests;
