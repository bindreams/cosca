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
//! **Windows.** The prepared sends deliver a console event, and the containment mechanism sends nothing
//! of its own, so a root target and a tree target reach the same processes:
//!
//! | Send | The event reaches |
//! |---|---|
//! | direct (`send_ctrl_break_to_group`) | when the child is on this process's console, every process in its console process group: the child, and the descendants that stayed in the group, not a nested contained descendant, which leads a group of its own. A child with a console of its own, or with none, is sent nothing, and the send still answers `Ok` |
//! | through the proxy (`send_console_event_via_proxy`) | every process on the child's console, in whatever process group: the child, its descendants that share the console, and any other process attached to it |
//!
//! Neither reaches a descendant that has a console of its own or was started detached. A root that has
//! already exited changes what the proxy reaches: it sends nothing, even to descendants on the root's
//! console, which `graceful_shutdown_tree`'s sweep ends, where the direct send to the group would still
//! reach them (see `send_console_event_via_proxy`).
//!
//! # Choosing an action
//!
//! [`Command::graceful_stop`](crate::Command::graceful_stop) takes a function of a [`StopTarget`]; it
//! gives the signature and says what the call does with the function's answer. Four ways to write one:
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
//! // `cosca::init()` is the first call of this program's `main`.
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
//! - **The proxy needs a host that called [`init`](crate::init)**, or a `Command::ctrl_proxy` naming the
//!   `cosca-ctrl-proxy` executable: see `CtrlProxy`.
//! - **A stop sent before the child has set its console up.** A proxy-routed child can look like one with
//!   no console: see [`default`].
//! - **The wait for the proxy has no cap, and the grace starts when the action returns:** see
//!   `send_console_event_via_proxy` and
//!   [`Child::graceful_shutdown_tree`](crate::Child::graceful_shutdown_tree).
//! - **A front that does not relay the signal.** An elevated child behind such a front is refused the
//!   signal, with nothing sent: see `send_signal`.
//! - **A direct send's success does not prove delivery:** see [`Child::terminate`](crate::Child::terminate).

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
///    [`cosca::init()`](crate::init) (see `send_console_event_via_proxy`).
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
///   child alone, and one sent to the console would reach this process as well. No proxy is started, so
///   `init` is not needed. The direct send refuses before it looks at the child, so the refusal is the same
///   for a child that has exited, where every other child that has exited is answered `Ok` (see
///   [`Child::terminate`](crate::Child::terminate)).
/// - Case 3, the host program has not called `init` and the command names no `CtrlProxy::Executable`: the
///   error names `cosca::init()` and the `Executable` setting. Nothing is started.
/// - Case 3, the child has no identity to name it by: the error names `Child::kill`. Nothing is started.
/// - Case 3, a child a system elevation service created on a UAC consent: the error names `kill()`. Nothing
///   is started.
/// - Case 3, the child has no console to attach to (`detached()`, or a GUI-subsystem program given
///   `no_window`), or has not set one up yet: the proxy finds none and the error names `Child::kill`.
/// - Case 3, the child's console is also this process's own (one changed console after the spawn): an event
///   sent there would reach this process too. The error names `stop::send_ctrl_break_to_group`, and
///   `Command::new_process_group` for a child that leads no group.
///
/// **Before the child has run.** A child that has not set its console up yet looks like one without a
/// console, so a stop sent to a just-spawned child of case 3 can be refused as in the case 3 item for a
/// child with no console to attach to, and the graceful calls end there with the child running. A caller
/// that has observed output or a handshake from the child is past that window. A caller that wants the
/// child gone before it has run at all uses `Child::kill`.
///
/// The route is chosen from what was true at the spawn, so a caller that changes its own console
/// afterwards (frees it, attaches another) sets an explicit action. A child that was created on this
/// process's console and later moved to a console of its own is not reached: the default refuses one that
/// leads no group, and sends one that leads a group a break that reaches nobody (see
/// `send_ctrl_break_to_group`). It stays reachable through an explicit
/// `graceful_stop(|t| stop::send_console_event_via_proxy(t, CtrlEvent::CtrlBreak))`.
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
/// does nothing to such a child. A child created without the flag inherits this process's own state, which
/// is ignored when this process was itself created with the flag (a contained cosca child is, by default).
/// [`CtrlEvent::CtrlC`] therefore reaches a child only when its Ctrl+C is not ignored: a child created
/// without the flag by a process whose own is not ignored, or one that re-enables it itself. The proxy
/// re-enables Ctrl+C for itself and nothing else.
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
/// [`Error::Unsupported`], with nothing sent and, for the first three, nothing started (for a child that
/// has not exited; see below):
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
/// The call's first act is one look at the child through its handle, which reaps nothing. A child that
/// has exited is answered then, before any rule above and with nothing started (so a host that has not
/// called `init` gets the answer too): nothing was sent. On a root target the answer is `Ok`, as
/// [`send_ctrl_break_to_group`] answers an exited child that leads a group. On a tree target `terminate_tree` answers an
/// error, and `graceful_shutdown_tree` goes on to its grace, sweep and reap with no event sent: members
/// that outlived the root are ended by the sweep without a console event, where the direct send to the
/// group would have reached them.
///
/// A child that exits after that look is answered the same way when the proxy cannot attach and cosca's
/// look at the proxy's answer finds the child exited.
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
