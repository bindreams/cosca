//! Windows: `stop::send_wm_close`'s one body ([`send`]): the windows of the target's processes, which of
//! them a stop asks, and what the posts come to. A hidden window, an owned one and a console's are not asked.

use std::ffi::c_void;
use std::io;
use std::time::Duration;

use windows::core::BOOL;
use windows::Win32::Foundation::{
    SetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_WINDOW_HANDLE, HWND, LPARAM, WIN32_ERROR, WPARAM,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindow, GetWindowThreadProcessId, IsWindowVisible, PostMessageW, GW_OWNER, WM_CLOSE,
};

use super::{conclude, root_exited, unsupported, Scope, StopTarget, StopWaits, REMEDIES};
use crate::containment::mechanism::Members;
use crate::containment::{SendAnswer, UnsentKind};
use crate::error::{io_context, io_context_over, win32_io_error, Error};
use crate::identity::{Kernel, ProcessId};

/// The stop's name, as a tree route and the sweep's error word it.
const NAME: &str = "WM_CLOSE";

/// The classes of a console's window. A post to a `ConsoleWindowClass` window is `CTRL_CLOSE_EVENT` for
/// every process on that console, so no post to either class is made, whatever process the window is
/// listed under.
const CONSOLE_CLASSES: [&str; 2] = ["ConsoleWindowClass", "PseudoConsoleWindow"];

const NO_IDENTITY_REASON: &str = "this child has no identity (Child::id() is None), and the windows are asked \
     only of a process named by identity, so that a window of a process that took a reused pid is never sent a \
     close: it cannot be named exactly.";

// The rule -----

/// What kind of window a class names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Class {
    /// The class could not be read: the window is not asked, and counts as gone.
    Unread,
    /// A console's window ([`CONSOLE_CLASSES`]).
    Console,
    /// Any other class, by name.
    Other(String),
}

impl Class {
    /// The kind of window the class `name` names. Class names compare without regard to case, as Windows
    /// compares them.
    pub(super) fn of(name: &str) -> Class {
        if CONSOLE_CLASSES.iter().any(|class| class.eq_ignore_ascii_case(name)) {
            Class::Console
        } else {
            Class::Other(name.to_owned())
        }
    }
}

/// One top-level window, as one `EnumWindows` pass read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Listed {
    /// An `isize`, not an `HWND`, so the record is `Send`.
    pub(super) hwnd: isize,
    /// The process that owns the window's thread.
    pub(super) pid: u32,
    pub(super) visible: bool,
    /// The window has an owner (`GetWindow(GW_OWNER)`), or its owner could not be read.
    pub(super) has_owner: bool,
    pub(super) class: Class,
}

/// A window the rule selects, with the name of its class, which the rule has read.
#[derive(Debug)]
pub(super) struct Asked<'a> {
    pub(super) window: &'a Listed,
    pub(super) class: &'a str,
}

/// The windows of the process `pid` that a stop asks: those that are visible, have no owner, and have a
/// class that was read and is not a console's.
pub(super) fn asked(listing: &[Listed], pid: u32) -> Vec<Asked<'_>> {
    listing
        .iter()
        .filter_map(|window| match &window.class {
            Class::Other(class) if window.pid == pid && window.visible && !window.has_owner => {
                Some(Asked { window, class })
            }
            _ => None,
        })
        .collect()
}

// What the posts came to -----

/// What one window came to.
#[derive(Debug)]
pub(super) enum Window {
    /// `PostMessageW` returned true.
    Posted,
    /// The window's owner, read right before the post, is another process or none, or the post failed with
    /// `ERROR_INVALID_WINDOW_HANDLE`: neither a post nor a failure.
    Gone,
    /// The window was there and was not posted to.
    Unposted(Unposted),
}

/// A window that was not posted to, though it was there.
#[derive(Debug)]
pub(super) struct Unposted {
    pub(super) pid: u32,
    pub(super) class: String,
    pub(super) why: Why,
}

/// A process whose windows were not asked, because it could not be opened or named.
#[derive(Debug)]
pub(super) struct Unasked {
    /// What happened to the process, not what the stop made of it.
    pub(super) cause: Error,
}

/// What a stop did not do though it was to: post to a window, or ask a process's windows.
pub(super) type Missed = Result<Unposted, Unasked>;

/// Why a window was not posted to.
#[derive(Debug)]
pub(super) enum Why {
    /// `ERROR_ACCESS_DENIED`: a window of higher integrity, or a message filter, which is per window.
    Refused,
    /// Any other failure, with its cause: what happened to the window.
    Failed(io::Error),
}

fn window_subject(pid: u32, class: &str) -> String {
    format!("a window of class {class:?} of pid {pid}")
}

impl Unposted {
    fn subject(&self) -> String {
        window_subject(self.pid, &self.class)
    }
}

/// What the windows of every process asked come to: the first row that applies is the answer.
#[derive(Debug)]
pub(super) enum Fold {
    /// At least one window was posted to: the send went out. Each window not posted to and each process not
    /// asked is here, to be warned of.
    Sent(Vec<Missed>),
    /// No post, and at least one failure: the first's cause, and every other miss, to be warned of. Nothing
    /// was sent.
    Failed { first: Error, others: Vec<Missed> },
    /// No post and no failure, and at least one refusal: the first, and the other refusals, to be warned
    /// of. Nothing was sent.
    Refused { first: Unposted, others: Vec<Unposted> },
    /// No window was asked, or every one asked was gone.
    NothingAsked,
}

/// The fold of what asking each process came to (a window's result each, or that the process was not
/// asked), in the order they were asked (see [`Fold`]).
pub(super) fn fold(came: Vec<Result<Window, Unasked>>) -> Fold {
    let mut posted = false;
    let mut missed = Vec::new();
    for one in came {
        match one {
            Ok(Window::Posted) => posted = true,
            Ok(Window::Gone) => {}
            Ok(Window::Unposted(window)) => missed.push(Ok(window)),
            Err(process) => missed.push(Err(process)),
        }
    }
    if posted {
        return Fold::Sent(missed);
    }
    // The refusals before the first failure, then the first failure, if any.
    let mut missed = missed.into_iter();
    let mut refusals = Vec::new();
    let failure = missed.by_ref().find_map(|one| match failure_of(one) {
        Ok(cause) => Some(cause),
        Err(refusal) => {
            refusals.push(refusal);
            None
        }
    });
    if let Some(first) = failure {
        let others = refusals.into_iter().map(Ok).chain(missed).collect();
        return Fold::Failed { first, others };
    }
    // No failure: every miss is a refusal.
    let mut refusals = refusals.into_iter();
    match refusals.next() {
        Some(first) => Fold::Refused {
            first,
            others: refusals.collect(),
        },
        None => Fold::NothingAsked,
    }
}

/// The cause of a miss that is a failure (a process not asked, or a post that failed); a refusal is handed
/// back.
fn failure_of(missed: Missed) -> Result<Error, Unposted> {
    match missed {
        Err(Unasked { cause }) => Ok(cause),
        Ok(Unposted {
            why: Why::Failed(cause),
            ..
        }) => Ok(Error::Io(cause)),
        Ok(refusal) => Err(refusal),
    }
}

/// Warns of one window or process that a stop missed, in the cause's own words; `went_out`: another window
/// was posted to.
fn warn_of(missed: &Missed, went_out: bool) {
    match missed {
        Ok(window @ Unposted { why: Why::Refused, .. }) => warn_refused(window, went_out),
        Ok(Unposted {
            why: Why::Failed(cause),
            ..
        }) => log::warn!("{}: {}", lead(went_out), crate::error::Report(cause)),
        Err(unasked) => warn_unasked(unasked, went_out),
    }
}

fn lead(went_out: bool) -> &'static str {
    if went_out {
        "WM_CLOSE was sent to another window, but not to every window asked"
    } else {
        "WM_CLOSE was not sent to every window asked"
    }
}

fn warn_refused(window: &Unposted, went_out: bool) {
    log::warn!(
        "WM_CLOSE was refused by {} (error {}){}",
        window.subject(),
        ERROR_ACCESS_DENIED.0,
        if went_out {
            ", while another window was sent it"
        } else {
            ""
        }
    );
}

fn warn_unasked(unasked: &Unasked, went_out: bool) {
    log::warn!("{}: {}", lead(went_out), crate::error::Report(&unasked.cause));
}

fn warn_all(missed: &[Missed], went_out: bool) {
    for one in missed {
        warn_of(one, went_out);
    }
}

/// What `folded` is as the send's answer, warning of each window or process that was not posted to or
/// asked and is not the answer's cause; `None` for [`Fold::NothingAsked`], which the caller answers.
pub(super) fn answer(folded: Fold) -> Option<SendAnswer> {
    match folded {
        Fold::Sent(missed) => {
            warn_all(&missed, true);
            Some(SendAnswer::Sent(Ok(())))
        }
        Fold::Failed { first, others } => {
            warn_all(&others, false);
            Some(SendAnswer::NotSent(
                Error::Io(io_context_over("nothing was sent", first)),
                UnsentKind::NotSent,
            ))
        }
        Fold::Refused { first, others } => {
            for refusal in &others {
                warn_refused(refusal, false);
            }
            Some(SendAnswer::NotSent(
                unsupported(
                    format!(
                    "every window that was asked refused WM_CLOSE (the first: {}), as a window of higher integrity or \
                     one with a message filter does, so nothing was sent. {REMEDIES}",
                    first.subject()
                ),
                    Some(Error::io_cause(io::Error::from_raw_os_error(
                        ERROR_ACCESS_DENIED.0 as i32,
                    ))),
                ),
                UnsentKind::NotSent,
            ))
        }
        Fold::NothingAsked => None,
    }
}

/// The answer for a target none of whose processes shows a visible top-level window: it is what a program
/// that keeps its window hidden, or lives in the notification area, gets, and so does a child that has not
/// shown its window yet.
fn no_visible_window(tree: bool) -> Error {
    let who = if tree {
        "no member of the contained tree shows"
    } else {
        "the process shows"
    };
    unsupported(
        format!(
            "{who} a visible top-level window without an owner on this desktop, which is all WM_CLOSE is posted \
             to, so nothing was sent. That covers a program that keeps its window hidden or lives in the \
             notification area, a child that has not shown its window yet, a window on another desktop or in \
             another session, and a console program (a console's window is never posted to). {REMEDIES}"
        ),
        None,
    )
}

// The OS half -----

/// What one `EnumWindows` pass collects: the windows of `pids`.
struct Collecting<'a> {
    pids: &'a [u32],
    listing: Vec<Listed>,
}

/// The top-level windows of this thread's desktop that belong to one of `pids`, read by one `EnumWindows`
/// pass. Each window's owning process is read first, and the rest of a window is read only for a window of
/// one of `pids`.
fn list_windows(pids: &[u32]) -> io::Result<Vec<Listed>> {
    let mut collecting = Collecting {
        pids,
        listing: Vec::new(),
    };
    // `EnumWindows` answers FALSE both for a failure and for a desktop with no top-level window, and a stale
    // last error would read as the first: clear it first.
    // SAFETY: sets this thread's last error.
    unsafe { SetLastError(WIN32_ERROR(0)) };
    // SAFETY: `collect` reads `lparam` only as the `Collecting` this call lends it, which `EnumWindows` does not
    // keep past its return.
    match unsafe { EnumWindows(Some(collect), LPARAM(&raw mut collecting as isize)) } {
        Ok(()) => {}
        // FALSE with no error: the desktop has no top-level window (measured on CI, run 45442280861: 160 of 160
        // passes, a fresh desktop on `WinSta0` included).
        Err(e) if e.code().is_ok() => debug_assert!(collecting.listing.is_empty()),
        Err(e) => return Err(win32_io_error(e)),
    }
    Ok(collecting.listing)
}

/// `EnumWindows`'s callback: reads `hwnd` into the `Collecting` that `lparam` points to, if it is wanted.
unsafe extern "system" fn collect(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: `list_windows` passed a live `&mut Collecting`, and `EnumWindows` calls this on its thread.
    let collecting = unsafe { &mut *(lparam.0 as *mut Collecting<'_>) };
    let mut pid = 0u32;
    // SAFETY: `pid` is a live out-parameter.
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    if collecting.pids.contains(&pid) {
        collecting.listing.push(read(hwnd, pid));
    }
    BOOL(1)
}

/// Logs a failed call on a window of the asked process `pid` whose failure the send answers by the safe
/// side (not asked, or gone), with the OS error the call left.
fn swallowed(pid: u32, call: &str, error: io::Error) {
    log::debug!(
        "WM_CLOSE: {call} on a window of pid {pid} failed: {report}",
        report = crate::error::Report(&error)
    );
}

/// What the OS says of `hwnd`, a window of the process `pid`, now.
fn read(hwnd: HWND, pid: u32) -> Listed {
    // SAFETY: a call with a handle value only; a stale one is answered false.
    let visible = unsafe { IsWindowVisible(hwnd) }.as_bool();
    // `GetWindow` answers null both for "no owner" and for a failure, and a stale last error would read
    // as the second: clear it first. A failure (the window is gone) leaves the window unasked.
    // SAFETY: sets this thread's last error.
    unsafe { SetLastError(WIN32_ERROR(0)) };
    // SAFETY: a call with a handle value only.
    let has_owner = match unsafe { GetWindow(hwnd, GW_OWNER) } {
        Ok(_) => true,
        // Null with no error: the window has no owner.
        Err(e) if e.code().is_ok() => false,
        Err(e) => {
            swallowed(pid, "GetWindow(GW_OWNER)", win32_io_error(e));
            true
        }
    };
    // Class names are at most 256 characters; +1 for the NUL.
    let mut name = [0u16; 257];
    // SAFETY: `name` is a live buffer, and its length is passed.
    let read = unsafe { GetClassNameW(hwnd, &mut name) };
    let class = match usize::try_from(read) {
        Ok(len) if len > 0 => Class::of(&String::from_utf16_lossy(&name[..len])),
        _ => {
            swallowed(pid, "GetClassNameW", io::Error::last_os_error());
            Class::Unread
        }
    };
    Listed {
        hwnd: hwnd.0 as isize,
        pid,
        visible,
        has_owner,
        class,
    }
}

/// Asks the windows of the process `id` that the rule selects from `listing`, and what each came to, or that
/// the process was not asked. A process with no window to ask is not opened. Otherwise it is opened through
/// `kernel` by its identity (a process that is gone has no windows to ask) and held until its last post, so
/// its pid cannot be taken by another program while its windows are asked; each window's owner is read again
/// right before its post, which is made only if it still names the process.
fn ask(listing: &[Listed], kernel: &dyn Kernel, id: ProcessId) -> Vec<Result<Window, Unasked>> {
    let to_ask = asked(listing, id.pid());
    if to_ask.is_empty() {
        return Vec::new();
    }
    let held = match crate::os_process::open_with(kernel, id) {
        Ok(Some(held)) => held,
        Ok(None) => return Vec::new(),
        Err(failure) => {
            return vec![Err(Unasked {
                cause: failure.into_open_error(),
            })]
        }
    };
    let came = to_ask.into_iter().map(|asked| Ok(post(asked))).collect();
    drop(held);
    came
}

/// `WM_CLOSE` to `asked`, if its owner is still the process it was listed under.
fn post(asked: Asked<'_>) -> Window {
    let Asked { window, class } = asked;
    let hwnd = HWND(window.hwnd as *mut c_void);
    let mut owner = 0u32;
    // SAFETY: `owner` is a live out-parameter; a stale handle value is answered 0.
    let thread = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner)) };
    if thread == 0 {
        swallowed(window.pid, "GetWindowThreadProcessId", io::Error::last_os_error());
    }
    if owner != window.pid {
        return Window::Gone;
    }
    // SAFETY: a call with a handle value only; a stale one is answered with an error.
    match unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) } {
        Ok(()) => Window::Posted,
        Err(e) => after_failed_post(window.pid, class, win32_io_error(e)),
    }
}

/// What a window of class `class` of the process `pid` came to, when its post failed with `error`.
fn after_failed_post(pid: u32, class: &str, error: io::Error) -> Window {
    let unposted = |why| {
        Window::Unposted(Unposted {
            pid,
            class: class.to_owned(),
            why,
        })
    };
    match error.raw_os_error().map(|code| code as u32) {
        Some(code) if code == ERROR_INVALID_WINDOW_HANDLE.0 => Window::Gone,
        Some(code) if code == ERROR_ACCESS_DENIED.0 => unposted(Why::Refused),
        _ => unposted(Why::Failed(io_context(
            format!("WM_CLOSE could not be posted to {}", window_subject(pid, class)),
            error,
        ))),
    }
}

// The send -----

/// The identity of the root, for a root target whose child has one: the process whose windows a root target
/// asks. A tree target asks its members', so it has none.
fn root_identity(target: &StopTarget<'_>) -> Option<ProcessId> {
    match target.scope() {
        Scope::Root => target.id(),
        Scope::Tree(_) => None,
    }
}

/// The send, made without waiting: `None` when no window was asked; [`outcome`] then looks at the root.
fn attempt(target: &StopTarget<'_>) -> Option<SendAnswer> {
    let not_sent = |error| Some(SendAnswer::NotSent(error, UnsentKind::NotSent));
    if target.id().is_none() {
        return not_sent(unsupported(format!("{NO_IDENTITY_REASON} {REMEDIES}"), None));
    }
    let Members { named, unnamed } = match root_identity(target) {
        Some(id) => Members {
            named: vec![id],
            unnamed: Vec::new(),
        },
        None => {
            debug_assert!(
                target.covers_tree(),
                "a root target has the identity the refusal above checked"
            );
            match target.child().tree.member_ids() {
                Ok(members) => members,
                Err(listing_failed) => return not_sent(listing_failed),
            }
        }
    };
    let unasked: Vec<Unasked> = unnamed.into_iter().map(|cause| Unasked { cause }).collect();
    let mut came = Vec::new();
    // With no process to ask, the desktop is not listed: a listing that fails would turn that case into a
    // failure of the send.
    if !named.is_empty() {
        let pids: Vec<u32> = named.iter().map(ProcessId::pid).collect();
        let listing = match list_windows(&pids) {
            Ok(listing) => listing,
            Err(e) => {
                for one in &unasked {
                    warn_unasked(one, false);
                }
                return not_sent(Error::Io(io_context(
                    "nothing was sent: the windows of this desktop could not be listed",
                    e,
                )));
            }
        };
        let kernel = target.child().proc.kernel();
        came.extend(named.into_iter().flat_map(|id| ask(&listing, kernel, id)));
    }
    came.extend(unasked.into_iter().map(Err));
    answer(fold(came))
}

/// The answer for a root that had exited when it was looked at, and for which no window was asked.
fn exited(target: &StopTarget<'_>) -> SendAnswer {
    SendAnswer::RootExited(root_exited(
        &format!(
            "the child (pid {}) had exited when cosca looked, and no window of it was asked",
            target.pid()
        ),
        "no window of a member of its tree that outlived it was asked",
    ))
}

/// How the send went: on a root target with an identity, one look at the root first, so that a root that has
/// exited costs no window listing; then [`attempt`], and when no window was asked, one look at the root.
async fn outcome<D: StopWaits>(driver: &D, target: &StopTarget<'_>) -> SendAnswer {
    if root_identity(target).is_some() {
        match driver.root_exited(Duration::ZERO).await {
            Ok(true) => return exited(target),
            Ok(false) => {}
            Err(look_failed) => log::debug!(
                "WM_CLOSE: the first look at the root (pid {}) failed, the send goes on: {look_failed}",
                target.pid()
            ),
        }
    }
    match attempt(target) {
        Some(sent) => sent,
        None => match driver.root_exited(Duration::ZERO).await {
            Ok(true) => exited(target),
            Ok(false) => SendAnswer::NotSent(no_visible_window(target.covers_tree()), UnsentKind::NotSent),
            Err(look_failed) => SendAnswer::NotSent(look_failed, UnsentKind::NotSent),
        },
    }
}

/// The one body of `stop::send_wm_close` for any [`StopWaits`] driver.
pub(super) async fn send<D: StopWaits>(driver: &D, target: &StopTarget<'_>) -> Result<(), Error> {
    conclude(target, NAME, outcome(driver, target).await)
}

#[cfg(test)]
#[path = "wm_close_tests.rs"]
mod wm_close_tests;

#[cfg(test)]
#[path = "wm_close_real_tests.rs"]
mod wm_close_real_tests;
