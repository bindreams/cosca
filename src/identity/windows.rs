//! Windows process-identity backend.
//!
//! - `start_token`: raw creation `FILETIME` (identity, NOT epoch-adjusted).
//! - `created_at`: that 100 ns-since-1601 value converted to `SystemTime`.
//! - `ordered_read`: the id's key and the `OrderKey` (the process sequence number, through the
//!   private `NtQueryInformationProcess` class 92), read on one handle; when asked, also the
//!   creator pid (class 0), on the same handle.
//! - `is_running`: authoritative "not exited" via `WaitForSingleObject(_, 0)`, which tests
//!   the process's *signaled state* — so it flips to dead the instant the process exits,
//!   without the object-teardown window that an existence check (`OpenProcess` succeeding)
//!   would have. Reading the signaled state needs `SYNCHRONIZE`; when only
//!   `PROCESS_QUERY_LIMITED_INFORMATION` is granted, `GetExitCodeProcess` can still prove an
//!   exit but not the absence of one.
//!
//! An `OpenProcess` failure is classified, never collapsed: `ERROR_INVALID_PARAMETER` is the
//! OS saying "no such pid" and is the ONLY failure that means absence. Everything else —
//! `ERROR_ACCESS_DENIED` above all — means we were not allowed to ask.

use std::time::{Duration, SystemTime};

use windows::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation, PROCESSINFOCLASS};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, NTSTATUS, STILL_ACTIVE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess, TerminateProcess, WaitForSingleObject,
    PROCESS_ACCESS_RIGHTS, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE,
};
use windows::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;

use super::{Key, Liveness, OrderKey, OrderedRead, ParentRead, RawPid, Resolved, UnknownCause};

/// 100 ns intervals between 1601-01-01 (FILETIME epoch) and 1970-01-01 (Unix).
const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;

/// The `OpenProcess` failure that means "no such pid". Derived, never hand-packed: this
/// constant is the crate's whole classification rule, and one wrong nibble in a literal
/// would silently reclassify every access-denied process as gone.
pub(crate) const ERROR_INVALID_PARAMETER_HRESULT: windows::core::HRESULT =
    windows::core::HRESULT::from_win32(ERROR_INVALID_PARAMETER.0);

/// The outcome of a classified `OpenProcess`. `Denied` carries the failure because a caller
/// that has to report it cannot recover it afterwards: `GetLastError` is thread-global and
/// every intervening call overwrites it.
pub(crate) enum Opened {
    Found(HANDLE),
    /// `ERROR_INVALID_PARAMETER` — the OS's "no such pid". The ONLY failure meaning absence.
    Gone,
    /// Anything else, `ERROR_ACCESS_DENIED` above all: we were not allowed to ask.
    Denied(windows::core::Error),
}

/// `OpenProcess` with `mask`, classified. The crate's single rule. The caller closes the
/// handle.
pub(crate) fn open_classified(pid: RawPid, mask: PROCESS_ACCESS_RIGHTS) -> Opened {
    // SAFETY: OpenProcess tolerates any pid value (it returns Err).
    match unsafe { OpenProcess(mask, false, pid) } {
        Ok(h) => Opened::Found(h),
        Err(e) if e.code() == ERROR_INVALID_PARAMETER_HRESULT => Opened::Gone,
        // `debug`, not `warn`: the tree-walk calls this once per pid per sweep. The event is
        // reported at `warn` exactly once, by the call site that decided what the denial
        // means; this line is the per-call detail — which pid, which mask — that those
        // messages cannot carry.
        Err(e) => {
            log::debug!(
                "OpenProcess({pid}, {mask:?}) failed: {report} — reporting Unknown, not absence",
                report = crate::error::Report(&e)
            );
            Opened::Denied(e)
        }
    }
}

/// `OpenProcess` for `PROCESS_QUERY_LIMITED_INFORMATION` plus as many of `optional` as the process
/// grants, and the rights granted. Tries every subset of `optional`, the largest first and, among
/// equals, the earlier rights first, down to the query right alone. A right is dropped only when its
/// open fails with `ERROR_ACCESS_DENIED`; `Gone` and any other failure end the search. A final
/// denial is [`Opened::Denied`] of the query-only attempt. The caller closes the handle.
pub(crate) fn open_dropping_refused(
    pid: RawPid,
    optional: &[PROCESS_ACCESS_RIGHTS],
) -> (Opened, PROCESS_ACCESS_RIGHTS) {
    debug_assert!(optional.len() < 32, "a subset of the optional rights is a u32 mask");
    let mut subsets: Vec<u32> = (0..1u32 << optional.len()).collect();
    subsets.sort_by_key(|subset| (std::cmp::Reverse(subset.count_ones()), *subset));
    let mut denied = None;
    for subset in subsets {
        let rights = optional
            .iter()
            .enumerate()
            .filter(|(i, _)| subset >> i & 1 == 1)
            .fold(PROCESS_QUERY_LIMITED_INFORMATION, |rights, (_, right)| rights | *right);
        match open_classified(pid, rights) {
            Opened::Denied(e) if is_access_denied(&e) => denied = Some((e, rights)),
            opened => return (opened, rights),
        }
    }
    let (e, rights) = denied.expect("the empty subset is always tried");
    (Opened::Denied(e), rights)
}

pub(crate) fn close(handle: HANDLE) {
    // SAFETY: `handle` is an owned process handle.
    if let Err(e) = unsafe { CloseHandle(handle) } {
        log::warn!(
            "CloseHandle of an owned process handle failed: {report}",
            report = crate::error::Report(&e)
        );
        debug_assert!(false, "CloseHandle of an owned process handle should not fail: {e}");
    }
}

pub(crate) enum Termination {
    /// `TerminateProcess` accepted the request.
    Terminated,
    /// `TerminateProcess` refused because the process is exiting or has exited: a termination under
    /// way, not a completed one.
    Exited,
    /// `TerminateProcess` failed, or refused a handle that is not shown to be of an exited process.
    Failed(windows::core::Error),
}

/// Whether `e` is `ERROR_ACCESS_DENIED`; see [`terminate_held`].
pub(crate) fn is_access_denied(e: &windows::core::Error) -> bool {
    e.code() == windows::core::HRESULT::from_win32(windows::Win32::Foundation::ERROR_ACCESS_DENIED.0)
}

/// `TerminateProcess` on `handle`, a live process handle the caller closes afterwards. Never
/// blocks. `granted` is the access the handle holds, which its opener knows (it asked for it, or
/// read it from the handle once: [`granted_access`]).
///
/// `TerminateProcess` refuses with `ERROR_ACCESS_DENIED` both a handle that lacks
/// `PROCESS_TERMINATE` and a process that has terminated (Microsoft's `TerminateProcess` page), so
/// `granted` decides what a refusal means:
/// - It holds the right: the refusal is the exit, [`Termination::Exited`]. The refusal is already
///   given while the process object is not signalled yet (measured on Windows 11 26100), so
///   reading the signalled state instead would miss that window.
/// - It lacks the right: only an [`exit_look`] that finds the process exited proves an exit. The
///   exit code is read to prove an exit, never to prove liveness, because 259 cannot be told from a
///   live process. Anything else is [`Termination::Failed`] with the refusal.
pub(crate) fn terminate_held(handle: HANDLE, granted: PROCESS_ACCESS_RIGHTS) -> Termination {
    let refusal = match terminate_process(handle) {
        Ok(()) => return Termination::Terminated,
        Err(e) if !is_access_denied(&e) => return Termination::Failed(e),
        Err(e) => e,
    };
    if granted.0 & PROCESS_TERMINATE.0 != 0 {
        return Termination::Exited;
    }
    match exit_look(handle, granted.0 & PROCESS_SYNCHRONIZE.0 != 0) {
        Ok(Look::Exited) => Termination::Exited,
        Ok(Look::Running) => Termination::Failed(refusal),
        Err(e) => {
            log::debug!(
                "terminate_held: a handle without PROCESS_TERMINATE could not prove an exit: {report}",
                report = crate::error::Report(&e)
            );
            Termination::Failed(refusal)
        }
    }
}

/// What one look at a process handle found.
pub(crate) enum Look {
    Exited,
    Running,
}

/// One look at whether the process `handle` names has exited, without blocking. `has_synchronize`
/// says whether the handle was granted `SYNCHRONIZE`.
///
/// With it, a zero-timeout wait reads the process's signalled state. Without it, only
/// `GetExitCodeProcess` is left: an exit code other than `STILL_ACTIVE` proves an exit, but
/// `STILL_ACTIVE` cannot be told from a process that exited with code 259, so a running process
/// reads as `Err(ERROR_ACCESS_DENIED)`: the look is refused, not answered.
pub(crate) fn exit_look(handle: HANDLE, has_synchronize: bool) -> windows::core::Result<Look> {
    if has_synchronize {
        // SAFETY: the caller's live process handle; a zero-timeout wait only reads its state.
        return match unsafe { WaitForSingleObject(handle, 0) } {
            WAIT_OBJECT_0 => Ok(Look::Exited),
            WAIT_TIMEOUT => Ok(Look::Running),
            WAIT_FAILED => Err(windows::core::Error::from_thread()),
            other => {
                debug_assert!(false, "WaitForSingleObject returned {other:?}");
                Err(windows::core::Error::new(
                    windows::Win32::Foundation::E_UNEXPECTED,
                    format!("WaitForSingleObject returned {other:?}"),
                ))
            }
        };
    }
    let mut code = 0u32;
    // SAFETY: the caller's live process handle; `GetExitCodeProcess` needs the query right, which
    // every handle this crate opens holds.
    unsafe { GetExitCodeProcess(handle, &mut code) }?;
    if code != STILL_ACTIVE.0 as u32 {
        return Ok(Look::Exited);
    }
    Err(windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(
        windows::Win32::Foundation::ERROR_ACCESS_DENIED.0,
    )))
}

/// The access `handle` was granted, from `NtQueryObject(ObjectBasicInformation)`. For a handle whose
/// opener did not choose its access (`ShellExecuteEx`'s): read it once, where the handle is taken.
pub(crate) fn granted_access(handle: HANDLE) -> std::io::Result<u32> {
    let mut info = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    // SAFETY: `handle` is live; `info` is the buffer the class describes, and its size is passed.
    let status = unsafe {
        NtQueryObject(
            Some(handle),
            ObjectBasicInformation,
            Some(std::ptr::from_mut(&mut info).cast()),
            std::mem::size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32,
            None,
        )
    };
    if status.is_ok() {
        return Ok(info.GrantedAccess);
    }
    Err(crate::error::nt_io_error(status))
}

/// The exit code `terminate_held` ends a process with.
pub(crate) const TERMINATE_EXIT_CODE: u32 = 1;

fn terminate_process(handle: HANDLE) -> windows::core::Result<()> {
    #[cfg(test)]
    if fault::fire_exiting_refusal() {
        return Err(windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(
            windows::Win32::Foundation::ERROR_ACCESS_DENIED.0,
        )));
    }
    // SAFETY: the caller's live process handle.
    unsafe { TerminateProcess(handle, TERMINATE_EXIT_CODE) }
}

/// Test seam for the window Windows leaves open while a process exits.
#[cfg(test)]
pub(crate) mod fault {
    use crate::oneshot_hook::{self, Armed, OneShotHook};

    thread_local! {
        static EXITING: OneShotHook = const { OneShotHook::new() };
    }

    /// Make the next `terminate_held` on this thread refuse with `ERROR_ACCESS_DENIED` without
    /// calling `TerminateProcess`; the process stays alive. The guard clears the refusal on drop,
    /// used or not, so one that no kill reached cannot refuse the next test's kill on this thread.
    pub(crate) fn refuse_next_terminate_as_exiting() -> Armed {
        oneshot_hook::arm(&EXITING, || {})
    }

    /// Whether an armed refusal was waiting, which this answers.
    pub(super) fn fire_exiting_refusal() -> bool {
        oneshot_hook::fire_with(&EXITING, ()).is_some()
    }
}

/// Read the creation FILETIME of an open process handle as a raw token, preserving the
/// failure. `creation_token` is this with the error dropped.
// SAFETY: `handle` must be a live process handle with QUERY_LIMITED rights.
pub(crate) fn creation_token_result(handle: HANDLE) -> windows::core::Result<Key> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }?;
    let ft = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    Ok(Key::from_raw(ft))
}

pub(super) fn creation_token(handle: HANDLE) -> Option<Key> {
    creation_token_result(handle).ok()
}

/// `PROCESSINFOCLASS` 92, `ProcessSequenceNumber`: an 8-byte count of process creations on this
/// boot, unique per process and greater for a process than for its creator. Not in the `windows`
/// crate's constants (its `MaxProcessInfoClass` is 83).
const PROCESS_SEQUENCE_NUMBER: PROCESSINFOCLASS = PROCESSINFOCLASS(92);

/// `NtQueryInformationProcess` of `class` on `handle`, into `out`, or the `NTSTATUS` that refused it.
/// The handle needs `PROCESS_QUERY_LIMITED_INFORMATION`.
///
/// # Safety
/// `T` must be the buffer `class` writes.
unsafe fn query<T>(handle: HANDLE, class: PROCESSINFOCLASS, out: &mut T) -> Result<(), NTSTATUS> {
    // SAFETY: `handle` is live; `out` is the buffer the caller says `class` writes, and its size is
    // passed.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            class,
            std::ptr::from_mut(out).cast(),
            std::mem::size_of::<T>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status.is_ok() {
        Ok(())
    } else {
        Err(status)
    }
}

/// The sequence number of the process `handle` names, or the `NTSTATUS` that refused it. The
/// handle needs `PROCESS_QUERY_LIMITED_INFORMATION`.
fn sequence_number(handle: HANDLE) -> Result<u64, NTSTATUS> {
    let mut sequence = 0u64;
    // SAFETY: class 92 writes an 8-byte count.
    unsafe { query(handle, PROCESS_SEQUENCE_NUMBER, &mut sequence) }?;
    Ok(sequence)
}

/// The pid of the process that created the process `handle` names
/// (`ProcessBasicInformation.InheritedFromUniqueProcessId`), or the `NTSTATUS` that refused it.
/// Windows never updates it: it survives its creator's exit, and the number may be another
/// process's by then. The handle needs `PROCESS_QUERY_LIMITED_INFORMATION`.
fn creator_pid(handle: HANDLE) -> Result<usize, NTSTATUS> {
    let mut info = PROCESS_BASIC_INFORMATION::default();
    // SAFETY: class 0 writes a `PROCESS_BASIC_INFORMATION`.
    unsafe { query(handle, ProcessBasicInformation, &mut info) }?;
    Ok(info.InheritedFromUniqueProcessId)
}

/// The id key and the order key of `pid`, read on one `PROCESS_QUERY_LIMITED_INFORMATION` handle,
/// so both describe the same process. `expected`: see
/// [`ProcessId::of_ordered_with`](super::ProcessId::of_ordered_with). `ask_parent`: also read the creator
/// pid on that handle, never a fall back to the snapshot's `th32ParentProcessID`; a refused creator
/// query is [`ParentRead::Unreadable`] with its `NTSTATUS` in the cause ([`creator_read`]).
pub(super) fn ordered_read(pid: RawPid, expected: Option<Key>, ask_parent: bool) -> OrderedRead {
    let (read, parent, cause) = open_and_read(pid, expected, ask_parent);
    OrderedRead {
        read: read.map(|(key, order)| (key, Some(order))),
        parent,
        cause,
    }
}

/// The one open-then-read sequence of [`ordered_read`] and [`order_key`]: the handle of `pid`
/// ([`open_for_query`]), the reads on it, and its close. With no handle there is no creator, so a
/// read that asked for it is told it could not read it.
fn open_and_read(
    pid: RawPid,
    expected: Option<Key>,
    ask_parent: bool,
) -> (Resolved<(Key, OrderKey)>, ParentRead, UnknownCause) {
    let handle = match open_for_query(pid) {
        Ok(handle) => handle,
        Err(read) => return (read, ParentRead::not_read(ask_parent), UnknownCause::default()),
    };
    let (read, cause) = combine(pid, expected, creation_token_result(handle), sequence_number(handle));
    let (parent, cause) = if ask_parent {
        creator_read(pid, creator_pid(handle), cause)
    } else {
        (ParentRead::NotAsked, cause)
    };
    close(handle);
    (read, parent, cause)
}

/// A `PROCESS_QUERY_LIMITED_INFORMATION` handle of `pid`, the weakest mask that can read the
/// creation time. It is not universally granted to an unelevated caller, so a failure is
/// classified rather than treated as absence: otherwise why there is no handle, [`Resolved::Gone`]
/// or [`Resolved::Unknown`].
fn open_for_query<T>(pid: RawPid) -> Result<HANDLE, Resolved<T>> {
    match open_classified(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
        Opened::Found(handle) => Ok(handle),
        Opened::Gone => Err(Resolved::Gone),
        Opened::Denied(_) => Err(Resolved::Unknown),
    }
}

/// The parent number `creator`, the answer of [`creator_pid`] for `pid`, gives; a refused query is
/// [`ParentRead::Unreadable`] with its `NTSTATUS` added to `cause`. A pid is a `DWORD`, so a creator
/// wider than one is a contract violation: asserted in debug, and in release a parent number that
/// cannot be read, which goes to the parent's proof and the walk's warning like any other.
fn creator_read(pid: RawPid, creator: Result<usize, NTSTATUS>, cause: UnknownCause) -> (ParentRead, UnknownCause) {
    match creator {
        Ok(creator) => match RawPid::try_from(creator) {
            Ok(creator) => (ParentRead::Is(creator), cause),
            Err(_) => {
                log::warn!("the creator pid {creator:#x} of pid {pid} is wider than a DWORD");
                debug_assert!(false, "the creator pid {creator:#x} of pid {pid} is wider than a DWORD");
                (ParentRead::Unreadable, cause)
            }
        },
        Err(status) => {
            log::debug!(
                "NtQueryInformationProcess(ProcessBasicInformation) failed on an opened handle for pid {pid}: \
                 NTSTATUS {:#010x}",
                status.0 as u32
            );
            (ParentRead::Unreadable, cause.with_creator_status(status))
        }
    }
}

/// What the two reads of one handle of `pid` say together. The key is compared with `expected`
/// first: another process's key is [`Resolved::Gone`] whatever the sequence-number query said. A
/// failure of either read is `Unknown`; a refused sequence-number query is the cause, and a failed
/// key read is logged.
fn combine(
    pid: RawPid,
    expected: Option<Key>,
    key: windows::core::Result<Key>,
    sequence: Result<u64, NTSTATUS>,
) -> (Resolved<(Key, OrderKey)>, UnknownCause) {
    match (key, sequence) {
        (Ok(now), _) if expected.is_some_and(|expected| expected != now) => (Resolved::Gone, UnknownCause::default()),
        (Ok(key), Ok(sequence)) => (Resolved::Found((key, OrderKey(sequence))), UnknownCause::default()),
        (Ok(_), Err(status)) => {
            log::debug!(
                "NtQueryInformationProcess(ProcessSequenceNumber) failed on an opened handle for pid {pid}: \
                 NTSTATUS {:#010x}",
                status.0 as u32
            );
            (Resolved::Unknown, UnknownCause::of_sequence_status(status))
        }
        (Err(e), sequence) => {
            log::debug!(
                "GetProcessTimes failed on an opened handle for pid {pid}: {report}",
                report = crate::error::Report(&e)
            );
            let cause = match sequence {
                Ok(_) => UnknownCause::default(),
                Err(status) => {
                    log::debug!(
                        "NtQueryInformationProcess(ProcessSequenceNumber) failed on an opened handle for pid {pid}: \
                         NTSTATUS {:#010x}",
                        status.0 as u32
                    );
                    UnknownCause::of_sequence_status(status)
                }
            };
            (Resolved::Unknown, cause)
        }
    }
}

/// The order key of the process that holds `pid` as `key`: [`Resolved::Gone`] when another
/// process holds it now. The read that proves the process is still there is the one that gives the
/// key.
pub(super) fn order_key(pid: RawPid, key: Key) -> (Resolved<OrderKey>, UnknownCause) {
    let (read, _, cause) = open_and_read(pid, Some(key), false);
    (read.map(|(_, order)| order), cause)
}

/// Build a `ProcessId` from an already-open Windows process handle and its pid, reusing the
/// creation-token read. Avoids a second `OpenProcess` (which can fail and would otherwise
/// force dropping a live elevated child).
pub(crate) fn windows_identity_from_handle(handle: HANDLE, pid: RawPid) -> Option<crate::identity::ProcessId> {
    let start = creation_token(handle)?;
    Some(crate::identity::ProcessId { pid, key: start })
}

/// This process's own start token, read from the pseudo-handle. `GetCurrentProcess` performs
/// NO access check, so unlike a by-pid open this cannot be denied — which matters for a
/// process whose own DACL is restricted (AppContainer, low integrity).
pub(super) fn current_token() -> Resolved<Key> {
    // SAFETY: the pseudo-handle is always valid and must not be closed.
    match creation_token(unsafe { GetCurrentProcess() }) {
        Some(t) => Resolved::Found(t),
        // No log: `ProcessId::current()` turns this into a panic whose message says the same
        // thing, louder.
        None => Resolved::Unknown,
    }
}

pub(super) fn start_token(pid: RawPid) -> Resolved<Key> {
    let handle = match open_for_query(pid) {
        Ok(handle) => handle,
        Err(read) => return read,
    };
    let token = creation_token_result(handle);
    close(handle);
    match token {
        Ok(t) => Resolved::Found(t),
        // The open SUCCEEDED, so the process object exists. A GetProcessTimes failure is not
        // evidence of absence — and it is reachable when the process exits mid-query, so it
        // must not be an assertion.
        Err(e) => {
            log::debug!(
                "GetProcessTimes failed on an opened handle for pid {pid}: {report}",
                report = crate::error::Report(&e)
            );
            Resolved::Unknown
        }
    }
}

pub(super) fn created_at(start: Key) -> Option<SystemTime> {
    let unix_100ns = start.raw().checked_sub(EPOCH_DIFF_100NS)?;
    let secs = unix_100ns / 10_000_000;
    let nanos = (unix_100ns % 10_000_000) * 100;
    Some(SystemTime::UNIX_EPOCH + Duration::new(secs, nanos as u32))
}

pub(super) fn is_running(pid: RawPid, start: Key) -> Liveness {
    // `SYNCHRONIZE` is asked for and dropped when refused: `QUERY_LIMITED` alone still rejects a
    // reused pid and still lets `GetExitCodeProcess` prove an exit.
    let (opened, granted) = open_dropping_refused(pid, &[PROCESS_SYNCHRONIZE]);
    let handle = match opened {
        Opened::Found(h) => h,
        Opened::Gone => return Liveness::Dead,
        Opened::Denied(_) => return Liveness::Unknown,
    };
    // The identity check runs on the HELD handle, which pins the kernel object, so no recycle can
    // slip between the check and the look.
    let verdict = match creation_token_result(handle) {
        Ok(t) if t == start => match exit_look(handle, granted.0 & PROCESS_SYNCHRONIZE.0 != 0) {
            Ok(Look::Running) => Liveness::Alive,
            Ok(Look::Exited) => Liveness::Dead,
            // A look that never reported on the process: we learned nothing.
            Err(e) => {
                log::debug!(
                    "exit look at pid {pid} failed: {report}",
                    report = crate::error::Report(&e)
                );
                Liveness::Unknown
            }
        },
        Ok(_) => Liveness::Dead, // reused PID: a different process holds it now
        Err(e) => {
            // Opened but unreadable: never claim Dead.
            log::debug!(
                "GetProcessTimes failed on an opened handle for pid {pid}: {report}",
                report = crate::error::Report(&e)
            );
            Liveness::Unknown
        }
    };
    close(handle);
    verdict
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;

/// Windows creation `FILETIME` is an absolute count of 100 ns ticks since 1601-01-01 UTC:
/// recorded once, at creation, and unchanged by a reboot. There is nothing to scope it by.
pub(super) fn session_scope() -> Result<super::persist::Scope, super::persist::ScopeReadError> {
    Ok(super::persist::Scope::none())
}
