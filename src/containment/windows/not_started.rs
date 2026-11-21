//! The proof that a strict Windows root never ran its program, taken from the process.
//!
//! A root is created suspended and a failed Job assignment ends it before its first resume, so the
//! spawn can answer "not started" ([`AttachFailure::not_started`]). Something else can resume it
//! first (a debugger, an EDR agent), or run a thread of its own in it, so the answer rests on the
//! process, not on one thread's count: the initial thread is still suspended, it is the process's
//! only thread, and the loader has not initialised the process (`PEB.Ldr` is still `NULL`; ntdll
//! sets it before any program code, a static import's `DllMain` or a TLS callback, runs).
//!
//! [`AttachFailure::not_started`]: crate::containment::dispatch::AttachFailure

use std::io;
use std::sync::Arc;

use windows::Wdk::System::Threading::ProcessBasicInformation;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{PEB, PROCESS_BASIC_INFORMATION};

use super::{open_for_resume, owner_of, process_pid_of, resume_thread, suspend_thread, thread_entries, ThreadHandle};
use crate::error::{io_context, nt_io_error, win32_io_error, Error};

/// A root proved not to have started: its initial thread, kept suspended by the suspend the proof
/// took. Dropping it closes the handle and resumes nothing: the root is ended next, and a resume in
/// between would let it run.
#[derive(Debug)]
pub(crate) struct ProvenRoot(#[allow(dead_code, reason = "held for its suspend; closed on drop")] ThreadHandle);

/// Why a root is not proved not to have started, and the failure of the undo the proof ran.
#[derive(Debug)]
pub(crate) struct NotProved {
    pub(crate) reason: Reason,
    /// The failure of undoing the read's suspend (`ResumeThread`), which leaves the root suspended once
    /// more than it was found. Another failure of the call, never the cause of `reason`.
    pub(crate) undo: Option<Arc<Error>>,
}

/// What stops the proof.
#[derive(Debug)]
pub(crate) enum Reason {
    /// What the proof saw: the root may have run, or its process is not the one to read. The
    /// words of the error that carries it, not a failure of any call.
    Observed(String),
    /// A read the proof needs failed (an [`Error::Unassessable`] naming the call, with the OS error as
    /// its `source`), so the root's state is not known.
    Unread(Error),
}

impl NotProved {
    /// The spawn's [`Error::Containment`], sourced by the failed assignment. What the proof saw is in its
    /// detail; a failed read and a failed undo are peers beside the assignment, in that order.
    pub(crate) fn into_error(self, assignment_detail: &str, assignment: Arc<Error>) -> Error {
        let (detail, read) = match self.reason {
            Reason::Observed(saw) => (
                format!("{assignment_detail}, and it could not be shown that the program did not run: {saw}"),
                None,
            ),
            Reason::Unread(read) => (
                format!("{assignment_detail}, and whether the program ran could not be told"),
                Some(Arc::new(read)),
            ),
        };
        Error::Containment {
            detail,
            source: Some(assignment),
        }
        .with_peers(read.into_iter().chain(self.undo))
    }
}

/// Proves that the program of the process at `proc_handle`, created suspended, has not run, or says
/// why it cannot. `Err` is the [`NotProved`]: the root may have run, or its process is not the one to
/// read (a [`Reason::Observed`]), or a read the proof needs failed, which proves nothing (a
/// [`Reason::Unread`]). The proof holds when all of these do:
///
/// - the snapshot lists exactly one thread for the pid;
/// - its suspend count is not 0 (the read suspends it once, the one thing the OS offers, and the
///   proof keeps that suspend: count 0 means something resumed it, and the read's suspend is undone);
/// - the loader has not initialised the process ([`loader_started`]).
///
/// The proof is of the state at its reads: a thread that another party creates after them can run
/// before the caller ends the process, which a snapshot cannot rule out.
///
/// `proc_handle` must be a live process handle with `PROCESS_QUERY_LIMITED_INFORMATION` and
/// `PROCESS_VM_READ`, as `CreateProcess`'s is.
pub(crate) fn prove_not_started(proc_handle: std::os::windows::io::RawHandle) -> Result<ProvenRoot, NotProved> {
    let process = HANDLE(proc_handle.cast());
    let pid = process_pid_of(process).map_err(|e| read_failed("GetProcessId", e))?;
    let entries = thread_entries().map_err(|e| read_failed("the thread snapshot", e))?;
    let own: Vec<u32> = entries
        .iter()
        .filter(|e| e.th32OwnerProcessID == pid)
        .map(|e| e.th32ThreadID)
        .collect();
    let [initial] = own[..] else {
        return Err(saw(format!(
            "the snapshot lists {} threads for pid {pid}, not one",
            own.len()
        )));
    };

    let call = |call: &str, e: windows::core::Error| {
        read_failed(&format!("{call} for thread {initial} of pid {pid}"), win32_io_error(e))
    };
    let thread = open_for_resume(initial).map_err(|e| call("OpenThread(suspend/resume)", e))?;
    let owner = owner_of(&thread).map_err(|e| call("GetProcessIdOfThread", e))?;
    if owner != pid {
        return Err(saw(format!(
            "thread {initial} belongs to pid {owner}, not to pid {pid}"
        )));
    }
    let previous = suspend_thread(&thread).map_err(|e| call("SuspendThread", e))?;
    let Some(reason) = unproved(previous, || loader_started(process)) else {
        return Ok(ProvenRoot(thread));
    };
    // Not proved: undo the read's suspend, so a root handed back is left as it was found.
    let undo = resume_thread(&thread).err().map(|e| {
        Error::io_cause(io_context(
            format!("undoing the read's suspend (ResumeThread for thread {initial} of pid {pid}) failed"),
            win32_io_error(e),
        ))
    });
    Err(NotProved { reason, undo })
}

/// A failed read the proof needs: `what` failed with `source`, so the root's state is not known.
fn read_failed(what: &str, source: io::Error) -> NotProved {
    NotProved {
        reason: unread(what, source),
        undo: None,
    }
}

fn unread(what: &str, source: io::Error) -> Reason {
    Reason::Unread(Error::Unassessable {
        detail: format!("{what} failed"),
        source: Some(Error::io_cause(source)),
    })
}

/// What the proof saw that shows the root may have run, or that the process is not the one it
/// should read. Phrased as a whole sentence of the error's detail.
fn saw(what: String) -> NotProved {
    NotProved {
        reason: Reason::Observed(what),
        undo: None,
    }
}

/// Why a root whose initial thread had suspend count `previous` before the proof's suspend is not
/// proved, or `None` when it is: a thread that was running, a loader that ran (`loader` reads it,
/// and only when the thread was suspended), or a loader state that cannot be read.
fn unproved(previous: u32, loader: impl FnOnce() -> io::Result<bool>) -> Option<Reason> {
    if previous == 0 {
        return Some(Reason::Observed("the child's initial thread was running".to_owned()));
    }
    match loader() {
        Ok(false) => None,
        Ok(true) => Some(Reason::Observed("the loader had initialised the child".to_owned())),
        Err(e) => Some(unread("reading the loader's state", e)),
    }
}

/// Whether the loader has initialised the process at `process`: its PEB's `Ldr` is set. A process
/// created suspended has it `NULL` until its first thread runs `LdrInitializeThunk`. The handle needs
/// `PROCESS_QUERY_LIMITED_INFORMATION` and `PROCESS_VM_READ`. A 32-bit process on a 64-bit host is
/// read through its native PEB, which the 64-bit loader sets first.
fn loader_started(process: HANDLE) -> io::Result<bool> {
    #[cfg(test)]
    super::forced(super::fault::Step::LoaderRead, None).map_err(win32_io_error)?;

    let mut info = PROCESS_BASIC_INFORMATION::default();
    // SAFETY: class 0 writes a `PROCESS_BASIC_INFORMATION`.
    unsafe { crate::identity::windows_query_process(process, ProcessBasicInformation, &mut info) }.map_err(
        |status| {
            io_context(
                "NtQueryInformationProcess(ProcessBasicInformation) failed",
                nt_io_error(status),
            )
        },
    )?;
    if info.PebBaseAddress.is_null() {
        return Err(io::Error::other("the process has no PEB"));
    }
    let ldr_at = info
        .PebBaseAddress
        .cast::<u8>()
        .wrapping_add(std::mem::offset_of!(PEB, Ldr));
    let mut ldr: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut read = 0usize;
    // SAFETY: `ldr` is a pointer-sized buffer, whose size is passed; the address is read in the
    // other process and never dereferenced here.
    unsafe {
        ReadProcessMemory(
            process,
            ldr_at.cast(),
            std::ptr::addr_of_mut!(ldr).cast(),
            size_of::<*mut core::ffi::c_void>(),
            Some(&mut read),
        )
    }
    .map_err(|e| io_context("ReadProcessMemory(PEB.Ldr) failed", win32_io_error(e)))?;
    if read != size_of::<*mut core::ffi::c_void>() {
        return Err(io::Error::other(format!(
            "ReadProcessMemory(PEB.Ldr) read {read} bytes"
        )));
    }
    Ok(!ldr.is_null())
}

#[cfg(test)]
#[path = "not_started_tests.rs"]
mod not_started_tests;
