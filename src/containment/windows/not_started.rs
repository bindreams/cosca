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

use windows::Wdk::System::Threading::ProcessBasicInformation;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{PEB, PROCESS_BASIC_INFORMATION};

use super::{open_for_resume, owner_of, process_pid_of, resume_thread, suspend_thread, thread_entries, ThreadHandle};
use crate::error::{io_context, nt_io_error, win32_io_error, Report};

/// A root proved not to have started: its initial thread, kept suspended by the suspend the proof
/// took. Dropping it closes the handle and resumes nothing: the root is ended next, and a resume in
/// between would let it run.
#[derive(Debug)]
pub(crate) struct ProvenRoot(#[allow(dead_code, reason = "held for its suspend; closed on drop")] ThreadHandle);

/// Proves that the program of the process at `proc_handle`, created suspended, has not run, or says
/// why it cannot. `Err` holds the reason: the root may have started, or a read the proof needs
/// failed, which proves nothing. The proof holds when all of these do:
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
pub(crate) fn prove_not_started(proc_handle: std::os::windows::io::RawHandle) -> Result<ProvenRoot, String> {
    let process = HANDLE(proc_handle.cast());
    let read = |what: &str, e: io::Error| format!("{what} failed: {report}", report = Report(&e));
    let pid = process_pid_of(process).map_err(|e| read("GetProcessId", e))?;
    let entries = thread_entries().map_err(|e| read("the thread snapshot", e))?;
    let own: Vec<u32> = entries
        .iter()
        .filter(|e| e.th32OwnerProcessID == pid)
        .map(|e| e.th32ThreadID)
        .collect();
    let [initial] = own[..] else {
        return Err(format!(
            "the snapshot lists {} threads for pid {pid}, not one",
            own.len()
        ));
    };

    let call = |call: &str, e: windows::core::Error| {
        read(&format!("{call} for thread {initial} of pid {pid}"), win32_io_error(e))
    };
    let thread = open_for_resume(initial).map_err(|e| call("OpenThread(suspend/resume)", e))?;
    let owner = owner_of(&thread).map_err(|e| call("GetProcessIdOfThread", e))?;
    if owner != pid {
        return Err(format!("thread {initial} belongs to pid {owner}, not to pid {pid}"));
    }
    let previous = suspend_thread(&thread).map_err(|e| call("SuspendThread", e))?;
    let Some(why) = unproved(previous, || loader_started(process)) else {
        return Ok(ProvenRoot(thread));
    };
    // Not proved: undo the read's suspend, so a root handed back is left as it was found.
    match resume_thread(&thread) {
        Ok(_) => Err(why),
        Err(e) => Err(format!(
            "{why}; undoing the read's suspend failed too: {}",
            call("ResumeThread", e)
        )),
    }
}

/// Why a root whose initial thread had suspend count `previous` before the proof's suspend is not
/// proved, or `None` when it is: a thread that was running, a loader that ran (`loader` reads it,
/// and only when the thread was suspended), or a loader state that cannot be read.
fn unproved(previous: u32, loader: impl FnOnce() -> io::Result<bool>) -> Option<String> {
    if previous == 0 {
        return Some("its initial thread was running".to_owned());
    }
    match loader() {
        Ok(false) => None,
        Ok(true) => Some("the loader had initialised it".to_owned()),
        Err(e) => Some(format!(
            "reading the loader's state failed: {report}",
            report = Report(&e)
        )),
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
