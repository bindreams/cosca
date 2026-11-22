//! How far a process has got in starting, read from its own memory through a handle the caller holds:
//! its PEB's loader pointer (`Ldr`), the `ProcessInitializing` bit of its `CrossProcessFlags`, and, once
//! those say it has finished, the console handle of its process parameters. Neither the PEB's tail nor
//! the parameters block is documented, so the layout is taken from public listings and pinned by the
//! tests that read real processes.
//!
//! [`read_peb`] is the one read of a word of another process's PEB. [`start_state`] takes the facts in an
//! order, each in a read of its own, a later one only after an earlier one has made it stable; it is the
//! read, of a child native to the host, the stop's proxy route decides whether the child had set its
//! console up by ([`Kernel::start_state`](super::kernel::Kernel::start_state)).
//!
//! The order is the child's own timeline, as measured (pinned by the tests): `Ldr` is null and the bit
//! clear before the loader begins; the loader sets the bit before it sets `Ldr`; `Ldr`, once set, stays
//! set; the bit, once cleared after it was set, is not set again; and the parameters block does not move
//! after the bit clears.
//! So no fact is read together with another, whose sampling order within one copy is not defined, and each
//! is read after the one that makes it stable: `Ldr` first; then the bit, which, read clear after `Ldr`
//! was seen set, means the start-up has finished; then the parameters pointer; then the console handle.

use std::ffi::c_void;
use std::io;
use std::mem::{offset_of, size_of};

use windows::Wdk::System::Threading::ProcessBasicInformation;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_UNKNOWN,
};
use windows::Win32::System::Threading::{
    GetProcessInformation, IsWow64Process2, ProcessMachineTypeInfo, PEB, PROCESS_BASIC_INFORMATION,
    PROCESS_MACHINE_INFORMATION, RTL_USER_PROCESS_PARAMETERS,
};

use crate::error::{io_context, nt_io_error, win32_io_error};

/// `PEB.CrossProcessFlags`, a `ULONG` the `windows` crate leaves unnamed (`Reserved6`): 0x50 in the 64-bit
/// PEB (Vergilius Project `_PEB`, Windows 11 24H2 x64). Pinned by `peb_tests` (bit 0, `ProcessInJob`,
/// equals `IsProcessInJob`) and by the held-start test (the bit below is set inside the start-up).
const CROSS_PROCESS_FLAGS: usize = offset_of!(PEB, Reserved6);

/// `ProcessInitializing`, bit 1 of `CrossProcessFlags` (bit order: `phnt`, `ntpebteb.h`).
const PROCESS_INITIALIZING: u32 = 1 << 1;

/// `RTL_USER_PROCESS_PARAMETERS.ConsoleHandle`, the first of the pointers the `windows` crate leaves
/// unnamed (`Reserved2`): 0x10 in the 64-bit block. Pinned by `peb_tests`.
const CONSOLE_HANDLE: usize = offset_of!(RTL_USER_PROCESS_PARAMETERS, Reserved2);

/// A word of the PEB that [`read_peb`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PebField {
    /// `Ldr`: set once ntdll's loader has begun initialising the process, before any program code runs.
    Ldr,
    /// `CrossProcessFlags`, a `ULONG` (read as 4 bytes).
    CrossProcessFlags,
    /// `ProcessParameters`, the pointer to the parameters block. The loader moves the block while the
    /// process starts (a read through the old pointer fails with `ERROR_PARTIAL_COPY`, with the initialising
    /// bit set), so the pointer counts only when it is read after the bit was seen clear.
    ProcessParameters,
}

impl PebField {
    fn offset(self) -> usize {
        match self {
            Self::Ldr => offset_of!(PEB, Ldr),
            Self::CrossProcessFlags => CROSS_PROCESS_FLAGS,
            Self::ProcessParameters => offset_of!(PEB, ProcessParameters),
        }
    }

    fn what(self) -> &'static str {
        match self {
            Self::Ldr => "the PEB's loader pointer",
            Self::CrossProcessFlags => "the PEB's cross-process flags",
            Self::ProcessParameters => "the process parameters pointer",
        }
    }
}

/// How far a process had got in starting when its memory was read. The parameters block's console handle
/// is read only for [`Finished`](Self::Finished).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupRead {
    /// `Ldr` is null: the loader has not begun (a process created suspended and never run).
    NotBegun,
    /// `Ldr` is set and `ProcessInitializing` is set: the loader is running the process's start-up.
    Initializing,
    /// `Ldr` is set and `ProcessInitializing` is clear. `console_handle` is
    /// `RTL_USER_PROCESS_PARAMETERS.ConsoleHandle`: a value `0`, `-1`, `-3`, `4` or a console's handle.
    Finished { console_handle: isize },
}

impl StartupRead {
    /// The child finished starting with no console: [`Finished`](Self::Finished) with console handle `0`,
    /// the only state of such a child (handle `4` is positive and attaches nothing).
    pub(crate) fn finished_without_console(self) -> bool {
        matches!(self, StartupRead::Finished { console_handle: 0 })
    }
}

/// Reads `field` of the PEB of the process `process` names, in one `ReadProcessMemory`: the one read of a
/// word of another process's PEB. A `CrossProcessFlags` is widened to a `usize`. The handle needs
/// `PROCESS_QUERY_LIMITED_INFORMATION` and `PROCESS_VM_READ`. A 32-bit process on a 64-bit host is read
/// through its native PEB, which the 64-bit loader sets first.
pub(crate) fn read_peb(process: HANDLE, field: PebField) -> io::Result<usize> {
    let mut info = PROCESS_BASIC_INFORMATION::default();
    // SAFETY: class 0 writes a `PROCESS_BASIC_INFORMATION`.
    unsafe { super::query(process, ProcessBasicInformation, &mut info) }.map_err(|status| {
        io_context(
            "NtQueryInformationProcess(ProcessBasicInformation) failed",
            nt_io_error(status),
        )
    })?;
    if info.PebBaseAddress.is_null() {
        return Err(io::Error::other("the process has no PEB"));
    }
    let address = info.PebBaseAddress as usize + field.offset();
    match field {
        PebField::CrossProcessFlags => {
            let mut flags = [0u8; size_of::<u32>()];
            read_exact(process, address, &mut flags, field.what())?;
            Ok(u32::from_ne_bytes(flags) as usize)
        }
        PebField::Ldr | PebField::ProcessParameters => read_word(process, address, field.what()),
    }
}

/// Reads how far the process `process` names has got in starting ([`StartupRead`]). Only a child native
/// to the host was measured (see [`require_native`]): any other is an `ErrorKind::Unsupported` error and
/// nothing is read. A read that fails is the error, of the OS error's kind. The handle needs the rights
/// [`read_peb`] does.
pub(crate) fn start_state(process: HANDLE) -> io::Result<StartupRead> {
    require_native(process)?;
    if read_peb(process, PebField::Ldr)? == 0 {
        return Ok(StartupRead::NotBegun);
    }
    if read_peb(process, PebField::CrossProcessFlags)? as u32 & PROCESS_INITIALIZING != 0 {
        return Ok(StartupRead::Initializing);
    }
    let parameters = read_peb(process, PebField::ProcessParameters)?;
    if parameters == 0 {
        return Err(io::Error::other("the process has no parameters block"));
    }
    let console_handle = read_word(process, parameters + CONSOLE_HANDLE, "the console handle")?;
    Ok(StartupRead::Finished {
        console_handle: console_handle as isize,
    })
}

/// The machine this build of cosca is for, as the OS names it: `UNKNOWN` for an architecture whose layout
/// of a process's start-up state was not measured.
const BUILD_MACHINE: IMAGE_FILE_MACHINE = if cfg!(target_arch = "x86_64") {
    IMAGE_FILE_MACHINE_AMD64
} else if cfg!(target_arch = "aarch64") {
    IMAGE_FILE_MACHINE_ARM64
} else {
    IMAGE_FILE_MACHINE_UNKNOWN
};

/// Errors with `ErrorKind::Unsupported` unless `process` is native to the host (see [`check_native`], and
/// [`check_machine`] on an ARM64 build, which asks `GetProcessInformation` and so needs Windows 11).
fn require_native(process: HANDLE) -> io::Result<()> {
    let mut wow64 = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut host = IMAGE_FILE_MACHINE_UNKNOWN;
    // SAFETY: both buffers are the ones the call writes.
    unsafe { IsWow64Process2(process, &mut wow64, Some(&mut host)) }
        .map_err(|e| io_context("IsWow64Process2 failed", win32_io_error(e)))?;
    check_native(BUILD_MACHINE, host, wow64)?;
    if BUILD_MACHINE == IMAGE_FILE_MACHINE_ARM64 {
        check_machine(process_machine(process)?)?;
    }
    Ok(())
}

/// The refusal of a child that is not native to the host; `why` goes in its text.
fn refuse(why: String) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("the process is not native to the host ({why}), and only the native x64 and ARM64 layouts of a process's start-up state were measured"),
    ))
}

/// Whether a child is native to the host, over the facts `IsWow64Process2` gives: the machine `build` of
/// this build of cosca, the `host`'s native machine and the child's machine under WOW64 (`UNKNOWN` when it
/// is not under WOW64). An x64 program emulated on an ARM64 host is not shown by them: that is
/// [`check_machine`]'s.
fn check_native(build: IMAGE_FILE_MACHINE, host: IMAGE_FILE_MACHINE, wow64: IMAGE_FILE_MACHINE) -> io::Result<()> {
    if build != IMAGE_FILE_MACHINE_AMD64 && build != IMAGE_FILE_MACHINE_ARM64 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this build of cosca is for neither x64 nor ARM64, and only those layouts of a process's start-up state were measured",
        ));
    }
    if wow64 != IMAGE_FILE_MACHINE_UNKNOWN {
        return refuse(format!("it runs under WOW64 as machine {:#x}", wow64.0));
    }
    if host != build {
        return refuse(format!(
            "the host's native machine ({:#x}) is not this build's ({:#x})",
            host.0, build.0
        ));
    }
    Ok(())
}

/// Whether a child of an ARM64 build on an ARM64 host runs as ARM64, from `machine`, the machine it runs
/// as, and not as an emulated x64 program.
fn check_machine(machine: IMAGE_FILE_MACHINE) -> io::Result<()> {
    if machine != IMAGE_FILE_MACHINE_ARM64 {
        return refuse(format!("it is an emulated process of machine {:#x}", machine.0));
    }
    Ok(())
}

/// The machine the process runs as, which tells an emulated x64 process on an ARM64 host from a native one
/// (`GetProcessInformation(ProcessMachineTypeInfo)`, which needs `PROCESS_QUERY_LIMITED_INFORMATION` and
/// Windows 11).
fn process_machine(process: HANDLE) -> io::Result<IMAGE_FILE_MACHINE> {
    let mut info = PROCESS_MACHINE_INFORMATION::default();
    // SAFETY: class `ProcessMachineTypeInfo` writes a `PROCESS_MACHINE_INFORMATION`, whose size is passed.
    unsafe {
        GetProcessInformation(
            process,
            ProcessMachineTypeInfo,
            (&mut info as *mut PROCESS_MACHINE_INFORMATION).cast(),
            size_of::<PROCESS_MACHINE_INFORMATION>() as u32,
        )
    }
    .map_err(|e| {
        io_context(
            "GetProcessInformation(ProcessMachineTypeInfo) failed",
            win32_io_error(e),
        )
    })?;
    Ok(info.ProcessMachine)
}

fn read_word(process: HANDLE, address: usize, what: &str) -> io::Result<usize> {
    let mut word = [0u8; size_of::<usize>()];
    read_exact(process, address, &mut word, what)?;
    Ok(usize::from_ne_bytes(word))
}

/// A short read is an error.
fn read_exact(process: HANDLE, address: usize, buf: &mut [u8], what: &str) -> io::Result<()> {
    let mut read = 0usize;
    // SAFETY: `buf` is a writable buffer of the length passed; the address is read in the other process
    // and never dereferenced here.
    unsafe {
        ReadProcessMemory(
            process,
            address as *const c_void,
            buf.as_mut_ptr().cast(),
            buf.len(),
            Some(&mut read),
        )
    }
    .map_err(|e| io_context(format!("ReadProcessMemory({what}) failed"), win32_io_error(e)))?;
    if read != buf.len() {
        return Err(io::Error::other(format!(
            "ReadProcessMemory({what}) read {read} of {} bytes",
            buf.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "peb_tests.rs"]
mod peb_tests;
