//! Windows: the child pipe, and the per-operation overlapped I/O that reads and writes it.
//!
//! The pipe is the kind std makes for a child (`child_pipe` in std's
//! `sys/process/windows/child_pipe.rs`): unnamed, our end overlapped, the child's end synchronous.
//! Our end is only ever used with an `OVERLAPPED` of its own per operation, with an event of its
//! own, so any number of threads can use one end at once, and the same end can later be handed to
//! tokio, which associates it with a completion port (a handle can have only one such
//! association, and these operations make none).

use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::process::Stdio;

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::NtOpenFile;
use windows::Win32::Foundation::{
    RtlNtStatusToDosError, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, HANDLE, NTSTATUS, UNICODE_STRING, WAIT_OBJECT_0,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows::Win32::System::IO::{GetOverlappedResult, IO_STATUS_BLOCK, OVERLAPPED};

use super::{PipeReader, PipeWriter};
use crate::error::win32_io_error;

// The NT create =====
//
// Values are std's, from `child_pipe.rs` of the toolchain's std (`child_pipe`, lines 56-189):
// the access and share masks, the options, and `PIPE_BUFFER_CAPACITY` (line 58).

const SYNCHRONIZE: u32 = 0x0010_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const FILE_CREATE: u32 = 0x2;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_PIPE_BYTE_STREAM_TYPE: u32 = 0;
const FILE_PIPE_BYTE_STREAM_MODE: u32 = 0;
const FILE_PIPE_QUEUE_OPERATION: u32 = 0;
/// A 64 KiB pipe capacity is the same as a typical Linux default (std, line 57).
const PIPE_BUFFER_CAPACITY: u32 = 64 * 1024;
/// The pipe filesystem's directory, where an unnamed pipe is created (std, line 87).
const PIPE_DIRECTORY: &str = r"\Device\NamedPipe\";

// `windows` 0.62 does not bind `NtCreateNamedPipeFile`.
#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn NtCreateNamedPipeFile(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *const OBJECT_ATTRIBUTES,
        io_status_block: *mut IO_STATUS_BLOCK,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        named_pipe_type: u32,
        read_mode: u32,
        completion_mode: u32,
        maximum_instances: u32,
        inbound_quota: u32,
        outbound_quota: u32,
        default_timeout: *const i64,
    ) -> NTSTATUS;
}

fn nt_error(status: NTSTATUS) -> io::Error {
    // SAFETY: a pure status-to-code mapping.
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

/// An unnamed pipe for a child: `(ours, theirs)`. `ours` is overlapped and readable if
/// `ours_readable`, else writable; `theirs` is synchronous and the other direction, the end the
/// child is given. Neither is inheritable: the spawn gives the child its end explicitly.
///
/// The one place a child pipe is made, for the sync and the async spawn alike. A failed NT call is
/// an error; there is no fall back to `CreatePipe`, whose ends cannot be overlapped.
pub(crate) fn child_pipe(ours_readable: bool) -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut io_status = IO_STATUS_BLOCK::default();
    let directory: Vec<u16> = PIPE_DIRECTORY.encode_utf16().collect();
    let directory_name = UNICODE_STRING {
        Length: (directory.len() * 2) as u16,
        MaximumLength: (directory.len() * 2) as u16,
        Buffer: windows::core::PWSTR(directory.as_ptr().cast_mut()),
    };
    let mut attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        ObjectName: &directory_name,
        ..Default::default()
    };

    // The pipe filesystem, to create the pipe in.
    let mut directory_handle = HANDLE::default();
    // SAFETY: every pointer is to a live local; the attributes name a directory by a string that
    // outlives the call.
    let status = unsafe {
        NtOpenFile(
            &mut directory_handle,
            SYNCHRONIZE | GENERIC_READ,
            &attributes,
            &mut io_status,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_SYNCHRONOUS_IO_NONALERT,
        )
    };
    if status.is_err() {
        return Err(nt_error(status));
    }
    // SAFETY: `NtOpenFile` succeeded, so the handle is ours to close.
    let directory_handle = unsafe { OwnedHandle::from_raw_handle(directory_handle.0) };

    // With the directory as root and an empty name, the pipe is unnamed. std passes a null buffer
    // for the empty name (line 117).
    let empty = UNICODE_STRING::default();
    attributes.ObjectName = &empty;
    attributes.RootDirectory = HANDLE(directory_handle.as_raw_handle());

    // A negative timeout is relative, in 100 ns units: 50 ms, `CreateNamedPipeW`'s default
    // (std, line 130).
    let timeout = -(50_i64 * 10_000);
    let mut ours = HANDLE::default();
    // SAFETY: as above; `timeout` outlives the call.
    let status = unsafe {
        NtCreateNamedPipeFile(
            &mut ours,
            SYNCHRONIZE | if ours_readable { GENERIC_READ } else { GENERIC_WRITE },
            &attributes,
            &mut io_status,
            if ours_readable {
                FILE_SHARE_WRITE
            } else {
                FILE_SHARE_READ
            },
            FILE_CREATE,
            // No `FILE_SYNCHRONOUS_IO_*` option: this is what makes the handle overlapped.
            0,
            FILE_PIPE_BYTE_STREAM_TYPE,
            FILE_PIPE_BYTE_STREAM_MODE,
            FILE_PIPE_QUEUE_OPERATION,
            // Only one client end.
            1,
            PIPE_BUFFER_CAPACITY,
            PIPE_BUFFER_CAPACITY,
            &timeout,
        )
    };
    if status.is_err() {
        return Err(nt_error(status));
    }
    // SAFETY: `NtCreateNamedPipeFile` succeeded.
    let ours = unsafe { OwnedHandle::from_raw_handle(ours.0) };

    // Their end: opened through ours, by an empty name, for synchronous access.
    attributes.RootDirectory = HANDLE(ours.as_raw_handle());
    let mut theirs = HANDLE::default();
    // SAFETY: as above.
    let status = unsafe {
        NtOpenFile(
            &mut theirs,
            SYNCHRONIZE
                | if ours_readable {
                    GENERIC_WRITE | FILE_READ_ATTRIBUTES
                } else {
                    GENERIC_READ
                },
            &attributes,
            &mut io_status,
            0,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
    };
    if status.is_err() {
        return Err(nt_error(status));
    }
    // SAFETY: `NtOpenFile` succeeded.
    let theirs = unsafe { OwnedHandle::from_raw_handle(theirs.0) };
    Ok((ours, theirs))
}

// The ends =====

/// An overlapped pipe end. It is used only through [`read`](Handle::read) and
/// [`write`](Handle::write), which never wait on the handle.
#[derive(Debug)]
pub(super) struct Handle(OwnedHandle);

pub(super) type Reader = Handle;
pub(super) type Writer = Handle;

impl Handle {
    pub(super) fn try_clone(&self) -> io::Result<Handle> {
        self.0.try_clone().map(Handle)
    }

    fn as_raw(&self) -> HANDLE {
        HANDLE(self.0.as_raw_handle())
    }
}

impl Read for &Handle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min(u32::MAX as usize);
        let buf = &mut buf[..len];
        // SAFETY (the closure's `ReadFile`): `buf` is live until `overlapped_io` returns, and it
        // does not return while the kernel may write into it.
        let read = overlapped_io(self.as_raw(), |overlapped| unsafe {
            ReadFile(self.as_raw(), Some(&mut *buf), None, Some(overlapped))
        });
        match read {
            // Reading from a pipe whose other end is closed fails this way; std reads it as the end
            // of the stream.
            Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE.0 as i32) => Ok(0),
            read => read,
        }
    }
}

impl Write for &Handle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let buf = &buf[..buf.len().min(u32::MAX as usize)];
        // SAFETY (the closure's `WriteFile`): as for `read`.
        overlapped_io(self.as_raw(), |overlapped| unsafe {
            WriteFile(self.as_raw(), Some(buf), None, Some(overlapped))
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One overlapped operation on `handle`, started by `start` with an `OVERLAPPED` whose event is new
/// for this call, run to its end: the bytes it moved.
///
/// The wait is on the event, so another operation on the same handle, in another thread, does not
/// release it. A wait that fails leaves the kernel owning the caller's buffer, and nothing safe is
/// left to do: the process aborts.
fn overlapped_io(
    handle: HANDLE,
    start: impl FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
) -> io::Result<usize> {
    // SAFETY: an unnamed manual-reset event, no preconditions.
    let event = unsafe { CreateEventW(None, true, false, None) }.map_err(win32_io_error)?;
    // SAFETY: `event` is new and ours alone; the guard closes it after the operation is over.
    let event = unsafe { OwnedHandle::from_raw_handle(event.0) };
    let mut overlapped = OVERLAPPED {
        hEvent: HANDLE(event.as_raw_handle()),
        ..Default::default()
    };
    match start(&mut overlapped) {
        Ok(()) => {}
        Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_IO_PENDING.0) => {
            // SAFETY: a wait on an event this call owns.
            if unsafe { WaitForSingleObject(HANDLE(event.as_raw_handle()), INFINITE) } != WAIT_OBJECT_0 {
                eprintln!("cosca: waiting for a pipe operation failed with the buffer still in the kernel's hands");
                std::process::abort();
            }
        }
        Err(e) => return Err(win32_io_error(e)),
    }
    let mut moved = 0u32;
    // SAFETY: the operation is complete, so `overlapped` holds its result; it does not wait.
    unsafe { GetOverlappedResult(handle, &overlapped, &mut moved, false) }.map_err(win32_io_error)?;
    Ok(moved as usize)
}

// Conversions =====

impl PipeReader {
    /// The parent's end of a pipe [`child_pipe`] made: overlapped, and readable.
    pub(crate) fn from_overlapped(end: OwnedHandle) -> PipeReader {
        PipeReader(Handle(end))
    }
}

impl PipeWriter {
    /// The parent's end of a pipe [`child_pipe`] made: overlapped, and writable.
    pub(crate) fn from_overlapped(end: OwnedHandle) -> PipeWriter {
        PipeWriter(Handle(end))
    }
}

/// A std pipe end is synchronous: each operation completes inside its call, and is still safe to
/// use from several threads at once.
impl From<std::io::PipeReader> for PipeReader {
    fn from(p: std::io::PipeReader) -> PipeReader {
        PipeReader(Handle(p.into()))
    }
}

/// A std pipe end is synchronous; see the reader's conversion.
impl From<std::io::PipeWriter> for PipeWriter {
    fn from(p: std::io::PipeWriter) -> PipeWriter {
        PipeWriter(Handle(p.into()))
    }
}

impl From<PipeReader> for OwnedHandle {
    fn from(p: PipeReader) -> OwnedHandle {
        p.0 .0
    }
}

impl From<PipeWriter> for OwnedHandle {
    fn from(p: PipeWriter) -> OwnedHandle {
        p.0 .0
    }
}

impl AsHandle for PipeReader {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0 .0.as_handle()
    }
}

impl AsHandle for PipeWriter {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0 .0.as_handle()
    }
}

impl AsRawHandle for PipeReader {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.0 .0.as_raw_handle()
    }
}

impl AsRawHandle for PipeWriter {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.0 .0.as_raw_handle()
    }
}

impl From<PipeReader> for Stdio {
    fn from(p: PipeReader) -> Stdio {
        Stdio::from(OwnedHandle::from(p))
    }
}

impl From<PipeWriter> for Stdio {
    fn from(p: PipeWriter) -> Stdio {
        Stdio::from(OwnedHandle::from(p))
    }
}
