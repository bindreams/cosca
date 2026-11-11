//! Windows: the child pipe, and the per-operation overlapped I/O that reads and writes it.
//!
//! The types hold either the parent's end of a child's pipe as the spawn makes it, or any pipe
//! handle a caller converts in (std's pipe ends, an `OwnedHandle`). The spawn's pipe is the kind std
//! makes for a child (`child_pipe` in std's `sys/process/windows/child_pipe.rs`): unnamed, our end
//! overlapped, the child's end synchronous. Either way each read and write is made with an
//! `OVERLAPPED` of its own and waits on its own event, so any number of threads can use one end at
//! once, and an overlapped end can later be handed to tokio, which associates it with a completion
//! port (a handle can have only one such association, and these operations make none). The
//! conversions record nothing and make no system call.

use std::borrow::BorrowMut;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::windows::io::{
    AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle,
};
use std::process::Stdio;

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::NtOpenFile;
use windows::Win32::Foundation::{
    RtlNtStatusToDosError, ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_NOT_FOUND, HANDLE, NTSTATUS,
    UNICODE_STRING, WAIT_OBJECT_0,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, IO_STATUS_BLOCK, OVERLAPPED};

use super::{ParentEnd, PipeReader, PipeWriter};
use crate::error::win32_io_error;
use crate::stdio::Direction;

// The NT create =====
//
// Values are std's, from `child_pipe.rs` of the toolchain's std: the access and share masks, the
// options, and `PIPE_BUFFER_CAPACITY`.

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
/// A 64 KiB pipe capacity is the same as a typical Linux default.
const PIPE_BUFFER_CAPACITY: u32 = 64 * 1024;
/// The pipe filesystem's directory, where an unnamed pipe is created.
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
/// A failed NT call is an error; there is no fall back to `CreatePipe`, whose ends cannot be
/// overlapped.
fn nt_pipe(ours_readable: bool) -> io::Result<(OwnedHandle, OwnedHandle)> {
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
    // for the empty name.
    let empty = UNICODE_STRING::default();
    attributes.ObjectName = &empty;
    attributes.RootDirectory = HANDLE(directory_handle.as_raw_handle());

    // A negative timeout is relative, in 100 ns units: 50 ms, `CreateNamedPipeW`'s default.
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

/// The pipe for one piped slot: the child's end, and the parent's, overlapped, as `dir` says
/// (`In`: the child reads, the parent writes). Neither is inheritable: the spawn gives the child
/// its end explicitly.
pub(crate) fn child_pipe(dir: Direction) -> io::Result<(OwnedHandle, ParentEnd)> {
    let (ours, theirs) = nt_pipe(dir == Direction::Out)?;
    Ok((
        theirs,
        match dir {
            Direction::In => ParentEnd::Writer(PipeWriter::from(ours)),
            Direction::Out => ParentEnd::Reader(PipeReader::from(ours)),
        },
    ))
}

// The ends =====

/// A pipe end, overlapped or synchronous. It is used only through the `Read` and `Write` impls
/// below, which never wait on the handle, so either mode works.
#[derive(Debug)]
pub(super) struct Handle {
    handle: OwnedHandle,
}

pub(super) type Reader = Handle;
pub(super) type Writer = Handle;

/// Whether `handle` is overlapped: its file object has no synchronous-I/O flag. Never call it on a
/// pipe end another thread may be reading: the query can block behind a synchronous read.
#[cfg(any(feature = "tokio", test, debug_assertions))]
pub(crate) fn is_overlapped(handle: BorrowedHandle<'_>) -> io::Result<bool> {
    use windows::Wdk::Storage::FileSystem::{FileModeInformation, NtQueryInformationFile, FILE_MODE_INFORMATION};

    /// The file object mode bits that make a handle synchronous (`FILE_SYNCHRONOUS_IO_ALERT` and
    /// `FILE_SYNCHRONOUS_IO_NONALERT`).
    const FILE_SYNCHRONOUS_IO_MASK: u32 = 0x10 | FILE_SYNCHRONOUS_IO_NONALERT;

    let mut io_status = IO_STATUS_BLOCK::default();
    let mut mode = FILE_MODE_INFORMATION::default();
    // SAFETY: the handle is live for the call; `mode` is the buffer the class describes.
    let status = unsafe {
        NtQueryInformationFile(
            HANDLE(handle.as_raw_handle()),
            &mut io_status,
            std::ptr::from_mut(&mut mode).cast(),
            size_of::<FILE_MODE_INFORMATION>() as u32,
            FileModeInformation,
        )
    };
    if status.is_err() {
        return Err(nt_error(status));
    }
    Ok(mode.Mode & FILE_SYNCHRONOUS_IO_MASK == 0)
}

impl Handle {
    pub(super) fn try_clone(&self) -> io::Result<Handle> {
        Ok(Handle {
            handle: self.handle.try_clone()?,
        })
    }

    fn as_raw(&self) -> HANDLE {
        HANDLE(self.handle.as_raw_handle())
    }
}

impl Read for &Handle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // A zero-length `ReadFile` on a pipe waits for data to arrive.
        if buf.is_empty() {
            return Ok(0);
        }
        // SAFETY: `buf` is live until `overlapped_io` returns, and it does not return while the
        // kernel may write into it.
        eof_as_zero(overlapped_io(|operation| unsafe { operation.read(self.as_raw(), buf) }))
    }
}

impl Write for &Handle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: as for `read`.
        overlapped_io(|operation| unsafe { operation.write(self.as_raw(), buf) })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A read's result, with a pipe whose other end is closed (`ERROR_BROKEN_PIPE`, at the call or at the
/// completion) read as the end of the stream, as std does.
pub(crate) fn eof_as_zero(read: io::Result<usize>) -> io::Result<usize> {
    match read {
        Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE.0 as i32) => Ok(0),
        read => read,
    }
}

/// One overlapped operation, started by `start`, run to its end: the bytes it moved.
///
/// The wait is on the operation's own event, so another operation on the same handle, in another
/// thread, does not release it.
fn overlapped_io(start: impl FnOnce(&mut Operation<OVERLAPPED>) -> io::Result<StartOutcome>) -> io::Result<usize> {
    let mut operation = Operation::<OVERLAPPED>::new()?;
    if start(&mut operation)? == StartOutcome::Pending {
        wait_or_abort(operation.event());
    }
    operation.finish()
}

/// A wait that fails leaves the kernel owning the caller's buffer, and nothing safe is left to do:
/// the process aborts.
fn wait_or_abort(event: HANDLE) {
    // SAFETY: a wait on an event the caller owns.
    if unsafe { WaitForSingleObject(event, INFINITE) } != WAIT_OBJECT_0 {
        abort_with_buffer_in_kernel("waiting for a pipe operation");
    }
}

/// Aborts the process after `step` failed with the caller's buffer still owned by the kernel.
fn abort_with_buffer_in_kernel(step: &str) -> ! {
    // `eprintln!` panics when writing to stderr fails (e.g. a pipe whose reader has
    // gone), which would unwind with the buffer still in the kernel's hands.
    Write::write_all(
        &mut io::stderr(),
        format!("cosca: {step} failed with the buffer still in the kernel's hands\n").as_bytes(),
    )
    .ok();
    std::process::abort();
}

// The operation =====

/// What starting an operation did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartOutcome {
    /// The kernel has the operation and the buffer; the event fires when it completes.
    Pending,
    /// The operation finished inside the call; `finish` reads its result. The event is signalled.
    Completed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Pending,
    Completed,
}

/// The `OVERLAPPED` and the event of one overlapped read or write at a time on a pipe end, reusable
/// for the next one. Each operation has an event of its own (never the handle), so any number of
/// operations on one end can be waited on separately.
///
/// Started with [`read`](Self::read) or [`write`](Self::write), whose buffer and pipe end the kernel
/// holds until [`finish`](Self::finish) ends the operation or the drop cancels it: dropping a
/// pending `Operation` cancels it and waits for the kernel to let go, so a panic cannot free what
/// the kernel owns. The buffer and the end must outlive the `Operation`.
///
/// `S` is where the `OVERLAPPED` lives, since the kernel keeps its address while pending:
/// `OVERLAPPED` for an operation that never moves once started, `Box<OVERLAPPED>` for one that may
/// move.
pub(crate) struct Operation<S: BorrowMut<OVERLAPPED> = Box<OVERLAPPED>> {
    event: OwnedHandle,
    overlapped: S,
    /// The end the operation was started on, valid while it is not idle.
    handle: HANDLE,
    state: State,
}

impl<S: BorrowMut<OVERLAPPED> + Default> Operation<S> {
    pub(crate) fn new() -> io::Result<Self> {
        // SAFETY: an unnamed manual-reset event, no preconditions.
        let event = unsafe { CreateEventW(None, true, false, None) }.map_err(win32_io_error)?;
        // SAFETY: `event` is new and ours alone.
        let event = unsafe { OwnedHandle::from_raw_handle(event.0) };
        Ok(Operation {
            event,
            overlapped: S::default(),
            handle: HANDLE::default(),
            state: State::Idle,
        })
    }
}

impl<S: BorrowMut<OVERLAPPED>> Operation<S> {
    /// The event that fires when the operation completes. It is the event itself, the handle to wait
    /// on: the one in the `OVERLAPPED` has its low bit set.
    pub(crate) fn event(&self) -> HANDLE {
        HANDLE(self.event.as_raw_handle())
    }

    /// Starts one `ReadFile` of up to `u32::MAX` bytes of `buf` on `handle`.
    ///
    /// # Safety
    ///
    /// `buf` must stay live, unmoved and unread until `finish` or the drop has ended the operation,
    /// and the operation must be idle. `handle` is an overlapped pipe end that stays open until
    /// then. If `S` is `OVERLAPPED`, `self` must not move until then either.
    pub(crate) unsafe fn read(&mut self, handle: HANDLE, buf: &mut [u8]) -> io::Result<StartOutcome> {
        let len = buf.len().min(u32::MAX as usize);
        let buf = &mut buf[..len];
        // SAFETY: `begin`'s closure gets this operation's own `OVERLAPPED`; `buf` is the caller's
        // contract.
        self.begin(handle, |overlapped| unsafe {
            ReadFile(handle, Some(buf), None, Some(overlapped))
        })
    }

    /// Starts one `WriteFile` of up to `u32::MAX` bytes of `buf` on `handle`.
    ///
    /// # Safety
    ///
    /// As [`read`](Self::read), with `buf` unwritten.
    pub(crate) unsafe fn write(&mut self, handle: HANDLE, buf: &[u8]) -> io::Result<StartOutcome> {
        let buf = &buf[..buf.len().min(u32::MAX as usize)];
        // SAFETY: as in `read`.
        self.begin(handle, |overlapped| unsafe {
            WriteFile(handle, Some(buf), None, Some(overlapped))
        })
    }

    fn begin(
        &mut self,
        handle: HANDLE,
        start: impl FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
    ) -> io::Result<StartOutcome> {
        debug_assert!(
            self.state == State::Idle,
            "an operation is started while one is under way"
        );
        self.handle = handle;
        // The low bit of `hEvent` tells the kernel not to queue a completion packet for this
        // operation to a completion port the file object may be associated with. Tokio associates
        // the end it adopts, and a clone of that end shares the association: without the bit, a
        // synchronous read through the clone posts a packet pointing at an `OVERLAPPED` for the
        // reactor to dequeue after its owner is gone.
        *self.overlapped.borrow_mut() = OVERLAPPED {
            hEvent: HANDLE(self.event.as_raw_handle().map_addr(|address| address | 1)),
            ..Default::default()
        };
        match start(self.overlapped.borrow_mut()) {
            Ok(()) => {
                self.state = State::Completed;
                Ok(StartOutcome::Completed)
            }
            Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_IO_PENDING.0) => {
                self.state = State::Pending;
                Ok(StartOutcome::Pending)
            }
            Err(e) => Err(win32_io_error(e)),
        }
    }

    /// Ends the operation: the bytes it moved, or the error it ended with. Call it once the event has
    /// fired, or the start returned [`StartOutcome::Completed`].
    pub(crate) fn finish(&mut self) -> io::Result<usize> {
        debug_assert!(self.state != State::Idle, "finish on an operation that was not started");
        let mut moved = 0u32;
        // SAFETY: the operation is complete, so `overlapped` holds its result; it does not wait. The
        // end is open, by the contract of `read` and `write`.
        let result = unsafe { GetOverlappedResult(self.handle, self.overlapped.borrow(), &mut moved, false) };
        match result {
            Ok(()) => {
                self.state = State::Idle;
                Ok(moved as usize)
            }
            Err(e) => {
                let incomplete = e.code() == windows::core::HRESULT::from_win32(ERROR_IO_INCOMPLETE.0);
                debug_assert!(!incomplete, "finish before the operation's event fired");
                // An operation still under way stays pending: its buffer is not yet ours.
                if !incomplete {
                    self.state = State::Idle;
                }
                Err(win32_io_error(e))
            }
        }
    }
}

/// Cancels the operation if it is pending and waits for the kernel to let go of its buffer, whatever
/// the operation ended with; does nothing if it is idle. The cancel and the wait are the abortable
/// steps (see [`abort_with_buffer_in_kernel`]); the operation's own status is not read as a failure
/// (it is `ERROR_OPERATION_ABORTED` after a cancel).
impl<S: BorrowMut<OVERLAPPED>> Drop for Operation<S> {
    fn drop(&mut self) {
        match self.state {
            State::Idle => return,
            State::Completed => {
                self.state = State::Idle;
                return;
            }
            State::Pending => {}
        }
        // SAFETY: cancels this operation's own `OVERLAPPED`, started on `handle`, which is open by
        // the contract of `read` and `write`.
        if let Err(e) = unsafe { CancelIoEx(self.handle, Some(self.overlapped.borrow())) } {
            // `ERROR_NOT_FOUND`: the operation completed first. Any other error leaves the kernel
            // with the buffer, and unwinding would free it.
            if e.code() != windows::core::HRESULT::from_win32(ERROR_NOT_FOUND.0) {
                abort_with_buffer_in_kernel(&format!("cancelling a pipe operation ({})", crate::error::Report(&e)));
            }
        }
        wait_or_abort(self.event());
        let mut moved = 0u32;
        // SAFETY: the event fired, so the operation is over; it does not wait.
        unsafe { GetOverlappedResult(self.handle, self.overlapped.borrow(), &mut moved, false) }.ok();
        self.state = State::Idle;
    }
}

// Conversions =====

/// A std pipe end is synchronous: each operation completes inside its call, and is still safe to
/// use from several threads at once.
impl From<std::io::PipeReader> for PipeReader {
    fn from(p: std::io::PipeReader) -> PipeReader {
        PipeReader::from(OwnedHandle::from(p))
    }
}

/// A std pipe end is synchronous; see the reader's conversion.
impl From<std::io::PipeWriter> for PipeWriter {
    fn from(p: std::io::PipeWriter) -> PipeWriter {
        PipeWriter::from(OwnedHandle::from(p))
    }
}

/// The handle must be a readable pipe end, overlapped or synchronous.
impl From<OwnedHandle> for PipeReader {
    fn from(handle: OwnedHandle) -> PipeReader {
        PipeReader(Handle { handle })
    }
}

/// The handle must be a writable pipe end, overlapped or synchronous.
impl From<OwnedHandle> for PipeWriter {
    fn from(handle: OwnedHandle) -> PipeWriter {
        PipeWriter(Handle { handle })
    }
}

impl FromRawHandle for PipeReader {
    /// # Safety
    ///
    /// As [`OwnedHandle::from_raw_handle`]: `handle` is open and owned by nothing else. It must be
    /// a readable pipe end.
    unsafe fn from_raw_handle(handle: RawHandle) -> PipeReader {
        // SAFETY: the caller's contract.
        PipeReader::from(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}

impl FromRawHandle for PipeWriter {
    /// # Safety
    ///
    /// As [`OwnedHandle::from_raw_handle`]: `handle` is open and owned by nothing else. It must be
    /// a writable pipe end.
    unsafe fn from_raw_handle(handle: RawHandle) -> PipeWriter {
        // SAFETY: the caller's contract.
        PipeWriter::from(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}

impl From<PipeReader> for OwnedHandle {
    fn from(p: PipeReader) -> OwnedHandle {
        p.0.handle
    }
}

impl From<PipeWriter> for OwnedHandle {
    fn from(p: PipeWriter) -> OwnedHandle {
        p.0.handle
    }
}

impl IntoRawHandle for PipeReader {
    fn into_raw_handle(self) -> RawHandle {
        self.0.handle.into_raw_handle()
    }
}

impl IntoRawHandle for PipeWriter {
    fn into_raw_handle(self) -> RawHandle {
        self.0.handle.into_raw_handle()
    }
}

impl AsHandle for PipeReader {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.handle.as_handle()
    }
}

impl AsHandle for PipeWriter {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.0.handle.as_handle()
    }
}

impl AsRawHandle for PipeReader {
    fn as_raw_handle(&self) -> RawHandle {
        self.0.handle.as_raw_handle()
    }
}

impl AsRawHandle for PipeWriter {
    fn as_raw_handle(&self) -> RawHandle {
        self.0.handle.as_raw_handle()
    }
}

/// The child gets the handle as it is, overlapped or not, as std's own `ChildStdout` does: an
/// overlapped pipe end cannot be made synchronous.
///
/// If the end is overlapped, the parent must not use another handle to it (a
/// [`try_clone`](PipeReader::try_clone), a duplicate) while the child reads or writes through it:
/// the child's plain `ReadFile` waits on the shared file object, so the parent's operation through
/// another handle can wake it.
impl From<PipeReader> for Stdio {
    fn from(p: PipeReader) -> Stdio {
        Stdio::from(OwnedHandle::from(p))
    }
}

/// See the reader's conversion.
impl From<PipeWriter> for Stdio {
    fn from(p: PipeWriter) -> Stdio {
        Stdio::from(OwnedHandle::from(p))
    }
}
