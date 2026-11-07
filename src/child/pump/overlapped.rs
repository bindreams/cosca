//! Windows: stdin, stdout and stderr go through overlapped operations on the calling thread, which
//! waits for whichever completes first. No pipe can fill and stall the child, and nothing after the
//! spawn needs a thread, so no thread can fail to be created.
//!
//! Each open stream has one operation in flight, an [`Op`] with an `OVERLAPPED` and an event of its
//! own and the buffer the kernel reads or writes. The ends are the spawn's (overlapped, made by
//! `child_pipe`).

use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle};

use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{WaitForMultipleObjects, INFINITE};

use super::{Drain, Pump, Slot, CHUNK};
use crate::pipe::windows::{eof_as_zero, Operation};
use crate::pipe::{PipeReader, PipeWriter};

/// A pipe end and the one operation in flight on it. The operation owns the end, so the handle
/// outlives the operation, and the buffer, so the kernel's view of it is valid until the operation
/// is over: dropping a pending `Op` cancels it and waits for the kernel to let go first.
pub(super) struct Op<E: AsHandle> {
    // Declaration order is not relied on: `drop` ends the operation before any field is dropped.
    end: E,
    buffer: Vec<u8>,
    operation: Operation,
}

impl<E: AsHandle> Op<E> {
    pub(super) fn new(end: E) -> io::Result<Self> {
        // `is_overlapped` exists only where something asserts with it.
        #[cfg(debug_assertions)]
        assert!(
            crate::pipe::windows::is_overlapped(end.as_handle()).expect("query the end's mode"),
            "communicate drains the spawn's ends, which are overlapped"
        );
        Ok(Op {
            end,
            buffer: Vec::new(),
            operation: Operation::new()?,
        })
    }

    fn handle(&self) -> HANDLE {
        HANDLE(self.end.as_handle().as_raw_handle())
    }

    /// The event that fires when the operation in flight completes.
    pub(super) fn event(&self) -> HANDLE {
        self.operation.event()
    }

    /// Ends the operation after its event fired: the bytes moved. A read's are in [`buffer`](Self::buffer).
    pub(super) fn complete(&mut self) -> io::Result<usize> {
        let handle = self.handle();
        self.operation.finish(handle)
    }

    pub(super) fn buffer(&self) -> &[u8] {
        &self.buffer
    }
}

impl Op<PipeReader> {
    /// Starts a read of up to [`CHUNK`] bytes into the buffer.
    pub(super) fn start_read(&mut self) -> io::Result<()> {
        self.buffer.resize(CHUNK, 0);
        let handle = self.handle();
        // SAFETY: the buffer is this `Op`'s own and is not touched until the operation ends, in
        // `complete` or `drop`; the end is open until then, since `Op` owns it.
        unsafe { self.operation.read(handle, &mut self.buffer) }.map(|_| ())
    }
}

impl Op<PipeWriter> {
    /// Starts a write of `bytes`, copied into the buffer.
    pub(super) fn start_write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.buffer.clear();
        self.buffer.extend_from_slice(bytes);
        let handle = self.handle();
        // SAFETY: as for `start_read`.
        unsafe { self.operation.write(handle, &self.buffer) }.map(|_| ())
    }
}

impl<E: AsHandle> Drop for Op<E> {
    fn drop(&mut self) {
        let handle = self.handle();
        self.operation.cancel(handle);
    }
}

impl<'a> Pump<'a, Op<PipeWriter>, Op<PipeReader>> {
    pub(super) fn new(
        stdin: Option<PipeWriter>,
        input: &'a [u8],
        stdout: Option<PipeReader>,
        stderr: Option<PipeReader>,
    ) -> Self {
        Pump::assemble(stdin, input, stdout, stderr, Op::new, Op::new)
    }

    /// Moves bytes until every stream is closed. Fails only when the wait does; the operations still
    /// in flight are then ended by the drop of the pump.
    pub(super) fn run(&mut self) -> io::Result<()> {
        for slot in [Slot::Stdin, Slot::Stdout, Slot::Stderr] {
            self.issue(slot);
        }
        loop {
            // Every open stream has an operation in flight.
            let mut slots = Vec::with_capacity(3);
            let mut events = Vec::with_capacity(3);
            if let Some(feed) = &self.feed {
                slots.push(Slot::Stdin);
                events.push(feed.pipe.event());
            }
            if let Some(pipe) = &self.stdout.pipe {
                slots.push(Slot::Stdout);
                events.push(pipe.event());
            }
            if let Some(pipe) = &self.stderr.pipe {
                slots.push(Slot::Stderr);
                events.push(pipe.event());
            }
            if events.is_empty() {
                return Ok(());
            }
            let slot = slots[wait_any(&events)?];
            self.complete(slot);
            self.issue(slot);
        }
    }

    /// Starts the next operation of a stream that is still open. One that cannot even start has
    /// ended the way a completed one would.
    fn issue(&mut self, slot: Slot) {
        match slot {
            Slot::Stdin => {
                let Some(feed) = &mut self.feed else { return };
                let n = feed.rest.len().min(CHUNK);
                if let Err(e) = feed.pipe.start_write(&feed.rest[..n]) {
                    self.wrote(Err(e));
                }
            }
            Slot::Stdout => self.stdout.issue(),
            Slot::Stderr => self.stderr.issue(),
        }
    }

    /// Takes the result of the operation of `slot` that completed.
    fn complete(&mut self, slot: Slot) {
        match slot {
            Slot::Stdin => {
                let Some(feed) = &mut self.feed else { return };
                let written = feed.pipe.complete();
                self.wrote(written);
            }
            Slot::Stdout => self.stdout.complete(),
            Slot::Stderr => self.stderr.complete(),
        }
    }
}

impl Drain<Op<PipeReader>> {
    fn issue(&mut self) {
        let Some(op) = &mut self.pipe else { return };
        if let Err(e) = op.start_read() {
            if !self.collected.took(eof_as_zero(Err(e)), &[]) {
                self.pipe = None;
            }
        }
    }

    fn complete(&mut self) {
        let Some(op) = &mut self.pipe else { return };
        let read = eof_as_zero(op.complete());
        if !self.collected.took(read, op.buffer()) {
            self.pipe = None;
        }
    }
}

/// Waits until one of `events` fires: its index. `INFINITE`: an event fires only when its operation
/// completes, and each is one in flight, so there is no time to wait out.
fn wait_any(events: &[HANDLE]) -> io::Result<usize> {
    // SAFETY: the events are those of live operations, each owned by its `Op`.
    let waited = unsafe { WaitForMultipleObjects(events, false, INFINITE) };
    let index = waited.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
    if index < events.len() {
        Ok(index)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
#[path = "overlapped_tests.rs"]
mod overlapped_tests;
