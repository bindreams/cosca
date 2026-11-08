//! Windows: stdin, stdout and stderr go through overlapped operations on the calling thread, which
//! waits for whichever completes first.
//!
//! Each open stream has one operation in flight, an [`Op`] with an `OVERLAPPED` and an event of its
//! own and the buffer the kernel reads or writes. The ends are the spawn's (overlapped, made by
//! `child_pipe`).

use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle};

use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{WaitForMultipleObjects, WaitForSingleObject, INFINITE};

use super::{Drain, Pump, Slot, CHUNK};
use crate::pipe::windows::{eof_as_zero, Operation};
use crate::pipe::{PipeReader, PipeWriter};

/// A pipe end and the one operation in flight on it. The operation owns the end, so the handle
/// outlives the operation, and the buffer, so the kernel's view of it is valid until the operation
/// is over.
pub(super) struct Op<E: AsHandle> {
    // Drop order matters: a pending `operation` cancels itself and waits for the kernel to let go
    // when it drops, which must come before the buffer and the end are freed.
    operation: Operation,
    buffer: Vec<u8>,
    end: E,
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
            operation: Operation::new()?,
            buffer: Vec::new(),
            end,
        })
    }

    fn handle(&self) -> HANDLE {
        HANDLE(self.end.as_handle().as_raw_handle())
    }

    /// The event that fires when the operation in flight completes.
    pub(super) fn event(&self) -> HANDLE {
        self.operation.event()
    }

    /// Whether the operation has completed; does not wait.
    pub(super) fn is_done(&self) -> io::Result<bool> {
        // SAFETY: the event is the operation's own, live for the call.
        match unsafe { WaitForSingleObject(self.event(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Ends the operation after it completed: the bytes moved. A read's are in [`buffer`](Self::buffer).
    pub(super) fn complete(&mut self) -> io::Result<usize> {
        self.operation.finish()
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
        // `complete` or the drop; the end is open until then, since `Op` owns it. The `OVERLAPPED`
        // is boxed, so moving the `Op` while pending is fine.
        unsafe { self.operation.read(handle, &mut self.buffer) }.map(|_| ())
    }
}

impl Op<PipeWriter> {
    /// Starts a write of `bytes`.
    ///
    /// # Safety
    ///
    /// `bytes` must stay live and unmoved until the operation ends, in `complete` or the drop.
    pub(super) unsafe fn start_write(&mut self, bytes: &[u8]) -> io::Result<()> {
        let handle = self.handle();
        // SAFETY: `bytes` is the caller's contract; the end is open until the operation ends, since
        // `Op` owns it.
        unsafe { self.operation.write(handle, bytes) }.map(|_| ())
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

    /// Moves bytes until every stream is closed. Fails only when a wait does; the operations still
    /// in flight are then ended by the drop of the pump.
    pub(super) fn run(&mut self) -> io::Result<()> {
        for slot in [Slot::Stdin, Slot::Stdout, Slot::Stderr] {
            self.issue(slot);
        }
        loop {
            // Every open stream has an operation in flight.
            let mut slots = [Slot::Stdin; 3];
            let mut events = [HANDLE::default(); 3];
            let mut open = 0;
            for (slot, event) in [
                (Slot::Stdin, self.feed.as_ref().map(|feed| feed.pipe.event())),
                (Slot::Stdout, self.stdout.pipe.as_ref().map(Op::event)),
                (Slot::Stderr, self.stderr.pipe.as_ref().map(Op::event)),
            ] {
                if let Some(event) = event {
                    slots[open] = slot;
                    events[open] = event;
                    open += 1;
                }
            }
            if open == 0 {
                return Ok(());
            }
            wait_any(&events[..open])?;
            // Every stream whose operation completed is served, as every ready fd is on Unix: what
            // one wait woke for is not the only one that may be done.
            for &slot in &slots[..open] {
                if self.is_done(slot)? {
                    self.complete(slot);
                    self.issue(slot);
                }
            }
        }
    }

    fn is_done(&self, slot: Slot) -> io::Result<bool> {
        match slot {
            Slot::Stdin => self.feed.as_ref().map_or(Ok(false), |feed| feed.pipe.is_done()),
            Slot::Stdout => self.stdout.pipe.as_ref().map_or(Ok(false), Op::is_done),
            Slot::Stderr => self.stderr.pipe.as_ref().map_or(Ok(false), Op::is_done),
        }
    }

    /// Starts the next operation of a stream that is still open. One that cannot even start has
    /// ended the way a completed one would.
    fn issue(&mut self, slot: Slot) {
        match slot {
            Slot::Stdin => {
                let Some(feed) = &mut self.feed else { return };
                let n = feed.rest.len().min(CHUNK);
                // SAFETY: the bytes are the pump's input, `'a`, which outlives the pump and is never
                // moved; the pump's drop ends the operation first.
                if let Err(e) = unsafe { feed.pipe.start_write(&feed.rest[..n]) } {
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
        // A read that succeeds with no bytes is not EOF here (it is on Unix, as `read(2)` has it):
        // the end closing is `ERROR_BROKEN_PIPE`, which `eof_as_zero` turns into the EOF read.
        let read = match op.complete() {
            Ok(0) => return,
            read => eof_as_zero(read),
        };
        if !self.collected.took(read, op.buffer()) {
            self.pipe = None;
        }
    }
}

/// Waits until one of `events` fires. `INFINITE`: each event fires when its in-flight operation
/// completes, so no timeout applies.
fn wait_any(events: &[HANDLE]) -> io::Result<()> {
    // SAFETY: the events are those of live operations, each owned by its `Op`.
    let waited = unsafe { WaitForMultipleObjects(events, false, INFINITE) };
    let index = waited.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
    if index < events.len() {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
#[path = "overlapped_tests.rs"]
mod overlapped_tests;
