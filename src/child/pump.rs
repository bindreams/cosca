//! Deadlock-free I/O: one thread per active stream so stdin/stdout/stderr are
//! serviced concurrently and no full pipe buffer can wedge the others.

use std::io::{Read, Write};
use std::thread;

use crate::child::Child;
use crate::error::Error;
use crate::stdio::Fd;
use crate::Output;

pub(crate) fn communicate(child: &mut Child, input: Option<&[u8]>) -> Result<Output, Error> {
    // Move the parent ends out so the borrow of `child` for `wait()` is free
    // while the pump threads own the pipes.
    let stdin = child.take_stdin_writer();
    let stdout = child.take_reader(Fd::STDOUT);
    let stderr = child.take_reader(Fd::STDERR);

    thread::scope(|scope| -> Result<Output, Error> {
        // Writer: feed input, then drop the write end so the child sees EOF.
        // If there is a stdin pipe but no input, closing it immediately gives EOF.
        let writer = stdin.map(|mut w| {
            let data = input.unwrap_or(&[]).to_vec();
            scope.spawn(move || -> std::io::Result<()> {
                // A child that exits early makes writes fail with BrokenPipe;
                // that is a clean end-of-input, not an error.
                match w.write_all(&data) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                    Err(e) => return Err(e),
                }
                drop(w); // EOF for the child
                Ok(())
            })
        });

        let out_reader = stdout.map(|mut r| {
            scope.spawn(move || -> std::io::Result<Vec<u8>> {
                let mut buf = Vec::new();
                r.read_to_end(&mut buf)?;
                Ok(buf)
            })
        });
        let err_reader = stderr.map(|mut r| {
            scope.spawn(move || -> std::io::Result<Vec<u8>> {
                let mut buf = Vec::new();
                r.read_to_end(&mut buf)?;
                Ok(buf)
            })
        });

        // Wait concurrently with the pumps (wait() borrows only the wait handle).
        let status = child.wait()?;

        let stdout = join_bytes(out_reader)?;
        let stderr = join_bytes(err_reader)?;
        if let Some(h) = writer {
            h.join().expect("stdin pump thread panicked").map_err(Error::Io)?;
        }
        Ok(Output { status, stdout, stderr })
    })
}

fn join_bytes(h: Option<thread::ScopedJoinHandle<'_, std::io::Result<Vec<u8>>>>) -> Result<Vec<u8>, Error> {
    match h {
        Some(h) => h.join().expect("reader pump thread panicked").map_err(Error::Io),
        None => Ok(Vec::new()),
    }
}
