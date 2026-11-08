//! Async `communicate`: write input to stdin (drop it for EOF) and read stdout + stderr to EOF
//! concurrently with `wait`, via `tokio::try_join!` — close-stdin-then-read-both with zero
//! threads. A child closing stdin early (BrokenPipe) is a normal EOF, not an error.

use ::tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::Error;
use crate::Output;

use super::child::Child;

impl Child {
    /// Writes `input` to stdin, then closes it, and reads stdout and stderr to EOF while waiting
    /// for the child. The sync [`communicate`](crate::Child::communicate) has the details.
    ///
    /// `input` of `Some` for a child whose stdin is not piped, or was already taken, is an
    /// [`Error::Io`] of kind `InvalidInput`; no pipe is taken then. A stdin the reactor refuses to
    /// register fails with the reactor's error, with or without input; its end is closed, so the
    /// child sees EOF, and stdout and stderr stay in place.
    pub async fn communicate(&mut self, input: Option<Vec<u8>>) -> Result<Output, Error> {
        #[cfg(test)]
        if let Some(error) = crate::child::spawn::failure::seams::take_pump_failure() {
            return Err(error);
        }
        // Take the three streams into owned locals BEFORE the join: only `wait` then borrows
        // `self.proc_mut()` (so the four-future join compiles). The inner wait closes no stdin; only
        // the write future, which owns it, does.
        let mut stdin = self.stdin_or_error().map_err(Error::Io)?;
        if input.is_some() && stdin.is_none() {
            return Err(crate::child::pump::input_without_stdin());
        }
        let mut stdout = self.stdout();
        let mut stderr = self.stderr();

        let write = async {
            // A child that exits without consuming all input closes the pipe early; a BrokenPipe
            // (on write OR flush) is a benign EOF — but surface any real I/O error.
            fn swallow_broken_pipe(e: std::io::Error) -> Result<(), std::io::Error> {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    Ok(())
                } else {
                    Err(e)
                }
            }
            if let Some(mut w) = stdin.take() {
                if let Some(bytes) = input.as_ref() {
                    w.write_all(bytes)
                        .await
                        .or_else(swallow_broken_pipe)
                        .map_err(Error::Io)?;
                    w.flush().await.or_else(swallow_broken_pipe).map_err(Error::Io)?;
                }
                drop(w); // EOF
            }
            Ok::<(), Error>(())
        };
        let read_out = async {
            let mut buf = Vec::new();
            if let Some(mut r) = stdout.take() {
                r.read_to_end(&mut buf).await.map_err(Error::Io)?;
            }
            Ok::<Vec<u8>, Error>(buf)
        };
        let read_err = async {
            let mut buf = Vec::new();
            if let Some(mut r) = stderr.take() {
                r.read_to_end(&mut buf).await.map_err(Error::Io)?;
            }
            Ok::<Vec<u8>, Error>(buf)
        };
        // `wait` is the sole borrow of `self` here (already mapped to `Error`); the stream futures
        // own their taken locals, so the four-future join has no aliasing conflict.
        let wait = async { self.proc_mut().wait().await };

        let ((), out, err, status) = ::tokio::try_join!(write, read_out, read_err, wait)?;
        Ok(Output {
            status,
            stdout: out,
            stderr: err,
        })
    }
}
