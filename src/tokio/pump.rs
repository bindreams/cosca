//! Async `communicate`: write input to stdin (drop it for EOF) and read stdout + stderr to EOF
//! concurrently with `wait`, via `tokio::try_join!` — close-stdin-then-read-both with zero
//! threads. A child closing stdin early (BrokenPipe) is a normal EOF, not an error.

use ::tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::Error;
use crate::Output;

use super::child::Child;

impl Child {
    pub async fn communicate(&mut self, input: Option<Vec<u8>>) -> Result<Output, Error> {
        // Take the three streams into owned locals BEFORE the join: only `wait` then borrows
        // `self.child` (so the four-future join compiles), and tokio's `Child::wait` internally
        // drops `self.child.stdin`, already None here, so it cannot race the write future.
        let mut stdin = self.stdin();
        let mut stdout = self.stdout();
        let mut stderr = self.stderr();
        // Caller contract: input can only be delivered if stdin was piped — surface the misuse
        // rather than silently dropping the bytes.
        debug_assert!(
            input.is_none() || stdin.is_some(),
            "communicate given input but stdin was not piped"
        );

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
                    w.write_all(bytes).await.or_else(swallow_broken_pipe)?;
                    w.flush().await.or_else(swallow_broken_pipe)?;
                }
                drop(w); // EOF
            }
            Ok::<(), std::io::Error>(())
        };
        let read_out = async {
            let mut buf = Vec::new();
            if let Some(mut r) = stdout.take() {
                r.read_to_end(&mut buf).await?;
            }
            Ok::<Vec<u8>, std::io::Error>(buf)
        };
        let read_err = async {
            let mut buf = Vec::new();
            if let Some(mut r) = stderr.take() {
                r.read_to_end(&mut buf).await?;
            }
            Ok::<Vec<u8>, std::io::Error>(buf)
        };
        let wait = async { self.child.wait().await };

        let ((), out, err, status) = ::tokio::try_join!(write, read_out, read_err, wait).map_err(Error::Io)?;
        Ok(Output {
            status,
            stdout: out,
            stderr: err,
        })
    }
}
