//! The test side of testbin's `block-on-socket` payload.

use std::io::BufRead as _;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;

/// A per-run nonce the payload must echo, so a stray connection to the listener is not taken
/// for it.
pub fn fresh_nonce() -> String {
    use std::hash::{BuildHasher as _, Hasher as _};
    let word = || std::collections::hash_map::RandomState::new().build_hasher().finish();
    format!("{:016x}{:016x}", word(), word())
}

#[derive(Debug)]
pub struct Payload {
    /// EOF on this stream is the payload's death; dropping it releases the payload.
    pub sock: TcpStream,
    /// For messages only.
    pub pid: u32,
    watcher: std::thread::JoinHandle<()>,
}

impl Payload {
    /// Releases the payload, then waits for the `client_exit` closure to return and drop what it
    /// captured. A test whose closure holds the client's `Child` uses this to have that `Child`
    /// dropped (and its `Drop` return) before the test ends.
    pub fn release(self) {
        drop(self.sock);
        self.watcher.join().expect("client-exit watcher panicked");
    }
}

enum Event {
    Line(TcpStream, std::io::Result<String>),
    AcceptFailed(std::io::Error),
    ClientExited(String),
}

/// Accepts connections until one sends `<nonce> <pid>\n`, rejecting the rest. Panics if
/// `client_exit` returns first: the payload's launcher died before the payload arrived. Every
/// blocking step is its own thread racing on one channel, so a peer that connects and never
/// writes stalls only its own reader. `client_exit` blocks until the launcher exits and returns
/// a description of how.
pub fn accept_payload(
    listener: TcpListener,
    nonce: &str,
    client_exit: impl FnOnce() -> String + Send + 'static,
) -> Payload {
    let (tx, rx) = mpsc::channel();
    let watcher = std::thread::spawn({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Event::ClientExited(client_exit()));
        }
    });
    // The original `tx` moves into this thread and the main thread keeps none, so if every
    // sender hangs up `recv` fails instead of blocking forever.
    std::thread::spawn(move || loop {
        match listener.accept() {
            Ok((sock, _)) => {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let mut reader = std::io::BufReader::new(sock);
                    let mut line = String::new();
                    let read = reader.read_line(&mut line).map(|_| line);
                    debug_assert!(reader.buffer().is_empty(), "the payload sends nothing after its line");
                    let _ = tx.send(Event::Line(reader.into_inner(), read));
                });
            }
            Err(e) => {
                let _ = tx.send(Event::AcceptFailed(e));
                return;
            }
        }
    });
    loop {
        match rx.recv().expect("every payload-race thread hung up without a verdict") {
            Event::Line(sock, Ok(line)) => {
                let mut fields = line.split_whitespace();
                if fields.next() == Some(nonce) {
                    if let Some(pid) = fields.next().and_then(|p| p.parse().ok()) {
                        return Payload { sock, pid, watcher };
                    }
                }
            }
            Event::Line(_, Err(_)) => {}
            Event::AcceptFailed(e) => panic!("accepting the payload's connection failed: {e}"),
            Event::ClientExited(how) => panic!("the client exited ({how}) before its payload reported ready"),
        }
    }
}
