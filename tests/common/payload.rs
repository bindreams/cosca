//! The test side of testbin's `block-on-socket` payload.

use std::io::Read as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;

/// A per-run nonce the payload must echo, so a stray connection to the listener is not taken
/// for it.
pub fn fresh_nonce() -> String {
    use std::hash::{BuildHasher as _, Hasher as _};
    let word = || std::collections::hash_map::RandomState::new().build_hasher().finish();
    format!("{:016x}{:016x}", word(), word())
}

/// How [`accept_payload`] learns that the payload's launcher died before the payload arrived.
///
/// No variant may own the launcher's `Child`: the test under way often drops that `Child` to
/// check that its `Drop` returns, and a watcher holding the other reference would make that drop
/// a no-op decrement.
pub enum ExitWatch {
    /// An OS exit notification for `pid` (a `pidfd`, `kqueue` `NOTE_EXIT`, or process HANDLE),
    /// armed before [`accept_payload`] goes on. The pid must be an unreaped child of this process,
    /// and this process must not reap it before the payload is accepted.
    Process(u32),
    /// A closure that blocks until the launcher exits and describes how. For tests of the wiring
    /// itself, where the "launcher" is a channel.
    Custom(Box<dyn FnOnce() -> String + Send>),
    /// No notification is available: a medium-integrity Windows parent cannot open a UAC-elevated
    /// child by pid, and the crate exposes no handle to wait on. A launcher that dies before its
    /// payload connects then leaves the accept blocked.
    Unobservable,
}

impl ExitWatch {
    pub fn custom(f: impl FnOnce() -> String + Send + 'static) -> ExitWatch {
        ExitWatch::Custom(Box::new(f))
    }
}

#[derive(Debug)]
pub struct Payload {
    /// EOF on this stream is the payload's death; dropping it releases the payload.
    pub sock: TcpStream,
    /// For messages only.
    pub pid: u32,
    watcher: Option<JoinHandle<()>>,
}

impl Payload {
    /// Releases the payload, then waits for the exit watch to return. A launcher that exits
    /// only once the payload does is thereby known to have exited.
    pub fn release(self) {
        drop(self.sock);
        if let Some(watcher) = self.watcher {
            watcher.join().expect("client-exit watcher panicked");
        }
    }
}

/// What the threads behind [`accept_payload`] report to its deciding loop.
#[derive(Debug)]
pub enum Event {
    /// A peer's first line, or why it has none. Carries the peer's socket.
    Line(TcpStream, std::io::Result<String>),
    AcceptFailed(std::io::Error),
    ClientExited(String),
}

/// Reads one `\n`-terminated line a byte at a time, so nothing past it is consumed: whatever else
/// a peer sends stays in the socket, and nothing a stranger sends can trip an assertion.
pub fn read_peer(mut sock: TcpStream) -> Event {
    let mut line = Vec::new();
    let read = loop {
        let mut byte = [0u8; 1];
        match sock.read(&mut byte) {
            Ok(0) => break Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(_) if byte[0] == b'\n' => {
                break String::from_utf8(line).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            }
            Ok(_) => line.push(byte[0]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => break Err(e),
        }
    };
    Event::Line(sock, read)
}

/// The deciding loop: the first peer to send `<nonce> <pid>` wins, every other peer is rejected,
/// and the launcher's exit or a failed accept ends it with a message. Pure over `events`, so a
/// test can script them; an exhausted iterator is a verdict too, not a wait.
pub fn decide(nonce: &str, events: impl IntoIterator<Item = Event>) -> Result<(TcpStream, u32), String> {
    for event in events {
        match event {
            Event::Line(sock, Ok(line)) => {
                let mut fields = line.split_whitespace();
                if fields.next() == Some(nonce) {
                    if let Some(pid) = fields.next().and_then(|p| p.parse().ok()) {
                        return Ok((sock, pid));
                    }
                }
            }
            Event::Line(_, Err(_)) => {}
            Event::AcceptFailed(e) => return Err(format!("accepting the payload's connection failed: {e}")),
            Event::ClientExited(how) => {
                return Err(format!("the client exited ({how}) before its payload reported ready"))
            }
        }
    }
    Err("every payload-race thread hung up without a verdict".into())
}

/// The threads behind [`accept_payload`]: one accepting, one per peer reading its line, and one
/// watching the launcher, all reporting on one channel, so a peer that connects and never writes
/// stalls only its own reader.
pub struct Sources {
    rx: mpsc::Receiver<Event>,
    watcher: Option<JoinHandle<()>>,
    acceptor: JoinHandle<()>,
    stop: Arc<AtomicBool>,
    addr: SocketAddr,
}

impl Sources {
    /// Starts the threads. Returns once the launcher watch, if it is an OS one, is armed.
    pub fn start(listener: TcpListener, watch: ExitWatch) -> Sources {
        let addr = listener.local_addr().expect("local_addr of the readiness listener");
        let (tx, rx) = mpsc::channel();
        let watcher = match watch {
            ExitWatch::Unobservable => None,
            ExitWatch::Custom(client_exit) => {
                let tx = tx.clone();
                Some(std::thread::spawn(move || {
                    let _ = tx.send(Event::ClientExited(client_exit()));
                }))
            }
            ExitWatch::Process(pid) => {
                let tx = tx.clone();
                let (armed_tx, armed_rx) = mpsc::channel::<()>();
                let watcher = std::thread::spawn(move || {
                    super::accept::with_armed_hook(
                        move || {
                            let _ = armed_tx.send(());
                        },
                        || super::accept::wait_for_exit(pid),
                    );
                    let _ = tx.send(Event::ClientExited(format!("process {pid} exited")));
                });
                // `Err` means the thread ended without arming: the pid was already gone.
                let _ = armed_rx.recv();
                Some(watcher)
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let acceptor = std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || loop {
                match listener.accept() {
                    Ok(_) if stop.load(Ordering::SeqCst) => return,
                    Ok((sock, _)) => {
                        let tx = tx.clone();
                        std::thread::spawn(move || {
                            let _ = tx.send(read_peer(sock));
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(Event::AcceptFailed(e));
                        return;
                    }
                }
            }
        });
        Sources {
            rx,
            watcher,
            acceptor,
            stop,
            addr,
        }
    }

    /// Ends the accepting thread: it is blocked in `accept`, and a connection to its own address
    /// is what returns it. Closes the listener.
    fn stop_accepting(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // A failed connect means `accept` already returned an error, and the thread has ended.
        let _ = TcpStream::connect(self.addr);
    }

    /// Waits for the launcher watch to return, stops accepting, and returns everything reported
    /// so far. For tests of the wiring: unlike [`accept_payload`] it cannot block on an event
    /// that never comes.
    pub fn settle(self) -> Vec<Event> {
        if let Some(watcher) = self.watcher {
            watcher.join().expect("client-exit watcher panicked");
        }
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        self.acceptor.join().expect("accepting thread panicked");
        self.rx.try_iter().collect()
    }
}

/// Accepts connections until one sends `<nonce> <pid>\n`, rejecting the rest. Panics if the
/// launcher dies first ([`ExitWatch`]): the payload's launcher died before the payload arrived.
pub fn accept_payload(listener: TcpListener, nonce: &str, watch: ExitWatch) -> Payload {
    let sources = Sources::start(listener, watch);
    // The threads hold every sender and the main thread none, so if all hang up the iterator
    // ends instead of blocking forever.
    let verdict = decide(nonce, sources.rx.iter());
    sources.stop_accepting();
    match verdict {
        Ok((sock, pid)) => Payload {
            sock,
            pid,
            watcher: sources.watcher,
        },
        Err(message) => panic!("{message}"),
    }
}
