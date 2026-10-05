//! A shim played by the test: connects to the link's socket and writes whatever bytes it likes.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc::Receiver;

use super::probe::LinkEvent;
use super::SOCKET_NAME;
use crate::elevation::shim::protocol::Frame;

pub(crate) struct FakeShim(UnixStream);

impl FakeShim {
    /// Connects the way the real shim will: relative to the directory's descriptor on Linux, so a
    /// long path cannot overflow `sun_path`; by full path on macOS.
    pub(crate) fn connect(dir: &Path) -> io::Result<FakeShim> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let held = std::fs::File::open(dir)?;
            UnixStream::connect(format!("/proc/thread-self/fd/{}/{SOCKET_NAME}", held.as_raw_fd())).map(FakeShim)
        }
        #[cfg(not(target_os = "linux"))]
        UnixStream::connect(dir.join(SOCKET_NAME)).map(FakeShim)
    }

    pub(crate) fn hello(&mut self) {
        self.send(b"H");
    }

    pub(crate) fn send(&mut self, bytes: &[u8]) {
        self.0.write_all(bytes).expect("the link's end is open");
    }

    pub(crate) fn send_frame(&mut self, frame: Frame) {
        self.send(&frame.encode());
    }

    /// The next byte cosca sent, or `None` once the link closed its end.
    pub(crate) fn read_byte(&mut self) -> Option<u8> {
        let mut byte = [0u8];
        match self.0.read(&mut byte) {
            Ok(1) => Some(byte[0]),
            // A reset is the link closing with our hello unread.
            Ok(_) | Err(_) => None,
        }
    }

    pub(crate) fn close(self) {
        drop(self);
    }
}

/// The next event the acceptor emitted, skipping those of waiters.
pub(crate) fn next_acceptor_event(rx: &Receiver<LinkEvent>) -> LinkEvent {
    loop {
        match rx.recv().expect("the link's probe outlives its events") {
            LinkEvent::Parked(_) | LinkEvent::Read(..) => continue,
            event => return event,
        }
    }
}

/// A link bound in a fresh temp directory, with a test probe.
pub(crate) struct Rig {
    pub(crate) link: super::ShimLink,
    pub(crate) probe: super::probe::Probe,
    pub(crate) events: Receiver<LinkEvent>,
    /// Removed last, after the link has torn its directory down.
    pub(crate) tmp: tempfile::TempDir,
}

pub(crate) fn my_euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

impl Rig {
    /// A link that takes this process's own euid for root's, so a test needs no privilege.
    pub(crate) fn new() -> Rig {
        Rig::with_peer_euid(my_euid())
    }

    pub(crate) fn with_peer_euid(peer_euid: u32) -> Rig {
        crate::log_capture::install();
        let tmp = tempfile::tempdir().expect("a temp directory");
        let (probe, events) = super::probe::Probe::new();
        let link = super::ShimLink::bind_probed(tmp.path(), peer_euid, probe.clone()).expect("the link binds");
        Rig {
            link,
            probe,
            events,
            tmp,
        }
    }

    /// A link whose directory is under a temp directory nested deeper than `min_len` bytes.
    #[cfg(target_os = "linux")]
    pub(crate) fn deep(min_len: usize) -> Rig {
        let tmp = tempfile::tempdir().expect("a temp directory");
        let base = crate::elevation::shim::private_dir::PrivateDir::resolve(tmp.path()).unwrap();
        let nested = nested_of_len(&base, min_len + 1);
        Rig::bind_at(tmp, &nested)
    }

    /// A link whose temp directory has exactly the real path length `len`.
    pub(crate) fn at_real_len(len: usize) -> Rig {
        let tmp = tempfile::tempdir().expect("a temp directory");
        let base = crate::elevation::shim::private_dir::PrivateDir::resolve(tmp.path()).unwrap();
        let nested = nested_of_len(&base, len);
        Rig::bind_at(tmp, &nested)
    }

    fn bind_at(tmp: tempfile::TempDir, at: &Path) -> Rig {
        crate::log_capture::install();
        let (probe, events) = super::probe::Probe::new();
        let link = super::ShimLink::bind_probed(at, my_euid(), probe.clone()).expect("the link binds");
        Rig {
            link,
            probe,
            events,
            tmp,
        }
    }

    pub(crate) fn connect(&self) -> FakeShim {
        FakeShim::connect(self.link.dir()).expect("the socket accepts a connection")
    }

    /// The acceptor's next event, which must be `expected`.
    pub(crate) fn expect_event(&self, expected: LinkEvent) {
        assert_eq!(next_acceptor_event(&self.events), expected);
    }

    /// A shim that said hello and was answered `A`.
    pub(crate) fn live(&self) -> FakeShim {
        let mut shim = self.connect();
        shim.hello();
        self.expect_event(LinkEvent::Accepted);
        self.expect_event(LinkEvent::Answered(crate::elevation::shim::protocol::Command::Allow));
        assert_eq!(shim.read_byte(), Some(b'A'));
        shim
    }

    /// The text every log line about this link contains.
    pub(crate) fn log_marker(&self) -> String {
        self.link.dir().display().to_string()
    }
}

/// Directories under `base` (a real path), made `0700`, so that the deepest has a path of exactly
/// `len` bytes. Components are at most 200 bytes. `base` must be shorter than `len`.
pub(crate) fn nested_of_len(base: &Path, len: usize) -> std::path::PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let mut path = base.to_owned();
    while path.as_os_str().len() < len {
        let remaining = len - path.as_os_str().len();
        assert!(remaining >= 2, "cannot reach {len} from {}", path.display());
        let mut component = (remaining - 1).min(200);
        if remaining - (component + 1) == 1 {
            component -= 1;
        }
        path.push("n".repeat(component));
    }
    assert_eq!(path.as_os_str().len(), len);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&path)
        .expect("the nested directories");
    path
}
