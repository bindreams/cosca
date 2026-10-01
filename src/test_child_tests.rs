//! Unit tests for the fixtures in `test_child`: [`super::RestoreMode`], plus controls for the
//! assumptions a test's assertion leans on, run against the fixture alone so a wrong one fails
//! here and not as a confusing failure elsewhere.

#[cfg(unix)]
mod restore_mode_tests {
    use crate::test_child::RestoreMode;
    use std::os::unix::fs::PermissionsExt as _;

    /// `TempDir::drop` needs to list a directory to remove it, so a locked one would leak without
    /// the restore. This mirrors the declaration order callers rely on (`dir`, then `_restore`).
    #[test]
    fn a_locked_dir_is_removed_on_drop() {
        let path = {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir(dir.path().join("inner")).unwrap();
            let locked = dir.path().join("inner");
            let _restore = RestoreMode::new(&locked, 0o755);
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            dir.path().to_path_buf()
        };
        assert!(!path.exists(), "{path:?} was not removed on drop");
    }
}

/// [`windows_more`](super::windows_more) exits 0 when its stdin closes. Every Windows test that
/// takes a non-zero exit as proof of a kill relies on this: were it non-zero, a natural end would
/// read as a kill.
#[cfg(windows)]
#[test]
fn windows_more_exits_zero_when_its_stdin_closes() {
    let mut cmd = crate::Command::new();
    cmd.args([super::windows_more()]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    let mut child = cmd.spawn().expect("spawn");
    drop(child.stdin().expect("piped stdin"));
    let status = child.wait().expect("wait");
    assert!(
        status.success(),
        "more.com must exit 0 on stdin EOF, or a natural end reads as a kill: {status:?}"
    );
}

/// macOS `kevent` returns `EINTR` even under `SA_RESTART`, so a signal handled while
/// `watch_macos` is parked must retry the wait, not panic. The helper
/// signals the waiting thread, then closes the target's stdin: the wait must survive the signal
/// and still report the exit.
#[cfg(target_os = "macos")]
#[test]
fn death_watch_accept_or_die_retries_a_kevent_wait_interrupted_by_a_signal() {
    use super::kevent_eintr;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind rendezvous listener");
    let mut cmd = std::process::Command::new("/bin/cat");
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn a target that waits for its stdin to close");
    let target = crate::Process::from_pid(child.id())
        .found()
        .expect("resolve the freshly spawned target")
        .id();
    let stdin = child.stdin.take();
    let interrupter = kevent_eintr::interrupt_once_blocked(move || drop(stdin));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::test_child::accept_or_die(&listener, target)
    }));
    interrupter.finish();
    let payload = result.expect_err("accept_or_die must panic for an exited target");
    let message = payload.downcast_ref::<String>().cloned().expect("string panic payload");
    assert_eq!(
        message,
        format!("the control target (pid {}) died before it connected", target.pid())
    );
    child.wait().expect("reap the target");
}

/// Windows `accept_or_signalled`: a connection that arrives while nothing has drained is accepted
/// and acked, and its stream is returned.
#[cfg(windows)]
#[test]
fn death_watch_accept_or_signalled_returns_the_acked_connection_while_nothing_has_drained() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let drained = super::DrainSignal::new();
    let client = std::thread::spawn(move || {
        let mut sock = std::net::TcpStream::connect(addr).expect("connect");
        let mut ack = [0u8; 1];
        sock.read_exact(&mut ack).expect("read the ack");
        sock.write_all(b"T").expect("write the tag");
        ack[0]
    });
    let mut stream = super::accept_or_signalled(&listener, &drained);
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).expect("read the tag");
    assert_eq!(&tag, b"T");
    assert_eq!(client.join().expect("the client"), super::ack::ACK_BYTE);
}

/// A drain and a queued connection both ready: the drain wins.
#[cfg(windows)]
#[test]
fn death_watch_accept_or_signalled_reports_the_drain_when_a_connection_is_also_queued() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let _queued = std::net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
    let drained = super::DrainSignal::new();
    drained.record(Ok::<_, String>("AllMembersExited"));
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::accept_or_signalled(&listener, &drained)
    }))
    .expect_err("a drain must panic");
    let message = payload.downcast_ref::<String>().cloned().expect("string panic payload");
    assert_eq!(
        message,
        "the tree drained (\"AllMembersExited\") before anything connected"
    );
}

/// A watcher whose `wait_tree` panics still wakes the acceptor, with an error.
#[cfg(windows)]
#[test]
fn death_watch_a_panicking_watcher_wakes_the_acceptor_with_an_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let drained = super::DrainSignal::new();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drained.watch(|| -> Result<(), String> { panic!("wait_tree blew up") })
    }));
    assert!(unwound.is_err(), "the watcher's panic must propagate");
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::accept_or_signalled(&listener, &drained)
    }))
    .expect_err("an errored watcher must panic");
    let message = payload.downcast_ref::<String>().cloned().expect("string panic payload");
    assert_eq!(
        message,
        "wait_tree failed while waiting for a connection: the watcher panicked before wait_tree returned"
    );
}
