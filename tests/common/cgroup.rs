//! cgroup v2 helpers for the Linux cgroup lane.

/// Fail a lane test run outside the lane. It is `#[ignore]`d, so reaching this means it was
/// requested explicitly, and an unset `COSCA_TEST_CGROUP` is a misconfigured invocation.
pub fn require_lane() {
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "this #[ignore]d test was requested explicitly, but COSCA_TEST_CGROUP is unset: run it \
         in a delegated cgroup with COSCA_TEST_CGROUP=1"
    );
}

/// The cgroup v2 leaf `pid` is in, as an absolute path. Mirrors the join
/// `containment::cgroup` makes for itself: `/proc/<pid>/cgroup`'s `0::` line is relative to
/// this process's cgroup namespace, whose root is `/sys/fs/cgroup`.
pub fn cgroup_of(pid: u32) -> std::path::PathBuf {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("read /proc/<pid>/cgroup");
    let rel = contents
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .expect("a cgroup v2 unified (`0::`) line")
        .to_string();
    std::path::Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'))
}

/// Wait for `leaf` to drain, then remove it, unless something else removes it first.
///
/// A tree whose handle opted out of teardown, still running when the handle drops, leaves its leaf
/// behind, and cosca does not come back for it. Removing it is the test's job, so the lane that counts stray
/// `cosca-*` leaves counts none of the tests' own.
///
/// The wait is on kernel events, never on a clock, and wakes on either of two, armed before the
/// first read: `cgroup.events` changing, and the leaf's removal (`IN_DELETE` on its parent). The
/// second matters because removing a cgroup can cancel the `populated` notification the kernel
/// postponed (see cosca's `DrainWatch`), and the handle's own `Drop` may remove the leaf
/// concurrently: the async handle drops it on a reaper thread. `ENOENT` or `ENODEV` from any step
/// means it is gone, which is the goal.
pub fn drain_and_remove_leaf(leaf: &std::path::Path) {
    wait_drained(leaf);
    match std::fs::remove_dir(leaf) {
        Ok(()) => {}
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ENODEV)) => {}
        Err(e) => panic!("remove the drained leaf: {e}"),
    }
}

/// Block until `leaf` has no live member: `populated` reads 0, or the leaf is gone. See
/// [`drain_and_remove_leaf`] for the wait.
pub fn wait_drained(leaf: &std::path::Path) {
    use std::io::{Read as _, Seek as _, SeekFrom};

    use rustix::fs::inotify;

    let gone = |e: &std::io::Error| matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ENODEV));
    let name = leaf.file_name().expect("a leaf has a name").to_os_string();
    let watch = inotify::init(inotify::CreateFlags::CLOEXEC).expect("create an inotify instance");
    let parent = inotify::add_watch(
        &watch,
        leaf.parent().expect("a leaf has a parent"),
        inotify::WatchFlags::DELETE,
    )
    .expect("watch the leaf's parent");
    match inotify::add_watch(&watch, leaf.join("cgroup.events"), inotify::WatchFlags::MODIFY) {
        Ok(_) => {}
        Err(rustix::io::Errno::NOENT) => return,
        Err(e) => panic!("watch cgroup.events: {e}"),
    }
    let mut events = match std::fs::File::open(leaf.join("cgroup.events")) {
        Ok(f) => f,
        Err(e) if gone(&e) => return,
        Err(e) => panic!("open the leaf's cgroup.events: {e}"),
    };
    let mut buf = String::new();
    loop {
        buf.clear();
        match events
            .seek(SeekFrom::Start(0))
            .and_then(|_| events.read_to_string(&mut buf))
        {
            Ok(_) => {}
            Err(e) if gone(&e) => return,
            Err(e) => panic!("read cgroup.events: {e}"),
        }
        if buf.lines().any(|l| l.trim() == "populated 0") {
            return;
        }
        // Blocks for at least one event. `read` is never restarted after a signal handler, and a
        // tokio runtime in this process handles SIGCHLD: an interrupted read re-reads `populated`.
        let mut raw = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
        let mut reader = inotify::Reader::new(&watch, &mut raw);
        loop {
            match reader.next() {
                Ok(event) => {
                    let named = event
                        .file_name()
                        .is_some_and(|n| n.to_bytes() == name.as_encoded_bytes());
                    if event.wd() == parent && named {
                        return;
                    }
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => panic!("read the inotify watch: {e}"),
            }
            if reader.is_buffer_empty() {
                break;
            }
        }
    }
}

/// Accepts a connection on `listener` and acks it (the handshake in `common::accept`), or fails
/// loudly once `drained` is signalled. For a target whose own pid cannot be watched because it is
/// EXPECTED to exit at once while a descendant it left in the leaf is the one that connects: the
/// leaf emptying is the death of every possible connector.
///
/// `drained` is an `eventfd` that a watcher thread writes when the leaf drains (`wait_tree`
/// returning). The watcher only signals; this thread is the only one that ever calls `accept()`.
/// One `poll()` waits on both. A connector waits for the ack after connecting, so it cannot have
/// drained the leaf with a connection still queued: a drain with nothing accepted is a failure.
pub fn accept_or_signalled(listener: &std::net::TcpListener, drained: &rustix::fd::OwnedFd) -> std::net::TcpStream {
    use std::os::fd::AsRawFd as _;

    let mut fds = [
        libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: drained.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `fds` is a valid, correctly-sized array for the call's duration.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            panic!("poll while waiting for a connection: {e}");
        }
        if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            panic!("the listener reported an error (revents={:#x})", fds[0].revents);
        }
        // The drain is checked first, as `accept_or_die` checks exits first.
        if fds[1].revents & libc::POLLIN != 0 {
            panic!("the leaf drained before anything connected");
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let (stream, _) = listener.accept().expect("accept a connection");
            return super::accept::ack_now(stream);
        }
    }
}
