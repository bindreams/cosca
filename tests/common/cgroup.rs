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
/// The wait is on the kernel's own edge, never on a clock: `cgroup.events`'s `populated` flips
/// 1 -> 0 exactly when the leaf's last task exits, and `POLLPRI` fires on that transition.
/// `populated` is read before every poll, so a transition that already happened is seen on the
/// read rather than waited out for an edge that will not fire again.
///
/// The handle's own `Drop` may remove the leaf concurrently: the async handle drops it on a
/// reaper thread. `ENOENT` or `ENODEV` from any step means it is gone, which is the goal.
pub fn drain_and_remove_leaf(leaf: &std::path::Path) {
    use std::io::{Read as _, Seek as _, SeekFrom};

    use rustix::event::{poll, PollFd, PollFlags};

    let gone = |e: &std::io::Error| matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ENODEV));
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
            break;
        }
        let mut fds = [PollFd::new(&events, PollFlags::PRI)];
        // `poll` is never restarted after a signal handler, and a tokio runtime in this process
        // handles SIGCHLD. An interrupted poll re-reads `populated` like any other wakeup.
        match poll(&mut fds, None) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(e) => panic!("poll cgroup.events: {e}"),
        }
    }
    match std::fs::remove_dir(leaf) {
        Ok(()) => {}
        Err(e) if gone(&e) => {}
        Err(e) => panic!("remove the drained leaf: {e}"),
    }
}
