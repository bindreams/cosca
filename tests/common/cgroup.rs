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

/// Wait for `leaf` to drain, then remove it.
///
/// A tree still running or still exiting when its handle drops leaves its leaf behind, and cosca
/// does not come back for it. Removing it is the test's job, so the lane that counts stray
/// `cosca-*` leaves counts none of the tests' own.
///
/// The wait is on the kernel's own edge, never on a clock: `cgroup.events`'s `populated` flips
/// 1 -> 0 exactly when the leaf's last task exits, and `POLLPRI` fires on that transition.
/// `populated` is read before every poll, so a transition that already happened is seen on the
/// read rather than waited out for an edge that will not fire again.
pub fn drain_and_remove_leaf(leaf: &std::path::Path) {
    use std::io::{Read as _, Seek as _, SeekFrom};

    use rustix::event::{poll, PollFd, PollFlags};

    let mut events = std::fs::File::open(leaf.join("cgroup.events")).expect("open the leaf's cgroup.events");
    let mut buf = String::new();
    loop {
        buf.clear();
        events.seek(SeekFrom::Start(0)).expect("rewind cgroup.events");
        events.read_to_string(&mut buf).expect("read cgroup.events");
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
    std::fs::remove_dir(leaf).expect("remove the drained leaf");
}
