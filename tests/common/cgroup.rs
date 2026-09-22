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
/// A tree whose handle opted out of teardown keeps its leaf, and nothing — cosca, or any
/// cgroup manager — ever revisits a `cosca-*` cgroup, so a test that walks away from one adds
/// a permanent stray to the very lane that counts them (issue #140). Cleaning up is the test's
/// own job, exactly as it is `drop_warns_for_a_real_leaf_held_by_a_descendant_cgroup`'s.
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
        poll(&mut fds, None).expect("poll cgroup.events");
    }
    std::fs::remove_dir(leaf).expect("remove the drained leaf");
}
