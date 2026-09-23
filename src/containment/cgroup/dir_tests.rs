use std::os::fd::AsRawFd;

use super::{fd_path, LeafDir};

/// `fd_path` names the calling thread's own descriptor, even in a thread that no longer shares
/// the process's descriptor table: there `/proc/self/fd/<n>` is the thread-group leader's `<n>`.
///
/// Container seccomp profiles refuse `unshare`, so the lane, which runs unconfined, runs this.
#[test]
#[ignore = "requires unshare(CLONE_FILES), which container seccomp profiles refuse; run in the cgroup lane"]
fn cgroup_fd_path_names_the_calling_threads_own_descriptor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (leader_file, thread_file) = (dir.path().join("leader"), dir.path().join("thread"));
    std::fs::write(&leader_file, "").expect("create the leader's file");
    std::fs::write(&thread_file, "").expect("create the thread's file");
    // One descriptor number, shared until the thread unshares.
    let shared = std::fs::File::open(&leader_file).expect("open the leader's file");
    let n = shared.as_raw_fd();

    let thread_file_ = thread_file.clone();
    let named = std::thread::spawn(move || {
        // SAFETY: `unshare(CLONE_FILES)` gives this thread a private copy of the table.
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_FILES) },
            0,
            "unshare: {}",
            std::io::Error::last_os_error()
        );
        let own = std::fs::File::open(&thread_file_).expect("open the thread's file");
        // SAFETY: `n` is open in this thread's private table; replacing it touches only that table.
        assert_eq!(unsafe { libc::dup2(own.as_raw_fd(), n) }, n, "dup2");
        // SAFETY: `n` is open in this thread's table for the borrow's whole life.
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(n) };
        std::fs::metadata(fd_path(borrowed)).expect("stat through fd_path")
    })
    .join()
    .expect("the thread");

    use std::os::unix::fs::MetadataExt as _;
    let expected = std::fs::metadata(&thread_file).expect("stat the thread's file");
    assert_eq!(
        (named.dev(), named.ino()),
        (expected.dev(), expected.ino()),
        "fd_path must name this thread's descriptor, not the leader's"
    );
    drop(shared);
}

/// A leaf whose directory was made but could not be held is removed again, not leaked.
#[test]
fn a_leaf_that_cannot_be_held_after_its_mkdir_is_removed() {
    let dir = tempfile::tempdir().expect("tempdir");
    crate::containment::cgroup::fault::set_force_leaf_open_failure(true);
    let err = match LeafDir::create(dir.path(), "cosca-unheld") {
        Err(e) => e,
        Ok(_) => panic!("the forced open failure must fail the creation"),
    };
    assert!(
        !crate::containment::cgroup::fault::take_force_leaf_open_failure(),
        "the seam must be consumed"
    );
    assert_eq!(err.raw_os_error(), Some(libc::EMFILE), "got {err}");
    assert!(
        !dir.path().join("cosca-unheld").exists(),
        "the made directory must be removed"
    );
}

/// Mounts are never crossed by the child sweep. A bind mount inside a leaf keeps whatever it
/// shows: an unprivileged run cannot mount, so the lane runs this one.
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_the_child_sweep_never_crosses_a_mount() {
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "this #[ignore]d test was requested explicitly, but COSCA_TEST_CGROUP is unset"
    );
    let victim = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(victim.path().join("keep/me")).expect("make the victim's empty dirs");
    let victim_path = victim.path().to_path_buf();
    // The lane's own cgroup, which may hold child cgroups.
    let own = std::fs::read_to_string("/proc/self/cgroup").expect("read /proc/self/cgroup");
    let parent = std::path::Path::new("/sys/fs/cgroup").join(
        own.lines()
            .find_map(|l| l.strip_prefix("0::/"))
            .expect("a unified line"),
    );
    let name = format!("cosca-{}-sweep", std::process::id());
    let sub = parent.join(&name).join("sub");
    let sub_in_thread = sub.clone();

    let swept = std::thread::spawn(move || {
        use std::ffi::CString;

        let c = |p: &std::path::Path| CString::new(p.as_os_str().as_encoded_bytes()).expect("no NUL");
        // SAFETY: plain syscalls on valid NUL-terminated strings. `unshare` gives this thread
        // alone a mount namespace; making it private first keeps the bind below in it.
        unsafe {
            assert_eq!(
                libc::unshare(libc::CLONE_NEWNS),
                0,
                "unshare: {}",
                std::io::Error::last_os_error()
            );
            assert_eq!(
                libc::mount(
                    std::ptr::null(),
                    c(std::path::Path::new("/")).as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null()
                ),
                0,
                "make / private: {}",
                std::io::Error::last_os_error()
            );
        }
        let leaf = LeafDir::create(&parent, &name).expect("create the leaf");
        let sub = sub_in_thread;
        std::fs::create_dir(&sub).expect("make a child cgroup");
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                libc::mount(
                    c(&victim_path).as_ptr(),
                    c(&sub).as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null()
                ),
                0,
                "bind the victim over the child: {}",
                std::io::Error::last_os_error()
            );
        }
        leaf.remove_children()
    })
    .join()
    .expect("the sweeping thread");

    // The dropping thread's namespace, and its bind, are gone with it: nothing is mounted in ours.
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
    assert!(
        !mounts.lines().any(|l| l.contains(&*sub.to_string_lossy())),
        "the bind must not outlive its namespace; refusing to clean up"
    );
    let survived = victim.path().join("keep/me").is_dir();
    std::fs::remove_dir(&sub).expect("remove the child cgroup");
    std::fs::remove_dir(sub.parent().expect("the leaf")).expect("remove the leaf");

    swept.expect("the sweep");
    assert!(
        survived,
        "the sweep crossed the mount and deleted the victim's directories"
    );
}
