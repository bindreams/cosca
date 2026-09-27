//! Helpers the cgroup module's tests share.

/// Fork a child that runs `body` and exits with `_exit(0)`. `body` must be async-signal-safe:
/// this process has other threads.
#[cfg(target_os = "linux")]
pub(crate) fn fork_running(body: impl FnOnce()) -> u32 {
    // SAFETY: the child runs only `body`, async-signal-safe by the caller's contract, then
    // `_exit`s without unwinding or running destructors.
    match unsafe { libc::fork() } {
        -1 => panic!("fork: {}", std::io::Error::last_os_error()),
        0 => {
            body();
            // SAFETY: async-signal-safe.
            unsafe { libc::_exit(0) }
        }
        pid => pid as u32,
    }
}

/// Reap `pid`, a child of this process.
#[cfg(target_os = "linux")]
pub(crate) fn reap(pid: u32) {
    let mut status = 0;
    // SAFETY: `pid` is this process's own child; `status` is a valid, writable int.
    let reaped = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    assert_eq!(reaped, pid as i32, "waitpid: {}", std::io::Error::last_os_error());
}

/// A forked child that fails inside [`block_on`] cannot say why — no formatted panic, no
/// allocation — so this number is the only diagnostic a hang left blocked on that read gets.
#[cfg(target_os = "linux")]
const BLOCK_ON_READ_FAILED_EXIT: i32 = 111;

/// Block on `gate` until a byte arrives. Async-signal-safe: may run in a forked, pre-exec child.
#[cfg(target_os = "linux")]
pub(crate) fn block_on(gate: std::os::fd::RawFd) {
    let mut byte = 0u8;
    let n = loop {
        // SAFETY: `gate` is an open read end; `byte` is a valid one-byte buffer.
        let n = unsafe { libc::read(gate, (&raw mut byte).cast(), 1) };
        if n == -1 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // A real read failure leaves nothing to retry, and this may run pre-exec in a forked
            // child: no formatted panic (allocates), a distinct exit instead.
            // SAFETY: async-signal-safe.
            unsafe { libc::_exit(BLOCK_ON_READ_FAILED_EXIT) };
        }
        break n;
    };
    debug_assert_eq!(n, 1, "read");
}

/// A copy of `channel`'s child end, standing in for the one a forked child inherits: the parent's
/// own copy closes when the exchange ends, as it does in a real spawn.
#[cfg(target_os = "linux")]
pub(crate) fn childs_copy(
    channel: &crate::containment::cgroup::ReportChannel,
) -> (std::os::fd::OwnedFd, crate::containment::cgroup::ReportSlot) {
    use std::os::fd::{AsRawFd, BorrowedFd};

    // SAFETY: the slot's descriptor is open for as long as `channel` lives, which spans this call.
    let end = unsafe { BorrowedFd::borrow_raw(channel.slot().fd) }
        .try_clone_to_owned()
        .expect("dup the child's end");
    let slot = crate::containment::cgroup::ReportSlot {
        fd: end.as_raw_fd(),
        parent_fd: -1,
    };
    (end, slot)
}

/// The re-exec args [`alone`] passes after the test name, and the shape [`alone_marker_matches`]
/// demands this process's own argv match before trusting a `COSCA_TEST_ALONE` env var — shared by
/// both, and by `child::spawn::fd_map::fd_map_tests`' `require_process_per_test` (a separate file in this
/// same compilation unit), so all three can never drift apart into different ideas of "the
/// isolated shape".
#[cfg(unix)]
pub(crate) const ALONE_ARGS: [&str; 4] = ["--exact", "--include-ignored", "--nocapture", "--test-threads=1"];

/// True only if `value` is `Some` AND this process's own argv (skipping argv[0], the binary path)
/// is exactly `[value, ALONE_ARGS...]` — proof that libtest itself was invoked to run exactly one
/// named test, not merely that some env var happens to be set.
///
/// A `COSCA_TEST_ALONE` env var alone is not enough: it is inherited by every child of the
/// process that set it, including — if a caller ever exports it into their own shell, or it leaks
/// from an outer re-exec — the whole, ordinary, many-threads `cargo test` run itself. That run's
/// OWN argv is never this exact one-test-and-no-more shape, so checking argv here is what a
/// forged or leaked env var cannot fake: argv is controlled by whatever actually invoked THIS
/// process, which for the genuine isolated child is [`alone`] itself and nothing else. Measured:
/// without this check, an inherited `COSCA_TEST_ALONE=<a real test's name>` made that one test's
/// guard accept a plain, many-threads `cargo test` run as "isolated" and corrupt others.
///
/// A copy of `tests/common/mod.rs`'s identical function — see `alone`'s own doc for why this
/// crate keeps one copy per compilation unit rather than a shared dependency.
#[cfg(unix)]
pub(crate) fn alone_marker_matches(value: Option<&str>, argv: &[String]) -> bool {
    let Some(value) = value else { return false };
    argv.len() == ALONE_ARGS.len() + 1
        && argv[0] == value
        && argv[1..].iter().map(String::as_str).eq(ALONE_ARGS.iter().copied())
}

/// Run the test `name` (its full path) alone, in a copy of this test binary, and assert it passed.
/// `true` in the copy, which runs the test's body; `false` in the caller, which returns.
///
/// For a test that closes the parent's end of a channel and needs the child to see that close: any
/// process another test forks meanwhile holds a copy of that end until its own `exec`, and keeps
/// the socket open past the close. `child::spawn::fd_map::fd_map_tests` also uses this, for the same
/// reason but a plainer one: a test that closes this process's own fd 0/1/2 (process-wide, not
/// per-thread) must not run alongside any other test in the same binary, on any Unix, not just
/// Linux — hence `unix` rather than this file's otherwise Linux-only gate. Sets `COSCA_TEST_ALONE`
/// in the copy so a precondition assert guarding the actual mutation (e.g.
/// `tests/common::require_process_per_test`, a separate copy in a separate compilation unit that
/// cannot name this one) can accept it.
///
/// Checks BOTH that the env var equals `name` AND that this process's own argv matches
/// [`alone_marker_matches`]'s shape — the first alone is not enough (see that function's doc for
/// the inherited/forged-env-var corruption checking only presence, or only the wrong one of these
/// two, would let back in), and belt-and-suspenders costs nothing here.
///
/// Spawns under `crate::child::spawn::spawn_lock()`, waits outside it: on macOS, a fork here that
/// lands while another test's fd-marker write end happens to have its `CLOEXEC` cleared (a real,
/// bounded window `child::spawn`'s own `prepare`-to-`drop(std_cmd)` comment names) would
/// transiently inherit it and carry it past this re-exec's own `exec`, becoming an unrelated
/// bystander a concurrent sweep can misidentify. `spawn_lock()` is the same lock every
/// cosca-originated spawn in this process already takes. The lock is a plain, non-reentrant
/// mutex: every caller here calls `alone` FIRST, while holding nothing else, and must keep doing
/// so — nesting a second `spawn_lock()`-taking call inside an already-locked scope deadlocks.
#[cfg(unix)]
pub(crate) fn alone(name: &str) -> bool {
    const ALONE: &str = "COSCA_TEST_ALONE";
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let env_value = std::env::var(ALONE).ok();
    if env_value.as_deref() == Some(name) && alone_marker_matches(env_value.as_deref(), &argv) {
        return true;
    }
    let child = {
        let _guard = crate::child::spawn::spawn_lock();
        std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args(std::iter::once(name).chain(ALONE_ARGS))
            .env(ALONE, name)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the test alone")
    };
    let out = child.wait_with_output().expect("wait for the test alone");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    false
}

/// A test leaf at `leaf_path` whose verdict is taken, with the child reported `Placed`: an
/// attached leaf whose `Drop` may kill.
#[cfg(target_os = "linux")]
pub(crate) fn entered_leaf_at(leaf_path: std::path::PathBuf) -> crate::containment::cgroup::CgroupLeaf {
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    // SAFETY: the slot's channel lives as long as `leaf`.
    unsafe { leaf.placement_slot().report_placed_for_test() };
    // The verdict needs a live pid: this process's own stands in for the child.
    leaf.take_placement(std::process::id())
        .expect("decidable")
        .expect("the child reported Placed");
    leaf
}

/// A temp-directory stand-in for a cgroup leaf, `<tempdir>/<name>`.
///
/// Its `cgroup.events` is a symlink to a file outside the leaf, so removing the leaf leaves that
/// file, and every fd and watch on it, untouched: as removing a real leaf neither modifies its
/// `cgroup.events` nor delivers any event on it. [`rmdir`](FakeLeaf::rmdir) answers as cgroupfs
/// does, through [`fault::set_rmdir_hook`](super::fault::set_rmdir_hook).
#[cfg(target_os = "linux")]
pub(crate) struct FakeLeaf {
    _dir: tempfile::TempDir,
    pub(crate) leaf: std::path::PathBuf,
    /// The file the leaf's `cgroup.events` resolves to.
    pub(crate) events: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl FakeLeaf {
    pub(crate) fn new(name: &str, populated: bool) -> FakeLeaf {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf = dir.path().join(name);
        std::fs::create_dir(&leaf).expect("create the leaf");
        let events = dir.path().join(format!("{name}.events"));
        std::fs::write(&events, format!("populated {}\nfrozen 0\n", u8::from(populated))).expect("write cgroup.events");
        std::os::unix::fs::symlink(&events, leaf.join("cgroup.events")).expect("link cgroup.events");
        std::fs::write(leaf.join("cgroup.kill"), b"").expect("create cgroup.kill");
        FakeLeaf {
            _dir: dir,
            leaf,
            events,
        }
    }

    /// Flip `populated` by rewriting its one digit in place: a truncating rewrite could be read
    /// half-done, as an empty file.
    pub(crate) fn set_populated(events: &std::path::Path, populated: bool) {
        use std::os::unix::fs::FileExt as _;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(events)
            .expect("open cgroup.events");
        file.write_all_at(if populated { b"1" } else { b"0" }, "populated ".len() as u64)
            .expect("flip populated");
    }

    pub(crate) fn is_populated(events: &std::path::Path) -> bool {
        let contents = std::fs::read_to_string(events).expect("read cgroup.events");
        contents.lines().any(|l| l.trim() == "populated 1")
    }

    /// What a third party's `rmdir` of the leaf does: the leaf is gone, its `cgroup.events` file
    /// is untouched.
    pub(crate) fn remove(leaf: &std::path::Path) {
        for entry in std::fs::read_dir(leaf).expect("list the leaf") {
            std::fs::remove_file(entry.expect("leaf entry").path()).expect("remove a leaf file");
        }
        std::fs::remove_dir(leaf).expect("remove the leaf");
    }

    /// cgroupfs's `rmdir`: `ENOENT` once gone, `EBUSY` while populated, else the leaf goes.
    pub(crate) fn rmdir(leaf: &std::path::Path, events: &std::path::Path) -> std::io::Result<()> {
        if !leaf.exists() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
        }
        if FakeLeaf::is_populated(events) {
            return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
        }
        FakeLeaf::remove(leaf);
        Ok(())
    }
}

/// Remove a real leaf once it drains, for a test's cleanup after a failure. Blocks on the leaf's
/// own drain watch.
#[cfg(target_os = "linux")]
pub(crate) fn remove_drained_leaf(leaf_path: &std::path::Path) {
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.to_path_buf());
    leaf.wait_drained(None).expect("wait for the drain");
    match std::fs::remove_dir(leaf_path) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        Err(e) => panic!("remove the leaf: {e}"),
    }
}

#[cfg(unix)]
#[cfg(test)]
mod alone_marker_tests {
    use super::{alone_marker_matches, ALONE_ARGS};

    fn genuine_argv(name: &str) -> Vec<String> {
        std::iter::once(name.to_string())
            .chain(ALONE_ARGS.iter().map(|s| s.to_string()))
            .collect()
    }

    #[test]
    fn the_genuine_re_exec_shape_matches() {
        assert!(alone_marker_matches(Some("some_test"), &genuine_argv("some_test")));
    }

    #[test]
    fn no_env_value_never_matches() {
        assert!(!alone_marker_matches(None, &genuine_argv("some_test")));
    }

    #[test]
    fn an_inherited_env_value_with_the_ordinary_suites_own_argv_does_not_match() {
        // The exact corruption measured: `COSCA_TEST_ALONE` set (e.g. leaked from an outer
        // shell or re-exec) to some real test's name, but THIS process's own argv is whatever
        // an ordinary `cargo test` run passes — never the isolated one-test-exact shape.
        assert!(!alone_marker_matches(Some("some_test"), &[]));
        assert!(!alone_marker_matches(Some("some_test"), &["some_test".to_string()]));
    }

    #[test]
    fn a_name_mismatch_does_not_match_even_with_the_right_shape() {
        let mut argv = genuine_argv("some_test");
        argv[0] = "other_test".to_string();
        assert!(!alone_marker_matches(Some("some_test"), &argv));
    }

    #[test]
    fn a_trailing_extra_argument_does_not_match() {
        let mut argv = genuine_argv("some_test");
        argv.push("--extra".to_string());
        assert!(!alone_marker_matches(Some("some_test"), &argv));
    }
}
