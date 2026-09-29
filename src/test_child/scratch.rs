//! The scratch space and executable a fixture needs once it has dropped DAC bypass, which its
//! driver has to prepare from outside: after the drop the fixture can neither create files under
//! the driver's ambient `TMPDIR` nor necessarily reach its own executable.

#[cfg(target_os = "linux")]
mod linux {
    /// A raw directory fd, closed on drop.
    pub(in crate::test_child) struct OwnedRawFd(pub(in crate::test_child) std::os::unix::io::RawFd);

    impl Drop for OwnedRawFd {
        fn drop(&mut self) {
            // SAFETY: `self.0` is open, uniquely owned by this value, and closed only here.
            unsafe {
                libc::close(self.0);
            }
        }
    }

    /// Opens `dir` (the scratch root) `O_DIRECTORY | O_CLOEXEC`.
    ///
    /// The fixture reaches the directory as `/proc/self/fd/<n>`. A lookup through that link starts
    /// at the fd's target, so the ambient `TMPDIR`'s ancestors, which this crate does not own and
    /// must not `chmod`, need not be searchable by the dropped identity. Only `dir` and what a
    /// fixture builds under it must be.
    ///
    /// `run_fixture` clears close-on-exec in the fixture child only, and the fixture's own
    /// children inherit the fd. That is why the path names `self`: it resolves in the fixture and in
    /// any grandchild alike.
    pub(in crate::test_child) fn open_scratch_fd(dir: &std::path::Path) -> OwnedRawFd {
        use std::os::unix::ffi::OsStrExt as _;
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).expect("scratch root path has no interior NUL");
        // SAFETY: `path` is a valid, NUL-terminated C string.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(
            fd >= 0,
            "open scratch root as O_DIRECTORY: {}",
            std::io::Error::last_os_error()
        );
        OwnedRawFd(fd)
    }

    /// Carries the scratch directory's fd number to the fixture.
    pub(in crate::test_child) const FIXTURE_SCRATCH_FD_ENV: &str = "COSCA_FIXTURE_SCRATCH_FD";
}
#[cfg(target_os = "linux")]
pub(super) use linux::{open_scratch_fd, FIXTURE_SCRATCH_FD_ENV};

/// Carries the scratch directory's path to the fixture, where there is no `/proc` link to hand it
/// through.
#[cfg(all(unix, not(target_os = "linux")))]
pub(super) const FIXTURE_SCRATCH_ROOT_ENV: &str = "COSCA_FIXTURE_SCRATCH_ROOT";

/// A tempdir under the scratch root [`super::run_fixture`] prepared. Call it only from a fixture
/// `run_fixture` started: a tempdir under the ambient `TMPDIR` may be out of reach after the drop.
#[cfg(target_os = "linux")]
pub(crate) fn fixture_scratch_tempdir() -> tempfile::TempDir {
    let fd: i32 = std::env::var(FIXTURE_SCRATCH_FD_ENV)
        .expect("run_fixture sets the scratch fd")
        .parse()
        .expect("the scratch fd is a number");
    tempfile::Builder::new()
        .tempdir_in(format!("/proc/self/fd/{fd}"))
        .expect("tempdir_in the fixture scratch root")
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn fixture_scratch_tempdir() -> tempfile::TempDir {
    let root = std::env::var_os(FIXTURE_SCRATCH_ROOT_ENV).expect("run_fixture sets the scratch root");
    tempfile::Builder::new()
        .tempdir_in(root)
        .expect("tempdir_in the fixture scratch root")
}

/// Why [`check_path_traversable_by`] refused a path.
#[cfg(all(unix, not(target_os = "linux")))]
#[derive(Debug)]
pub(super) enum TraversalError {
    /// The dropped identity is denied: the kernel's `errno` from `access(path, X_OK)`.
    Denied { path: std::path::PathBuf, errno: i32 },
    /// The check itself could not run, so it says nothing about the path.
    Unchecked { path: std::path::PathBuf, cause: String },
}

#[cfg(all(unix, not(target_os = "linux")))]
impl std::fmt::Display for TraversalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied { path, errno } => write!(
                f,
                "{path:?} is not reachable by the identity a fixture drops to: {}",
                std::io::Error::from_raw_os_error(*errno)
            ),
            Self::Unchecked { path, cause } => write!(f, "could not check whether {path:?} is reachable: {cause}"),
        }
    }
}

/// Fails loudly, naming the directory, if the identity a root driver's fixtures drop to cannot
/// reach the ambient `TMPDIR`, rather than loosening a directory this crate does not own.
#[cfg(all(unix, not(target_os = "linux")))]
pub(super) fn assert_dropped_identity_can_traverse_tmpdir() {
    let tmpdir = std::env::temp_dir();
    if let Err(e) = check_path_traversable_by(&tmpdir) {
        panic!("{e}");
    }
}

/// Exit status of the check child when it could not drop to [`crate::test_privilege::UNPRIVILEGED`].
/// Above every errno.
#[cfg(all(unix, not(target_os = "linux")))]
const CHILD_DROP_FAILED: i32 = 126;

/// Whether [`crate::test_privilege::UNPRIVILEGED`] can execute or search `path`. A forked child
/// drops to that identity (only if this process is root) and asks the kernel with
/// `access(path, X_OK)`, so symlinks, ACLs and mount options are all the kernel's call, not a
/// model of the mode bits.
///
/// `X_OK`, not a read check: every caller needs to enter a directory or run a binary. A directory
/// that is search-only for others is reachable, and a readable file with no `x` bit is not.
///
/// Holds `spawn_lock()` across the `fork` like every other fork in this binary (see
/// `spawn_a_process_that_exits`).
#[cfg(all(unix, not(target_os = "linux")))]
pub(super) fn check_path_traversable_by(path: &std::path::Path) -> Result<(), TraversalError> {
    use std::os::unix::ffi::OsStrExt as _;
    let unchecked = |cause: String| TraversalError::Unchecked {
        path: path.to_path_buf(),
        cause,
    };
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| unchecked("interior NUL".into()))?;

    // The guard stays in the parent: the child only makes raw syscalls and `_exit`s, so it never
    // runs the guard's `Drop`.
    let guard = crate::child::spawn::spawn_lock();
    // SAFETY: fork under `spawn_lock`; the child makes only async-signal-safe calls and always
    // `_exit`s.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: async-signal-safe syscalls only, then `_exit`.
        unsafe {
            if libc::geteuid() == 0 {
                let uid = crate::test_privilege::UNPRIVILEGED;
                if libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(uid) != 0 || libc::setuid(uid) != 0 {
                    libc::_exit(CHILD_DROP_FAILED);
                }
            }
            if libc::access(c_path.as_ptr(), libc::X_OK) == 0 {
                libc::_exit(0);
            }
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
            libc::_exit(errno.clamp(1, CHILD_DROP_FAILED - 1));
        }
    }
    let fork_error = (pid < 0).then(std::io::Error::last_os_error);
    drop(guard);
    if let Some(e) = fork_error {
        return Err(unchecked(format!("fork: {e}")));
    }

    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a valid, writable int and `pid` is this call's own child.
        if unsafe { libc::waitpid(pid, &mut status, 0) } >= 0 {
            break;
        }
        let e = std::io::Error::last_os_error();
        // A signal delivered while waiting is not the child's exit.
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(unchecked(format!("waitpid: {e}")));
        }
    }
    if !libc::WIFEXITED(status) {
        return Err(unchecked(format!(
            "the check child did not exit (raw status {status:#x})"
        )));
    }
    match libc::WEXITSTATUS(status) {
        0 => Ok(()),
        CHILD_DROP_FAILED => Err(unchecked("the check child could not drop to UNPRIVILEGED".into())),
        errno => Err(TraversalError::Denied {
            path: path.to_path_buf(),
            errno,
        }),
    }
}

/// A `0755` dir directly under `/tmp` holding a world-executable COPY of this test binary, for a
/// root driver to re-exec instead of `current_exe()`. The caller keeps the returned `TempDir`
/// alive until the fixture exits.
#[cfg(all(unix, not(target_os = "linux")))]
pub(super) fn copy_exe_to_traversable_scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::Builder::new()
        .tempdir_in("/tmp")
        .expect("tempdir directly under /tmp for a traversable fixture-exe copy");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the exe-copy scratch dir world-traversable");
    let src = std::env::current_exe().expect("current_exe");
    let dest = dir.path().join("fixture-exe");
    std::fs::copy(&src, &dest).expect("copy the test binary into the traversable scratch dir");
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
        .expect("chmod the exe copy world-readable+executable");
    if let Err(e) = check_path_traversable_by(&dest) {
        panic!("copied fixture exe: {e}");
    }
    (dir, dest)
}

#[cfg(all(test, unix, not(target_os = "linux")))]
#[path = "scratch_tests.rs"]
mod scratch_tests;
