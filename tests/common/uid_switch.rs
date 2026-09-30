//! Support for the `UID_SWITCH` group (`COSCA_TEST_UID_SWITCH`, principles 9 and 10): tests that run
//! as real root and switch to other real uids. Gating is `common::require_group("UID_SWITCH")`;
//! this module adds what it cannot check, that the process really can do the switching.

/// The target's uid/gid: an ordinary unprivileged account, distinct from both root (0) and
/// `READER_UID` below. No `/etc/passwd` entry is required for either — `setuid`/`execve` only
/// need a number, and neither the target nor the reader ever looks itself up by name.
#[cfg(unix)]
pub const TARGET_UID: u32 = 65534;
/// The uid/gid a root test re-execs itself as, to make the actual privileged call under test.
/// Different from `TARGET_UID`: this proves a GENUINELY foreign, unprivileged caller, not merely
/// "some non-root uid or other."
#[cfg(unix)]
pub const READER_UID: u32 = 65533;

/// Asserts this process can do what a `UID_SWITCH` test needs: real root, and on Linux the ability
/// to `setuid`/`setgid` to both `TARGET_UID` and `READER_UID` in this user namespace. Call it from
/// the test body once `require_group` has returned `true`: a group that is on and consented to
/// but cannot run is a failure, not a skip.
///
/// The capability probe forks a throwaway child that attempts `setgid(uid)` then `setuid(uid)`
/// and reports success via its exit code, rather than parsing `/proc/self/{uid,gid}_map`: this is
/// the exact pair of syscalls the test itself relies on next, so a "yes" here cannot disagree with
/// what the test does. The child does no allocation and takes no lock between `fork` and `_exit`
/// — only the two syscalls under test — so the usual fork-in-a-multithreaded-process hazards (a
/// held libc lock, an allocator in an inconsistent state) do not apply. macOS has no equivalent
/// namespace/capability split — root is sufficient there.
#[cfg(unix)]
pub fn assert_root_capable() {
    // SAFETY: geteuid() takes no arguments and has no preconditions.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "not root, despite COSCA_TEST_UID_SWITCH_CONSENT=1: this lane must be real root, or set \
         COSCA_TEST_UID_SWITCH=0 to turn the group off; see README.md's \"Tests that need root\""
    );
    #[cfg(target_os = "linux")]
    for uid in [TARGET_UID, READER_UID] {
        let can = can_setuid_setgid_to(uid)
            .unwrap_or_else(|e| panic!("the setuid/setgid capability probe for {uid} could not run: {e}"));
        assert!(
            can,
            "root, but this namespace cannot setuid/setgid to {uid} (CAP_SETUID/CAP_SETGID, or the \
             uid/gid map does not cover it); set COSCA_TEST_UID_SWITCH=0 to turn the group off; see \
             README.md's \"Tests that need root\""
        );
    }
}

/// Whether a forked child can `setgid` then `setuid` to `uid`. `Err` is a failure of the probe
/// itself (`fork`, `waitpid`, or the child dying abnormally), never a "no": each names its own
/// cause so it cannot be misread as missing `CAP_SETUID`.
#[cfg(target_os = "linux")]
fn can_setuid_setgid_to(uid: u32) -> std::io::Result<bool> {
    // Held across fork and reap like every other fork in this suite (see `output_locked`).
    let _guard = cosca::test_spawn_lock();
    // SAFETY: fork() takes no arguments. The child below calls only async-signal-safe raw
    // syscalls before exiting.
    match unsafe { libc::fork() } {
        0 => {
            // SAFETY: `uid` fits both `gid_t` and `uid_t` (both are u32-width on Linux).
            let ok =
                unsafe { libc::setgid(uid as libc::gid_t) } == 0 && unsafe { libc::setuid(uid as libc::uid_t) } == 0;
            // SAFETY: exits this forked child only; never returns.
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        pid if pid > 0 => {
            let mut status: libc::c_int = 0;
            loop {
                // SAFETY: `pid` is our own just-forked child; `status` is a valid out-param.
                let r = unsafe { libc::waitpid(pid, &mut status, 0) };
                if r >= 0 {
                    break;
                }
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::Interrupted {
                    return Err(std::io::Error::new(e.kind(), format!("waitpid({pid}) failed: {e}")));
                }
            }
            if libc::WIFEXITED(status) {
                Ok(libc::WEXITSTATUS(status) == 0)
            } else {
                Err(std::io::Error::other(format!(
                    "the capability probe child (pid {pid}) did not exit normally (wait status {status:#x})"
                )))
            }
        }
        _ => {
            let e = std::io::Error::last_os_error();
            Err(std::io::Error::new(e.kind(), format!("fork() failed: {e}")))
        }
    }
}

/// Kills and reaps a raw `std::process::Child` on drop, including mid-unwind. Construct it
/// immediately after `spawn()` — before anything else has a chance to panic — so a panic anywhere
/// afterward cannot orphan the wrapped child.
#[cfg(unix)]
pub struct KillOnDrop(Option<std::process::Child>);

#[cfg(unix)]
impl KillOnDrop {
    pub fn new(child: std::process::Child) -> Self {
        Self(Some(child))
    }

    pub fn id(&self) -> u32 {
        self.0.as_ref().expect("KillOnDrop used after its child was taken").id()
    }

    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.0
            .as_mut()
            .expect("KillOnDrop used after its child was taken")
            .try_wait()
    }
}

#[cfg(unix)]
impl super::Target for KillOnDrop {
    fn pid(&self) -> u32 {
        self.id()
    }

    fn has_exited(&mut self) -> bool {
        self.try_wait()
            .expect("try_wait the control target before watching it")
            .is_some()
    }
}

#[cfg(unix)]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else { return };
        let kill_result = child.kill();
        let wait_result = child.wait();
        // A failure here during an ordinary (non-unwinding) drop is a broken contract this guard
        // exists to uphold — assert it. During unwind, a second panic would abort the process
        // and hide the ORIGINAL panic's message, so this reports instead of asserting.
        if std::thread::panicking() {
            if let Err(e) = &kill_result {
                eprintln!("KillOnDrop: kill failed during unwind: {e}");
            }
            if let Err(e) = &wait_result {
                eprintln!("KillOnDrop: wait failed during unwind: {e}");
            }
        } else {
            debug_assert!(kill_result.is_ok(), "KillOnDrop: kill failed: {kill_result:?}");
            debug_assert!(wait_result.is_ok(), "KillOnDrop: wait failed: {wait_result:?}");
        }
    }
}

/// Copies `src` into `dir` (a directory the caller has already chmod'd world-traversable) and
/// chmods the copy `0o755` regardless of `src`'s own mode.
#[cfg(unix)]
pub fn world_executable_copy(src: &std::path::Path, dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dest = dir.join(src.file_name().expect("src has a file name"));
    std::fs::copy(src, &dest).expect("copy into the scratch directory");
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).expect("chmod the copy world-executable");
    dest
}
