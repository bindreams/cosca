//! Support for the `UID_SWITCH` group (`COSCA_TEST_UID_SWITCH`, principles 9 and 10): tests that run
//! as real root and switch to other real uids. This module checks what the group fixture cannot: that
//! the process really can do the switching.

/// The target's uid/gid: unprivileged, distinct from root and `READER_UID`. No `/etc/passwd` entry
/// is needed.
pub const TARGET_UID: u32 = 65534;
/// The uid/gid the reader runs as; differs from `TARGET_UID` so the kill is cross-uid.
pub const READER_UID: u32 = 65533;

/// Asserts this process can do what a `UID_SWITCH` test needs: real root, and on Linux the ability
/// to `setgroups`/`setgid`/`setuid` to both `TARGET_UID` and `READER_UID` in this user namespace.
/// Call it from the test body: a group that is on and consented to but cannot run is a failure,
/// not a skip.
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
        let can = can_switch_to(uid)
            .unwrap_or_else(|e| panic!("the uid-switch capability probe for {uid} could not run: {e}"));
        assert!(
            can,
            "root, but this namespace cannot setgroups/setgid/setuid to {uid} (CAP_SETUID/CAP_SETGID, \
             or the uid/gid map does not cover it); set COSCA_TEST_UID_SWITCH=0 to turn the group \
             off; see README.md's \"Tests that need root\""
        );
    }
}

/// A `requires` precondition: this process is not root, and pid 1 is root-owned, so a `SIGKILL` to
/// pid 1 is refused with `EPERM` and can never be delivered.
pub fn unprivileged_with_root_init() -> Result<(), String> {
    // SAFETY: geteuid() takes no arguments and has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return Err("running as root".into());
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt as _;
        let owner = std::fs::metadata("/proc/1")
            .map_err(|e| format!("cannot stat /proc/1: {e}"))?
            .uid();
        if owner != 0 {
            return Err(format!("pid 1 is owned by uid {owner}, not root"));
        }
    }
    Ok(())
}

/// Whether a forked child can `setgroups(0)`, `setgid` and `setuid` to `uid`, the sequence std's
/// `Command::uid()/gid()` runs as root. `Err` is a failure of the probe itself (`fork`, `waitpid`,
/// or the child dying abnormally), never a "no": each names its own cause so it cannot be misread
/// as missing `CAP_SETUID`.
#[cfg(target_os = "linux")]
fn can_switch_to(uid: u32) -> std::io::Result<bool> {
    // See `output_locked` for why forks hold the spawn lock.
    let _guard = cosca::test_spawn_lock();
    // SAFETY: fork() takes no arguments. The child below calls only async-signal-safe raw
    // syscalls before exiting.
    match unsafe { libc::fork() } {
        0 => {
            let ok = unsafe { libc::setgroups(0, std::ptr::null()) } == 0
                && unsafe { libc::setgid(uid as libc::gid_t) } == 0
                && unsafe { libc::setuid(uid as libc::uid_t) } == 0;
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

/// Kills and reaps a raw `std::process::Child` on drop, including during unwind. Wrap it right
/// after `spawn()`.
pub struct KillOnDrop(Option<std::process::Child>);

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

/// A single process, whose drop kills no tree, so reaping it here skips nothing.
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

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else { return };
        let kill_result = child.kill();
        let wait_result = child.wait();
        // Outside unwind, failure is a broken contract: assert. During unwind a second panic would
        // abort and hide the original, so only report.
        if std::thread::panicking() {
            if let Err(e) = &kill_result {
                eprintln!("KillOnDrop: kill failed during unwind: {e}");
            }
            if let Err(e) = &wait_result {
                eprintln!("KillOnDrop: wait failed during unwind: {e}");
            }
        } else {
            assert!(kill_result.is_ok(), "KillOnDrop: kill failed: {kill_result:?}");
            assert!(wait_result.is_ok(), "KillOnDrop: wait failed: {wait_result:?}");
        }
    }
}

/// Copies `src` into `dir` as `0o755`; `dir` must already be world-traversable.
pub fn world_executable_copy(src: &std::path::Path, dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dest = dir.join(src.file_name().expect("src has a file name"));
    std::fs::copy(src, &dest).expect("copy into the scratch directory");
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).expect("chmod the copy world-executable");
    dest
}
