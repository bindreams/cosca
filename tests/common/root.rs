//! Root-precondition test infrastructure: the `ROOT` group's switch/consent/capability pieces,
//! plus the generic `switch`/`consent` engine a later group (`CGROUP`, ...) reuses with its own
//! name. Split out of `tests/common/mod.rs` to keep that file from growing a "just one more
//! section" pile — see its own history for why.

use std::io::Read;
use std::net::{TcpListener, TcpStream};

// Conditional-test groups =========================================================================
//
// The owner's shape for a test that needs real privilege or mutates real system state (2026-09-28,
// docs/principles.md): three separate things, not one runtime probe.
//   - An on/off SWITCH, `COSCA_TEST_<GROUP>` — default ON, disabled only by an explicit `"0"`. A
//     pure convention: it makes NO judgment about whether the environment can actually satisfy the
//     test, only whether this run wants to attempt it at all. Read by `switch()`, used as a skuld
//     `requires` precondition — an unmet one reports the test `ignored`, never a failure.
//   - CONSENT, `COSCA_TEST_<GROUP>_CONSENT` — default OFF, granted only by exactly `"1"`. Required
//     in addition to the switch because this class of test changes real system state (uid
//     switches, delegated cgroups, ...); "the switch happened to be on" is not the same as "you
//     meant to run this". Read by `consent()`, used as a skuld FIXTURE — an unmet one FAILS the
//     test (a fixture `Err` panics, by skuld's own contract), never reports it unavailable.
//   - Its own capability assertion, called from the test body once both of the above hold: a
//     missing capability (not root, an unmapped uid under `unshare -r`, ...) is the environment
//     breaking a promise "switch on + consent given" made — that FAILS the test, with a message
//     naming the precondition and how to opt out, never reports it unavailable either.
//
// Shared here, not duplicated per binary, so a later group (CGROUP, ...) reuses `switch`/`consent`
// with its own name instead of copying this file. `ROOT`'s own three pieces
// (`preconditions::root`, the `consent_root` fixture, `assert_root_capable`) are the one instance
// of this shape that exists today.

/// `COSCA_TEST_<group>` as a skuld `requires` precondition: enabled unless explicitly `"0"`.
pub fn switch(group: &str) -> Result<(), String> {
    let var = format!("COSCA_TEST_{group}");
    if std::env::var(&var).as_deref() == Ok("0") {
        Err(format!("disabled via {var}=0"))
    } else {
        Ok(())
    }
}

/// `COSCA_TEST_<group>_CONSENT` as a skuld fixture: FAILS the test unless exactly `"1"`.
pub fn consent(group: &str) -> Result<(), String> {
    let var = format!("COSCA_TEST_{group}_CONSENT");
    if std::env::var(&var).as_deref() == Ok("1") {
        Ok(())
    } else {
        Err(format!(
            "{var} is not \"1\" — this test changes real system state and needs explicit \
             consent, see README.md's \"Tests that need root\""
        ))
    }
}

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

/// The `ROOT` group's on/off switch, wired to `#[skuld::test(requires = [...])]`. Not a
/// capability check — see the module doc and `assert_root_capable`.
#[cfg(unix)]
pub mod preconditions {
    pub fn root() -> Result<(), String> {
        super::switch("ROOT")
    }
}

/// The `ROOT` group's consent fixture. Its value is `()` — a test using it (`#[fixture
/// (consent_root)] _consent: &()`) cares only that the dependency was satisfied, not any payload.
#[cfg(unix)]
#[skuld::fixture]
pub fn consent_root() -> Result<(), String> {
    consent("ROOT")
}

/// Asserts this process can actually do what a ROOT-group test needs: real root, and — on Linux —
/// the ability to `setuid`/`setgid` to both `TARGET_UID` and `READER_UID` in this user namespace.
/// Call this from the test body itself, once both `preconditions::root` (the switch) and
/// `consent_root` (consent) have already passed: a failure here means the environment broke the
/// promise "switch on + consent given" made, so it panics — a `requires` precondition would
/// report the test merely unavailable, which is the wrong outcome once consent was given.
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
        "not root — see README.md's \"Tests that need root\""
    );
    #[cfg(target_os = "linux")]
    for uid in [TARGET_UID, READER_UID] {
        assert!(
            can_setuid_setgid_to(uid),
            "root, but this namespace cannot setuid/setgid to {uid} — CAP_SETUID/CAP_SETGID or \
             the uid/gid map may not cover it; see README.md's \"Tests that need root\""
        );
    }
}

#[cfg(target_os = "linux")]
fn can_setuid_setgid_to(uid: u32) -> bool {
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
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    return false;
                }
            }
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        }
        _ => false, // fork() itself failed
    }
}

/// Selects tests that need a root caller; CI's root step runs `SKULD_LABELS=ROOT`.
#[cfg(unix)]
#[skuld::label]
pub const ROOT: skuld::Label;

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

    /// Takes the child's stdout pipe (only meaningful if it was spawned with
    /// `Stdio::piped()`). Returns `None` on a second call.
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.0
            .as_mut()
            .expect("KillOnDrop used after its child was taken")
            .stdout
            .take()
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

/// Blocks until either `listener` gets an incoming connection, or `dead_watch` (a pipe the
/// target's stdout was redirected to, which it never writes to) reaches EOF or errors — meaning
/// the target died before connecting. A plain blocking `accept()` would hang forever in that case
/// instead of failing.
///
/// No thread, no reconnect: both the listener and the pipe are polled directly as the file
/// descriptors this process already owns. An earlier revision used a background thread that
/// death-watched the target and, on death, RECONNECTED to `listener`'s own address to signal it —
/// measured to be unsound: after the real target's own process (and this function) have moved on,
/// nothing keeps that port reserved, and the OS can and does reissue it (observed on macOS) to a
/// completely unrelated later listener, which then sees a spurious, wrongly-attributed connection.
/// A pipe already held open by both ends has no such window. (Identical to `common::accept_or_die`
/// in bindreams/cosca#232 — this copy exists because #204 and #232 fork from different bases;
/// once #232 lands on `main` and this branch rebases past it, this becomes the shared one.)
///
/// Checks the listener before the death signal when both are ready: a target that manages to
/// connect and then immediately exits (an ordinary, successful run for most callers) must not be
/// misreported as having died before connecting.
pub fn accept_or_die(
    listener: &TcpListener,
    dead_watch: &mut (impl std::io::Read + std::os::fd::AsRawFd),
) -> TcpStream {
    use std::os::fd::AsRawFd;

    let mut fds = [
        libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: dead_watch.as_raw_fd(),
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
            panic!("poll while waiting for a control connection: {e}");
        }
        if fds[0].revents & libc::POLLIN != 0 {
            return listener.accept().expect("accept a control connection").0;
        }
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let mut buf = [0u8; 1];
            match dead_watch.read(&mut buf) {
                Ok(0) => panic!("the control target died before it connected"),
                Ok(n) => panic!("the control target wrote {n} unexpected byte(s) to stdout before connecting"),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {} // spurious wakeup
                // A read error is reported as exactly that error — never folded into "died",
                // which would misattribute (say) an EIO on the pipe itself to the target.
                Err(e) => panic!("reading the control target's death-watch pipe: {e}"),
            }
        }
    }
}
