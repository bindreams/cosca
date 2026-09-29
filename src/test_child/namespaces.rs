//! Tests that need private mount or pid namespaces, run in a re-exec'd child of this test binary
//! so the shared, multithreaded test process never changes its own namespaces.
//!
//! They need `CAP_SYS_ADMIN`, so they are a system-affecting group (`docs/principles.md` 9 and
//! 10): on by default, `COSCA_TEST_NAMESPACES=0` switches the group off, and running it needs
//! `COSCA_TEST_NAMESPACES_CONSENT=1` — a missing consent FAILS the test. Run them in a container,
//! VM, or CI's root lane, never on a developer host: every mount here is made after
//! [`enter_private_mount_ns`] and dies with the child.

use std::path::Path;

use rustix::mount::{mount, mount_bind, mount_change, MountPropagationFlags};
use rustix::thread::{unshare_unsafe, UnshareFlags};

const GROUP: &str = "COSCA_TEST_NAMESPACES";
const CONSENT: &str = "COSCA_TEST_NAMESPACES_CONSENT";

/// Whether the caller should run the group's body. `false` only for an explicit
/// `COSCA_TEST_NAMESPACES=0`; otherwise panics unless consent was given.
pub(crate) fn enabled() -> bool {
    if std::env::var_os(GROUP).is_some_and(|v| v == "0") {
        return false;
    }
    assert!(
        std::env::var_os(CONSENT).is_some_and(|v| v == "1"),
        "this test unshares namespaces and mounts, which must never run on a developer host. \
         Run it in a container, VM or CI's root lane with {CONSENT}=1, or switch the group off \
         with {GROUP}=0"
    );
    true
}

/// Re-exec this binary on `fixture` with `marker_env` set, to run as the child half of a test.
pub(crate) fn run(fixture: &str, marker_env: &str) {
    let mut cmd = super::fixture_command(fixture);
    cmd.env(marker_env, "1");
    super::run_fixture_command(fixture, cmd);
}

/// Whether this process is the re-exec'd child for `marker_env`; a fixture is also picked up by
/// an ordinary suite run, where it must do nothing.
pub(crate) fn is_child(marker_env: &str) -> bool {
    std::env::var_os(marker_env).is_some_and(|v| v == "1")
}

/// Give this process its own mount namespace, with nothing propagating back out.
pub(crate) fn enter_private_mount_ns() {
    // SAFETY: `NEWNS` leaves the fd table alone; the hazard `unshare_unsafe` documents is `FILES`.
    unsafe { unshare_unsafe(UnshareFlags::NEWNS) }.expect("unshare(CLONE_NEWNS)");
    mount_change("/", MountPropagationFlags::PRIVATE | MountPropagationFlags::REC).expect("make / rprivate");
}

/// The next child this process creates is pid 1 of a new pid namespace, whose `/proc` stays the
/// outer one.
pub(crate) fn enter_new_pid_ns_for_children() {
    // SAFETY: `NEWPID` leaves the fd table alone.
    unsafe { unshare_unsafe(UnshareFlags::NEWPID) }.expect("unshare(CLONE_NEWPID)");
}

/// Bind `source` over `target`.
pub(crate) fn bind_over(source: &Path, target: &Path) {
    mount_bind(source, target).unwrap_or_else(|e| panic!("bind {} over {}: {e}", source.display(), target.display()));
}

/// Mount a fresh tmpfs on `target`.
pub(crate) fn mount_tmpfs(target: &Path) {
    mount("tmpfs", target, "tmpfs", rustix::mount::MountFlags::empty(), None::<&std::ffi::CStr>)
        .unwrap_or_else(|e| panic!("mount tmpfs on {}: {e}", target.display()));
}
