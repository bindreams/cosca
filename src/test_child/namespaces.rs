//! Tests that need private mount or pid namespaces, run in a re-exec'd child of this test binary
//! so the shared, multithreaded test process never changes its own namespaces.
//!
//! They need `CAP_SYS_ADMIN`, so they are a system-affecting group (see the
//! system-affecting-tests principle in `docs/principles.md`), declared in `test_groups.rs`: on by
//! default, `COSCA_TEST_NAMESPACES=0` ignores the group's tests, and running them needs
//! `COSCA_TEST_NAMESPACES_CONSENT=1` — a missing consent FAILS the test. A test joins with
//! `#[fixture(namespaces)] _group: &Group`, which also labels it `namespaces`. Run them in a
//! container, VM, or CI's root lane, never on a developer host.

mod chroot_scratch;
pub(crate) use chroot_scratch::{remove_root as remove_chroot_root, ChrootScratch};

use std::path::Path;

pub(crate) use super::db_dir::SKULD_DB_DIR_ENV;

use rustix::mount::{mount, mount_bind, mount_change, MountPropagationFlags};
use rustix::thread::{unshare_unsafe, UnshareFlags};

/// Re-exec this binary on `fixture`, to run as the child half of a test.
pub(crate) fn run(fixture: &str) {
    super::run_fixture_command(fixture, super::fixture_command(fixture));
}

/// [`run`] with `env` set on the child only.
pub(crate) fn run_with_env(fixture: &str, env: &[(&str, &Path)]) {
    let mut cmd = super::fixture_command(fixture);
    cmd.envs(env.iter().copied());
    super::run_fixture_command(fixture, cmd);
}

/// [`run`] for a fixture that calls [`drop_to_nobody`]. Skuld opened its DB as root, and checks at
/// the end of the test that the DB's path still resolves; `nobody` must be able to search it, which
/// the directory beside the executable need not allow. The directory stays root-owned.
pub(crate) fn run_dropping_to_nobody(fixture: &str) {
    let db_dir = super::db_dir::fixture_db_dir_searchable();
    let mut cmd = super::fixture_command(fixture);
    cmd.env(SKULD_DB_DIR_ENV, db_dir.path());
    super::run_fixture_command(fixture, cmd);
}

/// Whether this process is the re-exec'd child of [`run`]; a fixture is also picked up by an
/// ordinary suite run, where it must do nothing.
pub(crate) fn is_child() -> bool {
    super::is_fixture_reexec()
}

/// [`is_child`] for a fixture that is pid 1 of a new pid namespace: its parent is outside the
/// namespace, so `getppid()` is `0` and the parent-pid check of [`is_child`] cannot hold.
pub(crate) fn is_child_in_new_pid_ns() -> bool {
    let reexec = std::env::var_os(super::FIXTURE_PARENT_PID_ENV).is_some()
        && std::process::id() == 1
        && std::os::unix::process::parent_id() == 0;
    if reexec {
        super::write_gate_passed();
    }
    reexec
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

/// Mount a procfs of this process's own pid namespace on `target`.
pub(crate) fn mount_proc(target: &Path) {
    use rustix::mount::MountFlags;
    mount(
        "proc",
        target,
        "proc",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        None::<&std::ffi::CStr>,
    )
    .unwrap_or_else(|e| panic!("mount proc on {}: {e}", target.display()));
}

/// Make `last` the last pid allocated in this process's pid namespace, so the next task created
/// in it gets `last + 1` if that is free. The sysctl acts on the writer's pid namespace whichever
/// procfs it is reached through.
pub(crate) fn set_last_pid(last: u32) {
    std::fs::write("/proc/sys/kernel/ns_last_pid", last.to_string()).expect("write ns_last_pid");
}

/// The calling thread's id as the procfs at `/proc` numbers it, from `thread-self`'s target
/// (`<tgid>/task/<tid>`).
pub(crate) fn tid_in_proc() -> u32 {
    let target = std::fs::read_link("/proc/thread-self").expect("readlink /proc/thread-self");
    let target = target.to_str().expect("thread-self's target is UTF-8");
    target
        .rsplit_once('/')
        .and_then(|(_, tid)| tid.parse().ok())
        .unwrap_or_else(|| panic!("thread-self's target {target:?} has no tid"))
}

/// The uid and gid of `nobody`, which [`drop_to_nobody`] drops to.
const NOBODY: libc::uid_t = 65534;

/// Drop this whole process to `nobody` ([`NOBODY`]) with no supplementary groups.
pub(crate) fn drop_to_nobody() {
    let nobody = NOBODY;
    // SAFETY: plain credential syscalls; glibc and musl apply `setres[ug]id` to every thread.
    unsafe {
        assert_eq!(
            libc::setgroups(0, std::ptr::null()),
            0,
            "setgroups: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            libc::setresgid(nobody, nobody, nobody),
            0,
            "setresgid: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            libc::setresuid(nobody, nobody, nobody),
            0,
            "setresuid: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Mount a fresh tmpfs on `target`.
pub(crate) fn mount_tmpfs(target: &Path) {
    mount(
        "tmpfs",
        target,
        "tmpfs",
        rustix::mount::MountFlags::empty(),
        None::<&std::ffi::CStr>,
    )
    .unwrap_or_else(|e| panic!("mount tmpfs on {}: {e}", target.display()));
}

/// Make `dir` visible at the same absolute path inside `root`, in this process's mount namespace
/// (enter a private one first), so that after [`chroot_into`]`(root)` a path to `dir` still names it.
/// Creates the mount point's directories under `root`; the driver removes them
/// ([`ChrootScratch::finish`]).
pub(crate) fn bind_into_root(root: &Path, dir: &Path) {
    let inside = root.join(dir.strip_prefix("/").expect("an absolute directory"));
    std::fs::create_dir_all(&inside).unwrap_or_else(|e| panic!("mkdir the mount point {}: {e}", inside.display()));
    bind_over(dir, &inside);
}

/// Make `root` this process's `/`, so an absolute path such as `/proc` is looked up beneath it.
/// The working directory stays where it was.
pub(crate) fn chroot_into(root: &Path) {
    rustix::process::chroot(root).unwrap_or_else(|e| panic!("chroot {}: {e}", root.display()));
}
