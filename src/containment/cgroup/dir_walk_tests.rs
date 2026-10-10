//! The walk of a leaf's descendant cgroups, on real cgroups: the cgroup lane (the `cgroup` group,
//! as root). Each test makes a scratch cgroup under the lane's own, and removes what it made.

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use super::{cgroup_id, find_descendant, Walked};
use crate::containment::cgroup::fault::fail_walk_step;
use crate::containment::cgroup::WalkStep;
use crate::test_groups::{cgroup, Group};

/// A cgroup under the lane's own, removed with every cgroup made under it when dropped. Removal is
/// by `rmdir` alone, deepest first: nothing is deleted through a mount.
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    pub(crate) fn new(tag: &str) -> Scratch {
        let own = std::fs::read_to_string("/proc/self/cgroup").expect("read /proc/self/cgroup");
        let own = own
            .lines()
            .find_map(|l| l.strip_prefix("0::/"))
            .expect("a unified line");
        let path = Path::new("/sys/fs/cgroup")
            .join(own)
            .join(format!("cosca-{}-{tag}", std::process::id()));
        std::fs::create_dir(&path).unwrap_or_else(|e| panic!("make {}: {e}", path.display()));
        Scratch(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// Make the cgroup `rel` under the scratch cgroup, and its parents.
    pub(crate) fn make(&self, rel: &str) -> PathBuf {
        let path = self.0.join(rel);
        std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("make {}: {e}", path.display()));
        path
    }

    /// The scratch cgroup, held as the walk holds a leaf.
    pub(crate) fn fd(&self) -> OwnedFd {
        open_path(&self.0)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let mut dirs = Vec::new();
        let mut pending = vec![self.0.clone()];
        while let Some(dir) = pending.pop() {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                pending.extend(
                    entries
                        .flatten()
                        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                        .map(|e| e.path()),
                );
            }
            dirs.push(dir);
        }
        for dir in dirs.iter().rev() {
            if let Err(e) = std::fs::remove_dir(dir) {
                if e.kind() != std::io::ErrorKind::NotFound && !std::thread::panicking() {
                    panic!("remove the scratch cgroup {}: {e}", dir.display());
                }
            }
        }
    }
}

pub(crate) fn open_path(path: &Path) -> OwnedFd {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap_or_else(|e| panic!("open {}: {e}", path.display()))
}

/// The cgroup id of the cgroup at `path`.
pub(crate) fn id_at(path: &Path) -> u64 {
    cgroup_id(open_path(path).as_fd()).unwrap_or_else(|e| panic!("the cgroup id of {}: {e}", path.display()))
}

/// A leaf's id is the cgroup id its members read through their pidfds (6.13 and later).
#[skuld::test]
fn cgroup_a_leaf_id_is_the_cgroup_id_its_members_read(#[fixture(cgroup)] _group: &Group) {
    let own = std::fs::read_to_string("/proc/self/cgroup").expect("read /proc/self/cgroup");
    let own = own
        .lines()
        .find_map(|l| l.strip_prefix("0::/"))
        .expect("a unified line");
    let pidfd = rustix::process::pidfd_open(rustix::process::getpid(), rustix::process::PidfdFlags::empty())
        .expect("pidfd_open");
    let read = crate::containment::cgroup::pidfd_cgroup_id(pidfd.as_fd())
        .expect("PIDFD_GET_INFO")
        .expect("the lane's kernel has PIDFD_GET_INFO");
    assert_eq!(id_at(&Path::new("/sys/fs/cgroup").join(own)), read);
}

/// The walk finds a cgroup at any depth under its root, and neither the root itself nor a cgroup
/// elsewhere. It needs no recursion: a chain 200 deep is walked.
#[skuld::test]
fn cgroup_the_walk_finds_a_cgroup_at_any_depth_and_only_under_its_root(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("walk-depth");
    let deep: String = ["d"; 200].join("/");
    let found = [scratch.make(&deep), scratch.make("wide/x"), scratch.path().join("wide")];
    let root = scratch.fd();
    for path in &found {
        assert!(
            matches!(find_descendant(root.as_fd(), id_at(path)), Walked::Found),
            "{}",
            path.display()
        );
    }
    let elsewhere = scratch.path().parent().expect("the lane's cgroup");
    for path in [scratch.path(), elsewhere] {
        let walked = find_descendant(root.as_fd(), id_at(path));
        assert!(matches!(walked, Walked::Absent), "{}: {walked:?}", path.display());
    }
}

/// A cgroup removed during the walk is skipped: what was under it is not found, and the rest is.
#[skuld::test]
fn cgroup_the_walk_skips_a_cgroup_removed_mid_walk(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("walk-removed");
    let target = id_at(&scratch.make("kept/target"));
    let root = scratch.fd();
    // Removes `gone` as the walk is about to open it, and says whether it did.
    let removing = || {
        let under = scratch.make("gone/under");
        let id = id_at(&under);
        let gone = scratch.path().join("gone");
        let removed = std::rc::Rc::new(std::cell::Cell::new(false));
        let hook = crate::containment::cgroup::fault::set_before_walk_open({
            let removed = std::rc::Rc::clone(&removed);
            move |path| {
                if path == Path::new("./gone") {
                    std::fs::remove_dir(gone.join("under")).expect("remove `gone/under` mid-walk");
                    std::fs::remove_dir(&gone).expect("remove `gone` mid-walk");
                    removed.set(true);
                }
            }
        });
        (hook, removed, id)
    };
    let (hook, removed, _) = removing();
    assert!(matches!(find_descendant(root.as_fd(), target), Walked::Found));
    assert!(removed.get(), "the walk reached `gone` before it found the target, and skipped it once removed");
    drop(hook);
    let (_hook, removed, under) = removing();
    let walked = find_descendant(root.as_fd(), under);
    assert!(matches!(walked, Walked::Absent), "{walked:?}");
    assert!(removed.get(), "the walk reached `gone`, and skipped it once removed");
}

/// A root removed before the walk lists anything leaves nothing listed, so nothing is known of the
/// cgroup sought: `Unknown`, never `Absent`. Mutant: "a gone root is skipped like any gone cgroup".
#[skuld::test]
fn cgroup_a_walk_of_a_removed_root_cannot_tell(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("walk-gone-root");
    let root = scratch.fd();
    std::fs::remove_dir(scratch.path()).expect("remove the root");
    let walked = find_descendant(root.as_fd(), 1);
    assert!(matches!(walked, Walked::Unknown(_)), "{walked:?}");
}

/// The same for a root that goes at any step: nothing, or not everything, of it was listed.
/// Mutant: as above.
#[skuld::test]
fn cgroup_a_walk_of_a_root_gone_at_any_step_cannot_tell(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("walk-gone-root-steps");
    scratch.make("under");
    let root = scratch.fd();
    for step in [WalkStep::Open, WalkStep::List, WalkStep::Entries, WalkStep::Alive] {
        for errno in [libc::ENOENT, libc::ENODEV] {
            let _failing = fail_walk_step(".", step, errno);
            let walked = find_descendant(root.as_fd(), 1);
            assert!(matches!(walked, Walked::Unknown(_)), "{step:?} {errno}: {walked:?}");
        }
    }
}

/// A refusal the walk cannot get past is `Unknown`, never `Absent`: a path past `PATH_MAX`
/// (`ENAMETOOLONG`) and a cgroup this process may not read (`EACCES`), at any step. Mutant: "the
/// refusal is skipped like a removed cgroup".
#[skuld::test]
fn cgroup_a_walk_that_is_refused_cannot_tell(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("walk-refused");
    scratch.make("a/b");
    let root = scratch.fd();
    for step in [WalkStep::Open, WalkStep::Id, WalkStep::List, WalkStep::Entries] {
        for errno in [libc::ENAMETOOLONG, libc::EACCES] {
            let _failing = fail_walk_step("./a", step, errno);
            let walked = find_descendant(root.as_fd(), 1);
            assert!(matches!(walked, Walked::Unknown(_)), "{step:?} {errno}: {walked:?}");
        }
    }
}

/// A cgroup that is gone at a step after the walk's open of it (its id read, the open for its
/// listing, its `getdents`) is skipped, as one gone at the open is: the rest of the tree is still
/// searched. Mutant: "a gone cgroup after the open is an error".
#[skuld::test]
fn cgroup_a_walk_skips_a_cgroup_gone_after_its_open(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("walk-gone-late");
    scratch.make("a");
    let target = id_at(&scratch.make("z/target"));
    let root = scratch.fd();
    for step in [WalkStep::Id, WalkStep::List, WalkStep::Entries] {
        for errno in [libc::ENODEV, libc::ENOENT] {
            let _failing = fail_walk_step("./a", step, errno);
            let walked = find_descendant(root.as_fd(), target);
            assert!(matches!(walked, Walked::Found), "{step:?} {errno}: {walked:?}");
            let walked = find_descendant(root.as_fd(), 1);
            assert!(matches!(walked, Walked::Absent), "{step:?} {errno}: {walked:?}");
        }
    }
}

/// The walk holds no descriptor from one cgroup to the next, however wide or deep the tree: each
/// time it is about to open a cgroup, this process holds the descriptors it held before the walk.
#[skuld::test]
fn cgroup_the_walk_holds_no_descriptor_between_cgroups(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("walk-fds");
    for i in 0..20 {
        scratch.make(&format!("w{i}/{}", ["d"; 10].join("/")));
    }
    let root = scratch.fd();
    let open_fds = || std::fs::read_dir("/proc/self/fd").expect("list fds").count();
    let before = open_fds();
    let counts = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let _hook = crate::containment::cgroup::fault::set_before_walk_open({
        let counts = std::rc::Rc::clone(&counts);
        move |_| counts.borrow_mut().push(open_fds())
    });
    let walked = find_descendant(root.as_fd(), 0);
    assert!(matches!(walked, Walked::Absent), "{walked:?}");
    let counts = counts.borrow();
    assert_eq!(counts.len(), 1 + 20 * 11, "the walk visits every cgroup once");
    assert!(
        counts.iter().all(|&n| n == before),
        "{before} before the walk, then {counts:?}"
    );
}

/// A cgroup behind a mount cannot be listed, so a walk that meets one cannot tell what is under
/// it: it answers `Unknown`, never `Absent`, whether the cgroup sought is behind the mount or
/// nowhere. The walking thread has its own mount namespace, the mount's, in which it holds the
/// leaf, as a process holds its leaves in its own; the mount is gone with the thread.
#[skuld::test]
fn cgroup_the_walk_cannot_tell_behind_a_mount(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("walk-mount");
    let hidden = id_at(&scratch.make("sub/x"));
    let elsewhere = id_at(scratch.path().parent().expect("the lane's cgroup"));
    let sub = scratch.path().join("sub");
    let walked = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                enter_private_mount_ns();
                let root = scratch.fd();
                let _mounted = TmpfsOver::new(&sub);
                [hidden, elsewhere].map(|id| find_descendant(root.as_fd(), id))
            })
            .join()
            .expect("the walking thread")
    });
    for walked in walked {
        assert!(matches!(walked, Walked::Unknown(_)), "{walked:?}");
    }
    let root = scratch.fd();
    assert!(matches!(find_descendant(root.as_fd(), hidden), Walked::Found));
}

/// Give this thread its own private mount namespace: a mount made in it stays in it, and goes with
/// the thread.
pub(crate) fn enter_private_mount_ns() {
    let root = std::ffi::CString::new("/").expect("no NUL");
    // SAFETY: plain syscalls on a valid NUL-terminated string. `unshare` gives this thread alone a
    // mount namespace; making it private keeps what is mounted in it there.
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
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null()
            ),
            0,
            "make / private: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// A tmpfs mounted over a directory, unmounted when dropped. Made only in a thread that called
/// [`enter_private_mount_ns`]. A failed unmount panics: nothing is removed through a mount.
pub(crate) struct TmpfsOver(std::ffi::CString);

impl TmpfsOver {
    pub(crate) fn new(target: &Path) -> TmpfsOver {
        let target = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).expect("no NUL");
        // SAFETY: `mount` on valid NUL-terminated strings.
        let rc = unsafe {
            libc::mount(
                c"none".as_ptr(),
                target.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        assert_eq!(
            rc,
            0,
            "mount a tmpfs over the cgroup: {}",
            std::io::Error::last_os_error()
        );
        TmpfsOver(target)
    }
}

impl Drop for TmpfsOver {
    fn drop(&mut self) {
        // SAFETY: `umount2` on a valid NUL-terminated string.
        let rc = unsafe { libc::umount2(self.0.as_ptr(), 0) };
        assert_eq!(rc, 0, "unmount the tmpfs: {}", std::io::Error::last_os_error());
    }
}
