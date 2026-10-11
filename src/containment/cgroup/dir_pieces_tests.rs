//! The traversal of a tree whose path from the leaf is longer than `PATH_MAX`: how a path is split
//! into pieces, what the pieces are opened with, and what the traversal stores of the tree. The
//! cgroup lane (the `cgroup` group, as root) runs the tests on real cgroups; the others need none.

use std::ffi::OsStr;
use std::os::fd::{AsFd as _, OwnedFd};

use rustix::io::Errno;

use super::{cgroup_id, find_descendant, open_cgroup, pieces, traverse, LeafDir, Tree, Visit, Walked, PATH_MAX_BYTES};
use crate::containment::cgroup::dir_walk_tests::{enter_private_mount_ns, open_path, DeepTree, Scratch};
use crate::test_groups::{cgroup, Group};

fn names_of(lens: &[usize]) -> Vec<String> {
    lens.iter().map(|&n| "n".repeat(n)).collect()
}

fn runs(lens: &[usize]) -> Vec<std::ops::Range<usize>> {
    let names = names_of(lens);
    let names: Vec<&OsStr> = names.iter().map(OsStr::new).collect();
    pieces(&names, PATH_MAX_BYTES)
}

// pieces =====

/// A piece is exactly `PATH_MAX - 1` bytes when that is what fills it: 16 names of 255 bytes and 15
/// separators are 4095. Mutant: a piece must be shorter than `PATH_MAX - 1`.
#[skuld::test]
fn a_piece_of_exactly_path_max_minus_one_bytes_is_one_piece() {
    assert_eq!(runs(&[255; 17]), [0..16, 16..17]);
    assert_eq!(runs(&[255; 16]), vec![0..16]);
}

/// One byte more starts the next piece: 15 names of 255 bytes and a name of 256 are 4096 bytes,
/// which no open takes. Mutant: a piece may be `PATH_MAX` bytes.
#[skuld::test]
fn a_piece_of_path_max_bytes_is_split() {
    let mut lens = vec![255; 15];
    lens.extend([256, 255]);
    assert_eq!(runs(&lens), [0..15, 15..17]);
}

/// A name that is the whole of a piece stands alone between its neighbours'.
#[skuld::test]
fn a_name_that_fills_a_piece_stands_alone() {
    assert_eq!(runs(&[300, 4000, 300]), [0..1, 1..2, 2..3]);
    assert_eq!(runs(&[100, 4000, 100, 100]), [0..1, 1..2, 2..4]);
    assert_eq!(runs(&[]), Vec::<std::ops::Range<usize>>::new());
}

// guards =====

/// Names of 200 bytes put the 21st at the start of the second piece (20 of them are 4019 bytes).
fn long_names(count: usize) -> Vec<String> {
    names_of(&vec![200; count])
}

/// A symlink at the split, as the last name of the first piece or the first of the second, is not
/// followed, though a name after it leads somewhere through it. Mutant: the pieces after the first
/// are opened without `RESOLVE_NO_SYMLINKS`.
#[skuld::test]
fn a_symlink_at_the_split_of_a_long_path_is_refused() {
    use rustix::fs::AtFlags;

    let names = long_names(22);
    for symlink_at in [19, 20] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = open_path(tmp.path());
        let real = tmp.path().join("real");
        std::fs::create_dir_all(real.join(&names[0])).expect("make the symlink's target");
        let chain = DeepTree::with_names(&root, names[..symlink_at].to_vec());
        let parent = if symlink_at == 0 { &root } else { chain.bottom() };
        rustix::fs::symlinkat(&real, parent, names[symlink_at].as_str()).expect("make the symlink");
        let opened = open_cgroup(root.as_fd(), &names.iter().map(OsStr::new).collect::<Vec<_>>());
        rustix::fs::unlinkat(parent, names[symlink_at].as_str(), AtFlags::empty()).expect("remove the symlink");
        assert!(
            matches!(opened, Err(Errno::LOOP | Errno::NOTDIR)),
            "a symlink as name {} was followed: {opened:?}",
            symlink_at + 1
        );
    }
}

/// A mount at the split, on the last cgroup of the first piece or the first of the second, is not
/// crossed: the walk cannot tell, and the sweep removes nothing through it. The mount shows a
/// directory that is no cgroup's. Mutant: the pieces after the first are opened without
/// `RESOLVE_NO_XDEV`.
#[skuld::test]
fn cgroup_a_mount_at_the_split_of_a_long_path_is_not_crossed(#[fixture(cgroup)] _group: &Group) {
    for mounted in [20, 21] {
        let scratch = Scratch::new(&format!("split-mount-{mounted}"));
        let root = scratch.fd();
        let chain = DeepTree::new(&root, &"n".repeat(200), 25);
        let bottom = cgroup_id(chain.bottom().as_fd()).expect("the bottom's id");
        let names = long_names(mounted);
        let names: Vec<&OsStr> = names.iter().map(OsStr::new).collect();
        let victim = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(victim.path().join("keep/me")).expect("make the victim's empty dirs");
        let (walked, swept) = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    enter_private_mount_ns();
                    // Descriptors opened before the namespace was made belong to the old one.
                    let root = scratch.fd();
                    let level = open_cgroup(root.as_fd(), &names[..mounted]).expect("open the level to mount over");
                    let _mounted = BindOver::new(victim.path(), &level);
                    let walked = find_descendant(root.as_fd(), bottom);
                    (walked, LeafDir::open_for_test(scratch.path()).remove_children())
                })
                .join()
                .expect("the walking thread")
        });
        assert!(matches!(walked, Walked::Unknown(_)), "mount at {mounted}: {walked:?}");
        assert!(
            swept.is_ok(),
            "mount at {mounted}: the sweep failed: {}",
            swept.as_ref().err().map_or(String::new(), ToString::to_string)
        );
        assert!(
            victim.path().join("keep/me").is_dir(),
            "mount at {mounted}: the sweep crossed the mount and deleted the victim's directories"
        );
        assert!(
            matches!(find_descendant(root.as_fd(), bottom), Walked::Found),
            "mount at {mounted}: the sweep removed what is beyond the mount"
        );
    }
}

/// `source` bind-mounted over the directory `target` is held on, unmounted when dropped. Made only
/// in a thread that called [`enter_private_mount_ns`]. A failed unmount panics: nothing is removed
/// through a mount.
struct BindOver(std::ffi::CString);

impl BindOver {
    fn new(source: &std::path::Path, target: &OwnedFd) -> BindOver {
        let source = std::ffi::CString::new(source.as_os_str().as_encoded_bytes()).expect("no NUL");
        let target = std::ffi::CString::new(super::fd_path(target.as_fd())).expect("no NUL");
        // SAFETY: `mount` on valid NUL-terminated strings.
        let rc = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "bind over the cgroup: {}", std::io::Error::last_os_error());
        BindOver(target)
    }
}

impl Drop for BindOver {
    fn drop(&mut self) {
        // SAFETY: `umount2` on a valid NUL-terminated string.
        let rc = unsafe { libc::umount2(self.0.as_ptr(), 0) };
        assert_eq!(rc, 0, "unmount the bind: {}", std::io::Error::last_os_error());
    }
}

/// `open_cgroup` takes names, not paths: one that is absolute, `..`, or holds a `/` would become a
/// different path silently.
#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "every name is one plain path component")]
fn open_cgroup_refuses_a_name_that_is_not_one_component() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = open_path(tmp.path());
    drop(open_cgroup(root.as_fd(), &[OsStr::new("..")]));
}

// real trees =====

/// Sweep and walk the chain of cgroups named `lens` bytes, each: the walk finds the bottom, and
/// answers `Absent` for a cgroup that is not there; the sweep removes every one, with no error, and
/// records the bottom's id.
fn sweep_and_walk(tag: &str, lens: &[usize]) {
    let scratch = Scratch::new(tag);
    let root = scratch.fd();
    let chain = DeepTree::with_names(&root, names_of(lens));
    let bottom = cgroup_id(chain.bottom().as_fd()).expect("the bottom's id");
    let walked = find_descendant(root.as_fd(), bottom);
    assert!(matches!(walked, Walked::Found), "{walked:?}");
    let walked = find_descendant(root.as_fd(), 1);
    assert!(matches!(walked, Walked::Absent), "{walked:?}");
    let leaf = LeafDir::open_for_test(scratch.path());
    let swept = leaf.remove_children();
    assert_eq!(swept.expect("the sweep"), lens.len());
    assert!(
        std::fs::read_dir(scratch.path())
            .expect("list the scratch cgroup")
            .flatten()
            .all(|e| !e.file_type().is_ok_and(|t| t.is_dir())),
        "the first cgroup is removed"
    );
    assert!(leaf.swept().holds(bottom), "the bottom's id is recorded");
}

/// A first piece of exactly 4095 bytes is taken by the kernel, and so is one of 4096 bytes' worth of
/// names split in two. Mutants: a piece may be `PATH_MAX` bytes; a piece must be shorter than 4095.
#[skuld::test]
fn cgroup_pieces_at_the_edge_of_path_max_are_opened(#[fixture(cgroup)] _group: &Group) {
    sweep_and_walk("edge-4095", &[255; 17]);
    let mut lens = vec![255; 15];
    lens.extend([256, 255]);
    sweep_and_walk("edge-4096", &lens);
}

/// A cgroup name over 255 bytes (cgroupfs takes it), and names that each fill a piece.
#[skuld::test]
fn cgroup_names_over_name_max_are_swept_and_walked(#[fixture(cgroup)] _group: &Group) {
    sweep_and_walk("names-300", &[300; 20]);
    sweep_and_walk("names-whole-piece", &[4000, 4000, 300, 4000]);
}

// storage =====

/// The traversal stores each name once: the bytes it stores of a chain are the bytes of its names,
/// however deep, where the paths of the chain's cgroups are quadratic in its depth. Mutant: a node
/// stores its whole path from the root.
#[skuld::test]
fn cgroup_the_traversal_stores_the_names_of_a_tree_once(#[fixture(cgroup)] _group: &Group) {
    const DEPTH: usize = 100;
    let scratch = Scratch::new("stored");
    let root = scratch.fd();
    let _chain = DeepTree::new(&root, &"n".repeat(200), DEPTH);
    let mut tree = Tree::new();
    let visited = std::cell::Cell::new(0);
    let traversed = traverse(&mut tree, root.as_fd(), true, |_, _, _| {
        visited.set(visited.get() + 1);
        Ok(Visit::Continue)
    });
    assert!(traversed.is_ok(), "the traversal failed");
    assert_eq!(visited.get(), DEPTH);
    assert_eq!(tree.stored_bytes(), DEPTH * 200, "the names of the tree, once");
}
