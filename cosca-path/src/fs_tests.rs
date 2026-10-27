use std::io::ErrorKind;

use crate::fs::{BoundPath, Filesystem};
use crate::{posix, windows};

fn kind<T: std::fmt::Debug>(r: std::io::Result<T>) -> ErrorKind {
    r.expect_err("expected an error").kind()
}

/// A bound path asks its filesystem about its own path.
///
/// Mutants: a `BoundPath` that asks about a different path than the one it holds; a `same_file` that
/// ignores `other` or answers about `self` twice.
#[skuld::test]
fn a_bound_path_asks_its_filesystem() {
    let (file, dir) = (posix::Path::new("/d/f"), posix::Path::new("/d"));
    let fs = posix::FakeFilesystem::new().with_file(file).with_dir(dir);
    let bound = BoundPath::new(&fs, file);
    assert_eq!(bound.path(), file);
    assert!(bound.is_file().unwrap());
    assert!(!bound.is_dir().unwrap());
    assert_eq!(bound.canonical().unwrap(), file.to_path_buf());

    let bound = BoundPath::new(&fs, dir);
    assert!(bound.is_dir().unwrap());
    assert!(!bound.is_file().unwrap());

    // `same_file` compares the two bound paths, in either order.
    let (file_b, dir_b) = (BoundPath::new(&fs, file), BoundPath::new(&fs, dir));
    assert!(file_b.same_file(&file_b).unwrap());
    assert!(!file_b.same_file(&dir_b).unwrap());
    assert!(!dir_b.same_file(&file_b).unwrap());
    let absent = BoundPath::new(&fs, posix::Path::new("/nope"));
    assert_eq!(kind(file_b.same_file(&absent)), ErrorKind::NotFound);
    assert_eq!(kind(absent.same_file(&file_b)), ErrorKind::NotFound);

    // Through a trait object too: the resolver takes `&dyn Filesystem`.
    let dynamic: &dyn Filesystem<Path = posix::Path> = &fs;
    assert!(BoundPath::new(dynamic, file).is_file().unwrap());
}

/// `BoundPath` is `Clone`, `Copy` and `Debug` whatever its filesystem is, a `dyn Filesystem`
/// included, and `Debug` prints the path.
///
/// Mutant: derives on `BoundPath`, which demand `F: Clone`, so a `dyn Filesystem` does not qualify.
#[skuld::test]
fn a_bound_path_is_clone_copy_and_debug_for_any_filesystem() {
    fn bounds<T: Clone + Copy + std::fmt::Debug>() {}
    bounds::<BoundPath<'static, dyn Filesystem<Path = posix::Path>>>();
    bounds::<BoundPath<'static, dyn Filesystem<Path = windows::Path>>>();
    bounds::<BoundPath<'static, windows::FakeFilesystem>>();
    #[cfg(any(unix, windows))]
    bounds::<BoundPath<'static, crate::fs::HostFilesystem>>();

    let file = posix::Path::new("/d/f");
    let fs = posix::FakeFilesystem::new().with_file(file);
    let dynamic: &dyn Filesystem<Path = posix::Path> = &fs;
    let bound = BoundPath::new(dynamic, file);
    let copy = bound;
    assert!(bound.is_file().unwrap() && copy.is_file().unwrap());
    assert!(format!("{bound:?}").contains("/d/f"), "{bound:?}");
}
