//! The directory a driver hands a chroot-ing fixture, and its cleanup.
//!
//! The fixture never leaves its root, so it cannot remove anything: the driver makes the root and
//! removes it. The cleanup never deletes recursively. A root that cannot be removed may hold a
//! mount, and a recursive delete would reach through it and destroy what is being diagnosed.

use std::io;
use std::path::{Path, PathBuf};

/// `scratch/root`, both made by the driver. `scratch` is the fixture's `TMPDIR`, so anything the
/// fixture leaves in its temp dir lands in `scratch`, outside `root`.
///
/// It also holds the fixture's skuld DB directory. Skuld checks, at the end of every test, that the
/// DB's path still names the DB, and a chroot makes the path name nothing. A fixture that chroots
/// into `root` binds [`db_dir`](Self::db_dir) to the same absolute path inside `root` first (see
/// `namespaces::bind_into_root`), in its own mount namespace.
pub(crate) struct ChrootScratch {
    scratch: PathBuf,
    root: PathBuf,
    // Removed recursively by `finish`: no mount can be in it (the fixture binds it only in a
    // namespace of its own).
    db: tempfile::TempDir,
}

impl ChrootScratch {
    pub(crate) fn new() -> Self {
        // `keep` hands over a plain path: there is no guard whose `Drop` could remove it recursively.
        let scratch = tempfile::Builder::new()
            .prefix("cosca-chroot-scratch-")
            .tempdir()
            .expect("tempdir for the chroot scratch")
            .keep();
        let root = scratch.join("root");
        std::fs::create_dir(&root).expect("mkdir the chroot root");
        let db = super::super::db_dir::fixture_db_dir();
        Self { scratch, root, db }
    }

    /// The fixture's `SKULD_DB_DIR`.
    pub(crate) fn db_dir(&self) -> &Path {
        self.db.path()
    }

    pub(crate) fn scratch(&self) -> &Path {
        &self.scratch
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Removes `root`, requires `scratch` to hold nothing else, then removes `scratch`; each with
    /// a non-recursive `remove_dir`. On `Err` whatever failed is left in place, for the message to
    /// name.
    pub(crate) fn finish(self) -> Result<(), String> {
        let Self { scratch, root, db } = self;
        let dirs = remove_dirs(&scratch, &root, db.path());
        // The DB directory holds only skuld's files, and no mount in this namespace.
        let db_path = db.path().to_owned();
        let closed = db
            .close()
            .map_err(|e| format!("remove the skuld DB directory {db_path:?}: {e}"));
        match (dirs, closed) {
            (Ok(()), closed) => closed,
            (Err(dirs), Ok(())) => Err(dirs),
            (Err(dirs), Err(closed)) => Err(format!("{dirs}; also {closed}")),
        }
    }
}

/// The non-recursive removals of [`ChrootScratch::finish`].
fn remove_dirs(scratch: &Path, root: &Path, db_dir: &Path) -> Result<(), String> {
    // The mount point of the DB directory, if the fixture made one: `root/tmp/<name>`, empty once
    // the fixture's mount namespace is gone.
    let mount_point = root.join(db_dir.strip_prefix("/").expect("an absolute DB directory"));
    for dir in mount_point.ancestors().take_while(|dir| *dir != root) {
        match std::fs::remove_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(describe_remove_dir(dir, &e)),
        }
    }
    remove_root(root)?;
    let left: Vec<_> = std::fs::read_dir(scratch)
        .map_err(|e| format!("read the scratch directory {scratch:?}: {e}"))?
        .map(|entry| entry.map(|e| e.path()))
        .collect();
    if !left.is_empty() {
        return Err(format!("the fixture left {} behind in {scratch:?}", list(&left)));
    }
    std::fs::remove_dir(scratch).map_err(|e| format!("remove the scratch directory {scratch:?}: {e}"))
}

/// Removes the chroot root with a non-recursive `remove_dir`; on failure it stays, and the message
/// names why.
pub(crate) fn remove_root(root: &Path) -> Result<(), String> {
    std::fs::remove_dir(root).map_err(|e| describe_remove_dir(root, &e))
}

/// [`describe_remove_failure`] for a failed `remove_dir(dir)`, listing `dir` itself.
fn describe_remove_dir(dir: &Path, error: &io::Error) -> String {
    let inside = std::fs::read_dir(dir).map(|entries| entries.map(|entry| entry.map(|e| e.path())).collect());
    describe_remove_failure(dir, error, inside)
}

/// The message for a failed `remove_dir(root)`. `inside` is what listing `root` returned. Leftovers
/// are claimed only when the OS said the directory is not empty; any other error is named by its
/// errno, with the listing as context.
pub(super) fn describe_remove_failure(
    root: &Path,
    error: &io::Error,
    inside: io::Result<Vec<io::Result<PathBuf>>>,
) -> String {
    let listing = match &inside {
        Ok(entries) => list(entries),
        Err(e) => format!("(listing it failed: {e})"),
    };
    if error.kind() == io::ErrorKind::DirectoryNotEmpty {
        format!("remove the chroot root {root:?}: {error}; the fixture left {listing} inside it")
    } else {
        format!(
            "remove the chroot root {root:?}: errno {:?}: {error}; its contents were {listing}",
            error.raw_os_error()
        )
    }
}

fn list(entries: &[io::Result<PathBuf>]) -> String {
    if entries.is_empty() {
        return "[]".into();
    }
    let items: Vec<_> = entries
        .iter()
        .map(|entry| match entry {
            Ok(path) => format!("{path:?}"),
            Err(e) => format!("<entry error: {e}>"),
        })
        .collect();
    format!("[{}]", items.join(", "))
}

#[cfg(test)]
#[path = "chroot_scratch_tests.rs"]
mod chroot_scratch_tests;
