//! The directory a driver hands a chroot-ing fixture, and its cleanup.
//!
//! The fixture never leaves its root, so it cannot remove anything: the driver makes the root and
//! removes it. The cleanup never deletes recursively. A root that cannot be removed may hold a
//! mount, and a recursive delete would reach through it and destroy what is being diagnosed.

use std::io;
use std::path::{Path, PathBuf};

/// `scratch/root`, both made by the driver. `scratch` is the fixture's `TMPDIR`, so anything the
/// fixture leaves in its temp dir lands in `scratch`, outside `root`.
pub(crate) struct ChrootScratch {
    scratch: PathBuf,
    root: PathBuf,
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
        Self { scratch, root }
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
        remove_root(&self.root)?;
        let left: Vec<_> = std::fs::read_dir(&self.scratch)
            .map_err(|e| format!("read the scratch directory {:?}: {e}", self.scratch))?
            .map(|entry| entry.map(|e| e.path()))
            .collect();
        if !left.is_empty() {
            return Err(format!("the fixture left {} behind in {:?}", list(&left), self.scratch));
        }
        std::fs::remove_dir(&self.scratch).map_err(|e| format!("remove the scratch directory {:?}: {e}", self.scratch))
    }
}

/// Removes the chroot root with a non-recursive `remove_dir`; on failure it stays, and the message
/// names why.
pub(crate) fn remove_root(root: &Path) -> Result<(), String> {
    std::fs::remove_dir(root).map_err(|e| {
        let inside = std::fs::read_dir(root).map(|entries| entries.map(|entry| entry.map(|e| e.path())).collect());
        describe_remove_failure(root, &e, inside)
    })
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
