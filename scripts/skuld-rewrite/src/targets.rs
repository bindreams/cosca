//! The cargo targets of a manifest, read through `cargo metadata`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cargo_metadata::MetadataCommand;

/// One target's name and root source file.
pub struct Target {
    pub name: String,
    pub src_path: PathBuf,
}

fn metadata(manifest: Option<&Path>) -> Result<cargo_metadata::Metadata> {
    let mut cmd = MetadataCommand::new();
    cmd.no_deps();
    if let Some(m) = manifest {
        cmd.manifest_path(m);
    }
    cmd.exec().context("running cargo metadata")
}

/// Every target of every package in the manifest.
pub fn all(manifest: Option<&Path>) -> Result<Vec<Target>> {
    let meta = metadata(manifest)?;
    meta.packages
        .iter()
        .flat_map(|p| p.targets.iter())
        .map(|t| {
            let src_path = std::fs::canonicalize(t.src_path.as_std_path())
                .with_context(|| format!("resolving the source of target {}", t.name))?;
            Ok(Target {
                name: t.name.clone(),
                src_path,
            })
        })
        .collect()
}

/// The git repository root containing the manifest's workspace.
pub fn toplevel(manifest: Option<&Path>) -> Result<PathBuf> {
    let root = metadata(manifest)?.workspace_root;
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root.as_std_path())
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("running git rev-parse")?;
    anyhow::ensure!(out.status.success(), "{root} is not inside a git repository");
    let top = String::from_utf8(out.stdout).context("git printed a non-UTF-8 path")?;
    std::fs::canonicalize(top.trim_end_matches(['\n', '\r'])).context("canonicalizing the repository root")
}
