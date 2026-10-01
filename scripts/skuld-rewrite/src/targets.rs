//! The cargo targets of a manifest, read through `cargo metadata`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cargo_metadata::MetadataCommand;

/// One target's name, kinds and root source file.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target {
    pub name: String,
    pub kinds: Vec<String>,
    /// Canonical and absolute.
    pub src_path: PathBuf,
}

/// The targets of every package in a workspace.
pub struct Listing {
    /// Canonical.
    pub workspace_root: PathBuf,
    pub targets: Vec<Target>,
}

/// Reads `manifest`, or the manifest above the current directory.
pub fn load(manifest: Option<&Path>) -> Result<Listing> {
    let mut cmd = MetadataCommand::new();
    cmd.no_deps();
    if let Some(m) = manifest {
        cmd.manifest_path(m);
    }
    let meta = cmd.exec().context("running cargo metadata")?;
    let targets = meta
        .packages
        .iter()
        .flat_map(|p| p.targets.iter())
        .map(|t| {
            let src_path = std::fs::canonicalize(t.src_path.as_std_path())
                .with_context(|| format!("resolving the source of target {}", t.name))?;
            let mut kinds: Vec<String> = t.kind.iter().map(ToString::to_string).collect();
            kinds.sort();
            Ok(Target {
                name: t.name.clone(),
                kinds,
                src_path,
            })
        })
        .collect::<Result<_>>()?;
    let workspace_root =
        std::fs::canonicalize(meta.workspace_root.as_std_path()).context("resolving the workspace root")?;
    Ok(Listing {
        workspace_root,
        targets,
    })
}

/// Every target of every package in the manifest.
pub fn all(manifest: Option<&Path>) -> Result<Vec<Target>> {
    Ok(load(manifest)?.targets)
}

/// The git repository root containing `dir`.
pub fn toplevel(dir: &Path) -> Result<PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("running git rev-parse")?;
    anyhow::ensure!(out.status.success(), "{} is not inside a git repository", dir.display());
    let top = String::from_utf8(out.stdout).context("git printed a non-UTF-8 path")?;
    std::fs::canonicalize(top.trim_end_matches(['\n', '\r'])).context("canonicalizing the repository root")
}
