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
    /// `cargo test` runs it.
    pub test: bool,
    pub doctest: bool,
    pub required_features: Vec<String>,
    /// The manifest's `harness`, true when unset.
    pub harness: bool,
    /// The manifest's `bench`, when set.
    pub bench: Option<bool>,
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
    let mut targets = Vec::new();
    for package in &meta.packages {
        let manifest: toml::Table = std::fs::read_to_string(package.manifest_path.as_std_path())
            .context("reading a package manifest")?
            .parse()
            .with_context(|| format!("parsing {}", package.manifest_path))?;
        for t in &package.targets {
            let src_path = std::fs::canonicalize(t.src_path.as_std_path())
                .with_context(|| format!("resolving the source of target {}", t.name))?;
            let mut kinds: Vec<String> = t.kind.iter().map(ToString::to_string).collect();
            kinds.sort();
            let declared = declaration(&manifest, &kinds, &t.name);
            targets.push(Target {
                name: t.name.clone(),
                kinds,
                src_path,
                test: t.test,
                doctest: t.doctest,
                required_features: t.required_features.clone(),
                harness: declared.and_then(|d| d.get("harness")?.as_bool()).unwrap_or(true),
                bench: declared.and_then(|d| d.get("bench")?.as_bool()),
            });
        }
    }
    let workspace_root =
        std::fs::canonicalize(meta.workspace_root.as_std_path()).context("resolving the workspace root")?;
    Ok(Listing {
        workspace_root,
        targets,
    })
}

/// The manifest table that declares a target, if it declares one: `[lib]`, or the `[[bin]]`,
/// `[[test]]`, `[[bench]]` or `[[example]]` entry of that name.
fn declaration<'a>(manifest: &'a toml::Table, kinds: &[String], name: &str) -> Option<&'a toml::Table> {
    let section = match kinds.first()?.as_str() {
        "bin" | "test" | "bench" | "example" => kinds[0].as_str(),
        "custom-build" => return None,
        _ => return manifest.get("lib")?.as_table(),
    };
    manifest
        .get(section)?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_table())
        .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(name))
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
