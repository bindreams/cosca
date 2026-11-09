//! Pre-commit lint: no libtest test attribute (`#[test]`, `#[tokio::test]`, ...) in a workspace member.
//!
//! cosca's lib and every test target run on skuld (`harness = false`), where a libtest attribute is stripped and its
//! test silently never runs. The lint reads every tracked `.rs` file of every workspace member with `syn`, so every
//! `cfg` branch is seen at once, and reports each libtest attribute: on any item, inside `cfg_attr`, inside macro
//! bodies and invocations, imported by `use`, or reached through a `use` or `extern crate` name. It also checks the
//! premise: each member's manifest has no target that runs on libtest.
//!
//! Exit 0: clean. 1: a libtest attribute, an unparsable file or a path that is not UTF-8. 2: a manifest target on
//! libtest, or the tool could not run. Not covered: an attribute a third-party proc macro emits, one assembled with
//! `concat!` or from a `$m:meta`, or an alias bound in one file (`pub use tokio as tk;`) and used in another. A syntax
//! `syn` cannot parse yet is reported as an unparsable file until `syn` is bumped. A file that is not a whole Rust file
//! (an `include!` fragment) is lexed instead and read without the `use`s of the file that includes it, so a bare
//! `#[test]` there may be skuld's: only `tokio::test` and the `core`/`std` prelude paths are flagged in a fragment.
//!
//! Run from inside the workspace; takes no arguments.

mod manifest;
mod source;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

type Failure = Box<dyn std::error::Error>;

struct Member {
    /// Directory relative to the workspace root, `/`-separated; empty for the root package.
    dir: String,
    manifest: PathBuf,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("libtest-lint: {e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, Failure> {
    let (root, members) = members()?;
    let excluded = excluded(&root)?;
    let (tracked, invalid) = tracked(&root)?;
    let mut findings = invalid.len();
    for path in &invalid {
        println!("{path}: path is not UTF-8");
    }
    let manifest_dirs: BTreeSet<&str> = tracked
        .iter()
        .filter_map(|f| {
            f.strip_suffix("Cargo.toml")
                .filter(|d| d.is_empty() || d.ends_with('/'))
        })
        .map(|d| d.trim_end_matches('/'))
        .collect();

    let mut premise = 0;
    for member in &members {
        let mine: BTreeSet<String> = tracked
            .iter()
            .filter(|f| belongs(f, &member.dir, &manifest_dirs) && !excluded.iter().any(|e| under(f, e)))
            .filter_map(|f| relative(f, &member.dir).map(str::to_string))
            .collect();
        let manifest_path = if member.dir.is_empty() {
            "Cargo.toml".to_string()
        } else {
            format!("{}/Cargo.toml", member.dir)
        };
        let text = std::fs::read_to_string(&member.manifest)?;
        for line in manifest::check(&manifest_path, &text, &mine).map_err(|e| format!("{manifest_path}: {e}"))? {
            println!("{line}");
            premise += 1;
        }
        for rel in mine.iter().filter(|f| f.ends_with(".rs")) {
            let path = if member.dir.is_empty() {
                rel.clone()
            } else {
                format!("{}/{rel}", member.dir)
            };
            let text = match std::fs::read_to_string(root.join(&path)) {
                Ok(text) => text,
                // Tracked but deleted in the working tree.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    println!("{path}: cannot read: {e}");
                    findings += 1;
                    continue;
                }
            };
            match source::check_file(&text) {
                Ok(fs) => {
                    for f in fs {
                        println!("{path}:{}:{}: {} (write #[skuld::test])", f.line, f.col, f.what);
                        findings += 1;
                    }
                }
                Err(e) => {
                    let at = e.span().start();
                    println!("{path}:{}:{}: does not parse: {e}", at.line, at.column + 1);
                    findings += 1;
                }
            }
        }
    }
    Ok(match (premise, findings) {
        (0, 0) => ExitCode::SUCCESS,
        (0, _) => ExitCode::from(1),
        _ => ExitCode::from(2),
    })
}

/// The workspace root and its members, from `cargo metadata`.
fn members() -> Result<(PathBuf, Vec<Member>), Failure> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()?;
    if !out.status.success() {
        return Err(format!("cargo metadata failed: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let root = PathBuf::from(meta["workspace_root"].as_str().ok_or("no workspace_root")?);
    let ids: BTreeSet<&str> = meta["workspace_members"]
        .as_array()
        .ok_or("no workspace_members")?
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let mut members = Vec::new();
    for package in meta["packages"].as_array().ok_or("no packages")? {
        if !ids.contains(package["id"].as_str().ok_or("no package id")?) {
            continue;
        }
        let manifest = PathBuf::from(package["manifest_path"].as_str().ok_or("no manifest_path")?);
        let dir = manifest
            .parent()
            .ok_or("manifest without a directory")?
            .strip_prefix(&root)?;
        let dir = dir.to_str().ok_or("non-UTF-8 member path")?.replace('\\', "/");
        members.push(Member { dir, manifest });
    }
    Ok((root, members))
}

/// `[workspace] exclude` of the root manifest.
fn excluded(root: &Path) -> Result<Vec<String>, Failure> {
    let manifest: toml::Table = std::fs::read_to_string(root.join("Cargo.toml"))?.parse()?;
    let list = manifest
        .get("workspace")
        .and_then(|w| w.get("exclude"))
        .and_then(|e| e.as_array());
    Ok(list
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .map(|s| s.trim_matches('/').to_string())
        .collect())
}

/// Tracked `.rs` files and `Cargo.toml`s, relative to the workspace root, and the lossy names of those whose path is
/// not UTF-8. Only tracked files: never untracked scratch.
fn tracked(root: &Path) -> Result<(BTreeSet<String>, Vec<String>), Failure> {
    let out = Command::new("git")
        .current_dir(root)
        .args(["ls-files", "-z", "--", "*.rs", "*Cargo.toml"])
        .output()?;
    if !out.status.success() {
        return Err(format!("git ls-files failed: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    let (mut files, mut invalid) = (BTreeSet::new(), Vec::new());
    for name in out.stdout.split(|&b| b == 0).filter(|f| !f.is_empty()) {
        if !(name.ends_with(b".rs") || name.rsplit(|&b| b == b'/').next() == Some(b"Cargo.toml".as_slice())) {
            continue;
        }
        match std::str::from_utf8(name) {
            Ok(name) => {
                files.insert(name.to_string());
            }
            Err(_) => invalid.push(String::from_utf8_lossy(name).into_owned()),
        }
    }
    Ok((files, invalid))
}

fn under(file: &str, dir: &str) -> bool {
    dir.is_empty() || file.strip_prefix(dir).is_some_and(|r| r.starts_with('/'))
}

fn relative<'a>(file: &'a str, dir: &str) -> Option<&'a str> {
    if dir.is_empty() {
        Some(file)
    } else {
        file.strip_prefix(dir)?.strip_prefix('/')
    }
}

/// A file belongs to the member whose directory is the nearest one above it that holds a `Cargo.toml`: no other
/// crate's directory lies between them. A nested non-member crate (`scripts/skuld-rewrite`) belongs to none.
fn belongs(file: &str, member_dir: &str, manifest_dirs: &BTreeSet<&str>) -> bool {
    let Some(rel) = relative(file, member_dir) else {
        return false;
    };
    let mut dir = Path::new(rel).parent();
    while let Some(d) = dir.filter(|d| !d.as_os_str().is_empty()) {
        let full = if member_dir.is_empty() {
            d.to_str().unwrap_or("").to_string()
        } else {
            format!("{member_dir}/{}", d.to_str().unwrap_or(""))
        };
        if manifest_dirs.contains(full.as_str()) {
            return false;
        }
        dir = d.parent();
    }
    true
}
