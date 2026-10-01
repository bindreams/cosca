//! Command-line arguments to walk roots, shared by `apply` and `verify`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::modtree::Root;
use crate::targets;

/// Files named on the command line become crate roots; every `.rs` under a named directory is a
/// module file, unless it is a target or named like a root file.
pub fn resolve(args: &[PathBuf], manifest: Option<&Path>) -> Result<Vec<Root>> {
    let mut files: Vec<(PathBuf, bool)> = Vec::new();
    for arg in args {
        let path = std::fs::canonicalize(arg).with_context(|| format!("resolving {}", arg.display()))?;
        if path.is_dir() {
            let mut found = Vec::new();
            collect_rs(&path, &mut found)?;
            files.extend(found.into_iter().map(|f| (f, false)));
        } else {
            files.push((path, true));
        }
    }
    let rootish = |p: &Path| {
        matches!(
            p.file_name().and_then(|n| n.to_str()),
            Some("lib.rs" | "main.rs" | "mod.rs")
        )
    };
    let target_files: Vec<PathBuf> = if files.iter().all(|(f, _)| rootish(f)) {
        Vec::new()
    } else {
        targets::all(manifest)?.into_iter().map(|t| t.src_path).collect()
    };
    let mut roots: Vec<Root> = Vec::new();
    for (path, explicit) in files {
        let is_target = target_files.contains(&path);
        let mod_rs_like = rootish(&path) || is_target;
        let explicit = explicit || is_target;
        match roots.iter_mut().find(|r| r.path == path) {
            Some(existing) => existing.is_root |= explicit,
            None => roots.push(Root {
                path,
                mod_rs_like,
                is_root: explicit,
            }),
        }
    }
    // Crate roots first, so each module file is parsed in its owner's context.
    roots.sort_by(|a, b| (!a.mod_rs_like, &a.path).cmp(&(!b.mod_rs_like, &b.path)));
    Ok(roots)
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rs(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}
