//! `skuld-rewrite apply` and `skuld-rewrite verify`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use skuld_rewrite::modtree::{FsSource, GitSource, Root};
use skuld_rewrite::rewrite::{self, Options, Outcome};
use skuld_rewrite::{targets, verify};

#[derive(Parser)]
#[command(about = "Move cosca's tests onto skuld's harness, and prove nothing else changed")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Only {
    /// Rewrite `tokio::test` spellings and leave bare `#[test]` alone.
    Tokio,
}

#[derive(Subcommand)]
enum Command {
    /// Rewrite test attributes in the module tree of each ROOT, in place.
    ///
    /// Exits 2, writing nothing, when a site cannot be mapped or a file that would change is also
    /// reachable from a root named in --unflipped.
    Apply {
        #[arg(long, value_enum)]
        only: Option<Only>,
        /// Move each root's `#![cfg(P)]` onto its top-level items, except `main` and `mod test_harness`.
        #[arg(long)]
        hoist_crate_cfg: bool,
        /// Lines naming roots that still run under libtest: a `.rs` path, or a cargo target name.
        #[arg(long, value_name = "FILE")]
        unflipped: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        manifest_path: Option<PathBuf>,
        /// Files are crate roots; a directory means every `.rs` under it.
        #[arg(required = true)]
        roots: Vec<PathBuf>,
    },
    /// Prove the working tree equals OLD_REV under the canonical form. Exits 1 on a difference.
    ///
    /// With no ROOT, compares the manifest's targets with OLD_REV's, then every target's module tree.
    Verify {
        old_rev: String,
        #[arg(long, value_name = "PATH")]
        manifest_path: Option<PathBuf>,
        roots: Vec<PathBuf>,
    },
}

fn read_unflipped(file: &Path, manifest: Option<&Path>) -> Result<Vec<PathBuf>> {
    let text = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let mut roots = Vec::new();
    let mut by_name = None;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.ends_with(".rs") {
            roots.push(PathBuf::from(line));
            continue;
        }
        let all = match &by_name {
            Some(all) => all,
            None => by_name.insert(targets::all(manifest)?),
        };
        let found: Vec<_> = all.iter().filter(|t| t.name == line).collect();
        if found.is_empty() {
            bail!(
                "{}: `{line}` is neither a .rs path nor a target of the manifest",
                file.display()
            );
        }
        roots.extend(found.into_iter().map(|t| t.src_path.clone()));
    }
    Ok(roots)
}

fn canonical(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    paths
        .iter()
        .map(|p| std::fs::canonicalize(p).with_context(|| format!("resolving {}", p.display())))
        .collect()
}

/// Files named on the command line become crate roots; every `.rs` under a named directory is a
/// module file, unless it is a target or named like a root file.
fn cli_roots(args: &[PathBuf], manifest: Option<&Path>) -> Result<Vec<Root>> {
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
        let mod_rs_like = rootish(&path) || target_files.contains(&path);
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

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Apply {
            only,
            hoist_crate_cfg,
            unflipped,
            manifest_path,
            roots,
        } => {
            let unflipped = match unflipped {
                Some(f) => read_unflipped(&f, manifest_path.as_deref())?,
                None => Vec::new(),
            };
            let roots = cli_roots(&roots, manifest_path.as_deref())?;
            let unflipped = canonical(&unflipped)?;
            let opts = Options {
                only_tokio: only.is_some(),
                hoist_crate_cfg,
            };
            match rewrite::apply_roots(&FsSource, &roots, &unflipped, opts)? {
                Outcome::Refused(refusals) => {
                    for r in refusals {
                        eprintln!("refused: {r}");
                    }
                    Ok(ExitCode::from(2))
                }
                Outcome::Rewritten(files) => {
                    for (path, text) in files {
                        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
                        println!("rewrote {}", path.display());
                    }
                    Ok(ExitCode::SUCCESS)
                }
            }
        }
        Command::Verify {
            old_rev,
            manifest_path,
            roots,
        } => {
            let mismatches = if roots.is_empty() {
                verify::verify_targets(manifest_path.as_deref(), &old_rev)?
            } else {
                let toplevel = targets::toplevel(&std::env::current_dir()?)?;
                let old = GitSource::new(&toplevel, &old_rev)?;
                verify::verify(&old, &FsSource, &canonical(&roots)?)?
            };
            for m in &mismatches {
                eprintln!("mismatch: {m}");
            }
            Ok(if mismatches.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}
