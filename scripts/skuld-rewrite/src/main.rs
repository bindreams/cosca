//! `skuld-rewrite apply` and `skuld-rewrite verify`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use skuld_rewrite::modtree::FsSource;
use skuld_rewrite::rewrite::{self, Options, Outcome};
use skuld_rewrite::{roots, targets, verify};

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
            let roots = roots::resolve(&roots, manifest_path.as_deref())?;
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
                    rewrite::commit(&files)?;
                    for f in &files {
                        println!("rewrote {}", f.path.display());
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
            let roots = roots::resolve(&roots, manifest_path.as_deref())?;
            let mismatches = verify::verify_targets(manifest_path.as_deref(), &old_rev, &roots)?;
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
