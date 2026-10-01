//! Walking a root's module tree, resolving `#[path]` the way rustc does.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use syn::punctuated::Punctuated;
use syn::{Item, ItemMod, Lit, Meta, Token};

/// The mod name of the shared label file every root includes; never walked or rewritten.
pub const HARNESS_MOD: &str = "test_harness";

/// Where source text comes from: the working tree, or a git revision.
pub trait Source {
    /// `Ok(None)` when the file does not exist.
    fn read(&self, path: &Path) -> Result<Option<String>>;
}

/// The working tree.
pub struct FsSource;

impl Source for FsSource {
    fn read(&self, path: &Path) -> Result<Option<String>> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
}

/// A git revision of the repository containing `toplevel`.
pub struct GitSource {
    toplevel: PathBuf,
    rev: String,
}

impl GitSource {
    /// Fails when `rev` does not name a commit.
    pub fn new(toplevel: &Path, rev: &str) -> Result<Self> {
        let status = Command::new("git")
            .arg("-C")
            .arg(toplevel)
            .args(["rev-parse", "--verify", "--quiet", "--end-of-options"])
            .arg(format!("{rev}^{{commit}}"))
            .stdout(Stdio::null())
            .status()
            .context("running git rev-parse")?;
        if !status.success() {
            bail!("`{rev}` does not name a commit");
        }
        Ok(Self {
            toplevel: toplevel.to_owned(),
            rev: rev.to_owned(),
        })
    }
}

impl Source for GitSource {
    fn read(&self, path: &Path) -> Result<Option<String>> {
        let rel = path.strip_prefix(&self.toplevel).with_context(|| {
            format!(
                "{} is outside the repository {}",
                path.display(),
                self.toplevel.display()
            )
        })?;
        let spec = format!("{}:{}", self.rev, rel.to_string_lossy().replace('\\', "/"));
        // `cat-file -e` succeeds exactly when the object exists, so a missing file is a status, not text.
        let exists = Command::new("git")
            .arg("-C")
            .arg(&self.toplevel)
            .args(["cat-file", "-e"])
            .arg(&spec)
            .stderr(Stdio::null())
            .status()
            .context("running git cat-file")?;
        if !exists.success() {
            return Ok(None);
        }
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.toplevel)
            .args(["cat-file", "blob"])
            .arg(&spec)
            .output()
            .context("running git cat-file")?;
        if !out.status.success() {
            bail!("git cat-file blob {spec} failed");
        }
        Ok(Some(
            String::from_utf8(out.stdout).with_context(|| format!("{spec} is not UTF-8"))?,
        ))
    }
}

/// One parsed source file of a module tree.
pub struct ParsedFile {
    pub path: PathBuf,
    pub src: String,
    pub ast: syn::File,
    /// True for a file passed as a root.
    pub is_root: bool,
}

/// Collapses `.` and `..` lexically, so a `#[path = "../x.rs"]` names one file one way.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

struct Ctx {
    /// Where `mod x;` looks for `x.rs` and `x/mod.rs`.
    mod_dir: PathBuf,
    /// What a `#[path]` attribute is relative to.
    path_base: PathBuf,
}

/// Every file reachable from `root` through `mod` declarations, root first, each once.
/// Modules are followed whatever their `cfg`: a file for another OS is still part of the tree.
pub fn walk(source: &dyn Source, root: &Path) -> Result<Vec<ParsedFile>> {
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    visit_file(source, &normalize(root), true, true, &mut files, &mut seen)?;
    Ok(files)
}

fn visit_file(
    source: &dyn Source,
    path: &Path,
    mod_rs_like: bool,
    is_root: bool,
    files: &mut Vec<ParsedFile>,
    seen: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    if !seen.insert(path.to_owned()) {
        return Ok(());
    }
    let src = source
        .read(path)?
        .with_context(|| format!("{} does not exist", path.display()))?;
    let ast = syn::parse_file(&src).with_context(|| format!("parsing {}", path.display()))?;
    let dir = path
        .parent()
        .context("a source file has a parent directory")?
        .to_owned();
    let mod_dir = if mod_rs_like {
        dir.clone()
    } else {
        dir.join(path.file_stem().context("a source file has a stem")?)
    };
    let ctx = Ctx {
        mod_dir,
        path_base: dir,
    };
    let items = ast.items.clone();
    files.push(ParsedFile {
        path: path.to_owned(),
        src,
        ast,
        is_root,
    });
    visit_items(source, path, &items, &ctx, files, seen)
}

/// Every `#[path = ".."]` of a module, plain or inside a `cfg_attr`, and whether any was
/// conditional. The walk follows every cfg, so every alternative is part of the tree.
fn path_attrs(m: &ItemMod) -> Result<(Vec<String>, bool)> {
    fn string_of(nv: &syn::MetaNameValue, name: &str) -> Result<String> {
        match &nv.value {
            syn::Expr::Lit(syn::ExprLit { lit: Lit::Str(s), .. }) => Ok(s.value()),
            _ => bail!("`#[path]` on `mod {name}` is not a string literal"),
        }
    }
    let mut paths = Vec::new();
    let mut conditional = false;
    for a in &m.attrs {
        match &a.meta {
            Meta::NameValue(nv) if nv.path.is_ident("path") => paths.push(string_of(nv, &m.ident.to_string())?),
            Meta::List(list) if list.path.is_ident("cfg_attr") => {
                let args = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
                for arg in args.iter().skip(1) {
                    if let Meta::NameValue(nv) = arg {
                        if nv.path.is_ident("path") {
                            paths.push(string_of(nv, &m.ident.to_string())?);
                            conditional = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok((paths, conditional))
}

fn visit_items(
    source: &dyn Source,
    file: &Path,
    items: &[Item],
    ctx: &Ctx,
    files: &mut Vec<ParsedFile>,
    seen: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for item in items {
        let Item::Mod(m) = item else { continue };
        if m.ident == HARNESS_MOD {
            continue;
        }
        let (paths, conditional) = path_attrs(m)?;
        match &m.content {
            Some((_, inner)) => {
                let mut dirs: Vec<PathBuf> = paths.iter().map(|p| normalize(&ctx.path_base.join(p))).collect();
                if paths.is_empty() || conditional {
                    dirs.push(ctx.mod_dir.join(m.ident.to_string()));
                }
                for dir in dirs {
                    let inner_ctx = Ctx {
                        mod_dir: dir.clone(),
                        path_base: dir,
                    };
                    visit_items(source, file, inner, &inner_ctx, files, seen)?;
                }
            }
            None => {
                let mut children: Vec<(PathBuf, bool)> = paths
                    .iter()
                    .map(|p| (normalize(&ctx.path_base.join(p)), true))
                    .collect();
                if paths.is_empty() || conditional {
                    match resolve_mod_file(source, ctx, &m.ident.to_string(), file)? {
                        Some(found) => children.push(found),
                        None if children.is_empty() => bail!(
                            "`mod {};` in {} has no file: neither {} nor {} exists",
                            m.ident,
                            file.display(),
                            ctx.mod_dir.join(format!("{}.rs", m.ident)).display(),
                            ctx.mod_dir.join(m.ident.to_string()).join("mod.rs").display()
                        ),
                        None => {}
                    }
                }
                for (child, mod_rs_like) in children {
                    visit_file(source, &child, mod_rs_like, false, files, seen)?;
                }
            }
        }
    }
    Ok(())
}

fn resolve_mod_file(source: &dyn Source, ctx: &Ctx, name: &str, declared_in: &Path) -> Result<Option<(PathBuf, bool)>> {
    let flat = ctx.mod_dir.join(format!("{name}.rs"));
    let nested = ctx.mod_dir.join(name).join("mod.rs");
    match (source.read(&flat)?.is_some(), source.read(&nested)?.is_some()) {
        (true, false) => Ok(Some((flat, false))),
        (false, true) => Ok(Some((nested, true))),
        (true, true) => bail!(
            "`mod {name};` in {} is ambiguous: both {} and {} exist",
            declared_in.display(),
            flat.display(),
            nested.display()
        ),
        (false, false) => Ok(None),
    }
}
