//! Walking a root's module tree, resolving `#[path]` the way rustc does.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use syn::punctuated::Punctuated;
use syn::{Item, ItemMod, Lit, Meta, Token};

/// The mod name of the shared label file every root includes. Only the exact include is skipped.
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

/// One commit of the repository containing `toplevel`, pinned when the source is made so that
/// every read sees the same tree even if a branch name moves meanwhile.
pub struct GitSource {
    toplevel: PathBuf,
    commit: String,
}

impl GitSource {
    /// Fails when `rev` does not name a commit.
    pub fn new(toplevel: &Path, rev: &str) -> Result<Self> {
        let out = Command::new("git")
            .arg("-C")
            .arg(toplevel)
            .args(["rev-parse", "--verify", "--quiet", "--end-of-options"])
            .arg(format!("{rev}^{{commit}}"))
            .output()
            .context("running git rev-parse")?;
        if !out.status.success() {
            bail!("`{rev}` does not name a commit");
        }
        let commit = String::from_utf8(out.stdout).context("git printed a non-UTF-8 commit id")?;
        Ok(Self {
            toplevel: toplevel.to_owned(),
            commit: commit.trim().to_owned(),
        })
    }

    /// The commit id every read is pinned to.
    pub fn commit(&self) -> &str {
        &self.commit
    }
}

impl Source for GitSource {
    /// One `cat-file --batch` call answers "missing" in its output and fails on any real error, so
    /// a git failure can never read as an absent file.
    fn read(&self, path: &Path) -> Result<Option<String>> {
        let rel = path.strip_prefix(&self.toplevel).with_context(|| {
            format!(
                "{} is outside the repository {}",
                path.display(),
                self.toplevel.display()
            )
        })?;
        let spec = format!("{}:{}", self.commit, rel.to_string_lossy().replace('\\', "/"));
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&self.toplevel)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("running git cat-file")?;
        child
            .stdin
            .take()
            .context("git cat-file has stdin")?
            .write_all(format!("{spec}\n").as_bytes())
            .with_context(|| format!("asking git for {spec}"))?;
        let out = child.wait_with_output().context("waiting for git cat-file")?;
        if !out.status.success() {
            bail!(
                "git cat-file {spec} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let reply = &out.stdout;
        let nl = reply
            .iter()
            .position(|&b| b == b'\n')
            .with_context(|| format!("git cat-file {spec} printed no reply"))?;
        let header = String::from_utf8_lossy(&reply[..nl]).into_owned();
        if header.ends_with(" missing") {
            return Ok(None);
        }
        let fields: Vec<&str> = header.split(' ').collect();
        let [_oid, kind, size] = fields[..] else {
            bail!("git cat-file {spec} printed an unexpected reply: {header}");
        };
        if kind != "blob" {
            return Ok(None);
        }
        let size: usize = size
            .parse()
            .with_context(|| format!("git cat-file {spec} printed a bad size"))?;
        let body = reply
            .get(nl + 1..nl + 1 + size)
            .with_context(|| format!("git cat-file {spec} printed a short blob"))?;
        Ok(Some(
            String::from_utf8(body.to_vec()).with_context(|| format!("{spec} is not UTF-8"))?,
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
    /// True directly in a root file, where the shared label include lives.
    root_top: bool,
}

/// Where a walk starts.
#[derive(Clone, Debug)]
pub struct Root {
    pub path: PathBuf,
    /// True for `lib.rs`, `main.rs`, `mod.rs` and every cargo target's file: their `mod x;` looks
    /// beside them. False for a module file such as `quote.rs`, whose children sit in `quote/`.
    pub mod_rs_like: bool,
    /// True for a crate root, where a flip adds `main` and the label include.
    pub is_root: bool,
}

impl Root {
    pub fn crate_root(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            mod_rs_like: true,
            is_root: true,
        }
    }
}

/// Every file reachable from `root` through `mod` declarations, root first, each once.
/// Modules are followed whatever their `cfg`: a file for another OS is still part of the tree.
pub fn walk(source: &dyn Source, root: &Path) -> Result<Vec<ParsedFile>> {
    walk_roots(source, &[Root::crate_root(root)])
}

/// [`walk`] from several roots at once. A file is parsed once, in the context that reaches it
/// first, so list the crate roots before the module files they own.
pub fn walk_roots(source: &dyn Source, roots: &[Root]) -> Result<Vec<ParsedFile>> {
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    for root in roots {
        let path = normalize(&root.path);
        visit_file(source, &path, root.mod_rs_like, root.is_root, &mut files, &mut seen)?;
        if root.is_root {
            if let Some(f) = files.iter_mut().find(|f| f.path == path) {
                f.is_root = true;
            }
        }
    }
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
        root_top: is_root,
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
fn conditional_paths(
    list: &syn::MetaList,
    name: &str,
    paths: &mut Vec<String>,
    string_of: &dyn Fn(&syn::MetaNameValue, &str) -> Result<String>,
) -> Result<()> {
    let args = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
    for arg in args.iter().skip(1) {
        match arg {
            Meta::NameValue(nv) if nv.path.is_ident("path") => paths.push(string_of(nv, name)?),
            Meta::List(inner) if inner.path.is_ident("cfg_attr") => conditional_paths(inner, name, paths, string_of)?,
            _ => {}
        }
    }
    Ok(())
}

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
                let before = paths.len();
                conditional_paths(list, &m.ident.to_string(), &mut paths, &string_of)?;
                conditional |= paths.len() > before;
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
        if ctx.root_top && crate::shapes::is_exact_include(m, file) {
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
                        root_top: false,
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
