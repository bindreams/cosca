//! `verify`: two revisions are equal after a canonical form that keeps each test's runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::visit_mut::VisitMut;
use syn::{Attribute, Item, ItemFn, ItemMacro, Meta};

use crate::attr;
use crate::modtree::{self, GitSource, ParsedFile, Root, Source};
use crate::shapes;
use crate::targets;

/// A file whose two revisions differ after canonicalisation.
#[derive(Debug, PartialEq, Eq)]
pub struct Mismatch {
    pub path: PathBuf,
    pub detail: String,
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.detail)
    }
}

fn canonical_meta(meta: &Meta) -> Option<Meta> {
    match attr::classify_meta(meta)? {
        Ok(t) => Some(attr::canonical(&t).meta),
        Err(_) => Some(attr::canonical_unsupported(meta).meta),
    }
}

/// An attribute inside a macro body in canonical form. One that does not parse is compared as
/// written, so any change to it still shows.
fn canon_tokens(ts: TokenStream) -> TokenStream {
    attr::map_sites(ts, &mut |site| {
        site.meta.as_ref().and_then(canonical_meta).map(|m| m.to_token_stream())
    })
}

struct Canon;

impl VisitMut for Canon {
    fn visit_item_fn_mut(&mut self, f: &mut ItemFn) {
        for a in &mut f.attrs {
            if matches!(a.style, syn::AttrStyle::Outer) {
                if let Some(meta) = canonical_meta(&a.meta) {
                    *a = Attribute { meta, ..a.clone() };
                }
            }
        }
        syn::visit_mut::visit_item_fn_mut(self, f);
    }

    fn visit_item_macro_mut(&mut self, m: &mut ItemMacro) {
        if m.mac.path.is_ident("macro_rules") {
            m.mac.tokens = shapes::map_transcribers(m.mac.tokens.clone(), canon_tokens);
        }
    }
}

fn is_exact_main(i: &Item) -> bool {
    matches!(i, Item::Fn(f) if shapes::is_exact_main(f))
}

fn is_exact_include(i: &Item, file: &Path) -> bool {
    matches!(i, Item::Mod(m) if shapes::is_exact_include(m, file))
}

fn is_exact_net(i: &Item) -> bool {
    matches!(i, Item::ExternCrate(e) if shapes::is_exact_net(e))
}

/// In a root, removes what a flip adds (`main`, the label include, the `extern crate skuld` net)
/// in exactly the shapes the units add, unless the old revision had it; then restores a hoisted
/// crate-level `#![cfg]`. Other files are compared as they are.
fn undo_additions(new: &mut syn::File, old: &syn::File, file: &Path, allow_include: bool) {
    for (is, has) in [
        (
            &is_exact_main as &dyn Fn(&Item) -> bool,
            old.items.iter().any(is_exact_main),
        ),
        (
            &|i| is_exact_include(i, file),
            !allow_include || old.items.iter().any(|i| is_exact_include(i, file)),
        ),
        (&is_exact_net, old.items.iter().any(is_exact_net)),
    ] {
        if !has {
            new.items.retain(|i| !is(i));
        }
    }
    let cfgs: Vec<&Attribute> = old.attrs.iter().filter(|a| shapes::is_cfg_inner(a)).collect();
    if cfgs.is_empty() || new.attrs.iter().any(shapes::is_cfg_inner) || new.items.is_empty() {
        return;
    }
    let carries = |i: &Item| {
        item_attrs(i).is_some_and(|a| {
            a.len() >= cfgs.len()
                && a.iter()
                    .zip(&cfgs)
                    .all(|(x, y)| matches!(x.style, syn::AttrStyle::Outer) && x.meta == y.meta)
        })
    };
    // `apply` leaves `main` and the include unhoisted, so they neither carry nor lose the cfg.
    if !new
        .items
        .iter()
        .filter(|i| !shapes::is_hoist_exempt(i, file))
        .all(carries)
    {
        return;
    }
    let outer: Vec<Attribute> = cfgs.iter().map(|a| (*a).clone()).collect();
    for item in new.items.iter_mut().filter(|i| !shapes::is_hoist_exempt(i, file)) {
        if let Some(attrs) = item_attrs_mut(item) {
            attrs.drain(..outer.len());
        }
    }
    new.attrs.extend(outer);
}

macro_rules! attrs_of {
    ($item:expr, $($v:ident),* $(,)?) => {
        match $item { $(Item::$v(x) => Some(&mut x.attrs),)* _ => None }
    };
}

fn item_attrs_mut(item: &mut Item) -> Option<&mut Vec<Attribute>> {
    attrs_of!(
        item,
        Const,
        Enum,
        ExternCrate,
        Fn,
        ForeignMod,
        Impl,
        Macro,
        Mod,
        Static,
        Struct,
        Trait,
        TraitAlias,
        Type,
        Union,
        Use
    )
}

fn item_attrs(item: &Item) -> Option<Vec<Attribute>> {
    item_attrs_mut(&mut item.clone()).map(|a| a.clone())
}

/// Crate-level `cfg` attributes go last, so their position among other inner attributes is not
/// part of the comparison.
fn order_inner_cfgs(file: &mut syn::File) {
    let (cfgs, mut rest): (Vec<_>, Vec<_>) = file.attrs.drain(..).partition(shapes::is_cfg_inner);
    rest.extend(cfgs);
    file.attrs = rest;
}

fn canonicalize(
    mut file: syn::File,
    old: Option<&syn::File>,
    root_path: Option<&Path>,
    allow_include: bool,
) -> syn::File {
    if let (Some(old), Some(path)) = (old, root_path) {
        undo_additions(&mut file, old, path, allow_include);
    }
    Canon.visit_file_mut(&mut file);
    order_inner_cfgs(&mut file);
    file
}

fn describe(item: Option<&Item>) -> String {
    item.map_or_else(|| "<absent>".to_owned(), |i| i.to_token_stream().to_string())
}

fn diff(old: &syn::File, new: &syn::File) -> Option<String> {
    if old.attrs != new.attrs {
        return Some(format!(
            "crate attributes differ:\n  old: {}\n  new: {}",
            old.attrs
                .iter()
                .map(|a| a.to_token_stream().to_string())
                .collect::<Vec<_>>()
                .join(" "),
            new.attrs
                .iter()
                .map(|a| a.to_token_stream().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }
    let n = old.items.len().max(new.items.len());
    (0..n).find(|&i| old.items.get(i) != new.items.get(i)).map(|i| {
        format!(
            "item {i} differs:\n  old: {}\n  new: {}",
            describe(old.items.get(i)),
            describe(new.items.get(i))
        )
    })
}

fn collect(source: &dyn Source, roots: &[Root]) -> Result<BTreeMap<PathBuf, ParsedFile>> {
    Ok(modtree::walk_roots(source, roots)?
        .into_iter()
        .map(|f| (f.path.clone(), f))
        .collect())
}

/// [`verify_roots`] over crate roots that may all gain the label include.
pub fn verify(old: &dyn Source, new: &dyn Source, roots: &[PathBuf]) -> Result<Vec<Mismatch>> {
    let flipped: BTreeSet<PathBuf> = roots.iter().map(|r| modtree::normalize(r)).collect();
    let roots: Vec<Root> = roots.iter().map(Root::crate_root).collect();
    verify_roots(old, new, &roots, &flipped)
}

/// Compares every file reachable from `roots` in `old` and `new`. Only a root in `flipped` may
/// gain the label include.
pub fn verify_roots(
    old: &dyn Source,
    new: &dyn Source,
    roots: &[Root],
    flipped: &BTreeSet<PathBuf>,
) -> Result<Vec<Mismatch>> {
    let old_files = collect(old, roots)?;
    let new_files = collect(new, roots)?;
    let mut out = Vec::new();
    for path in old_files.keys().filter(|p| !new_files.contains_key(*p)) {
        out.push(Mismatch {
            path: path.clone(),
            detail: "reachable in the old revision only".to_owned(),
        });
    }
    for (path, n) in &new_files {
        let Some(o) = old_files.get(path) else {
            out.push(Mismatch {
                path: path.clone(),
                detail: "reachable in the new revision only".to_owned(),
            });
            continue;
        };
        let canon_old = canonicalize(o.ast.clone(), None, None, false);
        let canon_new = canonicalize(
            n.ast.clone(),
            Some(&o.ast),
            n.is_root.then_some(path.as_path()),
            flipped.contains(path),
        );
        if let Some(detail) = diff(&canon_old, &canon_new) {
            out.push(Mismatch {
                path: path.clone(),
                detail,
            });
        }
        if n.is_root && flipped.contains(path) {
            out.extend(check_harness(old, new, o, n, path)?);
        }
    }
    Ok(out)
}

/// The label file a root's include loads. When the old revision had the include, the file is
/// compared with its old self; when the include is new, the file may hold only label
/// declarations, so a flip cannot smuggle code or tests in through it.
fn check_harness(
    old: &dyn Source,
    new: &dyn Source,
    o: &ParsedFile,
    n: &ParsedFile,
    root: &Path,
) -> Result<Option<Mismatch>> {
    let new_has = n.ast.items.iter().any(|i| is_exact_include(i, root));
    let (Some(file), true) = (shapes::harness_file(root), new_has) else {
        return Ok(None);
    };
    let fail = |detail: String| {
        Ok(Some(Mismatch {
            path: file.clone(),
            detail,
        }))
    };
    let Some(text) = new.read(&file)? else {
        return fail("the include names a file that does not exist".to_owned());
    };
    let ast = match syn::parse_file(&text) {
        Ok(a) => a,
        Err(e) => return fail(format!("cannot parse the label file: {e}")),
    };
    let old_has = o.ast.items.iter().any(|i| is_exact_include(i, root));
    if let (true, Some(old_text)) = (old_has, old.read(&file)?) {
        let old_ast =
            syn::parse_file(&old_text).with_context(|| format!("parsing {} in the old revision", file.display()))?;
        let detail = diff(
            &canonicalize(old_ast, None, None, false),
            &canonicalize(ast, None, None, false),
        );
        return Ok(detail.map(|detail| Mismatch {
            path: file.clone(),
            detail,
        }));
    }
    match ast.items.iter().find_map(shapes::label_file_violation) {
        Some(item) => fail(format!("unexpected item in the label file:\n  {item}")),
        None => Ok(None),
    }
}

/// A target as `verify` identifies it. Where it lives is relative to its own revision's root.
/// Everything libtest can see of it is here: whether it runs, what gates it, and its harness.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetKey {
    pub name: String,
    pub kinds: Vec<String>,
    pub src: PathBuf,
    pub test: bool,
    pub doctest: bool,
    pub required_features: Vec<String>,
    pub bench: Option<bool>,
    pub edition: String,
    pub harness: bool,
}

impl TargetKey {
    /// The key without `harness`, which is allowed to change in one direction.
    fn identity(&self) -> TargetKey {
        TargetKey {
            harness: true,
            ..self.clone()
        }
    }
}

fn keys(listing: &targets::Listing) -> Result<Vec<TargetKey>> {
    let mut out = Vec::new();
    for t in &listing.targets {
        out.push(TargetKey {
            name: t.name.clone(),
            kinds: t.kinds.clone(),
            src: t
                .src_path
                .strip_prefix(&listing.workspace_root)
                .with_context(|| {
                    format!(
                        "target {} at {} is outside the workspace {}",
                        t.name,
                        t.src_path.display(),
                        listing.workspace_root.display()
                    )
                })?
                .to_owned(),
            test: t.test,
            doctest: t.doctest,
            required_features: t.required_features.clone(),
            bench: t.bench,
            edition: t.edition.clone(),
            harness: t.harness,
        });
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn differing_fields(a: &TargetKey, b: &TargetKey) -> Vec<&'static str> {
    [
        ("kinds", a.kinds != b.kinds),
        ("src", a.src != b.src),
        ("test", a.test != b.test),
        ("doctest", a.doctest != b.doctest),
        ("required_features", a.required_features != b.required_features),
        ("bench", a.bench != b.bench),
        ("edition", a.edition != b.edition),
    ]
    .into_iter()
    .filter_map(|(name, differs)| differs.then_some(name))
    .collect()
}

/// What differs between two target sets. A target deleted, added, repointed, disabled, gated or
/// moved to another edition is a change that file comparison never sees. A harness may be
/// switched off (the planned flip) and never back on.
pub fn target_mismatches(old: &[TargetKey], new: &[TargetKey]) -> Vec<Mismatch> {
    let describe = |k: &TargetKey, what: &str| Mismatch {
        path: k.src.clone(),
        detail: format!("target `{}` ({}) {what}", k.name, k.kinds.join(", ")),
    };
    let mut out = Vec::new();
    let mut matched = vec![false; new.len()];
    for k in old {
        let same = new.iter().position(|n| n.identity() == k.identity());
        let named = || {
            new.iter()
                .enumerate()
                .position(|(i, n)| !matched[i] && n.name == k.name)
        };
        match same.or_else(named) {
            Some(i) => {
                matched[i] = true;
                let n = &new[i];
                let fields = differing_fields(k, n);
                if !fields.is_empty() {
                    out.push(describe(k, &format!("differs in {}", fields.join(", "))));
                } else if n.harness && !k.harness {
                    out.push(describe(k, "had `harness = false` and now has the default harness"));
                }
            }
            None => out.push(describe(k, "is missing in the new revision")),
        }
    }
    out.extend(
        new.iter()
            .zip(&matched)
            .filter(|(_, m)| !**m)
            .map(|(k, _)| describe(k, "is missing in the old revision")),
    );
    out
}

/// Package name to feature table.
pub type Features = BTreeMap<String, BTreeMap<String, Vec<String>>>;

/// What differs between the feature tables of two revisions, per package. Features decide which
/// `#![cfg(feature = ..)]` test files compile.
pub fn feature_mismatches(old: &Features, new: &Features) -> Vec<Mismatch> {
    let packages: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    packages
        .into_iter()
        .filter(|p| old.get(*p) != new.get(*p))
        .map(|p| Mismatch {
            path: "Cargo.toml".into(),
            detail: format!("features of package `{p}` differ"),
        })
        .collect()
}

/// Unpacks the tree of `commit` into `dest`. Git writes the archive to a file and is waited for
/// before anything is read, so its failure is reported as its own and never as a tar error.
pub fn extract_archive(toplevel: &Path, commit: &str, dest: &Path) -> Result<()> {
    let scratch = tempfile::tempdir().context("creating a scratch directory for the archive")?;
    let tarball = scratch.path().join("old.tar");
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(toplevel)
        .args(["archive", "--format=tar", "-o"])
        .arg(&tarball)
        .args(["--end-of-options", commit])
        .output()
        .context("running git archive")?;
    anyhow::ensure!(
        out.status.success(),
        "git archive {commit} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let file = std::fs::File::open(&tarball).context("opening the archive git wrote")?;
    tar::Archive::new(file).unpack(dest).context("unpacking the archive")
}

/// Compares the target sets of `rev` and the working tree, then every file reachable from each
/// target both have.
pub fn verify_targets(manifest: Option<&Path>, rev: &str, roots: &[Root]) -> Result<Vec<Mismatch>> {
    let new = targets::load(manifest)?;
    let toplevel = targets::toplevel(&new.workspace_root)?;
    let git = GitSource::new(&toplevel, rev)?;

    let scratch = tempfile::tempdir().context("creating a scratch directory for the old revision")?;
    let old_root = std::fs::canonicalize(scratch.path())?;
    extract_archive(&toplevel, git.commit(), &old_root)?;
    let old_manifest = old_root
        .join(new.workspace_root.strip_prefix(&toplevel)?)
        .join("Cargo.toml");
    let old = targets::load(Some(&old_manifest))?;

    let (old_keys, new_keys) = (keys(&old)?, keys(&new)?);
    let mut out = target_mismatches(&old_keys, &new_keys);
    out.extend(feature_mismatches(&old.features, &new.features));
    let at = |k: &TargetKey| new.workspace_root.join(&k.src);
    let target_roots: Vec<Root> = new_keys
        .iter()
        .filter(|k| old_keys.iter().any(|o| o.identity() == k.identity()))
        .map(|k| Root::crate_root(at(k)))
        .collect();
    // Only a target whose harness is off may gain the label include.
    let flipped: BTreeSet<PathBuf> = new_keys.iter().filter(|k| !k.harness).map(at).collect();
    let roots = if roots.is_empty() { target_roots } else { roots.to_vec() };
    out.extend(verify_roots(&git, &modtree::FsSource, &roots, &flipped)?);
    Ok(out)
}
