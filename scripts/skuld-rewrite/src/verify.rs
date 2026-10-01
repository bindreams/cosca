//! `verify`: two revisions are equal after a canonical form that keeps each test's runtime.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use proc_macro2::{Group, TokenStream, TokenTree};
use quote::ToTokens;
use syn::visit_mut::VisitMut;
use syn::{Attribute, Item, ItemFn, ItemMacro, Meta};

use crate::attr;
use crate::modtree::{self, GitSource, ParsedFile, Source};
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

fn canon_tokens(ts: TokenStream) -> TokenStream {
    let trees: Vec<TokenTree> = ts.into_iter().collect();
    let mut out = TokenStream::new();
    let mut i = 0;
    while i < trees.len() {
        if let (TokenTree::Punct(p), Some(TokenTree::Group(g))) = (&trees[i], trees.get(i + 1)) {
            if p.as_char() == '#' && g.delimiter() == proc_macro2::Delimiter::Bracket {
                if let Some(meta) = syn::parse2::<Meta>(g.stream()).ok().as_ref().and_then(canonical_meta) {
                    let mut canon = Group::new(proc_macro2::Delimiter::Bracket, meta.to_token_stream());
                    canon.set_span(g.span());
                    out.extend([trees[i].clone(), TokenTree::Group(canon)]);
                    i += 2;
                    continue;
                }
            }
        }
        match &trees[i] {
            TokenTree::Group(g) => {
                let mut inner = Group::new(g.delimiter(), canon_tokens(g.stream()));
                inner.set_span(g.span());
                out.extend([TokenTree::Group(inner)]);
            }
            other => out.extend([other.clone()]),
        }
        i += 1;
    }
    out
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

fn is_cfg_inner(a: &Attribute) -> bool {
    matches!(a.style, syn::AttrStyle::Inner(_)) && a.path().is_ident("cfg")
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
fn undo_additions(new: &mut syn::File, old: &syn::File, file: &Path) {
    for (is, has) in [
        (
            &is_exact_main as &dyn Fn(&Item) -> bool,
            old.items.iter().any(is_exact_main),
        ),
        (
            &|i| is_exact_include(i, file),
            old.items.iter().any(|i| is_exact_include(i, file)),
        ),
        (&is_exact_net, old.items.iter().any(is_exact_net)),
    ] {
        if !has {
            new.items.retain(|i| !is(i));
        }
    }
    let cfgs: Vec<&Attribute> = old.attrs.iter().filter(|a| is_cfg_inner(a)).collect();
    if cfgs.is_empty() || new.attrs.iter().any(is_cfg_inner) || new.items.is_empty() {
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
    let (cfgs, mut rest): (Vec<_>, Vec<_>) = file.attrs.drain(..).partition(is_cfg_inner);
    rest.extend(cfgs);
    file.attrs = rest;
}

fn canonicalize(mut file: syn::File, old: Option<&syn::File>, root_path: Option<&Path>) -> syn::File {
    if let (Some(old), Some(path)) = (old, root_path) {
        undo_additions(&mut file, old, path);
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

fn collect(source: &dyn Source, roots: &[PathBuf]) -> Result<BTreeMap<PathBuf, ParsedFile>> {
    let mut files: BTreeMap<PathBuf, ParsedFile> = BTreeMap::new();
    for root in roots {
        for f in modtree::walk(source, root)? {
            match files.entry(f.path.clone()) {
                std::collections::btree_map::Entry::Occupied(mut e) => e.get_mut().is_root |= f.is_root,
                std::collections::btree_map::Entry::Vacant(e) => {
                    e.insert(f);
                }
            }
        }
    }
    Ok(files)
}

/// Compares every file reachable from `roots` in `old` and `new`.
pub fn verify(old: &dyn Source, new: &dyn Source, roots: &[PathBuf]) -> Result<Vec<Mismatch>> {
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
        let canon_old = canonicalize(o.ast.clone(), None, None);
        let canon_new = canonicalize(n.ast.clone(), Some(&o.ast), n.is_root.then_some(path.as_path()));
        if let Some(detail) = diff(&canon_old, &canon_new) {
            out.push(Mismatch {
                path: path.clone(),
                detail,
            });
        }
    }
    Ok(out)
}

/// Used by tests and the CLI to name a path the way `verify` keys it.
pub fn key(path: &Path) -> PathBuf {
    modtree::normalize(path)
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
            src: t.src_path.strip_prefix(&listing.workspace_root)?.to_owned(),
            test: t.test,
            doctest: t.doctest,
            required_features: t.required_features.clone(),
            bench: t.bench,
            harness: t.harness,
        });
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// What differs between two target sets. A target deleted, added, repointed, disabled or gated is
/// a change that file comparison never sees. A harness may be switched off (the planned flip) and
/// never back on.
pub fn target_mismatches(old: &[TargetKey], new: &[TargetKey]) -> Vec<Mismatch> {
    let describe = |k: &TargetKey, what: &str| Mismatch {
        path: k.src.clone(),
        detail: format!("target `{}` ({}) {what}", k.name, k.kinds.join(", ")),
    };
    let mut out = Vec::new();
    for k in old {
        match new.iter().find(|n| n.identity() == k.identity()) {
            None => out.push(describe(k, "differs or is missing in the new revision")),
            Some(n) if n.harness && !k.harness => {
                out.push(describe(k, "had `harness = false` and now has the default harness"))
            }
            Some(_) => {}
        }
    }
    out.extend(
        new.iter()
            .filter(|k| !old.iter().any(|o| o.identity() == k.identity()))
            .map(|k| describe(k, "differs or is missing in the old revision")),
    );
    out
}

/// Compares the target sets of `rev` and the working tree, then every file reachable from each
/// target both have.
pub fn verify_targets(manifest: Option<&Path>, rev: &str) -> Result<Vec<Mismatch>> {
    let new = targets::load(manifest)?;
    let toplevel = targets::toplevel(&new.workspace_root)?;
    let git = GitSource::new(&toplevel, rev)?;

    let scratch = tempfile::tempdir().context("creating a scratch directory for the old revision")?;
    let old_root = std::fs::canonicalize(scratch.path())?;
    let mut archive = std::process::Command::new("git")
        .arg("-C")
        .arg(&toplevel)
        .args(["archive", "--format=tar", "--end-of-options", rev])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("running git archive")?;
    tar::Archive::new(archive.stdout.take().context("git archive has stdout")?).unpack(&old_root)?;
    anyhow::ensure!(archive.wait()?.success(), "git archive {rev} failed");
    let old_manifest = old_root
        .join(new.workspace_root.strip_prefix(&toplevel)?)
        .join("Cargo.toml");
    let old = targets::load(Some(&old_manifest))?;

    let (old_keys, new_keys) = (keys(&old)?, keys(&new)?);
    let mut out = target_mismatches(&old_keys, &new_keys);
    let roots: Vec<PathBuf> = new_keys
        .iter()
        .filter(|k| old_keys.contains(k))
        .map(|k| new.workspace_root.join(&k.src))
        .collect();
    out.extend(verify(&git, &modtree::FsSource, &roots)?);
    Ok(out)
}
