//! `verify`: two revisions are equal after a canonical form that keeps each test's runtime.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use proc_macro2::{Group, TokenStream, TokenTree};
use quote::ToTokens;
use syn::visit_mut::VisitMut;
use syn::{Attribute, Item, ItemFn, ItemMacro, Meta};

use crate::attr;
use crate::modtree::{self, ParsedFile, Source, HARNESS_MOD};

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
            m.mac.tokens = canon_tokens(m.mac.tokens.clone());
        }
    }
}

fn is_cfg_inner(a: &Attribute) -> bool {
    matches!(a.style, syn::AttrStyle::Inner(_)) && a.path().is_ident("cfg")
}

fn is_main(i: &Item) -> bool {
    matches!(i, Item::Fn(f) if f.sig.ident == "main")
}

fn is_harness(i: &Item) -> bool {
    matches!(i, Item::Mod(m) if m.ident == HARNESS_MOD)
}

fn is_skuld_net(i: &Item) -> bool {
    matches!(i, Item::ExternCrate(e) if e.ident == "skuld")
}

/// Removes what a flip adds (`main`, the label include, the `extern crate skuld` net), unless the
/// old revision had it, and restores a hoisted crate-level `#![cfg]`.
fn undo_additions(new: &mut syn::File, old: &syn::File) {
    for (is, has) in [
        (is_main as fn(&Item) -> bool, old.items.iter().any(is_main)),
        (is_harness, old.items.iter().any(is_harness)),
        (is_skuld_net, old.items.iter().any(is_skuld_net)),
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
    if !new.items.iter().all(carries) {
        return;
    }
    // Every item carried the cfg, so strip it; the inner copy takes its place.
    let outer: Vec<Attribute> = cfgs.iter().map(|a| (*a).clone()).collect();
    for item in &mut new.items {
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

fn canonicalize(mut file: syn::File, old: Option<&syn::File>) -> syn::File {
    if let Some(old) = old {
        undo_additions(&mut file, old);
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
    let mut files = BTreeMap::new();
    for root in roots {
        for f in modtree::walk(source, root)? {
            files.entry(f.path.clone()).or_insert(f);
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
        let canon_old = canonicalize(o.ast.clone(), None);
        let canon_new = canonicalize(n.ast.clone(), Some(&o.ast));
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
