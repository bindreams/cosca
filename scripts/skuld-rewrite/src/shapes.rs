//! The exact items a flip adds to a root, and the macro-arm structure `macro_rules!` bodies share.

use std::path::{Path, PathBuf};

use proc_macro2::{Group, TokenStream, TokenTree};
use quote::ToTokens;
use syn::{Attribute, Item, ItemExternCrate, ItemFn, ItemMod, Meta};

use crate::modtree::{normalize, HARNESS_MOD};

fn is_cfg(a: &Attribute) -> bool {
    matches!(a.style, syn::AttrStyle::Outer) && a.path().is_ident("cfg")
}

fn squash(t: &impl ToTokens) -> String {
    t.to_token_stream().to_string().split_whitespace().collect()
}

/// `fn main()` whose body is the runner chain: `new`, `libtest_names`, an optional
/// `require_known_labels`, `run`. Only `cfg` attributes may decorate it.
pub fn is_exact_main(f: &ItemFn) -> bool {
    let sig = &f.sig;
    let plain = sig.ident == "main"
        && sig.inputs.is_empty()
        && matches!(sig.output, syn::ReturnType::Default)
        && sig.asyncness.is_none()
        && sig.constness.is_none()
        && sig.unsafety.is_none()
        && sig.abi.is_none()
        && sig.generics.params.is_empty()
        && sig.generics.where_clause.is_none()
        && matches!(f.vis, syn::Visibility::Inherited)
        && f.attrs.iter().all(is_cfg);
    if !plain {
        return false;
    }
    let body: Vec<String> = f
        .block
        .stmts
        .iter()
        .map(|s| squash(s).trim_end_matches(';').to_owned())
        .collect();
    let new = "letmutrunner=skuld::TestRunner::new()";
    let names = "runner.libtest_names()";
    let known = "runner.require_known_labels()";
    let run = "runner.run()";
    body == [new, names, run] || body == [new, names, known, run]
}

/// Where `mod test_harness;` declared directly in the root file `file` would be loaded from.
fn include_target(m: &ItemMod, file: &Path) -> Option<PathBuf> {
    let dir = file.parent()?;
    let mut path = None;
    for a in &m.attrs {
        if let Meta::NameValue(nv) = &a.meta {
            if nv.path.is_ident("path") {
                match &nv.value {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(s), ..
                    }) => path = Some(s.value()),
                    _ => return None,
                }
            }
        }
    }
    Some(normalize(
        &dir.join(path.unwrap_or_else(|| format!("{HARNESS_MOD}.rs"))),
    ))
}

/// The one file a root's include may load: `src/test_harness.rs` of the root's package, which is
/// the directory above the root file's own.
pub fn harness_file(root: &Path) -> Option<PathBuf> {
    Some(normalize(&root.parent()?.parent()?.join("src").join("test_harness.rs")))
}

/// `mod test_harness;` in the root file `file`, with only `cfg` and `path` attributes, that loads
/// exactly the package's `src/test_harness.rs`.
pub fn is_exact_include(m: &ItemMod, file: &Path) -> bool {
    m.ident == HARNESS_MOD
        && m.content.is_none()
        && m.attrs.iter().all(|a| is_cfg(a) || a.path().is_ident("path"))
        && include_target(m, file).is_some_and(|t| harness_file(file) == Some(t))
}

/// `extern crate skuld;`, optionally under `macro_use`, `allow` and `cfg`; never renamed.
pub fn is_exact_net(e: &ItemExternCrate) -> bool {
    e.ident == "skuld"
        && e.rename.is_none()
        && e.attrs.iter().all(|a| {
            matches!(a.style, syn::AttrStyle::Outer)
                && (a.path().is_ident("cfg") || a.path().is_ident("macro_use") || a.path().is_ident("allow"))
        })
}

/// The items `--hoist-crate-cfg` leaves alone and `verify` restores around.
pub fn is_hoist_exempt(item: &Item, file: &Path) -> bool {
    match item {
        Item::Fn(f) => f.sig.ident == "main",
        Item::Mod(m) => is_exact_include(m, file),
        _ => false,
    }
}

/// Indices of the transcriber groups of a `macro_rules!` body: the group after each `=>`. The
/// matcher side is never code, and is never rewritten.
pub fn transcriber_indices(trees: &[TokenTree]) -> Vec<usize> {
    (0..trees.len().saturating_sub(2))
        .filter(|&i| {
            matches!((&trees[i], &trees[i + 1]), (TokenTree::Punct(a), TokenTree::Punct(b)) if a.as_char() == '=' && b.as_char() == '>')
                && matches!(&trees[i + 2], TokenTree::Group(_))
        })
        .map(|i| i + 2)
        .collect()
}

/// `ts` with each transcriber group's stream replaced by `f` of it.
pub fn map_transcribers(ts: TokenStream, f: impl Fn(TokenStream) -> TokenStream) -> TokenStream {
    let mut trees: Vec<TokenTree> = ts.into_iter().collect();
    for i in transcriber_indices(&trees) {
        if let TokenTree::Group(g) = &trees[i] {
            let mut inner = Group::new(g.delimiter(), f(g.stream()));
            inner.set_span(g.span());
            trees[i] = TokenTree::Group(inner);
        }
    }
    trees.into_iter().collect()
}

/// The streams of a `macro_rules!` body's transcriber groups.
pub fn transcribers(ts: TokenStream) -> Vec<TokenStream> {
    let trees: Vec<TokenTree> = ts.into_iter().collect();
    transcriber_indices(&trees)
        .into_iter()
        .filter_map(|i| match &trees[i] {
            TokenTree::Group(g) => Some(g.stream()),
            _ => None,
        })
        .collect()
}
