//! `apply`: plans byte-range splices over a module tree and applies them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use proc_macro2::{LineColumn, TokenStream, TokenTree};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, Item, ItemFn, ItemMacro, Meta};

use crate::attr::{self, Origin, Runtime, TestAttr};
use crate::modtree::{self, ParsedFile, Source, HARNESS_MOD};

/// What `apply` may touch.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Rewrite only `tokio::test` spellings, leaving bare `#[test]` alone.
    pub only_tokio: bool,
    /// Move each root's `#![cfg(P)]` onto its top-level items.
    pub hoist_crate_cfg: bool,
}

impl Options {
    fn selects(&self, origin: Origin) -> bool {
        match origin {
            Origin::Skuld => false,
            Origin::Tokio => true,
            Origin::Test => !self.only_tokio,
        }
    }
}

/// Replaces `src[start..end]` with `text`; `start == end` inserts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edit {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

/// A site the tool will not guess about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub path: PathBuf,
    /// 1-based; 0 when the refusal is about the whole file.
    pub line: usize,
    pub reason: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line == 0 {
            write!(f, "{}: {}", self.path.display(), self.reason)
        } else {
            write!(f, "{}:{}: {}", self.path.display(), self.line, self.reason)
        }
    }
}

/// Maps `LineColumn` (1-based line, 0-based char column) to byte offsets.
struct LineIndex<'a> {
    src: &'a str,
    starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    fn new(src: &'a str) -> Self {
        let mut starts = vec![0];
        starts.extend(src.match_indices('\n').map(|(i, _)| i + 1));
        Self { src, starts }
    }

    fn offset(&self, lc: LineColumn) -> usize {
        let start = self.starts[lc.line - 1];
        let line = &self.src[start..];
        start + line.char_indices().nth(lc.column).map_or(line.len(), |(i, _)| i)
    }
}

fn replacement(attr: &TestAttr) -> String {
    match attr.runtime {
        Runtime::Paused => format!(
            "#[skuld::test(runtime = {})]",
            attr::PAUSED_RUNTIME.replace(" :: ", "::")
        ),
        _ => "#[skuld::test]".to_owned(),
    }
}

struct Planner<'a> {
    path: &'a Path,
    index: LineIndex<'a>,
    opts: Options,
    edits: Vec<Edit>,
    refusals: Vec<Refusal>,
}

impl Planner<'_> {
    fn refuse(&mut self, at: LineColumn, reason: String) {
        self.refusals.push(Refusal {
            path: self.path.to_owned(),
            line: at.line,
            reason,
        });
    }

    fn attribute(&mut self, a: &Attribute) {
        let selects = |o| self.opts.selects(o);
        if attr::cfg_attr_hides_test(&a.meta, selects) {
            self.refuse(
                a.pound_token.span.start(),
                format!("`{}` hides a test attribute", a.meta.to_token_stream()),
            );
            return;
        }
        match attr::classify(a) {
            Some(Ok(t)) if self.opts.selects(t.origin) => {
                let start = self.index.offset(a.pound_token.span.start());
                let end = self.index.offset(a.bracket_token.span.close().end());
                self.edits.push(Edit {
                    start,
                    end,
                    text: replacement(&t),
                });
            }
            Some(Err(why)) if self.opts.selects(attr::origin_of(a.meta.path()).expect("classified")) => {
                self.refuse(a.pound_token.span.start(), why.0);
            }
            _ => {}
        }
    }

    fn macro_tokens(&mut self, ts: TokenStream) {
        let trees: Vec<TokenTree> = ts.into_iter().collect();
        let mut i = 0;
        while i < trees.len() {
            if let (TokenTree::Punct(p), Some(TokenTree::Group(g))) = (&trees[i], trees.get(i + 1)) {
                if p.as_char() == '#' && g.delimiter() == proc_macro2::Delimiter::Bracket {
                    if let Ok(meta) = syn::parse2::<Meta>(g.stream()) {
                        self.macro_attr(p.span().start(), g.span().end(), &meta);
                    }
                    i += 2;
                    continue;
                }
            }
            if let TokenTree::Group(g) = &trees[i] {
                self.macro_tokens(g.stream());
            }
            i += 1;
        }
    }

    fn macro_attr(&mut self, at: LineColumn, end: LineColumn, meta: &Meta) {
        if attr::cfg_attr_hides_test(meta, |o| self.opts.selects(o)) {
            self.refuse(at, format!("`{}` hides a test attribute", meta.to_token_stream()));
            return;
        }
        match attr::classify_meta(meta) {
            Some(Ok(t)) if self.opts.selects(t.origin) => {
                let (start, end) = (self.index.offset(at), self.index.offset(end));
                self.edits.push(Edit {
                    start,
                    end,
                    text: replacement(&t),
                });
            }
            Some(Err(why)) if self.opts.selects(attr::origin_of(meta.path()).expect("classified")) => {
                self.refuse(at, why.0);
            }
            _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for Planner<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        for a in &f.attrs {
            self.attribute(a);
        }
        syn::visit::visit_item_fn(self, f);
    }

    fn visit_item_macro(&mut self, m: &'ast ItemMacro) {
        if m.mac.path.is_ident("macro_rules") {
            self.macro_tokens(m.mac.tokens.clone());
        }
    }
}

fn is_cfg_inner(a: &Attribute) -> bool {
    matches!(a.style, syn::AttrStyle::Inner(_)) && a.path().is_ident("cfg")
}

/// An item `--hoist-crate-cfg` leaves alone: the added `main` and the shared label include.
pub fn is_hoist_exempt(item: &Item) -> bool {
    match item {
        Item::Fn(f) => f.sig.ident == "main",
        Item::Mod(m) => m.ident == HARNESS_MOD,
        _ => false,
    }
}

fn hoist(p: &mut Planner<'_>, file: &syn::File) {
    let cfgs: Vec<&Attribute> = file.attrs.iter().filter(|a| is_cfg_inner(a)).collect();
    if cfgs.is_empty() {
        return;
    }
    let mut outer = String::new();
    for a in &cfgs {
        let open = p.index.offset(a.bracket_token.span.open().start());
        let close = p.index.offset(a.bracket_token.span.close().end());
        outer.push('#');
        outer.push_str(&p.index.src[open..close]);
        outer.push('\n');
        // Delete the whole line the inner attribute sat on, when it had it to itself.
        let start = p.index.offset(a.pound_token.span.start());
        let mut end = close;
        let rest = &p.index.src[end..];
        let trimmed = rest.trim_start_matches([' ', '\t']);
        if let Some(after) = trimmed.strip_prefix("\r\n").or_else(|| trimmed.strip_prefix('\n')) {
            end = p.index.src.len() - after.len();
        }
        p.edits.push(Edit {
            start,
            end,
            text: String::new(),
        });
    }
    for item in file.items.iter().filter(|i| !is_hoist_exempt(i)) {
        if let Item::Verbatim(_) = item {
            p.refuse(
                item.span().start(),
                "cannot hoist a crate-level cfg onto an unparsed item".to_owned(),
            );
            continue;
        }
        let first = item.to_token_stream().into_iter().next().expect("an item has tokens");
        let at = p.index.offset(first.span().start());
        p.edits.push(Edit {
            start: at,
            end: at,
            text: outer.clone(),
        });
    }
}

/// The edits and refusals for one parsed file.
pub fn plan_file(file: &ParsedFile, opts: Options) -> (Vec<Edit>, Vec<Refusal>) {
    let mut p = Planner {
        path: &file.path,
        index: LineIndex::new(&file.src),
        opts,
        edits: Vec::new(),
        refusals: Vec::new(),
    };
    p.visit_file(&file.ast);
    if opts.hoist_crate_cfg && file.is_root {
        hoist(&mut p, &file.ast);
    }
    (p.edits, p.refusals)
}

/// Applies non-overlapping edits.
pub fn splice(src: &str, edits: &[Edit]) -> Result<String> {
    let mut sorted: Vec<&Edit> = edits.iter().collect();
    sorted.sort_by_key(|e| (e.start, e.end));
    let mut out = String::with_capacity(src.len());
    let mut cursor = 0;
    for e in sorted {
        if e.start < cursor {
            bail!("overlapping edits at byte {}", e.start);
        }
        out.push_str(&src[cursor..e.start]);
        out.push_str(&e.text);
        cursor = e.end;
    }
    out.push_str(&src[cursor..]);
    Ok(out)
}

/// The result of `apply`.
#[derive(Debug)]
pub enum Outcome {
    /// Nothing was written; every site that stopped the run.
    Refused(Vec<Refusal>),
    /// The files that change, with their new text.
    Rewritten(Vec<(PathBuf, String)>),
}

/// Plans a rewrite of every file reachable from `roots`, refusing a file that changes and is
/// also reachable from one of `unflipped`.
pub fn apply(source: &dyn Source, roots: &[PathBuf], unflipped: &[PathBuf], opts: Options) -> Result<Outcome> {
    let mut files: BTreeMap<PathBuf, ParsedFile> = BTreeMap::new();
    for root in roots {
        for f in modtree::walk(source, root)? {
            match files.get_mut(&f.path) {
                Some(existing) => existing.is_root |= f.is_root,
                None => {
                    files.insert(f.path.clone(), f);
                }
            }
        }
    }
    let applied_roots: BTreeSet<PathBuf> = roots.iter().map(|r| modtree::normalize(r)).collect();
    let mut reach: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();
    for u in unflipped {
        let u = modtree::normalize(u);
        if applied_roots.contains(&u) {
            continue;
        }
        for f in modtree::walk(source, &u)? {
            reach.entry(f.path).or_insert_with(|| u.clone());
        }
    }

    let mut refusals = Vec::new();
    let mut rewritten = Vec::new();
    for (path, file) in &files {
        let (edits, mut refused) = plan_file(file, opts);
        refusals.append(&mut refused);
        if edits.is_empty() {
            continue;
        }
        if let Some(root) = reach.get(path) {
            refusals.push(Refusal {
                path: path.clone(),
                line: 0,
                reason: format!(
                    "would change, but is also reachable from the unflipped root {}",
                    root.display()
                ),
            });
        }
        rewritten.push((path.clone(), splice(&file.src, &edits)?));
    }
    if refusals.is_empty() {
        Ok(Outcome::Rewritten(rewritten))
    } else {
        Ok(Outcome::Refused(refusals))
    }
}
