//! `apply`: plans byte-range splices over a module tree and applies them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use proc_macro2::{LineColumn, TokenStream};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, Item, ItemFn, ItemMacro, Meta};

use crate::attr::{self, Hidden, Origin, Runtime, TestAttr};
use crate::modtree::{self, ParsedFile, Root, Source};
use crate::shapes;

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
        // `syn` parses the text after a BOM, so its columns on line 1 start after those 3 bytes.
        let mut starts = vec![if src.starts_with('\u{feff}') {
            '\u{feff}'.len_utf8()
        } else {
            0
        }];
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

/// What to do with one attribute-shaped site.
enum Verdict {
    Rewrite(TestAttr),
    Refuse(String),
    Leave,
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

    fn judge(&self, meta: &Meta) -> Verdict {
        let hides = attr::hidden_tests(meta)
            .into_iter()
            .any(|h| matches!(h, Hidden::Unknown) || matches!(h, Hidden::Known(o) if self.opts.selects(o)));
        if hides {
            return Verdict::Refuse(format!("`{}` hides a test attribute", meta.to_token_stream()));
        }
        match attr::classify_meta(meta) {
            Some(Ok(t)) if self.opts.selects(t.origin) => Verdict::Rewrite(t),
            Some(Err(why)) if self.opts.selects(attr::origin_of(meta.path()).expect("classified")) => {
                Verdict::Refuse(why.0)
            }
            Some(_) => Verdict::Leave,
            None if attr::is_unmapped_test(meta) => Verdict::Refuse(format!(
                "`#[{}]` is a test attribute this tool does not map",
                meta.to_token_stream()
            )),
            None => Verdict::Leave,
        }
    }

    /// Replaces `at..end` with the skuld spelling, unless a comment would be lost.
    fn rewrite(&mut self, at: LineColumn, end: LineColumn, t: &TestAttr) {
        let (start, end) = (self.index.offset(at), self.index.offset(end));
        let old = &self.index.src[start..end];
        if old.contains("//") || old.contains("/*") {
            self.refuse(at, format!("a comment inside `{old}` would be lost"));
            return;
        }
        self.edits.push(Edit {
            start,
            end,
            text: replacement(t),
        });
    }

    fn attribute(&mut self, a: &Attribute) {
        if !matches!(a.style, syn::AttrStyle::Outer) {
            return;
        }
        let at = a.pound_token.span.start();
        match self.judge(&a.meta) {
            Verdict::Rewrite(t) => self.rewrite(at, a.bracket_token.span.close().end(), &t),
            Verdict::Refuse(why) => self.refuse(at, why),
            Verdict::Leave => {}
        }
    }

    /// Scans a token stream for `#[..]` sites. `in_macro` is `Some(name)` for an invocation's
    /// arguments, where the expansion decides what an attribute means, so a test there is refused.
    fn tokens(&mut self, ts: TokenStream, in_macro: Option<&str>) {
        let mut visit = |site: &attr::Site<'_>| {
            let (at, end) = (site.pound.span().start(), site.group.span().end());
            match &site.meta {
                Some(meta) => match (self.judge(meta), in_macro) {
                    (Verdict::Rewrite(t), None) => self.rewrite(at, end, &t),
                    (Verdict::Rewrite(_), Some(name)) => {
                        self.refuse(at, format!("a test attribute inside `{name}!` cannot be mapped"));
                    }
                    (Verdict::Refuse(why), _) => self.refuse(at, why),
                    (Verdict::Leave, _) => {}
                },
                None if site.mentions_test => self.refuse(
                    at,
                    format!(
                        "`#[{}]` is not an attribute this tool can read, and it mentions `test`",
                        site.group.stream()
                    ),
                ),
                None => {}
            }
            None
        };
        attr::map_sites(ts, &mut visit);
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
            for body in shapes::transcribers(m.mac.tokens.clone()) {
                self.tokens(body, None);
            }
        } else {
            syn::visit::visit_item_macro(self, m);
        }
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let name = m.path.segments.last().map_or_else(String::new, |s| s.ident.to_string());
        self.tokens(m.tokens.clone(), Some(&name));
    }
}

fn blank_before(before: &str) -> bool {
    let Some(rest) = before.strip_suffix('\n') else {
        return before.is_empty();
    };
    rest.rsplit('\n').next().is_some_and(|l| l.trim().is_empty())
}

/// The length of a whole blank line at the start of `rest`, newline included.
fn blank_line_len(rest: &str) -> Option<usize> {
    let nl = rest.find('\n')?;
    rest[..nl].trim().is_empty().then_some(nl + 1)
}

fn hoist(p: &mut Planner<'_>, file: &syn::File) {
    let cfgs: Vec<&Attribute> = file.attrs.iter().filter(|a| shapes::is_cfg_inner(a)).collect();
    if cfgs.is_empty() {
        return;
    }
    let mut outer = String::new();
    let (mut last_end, mut carried_blank) = (None, false);
    for a in &cfgs {
        let open = p.index.offset(a.bracket_token.span.open().start());
        let close = p.index.offset(a.bracket_token.span.close().end());
        outer.push('#');
        outer.push_str(&p.index.src[open..close]);
        outer.push('\n');
        let start = p.index.offset(a.pound_token.span.start());
        let src = p.index.src;
        let bof = p.index.starts[0];
        let line_start = src[..start].rfind('\n').map_or(bof, |i| i + 1).max(bof);
        let whole_line = src[line_start..start].trim().is_empty();
        let mut end = close;
        let trimmed = src[end..].trim_start_matches([' ', '\t']);
        let ends_line = if let Some(after) = trimmed.strip_prefix("\r\n").or_else(|| trimmed.strip_prefix('\n')) {
            end = src.len() - after.len();
            true
        } else {
            false
        };
        let mut from = start;
        if whole_line && ends_line {
            from = line_start;
            // Deleting the line must not leave a blank line at the top, or two in a row.
            let before_blank = if last_end == Some(line_start) {
                carried_blank
            } else {
                blank_before(&src[bof..line_start])
            };
            if before_blank {
                end += blank_line_len(&src[end..]).unwrap_or(0);
            }
            carried_blank = before_blank;
        }
        last_end = Some(end);
        p.edits.push(Edit {
            start: from,
            end,
            text: String::new(),
        });
    }
    for item in file.items.iter().filter(|i| !shapes::is_hoist_exempt(i, p.path)) {
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
    /// The files that change.
    Rewritten(Vec<Planned>),
}

/// A file `apply` will change: its text when planned, and the text to put there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub path: PathBuf,
    pub before: String,
    pub after: String,
}

/// Writes every planned file, or none: each is checked against its planned text, then written
/// beside its target, and only then renamed into place. A failure names what was already renamed.
pub fn commit(files: &[Planned]) -> Result<()> {
    for f in files {
        let now = std::fs::read_to_string(&f.path).with_context(|| format!("reading {}", f.path.display()))?;
        if now != f.before {
            bail!("{} changed since it was planned; nothing was written", f.path.display());
        }
    }
    let mut staged: Vec<(PathBuf, &Planned)> = Vec::new();
    for f in files {
        let name = f
            .path
            .file_name()
            .context("a planned file has a name")?
            .to_string_lossy();
        let tmp = f.path.with_file_name(format!(".{name}.skuld-rewrite.tmp"));
        let stage = || -> Result<()> {
            std::fs::write(&tmp, &f.after)?;
            std::fs::set_permissions(&tmp, std::fs::metadata(&f.path)?.permissions())?;
            Ok(())
        };
        if let Err(e) = stage() {
            for (t, _) in &staged {
                let _ = std::fs::remove_file(t);
            }
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("staging {}; nothing was written", f.path.display()));
        }
        staged.push((tmp, f));
    }
    let mut done: Vec<String> = Vec::new();
    for (i, (tmp, f)) in staged.iter().enumerate() {
        if let Err(e) = std::fs::rename(tmp, &f.path) {
            for (t, _) in &staged[i..] {
                let _ = std::fs::remove_file(t);
            }
            bail!(
                "renaming into {}: {e}; already written: [{}]",
                f.path.display(),
                done.join(", ")
            );
        }
        done.push(f.path.display().to_string());
    }
    Ok(())
}

/// Plans a rewrite of every file reachable from `roots`, refusing a file that changes and is
/// also reachable from one of `unflipped`.
pub fn apply(source: &dyn Source, roots: &[PathBuf], unflipped: &[PathBuf], opts: Options) -> Result<Outcome> {
    let roots: Vec<Root> = roots.iter().map(Root::crate_root).collect();
    apply_roots(source, &roots, unflipped, opts)
}

/// [`apply`] over roots that may be module files.
pub fn apply_roots(source: &dyn Source, roots: &[Root], unflipped: &[PathBuf], opts: Options) -> Result<Outcome> {
    let files: BTreeMap<PathBuf, ParsedFile> = modtree::walk_roots(source, roots)?
        .into_iter()
        .map(|f| (f.path.clone(), f))
        .collect();
    let applied_roots: BTreeSet<PathBuf> = roots.iter().map(|r| modtree::normalize(&r.path)).collect();
    let mut reach: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();
    let mut refusals = Vec::new();
    for u in unflipped {
        let u = modtree::normalize(u);
        if applied_roots.contains(&u) {
            refusals.push(Refusal {
                path: u.clone(),
                line: 0,
                reason: "is listed as unflipped but is also being applied".to_owned(),
            });
            continue;
        }
        for f in modtree::walk(source, &u)? {
            reach.entry(f.path).or_insert_with(|| u.clone());
        }
    }

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
        rewritten.push(Planned {
            path: path.clone(),
            before: file.src.clone(),
            after: splice(&file.src, &edits)?,
        });
    }
    if refusals.is_empty() {
        Ok(Outcome::Rewritten(rewritten))
    } else {
        Ok(Outcome::Refused(refusals))
    }
}
