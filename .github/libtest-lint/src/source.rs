//! Rules 1-3: libtest test attributes in parsed source, in every form the grammar has.

use std::collections::{HashMap, HashSet};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{Attribute, ItemExternCrate, ItemUse, Macro, Meta, UseTree};

pub struct Finding {
    pub line: usize,
    pub col: usize,
    pub what: String,
}

/// Parses one file and returns what it finds. A file that is not a whole Rust file (an `include!` fragment) but still
/// lexes is scanned as tokens, so only its attributes are seen; one that does not even lex is the parse error.
pub fn check_file(text: &str) -> Result<Vec<Finding>, syn::Error> {
    let file = match syn::parse_file(text) {
        Ok(file) => file,
        Err(e) => {
            let Ok(tokens) = text.parse::<TokenStream>() else {
                return Err(e);
            };
            let mut lint = Lint {
                aliases: HashMap::new(),
                qualified_only: true,
                findings: Vec::new(),
            };
            lint.scan(tokens, " in a file read as tokens");
            return Ok(lint.findings);
        }
    };
    let mut collect = Aliases::default();
    collect.visit_file(&file);
    let mut lint = Lint {
        aliases: collect.names,
        qualified_only: false,
        findings: Vec::new(),
    };
    lint.visit_file(&file);
    Ok(lint.findings)
}

/// Whether `path` names a libtest test attribute: `test`, `bench`, `tokio::test`, or a prelude path.
fn is_libtest_attribute(path: &[String]) -> bool {
    let is = |s: &String, want: &[&str]| want.contains(&s.as_str());
    match path {
        [name] => is(name, &["test", "bench"]),
        [krate, name] => krate == "tokio" && name == "test",
        [root, prelude, _, name] => is(root, &["core", "std"]) && prelude == "prelude" && is(name, &["test", "bench"]),
        _ => false,
    }
}

// Aliases -----------------------------------------------------------------------------------------------------------

/// Every name a `use` or `extern crate` of the file binds, with the path it stands for.
#[derive(Default)]
struct Aliases {
    names: HashMap<String, Vec<String>>,
}

impl Aliases {
    fn bind(&mut self, name: String, path: Vec<String>) {
        self.names.insert(name, path);
    }

    fn walk(&mut self, tree: &UseTree, prefix: &mut Vec<String>) {
        match tree {
            UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                self.walk(&p.tree, prefix);
                prefix.pop();
            }
            UseTree::Name(n) => self.leaf(prefix, &n.ident.to_string(), None),
            UseTree::Rename(r) => self.leaf(prefix, &r.ident.to_string(), Some(r.rename.to_string())),
            UseTree::Glob(_) => {}
            UseTree::Group(g) => g.items.iter().for_each(|t| self.walk(t, prefix)),
        }
    }

    fn leaf(&mut self, prefix: &[String], ident: &str, rename: Option<String>) {
        let mut path = prefix.to_vec();
        if ident != "self" {
            path.push(ident.to_string());
        }
        if let Some(name) = rename.or_else(|| path.last().cloned()) {
            self.bind(name, path);
        }
    }
}

impl<'ast> Visit<'ast> for Aliases {
    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.walk(&item.tree, &mut Vec::new());
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        let name = item.rename.as_ref().map_or(&item.ident, |(_, n)| n);
        self.bind(name.to_string(), vec![item.ident.to_string()]);
    }
}

// Lint --------------------------------------------------------------------------------------------------------------

struct Lint {
    aliases: HashMap<String, Vec<String>>,
    /// Set for a file read as tokens: its `use`s are not here, so a bare `test` may be skuld's and is not flagged.
    qualified_only: bool,
    findings: Vec<Finding>,
}

impl Lint {
    fn report(&mut self, span: proc_macro2::Span, what: String) {
        let start = span.start();
        self.findings.push(Finding {
            line: start.line,
            col: start.column + 1,
            what,
        });
    }

    /// `path` with its leading name replaced by what a `use` or `extern crate` bound it to, as often as that applies.
    fn resolve(&self, path: &[String]) -> Vec<String> {
        let mut path = path.to_vec();
        let mut seen = HashSet::new();
        while let Some(target) = path.first().and_then(|first| self.aliases.get(first)) {
            if !seen.insert(path[0].clone()) {
                break;
            }
            path.splice(..1, target.iter().cloned());
        }
        path
    }

    /// Whether `path` is a libtest test attribute. A first segment the file binds with `use` or `extern crate` means
    /// what it was bound to (`use skuld::test;` makes `#[test]` skuld's); an unbound one means what it says.
    fn is_libtest(&self, path: &[String]) -> bool {
        if self.qualified_only && path.len() < 2 {
            return false;
        }
        match path.first() {
            Some(first) if self.aliases.contains_key(first) => is_libtest_attribute(&self.resolve(path)),
            _ => is_libtest_attribute(path),
        }
    }

    fn check_meta(&mut self, meta: &Meta) {
        let path: Vec<String> = meta.path().segments.iter().map(|s| s.ident.to_string()).collect();
        if self.is_libtest(&path) {
            self.report(
                meta.path().segments[0].ident.span(),
                format!("libtest attribute `#[{}]`", path.join("::")),
            );
        } else if path == ["cfg_attr"] {
            // Read as tokens: `syn` takes the predicate as a `Meta`, which rejects `cfg_attr(true, ..)`.
            if let Meta::List(list) = meta {
                let args: Vec<TokenTree> = list.tokens.clone().into_iter().collect();
                self.check_cfg_attr(&args, "");
            }
        }
    }

    /// The arguments of a `cfg_attr`: a predicate, then the attributes it applies. Only top-level commas split them:
    /// commas inside a group are inside its `Group` token.
    fn check_cfg_attr(&mut self, args: &[TokenTree], site: &str) {
        for part in args
            .split(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == ','))
            .skip(1)
        {
            self.check_tokens(part, site);
        }
    }

    /// Rule 2: `#[...]` written in tokens `syn` does not parse as attributes. `site` says where they came from.
    fn scan(&mut self, tokens: TokenStream, site: &str) {
        let tokens: Vec<TokenTree> = tokens.into_iter().collect();
        for (i, tree) in tokens.iter().enumerate() {
            match tree {
                TokenTree::Group(g) => self.scan(g.stream(), site),
                TokenTree::Punct(p) if p.as_char() == '#' => {
                    let mut next = i + 1;
                    if matches!(tokens.get(next), Some(TokenTree::Punct(bang)) if bang.as_char() == '!') {
                        next += 1;
                    }
                    if let Some(TokenTree::Group(g)) = tokens.get(next) {
                        if g.delimiter() == Delimiter::Bracket {
                            let body: Vec<TokenTree> = g.stream().into_iter().collect();
                            self.check_tokens(&body, site);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// The inside of one `[...]`: a path, then nothing or an argument group. `site` ends the message of a finding.
    fn check_tokens(&mut self, body: &[TokenTree], site: &str) {
        let mut at = 0;
        let mut path = Vec::new();
        let mut first = None;
        let colon = |t: Option<&TokenTree>| matches!(t, Some(TokenTree::Punct(p)) if p.as_char() == ':');
        if colon(body.first()) && colon(body.get(1)) {
            at = 2;
        }
        while let Some(TokenTree::Ident(id)) = body.get(at) {
            first.get_or_insert_with(|| id.span());
            path.push(id.to_string());
            at += 1;
            if colon(body.get(at)) && colon(body.get(at + 1)) {
                at += 2;
            } else {
                break;
            }
        }
        let Some(span) = first else { return };
        let args = match body.get(at) {
            None => None,
            Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis => Some(g),
            Some(_) => return,
        };
        if self.is_libtest(&path) {
            self.report(span, format!("libtest attribute `#[{}]`{site}", path.join("::")));
        } else if let (true, Some(g)) = (path == ["cfg_attr"], args) {
            let inner: Vec<TokenTree> = g.stream().into_iter().collect();
            self.check_cfg_attr(&inner, site);
        }
    }
}

/// `visit_*` overrides for the node kinds with a `Verbatim` variant: the tokens `syn` could not parse, attributes
/// included, which no other visitor reaches.
macro_rules! scan_verbatim {
    ($($method:ident, $node:ident;)*) => {$(
        fn $method(&mut self, node: &'ast syn::$node) {
            if let syn::$node::Verbatim(tokens) = node {
                self.scan(tokens.clone(), " in a verbatim item");
            }
            visit::$method(self, node);
        }
    )*};
}

impl<'ast> Visit<'ast> for Lint {
    scan_verbatim! {
        visit_item, Item;
        visit_foreign_item, ForeignItem;
        visit_impl_item, ImplItem;
        visit_trait_item, TraitItem;
        visit_expr, Expr;
        visit_pat, Pat;
        visit_type, Type;
        visit_type_param_bound, TypeParamBound;
    }

    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        self.check_meta(&attr.meta);
        visit::visit_attribute(self, attr);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan(mac.tokens.clone(), " in macro tokens");
        visit::visit_macro(self, mac);
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let mut found = Vec::new();
        collect_leaves(&item.tree, &mut Vec::new(), &mut found);
        for (path, span) in found {
            if self.is_libtest(&path) {
                self.report(
                    span,
                    format!("`use` brings the libtest attribute `{}` into scope", path.join("::")),
                );
            }
        }
        visit::visit_item_use(self, item);
    }
}

/// The full path and span of every non-glob leaf of a `use` tree.
fn collect_leaves(tree: &UseTree, prefix: &mut Vec<String>, out: &mut Vec<(Vec<String>, proc_macro2::Span)>) {
    match tree {
        UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            collect_leaves(&p.tree, prefix, out);
            prefix.pop();
        }
        UseTree::Name(n) => out.push(([prefix.as_slice(), &[n.ident.to_string()]].concat(), n.ident.span())),
        UseTree::Rename(r) => out.push(([prefix.as_slice(), &[r.ident.to_string()]].concat(), r.ident.span())),
        UseTree::Glob(_) => {}
        UseTree::Group(g) => g.items.iter().for_each(|t| collect_leaves(t, prefix, out)),
    }
}
