//! Recognising test attributes and the runtime each one asks for.

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::punctuated::Punctuated;
use syn::{Attribute, Expr, Lit, Meta, Path, Token};

/// The path the migrated `start_paused` tests name.
pub const PAUSED_RUNTIME: &str = "crate :: tokio :: test_runtime :: paused";

/// How the attribute was spelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// `#[test]`.
    Test,
    /// `#[tokio::test(..)]` or `#[::tokio::test(..)]`.
    Tokio,
    /// `#[skuld::test(..)]` or `#[::skuld::test(..)]`.
    Skuld,
}

/// The runtime a test asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Runtime {
    /// Skuld's own current-thread runtime, which is `tokio::test`'s default.
    Default,
    /// `start_paused = true`.
    Paused,
    /// Any other `skuld::test` argument, kept verbatim as tokens so it never equals another.
    Other(String),
}

/// A recognised test attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestAttr {
    pub origin: Origin,
    pub runtime: Runtime,
}

/// Why a test-like attribute cannot be mapped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unsupported(pub String);

fn segments(path: &Path) -> Vec<String> {
    path.segments.iter().map(|s| s.ident.to_string()).collect()
}

/// `Some` when the path names a test attribute macro.
pub fn origin_of(path: &Path) -> Option<Origin> {
    let segs = segments(path);
    let segs: Vec<&str> = segs.iter().map(String::as_str).collect();
    match (path.leading_colon.is_some(), segs.as_slice()) {
        (false, ["test"]) => Some(Origin::Test),
        (_, ["tokio", "test"]) => Some(Origin::Tokio),
        (_, ["skuld", "test"]) => Some(Origin::Skuld),
        _ => None,
    }
}

fn is_str_lit(expr: &Expr, want: &str) -> bool {
    matches!(expr, Expr::Lit(l) if matches!(&l.lit, Lit::Str(s) if s.value() == want))
}

fn is_true_lit(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(l) if matches!(&l.lit, Lit::Bool(b) if b.value))
}

fn tokens_text(t: &impl ToTokens) -> String {
    t.to_token_stream().to_string()
}

/// `None` when `meta` is not a test attribute at all.
pub fn classify_meta(meta: &Meta) -> Option<Result<TestAttr, Unsupported>> {
    let origin = origin_of(meta.path())?;
    let args: Punctuated<Meta, Token![,]> = match meta {
        Meta::Path(_) => Punctuated::new(),
        Meta::List(list) => match list.parse_args_with(Punctuated::parse_terminated) {
            Ok(a) => a,
            Err(_) => {
                return Some(Err(Unsupported(format!(
                    "unparseable arguments `{}`",
                    tokens_text(&list.tokens)
                ))))
            }
        },
        Meta::NameValue(_) => {
            return Some(Err(Unsupported(format!(
                "`{}` is not a plain attribute",
                tokens_text(meta)
            ))))
        }
    };
    Some(match origin {
        Origin::Test => {
            if args.is_empty() {
                Ok(TestAttr {
                    origin,
                    runtime: Runtime::Default,
                })
            } else {
                Err(Unsupported(format!("`#[test]` argument `{}`", tokens_text(&args))))
            }
        }
        Origin::Tokio => classify_tokio_args(&args).map(|runtime| TestAttr { origin, runtime }),
        Origin::Skuld => Ok(TestAttr {
            origin,
            runtime: classify_skuld_args(&args),
        }),
    })
}

fn classify_tokio_args(args: &Punctuated<Meta, Token![,]>) -> Result<Runtime, Unsupported> {
    let mut paused = false;
    for arg in args {
        match arg {
            Meta::NameValue(nv) if nv.path.is_ident("flavor") && is_str_lit(&nv.value, "current_thread") => {}
            Meta::NameValue(nv) if nv.path.is_ident("start_paused") && is_true_lit(&nv.value) => paused = true,
            other => {
                return Err(Unsupported(format!("`tokio::test` argument `{}`", tokens_text(other))));
            }
        }
    }
    Ok(if paused { Runtime::Paused } else { Runtime::Default })
}

fn classify_skuld_args(args: &Punctuated<Meta, Token![,]>) -> Runtime {
    if args.is_empty() {
        return Runtime::Default;
    }
    if args.len() == 1 {
        if let Meta::NameValue(nv) = &args[0] {
            if nv.path.is_ident("runtime") && tokens_text(&nv.value) == PAUSED_RUNTIME {
                return Runtime::Paused;
            }
        }
    }
    Runtime::Other(tokens_text(args))
}

/// `None` when `attr` is not a test attribute; only outer attributes count.
pub fn classify(attr: &Attribute) -> Option<Result<TestAttr, Unsupported>> {
    if !matches!(attr.style, syn::AttrStyle::Outer) {
        return None;
    }
    classify_meta(&attr.meta)
}

/// A test attribute inside a `cfg_attr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hidden {
    /// A spelling this tool knows.
    Known(Origin),
    /// A path ending in `test` that no mapping covers, or arguments too opaque to read that
    /// mention `test`.
    Unknown,
}

fn mentions_test(ts: TokenStream) -> bool {
    ts.into_iter().any(|t| match t {
        proc_macro2::TokenTree::Ident(i) => i == "test",
        proc_macro2::TokenTree::Group(g) => mentions_test(g.stream()),
        _ => false,
    })
}

/// True when `path` ends in `test`, whatever precedes it.
pub fn ends_in_test(path: &Path) -> bool {
    path.segments.last().is_some_and(|s| s.ident == "test")
}

/// True when `meta` is a test attribute spelling that [`classify_meta`] does not map.
pub fn is_unmapped_test(meta: &Meta) -> bool {
    origin_of(meta.path()).is_none() && ends_in_test(meta.path())
}

/// Every test attribute `meta` would apply through any depth of `cfg_attr`. A conditional test
/// is conditionally a test, which a splice cannot map.
pub fn hidden_tests(meta: &Meta) -> Vec<Hidden> {
    let Meta::List(list) = meta else { return Vec::new() };
    if !list.path.is_ident("cfg_attr") {
        return Vec::new();
    }
    let Ok(args) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else {
        return if mentions_test(list.tokens.clone()) {
            vec![Hidden::Unknown]
        } else {
            Vec::new()
        };
    };
    let mut out = Vec::new();
    for arg in args.iter().skip(1) {
        if arg.path().is_ident("cfg_attr") {
            out.extend(hidden_tests(arg));
        } else if let Some(o) = origin_of(arg.path()) {
            out.push(Hidden::Known(o));
        } else if ends_in_test(arg.path()) {
            out.push(Hidden::Unknown);
        }
    }
    out
}

/// The canonical attribute used by `verify`: `#[test(default)]`, `#[test(paused)]`, or
/// `#[test(other(<tokens>))]`.
pub fn canonical(attr: &TestAttr) -> Attribute {
    match &attr.runtime {
        Runtime::Default => syn::parse_quote!(#[test(default)]),
        Runtime::Paused => syn::parse_quote!(#[test(paused)]),
        Runtime::Other(text) => {
            let ts: TokenStream = text.parse().expect("tokens printed by proc-macro2 re-lex");
            syn::parse_quote!(#[test(other(#ts))])
        }
    }
}

/// The canonical form of a test attribute that failed to map, so it never equals a good one.
pub fn canonical_unsupported(meta: &Meta) -> Attribute {
    let ts = meta.to_token_stream();
    syn::parse_quote!(#[test(unsupported(#ts))])
}
