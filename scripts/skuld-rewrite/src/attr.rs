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

/// True when `meta` is a `cfg_attr` whose conditional attributes include a test attribute that
/// `selects`. Such a test is conditionally a test, which a splice cannot map.
pub fn cfg_attr_hides_test(meta: &Meta, selects: impl Fn(Origin) -> bool) -> bool {
    let Meta::List(list) = meta else { return false };
    if !list.path.is_ident("cfg_attr") {
        return false;
    }
    let Ok(args) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else {
        return false;
    };
    args.iter().skip(1).any(|m| origin_of(m.path()).is_some_and(&selects))
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
