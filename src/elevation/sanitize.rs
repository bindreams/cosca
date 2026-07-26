//! The env consent gradient (layer 2): a denylist over the vars the user
//! *deliberately* forwards past the backend's env_reset scrub.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};

/// Loader/injection footguns that would otherwise be re-injected past `ld.so`'s
/// setuid scrub (load-bearing for run0's `--setenv`, defense-in-depth for sudo's
/// `--preserve-env`). Prefix families are matched in [`is_denied`].
pub(crate) const DEFAULT_DENYLIST: &[&str] = &[
    "IFS",
    "BASH_ENV",
    "ENV",
    "PS4",
    "TERMINFO",
    "TERMCAP",
    "HOSTALIASES",
    "RES_OPTIONS",
    "LIBPATH",
    "SHLIB_PATH",
    "GCONV_PATH",
    "PYTHONPATH",
    "PERL5LIB",
    "NODE_OPTIONS",
];
const DENYLIST_PREFIXES: &[&str] = &["LD_", "DYLD_", "_RLD", "LDR_"];

fn is_denied(key: &OsStr) -> bool {
    let k = key.to_string_lossy();
    DENYLIST_PREFIXES.iter().any(|p| k.starts_with(p)) || DEFAULT_DENYLIST.contains(&k.as_ref())
}

type FilterFn = Box<dyn Fn(&OsStr, &OsStr) -> bool + Send + Sync + 'static>;

enum Policy {
    Denylist { keep: BTreeSet<OsString> },
    Allowlist { allow: BTreeSet<OsString> },
    Filter(FilterFn),
    None,
}

/// A sanitizer policy over the explicitly-forwarded env set.
pub struct EnvSanitizer {
    policy: Policy,
}

impl Default for EnvSanitizer {
    fn default() -> EnvSanitizer {
        EnvSanitizer {
            policy: Policy::Denylist { keep: BTreeSet::new() },
        }
    }
}

impl std::fmt::Debug for EnvSanitizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match &self.policy {
            Policy::Denylist { .. } => "Denylist",
            Policy::Allowlist { .. } => "Allowlist",
            Policy::Filter(_) => "Filter",
            Policy::None => "None",
        };
        f.debug_struct("EnvSanitizer").field("policy", &name).finish()
    }
}

impl EnvSanitizer {
    /// Additively keep `keys`, WITHIN the current policy — never a downgrade.
    pub fn keep<I, S>(mut self, keys: I) -> EnvSanitizer
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let extra: BTreeSet<OsString> = keys.into_iter().map(Into::into).collect();
        self.policy = match self.policy {
            Policy::Denylist { mut keep } => {
                keep.extend(extra);
                Policy::Denylist { keep }
            }
            Policy::Allowlist { mut allow } => {
                allow.extend(extra);
                Policy::Allowlist { allow }
            }
            Policy::Filter(f) => Policy::Filter(Box::new(move |k, v| extra.contains(k) || f(k, v))),
            Policy::None => Policy::None,
        };
        self
    }

    /// Opt-in, fail-closed: forward ONLY these keys.
    pub fn allowlist<I, S>(keys: I) -> EnvSanitizer
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        EnvSanitizer {
            policy: Policy::Allowlist {
                allow: keys.into_iter().map(Into::into).collect(),
            },
        }
    }

    /// Arbitrary predicate: return `true` to KEEP the var.
    pub fn filter<F>(f: F) -> EnvSanitizer
    where
        F: Fn(&OsStr, &OsStr) -> bool + Send + Sync + 'static,
    {
        EnvSanitizer {
            policy: Policy::Filter(Box::new(f)),
        }
    }

    /// The full foot-gun: forward everything (greppable in source).
    pub fn none() -> EnvSanitizer {
        EnvSanitizer { policy: Policy::None }
    }

    /// Partition `env` into `(kept, stripped)`, both sorted by key.
    // Not yet called by production code: only tests drive `apply` today; the sync/async
    // POSIX spawn arms that read `ElevationRequest::sanitizer` land in later elevation-plan
    // tasks (see the sibling `#[allow(dead_code)]`s in `src/elevation.rs`).
    #[allow(dead_code)]
    pub(crate) fn apply(&self, env: Vec<(OsString, OsString)>) -> (Vec<(OsString, OsString)>, Vec<OsString>) {
        let mut kept: Vec<(OsString, OsString)> = Vec::new();
        let mut stripped: Vec<OsString> = Vec::new();
        for (k, v) in env {
            let keep = match &self.policy {
                Policy::None => true,
                Policy::Allowlist { allow } => allow.contains(&k),
                Policy::Filter(f) => f(&k, &v),
                Policy::Denylist { keep } => keep.contains(&k) || !is_denied(&k),
            };
            if keep {
                kept.push((k, v));
            } else {
                log::info!("sanitize_env dropped {} before elevating", k.to_string_lossy());
                stripped.push(k);
            }
        }
        kept.sort_by(|a, b| a.0.cmp(&b.0));
        stripped.sort();
        (kept, stripped)
    }
}

#[cfg(test)]
#[path = "sanitize_tests.rs"]
mod sanitize_tests;
