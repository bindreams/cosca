use super::EnvSanitizer;
use std::ffi::{OsStr, OsString};

fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs
        .iter()
        .map(|(k, v)| (OsString::from(*k), OsString::from(*v)))
        .collect()
}

// `apply` returns `kept: Vec<(OsString, OsString)>` and `stripped: Vec<OsString>` — this
// trait lets the one `keys()` helper below read the key out of either shape.
trait KeyLike {
    fn key(&self) -> &OsStr;
}

impl KeyLike for (OsString, OsString) {
    fn key(&self) -> &OsStr {
        &self.0
    }
}

impl KeyLike for OsString {
    fn key(&self) -> &OsStr {
        self
    }
}

fn keys<T: KeyLike>(v: &[T]) -> Vec<String> {
    v.iter().map(|x| x.key().to_string_lossy().into_owned()).collect()
}

#[test]
fn default_strips_the_loader_family_and_injection_set() {
    let s = EnvSanitizer::default();
    let (kept, stripped) = s.apply(env(&[
        ("PATH", "/usr/bin"),
        ("LD_PRELOAD", "/evil.so"),
        ("LD_BIND_NOW", "1"),
        ("DYLD_INSERT_LIBRARIES", "/e.dylib"),
        ("IFS", " "),
        ("MY_APP_CONFIG", "ok"),
    ]));
    assert_eq!(keys(&kept), vec!["MY_APP_CONFIG", "PATH"]);
    let mut got = keys(&stripped);
    got.sort();
    assert_eq!(got, vec!["DYLD_INSERT_LIBRARIES", "IFS", "LD_BIND_NOW", "LD_PRELOAD"]);
}

#[test]
fn keep_pokes_a_hole_in_a_denylist() {
    let s = EnvSanitizer::default().keep(["LD_LIBRARY_PATH"]);
    let (kept, stripped) = s.apply(env(&[("LD_LIBRARY_PATH", "/opt/lib"), ("LD_PRELOAD", "/e.so")]));
    assert_eq!(keys(&kept), vec!["LD_LIBRARY_PATH"]);
    assert_eq!(keys(&stripped), vec!["LD_PRELOAD"]);
}

#[test]
fn keep_widens_an_allowlist_and_never_downgrades_it() {
    let s = EnvSanitizer::allowlist(["PATH"]).keep(["LANG"]);
    let (kept, stripped) = s.apply(env(&[("PATH", "/b"), ("LANG", "C"), ("MY_APP_CONFIG", "x")]));
    assert_eq!(keys(&kept), vec!["LANG", "PATH"]);
    assert_eq!(keys(&stripped), vec!["MY_APP_CONFIG"]);
}

#[test]
fn keep_on_a_filter_widens_it() {
    let s = EnvSanitizer::filter(|k, _v| k == "PATH").keep(["LANG"]);
    let (kept, stripped) = s.apply(env(&[("PATH", "/b"), ("LANG", "C"), ("OTHER", "x")]));
    assert_eq!(keys(&kept), vec!["LANG", "PATH"]);
    assert_eq!(keys(&stripped), vec!["OTHER"]);
}

#[test]
fn allowlist_is_fail_closed() {
    let s = EnvSanitizer::allowlist(["PATH", "LANG"]);
    let (kept, stripped) = s.apply(env(&[("PATH", "/b"), ("LANG", "C"), ("MY_APP_CONFIG", "x")]));
    assert_eq!(keys(&kept), vec!["LANG", "PATH"]);
    assert_eq!(keys(&stripped), vec!["MY_APP_CONFIG"]);
}

#[test]
fn none_keeps_everything() {
    let s = EnvSanitizer::none();
    let (kept, stripped) = s.apply(env(&[("LD_PRELOAD", "/e.so")]));
    assert_eq!(keys(&kept), vec!["LD_PRELOAD"]);
    assert!(stripped.is_empty());
}

#[test]
fn filter_runs_the_closure() {
    let s = EnvSanitizer::filter(|k, _v| k != "SECRET");
    let (kept, stripped) = s.apply(env(&[("SECRET", "x"), ("PATH", "/b")]));
    assert_eq!(keys(&kept), vec!["PATH"]);
    assert_eq!(keys(&stripped), vec!["SECRET"]);
}
