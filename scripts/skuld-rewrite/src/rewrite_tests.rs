use std::path::PathBuf;

use crate::modtree::FsSource;
use crate::rewrite::{apply, Options, Outcome};
use crate::test_util::MemSource;

fn run(files: &[(&str, &str)], roots: &[&str], unflipped: &[&str], opts: Options) -> Outcome {
    let src = MemSource::new(files);
    let roots: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
    let unflipped: Vec<PathBuf> = unflipped.iter().map(PathBuf::from).collect();
    apply(&src, &roots, &unflipped, opts).expect("apply")
}

fn rewritten(out: Outcome) -> Vec<(String, String)> {
    match out {
        Outcome::Rewritten(f) => f
            .into_iter()
            .map(|(p, t)| (p.to_string_lossy().into_owned(), t))
            .collect(),
        Outcome::Refused(r) => panic!("unexpected refusal: {r:?}"),
    }
}

fn one(src: &str, opts: Options) -> String {
    let mut files = rewritten(run(&[("/t/r.rs", src)], &["/t/r.rs"], &[], opts));
    assert_eq!(files.len(), 1, "{files:?}");
    files.pop().unwrap().1
}

#[test]
fn maps_each_spelling_and_flavour() {
    let src = r#"
#[test]
fn a() {}
#[tokio::test]
async fn b() {}
#[::tokio::test]
async fn c() {}
#[tokio::test(flavor = "current_thread")]
async fn d() {}
#[::tokio::test(flavor = "current_thread")]
#[ignore = "why"]
async fn e() {}
mod m {
    #[test]
    fn f() {
        #[tokio::test]
        async fn nested() {}
    }
}
"#;
    let want = r#"
#[skuld::test]
fn a() {}
#[skuld::test]
async fn b() {}
#[skuld::test]
async fn c() {}
#[skuld::test]
async fn d() {}
#[skuld::test]
#[ignore = "why"]
async fn e() {}
mod m {
    #[skuld::test]
    fn f() {
        #[skuld::test]
        async fn nested() {}
    }
}
"#;
    assert_eq!(one(src, Options::default()), want);
}

#[test]
fn only_tokio_leaves_a_bare_test_alone() {
    let src = "#[test]\nfn a() {}\n#[tokio::test]\nasync fn b() {}\n";
    assert_eq!(
        one(
            src,
            Options {
                only_tokio: true,
                ..Options::default()
            }
        ),
        "#[test]\nfn a() {}\n#[skuld::test]\nasync fn b() {}\n"
    );
}

#[test]
fn an_already_skuld_test_and_unrelated_attributes_are_untouched() {
    let src = "#[skuld::test]\nfn a() {}\n#[cfg_attr(debug_assertions, should_panic(expected = \"x\"))]\n#[tokio::main]\nfn b() {}\n";
    match run(&[("/t/r.rs", src)], &["/t/r.rs"], &[], Options::default()) {
        Outcome::Rewritten(f) => assert!(f.is_empty(), "{f:?}"),
        Outcome::Refused(r) => panic!("{r:?}"),
    }
}

#[test]
fn start_paused_maps_to_the_paused_runtime() {
    let src = "#[tokio::test(start_paused = true)]\nasync fn a() {}\n#[::tokio::test(start_paused = true)]\nasync fn b() {}\n#[tokio::test(flavor = \"current_thread\", start_paused = true)]\nasync fn c() {}\n";
    let want = "#[skuld::test(runtime = crate::tokio::test_runtime::paused)]\nasync fn a() {}\n#[skuld::test(runtime = crate::tokio::test_runtime::paused)]\nasync fn b() {}\n#[skuld::test(runtime = crate::tokio::test_runtime::paused)]\nasync fn c() {}\n";
    assert_eq!(one(src, Options::default()), want);
}

#[test]
fn refuses_cfg_attr_test_and_unknown_args() {
    let src = "#[cfg_attr(unix, test)]\nfn a() {}\n\n#[tokio::test(flavor = \"multi_thread\")]\nasync fn b() {}\n#[tokio::test(worker_threads = 2)]\nasync fn c() {}\n#[tokio::test(start_paused = false)]\nasync fn d() {}\n#[test(x)]\nfn e() {}\n#[cfg_attr(unix, tokio::test)]\nasync fn f() {}\n#[test]\nfn fine() {}\n";
    let Outcome::Refused(r) = run(&[("/t/r.rs", src)], &["/t/r.rs"], &[], Options::default()) else {
        panic!("expected a refusal");
    };
    let lines: Vec<usize> = r.iter().map(|r| r.line).collect();
    assert_eq!(lines, [1, 4, 6, 8, 10, 12], "{r:?}");
    assert!(r.iter().all(|r| r.path.as_path() == std::path::Path::new("/t/r.rs")));
}

#[test]
fn splices_macro_rules_tokens() {
    let src = "macro_rules! t {\n    ($n:ident) => {\n        # [ test ]\n        fn $n() {}\n        #[tokio::test(start_paused = true)]\n        async fn p() {}\n        #[$m]\n        fn q() {}\n    };\n}\nfn after() { macro_rules! inner { () => { #[tokio::test] async fn z() {} } } }\n";
    let want = "macro_rules! t {\n    ($n:ident) => {\n        #[skuld::test]\n        fn $n() {}\n        #[skuld::test(runtime = crate::tokio::test_runtime::paused)]\n        async fn p() {}\n        #[$m]\n        fn q() {}\n    };\n}\nfn after() { macro_rules! inner { () => { #[skuld::test] async fn z() {} } } }\n";
    assert_eq!(one(src, Options::default()), want);
}

#[test]
fn splices_survive_multibyte_text_before_the_site() {
    let src = "// zażółć gęślą jaźń\nconst S: &str = \"日本語\"; #[test] fn a() {}\n";
    assert_eq!(
        one(src, Options::default()),
        "// zażółć gęślą jaźń\nconst S: &str = \"日本語\"; #[skuld::test] fn a() {}\n"
    );
}

#[test]
fn hoists_crate_cfg_except_main_and_include() {
    let src = "//! docs\n#![cfg(all(windows, feature = \"tokio\"))]\n#![allow(dead_code)]\n\n#[path = \"../src/test_harness.rs\"]\nmod test_harness;\nuse std::io;\n/// doc\n#[tokio::test]\nasync fn a() {}\nmod m;\nfn main() {}\n";
    let files = rewritten(run(
        &[("/t/r.rs", src), ("/t/m.rs", "#![cfg(unix)]\n#[test]\nfn x() {}\n")],
        &["/t/r.rs"],
        &[],
        Options {
            hoist_crate_cfg: true,
            ..Options::default()
        },
    ));
    let want_root = "//! docs\n#![allow(dead_code)]\n\n#[path = \"../src/test_harness.rs\"]\nmod test_harness;\n#[cfg(all(windows, feature = \"tokio\"))]\nuse std::io;\n#[cfg(all(windows, feature = \"tokio\"))]\n/// doc\n#[skuld::test]\nasync fn a() {}\n#[cfg(all(windows, feature = \"tokio\"))]\nmod m;\nfn main() {}\n";
    let want_m = "#![cfg(unix)]\n#[skuld::test]\nfn x() {}\n";
    let get = |name: &str| files.iter().find(|(p, _)| p == name).map(|(_, t)| t.as_str());
    assert_eq!(get("/t/r.rs"), Some(want_root));
    // A module's own `#![cfg]` is a module-level gate, not the crate's: it stays.
    assert_eq!(get("/t/m.rs"), Some(want_m));
}

#[test]
fn hoisting_is_idempotent() {
    let src = "#![cfg(unix)]\nfn a() {}\n";
    let once = one(
        src,
        Options {
            hoist_crate_cfg: true,
            ..Options::default()
        },
    );
    assert_eq!(once, "#[cfg(unix)]\nfn a() {}\n");
    match run(
        &[("/t/r.rs", &once)],
        &["/t/r.rs"],
        &[],
        Options {
            hoist_crate_cfg: true,
            ..Options::default()
        },
    ) {
        Outcome::Rewritten(f) => assert!(f.is_empty()),
        Outcome::Refused(r) => panic!("{r:?}"),
    }
}

#[test]
fn refuses_files_reachable_from_unflipped_roots() {
    let files = [
        ("/t/a.rs", "mod common;\n#[test]\nfn a() {}\n"),
        ("/t/b.rs", "mod common;\n#[test]\nfn b() {}\n"),
        ("/t/common.rs", "#[test]\nfn shared() {}\n"),
    ];
    let Outcome::Refused(r) = run(&files, &["/t/a.rs"], &["/t/b.rs"], Options::default()) else {
        panic!("expected a refusal");
    };
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].path, PathBuf::from("/t/common.rs"));
    assert!(r[0].reason.contains("/t/b.rs"), "{}", r[0].reason);
}

#[test]
fn a_shared_file_that_does_not_change_is_not_refused() {
    let files = [
        ("/t/a.rs", "mod common;\n#[test]\nfn a() {}\n"),
        ("/t/b.rs", "mod common;\n#[test]\nfn b() {}\n"),
        ("/t/common.rs", "pub fn helper() {}\n"),
    ];
    let out = rewritten(run(&files, &["/t/a.rs"], &["/t/b.rs"], Options::default()));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "/t/a.rs");
}

#[test]
fn fs_source_reports_a_missing_file_as_absent() {
    use crate::modtree::Source;
    assert!(FsSource
        .read(std::path::Path::new("/definitely/not/here.rs"))
        .unwrap()
        .is_none());
}
