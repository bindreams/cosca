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
            .map(|p| (p.path.to_string_lossy().into_owned(), p.after))
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

fn refused_lines(src: &str, opts: Options) -> Vec<usize> {
    match run(&[("/t/r.rs", src)], &["/t/r.rs"], &[], opts) {
        Outcome::Refused(r) => r.iter().map(|r| r.line).collect(),
        Outcome::Rewritten(f) => panic!("expected a refusal for {src:?}, got {f:?}"),
    }
}

#[test]
fn refuses_every_unmapped_test_spelling() {
    let cases = [
        "#[core::prelude::v1::test]\nfn f() {}\n",
        "#[std::prelude::v1::test]\nfn f() {}\n",
        "#[::core::prelude::v1::test]\nfn f() {}\n",
        "#[cfg_attr(unix, cfg_attr(all(), tokio::test))]\nfn f() {}\n",
        "#[cfg_attr(unix, core::prelude::v1::test)]\nfn f() {}\n",
        "some_macro! {\n    #[tokio::test]\n    async fn f() {}\n}\n",
        "cfg_if! { if #[cfg(unix)] { #[tokio::test] async fn f() {} } }\n",
        "macro_rules! m { ($c:meta) => { #[cfg_attr($c, test)] fn f() {} }; }\n",
    ];
    for src in cases {
        for only_tokio in [false, true] {
            let lines = refused_lines(
                src,
                Options {
                    only_tokio,
                    ..Options::default()
                },
            );
            assert!(!lines.is_empty(), "{src} (only_tokio = {only_tokio})");
        }
    }
}

#[test]
fn a_nested_cfg_attr_bare_test_is_refused_unless_only_tokio_leaves_bare_tests() {
    let src = "#[cfg_attr(unix, cfg_attr(all(), test))]\nfn f() {}\n";
    assert_eq!(refused_lines(src, Options::default()), [1]);
    let invoked = "some_macro! {\n    #[test]\n    fn f() {}\n}\n";
    assert_eq!(refused_lines(invoked, Options::default()), [2]);
    match run(
        &[("/t/r.rs", src)],
        &["/t/r.rs"],
        &[],
        Options {
            only_tokio: true,
            ..Options::default()
        },
    ) {
        Outcome::Rewritten(f) => assert!(f.is_empty()),
        Outcome::Refused(r) => panic!("{r:?}"),
    }
}

#[test]
fn an_invocation_carrying_only_skuld_or_other_attributes_is_not_refused() {
    let src = "some_macro! {\n    #[skuld::test]\n    #[should_panic]\n    fn f() {}\n}\n#[::core::prelude::v1::derive(Clone)]\nstruct S;\n";
    match run(&[("/t/r.rs", src)], &["/t/r.rs"], &[], Options::default()) {
        Outcome::Rewritten(f) => assert!(f.is_empty(), "{f:?}"),
        Outcome::Refused(r) => panic!("{r:?}"),
    }
}

#[test]
fn macro_rules_refusals_cover_unsupported_args_and_cfg_attr() {
    let a = "macro_rules! t { () => { #[tokio::test(flavor = \"multi_thread\")] async fn a() {} } }\n";
    assert_eq!(refused_lines(a, Options::default()), [1]);
    let b = "macro_rules! t {\n    () => {\n        #[cfg_attr(unix, test)]\n        fn a() {}\n    };\n}\n";
    assert_eq!(refused_lines(b, Options::default()), [3]);
}

#[test]
fn macro_rules_matcher_side_is_left_alone() {
    let src = "macro_rules! only_tests {\n    (#[test] fn $n:ident() $b:block) => {\n        #[test]\n        fn $n() $b\n    };\n}\n";
    let want = "macro_rules! only_tests {\n    (#[test] fn $n:ident() $b:block) => {\n        #[skuld::test]\n        fn $n() $b\n    };\n}\n";
    assert_eq!(one(src, Options::default()), want);
}

#[test]
fn a_bom_is_kept_and_does_not_shift_spans() {
    let src = "\u{feff}#[test]\nfn a() {}\n";
    assert_eq!(one(src, Options::default()), "\u{feff}#[skuld::test]\nfn a() {}\n");
    let src = "\u{feff}#![cfg(unix)]\n#[test]\nfn a() {}\n";
    assert_eq!(
        one(
            src,
            Options {
                hoist_crate_cfg: true,
                ..Options::default()
            }
        ),
        "\u{feff}#[cfg(unix)]\n#[skuld::test]\nfn a() {}\n"
    );
}

#[test]
fn a_comment_inside_a_rewritten_attribute_is_refused_but_one_after_it_is_kept() {
    let inside = "#[tokio::test( // why\n    flavor = \"current_thread\",\n)]\nasync fn a() {}\n";
    assert_eq!(refused_lines(inside, Options::default()), [1]);
    let block = "#[tokio::test(/* why */ flavor = \"current_thread\")]\nasync fn a() {}\n";
    assert_eq!(refused_lines(block, Options::default()), [1]);
    let after = "#[tokio::test] // why\nasync fn a() {}\n";
    assert_eq!(
        one(after, Options::default()),
        "#[skuld::test] // why\nasync fn a() {}\n"
    );
}

#[test]
fn hoists_two_crate_cfgs_in_order() {
    let src = "#![cfg(unix)]\n#![cfg(feature = \"tokio\")]\nfn a() {}\nfn b() {}\n";
    let want =
        "#[cfg(unix)]\n#[cfg(feature = \"tokio\")]\nfn a() {}\n#[cfg(unix)]\n#[cfg(feature = \"tokio\")]\nfn b() {}\n";
    assert_eq!(
        one(
            src,
            Options {
                hoist_crate_cfg: true,
                ..Options::default()
            }
        ),
        want
    );
}

#[test]
fn a_root_also_reached_as_a_module_is_still_hoisted() {
    let files = [("/t/r.rs", "mod m;\n"), ("/t/m.rs", "#![cfg(unix)]\nfn a() {}\n")];
    let out = rewritten(run(
        &files,
        &["/t/r.rs", "/t/m.rs"],
        &[],
        Options {
            hoist_crate_cfg: true,
            ..Options::default()
        },
    ));
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0], ("/t/m.rs".to_owned(), "#[cfg(unix)]\nfn a() {}\n".to_owned()));
}

#[test]
fn raw_identifier_spellings_map_or_refuse_like_the_plain_ones() {
    assert_eq!(
        one("#[r#test]\nfn a() {}\n", Options::default()),
        "#[skuld::test]\nfn a() {}\n"
    );
    assert_eq!(
        one("#[tokio::r#test]\nasync fn a() {}\n", Options::default()),
        "#[skuld::test]\nasync fn a() {}\n"
    );
    assert_eq!(
        one(
            "#[r#tokio::test(start_paused = true)]\nasync fn a() {}\n",
            Options::default()
        ),
        "#[skuld::test(runtime = crate::tokio::test_runtime::paused)]\nasync fn a() {}\n"
    );
    for src in [
        "#[cfg_attr(unix, r#test)]\nfn a() {}\n",
        "#[core::prelude::v1::r#test]\nfn a() {}\n",
        "macro_rules! m { () => { #[cfg_attr(unix, r#test)] fn a() {} }; }\n",
        "some_macro! { #[r#test] fn a() {} }\n",
    ] {
        assert_eq!(refused_lines(src, Options::default()).len(), 1, "{src}");
    }
}

fn rustfmt_clean(src: &str) -> bool {
    use std::io::Write;
    let mut child = std::process::Command::new("rustfmt")
        .args(["--check", "--edition", "2021"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(src.as_bytes()).unwrap();
    child.wait().unwrap().success()
}

#[test]
fn hoisting_leaves_no_blank_line_rustfmt_rejects() {
    let hoist = Options {
        hoist_crate_cfg: true,
        ..Options::default()
    };
    let cases = [
        (
            "#![cfg(unix)]\n\n#[test]\nfn a() {}\n",
            "#[cfg(unix)]\n#[skuld::test]\nfn a() {}\n",
        ),
        (
            "//! d\n\n#![cfg(unix)]\n\nuse std::io;\n",
            "//! d\n\n#[cfg(unix)]\nuse std::io;\n",
        ),
        (
            "#![cfg(unix)]\n#![cfg(feature = \"x\")]\n\nuse std::io;\n",
            "#[cfg(unix)]\n#[cfg(feature = \"x\")]\nuse std::io;\n",
        ),
        (
            "//! d\n#![cfg(unix)]\n\nuse std::io;\n",
            "//! d\n\n#[cfg(unix)]\nuse std::io;\n",
        ),
    ];
    for (src, want) in cases {
        assert!(rustfmt_clean(src), "input must be clean: {src:?}");
        let got = one(src, hoist);
        assert_eq!(got, want);
        assert!(rustfmt_clean(&got), "{got:?}");
    }
}

#[test]
fn hoisting_deletes_a_crlf_line_whole() {
    let src = "#![cfg(unix)]\r\n#[test]\r\nfn a() {}\r\n";
    assert_eq!(
        one(
            src,
            Options {
                hoist_crate_cfg: true,
                ..Options::default()
            }
        ),
        "#[cfg(unix)]\n#[skuld::test]\r\nfn a() {}\r\n"
    );
}

#[test]
fn an_unparseable_attribute_that_mentions_test_is_refused() {
    let src = "macro_rules! m {\n    ($m:meta) => {\n        #[$m test]\n        fn f() {}\n    };\n}\n";
    assert_eq!(refused_lines(src, Options::default()), [3]);
    let invoked = "some_macro! {\n    #[$m test]\n    fn f() {}\n}\n";
    assert_eq!(refused_lines(invoked, Options::default()), [2]);
    // One that does not mention `test` is somebody else's attribute.
    let other = "macro_rules! m {\n    ($m:meta) => {\n        #[$m other]\n        fn f() {}\n    };\n}\n";
    match run(&[("/t/r.rs", other)], &["/t/r.rs"], &[], Options::default()) {
        Outcome::Rewritten(f) => assert!(f.is_empty()),
        Outcome::Refused(r) => panic!("{r:?}"),
    }
}

#[test]
fn an_unflipped_root_that_is_also_applied_is_refused() {
    let files = [("/t/a.rs", "#[test]\nfn a() {}\n"), ("/t/b.rs", "#[test]\nfn b() {}\n")];
    let Outcome::Refused(r) = run(&files, &["/t/a.rs", "/t/b.rs"], &["/t/b.rs"], Options::default()) else {
        panic!("expected a refusal");
    };
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].path.as_path(), std::path::Path::new("/t/b.rs"));
    assert!(
        r[0].reason.contains("unflipped") && r[0].reason.contains("applied"),
        "{}",
        r[0].reason
    );
}

#[test]
fn an_unflipped_root_reached_through_an_applied_directory_is_refused() {
    use crate::modtree::Root;
    let src = MemSource::new(&[("/t/a.rs", "#[test]\nfn a() {}\n"), ("/t/b.rs", "#[test]\nfn b() {}\n")]);
    let roots = [
        Root::crate_root("/t/a.rs"),
        Root {
            path: "/t/b.rs".into(),
            mod_rs_like: true,
            is_root: false,
        },
    ];
    let out = crate::rewrite::apply_roots(&src, &roots, &[PathBuf::from("/t/b.rs")], Options::default()).unwrap();
    assert!(
        matches!(out, Outcome::Refused(r) if r.len() == 1 && r[0].path.as_path() == std::path::Path::new("/t/b.rs"))
    );
}

// Writing ---------------------------------------------------------------------------------------

fn planned(dir: &std::path::Path, name: &str, before: &str, after: &str) -> crate::rewrite::Planned {
    let path = dir.join(name);
    std::fs::write(&path, before).unwrap();
    crate::rewrite::Planned {
        path,
        before: before.to_owned(),
        after: after.to_owned(),
    }
}

fn names(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn commit_writes_every_file_and_leaves_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let files = [
        planned(dir.path(), "a.rs", "1", "one"),
        planned(dir.path(), "b.rs", "2", "two"),
    ];
    crate::rewrite::commit(&files).unwrap();
    assert_eq!(std::fs::read_to_string(dir.path().join("a.rs")).unwrap(), "one");
    assert_eq!(std::fs::read_to_string(dir.path().join("b.rs")).unwrap(), "two");
    assert_eq!(names(dir.path()), ["a.rs", "b.rs"]);
}

#[test]
fn commit_refuses_a_file_that_changed_since_it_was_planned_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let files = [
        planned(dir.path(), "a.rs", "1", "one"),
        planned(dir.path(), "b.rs", "2", "two"),
    ];
    std::fs::write(dir.path().join("b.rs"), "edited meanwhile").unwrap();
    let err = crate::rewrite::commit(&files).unwrap_err().to_string();
    assert!(err.contains("b.rs") && err.contains("changed"), "{err}");
    assert_eq!(std::fs::read_to_string(dir.path().join("a.rs")).unwrap(), "1");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("b.rs")).unwrap(),
        "edited meanwhile"
    );
    assert_eq!(names(dir.path()), ["a.rs", "b.rs"]);
}

#[test]
fn commit_writes_nothing_when_a_later_file_cannot_be_written() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let files = [
        planned(dir.path(), "a.rs", "1", "one"),
        planned(&sub, "b.rs", "2", "two"),
    ];
    std::fs::remove_dir_all(&sub).unwrap();
    assert!(crate::rewrite::commit(&files).is_err());
    assert_eq!(std::fs::read_to_string(dir.path().join("a.rs")).unwrap(), "1");
    assert_eq!(names(dir.path()), ["a.rs"]);
}
