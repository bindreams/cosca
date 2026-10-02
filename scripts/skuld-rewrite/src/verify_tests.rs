use std::path::PathBuf;

use crate::rewrite::{apply, Options, Outcome};
use crate::test_util::MemSource;
use crate::verify::{verify, Mismatch};

const ROOT: &str = "/t/r.rs";

fn check(old: &str, new: &str) -> Vec<String> {
    let roots = [PathBuf::from(ROOT)];
    verify(&MemSource::new(&[(ROOT, old)]), &MemSource::new(&[(ROOT, new)]), &roots)
        .unwrap()
        .into_iter()
        .map(|m| m.to_string())
        .collect()
}

fn check_with(old: &[(&str, &str)], new: &[(&str, &str)]) -> Vec<String> {
    let roots = [PathBuf::from(ROOT)];
    verify(&MemSource::new(old), &MemSource::new(new), &roots)
        .unwrap()
        .into_iter()
        .map(|m| m.to_string())
        .collect()
}

fn rewrite(src: &str, opts: Options) -> String {
    let files = MemSource::new(&[(ROOT, src)]);
    match apply(&files, &[PathBuf::from(ROOT)], &[], opts).unwrap() {
        Outcome::Rewritten(mut f) => f.pop().map_or_else(|| src.to_owned(), |p| p.after),
        Outcome::Refused(r) => panic!("{r:?}"),
    }
}

const OLD: &str = "#![cfg(all(windows, feature = \"tokio\"))]\nuse std::io;\n#[tokio::test(start_paused = true)]\n#[should_panic(expected = \"boom\")]\nasync fn a() { panic!(\"boom\") }\n#[tokio::test(flavor = \"current_thread\")]\n#[ignore]\nasync fn b() {}\n#[test]\nfn c() {}\nmacro_rules! t { () => { # [ test ] fn m() {} } }\n";

#[test]
fn an_applied_rewrite_verifies() {
    let new = rewrite(
        OLD,
        Options {
            hoist_crate_cfg: true,
            ..Options::default()
        },
    );
    assert_eq!(check(OLD, &new), Vec::<String>::new());
}

#[test]
fn a_flip_with_main_net_and_include_verifies() {
    let old = "#![cfg(unix)]\n#[test]\nfn a() {}\n";
    let new = "#[cfg(unix)]\n#[macro_use]\nextern crate skuld;\n#[path = \"../src/test_harness.rs\"]\nmod test_harness;\n#[cfg(unix)]\n#[skuld::test]\nfn a() {}\nfn main() {\n    let mut runner = skuld::TestRunner::new();\n    runner.libtest_names();\n    runner.run()\n}\n";
    assert_eq!(
        check_with(&[(ROOT, old)], &[(ROOT, new), ("/src/test_harness.rs", "")]),
        Vec::<String>::new()
    );
}

#[test]
fn formatting_and_comments_do_not_matter() {
    let new = "// c\n#[ test ]\nfn a(){ }\n";
    assert_eq!(
        check(
            "#[test]\nfn a() {}\n",
            new.replace("#[ test ]", "#[skuld::test]").as_str()
        ),
        Vec::<String>::new()
    );
}

#[test]
fn verify_fails_on_a_dropped_start_paused() {
    let old = "#[tokio::test(start_paused = true)]\nasync fn a() {}\n";
    let new = "#[skuld::test]\nasync fn a() {}\n";
    let got = check(old, new);
    assert_eq!(got.len(), 1, "{got:?}");
    assert!(got[0].contains("/t/r.rs") && got[0].contains("item 0"), "{got:?}");
}

#[test]
fn verify_fails_on_paused_moved_to_another_fn() {
    let old = "#[tokio::test(start_paused = true)]\nasync fn a() {}\n#[tokio::test]\nasync fn b() {}\n";
    let new = "#[skuld::test]\nasync fn a() {}\n#[skuld::test(runtime = crate::tokio::test_runtime::paused)]\nasync fn b() {}\n";
    assert_eq!(check(old, new).len(), 1);
}

#[test]
fn verify_fails_on_a_changed_should_panic_message() {
    let old = "#[test]\n#[should_panic(expected = \"boom\")]\nfn a() {}\n";
    let new = "#[skuld::test]\n#[should_panic(expected = \"bang\")]\nfn a() {}\n";
    assert_eq!(check(old, new).len(), 1);
}

#[test]
fn verify_fails_on_a_dropped_ignore_a_dropped_test_and_an_unhoisted_cfg_leftover() {
    assert_eq!(
        check("#[test]\n#[ignore]\nfn a() {}\n", "#[skuld::test]\nfn a() {}\n").len(),
        1
    );
    assert_eq!(
        check(
            "#[test]\nfn a() {}\n#[test]\nfn b() {}\n",
            "#[skuld::test]\nfn a() {}\n"
        )
        .len(),
        1
    );
    // A cfg the old crate did not have, added to every item, is a change.
    assert_eq!(check("fn a() {}\n", "#[cfg(unix)]\nfn a() {}\n").len(), 1);
    // A crate cfg that was dropped rather than hoisted is a change.
    assert_eq!(check("#![cfg(unix)]\nfn a() {}\n", "fn a() {}\n").len(), 1);
}

#[test]
fn verify_fails_on_a_dropped_macro_rules_runtime() {
    let old = "macro_rules! t { () => { #[tokio::test(start_paused = true)] async fn m() {} } }\n";
    let new = "macro_rules! t { () => { #[skuld::test] async fn m() {} } }\n";
    assert_eq!(check(old, new).len(), 1);
}

#[test]
fn a_file_only_one_revision_reaches_is_a_mismatch() {
    let roots = [PathBuf::from(ROOT)];
    let old = MemSource::new(&[(ROOT, "mod m;\n"), ("/t/m.rs", "")]);
    let new = MemSource::new(&[
        (ROOT, "mod m;\n#[path = \"n.rs\"] mod n;\n"),
        ("/t/m.rs", ""),
        ("/t/n.rs", ""),
    ]);
    let got = verify(&old, &new, &roots).unwrap();
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(
        got[0],
        Mismatch {
            path: "/t/n.rs".into(),
            detail: "reachable in the new revision only".into()
        }
    );
    assert_eq!(got[1].path.as_path(), std::path::Path::new("/t/r.rs"));
    assert!(got[1].detail.starts_with("item 1 differs"), "{}", got[1].detail);
}

fn mismatches(old: &[(&str, &str)], new: &[(&str, &str)]) -> usize {
    let roots = [PathBuf::from(ROOT)];
    verify(&MemSource::new(old), &MemSource::new(new), &roots)
        .unwrap()
        .len()
}

#[test]
fn an_unsupported_old_spelling_never_equals_a_new_skuld_test() {
    let old = "#[tokio::test(flavor = \"multi_thread\")]\nasync fn a() {}\n";
    assert_eq!(check(old, "#[skuld::test]\nasync fn a() {}\n").len(), 1);
}

#[test]
fn skuld_test_arguments_are_part_of_the_comparison() {
    assert_eq!(
        check("#[test]\nfn a() {}\n", "#[skuld::test(serial)]\nfn a() {}\n").len(),
        1
    );
    assert_eq!(
        check(
            "#[test]\nfn a() {}\n",
            "#[skuld::test(runtime = foo::bar)]\nfn a() {}\n"
        )
        .len(),
        1
    );
}

#[test]
fn a_hoisted_cfg_must_carry_the_same_predicate() {
    let old = "#![cfg(unix)]\nfn a() {}\n";
    assert_eq!(check(old, "#[cfg(windows)]\nfn a() {}\n").len(), 1);
    assert_eq!(check(old, "#[cfg(unix)]\nfn a() {}\n"), Vec::<String>::new());
}

#[test]
fn an_existing_main_is_compared_not_dropped() {
    let old = "fn main() { run() }\n";
    assert_eq!(check(old, "fn main() { run() }\n"), Vec::<String>::new());
    assert_eq!(check(old, "fn main() { std::process::exit(1) }\n").len(), 1);
    assert_eq!(check(old, "").len(), 1);
}

#[test]
fn a_file_only_the_old_revision_reaches_is_reported() {
    let roots = [PathBuf::from(ROOT)];
    let old = MemSource::new(&[(ROOT, "mod m;\n"), ("/t/m.rs", "")]);
    let new = MemSource::new(&[(ROOT, "")]);
    let got = verify(&old, &new, &roots).unwrap();
    assert!(got.iter().any(|m| m.detail.contains("old revision only")), "{got:?}");
}

#[test]
fn the_net_and_include_are_kept_when_the_old_revision_had_them() {
    let old = "#[macro_use]\nextern crate skuld;\n#[path = \"../src/test_harness.rs\"]\nmod test_harness;\n";
    assert_eq!(
        mismatches(
            &[(ROOT, old), ("/src/test_harness.rs", "")],
            &[(ROOT, old), ("/src/test_harness.rs", "")]
        ),
        0
    );
    assert_eq!(
        mismatches(&[(ROOT, old), ("/src/test_harness.rs", "")], &[(ROOT, "")]),
        1
    );
}

#[test]
fn tests_nested_in_fn_bodies_are_canonicalised() {
    let old = "fn f() {\n    #[tokio::test(start_paused = true)]\n    async fn n() {}\n}\n";
    let new = "fn f() {\n    #[skuld::test(runtime = crate::tokio::test_runtime::paused)]\n    async fn n() {}\n}\n";
    assert_eq!(check(old, new), Vec::<String>::new());
}

#[test]
fn crate_cfg_position_among_inner_attributes_does_not_matter() {
    let old = "#![cfg(unix)]\n#![allow(dead_code)]\nfn a() {}\n";
    let new = rewrite(
        old,
        Options {
            hoist_crate_cfg: true,
            ..Options::default()
        },
    );
    assert_eq!(check(old, &new), Vec::<String>::new());
    let old = "#![allow(dead_code)]\n#![cfg(unix)]\nfn a() {}\n";
    let new = rewrite(
        old,
        Options {
            hoist_crate_cfg: true,
            ..Options::default()
        },
    );
    assert_eq!(check(old, &new), Vec::<String>::new());
}

#[test]
fn two_hoisted_crate_cfgs_verify() {
    let old = "#![cfg(unix)]\n#![cfg(feature = \"tokio\")]\n#[test]\nfn a() {}\nfn b() {}\n";
    let new = rewrite(
        old,
        Options {
            hoist_crate_cfg: true,
            ..Options::default()
        },
    );
    assert_eq!(check(old, &new), Vec::<String>::new());
}

#[test]
fn a_root_with_a_main_and_a_crate_cfg_round_trips() {
    let old = "#![cfg(unix)]\n#[test]\nfn a() {}\nfn main() { run() }\n";
    let new = rewrite(
        old,
        Options {
            hoist_crate_cfg: true,
            ..Options::default()
        },
    );
    assert_eq!(check(old, &new), Vec::<String>::new());
}

#[test]
fn a_flip_with_the_k1_main_verifies() {
    let old = "#[test]\nfn a() {}\n";
    let new = "#[skuld::test]\nfn a() {}\nfn main() {\n    let mut runner = skuld::TestRunner::new();\n    runner.libtest_names();\n    runner.require_known_labels();\n    runner.run()\n}\n";
    assert_eq!(check(old, new), Vec::<String>::new());
}

#[test]
fn only_the_exact_additions_are_forgiven() {
    let old = "#[test]\nfn a() {}\n";
    let base = "#[skuld::test]\nfn a() {}\n";
    let bad = [
        format!("{base}pub fn main() {{ std::process::exit(1) }}\n"),
        format!("{base}fn main() {{ let mut runner = skuld::TestRunner::new(); runner.libtest_names(); evil(); runner.run() }}\n"),
        format!("{base}mod test_harness {{ #[skuld::test] fn smuggled() {{ panic!() }} }}\n"),
        format!("{base}extern crate skuld as tokio;\n"),
    ];
    for new in &bad {
        assert_eq!(check(old, new).len(), 1, "{new}");
    }
    // A repointed include pulls another file's tests in.
    let new = format!("{base}#[path = \"b.rs\"]\nmod test_harness;\n");
    let got = details(&[(ROOT, old)], &[(ROOT, &new), ("/t/b.rs", "")], ROOT);
    assert_eq!(
        got,
        [
            ("/t/b.rs".to_owned(), "reachable in the new revision only".to_owned()),
            ("/t/r.rs".to_owned(), "item 1 differs".to_owned())
        ]
    );
}

#[test]
fn additions_are_forgiven_only_in_roots() {
    let old = [(ROOT, "mod common;\n"), ("/t/common.rs", "pub fn f() {}\n")];
    let with_main = [
        (ROOT, "mod common;\n"),
        (
            "/t/common.rs",
            "pub fn f() {}\npub fn main() { std::process::exit(1) }\n",
        ),
    ];
    assert_eq!(mismatches(&old, &with_main), 1);
    let with_net = [
        (ROOT, "mod common;\n"),
        ("/t/common.rs", "pub fn f() {}\nextern crate skuld;\n"),
    ];
    assert_eq!(mismatches(&old, &with_net), 1);
}

#[test]
fn a_root_also_reached_as_a_module_is_still_a_root_for_additions() {
    let main = "fn main() {\n    let mut runner = skuld::TestRunner::new();\n    runner.libtest_names();\n    runner.run()\n}\n";
    let old = MemSource::new(&[(ROOT, "mod m;\n"), ("/t/m.rs", "fn a() {}\n")]);
    let new = MemSource::new(&[(ROOT, "mod m;\n"), ("/t/m.rs", &format!("fn a() {{}}\n{main}"))]);
    let roots = [PathBuf::from(ROOT), PathBuf::from("/t/m.rs")];
    assert_eq!(verify(&old, &new, &roots).unwrap(), Vec::new());
}

#[test]
fn a_smuggled_include_that_is_not_src_test_harness_is_a_mismatch() {
    let root = "/t/tests/r.rs";
    let old = [(root, "#[test]\nfn a() {}\n")];
    let base = "#[skuld::test]\nfn a() {}\n";
    // Right shape, wrong resolved file.
    let wrong = format!("{base}#[path = \"../tests/src/test_harness.rs\"]\nmod test_harness;\n");
    let got = details(&old, &[(root, &wrong), ("/t/tests/src/test_harness.rs", "")], root);
    assert_eq!(
        got,
        [
            ("/t/tests/r.rs".to_owned(), "item 1 differs".to_owned()),
            (
                "/t/tests/src/test_harness.rs".to_owned(),
                "reachable in the new revision only".to_owned()
            )
        ]
    );
    // Pathless, so it resolves under `tests/`.
    let pathless = format!("{base}mod test_harness;\n");
    let got = details(&old, &[(root, &pathless), ("/t/tests/test_harness.rs", "")], root);
    assert_eq!(
        got,
        [
            ("/t/tests/r.rs".to_owned(), "item 1 differs".to_owned()),
            (
                "/t/tests/test_harness.rs".to_owned(),
                "reachable in the new revision only".to_owned()
            )
        ]
    );
    // The planned include, with its file, is forgiven.
    let planned = format!("{base}#[path = \"../src/test_harness.rs\"]\nmod test_harness;\n");
    assert_eq!(
        details(&old, &[(root, &planned), ("/t/src/test_harness.rs", "")], root),
        []
    );
}

/// `(path, first line of detail)` per mismatch, sorted, with every root in `flipped`.
fn details(old: &[(&str, &str)], new: &[(&str, &str)], root: &str) -> Vec<(String, String)> {
    details_with(old, new, root, true)
}

fn details_with(old: &[(&str, &str)], new: &[(&str, &str)], root: &str, flipped: bool) -> Vec<(String, String)> {
    use std::collections::BTreeSet;
    let set: BTreeSet<PathBuf> = if flipped {
        [PathBuf::from(root)].into()
    } else {
        BTreeSet::new()
    };
    let roots = [crate::modtree::Root::crate_root(root)];
    let mut got: Vec<(String, String)> =
        crate::verify::verify_roots(&MemSource::new(old), &MemSource::new(new), &roots, &set)
            .unwrap()
            .into_iter()
            .map(|m| {
                (
                    m.path.to_string_lossy().into_owned(),
                    m.detail.lines().next().unwrap_or("").trim_end_matches(':').to_owned(),
                )
            })
            .collect();
    got.sort();
    got
}

// The label include -----------------------------------------------------------------------------

const TROOT: &str = "/t/tests/r.rs";
const HARNESS: &str = "/t/src/test_harness.rs";
const INCLUDE: &str = "#[path = \"../src/test_harness.rs\"]\nmod test_harness;\n";

#[test]
fn only_a_flipped_root_may_gain_the_include() {
    let old = [(TROOT, "#[test]\nfn a() {}\n")];
    let new_text = format!("#[skuld::test]\nfn a() {{}}\n{INCLUDE}");
    let new = [(TROOT, new_text.as_str()), (HARNESS, "")];
    assert_eq!(details_with(&old, &new, TROOT, true), []);
    let got = details_with(&old, &new, TROOT, false);
    assert_eq!(got, [(TROOT.to_owned(), "item 1 differs".to_owned())]);
}

#[test]
fn the_added_harness_file_holds_only_label_declarations() {
    let old = [(TROOT, "#[test]\nfn a() {}\n")];
    let new_text = format!("#[skuld::test]\nfn a() {{}}\n{INCLUDE}");
    let ok = "use skuld::Label;\n#[skuld::label] pub const SLOW: skuld::Label;\n#[skuld::label] pub const DOCKER: skuld::Label;\nskuld::default_labels!(SLOW);\n";
    assert_eq!(details(&old, &[(TROOT, new_text.as_str()), (HARNESS, ok)], TROOT), []);
    for bad in [
        "pub fn anything() { std::process::exit(3) }\n",
        "#[skuld::test] fn smuggled() { panic!() }\n",
        "#[skuld::label] pub const SLOW: skuld::Label;\nstatic X: u8 = 0;\n",
        "mod inner { pub fn f() {} }\n",
    ] {
        let got = details(&old, &[(TROOT, new_text.as_str()), (HARNESS, bad)], TROOT);
        assert_eq!(
            got,
            [(HARNESS.to_owned(), "unexpected item in the label file".to_owned())],
            "{bad}"
        );
    }
}

#[test]
fn an_include_without_its_file_is_a_mismatch() {
    let old = [(TROOT, "#[test]\nfn a() {}\n")];
    let new_text = format!("#[skuld::test]\nfn a() {{}}\n{INCLUDE}");
    let got = details(&old, &[(TROOT, new_text.as_str())], TROOT);
    assert_eq!(
        got,
        [(
            HARNESS.to_owned(),
            "the include names a file that does not exist".to_owned()
        )]
    );
}

#[test]
fn a_harness_file_the_old_revision_had_is_compared() {
    let root = format!("#[skuld::test]\nfn a() {{}}\n{INCLUDE}");
    let old = [
        (TROOT, root.as_str()),
        (HARNESS, "#[skuld::label] pub const SLOW: skuld::Label;\n"),
    ];
    let same = [
        (TROOT, root.as_str()),
        (HARNESS, "#[skuld::label] pub const SLOW: skuld::Label;\n"),
    ];
    assert_eq!(details(&old, &same, TROOT), []);
    let changed = [
        (TROOT, root.as_str()),
        (HARNESS, "#[skuld::label] pub const FAST: skuld::Label;\n"),
    ];
    assert_eq!(
        details(&old, &changed, TROOT),
        [(HARNESS.to_owned(), "item 0 differs".to_owned())]
    );
}

// Macro bodies ----------------------------------------------------------------------------------

#[test]
fn an_unparseable_attribute_in_a_macro_body_is_compared_as_it_is() {
    let a = "macro_rules! m { ($m:meta) => { #[$m test] fn f() {} }; }\n";
    assert_eq!(check(a, a), Vec::<String>::new());
    let b = "macro_rules! m { ($m:meta) => { #[$m test2] fn f() {} }; }\n";
    assert_eq!(check(a, b).len(), 1);
}

// Target sets -----------------------------------------------------------------------------------

fn key(name: &str) -> crate::verify::TargetKey {
    crate::verify::TargetKey {
        name: name.to_owned(),
        kinds: vec!["test".to_owned()],
        src: format!("tests/{name}.rs").into(),
        test: true,
        doctest: false,
        required_features: Vec::new(),
        bench: None,
        edition: "2021".to_owned(),
        harness: true,
    }
}

fn text(m: Vec<Mismatch>) -> Vec<String> {
    m.into_iter()
        .map(|m| format!("{}: {}", m.path.display(), m.detail))
        .collect()
}

#[test]
fn target_mismatches_names_what_differs() {
    use crate::verify::target_mismatches;
    let a = key("a");
    assert_eq!(
        text(target_mismatches(std::slice::from_ref(&a), std::slice::from_ref(&a))),
        Vec::<String>::new()
    );
    for (field, changed) in [
        (
            "edition",
            crate::verify::TargetKey {
                edition: "2015".into(),
                ..a.clone()
            },
        ),
        (
            "test",
            crate::verify::TargetKey {
                test: false,
                ..a.clone()
            },
        ),
        (
            "doctest",
            crate::verify::TargetKey {
                doctest: true,
                ..a.clone()
            },
        ),
        (
            "bench",
            crate::verify::TargetKey {
                bench: Some(true),
                ..a.clone()
            },
        ),
        (
            "required_features",
            crate::verify::TargetKey {
                required_features: vec!["x".into()],
                ..a.clone()
            },
        ),
        (
            "kinds",
            crate::verify::TargetKey {
                kinds: vec!["bench".into()],
                ..a.clone()
            },
        ),
        (
            "src",
            crate::verify::TargetKey {
                src: "tests/other.rs".into(),
                ..a.clone()
            },
        ),
    ] {
        let got = text(target_mismatches(std::slice::from_ref(&a), &[changed]));
        assert_eq!(got.len(), 1, "{field}: {got:?}");
        assert!(got[0].contains(&format!("differs in {field}")), "{field}: {got:?}");
    }
}

#[test]
fn target_mismatches_reports_added_and_deleted_targets() {
    use crate::verify::target_mismatches;
    let got = text(target_mismatches(&[key("a"), key("b")], &[key("a"), key("c")]));
    assert_eq!(
        got,
        [
            "tests/b.rs: target `b` (test) is missing in the new revision",
            "tests/c.rs: target `c` (test) is missing in the old revision"
        ]
    );
}

#[test]
fn the_harness_may_be_switched_off_but_never_back_on() {
    use crate::verify::{target_mismatches, TargetKey};
    let off = |n: &str| TargetKey {
        harness: false,
        ..key(n)
    };
    assert_eq!(text(target_mismatches(&[key("a")], &[off("a")])), Vec::<String>::new());
    assert_eq!(text(target_mismatches(&[off("a")], &[off("a")])), Vec::<String>::new());
    // One target flips legitimately while another is switched back on.
    let got = text(target_mismatches(&[key("a"), off("b")], &[off("a"), key("b")]));
    assert_eq!(
        got,
        ["tests/b.rs: target `b` (test) had `harness = false` and now has the default harness"]
    );
}

#[test]
fn feature_tables_are_compared_per_package() {
    use crate::verify::{feature_mismatches, Features};
    let table = |pairs: &[(&str, &[&str])]| -> std::collections::BTreeMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.iter().map(|s| (*s).to_owned()).collect()))
            .collect()
    };
    let old: Features = [("toy".to_owned(), table(&[("x", &[]), ("default", &["x"])]))].into();
    assert_eq!(text(feature_mismatches(&old, &old)), Vec::<String>::new());
    let new: Features = [("toy".to_owned(), table(&[("x", &[])]))].into();
    let got = text(feature_mismatches(&old, &new));
    assert_eq!(got.len(), 1, "{got:?}");
    assert!(got[0].contains("toy") && got[0].contains("features"), "{got:?}");
    let renamed: Features = [("other".to_owned(), table(&[("x", &[])]))].into();
    assert_eq!(feature_mismatches(&old, &renamed).len(), 2);
}

#[test]
fn a_failed_archive_is_reported_as_git_failing() {
    let dir = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let err = crate::verify::extract_archive(dir.path(), &"0".repeat(40), dest.path()).unwrap_err();
    assert!(format!("{err:#}").contains("git archive"), "{err:#}");
}
