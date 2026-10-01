use std::path::PathBuf;

use crate::rewrite::{apply, Options, Outcome};
use crate::test_util::MemSource;
use crate::verify::verify;

const ROOT: &str = "/t/r.rs";

fn check(old: &str, new: &str) -> Vec<String> {
    let roots = [PathBuf::from(ROOT)];
    verify(&MemSource::new(&[(ROOT, old)]), &MemSource::new(&[(ROOT, new)]), &roots)
        .unwrap()
        .into_iter()
        .map(|m| m.to_string())
        .collect()
}

fn rewrite(src: &str, opts: Options) -> String {
    let files = MemSource::new(&[(ROOT, src)]);
    match apply(&files, &[PathBuf::from(ROOT)], &[], opts).unwrap() {
        Outcome::Rewritten(mut f) => f.pop().map_or_else(|| src.to_owned(), |(_, t)| t),
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
    assert_eq!(check(old, new), Vec::<String>::new());
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
    assert!(got.len() >= 2, "{got:?}");
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
        // A main that does something else.
        format!("{base}pub fn main() {{ std::process::exit(1) }}\n"),
        // The runner chain with an extra statement.
        format!("{base}fn main() {{ let mut runner = skuld::TestRunner::new(); runner.libtest_names(); evil(); runner.run() }}\n"),
        // An inline module named like the include, smuggling a test.
        format!("{base}mod test_harness {{ #[skuld::test] fn smuggled() {{ panic!() }} }}\n"),
        // A renamed net.
        format!("{base}extern crate skuld as tokio;\n"),
    ];
    for new in &bad {
        assert_eq!(check(old, new).len(), 1, "{new}");
    }
    // A repointed include pulls another file's tests in.
    let new = format!("{base}#[path = \"b.rs\"]\nmod test_harness;\n");
    assert!(mismatches(&[(ROOT, old)], &[(ROOT, &new), ("/t/b.rs", "")]) >= 1);
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
    let old = [("/t/tests/r.rs", "#[test]\nfn a() {}\n")];
    let roots = [PathBuf::from("/t/tests/r.rs")];
    let run = |new: &[(&str, &str)]| {
        verify(&MemSource::new(&old), &MemSource::new(new), &roots)
            .unwrap()
            .len()
    };
    let base = "#[skuld::test]\nfn a() {}\n";
    // Right shape, wrong resolved file.
    let wrong = format!("{base}#[path = \"../tests/src/test_harness.rs\"]\nmod test_harness;\n");
    assert!(
        run(&[
            ("/t/tests/r.rs", &wrong),
            ("/t/tests/src/test_harness.rs", "#[skuld::test] fn smuggled() {}\n")
        ]) >= 1
    );
    // Pathless, so it resolves under `tests/`.
    let pathless = format!("{base}mod test_harness;\n");
    assert!(
        run(&[
            ("/t/tests/r.rs", &pathless),
            ("/t/tests/test_harness.rs", "#[skuld::test] fn smuggled() {}\n")
        ]) >= 1
    );
    // The planned include is forgiven.
    let planned = format!("{base}#[path = \"../src/test_harness.rs\"]\nmod test_harness;\n");
    assert_eq!(run(&[("/t/tests/r.rs", &planned)]), 0);
}

const EXACT_MAIN: &str =
    "fn main() {\n    let mut runner = skuld::TestRunner::new();\n    runner.libtest_names();\n    runner.run()\n}\n";

#[test]
fn an_exact_main_the_old_revision_had_is_compared_not_dropped() {
    assert_eq!(check(EXACT_MAIN, EXACT_MAIN), Vec::<String>::new());
    assert_eq!(check(EXACT_MAIN, "").len(), 1);
}

#[test]
fn a_decorated_main_or_net_is_not_forgiven() {
    let old = "#[test]\nfn a() {}\n";
    let base = "#[skuld::test]\nfn a() {}\n";
    for extra in [
        format!("#[inline]\n{EXACT_MAIN}"),
        format!("pub {EXACT_MAIN}"),
        "#[deprecated]\nextern crate skuld;\n".to_owned(),
    ] {
        assert_eq!(check(old, &format!("{base}{extra}")).len(), 1, "{extra}");
    }
    // The shapes the units add: `cfg` on main, `macro_use`/`allow`/`cfg` on the net.
    let ok = format!("{base}#[cfg(test)]\n{EXACT_MAIN}#[cfg(test)]\n#[allow(unused_imports, reason = \"net\")]\n#[macro_use]\nextern crate skuld;\n");
    assert_eq!(check(old, &ok), Vec::<String>::new());
}
