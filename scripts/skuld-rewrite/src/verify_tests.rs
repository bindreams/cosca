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
