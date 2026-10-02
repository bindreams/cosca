//! The binary end to end, on toy repositories.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_skuld-rewrite");

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn write(dir: &Path, rel: &str, text: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// A committed toy crate with targets `a` and `b` that share `tests/common/mod.rs`.
fn toy() -> (tempfile::TempDir, PathBuf) {
    toy_with("")
}

/// `toy`, with `extra` appended to the committed manifest.
fn toy_with(extra: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    write(
        &root,
        "Cargo.toml",
        &format!(
            "[package]\nname = \"toy\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[features]\nx = []\n\n[workspace]\n{extra}"
        ),
    );
    write(&root, "src/lib.rs", "mod quote;\n");
    write(&root, "src/quote.rs", "mod applescript;\n#[test]\nfn q() {}\n");
    write(&root, "src/quote/applescript.rs", "#[test]\nfn t() {}\n");
    write(&root, "tests/a.rs", "mod common;\n#[test]\nfn a() {}\n");
    write(&root, "tests/b.rs", "mod common;\n#[test]\nfn will_vanish() {}\n");
    write(&root, "tests/common/mod.rs", "#[test]\nfn shared() {}\n");
    git(&root, &["init", "-q"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-q", "-m", "base"]);
    (dir, root)
}

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(BIN).current_dir(root).args(args).output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Runs `args`, expects exit 1, and returns what it printed.
fn mismatch(root: &Path, args: &[&str]) -> String {
    let out = run(root, args);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    stderr(&out)
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

#[test]
fn verify_passes_on_an_unchanged_tree() {
    let (_d, root) = toy();
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 0);
}

#[test]
fn verify_fails_when_a_target_is_deleted() {
    let (_d, root) = toy();
    std::fs::remove_file(root.join("tests/b.rs")).unwrap();
    let err = mismatch(&root, &["verify", "HEAD"]);
    assert!(
        err.contains("tests/b.rs: target `b` (test) is missing in the new revision"),
        "{err}"
    );
}

#[test]
fn verify_fails_when_a_target_is_repointed() {
    let (_d, root) = toy();
    let manifest = root.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(
        &manifest,
        format!("{text}\n[[test]]\nname = \"b\"\npath = \"tests/a.rs\"\n"),
    )
    .unwrap();
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 1);
}

#[test]
fn verify_fails_when_a_target_is_added() {
    let (_d, root) = toy();
    write(&root, "tests/c.rs", "#[test]\nfn c() {}\n");
    let err = mismatch(&root, &["verify", "HEAD"]);
    assert!(
        err.contains("tests/c.rs: target `c` (test) is missing in the old revision"),
        "{err}"
    );
}

#[test]
fn apply_then_verify_round_trips_the_toy() {
    let (_d, root) = toy();
    assert_eq!(
        code(&run(&root, &["apply", "src/lib.rs", "tests/a.rs", "tests/b.rs"])),
        0
    );
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 0);
}

#[test]
fn unflipped_target_names_are_looked_up_in_the_manifest() {
    let (_d, root) = toy();
    write(&root, "unflipped.txt", "# targets still on libtest\nb\n");
    let before = std::fs::read_to_string(root.join("tests/common/mod.rs")).unwrap();
    let out = run(&root, &["apply", "--unflipped", "unflipped.txt", "tests/a.rs"]);
    assert_eq!(code(&out), 2, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("tests/common/mod.rs"));
    // Nothing is written on a refusal.
    assert_eq!(
        std::fs::read_to_string(root.join("tests/common/mod.rs")).unwrap(),
        before
    );
    assert!(std::fs::read_to_string(root.join("tests/a.rs"))
        .unwrap()
        .contains("#[test]"));
}

/// The guard's `unflipped.txt` names targets as `<kind>:<name>`.
#[test]
fn unflipped_kind_name_entries_are_looked_up_in_the_manifest() {
    let (_d, root) = toy();
    write(&root, "unflipped.txt", "test:b\n");
    let out = run(&root, &["apply", "--unflipped", "unflipped.txt", "tests/a.rs"]);
    assert_eq!(code(&out), 2, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("tests/common/mod.rs"));
    // A kind that does not match the target's own is an error, not a silent pass.
    write(&root, "unflipped.txt", "lib:b\n");
    let out = run(&root, &["apply", "--unflipped", "unflipped.txt", "tests/a.rs"]);
    assert_eq!(code(&out), 2);
    assert!(String::from_utf8_lossy(&out.stderr).contains("lib:b"));
}

#[test]
fn unflipped_paths_work_and_a_name_that_matches_nothing_is_an_error() {
    let (_d, root) = toy();
    write(&root, "unflipped.txt", "tests/b.rs\n");
    assert_eq!(
        code(&run(&root, &["apply", "--unflipped", "unflipped.txt", "tests/a.rs"])),
        2
    );
    write(&root, "unflipped.txt", "nosuch\n");
    let out = run(&root, &["apply", "--unflipped", "unflipped.txt", "tests/a.rs"]);
    assert_eq!(code(&out), 2);
    assert!(String::from_utf8_lossy(&out.stderr).contains("nosuch"));
}

#[test]
fn an_unflipped_name_that_shares_nothing_lets_apply_through() {
    let (_d, root) = toy();
    write(&root, "unflipped.txt", "toy\n");
    assert_eq!(
        code(&run(&root, &["apply", "--unflipped", "unflipped.txt", "tests/a.rs"])),
        0
    );
    assert!(std::fs::read_to_string(root.join("tests/a.rs"))
        .unwrap()
        .contains("#[skuld::test]"));
}

fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap()
}

fn append_manifest(root: &Path, text: &str) {
    let manifest = root.join("Cargo.toml");
    let old = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(&manifest, format!("{old}\n{text}")).unwrap();
}

// A changed file is a change ---------------------------------------------------------------------

#[test]
fn verify_fails_when_a_root_file_changes() {
    let (_d, root) = toy();
    write(&root, "tests/a.rs", "mod common;\n#[test]\nfn a() { panic!() }\n");
    let err = mismatch(&root, &["verify", "HEAD"]);
    assert!(err.contains("tests/a.rs: item 1 differs"), "{err}");
}

#[test]
fn verify_fails_when_a_module_file_changes() {
    let (_d, root) = toy();
    write(&root, "tests/common/mod.rs", "#[test]\nfn shared() { panic!() }\n");
    let err = mismatch(&root, &["verify", "HEAD"]);
    assert!(err.contains("tests/common/mod.rs: item 0 differs"), "{err}");
    let (_d, root) = toy();
    write(&root, "src/quote/applescript.rs", "#[test]\nfn t() { panic!() }\n");
    let err = mismatch(&root, &["verify", "HEAD"]);
    assert!(err.contains("src/quote/applescript.rs: item 0 differs"), "{err}");
}

// Modules and directories -----------------------------------------------------------------------

#[test]
fn a_module_file_given_directly_resolves_its_children_as_a_module() {
    let (_d, root) = toy();
    let out = run(&root, &["apply", "src/quote.rs"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(read(&root, "src/quote.rs").contains("#[skuld::test]"));
    assert!(read(&root, "src/quote/applescript.rs").contains("#[skuld::test]"));
    assert!(read(&root, "tests/a.rs").contains("#[test]"));
}

#[test]
fn a_directory_applies_to_every_rs_file_under_it() {
    let (_d, root) = toy();
    let out = run(&root, &["apply", "src/quote"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(read(&root, "src/quote/applescript.rs").contains("#[skuld::test]"));
    assert!(read(&root, "src/quote.rs").contains("#[test]"));
}

#[test]
fn a_directory_of_crate_roots_resolves_their_modules_as_a_root_would() {
    let (_d, root) = toy();
    let out = run(&root, &["apply", "src", "tests"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    for f in [
        "src/quote.rs",
        "src/quote/applescript.rs",
        "tests/a.rs",
        "tests/b.rs",
        "tests/common/mod.rs",
    ] {
        assert!(!read(&root, f).contains("#[test]"), "{f}");
    }
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 0);
}

// Every libtest-visible target field ------------------------------------------------------------

#[test]
fn verify_fails_when_a_target_is_disabled_or_gated() {
    for (extra, field) in [
        ("[[test]]\nname = \"b\"\npath = \"tests/b.rs\"\ntest = false\n", "test"),
        (
            "[[test]]\nname = \"b\"\npath = \"tests/b.rs\"\nrequired-features = [\"x\"]\n",
            "required_features",
        ),
        ("[[test]]\nname = \"b\"\npath = \"tests/b.rs\"\nbench = true\n", "bench"),
        (
            "[[test]]\nname = \"b\"\npath = \"tests/b.rs\"\nedition = \"2015\"\n",
            "edition",
        ),
        ("[lib]\ndoctest = false\n", "doctest"),
        ("[lib]\ncrate-type = [\"lib\", \"rlib\"]\n", "kinds"),
    ] {
        let (_d, root) = toy();
        append_manifest(&root, extra);
        let err = mismatch(&root, &["verify", "HEAD"]);
        assert!(err.contains(&format!("differs in {field}")), "{extra}: {err}");
    }
}

#[test]
fn verify_fails_when_the_package_features_change() {
    let (_d, root) = toy();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        manifest.replace("x = []", "x = []\ny = [\"x\"]"),
    )
    .unwrap();
    let err = mismatch(&root, &["verify", "HEAD"]);
    assert!(err.contains("Cargo.toml: features of package `toy` differ"), "{err}");
}

#[test]
fn verify_allows_the_planned_harness_false_flip_and_nothing_back() {
    let (_d, root) = toy();
    append_manifest(
        &root,
        "[[test]]\nname = \"b\"\npath = \"tests/b.rs\"\nharness = false\n[lib]\nharness = false\n",
    );
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 0);
    let (_d, root) = toy_with("\n[[test]]\nname = \"b\"\npath = \"tests/b.rs\"\nharness = false\n");
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 0);
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        manifest.replace("harness = false", "harness = true"),
    )
    .unwrap();
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 1);
}

// A flipped target is still compared ------------------------------------------------------------

const FLIP_A: &str = "[[test]]\nname = \"a\"\npath = \"tests/a.rs\"\nharness = false\n";

/// `toy` with a paused tokio test in `a`, applied and flipped.
fn flipped() -> (tempfile::TempDir, PathBuf) {
    let (d, root) = toy();
    write(
        &root,
        "tests/a.rs",
        "mod common;\n#[tokio::test(start_paused = true)]\nasync fn a() {}\n",
    );
    git(&root, &["commit", "-q", "-a", "-m", "paused"]);
    assert_eq!(
        code(&run(&root, &["apply", "src/lib.rs", "tests/a.rs", "tests/b.rs"])),
        0
    );
    append_manifest(&root, FLIP_A);
    (d, root)
}

#[test]
fn a_legitimate_flip_verifies() {
    let (_d, root) = flipped();
    let out = run(&root, &["verify", "HEAD"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn verify_still_compares_the_files_of_a_flipped_target() {
    let a = "tests/a.rs";
    let paused = "#[skuld::test(runtime = crate::tokio::test_runtime::paused)]";
    for (what, edit) in [
        (
            "a smuggled test",
            (String::new(), "#[skuld::test]\nfn smuggled() { panic!() }\n".to_owned()),
        ),
        ("a new #[ignore]", (paused.to_owned(), format!("{paused}\n#[ignore]"))),
        (
            "a dropped paused runtime",
            (paused.to_owned(), "#[skuld::test]".to_owned()),
        ),
    ] {
        let (_d, root) = flipped();
        let text = read(&root, a);
        let changed = if edit.0.is_empty() {
            format!("{text}{}", edit.1)
        } else {
            text.replace(&edit.0, &edit.1)
        };
        assert_ne!(changed, text, "{what}");
        write(&root, a, &changed);
        let err = mismatch(&root, &["verify", "HEAD"]);
        assert!(err.contains("tests/a.rs: item"), "{what}: {err}");
    }
}

// Roots resolve one way for apply and verify ----------------------------------------------------

#[test]
fn hoisting_through_a_directory_treats_its_targets_as_roots_and_spares_the_harness() {
    let (_d, root) = toy();
    write(
        &root,
        "tests/a.rs",
        "#![cfg(unix)]\n#[path = \"../src/test_harness.rs\"]\nmod test_harness;\nmod common;\n#[test]\nfn a() {}\n",
    );
    write(&root, "src/test_harness.rs", "#[test]\nfn h() {}\n");
    git(&root, &["add", "."]);
    git(&root, &["commit", "-q", "-m", "harness"]);
    let out = run(&root, &["apply", "--hoist-crate-cfg", "tests"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let a = read(&root, "tests/a.rs");
    assert!(
        !a.contains("#![cfg(unix)]") && a.contains("#[cfg(unix)]\nmod common;"),
        "{a}"
    );
    assert_eq!(read(&root, "src/test_harness.rs"), "#[test]\nfn h() {}\n");
}

#[test]
fn an_unflipped_target_inside_an_applied_directory_is_refused() {
    let (_d, root) = toy();
    write(&root, "unflipped.txt", "b\n");
    let out = run(&root, &["apply", "--unflipped", "unflipped.txt", "tests"]);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("tests/b.rs") && stderr(&out).contains("unflipped"),
        "{}",
        stderr(&out)
    );
    assert!(read(&root, "tests/b.rs").contains("#[test]"));
    assert!(read(&root, "tests/a.rs").contains("#[test]"));
    write(&root, "unflipped.txt", "tests/b.rs\n");
    assert_eq!(
        code(&run(
            &root,
            &["apply", "--unflipped", "unflipped.txt", "tests/a.rs", "tests/b.rs"]
        )),
        2
    );
}

#[test]
fn verify_resolves_directory_and_module_roots_like_apply() {
    let (_d, root) = toy();
    assert_eq!(code(&run(&root, &["verify", "HEAD", "src/quote"])), 0);
    assert_eq!(code(&run(&root, &["verify", "HEAD", "src/quote.rs"])), 0);
    assert_eq!(code(&run(&root, &["verify", "HEAD", "tests"])), 0);
    write(&root, "src/quote/applescript.rs", "#[test]\nfn t() { panic!() }\n");
    for arg in ["src/quote", "src/quote.rs"] {
        let err = mismatch(&root, &["verify", "HEAD", arg]);
        assert!(err.contains("src/quote/applescript.rs: item 0 differs"), "{arg}: {err}");
    }
}

#[test]
fn verify_with_explicit_roots_still_compares_the_target_set() {
    let (_d, root) = toy();
    std::fs::remove_file(root.join("tests/b.rs")).unwrap();
    let err = mismatch(&root, &["verify", "HEAD", "tests/a.rs"]);
    assert!(
        err.contains("target `b` (test) is missing in the new revision"),
        "{err}"
    );
}

#[test]
fn apply_only_tokio_and_manifest_path_from_another_directory() {
    let (_d, root) = toy();
    write(
        &root,
        "tests/a.rs",
        "mod common;\n#[test]\nfn a() {}\n#[tokio::test]\nasync fn t() {}\n",
    );
    let elsewhere = tempfile::tempdir().unwrap();
    let manifest = root.join("Cargo.toml");
    let out = Command::new(BIN)
        .current_dir(elsewhere.path())
        .args(["apply", "--only", "tokio", "--manifest-path"])
        .arg(&manifest)
        .arg(root.join("tests/a.rs"))
        .output()
        .unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(
        read(&root, "tests/a.rs"),
        "mod common;\n#[test]\nfn a() {}\n#[skuld::test]\nasync fn t() {}\n"
    );
    // `mod common;` resolved beside the target, which only a manifest-aware run can know.
    assert!(read(&root, "tests/common/mod.rs").contains("#[test]"));
}

// The label include -----------------------------------------------------------------------------

const HARNESS_FILE: &str = "#[skuld::label] pub const SLOW: skuld::Label;\n";

#[test]
fn a_flipped_target_may_gain_the_include_with_a_label_file() {
    let (_d, root) = flipped();
    let a = read(&root, "tests/a.rs");
    write(
        &root,
        "tests/a.rs",
        &format!("{a}#[path = \"../src/test_harness.rs\"]\nmod test_harness;\n"),
    );
    write(&root, "src/test_harness.rs", HARNESS_FILE);
    let out = run(&root, &["verify", "HEAD"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}

#[test]
fn an_unflipped_lib_may_not_gain_the_include_and_a_harness_file_must_be_labels_only() {
    let (_d, root) = toy();
    write(&root, "src/lib.rs", "mod quote;\nmod test_harness;\n");
    write(
        &root,
        "src/test_harness.rs",
        "pub fn anything() { std::process::exit(3) }\n#[test] fn new_test() { panic!() }\n",
    );
    let err = mismatch(&root, &["verify", "HEAD"]);
    assert!(err.contains("src/lib.rs: item 1 differs"), "{err}");

    let (_d, root) = flipped();
    let a = read(&root, "tests/a.rs");
    write(
        &root,
        "tests/a.rs",
        &format!("{a}#[path = \"../src/test_harness.rs\"]\nmod test_harness;\n"),
    );
    write(
        &root,
        "src/test_harness.rs",
        "pub fn anything() { std::process::exit(3) }\n",
    );
    let err = mismatch(&root, &["verify", "HEAD"]);
    assert!(
        err.contains("src/test_harness.rs: unexpected item in the label file"),
        "{err}"
    );
}

#[test]
fn explicit_roots_narrow_the_file_comparison() {
    let (_d, root) = toy();
    write(
        &root,
        "tests/b.rs",
        "mod common;\n#[test]\nfn will_vanish() { panic!() }\n",
    );
    assert_eq!(code(&run(&root, &["verify", "HEAD", "tests/a.rs"])), 0);
    let err = mismatch(&root, &["verify", "HEAD"]);
    assert!(err.contains("tests/b.rs: item 1 differs"), "{err}");
}
