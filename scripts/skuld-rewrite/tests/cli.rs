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
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 1);
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
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 1);
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
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 1);
}

#[test]
fn verify_fails_when_a_module_file_changes() {
    let (_d, root) = toy();
    write(&root, "tests/common/mod.rs", "#[test]\nfn shared() { panic!() }\n");
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 1);
    let (_d, root) = toy();
    write(&root, "src/quote/applescript.rs", "#[test]\nfn t() { panic!() }\n");
    assert_eq!(code(&run(&root, &["verify", "HEAD"])), 1);
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
    for extra in [
        "[[test]]\nname = \"b\"\npath = \"tests/b.rs\"\ntest = false\n",
        "[[test]]\nname = \"b\"\npath = \"tests/b.rs\"\nrequired-features = [\"x\"]\n",
        "[[test]]\nname = \"b\"\npath = \"tests/b.rs\"\nbench = true\n",
        "[lib]\ndoctest = false\n",
        "[lib]\ncrate-type = [\"lib\", \"rlib\"]\n",
    ] {
        let (_d, root) = toy();
        append_manifest(&root, extra);
        assert_eq!(code(&run(&root, &["verify", "HEAD"])), 1, "{extra}");
    }
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
