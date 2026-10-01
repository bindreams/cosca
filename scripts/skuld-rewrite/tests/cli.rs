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
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    write(
        &root,
        "Cargo.toml",
        "[package]\nname = \"toy\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n",
    );
    write(&root, "src/lib.rs", "");
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
