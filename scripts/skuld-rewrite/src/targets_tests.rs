use crate::targets;

#[test]
fn lists_every_target_of_a_manifest_by_canonical_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"toy\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(root.join("src/lib.rs"), "").unwrap();
    std::fs::write(root.join("tests/it.rs"), "").unwrap();
    let mut got: Vec<(String, std::path::PathBuf)> = targets::all(Some(&root.join("Cargo.toml")))
        .unwrap()
        .into_iter()
        .map(|t| (t.name, t.src_path))
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("it".to_owned(), root.join("tests/it.rs")),
            ("toy".to_owned(), root.join("src/lib.rs"))
        ]
    );
}
