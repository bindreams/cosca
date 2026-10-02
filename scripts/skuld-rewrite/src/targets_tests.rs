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

#[test]
fn a_manifest_flag_is_absent_a_bool_or_an_error() {
    let table: toml::Table = "a = true\nb = false\nc = \"false\"\nd = 1\n".parse().unwrap();
    assert_eq!(targets::flag(&table, "a").unwrap(), Some(true));
    assert_eq!(targets::flag(&table, "b").unwrap(), Some(false));
    assert_eq!(targets::flag(&table, "missing").unwrap(), None);
    for key in ["c", "d"] {
        let err = targets::flag(&table, key).unwrap_err().to_string();
        assert!(err.contains(key) && err.contains("boolean"), "{err}");
    }
}

#[test]
fn a_target_lists_its_edition_and_each_package_its_features() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"toy\"\nversion = \"0.0.0\"\nedition = \"2018\"\n\n[features]\nx = []\ny = [\"x\"]\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(root.join("src/lib.rs"), "").unwrap();
    let listing = targets::load(Some(&root.join("Cargo.toml"))).unwrap();
    assert_eq!(listing.targets[0].edition, "2018");
    let toy = &listing.features["toy"];
    assert_eq!(toy["x"], Vec::<String>::new());
    assert_eq!(toy["y"], ["x"]);
}
