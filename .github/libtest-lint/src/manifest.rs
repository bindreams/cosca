//! No target of a package runs on libtest, because a libtest attribute only works where one does.

use std::collections::BTreeSet;

use toml::{Table, Value};

/// One kind of cargo target: its table key, the package key that turns discovery off, whether it counts as a libtest
/// target unless `test = false`, and the files cargo finds without a table entry.
struct Kind {
    key: &'static str,
    auto: &'static str,
    tests_by_default: bool,
    discovered: fn(&str) -> Option<Option<String>>,
}

/// `Some(Some(name))` for a discovered target named `name`, `Some(None)` for one named after the package.
fn bin_file(path: &str) -> Option<Option<String>> {
    if path == "src/main.rs" {
        return Some(None);
    }
    discovered_in("src/bin/", path)
}

fn test_file(path: &str) -> Option<Option<String>> {
    discovered_in("tests/", path)
}

/// `<dir>/<name>.rs` or `<dir>/<name>/main.rs`.
fn discovered_in(dir: &str, path: &str) -> Option<Option<String>> {
    let rest = path.strip_prefix(dir)?;
    match rest.split('/').collect::<Vec<_>>().as_slice() {
        [file] => file.strip_suffix(".rs").map(|n| Some(n.to_string())),
        [name, "main.rs"] => Some(Some(name.to_string())),
        _ => None,
    }
}

fn bench_file(path: &str) -> Option<Option<String>> {
    discovered_in("benches/", path)
}

fn no_file(_: &str) -> Option<Option<String>> {
    None
}

const KINDS: [Kind; 4] = [
    Kind {
        key: "bin",
        auto: "autobins",
        tests_by_default: true,
        discovered: bin_file,
    },
    Kind {
        key: "test",
        auto: "autotests",
        tests_by_default: true,
        discovered: test_file,
    },
    // `cargo test --benches` and `--all-targets` run a default-harness bench in test mode.
    Kind {
        key: "bench",
        auto: "autobenches",
        tests_by_default: true,
        discovered: bench_file,
    },
    Kind {
        key: "example",
        auto: "autoexamples",
        tests_by_default: false,
        discovered: no_file,
    },
];

fn runs_libtest(entry: &Table, tests_by_default: bool) -> bool {
    let flag = |key: &str, default: bool| entry.get(key).and_then(Value::as_bool).unwrap_or(default);
    flag("test", tests_by_default) && flag("harness", true)
}

/// The targets of the package whose manifest is `text` that would run on libtest. `tracked` holds the package's
/// tracked files, relative to its directory with `/` separators.
pub fn check(manifest_path: &str, text: &str, tracked: &BTreeSet<String>) -> Result<Vec<String>, toml::de::Error> {
    let manifest: Table = text.parse()?;
    let package = manifest.get("package").and_then(Value::as_table);
    let package_name = package
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut found = Vec::new();
    let mut problem = |kind: &str, name: &str| {
        found.push(format!(
            "{manifest_path}: {kind} target `{name}` runs on libtest: set `harness = false` (or `test = false`) and run it under skuld"
        ));
    };

    // The lib: a `[lib]` table, or `src/lib.rs` without one.
    match manifest.get("lib").and_then(Value::as_table) {
        Some(lib) if runs_libtest(lib, true) => {
            problem("lib", lib.get("name").and_then(Value::as_str).unwrap_or(package_name))
        }
        None if tracked.contains("src/lib.rs") => problem("lib", package_name),
        _ => {}
    }

    for kind in KINDS {
        let entries: Vec<&Table> = manifest
            .get(kind.key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_table).collect())
            .unwrap_or_default();
        for entry in &entries {
            if runs_libtest(entry, kind.tests_by_default) {
                problem(kind.key, entry.get("name").and_then(Value::as_str).unwrap_or("?"));
            }
        }
        // Discovery defaults to on; a discovered file an entry names (by path or name) is that entry's.
        let auto = package
            .and_then(|p| p.get(kind.auto))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !auto || !kind.tests_by_default {
            continue;
        }
        for file in tracked {
            let Some(name) = (kind.discovered)(file) else { continue };
            let name = name.unwrap_or_else(|| package_name.to_string());
            let named = entries.iter().any(|e| {
                e.get("path")
                    .and_then(Value::as_str)
                    .is_some_and(|p| p.trim_start_matches("./") == file)
                    || e.get("name").and_then(Value::as_str) == Some(name.as_str())
            });
            if !named {
                problem(kind.key, &name);
            }
        }
    }
    Ok(found)
}
