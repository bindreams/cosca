//! Guards `src/`, `tests/` and `testbin/` against a `set_current_dir` call creeping back in.
//!
//! `std::env::set_current_dir` mutates the WHOLE process's cwd — process-global state shared by
//! every concurrently running `#[test]` in the same test binary. A test that calls it races every
//! other cwd-sensitive test in that binary, which is exactly the class of bug
//! `azhukova/tests-no-chdir` removed (four tests in `src/resolve_tests.rs`, one in
//! `src/child/spawn/windows_raw/resolve_tests.rs`, all previously paired with a since-deleted
//! `RestoreCwd` guard that admitted, in its own doc, that it did not cover program resolution).
//! Each was rewritten to prove the same thing about a process's REAL cwd from a freshly spawned
//! CHILD process instead — see `crate::test_child::run_fixture_with_cwd` (`Command::current_dir`
//! on the spawned process, never `set_current_dir` on this one).
//!
//! `testbin/main.rs`'s two `set_current_dir` calls are the one legitimate exception, and are
//! allowlisted below by exact line text rather than skipped by file: `testbin` is itself a
//! freshly spawned, single-purpose PROCESS per invocation, never the shared multithreaded `cargo
//! test` binary, so mutating ITS OWN cwd races nothing — it IS the "spawn a dedicated child"
//! pattern this guard exists to push every other cwd-needing test toward, not an instance of the
//! bug. A `set_current_dir` call anywhere else in `testbin/main.rs` — including a third one with
//! different text — still fails this guard.

use std::path::Path;

/// `(file path relative to the repo root, exact trimmed line text)` for every allowlisted
/// `set_current_dir` call site. Matching on exact text (not merely "this file is exempt") means a
/// differently-shaped call added anywhere in `testbin/main.rs` still fails the guard.
const ALLOWLIST: &[(&str, &str)] = &[(
    "testbin/main.rs",
    "std::env::set_current_dir(dir).expect(\"chdir to the decoy directory\");",
)];

/// The exact call shape this guard looks for. Matches only an actual invocation (identifier
/// immediately followed by `(`), not a doc comment that merely mentions the identifier — e.g.
/// `src/child/spawn/windows_raw/resolve_tests.rs` has one such comment today, and it must not trip
/// this guard.
const NEEDLE: &str = "set_current_dir(";

#[test]
fn no_test_mutates_the_process_cwd() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut scanned = 0usize;
    let mut offenders = Vec::new();

    for dir in ["src", "tests", "testbin"] {
        visit(&root.join(dir), root, &mut scanned, &mut offenders);
    }

    assert!(scanned > 0, "scanned zero .rs files — the guard itself is broken");
    assert!(
        offenders.is_empty(),
        "found a `set_current_dir` call outside this guard's allowlist (races every other \
         concurrently running test in the same binary — see this file's module doc for the \
         spawn-a-child alternative): {offenders:#?}"
    );
}

fn visit(dir: &Path, root: &Path, scanned: &mut usize, offenders: &mut Vec<String>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let file_type = entry.file_type().expect("file_type");
        if file_type.is_dir() {
            visit(&path, root, scanned, offenders);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        *scanned += 1;
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        // This guard's own source necessarily spells out the needle it looks for (in the
        // allowlist and in `NEEDLE` itself), so it must exclude itself rather than the pattern it
        // is enforcing everywhere else.
        if rel == "tests/no_chdir_guard.rs" {
            continue;
        }
        for (i, line) in text.lines().enumerate() {
            if !line.contains(NEEDLE) {
                continue;
            }
            let trimmed = line.trim();
            if ALLOWLIST.iter().any(|(f, l)| *f == rel && *l == trimmed) {
                continue;
            }
            offenders.push(format!("{rel}:{}: {trimmed}", i + 1));
        }
    }
}
