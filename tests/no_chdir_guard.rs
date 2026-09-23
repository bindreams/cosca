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
//! allowlisted below by exact line text AND an exact expected count, rather than skipped by file:
//! `testbin` is itself a freshly spawned, single-purpose PROCESS per invocation, never the shared
//! multithreaded `cargo test` binary, so mutating ITS OWN cwd races nothing — it IS the "spawn a
//! dedicated child" pattern this guard exists to push every other cwd-needing test toward, not an
//! instance of the bug. A `set_current_dir` call anywhere else in `testbin/main.rs` — including a
//! third one with different text — still fails this guard, and so does a THIRD occurrence of the
//! two calls' identical text: matching by text alone would let a duplicate of an already-allowed
//! line slip in uncounted, so each entry also carries the exact number of lines it may match.
//!
//! The match itself is word-boundary, not substring: a bare identifier occurrence trips it, with
//! no trailing `(` required, so an aliased import (`use ... as cd; cd(d)`), a `.map(...)`
//! reference, and turbofish syntax all still get caught, alongside the non-std spellings
//! (`libc`/`nix`/`rustix` `chdir`/`fchdir`, Win32 `SetCurrentDirectoryA`/`W`, `_wchdir`/`wchdir`).
//! A line is skipped only when its trimmed text starts with `//` — a prose mention in a doc
//! comment, like several in this very file, must not trip the guard.

use std::path::Path;

/// `(file path relative to the repo root, exact trimmed line text, exact expected match count)`
/// for every allowlisted call site. Matching on exact text (not merely "this file is exempt")
/// means a differently-shaped call added anywhere in `testbin/main.rs` still fails the guard;
/// matching on an exact COUNT, not just presence, means a second occurrence of an
/// already-allowlisted line sneaking in still fails it too — presence alone cannot tell "the one
/// allowed line is still there" apart from "the one allowed line, plus an uncounted extra".
const ALLOWLIST: &[(&str, &str, usize)] = &[(
    "testbin/main.rs",
    concat!(
        "std::env::set_current",
        "_dir(dir).expect(\"ch",
        "dir to the decoy directory\");"
    ),
    2,
)];

/// Two-piece halves of every identifier this guard treats as a process-cwd mutation. Never written
/// contiguously anywhere in this file: this file is scanned by its own [`no_test_mutates_the_process_cwd`]
/// too (no exemption by path), and a contiguous spelling in CODE here — as opposed to inside a `//`
/// doc-comment line, which the scan skips — would trip its own scan. [`spell`] is the only place
/// each pair is reassembled into the real identifier, and only as a runtime `String`, never as
/// source text.
const NEEDLE_FRAGMENTS: &[(&str, &str)] = &[
    ("set_current", "_dir"),
    ("ch", "dir"),
    ("fch", "dir"),
    ("_wch", "dir"),
    ("wch", "dir"),
    ("SetCurrentDirectory", "A"),
    ("SetCurrentDirectory", "W"),
];

fn spell(fragments: (&str, &str)) -> String {
    format!("{}{}", fragments.0, fragments.1)
}

fn needle_words() -> Vec<String> {
    NEEDLE_FRAGMENTS.iter().copied().map(spell).collect()
}

/// Compiles the word-boundary regex matching any [`needle_words`] identifier, once per process.
fn needle_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        let pattern = format!(r"\b({})\b", needle_words().join("|"));
        regex::Regex::new(&pattern).expect("needle pattern is a valid regex")
    })
}

/// True if `line` contains any needle identifier as a whole word — see this file's module doc for
/// what that does and does not catch. Callers are responsible for skipping full-line comments
/// first (see [`visit`]); this function does not know about comment syntax.
fn line_matches_needle(line: &str) -> bool {
    needle_regex().is_match(line)
}

#[test]
fn needle_matcher_catches_every_known_bypass() {
    let cd_word = spell(NEEDLE_FRAGMENTS[0]);
    let chdir_word = spell(NEEDLE_FRAGMENTS[1]);
    let fchdir_word = spell(NEEDLE_FRAGMENTS[2]);
    let leading_underscore_wchdir_word = spell(NEEDLE_FRAGMENTS[3]);
    let wchdir_word = spell(NEEDLE_FRAGMENTS[4]);
    let set_dir_a_word = spell(NEEDLE_FRAGMENTS[5]);
    let set_dir_w_word = spell(NEEDLE_FRAGMENTS[6]);

    let bypass_lines = [
        format!("use std::env::{cd_word} as cd; cd(d)"),
        format!(".map(std::env::{cd_word})"),
        format!("{cd_word}::<&str>"),
        format!("libc::{chdir_word}"),
        format!("nix::unistd::{chdir_word}"),
        format!("rustix::process::{chdir_word}"),
        format!("libc::{fchdir_word}"),
        format!("windows_sys::Win32::Storage::FileSystem::{set_dir_a_word}(path)"),
        format!("windows_sys::Win32::Storage::FileSystem::{set_dir_w_word}(path)"),
        format!("libc::{leading_underscore_wchdir_word}(path)"),
        format!("libc::{wchdir_word}(path)"),
    ];
    for line in &bypass_lines {
        assert!(line_matches_needle(line), "needle matcher must catch: {line}");
    }

    let negative_control = "let tempdir = tempfile::tempdir().unwrap();";
    assert!(
        !line_matches_needle(negative_control),
        "needle matcher must not fire on an unrelated line: {negative_control}"
    );
}

#[test]
fn no_test_mutates_the_process_cwd() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut scanned = 0usize;
    let mut offenders = Vec::new();
    let mut allowlist_hits = vec![0usize; ALLOWLIST.len()];

    for dir in ["src", "tests", "testbin"] {
        visit(&root.join(dir), root, &mut scanned, &mut offenders, &mut allowlist_hits);
    }

    assert!(scanned > 0, "scanned zero .rs files — the guard itself is broken");

    for (i, (file, text, expected)) in ALLOWLIST.iter().enumerate() {
        let found = allowlist_hits[i];
        if found == 0 || found > *expected {
            offenders.push(format!(
                "allowlist entry {file}:{text:?} expects exactly {expected} match(es), found {found}"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "found a process-cwd-mutation call outside this guard's allowlist, or an allowlisted \
         line's match count drifted from what is expected (races every other concurrently \
         running test in the same binary — see this file's module doc for the spawn-a-child \
         alternative): {offenders:#?}"
    );
}

fn visit(dir: &Path, root: &Path, scanned: &mut usize, offenders: &mut Vec<String>, allowlist_hits: &mut [usize]) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let file_type = entry.file_type().expect("file_type");
        if file_type.is_dir() {
            visit(&path, root, scanned, offenders, allowlist_hits);
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
        for (i, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            if !line_matches_needle(line) {
                continue;
            }
            if let Some(idx) = ALLOWLIST.iter().position(|(f, l, _)| *f == rel && *l == trimmed) {
                allowlist_hits[idx] += 1;
                continue;
            }
            offenders.push(format!("{rel}:{}: {trimmed}", i + 1));
        }
    }
}
