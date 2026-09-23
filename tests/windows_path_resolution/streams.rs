//! Canary: data-stream suffixes.

use crate::harness::{check_resolutions, literal_rows, Disagreements};
use crate::provenance::announce_platform;
use crate::winapi::full_path_name;

/// Canary: a `:stream` suffix stays in the final component, and only a trailing dot or space at
/// the END of that whole component is trimmed.
///
/// So the resolved name ends in the stream name: `x.exe:payload.bat` resolves to a string std's
/// `has_bat_extension` reads as a batch file, `x.bat:s` to one it does not. `GetFullPathNameW` does
/// not split at the separator before trimming: `x.bat.:s` and `x.bat :s` (one space) come back
/// unchanged. String-level only: no stream is created or opened, so which file the file system
/// would open for them is not measured here.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn a_stream_suffix_stays_in_the_final_component() {
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::default();
    let mut rows = literal_rows(&[
        (r"C:\dir\x.bat:s", r"C:\dir\x.bat:s", "kept as given"),
        (
            r"C:\dir\x.exe:payload.bat",
            r"C:\dir\x.exe:payload.bat",
            "kept as given",
        ),
        (r"C:\dir\x.bat::$DATA", r"C:\dir\x.bat::$DATA", "a stream type is kept"),
        (
            r"C:\dir\x.exe:p.bat:$DATA",
            r"C:\dir\x.exe:p.bat:$DATA",
            "a stream type is kept",
        ),
        (r"C:\dir\x.bat:", r"C:\dir\x.bat:", "an empty stream name is kept"),
        (
            r"C:\dir\x.bat:s.",
            r"C:\dir\x.bat:s",
            "a trailing dot is trimmed from the stream name",
        ),
        (
            r"C:\dir\x.exe:p.bat.",
            r"C:\dir\x.exe:p.bat",
            "a trailing dot is trimmed",
        ),
        (
            r"C:\dir\x.exe:p.bat ",
            r"C:\dir\x.exe:p.bat",
            "a trailing space is trimmed",
        ),
        (
            r"\\?\C:\dir\x.exe:p.bat",
            r"\\?\C:\dir\x.exe:p.bat",
            "kept under the verbatim marker",
        ),
        (
            r"C:\dir\x.bat.:s",
            r"C:\dir\x.bat.:s",
            "a dot before the separator is kept",
        ),
        (
            r"C:\dir\x.bat :s",
            r"C:\dir\x.bat :s",
            "a space before the separator is kept",
        ),
        (r"C:\dir\x.bat. :s", r"C:\dir\x.bat. :s", "both are kept"),
        (r"C:\dir\x.bat..:s", r"C:\dir\x.bat..:s", "two dots are kept"),
        (
            r"C:\dir\x.bat.:s.",
            r"C:\dir\x.bat.:s",
            "only the end of the whole component is trimmed",
        ),
        (
            r"C:\dir\x.bat.::$DATA",
            r"C:\dir\x.bat.::$DATA",
            "kept with a stream type",
        ),
        (
            r"C:\dir\x.exe.:p.bat",
            r"C:\dir\x.exe.:p.bat",
            "a dot before a batch-named stream is kept",
        ),
        (
            r"\\?\C:\dir\x.bat.:s",
            r"\\?\C:\dir\x.bat.:s",
            "kept under the verbatim marker",
        ),
    ]);
    match std::env::current_dir() {
        Ok(cwd) => {
            let cwd = cwd
                .to_str()
                .expect("cwd is not UTF-8")
                .trim_end_matches('\\')
                .to_string();
            println!("current directory: {cwd:?}");
            rows.push(("x.bat:s".to_string(), format!(r"{cwd}\x.bat:s"), "relative, kept"));
            rows.push(("x.bat.:s".to_string(), format!(r"{cwd}\x.bat.:s"), "relative, dot kept"));
            rows.push((
                "x.bat :s".to_string(),
                format!(r"{cwd}\x.bat :s"),
                "relative, space kept",
            ));
            rows.push((
                "x.exe:payload.bat".to_string(),
                format!(r"{cwd}\x.exe:payload.bat"),
                "relative, kept",
            ));
        }
        Err(e) => failures.push(format!("could not read the current directory: {e}")),
    }
    check_resolutions(&rows, &mut facts, &mut failures);
    // Drive-relative: which directory `C:` means depends on the per-drive current directory, so
    // only the shape is asserted.
    const DRIVE_RELATIVE: &str = r"C:x.bat:s";
    match full_path_name(DRIVE_RELATIVE) {
        Ok(resolved) => {
            println!("  {DRIVE_RELATIVE:?} -> {resolved:?}  (drive-relative)");
            facts.check(
                resolved.starts_with(r"C:\") && resolved.ends_with(r"\x.bat:s"),
                &format!(r"{DRIVE_RELATIVE:?} resolves to C:\…\x.bat:s"),
                format_args!("{resolved:?}"),
            );
        }
        Err(why) => failures.push(why),
    }
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
}
