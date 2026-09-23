//! Canaries: dots-and-spaces components, final and interior, plain and verbatim.

use crate::harness::{canary, check_resolutions};
use crate::pure::pop_past_expectation;
use crate::winapi::{entries, full_path_name, full_path_name_parts, has_bat_extension, listing, outcome, report_roots};

/// The final components under test, each only dots and/or spaces or ending in one, with whether a
/// VERBATIM spelling can hold a file of that name. `.` and `..` cannot: they fail
/// `ERROR_INVALID_NAME` even under `\\?\`. `. ` rides along because under the prefix it is a
/// different literal name from `.`, not a spelling of it.
pub(crate) const WEIRD_NAMES: &[(&str, &str, bool)] = &[
    ("...", "three dots", true),
    ("....", "four dots", true),
    (" ", "a single space", true),
    ("x ", "an ordinary name with a trailing space", true),
    ("..", "the parent-directory component, spelled as a literal name", false),
    (".", "the self component, spelled as a literal name", false),
    (". ", "the self component plus a space: a different literal name", true),
];

/// `ERROR_INVALID_NAME`: "The filename, directory name, or volume label syntax is incorrect."
pub(crate) const ERROR_INVALID_NAME: i32 = 123;

/// Canary: a final component of only dots and spaces DROPS OUT and pops nothing, while `..` pops.
///
/// The inputs are chosen so the two candidate readings of a dots-and-spaces component give
/// OPPOSITE answers — dropping it leaves `y`, reading it as `..` leaves `x.bat` — and, since std
/// tests the RESOLVED path, which one Win32 picks decides whether `cmd.exe` runs. `x.bat\y\..`
/// reaches a batch name through `..`. `x\..\..` shows that a relative path popping past its own
/// first component lands in the current directory's ancestors, which the string alone does not
/// name. The trailing separator on an elided result matters too: std's `has_bat_extension` does
/// not read `…\x.bat\` as a batch file.
///
/// Relative inputs, so each is compared against the current directory `GetFullPathNameW` resolves
/// them in.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn a_final_dots_and_spaces_component_drops_out_and_pops_nothing() {
    // (input, what follows the current directory in the result, why)
    let probes = [
        (r"x.bat\y\..", r"x.bat", "`..` pops `y`, exposing the batch file"),
        (r"x.bat\y\.. ", r"x.bat\y\", "`.. ` is NOT `..`: it drops out"),
        (r"x.bat\y\. ", r"x.bat\y\", "`. ` drops out"),
        (r"x.bat\y\.. .", r"x.bat\y\", "drops out, so `y` survives"),
        (r"x.bat\y\...", r"x.bat\y\", "drops out, so `y` survives"),
        (r"x.bat\y\....", r"x.bat\y\", "drops out, so `y` survives"),
        (r"x.bat\y\.. ..", r"x.bat\y\", "drops out, so `y` survives"),
        (r"x.bat\y\ ", r"x.bat\y\", "drops out, so `y` survives"),
        (
            r"x.bat\...",
            r"x.bat\",
            "drops out, leaving a separator after the batch name",
        ),
        (
            r"x.bat\y\...\z.exe",
            r"x.bat\y\...\z.exe",
            "an interior `...` is kept verbatim",
        ),
    ];
    canary("Windows", |facts, failures| {
        match std::env::current_dir() {
            Ok(cwd) => {
                let cwd = cwd
                    .to_str()
                    .expect("cwd is not UTF-8")
                    .trim_end_matches('\\')
                    .to_string();
                println!("current directory: {cwd:?}");
                for (probe, tail, why) in probes {
                    match full_path_name(probe) {
                        Ok(resolved) => {
                            println!(
                                "{probe:?} -> {resolved:?}  batch_to_std={}  ({why})",
                                has_bat_extension(&resolved)
                            );
                            let want = format!(r"{cwd}\{tail}");
                            facts.check(
                                resolved == want,
                                &format!("{probe:?} resolves to {want:?} ({why})"),
                                format_args!("{resolved:?}"),
                            );
                        }
                        Err(why) => failures.push(why),
                    }
                }
                // Popping past the path's own first component continues into the cwd's ancestors,
                // or stays at the root when the cwd is one.
                const POP_PAST: &str = r"x\..\..";
                match full_path_name(POP_PAST) {
                    Ok(resolved) => {
                        println!("{POP_PAST:?} -> {resolved:?}  (pops past its own first component)");
                        let want = pop_past_expectation(&cwd);
                        let got = resolved.trim_end_matches('\\');
                        facts.check(
                            got == want,
                            &format!("{POP_PAST:?} resolves to the cwd's parent, or its root, {want:?}"),
                            format_args!("{resolved:?}"),
                        );
                    }
                    Err(why) => failures.push(why),
                }
            }
            Err(e) => failures.push(format!(
                "could not read the working directory these resolve against: {e}"
            )),
        }
    });
}

/// Canary: `GetFullPathNameW` strips a final dots-and-spaces component in BOTH spellings — the
/// verbatim `\\?\` prefix does not stop it — and a trailing separator does.
///
/// So for a verbatim path the string and the file disagree: `\\?\C:\dir\...` OPENS the file `...`
/// (see `spawn::a_verbatim_dots_and_spaces_file_exists_and_loads`) while `GetFullPathNameW` says it
/// names `C:\dir\`. A model of verbatim paths has to read the literal string, not this result. If
/// Win32 began honouring the prefix here, the two readings would converge.
///
/// The trailing-separator rows are printed, not asserted. `C:\dir\x` must come back untouched, or
/// the probe itself is broken.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn a_final_dots_and_spaces_component_is_stripped_even_verbatim() {
    // (tail, note, stripped): `stripped` tails lose the whole final component without a trailing
    // separator, in either spelling.
    let tails = [
        ("...", "three dots", true),
        ("....", "four dots", true),
        (". ", "`.` plus a space", true),
        (" ", "a single space", true),
        (".. .", "neither `.` nor `..`, but trims to `..`", true),
        ("..", "the parent-directory component", false),
        (".", "the self component", false),
        ("x", "control: an ordinary name", false),
    ];
    canary("Windows", |facts, failures| {
        report_roots(&[r"C:\dir", r"C:\"]);
        for (tail, note, stripped) in tails {
            println!("--- {tail:?}  ({note})");
            for prefix in ["", r"\\?\"] {
                for trailing_sep in ["", r"\"] {
                    let input = format!(r"{prefix}C:\dir\{tail}{trailing_sep}");
                    match full_path_name_parts(&input) {
                        Ok((resolved, part)) => {
                            let shown = part
                                .as_ref()
                                .map_or_else(|| "<none: names a directory>".to_string(), |p| format!("{p:?}"));
                            let verdict = if resolved == input { "unchanged" } else { "REWRITTEN" };
                            println!("  {input:?} -> {resolved:?}  file_part={shown}  [{verdict}]");
                            if trailing_sep.is_empty() && stripped {
                                let want = format!(r"{prefix}C:\dir\");
                                facts.check(
                                    resolved == want && part.is_none(),
                                    &format!("{input:?} is stripped to the directory {want:?}"),
                                    format_args!("{resolved:?} with file_part={shown}"),
                                );
                            }
                            if tail == "x" {
                                facts.check(
                                    resolved == input,
                                    &format!("control {input:?} comes back unchanged"),
                                    format_args!("{resolved:?}"),
                                );
                            }
                        }
                        Err(why) if (trailing_sep.is_empty() && stripped) || tail == "x" => failures.push(why),
                        Err(why) => println!("  {why}  [printed row: not asserted]"),
                    }
                }
            }
        }
    });
}

/// Canary: through `\\?\`, a dots-and-spaces name is an ordinary file — except `.` and `..`,
/// which fail `ERROR_INVALID_NAME`.
///
/// So a verbatim final `.` or `..` can never name a file, while `...`, `" "`, `"x "` and `". "`
/// can. A model of verbatim paths that treats either group otherwise is wrong on this Windows.
///
/// The plain-spelling rows, `GetFullPathNameW` and the listings are printed, not asserted. Each
/// (name, spelling) pair gets its OWN directory, so a listing can never be ambiguous about which
/// attempt produced which entry.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn only_dot_and_dotdot_are_refused_as_verbatim_file_names() {
    canary("Windows", |facts, failures| {
        let root = tempfile::tempdir().expect("tempdir");
        let root = root.path().to_str().expect("temp path is not UTF-8").to_string();
        println!("temp root: {root:?}");

        for (i, &(name, note, creatable)) in WEIRD_NAMES.iter().enumerate() {
            for (tag, prefix) in [("plain", ""), ("verbatim", r"\\?\")] {
                let case_dir = format!(r"{root}\case{i}_{tag}");
                if let Err(e) = std::fs::create_dir(&case_dir) {
                    failures.push(format!("could not create the case directory {case_dir:?}: {e}"));
                    continue;
                }
                let target = format!(r"{prefix}{case_dir}\{name}");
                println!("--- create {target:?}  ({note}, {tag} spelling)");
                let written = std::fs::write(&target, b"probe");
                let created = written.is_ok();
                if !prefix.is_empty() {
                    let code = written.as_ref().err().and_then(std::io::Error::raw_os_error);
                    let fact = if creatable {
                        format!("{name:?} can be created through the verbatim spelling")
                    } else {
                        format!(
                        "{name:?} fails ERROR_INVALID_NAME ({ERROR_INVALID_NAME}) even through the verbatim spelling"
                    )
                    };
                    facts.check(
                        if creatable {
                            created
                        } else {
                            code == Some(ERROR_INVALID_NAME)
                        },
                        &fact,
                        outcome(&written),
                    );
                }
                println!("  write: {}", outcome(&written));

                // Everything below is what the platform says about whatever that write produced —
                // including nothing, which is itself an answer.
                match full_path_name_parts(&target) {
                    Ok((resolved, part)) => {
                        let part = part.map_or_else(|| "<none: names a directory>".to_string(), |p| format!("{p:?}"));
                        println!("  GetFullPathNameW -> {resolved:?}  file_part={part}");
                    }
                    Err(why) => println!("  {why}"),
                }
                match listing(&format!(r"\\?\{case_dir}")) {
                    Ok(names) => println!("  listing: {names:?}"),
                    Err(why) => println!("  listing: {why}"),
                }
                let plain_back = format!(r"{case_dir}\{name}");
                let verbatim_back = format!(r"\\?\{case_dir}\{name}");
                println!(
                    "  open as plain    {plain_back:?}: {}",
                    outcome(&std::fs::File::open(&plain_back))
                );
                let reopened = std::fs::File::open(&verbatim_back);
                println!("  open as verbatim {verbatim_back:?}: {}", outcome(&reopened));
                if created && !prefix.is_empty() {
                    facts.check(
                        reopened.is_ok(),
                        &format!("{name:?}, created verbatim, opens back through the verbatim spelling"),
                        outcome(&reopened),
                    );
                }
                // Remove whatever the write produced — a plain `x ` creates `x` — through the
                // verbatim spelling, the only one guaranteed to name the literal entry. The
                // directory is this case's alone. A failure here leaves the ephemeral runner to
                // clean up, but say so.
                drop(reopened);
                match entries(&format!(r"\\?\{case_dir}")) {
                    Ok(names) => {
                        for entry in names {
                            let path = format!(r"\\?\{case_dir}\{}", entry.to_string_lossy());
                            if let Err(e) = std::fs::remove_file(&path) {
                                println!("  CLEANUP: {path:?} could not be removed: {e}");
                            }
                        }
                    }
                    Err(why) => println!("  CLEANUP: {why}"),
                }
            }
        }
    });
}

/// Canary: a plain `x.bat.` or `x.bat ` IS `x.bat`, while a verbatim one is a distinct file, and a
/// slash in the verbatim marker makes the path plain.
///
/// Plain: `GetFullPathNameW` hands std `…\x.bat`, which std tests for `.bat`/`.cmd` and so runs
/// through `cmd.exe`, so a model of plain paths must trim trailing dots and spaces before reading
/// the extension. Verbatim: `x.bat.` is a file of its own, which std tests as given.
///
/// Which spellings are verbatim is part of the fact. `\\?\` and the NT prefix `\??\` open the
/// literal name; `//?/` and `\\?/`, a slash anywhere in the marker, open `x.bat` like a plain path.
///
/// The `GetFullPathNameW` result of a verbatim spelling is printed, not asserted.
///
/// Each file holds its own name, so reading a spelling back says exactly which entry it reached.
/// **Nothing here is executed**: the files are text, not images.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn a_trailing_dot_or_space_reaches_the_batch_file_only_when_plain() {
    const LOOKALIKES: &[&str] = &["x.bat.", "x.bat ", "x.bat"];
    canary("Windows", |facts, failures| {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().to_str().expect("temp path is not UTF-8").to_string();
        println!("temp dir: {dir:?}");

        for name in LOOKALIKES {
            let verbatim = format!(r"\\?\{dir}\{name}");
            let written = std::fs::write(&verbatim, name.as_bytes());
            println!("write {verbatim:?}: {}", outcome(&written));
            if let Err(e) = written {
                failures.push(format!("could not plant {verbatim:?}: {e}"));
            }
        }
        match listing(&format!(r"\\?\{dir}")) {
            Ok(names) => println!("listing: {names:?}"),
            Err(why) => println!("listing: {why}"),
        }
        for name in LOOKALIKES {
            println!("--- {name:?}");
            for (verbatim, path) in [(false, format!(r"{dir}\{name}")), (true, format!(r"\\?\{dir}\{name}"))] {
                let tag = if verbatim { "verbatim" } else { "plain   " };
                match full_path_name(&path) {
                    // `std_has_bat_extension` is std's own `has_bat_extension` on the resolved
                    // name: true is what makes `std::process` swap in cmd.exe for a plain path.
                    Ok(resolved) => {
                        println!(
                            "  {tag} GetFullPathNameW -> {resolved:?}  std_has_bat_extension={}",
                            has_bat_extension(&resolved)
                        );
                        if !verbatim {
                            let want = format!(r"{dir}\x.bat");
                            facts.check(
                                resolved == want,
                                &format!("plain {name:?} resolves to {want:?}"),
                                format_args!("{resolved:?}"),
                            );
                        }
                    }
                    Err(why) if !verbatim => failures.push(why),
                    Err(why) => println!("  {tag} {why}"),
                }
                let body = std::fs::read_to_string(&path);
                match &body {
                    Ok(body) => println!("  {tag} reads the file named {body:?}"),
                    Err(e) => println!("  {tag} read FAILED: {e} (raw_os_error={:?})", e.raw_os_error()),
                }
                let want = if verbatim { *name } else { "x.bat" };
                facts.check(
                    body.as_deref().is_ok_and(|b| b == want),
                    &format!("{} {name:?} opens the file {want:?}", tag.trim_end()),
                    format_args!("{body:?}"),
                );
            }
        }
        // The other verbatim-looking spellings: a slash anywhere in the marker makes it plain,
        // while the NT prefix `\??\` is as literal as `\\?\`.
        let forward = dir.replace('\\', "/");
        for name in LOOKALIKES {
            for (tag, path, want) in [
                ("//?/", format!("//?/{forward}/{name}"), "x.bat"),
                (r"\\?/", format!(r"\\?/{dir}\{name}"), "x.bat"),
                (r"\??\", format!(r"\??\{dir}\{name}"), *name),
            ] {
                let body = std::fs::read_to_string(&path);
                match &body {
                    Ok(body) => println!("  {tag:<5} {path:?} reads the file named {body:?}"),
                    Err(e) => println!(
                        "  {tag:<5} {path:?} read FAILED: {e} (raw_os_error={:?})",
                        e.raw_os_error()
                    ),
                }
                facts.check(
                    body.as_deref().is_ok_and(|b| b == want),
                    &format!("{tag} {name:?} opens the file {want:?}"),
                    format_args!("{body:?}"),
                );
            }
        }
    });
}

/// Canary: an INTERIOR segment loses a single trailing period and nothing else.
///
/// A trailing run of two or more periods is kept, and so are trailing spaces: interior `...`, `" "`
/// and `x ` are names, `x.` becomes `x`, `.. .` becomes `.. `. Being names, a following `..` pops
/// them: `y\x.bat\...\..` is `y\x.bat`. Both spellings, at one and two segments from the end,
/// behave alike. This differs from the FINAL-component rule
/// ([`a_final_dots_and_spaces_component_drops_out_and_pops_nothing`]), so a model of path
/// normalisation needs both.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn an_interior_segment_loses_only_a_single_trailing_period() {
    // (segment, what it becomes when not final)
    const INTERIOR: &[(&str, &str)] = &[
        ("x", "x"),
        (".x", ".x"),
        ("x.", "x"),
        ("x..", "x.."),
        ("x...", "x..."),
        ("x....", "x...."),
        ("x ", "x "),
        ("x  ", "x  "),
        ("x. ", "x. "),
        ("x .", "x "),
        ("...", "..."),
        (".. .", ".. "),
        (" ", " "),
    ];
    canary("Windows", |facts, failures| {
        let mut rows = Vec::new();
        for (seg, kept) in INTERIOR {
            for prefix in ["", r"\\?\"] {
                for tail in [r"z.exe", r"mid\z.exe"] {
                    rows.push((
                        format!(r"{prefix}C:\dir\{seg}\{tail}"),
                        format!(r"{prefix}C:\dir\{kept}\{tail}"),
                        "interior segment",
                    ));
                }
            }
        }
        check_resolutions(&rows, facts, failures);

        // A kept interior segment is a name, so the `..` after it pops it.
        match std::env::current_dir() {
            Ok(cwd) => {
                let cwd = cwd
                    .to_str()
                    .expect("cwd is not UTF-8")
                    .trim_end_matches('\\')
                    .to_string();
                println!("current directory: {cwd:?}");
                let popped = [
                    (r"y\x.bat\...\..", "`...` is kept, then popped"),
                    (r"y\x.bat\ \..", "a lone space is kept, then popped"),
                    (r"y\x.bat\.. .\..", "`.. .` becomes the name `.. `, then popped"),
                ]
                .map(|(input, why)| (input.to_string(), format!(r"{cwd}\y\x.bat"), why));
                check_resolutions(&popped, facts, failures);
            }
            Err(e) => failures.push(format!("could not read the current directory: {e}")),
        }
    });
}
