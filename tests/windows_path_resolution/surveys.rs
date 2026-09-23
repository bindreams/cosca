//! Surveys: print-only measurements that nothing asserts on.

use crate::provenance::survey_platform;
use crate::pure::compare_across_roots;
use crate::winapi::{full_path_name, full_path_name_parts, full_path_name_raw, listing, outcome, report_roots};

/// Segment shapes for [`which_segment_positions_get_trimmed`]. Every one is an ORDINARY name — `x`
/// with something trailing — or a named control, so "was this segment trimmed?" has an
/// unambiguous answer wherever it sits.
pub(crate) const SEGMENTS: &[(&str, &str)] = &[
    ("x", "control: nothing to trim"),
    (".x", "control: the period is LEADING, not trailing"),
    ("x.", "one trailing period"),
    ("x..", "two trailing periods"),
    (
        "x...",
        "three trailing periods — is the exemption about the segment or its position?",
    ),
    ("x....", "four trailing periods"),
    ("x ", "one trailing space"),
    ("x  ", "two trailing spaces"),
    ("x. ", "period then space"),
    ("x .", "space then period"),
    (
        "...",
        "nothing but three periods: the documented exemption, for comparison",
    ),
    (".. .", "trims to `..` if trimmed at all"),
];

/// The positions a segment can occupy, as templates over `{root}` and `{seg}`.
pub(crate) const POSITIONS: &[(&str, &str)] = &[
    ("final, no sep", r"{root}\{seg}"),
    ("final, +sep  ", r"{root}\{seg}\"),
    ("interior x1  ", r"{root}\{seg}\z.exe"),
    ("interior x2  ", r"{root}\{seg}\mid\z.exe"),
];

pub(crate) fn build(shape: &str, root: &str, seg: &str) -> String {
    shape.replace("{root}", root).replace("{seg}", seg)
}

/// Survey: which SEGMENT POSITIONS does `GetFullPathNameW` trim, and does the root's existence
/// change the answer?
///
/// `dots_and_spaces::an_interior_segment_loses_only_a_single_trailing_period` asserts the interior
/// rows.
///
/// Each case is also run under two sibling roots of EQUAL length, one created on disk and one not,
/// so "does the directory have to exist?" is settled by comparing two strings rather than by
/// trusting the documentation's claim that this is pure string manipulation.
#[test]
#[ignore = "platform survey: needs a Windows runner; prints a measurement rather than asserting"]
fn which_segment_positions_get_trimmed() {
    survey_platform();

    let tmp = tempfile::tempdir().expect("tempdir");
    let tmp = tmp.path().to_str().expect("temp path is not UTF-8").to_string();
    assert!(
        !tmp.contains(r"\edir") && !tmp.contains(r"\ndir"),
        "the temp root {tmp:?} already contains one of the substitution tokens, so the \
         existing-versus-missing comparison below would be meaningless"
    );
    let root_e = format!(r"{tmp}\edir");
    let root_n = format!(r"{tmp}\ndir");
    std::fs::create_dir(&root_e).expect("create the root that exists");

    report_roots(&[r"C:\dir", root_e.as_str(), root_n.as_str()]);
    println!(
        "each row resolves under {:?}; `root-existence` re-runs the SAME shape under {root_e:?} \
         (created) and {root_n:?} (never created) and compares them after mapping one name onto \
         the other",
        r"C:\dir"
    );

    for (seg, note) in SEGMENTS {
        println!("--- segment {seg:?}  ({note})");
        for (position, shape) in POSITIONS {
            for (spelling, prefix) in [("plain   ", ""), ("verbatim", r"\\?\")] {
                let input = format!("{prefix}{}", build(shape, r"C:\dir", seg));
                match full_path_name_parts(&input) {
                    Ok((resolved, part)) => {
                        let part = part.map_or_else(|| "<none: names a directory>".to_string(), |p| format!("{p:?}"));
                        let verdict = if resolved == input { "unchanged" } else { "REWRITTEN" };
                        let existence = cross_root(prefix, shape, seg, &root_e, &root_n);
                        println!(
                            "  {position} {spelling} {input:?} -> {resolved:?}  file_part={part}  \
                             [{verdict}]  root-existence: {existence}"
                        );
                    }
                    Err(why) => println!("  {position} {spelling} {why}"),
                }
            }
        }
    }

    // Relative shapes resolve against the working directory rather than a drive root, which is a
    // third position again.
    println!("--- relative shapes");
    match std::env::current_dir() {
        Ok(cwd) => println!(
            "  resolved against the CWD {cwd:?}; `x.bat` there exists={}",
            cwd.join("x.bat").exists()
        ),
        Err(e) => println!("  could not read the working directory these resolve against: {e}"),
    }
    for input in [
        r"x.bat\y.\z.exe",
        r"x.bat\y. \z.exe",
        r"x.bat\y...\z.exe",
        r"x.bat\y.",
        r"x.bat\y. ",
        r"x.bat\y...",
        r"x.bat\y.\",
        r"x.bat\y. \",
        r"x.bat\y...\",
    ] {
        match full_path_name_parts(input) {
            Ok((resolved, part)) => {
                let part = part.map_or_else(|| "<none: names a directory>".to_string(), |p| format!("{p:?}"));
                println!("  {input:?} -> {resolved:?}  file_part={part}");
            }
            Err(why) => println!("  {why}"),
        }
    }
}

/// The same shape resolved under a root that exists and a root that does not, compared after
/// mapping the missing root's name onto the existing one. An error on either side is part of the
/// comparison.
///
/// The two roots are siblings of equal length, so the mapping is a plain substring replacement and
/// cannot itself introduce a difference. A case that pops above both roots produces text mentioning
/// neither, which compares equal without any mapping at all — also correct.
pub(crate) fn cross_root(prefix: &str, shape: &str, seg: &str, root_e: &str, root_n: &str) -> String {
    let existing = full_path_name(&format!("{prefix}{}", build(shape, root_e, seg)));
    let missing = full_path_name(&format!("{prefix}{}", build(shape, root_n, seg)));
    compare_across_roots(&existing, &missing, root_e, root_n)
}

/// Survey: is `\\?\C:\dir\..` -> `\\?\C:` a Win32 answer or a probe artefact?
///
/// It is the only result of
/// `dots_and_spaces::a_final_dots_and_spaces_component_is_stripped_even_verbatim` that is not a
/// usable path — no trailing separator, and drive-relative under a prefix whose whole point is that
/// nothing is relative. A trimmed `String` cannot say whether Win32 produced that or the probe cut
/// it short, so this reports the raw UTF-16 units, the length Win32 returned, an independent size
/// query, and where `lpFilePart` lands in the buffer.
#[test]
#[ignore = "platform survey: needs a Windows runner; prints a measurement rather than asserting"]
fn the_verbatim_parent_result_is_raw_or_truncated() {
    survey_platform();
    report_roots(&[r"C:\dir", r"C:\"]);
    for (input, note) in [
        (
            r"\\?\C:\dir\..",
            "the suspect: resolves to \"\\\\?\\C:\" with file_part \"C:\"",
        ),
        (
            r"\\?\C:\dir\..\",
            "the same input with a trailing separator, which resolves normally",
        ),
        (r"C:\dir\..", "control: the plain spelling of the suspect"),
        (r"\\?\C:\dir\x", "control: an ordinary name comes back whole"),
        (r"\\?\C:\..", "one level further up than the suspect"),
    ] {
        println!("--- {input:?}  ({note})");
        match full_path_name_raw(input) {
            Ok(report) => print!("{report}"),
            Err(why) => println!("  {why}"),
        }
    }
}

/// Survey: `x<sp>`, start to finish, in ONE directory.
///
/// `dots_and_spaces::only_dot_and_dotdot_are_refused_as_verbatim_file_names` gives each spelling
/// its own directory; here every step touches the same one and says so, so the plain and verbatim
/// `x<sp>` can be seen coexisting.
#[test]
#[ignore = "platform survey: needs a Windows runner; prints a measurement rather than asserting"]
fn x_space_measured_in_a_single_directory() {
    survey_platform();
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path().to_str().expect("temp path is not UTF-8").to_string();
    println!("THE ONE DIRECTORY. Every step below reads or writes inside {dir:?} and nowhere else.");

    let spellings = [
        ("plain    x<sp>", format!(r"{dir}\x ")),
        ("verbatim x<sp>", format!(r"\\?\{dir}\x ")),
        ("plain    x", format!(r"{dir}\x")),
        ("verbatim x", format!(r"\\?\{dir}\x")),
    ];
    let verbatim_dir = format!(r"\\?\{dir}");

    let show_dir = |label: &str| match listing(&verbatim_dir) {
        Ok(names) => println!("  listing of {dir:?} {label}: {names:?}"),
        Err(why) => println!("  listing of {dir:?} {label}: {why}"),
    };
    let read_back = |label: &str| {
        println!("  reading every spelling {label}:");
        for (tag, path) in &spellings {
            match std::fs::read_to_string(path) {
                Ok(body) => println!("    {tag} {path:?} -> reads the file written as {body:?}"),
                Err(e) => println!(
                    "    {tag} {path:?} -> FAILED: {e} (raw_os_error={:?})",
                    e.raw_os_error()
                ),
            }
        }
    };

    println!("step 1: the directory starts empty");
    show_dir("at step 1");

    println!(r"step 2: create through the PLAIN spelling {:?}", spellings[0].1);
    println!("  write: {}", outcome(&std::fs::write(&spellings[0].1, b"plain x<sp>")));
    show_dir("after step 2");
    read_back("after step 2");

    println!(r"step 3: create through the VERBATIM spelling {:?}", spellings[1].1);
    println!(
        "  write: {}",
        outcome(&std::fs::write(&spellings[1].1, b"verbatim x<sp>"))
    );
    show_dir("after step 3");
    read_back("after step 3");

    println!("step 4: what GetFullPathNameW makes of each spelling, with the files now on disk");
    for (tag, path) in &spellings {
        match full_path_name_parts(path) {
            Ok((resolved, part)) => {
                let part = part.map_or_else(|| "<none: names a directory>".to_string(), |p| format!("{p:?}"));
                println!("  {tag} {path:?} -> {resolved:?}  file_part={part}");
            }
            Err(why) => println!("  {tag} {why}"),
        }
    }
}
