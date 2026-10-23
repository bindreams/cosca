//! M17: where `SetEnvironmentVariableW` puts a name, against N1's rule for `Env::set` (removes every
//! match, inserts in sorted place). Each case runs in a child whose block is exactly the case's
//! entries; the child changes only its own environment and dumps `GetEnvironmentStringsW` after
//! each call, so no test process's environment changes.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::process::Command;

use crate::common::testbin;
use crate::measure::probe;
use crate::provenance::survey_platform;
use crate::test_groups::{path_probes, Group};

/// `(case, block entries, ops)`. An op is `set:NAME=VALUE` or `remove:NAME`, applied in order.
fn cases(system_root: &str) -> Vec<(&'static str, Vec<String>, Vec<&'static str>)> {
    let sr = format!("SystemRoot={system_root}");
    vec![
        // (i) sorted blocks: a new name, a re-set name (also in another case), and names whose
        // upper case is not ASCII: `µ` (U+00B5, upper-cases to U+039C), `ß`, and a surrogate pair.
        (
            "sorted",
            vec!["A=1".into(), "B=1".into(), sr.clone(), "Z=1".into()],
            vec![
                "set:M=1",
                "set:B=2",
                "set:b=3",
                "set:µ=1",
                "set:ß=1",
                "set:𝔸=1",
                "set:a0=1",
            ],
        ),
        // (ii) a duplicated name: which entries a set or a remove touches, and which spelling stays.
        (
            "duplicate_set",
            vec!["Path=a".into(), "PATH=b".into(), sr.clone()],
            vec!["set:PATH=c"],
        ),
        (
            "duplicate_set_other_case",
            vec!["Path=a".into(), "PATH=b".into(), sr.clone()],
            vec!["set:path=d"],
        ),
        (
            "duplicate_remove",
            vec!["Path=a".into(), "PATH=b".into(), sr.clone()],
            vec!["remove:PATH"],
        ),
        // (iii) an unsorted block: where a new name lands, and where a re-set one stays.
        (
            "unsorted",
            vec!["Z=1".into(), "A=1".into(), sr, "M=1".into()],
            vec!["set:B=1", "set:N=1", "set:A=2"],
        ),
    ]
}

#[skuld::test]
fn m17_set_environment_variable_semantics(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let system_root = std::env::var("SystemRoot").expect("SystemRoot");
    for (case, entries, ops) in cases(&system_root) {
        let out = probe(
            Command::new(testbin())
                .arg("with-env-block")
                .args(&entries)
                .arg("--")
                .arg("env-set-probe")
                .args(&ops),
        );
        let sections = sections(&out);
        assert_eq!(
            sections.first().map(|(label, block)| (label.as_str(), block.clone())),
            Some(("before", entries.clone())),
            "precondition: the child started with exactly the case's block"
        );
        for (label, block) in sections {
            let block = block
                .iter()
                .map(|e| e.replace(&system_root, "<sr>"))
                .collect::<Vec<_>>();
            println!("M17 {case} {label}: {block:?}");
        }
    }
}

/// `env-set-probe`'s output: a `# <label>` line before each dump, then one hex-encoded entry per
/// line.
fn sections(out: &str) -> Vec<(String, Vec<String>)> {
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    for line in out.lines() {
        if let Some(label) = line.strip_prefix("# ") {
            sections.push((label.to_owned(), Vec::new()));
        } else {
            let units: Vec<u16> = (0..line.len())
                .step_by(4)
                .map(|i| u16::from_str_radix(&line[i..i + 4], 16).expect("hex"))
                .collect();
            let entry = OsString::from_wide(&units).to_string_lossy().into_owned();
            sections.last_mut().expect("a section header first").1.push(entry);
        }
    }
    sections
}
