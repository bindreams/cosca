//! M7 (#156, untangling P1a): the `=X:` rows that need no mapped drive. `tests/common/drive_rule.rs`
//! has the runner and D1's arms; `windows_process_cwd.rs` has the rows whose `=X:` value names a
//! directory on drive X itself, which needs X mapped.

use crate::common::drive_rule::{canonical, free_drive, run, Cwd, Render, Row, Var};
use crate::provenance::survey_platform;
use crate::test_groups::{path_probes, Group};

/// Survey: M7's rows on an unmapped drive letter (rendered `D:`), with every `=D:` value naming a
/// directory on the temp directory's drive T. Then the rows where E is on T, verbatim or UNC.
///
/// Preconditions, asserted: the child runs in the row's cwd and sees the row's `=X:` value. The UNC
/// rows, last, need `\\localhost\<T>$` served and openable, as CI runners serve it.
#[skuld::test]
fn m7_a_drive_relative_name_against_the_childs_own_drive_directory(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let tmp = tempfile::tempdir().expect("tempdir");
    let d = canonical(tmp.path());
    for sub in ["e", "exists", "exists2"] {
        std::fs::create_dir(format!(r"{d}\{sub}")).expect("create the row directories");
    }
    let e = format!(r"{d}\e");
    let exists = format!(r"{d}\exists");
    let exists2 = format!(r"{d}\exists2");
    let t = &d[..2];
    let letter = free_drive(b'G'..=b'Z');
    let q = format!("{letter}:");
    let lq = q.to_ascii_lowercase();
    let lt = t.to_ascii_lowercase();
    let sr = format!("SystemRoot={}", std::env::var("SystemRoot").expect("SystemRoot"));
    let unc = format!(r"\\localhost\{}${}", &t[..1], &d[2..]);
    let render = Render(vec![(unc.clone(), "<unc>".into()), (d.clone(), "<d>".into())]);
    println!("M7 drive_t={t}");

    let given = || Cwd::Given(e.clone());
    let block = |entries: &[String]| [vec![sr.clone()], entries.to_vec()].concat();
    let set = |v: &str| Var::Is(Some(v.to_owned()));
    let rows = vec![
        // #173's B3 values, replayed through a child's block. `=D:` names no existing directory
        // here except where it names one on T.
        Row {
            key: "unset",
            cwd: given(),
            block: block(&[]),
            name: format!("{q}tool"),
            arm: "Root",
            predicted: format!(r"{q}\tool"),
            var: Var::Is(None),
        },
        Row {
            key: "drive_relative",
            cwd: given(),
            block: block(&[format!("={q}={q}exists")]),
            name: format!("{q}tool"),
            arm: "Root",
            predicted: format!(r"{q}\tool"),
            var: set(&format!("{q}exists")),
        },
        Row {
            key: "relative",
            cwd: given(),
            block: block(&[format!("={q}=exists")]),
            name: format!("{q}tool"),
            arm: "Root",
            predicted: format!(r"{q}\tool"),
            var: set("exists"),
        },
        Row {
            key: "rooted",
            cwd: given(),
            block: block(&[format!(r"={q}=\exists")]),
            name: format!("{q}tool"),
            arm: "Root",
            predicted: format!(r"{q}\tool"),
            var: set(r"\exists"),
        },
        Row {
            key: "other_drive",
            cwd: given(),
            block: block(&[format!("={q}={exists}")]),
            name: format!("{q}tool"),
            arm: "Value",
            predicted: format!(r"{exists}\tool"),
            var: set(&exists),
        },
        Row {
            key: "empty",
            cwd: given(),
            block: block(&[format!("={q}=")]),
            name: format!("{q}tool"),
            arm: "Root",
            predicted: format!(r"{q}\tool"),
            var: set(""),
        },
        // Case and drive units.
        Row {
            key: "lowercase_program",
            cwd: given(),
            block: block(&[format!("={q}={exists}")]),
            name: format!("{lq}tool"),
            arm: "Value",
            predicted: format!(r"{exists}\tool"),
            var: set(&exists),
        },
        Row {
            key: "lowercase_key",
            cwd: given(),
            block: block(&[format!("={lq}={exists}")]),
            name: format!("{q}tool"),
            arm: "Value",
            predicted: format!(r"{exists}\tool"),
            var: Var::Recorded,
        },
        Row {
            key: "digit_drive",
            cwd: given(),
            block: block(&[format!("=1:={exists}")]),
            name: "1:tool".into(),
            arm: "Value",
            predicted: format!(r"{exists}\tool"),
            var: set(&exists),
        },
        Row {
            key: "e_acute_drive",
            cwd: given(),
            block: block(&[format!("=é:={exists}")]),
            name: "é:tool".into(),
            arm: "Value",
            predicted: format!(r"{exists}\tool"),
            var: set(&exists),
        },
        Row {
            key: "e_acute_drive_upper_key",
            cwd: given(),
            block: block(&[format!("=É:={exists}")]),
            name: "é:tool".into(),
            arm: "Value",
            predicted: format!(r"{exists}\tool"),
            var: Var::Recorded,
        },
        // Duplicates in an inherited block: D1 reads the first match.
        Row {
            key: "duplicate_lower_first",
            cwd: given(),
            block: block(&[format!("={lq}={exists}"), format!("={q}={exists2}")]),
            name: format!("{q}tool"),
            arm: "Value",
            predicted: format!(r"{exists}\tool"),
            var: Var::Recorded,
        },
        Row {
            key: "duplicate_upper_first",
            cwd: given(),
            block: block(&[format!("={q}={exists}"), format!("={lq}={exists2}")]),
            name: format!("{q}tool"),
            arm: "Value",
            predicted: format!(r"{exists}\tool"),
            var: Var::Recorded,
        },
        // `env_clear()`: the block is empty, so there is no `=D:` either.
        Row {
            key: "env_clear",
            cwd: given(),
            block: vec![],
            name: format!("{q}tool"),
            arm: "Root",
            predicted: format!(r"{q}\tool"),
            var: Var::Is(None),
        },
        // E on T, the name's own drive: `Base`, whatever `=T:` holds.
        Row {
            key: "e_on_the_drive_given",
            cwd: given(),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: "Base",
            predicted: format!(r"{e}\tool"),
            var: set(&exists),
        },
        Row {
            key: "e_on_the_drive_inherited",
            cwd: Cwd::Inherited(e.clone()),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: "Base",
            predicted: format!(r"{e}\tool"),
            var: set(&exists),
        },
        Row {
            key: "e_on_the_drive_lowercase_program",
            cwd: given(),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{lt}tool"),
            arm: "Base",
            predicted: format!(r"{e}\tool"),
            var: set(&exists),
        },
        // A verbatim E has no drive, so D1 takes `=T:`. The row blocks P4 and P5 if ntdll takes E.
        Row {
            key: "verbatim_e",
            cwd: Cwd::Given(format!(r"\\?\{e}")),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: "Value",
            predicted: format!(r"{exists}\tool"),
            var: set(&exists),
        },
    ];
    for row in &rows {
        run(row, &render, Some((letter, 'D')));
    }

    assert!(
        std::path::Path::new(&format!(r"{unc}\exists")).is_dir(),
        "precondition: {unc} is reachable through the administrative share"
    );
    let unc_exists = format!(r"{unc}\exists");
    let unc_rows = vec![
        Row {
            key: "unc_value",
            cwd: given(),
            block: block(&[format!("={q}={unc_exists}")]),
            name: format!("{q}tool"),
            arm: "Value",
            predicted: format!(r"{unc_exists}\tool"),
            var: set(&unc_exists),
        },
        // A UNC E has no drive either.
        Row {
            key: "unc_e",
            cwd: Cwd::Given(format!(r"{unc}\e")),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: "Value",
            predicted: format!(r"{exists}\tool"),
            var: set(&exists),
        },
    ];
    for row in &unc_rows {
        run(row, &render, Some((letter, 'D')));
    }
}
