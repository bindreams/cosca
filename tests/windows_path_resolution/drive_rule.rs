//! M7: the `=X:` rows that need no mapped drive. `tests/common/drive_rule.rs` has the runner and
//! D1's arms; `windows_process_cwd.rs` has the rows that need a mapped drive: an `=X:` value naming
//! a directory on drive X itself, and a partially qualified value whose target must exist.

use crate::common::drive_rule::{canonical, free_drive, run, Arm, Cwd, Render, Row, Var};
use crate::provenance::survey_platform;
use crate::test_groups::{path_probes, Group};

/// M7's rows that need no mapped drive: an unmapped drive letter (printed `<X>:`) whose `=X:` value,
/// where it names a directory, names one on the temp directory's drive T (printed `<T>:`). Then the
/// rows where E is on T, verbatim or UNC. The rows whose value must exist relative to the child's cwd
/// are in `windows_process_cwd`'s mapped test. The letter is searched in `G..=L`, disjoint from the
/// mapped tests' `M..=Z`.
///
/// Preconditions, asserted: the child runs in the row's cwd and sees the row's `=X:` value (for a
/// `Recorded` row, one the block holds). The UNC rows, last, need `\\localhost\<T>$` served and
/// openable, as CI runners serve it.
#[skuld::test]
fn m7_a_drive_relative_name_against_a_childs_block_without_a_mapped_drive(#[fixture(path_probes)] _group: &Group) {
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
    let letter = free_drive(b'G'..=b'L');
    let q = format!("{letter}:");
    let lq = q.to_ascii_lowercase();
    let lt = t.to_ascii_lowercase();
    let sr = format!("SystemRoot={}", std::env::var("SystemRoot").expect("SystemRoot"));
    let unc = format!(r"\\localhost\{}${}", &t[..1], &d[2..]);
    let render = Render(vec![(unc.clone(), "<unc>".into()), (d.clone(), "<d>".into())]);
    let drives = [(letter, 'X'), (t.chars().next().expect("a drive"), 'T')];

    let given = || Cwd::Given(e.clone());
    let block = |entries: &[String]| [vec![sr.clone()], entries.to_vec()].concat();
    let set = |v: &str| Var::Is(Some(v.to_owned()));
    let rows = vec![
        // Replays the drive rule's value cases through a child's block. The partially qualified
        // values are in `windows_process_cwd`: they need a target that exists.
        Row {
            key: "unset",
            cwd: given(),
            block: block(&[]),
            name: format!("{q}tool"),
            arm: Arm::Root,
            var: Var::Is(None),
        },
        Row {
            key: "other_drive",
            cwd: given(),
            block: block(&[format!("={q}={exists}")]),
            name: format!("{q}tool"),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
        Row {
            key: "empty",
            cwd: given(),
            block: block(&[format!("={q}=")]),
            name: format!("{q}tool"),
            arm: Arm::Root,
            var: set(""),
        },
        // Case and drive units.
        Row {
            key: "lowercase_program",
            cwd: given(),
            block: block(&[format!("={q}={exists}")]),
            name: format!("{lq}tool"),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
        Row {
            key: "lowercase_key",
            cwd: given(),
            block: block(&[format!("={lq}={exists}")]),
            name: format!("{q}tool"),
            arm: Arm::Value(exists.clone()),
            var: Var::Recorded,
        },
        Row {
            key: "digit_drive",
            cwd: given(),
            block: block(&[format!("=1:={exists}")]),
            name: "1:tool".into(),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
        Row {
            key: "e_acute_drive",
            cwd: given(),
            block: block(&[format!("=é:={exists}")]),
            name: "é:tool".into(),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
        Row {
            key: "e_acute_drive_upper_key",
            cwd: given(),
            block: block(&[format!("=É:={exists}")]),
            name: "é:tool".into(),
            arm: Arm::Value(exists.clone()),
            var: Var::Recorded,
        },
        // Duplicates in an inherited block: D1 reads the first match.
        Row {
            key: "duplicate_lower_first",
            cwd: given(),
            block: block(&[format!("={lq}={exists}"), format!("={q}={exists2}")]),
            name: format!("{q}tool"),
            arm: Arm::Value(exists.clone()),
            var: Var::Recorded,
        },
        Row {
            key: "duplicate_upper_first",
            cwd: given(),
            block: block(&[format!("={q}={exists}"), format!("={lq}={exists2}")]),
            name: format!("{q}tool"),
            arm: Arm::Value(exists.clone()),
            var: Var::Recorded,
        },
        // `env_clear()`: the block is empty, so there is no `=X:` either.
        Row {
            key: "env_clear",
            cwd: given(),
            block: vec![],
            name: format!("{q}tool"),
            arm: Arm::Root,
            var: Var::Is(None),
        },
        // E on T, the name's own drive: `Base`, whatever `=T:` holds.
        Row {
            key: "e_on_the_drive_given",
            cwd: given(),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: Arm::Base,
            var: set(&exists),
        },
        Row {
            key: "e_on_the_drive_inherited",
            cwd: Cwd::Inherited(e.clone()),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: Arm::Base,
            var: set(&exists),
        },
        Row {
            key: "e_on_the_drive_lowercase_program",
            cwd: given(),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{lt}tool"),
            arm: Arm::Base,
            var: set(&exists),
        },
        // A verbatim E has no drive, so D1 takes `=T:`.
        Row {
            key: "verbatim_e",
            cwd: Cwd::Given(format!(r"\\?\{e}")),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
    ];
    for row in &rows {
        run(row, &render, &drives);
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
            arm: Arm::Value(unc_exists.clone()),
            var: set(&unc_exists),
        },
        // A UNC E has no drive either.
        Row {
            key: "unc_e",
            cwd: Cwd::Given(format!(r"{unc}\e")),
            block: block(&[format!("={t}={exists}")]),
            name: format!("{t}tool"),
            arm: Arm::Value(exists.clone()),
            var: set(&exists),
        },
    ];
    for row in &unc_rows {
        run(row, &render, &drives);
    }
}
