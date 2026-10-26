//! M7b: how long, and of what form, a child's `=X:` value may be for ntdll to use it. M7 found that
//! a value over `MAX_PATH` is ignored; this finds where the line is. The runner and D1's arms are in
//! `tests/common/drive_rule.rs`; M7 has the other rows.

use crate::common::drive_rule::{canonical, dir_of_len, free_drive, run_as, Arm, Cwd, Render, Row, Var};
use crate::provenance::survey_platform;
use crate::test_groups::{path_probes, Group};

/// M7b: an `=X:` value naming an existing directory, of exactly 259, 260 and 261 UTF-16 units, and
/// one spelled `\\.\<T>:\…`, for the names `X:tool` and `X:` (X unmapped, printed `<X>:`). With the
/// bare name the result is the value, so its length is the value's; with `X:tool` it is five units
/// more, which tells a limit on the value from a limit on the result. A row prints the arm D1
/// predicts (`Value`) and the arm observed (`Root` when ntdll falls back to `X:\`, `Error` when
/// `GetFullPathNameW` fails).
///
/// Preconditions, asserted: each value directory has the length its row says; the child runs in the
/// row's cwd and sees the row's `=X:` value. The letter is searched in `G..=L`, as M7's.
#[skuld::test]
fn m7b_the_length_and_form_of_a_childs_drive_directory_value(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let tmp = tempfile::tempdir().expect("tempdir");
    let d = canonical(tmp.path());
    let e = format!(r"{d}\e");
    std::fs::create_dir(&e).expect("create the row's cwd");
    let letter = free_drive(b'G'..=b'L');
    let q = format!("{letter}:");
    let sr = format!("SystemRoot={}", std::env::var("SystemRoot").expect("SystemRoot"));
    let render = Render(vec![(d.clone(), "<d>".into())]);
    let drives = [(letter, 'X')];

    let sized = |units: usize| {
        // `dir_of_len` extends its base, so each length gets a base of its own.
        let value = dir_of_len(&format!(r"{d}\v{units}"), units);
        assert_eq!(
            value.encode_utf16().count(),
            units,
            "precondition: the value directory has {units} units"
        );
        value
    };
    let values = [
        ("units259", sized(259)),
        ("units260", sized(260)),
        ("units261", sized(261)),
        ("device", format!(r"\\.\{e}")),
    ];
    for (key, value) in &values {
        for (suffix, name) in [("tool", format!("{q}tool")), ("bare", q.clone())] {
            let row = Row {
                key: Box::leak(format!("{key}_{suffix}").into_boxed_str()),
                cwd: Cwd::Given(e.clone()),
                block: vec![sr.clone(), format!("={q}={value}")],
                name,
                arm: Arm::Value(value.clone()),
                var: Var::Is(Some(value.clone())),
            };
            run_as("M7b", &row, &render, &drives);
        }
    }
}
