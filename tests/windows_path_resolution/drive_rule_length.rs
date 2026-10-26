//! M7b: how long, and of what form, a child's `=X:` value may be for ntdll to use it. The runner and
//! D1's arms are in `tests/common/drive_rule.rs`.

use crate::common::drive_rule::{canonical, dir_of_len, free_drive, run_in, Arm, Cwd, Render, Row, Var};
use crate::common::testbin;
use crate::provenance::{or_missing, reg_dword, survey_platform};
use crate::test_groups::{path_probes, Group};

/// M7b: an `=X:` value naming an existing directory, of exactly 259, 260 and 261 UTF-16 units, and
/// one spelled `\\.\<T>:\…`, for the names `X:tool` and `X:` (X unmapped, printed `<X>:`). With the
/// bare name the result is the value, so its length is the value's; with `X:tool` it is five units
/// more, which tells a limit on the value from a limit on the result.
///
/// Each row runs twice, in a child without a `longPathAware` manifest (`cosca_testbin`, lines
/// labelled `M7b unaware`) and in one with it (`cosca_testbin_cwd`, `M7b aware`). Awareness takes
/// effect only with the machine's `LongPathsEnabled` policy, so the policy is printed too, as
/// `M7b policy LongPathsEnabled=<value>`; it is read, never changed.
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
    let policy = reg_dword(r"SYSTEM\CurrentControlSet\Control\FileSystem", "LongPathsEnabled");
    println!("M7b policy LongPathsEnabled={}", or_missing(policy.clone()));
    assert_eq!(
        policy,
        Ok(1),
        r"precondition: HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled is 1, which the `aware` half needs"
    );
    let children = [
        ("unaware", testbin(), false),
        ("aware", env!("CARGO_BIN_EXE_cosca_testbin_cwd"), true),
    ];

    let sized = |units: usize| dir_of_len(&format!(r"{d}\v{units}"), units);
    let values = [
        ("units259", sized(259)),
        ("units260", sized(260)),
        ("units261", sized(261)),
        ("device", format!(r"\\.\{e}")),
    ];
    for (key, value) in &values {
        for (suffix, name) in [("tool", format!("{q}tool")), ("bare", q.clone())] {
            for (half, bin, long_paths) in &children {
                let row = Row {
                    key: Box::leak(format!("{key}_{suffix}").into_boxed_str()),
                    cwd: Cwd::Given(e.clone()),
                    block: vec![sr.clone(), format!("={q}={value}")],
                    name: name.clone(),
                    arm: Arm::Value(value.clone()),
                    var: Var::Is(Some(value.clone())),
                };
                run_in(&format!("M7b {half}"), bin, *long_paths, &row, &render, &drives);
            }
        }
    }
}
