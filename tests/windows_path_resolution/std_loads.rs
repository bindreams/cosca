//! M5, std's column: what `main` loads for an argv-only command, one row per §3 case of the
//! untangling plan and at least one member of each class it lists. P7 asserts its own column
//! against these.

use std::process::Command;

use crate::common::testbin;
use crate::measure::{canonical, probe, record};
use crate::provenance::survey_platform;
use crate::test_groups::{path_probes, Group};

/// The probe runs as a copy of `cosca_testbin` in `<t>\app`, so std's application directory is
/// one this test owns, with `<t>` as its cwd and `<t>\p` first on its `PATH`. Each row reports
/// `std=` (`std::process::Command`), `cosca=` (an argv-only `cosca::Command`, std's route on
/// `main`) and `raw_fd3=` (the same with fd 3 mapped, the raw backend). Class 8 runs in a second
/// probe whose environment block holds `Path` and then `PATH`.
#[skuld::test]
fn m5_what_std_loads(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let root = tempfile::tempdir().expect("tempdir");
    let t = canonical(root.path());
    let app = t.join("app");
    std::fs::create_dir(&app).expect("create <t>\\app");
    let probe_exe = app.join("cosca_testbin.exe");
    std::fs::copy(testbin(), &probe_exe).expect("copy the probe");
    let image = env!("CARGO_BIN_EXE_cosca_testbin_image");

    let parent_path = std::env::var_os("PATH").expect("PATH");
    let mut path = t.join("p").into_os_string();
    path.push(";");
    path.push(&parent_path);
    let report = probe(
        Command::new(&probe_exe)
            .args(["std-loads"])
            .arg(&t)
            .arg(image)
            .current_dir(&t)
            .env("PATH", path),
    );
    record("M5", &report);

    let system_root = std::env::var("SystemRoot").expect("SystemRoot");
    let block = [
        format!("Path={}", t.join("c8a").display()),
        format!("PATH={}", t.join("c8b").display()),
        format!("SystemRoot={system_root}"),
    ];
    let report = probe(
        Command::new(&probe_exe)
            .arg("with-env-block")
            .args(&block)
            .args(["--", "std-loads-dup"])
            .arg(&t)
            .arg(image),
    );
    record("M5", &report);
}
