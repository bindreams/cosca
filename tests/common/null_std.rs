//! Runs the testbin's `spawn-with-null-std` mode and checks what each grandchild received.

use std::os::windows::process::CommandExt;

/// `CREATE_NO_WINDOW`: the intermediate gets a console of its own whether or not the test runner
/// has one, so the grandchildren's std handles do not depend on the runner's console.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The `<route>=<report>` lines of `spawn-with-null-std <backend> <nulled>`.
pub fn reports(backend: &str, nulled: &str) -> Vec<String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = std::process::Command::new(super::testbin());
    cmd.args(["spawn-with-null-std", backend, nulled])
        .arg(dir.path())
        .creation_flags(CREATE_NO_WINDOW);
    let out = super::output_locked(&mut cmd).expect("spawn the intermediate");
    assert!(
        out.status.success(),
        "intermediate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("UTF-8 report")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Every route spawned and its grandchild got the std handles `expected`, as from std's route.
/// The grandchildren of std and of cosca's std route inherit the stray handle; none of the raw
/// backend's does.
pub fn assert_every_route(backend: &str, nulled: &str, expected: &str) {
    let mut want = vec![
        format!("std={expected},stray=true"),
        format!("argv={expected},stray=true"),
    ];
    want.extend(
        ["exe", "fd3", "exe_merge"]
            .iter()
            .map(|route| format!("{route}={expected},stray=false")),
    );
    assert_eq!(reports(backend, nulled), want);
}
