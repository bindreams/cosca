//! Tests of `.github/scripts/setuid-lane-check.sh` against fake helpers.

/// A helper body that behaves as a real one does on this OS.
#[cfg(target_os = "linux")]
const GOOD: &str = "cat > /dev/null; printf '+N'; echo 'setuid-stdin-block: setresuid(0, 0, 0): Invalid argument (os error 22)' >&2; exit 3";
#[cfg(not(target_os = "linux"))]
const GOOD: &str = "cat > /dev/null; printf '+'";

/// The output a real helper prints on this OS.
#[cfg(target_os = "linux")]
const GOOD_OUT: &str = "+N";
#[cfg(not(target_os = "linux"))]
const GOOD_OUT: &str = "+";

fn lane_check(helper_body: &str) -> std::process::Output {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let fake = dir.path().join("helper");
    std::fs::write(&fake, format!("#!/bin/sh\n{helper_body}\n")).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut cmd = std::process::Command::new("bash");
    cmd.arg(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/scripts/setuid-lane-check.sh"
    ))
    .arg(&fake);
    crate::test_spawn::output_captured(&mut cmd).expect("run the lane check")
}

/// The script rejects a caller that is root, before it looks at the helper. Every case below
/// names its own reason, so a root run fails here instead of passing vacuously.
fn assert_unprivileged_caller() {
    // SAFETY: `geteuid` has no preconditions.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "the lane check tests need an unprivileged caller: the script rejects uid 0 before it reads the helper"
    );
}

#[test]
fn setuid_lane_check_accepts_a_helper_that_behaves_like_a_real_one() {
    assert_unprivileged_caller();
    let out = lane_check(GOOD);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("setuid lane ok"),
        "{out:?}"
    );
}

/// A helper that does not reach uid 0 prints nothing, or the wrong thing, or exits wrongly: the
/// check must fail for each, and say why.
#[test]
fn setuid_lane_check_rejects_a_helper_that_does_not_reach_root() {
    assert_unprivileged_caller();
    let mut cases = vec![
        ("silent", "cat > /dev/null".to_owned(), "printed ''".to_owned()),
        (
            "wrong output",
            "cat > /dev/null; printf 'x'".to_owned(),
            "printed 'x'".to_owned(),
        ),
        (
            "extra output",
            format!("cat > /dev/null; printf '{GOOD_OUT}+'"),
            format!("printed '{GOOD_OUT}+'"),
        ),
    ];
    #[cfg(target_os = "linux")]
    cases.extend([
        (
            "no failure after unshare",
            "cat > /dev/null; printf '+N'".to_owned(),
            "exited 0".to_owned(),
        ),
        (
            "failure without the EINVAL",
            "cat > /dev/null; printf '+N'; echo boom >&2; exit 3".to_owned(),
            "does not name the failed setresuid".to_owned(),
        ),
    ]);
    #[cfg(not(target_os = "linux"))]
    cases.push((
        "nonzero exit",
        format!("cat > /dev/null; printf '{GOOD_OUT}'; exit 3"),
        "exited nonzero".to_owned(),
    ));
    for (name, body, reason) in cases {
        let out = lane_check(&body);
        assert!(!out.status.success(), "{name}: the lane check passed");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("::error::setuid lane check failed") && stderr.contains(&reason),
            "{name}: expected the reason {reason:?}, got: {stderr}"
        );
    }
}
