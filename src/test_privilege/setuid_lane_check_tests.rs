//! Tests of `.github/scripts/setuid-lane-check.sh` against fake helpers. The script takes its uid
//! and OS from `SETUID_LANE_CHECK_UID` and `SETUID_LANE_CHECK_OS`, so every case runs on every host
//! and none depends on who the caller is.

use std::io::Write as _;
use std::path::Path;
use std::process::{Output, Stdio};

// Selection only.
skuld::default_labels!(crate::test_harness::SETUID);

const LINUX: &str = "Linux";
const DARWIN: &str = "Darwin";

/// The real helper's stderr line when `r` follows `n` on Linux.
const EINVAL_LINE: &str = "setuid-stdin-block: setresuid(0, 0, 0): Invalid argument (os error 22)";

/// The invocation the script must make: `printf nr | helper setuid-stdin-block root` on Linux,
/// `helper setuid-stdin-block root </dev/null` on macOS. A fake exits 99 on any other.
fn prelude(os: &str) -> &'static str {
    match os {
        LINUX => r#"[ "$#" = 2 ] && [ "$1" = setuid-stdin-block ] && [ "$2" = root ] && [ "$(cat)" = nr ] || exit 99;"#,
        _ => r#"[ "$#" = 2 ] && [ "$1" = setuid-stdin-block ] && [ "$2" = root ] && [ -z "$(cat)" ] || exit 99;"#,
    }
}

/// A fake that behaves as a real helper does on `os`.
fn good(os: &str) -> String {
    match os {
        LINUX => format!("{} printf '+N'; echo '{EINVAL_LINE}' >&2; exit 3", prelude(os)),
        _ => format!("{} printf '+'", prelude(os)),
    }
}

/// Writes an executable script. The write descriptor must be closed before anything execs the
/// file, or `exec` fails with `ETXTBSY`; a fork that never execs, from another test thread, would
/// inherit it, so no such fork may land inside the write.
fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let _guard = crate::child::spawn::spawn_lock();
    assert!(
        crate::test_spawn::held_by_this_thread(),
        "the fake must be written under spawn_lock"
    );
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn lane_check(os: &str, uid: &str, body: &str) -> Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let fake = dir.path().join("helper");
    write_executable(&fake, body);
    let mut cmd = std::process::Command::new("bash");
    cmd.arg(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/scripts/setuid-lane-check.sh"
    ))
    .arg(&fake)
    .env("SETUID_LANE_CHECK_OS", os)
    .env("SETUID_LANE_CHECK_UID", uid);
    crate::test_spawn::output_captured(&mut cmd).expect("run the lane check")
}

fn assert_rejected(name: &str, out: &Output, reason: &str) {
    assert!(!out.status.success(), "{name}: the lane check passed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("::error::setuid lane check failed") && stderr.contains(reason),
        "{name}: expected the reason {reason:?}, got: {stderr}"
    );
}

#[skuld::test]
fn setuid_lane_check_accepts_a_helper_that_behaves_like_a_real_one() {
    for os in [LINUX, DARWIN] {
        let out = lane_check(os, "1000", &good(os));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{os}: {stderr}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("setuid lane ok"),
            "{os}: {out:?}"
        );
    }
}

#[skuld::test]
fn setuid_lane_check_rejects_a_root_caller_before_reading_the_helper() {
    for os in [LINUX, DARWIN] {
        let out = lane_check(os, "0", &good(os));
        assert_rejected(os, &out, "the caller is uid 0");
    }
}

#[skuld::test]
fn setuid_lane_check_rejects_an_unsupported_os() {
    assert_rejected(
        "Plan9",
        &lane_check("Plan9", "1000", &good(LINUX)),
        "unsupported OS Plan9",
    );
}

/// A helper that does not reach uid 0 prints nothing, or the wrong thing, or exits wrongly: the
/// check must fail for each, and say why.
#[skuld::test]
fn setuid_lane_check_rejects_a_linux_helper_that_does_not_reach_root() {
    let p = prelude(LINUX);
    for (name, tail, reason) in [
        ("silent", "".to_owned(), "printed ''"),
        ("wrong output", "printf 'x'".to_owned(), "printed 'x'"),
        ("extra output", "printf '+N+'".to_owned(), "printed '+N+'"),
        ("no failure after unshare", "printf '+N'".to_owned(), "exited 0"),
        (
            "exit 1 with the right stderr",
            format!("printf '+N'; echo '{EINVAL_LINE}' >&2; exit 1"),
            "exited 1",
        ),
        (
            "only the syscall named",
            "printf '+N'; echo 'setresuid(0, 0, 0): boom' >&2; exit 3".to_owned(),
            "does not name the failed setresuid",
        ),
        (
            "only the errno named",
            "printf '+N'; echo 'Invalid argument' >&2; exit 3".to_owned(),
            "does not name the failed setresuid",
        ),
        (
            "neither named",
            "printf '+N'; echo boom >&2; exit 3".to_owned(),
            "does not name the failed setresuid",
        ),
    ] {
        assert_rejected(name, &lane_check(LINUX, "1000", &format!("{p} {tail}")), reason);
    }
}

#[skuld::test]
fn setuid_lane_check_rejects_a_macos_helper_that_does_not_reach_root() {
    let p = prelude(DARWIN);
    for (name, tail, reason) in [
        ("silent", "", "printed ''"),
        ("wrong output", "printf 'x'", "printed 'x'"),
        ("extra output", "printf '++'", "printed '++'"),
        ("exit 3", "printf '+'; exit 3", "exited nonzero (3)"),
        ("exit 1", "printf '+'; exit 1", "exited nonzero (1)"),
    ] {
        assert_rejected(name, &lane_check(DARWIN, "1000", &format!("{p} {tail}")), reason);
    }
}

/// The fakes above are only as strict as their prelude: it must exit 99 on any other invocation.
#[skuld::test]
fn setuid_lane_check_fake_rejects_any_other_invocation() {
    fn run(os: &str, args: &[&str], stdin: &str) -> Option<i32> {
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join("helper");
        write_executable(&fake, &good(os));
        let mut cmd = std::process::Command::new(&fake);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the fake");
        // A fake that rejects the invocation exits without reading stdin: a broken pipe is its answer.
        match child.stdin.take().unwrap().write_all(stdin.as_bytes()) {
            Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => panic!("write the fake's stdin: {e}"),
            _ => {}
        }
        child.wait().expect("wait for the fake").code()
    }
    let real = ["setuid-stdin-block", "root"];
    assert_eq!(run(LINUX, &real, "nr"), Some(3));
    assert_eq!(run(DARWIN, &real, ""), Some(0));
    for os in [LINUX, DARWIN] {
        let stdin = if os == LINUX { "nr" } else { "" };
        assert_eq!(
            run(os, &["setuid-stdin-block", "permitted"], stdin),
            Some(99),
            "{os} mode"
        );
        assert_eq!(run(os, &["other", "root"], stdin), Some(99), "{os} subcommand");
        assert_eq!(run(os, &["setuid-stdin-block"], stdin), Some(99), "{os} arity");
        assert_eq!(
            run(os, &["setuid-stdin-block", "root", "x"], stdin),
            Some(99),
            "{os} extra arg"
        );
    }
    assert_eq!(run(LINUX, &real, "n"), Some(99), "linux stdin");
    assert_eq!(run(LINUX, &real, ""), Some(99), "linux empty stdin");
    assert_eq!(run(DARWIN, &real, "n"), Some(99), "darwin stdin");
}
