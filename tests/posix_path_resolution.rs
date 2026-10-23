//! M18: what std's spawn does today with an executable file that has no `#!` and is not a binary.
//! A shell fallback (`execvp`'s on `ENOEXEC`) runs it as a script. The test records; it asserts
//! only its preconditions. Writes only in its own temp directory.

#[cfg(unix)]
#[path = "common/mod.rs"]
mod common;

/// Spawns `script` by each std route and records whether a shell ran it: its body creates the
/// marker. `(i)` is a plain `std::process::Command` (`posix_spawnp` where std takes it), `(ii)`
/// the same with a no-op `pre_exec`, which forces fork and `execvp`. Each runs as an absolute path
/// and as a bare name found on `PATH`.
#[cfg(unix)]
#[skuld::test]
fn m18_std_routes_and_the_shell_fallback() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");
    let script = dir.path().join("m18-script");
    let body = format!(": > '{}'\n", marker.display());
    std::fs::write(&script, &body).expect("write the script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod 0755");

    // Preconditions: executable, no `#!`, and not an image the kernel loads.
    let mode = std::fs::metadata(&script).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "precondition: the script is mode 0755");
    let head = std::fs::read(&script).expect("read the script");
    assert!(!head.starts_with(b"#!"), "precondition: no #! line");
    assert!(
        !head.starts_with(b"\x7fELF") && !head.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]),
        "precondition: not an ELF or Mach-O image"
    );

    println!("M18 os={} target_env={}", std::env::consts::OS, target_env());
    for (name, program) in [("absolute", script.as_os_str()), ("bare", "m18-script".as_ref())] {
        for (route, pre_exec) in [("plain", false), ("pre_exec", true)] {
            let _ = std::fs::remove_file(&marker);
            let mut cmd = std::process::Command::new(program);
            cmd.env("PATH", dir.path());
            if pre_exec {
                // SAFETY: the closure does nothing, so it is async-signal-safe.
                unsafe { cmd.pre_exec(|| Ok(())) };
            }
            let outcome = match common::status_locked(&mut cmd) {
                Ok(status) => format!("ok,{status}"),
                Err(e) => format!("err={},{:?}", e.raw_os_error().unwrap_or(-1), e.kind()),
            };
            println!("M18 {name}_{route}={outcome},marker={}", marker.exists());
        }
    }
}

#[cfg(unix)]
fn target_env() -> &'static str {
    if cfg!(target_env = "gnu") {
        "gnu"
    } else if cfg!(target_env = "musl") {
        "musl"
    } else {
        "other"
    }
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
