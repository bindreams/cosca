//! M18: what std's spawn does today with an executable file that has no `#!` and is not a binary.
//! A shell fallback (`execvp`'s on `ENOEXEC`) runs it as a script. The test records; it asserts
//! only its preconditions. Writes only in its own temp directory.

#[cfg(unix)]
#[path = "common/mod.rs"]
mod common;

/// Runs `script` through std and records whether a shell ran it: its body creates the marker.
/// Three cases, each plain (no `pre_exec`) and with a no-op `pre_exec`:
///
/// - `absolute`: the path.
/// - `bare_set_path`: the name, with `Command::env("PATH", dir)`, which std cannot give
///   `posix_spawnp`.
/// - `bare_inherited`: the name, run by a `cosca_testbin` child whose own `PATH` is `dir`, so std
///   keeps `posix_spawnp`'s `PATH` search.
///
/// Each row starts with `route=`, a label taken from std's source and not observed: `spawn` is the
/// route std gives to `posix_spawn(p)` where it has one (glibc, macOS); `fork` is fork and
/// `execvp`, which `pre_exec` and a set `PATH` force. A change in std would leave the label wrong
/// while the outcome and marker stay measured. The `os` and `target_env` line says whether std has
/// `posix_spawn(p)` at all.
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
    for case in ["absolute", "bare_set_path", "bare_inherited"] {
        for variant in ["plain", "pre_exec"] {
            let _ = std::fs::remove_file(&marker);
            let pre_exec = variant == "pre_exec";
            let route = if pre_exec || case == "bare_set_path" {
                "fork"
            } else {
                "spawn"
            };
            let outcome = if case == "bare_inherited" {
                let mut cmd = std::process::Command::new(common::testbin());
                cmd.args(["std-spawn-bare", "m18-script", variant])
                    .env("PATH", dir.path());
                let out = common::output_locked(&mut cmd).expect("run the testbin");
                assert!(out.status.success(), "precondition: the testbin ran: {:?}", out.status);
                String::from_utf8_lossy(&out.stdout).trim_end().to_owned()
            } else {
                let mut cmd = if case == "absolute" {
                    std::process::Command::new(&script)
                } else {
                    let mut cmd = std::process::Command::new("m18-script");
                    cmd.env("PATH", dir.path());
                    cmd
                };
                if pre_exec {
                    // SAFETY: the closure does nothing, so it is async-signal-safe.
                    unsafe { cmd.pre_exec(|| Ok(())) };
                }
                match common::status_locked(&mut cmd) {
                    Ok(status) => format!("ok,{status}"),
                    Err(e) => format!("err={},{:?}", e.raw_os_error().unwrap_or(-1), e.kind()),
                }
            };
            println!(
                "M18 {case}_{variant}=route={route},{outcome},marker={}",
                marker.exists()
            );
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
