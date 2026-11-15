//! M18: what std's spawn does today with an executable file that has no `#!` and is not a binary.
//! A shell fallback (`execvp`'s on `ENOEXEC`) runs it as a script. The test records; it asserts
//! only its preconditions. Writes only in its own temp directory.
//!
//! The `absolute` case is what cosca's macOS spawn hands std (it finds the program itself), so it
//! records the `/bin/sh` fallback that stays on macOS until macOS forks itself; Linux's own fork does
//! not have it. The second test asserts it, through cosca's own spawn, on macOS and Linux.

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
/// Each row starts with `route~`, a label inferred from std's source and not observed: `spawn` is the
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
            if let Err(e) = std::fs::remove_file(&marker) {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "remove {marker:?}: {e}");
            }
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
                "M18 {case}_{variant}=route~{route},{outcome},marker={}",
                marker.exists()
            );
        }
    }
}

/// The OS errno of a failed spawn, which the spawn gives as it is.
#[cfg(unix)]
fn raw_errno(error: &cosca::error::Error) -> Option<i32> {
    match error {
        cosca::error::Error::Io(e) => e.raw_os_error(),
        other => panic!("expected the OS's own error, got {other:?}"),
    }
}

/// cosca's spawn of a bare name finds the program itself, in the parent, and gives std (macOS) or the
/// child (Linux) its absolute path: the first file on the child's `PATH` is the program, whatever its mode,
/// where std's own `execvp` would skip it for a later executable one. And the `/bin/sh` fallback is the
/// stated macOS limit: a file with no `#!` and no binary format runs through the shell on macOS, and is
/// `ENOEXEC` on Linux, whose child makes one `execve`.
///
/// Mutants: the spawn leaves the search to std on macOS (the first file is skipped for the second); the
/// Linux child retries `ENOEXEC` through `/bin/sh`; the macOS spawn stops the shell fallback.
#[cfg(unix)]
#[skuld::test]
fn a_cosca_spawn_finds_its_program_in_the_parent_and_only_macos_falls_back_to_the_shell() {
    use std::os::unix::fs::PermissionsExt;

    let write = |dir: &std::path::Path, name: &str, body: &str, mode: u32| {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    };

    // The first file is the program, though it cannot be started: not skipped for the second.
    let first = tempfile::tempdir().expect("tempdir");
    let second = tempfile::tempdir().expect("tempdir");
    let ran = second.path().join("ran");
    write(first.path(), "m18-tool", "#!/bin/sh\n", 0o644);
    write(
        second.path(),
        "m18-tool",
        &format!("#!/bin/sh\n: > '{}'\n", ran.display()),
        0o755,
    );
    let mut cmd = common::command(common::Console::Hidden);
    cmd.args(["m18-tool"]).env(
        "PATH",
        std::env::join_paths([first.path(), second.path()]).expect("join"),
    );
    assert_eq!(
        raw_errno(&cmd.spawn().expect_err("the first file on the PATH is the program")),
        Some(libc::EACCES)
    );
    assert!(!ran.exists(), "the second file ran");

    // A file with no `#!` and no binary format.
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");
    write(
        dir.path(),
        "m18-script",
        &format!(": > '{}'\n", marker.display()),
        0o755,
    );
    let mut cmd = common::command(common::Console::Hidden);
    cmd.args(["m18-script"]).env("PATH", dir.path());
    let spawned = cmd.spawn();
    #[cfg(target_os = "macos")]
    {
        let child = spawned.expect("macOS runs a file with no `#!` through the shell");
        assert_eq!(child.wait().expect("wait").code(), Some(0));
        assert!(marker.exists(), "the shell did not run the script");
    }
    #[cfg(not(target_os = "macos"))]
    {
        let error = spawned.expect_err("only macOS runs a file with no `#!` through the shell");
        assert_eq!(raw_errno(&error), Some(libc::ENOEXEC), "{error:?}");
        assert!(!marker.exists(), "the script ran");
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
