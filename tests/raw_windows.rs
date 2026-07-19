//! Smoke tests for the testbin helper modes the raw-`CreateProcessW` backend tests rely on
//! (`read-fd` / `write-fd` / `argv0-report` / `isatty-fd`). Windows-only: the raw backend and
//! its fd/argv[0]/CRT-device proofs are a Windows concern, so the whole crate is `#![cfg(windows)]`.
//! These prove the four modes EXIST and emit their documented output over std pipes; the
//! executable-vs-argv[0] independence itself is proven later via the crate's own `Command`.
#![cfg(windows)]

use std::io::Write;
use std::process::{Command, Stdio};

#[path = "common/mod.rs"]
mod common;

/// `argv0-report` emits both an `argv0=` and an `image=` line. Spawned via a RAW
/// `std::process::Command`, so argv[0] is the exe path and the mode is `args[0]` — do NOT
/// prepend "subprocess_testbin" (that convention is the crate's own `Command`). This asserts
/// only that the mode works; the argv[0]≠exe behavior is proven later via `subprocess::Command`.
#[test]
fn testbin_argv0_report_emits_argv0_and_image() {
    let out = Command::new(common::testbin())
        .args(["argv0-report"])
        .output()
        .expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("argv0=") && s.contains("image="), "got: {s}");
}

/// `write-fd <n> <text>` writes `text` straight to CRT fd `n`. Targeting fd 1 (stdout) with a
/// piped stdout proves the fd→`File` path reaches the intended handle.
#[test]
fn testbin_write_fd_writes_to_the_target_fd() {
    let out = Command::new(common::testbin())
        .args(["write-fd", "1", "hello-fd1"])
        .output()
        .expect("spawn");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello-fd1");
}

/// `read-fd <n>` copies CRT fd `n` to stdout. Feeding a piped stdin (fd 0) and reading it back
/// on stdout proves the read direction of the fd→`File` path. The child sees EOF when the write
/// end drops — a real close event, not a timer.
#[test]
fn testbin_read_fd_copies_the_source_fd_to_stdout() {
    let mut child = Command::new(common::testbin())
        .args(["read-fd", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(b"payload-fd0")
        .expect("write stdin");
    // stdin dropped above → child reads to EOF, copies, exits.
    let out = child.wait_with_output().expect("wait");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "payload-fd0");
}

/// `isatty-fd <n>` reports `isatty=<0|1>` via `libc::isatty`. A piped fd is not a console, so a
/// piped stdout (fd 1) must classify as `isatty=0`.
#[test]
fn testbin_isatty_fd_reports_zero_for_a_pipe() {
    let out = Command::new(common::testbin())
        .args(["isatty-fd", "1"])
        .output()
        .expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("isatty=0"), "got: {s}");
}

// Raw `CreateProcessW` backend, sync path (Plan 12 Task 4) =====

/// The raw backend loads `executable()` while the child's argv[0] is the command line's first
/// token — the independence std cannot express on Windows. `argv0-report` echoes both, proving
/// the loaded image (`testbin`) differs from the reported argv[0] (`pretend-name`).
#[test]
fn executable_independent_of_argv0_on_windows() {
    let exe = common::testbin();
    let mut c = subprocess::Command::new();
    c.executable(exe)
        .commandline("pretend-name argv0-report")
        .stdout(subprocess::Stdio::pipe())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.stdout().unwrap(), &mut s).unwrap();
    child.wait().unwrap();
    assert!(
        s.contains("argv0=pretend-name") && s.to_lowercase().contains("testbin"),
        "{s}"
    );
}

/// An embedded NUL in the command line cannot reach `CreateProcessW` (it would truncate the
/// wide buffer); the raw backend rejects it up front as an `Io` error.
#[test]
fn embedded_nul_in_commandline_is_rejected() {
    let e = subprocess::Command::new()
        .executable(common::testbin())
        .commandline("a\u{0}b")
        .spawn()
        .unwrap_err();
    assert!(matches!(e, subprocess::error::Error::Io(_)), "{e:?}");
}

/// An embedded NUL in the working directory is rejected the same way (it would truncate the
/// wide `lpCurrentDirectory`).
#[test]
fn embedded_nul_in_cwd_is_rejected() {
    let mut c = subprocess::Command::new();
    c.executable(common::testbin())
        .commandline("x argv0-report")
        .current_dir(std::path::PathBuf::from("a\u{0}b"));
    assert!(matches!(c.spawn().unwrap_err(), subprocess::error::Error::Io(_)));
}

/// A `.bat`/`.cmd` reached via `executable()` is rejected BEFORE resolution (CVE-2024-24576): a
/// batch program has cmd.exe escaping semantics the raw quoter does not implement.
#[test]
fn batch_script_via_executable_is_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let bat = dir.path().join("x.bat");
    std::fs::write(&bat, b"@echo off\n").unwrap();
    let e = subprocess::Command::new()
        .executable(&bat)
        .commandline("x.bat")
        .spawn()
        .unwrap_err();
    assert!(matches!(e, subprocess::error::Error::Unsupported { .. }), "{e:?}");
}

// Raw backend, sync fd >= 3 via the MSVCRT lpReserved2 table (Plan 12 Task 5) =====

/// A child-writes pipe on fd 3 delivers the child's bytes to the parent's read end — proving the
/// fd-table wired fd 3 into the child's CRT and the parent kept the read end. EOF (from the child
/// closing fd 3 on exit) bounds the read; no timer.
#[test]
fn fd3_pipe_out_delivers_child_bytes() {
    let mut c = subprocess::Command::new();
    c.executable(common::testbin())
        .args(["subprocess_testbin", "write-fd", "3", "hi-fd3"])
        .fd(3, subprocess::Stdio::pipe_out())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.fd_read_end(subprocess::Fd::from(3)).unwrap(), &mut s).unwrap();
    child.wait().unwrap();
    assert_eq!(s, "hi-fd3");
}

/// A parent-writes pipe on fd 3 feeds the child: the child copies fd 3 to stdout, so dropping the
/// parent's write end (EOF) makes the child echo exactly what was written. EOF bounds both reads.
#[test]
fn fd3_pipe_in_feeds_child() {
    let mut c = subprocess::Command::new();
    c.executable(common::testbin())
        .args(["subprocess_testbin", "read-fd", "3"])
        .fd(3, subprocess::Stdio::pipe_in())
        .unwrap()
        .stdout(subprocess::Stdio::pipe())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut w = child.fd_write_end(subprocess::Fd::from(3)).unwrap();
    std::io::Write::write_all(&mut w, b"ping3").unwrap();
    drop(w); // child reads to EOF, copies, exits
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.stdout().unwrap(), &mut s).unwrap();
    child.wait().unwrap();
    assert_eq!(s, "ping3");
}

/// `Stdio::inherit()` on fd >= 3 has no defined parent stream to dup — the raw path rejects it via
/// the hardened `inherit_end` arm.
#[test]
fn inherit_on_fd3_is_unsupported() {
    let e = subprocess::Command::new()
        .executable(common::testbin())
        .args(["subprocess_testbin", "exit", "0"])
        .fd(3, subprocess::Stdio::inherit())
        .unwrap()
        .spawn()
        .unwrap_err();
    assert!(matches!(e, subprocess::error::Error::Unsupported { .. }), "{e:?}");
}

/// A regular file on fd 3 classifies as a disk file (`FILE_TYPE_DISK` -> no `FDEV`), so the child's
/// `_isatty(3)` reports 0. Deterministic device-class coverage with no console needed.
#[test]
fn fd3_file_is_not_a_tty() {
    let f = tempfile::tempfile().expect("tempfile");
    let mut c = subprocess::Command::new();
    c.executable(common::testbin())
        .args(["subprocess_testbin", "isatty-fd", "3"])
        .fd(3, subprocess::Stdio::from_file(f))
        .unwrap()
        .stdout(subprocess::Stdio::pipe())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.stdout().unwrap(), &mut s).unwrap();
    child.wait().unwrap();
    assert!(s.contains("isatty=0"), "file on fd3 is not a tty: {s}");
}

/// NUL is `FILE_TYPE_CHAR` -> `classify` = `CharDev` -> `FDEV`, so the child's `_isatty(3)` is
/// nonzero (MSVCRT returns the raw `FDEV` bit, `0x40`, not a normalized 1 — the file/pipe case
/// still returns 0). Deterministic `CharDev` coverage without allocating a real console.
#[test]
fn fd3_nul_is_a_char_device() {
    let mut c = subprocess::Command::new();
    c.executable(common::testbin())
        .args(["subprocess_testbin", "isatty-fd", "3"])
        .fd(3, subprocess::Stdio::null())
        .unwrap()
        .stdout(subprocess::Stdio::pipe())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.stdout().unwrap(), &mut s).unwrap();
    child.wait().unwrap();
    let val: i32 = s
        .trim()
        .strip_prefix("isatty=")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("unexpected isatty output: {s}"));
    assert_ne!(val, 0, "NUL on fd3 is a char device (tty), got {s}");
}

/// A descriptor whose dense fd table would exceed the `WORD`-sized `cbReserved2` field is rejected
/// up front (before any allocation), as `Unsupported`.
#[test]
fn oversized_fd_is_unsupported() {
    let e = subprocess::Command::new()
        .executable(common::testbin())
        .args(["subprocess_testbin", "exit", "0"])
        .fd(70_000, subprocess::Stdio::null())
        .unwrap()
        .spawn()
        .unwrap_err();
    assert!(matches!(e, subprocess::error::Error::Unsupported { .. }), "{e:?}");
}

// Containment over the raw backend (Plan 12 Task 6) =====

/// A CONTAINED child with fd >= 3 routes through the raw backend AND lands in OUR Job Object:
/// `test_job_handle_contains_self()` confirms membership (immutable once assigned, so it is
/// deterministic for a handle-pinned child regardless of run state), fd 3 delivers the child's
/// bytes, and `kill_tree()` tears the tree down cleanly. EOF (child closing fd 3 on exit) bounds
/// the read; no timer.
#[test]
fn contained_raw_child_is_in_our_job_and_kill_tree_reaps() {
    let mut c = subprocess::Command::new();
    c.executable(common::testbin())
        .args(["subprocess_testbin", "write-fd", "3", "x"])
        .fd(3, subprocess::Stdio::pipe_out())
        .unwrap()
        .contain();
    let mut child = c.spawn().expect("contained raw spawn");
    // Fixed at spawn (run-state-independent): the achieved mechanism is the Job Object.
    assert_eq!(child.containment(), subprocess::Containment::JobObject);
    assert!(child.test_job_handle_contains_self(), "child must be inside OUR job");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.fd_read_end(subprocess::Fd::from(3)).unwrap(), &mut s).unwrap();
    assert_eq!(s, "x");
    child.kill_tree().expect("kill_tree");
}

/// An UNCONTAINED executable spawn (no `.contain()`) reports `Containment::None` — the raw backend
/// wires containment only when requested; without it the child is a lone process.
#[test]
fn uncontained_raw_child_has_no_containment() {
    let mut c = subprocess::Command::new();
    c.executable(common::testbin())
        .commandline("x argv0-report")
        .stdout(subprocess::Stdio::pipe())
        .unwrap();
    assert!(matches!(
        c.spawn().unwrap().containment(),
        subprocess::Containment::None
    ));
}
