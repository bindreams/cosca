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
