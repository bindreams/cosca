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
/// prepend "cosca_testbin" (that convention is the crate's own `Command`). This asserts
/// only that the mode works; the argv[0]≠exe behavior is proven later via `cosca::Command`.
#[test]
fn testbin_argv0_report_emits_argv0_and_image() {
    let mut cmd = Command::new(common::testbin());
    cmd.args(["argv0-report"]);
    let out = common::output_locked(&mut cmd).expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("argv0=") && s.contains("image="), "got: {s}");
}

/// `write-fd <n> <text>` writes `text` straight to CRT fd `n`. Targeting fd 1 (stdout) with a
/// piped stdout proves the fd→`File` path reaches the intended handle.
#[test]
fn testbin_write_fd_writes_to_the_target_fd() {
    let mut cmd = Command::new(common::testbin());
    cmd.args(["write-fd", "1", "hello-fd1"]);
    let out = common::output_locked(&mut cmd).expect("spawn");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello-fd1");
}

/// `read-fd <n>` copies CRT fd `n` to stdout. Feeding a piped stdin (fd 0) and reading it back
/// on stdout proves the read direction of the fd→`File` path. The child sees EOF when the write
/// end drops — a real close event, not a timer.
#[test]
fn testbin_read_fd_copies_the_source_fd_to_stdout() {
    let mut child = {
        let _guard = cosca::test_spawn_lock();
        Command::new(common::testbin())
            .args(["read-fd", "0"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn")
        // Guard dropped here, before the stdin write and wait below: holding it any longer would
        // serialize every cosca spawn in this binary against this one for no reason — the window
        // this lock closes (std marking its child-side pipe handles inheritable and calling
        // CreateProcessW with bInheritHandles=TRUE, while a concurrent cosca raw-backend spawn has
        // its own child ends marked inheritable — see `spawn_lock`'s doc) ends inside `spawn()`,
        // which closes std's child-side copies before returning.
    };
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
    let mut cmd = Command::new(common::testbin());
    cmd.args(["isatty-fd", "1"]);
    let out = common::output_locked(&mut cmd).expect("spawn");
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
    let mut c = cosca::Command::new();
    c.executable(exe)
        .commandline("pretend-name argv0-report")
        .stdout(cosca::Stdio::pipe())
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
    let e = cosca::Command::new()
        .executable(common::testbin())
        .commandline("a\u{0}b")
        .spawn()
        .unwrap_err();
    assert!(matches!(e, cosca::error::Error::Io(_)), "{e:?}");
    // The refusal must name the command line. One NUL checker serves every wide string the backend
    // builds, so a message fixed to the environment would send the caller to audit `env()`.
    assert!(e.to_string().contains("command line"), "{e}");
}

/// An embedded NUL in the working directory is rejected the same way (it would truncate the
/// wide `lpCurrentDirectory`).
#[test]
fn embedded_nul_in_cwd_is_rejected() {
    let mut c = cosca::Command::new();
    c.executable(common::testbin())
        .commandline("x argv0-report")
        .current_dir(std::path::PathBuf::from("a\u{0}b"));
    let e = c.spawn().unwrap_err();
    assert!(matches!(e, cosca::error::Error::Io(_)), "{e:?}");
    assert!(e.to_string().contains("working directory"), "{e}");
}

/// A `.bat`/`.cmd` reached via `executable()` is rejected BEFORE resolution (CVE-2024-24576): a
/// batch program has cmd.exe escaping semantics the raw quoter does not implement.
#[test]
fn batch_script_via_executable_is_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let bat = dir.path().join("x.bat");
    std::fs::write(&bat, b"@echo off\n").unwrap();
    let e = cosca::Command::new()
        .executable(&bat)
        .commandline("x.bat")
        .spawn()
        .unwrap_err();
    assert!(matches!(e, cosca::error::Error::Unsupported { .. }), "{e:?}");
}

/// A token routed raw by fd 3, via `executable()` and via argv[0].
fn raw_routed(token: &std::path::Path) -> [(&'static str, cosca::Command); 2] {
    let mut exe = cosca::Command::new();
    exe.executable(token).args(["x", "write-fd", "3", "ok"]);
    let mut argv0 = cosca::Command::new();
    argv0.args([token.as_os_str(), "write-fd".as_ref(), "3".as_ref(), "ok".as_ref()]);
    for c in [&mut exe, &mut argv0] {
        c.fd(3, cosca::Stdio::null()).unwrap();
    }
    [("executable()", exe), ("argv[0]", argv0)]
}

/// A batch file that only Win32's normalisation exposes resolves (the file exists) and must still
/// be refused: `Path::extension()` reads `""`, `"bat "` and `None` for these three.
#[test]
fn a_batch_reached_through_normalisation_is_refused_on_the_raw_backend() {
    let dir = tempfile::tempdir().unwrap();
    for f in ["x.bat", ".bat"] {
        std::fs::write(dir.path().join(f), b"@echo off\n").unwrap();
    }
    // Trailing dot; one trailing space; a file named `.bat`.
    for name in ["x.bat.", "x.bat ", ".bat"] {
        let token = dir.path().join(name);
        for (via, mut c) in raw_routed(&token) {
            match c.spawn() {
                Err(e @ cosca::error::Error::Unsupported { .. }) => {
                    assert!(e.to_string().contains("CVE-2024-24576"), "{via} {name:?}: {e}");
                }
                other => panic!(
                    "{via} {name:?}: expected Unsupported, got {:?}",
                    other.map(|_| "a child")
                ),
            }
        }
    }
}

/// Controls: a `.exe` whose stem merely contains `.bat` runs, as does a plain one.
#[test]
fn an_exe_named_like_a_batch_still_runs_on_the_raw_backend() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["x.bat.exe", "tool.exe"] {
        let token = dir.path().join(name);
        std::fs::copy(common::testbin(), &token).unwrap();
        for (via, mut c) in raw_routed(&token) {
            let child = c.spawn().unwrap_or_else(|e| panic!("{via} {name:?}: {e}"));
            assert!(child.wait().unwrap().success(), "{via} {name:?}");
        }
    }
}

/// End-to-end proof of the gate's ORDERING, through `spawn()` rather than the gate alone. A token
/// carrying an interior NUL must come back as the NUL whichever side of the batch rule it falls:
///
/// - `x` + NUL + `.bat` has `extension() == "bat"`, so without the NUL-first ordering the batch gate
///   claims it — CVE-2024-24576 for a prefix that is not a batch file.
/// - `x.bat` + NUL + `junk` has `extension() == "bat\0junk"`, so the batch gate is blind and,
///   without the NUL check, the refusal degrades to resolution's `NotFound`.
///
/// Both refusals precede resolution, so nothing is spawned and no batch file need exist.
#[test]
fn a_nul_bearing_program_token_is_refused_as_a_nul_on_either_side_of_the_batch_rule() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let nul_token = |prefix: &str, suffix: &str| {
        OsString::from_wide(
            &prefix
                .encode_utf16()
                .chain([0])
                .chain(suffix.encode_utf16())
                .collect::<Vec<u16>>(),
        )
    };

    for token in [nul_token(r"C:\tools\x", ".bat"), nul_token(r"C:\tools\x.bat", "junk")] {
        let e = cosca::Command::new()
            .executable(&token)
            .commandline("x")
            .spawn()
            .unwrap_err();
        match e {
            cosca::error::Error::Io(ref io) => {
                assert_eq!(io.kind(), std::io::ErrorKind::InvalidInput, "{e:?}");
                assert!(io.to_string().contains("program token"), "{e}");
            }
            other => panic!("a NUL-bearing program token must be refused as a NUL, got {other:?}"),
        }
    }
}

// Raw backend, sync fd >= 3 via the MSVCRT lpReserved2 table (Plan 12 Task 5) =====

/// A child-writes pipe on fd 3 delivers the child's bytes to the parent's read end — proving the
/// fd-table wired fd 3 into the child's CRT and the parent kept the read end. EOF (from the child
/// closing fd 3 on exit) bounds the read; no timer.
#[test]
fn fd3_pipe_out_delivers_child_bytes() {
    let mut c = cosca::Command::new();
    c.executable(common::testbin())
        .args(["cosca_testbin", "write-fd", "3", "hi-fd3"])
        .fd(3, cosca::Stdio::pipe_out())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.fd_read_end(cosca::Fd::from(3)).unwrap(), &mut s).unwrap();
    child.wait().unwrap();
    assert_eq!(s, "hi-fd3");
}

/// A parent-writes pipe on fd 3 feeds the child: the child copies fd 3 to stdout, so dropping the
/// parent's write end (EOF) makes the child echo exactly what was written. EOF bounds both reads.
#[test]
fn fd3_pipe_in_feeds_child() {
    let mut c = cosca::Command::new();
    c.executable(common::testbin())
        .args(["cosca_testbin", "read-fd", "3"])
        .fd(3, cosca::Stdio::pipe_in())
        .unwrap()
        .stdout(cosca::Stdio::pipe())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn");
    let mut w = child.fd_write_end(cosca::Fd::from(3)).unwrap();
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
    let e = cosca::Command::new()
        .executable(common::testbin())
        .args(["cosca_testbin", "exit", "0"])
        .fd(3, cosca::Stdio::inherit())
        .unwrap()
        .spawn()
        .unwrap_err();
    assert!(matches!(e, cosca::error::Error::Unsupported { .. }), "{e:?}");
}

/// A regular file on fd 3 classifies as a disk file (`FILE_TYPE_DISK` -> no `FDEV`), so the child's
/// `_isatty(3)` reports 0. Deterministic device-class coverage with no console needed.
#[test]
fn fd3_file_is_not_a_tty() {
    let f = tempfile::tempfile().expect("tempfile");
    let mut c = cosca::Command::new();
    c.executable(common::testbin())
        .args(["cosca_testbin", "isatty-fd", "3"])
        .fd(3, cosca::Stdio::from_file(f))
        .unwrap()
        .stdout(cosca::Stdio::pipe())
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
    let mut c = cosca::Command::new();
    c.executable(common::testbin())
        .args(["cosca_testbin", "isatty-fd", "3"])
        .fd(3, cosca::Stdio::null())
        .unwrap()
        .stdout(cosca::Stdio::pipe())
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
    let e = cosca::Command::new()
        .executable(common::testbin())
        .args(["cosca_testbin", "exit", "0"])
        .fd(70_000, cosca::Stdio::null())
        .unwrap()
        .spawn()
        .unwrap_err();
    assert!(matches!(e, cosca::error::Error::Unsupported { .. }), "{e:?}");
}

/// An argv-only command (no `.executable()`) that maps fd >= 3 still routes to the raw backend —
/// `routes_to_raw_backend`'s OTHER trigger, independent of `executable()`. std has no way to hand a
/// child fd >= 3 on Windows at all: `spawn_unelevated`'s fd >= 3 collection loop is
/// `#[cfg(unix)]`-gated (`src/child/spawn.rs`), so fd 3 actually delivering the marker bytes below
/// is itself proof this went through the raw backend.
#[test]
fn argv_only_fd3_routes_through_the_raw_backend_and_works() {
    let mut c = cosca::Command::new();
    c.args([common::testbin(), "write-fd", "3", "argv-only-fd3"])
        .fd(3, cosca::Stdio::pipe_out())
        .unwrap();
    let mut child = c.spawn().expect("raw spawn via the argv-only + fd>=3 route");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.fd_read_end(cosca::Fd::from(3)).unwrap(), &mut s).unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(s, "argv-only-fd3");
}

/// The `CommandLine` arm of `program_token` (no `.executable()`, built with `.commandline(...)`
/// instead of `.args(...)`) that maps fd >= 3: a different code path from the argv-only test
/// above — `program_token` re-derives its token via `first_token_wide` on this arm rather than
/// reusing `Argv`'s `argv.first()` (see `program_token`'s doc in `src/child/spawn/windows_raw.rs`).
/// Same proof shape as above: std has no way to hand a child fd >= 3 on Windows at all
/// (`spawn_unelevated`'s fd >= 3 collection loop is `#[cfg(unix)]`-gated, `src/child/spawn.rs`), so
/// fd 3 delivering the marker bytes below is itself proof this went through the raw backend via
/// the `CommandLine` token.
#[test]
fn commandline_only_fd3_routes_through_the_raw_backend_and_works() {
    let wide_args: Vec<Vec<u16>> = [common::testbin(), "write-fd", "3", "commandline-only-fd3"]
        .iter()
        .map(|a| a.encode_utf16().collect())
        .collect();
    let refs: Vec<&[u16]> = wide_args.iter().map(Vec::as_slice).collect();
    let line = String::from_utf16(&cosca::quote::windows::join_wide(&refs)).unwrap();

    let mut c = cosca::Command::new();
    c.commandline(line).fd(3, cosca::Stdio::pipe_out()).unwrap();
    let mut child = c.spawn().expect("raw spawn via the commandline + fd>=3 route");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.fd_read_end(cosca::Fd::from(3)).unwrap(), &mut s).unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(s, "commandline-only-fd3");
}

// Containment over the raw backend (Plan 12 Task 6) =====

/// A CONTAINED child with fd >= 3 routes through the raw backend AND lands in OUR Job Object:
/// `test_job_handle_contains_self()` confirms membership (immutable once assigned, so it is
/// deterministic for a handle-pinned child regardless of run state), fd 3 delivers the child's
/// bytes, and `kill_tree()` tears the tree down cleanly. EOF (child closing fd 3 on exit) bounds
/// the read; no timer.
#[test]
fn contained_raw_child_is_in_our_job_and_kill_tree_reaps() {
    let mut c = cosca::Command::new();
    c.executable(common::testbin())
        .args(["cosca_testbin", "write-fd", "3", "x"])
        .fd(3, cosca::Stdio::pipe_out())
        .unwrap()
        .contain();
    let mut child = c.spawn().expect("contained raw spawn");
    // Fixed at spawn (run-state-independent): the achieved mechanism is the Job Object.
    assert_eq!(child.containment(), cosca::Containment::JobObject);
    assert!(child.test_job_handle_contains_self(), "child must be inside OUR job");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.fd_read_end(cosca::Fd::from(3)).unwrap(), &mut s).unwrap();
    assert_eq!(s, "x");
    child.kill_tree().expect("kill_tree");
}

/// An UNCONTAINED executable spawn (no `.contain()`) reports `Containment::None` — the raw backend
/// wires containment only when requested; without it the child is a lone process.
#[test]
fn uncontained_raw_child_has_no_containment() {
    let mut c = cosca::Command::new();
    c.executable(common::testbin())
        .commandline("x argv0-report")
        .stdout(cosca::Stdio::pipe())
        .unwrap();
    assert!(matches!(c.spawn().unwrap().containment(), cosca::Containment::None));
}

/// A `Command` with NO `.executable()` set still routes to the raw backend purely because it wires
/// fd >= 3 (`routes_to_raw_backend`'s other trigger, independent of `executable()`). With no
/// `executable()`, `image` used to be `None`, handing `CreateProcessW` a NULL `lpApplicationName`
/// — which makes `CreateProcessW` perform its OWN image search. That search's step 2 (per its
/// documented order) is the CALLING PROCESS's current directory — never the child's
/// `lpCurrentDirectory`/`Command::cwd()`. So the decoy must be planted in a process's REAL cwd at
/// the moment of the vulnerable/fixed spawn call — a decoy dropped merely in the CHILD's
/// `Command::cwd()` sits outside that search path either way and cannot tell the pre-fix and
/// post-fix code apart (both fail `NotFound`, for different reasons).
///
/// That process cannot be THIS test process, though: it cannot mutate its own cwd under
/// `cosca::test_spawn_lock()` while it also calls `cosca::Command::spawn()`, because that spawn
/// takes the exact same non-reentrant mutex internally (see `tests/common/mod.rs`'s
/// `output_locked`/`status_locked` docs and `src/test_child.rs`) — holding the guard across the
/// call self-deadlocks the test process forever. Instead, this test plants the decoy in a tempdir
/// and spawns the `cosca_testbin` helper's `report-bare-argv0-cwd-spawn` mode via one ordinary,
/// single-level `cosca::Command::spawn()` call, passing the decoy directory as an argument. THAT
/// helper process — a fresh, isolated process with its own cwd and no lock contention with this
/// one — does the chdir and the vulnerable/fixed spawn itself, and reports the outcome on stdout.
///
/// With the bug, the helper's inner spawn would find and load the planted decoy from its own
/// current directory — the CWE-426/427 binary-planting hole — and report "loaded". Fixed, the
/// bare argv[0] is resolved through the crate's own resolver (`lpApplicationName` is never NULL),
/// which for a bare name visits the system directories (app dir, `System32`, the Windows
/// directory) and then `PATH` — never any cwd — so the planted copy is never loaded and the
/// helper reports "notfound".
///
/// The decoy is planted under a FABRICATED name, never the literal "cosca_testbin": on a real
/// build runner that literal name can legitimately resolve via the ACTUAL `PATH` (e.g. Cargo
/// prepends a deps search directory on Windows for DLL resolution, and that directory can itself
/// hold a same-named copy of this very binary) — measured on CI, where the fixed backend's
/// legitimate PATH search silently found a real `cosca_testbin` and made the (undiscriminating)
/// first version of this test report "loaded" for a reason having nothing to do with the bug.
/// A name that exists nowhere but the planted decoy removes that ambiguity: any successful
/// resolution of it can only have come from the vulnerable cwd search — and, since the decoy
/// lives ONLY in this tempdir cwd, never the app dir, `System32`, or the Windows directory either,
/// the resolver's system-directory search step cannot accidentally find it and mask a cwd-search
/// regression this test would otherwise catch.
#[test]
fn fd3_only_routing_does_not_load_a_binary_planted_in_the_process_cwd() {
    let dir = tempfile::tempdir().unwrap();
    let decoy_program = "cosca_testbin_b2_cwd_decoy";
    std::fs::copy(common::testbin(), dir.path().join(format!("{decoy_program}.exe"))).unwrap();

    let mut c = cosca::Command::new();
    c.executable(common::testbin())
        .args([
            "cosca_testbin",
            "report-bare-argv0-cwd-spawn",
            dir.path().to_str().expect("tempdir path is valid UTF-8"),
            decoy_program,
        ])
        .stdout(cosca::Stdio::pipe())
        .unwrap();
    let mut child = c.spawn().expect("spawn the probe helper");
    let mut s = String::new();
    std::io::Read::read_to_string(&mut child.stdout().unwrap(), &mut s).unwrap();
    child.wait().unwrap();
    assert_eq!(s.trim(), "notfound", "helper report: {s}");
}
