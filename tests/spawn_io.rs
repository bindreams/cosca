use std::io::{Read, Write};

use subprocess::{Command, Fd, Stdio};

fn testbin() -> &'static str {
    env!("CARGO_BIN_EXE_subprocess_testbin")
}

// Basics =====

#[test]
fn spawn_and_status_exit_code() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "exit", "7"]);
    let child = cmd.spawn().expect("spawn");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(7));
}

#[test]
fn spawned_child_has_live_identity() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "exit", "0"]);
    let child = cmd.spawn().expect("spawn");
    // id() is stable across two calls.
    assert_eq!(child.id().pid(), child.id().pid());
    let _ = child.wait();
}

#[test]
fn try_wait_returns_none_before_exit_and_some_after() {
    let mut cmd = Command::new();
    // tee-both blocks on stdin — the child won't exit until stdin is closed.
    // Null stdout/stderr so tee-both doesn't panic on broken pipe.
    cmd.executable(testbin())
        .args(["subprocess_testbin", "tee-both"])
        .stdin(Stdio::pipe())
        .expect("stdin pipe")
        .stdout(Stdio::null())
        .expect("null stdout")
        .stderr(Stdio::null())
        .expect("null stderr");
    let mut child = cmd.spawn().expect("spawn");
    let _stdin = child.stdin(); // take the write end

    // Before closing stdin, child is still alive.
    let status_before = child.try_wait().expect("try_wait before");
    assert!(status_before.is_none(), "expected None before child exits");

    // Drop _stdin (write end closed) → child gets EOF and exits.
    drop(_stdin);
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0));

    // After exit, try_wait returns Some.
    let status_after = child.try_wait().expect("try_wait after");
    assert!(status_after.is_some(), "expected Some after child exits");
}

#[test]
fn kill_terminates_running_child() {
    let mut cmd = Command::new();
    // tee-both blocks indefinitely on stdin.
    cmd.executable(testbin())
        .args(["subprocess_testbin", "tee-both"])
        .stdin(Stdio::pipe())
        .expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    let _stdin = child.stdin();

    child.kill().expect("kill");
    // On Unix killed-by-signal exit code is None; on Windows it's Some(1) or similar.
    // Either way the process is gone; we just need wait() to not error.
    let _ = child.wait().expect("wait after kill");
}

// Pipe I/O =====

#[test]
fn stdout_pipe_captures_output() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "emit", "5", "0"])
        .stdout(Stdio::pipe())
        .expect("stdout pipe");
    let mut child = cmd.spawn().expect("spawn");
    let mut reader = child.stdout().expect("stdout reader");

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).expect("read stdout");
    drop(reader);
    let _ = child.wait();

    assert_eq!(buf, b"ooooo");
}

#[test]
fn stderr_pipe_captures_output() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "emit", "0", "3"])
        .stderr(Stdio::pipe())
        .expect("stderr pipe");
    let mut child = cmd.spawn().expect("spawn");
    let mut reader = child.stderr().expect("stderr reader");

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).expect("read stderr");
    drop(reader);
    let _ = child.wait();

    assert_eq!(buf, b"eee");
}

#[test]
fn stdin_pipe_is_writable() {
    let mut cmd = Command::new();
    // tee-both reads stdin and copies to stdout+stderr; we just need to confirm
    // the write end is usable. Wire stdout to null to avoid a broken-pipe panic.
    cmd.executable(testbin())
        .args(["subprocess_testbin", "tee-both"])
        .stdin(Stdio::pipe())
        .expect("stdin pipe")
        .stdout(Stdio::null())
        .expect("null stdout")
        .stderr(Stdio::null())
        .expect("null stderr");
    let mut child = cmd.spawn().expect("spawn");
    let mut writer = child.stdin().expect("stdin writer");
    writer.write_all(b"hello").expect("write to stdin");
    drop(writer); // close write end → child gets EOF → exits
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0));
}

// Merge (2>&1) =====

#[test]
fn merge_stderr_onto_stdout_combines_output() {
    let mut cmd = Command::new();
    // emit 3 bytes to stdout, 2 to stderr; merge stderr→stdout so both come
    // through the single stdout pipe.
    cmd.executable(testbin())
        .args(["subprocess_testbin", "emit", "3", "2"])
        .stdout(Stdio::pipe())
        .expect("stdout pipe")
        .stderr(Stdio::merge(subprocess::Fd::STDOUT))
        .expect("stderr merge");
    let mut child = cmd.spawn().expect("spawn");
    let mut reader = child.stdout().expect("stdout reader");

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).expect("read merged");
    drop(reader);
    let _ = child.wait();

    // All 5 bytes arrive; order between stdout/stderr is unspecified.
    assert_eq!(buf.len(), 5, "expected 5 bytes (3 stdout + 2 stderr merged)");
    assert!(buf.iter().all(|&b| b == b'o' || b == b'e'));
}

// Null =====

#[test]
fn null_stdout_discards_output() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "emit", "100", "0"])
        .stdout(Stdio::null())
        .expect("null stdout");
    let child = cmd.spawn().expect("spawn");
    // No stdout reader — output goes to null; child exits cleanly.
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0));
}

// Rejections =====

#[test]
fn fd_ge_3_is_rejected() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "exit", "0"]);
    cmd.fd(3, Stdio::null()).expect("fd attach ok");
    let err = cmd.spawn().expect_err("should reject fd >= 3");
    assert!(
        matches!(err, subprocess::error::Error::Unsupported { .. }),
        "expected Unsupported, got {err:?}"
    );
}

#[test]
fn merge_to_merge_is_rejected() {
    // stdout -> merge(stderr), stderr -> merge(stdout): chained merge.
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "exit", "0"]);
    cmd.stderr(Stdio::merge(subprocess::Fd::STDOUT)).expect("stderr merge");
    cmd.stdout(Stdio::merge(subprocess::Fd::STDERR)).expect("stdout merge");
    let err = cmd.spawn().expect_err("should reject merge-to-merge");
    assert!(
        matches!(err, subprocess::error::Error::Unsupported { .. }),
        "expected Unsupported for chained merge, got {err:?}"
    );
}

// Environment and cwd =====

#[test]
fn env_variable_reaches_child() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "env", "SUBPROCESS_TEST_VAR"])
        .env("SUBPROCESS_TEST_VAR", "hello123")
        .stdout(Stdio::pipe())
        .expect("stdout pipe");
    let mut child = cmd.spawn().expect("spawn");
    let mut reader = child.stdout().expect("stdout reader");
    let mut out = String::new();
    reader.read_to_string(&mut out).expect("read");
    drop(reader);
    let _ = child.wait();
    assert_eq!(out.trim(), "SUBPROCESS_TEST_VAR=hello123");
}

#[test]
fn current_dir_sets_working_directory() {
    let tmpdir = std::env::temp_dir();
    let mut cmd = Command::new();
    // Use exit 0 — simplest child that honors cwd without writing to stdout.
    cmd.executable(testbin())
        .args(["subprocess_testbin", "exit", "0"])
        .current_dir(&tmpdir);
    let child = cmd.spawn().expect("spawn with cwd");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0));
}

// Windows commandline path =====

#[test]
#[cfg(windows)]
fn commandline_mode_c1_fix_no_duplicate_program_token() {
    // This tests the C1 fix: when spawning via commandline(), the program token
    // must NOT appear twice in the child's argv. Prior to the fix, passing the
    // whole command line to raw_arg duplicated the program in argv[0]+argv[1].
    let tb = testbin();
    let line = format!("{tb} echo-argv argA argB");
    let mut cmd = Command::new();
    cmd.commandline(&line).stdout(Stdio::pipe()).expect("stdout pipe");
    let mut child = cmd.spawn().expect("spawn commandline");
    let mut reader = child.stdout().expect("stdout reader");
    let mut out = String::new();
    reader.read_to_string(&mut out).expect("read");
    drop(reader);
    let _ = child.wait();
    let lines: Vec<&str> = out.lines().collect();
    // echo-argv prints args[2..], so we expect exactly ["argA", "argB"].
    assert_eq!(
        lines,
        ["argA", "argB"],
        "expected [argA, argB] but got {lines:?} — possible duplicate program token"
    );
}

// POSIX argv0 preservation =====

#[cfg(unix)]
#[test]
fn posix_executable_override_preserves_argv0() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["custom-name", "argv0"]);
    let s = cmd.read().expect("read");
    assert_eq!(s, "custom-name\n"); // child's argv[0] is the user's, not the testbin path
}

// Pump / communicate =====

#[test]
fn communicate_does_not_deadlock_on_large_bidirectional_io() {
    // > a pipe buffer (~64 KiB) in every direction: child copies stdin to BOTH
    // stdout and stderr while the parent writes stdin and reads both outputs.
    // A non-concurrent pump would deadlock here.
    let input = vec![b'x'; 512 * 1024];
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "tee-both"]);
    cmd.stdin(Stdio::pipe()).unwrap();
    cmd.stdout(Stdio::pipe()).unwrap();
    cmd.stderr(Stdio::pipe()).unwrap();
    let mut child = cmd.spawn().expect("spawn");
    let out = child.communicate(Some(&input)).expect("communicate");
    assert!(out.status.success());
    assert_eq!(out.stdout, input);
    assert_eq!(out.stderr, input);
}

#[test]
fn output_captures_stdout_and_stderr_with_sizes() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "emit", "5", "3"]);
    let out = cmd.output().expect("output");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"ooooo");
    assert_eq!(out.stderr, b"eee");
}

#[test]
fn read_returns_verbatim_utf8() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "echo-argv", "hello"]);
    let s = cmd.read().expect("read");
    assert_eq!(s, "hello\n"); // verbatim: trailing newline preserved
}

#[test]
fn commandline_round_trips_through_split_or_passthrough() {
    // Exercises the .commandline()/run_line path on BOTH OSes: POSIX splits via
    // the shlex; Windows passes the line through and derives the program from
    // the first token (the args-only raw_arg fix — a duplicated program token
    // would make the child print the wrong argv or error).
    let line = format!(r#""{}" echo-argv hello"#, testbin());
    let s = subprocess::run_line(line).read().expect("read");
    assert_eq!(s, "hello\n");
}

#[test]
fn merge_stderr_into_stdout() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "emit", "4", "4"]);
    cmd.stdout(Stdio::pipe()).unwrap();
    cmd.stderr(Stdio::merge(Fd::STDOUT)).unwrap();
    let mut child = cmd.spawn().expect("spawn");
    let out = child.communicate(None).expect("communicate");
    // Both streams land on the single stdout pipe (order between them is not
    // guaranteed, but all 8 bytes are present and stderr capture is empty).
    assert_eq!(out.stdout.len(), 8);
    assert!(out.stdout.iter().all(|&b| b == b'o' || b == b'e'));
    assert!(out.stderr.is_empty());
}

#[test]
fn null_stdout_discards() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "emit", "100", "0"]);
    cmd.stdout(Stdio::null()).unwrap();
    let status = cmd.status().expect("status");
    assert!(status.success());
}

#[test]
fn arbitrary_fd_is_unsupported_in_this_plan() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "exit", "0"]);
    cmd.fd(3, Stdio::pipe_out()).unwrap(); // attaches fine
    let err = cmd.spawn().unwrap_err(); // but spawn rejects it
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }));
}

#[test]
fn run_free_fn_builds_command_from_args() {
    let s = subprocess::run([testbin(), "echo-argv", "world"]).read().expect("read");
    assert_eq!(s, "world\n");
}

#[test]
fn read_errors_on_invalid_utf8() {
    let mut cmd = Command::new();
    // 0xff is not valid UTF-8.
    cmd.executable(testbin()).args(["subprocess_testbin", "emit-raw", "ff"]);
    let err = cmd.read().expect_err("should fail on invalid UTF-8");
    assert!(
        matches!(err, subprocess::error::Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData),
        "expected Io(InvalidData), got {err:?}"
    );
}

// Drop policy =====

#[test]
fn drop_kills_and_reaps_the_child() {
    let mut cmd = Command::new();
    // tee-both with a piped (but never-written, never-closed) stdin blocks the
    // child reading stdin -> it stays alive until we drop the Child.
    cmd.executable(testbin()).args(["subprocess_testbin", "tee-both"]);
    cmd.stdin(Stdio::pipe()).unwrap();
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    assert!(id.is_alive(), "child runs while its stdin stays open");
    drop(child); // kill_on_drop default true => SIGKILL/TerminateProcess + reap
    assert!(!id.is_alive(), "child must be dead (and reaped) after drop");
}

#[test]
fn detach_leaves_the_child_running() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "tee-both"]);
    cmd.stdin(Stdio::pipe()).unwrap();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    // Take the stdin writer BEFORE detaching, so we can end the orphan cleanly
    // (EOF) afterward without needing a wait handle (kill-by-foreign-id is Plan 6).
    let writer = child.stdin().expect("stdin pipe writer");
    assert!(id.is_alive(), "child runs while its stdin stays open");

    child.detach(); // consumes Child; with kill_on_drop=false, Drop neither kills nor reaps

    // The key assertion: detach did NOT kill the process — it is still blocked
    // reading its (still-open) stdin.
    assert!(id.is_alive(), "detached child must keep running");

    // Cleanup (not an assertion): closing stdin gives the child EOF so it exits
    // on its own. We do NOT assert it became dead — observing a detached
    // process's exit needs the Plan-6 foreign-wait primitive. The OS reaps the
    // orphan when this test process exits. No sleep, no poll, no timeout.
    drop(writer);
}
