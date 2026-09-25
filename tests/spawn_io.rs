use std::io::{Read, Write};

use cosca::{Command, Fd, Stdio};

#[path = "common/mod.rs"]
mod common;

fn testbin() -> &'static str {
    env!("CARGO_BIN_EXE_cosca_testbin")
}

/// Route the library's `log` records to this test binary's stderr.
///
/// Without a logger installed, `log` drops every record on the floor — so a containment
/// degrade explains itself into nothing and a failing `assert_eq!(…, CgroupV2)` is as
/// undiagnosable from CI output as it was before the reason existed. libtest captures a
/// failing test's stderr and prints it with the failure (and the CI cgroup step runs with
/// `--nocapture`), so with this installed the reason lands directly above the assertion.
///
/// Unix-gated, not Linux-gated: BOTH Unix containment mechanisms that can degrade explain
/// themselves through `log` — Linux's cgroup leaf (`cgroup::log_degrade`) and macOS's fd marker
/// (`fdmarker::install`) — so routing only the Linux one leaves the macOS reasons on the floor
/// on the host that has them.
#[cfg(unix)]
mod stderr_log {
    use std::sync::OnceLock;

    struct StderrLog;

    impl log::Log for StderrLog {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            eprintln!("[{}] {}", record.level(), record.args());
        }
        fn flush(&self) {}
    }

    static INSTALLED: OnceLock<()> = OnceLock::new();

    /// Idempotent: `log::set_logger` is once-per-process, so every test that wants the
    /// library's reasoning calls this and the first one wins.
    pub fn install() {
        INSTALLED.get_or_init(|| {
            log::set_logger(&StderrLog).expect("first logger in this test binary");
            // `Debug`, because a degrade reason is only reported at `warn` the FIRST time this
            // process sees it — `cgroup::log_degrade` reports every repeat at `debug`. A
            // narrower filter therefore keeps whichever test happened to degrade first and
            // discards every repeat — `log!` checks `max_level()` before any logger is reached,
            // so a filtered-out record is never emitted to capture in the first place.
            //
            // `Debug` is the full set and costs nothing beyond it: this crate emits no `trace`
            // records at all, and libtest prints a passing test's stderr nowhere.
            log::set_max_level(log::LevelFilter::Debug);
        });
    }
}

// Basics =====

#[test]
fn spawn_and_status_exit_code() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["cosca_testbin", "exit", "7"]);
    let child = cmd.spawn().expect("spawn");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(7));
}

#[test]
fn spawned_child_has_live_identity() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["cosca_testbin", "exit", "0"]);
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
        .args(["cosca_testbin", "tee-both"])
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
        .args(["cosca_testbin", "tee-both"])
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
        .args(["cosca_testbin", "emit", "5", "0"])
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
        .args(["cosca_testbin", "emit", "0", "3"])
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
        .args(["cosca_testbin", "tee-both"])
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
        .args(["cosca_testbin", "emit", "3", "2"])
        .stdout(Stdio::pipe())
        .expect("stdout pipe")
        .stderr(Stdio::merge(cosca::Fd::STDOUT))
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
        .args(["cosca_testbin", "emit", "100", "0"])
        .stdout(Stdio::null())
        .expect("null stdout");
    let child = cmd.spawn().expect("spawn");
    // No stdout reader — output goes to null; child exits cleanly.
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0));
}

// Rejections =====

#[test]
fn merge_to_merge_is_rejected() {
    // stdout -> merge(stderr), stderr -> merge(stdout): chained merge.
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["cosca_testbin", "exit", "0"]);
    cmd.stderr(Stdio::merge(cosca::Fd::STDOUT)).expect("stderr merge");
    cmd.stdout(Stdio::merge(cosca::Fd::STDERR)).expect("stdout merge");
    let err = cmd.spawn().expect_err("should reject merge-to-merge");
    assert!(
        matches!(err, cosca::error::Error::Unsupported { .. }),
        "expected Unsupported for chained merge, got {err:?}"
    );
}

// Environment and cwd =====

#[test]
fn env_variable_reaches_child() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "env", "COSCA_TEST_VAR"])
        .env("COSCA_TEST_VAR", "hello123")
        .stdout(Stdio::pipe())
        .expect("stdout pipe");
    let mut child = cmd.spawn().expect("spawn");
    let mut reader = child.stdout().expect("stdout reader");
    let mut out = String::new();
    reader.read_to_string(&mut out).expect("read");
    drop(reader);
    let _ = child.wait();
    assert_eq!(out.trim(), "COSCA_TEST_VAR=hello123");
}

#[test]
fn current_dir_sets_working_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "cwd"])
        .current_dir(dir.path())
        .stdout(Stdio::pipe())
        .expect("stdout pipe");
    let mut child = cmd.spawn().expect("spawn with cwd");
    let mut out = String::new();
    child
        .stdout()
        .expect("stdout reader")
        .read_to_string(&mut out)
        .expect("read");
    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert_eq!(
        std::fs::canonicalize(out.trim()).expect("the child's cwd exists"),
        std::fs::canonicalize(dir.path()).expect("canonicalize"),
    );
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
    cmd.executable(testbin()).args(["cosca_testbin", "tee-both"]);
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
    cmd.executable(testbin()).args(["cosca_testbin", "emit", "5", "3"]);
    let out = cmd.output().expect("output");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"ooooo");
    assert_eq!(out.stderr, b"eee");
}

#[test]
fn read_returns_verbatim_utf8() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["cosca_testbin", "echo-argv", "hello"]);
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
    let s = cosca::run_line(line).read().expect("read");
    assert_eq!(s, "hello\n");
}

#[test]
fn merge_stderr_into_stdout() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["cosca_testbin", "emit", "4", "4"]);
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
    cmd.executable(testbin()).args(["cosca_testbin", "emit", "100", "0"]);
    cmd.stdout(Stdio::null()).unwrap();
    let status = cmd.status().expect("status");
    assert!(status.success());
}

// Arbitrary fd (n>=3) — Unix only, wired via fd_map =====

/// Prove that a child fd 3 configured as a pipe is reachable from the child:
/// the testbin's `fd3-echo` mode reads fd 3 and copies it to stdout. We write
/// a known payload into the parent write-end, close it, then read stdout to
/// EOF — no timers, no polling, fully deterministic.
#[cfg(unix)]
#[test]
fn unix_fd3_pipe_round_trips() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "fd3-echo"])
        .stdout(Stdio::pipe())
        .expect("stdout pipe")
        // pipe_in: child reads, parent holds the write end.
        .fd(3, Stdio::pipe_in())
        .expect("fd 3 pipe_in");
    let mut child = cmd.spawn().expect("spawn with fd 3");
    let mut stdout = child.stdout().expect("stdout reader");
    let mut fd3_writer = child.fd_write_end(Fd::from(3)).expect("fd 3 writer");

    fd3_writer.write_all(b"hello fd3").expect("write to fd 3");
    drop(fd3_writer); // EOF on the child's fd 3 read end

    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).expect("read stdout");
    drop(stdout);
    let _ = child.wait();

    assert_eq!(buf, b"hello fd3");
}

/// Prove that fd 3 with Stdio::null() is accepted and spawns successfully.
/// The child reads from fd 3 (which is /dev/null) and gets immediate EOF,
/// producing no stdout output. Confirms the null path reaches fd_map.
#[cfg(unix)]
#[test]
fn unix_fd3_null_is_accepted() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "fd3-echo"])
        .stdout(Stdio::pipe())
        .expect("stdout pipe")
        .fd(3, Stdio::null())
        .expect("fd 3 null");
    let mut child = cmd.spawn().expect("spawn with fd 3 null");
    let mut stdout = child.stdout().expect("stdout reader");

    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).expect("read stdout");
    drop(stdout);
    let status = child.wait().expect("wait");

    assert!(status.success());
    assert!(buf.is_empty(), "null fd 3 should produce no output");
}

/// Prove that Stdio::inherit() on fd 3 is rejected with Unsupported (no defined
/// parent stream to dup for n>=3) — a retained design limit on every path.
#[cfg(unix)]
#[test]
fn unix_fd3_inherit_is_rejected() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "exit", "0"])
        .fd(3, Stdio::inherit())
        .expect("fd attach ok");
    let err = cmd.spawn().expect_err("inherit on fd 3 should be rejected");
    assert!(
        matches!(err, cosca::error::Error::Unsupported { .. }),
        "expected Unsupported, got {err:?}"
    );
}

/// I14 regression: an out-of-range but syscall-representable child fd (far beyond any real
/// process' open-file limit) must fail the SPAWN with an ordinary `Err` — never `Ok` followed by
/// the child dying of SIGABRT. Before the fix, `command-fds` wrapped a failed `dup2`'s `-1`
/// return in an `OwnedFd` (nix-rust/nix#2797), which aborted the child instead of surfacing a
/// clean error.
#[cfg(unix)]
#[test]
fn unix_fd_out_of_range_fails_spawn_cleanly_not_abort() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "exit", "0"])
        .fd(1_000_000, Stdio::null())
        .expect("fd() itself accepts an out-of-range but representable number");
    let err = cmd
        .spawn()
        .expect_err("dup2 onto an unachievable fd number must fail the spawn with Err, not abort");
    assert!(
        matches!(err, cosca::error::Error::Io(_)),
        "expected a plain Io error (propagated via the child's error pipe), got {err:?}"
    );
}

/// I14 regression: `fd(i32::MAX, ...)` must fail — either at `Command::fd()` or at `spawn()` —
/// with an ordinary `Err`, in both debug and release builds. Before the fix, `command-fds`
/// computed a collision-avoidance temporary-fd floor via unchecked `i32` arithmetic
/// (`max(...) + 1`), which overflowed for `i32::MAX` (panicking in debug, wrapping in release).
/// cosca's own `fd_map` module rejects this in the PARENT, before any fork, with
/// `InvalidInput` — verified here via `cmd.spawn()`, which is the one call site the bug could
/// actually reach.
#[cfg(unix)]
#[test]
fn unix_fd_i32_max_fails_spawn_in_both_profiles() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "exit", "0"])
        .fd(i32::MAX, Stdio::null())
        .expect("fd() itself accepts i32::MAX (only the collision-avoidance arithmetic overflows)");
    let err = cmd
        .spawn()
        .expect_err("i32::MAX must be rejected by fd_map's parent-side checked arithmetic before any fork");
    match err {
        cosca::error::Error::Io(e) => assert_eq!(
            e.kind(),
            std::io::ErrorKind::InvalidInput,
            "expected InvalidInput, got {e:?}"
        ),
        other => panic!("expected Io(InvalidInput), got {other:?}"),
    }
}

/// Prove that fd 3 configured as a file is passed through to the child:
/// the child reads fd 3 and echoes it to stdout; we compare the payload.
#[cfg(unix)]
#[test]
fn unix_fd3_file_round_trips() {
    use std::io::{Seek, Write};

    // Write a payload to a unique temp file, then rewind for the child to read.
    // `tempfile()` gives a process-unique, auto-cleaned file so two concurrent
    // test runs cannot collide on a shared fixed name.
    let mut tmp = tempfile::tempfile().expect("create tmpfile");
    tmp.write_all(b"from file via fd3").expect("write tmpfile");
    tmp.seek(std::io::SeekFrom::Start(0)).expect("seek");

    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "fd3-echo"])
        .stdout(Stdio::pipe())
        .expect("stdout pipe")
        .fd(3, Stdio::from_file(tmp.try_clone().expect("clone file")))
        .expect("fd 3 from file");
    let mut child = cmd.spawn().expect("spawn with fd 3 file");
    let mut stdout = child.stdout().expect("stdout reader");

    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).expect("read stdout");
    drop(stdout);
    let _ = child.wait();

    assert_eq!(buf, b"from file via fd3");
}

/// Spawn a contained child that writes a token to fd 3, and return the containment it achieved
/// and what fd 3 carried. Read to EOF; no timers.
#[cfg(target_os = "linux")]
fn contain_with_fd3() -> (cosca::Containment, Vec<u8>) {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "fd3-write", "FD3PAYLOAD"])
        // pipe_out: child writes, parent holds the read end.
        .fd(3, Stdio::pipe_out())
        .expect("fd 3 pipe_out");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn contained child with fd 3");
    let containment = child.containment();
    let mut fd3_reader = child.fd_read_end(Fd::from(3)).expect("fd 3 reader");
    let mut buf = Vec::new();
    fd3_reader.read_to_end(&mut buf).expect("read fd 3");
    drop(fd3_reader);
    let _ = child.wait();
    (containment, buf)
}

/// `.contain()` + `.fd(3, pipe_out())` on Linux: whatever mechanism is achieved, the child's fd 3
/// carries exactly its own token, and containment is established. The cgroup `pre_exec` writes
/// "0" to a pre-opened `cgroup.procs` fd, and fd_map's `pre_exec` dup2's the user's fd onto
/// child fd 3; if they collided, the "0" would land in the stream or the pipe would break.
#[cfg(target_os = "linux")]
#[test]
fn linux_contain_with_fd3_delivers_the_exact_payload() {
    stderr_log::install();
    let (containment, buf) = contain_with_fd3();
    assert_ne!(
        containment,
        cosca::Containment::None,
        "contain() + fd(3) must still establish containment"
    );
    assert_eq!(buf, b"FD3PAYLOAD", "fd 3 stream corrupted");
}

/// Regression: under a delegated cgroup, fd_map's dup2 onto fd 3 must not clobber the cgroup
/// placement's `cgroup.procs` fd. A clobbered write degrades the spawn to a process group, so
/// achieving `CgroupV2` is the proof.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn linux_cgroup_v2_contain_with_fd3_does_not_clobber_cgroup_procs_fd() {
    stderr_log::install();
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let (containment, buf) = contain_with_fd3();
    assert_eq!(
        containment,
        cosca::Containment::CgroupV2,
        "the cgroup write must not be clobbered by fd_map's dup2"
    );
    assert_eq!(buf, b"FD3PAYLOAD", "fd 3 stream corrupted");
}

#[test]
fn run_free_fn_builds_command_from_args() {
    let s = cosca::run([testbin(), "echo-argv", "world"]).read().expect("read");
    assert_eq!(s, "world\n");
}

#[test]
fn read_errors_on_invalid_utf8() {
    let mut cmd = Command::new();
    // 0xff is not valid UTF-8.
    cmd.executable(testbin()).args(["cosca_testbin", "emit-raw", "ff"]);
    let err = cmd.read().expect_err("should fail on invalid UTF-8");
    assert!(
        matches!(err, cosca::error::Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData),
        "expected Io(InvalidData), got {err:?}"
    );
}

// Drop policy =====

#[test]
fn drop_kills_and_reaps_the_child() {
    let mut cmd = Command::new();
    // tee-both with a piped (but never-written, never-closed) stdin blocks the
    // child reading stdin -> it stays alive until we drop the Child.
    cmd.executable(testbin()).args(["cosca_testbin", "tee-both"]);
    cmd.stdin(Stdio::pipe()).unwrap();
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    assert_eq!(
        id.is_alive(),
        cosca::identity::Liveness::Alive,
        "child runs while its stdin stays open"
    );
    drop(child); // kill_on_drop default true => SIGKILL/TerminateProcess + reap
    assert_eq!(
        id.is_alive(),
        cosca::identity::Liveness::Dead,
        "child must be dead (and reaped) after drop"
    );
}

#[test]
fn detach_leaves_the_child_running() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["cosca_testbin", "tee-both"]);
    cmd.stdin(Stdio::pipe()).unwrap();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    // Take the stdin writer BEFORE detaching, so we can end the orphan cleanly
    // (EOF) afterward without needing a wait handle (kill-by-foreign-id is Plan 6).
    let writer = child.stdin().expect("stdin pipe writer");
    assert_eq!(
        id.is_alive(),
        cosca::identity::Liveness::Alive,
        "child runs while its stdin stays open"
    );

    child.detach(); // consumes Child; with kill_on_drop=false, Drop neither kills nor reaps

    // The key assertion: detach did NOT kill the process — it is still blocked
    // reading its (still-open) stdin.
    assert_eq!(
        id.is_alive(),
        cosca::identity::Liveness::Alive,
        "detached child must keep running"
    );

    // Cleanup (not an assertion): closing stdin gives the child EOF so it exits
    // on its own. We do NOT assert it became dead — observing a detached
    // process's exit needs the Plan-6 foreign-wait primitive. The OS reaps the
    // orphan when this test process exits. No sleep, no poll, no timeout.
    drop(writer);
}

// Containment =====

#[test]
fn uncontained_child_reports_containment_none() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["cosca_testbin", "exit", "0"]);
    let child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), cosca::Containment::None);
    let _ = child.wait();
}

/// Spawn a contained `spawn-grandchild` and return (child, grandchild_stream).
/// The grandchild's connected socket is proof it is alive; reading it to EOF
/// later is the deterministic proof it died.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
fn spawn_contained_tree() -> (cosca::Child, std::net::TcpStream) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "spawn-grandchild", &addr]);
    cmd.contain();
    // Every contained-tree test below goes through here, and each of them asserts an achieved
    // mechanism that can silently be a weaker one. Route the reason for that.
    #[cfg(unix)]
    stderr_log::install();
    let child = cmd.spawn().expect("spawn");
    // Accept both connections; keep the grandchild's (tag 'G'). Accepting it is
    // proof the grandchild is alive — no is_alive() race.
    let mut gc = None;
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept control conn");
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        if tag[0] == b'G' {
            gc = Some(s);
        }
    }
    (child, gc.expect("grandchild connected"))
}

/// A contained `spawn-grandchild-echo` tree, with BOTH members' live control sockets.
///
/// Unlike [`spawn_contained_tree`], each member round-trips a byte instead of merely holding
/// its socket open, so a test can prove a member is POSITIVELY alive. `control-block`'s EOF is
/// proof of death and no evidence at all of life: a peer that was killed and a peer that is
/// still running both fail to produce a byte, and the write that precedes the read succeeds
/// against a dead peer too (the first write into a socket whose peer is gone is buffered, not
/// refused). See `spawn-grandchild-echo` in `testbin/main.rs`.
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
struct EchoTree {
    child: cosca::Child,
    root: std::net::TcpStream,
    grand: std::net::TcpStream,
    /// The grandchild's own pid, for reading the tree's cgroup back out of `/proc`.
    #[cfg(target_os = "linux")]
    grand_pid: u32,
}

#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
fn spawn_contained_echo_tree(kill_on_drop: bool) -> EchoTree {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "spawn-grandchild-echo", &addr]);
    cmd.contain();
    cmd.kill_on_drop(kill_on_drop);
    // As in `spawn_contained_tree`: every caller asserts an achieved mechanism that can
    // silently be a weaker one, so route the reason for that.
    #[cfg(unix)]
    stderr_log::install();
    let child = cmd.spawn().expect("spawn");
    // Accept order is not guaranteed, so demux by tag. Both connections being accepted is
    // itself proof both members are alive — no is_alive() race.
    let (mut root, mut grand) = (None, None);
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept control conn");
        match common::read_tag_and_pid(&mut s) {
            (b'R', pid) => root = Some((s, pid)),
            (b'G', pid) => grand = Some((s, pid)),
            (tag, _) => panic!("unexpected tree tag {:?}", tag as char),
        }
    }
    let (root, _root_pid) = root.expect("root R connected");
    let (grand, _grand_pid) = grand.expect("grandchild G connected");
    EchoTree {
        child,
        root,
        grand,
        #[cfg(target_os = "linux")]
        grand_pid: _grand_pid,
    }
}

#[cfg(unix)]
#[test]
fn unix_kill_tree_reaps_the_grandchild() {
    let (child, mut gc_stream) = spawn_contained_tree();
    let expected = if cfg!(target_os = "macos") {
        cosca::Containment::FdMarker
    } else {
        cosca::Containment::ProcessGroup
    };
    assert_eq!(child.containment(), expected);

    child.kill_tree().expect("kill_tree");
    let _ = child.wait(); // reap the root

    // Deterministic proof the grandchild died: its control socket EOFs (the OS
    // closed it on the process's death). A blocking read returns 0 — no timer,
    // no immediate-is_alive race against the async group teardown.
    let mut buf = [0u8; 1];
    let n = gc_stream.read(&mut buf).expect("read grandchild control socket");
    assert_eq!(n, 0, "kill_tree must kill the grandchild, not just the root");
}

#[cfg(unix)]
#[test]
fn unix_terminate_tree_reaps_the_grandchild() {
    let (child, mut gc_stream) = spawn_contained_tree();
    let expected = if cfg!(target_os = "macos") {
        cosca::Containment::FdMarker
    } else {
        cosca::Containment::ProcessGroup
    };
    assert_eq!(child.containment(), expected);

    child.terminate_tree().expect("terminate_tree");
    let _ = child.wait(); // reap the root

    // Same EOF-based proof: SIGTERM should have killed both the root and the
    // grandchild (they share a process group).
    let mut buf = [0u8; 1];
    let n = gc_stream
        .read(&mut buf)
        .expect("read grandchild control socket after SIGTERM");
    assert_eq!(n, 0, "terminate_tree must SIGTERM the grandchild, not just the root");
}

// unix_nested_contained_spawn_reports_process_group was removed: it used
// std::env::set_var (thread-unsafe, deprecated in Rust 1.81+) to simulate a
// nested spawn.  The nesting logic is now tested at the unit level via
// `dispatch::is_nested` in `src/containment/dispatch_tests.rs`, which covers
// both branches (marker absent → root, marker present → nested) without
// touching process-global state.

// Windows Job Object containment =====

#[cfg(windows)]
#[test]
fn windows_kill_tree_reaps_the_grandchild() {
    let (child, mut gc_stream) = spawn_contained_tree();
    assert_eq!(child.containment(), cosca::Containment::JobObject);

    child.kill_tree().expect("kill_tree");
    let _ = child.wait(); // reap the root

    // Deterministic proof: the grandchild's control socket closes on its death.
    // On Windows, TerminateJobObject causes the TCP socket to close with a
    // ConnectionReset (WSAECONNRESET/10054) rather than a graceful EOF — both
    // prove the grandchild is dead. Accept either: n==0 (EOF) or ConnectionReset.
    let mut buf = [0u8; 1];
    match gc_stream.read(&mut buf) {
        Ok(0) => {}                                                     // graceful EOF — grandchild exited
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {} // forceful kill — also proof of death
        Ok(n) => panic!("expected EOF/ConnectionReset after kill_tree, got {n} bytes"),
        Err(e) => panic!("unexpected error reading grandchild control socket: {e}"),
    }
}

/// `terminate_tree` under JobObject containment reaps the whole tree. The
/// JobObject `terminate` path sends CTRL_BREAK to the root's process group; the
/// grandchild (spawned plainly by the root, not contained itself) shares that
/// console group and dies too. Proof of death: the grandchild's control socket
/// EOFs / ConnectionReset — never a timer or an is_alive() race.
#[cfg(windows)]
#[test]
fn windows_terminate_tree_reaps_the_grandchild() {
    let (child, mut gc_stream) = spawn_contained_tree();
    assert_eq!(child.containment(), cosca::Containment::JobObject);

    child.terminate_tree().expect("terminate_tree");
    let _ = child.wait(); // reap the root

    let mut buf = [0u8; 1];
    match gc_stream.read(&mut buf) {
        Ok(0) => {}                                                     // graceful EOF — grandchild exited
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {} // forceful — also proof of death
        Ok(n) => panic!("expected EOF/ConnectionReset after terminate_tree, got {n} bytes"),
        Err(e) => panic!("unexpected error reading grandchild control socket: {e}"),
    }
}

/// Probe that our child is inside OUR job object (not just any job).
/// Uses the test-only `Child::test_job_handle_contains_self()` accessor so `IsProcessInJob`
/// asks about the handle we created, not an inherited one.
#[cfg(windows)]
#[test]
fn windows_child_is_inside_our_job_after_spawn() {
    let (child, _gc_stream) = spawn_contained_tree();
    assert_eq!(child.containment(), cosca::Containment::JobObject);

    // test_job_handle_contains_self() is cfg(all(windows,test)) — confirms the job we hold.
    let in_job = child.test_job_handle_contains_self();
    assert!(in_job, "child must be inside our job object after spawn");

    child.kill_tree().expect("kill_tree");
    let _ = child.wait();
}

/// `detach()` must NOT kill the tree: `KILL_ON_JOB_CLOSE` has to be cleared before the job
/// handle is released. Proof is a real byte round trip through BOTH members (see `EchoTree`),
/// taken AFTER the detach.
#[cfg(windows)]
#[test]
fn windows_detach_leaves_the_tree_running() {
    let EchoTree {
        child,
        mut root,
        mut grand,
    } = spawn_contained_echo_tree(true);
    assert_eq!(child.containment(), cosca::Containment::JobObject);

    child.detach();

    common::assert_echoes(&mut root, "the detached root");
    common::assert_echoes(&mut grand, "the detached grandchild");

    // Release both: each read returns Ok(0) and the member exits on its own.
    drop(root);
    drop(grand);
}

/// `kill_on_drop(false)` must leave a contained tree running, exactly as `detach()` does (see
/// `Attached::honor_kill_on_drop`).
#[cfg(windows)]
#[test]
fn windows_kill_on_drop_false_leaves_the_tree_running() {
    let EchoTree {
        child,
        mut root,
        mut grand,
    } = spawn_contained_echo_tree(false);
    assert_eq!(child.containment(), cosca::Containment::JobObject);

    drop(child);

    common::assert_echoes(&mut root, "the opted-out root");
    common::assert_echoes(&mut grand, "the opted-out grandchild");

    drop(root);
    drop(grand);
}

// Unix session containment =====

/// Spawn a contained tree using `ContainMode::Session` and return the handles.
/// This is separate from `spawn_contained_tree` (which uses `contain()` =
/// `Strongest`) so the two modes are tested independently.
#[cfg(unix)]
fn spawn_session_tree() -> (cosca::Child, std::net::TcpStream) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "spawn-grandchild", &addr]);
    cmd.contain_with(cosca::ContainMode::Session);
    let child = cmd.spawn().expect("spawn session-contained tree");
    let mut gc = None;
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept control conn");
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        if tag[0] == b'G' {
            gc = Some(s);
        }
    }
    (child, gc.expect("grandchild connected"))
}

#[cfg(unix)]
#[test]
fn unix_session_containment_reports_session() {
    let (child, mut gc_stream) = spawn_session_tree();
    let expected = if cfg!(target_os = "macos") {
        cosca::Containment::FdMarker
    } else {
        cosca::Containment::Session
    };
    assert_eq!(child.containment(), expected);

    child.kill_tree().expect("kill_tree");
    let _ = child.wait();

    // Deterministic proof: grandchild's control socket EOFs on its death.
    let mut buf = [0u8; 1];
    let n = gc_stream.read(&mut buf).expect("read grandchild control socket");
    assert_eq!(n, 0, "session kill_tree must kill the grandchild, not just the root");
}

/// Prove that `ContainMode::Session` actually calls `setsid`: the child must
/// report a session id that differs from the parent's (it became a session
/// leader in a new session). This distinguishes real `setsid` from a plain
/// `process_group(0)` which would share the parent's session.
#[cfg(unix)]
#[test]
fn unix_session_child_is_own_session_leader() {
    let parent_sid = unsafe { libc::getsid(0) };

    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "sid-report"])
        .stdout(Stdio::pipe())
        .expect("stdout pipe")
        .contain_with(cosca::ContainMode::Session);
    let mut child = cmd.spawn().expect("spawn sid-report");
    let expected = if cfg!(target_os = "macos") {
        cosca::Containment::FdMarker
    } else {
        cosca::Containment::Session
    };
    assert_eq!(child.containment(), expected);

    let mut reader = child.stdout().expect("stdout reader");
    let mut out = String::new();
    reader.read_to_string(&mut out).expect("read sid");
    drop(reader);
    let _ = child.wait();

    let child_sid: libc::pid_t = out.trim().parse().expect("parse sid");
    // A setsid child's sid == its own pid; crucially it must differ from the
    // parent's session id, proving a new session was created.
    assert_ne!(
        child_sid, parent_sid,
        "child sid {child_sid} must differ from parent sid {parent_sid}: setsid must have run"
    );
}

// TreeWalk containment =====

/// Spawn a contained tree using `ContainMode::TreeWalk` and return the handles.
/// Sibling of `spawn_session_tree`/`spawn_contained_tree`; selects the
/// identity-aware walk directly. Available on `any(unix, windows)`.
///
/// Returns `(child, grandchild_stream, root_stream)`. **The caller MUST keep
/// `root_stream` alive until after the teardown call.** TreeWalk enumerates the
/// live `/proc` (or per-OS) ppid tree at kill time; if the root process exited
/// first, the OS reparents the grandchild to a subreaper and it is no longer a
/// descendant of the root in the ppid tree — the documented "reparented orphan"
/// case TreeWalk cannot reach. The `spawn-grandchild` root blocks reading its
/// control socket and exits on EOF, so dropping `root_stream` early would kill
/// the root and orphan the grandchild. Kernel-container mechanisms (pgroup /
/// cgroup / job) are reparenting-immune, so `spawn_contained_tree` need not do
/// this; TreeWalk specifically does.
#[cfg(any(unix, windows))]
fn spawn_treewalk_tree() -> (cosca::Child, std::net::TcpStream, std::net::TcpStream) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "spawn-grandchild", &addr]);
    cmd.contain_with(cosca::ContainMode::TreeWalk);
    let child = cmd.spawn().expect("spawn tree-walk-contained tree");
    let mut gc = None;
    let mut root = None;
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept control conn");
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        match tag[0] {
            b'G' => gc = Some(s),
            _ => root = Some(s), // keep the root's socket open so the root stays alive
        }
    }
    (child, gc.expect("grandchild connected"), root.expect("root connected"))
}

/// `ContainMode::TreeWalk` kills the whole tree by identity. Deterministic
/// because the per-OS rule includes same-jiffy children on Linux/macOS; on
/// Windows the strict-`>` rule still catches the grandchild (it is created after
/// the root). Proof of death is the grandchild's control socket EOFing /
/// ConnectionReset — never an is_alive() race or a timer.
#[cfg(any(unix, windows))]
#[test]
fn treewalk_kill_tree_reaps_the_grandchild() {
    // Hold `_root_stream` for the whole test: it keeps the root alive so TreeWalk
    // enumerates the grandchild as a live descendant (not a reparented orphan).
    let (child, mut gc_stream, _root_stream) = spawn_treewalk_tree();
    let expected = if cfg!(target_os = "macos") {
        cosca::Containment::FdMarker
    } else {
        cosca::Containment::TreeWalk
    };
    assert_eq!(child.containment(), expected);

    child.kill_tree().expect("kill_tree");
    let _ = child.wait(); // reap the root

    // Deterministic proof: the grandchild's control socket closes on its death.
    // Accept graceful EOF (n==0) or, on Windows, a ConnectionReset — both prove
    // the grandchild is dead. (See windows_kill_tree_reaps_the_grandchild.)
    let mut buf = [0u8; 1];
    match gc_stream.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(n) => panic!("expected EOF/ConnectionReset after kill_tree, got {n} bytes"),
        Err(e) => panic!("unexpected error reading grandchild control socket: {e}"),
    }
}

/// `terminate_tree` under TreeWalk reaps the whole tree. Unix: TreeWalk's
/// terminate SIGTERMs each genuine identity (root then descendants); the
/// control-block grandchild has no SIGTERM handler so the default action kills
/// it. Windows: terminate sends CTRL_BREAK to the root's process group, which
/// the grandchild shares (it was NOT spawned contained), so it dies too. Proof
/// of death is the grandchild's control socket EOFing / ConnectionReset — never
/// a timer or an is_alive() race.
#[cfg(any(unix, windows))]
#[test]
fn treewalk_terminate_tree_reaps_the_grandchild() {
    // Hold `_root_stream` so the root stays alive through teardown (see
    // spawn_treewalk_tree): TreeWalk must enumerate a live root's descendants.
    let (child, mut gc_stream, _root_stream) = spawn_treewalk_tree();
    let expected = if cfg!(target_os = "macos") {
        cosca::Containment::FdMarker
    } else {
        cosca::Containment::TreeWalk
    };
    assert_eq!(child.containment(), expected);

    child.terminate_tree().expect("terminate_tree");
    let _ = child.wait(); // reap the root

    let mut buf = [0u8; 1];
    match gc_stream.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(n) => panic!("expected EOF/ConnectionReset after terminate_tree, got {n} bytes"),
        Err(e) => panic!("unexpected error reading grandchild control socket: {e}"),
    }
}

/// Prove TreeWalk's distinguishing capability: it kills a child that has
/// `setsid`'d out of any process group/session — which a `killpg`-based teardown
/// aimed at the original pgid would miss. The intermediate child escapes via
/// `setsid` BEFORE spawning the grandchild, then both are torn down by identity.
/// Unix-only (the escape uses `setsid`); EOF on the grandchild's control socket
/// is the deterministic proof of death.
#[cfg(unix)]
#[test]
fn treewalk_kills_process_group_escapee() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "spawn-grandchild-escapee", &addr]);
    cmd.contain_with(cosca::ContainMode::TreeWalk);
    let child = cmd.spawn().expect("spawn tree-walk escapee tree");
    let expected = if cfg!(target_os = "macos") {
        cosca::Containment::FdMarker
    } else {
        cosca::Containment::TreeWalk
    };
    assert_eq!(child.containment(), expected);

    let mut gc = None;
    let mut root = None;
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept control conn");
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        match tag[0] {
            b'G' => gc = Some(s),
            _ => root = Some(s), // keep the root alive (see spawn_treewalk_tree)
        }
    }
    let mut gc_stream = gc.expect("grandchild connected");
    // Hold the root's socket open so the escapee root stays alive until kill_tree;
    // otherwise it exits, the grandchild is reparented, and TreeWalk can't reach it.
    let _root_stream = root.expect("root connected");

    child.kill_tree().expect("kill_tree");
    let _ = child.wait();

    // The escapee left its process group; only identity-based teardown reaches
    // it and its grandchild. EOF proves the grandchild died.
    let mut buf = [0u8; 1];
    let n = gc_stream.read(&mut buf).expect("read grandchild control socket");
    assert_eq!(n, 0, "TreeWalk must kill a setsid-escapee tree, not just the root");
}

/// Drop kills the whole contained tree. Mirrors `drop_kills_and_reaps_the_child`
/// (the lone-child case) but wraps a contained `spawn-grandchild` tree so the
/// grandchild must also die. Proof of death: the grandchild's control socket
/// closes — either a graceful EOF (n==0) or a ConnectionReset; the match below
/// accepts EITHER on ALL platforms (the OS may surface either form on any host).
#[cfg(any(unix, windows))]
#[test]
fn drop_kills_contained_tree() {
    let (child, mut gc_stream) = spawn_contained_tree();
    // Assert containment was actually established BEFORE dropping, so a failure
    // here (e.g. the tree survived drop) is diagnosable as "containment was set
    // up" vs "containment never engaged". spawn_contained_tree uses contain()
    // (Strongest), so the achieved mechanism is the host's strongest.
    assert_ne!(
        child.containment(),
        cosca::Containment::None,
        "drop test requires real containment; got None"
    );
    #[cfg(windows)]
    assert_eq!(child.containment(), cosca::Containment::JobObject);
    #[cfg(target_os = "linux")]
    assert!(
        matches!(
            child.containment(),
            cosca::Containment::CgroupV2 | cosca::Containment::ProcessGroup
        ),
        "Linux must use CgroupV2 or ProcessGroup, got {:?}",
        child.containment()
    );
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    assert!(
        matches!(
            child.containment(),
            cosca::Containment::ProcessGroup | cosca::Containment::Session | cosca::Containment::FdMarker
        ),
        "macOS/BSD must use ProcessGroup, Session or FdMarker, got {:?}",
        child.containment()
    );

    // Drop triggers: attached.hard_kill() → shared.kill() → shared.wait()
    drop(child);

    let mut buf = [0u8; 1];
    match gc_stream.read(&mut buf) {
        Ok(0) => {}                                                     // graceful EOF — grandchild exited
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {} // forceful kill — also proof of death
        Ok(n) => panic!("expected EOF/ConnectionReset after drop, got {n} bytes"),
        Err(e) => panic!("unexpected error reading grandchild control socket after drop: {e}"),
    }
}

// cgroup v2 integration tests =====
// Linux only, and `#[ignore]`d: they need a delegated cgroup, which CI provisions and then runs
// them with `nextest run --run-ignored all` and COSCA_TEST_CGROUP=1. Run without the marker, each
// fails loudly rather than pass having tested nothing.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn linux_cgroup_v2_kill_tree_reaps_the_grandchild() {
    stderr_log::install();
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    // COSCA_TEST_CGROUP is set: a usable delegated cgroup must exist.
    // If try_create_leaf() returns None, containment falls back to ProcessGroup
    // and the assert below will fail loudly — that's intentional.
    let (child, mut gc_stream) = spawn_contained_tree();
    assert_eq!(
        child.containment(),
        cosca::Containment::CgroupV2,
        "expected CgroupV2 containment but got {:?}; \
         is a delegated cgroup v2 slice available?",
        child.containment()
    );

    child.kill_tree().expect("kill_tree");
    let _ = child.wait(); // reap the root

    // Deterministic proof: the grandchild's control socket EOFs on its death.
    let mut buf = [0u8; 1];
    let n = gc_stream.read(&mut buf).expect("read grandchild control socket");
    assert_eq!(n, 0, "cgroup.kill must kill the grandchild, not just the root");
}

/// `terminate_tree` under cgroup v2 containment. Mirrors the kill_tree cgroup
/// test but exercises the SIGTERM path (`CgroupLeaf::terminate` SIGTERMs every
/// pid in cgroup.procs). The control-block grandchild has no SIGTERM handler so
/// the default action kills it. Proof of death: grandchild socket EOF.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn linux_cgroup_v2_terminate_tree_reaps_the_grandchild() {
    stderr_log::install();
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let (child, mut gc_stream) = spawn_contained_tree();
    assert_eq!(
        child.containment(),
        cosca::Containment::CgroupV2,
        "expected CgroupV2 containment but got {:?}; \
         is a delegated cgroup v2 slice available?",
        child.containment()
    );

    child.terminate_tree().expect("terminate_tree");
    let _ = child.wait(); // reap the root

    // Deterministic proof: the grandchild's control socket EOFs on its death.
    let mut buf = [0u8; 1];
    let n = gc_stream.read(&mut buf).expect("read grandchild control socket");
    assert_eq!(n, 0, "cgroup terminate must SIGTERM the grandchild, not just the root");
}

/// `detach()` must NOT kill a cgroup-contained tree. `CgroupLeaf::drop` runs whatever
/// `kill_on_drop` says, and its first `rmdir` fails `EBUSY` over a live detached tree — so
/// without a disarm it fires `cgroup.kill` and both members below are already dead.
///
/// Same proof as `windows_detach_leaves_the_tree_running` (see there for why a write alone
/// isn't enough).
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn linux_cgroup_v2_detach_leaves_the_tree_running() {
    common::cgroup::require_lane();
    stderr_log::install();
    assert_opted_out_tree_survives(|| spawn_contained_echo_tree(true), |child| child.detach());
}

/// `kill_on_drop(false)` must leave a cgroup-contained tree running, exactly as `detach()`
/// does — `Command::kill_on_drop` documents the two as the same opt-out, and the leaf drops
/// with the handle whatever the flag says.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn linux_cgroup_v2_kill_on_drop_false_leaves_the_tree_running() {
    common::cgroup::require_lane();
    stderr_log::install();
    assert_opted_out_tree_survives(|| spawn_contained_echo_tree(false), drop);
}

/// An opted-out handle still removes the leaf of a tree that has fully exited, as
/// `Command::kill_on_drop` says: `kill_tree` then `wait_tree` before the drop leaves nothing.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn linux_cgroup_v2_kill_on_drop_false_removes_the_leaf_of_a_drained_tree() {
    common::cgroup::require_lane();
    stderr_log::install();
    let EchoTree {
        child,
        root,
        grand,
        grand_pid,
    } = spawn_contained_echo_tree(false);
    assert_eq!(child.containment(), cosca::Containment::CgroupV2);
    let leaf = common::cgroup::cgroup_of(grand_pid);

    child.kill_tree().expect("kill_tree");
    let _ = child.wait();
    child.wait_tree().expect("wait_tree");
    drop(child);

    assert!(
        !leaf.exists(),
        "an opted-out handle must still remove the leaf of a drained tree: {}",
        leaf.display()
    );
    drop((root, grand));
}

/// Shared body of the two cgroup opt-out tests: spawn a contained echo tree, note the leaf it
/// was placed in, release the handle through `opt_out`, and prove BOTH members are still alive
/// by a byte round trip. Then release the tree and remove the leaf it kept.
#[cfg(target_os = "linux")]
fn assert_opted_out_tree_survives(spawn: impl FnOnce() -> EchoTree, opt_out: impl FnOnce(cosca::Child)) {
    let EchoTree {
        child,
        mut root,
        mut grand,
        grand_pid,
    } = spawn();
    assert_eq!(
        child.containment(),
        cosca::Containment::CgroupV2,
        "expected CgroupV2 containment but got {:?}; \
         is a delegated cgroup v2 slice available?",
        child.containment()
    );
    let leaf = common::cgroup::cgroup_of(grand_pid);
    assert!(
        leaf.file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("cosca-")),
        "the tree must be in a cosca leaf, got {}",
        leaf.display()
    );

    opt_out(child);

    common::assert_echoes(&mut root, "the opted-out root");
    common::assert_echoes(&mut grand, "the opted-out grandchild");

    // Release both: each read returns Ok(0) and the member exits on its own.
    drop(root);
    drop(grand);
    common::cgroup::drain_and_remove_leaf(&leaf);
}

/// Run `f` with the calling thread pinned to one CPU, then restore its affinity. A child forked
/// inside `f` inherits the pin, so parent and child share that CPU.
#[cfg(target_os = "linux")]
fn on_one_cpu<T>(f: impl FnOnce() -> T) -> T {
    // SAFETY: `cpu_set_t` is plain data; zeroed is a valid (empty) set.
    let mut original: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::cpu_set_t>();
    // SAFETY: pid 0 is the calling thread; `original` is a valid, writable set of `size` bytes.
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, size, &mut original) },
        0,
        "read affinity"
    );
    let cpu = (0..libc::CPU_SETSIZE as usize)
        // SAFETY: `cpu` is below CPU_SETSIZE, so it indexes inside the set.
        .find(|&cpu| unsafe { libc::CPU_ISSET(cpu, &original) })
        .expect("this thread may run on at least one CPU");
    // SAFETY: as above.
    let mut pinned: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `cpu` is below CPU_SETSIZE.
    unsafe { libc::CPU_SET(cpu, &mut pinned) };
    // SAFETY: pid 0 is the calling thread; `pinned` is a valid set of `size` bytes.
    assert_eq!(
        unsafe { libc::sched_setaffinity(0, size, &pinned) },
        0,
        "pin to one CPU"
    );
    let result = f();
    // SAFETY: as above, restoring the set read at entry.
    assert_eq!(
        unsafe { libc::sched_setaffinity(0, size, &original) },
        0,
        "restore affinity"
    );
    result
}

/// A contained `sh -c 'worker & exit 0'` keeps its worker, and the worker is in the leaf.
///
/// The root can exit before cosca looks at the leaf, and `cgroup.procs` lists only live tasks,
/// so the root is then absent from it although the kernel accepted its placement. Parent and
/// child share one CPU here, which makes that the common outcome rather than a rare one.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn linux_cgroup_v2_keeps_the_worker_of_a_root_that_already_exited() {
    use std::io::BufRead;

    stderr_log::install();
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();
    // `sh` backgrounds the worker without waiting for its exec, so the root exits at once.
    let mut cmd = Command::new();
    cmd.executable("/bin/sh")
        .args(["sh", "-c", r#""$0" control-echo-pid "$1" G & exit 0"#, testbin(), &addr]);
    cmd.contain();
    // The pin makes the race this guards likely — the root exiting before cosca looks at the
    // leaf — but orders nothing: the assertions below hold whichever side wins it.
    let child = on_one_cpu(|| cmd.spawn()).expect("spawn");
    assert_eq!(
        child.containment(),
        cosca::Containment::CgroupV2,
        "a root whose placement the kernel accepted is cgroup-contained, whether or not it is \
         still alive to be listed"
    );

    let (worker, _) = listener.accept().expect("accept the worker");
    let mut worker = std::io::BufReader::new(worker);
    let mut hello = String::new();
    worker.read_line(&mut hello).expect("read the worker's hello");
    assert!(hello.starts_with('G'), "expected the worker's tag, got {hello:?}");
    let worker_pid: u32 = hello[1..].trim().parse().expect("the worker's pid");
    let leaf = common::cgroup::cgroup_of(worker_pid);
    // Proof of life, after the spawn returned: a round trip only a live worker completes.
    worker.get_mut().write_all(b"x").expect("write to the worker");
    let mut echo = [0u8; 1];
    worker
        .read_exact(&mut echo)
        .expect("the worker must still be alive to echo — cosca killed it at spawn time");
    assert_eq!(&echo, b"x");

    // The leaf owns the worker: its kill reaches it.
    child.kill_tree().expect("kill_tree");
    let _ = child.wait();
    let mut buf = [0u8; 1];
    let n = worker.read(&mut buf).expect("read the worker's control socket");
    assert_eq!(n, 0, "cgroup.kill must reach the worker the exited root left behind");

    // The worker's socket closes before it leaves the leaf; `Drop` waits for it to.
    drop(child);
    assert!(
        !leaf.exists(),
        "Drop must remove the leaf once it drains: {}",
        leaf.display()
    );
}

/// The unified-hierarchy path in the contents of a `/proc/<pid>/cgroup` file.
#[cfg(target_os = "linux")]
fn unified_cgroup(proc_cgroup: &str) -> &str {
    proc_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("a cgroup v2 `0::` line")
}

/// Closed descriptors among 0, 1 and 2 can neither capture the child's placement write nor
/// hide its placement report.
///
/// A descriptor the supervisor opens takes the lowest free number, and `std` `dup2`s the child's
/// stdio onto 0/1/2 before any `pre_exec` runs. So with slots closed at spawn time:
/// - a `cgroup.procs` fd opened in a gap would be replaced by the child's stdio, and the placement
///   write would land in the user's file and report a placement that never happened;
/// - with two or more closed, `std`'s own error channel lands its child end on one of them, the
///   child's stdio closes it, and `spawn` returns before the child has placed itself. Reading the
///   report then would miss the placement, degrade to a process group, and leave the child in a
///   leaf nothing kills through.
///
/// A `Stdio::from_file` end is a dup numbered 3 or above, so it does not fill a gap first.
///
/// Every case also runs with `pidfd_open` denied by a seccomp filter, where cosca cannot wait
/// for the report: the child may then land on either side of its leaf, but cosca must report the
/// side it is on.
///
/// Each case runs in a fresh copy of this test binary running only this test: a closed 0, 1 or 2
/// is process-wide, so in a binary with other tests running it would hand their next `open` the
/// slot, and with 2 closed a failing assertion's message would go nowhere.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn linux_cgroup_v2_closed_stdio_slots_cannot_misplace_or_misreport_the_child() {
    const NAME: &str = "linux_cgroup_v2_closed_stdio_slots_cannot_misplace_or_misreport_the_child";

    stderr_log::install();
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    if let Ok(slots) = std::env::var(CLOSED_SLOTS_ENV) {
        let deny_pidfd = std::env::var_os(DENY_PIDFD_ENV).is_some();
        return spawn_with_slots_closed(&parse_closed_slots(&slots), deny_pidfd);
    }
    // "" is the control: the same spawn with every slot open.
    let slot_cases = ["", "0", "1", "2", "1,2", "0,1", "0,2", "0,1,2"];
    let failures: Vec<String> = [false, true]
        .into_iter()
        .flat_map(|deny| slot_cases.map(|slots| (slots, deny)))
        .filter_map(|(slots, deny)| {
            let mut run = std::process::Command::new(std::env::current_exe().expect("this test binary"));
            run.args([NAME, "--exact", "--include-ignored", "--nocapture", "--test-threads=1"])
                .env(CLOSED_SLOTS_ENV, slots);
            if deny {
                run.env(DENY_PIDFD_ENV, "1");
            }
            let out = run.output().expect("run this test with the slots closed");
            let stdout = String::from_utf8_lossy(&out.stdout);
            (!(out.status.success() && stdout.contains("1 passed"))).then(|| {
                format!(
                    "slots [{slots}], pidfd denied: {deny}: {}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                )
            })
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Selects the slots one case of
/// [`linux_cgroup_v2_closed_stdio_slots_cannot_misplace_or_misreport_the_child`] closes:
/// comma-separated, empty for none.
#[cfg(target_os = "linux")]
const CLOSED_SLOTS_ENV: &str = "COSCA_TEST_CLOSED_SLOTS";

/// Set to deny `pidfd_open` in one case of
/// [`linux_cgroup_v2_closed_stdio_slots_cannot_misplace_or_misreport_the_child`].
#[cfg(target_os = "linux")]
const DENY_PIDFD_ENV: &str = "COSCA_TEST_DENY_PIDFD";

/// Make `pidfd_open` fail with `EPERM` on the calling thread and every process it forks, as a
/// seccomp-filtered container does.
#[cfg(target_os = "linux")]
fn deny_pidfd_open_on_this_thread() {
    // `seccomp_data.nr`, the syscall number, is at offset 0.
    let filter = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_pidfd_open as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: plain prctl calls; `program` and `filter` outlive the second, which copies them.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0, "no_new_privs");
        assert_eq!(
            libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
            0,
            "seccomp: {}",
            std::io::Error::last_os_error()
        );
        let pidfd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0);
        assert_eq!(pidfd, -1, "pidfd_open must be denied");
    }
}

#[cfg(target_os = "linux")]
fn parse_closed_slots(slots: &str) -> Vec<i32> {
    slots
        .split(',')
        .filter(|slot| !slot.is_empty())
        .map(|slot| {
            let slot: i32 = slot.parse().unwrap_or_else(|_| panic!("bad slot {slot:?}"));
            assert!((0..=2).contains(&slot), "slot {slot} is not a std slot");
            slot
        })
        .collect()
}

/// Spawn `cmd` with `slots` closed in this process across the spawn, and restore them.
#[cfg(target_os = "linux")]
fn spawn_with_std_slots_closed(cmd: &mut Command, slots: &[i32]) -> Result<cosca::Child, cosca::error::Error> {
    // Everything this process needs open is opened already, so nothing fills the gaps but the
    // spawn. Every slot is saved above 2 before any is closed: a plain `dup` would take a gap.
    // SAFETY: each slot is one of this process's own std descriptors; it is closed only across
    // the spawn and restored from its saved copy before anything else runs.
    let saved: Vec<(i32, i32)> = slots
        .iter()
        .map(|&slot| unsafe {
            let saved = libc::fcntl(slot, libc::F_DUPFD_CLOEXEC, 3);
            assert!(saved >= 3, "dup({slot}): {}", std::io::Error::last_os_error());
            (slot, saved)
        })
        .collect();
    for &(slot, _) in &saved {
        // SAFETY: as above.
        assert_eq!(unsafe { libc::close(slot) }, 0, "close({slot})");
    }
    // One CPU for parent and child makes it likely that `spawn` returns before the child has
    // reported — the case a report read at `spawn`'s return would get wrong. It orders nothing:
    // the verdict below compares cosca's answer with where the child really is, and holds
    // whichever side runs first.
    let spawned = on_one_cpu(|| cmd.spawn());
    for &(slot, saved) in &saved {
        // SAFETY: `saved` is this process's own open descriptor, duplicated above.
        unsafe {
            assert_eq!(libc::dup2(saved, slot), slot, "restore fd {slot}");
            libc::close(saved);
        }
    }
    spawned
}

/// Accept one connection on `listener`, or fail at once if the process `pid` — this process's
/// child, whose tree is to connect — exits first. No timeout: one of the two always happens.
#[cfg(target_os = "linux")]
fn accept_while_alive(listener: &std::net::TcpListener, pid: u32) -> std::net::TcpStream {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: a plain syscall; its result is checked before use.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(pidfd >= 0, "pidfd_open({pid}): {}", std::io::Error::last_os_error());
    // SAFETY: `pidfd` is a fresh descriptor this function owns.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };
    let mut fds = [
        libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: two valid pollfds; -1 blocks until one is ready.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if ready >= 0 {
            break;
        }
        let e = std::io::Error::last_os_error();
        assert_eq!(e.kind(), std::io::ErrorKind::Interrupted, "poll: {e}");
    }
    assert_ne!(
        fds[0].revents & libc::POLLIN,
        0,
        "child {pid} exited before its tree connected"
    );
    listener.accept().expect("accept the worker").0
}

/// One case of [`linux_cgroup_v2_closed_stdio_slots_cannot_misplace_or_misreport_the_child`]:
/// spawn a contained `sh` with `slots` closed in this process and each wired to a file in the
/// child, then check what cosca reports against where the child really is.
#[cfg(target_os = "linux")]
fn spawn_with_slots_closed(slots: &[i32], deny_pidfd: bool) {
    use std::io::{BufRead, Seek};

    const CONTENTS: &[u8] = b"untouched\n";

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();
    let own = std::fs::read_to_string("/proc/self/cgroup").expect("read /proc/self/cgroup");
    let own = unified_cgroup(&own).to_string();
    let mut file = tempfile::tempfile().expect("tempfile");
    file.write_all(CONTENTS).expect("fill the file");
    file.rewind().expect("rewind the file");

    let mut cmd = Command::new();
    // The root stays alive in `wait` for as long as the worker does.
    cmd.executable("/bin/sh")
        .args(["sh", "-c", r#""$0" control-echo-pid "$1" G & wait"#, testbin(), &addr]);
    for &slot in slots {
        cmd.fd(slot, Stdio::from_file(file.try_clone().expect("clone the file")))
            .expect("wire the slot to the file");
    }
    cmd.contain();

    // The spawn runs on a thread of its own: a seccomp filter is per thread, so this one keeps
    // the `pidfd_open` it needs to watch the child below.
    let spawned = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                if deny_pidfd {
                    deny_pidfd_open_on_this_thread();
                }
                spawn_with_std_slots_closed(&mut cmd, slots)
            })
            .join()
            .expect("the spawning thread")
    });
    let child = spawned.expect("spawn");
    let containment = child.containment();
    // Printed once 0, 1 and 2 are back, for a caller counting outcomes across runs.
    println!("closed-slots outcome: {containment:?}");

    let worker = accept_while_alive(&listener, child.id().pid());
    let mut worker = std::io::BufReader::new(worker);
    let mut hello = String::new();
    worker.read_line(&mut hello).expect("read the worker's hello");
    let worker_pid: u32 = hello
        .trim()
        .strip_prefix('G')
        .and_then(|pid| pid.parse().ok())
        .unwrap_or_else(|| panic!("expected the worker's tagged pid, got {hello:?}"));

    // The worker is `sh`'s own fork, made after `sh` exec'd, so the root's placement — whichever
    // way it went — is settled. The root is alive in `wait`, so its cgroup is readable.
    let root_cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", child.id().pid())).expect("root cgroup");
    let root_cgroup = unified_cgroup(&root_cgroup).to_string();
    let leaf_prefix = format!("{own}/cosca-{}-", std::process::id());
    // A leaf is `cosca-<pid>-<seq>-<random>`.
    let in_leaf = root_cgroup
        .strip_prefix(&leaf_prefix)
        .and_then(|rest| rest.split_once('-'))
        .is_some_and(|(seq, random)| {
            !seq.is_empty()
                && seq.bytes().all(|b| b.is_ascii_digit())
                && random.len() == 16
                && random.bytes().all(|b| b.is_ascii_hexdigit())
        });
    let expected = if deny_pidfd && slots.len() >= 2 {
        // `spawn` can return before the report, which cannot be waited for: either side of the
        // leaf is right, as long as it is reported.
        (
            if in_leaf {
                cosca::Containment::CgroupV2
            } else {
                cosca::Containment::ProcessGroup
            },
            in_leaf,
        )
    } else {
        (cosca::Containment::CgroupV2, true)
    };
    assert_eq!(
        (containment, in_leaf),
        expected,
        "slots {slots:?}, pidfd denied: {deny_pidfd}: cosca reports {containment:?}, and the \
         child is in {root_cgroup} (its leaf would be {leaf_prefix}<seq>-<random>)"
    );
    let worker_cgroup = std::fs::read_to_string(format!("/proc/{worker_pid}/cgroup")).expect("worker cgroup");
    assert_eq!(
        unified_cgroup(&worker_cgroup),
        root_cgroup,
        "the worker is in the root's cgroup"
    );

    let mut written = Vec::new();
    file.rewind().expect("rewind the file");
    file.read_to_end(&mut written).expect("read the file back");
    assert_eq!(
        String::from_utf8_lossy(&written),
        String::from_utf8_lossy(CONTENTS),
        "slots {slots:?}: the placement write landed in the child's stdio file"
    );

    // Proof of life before the kill: a round trip only a live worker completes.
    worker.get_mut().write_all(b"x").expect("write to the worker");
    let mut echo = [0u8; 1];
    worker.read_exact(&mut echo).expect("the worker echoes while alive");
    assert_eq!(&echo, b"x");

    child.kill_tree().expect("kill_tree");
    let _ = child.wait();
    let mut buf = [0u8; 1];
    let n = worker.read(&mut buf).expect("read the worker's control socket");
    assert_eq!(n, 0, "cgroup.kill must kill the worker");

    // The leaf is removed with the child: nothing is left behind once its members have exited.
    let own_dir = std::path::Path::new("/sys/fs/cgroup").join(own.trim_start_matches('/'));
    if in_leaf {
        common::cgroup::wait_drained(&own_dir.join(root_cgroup.rsplit('/').next().expect("a leaf name")));
    }
    drop(child);
    let prefix = format!("cosca-{}-", std::process::id());
    let left: Vec<String> = std::fs::read_dir(&own_dir)
        .expect("list this process's cgroup")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(&prefix))
        .collect();
    assert!(left.is_empty(), "slots {slots:?}: {left:?} left behind");
}

/// Once a spawn has returned, the supervisor holds no descriptor for the child's leaf
/// `cgroup.procs`: it is needed only for the child's own placement write, and one held per
/// live child would spend the supervisor's fd limit on children it no longer needs it for.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn linux_cgroup_v2_a_live_child_holds_no_cgroup_procs_fd_in_the_supervisor() {
    stderr_log::install();
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let (child, mut gc_stream) = spawn_contained_tree();
    assert_eq!(child.containment(), cosca::Containment::CgroupV2);

    // The root is alive (it holds its control socket), so its cgroup is readable.
    let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", child.id().pid())).expect("root cgroup");
    let procs = format!("{}/cgroup.procs", unified_cgroup(&cgroup));
    let held: Vec<String> = std::fs::read_dir("/proc/self/fd")
        .expect("list this process's fds")
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .map(|target| target.to_string_lossy().into_owned())
        .filter(|target| target.ends_with(&procs))
        .collect();
    assert!(held.is_empty(), "the supervisor still holds {held:?}");

    child.kill_tree().expect("kill_tree");
    let _ = child.wait();
    let mut buf = [0u8; 1];
    assert_eq!(gc_stream.read(&mut buf).expect("read the grandchild's socket"), 0);
}
