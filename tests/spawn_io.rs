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

#[cfg(windows)]
#[test]
fn fd_ge_3_is_rejected() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "exit", "0"]);
    cmd.fd(3, Stdio::null()).expect("fd attach ok");
    let err = cmd.spawn().expect_err("should reject fd >= 3 on Windows");
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

#[cfg(windows)]
#[test]
fn arbitrary_fd_is_unsupported_on_windows() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "exit", "0"]);
    cmd.fd(3, Stdio::pipe_out()).unwrap(); // attaches fine
    let err = cmd.spawn().unwrap_err(); // but spawn rejects it on Windows
    assert!(matches!(err, subprocess::error::Error::Unsupported { .. }));
}

// Arbitrary fd (n>=3) — Unix only, wired via command-fds =====

/// Prove that a child fd 3 configured as a pipe is reachable from the child:
/// the testbin's `fd3-echo` mode reads fd 3 and copies it to stdout. We write
/// a known payload into the parent write-end, close it, then read stdout to
/// EOF — no timers, no polling, fully deterministic.
#[cfg(unix)]
#[test]
fn unix_fd3_pipe_round_trips() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "fd3-echo"])
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
/// producing no stdout output. Confirms the null path reaches command-fds.
#[cfg(unix)]
#[test]
fn unix_fd3_null_is_accepted() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "fd3-echo"])
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
/// parent stream to dup for n>=3). The raw backend (Plan 4) lifts this.
#[cfg(unix)]
#[test]
fn unix_fd3_inherit_is_rejected() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "exit", "0"])
        .fd(3, Stdio::inherit())
        .expect("fd attach ok");
    let err = cmd.spawn().expect_err("inherit on fd 3 should be rejected");
    assert!(
        matches!(err, subprocess::error::Error::Unsupported { .. }),
        "expected Unsupported, got {err:?}"
    );
}

/// Prove that fd 3 configured as a file is passed through to the child:
/// the child reads fd 3 and echoes it to stdout; we compare the payload.
#[cfg(unix)]
#[test]
fn unix_fd3_file_round_trips() {
    use std::io::{Seek, Write};

    // Write a payload to a unique temp file, then rewind for the child to read.
    // `tempfile()` gives a process-unique, auto-cleaned file so two concurrent
    // `cargo test` runs cannot collide on a shared fixed name.
    let mut tmp = tempfile::tempfile().expect("create tmpfile");
    tmp.write_all(b"from file via fd3").expect("write tmpfile");
    tmp.seek(std::io::SeekFrom::Start(0)).expect("seek");

    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "fd3-echo"])
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

/// Regression: `.contain()` + `.fd(3, pipe_out())` on Linux must NOT let the
/// cgroup self-placement clobber (or be clobbered by) the command-fds dup2.
///
/// The cgroup `pre_exec` opens `cgroup.procs` with CLOEXEC cleared and writes
/// "0" to it. command-fds installs its own `pre_exec` that dup2's the user's
/// fd 3 onto child fd 3. If command-fds runs FIRST, its dup2 can land on the
/// same fd number the cgroup `procs_fd` occupies — silently downgrading
/// containment OR writing the cgroup's "0" into the user's fd 3 (corruption).
/// We assert the parent reads EXACTLY the child-written token (no inserted "0",
/// no broken pipe) AND that containment was actually established. Under a real
/// delegated cgroup (SUBPROCESS_TEST_CGROUP set) we additionally assert the
/// achieved mechanism is CgroupV2 — proof the cgroup write was not clobbered.
/// Read to EOF; no timers.
#[cfg(target_os = "linux")]
#[test]
fn linux_contain_with_fd3_does_not_clobber_cgroup_procs_fd() {
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "fd3-write", "FD3PAYLOAD"])
        // pipe_out: child writes, parent holds the read end.
        .fd(3, Stdio::pipe_out())
        .expect("fd 3 pipe_out");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn contained child with fd 3");

    // Containment must be a real mechanism (a clobbered procs_fd would silently
    // downgrade CgroupV2 -> ProcessGroup; None would mean containment vanished).
    assert_ne!(
        child.containment(),
        subprocess::Containment::None,
        "contain() + fd(3) must still establish containment"
    );
    // When a delegated cgroup is provisioned, the write must have landed in
    // cgroup.procs (not been clobbered by command-fds' dup2): CgroupV2 achieved.
    if std::env::var_os("SUBPROCESS_TEST_CGROUP").is_some() {
        assert_eq!(
            child.containment(),
            subprocess::Containment::CgroupV2,
            "cgroup write must not be clobbered by command-fds dup2; got {:?}",
            child.containment()
        );
    }

    let mut fd3_reader = child.fd_read_end(Fd::from(3)).expect("fd 3 reader");
    let mut buf = Vec::new();
    fd3_reader.read_to_end(&mut buf).expect("read fd 3");
    drop(fd3_reader);
    let _ = child.wait();

    // Exact payload: a clobber would prepend/insert the cgroup "0" or break the pipe.
    assert_eq!(
        buf, b"FD3PAYLOAD",
        "fd 3 stream corrupted — cgroup procs_fd clobbered command-fds"
    );
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

// Containment =====

#[test]
fn uncontained_child_reports_containment_none() {
    let mut cmd = Command::new();
    cmd.executable(testbin()).args(["subprocess_testbin", "exit", "0"]);
    let child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), subprocess::Containment::None);
    let _ = child.wait();
}

/// Spawn a contained `spawn-grandchild` and return (child, grandchild_stream).
/// The grandchild's connected socket is proof it is alive; reading it to EOF
/// later is the deterministic proof it died.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
fn spawn_contained_tree() -> (subprocess::Child, std::net::TcpStream) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "spawn-grandchild", &addr]);
    cmd.contain();
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

#[cfg(unix)]
#[test]
fn unix_kill_tree_reaps_the_grandchild() {
    let (child, mut gc_stream) = spawn_contained_tree();
    assert_eq!(child.containment(), subprocess::Containment::ProcessGroup);

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
    assert_eq!(child.containment(), subprocess::Containment::ProcessGroup);

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
    assert_eq!(child.containment(), subprocess::Containment::JobObject);

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
    assert_eq!(child.containment(), subprocess::Containment::JobObject);

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
    assert_eq!(child.containment(), subprocess::Containment::JobObject);

    // test_job_handle_contains_self() is cfg(all(windows,test)) — confirms the job we hold.
    let in_job = child.test_job_handle_contains_self();
    assert!(in_job, "child must be inside our job object after spawn");

    child.kill_tree().expect("kill_tree");
    let _ = child.wait();
}

/// `detach()` must NOT kill the grandchild's process tree.
/// Proof: the grandchild's control socket must stay open after detach. We
/// prove liveness by writing a byte (which causes the grandchild's blocking
/// `sock.read` to return 1, letting it exit cleanly) and then observing EOF —
/// a voluntary, natural exit rather than a job-kill EOF. The critical ordering
/// is: detach FIRST, then write. If KILL_ON_JOB_CLOSE fired on detach, the
/// grandchild would already be dead and the write would fail with BrokenPipe.
#[cfg(windows)]
#[test]
fn windows_detach_leaves_the_tree_running() {
    let (child, mut gc_stream) = spawn_contained_tree();
    assert_eq!(child.containment(), subprocess::Containment::JobObject);

    // detach() must clear KILL_ON_JOB_CLOSE before closing the job handle.
    child.detach();

    // Send a byte to the grandchild's control socket. If KILL_ON_JOB_CLOSE
    // fired during detach, the grandchild is dead and this write fails with
    // BrokenPipe — a hard assertion failure, not a silent pass.
    gc_stream
        .write_all(b"p")
        .expect("grandchild control socket must accept write after detach (tree still alive)");

    // Grandchild received the byte (its blocking read returned 1) and exited
    // voluntarily — confirm by waiting for EOF on the control socket.
    let mut buf = [0u8; 1];
    let n = gc_stream
        .read(&mut buf)
        .expect("read grandchild control socket after detach");
    assert_eq!(
        n, 0,
        "expected EOF after grandchild exited voluntarily; if n=1, it is still alive (not an error but unexpected)"
    );
}

// Unix session containment =====

/// Spawn a contained tree using `ContainMode::Session` and return the handles.
/// This is separate from `spawn_contained_tree` (which uses `contain()` =
/// `Strongest`) so the two modes are tested independently.
#[cfg(unix)]
fn spawn_session_tree() -> (subprocess::Child, std::net::TcpStream) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "spawn-grandchild", &addr]);
    cmd.contain_with(subprocess::ContainMode::Session);
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
    assert_eq!(child.containment(), subprocess::Containment::Session);

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
        .args(["subprocess_testbin", "sid-report"])
        .stdout(Stdio::pipe())
        .expect("stdout pipe")
        .contain_with(subprocess::ContainMode::Session);
    let mut child = cmd.spawn().expect("spawn sid-report");
    assert_eq!(child.containment(), subprocess::Containment::Session);

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
fn spawn_treewalk_tree() -> (subprocess::Child, std::net::TcpStream, std::net::TcpStream) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", "spawn-grandchild", &addr]);
    cmd.contain_with(subprocess::ContainMode::TreeWalk);
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
    assert_eq!(child.containment(), subprocess::Containment::TreeWalk);

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
    assert_eq!(child.containment(), subprocess::Containment::TreeWalk);

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
        .args(["subprocess_testbin", "spawn-grandchild-escapee", &addr]);
    cmd.contain_with(subprocess::ContainMode::TreeWalk);
    let child = cmd.spawn().expect("spawn tree-walk escapee tree");
    assert_eq!(child.containment(), subprocess::Containment::TreeWalk);

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
        subprocess::Containment::None,
        "drop test requires real containment; got None"
    );
    #[cfg(windows)]
    assert_eq!(child.containment(), subprocess::Containment::JobObject);
    #[cfg(target_os = "linux")]
    assert!(
        matches!(
            child.containment(),
            subprocess::Containment::CgroupV2 | subprocess::Containment::ProcessGroup
        ),
        "Linux must use CgroupV2 or ProcessGroup, got {:?}",
        child.containment()
    );
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    assert!(
        matches!(
            child.containment(),
            subprocess::Containment::ProcessGroup | subprocess::Containment::Session
        ),
        "macOS/BSD must use ProcessGroup or Session, got {:?}",
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

// cgroup v2 integration test =====
// Runs only on Linux, and only when the CI provisions a delegated cgroup
// (SUBPROCESS_TEST_CGROUP=1). The env guard means this is a true no-op when
// unprovisioned, but FAILS loudly when the marker is set but the cgroup is
// unavailable (the test asserts CgroupV2, so it won't silently pass).
#[cfg(target_os = "linux")]
#[test]
fn linux_cgroup_v2_kill_tree_reaps_the_grandchild() {
    if std::env::var_os("SUBPROCESS_TEST_CGROUP").is_none() {
        // Unprovisioned: skip (not CI-cgroup environment). The live cgroup test
        // requires SUBPROCESS_TEST_CGROUP=1 and a delegated cgroup slice.
        return;
    }
    // SUBPROCESS_TEST_CGROUP is set: a usable delegated cgroup must exist.
    // If try_create_leaf() returns None, containment falls back to ProcessGroup
    // and the assert below will fail loudly — that's intentional.
    let (child, mut gc_stream) = spawn_contained_tree();
    assert_eq!(
        child.containment(),
        subprocess::Containment::CgroupV2,
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
/// the default action kills it. Gated on SUBPROCESS_TEST_CGROUP — a true no-op
/// when unprovisioned, but FAILS loudly (CgroupV2 assertion) when the marker is
/// set without a usable delegated cgroup. Proof of death: grandchild socket EOF.
#[cfg(target_os = "linux")]
#[test]
fn linux_cgroup_v2_terminate_tree_reaps_the_grandchild() {
    if std::env::var_os("SUBPROCESS_TEST_CGROUP").is_none() {
        return; // unprovisioned: not a CI-cgroup environment.
    }
    let (child, mut gc_stream) = spawn_contained_tree();
    assert_eq!(
        child.containment(),
        subprocess::Containment::CgroupV2,
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
