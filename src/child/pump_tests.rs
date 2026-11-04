use crate::{Command, Stdio};

/// `/bin/sh -c script`, with all three standard streams piped.
fn sh(script: &str) -> crate::Child {
    let mut c = Command::new();
    c.args(["/bin/sh", "-c", script]);
    c.stdin(Stdio::pipe()).expect("stdin");
    c.stdout(Stdio::pipe()).expect("stdout");
    c.stderr(Stdio::pipe()).expect("stderr");
    c.spawn().expect("spawn")
}

/// A child that exits without reading its input ends the input: `communicate` returns what it
/// printed, not an error.
///
/// Mutant: a broken pipe on stdin is an `Err`.
#[skuld::test]
fn a_child_that_stops_reading_stdin_ends_the_input() {
    let mut child = sh("echo out; exit 3");
    let input = vec![b'x'; 1 << 20];
    let out = child.communicate(Some(&input)).expect("communicate");
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(out.stdout, b"out\n");
}

/// Each output stream is read while the other is idle: a child that fills stderr past a pipe
/// buffer before it writes stdout, and the reverse, both finish.
///
/// Mutant: stdout is read to EOF before stderr is read at all, or the reverse.
#[skuld::test]
fn each_stream_is_read_while_the_other_is_idle() {
    for script in [
        "head -c 1000000 /dev/zero >&2; head -c 1000000 /dev/zero",
        "head -c 1000000 /dev/zero; head -c 1000000 /dev/zero >&2",
    ] {
        let mut child = sh(script);
        let out = child.communicate(None).expect("communicate");
        assert!(out.status.success(), "{script}");
        assert_eq!(out.stdout.len(), 1_000_000, "{script}");
        assert_eq!(out.stderr.len(), 1_000_000, "{script}");
    }
}

/// With a piped stdin and no input, the child sees EOF at once.
///
/// Mutant: the stdin pipe is held open until the child exits.
#[skuld::test]
fn no_input_closes_stdin() {
    let mut child = sh("cat");
    let out = child.communicate(None).expect("communicate");
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}

// No threads =====

/// `communicate` starts no thread: it returns the child's output under a process limit that
/// refuses every new thread. Runs in a re-exec'd child, since `RLIMIT_NPROC` is process-wide and
/// irreversible once lowered with its hard limit.
///
/// Mutant: stdin, stdout or stderr is drained on a thread of its own.
#[cfg(target_os = "linux")]
#[skuld::test]
fn communicate_starts_no_thread() {
    crate::test_child::run_fixture(crate::test_child::fixture_path!(
        fixture_communicate_under_a_nproc_limit
    ));
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn fixture_communicate_under_a_nproc_limit() {
    if !crate::test_child::is_fixture_reexec() {
        return;
    }
    // The child is running before the limit exists, as in a caller that spawns and then drains.
    let mut child = sh("cat; echo done >&2");
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: lowers this fixture process's own process limit, and nothing else.
    let set = unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limit) };
    assert_eq!(set, 0, "lower RLIMIT_NPROC: {}", std::io::Error::last_os_error());
    // `RLIMIT_NPROC` does not bind uid 0 or a holder of CAP_SYS_RESOURCE or CAP_SYS_ADMIN.
    let refused = std::thread::Builder::new().spawn(|| {});
    assert!(
        refused.is_err(),
        "the precondition: RLIMIT_NPROC=0 must refuse a new thread; it does not bind uid 0 or \
         CAP_SYS_RESOURCE/CAP_SYS_ADMIN holders, so run this suite as an unprivileged user"
    );
    let input = vec![b'x'; 1 << 20];
    let out = child.communicate(Some(&input)).expect("communicate");
    assert!(out.status.success());
    assert_eq!(out.stdout, input);
    assert_eq!(out.stderr, b"done\n");
}
