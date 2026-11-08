#[cfg(target_os = "linux")]
use crate::test_groups::{unprivileged, Group};

/// `/bin/sh -c script`, with all three standard streams piped.
fn sh(script: &str) -> crate::Child {
    super::pump_common_tests::shell(script, "")
}

// No threads =====

/// `communicate` starts no thread: it returns the child's output under a process limit that
/// refuses every new thread. Runs in a re-exec'd child, since `RLIMIT_NPROC` is process-wide and
/// irreversible once lowered with its hard limit.
///
/// Mutant: stdin, stdout or stderr is drained on a thread of its own.
#[cfg(target_os = "linux")]
#[skuld::test]
fn communicate_starts_no_thread(#[fixture(unprivileged)] _group: &Group) {
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
    let refused = std::thread::Builder::new().spawn(|| {});
    assert!(
        refused.is_err(),
        "the precondition: RLIMIT_NPROC=0 must refuse a new thread; it does not bind uid 0 or \
         CAP_SYS_RESOURCE/CAP_SYS_ADMIN holders, so run as an unprivileged user, or set \
         COSCA_TEST_UNPRIVILEGED=0 to opt out"
    );
    let input = crate::test_pattern::pattern_bytes(1 << 20);
    let out = child.communicate(Some(&input)).expect("communicate");
    assert!(out.status.success());
    assert!(out.stdout == input, "stdout");
    assert_eq!(out.stderr, b"done\n");
}

// SIGPIPE =====

/// A host whose `SIGPIPE` disposition is the default (a C host, a cdylib, `-Zon-broken-pipe=kill`)
/// is not killed when a child stops reading stdin: `communicate` returns `Ok`. Runs in a re-exec'd
/// child, since the disposition is process-wide.
///
/// Mutant: the stdin write can raise `SIGPIPE` unguarded (unblocked, or without `F_SETNOSIGPIPE` on
/// macOS).
#[skuld::test]
fn a_child_that_stops_reading_stdin_does_not_kill_a_default_sigpipe_host() {
    crate::test_child::run_fixture(crate::test_child::fixture_path!(
        fixture_communicate_with_default_sigpipe
    ));
}

#[skuld::test]
fn fixture_communicate_with_default_sigpipe() {
    if !crate::test_child::is_fixture_reexec() {
        return;
    }
    // SAFETY: sets this fixture process's own `SIGPIPE` disposition, and nothing else.
    let previous = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    assert_ne!(
        previous,
        libc::SIG_ERR,
        "reset SIGPIPE: {}",
        std::io::Error::last_os_error()
    );
    let mut child = sh("echo out; exit 3");
    let input = vec![b'x'; 1 << 20];
    let out = child.communicate(Some(&input)).expect("communicate");
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(
        out.stdout,
        b"out
"
    );
}

/// A `SIGPIPE` the host already has pending is still pending after `communicate`: the one the
/// stdin write raised is consumed, the host's is not. Runs in a re-exec'd child, since it sets
/// `SIGPIPE`'s disposition to the default and blocks and raises it.
///
/// Mutant: `communicate` consumes a `SIGPIPE` that was pending before its write.
#[skuld::test]
fn a_sigpipe_pending_in_the_host_stays_pending() {
    crate::test_child::run_fixture(crate::test_child::fixture_path!(
        fixture_communicate_with_pending_sigpipe
    ));
}

#[skuld::test]
fn fixture_communicate_with_pending_sigpipe() {
    if !crate::test_child::is_fixture_reexec() {
        return;
    }
    // SAFETY: signal-mask and signal calls on this fixture's own thread and process, on sets
    // initialised by `sigemptyset`.
    unsafe {
        // Under Rust's ignored disposition macOS discards a raised SIGPIPE even while it is
        // blocked, so nothing would be pending to keep.
        assert_ne!(libc::signal(libc::SIGPIPE, libc::SIG_DFL), libc::SIG_ERR);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGPIPE);
        assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()), 0);
        assert_eq!(libc::raise(libc::SIGPIPE), 0);
        let mut raised: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigpending(&mut raised), 0);
        assert_eq!(
            libc::sigismember(&raised, libc::SIGPIPE),
            1,
            "the raised SIGPIPE is pending"
        );

        let mut child = sh("echo out; exit 3");
        let input = vec![b'x'; 1 << 20];
        let out = child.communicate(Some(&input)).expect("communicate");
        assert_eq!(
            out.stdout,
            b"out
"
        );

        let mut pending: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigpending(&mut pending), 0);
        assert_eq!(
            libc::sigismember(&pending, libc::SIGPIPE),
            1,
            "the host's SIGPIPE was consumed"
        );
    }
}
