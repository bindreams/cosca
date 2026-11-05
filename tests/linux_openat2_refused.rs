//! `openat2` refused by a real seccomp filter: `ProcessId::current` still works, and a by-pid read
//! is `Unknown`, or `Gone` for a pid no process can hold. The unit tests state the refusal through
//! a `Kernel` fake; these tests make the kernel answer it.

#[cfg(target_os = "linux")]
use cosca::identity::{Existence, Liveness, ProcessId, Resolved};

#[cfg(target_os = "linux")]
#[path = "common/mod.rs"]
mod common;

/// `openat2` answers `ENOSYS` before Linux 5.6, and `EPERM` under a seccomp profile that blocks it.
#[cfg(target_os = "linux")]
const REFUSALS: [(i32, &str); 2] = [(libc::ENOSYS, "ENOSYS"), (libc::EPERM, "EPERM")];

/// Above `PID_MAX_LIMIT` (2^22) yet a valid positive `kill` target, so `kill(pid, 0)` answers `ESRCH`.
#[cfg(target_os = "linux")]
const NO_PROCESS_CAN_HOLD: u32 = i32::MAX as u32;

/// Runs `f` on a thread with `openat2` refused with `errno`. A filter is per-thread and ends with
/// it, so the test's own thread keeps `openat2`.
#[cfg(target_os = "linux")]
fn with_openat2_refused(errno: i32, f: impl FnOnce() + Send) {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                common::seccomp::deny_openat2_on_this_thread(errno);
                f();
            })
            .join()
            .expect("the filtered thread");
    });
}

/// A host where `openat2` is unavailable still has `/proc`, and `current()` reads `self/stat`
/// without it.
///
/// Mutant: `current_token` opens the checked `/proc` (it panics on the filtered thread).
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_leaves_current_working() {
    let ordinary = ProcessId::current();
    for (errno, _) in REFUSALS {
        with_openat2_refused(errno, || assert_eq!(ProcessId::current(), ordinary, "{errno}"));
    }
}

/// Without `openat2` there is no view, so a by-pid read of a live pid is `Unknown`, and a pid no
/// process can hold is still `Gone`.
///
/// Mutants: an unavailable `openat2` hides an `ESRCH`; a live pid reads as `Gone`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_makes_by_pid_reads_unknown_or_gone() {
    let id = ProcessId::current();
    for (errno, _) in REFUSALS {
        with_openat2_refused(errno, || {
            assert!(
                matches!(ProcessId::of(std::process::id()), Resolved::Unknown),
                "{errno}"
            );
            assert_eq!(id.exists(), Existence::Unknown, "{errno}");
            assert_eq!(id.is_alive(), Liveness::Unknown, "{errno}");
            assert!(matches!(ProcessId::of(NO_PROCESS_CAN_HOLD), Resolved::Gone), "{errno}");
        });
    }
}

/// An open under a refused `openat2` is `Unsupported` naming it, in the policy's message shape.
#[cfg(target_os = "linux")]
fn assert_names_openat2(result: Result<impl std::fmt::Debug, cosca::error::Error>, errno: &str) {
    match result {
        Err(e @ cosca::error::Error::Unsupported { .. }) => assert_eq!(
            e.to_string(),
            format!(
                "process open is not supported on linux: cosca requires openat2 (Linux \u{2265} 5.6), \
                 refused here: openat2 answered {errno}"
            )
        ),
        other => panic!("an open under an openat2 answering {errno} must be Unsupported, got {other:?}"),
    }
}

/// `pidfd_open` succeeds, then the fdinfo check needs the `/proc` dirfd, which needs `openat2`.
///
/// Mutant: the success path reports an unopenable `/proc` as `Unassessable`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_makes_open_unsupported_naming_openat2() {
    let id = ProcessId::current();
    for (errno, name) in REFUSALS {
        with_openat2_refused(errno, || assert_names_openat2(cosca::Process::open(id), name));
    }
}

/// A live worker thread's tid is no thread-group leader, so `pidfd_open` refuses it (`EINVAL`
/// before 6.16, `ENOENT` from 6.16) and the open decides by the `/proc` view, which needs
/// `openat2`.
///
/// Mutant: that arm reports an unopenable `/proc` as `Unassessable`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_seccomp_refused_openat2_makes_open_of_a_live_non_leader_tid_unsupported_naming_openat2() {
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        // SAFETY: SYS_gettid takes no arguments and always succeeds.
        tid_tx.send(unsafe { libc::syscall(libc::SYS_gettid) } as u32).unwrap();
        _ = stop_rx.recv();
    });
    let tid = tid_rx.recv().expect("the worker reports its tid");
    let id = ProcessId::of(tid).found().expect("the live worker's tid resolves");
    for (errno, name) in REFUSALS {
        with_openat2_refused(errno, || assert_names_openat2(cosca::Process::open(id), name));
    }
    drop(stop_tx);
    worker.join().expect("the worker ends");
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    #[cfg(target_os = "linux")]
    common::install_log_capture();
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
