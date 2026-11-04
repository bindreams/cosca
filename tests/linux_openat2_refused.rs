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
const REFUSALS: [i32; 2] = [libc::ENOSYS, libc::EPERM];

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
    for errno in REFUSALS {
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
    for errno in REFUSALS {
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
