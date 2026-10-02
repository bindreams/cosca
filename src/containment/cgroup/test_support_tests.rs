use super::{fork_running, reap, reap_status};

/// A panic after `fork_running` must not leave the child unreaped: the guard's `Drop` reaps it
/// during unwind. Checked via an independent pidfd, which reports `ECHILD` once the child is
/// reaped. If the kill regresses, this hangs (bounded by `nextest.toml`).
#[cfg(target_os = "linux")]
#[test]
fn a_panic_after_fork_running_still_reaps_the_child() {
    use std::cell::RefCell;
    use std::os::fd::AsFd;

    let probe: RefCell<Option<std::os::fd::OwnedFd>> = RefCell::new(None);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let guard = fork_running(|| {
            // SAFETY: `pause` is async-signal-safe.
            unsafe { libc::pause() };
        });
        let child = rustix::process::Pid::from_raw(guard.pid() as i32).expect("a positive pid");
        *probe.borrow_mut() =
            Some(rustix::process::pidfd_open(child, rustix::process::PidfdFlags::empty()).expect("open a probe pidfd"));
        panic!("forced panic between the fork and any cleanup the caller would otherwise do");
    }));
    assert!(unwound.is_err(), "the forced panic must actually unwind");

    let probe = probe.into_inner().expect("the probe pidfd was opened before the panic");
    assert_eq!(
        rustix::process::waitid(
            rustix::process::WaitId::PidFd(probe.as_fd()),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
        )
        .unwrap_err(),
        rustix::io::Errno::CHILD,
        "the guard must have reaped the child during unwind"
    );
}

/// Dropping a guard normally (no panic) must reap the child too — the non-unwinding half of the
/// sibling test above. Checked the same way: an independent probe pidfd reports `ECHILD`.
#[cfg(target_os = "linux")]
#[test]
fn drop_without_a_panic_reaps_the_child() {
    use std::os::fd::AsFd;

    let guard = fork_running(|| {
        // SAFETY: `pause` is async-signal-safe.
        unsafe { libc::pause() };
    });
    let child = rustix::process::Pid::from_raw(guard.pid() as i32).expect("a positive pid");
    let probe = rustix::process::pidfd_open(child, rustix::process::PidfdFlags::empty()).expect("open a probe pidfd");

    drop(guard);

    assert_eq!(
        rustix::process::waitid(
            rustix::process::WaitId::PidFd(probe.as_fd()),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
        )
        .unwrap_err(),
        rustix::io::Errno::CHILD,
        "a normal drop must have reaped the child"
    );
}

/// `Drop`'s `waitid` retries on `EINTR` rather than treating it as the reap's real result. Forced
/// deterministically through a fault seam: a real signal landing mid-syscall would make this test
/// itself racy, exactly what this suite avoids elsewhere.
#[cfg(target_os = "linux")]
#[test]
fn drop_retries_waitid_on_eintr() {
    use std::os::fd::AsFd;

    let guard = fork_running(|| {
        // SAFETY: `pause` is async-signal-safe.
        unsafe { libc::pause() };
    });
    let child = rustix::process::Pid::from_raw(guard.pid() as i32).expect("a positive pid");
    let probe = rustix::process::pidfd_open(child, rustix::process::PidfdFlags::empty()).expect("open a probe pidfd");

    crate::containment::cgroup::fault::set_force_kill_on_drop_waitid_eintr(true);
    drop(guard);
    assert!(
        !crate::containment::cgroup::fault::take_force_kill_on_drop_waitid_eintr(),
        "the fault must be consumed by the retry loop"
    );

    assert_eq!(
        rustix::process::waitid(
            rustix::process::WaitId::PidFd(probe.as_fd()),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
        )
        .unwrap_err(),
        rustix::io::Errno::CHILD,
        "the child must still be reaped despite the injected EINTR"
    );
}

/// A failed `pidfd_send_signal` must not block on a `waitid` for a child the kill may never have
/// reached — checked by confirming the child is left alive and unreaped, not by timing.
#[cfg(target_os = "linux")]
#[test]
fn drop_reports_a_kill_failure_without_blocking() {
    use std::os::fd::AsFd;

    let guard = fork_running(|| {
        // SAFETY: `pause` is async-signal-safe.
        unsafe { libc::pause() };
    });
    let child_pid = guard.pid();
    let child = rustix::process::Pid::from_raw(child_pid as i32).expect("a positive pid");
    let probe = rustix::process::pidfd_open(child, rustix::process::PidfdFlags::empty()).expect("open a probe pidfd");

    crate::containment::cgroup::fault::set_force_kill_on_drop_kill_failure(true);
    // Not already unwinding, so the failure's contract (`debug_assert!`) fires — but only where
    // debug_assertions are compiled in: CI's release lane runs this same test with them off,
    // where the calm (non-panicking, still-reported) arm is the one under test instead.
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(guard)));
    assert_eq!(
        unwound.is_err(),
        cfg!(debug_assertions),
        "a failed kill should panic on its asserted contract only with debug_assertions on"
    );
    assert!(
        !crate::containment::cgroup::fault::take_force_kill_on_drop_kill_failure(),
        "the fault must be consumed by the failed kill"
    );

    // The forced failure means no real SIGKILL was ever sent: the child is still alive and
    // unreaped, and this must be true immediately, not eventually — Drop returned without
    // blocking on it.
    match rustix::process::waitid(
        rustix::process::WaitId::PidFd(probe.as_fd()),
        rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
    ) {
        Ok(None) => {}
        other => panic!("a forced kill failure must leave the child alive and unreaped, got {other:?}"),
    }

    // SAFETY: `child_pid` is this process's own child, still alive and unreaped.
    unsafe { libc::kill(child_pid as i32, libc::SIGKILL) };
    reap(child_pid);
}

/// A `pidfd_open` failure (e.g. `RLIMIT_NOFILE`) happens before any guard exists; `fork_running`
/// must still kill and reap the child before panicking. Probed via the failure path's recorded
/// pidfd, since the pid is never returned.
#[cfg(target_os = "linux")]
#[test]
fn a_pidfd_open_failure_still_reaps_the_child() {
    use std::os::fd::AsFd;

    crate::containment::cgroup::fault::set_force_fork_running_pidfd_failure(true);
    let unwound = std::panic::catch_unwind(|| {
        _ = fork_running(|| {
            // SAFETY: `pause` is async-signal-safe.
            unsafe { libc::pause() };
        });
    });
    let payload = unwound.expect_err("the forced pidfd_open failure must panic");
    let message = payload
        .downcast_ref::<String>()
        .expect("panic! with format args produces a String payload");
    assert!(
        message.contains("pidfd_open its own just-forked child"),
        "the panic must name the failure it's about, got {message:?}"
    );
    assert!(
        !crate::containment::cgroup::fault::take_force_fork_running_pidfd_failure(),
        "the fault must be consumed exactly once"
    );

    let probe = crate::containment::cgroup::fault::take_fork_running_pidfd_failure_probe()
        .expect("the failure path recorded a probe pidfd before killing the child");
    assert_eq!(
        rustix::process::waitid(
            rustix::process::WaitId::PidFd(probe.as_fd()),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
        )
        .unwrap_err(),
        rustix::io::Errno::CHILD,
        "the pidfd_open failure path must have reaped the child before panicking"
    );
}

/// The probe `pidfd_open` inside the failure path above can itself fail (the same exhaustion that
/// failed the main one). That must not skip the kill/reap: the panic still names the original
/// failure, with no "cleanup also failed" suffix, and nothing is recorded for a later test to read.
#[cfg(target_os = "linux")]
#[test]
fn a_probe_pidfd_open_failure_does_not_skip_the_cleanup() {
    crate::containment::cgroup::fault::set_force_fork_running_pidfd_failure(true);
    crate::containment::cgroup::fault::set_force_fork_running_probe_pidfd_failure(true);
    let unwound = std::panic::catch_unwind(|| {
        _ = fork_running(|| {
            // SAFETY: `pause` is async-signal-safe.
            unsafe { libc::pause() };
        });
    });
    let payload = unwound.expect_err("the forced pidfd_open failure must still panic");
    let message = payload
        .downcast_ref::<String>()
        .expect("panic! with format args produces a String payload");
    assert!(
        message.contains("pidfd_open its own just-forked child") && !message.contains("cleanup also failed"),
        "the kill/reap must still succeed even though the probe itself failed, got {message:?}"
    );
    assert!(
        !crate::containment::cgroup::fault::take_force_fork_running_pidfd_failure(),
        "the fault must be consumed exactly once"
    );
    assert!(
        !crate::containment::cgroup::fault::take_force_fork_running_probe_pidfd_failure(),
        "the probe fault must be consumed exactly once"
    );
    assert!(
        crate::containment::cgroup::fault::take_fork_running_pidfd_failure_probe().is_none(),
        "a failed probe must not have recorded anything"
    );
}

/// A defused guard's `Drop` must neither kill nor reap: the caller took that over by taking the
/// pid back.
///
/// Detected by an event, not a snapshot: `kill`/`pidfd_send_signal` only queues `SIGKILL` — the
/// child becomes a zombie whenever the scheduler next runs it, not synchronously — so polling
/// `waitid` `NOHANG` right after `defuse()` could see a not-yet-scheduled kill as `Ok(None)` and
/// pass regardless of whether the kill fired. Instead: the child blocks on a gate, then writes one
/// byte to an ack pipe (`_exit`ing if that write fails). After `defuse()`, the parent closes its
/// own copy of the ack pipe's write end, releases the gate, and blocks reading the ack: a byte
/// proves the child was never killed (only it could have written it); EOF proves it was (nothing
/// is left to write). Cleanup runs through an independent probe pidfd *before* that assertion, so
/// a failure here can't leak the child regardless of which outcome triggered it.
#[cfg(target_os = "linux")]
#[test]
fn defuse_disarms_the_guard() {
    use std::io::Write;
    use std::os::fd::{AsFd, AsRawFd};

    let (gate_read, mut gate_write) = std::io::pipe().expect("open the gate");
    let gate = gate_read.as_raw_fd();
    let (ack_read, ack_write) = std::io::pipe().expect("open the ack pipe");
    let ack_write_fd = ack_write.as_raw_fd();
    let guard = fork_running(move || {
        super::block_on(gate);
        // SAFETY (in the child): `write`, `_exit` and `pause` are async-signal-safe.
        unsafe {
            if libc::write(ack_write_fd, b"a".as_ptr().cast(), 1) != 1 {
                libc::_exit(1);
            }
            libc::pause();
        }
    });
    let child = rustix::process::Pid::from_raw(guard.pid() as i32).expect("a positive pid");
    let probe = rustix::process::pidfd_open(child, rustix::process::PidfdFlags::empty()).expect("open a probe pidfd");

    _ = guard.defuse();
    drop(ack_write); // our own copy: only the child's, if it's alive, keeps the pipe open

    gate_write.write_all(b"g").expect("release the child");
    let mut byte = 0u8;
    // SAFETY: `ack_read`'s fd is an open read end; `byte` is a valid one-byte buffer.
    let n = unsafe { libc::read(ack_read.as_raw_fd(), (&raw mut byte).cast(), 1) };

    // Through the probe pidfd, before the assertion below: harmless if the child is already
    // dead (the very regression this test would then be about to report).
    _ = rustix::process::pidfd_send_signal(probe.as_fd(), rustix::process::Signal::KILL);
    _ = rustix::process::waitid(
        rustix::process::WaitId::PidFd(probe.as_fd()),
        rustix::process::WaitIdOptions::EXITED,
    );

    assert_eq!(
        n, 1,
        "a defused guard must not have killed the child before it could ack"
    );
}

/// What the forked child of a `fork_running` lock probe reports, from its pipe.
#[cfg(target_os = "linux")]
fn read_report_byte(pipe: &mut impl std::io::Read) -> Option<u8> {
    let mut byte = 0u8;
    loop {
        match pipe.read(std::slice::from_mut(&mut byte)) {
            Ok(1) => return Some(byte),
            Ok(_) => return None,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // Nothing written, though the write ends are closed or the child is reaped: never a hang.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
            Err(e) => panic!("read failed unexpectedly: {e}"),
        }
    }
}

/// A `read` interrupted by a signal is retried, not reported as a failure.
#[cfg(target_os = "linux")]
#[test]
fn read_report_byte_retries_an_interrupted_read() {
    struct InterruptedOnce(bool);
    impl std::io::Read for InterruptedOnce {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !std::mem::replace(&mut self.0, true) {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            buf[0] = 1;
            Ok(1)
        }
    }
    assert_eq!(read_report_byte(&mut InterruptedOnce(false)), Some(1));
}

/// Wait status as text, for assertion messages.
#[cfg(target_os = "linux")]
fn describe_status(status: i32) -> String {
    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        if code == super::REPORT_WRITE_FAILED_EXIT {
            format!("exit {code} (REPORT_WRITE_FAILED_EXIT: the child's report write failed)")
        } else {
            format!("exit {code}")
        }
    } else {
        format!("raw wait status {status:#x}")
    }
}

#[cfg(target_os = "linux")]
fn set_nonblocking(fd: std::os::fd::RawFd) {
    // SAFETY: `fd` is the caller's open descriptor, which outlives this function.
    let fd = unsafe { rustix::fd::BorrowedFd::borrow_raw(fd) };
    let flags = rustix::fs::fcntl_getfl(fd).unwrap_or_else(|e| panic!("fcntl F_GETFL failed: {e}"));
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)
        .unwrap_or_else(|e| panic!("fcntl F_SETFL O_NONBLOCK failed: {e}"));
}

/// `fork_running` must hold `spawn_lock()` across its `fork()`, otherwise a concurrent cosca spawn
/// elsewhere in this test binary can inherit an fd that exists only inside that spawn's own
/// `spawn_lock` section.
///
/// Two checks:
///
/// - The child reports, over a pipe, its inherited copy of the thread-local flag
///   `spawn_lock_held_by_this_thread` reads on the forking thread. A parent-side check after the
///   fork returns can't tell "held across the fork" from "dropped before it, re-acquired after".
/// - The post-fork hook, on the forking thread, reports the same flag; it catches a lock released
///   right after the fork, before `pidfd_open` and the hook. The test thread asserts it, so a
///   failure names its cause instead of panicking on the fork thread.
///
/// The read end is `O_NONBLOCK` and the child is reaped before the read: once reaped, its byte is
/// in the pipe or never will be, and a missing byte answers `WouldBlock` instead of hanging.
#[cfg(target_os = "linux")]
#[test]
fn fork_running_holds_spawn_lock_across_the_fork() {
    use std::os::fd::AsRawFd;
    use std::sync::mpsc;

    let (mut report_read, report_write) = std::io::pipe().expect("open the report pipe");
    set_nonblocking(report_read.as_raw_fd());
    let report_write_fd = report_write.as_raw_fd();

    let (tx_hook, rx_hook) = mpsc::channel::<bool>();
    let fork_thread = std::thread::spawn(move || {
        // Set on THIS thread: the seams are thread-locals and `fork_running` runs here.
        let _report_guard = crate::containment::cgroup::fault::set_fork_running_lock_held_report_fd(report_write_fd);
        let _hook_guard = crate::containment::cgroup::fault::set_after_fork_still_locked(move || {
            _ = tx_hook.send(crate::child::spawn::spawn_lock_held_by_this_thread());
        });
        // The child reports, runs this empty body, and `_exit`s on its own; the test waits for
        // that exit instead of killing it, which could land before the report.
        fork_running(|| {})
    });

    let guard = match fork_thread.join() {
        Ok(guard) => guard,
        Err(payload) => std::panic::resume_unwind(payload),
    };
    // Reaped first: once reaped, the child's byte is in the pipe or never will be.
    let status = reap_status(guard.defuse());
    drop(report_write);

    let hook_saw_held = rx_hook.recv().expect("the post-fork hook must have run");
    assert!(
        hook_saw_held,
        "spawn_lock must still be held when the post-fork hook runs"
    );
    assert_eq!(
        read_report_byte(&mut report_read),
        Some(1),
        "the child must report that spawn_lock was held, from the forking thread's own point of \
         view, at the exact instant of the fork (child ended: {})",
        describe_status(status)
    );
}

/// A failed report `write` in the child is not swallowed: the child exits with
/// `REPORT_WRITE_FAILED_EXIT`, which the reaped status shows.
#[cfg(target_os = "linux")]
#[test]
fn fork_running_child_exits_with_a_dedicated_code_when_its_report_write_fails() {
    use std::os::fd::AsRawFd;

    // Writing to a pipe's read end fails with EBADF.
    let (report_read, _report_write) = std::io::pipe().expect("open the report pipe");
    let _report_guard =
        crate::containment::cgroup::fault::set_fork_running_lock_held_report_fd(report_read.as_raw_fd());

    let guard = fork_running(|| {});
    let status = reap_status(guard.defuse());

    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == super::REPORT_WRITE_FAILED_EXIT,
        "a child whose report write failed must exit with REPORT_WRITE_FAILED_EXIT, got {}",
        describe_status(status)
    );
}

/// What a `fork_running` blocked behind a held `spawn_lock` reports, in order.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum LockProbe {
    /// `fork_running` found the lock held and is about to block on it.
    Contended,
    /// `fork_running` has forked; whether the holder had released the lock by then.
    Forked { holder_released: bool },
}

/// `fork_running` waits for a `spawn_lock` held by another thread: it sees the lock contended
/// before it forks, and does not fork until the holder has released it.
///
/// The holder takes the real [`spawn_lock`](crate::child::spawn::spawn_lock). The forking thread
/// reports `Contended` when its acquisition finds the lock held, and `Forked` from the post-fork
/// hook. The test thread releases the holder only after `Contended`, so the first report proves
/// the fork did not run ahead, and the holder's release flag is set before its unlock, so a fork
/// that waited for the lock always sees it.
#[cfg(target_os = "linux")]
#[test]
fn fork_running_waits_for_a_held_spawn_lock() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};

    let released = Arc::new(AtomicBool::new(false));
    let (tx_held, rx_held) = mpsc::channel::<()>();
    let (tx_release, rx_release) = mpsc::channel::<()>();
    let holder = {
        let released = Arc::clone(&released);
        std::thread::spawn(move || {
            let lock = crate::child::spawn::spawn_lock();
            tx_held.send(()).expect("the test thread is waiting for the holder");
            _ = rx_release.recv();
            released.store(true, Ordering::SeqCst);
            drop(lock);
        })
    };
    rx_held.recv().expect("the holder must take the lock");

    let (tx_probe, rx_probe) = mpsc::channel::<LockProbe>();
    let fork_thread = {
        let released = Arc::clone(&released);
        let tx_contended = tx_probe.clone();
        std::thread::spawn(move || {
            let _contended_guard = crate::containment::cgroup::fault::set_fork_running_lock_contended(move || {
                _ = tx_contended.send(LockProbe::Contended);
            });
            let _hook_guard = crate::containment::cgroup::fault::set_after_fork_still_locked(move || {
                _ = tx_probe.send(LockProbe::Forked {
                    holder_released: released.load(Ordering::SeqCst),
                });
            });
            fork_running(|| {})
        })
    };

    // Whichever report comes first decides: a fork that ran ahead of the held lock reports
    // `Forked` first, and would never report `Contended` at all.
    let first = rx_probe.recv();
    tx_release.send(()).expect("the holder is waiting to be released");
    holder.join().expect("the holder must not panic");
    let guard = match fork_thread.join() {
        Ok(guard) => guard,
        Err(payload) => std::panic::resume_unwind(payload),
    };
    reap(guard.defuse());

    assert_eq!(
        first,
        Ok(LockProbe::Contended),
        "fork_running must find spawn_lock held and wait, not fork first"
    );
    assert_eq!(
        rx_probe.recv(),
        Ok(LockProbe::Forked { holder_released: true }),
        "fork_running must not fork before the holder released spawn_lock"
    );
}

/// The `pidfd_open`-failure path releases `spawn_lock` before it kills and reaps the child, not
/// at scope exit or unwind. Observed from the cleanup hook, which runs on the forking thread.
#[cfg(target_os = "linux")]
#[test]
fn a_pidfd_open_failure_releases_spawn_lock_before_cleanup() {
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel::<bool>();
    let fork_thread = std::thread::spawn(move || {
        crate::containment::cgroup::fault::set_force_fork_running_pidfd_failure(true);
        let _cleanup_guard = crate::containment::cgroup::fault::set_fork_running_cleanup(move || {
            _ = tx.send(crate::child::spawn::spawn_lock_held_by_this_thread());
        });
        _ = fork_running(|| {
            // SAFETY: `pause` is async-signal-safe.
            unsafe { libc::pause() };
        });
    });
    let unwound = fork_thread.join();
    assert!(unwound.is_err(), "the forced pidfd_open failure must panic");

    let held_during_cleanup = rx.recv().expect("the cleanup hook must have run");
    assert!(
        !held_during_cleanup,
        "spawn_lock must be released before the failure path's kill and reap"
    );
}

/// `fork_running` takes `spawn_lock` itself, and the mutex is not reentrant: a caller that already
/// holds it must get a named panic, not a hang.
#[cfg(target_os = "linux")]
#[test]
fn fork_running_under_an_outer_spawn_lock_panics_naming_the_reentry() {
    let outer = crate::child::spawn::spawn_lock();
    let unwound = std::panic::catch_unwind(|| {
        _ = fork_running(|| {});
    });
    drop(outer);
    let payload = unwound.expect_err("fork_running must refuse to run under an outer spawn_lock");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("<non-string panic payload>");
    assert!(
        message.contains("spawn_lock re-entered"),
        "the panic must name the re-entry, got: {message}"
    );
}
