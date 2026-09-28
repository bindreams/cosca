use super::{fork_running, reap};

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
        let _ = fork_running(|| {
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
        let _ = fork_running(|| {
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

    let _ = guard.defuse();
    drop(ack_write); // our own copy: only the child's, if it's alive, keeps the pipe open

    gate_write.write_all(b"g").expect("release the child");
    let mut byte = 0u8;
    // SAFETY: `ack_read`'s fd is an open read end; `byte` is a valid one-byte buffer.
    let n = unsafe { libc::read(ack_read.as_raw_fd(), (&raw mut byte).cast(), 1) };

    // Through the probe pidfd, before the assertion below: harmless if the child is already
    // dead (the very regression this test would then be about to report).
    let _ = rustix::process::pidfd_send_signal(probe.as_fd(), rustix::process::Signal::KILL);
    let _ = rustix::process::waitid(
        rustix::process::WaitId::PidFd(probe.as_fd()),
        rustix::process::WaitIdOptions::EXITED,
    );

    assert_eq!(
        n, 1,
        "a defused guard must not have killed the child before it could ack"
    );
}

/// `fork_running` must hold `spawn_lock()` across its `fork()`, not just release it before —
/// otherwise a concurrent cosca spawn elsewhere in this test binary can inherit an fd that
/// exists only inside that spawn's own `spawn_lock` section (`#200`'s finding).
///
/// Proved through a seam, observed AFTER the fork, not before it: the hook fires on
/// `fork_running`'s own thread right after its `fork()` returns in the parent, still holding
/// `spawn_lock`, and blocks there until this test releases it. Two independent, deterministic
/// checks while it is blocked, neither timing-dependent:
/// - the hook is handed the child's real pid, which only exists once `fork()` has actually
///   returned — this test confirms it independently of the hook's own honesty, via `kill(pid, 0)`
///   asking the kernel directly whether that pid is a live process right now;
/// - a `#[cfg(test)]` non-blocking `try_spawn_lock_for_test` on the very same mutex either
///   refuses immediately (`WouldBlock`, the lock is genuinely held) or succeeds (it is not) — a
///   real `Mutex::try_lock` never spins or blocks waiting to find out.
///
/// Together they rule out both a seam that fires before the fork (no real pid to hand it) and a
/// `fork_running` that never takes the lock at all (`try_lock` would simply succeed).
#[cfg(target_os = "linux")]
#[test]
fn fork_running_holds_spawn_lock_across_the_fork() {
    use std::sync::mpsc;

    let (tx_started, rx_started) = mpsc::channel::<u32>();
    let (tx_release, rx_release) = mpsc::channel::<()>();

    let fork_thread = std::thread::spawn(move || {
        crate::containment::cgroup::fault::set_between_spawn_lock_and_fork(move |child_pid| {
            tx_started
                .send(child_pid)
                .expect("the test thread is still waiting to receive");
            rx_release
                .recv()
                .expect("the test thread still holds the release sender");
        });
        fork_running(|| {
            // SAFETY: `pause` is async-signal-safe.
            unsafe { libc::pause() };
        })
    });

    // Blocks until fork_running's hook is running — not a fixed duration.
    let child_pid = rx_started
        .recv()
        .expect("fork_thread must reach the hook before this returns");

    // The hook can only be called with a real pid from the PARENT arm, after `fork()` has
    // already returned — a hook moved to before the `fork()` this lock is meant to cover has no
    // pid to pass. Confirmed independently of the hook's own honesty: `kill(pid, 0)` asks the
    // kernel directly whether a process at that pid exists right now, sending nothing.
    // SAFETY: signal 0 sends nothing; it only queries existence/permission.
    assert_eq!(
        unsafe { libc::kill(child_pid as i32, 0) },
        0,
        "the child must already exist by the time the hook runs, proving fork() already happened: {}",
        std::io::Error::last_os_error()
    );

    assert!(
        matches!(
            crate::child::spawn::try_spawn_lock_for_test(),
            Err(std::sync::TryLockError::WouldBlock)
        ),
        "spawn_lock must still be held on fork_running's own thread, after its fork, while the \
         hook is blocked"
    );

    tx_release
        .send(())
        .expect("fork_thread's hook is still waiting to receive");

    // Not re-checked as free afterward: `spawn_lock` is process-global, shared with every other
    // test in this binary that may spawn concurrently, so its state right after this thread's
    // own release is not this test's to assert on.
    let guard = fork_thread.join().expect("fork_thread must not panic");
    drop(guard);
}
