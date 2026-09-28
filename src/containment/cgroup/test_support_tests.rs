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

/// A `pidfd_open` failure (e.g. `RLIMIT_NOFILE`) happens before any guard exists; `fork_running`
/// must still kill and reap the child before panicking. Probed via the pidfd its failure path
/// records (see `fault::record_fork_running_pidfd_failure_probe`), since the pid is never
/// returned. Hang-if-regressed as above.
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

/// A defused guard's `Drop` must neither kill nor reap: the caller took that over by taking the
/// pid back. Checked via an independent pidfd — `waitid` `NOHANG` on a still-running child returns
/// `Ok(None)`, which a live kill or reap would instead turn into a real exit status or `ECHILD`.
#[cfg(target_os = "linux")]
#[test]
fn defuse_disarms_the_guard() {
    use std::os::fd::AsFd;

    let guard = fork_running(|| {
        // SAFETY: `pause` is async-signal-safe.
        unsafe { libc::pause() };
    });
    let child = rustix::process::Pid::from_raw(guard.pid() as i32).expect("a positive pid");
    let probe = rustix::process::pidfd_open(child, rustix::process::PidfdFlags::empty()).expect("open a probe pidfd");

    let pid = guard.defuse();
    match rustix::process::waitid(
        rustix::process::WaitId::PidFd(probe.as_fd()),
        rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
    ) {
        Ok(None) => {}
        other => panic!("a defused guard must not have killed or reaped the child, got {other:?}"),
    }

    // SAFETY: `pid` is this process's own child, still alive and unreaped.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    reap(pid);
}
