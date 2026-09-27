use super::fork_running;

/// A panic between `fork_running`'s return and whatever cleanup the caller would otherwise do
/// must not leave its child unreaped: the guard's `Drop` runs during unwind and reaps it there,
/// even though nothing else on the caller's stack got a chance to.
///
/// Probed by a pidfd this test opens independently of the guard's own: once the guard's `Drop`
/// has reaped the child, querying the same process through that separate pidfd finds no child
/// left to wait for (`ECHILD`) — proof the guard did the reaping, not a coincidence of timing.
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

/// A `pidfd_open` failure right after the fork — as `RLIMIT_NOFILE` can cause — runs before any
/// `KillOnDrop` exists to protect the child. `fork_running` must still not orphan it: it kills and
/// reaps through the bare pid itself, in that one narrow window, before panicking.
///
/// Probed the same way as the sibling test above, but the probe pidfd here is the one
/// `fork_running`'s own failure path records (see `fault::record_fork_running_pidfd_failure_probe`),
/// opened before it killed the child — this test cannot open its own, since it never gets the pid
/// back (the call panics instead of returning).
#[cfg(target_os = "linux")]
#[test]
fn a_pidfd_open_failure_still_reaps_the_child() {
    use std::os::fd::AsFd;

    crate::containment::cgroup::fault::set_force_fork_running_pidfd_failure(true);
    let unwound = std::panic::catch_unwind(|| {
        // `fork_running` panics before returning here (that's the point), so its `KillOnDrop`
        // never comes into existence for this call.
        let _ = fork_running(|| {
            // SAFETY: `pause` is async-signal-safe.
            unsafe { libc::pause() };
        });
    });
    assert!(unwound.is_err(), "the forced pidfd_open failure must panic");
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
