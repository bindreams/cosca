#[cfg(unix)]
use super::ProcHandle;
use super::{std_teardown_action, StdTeardown};

// The a36b0244 fix: the `Std` teardown arm must key on the OBSERVED kill result, NOT on any
// "was elevation requested" flag. A child that gained privilege ON ITS OWN (a setuid helper, or
// `sudo` spawned with no `.elevate()`) yields kill -> EPERM with elevated=false; if the dispatch
// keyed on the flag it would take the blocking-wait branch and HANG in Drop. Encoding the rule
// as a pure function makes the "any Err -> never block" invariant unit-testable without root.

#[test]
fn kill_success_reaps_with_a_blocking_wait() {
    assert_eq!(std_teardown_action(&Ok(())), StdTeardown::ReapBlocking);
}

#[test]
fn eperm_never_blocks_even_without_an_elevated_flag() {
    // The self-privileged-child case: EPERM must route to the NON-blocking reap, never a wait().
    let eperm = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert_eq!(std_teardown_action(&Err(eperm)), StdTeardown::ReapNonBlocking);
}

#[test]
fn any_other_kill_error_also_never_blocks() {
    let other = std::io::Error::from(std::io::ErrorKind::NotFound);
    assert_eq!(std_teardown_action(&Err(other)), StdTeardown::ReapNonBlocking);
}

// A kill alone does not set `is_reaped`: a zombie still pins its number.
#[cfg(unix)]
mod own_reap {
    use std::time::{Duration, Instant};

    use super::super::ProcHandle;

    fn adopt_child(child: std::process::Child) -> crate::child::shared::SharedChild {
        let id = crate::identity::ProcessId::of(child.id()).found().expect("identity");
        crate::child::shared::SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"))
    }

    fn adopt(argv: &[&str]) -> (ProcHandle, u32) {
        let mut cmd = std::process::Command::new(argv[0]);
        cmd.args(&argv[1..]);
        let child = crate::test_spawn::spawn(&mut cmd).expect("spawn");
        let pid = child.id();
        (ProcHandle::std(adopt_child(child)), pid)
    }

    /// A running child, killed but not yet reaped.
    fn killed_zombie() -> ProcHandle {
        let (h, pid) = adopt(&["sleep", "300"]);
        assert!(!h.is_reaped());
        h.kill().expect("kill");
        crate::test_child::wait_until_zombie(pid);
        assert!(!h.is_reaped(), "a kill does not reap");
        h
    }

    /// Adoption never reaps, so an already-exited child is still a zombie afterwards, and the
    /// handle's own `wait` is the reap.
    #[test]
    fn adopting_an_already_exited_child_is_not_a_reap() {
        let mut cmd = std::process::Command::new("true");
        let child = crate::test_spawn::spawn(&mut cmd).expect("spawn");
        crate::test_child::wait_until_zombie(child.id());
        let h = ProcHandle::std(adopt_child(child));
        assert!(!h.is_reaped());
        h.wait().expect("wait");
        assert!(h.is_reaped());
    }

    /// `is_reaped` is read from the state that records the reap, so it is `true` while the waiter
    /// that made the reap is still on its way out of `wait`.
    ///
    /// Mutant: `is_reaped` read from a flag stored after `wait` returns.
    #[test]
    fn is_reaped_is_true_as_soon_as_the_reap_is_recorded() {
        use crate::child::shared::seams;
        let h = killed_zombie();
        let (gate, reached, release) = seams::park_gate();
        std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                let _armed = seams::park_after_reap_recorded_on(gate);
                h.wait().expect("wait")
            });
            reached.recv().expect("the reap was recorded");
            let seen = h.is_reaped();
            release.send(()).expect("release");
            a.join().expect("join");
            assert!(seen, "the reap was recorded, but is_reaped answered false");
        });
    }

    /// [`is_reaped_is_true_as_soon_as_the_reap_is_recorded`], for the `try_wait` reap.
    ///
    /// Mutant: `is_reaped` read from a flag stored after `try_wait` returns.
    #[test]
    fn is_reaped_is_true_as_soon_as_try_wait_records_the_reap() {
        use crate::child::shared::seams;
        let h = killed_zombie();
        let (gate, reached, release) = seams::park_gate();
        std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                let _armed = seams::park_after_reap_recorded_on(gate);
                h.try_wait().expect("try_wait")
            });
            reached.recv().expect("the reap was recorded");
            let seen = h.is_reaped();
            release.send(()).expect("release");
            assert!(a.join().expect("join").is_some());
            assert!(seen, "the reap was recorded, but is_reaped answered false");
        });
    }

    #[test]
    fn wait_is_an_own_reap() {
        let h = killed_zombie();
        h.wait().expect("wait");
        assert!(h.is_reaped());
    }

    #[test]
    fn try_wait_is_an_own_reap_only_once_it_returns_a_status() {
        let (h, pid) = adopt(&["sleep", "300"]);
        assert_eq!(h.try_wait().expect("try_wait"), None);
        assert!(!h.is_reaped());
        h.kill().expect("kill");
        crate::test_child::wait_until_zombie(pid);
        assert!(h.try_wait().expect("try_wait").is_some());
        assert!(h.is_reaped());
    }

    #[test]
    fn wait_deadline_is_an_own_reap_only_once_it_returns_a_status() {
        let (h, pid) = adopt(&["sleep", "300"]);
        assert_eq!(h.wait_deadline(Instant::now()).expect("expired"), None);
        assert!(!h.is_reaped());
        h.kill().expect("kill");
        crate::test_child::wait_until_zombie(pid);
        // The child has exited, so this returns at once; the far deadline is only a failure bound.
        assert!(h
            .wait_deadline(Instant::now() + Duration::from_secs(600))
            .expect("wait_deadline")
            .is_some());
        assert!(h.is_reaped());
    }
}

// The reap after a successful kill =====

/// A live blocker adopted as a `Std` handle. The child is ended by the teardown under test.
#[cfg(unix)]
fn std_handle() -> (ProcHandle, std::process::ChildStdin) {
    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let id = crate::identity::ProcessId::of(child.id()).found().expect("identity");
    let shared = crate::child::shared::SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    (ProcHandle::std(shared), stdin)
}

/// The levels the teardown logged for its child, with the reap after the kill failing with
/// `errno`.
#[cfg(unix)]
fn teardown_levels_when_the_reap_fails(errno: i32) -> Vec<log::Level> {
    use crate::child::shared::seams::{self, ForcedWait};
    crate::log_capture::install();
    let (handle, _stdin) = std_handle();
    let marker = format!("teardown of child {}", handle.id());
    let mark = crate::log_capture::mark();
    let forced = seams::force_unlocked_wait(ForcedWait::Errno(errno));
    handle.teardown_on_drop();
    drop(forced);
    // The forced failure left the killed child unreaped: reap it for real.
    handle.wait().expect("reap the killed child");
    crate::log_capture::records_since_on_current_thread(mark, &marker)
        .into_iter()
        .map(|(level, _)| level)
        .collect()
}

/// A reap that fails after the kill is not dropped silently.
///
/// Mutant: `_ = s.wait()`.
#[cfg(unix)]
#[test]
fn a_failed_teardown_reap_is_warned() {
    assert_eq!(teardown_levels_when_the_reap_fails(libc::EIO), [log::Level::Warn]);
}

/// `ECHILD` (someone else reaped the child) is logged, at `debug`.
///
/// Mutant: every failure at `warn`; or none logged.
#[cfg(unix)]
#[test]
fn a_teardown_reap_that_meets_echild_is_debug() {
    assert_eq!(teardown_levels_when_the_reap_fails(libc::ECHILD), [log::Level::Debug]);
}
