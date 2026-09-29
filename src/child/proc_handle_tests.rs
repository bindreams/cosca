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

// `has_reaped` is this handle's own reap, exactly: adoption, `wait`, `try_wait` and `wait_deadline`
// set it, and a kill alone (a zombie still pins its number) does not.
#[cfg(unix)]
mod own_reap {
    use std::time::{Duration, Instant};

    use shared_child::SharedChild;

    use super::super::ProcHandle;

    fn adopt(argv: &[&str]) -> (ProcHandle, u32) {
        let mut cmd = std::process::Command::new(argv[0]);
        cmd.args(&argv[1..]);
        let child = crate::test_spawn::spawn(&mut cmd).expect("spawn");
        let pid = child.id();
        (ProcHandle::std(SharedChild::new(child).expect("adopt")), pid)
    }

    /// A running child, killed but not yet reaped.
    fn killed_zombie() -> ProcHandle {
        let (h, pid) = adopt(&["sleep", "300"]);
        assert!(!h.has_reaped());
        h.kill().expect("kill");
        crate::test_child::wait_until_zombie(pid);
        assert!(!h.has_reaped(), "a kill does not reap");
        h
    }

    #[test]
    fn adopting_an_already_exited_child_is_an_own_reap() {
        let mut cmd = std::process::Command::new("true");
        let child = crate::test_spawn::spawn(&mut cmd).expect("spawn");
        crate::test_child::wait_until_zombie(child.id());
        let h = ProcHandle::std(SharedChild::new(child).expect("adopt"));
        assert!(h.has_reaped());
    }

    #[test]
    fn wait_is_an_own_reap() {
        let h = killed_zombie();
        h.wait().expect("wait");
        assert!(h.has_reaped());
    }

    #[test]
    fn try_wait_is_an_own_reap_only_once_it_returns_a_status() {
        let (h, pid) = adopt(&["sleep", "300"]);
        assert_eq!(h.try_wait().expect("try_wait"), None);
        assert!(!h.has_reaped());
        h.kill().expect("kill");
        crate::test_child::wait_until_zombie(pid);
        assert!(h.try_wait().expect("try_wait").is_some());
        assert!(h.has_reaped());
    }

    #[test]
    fn wait_deadline_is_an_own_reap_only_once_it_returns_a_status() {
        let (h, pid) = adopt(&["sleep", "300"]);
        assert_eq!(h.wait_deadline(Instant::now()).expect("expired"), None);
        assert!(!h.has_reaped());
        h.kill().expect("kill");
        crate::test_child::wait_until_zombie(pid);
        // The child has exited, so this returns at once; the far deadline is only a failure bound.
        assert!(h
            .wait_deadline(Instant::now() + Duration::from_secs(600))
            .expect("wait_deadline")
            .is_some());
        assert!(h.has_reaped());
    }
}
