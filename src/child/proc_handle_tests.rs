#[cfg(unix)]
use super::ProcHandle;
use super::{std_teardown_action, StdTeardown};

// The a36b0244 fix: the `Std` teardown arm must key on the OBSERVED kill result, NOT on any
// "was elevation requested" flag. A child that gained privilege ON ITS OWN (a setuid helper, or
// `sudo` spawned with no `.elevate()`) yields kill -> EPERM with elevated=false; if the dispatch
// keyed on the flag it would take the blocking-wait branch and HANG in Drop. Encoding the rule
// as a pure function makes the "any Err -> never block" invariant unit-testable without root.

#[skuld::test]
fn kill_success_reaps_with_a_blocking_wait() {
    assert_eq!(std_teardown_action(&Ok(())), StdTeardown::ReapBlocking);
}

#[skuld::test]
fn eperm_never_blocks_even_without_an_elevated_flag() {
    // The self-privileged-child case: EPERM must route to the NON-blocking reap, never a wait().
    let eperm = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert_eq!(std_teardown_action(&Err(eperm)), StdTeardown::ReapNonBlocking);
}

#[skuld::test]
fn any_other_kill_error_also_never_blocks() {
    let other = std::io::Error::from(std::io::ErrorKind::NotFound);
    assert_eq!(std_teardown_action(&Err(other)), StdTeardown::ReapNonBlocking);
}

/// Whether the handle's own answer is `Reaped`, with its peek forced to `Running`: only the reap
/// the handle recorded can say `Reaped`.
#[cfg(unix)]
fn reaped(h: &ProcHandle) -> bool {
    let _running = crate::wait::exit_only::seams::force_peek_once(Ok(crate::wait::exit_only::Peek::Running));
    matches!(h.state(), crate::signal::RootState::Reaped)
}

// A kill alone is not a reap: a zombie still pins its number.
#[cfg(unix)]
mod own_reap {
    use std::time::{Duration, Instant};

    use super::super::ProcHandle;
    use super::reaped;

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
        assert!(!reaped(&h));
        h.kill().expect("kill");
        crate::test_child::wait_until_zombie(pid);
        assert!(!reaped(&h), "a kill does not reap");
        h
    }

    /// Adoption never reaps, so an already-exited child is still a zombie afterwards, and the
    /// handle's own `wait` is the reap.
    #[skuld::test]
    fn adopting_an_already_exited_child_is_not_a_reap() {
        let mut cmd = std::process::Command::new("true");
        let child = crate::test_spawn::spawn(&mut cmd).expect("spawn");
        crate::test_child::wait_until_zombie(child.id());
        let h = ProcHandle::std(adopt_child(child));
        assert!(!reaped(&h));
        h.wait().expect("wait");
        assert!(reaped(&h));
    }

    /// The state is `Reaped` once the reap is recorded, before `try_wait` returns.
    ///
    /// Mutant: `state` answers `Unreaped` once the reap is recorded.
    #[skuld::test]
    fn the_state_is_reaped_as_soon_as_try_wait_records_the_reap() {
        use crate::child::shared::seams;
        let h = killed_zombie();
        let (gate, reached, release) = seams::park_gate();
        std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                let _armed = seams::park_after_reap_recorded_on(gate);
                h.try_wait().expect("try_wait")
            });
            reached.recv().expect("the reap was recorded");
            let seen = reaped(&h);
            release.send(()).expect("release");
            assert!(a.join().expect("join").is_some());
            assert!(seen, "the reap was recorded, but the state was not Reaped");
        });
    }

    #[skuld::test]
    fn wait_is_an_own_reap() {
        let h = killed_zombie();
        h.wait().expect("wait");
        assert!(reaped(&h));
    }

    #[skuld::test]
    fn try_wait_is_an_own_reap_only_once_it_returns_a_status() {
        let (h, pid) = adopt(&["sleep", "300"]);
        assert_eq!(h.try_wait().expect("try_wait"), None);
        assert!(!reaped(&h));
        h.kill().expect("kill");
        crate::test_child::wait_until_zombie(pid);
        assert!(h.try_wait().expect("try_wait").is_some());
        assert!(reaped(&h));
    }

    #[skuld::test]
    fn wait_deadline_is_an_own_reap_only_once_it_returns_a_status() {
        let (h, pid) = adopt(&["sleep", "300"]);
        assert_eq!(h.wait_deadline(Instant::now()).expect("expired"), None);
        assert!(!reaped(&h));
        h.kill().expect("kill");
        crate::test_child::wait_until_zombie(pid);
        // The child has exited, so this returns at once; the far deadline is only a failure bound.
        assert!(h
            .wait_deadline(Instant::now() + Duration::from_secs(600))
            .expect("wait_deadline")
            .is_some());
        assert!(reaped(&h));
    }
}

// The reap is visible before the waiter returns =====

/// The state is `Reaped` once the reap is recorded, before `wait` returns.
///
/// Mutant: `state` answers `Unreaped` once the reap is recorded.
#[cfg(unix)]
#[skuld::test]
fn the_state_is_reaped_as_soon_as_the_reap_is_recorded() {
    use crate::child::shared::seams;
    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let id = crate::identity::ProcessId::of(child.id()).found().expect("identity");
    let shared = crate::child::shared::SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let h = ProcHandle::std(shared);
    assert!(!reaped(&h));
    let (gate, reached, release) = seams::park_gate();
    std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            let _armed = seams::park_after_reap_recorded_on(gate);
            h.wait().expect("wait")
        });
        // The blocker exits cleanly once its stdin closes; `wait` is blocked on that real exit.
        drop(stdin);
        reached.recv().expect("the reap was recorded");
        let seen = reaped(&h);
        release.send(()).expect("release");
        a.join().expect("join");
        assert!(seen, "the reap was recorded, but the state was not Reaped");
    });
}

/// The state is `Reaped` once the reap is recorded, before `wait_deadline` returns. The far deadline
/// is only a failure bound; the wait ends on the child's real exit.
///
/// Mutant: `state` answers `Unreaped` once the reap is recorded.
#[cfg(unix)]
#[skuld::test]
fn the_state_is_reaped_as_soon_as_wait_deadline_records_the_reap() {
    use crate::child::shared::seams;
    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let id = crate::identity::ProcessId::of(child.id()).found().expect("identity");
    let shared = crate::child::shared::SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let h = ProcHandle::std(shared);
    assert!(!reaped(&h));
    let (gate, reached, release) = seams::park_gate();
    std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            let _armed = seams::park_after_reap_recorded_on(gate);
            h.wait_deadline(std::time::Instant::now() + std::time::Duration::from_secs(600))
                .expect("wait_deadline")
        });
        // The blocker exits cleanly once its stdin closes; `wait` is blocked on that real exit.
        drop(stdin);
        reached.recv().expect("the reap was recorded");
        let seen = reaped(&h);
        release.send(()).expect("release");
        a.join().expect("join");
        assert!(seen, "the reap was recorded, but the state was not Reaped");
    });
}

/// A waiter parked in the unlocked wait is a holder (`W`), not a reap.
///
/// Mutant: `state` answers `Reaped` for a state that is not `E`.
#[cfg(unix)]
#[skuld::test]
fn the_state_is_unreaped_while_a_holder_waits() {
    use crate::child::shared::seams;
    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let id = crate::identity::ProcessId::of(child.id()).found().expect("identity");
    let shared = crate::child::shared::SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let h = ProcHandle::std(shared);
    let (gate, reached, release) = seams::park_gate();
    std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            let _armed = seams::park_in_unlocked_wait(gate);
            h.wait().expect("wait")
        });
        reached.recv().expect("the holder reached its unlocked wait");
        let seen = reaped(&h);
        // The blocker exits cleanly once its stdin closes; the holder's wait ends on that exit.
        drop(stdin);
        release.send(()).expect("release");
        a.join().expect("join");
        assert!(!seen, "a holder is waiting, but the state read Reaped");
        assert!(reaped(&h));
    });
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

/// What the teardown returned and the levels it logged for its child, with the reap after the kill
/// failing with `errno`.
#[cfg(unix)]
fn teardown_when_the_reap_fails(errno: i32) -> (Option<String>, Vec<log::Level>) {
    use crate::child::shared::seams::{self, ForcedWait};
    crate::log_capture::install();
    let (handle, _stdin) = std_handle();
    let marker = format!("teardown of child {}", handle.id());
    let mark = crate::log_capture::mark();
    let forced = seams::force_unlocked_wait(ForcedWait::Errno(errno));
    let left = handle.teardown_on_drop();
    drop(forced);
    // The forced failure left the killed child unreaped: reap it for real.
    handle.wait().expect("reap the killed child");
    let levels = crate::log_capture::records_since_on_current_thread(mark, &marker)
        .into_iter()
        .map(|(level, _)| level)
        .collect();
    (left, levels)
}

/// A reap that fails after the kill is not dropped silently: it is returned for the caller's one
/// warn, and logged by nobody here.
///
/// Mutants: `_ = s.wait()`; the teardown warns on its own.
#[cfg(unix)]
#[skuld::test]
fn a_failed_teardown_reap_is_returned_and_not_logged() {
    let (left, levels) = teardown_when_the_reap_fails(libc::EIO);
    assert!(
        left.as_deref().is_some_and(|text| text.contains("the reap after the kill failed")),
        "{left:?}"
    );
    assert_eq!(levels, Vec::<log::Level>::new());
}

/// `ECHILD` (someone else reaped the child) is logged at `debug` and returns nothing.
///
/// Mutant: every failure is returned; or none logged.
#[cfg(unix)]
#[skuld::test]
fn a_teardown_reap_that_meets_echild_is_debug() {
    assert_eq!(
        teardown_when_the_reap_fails(libc::ECHILD),
        (None, vec![log::Level::Debug])
    );
}
