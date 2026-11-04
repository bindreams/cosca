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

// The reap after a successful kill =====

/// A `Std` handle over a `FakeProcess` that answers a delivered kill and then `reaps`, with a
/// pid no process need have.
#[cfg(unix)]
fn std_handle(
    reaps: impl IntoIterator<Item = crate::os_process::fake::ReapAnswer>,
) -> (super::ProcHandle, crate::os_process::fake::FakeProcess) {
    let fake = crate::os_process::fake::FakeProcess::new([])
        .reaps(reaps)
        .signals([Ok(crate::signal::Sent::Delivered)]);
    let owned = crate::child::owned::OwnedChild::new(Box::new(fake.clone()));
    (super::ProcHandle::std(owned, 4242), fake)
}

/// What the teardown returned and the levels it logged for its child, with the reap after the kill
/// answering `reap`.
#[cfg(unix)]
fn teardown_when_the_reap_answers(reap: crate::os_process::fake::ReapAnswer) -> (Option<String>, Vec<log::Level>) {
    crate::log_capture::install();
    let (handle, _fake) = std_handle([reap]);
    let marker = format!("teardown of child {}", handle.id());
    let mark = crate::log_capture::mark();
    let left = handle.teardown_on_drop(crate::identity::ProcessId::current()).left;
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
    let (left, levels) =
        teardown_when_the_reap_answers(crate::os_process::fake::ReapAnswer::Err(std::io::ErrorKind::Other));
    assert!(
        left.as_deref()
            .is_some_and(|text| text.contains("the reap after the kill failed")),
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
        teardown_when_the_reap_answers(crate::os_process::fake::ReapAnswer::Foreign(
            crate::os_process::child::Foreign::Gone
        )),
        (None, vec![log::Level::Debug])
    );
}

/// A reap after a tree kill that was delivered meets `ECHILD`: someone else collected the exit after
/// the kill, which is `Killed`, never `Gone` (the fate of a child cosca delivered nothing to).
///
/// Mutant: the `ECHILD` arm answers `Gone`.
#[cfg(unix)]
#[skuld::test]
fn a_reap_after_a_delivered_tree_kill_that_meets_echild_is_killed() {
    let (handle, _fake) = std_handle([crate::os_process::fake::ReapAnswer::Foreign(
        crate::os_process::child::Foreign::Gone,
    )]);
    let torn = handle.reap_after_tree_kill();
    assert_eq!(torn.fate, crate::error::ChildFate::Killed);
}

/// A kill that delivered nothing (the child was reaped behind the handle's back), then a wait that
/// fails for another reason, shows nothing of what became of the child: `Unknown`, not `Killed`.
///
/// Mutant: a failed wait is `Killed` whatever the kill did.
#[cfg(unix)]
#[skuld::test]
fn a_failed_wait_after_a_kill_that_delivered_nothing_is_unknown() {
    let fake = crate::os_process::fake::FakeProcess::new([])
        .reaps([crate::os_process::fake::ReapAnswer::Err(std::io::ErrorKind::Other)])
        .signals([Ok(crate::signal::Sent::Gone)]);
    let handle = super::ProcHandle::std(crate::child::owned::OwnedChild::new(Box::new(fake)), 4242);
    let torn = handle.teardown_on_drop(crate::identity::ProcessId::current());
    assert_eq!(torn.fate, crate::error::ChildFate::Unknown);
}
