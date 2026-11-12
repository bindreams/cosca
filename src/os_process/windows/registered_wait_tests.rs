use std::future::Future as _;
use std::os::windows::io::{AsHandle, OwnedHandle};
use std::pin::pin;
use std::task::{Context, Waker};
use std::time::Duration;

use super::{wait_any, RegisteredWait, Woke};
use crate::os_process::windows::test_event::{new_test_event, signal_test_event};

fn event() -> OwnedHandle {
    new_test_event().expect("create an event")
}

/// Mutant: the callback does not complete the oneshot.
#[skuld::test]
async fn a_wait_resolves_once_its_handle_is_signalled() {
    let event = event();
    let mut wait = pin!(RegisteredWait::register(event.as_handle(), None).expect("register"));
    assert!(
        wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
        "an unsignalled handle is waited for"
    );
    signal_test_event(&event);
    assert_eq!(wait.await, Woke::Signalled);
}

/// A handle signalled before the registration still resolves: the OS runs the callback at once.
#[skuld::test]
async fn a_wait_on_a_signalled_handle_resolves() {
    let event = event();
    signal_test_event(&event);
    assert_eq!(
        RegisteredWait::register(event.as_handle(), None)
            .expect("register")
            .await,
        Woke::Signalled
    );
}

/// The registration's own timeout ends the wait, and says it was the timeout.
///
/// Mutant: the callback reports every wake as a signal; or the timeout is not passed to the OS.
#[skuld::test]
async fn a_wait_times_out_on_the_os_s_own_timer() {
    let event = event();
    let wait = RegisteredWait::register(event.as_handle(), Some(Duration::from_millis(1))).expect("register");
    assert_eq!(wait.await, Woke::TimedOut);
}

/// The wait owns a handle of its own: it resolves after the caller's handle is closed.
///
/// Mutant: the registration is made on the caller's handle, which the caller may close.
#[skuld::test]
async fn a_wait_outlives_the_handle_it_was_given() {
    let event = event();
    let signaller = event.try_clone().expect("duplicate the event");
    let wait = RegisteredWait::register(event.as_handle(), None).expect("register");
    drop(event);
    signal_test_event(&signaller);
    assert_eq!(wait.await, Woke::Signalled);
}

/// Mutant: the answer is not the signalled handle's.
#[skuld::test]
async fn wait_any_resolves_when_one_of_the_handles_is_signalled() {
    let events = [event(), event(), event()];
    signal_test_event(&events[1]);
    assert_eq!(
        wait_any(events.iter().map(|event| event.as_handle()), None)
            .await
            .expect("wait"),
        Woke::Signalled
    );
}

/// A bounded wait on handles that stay unsignalled ends at the real deadline, not before.
///
/// Mutant: the first timeout the OS reports is taken as the deadline.
#[skuld::test]
async fn wait_any_times_out_only_at_the_deadline() {
    let event = event();
    let deadline = crate::wait::deadline_from(Duration::from_millis(50)).expect("a finite deadline");
    let woke = wait_any(std::iter::once(event.as_handle()), Some(deadline))
        .await
        .expect("wait");
    assert_eq!(woke, Woke::TimedOut);
    assert!(crate::wait::now() >= deadline, "answered before its deadline");
}

/// The OS timeout is clamped at the `u32` millisecond ceiling, and a wait clamped short of the
/// deadline registers again for the time that is left: a second registration, with a smaller
/// remaining time, and the deadline honoured.
///
/// Mutant: the first timeout the OS reports ends the wait. Mutant: the remaining time is computed
/// once, before the loop.
#[skuld::test]
async fn wait_any_re_registers_past_a_clamped_timeout_until_the_deadline() {
    use crate::wait::{wait_clamp_seam, wait_ms_probe};

    let event = event();
    let deadline = crate::wait::deadline_from(Duration::from_millis(50)).expect("a finite deadline");
    wait_ms_probe::take();
    let _clamp = wait_clamp_seam::set(5);
    let woke = wait_any(std::iter::once(event.as_handle()), Some(deadline))
        .await
        .expect("wait");
    let arms = wait_ms_probe::take();
    assert_eq!(woke, Woke::TimedOut);
    assert!(crate::wait::now() >= deadline, "answered before its deadline");
    wait_ms_probe::assert_rearmed_with_fresh_remaining(&arms, 5);
}

/// A dropped wait leaves its handle waitable again.
#[skuld::test]
async fn a_dropped_wait_leaves_its_handle_waitable() {
    let event = event();
    drop(RegisteredWait::register(event.as_handle(), None).expect("register"));
    let wait = RegisteredWait::register(event.as_handle(), None).expect("register again");
    signal_test_event(&event);
    assert_eq!(wait.await, Woke::Signalled);
}
