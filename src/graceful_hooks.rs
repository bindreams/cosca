//! The test seam shared by the sync and tokio `graceful_shutdown_tree` / `graceful_shutdown`
//! fault modules: where a hook runs, and the release that ends a held-stdin fixture there.

use crate::oneshot_hook::{arm, fire, Armed, OneShotHook};

/// Where in a graceful shutdown a test hook runs.
#[derive(Clone, Copy)]
pub(crate) enum HookPoint {
    /// After `terminate_tree` (`graceful_shutdown`: `terminate`) returned `Ok` (or was held), or the
    /// `SIGTERM` to a root its handle cannot answer for went out through its pidfd, before any drain
    /// or exit watch.
    AfterTerminate,
    /// After the kill or sweep returned `Ok` (or was skipped), before the root is reaped.
    BeforeReap,
    /// `graceful_shutdown`: after the grace ran out, before the escalation.
    BeforeEscalation,
    /// The sync `Child`'s kill-on-drop teardown: after the root kill returned `Ok`, before the
    /// blocking wait for the root.
    AfterDropKill,
    /// A tree call (`kill_tree`, `terminate_tree`, `graceful_shutdown_tree`), a drop, a failed
    /// spawn's cleanup: after its one look at the root, before anything is sent.
    #[cfg(unix)]
    AfterRootLook,
}

thread_local! {
    static AFTER_TERMINATE: OneShotHook = const { OneShotHook::new() };
    static BEFORE_REAP: OneShotHook = const { OneShotHook::new() };
    static BEFORE_ESCALATION: OneShotHook = const { OneShotHook::new() };
    static AFTER_DROP_KILL: OneShotHook = const { OneShotHook::new() };
    #[cfg(unix)]
    static AFTER_ROOT_LOOK: OneShotHook = const { OneShotHook::new() };
}

fn slot(point: HookPoint) -> &'static std::thread::LocalKey<OneShotHook> {
    match point {
        HookPoint::AfterTerminate => &AFTER_TERMINATE,
        HookPoint::BeforeReap => &BEFORE_REAP,
        HookPoint::BeforeEscalation => &BEFORE_ESCALATION,
        HookPoint::AfterDropKill => &AFTER_DROP_KILL,
        #[cfg(unix)]
        HookPoint::AfterRootLook => &AFTER_ROOT_LOOK,
    }
}

/// Run `hook` when the shutdown reaches `point`.
pub(crate) fn at(point: HookPoint, hook: impl FnOnce() + 'static) -> Armed {
    arm(slot(point), hook)
}

/// Drop `held` (a stdin a fixture blocks on) when the shutdown reaches `point`.
///
/// A fixture whose only end is a real signal would otherwise hang the call's own blocking wait if
/// the signal under test never came. Released here instead, it ends by itself with status 0, so the
/// test's assertion on HOW it died fails at once. A real signal delivered before `point` is already
/// pending, so it always beats the release.
pub(crate) fn release_at(point: HookPoint, held: impl Sized + 'static) -> Armed {
    arm(slot(point), move || drop(held))
}

/// [`at`] for a hook the test needs to have run: a hook the shutdown never reached is dropped
/// without a trace, so call [`Checked::assert_fired`] after the shutdown.
#[cfg(windows)]
pub(crate) fn at_checked(point: HookPoint, hook: impl FnOnce() + 'static) -> Checked {
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    let seen = std::rc::Rc::clone(&fired);
    let armed = at(point, move || {
        hook();
        seen.set(true);
    });
    Checked { _armed: armed, fired }
}

/// The guard [`at_checked`] gives back; it clears an unfired hook on drop.
#[cfg(windows)]
#[must_use = "dropping this immediately clears the armed hook; bind it and call `assert_fired`"]
pub(crate) struct Checked {
    _armed: Armed,
    fired: std::rc::Rc<std::cell::Cell<bool>>,
}

#[cfg(windows)]
impl Checked {
    /// Fail the test unless the shutdown reached the hook's point and the hook ran to its end.
    pub(crate) fn assert_fired(&self) {
        assert!(self.fired.get(), "the shutdown never reached the hook's point");
    }
}

pub(crate) fn run_hook(point: HookPoint) {
    fire(slot(point));
}
