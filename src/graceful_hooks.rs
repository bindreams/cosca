//! The test seam shared by the sync and tokio `graceful_shutdown_tree` / `graceful_shutdown`
//! fault modules: where a hook runs, and the release that ends a held-stdin fixture there.

use crate::oneshot_hook::{arm, fire, Armed, OneShotHook};

/// Where in a graceful shutdown a test hook runs.
#[derive(Clone, Copy)]
pub(crate) enum HookPoint {
    /// After `terminate_tree` returned `Ok` (or was held), before any drain or exit watch.
    AfterTerminate,
    /// After the kill or sweep returned `Ok` (or was skipped), before the root is reaped.
    BeforeReap,
    /// `graceful_shutdown`: after the grace ran out, before the escalation.
    BeforeEscalation,
}

thread_local! {
    static AFTER_TERMINATE: OneShotHook = const { OneShotHook::new() };
    static BEFORE_REAP: OneShotHook = const { OneShotHook::new() };
    static BEFORE_ESCALATION: OneShotHook = const { OneShotHook::new() };
}

fn slot(point: HookPoint) -> &'static std::thread::LocalKey<OneShotHook> {
    match point {
        HookPoint::AfterTerminate => &AFTER_TERMINATE,
        HookPoint::BeforeReap => &BEFORE_REAP,
        HookPoint::BeforeEscalation => &BEFORE_ESCALATION,
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

pub(crate) fn run_hook(point: HookPoint) {
    fire(slot(point));
}
