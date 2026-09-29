//! The debug-checked contract behind principle 3: an async `Drop` does bounded work only.
//!
//! `Child::drop` enters a [`Section`]. These functions call [`assert_may_block`] first, so a wait
//! that creeps into a drop panics at once in a debug build instead of hanging a runtime thread:
//!
//! - process exit: `wait::block_until_exit` (behind every platform's exit wait),
//!   `wait::windows::block_until_exit_or_cancel`, and the tokio `reap_now` / `wait_and_reap`;
//! - tree drain: `Attached::wait_drained`, and under it `CgroupLeaf::wait_drained`,
//!   `CgroupLeaf::block_until_drained`, `Marker::wait_drained` (macOS), `JobHandle::wait_drained`
//!   and `wait_drained_raw` (Windows).
//!
//! A wait added elsewhere must join this list. In release builds both are no-ops.

#[cfg(debug_assertions)]
thread_local! {
    static DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A stretch of code on this thread that must not block. Ends when dropped; sections nest.
#[must_use = "the section ends as soon as the guard is dropped"]
pub(crate) struct Section(());

impl Section {
    pub(crate) fn enter() -> Section {
        #[cfg(debug_assertions)]
        DEPTH.with(|d| d.set(d.get() + 1));
        Section(())
    }
}

impl Drop for Section {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// Assert, in debug builds, that this thread is outside every [`Section`]. Call it at the top of a
/// function that waits for a process exit or a cgroup drain; `what` names the wait.
#[track_caller]
pub(crate) fn assert_may_block(what: &str) {
    #[cfg(debug_assertions)]
    assert!(
        DEPTH.with(std::cell::Cell::get) == 0,
        "{what} would block inside an async Drop, which does bounded work only (principle 3)"
    );
    #[cfg(not(debug_assertions))]
    let _ = what;
}

/// Whether this thread is inside a [`Section`]. Lets a test hook, running inside a drop, prove the
/// drop entered one.
#[cfg(all(test, debug_assertions, target_os = "linux"))]
pub(crate) fn in_section() -> bool {
    DEPTH.with(std::cell::Cell::get) > 0
}

#[cfg(test)]
#[path = "bounded_tests.rs"]
mod bounded_tests;
