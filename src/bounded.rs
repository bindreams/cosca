//! The debug-checked contract behind principle 3: an async `Drop` does bounded work only.
//!
//! `Child::drop` enters a [`Section`]. Every function that waits for a process exit or a cgroup
//! drain calls [`assert_may_block`] first, so a wait that creeps into a drop panics at once in a
//! debug build instead of hanging a runtime thread. A new wait must too. The assert is live in
//! debug builds and in this crate's own tests, whatever their profile, so the release test lane
//! detects a wait as well. In a release build of the library it is a no-op.

#[cfg(any(debug_assertions, test))]
thread_local! {
    static DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A stretch of code on this thread that must not block. Ends when dropped; sections nest.
#[must_use = "the section ends as soon as the guard is dropped"]
pub(crate) struct Section(());

impl Section {
    pub(crate) fn enter() -> Section {
        #[cfg(any(debug_assertions, test))]
        DEPTH.with(|d| d.set(d.get() + 1));
        Section(())
    }
}

impl Drop for Section {
    fn drop(&mut self) {
        #[cfg(any(debug_assertions, test))]
        DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// Assert, in debug builds, that this thread is outside every [`Section`]. Call it at the top of a
/// function that waits for a process exit or a cgroup drain; `what` names the wait.
#[track_caller]
pub(crate) fn assert_may_block(what: &str) {
    #[cfg(any(debug_assertions, test))]
    assert!(
        DEPTH.with(std::cell::Cell::get) == 0,
        "{what} would block inside an async Drop, which does bounded work only (principle 3)"
    );
    #[cfg(not(any(debug_assertions, test)))]
    let _ = what;
}

/// Whether this thread is inside a [`Section`]. Lets a test hook, running inside a drop, prove the
/// drop entered one.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn in_section() -> bool {
    DEPTH.with(std::cell::Cell::get) > 0
}

#[cfg(test)]
#[path = "bounded_tests.rs"]
mod bounded_tests;
