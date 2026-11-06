//! A thread-local one-shot hook slot for test seams that release a fixture at a fire point in
//! production code, and the RAII guard that arms it.
//!
//! Each seam owns a `thread_local!` [`OneShotHook`] and exposes `arm`/`fire` wrappers over it. A seam
//! whose hook takes an argument and answers with a value uses [`arm_with`]/[`fire_with`].

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::thread::LocalKey;

/// One armed hook and the flag its guard reads: the flag also names the guard.
type Slot<A, R> = Option<(Rc<Cell<bool>>, Box<dyn FnOnce(A) -> R>)>;

/// The slot behind one seam, whose hook is given an `A` and answers an `R`. `const`-constructible,
/// for `thread_local!`.
pub(crate) struct OneShotHook<A = (), R = ()> {
    slot: RefCell<Slot<A, R>>,
}

impl<A, R> OneShotHook<A, R> {
    pub(crate) const fn new() -> Self {
        Self {
            slot: RefCell::new(None),
        }
    }
}

/// Arm `key`'s slot with `hook`; the guard clears it on drop.
///
/// Debug-asserts that no earlier hook is still waiting to fire.
pub(crate) fn arm(key: &'static LocalKey<OneShotHook>, hook: impl FnOnce() + 'static) -> Armed {
    arm_with(key, move |()| hook())
}

/// [`arm`] for a hook given an `A` and answering an `R`.
pub(crate) fn arm_with<A: 'static, R: 'static>(
    key: &'static LocalKey<OneShotHook<A, R>>,
    hook: impl FnOnce(A) -> R + 'static,
) -> Armed<A, R> {
    let fired = Rc::new(Cell::new(false));
    key.with(|h| {
        let previous = h.slot.borrow_mut().replace((Rc::clone(&fired), Box::new(hook)));
        debug_assert!(previous.is_none(), "a one-shot hook is already armed");
    });
    Armed { key, fired }
}

/// Run and disarm `key`'s hook. Does nothing when it has already fired or was never armed.
pub(crate) fn fire(key: &'static LocalKey<OneShotHook>) {
    fire_with(key, ());
}

/// [`fire`] for a hook given `arg`: its answer, or `None` when there was no hook to run.
pub(crate) fn fire_with<A: 'static, R: 'static>(key: &'static LocalKey<OneShotHook<A, R>>, arg: A) -> Option<R> {
    let taken = key.with(|h| h.slot.borrow_mut().take());
    taken.map(|(fired, hook)| {
        fired.set(true);
        hook(arg)
    })
}

/// Clears the hook it armed, and only that one: a hook armed after this guard's fired stays.
#[must_use = "dropping this immediately clears the armed hook; bind it for the scope that needs it"]
pub(crate) struct Armed<A: 'static = (), R: 'static = ()> {
    key: &'static LocalKey<OneShotHook<A, R>>,
    /// Set by the fire of this guard's hook, and by nothing else.
    fired: Rc<Cell<bool>>,
}

impl<A: 'static, R: 'static> Armed<A, R> {
    /// Panics unless the hook this guard armed has fired: a test that counts on its fire point being
    /// reached asserts it.
    #[track_caller]
    pub(crate) fn assert_fired(&self) {
        assert!(
            self.fired.get(),
            "the armed one-shot hook never fired: its fire point was not reached"
        );
    }
}

impl<A: 'static, R: 'static> Drop for Armed<A, R> {
    fn drop(&mut self) {
        let mine = self.key.with(|h| {
            let mut slot = h.slot.borrow_mut();
            match &*slot {
                Some((fired, _)) if Rc::ptr_eq(fired, &self.fired) => slot.take(),
                _ => None,
            }
        });
        drop(mine);
    }
}

#[cfg(test)]
#[path = "oneshot_hook_tests.rs"]
mod oneshot_hook_tests;
