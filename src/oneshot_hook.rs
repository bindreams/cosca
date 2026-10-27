//! A thread-local one-shot hook slot for test seams that release a fixture at a fire point in
//! production code, and the RAII guard that arms it.
//!
//! Each seam owns a `thread_local!` [`OneShotHook`] and exposes `arm`/`fire` wrappers over it. A seam
//! whose hook takes an argument and answers with a value uses [`arm_with`]/[`fire_with`].

use std::cell::{Cell, RefCell};
use std::thread::LocalKey;

/// One armed hook, tagged with the generation that armed it.
type Slot<A, R> = Option<(u64, Box<dyn FnOnce(A) -> R>)>;

/// The slot behind one seam, whose hook is given an `A` and answers an `R`. `const`-constructible,
/// for `thread_local!`.
pub(crate) struct OneShotHook<A = (), R = ()> {
    slot: RefCell<Slot<A, R>>,
    generation: Cell<u64>,
}

impl<A, R> OneShotHook<A, R> {
    pub(crate) const fn new() -> Self {
        Self {
            slot: RefCell::new(None),
            generation: Cell::new(0),
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
    let generation = key.with(|h| {
        let generation = h.generation.get() + 1;
        h.generation.set(generation);
        let previous = h.slot.borrow_mut().replace((generation, Box::new(hook)));
        debug_assert!(previous.is_none(), "a one-shot hook is already armed");
        generation
    });
    Armed { key, generation }
}

/// Run and disarm `key`'s hook. Does nothing when it has already fired or was never armed.
pub(crate) fn fire(key: &'static LocalKey<OneShotHook>) {
    fire_with(key, ());
}

/// [`fire`] for a hook given `arg`: its answer, or `None` when there was no hook to run.
pub(crate) fn fire_with<A: 'static, R: 'static>(key: &'static LocalKey<OneShotHook<A, R>>, arg: A) -> Option<R> {
    let taken = key.with(|h| h.slot.borrow_mut().take());
    taken.map(|(_, hook)| hook(arg))
}

/// Clears the hook it armed, and only that one: a hook armed after this guard's fired stays.
#[must_use = "dropping this immediately clears the armed hook; bind it for the scope that needs it"]
pub(crate) struct Armed<A: 'static = (), R: 'static = ()> {
    key: &'static LocalKey<OneShotHook<A, R>>,
    generation: u64,
}

impl<A: 'static, R: 'static> Drop for Armed<A, R> {
    fn drop(&mut self) {
        let mine = self.key.with(|h| {
            let mut slot = h.slot.borrow_mut();
            match &*slot {
                Some((generation, _)) if *generation == self.generation => slot.take(),
                _ => None,
            }
        });
        drop(mine);
    }
}

#[cfg(test)]
#[path = "oneshot_hook_tests.rs"]
mod oneshot_hook_tests;
