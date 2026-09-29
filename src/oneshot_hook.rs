//! A thread-local one-shot hook slot for test seams that release a fixture at a fire point in
//! production code, and the RAII guard that arms it.
//!
//! Each seam owns a `thread_local!` [`OneShotHook`] and exposes `arm`/`fire` wrappers over it.

use std::cell::{Cell, RefCell};
use std::thread::LocalKey;

/// One armed hook, tagged with the generation that armed it.
type Slot = Option<(u64, Box<dyn FnOnce()>)>;

/// The slot behind one seam. `const`-constructible, for `thread_local!`.
pub(crate) struct OneShotHook {
    slot: RefCell<Slot>,
    generation: Cell<u64>,
}

impl OneShotHook {
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
    let taken = key.with(|h| h.slot.borrow_mut().take());
    if let Some((_, hook)) = taken {
        hook();
    }
}

/// Clears the hook it armed, and only that one: a hook armed after this guard's fired stays.
#[must_use = "dropping this immediately clears the armed hook; bind it for the scope that needs it"]
pub(crate) struct Armed {
    key: &'static LocalKey<OneShotHook>,
    generation: u64,
}

impl Drop for Armed {
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
