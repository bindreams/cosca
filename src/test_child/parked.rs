//! A fixture a test hands to a hook that runs on another thread.

use std::any::Any;
use std::sync::{Arc, Mutex};

/// What a [`Parked`] holds: the value, until the release, and whether the release came.
#[derive(Default)]
struct State {
    value: Option<Box<dyn Any + Send>>,
    released: bool,
}

/// A value a test parks where a hook it hands to another thread can reach it: a child's stdin,
/// whose drop ends the child's read, or a fault guard. The first [`release`](Parked::release) drops
/// it and is final: a value held after it is dropped at once. Clones share the value.
#[derive(Clone, Default)]
pub(crate) struct Parked(Arc<Mutex<State>>);

impl Parked {
    #[cfg_attr(
        not(windows),
        allow(dead_code, reason = "only Windows tests park a value when they build it")
    )]
    pub(crate) fn new(value: impl Any + Send) -> Self {
        let parked = Self::default();
        parked.hold(value);
        parked
    }

    /// Parks `value`, dropping what was parked; after a release, drops `value` itself.
    pub(crate) fn hold(&self, value: impl Any + Send) {
        let value: Box<dyn Any + Send> = Box::new(value);
        // Dropped after the lock is: a drop may run code that takes this lock again.
        let _dropped = {
            let mut state = self.0.lock().expect("the parked value");
            if state.released {
                Some(value)
            } else {
                state.value.replace(value)
            }
        };
    }

    /// Drops the parked value, and every value held later.
    pub(crate) fn release(&self) {
        let _dropped = {
            let mut state = self.0.lock().expect("the parked value");
            state.released = true;
            state.value.take()
        };
    }
}
