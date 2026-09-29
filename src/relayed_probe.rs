//! Test-only, thread-local probes that follow a wait onto a `spawn_blocking` thread.
//!
//! A probe is a channel a test installs on its own thread so code under test can report to it.
//! It is thread-local, not process-global: under plain `cargo test`'s shared process, a global
//! slot would let another thread's unrelated wait report to this test. But a wait may run its
//! blocking half on a pool thread, where this thread's slot is invisible. [`capture`] on the
//! arming thread, before anything yields, and [`Relay::reinstall`] inside the closure carry
//! every installed probe across, so a new probe is one [`Probe`] impl and no relay edit.

use std::any::{Any, TypeId};
use std::cell::RefCell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::mpsc::Sender;

/// Names one probe and the event it carries. A marker type, never constructed.
pub(crate) trait Probe: 'static {
    type Event: Send + 'static;
}

/// A type-erased, cloneable installed channel.
trait Entry: Send {
    fn clone_entry(&self) -> Box<dyn Entry>;
    fn as_any(&self) -> &dyn Any;
}

impl<T: Clone + Send + 'static> Entry for T {
    fn clone_entry(&self) -> Box<dyn Entry> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

thread_local! {
    static SLOTS: RefCell<HashMap<TypeId, Box<dyn Entry>>> = RefCell::new(HashMap::new());
}

fn insert(id: TypeId, entry: Box<dyn Entry>) {
    let prev = SLOTS.with(|slots| slots.borrow_mut().insert(id, entry));
    debug_assert!(prev.is_none(), "probe installed nested on the same thread");
}

/// Uninstalls on drop, including during an unwind. `!Send`: it must clear the thread it was
/// installed on.
#[must_use = "dropping this immediately uninstalls the probe; bind it for its duration"]
pub(crate) struct Guard<P: Probe>(PhantomData<*const ()>, PhantomData<fn() -> P>);

impl<P: Probe> Drop for Guard<P> {
    fn drop(&mut self) {
        SLOTS.with(|slots| slots.borrow_mut().remove(&TypeId::of::<P>()));
    }
}

/// Install `tx` as this thread's `P`. Nesting on one thread is a contract violation.
pub(crate) fn install<P: Probe>(tx: Sender<P::Event>) -> Guard<P> {
    insert(TypeId::of::<P>(), Box::new(tx));
    Guard(PhantomData, PhantomData)
}

/// This thread's `P`, cloned so the installation survives.
pub(crate) fn current<P: Probe>() -> Option<Sender<P::Event>> {
    SLOTS.with(|slots| {
        slots
            .borrow()
            .get(&TypeId::of::<P>())
            .and_then(|entry| entry.as_any().downcast_ref::<Sender<P::Event>>().cloned())
    })
}

/// Whether this thread has a `P` installed.
pub(crate) fn is_installed<P: Probe>() -> bool {
    SLOTS.with(|slots| slots.borrow().contains_key(&TypeId::of::<P>()))
}

/// Send `event` to this thread's `P`, if installed.
pub(crate) fn notify<P: Probe>(event: P::Event) {
    if let Some(tx) = current::<P>() {
        // The test may have stopped listening; that is not the caller's failure.
        _ = tx.send(event);
    }
}

/// Every probe installed on the capturing thread, ready to move into a closure.
pub(crate) struct Relay(Vec<(TypeId, Box<dyn Entry>)>);

/// Clone every probe installed on this thread. Call on the arming thread before anything yields.
pub(crate) fn capture() -> Relay {
    Relay(SLOTS.with(|slots| {
        slots
            .borrow()
            .iter()
            .filter(|(id, _)| **id != TypeId::of::<crate::wait::read_probe::Log>())
            .map(|(id, entry)| (*id, entry.clone_entry()))
            .collect()
    }))
}

impl Relay {
    /// Install the captured probes on this thread until the guard drops.
    pub(crate) fn reinstall(self) -> RelayGuard {
        let ids = self.0.iter().map(|(id, _)| *id).collect();
        for (id, entry) in self.0 {
            insert(id, entry);
        }
        RelayGuard(ids, PhantomData)
    }
}

/// Uninstalls what [`Relay::reinstall`] installed. `!Send`, like [`Guard`].
#[must_use = "dropping this immediately uninstalls the probes; bind it for the closure's duration"]
pub(crate) struct RelayGuard(Vec<TypeId>, PhantomData<*const ()>);

impl Drop for RelayGuard {
    fn drop(&mut self) {
        SLOTS.with(|slots| {
            let mut slots = slots.borrow_mut();
            for id in &self.0 {
                slots.remove(id);
            }
        });
    }
}

#[cfg(test)]
#[path = "relayed_probe_tests.rs"]
mod relayed_probe_tests;
